// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The embedded PEP wired into the service provider (#40): the `pep` section
//! and its defaults, the key refusal, the `SamlLogin` adapter, `decide` and
//! `decide_session` against a stub PDP, and the `pep-policies-changed` event
//! handed over by `SignalsReceiver`. The PEP's own behaviour (the
//! credential, both modes, the engine) is iya-pep's suite.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::support::*;
use crate::pep::{subject_of, Access, Decision, POLICIES_CHANGED_EVENT};
use crate::session::{MemorySessionIndex, SessionRecord};
use crate::ssf_test::start_transmitter;
use crate::{ReceiverOptions, SamlLogin, ServiceProvider, SignalsReceiver};

/// A stub PDP at `<url>/realm/r1`: the token endpoint, register, heartbeat,
/// the catalogue, the policy pull and the AuthZEN evaluation. `decisions`
/// are answered in order, then Permit.
struct Pdp {
    _server: TestServer,
    url: String,
    seen: Arc<Mutex<Vec<(String, Value)>>>,
    decisions: Arc<Mutex<Vec<bool>>>,
    /// `local`: whether the policy pull answers.
    policies_up: Arc<AtomicBool>,
}

impl Pdp {
    fn count(&self, path: &str) -> usize {
        self.seen.lock().unwrap().iter().filter(|(p, _)| p == path).count()
    }

    fn bodies(&self, path: &str) -> Vec<Value> {
        self.seen.lock().unwrap().iter().filter(|(p, _)| p == path).map(|(_, b)| b.clone()).collect()
    }
}

/// Permits `read`, and nothing else.
const READ_ONLY: &str = r#"<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" PolicyId="orders" Version="1.0" RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit"><Target/><Rule RuleId="read" Effect="Permit"><Target><AnyOf><AllOf><Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal"><AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">read</AttributeValue><AttributeDesignator Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action" AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id" DataType="http://www.w3.org/2001/XMLSchema#string" MustBePresent="false"/></Match></AllOf></AnyOf></Target></Rule></Policy>"#;

fn start_pdp() -> Pdp {
    let seen: Arc<Mutex<Vec<(String, Value)>>> = Arc::new(Mutex::new(Vec::new()));
    let decisions: Arc<Mutex<Vec<bool>>> = Arc::new(Mutex::new(Vec::new()));
    let policies_up = Arc::new(AtomicBool::new(true));
    let (log, queue, up) = (seen.clone(), decisions.clone(), policies_up.clone());
    let server = serve(Arc::new(move |req| {
        let path = req.path.trim_start_matches("/realm/r1").to_string();
        log.lock().unwrap().push((path.clone(), serde_json::from_slice(&req.body).unwrap_or(Value::Null)));
        let write = |status: u16, value: Value| (status, "application/json", serde_json::to_vec(&value).unwrap_or_default());
        if path != "/oauth2/token" && !req.headers.get("authorization").is_some_and(|a| a.starts_with("DPoP ")) {
            return write(401, json!({"error": "invalid_token"}));
        }
        match path.as_str() {
            "/oauth2/token" => write(200, json!({"access_token": "pep-token", "token_type": "DPoP", "expires_in": 300})),
            "/xacml/pep/register" => write(201, json!({"registered": true})),
            "/xacml/pep/heartbeat" => write(200, json!({"acknowledged": true, "current": true})),
            "/xacml/pep/authzen-catalogue" => write(
                200,
                json!({"syncToken": "c1", "realm": "r1", "rows": [
                    {"object": "subject", "property": "acr", "attributeId": "urn:example:acr"},
                    {"object": "subject", "property": "mail", "attributeId": "urn:example:mail"}
                ], "settings": {"obligationsProfile": false}}),
            ),
            "/xacml/pep/policies" if up.load(Ordering::SeqCst) => write(200, json!({"syncToken": "p1", "root": "orders", "policies": [{
                "name": "orders", "policyId": "orders", "kind": "Policy", "version": "1.0", "isRoot": true, "description": "",
                "combiningAlgId": "urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-unless-permit", "document": READ_ONLY}], "withheld": [], "note": ""})),
            "/xacml/pep/policies" => write(503, json!({"error": "server_error", "error_description": "not now"})),
            "/admin-api/pep-audit" => write(200, json!({"acknowledged": 0})),
            "/access/v1/evaluation" => {
                let mut queue = queue.lock().unwrap();
                let decision = if queue.is_empty() { true } else { queue.remove(0) };
                write(200, json!({"decision": decision}))
            }
            _ => write(404, json!({"error": "not_found"})),
        }
    }));
    let url = format!("{}/realm/r1", server.url);
    Pdp { _server: server, url, seen, decisions, policies_up }
}

fn key_file(tag: &str, pem: &str) -> String {
    let path = std::env::temp_dir().join(format!("saml2-sp-pep-{tag}-{}.pem", std::process::id()));
    std::fs::write(&path, pem).unwrap();
    path.to_string_lossy().into_owned()
}

/// A fresh EC P-256 key, PKCS #8 PEM: the PEP's own.
fn ec_pem() -> String {
    rcgen::KeyPair::generate().unwrap().serialize_pem()
}

fn pep_section(pdp: &Pdp, tag: &str, extra: Value) -> Value {
    let mut section = json!({"name": "pep-demo", "assertionKey": key_file(tag, &ec_pem()), "pdpUrl": pdp.url, "heartbeatIntervalMs": 60000});
    for (k, v) in extra.as_object().unwrap() {
        section[k] = v.clone();
    }
    section
}

fn extra(value: Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap()
}

/// The stub identity provider's metadata, under another entityID.
fn metadata_for(entity_id: &str) -> String {
    idp_metadata("").replace(&format!("entityID=\"{IDP_ENTITY}\""), &format!("entityID=\"{entity_id}\""))
}

fn create(over: Value) -> Result<ServiceProvider, crate::SamlError> {
    ServiceProvider::create(&test_config(extra(over), ""), "", None)
}

/// A sign-in as iya-sts writes one: a persistent NameID that is the username,
/// `uid` under the LDAP profile's OID and bare, and the mail address.
fn login() -> SamlLogin {
    let mut attributes = HashMap::new();
    attributes.insert("urn:oid:0.9.2342.19200300.100.1.1".to_string(), vec!["alice".to_string()]);
    attributes.insert("uid".to_string(), vec!["alice".to_string()]);
    attributes.insert("urn:oid:0.9.2342.19200300.100.1.3".to_string(), vec!["alice@example.com".to_string()]);
    attributes.insert("groups".to_string(), vec!["staff".to_string(), "admins".to_string()]);
    let mut friendly = HashMap::new();
    friendly.insert("urn:oid:0.9.2342.19200300.100.1.1".to_string(), "uid".to_string());
    friendly.insert("urn:oid:0.9.2342.19200300.100.1.3".to_string(), "mail".to_string());
    SamlLogin {
        name_id: "_3f9a-transient".into(),
        name_id_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient".into(),
        name_qualifier: String::new(),
        sp_name_qualifier: String::new(),
        session_index: "IDP-S1".into(),
        session_not_on_or_after_ms: None,
        authn_instant_ms: 1_700_000_000_123,
        authn_context_class_ref: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport".into(),
        attributes,
        attribute_friendly_names: friendly,
        issuer: IDP_ENTITY.into(),
        in_response_to: None,
        relay_state: None,
        binding: "post".into(),
        encrypted: false,
        response_id: String::new(),
        assertion_id: String::new(),
    }
}

#[test]
fn a_pep_section_builds_a_started_pep_with_the_librarys_defaults() {
    let pdp = start_pdp();
    // iya-sts's entityID is the realm's issuer: the PDP, realm prefix included.
    let mut section = pep_section(&pdp, "defaults", json!({}));
    section.as_object_mut().unwrap().remove("pdpUrl");
    let sp = create(json!({"idpMetadata": metadata_for(&pdp.url), "pep": section})).unwrap();
    let pep = sp.pep().expect("a PEP");
    assert_eq!(pep.config().pdp_url, pdp.url, "pdpUrl defaults to the identity provider's entityID");
    assert_eq!(pep.config().realm(), "r1");
    assert_eq!(pep.config().application, SP_ENTITY, "application defaults to entityId");
    assert!(!pep.config().signals, "no ssf block, no receiver");
    assert!(pep.config().tls_ca.is_empty());
    assert!(pep.status().running);
    let register = pdp.bodies("/xacml/pep/register");
    assert!(!register.is_empty(), "registered at create");
    assert_eq!(register[0]["kind"], "embedded");
    assert_eq!(register[0]["application"], SP_ENTITY);
    assert!(pep.status().registered);

    // signals follow the receiver: an ssf block, unless signals is false.
    let ssf = json!({"transmitter": "https://sts.test"});
    let on = create(json!({"ssf": ssf, "pep": pep_section(&pdp, "ssf", json!({}))})).unwrap();
    assert!(on.pep().unwrap().config().signals);
    let off = create(json!({"ssf": ssf, "signals": false, "pep": pep_section(&pdp, "nosignals", json!({}))})).unwrap();
    assert!(!off.pep().unwrap().config().signals);
    let named = create(json!({"pep": pep_section(&pdp, "named", json!({"signals": true, "application": "orders"}))})).unwrap();
    assert!(named.pep().unwrap().config().signals, "the section's own value wins");
    assert_eq!(named.pep().unwrap().config().application, "orders");

    // tlsCa is idpCa; a relative assertionKey is read from the configuration's directory.
    let dir = std::env::temp_dir().join(format!("saml2-sp-pep-dir-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pep-key.pem"), ec_pem()).unwrap();
    let ca = idp_key().certificate_pem.clone();
    let config = test_config(extra(json!({"idpCa": ca, "pep": {"name": "pep-demo", "assertionKey": "file:pep-key.pem", "pdpUrl": pdp.url, "heartbeatIntervalMs": 60000}})), "");
    let sp = ServiceProvider::create(&config, &dir.to_string_lossy(), None).unwrap();
    assert_eq!(sp.pep().unwrap().config().tls_ca, ca);
    assert_eq!(sp.pep().unwrap().config().assertion_key, dir.join("pep-key.pem").to_string_lossy());

    assert!(create(json!({})).unwrap().pep().is_none(), "no section, no PEP");
    assert!(create(json!({"pep": null})).unwrap().pep().is_none());
}

/// `from_file` reads the `pep` section as `create` does, and the PEP it
/// builds is started: the live run of oidc-caep-risc (its #46) found that
/// library's file reader dropped the section, so this one is held to it too.
#[test]
fn from_file_keeps_the_pep_section() {
    let pdp = start_pdp();
    let dir = std::env::temp_dir().join(format!("saml2-sp-pep-from-file-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pep-key.pem"), ec_pem()).unwrap();
    let doc = test_config(extra(json!({"pep": {"name": "pep-demo", "assertionKey": "file:pep-key.pem", "pdpUrl": pdp.url, "heartbeatIntervalMs": 60000}})), "");
    let path = dir.join("saml.json");
    std::fs::write(&path, Value::Object(doc).to_string()).unwrap();
    let sp = ServiceProvider::from_file(&path.to_string_lossy(), None, None).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let pep = sp.pep().expect("the configuration file's pep section built a PEP");
    assert_eq!(pep.config().name, "pep-demo");
    assert_eq!(pep.config().assertion_key, dir.join("pep-key.pem").to_string_lossy(), "relative to the file's directory");
    assert!(pep.status().running);
    assert!(pdp.count("/xacml/pep/register") >= 1, "and started it");
}

#[test]
fn a_bad_section_is_refused_at_create() {
    let pdp = start_pdp();
    for (over, says) in [
        (json!({"pep": "on"}), "pep must be an object"),
        (json!({"pep": pep_section(&pdp, "bad-mode", json!({"mode": "remote"}))}), "pep.mode"),
        (json!({"pep": pep_section(&pdp, "bad-member", json!({"polIntervalMs": 1}))}), "polIntervalMs"),
        (json!({"pep": {"name": "pep-demo", "pdpUrl": pdp.url}}), "assertionKey"),
        (json!({"pep": {"name": "pep-demo", "assertionKey": "/nowhere.pem", "pdpUrl": pdp.url}}), "could not be read"),
        // An identity provider that is not iya-sts gives no pdpUrl to default to.
        (json!({"idpMetadata": metadata_for("urn:example:idp"), "pep": {"name": "pep-demo", "assertionKey": key_file("urn", &ec_pem())}}), "name the service in pep.pdpUrl"),
    ] {
        let err = create(over).err().expect("refused");
        assert_eq!(err.code, "config");
        assert!(err.message.contains(says), "{} / {says}", err.message);
    }
}

#[test]
fn the_pep_key_must_differ_from_the_service_providers_key() {
    let pdp = start_pdp();
    // privateKey signs requests, decrypts assertions and is the receiver's
    // TLS client key: the one key this library holds.
    let same = json!({"name": "pep-demo", "assertionKey": key_file("same", &sp_key().private_key_pem), "pdpUrl": pdp.url});
    let err = create(json!({"pep": same})).err().expect("refused");
    assert_eq!(err.code, "config");
    assert!(err.message.contains("privateKey"), "{}", err.message);
    assert_eq!(pdp.count("/xacml/pep/register"), 0, "refused before anything is sent");

    // Another RSA key is fine.
    let other = create_self_signed_key_pair_pem();
    let sp = create(json!({"pep": {"name": "pep-demo", "assertionKey": key_file("other", &other), "pdpUrl": pdp.url}})).unwrap();
    assert!(sp.pep().is_some());
}

fn create_self_signed_key_pair_pem() -> String {
    crate::create_self_signed_key_pair("pep.test", 1, 2048).unwrap().private_key_pem
}

#[test]
fn a_saml_login_becomes_the_peps_subject() {
    let s = subject_of(&login());
    assert_eq!((s.kind.as_str(), s.id.as_str()), ("user", "alice"), "the uid attribute: the username the PIP resolves, not a transient NameID");
    assert_eq!(s.properties["acr"], "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
    assert_eq!(s.properties["auth_time"], 1_700_000_000, "AuthnInstant in epoch seconds");
    assert_eq!(s.properties["urn:oid:0.9.2342.19200300.100.1.3"], "alice@example.com");
    assert_eq!(s.properties["mail"], "alice@example.com", "under its FriendlyName too");
    assert_eq!(s.properties["groups"], json!(["staff", "admins"]), "several values are an array");
    assert!(s.properties.get("amr").is_none());

    let mut bare = login();
    bare.attributes.remove("urn:oid:0.9.2342.19200300.100.1.1");
    bare.attributes.remove("uid");
    bare.attributes.insert("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name".into(), vec!["alice-ad".into()]);
    assert_eq!(subject_of(&bare).id, "alice-ad", "the AD FS name claim");
    bare.attributes.remove("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name");
    bare.name_id = "alice-nameid".into();
    assert_eq!(subject_of(&bare).id, "alice-nameid", "the NameID when no attribute names the user");

    let mut amr = login();
    amr.attributes.insert("amr".into(), vec!["pwd".into()]);
    amr.authn_context_class_ref.clear();
    amr.authn_instant_ms = 0;
    let s = subject_of(&amr);
    assert_eq!(s.properties["amr"], json!(["pwd"]), "always an array");
    assert!(s.properties.get("acr").is_none() && s.properties.get("auth_time").is_none());
}

#[test]
fn decide_asks_the_service_with_the_declared_claims_only() {
    let pdp = start_pdp();
    let sp = create(json!({"pep": pep_section(&pdp, "decide", json!({}))})).unwrap();
    pdp.decisions.lock().unwrap().extend([true, false]);
    assert!(sp.decide(&login(), &Access::new("read", "order", "42")).is_permit());
    assert!(matches!(sp.decide(&login(), &Access::new("delete", "order", "42")), Decision::Deny { .. }));
    let bodies = pdp.bodies("/access/v1/evaluation");
    assert_eq!(bodies.len(), 2);
    let body = &bodies[0];
    assert_eq!(body["subject"]["type"], "user");
    assert_eq!(body["subject"]["id"], "alice");
    assert_eq!(
        body["subject"]["properties"],
        json!({"acr": "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", "mail": "alice@example.com"}),
        "auth_time, groups and the URN-named attributes are not in the catalogue"
    );
    assert_eq!(body["action"]["name"], "read");
    assert_eq!(body["resource"], json!({"type": "order", "id": "42"}));
    assert_eq!(body["context"]["application"], SP_ENTITY);

    // A session that is not tracked (signed out, expired, or ended by
    // session-revoked) has no subject, and nothing is asked.
    let index = MemorySessionIndex::new(0);
    let before = pdp.count("/access/v1/evaluation");
    let access = Access::new("read", "order", "42");
    assert!(matches!(sp.decide_session(&index, "L1", &login(), &access), Decision::Deny { .. }));
    assert_eq!(pdp.count("/access/v1/evaluation"), before);
    index.add(SessionRecord { local_id: "L1".into(), person: "alice".into(), email: String::new(), idp_session: "IDP-S1".into(), expires_at_ms: None });
    assert!(sp.decide_session(&index, "L1", &login(), &access).is_permit());
    index.remove("L1");
    assert!(matches!(sp.decide_session(&index, "L1", &login(), &access), Decision::Deny { .. }));
    index.add(SessionRecord { local_id: "L2".into(), person: "alice".into(), email: String::new(), idp_session: "IDP-S2".into(), expires_at_ms: Some(1) });
    assert!(matches!(sp.decide_session(&index, "L2", &login(), &access), Decision::Deny { .. }), "expired");
    assert_eq!(pdp.count("/access/v1/evaluation"), before + 1);

    let none = create(json!({})).unwrap();
    assert!(matches!(none.decide(&login(), &access), Decision::Unavailable { .. }), "no section never permits");
}

#[test]
fn the_receiver_asks_for_the_policy_event_and_hands_it_to_the_pep() {
    let pdp = start_pdp();
    let tx = start_transmitter(false);
    // central with a Permit cache: the event clears it.
    let sp = create(json!({"pep": pep_section(&pdp, "event", json!({"permitCacheMs": 30000}))})).unwrap();
    let options = |pep| ReceiverOptions {
        transmitter: tx.url.clone(),
        on_end_sessions: Some(Arc::new(|_: &[String], _: &crate::SignalEvent| Ok(()))),
        poll_interval_ms: 60_000,
        log: Some(Arc::new(Quiet)),
        pep,
        ..ReceiverOptions::default()
    };
    let without = SignalsReceiver::new(options(None)).unwrap();
    assert!(!without.events_requested().iter().any(|e| e == POLICIES_CHANGED_EVENT), "no PEP, no event asked for");
    let plain = create(json!({"pep": pep_section(&pdp, "plain", json!({}))})).unwrap();
    let central = SignalsReceiver::new(options(plain.pep().cloned())).unwrap();
    assert!(!central.events_requested().iter().any(|e| e == POLICIES_CHANGED_EVENT), "central without a cache has nothing to refresh");
    let receiver = SignalsReceiver::new(options(sp.pep().cloned())).unwrap();
    assert!(receiver.events_requested().iter().any(|e| e == POLICIES_CHANGED_EVENT), "asked for on the service provider's own stream");
    assert!(receiver.events_requested().len() > 1, "as well as the CAEP and RISC events");

    let access = Access::new("read", "order", "42");
    assert!(sp.decide(&login(), &access).is_permit());
    assert!(sp.decide(&login(), &access).is_permit());
    assert_eq!(pdp.count("/access/v1/evaluation"), 1, "the second came from the Permit cache");

    receiver.start().unwrap();
    receiver.stop();
    let subject = json!({"format": "opaque", "id": SP_ENTITY});
    let body = extra(json!({"pep": "pep-demo", "changed": ["policies"], "sync_token": "p2"}));
    // A SET signed by another key is refused and never reaches the PEP.
    tx.put_set(POLICIES_CHANGED_EVENT, subject.clone(), body.clone(), Some(other_key()), "", "");
    receiver.poll_once().unwrap();
    assert!(sp.decide(&login(), &access).is_permit());
    assert_eq!(pdp.count("/access/v1/evaluation"), 1, "an unverified event changes nothing");

    // A verified one is handed to the PEP, which clears its cache.
    tx.put_set(POLICIES_CHANGED_EVENT, subject, body, None, "", "");
    receiver.poll_once().unwrap();
    assert!(sp.decide(&login(), &access).is_permit());
    assert_eq!(pdp.count("/access/v1/evaluation"), 2, "the event cleared the cache");
}

/// Waits up to 10 s for a heartbeat whose `policyEvents` is `want` (one
/// built before the receiver started can still be on its way).
fn assert_policy_events(pdp: &Pdp, want: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let last = pdp.bodies("/xacml/pep/heartbeat").last().map(|beat| beat["policyEvents"].clone());
        if last.as_ref().is_some_and(|value| value == want) {
            return;
        }
        assert!(std::time::Instant::now() < deadline, "no heartbeat said {want}; the last said {last:?}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

struct Errors(Mutex<Vec<String>>);
impl crate::Logger for Errors {
    fn info(&self, _: &str) {}
    fn warn(&self, _: &str) {}
    fn error(&self, message: &str) { self.0.lock().unwrap().push(message.to_string()); }
}

/// oidc-caep-risc's live run (#46): a stream made while the PEP was
/// `central` (no event asked for) was found and reused by the `local` PEP's
/// receiver, so iya-sts never sent it `pep-policies-changed`. A reused stream
/// now gets the missing type PATCHed in, and the PEP's heartbeat says
/// `requested`, or `excluded` when the transmitter won't.
#[test]
fn a_reused_stream_gets_the_policy_event_added() {
    let pdp = start_pdp();
    let caep = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
    let old = |tx: &crate::ssf_test::Transmitter, id: &str| json!({
        "stream_id": id, "iss": tx.url, "aud": "my-app",
        "delivery": {"method": "urn:ietf:rfc:8936", "endpoint_url": format!("{}/ssf/poll/{id}", tx.url)},
        "events_requested": [caep], "events_delivered": [caep]
    });
    let errors = Arc::new(Errors(Mutex::new(Vec::new())));
    let options = |tx: &crate::ssf_test::Transmitter, pep| ReceiverOptions {
        transmitter: tx.url.clone(),
        on_end_sessions: Some(Arc::new(|_: &[String], _: &crate::SignalEvent| Ok(()))),
        poll_interval_ms: 60_000,
        log: Some(errors.clone() as Arc<dyn crate::Logger>),
        pep,
        ..ReceiverOptions::default()
    };
    // No ssf block, so the PEP starts out reporting `none`: a `requested`
    // heartbeat can only come from the receiver.
    let sp = create(json!({"pep": pep_section(&pdp, "reuse", json!({"permitCacheMs": 30000, "heartbeatIntervalMs": 1000}))})).unwrap();
    let tx = start_transmitter(false);
    tx.add_stream(old(&tx, "old"));
    let receiver = SignalsReceiver::new(options(&tx, sp.pep().cloned())).unwrap();
    receiver.start().unwrap();
    receiver.stop();
    assert_eq!(tx.created(), 0, "the stream was reused, not made again");
    let patches = tx.patches();
    assert_eq!(patches.len(), 1, "{patches:?}");
    assert_eq!(patches[0]["stream_id"], "old");
    let asked: Vec<&str> = patches[0]["events_requested"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    assert!(asked.contains(&caep), "what it asked for before is kept: {asked:?}");
    assert!(asked.contains(&POLICIES_CHANGED_EVENT), "the policy event is added: {asked:?}");
    let stream = receiver.stream();
    assert!(stream["events_delivered"].as_array().unwrap().iter().any(|e| e == POLICIES_CHANGED_EVENT));
    assert_eq!(stream["delivery"]["endpoint_url"], format!("{}/ssf/poll/old", tx.url), "the delivery the listing gave is kept");
    assert!(errors.0.lock().unwrap().is_empty(), "{:?}", errors.0.lock().unwrap());
    assert_policy_events(&pdp, "requested");

    // Nothing missing: no PATCH.
    let again = SignalsReceiver::new(options(&tx, sp.pep().cloned())).unwrap();
    again.start().unwrap();
    again.stop();
    assert_eq!(tx.patches().len(), 1, "a stream that already carries the event is left alone");

    // A transmitter that refuses: the receiver still starts, says so, and
    // the PEP's heartbeat reports the event excluded.
    let tx = start_transmitter(false);
    tx.refuse_patch();
    tx.add_stream(old(&tx, "fixed"));
    let refused = SignalsReceiver::new(options(&tx, sp.pep().cloned())).unwrap();
    refused.start().unwrap();
    refused.stop();
    assert_eq!(tx.patches().len(), 1);
    assert!(errors.0.lock().unwrap().iter().any(|l| l.contains("answered 405")), "{:?}", errors.0.lock().unwrap());
    assert_policy_events(&pdp, "excluded");
}

struct Quiet;
impl crate::Logger for Quiet {
    fn info(&self, _: &str) {}
    fn warn(&self, _: &str) {}
    fn error(&self, _: &str) {}
}

#[cfg(feature = "local")]
#[test]
fn local_mode_fails_closed_then_decides_in_process() {
    let pdp = start_pdp();
    pdp.policies_up.store(false, Ordering::SeqCst);
    let sp = create(json!({"pep": pep_section(&pdp, "local", json!({"mode": "local", "pollIntervalMs": 1000}))})).unwrap();
    let pep = sp.pep().unwrap();
    assert!(!pep.config().signals, "no receiver: the PEP polls at pollIntervalMs");
    assert!(matches!(sp.decide(&login(), &Access::new("read", "order", "42")), Decision::Unavailable { .. }), "no policy held yet");

    pdp.policies_up.store(true, Ordering::SeqCst);
    let held = (0..50).any(|_| {
        std::thread::sleep(Duration::from_millis(100));
        pep.status().holds_policy
    });
    assert!(held, "the poll pulled once the service answered");
    assert!(sp.decide(&login(), &Access::new("read", "order", "42")).is_permit());
    assert!(matches!(sp.decide(&login(), &Access::new("write", "order", "42")), Decision::Deny { .. }));
    assert_eq!(pdp.count("/access/v1/evaluation"), 0, "decided in process");
    assert!(pdp.count("/xacml/pep/policies") >= 2);
}
