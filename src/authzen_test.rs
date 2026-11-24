// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! This library's AuthZEN cases for the embedded PEP (#40): the table in
//! `src/authzen/cases.json`, run through this library's own API (a
//! `SamlLogin`, an `Access`, `ServiceProvider::decide` and `decide_session`).
//!
//! - `the_table_decides_as_it_says_offline` runs every case through a `local`
//!   ServiceProvider against a stub PDP that serves the table's catalogue,
//!   its XACML (`src/authzen/*.xml`, what iya-sts stored for the `.alfa`
//!   files) and its directory (the PIP), and checks the table's answer.
//! - `live_central_equals_local` is the differential test. It runs only when
//!   `AUTHZEN_LIVE` names a settings file, which `scripts/live_authzen.py`
//!   writes after provisioning a fresh iya-sts; it asks every case of one
//!   phase through a `central` and a `local` ServiceProvider and requires
//!   central == local == the table's answer, listing every case that is not.
//!
//! An answer is compared at the level the host sees: Permit (with each
//! obligation's id, type and properties), Deny or Unavailable. The reasons
//! differ between modes by design and are not compared, nor is local-mode
//! advice.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use super::support::*;
use crate::pep::{Access, Decision};
use crate::session::{MemorySessionIndex, SessionRecord};
use crate::{SamlLogin, ServiceProvider};

const CASES: &str = include_str!("authzen/cases.json");
const ROOT_XML: &str = include_str!("authzen/root.xml");
const SHARED_XML: &str = include_str!("authzen/shared.xml");
const APPLICATION_XML: &str = include_str!("authzen/application.xml");

const SESSION: &str = "L-authzen";

fn table() -> Value {
    serde_json::from_str(CASES).expect("src/authzen/cases.json is JSON")
}

fn phase_of(case: &Value) -> &str {
    case["phase"].as_str().unwrap_or("root")
}

fn strings(value: &Value) -> Vec<String> {
    value.as_array().map(|list| list.iter().filter_map(Value::as_str).map(str::to_string).collect()).unwrap_or_default()
}

/// The case's sign-in: its named login, with the case's `attributes` merged
/// (`null` removes one), `friendlyNames` added and `acr` replaced.
fn login_of(table: &Value, case: &Value) -> SamlLogin {
    let name = case["login"].as_str().expect("a case names a login");
    let base = &table["logins"][name];
    assert!(base.is_object(), "no login {name}");
    let mut attributes: HashMap<String, Vec<String>> = HashMap::new();
    for source in [&base["attributes"], &case["attributes"]] {
        for (key, value) in source.as_object().into_iter().flatten() {
            if value.is_null() {
                attributes.remove(key);
            } else {
                attributes.insert(key.clone(), strings(value));
            }
        }
    }
    let mut friendly = HashMap::new();
    for source in [&base["friendlyNames"], &case["friendlyNames"]] {
        for (key, value) in source.as_object().into_iter().flatten() {
            friendly.insert(key.clone(), value.as_str().unwrap_or("").to_string());
        }
    }
    let acr = case.get("acr").or(base.get("acr")).and_then(Value::as_str).unwrap_or("").to_string();
    SamlLogin {
        name_id: base["nameId"].as_str().unwrap_or("").into(),
        name_id_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient".into(),
        name_qualifier: String::new(),
        sp_name_qualifier: String::new(),
        session_index: "IDP-AZN".into(),
        session_not_on_or_after_ms: None,
        authn_instant_ms: 1_760_000_000_000,
        authn_context_class_ref: acr,
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

fn access_of(case: &Value) -> Access {
    let a = &case["access"];
    let text = |k: &str| a[k].as_str().unwrap_or("").to_string();
    let object = |k: &str| a[k].as_object().cloned().unwrap_or_default();
    let mut access = Access::new(text("action"), text("type"), text("id"));
    access.resource_properties = object("resource");
    access.action_properties = object("actionProperties");
    access.context = object("context");
    access
}

/// One case through one ServiceProvider: `decide`, or `decide_session`
/// with the session tracked or not.
fn ask(sp: &ServiceProvider, table: &Value, case: &Value) -> Decision {
    let login = login_of(table, case);
    let access = access_of(case);
    match case["session"].as_str() {
        None => sp.decide(&login, &access),
        Some(state) => {
            let index = MemorySessionIndex::new(0);
            if state == "tracked" {
                index.add(SessionRecord { local_id: SESSION.into(), person: "azn".into(), email: String::new(), idp_session: "IDP-AZN".into(), expires_at_ms: None });
            }
            sp.decide_session(&index, SESSION, &login, &access)
        }
    }
}

/// The answer as the host sees it.
fn answer_of(decision: &Decision) -> Value {
    match decision {
        Decision::Permit { obligations, .. } => json!({
            "decision": "Permit",
            "obligations": obligations.iter().map(|o| json!({"id": o.id, "type": o.kind, "properties": o.properties})).collect::<Vec<_>>(),
        }),
        Decision::Deny { .. } => json!({"decision": "Deny"}),
        Decision::Unavailable { .. } => json!({"decision": "Unavailable"}),
    }
}

/// Whether an answer is the table's: the decision, and for a Permit each
/// obligation's type and properties, in order (ids are the service's).
fn is_expected(answer: &Value, expect: &Value) -> bool {
    if answer["decision"] != expect["decision"] {
        return false;
    }
    if expect["decision"] != "Permit" {
        return true;
    }
    let got: Vec<Value> = answer["obligations"].as_array().cloned().unwrap_or_default().iter().map(|o| json!({"type": o["type"], "properties": o["properties"]})).collect();
    let want: Vec<Value> = expect["obligations"].as_array().cloned().unwrap_or_default();
    got == want
}

fn why(decision: &Decision) -> String {
    match decision {
        Decision::Deny { why } | Decision::Unavailable { why } => why.clone(),
        Decision::Permit { .. } => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Offline: a stub PDP serving the table.
// ---------------------------------------------------------------------------

fn document(file: &str) -> &'static str {
    match file {
        "root.xml" => ROOT_XML,
        "shared.xml" => SHARED_XML,
        "application.xml" => APPLICATION_XML,
        other => panic!("no policy file {other}"),
    }
}

/// The rows the bound-application pull sends for a phase: the root and its
/// reference closure (none), or the application's policy and the policy it
/// references.
fn pulled(table: &Value, phase: &str) -> Value {
    let row = |key: &str, root: bool| {
        let p = &table["policies"][key];
        let doc = document(p["xacml"].as_str().unwrap());
        assert!(doc.contains(p["policyId"].as_str().unwrap()), "src/authzen/{} is not {}: run scripts/live_authzen.py --write-xml", p["xacml"], p["policyId"]);
        json!({"name": p["name"].as_str().unwrap_or(key), "policyId": p["policyId"], "kind": p["kind"], "version": "1.0", "isRoot": root, "description": "", "document": doc})
    };
    let policies = if phase == "root" { vec![row("root", true)] } else { vec![row("application", true), row("shared", false)] };
    json!({"syncToken": format!("azn-{phase}"), "scope": "bound-application", "source": if phase == "root" { "root" } else { "application" }, "policies": policies, "withheld": [], "note": ""})
}

/// The PIP: the table's directory, for the bare names a designator asks.
fn pip_answer(table: &Value, query: &str) -> String {
    let subject = regex::Regex::new(r#"subject-id"[^>]*>\s*<AttributeValue[^>]*>([^<]*)<"#).unwrap();
    let designator = regex::Regex::new(r#"<AttributeDesignator[^>]*Category="([^"]*)"[^>]*AttributeId="([^"]*)"[^>]*DataType="([^"]*)""#).unwrap();
    let id = subject.captures(query).map(|c| c[1].to_string()).unwrap_or_default();
    let person = &table["directory"][id.as_str()];
    let mut out = String::from("<PIPResponse xmlns=\"urn:sts:xacml:pip:1.0\">");
    for c in designator.captures_iter(query) {
        if let Some(value) = person[&c[2]].as_str() {
            out.push_str(&format!(
                "<Attributes xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" Category=\"{}\"><Attribute AttributeId=\"{}\" IncludeInResult=\"false\"><AttributeValue DataType=\"{}\">{value}</AttributeValue></Attribute></Attributes>",
                &c[1], &c[2], &c[3]
            ));
        }
    }
    out.push_str("</PIPResponse>");
    out
}

fn stub(phase: &'static str) -> (TestServer, String) {
    let table = Arc::new(table());
    let server = serve(Arc::new(move |req| {
        let path = req.path.trim_start_matches("/realm/azn").to_string();
        let write = |status: u16, value: Value| (status, "application/json", serde_json::to_vec(&value).unwrap_or_default());
        if path != "/oauth2/token" && !req.headers.get("authorization").is_some_and(|a| a.starts_with("DPoP ")) {
            return write(401, json!({"error": "invalid_token"}));
        }
        match path.as_str() {
            "/oauth2/token" => write(200, json!({"access_token": "azn-token", "token_type": "DPoP", "expires_in": 300})),
            "/xacml/pep/register" => write(201, json!({"registered": true})),
            "/xacml/pep/heartbeat" => write(200, json!({"acknowledged": true, "current": true})),
            "/xacml/pep/authzen-catalogue" => write(200, json!({"syncToken": "azn-c", "realm": "azn", "rows": table["catalogue"], "settings": {"obligationsProfile": true}})),
            "/xacml/pep/policies" => write(200, pulled(&table, phase)),
            "/xacml/pip" => (200, "application/xml", pip_answer(&table, &String::from_utf8_lossy(&req.body)).into_bytes()),
            "/admin-api/pep-audit" => write(200, json!({"acknowledged": 0})),
            _ => write(404, json!({"error": "not_found"})),
        }
    }));
    let url = format!("{}/realm/azn", server.url);
    (server, url)
}

fn wait_until(what: &str, timeout: Duration, ready: impl Fn() -> bool) {
    let deadline = Instant::now() + timeout;
    while !ready() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn the_table_decides_as_it_says_offline() {
    let table = table();
    let cases = table["cases"].as_array().expect("cases");
    let subject_roots: std::collections::HashSet<&str> = table["catalogue"].as_array().unwrap().iter().filter(|r| r["object"] == "subject").filter_map(|r| r["property"].as_str()).map(|p| p.split('.').next().unwrap()).collect();
    let mut failures = Vec::new();
    let mut run = 0;
    for phase in ["root", "application"] {
        let (_server, url) = stub(phase);
        let key = std::env::temp_dir().join(format!("saml2-sp-authzen-{phase}-{}.pem", std::process::id()));
        std::fs::write(&key, rcgen::KeyPair::generate().unwrap().serialize_pem()).unwrap();
        let section = json!({"name": "pep-azn", "mode": "local", "assertionKey": key.to_string_lossy(), "pdpUrl": url,
            "heartbeatIntervalMs": 60000, "pollIntervalMs": 60000, "decisionRecords": false, "supportedObligations": table["supportedObligations"]});
        let mut extra = Map::new();
        extra.insert("pep".into(), section);
        let sp = ServiceProvider::create(&test_config(extra, ""), "", None).unwrap();
        let pep = sp.pep().unwrap();
        wait_until("the local PEP to hold the table's policy", Duration::from_secs(20), || pep.status().holds_policy);
        let _ = std::fs::remove_file(&key);
        let status = pep.status();
        assert_eq!(status.catalogue_subject_properties, subject_roots.len(), "every subject row of the table was read: {}", status.last_error);
        for case in cases.iter().filter(|c| phase_of(c) == phase) {
            run += 1;
            let decision = ask(&sp, &table, case);
            let answer = answer_of(&decision);
            // A case the local engine is known to get wrong (a defect outside
            // this library) is held to its present answer here, so the tag
            // must go when the defect is fixed. The live test has no such
            // exception.
            let (want, defect) = match case.get("localDefect") {
                Some(d) => (&d["answer"], true),
                None => (&case["expect"], false),
            };
            if !is_expected(&answer, want) {
                failures.push(format!("{} [{phase}]: {answer} ({}), {} {want}", case["name"], why(&decision), if defect { "the known defect answers" } else { "the table says" }));
            }
        }
    }
    assert_eq!(run, cases.len(), "every case has a phase this runner knows");
    assert!(failures.is_empty(), "{} of {run} cases:\n{}", failures.len(), failures.join("\n"));
}

// ---------------------------------------------------------------------------
// Live: central against local, on a provisioned iya-sts.
// ---------------------------------------------------------------------------

#[test]
fn live_central_equals_local() {
    let Ok(path) = std::env::var("AUTHZEN_LIVE") else {
        eprintln!("live_central_equals_local: AUTHZEN_LIVE is not set; scripts/live_authzen.py runs it");
        return;
    };
    let settings: Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("the live settings")).expect("JSON");
    let phase = settings["phase"].as_str().expect("a phase").to_string();
    let table = table();
    let build = |mode: &str| {
        let pep = &settings["peps"][mode];
        let mut config = settings["saml"].as_object().cloned().unwrap();
        config.insert("pep".into(), json!({"name": pep["name"], "mode": mode, "assertionKey": pep["assertionKey"],
            "pollIntervalMs": 1000, "heartbeatIntervalMs": 5000, "supportedObligations": table["supportedObligations"]}));
        ServiceProvider::create(&config, "", None).unwrap_or_else(|e| panic!("the {mode} ServiceProvider: {e}"))
    };
    let central = build("central");
    let local = build("local");
    for (mode, sp) in [("central", &central), ("local", &local)] {
        let pep = sp.pep().unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        while !(pep.status().registered && (mode == "central" || pep.status().holds_policy)) {
            assert!(Instant::now() < deadline, "the {mode} PEP did not get ready: {}", pep.status().last_error);
            std::thread::sleep(Duration::from_millis(200));
        }
        eprintln!("{mode} PEP ready: policies {} token {}, catalogue subject properties {}", pep.status().policy_count, pep.status().sync_token, pep.status().catalogue_subject_properties);
    }
    let mut mismatches = Vec::new();
    let (mut run, mut equal, mut expected) = (0, 0, 0);
    for case in table["cases"].as_array().unwrap().iter().filter(|c| phase_of(c) == phase) {
        run += 1;
        let (c, l) = (ask(&central, &table, case), ask(&local, &table, case));
        let (ca, la) = (answer_of(&c), answer_of(&l));
        let same = ca == la;
        let right = is_expected(&ca, &case["expect"]) && is_expected(&la, &case["expect"]);
        equal += same as usize;
        expected += right as usize;
        eprintln!("{} {}: central {ca} local {la}", if same && right { "ok  " } else { "FAIL" }, case["name"]);
        if !(same && right) {
            mismatches.push(json!({"phase": phase, "case": case["name"], "central": ca, "centralWhy": why(&c), "local": la, "localWhy": why(&l), "expected": case["expect"]}));
        }
    }
    let report = json!({"phase": phase, "casesRun": run, "centralEqualsLocal": equal, "equalExpected": expected, "mismatches": mismatches});
    if let Some(out) = settings["out"].as_str() {
        std::fs::write(out, serde_json::to_string_pretty(&report).unwrap()).expect("the results file");
    }
    assert!(mismatches.is_empty(), "{} of {run} cases differ:\n{}", mismatches.len(), serde_json::to_string_pretty(&mismatches).unwrap());
}
