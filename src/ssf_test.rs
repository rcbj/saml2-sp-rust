// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::error::{err, SamlError};
use crate::events::{caep_events, event, risc_events, subject_of};
use crate::receiver::{Logger, ReceiverOptions, SignalEvent, SignalsReceiver};
use crate::response::SamlLogin;
use crate::session::{MemorySessionIndex, DEFAULT_SUBJECT_ATTRIBUTE};
use crate::verify_compact_jws;

use super::support::*;

struct Quiet;
impl Logger for Quiet {
    fn info(&self, _: &str) {}
    fn warn(&self, _: &str) {}
    fn error(&self, _: &str) {}
}

struct Collecting { errors: Mutex<Vec<String>> }
impl Logger for Collecting {
    fn info(&self, _: &str) {}
    fn warn(&self, _: &str) {}
    fn error(&self, message: &str) { self.errors.lock().unwrap().push(message.to_string()); }
}

struct TxState {
    queue: HashMap<String, String>,
    acked: Vec<String>,
    errs: Map<String, Value>,
    streams: Vec<Value>,
    created: i32,
    /// Every PATCH body, and whether PATCH is refused (405).
    patches: Vec<Value>,
    refuse_patch: bool,
    /// When not 0, every poll is answered with this status (a transmitter down).
    poll_status: u16,
    hold: Option<Arc<(Mutex<bool>, std::sync::Condvar)>>,
    entered: Arc<(Mutex<bool>, std::sync::Condvar)>,
    held_once: bool,
    /// Every Add/Remove Subject call: ("add" or "remove", its body).
    subject_calls: Vec<(String, Value)>,
    /// The status Add Subject answers (0: 204).
    add_status: u16,
    /// Whether the metadata publishes add_subject_endpoint and remove_subject_endpoint.
    subject_endpoints: bool,
    /// Publishes this add_subject_endpoint instead of its own.
    add_endpoint: Option<String>,
}

pub(crate) struct Transmitter {
    server: TestServer,
    pub(crate) url: String,
    state: Arc<Mutex<TxState>>,
}

impl Transmitter {
    /// A poll stream that already exists: GET lists it, PATCH merges into it.
    pub(crate) fn add_stream(&self, stream: Value) {
        self.state.lock().unwrap().streams.push(stream);
    }

    pub(crate) fn created(&self) -> i32 {
        self.state.lock().unwrap().created
    }

    pub(crate) fn patches(&self) -> Vec<Value> {
        self.state.lock().unwrap().patches.clone()
    }

    pub(crate) fn refuse_patch(&self) {
        self.state.lock().unwrap().refuse_patch = true;
    }

    /// Every poll answers `status` from now on (0: answer normally again).
    pub(crate) fn poll_status(&self, status: u16) {
        self.state.lock().unwrap().poll_status = status;
    }

    /// The Add/Remove Subject calls so far, as ("add"|"remove", format, value).
    fn subject_calls(&self) -> Vec<(String, String, String)> {
        self.state.lock().unwrap().subject_calls.iter().map(|(kind, body)| {
            let subject = &body["subject"];
            let format = subject["format"].as_str().unwrap_or("").to_string();
            let value = if format == "email" { subject["email"].clone() } else { subject["sub"].clone() };
            (kind.clone(), format, value.as_str().unwrap_or("").to_string())
        }).collect()
    }

    pub(crate) fn put_set(&self, event_type: &str, sub_id: Value, extra: Map<String, Value>, key: Option<&rsa::RsaPrivateKey>, aud: &str, iss: &str) -> String {
        let key = key.unwrap_or(tx_key());
        let aud = if aud.is_empty() { "my-app" } else { aud };
        let iss = if iss.is_empty() { self.url.as_str() } else { iss };
        let jti = new_jti();
        let mut event = Map::new();
        event.insert("event_timestamp".into(), json!(1));
        for (k, v) in extra { event.insert(k, v); }
        let mut payload = Map::new();
        payload.insert("iss".into(), json!(iss));
        payload.insert("aud".into(), json!(aud));
        payload.insert("jti".into(), json!(jti));
        payload.insert("iat".into(), json!(1));
        payload.insert("sub_id".into(), sub_id);
        payload.insert("events".into(), json!({ event_type: event }));
        let token = sign_jws(&Value::Object(payload), key, None);
        let mut state = self.state.lock().unwrap();
        state.queue.insert(jti.clone(), token);
        jti
    }
}

fn new_jti() -> String { crate::artifact::new_id().trim_start_matches('_').to_string() }

pub(crate) fn start_transmitter(hold: bool) -> Transmitter {
    let state = Arc::new(Mutex::new(TxState {
        queue: HashMap::new(), acked: Vec::new(), errs: Map::new(), streams: Vec::new(), created: 0,
        patches: Vec::new(), refuse_patch: false, poll_status: 0,
        hold: if hold { Some(Arc::new((Mutex::new(true), std::sync::Condvar::new()))) } else { None },
        entered: Arc::new((Mutex::new(false), std::sync::Condvar::new())),
        held_once: false,
        subject_calls: Vec::new(), add_status: 0, subject_endpoints: true, add_endpoint: None,
    }));
    let shared = state.clone();
    let url_slot: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));
    let url_for_handler = url_slot.clone();
    let jwk = Value::Object(jwk_of(tx_key(), "k1"));
    let server = serve(Arc::new(move |req| {
        let url = url_for_handler.lock().unwrap().clone();
        let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        let write = |status: u16, value: Value| (status, "application/json", serde_json::to_vec(&value).unwrap_or_default());
        if req.path == "/.well-known/ssf-configuration" {
            let mut config = json!({
                "issuer": url, "jwks_uri": format!("{url}/jwks"),
                "configuration_endpoint": format!("{url}/ssf/stream"),
                "verification_endpoint": format!("{url}/ssf/verify"),
                "delivery_methods_supported": ["urn:ietf:rfc:8936"]
            });
            let (published, add_endpoint) = { let g = shared.lock().unwrap(); (g.subject_endpoints, g.add_endpoint.clone()) };
            if published {
                config["add_subject_endpoint"] = json!(add_endpoint.unwrap_or_else(|| format!("{url}/ssf/subjects:add")));
                config["remove_subject_endpoint"] = json!(format!("{url}/ssf/subjects:remove"));
            }
            return write(200, config);
        }
        if req.method == "POST" && (req.path == "/ssf/subjects:add" || req.path == "/ssf/subjects:remove") {
            let add = req.path.ends_with(":add");
            let mut guard = shared.lock().unwrap();
            guard.subject_calls.push((if add { "add" } else { "remove" }.to_string(), body.clone()));
            let status = if add && guard.add_status != 0 { guard.add_status } else { 204 };
            return (status, "application/json", if status == 204 { Vec::new() } else { br#"{"err":"refused"}"#.to_vec() });
        }
        if req.path == "/jwks" { return write(200, json!({"keys": [jwk.clone()]})); }
        if req.path == "/ssf/stream" && req.method == "GET" {
            let streams = shared.lock().unwrap().streams.clone();
            return write(200, Value::Array(streams));
        }
        if req.path == "/ssf/stream" && req.method == "PATCH" {
            let mut guard = shared.lock().unwrap();
            guard.patches.push(body.clone());
            if guard.refuse_patch {
                return write(405, json!({"err": "method_not_allowed"}));
            }
            let Some(stream) = guard.streams.iter_mut().find(|s| s["stream_id"] == body["stream_id"]) else {
                return write(404, json!({"err": "not found"}));
            };
            if let Some(events) = body.get("events_requested") {
                stream["events_requested"] = events.clone();
                stream["events_delivered"] = events.clone();
            }
            // An answer without delivery: the receiver keeps the one it listed.
            let mut answer = stream.clone();
            answer.as_object_mut().unwrap().remove("delivery");
            return write(200, answer);
        }
        if req.path == "/ssf/stream" && req.method == "POST" {
            let mut guard = shared.lock().unwrap();
            guard.created += 1;
            let n = guard.created;
            let method = body.get("delivery").and_then(|d| d.get("method")).cloned().unwrap_or(Value::Null);
            let stream = json!({
                "stream_id": format!("s{n}"), "iss": url, "aud": "my-app",
                "delivery": {"method": method, "endpoint_url": format!("{url}/ssf/poll/s{n}")},
                "events_requested": body.get("events_requested").cloned().unwrap_or(Value::Null),
                "events_delivered": body.get("events_requested").cloned().unwrap_or(Value::Null)
            });
            guard.streams.push(stream.clone());
            return write(201, stream);
        }
        if req.path.starts_with("/ssf/poll/") {
            let failing = shared.lock().unwrap().poll_status;
            if failing != 0 {
                return write(failing, json!({"err": "down"}));
            }
            let hold = shared.lock().unwrap().hold.clone();
            let entered = shared.lock().unwrap().entered.clone();
            let first = {
                let mut guard = shared.lock().unwrap();
                let first = !guard.held_once;
                guard.held_once = true;
                first
            };
            if hold.is_some() && first {
                let (lock, cv) = &*entered;
                *lock.lock().unwrap() = true;
                cv.notify_all();
                let (lock, cv) = &**hold.as_ref().unwrap();
                let mut held = lock.lock().unwrap();
                while *held { held = cv.wait(held).unwrap(); }
            }
            let mut guard = shared.lock().unwrap();
            if let Some(ack) = body.get("ack").and_then(|v| v.as_array()) {
                for item in ack {
                    let jti = item.as_str().unwrap_or("").to_string();
                    guard.acked.push(jti.clone());
                    guard.queue.remove(&jti);
                }
            }
            if let Some(errs) = body.get("setErrs").and_then(|v| v.as_object()) {
                for (jti, value) in errs {
                    guard.errs.insert(jti.clone(), value.clone());
                    guard.queue.remove(jti);
                }
            }
            let sets: Map<String, Value> = guard.queue.iter().map(|(k, v)| (k.clone(), json!(v))).collect();
            return write(200, json!({"sets": sets, "moreAvailable": false}));
        }
        write(404, json!({"err": "not found"}))
    }));
    *url_slot.lock().unwrap() = server.url.clone();
    Transmitter { url: server.url.clone(), server, state }
}

fn release(tx: &Transmitter) {
    if let Some(hold) = &tx.state.lock().unwrap().hold {
        let (lock, cv) = &**hold;
        *lock.lock().unwrap() = false;
        cv.notify_all();
    }
}

fn wait_entered(tx: &Transmitter) {
    let entered = tx.state.lock().unwrap().entered.clone();
    let (lock, cv) = &*entered;
    let mut ready = lock.lock().unwrap();
    let start = std::time::Instant::now();
    while !*ready {
        let (next, timeout) = cv.wait_timeout(ready, Duration::from_secs(5)).unwrap();
        ready = next;
        if timeout.timed_out() && !*ready { panic!("poll did not start"); }
        if start.elapsed() > Duration::from_secs(5) && !*ready { panic!("poll did not start"); }
    }
}

fn login_of(person: &str, session: &str) -> SamlLogin {
    let mut attributes = HashMap::new();
    attributes.insert(DEFAULT_SUBJECT_ATTRIBUTE.to_string(), vec![format!("urn:uuid:{person}")]);
    attributes.insert("urn:oid:0.9.2342.19200300.100.1.3".to_string(), vec![format!("{person}@example.com")]);
    SamlLogin {
        name_id: person.to_string(), name_id_format: String::new(), name_qualifier: String::new(), sp_name_qualifier: String::new(),
        session_index: session.to_string(), session_not_on_or_after_ms: None, authn_instant_ms: 0, authn_context_class_ref: String::new(),
        attributes, attribute_friendly_names: HashMap::new(), issuer: String::new(), in_response_to: None, relay_state: None,
        binding: String::new(), encrypted: false, response_id: String::new(), assertion_id: String::new(),
    }
}

fn receiver(url: &str, on_end: Arc<dyn Fn(&[String], &SignalEvent) -> Result<(), SamlError> + Send + Sync>, log: Option<Arc<dyn Logger>>, index: Option<Arc<MemorySessionIndex>>) -> SignalsReceiver {
    SignalsReceiver::new(ReceiverOptions {
        transmitter: url.to_string(),
        on_end_sessions: Some(on_end),
        poll_interval_ms: 60_000,
        log: Some(log.unwrap_or_else(|| Arc::new(Quiet))),
        session_index: index,
        ..ReceiverOptions::default()
    }).unwrap()
}

#[test]
fn verifies_a_set_against_the_jwks() {
    let jwk = jwk_of(tx_key(), "k1");
    let token = sign_jws(&json!({"a": 1}), tx_key(), None);
    let (_, payload) = verify_compact_jws(&token, &[jwk.clone()]).unwrap();
    assert_eq!(payload.get("a").and_then(|v| v.as_f64()), Some(1.0));
    rejects(verify_compact_jws(&sign_jws(&json!({"a": 1}), other_key(), None), &[jwk.clone()]).map(|_| ()), "signature", "does not verify");
    let mut header = Map::new();
    header.insert("alg".into(), json!("RS256"));
    header.insert("kid".into(), json!("nope"));
    rejects(verify_compact_jws(&sign_jws(&json!({"a": 1}), tx_key(), Some(header)), &[jwk.clone()]).map(|_| ()), "signature", "no RSA signing key with kid nope");
    let mut none = Map::new();
    none.insert("alg".into(), json!("none"));
    rejects(verify_compact_jws(&sign_jws(&json!({"a": 1}), tx_key(), Some(none)), &[jwk.clone()]).map(|_| ()), "signature", "does not verify");
    let mut hs = Map::new();
    hs.insert("alg".into(), json!("HS256"));
    hs.insert("kid".into(), json!("k1"));
    rejects(verify_compact_jws(&sign_jws(&json!({"a": 1}), tx_key(), Some(hs)), &[jwk]).map(|_| ()), "signature", "does not verify");
}

#[test]
fn reads_complex_iss_sub_and_email_subjects() {
    let got = subject_of(&json!({"format": "complex", "user": {"format": "iss_sub", "iss": "https://i", "sub": "urn:uuid:a"}, "session": {"format": "opaque", "id": "S1"}}), "https://i");
    assert_eq!(got.get("person").map(String::as_str), Some("urn:uuid:a"));
    assert_eq!(got.get("idp_session").map(String::as_str), Some("S1"));
    assert!(subject_of(&json!({"format": "iss_sub", "iss": "https://other", "sub": "urn:uuid:a"}), "https://i").is_empty());
    let email = subject_of(&json!({"format": "email", "email": "A@x.com"}), "https://i");
    assert_eq!(email.get("email").map(String::as_str), Some("A@x.com"));
}

#[test]
fn names_all_eight_caep_and_fourteen_risc_event_types() {
    assert_eq!(caep_events().len(), 8);
    assert_eq!(risc_events().len(), 14);
    assert!(caep_events().contains(&event("risk_level_change").to_string()));
    assert!(risc_events().contains(&event("opt_out_effective").to_string()));
}

#[test]
fn shared_signals() {
    let stub = start_transmitter(false);
    let ended = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
    let seen = Arc::new(Mutex::new(Vec::<SignalEvent>::new()));
    let ended_cb = ended.clone();
    let rx = receiver(&stub.url, Arc::new(move |ids, _| { ended_cb.lock().unwrap().push(ids.to_vec()); Ok(()) }), None, None);
    let seen_cb = seen.clone();
    rx.on("*", move |event| { seen_cb.lock().unwrap().push(event.clone()); Ok(()) });
    rx.start().unwrap();
    rx.stop();
    assert_eq!(stub.state.lock().unwrap().created, 1);
    assert_eq!(rx.stream().get("stream_id").and_then(|v| v.as_str()), Some("s1"));
    rx.track("L-a1", &login_of("alice", "IDP-A1"), None);
    rx.track("L-a2", &login_of("alice", "IDP-A2"), None);
    rx.track("L-b1", &login_of("bob", "IDP-B1"), None);
    let j1 = stub.put_set(event("session_revoked"), json!({"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:alice"}, "session": {"format": "opaque", "id": "IDP-A1"}}), Map::new(), None, "", "");
    let mut extra = Map::new();
    extra.insert("credential_type".into(), json!("password"));
    extra.insert("change_type".into(), json!("update"));
    let j2 = stub.put_set(event("credential_change"), json!({"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:bob"}}), extra, None, "", "");
    rx.poll_once().unwrap();
    assert_eq!(ended.lock().unwrap().first().map(|v| v.join(",")).as_deref(), Some("L-a1"));
    let found = seen.lock().unwrap().iter().find(|event| event.jti == j2).cloned();
    let found = found.expect("credential change");
    assert!(!found.ended);
    assert_eq!(found.sessions.join(","), "L-b1");
    let j3 = stub.put_set(event("account_disabled"), json!({"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:alice"}), Map::new(), None, "", "");
    rx.poll_once().unwrap();
    assert_eq!(ended.lock().unwrap().get(1).map(|v| v.join(",")).as_deref(), Some("L-a2"));
    rx.poll_once().unwrap();
    let acked = stub.state.lock().unwrap().acked.clone();
    assert!(acked.contains(&j1) && acked.contains(&j2), "{acked:?}");
    let mut extra = Map::new();
    extra.insert("credential_type".into(), json!("password"));
    stub.put_set(event("credential_compromise"), json!({"format": "email", "email": "BOB@example.com"}), extra, None, "", "");
    rx.poll_once().unwrap();
    assert_eq!(ended.lock().unwrap().get(2).map(|v| v.join(",")).as_deref(), Some("L-b1"));
    rx.poll_once().unwrap();
    assert!(stub.state.lock().unwrap().acked.contains(&j3));
    let again = receiver(&stub.url, Arc::new(|_, _| Ok(())), None, None);
    again.start().unwrap();
    again.stop();
    assert_eq!(stub.state.lock().unwrap().created, 1);
    assert_eq!(again.stream().get("stream_id").and_then(|v| v.as_str()), Some("s1"));

    let ended = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
    let index = Arc::new(MemorySessionIndex::new(0));
    let ended_cb = ended.clone();
    let rx = receiver(&stub.url, Arc::new(move |ids, _| { ended_cb.lock().unwrap().push(ids.to_vec()); Ok(()) }), None, Some(index.clone()));
    rx.start().unwrap();
    rx.stop();
    rx.track("L-c1", &login_of("carol", "IDP-C1"), None);
    let subject = json!({"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:carol"}, "session": {"format": "opaque", "id": "IDP-C1"}});
    let forged = stub.put_set(event("session_revoked"), subject.clone(), Map::new(), Some(other_key()), "", "");
    let mis = stub.put_set(event("session_revoked"), subject.clone(), Map::new(), None, "someone-else", "");
    let foreign = stub.put_set(event("session_revoked"), subject, Map::new(), None, "", "https://evil.example");
    rx.poll_once().unwrap();
    assert!(ended.lock().unwrap().is_empty());
    assert_eq!(index.by_person("urn:uuid:carol").join(","), "L-c1");
    rx.poll_once().unwrap();
    let errs = stub.state.lock().unwrap().errs.clone();
    for jti in [forged, mis, foreign] {
        assert!(errs.contains_key(&jti), "missing err {jti} in {errs:?}");
    }

    let errors = Arc::new(Collecting { errors: Mutex::new(Vec::new()) });
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let rx = receiver(&stub.url, Arc::new(|_, _| Err(err("ssf", "store down"))), Some(errors.clone()), None);
    rx.on(event("credential_change"), |_| Err(err("ssf", "handler bug")));
    let seen_cb = seen.clone();
    rx.on("*", move |event| { seen_cb.lock().unwrap().push(event.jti.clone()); Ok(()) });
    rx.start().unwrap();
    rx.stop();
    rx.track("L-d1", &login_of("dave", "IDP-D1"), None);
    let mut extra = Map::new();
    extra.insert("credential_type".into(), json!("password"));
    extra.insert("change_type".into(), json!("update"));
    let j1 = stub.put_set(event("credential_change"), json!({"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:dave"}}), extra, None, "", "");
    let j2 = stub.put_set(event("session_revoked"), json!({"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:dave"}, "session": {"format": "opaque", "id": "IDP-D1"}}), Map::new(), None, "", "");
    for _ in 0..3 { rx.poll_once().unwrap(); }
    let acked = stub.state.lock().unwrap().acked.clone();
    assert!(acked.contains(&j1) && acked.contains(&j2), "{acked:?}");
    assert!(!stub.state.lock().unwrap().errs.contains_key(&j1));
    assert!(!stub.state.lock().unwrap().errs.contains_key(&j2));
    let mut seen = seen.lock().unwrap().clone();
    seen.sort();
    let mut want = vec![j1, j2];
    want.sort();
    assert_eq!(seen, want);
    let logs = errors.errors.lock().unwrap().clone();
    assert!(logs.iter().any(|m| regex::Regex::new(r"handler for .*credential-change threw").unwrap().is_match(m)), "{logs:?}");
    assert!(logs.iter().any(|m| m.contains("onEndSessions threw")), "{logs:?}");

    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let rx = receiver(&stub.url, Arc::new(|_, _| Ok(())), None, None);
    let seen_cb = seen.clone();
    rx.on("*", move |event| { seen_cb.lock().unwrap().push(event.jti.clone()); Ok(()) });
    rx.start().unwrap();
    rx.stop();
    let jti = stub.put_set(event("account_enabled"), json!({"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:erin"}), Map::new(), None, "", "");
    let mut handles = Vec::new();
    for _ in 0..3 {
        let rx = rx.clone();
        handles.push(thread::spawn(move || { let _ = rx.poll_once(); }));
    }
    for handle in handles { handle.join().unwrap(); }
    rx.poll_once().unwrap();
    let count = seen.lock().unwrap().iter().filter(|item| *item == &jti).count();
    assert_eq!(count, 1, "{:?}", seen.lock().unwrap());
    drop(stub.server);
}

#[test]
fn refuses_a_transmitter_without_poll_delivery() {
    let rx = receiver("http://127.0.0.1:1", Arc::new(|_, _| Ok(())), None, None);
    let err = rx.start().unwrap_err();
    assert_eq!(err.code, "ssf", "{err}");
}

#[test]
fn stop_waits_for_an_in_flight_poll() {
    let stub = start_transmitter(true);
    let rx = receiver(&stub.url, Arc::new(|_, _| Ok(())), None, None);
    let started = thread::spawn({
        let rx = rx.clone();
        move || rx.start()
    });
    wait_entered(&stub);
    let stopped = thread::spawn({
        let rx = rx.clone();
        move || rx.stop()
    });
    thread::sleep(Duration::from_millis(150));
    assert!(!stopped.is_finished(), "stop returned before the poll finished");
    release(&stub);
    stopped.join().unwrap();
    started.join().unwrap().unwrap();
}

struct Warnings { lines: Mutex<Vec<String>> }
impl Logger for Warnings {
    fn info(&self, _: &str) {}
    fn warn(&self, message: &str) { self.lines.lock().unwrap().push(format!("warn {message}")); }
    fn error(&self, message: &str) { self.lines.lock().unwrap().push(format!("error {message}")); }
}

fn subject_receiver(stub: &Transmitter, add_subjects: bool, log: Arc<Warnings>) -> SignalsReceiver {
    let rx = SignalsReceiver::new(ReceiverOptions {
        transmitter: stub.url.clone(),
        on_end_sessions: Some(Arc::new(|_, _| Ok(()))),
        poll_interval_ms: 60_000,
        log: Some(log),
        add_subjects,
        ..ReceiverOptions::default()
    }).unwrap();
    rx.start().unwrap();
    rx.stop();
    rx
}

fn add(format: &str, value: &str) -> (String, String, String) { ("add".into(), format.into(), value.into()) }
fn remove(format: &str, value: &str) -> (String, String, String) { ("remove".into(), format.into(), value.into()) }

#[test]
fn sign_in_adds_the_subject_and_the_last_sign_out_removes_it() {
    let stub = start_transmitter(false);
    let log = Arc::new(Warnings { lines: Mutex::new(Vec::new()) });
    let rx = subject_receiver(&stub, true, log.clone());
    // Before any poll nothing is sent: sign-in never waits for the transmitter.
    rx.track("L-a1", &login_of("alice", "IDP-A1"), None);
    assert!(stub.subject_calls().is_empty());
    rx.poll_once().unwrap();
    assert_eq!(stub.subject_calls(), vec![add("iss_sub", "urn:uuid:alice"), add("email", "alice@example.com")]);
    let body = stub.state.lock().unwrap().subject_calls[0].1.clone();
    assert_eq!((body["stream_id"].clone(), body["subject"]["iss"].clone(), body["verified"].clone()), (json!("s1"), json!(stub.url), json!(true)), "{body}");
    // A second session for alice adds again; ending one of the two removes nothing.
    rx.track("L-a2", &login_of("alice", "IDP-A2"), None);
    rx.untrack("L-a1");
    rx.poll_once().unwrap();
    assert_eq!(stub.subject_calls().len(), 4, "{:?}", stub.subject_calls());
    assert!(stub.subject_calls().iter().all(|(kind, _, _)| kind == "add"), "alice still has L-a2: {:?}", stub.subject_calls());
    // The last one goes: both identifiers are removed.
    rx.untrack("L-a2");
    rx.untrack("L-a2"); // again: not tracked, nothing more
    rx.poll_once().unwrap();
    assert_eq!(stub.subject_calls()[4..].to_vec(), vec![remove("iss_sub", "urn:uuid:alice"), remove("email", "alice@example.com")]);
    assert!(stub.state.lock().unwrap().subject_calls[4].1.get("verified").is_none());
    assert!(log.lines.lock().unwrap().is_empty(), "{:?}", log.lines.lock().unwrap());
    assert_eq!(rx.subject_error(), None);
}

#[test]
fn a_session_ended_by_an_event_removes_the_subject_when_it_was_the_last() {
    let stub = start_transmitter(false);
    let rx = subject_receiver(&stub, true, Arc::new(Warnings { lines: Mutex::new(Vec::new()) }));
    rx.track("L-b1", &login_of("bob", "IDP-B1"), None);
    rx.track("L-b2", &login_of("bob", "IDP-B2"), None);
    rx.poll_once().unwrap();
    let revoke = |session: &str| json!({"format": "complex", "user": {"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:bob"}, "session": {"format": "opaque", "id": session}});
    stub.put_set(event("session_revoked"), revoke("IDP-B1"), Map::new(), None, "", "");
    rx.poll_once().unwrap();
    rx.poll_once().unwrap();
    assert!(!stub.subject_calls().iter().any(|(kind, _, _)| kind == "remove"), "bob still has L-b2: {:?}", stub.subject_calls());
    stub.put_set(event("account_disabled"), json!({"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:bob"}), Map::new(), None, "", "");
    rx.poll_once().unwrap();
    rx.poll_once().unwrap();
    let removes: Vec<_> = stub.subject_calls().into_iter().filter(|(kind, _, _)| kind == "remove").collect();
    assert_eq!(removes, vec![remove("iss_sub", "urn:uuid:bob"), remove("email", "bob@example.com")]);
}

#[test]
fn a_refused_add_is_reported_once_and_never_fatal() {
    let stub = start_transmitter(false);
    stub.state.lock().unwrap().add_status = 403;
    let log = Arc::new(Warnings { lines: Mutex::new(Vec::new()) });
    let rx = subject_receiver(&stub, true, log.clone());
    rx.track("L-c1", &login_of("carol", "IDP-C1"), None);
    stub.put_set(event("credential_change"), json!({"format": "iss_sub", "iss": stub.url, "sub": "urn:uuid:carol"}), Map::new(), None, "", "");
    assert!(!rx.poll_once().unwrap(), "the poll itself still succeeds");
    assert_eq!(stub.subject_calls().len(), 2);
    let lines = log.lines.lock().unwrap().clone();
    assert!(lines.iter().filter(|l| l.starts_with("warn ") && l.contains("(403")).count() == 2, "a 403 is a warning: {lines:?}");
    assert!(rx.subject_error().is_some_and(|e| e.contains("403")));
    assert_eq!(rx.session_index().by_person("urn:uuid:carol").len(), 1, "the session stands");
    // Not retried: the next polls send nothing more.
    rx.poll_once().unwrap();
    rx.poll_once().unwrap();
    assert_eq!(stub.subject_calls().len(), 2);
    assert!(stub.state.lock().unwrap().acked.len() == 1, "the event was still delivered and acknowledged");
    // Any other status, or no answer at all, is an error line, still not fatal.
    stub.state.lock().unwrap().add_status = 500;
    rx.track("L-c2", &login_of("carl", "IDP-C2"), None);
    rx.poll_once().unwrap();
    assert!(log.lines.lock().unwrap().iter().any(|l| l.starts_with("error ") && l.contains("answered 500")), "{:?}", log.lines.lock().unwrap());
    // An add endpoint nothing answers at: an error line, and the poll still runs.
    stub.state.lock().unwrap().add_endpoint = Some("http://127.0.0.1:1/subjects:add".into());
    let down = Arc::new(Warnings { lines: Mutex::new(Vec::new()) });
    let rx = subject_receiver(&stub, true, down.clone());
    rx.track("L-c3", &login_of("cara", "IDP-C3"), None);
    rx.poll_once().unwrap();
    assert!(down.lines.lock().unwrap().iter().any(|l| l.starts_with("error ") && l.contains("failed")), "{:?}", down.lines.lock().unwrap());
}

#[test]
fn nothing_is_sent_without_the_endpoints_or_with_the_switch_off() {
    let stub = start_transmitter(false);
    stub.state.lock().unwrap().subject_endpoints = false;
    let log = Arc::new(Warnings { lines: Mutex::new(Vec::new()) });
    let rx = subject_receiver(&stub, true, log.clone());
    rx.track("L-d1", &login_of("dave", "IDP-D1"), None);
    rx.poll_once().unwrap();
    rx.untrack("L-d1");
    rx.poll_once().unwrap();
    assert!(stub.subject_calls().is_empty());
    assert!(log.lines.lock().unwrap().is_empty(), "no endpoint is not a problem: {:?}", log.lines.lock().unwrap());

    let stub = start_transmitter(false);
    let rx = subject_receiver(&stub, false, Arc::new(Warnings { lines: Mutex::new(Vec::new()) }));
    rx.track("L-e1", &login_of("erin", "IDP-E1"), None);
    rx.poll_once().unwrap();
    rx.untrack("L-e1");
    rx.poll_once().unwrap();
    assert!(stub.subject_calls().is_empty(), "addSubjects false: {:?}", stub.subject_calls());
    assert!(ReceiverOptions::default().add_subjects, "on by default");
}
