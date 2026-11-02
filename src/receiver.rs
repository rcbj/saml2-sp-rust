// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use crate::error::{err, SamlError};
use crate::events::{default_ending_events, default_events_requested, event, string_of, subject_of};
use crate::http::{send, TlsOptions};
use crate::jws::verify_compact_jws;
use crate::response::SamlLogin;
use crate::session::{tracked_from, MemorySessionIndex};

const POLL_METHOD: &str = "urn:ietf:rfc:8936";

/// Operational messages from the receiver.
pub trait Logger: Send + Sync {
    fn info(&self, message: &str);
    fn warn(&self, message: &str);
    fn error(&self, message: &str);
}

struct PrintLogger;
impl Logger for PrintLogger {
    fn info(&self, message: &str) { println!("{message}"); }
    fn warn(&self, message: &str) { println!("{message}"); }
    fn error(&self, message: &str) { println!("{message}"); }
}

/// One event inside a Security Event Token.
#[derive(Clone, Debug)]
pub struct SignalEvent {
    pub event_type: String,
    pub payload: Map<String, Value>,
    pub subject: HashMap<String, String>,
    pub jti: String,
    pub sessions: Vec<String>,
    pub ended: bool,
    pub iat: Option<f64>,
    pub txn: Option<String>,
}

type Handler = Arc<dyn Fn(&SignalEvent) -> Result<(), SamlError> + Send + Sync>;
type EndFn = Arc<dyn Fn(&[String], &SignalEvent) -> Result<(), SamlError> + Send + Sync>;

/// Configures a Shared Signals poll receiver.
pub struct ReceiverOptions {
    pub transmitter: String,
    pub on_end_sessions: Option<EndFn>,
    pub tls: Option<TlsOptions>,
    pub headers: Option<Arc<dyn Fn() -> Vec<(String, String)> + Send + Sync>>,
    pub events_requested: Option<Vec<String>>,
    pub end_on: Option<Vec<String>>,
    pub session_index: Option<Arc<MemorySessionIndex>>,
    pub subject_attribute: String,
    pub description: String,
    pub poll_interval_ms: u64,
    pub max_events: u64,
    pub log: Option<Arc<dyn Logger>>,
}

impl Default for ReceiverOptions {
    fn default() -> Self {
        Self {
            transmitter: String::new(),
            on_end_sessions: None,
            tls: None,
            headers: None,
            events_requested: None,
            end_on: None,
            session_index: None,
            subject_attribute: String::new(),
            description: String::new(),
            poll_interval_ms: 0,
            max_events: 0,
            log: None,
        }
    }
}

struct Flight {
    result: Mutex<Option<Result<bool, SamlError>>>,
    cv: Condvar,
}

struct Gate {
    count: Mutex<i32>,
    cv: Condvar,
}

impl Gate {
    fn new() -> Self { Self { count: Mutex::new(0), cv: Condvar::new() } }
    fn add(&self) { *self.count.lock().expect("gate") += 1; }
    fn done(&self) {
        let mut count = self.count.lock().expect("gate");
        *count -= 1;
        if *count == 0 { self.cv.notify_all(); }
    }
    fn wait(&self) {
        let mut count = self.count.lock().expect("gate");
        while *count > 0 {
            count = self.cv.wait(count).expect("gate");
        }
    }
}

struct State {
    config: Map<String, Value>,
    stream: Map<String, Value>,
    keys: Vec<Map<String, Value>>,
    keys_at: Option<Instant>,
    ack: Vec<String>,
    errs: Map<String, Value>,
    handlers: HashMap<String, Vec<Handler>>,
}

struct Sched {
    running: bool,
    generation: u64,
    inflight: Option<Arc<Flight>>,
}

struct Inner {
    transmitter: String,
    on_end: EndFn,
    tls: Option<TlsOptions>,
    headers: Option<Arc<dyn Fn() -> Vec<(String, String)> + Send + Sync>>,
    events_requested: Vec<String>,
    end_on: HashMap<String, bool>,
    index: Arc<MemorySessionIndex>,
    subject_attribute: String,
    description: String,
    poll_interval: Duration,
    max_events: u64,
    log: Arc<dyn Logger>,
    state: Mutex<State>,
    sched: Mutex<Sched>,
    gate: Gate,
}

/// Polls one RFC 8936 stream of CAEP and RISC events.
#[derive(Clone)]
pub struct SignalsReceiver {
    inner: Arc<Inner>,
}

impl SignalsReceiver {
    /// Builds a receiver. It does not contact the transmitter until `start`.
    pub fn new(opt: ReceiverOptions) -> Result<Self, SamlError> {
        let on_end = opt.on_end_sessions.ok_or_else(|| err("config", "onEndSessions is required"))?;
        if !(opt.transmitter.starts_with("http://") || opt.transmitter.starts_with("https://")) {
            return Err(err("config", "transmitter must be an http(s) URL"));
        }
        let interval = if opt.poll_interval_ms == 0 { 5000 } else { opt.poll_interval_ms };
        let max_events = if opt.max_events == 0 { 50 } else { opt.max_events };
        let requested = opt.events_requested.unwrap_or_else(default_events_requested);
        let ending = opt.end_on.unwrap_or_else(default_ending_events);
        let mut end_on = HashMap::new();
        for item in ending {
            end_on.insert(item, true);
        }
        let index = opt.session_index.unwrap_or_else(|| Arc::new(MemorySessionIndex::new(0)));
        let log = opt.log.unwrap_or_else(|| Arc::new(PrintLogger));
        Ok(Self {
            inner: Arc::new(Inner {
                transmitter: opt.transmitter.trim_end_matches('/').to_string(),
                on_end,
                tls: opt.tls,
                headers: opt.headers,
                events_requested: requested,
                end_on,
                index,
                subject_attribute: opt.subject_attribute,
                description: opt.description,
                poll_interval: Duration::from_millis(interval),
                max_events,
                log,
                state: Mutex::new(State {
                    config: Map::new(),
                    stream: Map::new(),
                    keys: Vec::new(),
                    keys_at: None,
                    ack: Vec::new(),
                    errs: Map::new(),
                    handlers: HashMap::new(),
                }),
                sched: Mutex::new(Sched { running: false, generation: 0, inflight: None }),
                gate: Gate::new(),
            }),
        })
    }

    pub fn track(&self, local_id: &str, login: &SamlLogin, expires_at_ms: Option<i64>) {
        self.inner.index.add(tracked_from(local_id, login, &self.inner.subject_attribute, expires_at_ms));
    }

    pub fn untrack(&self, local_id: &str) {
        self.inner.index.remove(local_id);
    }

    pub fn on<F>(&self, event_type: &str, handler: F) -> &Self
    where
        F: Fn(&SignalEvent) -> Result<(), SamlError> + Send + Sync + 'static,
    {
        self.inner.state.lock().expect("state").handlers.entry(event_type.to_string()).or_default().push(Arc::new(handler));
        self
    }

    pub fn stream(&self) -> Map<String, Value> {
        self.inner.state.lock().expect("state").stream.clone()
    }

    /// Discovers the transmitter, ensures one poll stream, and polls once before returning.
    pub fn start(&self) -> Result<(), SamlError> {
        {
            let sched = self.inner.sched.lock().expect("sched");
            if sched.running {
                return Ok(());
            }
        }
        let config = self.discover()?;
        self.inner.state.lock().expect("state").config = config;
        self.jwks(true)?;
        let stream = self.ensure_stream()?;
        let endpoint = stream.get("delivery").and_then(|d| d.get("endpoint_url")).and_then(|v| v.as_str()).unwrap_or("");
        if endpoint.is_empty() {
            return Err(err("ssf", "the stream has no poll endpoint_url"));
        }
        {
            let mut sched = self.inner.sched.lock().expect("sched");
            if sched.running {
                return Ok(());
            }
            self.inner.state.lock().expect("state").stream = stream.clone();
            sched.running = true;
        }
        let delivered = stream.get("events_delivered").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
        let stream_id = string_of(stream.get("stream_id").unwrap_or(&Value::Null));
        self.inner.log.info(&format!("ssf: polling stream {stream_id} at {endpoint}, delivering {delivered} event type(s)"));
        self.iteration();
        Ok(())
    }

    /// Cancels the next poll and waits until a poll already running has finished.
    pub fn stop(&self) {
        {
            let mut sched = self.inner.sched.lock().expect("sched");
            sched.running = false;
            sched.generation += 1;
        }
        self.inner.gate.wait();
    }

    fn iteration(&self) {
        {
            let sched = self.inner.sched.lock().expect("sched");
            if !sched.running {
                return;
            }
            self.inner.gate.add();
        }
        let mut delay = self.inner.poll_interval;
        match self.poll_once() {
            Err(error) => {
                self.inner.log.warn(&format!("ssf: poll failed: {error}"));
                delay = (self.inner.poll_interval * 4).min(Duration::from_secs(60));
            }
            Ok(true) => delay = Duration::ZERO,
            Ok(false) => {}
        }
        let generation = {
            let mut sched = self.inner.sched.lock().expect("sched");
            if !sched.running {
                self.inner.gate.done();
                return;
            }
            sched.generation += 1;
            sched.generation
        };
        let again = self.clone();
        thread::spawn(move || {
            if !delay.is_zero() {
                thread::sleep(delay);
            }
            let go = {
                let sched = again.inner.sched.lock().expect("sched");
                sched.running && sched.generation == generation
            };
            if go {
                again.iteration();
            }
        });
        self.inner.gate.done();
    }

    /// Fetches one batch. Concurrent callers share that single request.
    pub fn poll_once(&self) -> Result<bool, SamlError> {
        let existing = {
            let mut sched = self.inner.sched.lock().expect("sched");
            if let Some(current) = &sched.inflight {
                Some(current.clone())
            } else {
                let flight = Arc::new(Flight { result: Mutex::new(None), cv: Condvar::new() });
                sched.inflight = Some(flight.clone());
                None
            }
        };
        if let Some(current) = existing {
            let mut slot = current.result.lock().expect("flight");
            while slot.is_none() {
                slot = current.cv.wait(slot).expect("flight");
            }
            return slot.clone().unwrap();
        }
        let result = self.poll_now();
        let flight = self.inner.sched.lock().expect("sched").inflight.clone();
        if let Some(flight) = flight {
            let mut slot = flight.result.lock().expect("flight");
            *slot = Some(result.clone());
            flight.cv.notify_all();
        }
        self.inner.sched.lock().expect("sched").inflight = None;
        result
    }

    fn poll_now(&self) -> Result<bool, SamlError> {
        let (url, ack, set_errs) = {
            let mut state = self.inner.state.lock().expect("state");
            let url = state.stream.get("delivery").and_then(|d| d.get("endpoint_url")).and_then(|v| v.as_str()).unwrap_or("").to_string();
            let ack = std::mem::take(&mut state.ack);
            let set_errs = std::mem::take(&mut state.errs);
            (url, ack, set_errs)
        };
        let mut body = Map::new();
        body.insert("maxEvents".to_string(), json!(self.inner.max_events));
        body.insert("returnImmediately".to_string(), Value::Bool(true));
        if !ack.is_empty() {
            body.insert("ack".to_string(), Value::Array(ack.iter().cloned().map(Value::String).collect()));
        }
        if !set_errs.is_empty() {
            body.insert("setErrs".to_string(), Value::Object(set_errs.clone()));
        }
        let sent = self.call("POST", &url, Some(&Value::Object(body)));
        let (status, parsed) = match sent {
            Ok(value) => value,
            Err(error) => {
                self.restore(ack, set_errs);
                return Err(error);
            }
        };
        if status != 200 {
            self.restore(ack, set_errs);
            let mut text = parsed.to_string();
            if text.len() > 300 { text.truncate(300); }
            return Err(err("ssf", format!("the poll answered {status}: {text}")));
        }
        let sets = parsed.get("sets").and_then(|v| v.as_object()).cloned().unwrap_or_default();
        for (jti, token) in sets {
            let token = string_of(&token);
            if let Err(error) = self.handle(&jti, &token) {
                let description = error.to_string();
                self.inner.log.warn(&format!("ssf: SET {jti} refused: {description}"));
                let kind = if error.code == "signature" { "invalid_key" } else { "invalid_request" };
                self.inner.state.lock().expect("state").errs.insert(jti, json!({"err": kind, "description": description}));
                continue;
            }
            self.inner.state.lock().expect("state").ack.push(jti);
        }
        Ok(parsed.get("moreAvailable").and_then(|v| v.as_bool()).unwrap_or(false))
    }

    fn restore(&self, ack: Vec<String>, set_errs: Map<String, Value>) {
        let mut state = self.inner.state.lock().expect("state");
        let mut merged = ack;
        merged.append(&mut state.ack);
        state.ack = merged;
        let mut errs = set_errs;
        let current = std::mem::take(&mut state.errs);
        for (k, v) in current {
            errs.insert(k, v);
        }
        state.errs = errs;
    }

    fn handle(&self, jti: &str, token: &str) -> Result<(), SamlError> {
        let keys = self.jwks(false)?;
        let verified = match verify_compact_jws(token, &keys) {
            Ok(value) => Ok(value),
            Err(error) => {
                if error.code == "signature" && (error.message.contains("publishes no") || error.message.contains("does not verify")) {
                    let keys = self.jwks(true).map_err(|_| error.clone())?;
                    verify_compact_jws(token, &keys)
                } else {
                    Err(error)
                }
            }
        };
        let (header, payload) = verified?;
        if header.get("typ").is_some() && string_of(header.get("typ").unwrap()).to_ascii_lowercase() != "secevent+jwt" {
            return Err(err("validation", format!("the SET's typ is {}", string_of(header.get("typ").unwrap()))));
        }
        let (issuer, want) = {
            let state = self.inner.state.lock().expect("state");
            (string_of(state.config.get("issuer").unwrap_or(&Value::Null)), state.stream.get("aud").cloned())
        };
        if string_of(payload.get("iss").unwrap_or(&Value::Null)) != issuer {
            return Err(err("validation", format!("the SET was issued by {}, not {issuer}", string_of(payload.get("iss").unwrap_or(&Value::Null)))));
        }
        let wanted = audience_list(want.as_ref());
        let audience = audience_list(payload.get("aud"));
        if !wanted.is_empty() && !audience.iter().any(|item| wanted.iter().any(|allowed| item == allowed)) {
            return Err(err("validation", format!("the SET is for {}, not this stream", audience.join(", "))));
        }
        if payload.get("jti").is_some() && string_of(payload.get("jti").unwrap()) != jti {
            return Err(err("validation", "the SET's jti is not the one it was delivered under"));
        }
        let events = payload.get("events").and_then(|v| v.as_object()).cloned().unwrap_or_default();
        if events.is_empty() {
            return Err(err("validation", "the SET carries no events"));
        }
        for (event_type, raw_body) in events {
            let body = raw_body.as_object().cloned().unwrap_or_default();
            let subject_source = if payload.get("sub_id").is_some() {
                payload.get("sub_id").cloned().unwrap_or(Value::Null)
            } else {
                body.get("subject").cloned().unwrap_or(Value::Null)
            };
            let subject = subject_of(&subject_source, &issuer);
            let sessions = self.sessions_for(&event_type, &subject);
            let mut ends = self.inner.end_on.get(&event_type).copied().unwrap_or(false) && !sessions.is_empty();
            let iat = payload.get("iat").and_then(|v| v.as_f64());
            let txn = payload.get("txn").and_then(|v| v.as_str()).map(str::to_string);
            let mut signal = SignalEvent {
                event_type: event_type.clone(),
                payload: body,
                subject,
                jti: jti.to_string(),
                sessions: sessions.clone(),
                ended: ends,
                iat,
                txn,
            };
            if ends {
                if let Err(error) = (self.inner.on_end)(&sessions, &signal) {
                    self.inner.log.error(&format!("ssf: onEndSessions threw for {event_type} (SET {jti} is still acknowledged): {error}"));
                    ends = false;
                    signal.ended = false;
                }
                if ends {
                    for local_id in &sessions {
                        self.inner.index.remove(local_id);
                    }
                }
            }
            let handlers = {
                let state = self.inner.state.lock().expect("state");
                let mut handlers = state.handlers.get(&event_type).cloned().unwrap_or_default();
                if let Some(star) = state.handlers.get("*") {
                    handlers.extend(star.iter().cloned());
                }
                handlers
            };
            for handler in handlers {
                if let Err(error) = handler(&signal) {
                    self.inner.log.error(&format!("ssf: a handler for {event_type} threw (SET {jti} is still acknowledged): {error}"));
                }
            }
        }
        Ok(())
    }

    fn sessions_for(&self, event_type: &str, subject: &HashMap<String, String>) -> Vec<String> {
        if event_type == event("verification") || event_type == event("stream_updated") {
            return Vec::new();
        }
        if let Some(idp_session) = subject.get("idp_session").filter(|s| !s.is_empty()) {
            let found = self.inner.index.by_idp_session(idp_session);
            if !found.is_empty() || event_type == event("session_revoked") {
                return found;
            }
        }
        if let Some(person) = subject.get("person").filter(|s| !s.is_empty()) {
            return self.inner.index.by_person(person);
        }
        if let Some(email) = subject.get("email").filter(|s| !s.is_empty()) {
            return self.inner.index.by_email(email);
        }
        Vec::new()
    }

    /// Asks the transmitter to deliver a verification event.
    pub fn verify(&self, state_value: &str) -> Result<(), SamlError> {
        let (endpoint, stream_id) = {
            let state = self.inner.state.lock().expect("state");
            (
                string_of(state.config.get("verification_endpoint").unwrap_or(&Value::Null)),
                string_of(state.stream.get("stream_id").unwrap_or(&Value::Null)),
            )
        };
        if endpoint.is_empty() {
            return Err(err("ssf", "the transmitter publishes no verification_endpoint"));
        }
        let mut body = Map::new();
        body.insert("stream_id".to_string(), Value::String(stream_id));
        if !state_value.is_empty() {
            body.insert("state".to_string(), Value::String(state_value.to_string()));
        }
        let (status, _) = self.call("POST", &endpoint, Some(&Value::Object(body)))?;
        if status != 200 && status != 204 {
            return Err(err("ssf", format!("verification answered {status}")));
        }
        Ok(())
    }

    fn call(&self, method: &str, raw_url: &str, body: Option<&Value>) -> Result<(u16, Value), SamlError> {
        let mut headers = vec![("accept".to_string(), "application/json".to_string())];
        if let Some(extra) = &self.inner.headers {
            for (key, value) in extra() {
                headers.push((key, value));
            }
        }
        let payload = if let Some(body) = body {
            headers.push(("content-type".to_string(), "application/json".to_string()));
            body.to_string()
        } else {
            String::new()
        };
        let header_refs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let answer = send(raw_url, method, &header_refs, &payload, self.inner.tls.as_ref(), "ssf")?;
        let parsed = if answer.body.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&answer.body).unwrap_or(Value::String(answer.body))
        };
        Ok((answer.status, parsed))
    }

    fn discover(&self) -> Result<Map<String, Value>, SamlError> {
        let url = format!("{}/.well-known/ssf-configuration", self.inner.transmitter);
        let (status, parsed) = self.call("GET", &url, None)?;
        let config = parsed.as_object().cloned().unwrap_or_default();
        if status != 200 || string_of(config.get("configuration_endpoint").unwrap_or(&Value::Null)).is_empty() || string_of(config.get("jwks_uri").unwrap_or(&Value::Null)).is_empty() {
            return Err(err("ssf", format!("{url} answered {status} without a usable transmitter configuration")));
        }
        if let Some(supported) = config.get("delivery_methods_supported").and_then(|v| v.as_array()) {
            if !supported.is_empty() && !supported.iter().any(|item| string_of(item) == POLL_METHOD) {
                return Err(err("ssf", "the transmitter does not offer poll delivery (RFC 8936)"));
            }
        }
        Ok(config)
    }

    fn jwks(&self, force: bool) -> Result<Vec<Map<String, Value>>, SamlError> {
        let cached = {
            let state = self.inner.state.lock().expect("state");
            if !force && !state.keys.is_empty() && state.keys_at.is_some_and(|at| at.elapsed() < Duration::from_secs(3600)) {
                Some(state.keys.clone())
            } else {
                None
            }
        };
        if let Some(keys) = cached {
            return Ok(keys);
        }
        let uri = string_of(self.inner.state.lock().expect("state").config.get("jwks_uri").unwrap_or(&Value::Null));
        let (status, parsed) = self.call("GET", &uri, None)?;
        let raw = parsed.get("keys").and_then(|v| v.as_array()).cloned();
        let Some(raw) = raw else {
            return Err(err("ssf", format!("the transmitter's JWKS answered {status}")));
        };
        if status != 200 {
            return Err(err("ssf", format!("the transmitter's JWKS answered {status}")));
        }
        let keys: Vec<Map<String, Value>> = raw.into_iter().filter_map(|item| item.as_object().cloned()).collect();
        let mut state = self.inner.state.lock().expect("state");
        state.keys = keys.clone();
        state.keys_at = Some(Instant::now());
        Ok(keys)
    }

    fn ensure_stream(&self) -> Result<Map<String, Value>, SamlError> {
        let endpoint = string_of(self.inner.state.lock().expect("state").config.get("configuration_endpoint").unwrap_or(&Value::Null));
        let (status, parsed) = self.call("GET", &endpoint, None)?;
        if status == 200 {
            let all: Vec<Value> = match &parsed {
                Value::Array(items) => items.clone(),
                Value::Object(_) => vec![parsed.clone()],
                _ => Vec::new(),
            };
            for item in all {
                let Some(stream) = item.as_object() else { continue };
                if string_of(stream.get("stream_id").unwrap_or(&Value::Null)).is_empty() {
                    continue;
                }
                let method = stream.get("delivery").and_then(|d| d.get("method")).map(string_of).unwrap_or_default();
                if method == POLL_METHOD {
                    return Ok(stream.clone());
                }
            }
        } else if status != 404 {
            let mut text = parsed.to_string();
            if text.len() > 300 { text.truncate(300); }
            return Err(err("ssf", format!("listing the streams at {endpoint} answered {status}: {text}")));
        }
        let mut body = Map::new();
        body.insert("delivery".to_string(), json!({"method": POLL_METHOD}));
        body.insert("events_requested".to_string(), Value::Array(self.inner.events_requested.iter().cloned().map(Value::String).collect()));
        if !self.inner.description.is_empty() {
            body.insert("description".to_string(), Value::String(self.inner.description.clone()));
        }
        let (created_status, created) = self.call("POST", &endpoint, Some(&Value::Object(body)))?;
        let stream = created.as_object().cloned().unwrap_or_default();
        if (created_status != 200 && created_status != 201) || string_of(stream.get("stream_id").unwrap_or(&Value::Null)).is_empty() {
            let mut text = created.to_string();
            if text.len() > 300 { text.truncate(300); }
            return Err(err("ssf", format!("creating a stream at {endpoint} answered {created_status}: {text}")));
        }
        Ok(stream)
    }
}

fn audience_list(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items.iter().map(string_of).filter(|s| !s.is_empty()).collect(),
        Some(Value::String(text)) if !text.is_empty() => vec![text.clone()],
        Some(Value::Null) | None => Vec::new(),
        Some(other) => vec![other.to_string()],
    }
}
