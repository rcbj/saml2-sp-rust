// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use hmac::{Hmac, Mac};
use saml2_sp::{AcsBody, LoginOptions, ReceiverOptions, SamlLogin, ServiceProvider, SignalEvent, SignalsReceiver};
use serde_json::{json, Map, Value};
use sha2::Sha256;

/// The pages' Content-Security-Policy: their own styles and scripts only.
const PAGE_CSP: &str = "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const SESSION_MS: i64 = 8 * 60 * 60 * 1000;

struct Held { login: SamlLogin, expires_ms: i64 }

/// One received Shared Signals event, as the CAEP & RISC events tab draws
/// it and `app.js` receives it from `/api/signals`.
#[derive(Clone)]
struct LiveEvent {
    id: u64,
    event_type: String,
    jti: String,
    /// CAEP, RISC, SSF (the stream's own) or STS (iya-sts's own).
    family: String,
    at: String,
    subject: String,
    members: Value,
    ended: bool,
}

/// The most events kept; the oldest go first.
const MAX_EVENTS: usize = 200;

const SESSION_REVOKED: &str = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";

struct App {
    port: u16,
    public_url: String,
    public_given: bool,
    config_path: String,
    secret: Vec<u8>,
    secure_cookies: bool,
    ssf_transmitter: String,
    ssf_poll_ms: u64,
    /// `ssf.addSubjects` (default true): Add/Remove Subject at sign-in and sign-out.
    ssf_add_subjects: bool,
    receiver: Arc<Mutex<Option<SignalsReceiver>>>,
    receiver_state: Arc<Mutex<String>>,
    sessions: Arc<Mutex<HashMap<String, Held>>>,
    events: Arc<Mutex<Vec<LiveEvent>>>,
    event_seq: Arc<std::sync::atomic::AtomicU64>,
    /// The service provider, built from `config_path` on first use (once
    /// per process: main makes one App). A test sets it beforehand.
    sp: OnceLock<Result<ServiceProvider, String>>,
}

fn main() {
    let app = match configure() {
        Ok(app) => Arc::new(app),
        Err(error) => { eprintln!("{error}"); std::process::exit(1); }
    };
    let signals = signal_set();
    let listener = match TcpListener::bind(("0.0.0.0", app.port)) {
        Ok(listener) => listener,
        Err(error) => { eprintln!("{error}"); std::process::exit(1); }
    };
    println!("saml2-sp demo on port {}, configuration {}", app.port, app.config_path);
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = stop.clone();
    let serving = app.clone();
    let port = app.port;
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            if flag.load(std::sync::atomic::Ordering::SeqCst) { break; }
            let Ok(mut stream) = conn else { break; };
            if flag.load(std::sync::atomic::Ordering::SeqCst) { break; }
            let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
            let Some(req) = read_request(&mut stream) else { continue };
            let response = route(&serving, &req);
            let _ = write_response(&mut stream, &response);
        }
    });
    let mut sig = 0i32;
    unsafe {
        libc::sigwait(&signals.0, &mut sig);
    }
    if let Some(receiver) = app.receiver.lock().expect("receiver").as_ref() {
        receiver.stop();
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _ = TcpStream::connect(("127.0.0.1", port));
}

struct SigSet(libc::sigset_t);
unsafe impl Sync for SigSet {}

fn signal_set() -> &'static SigSet {
    static SET: OnceLock<SigSet> = OnceLock::new();
    SET.get_or_init(|| unsafe {
        let mut set = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        SigSet(set)
    })
}

fn configure() -> Result<App, String> {
    let mut port = 3000u16;
    if let Ok(raw) = std::env::var("PORT") {
        if !raw.is_empty() {
            let parsed: u16 = raw.parse().map_err(|_| "PORT is not a port".to_string())?;
            if parsed < 1 { return Err("PORT is not a port".to_string()); }
            port = parsed;
        }
    }
    let mut public_url = std::env::var("PUBLIC_URL").unwrap_or_default().trim_end_matches('/').to_string();
    let mut public_given = std::env::var("PUBLIC_URL").is_ok();
    let mut config_path = std::env::var("SAML_CONFIG").unwrap_or_default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--public-url" => {
                let value = args.next().ok_or_else(|| "--public-url needs a value".to_string())?;
                public_url = value.trim_end_matches('/').to_string();
                public_given = true;
            }
            "--config" => { config_path = args.next().ok_or_else(|| "--config needs a value".to_string())?; }
            other => return Err(format!("Unknown argument {other}")),
        }
    }
    if public_given && public_url.is_empty() { return Err("--public-url is empty".to_string()); }
    if config_path.is_empty() { config_path = "demo/saml.json".to_string(); }
    if !std::path::Path::new(&config_path).is_absolute() {
        if let Ok(cwd) = std::env::current_dir() { config_path = cwd.join(&config_path).to_string_lossy().to_string(); }
    }
    let secret = if let Ok(raw) = std::env::var("SESSION_SECRET") {
        if raw.is_empty() { random(32) } else { raw.into_bytes() }
    } else { random(32) };
    let file = read_file(&config_path);
    let signals_off = file.get("signals").and_then(|v| v.as_bool()) == Some(false);
    let mut receiver_state = "not configured (no ssf block in the configuration file)".to_string();
    if signals_off { receiver_state = "not configured (signals are off)".to_string(); }
    let mut ssf_transmitter = String::new();
    let mut ssf_poll_ms = 0u64;
    let ssf_add_subjects = saml2_sp::ssf_add_subjects(file.get("ssf")).map_err(|e| e.to_string())?;
    if let Some(ssf) = file.get("ssf").and_then(|v| v.as_object()) {
        if !signals_off {
            ssf_transmitter = ssf.get("transmitter").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if let Some(n) = ssf.get("pollIntervalMs").and_then(|v| v.as_u64()) { ssf_poll_ms = n; }
        }
    }
    if signals_off || ssf_transmitter.is_empty() {
        if !signals_off && ssf_transmitter.is_empty() {
            receiver_state = "not configured (no ssf block in the configuration file)".to_string();
        }
    }
    let secure_cookies = secure_from(&endpoints_of(&file, port, public_given, &public_url).1, port);
    Ok(App {
        port, public_url, public_given, config_path, secret, secure_cookies, ssf_transmitter, ssf_poll_ms, ssf_add_subjects,
        receiver: Arc::new(Mutex::new(None)), receiver_state: Arc::new(Mutex::new(receiver_state)), sessions: Arc::new(Mutex::new(HashMap::new())),
        events: Arc::new(Mutex::new(Vec::new())), event_seq: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        sp: OnceLock::new(),
    })
}

fn read_file(path: &str) -> Map<String, Value> {
    let Ok(raw) = std::fs::read(path) else { return Map::new() };
    serde_json::from_slice::<Value>(&raw).ok().and_then(|v| v.as_object().cloned()).unwrap_or_default()
}

fn endpoints_of(file: &Map<String, Value>, port: u16, public_given: bool, public_url: &str) -> (String, String) {
    let entity = file.get("entityId").and_then(|v| v.as_str()).unwrap_or("");
    let acs = file.get("acsUrl").and_then(|v| v.as_str()).unwrap_or("");
    if entity.is_empty() || acs.is_empty() { return (String::new(), String::new()); }
    if public_given && !public_url.is_empty() {
        (replace_origin(entity, public_url), replace_origin(acs, public_url))
    } else {
        (on_port(entity, port), on_port(acs, port))
    }
}

fn replace_origin(value: &str, public: &str) -> String {
    let Some((scheme, host, path)) = split_origin(value) else { return value.to_string() };
    let Some((pscheme, phost, _)) = split_origin(public) else { return value.to_string() };
    let _ = (scheme, host);
    format!("{pscheme}://{phost}{path}")
}

fn on_port(raw: &str, number: u16) -> String {
    let Some((_, host, path)) = split_origin(raw) else { return raw.to_string() };
    let name = hostname(&host);
    if name != "localhost" && name != "127.0.0.1" && name != "::1" { return raw.to_string(); }
    let scheme = raw.split_once("://").map(|(s, _)| s).unwrap_or("http");
    let shown = if name.contains(':') { format!("[{name}]:{number}") } else { format!("{name}:{number}") };
    format!("{scheme}://{shown}{path}")
}

fn split_origin(raw: &str) -> Option<(String, String, String)> {
    let (scheme, rest) = raw.split_once("://")?;
    let (host, path) = match rest.find('/') {
        Some(i) => (rest[..i].to_string(), rest[i..].to_string()),
        None => (rest.to_string(), String::new()),
    };
    Some((scheme.to_string(), host, path))
}

fn hostname(hostport: &str) -> &str {
    if let Some(inner) = hostport.strip_prefix('[') { inner.split(']').next().unwrap_or(hostport) } else { hostport.split(':').next().unwrap_or(hostport) }
}

fn secure_from(acs: &str, port: u16) -> bool {
    let acs = if acs.is_empty() { format!("http://localhost:{port}/") } else { acs.to_string() };
    let Some((scheme, host, _)) = split_origin(&acs) else { return true };
    scheme == "https" || hostname(&host) == "localhost" || hostname(&host) == "127.0.0.1"
}

fn provider(app: &App) -> Result<&ServiceProvider, String> {
    app.sp.get_or_init(|| {
        let file = read_file(&app.config_path);
        let (entity, acs) = endpoints_of(&file, app.port, app.public_given, &app.public_url);
        let mut overrides = Map::new();
        if !entity.is_empty() { overrides.insert("entityId".into(), json!(entity)); overrides.insert("acsUrl".into(), json!(acs)); }
        match ServiceProvider::from_file(&app.config_path, Some(&overrides), None) {
            Ok(sp) => { start_receiver(app, &sp); Ok(sp) }
            Err(error) => Err(error.to_string()),
        }
    }).as_ref().map_err(|e| e.clone())
}

fn start_receiver(app: &App, sp: &ServiceProvider) {
    if sp.config.signals == Some(false) {
        *app.receiver_state.lock().expect("state") = "not configured (signals are off)".to_string();
        return;
    }
    if app.ssf_transmitter.is_empty() { return; }
    // The receiver's own TLS client identity (ssf.clientCertificate / ssf.clientKey,
    // the certificate the realm issued the application), else the SP key pair.
    let tls = sp.config.ssf_tls();
    let entity = sp.config.entity_id.clone();
    let sessions = app.sessions.clone();
    let built = SignalsReceiver::new(ReceiverOptions {
        transmitter: app.ssf_transmitter.clone(),
        tls: Some(tls),
        description: format!("saml2-sp demo ({entity})"),
        poll_interval_ms: app.ssf_poll_ms,
        add_subjects: app.ssf_add_subjects,
        // The embedded PEP's policy events ride this stream (the `pep` feature).
        #[cfg(feature = "pep")]
        pep: sp.pep().cloned(),
        on_end_sessions: Some(Arc::new(move |ids, _| {
            let mut guard = sessions.lock().expect("sessions");
            for id in ids { guard.remove(id); }
            println!("ssf: ended {} local session(s)", ids.len());
            Ok(())
        })),
        ..ReceiverOptions::default()
    });
    let built = match built {
        Ok(built) => built,
        Err(error) => { *app.receiver_state.lock().expect("state") = format!("not running: {error}"); return; }
    };
    let events = app.events.clone();
    let seq = app.event_seq.clone();
    let sessions = app.sessions.clone();
    let for_untrack = built.clone();
    built.on("*", move |signal| {
        remember_live_event(&events, &seq, signal);
        // The assertion SessionIndex often is the IdP session, and on_end_sessions already dropped it.
        // When it is only the assertion id, this demo still has that one login.
        if signal.event_type == SESSION_REVOKED {
            let sid = {
                let mut guard = sessions.lock().expect("sessions");
                if guard.len() != 1 { return Ok(()); }
                let sid = guard.keys().next().cloned().expect("session");
                guard.remove(&sid);
                sid
            };
            for_untrack.untrack(&sid);
            println!("ssf: the assertion SessionIndex is not the CAEP session id; ended this demo's one session");
        }
        Ok(())
    });
    *app.receiver.lock().expect("receiver") = Some(built.clone());
    let state = app.receiver_state.clone();
    let slot = app.receiver.clone();
    let transmitter = app.ssf_transmitter.clone();
    std::thread::spawn(move || {
        if let Err(error) = built.start() {
            *state.lock().expect("state") = format!("not running: {error}");
            println!("ssf: the receiver did not start: {error}");
            *slot.lock().expect("receiver") = None;
            return;
        }
        let stream = built.stream().get("stream_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        *state.lock().expect("state") = format!("polling stream {stream} at {transmitter}");
    });
}

struct Request { method: String, path: String, query: String, headers: HashMap<String, String>, body: String }

struct Response { status: u16, headers: Vec<(String, String)>, body: Vec<u8> }

fn route(app: &App, req: &Request) -> Response {
    if req.path == "/healthz" {
        return text(200, "text/plain", "ok");
    }
    if req.path == "/live-status" && req.method == "GET" {
        return live_status(app);
    }
    if (req.path == "/pep-status" || req.path == "/pep-status.html") && req.method == "GET" {
        return pep_status_page(app, req, req.path.ends_with(".html"));
    }
    match req.path.as_str() {
        "/styles.css" => return file_response("demo/public/styles.css", "text/css"),
        "/pep.js" => return file_response("demo/public/pep.js", "text/javascript"),
        "/app.js" => return file_response("demo/public/app.js", "text/javascript"),
        "/panes.js" => return file_response("demo/public/panes.js", "text/javascript"),
        "/menu.js" => return file_response("demo/public/menu.js", "text/javascript"),
        "/api/signals" if req.method == "GET" => return signals_api(app, req),
        // No Server-Sent Events here: 204 tells app.js's EventSource to give
        // up, and it polls /api/signals every 3 s instead.
        "/events" if req.method == "GET" => return text(204, "text/plain", ""),
        "/signals/verify" if req.method == "POST" => return verify_signals(app, req),
        "/saml/metadata" => {
            let sp = match provider(app) { Ok(sp) => sp, Err(error) => return text(500, "text/plain", &error) };
            return text(200, "application/samlmetadata+xml", &sp.metadata());
        }
        "/login" if req.method == "GET" => return login(app, req),
        "/saml/acs" if req.method == "GET" || req.method == "POST" => return acs(app, req),
        "/logout" if req.method == "POST" => return logout(app, req),
        "/" if req.method == "GET" => return page(app, req),
        _ => {}
    }
    #[cfg(feature = "pep")]
    if req.path == "/attribute-protected" {
        return attribute_protected(app, req);
    }
    #[cfg(feature = "pep")]
    if let Some(id) = req.path.strip_prefix("/orders/").filter(|id| !id.is_empty() && !id.contains('/')) {
        return order(app, req, id);
    }
    text(404, "text/plain", "not found")
}

/// A route the embedded PEP protects (the `pep` feature, iya-sts#1206): the
/// signed-in person's access to one order, decided by the `pep` section's
/// PEP from the validated assertion. A GET is `read` and anything else
/// `write`. No sign-in is 401, a Deny 403, and any other PEP failure 403
/// too (no decision, or no service provider to ask): an enforcement point
/// that cannot say yes says no, and the page says which. Never served.
#[cfg(feature = "pep")]
fn order(app: &App, req: &Request, id: &str) -> Response {
    use saml2_sp::pep::{Access, Decision};
    let Some(held) = current_session(app, req) else {
        return page_html("Sign in", "<h1>Sign in first</h1><p><a href=\"/login\">Sign in</a></p>", 401);
    };
    let sp = match provider(app) {
        Ok(sp) => sp,
        Err(error) => return page_for("Forbidden", &not_configured(&error), 403, Some(&held.login)),
    };
    let action = if req.method == "GET" { "read" } else { "write" };
    let decision = sp.decide(&held.login, &Access::new(action, "order", id));
    // 200 for a Permit, 403 for anything else (iya-pep's http_status()).
    let status = decision.http_status();
    let (title, body) = match decision {
        Decision::Permit { obligations, .. } => {
            let note = if obligations.is_empty() { String::new() } else { format!("<p><small>{} obligation(s) to discharge.</small></p>", obligations.len()) };
            ("Order", format!("<h1>Order {}</h1><p>The PEP permitted <code>{action}</code>.</p>{note}", escape(id)))
        }
        Decision::Deny { why } => ("Forbidden", format!("<h1>Not allowed</h1><p>The PEP denied <code>{action}</code> on order {}: {}</p>", escape(id), escape(&why))),
        Decision::Unavailable { why } => ("Forbidden", format!("<h1>No decision</h1><p>The PEP could not decide: {}</p>", escape(&why))),
    };
    page_for(title, &body, status, Some(&held.login))
}

/// The 403 page when no service provider is there to ask a decision of.
#[cfg(feature = "pep")]
fn not_configured(error: &str) -> String {
    format!("<h1>Not allowed</h1><p class=\"problem\">No decision could be asked for: the service provider is not configured: {}</p>", escape(error))
}

/// `GET /attribute-protected`: decided by the embedded PEP against the demo
/// application's own (fine-grained authorization) policy, which permits it
/// to a person whose directory attribute attr1 is abc123. The value is not
/// in the assertion: the PEP asks iya-sts's PIP for it (`POST /xacml/pip`),
/// in `local` mode as in `central`. 401 without a sign-in, 200 on a Permit,
/// 403 on a Deny and on any other PEP failure (no decision, or no service
/// provider to ask), the page saying which.
#[cfg(feature = "pep")]
fn attribute_protected(app: &App, req: &Request) -> Response {
    use saml2_sp::pep::{Access, Decision};
    let Some(held) = current_session(app, req) else {
        return page_html("Sign in", "<h1>Sign in first</h1><p><a href=\"/login\">Sign in</a></p>", 401);
    };
    let sp = match provider(app) {
        Ok(sp) => sp,
        Err(error) => return page_for("Forbidden", &not_configured(&error), 403, Some(&held.login)),
    };
    let what = "<p><small>The demo application's policy permits <code>read</code> on <code>attribute-protected</code> when your directory attribute <code>attr1</code> is <code>abc123</code>. The PEP asked iya-sts's PIP for it: it is not in your SAML assertion.</small></p>";
    let decision = sp.decide(&held.login, &Access::new("read", "attribute-protected", "attr1"));
    // 200 for a Permit, 403 for anything else (iya-pep's http_status()).
    let status = decision.http_status();
    let (title, body) = match decision {
        Decision::Permit { .. } => ("Attribute-protected", format!("<h1>Allowed</h1><p class=\"notice\">The PEP permitted it: your <code>attr1</code> is <code>abc123</code>.</p>{what}")),
        Decision::Deny { why } => ("Forbidden", format!("<h1>Not allowed</h1><p class=\"problem\">The PEP denied it: {}</p>{what}", escape(&why))),
        Decision::Unavailable { why } => ("Forbidden", format!("<h1>No decision</h1><p class=\"problem\">The PEP could not decide: {}</p>{what}", escape(&why))),
    };
    page_for(title, &body, status, Some(&held.login))
}

fn live_status(app: &App) -> Response {
    let now = now_ms();
    let (signed_in, subject) = {
        let sessions = app.sessions.lock().expect("sessions");
        let mut signed_in = false;
        let mut subject: Option<String> = None;
        for held in sessions.values() {
            if now > held.expires_ms { continue; }
            signed_in = true;
            // The username, as the page names the person; the NameID only
            // when the assertion carries nothing else.
            let who = display_name(&held.login);
            if subject.is_none() && !who.is_empty() {
                subject = Some(who);
            }
        }
        (signed_in, subject)
    };
    let receiver = app.receiver_state.lock().expect("state").clone();
    let events: Vec<Value> = app.events.lock().expect("events").iter().map(|item| json!({"type": item.event_type, "jti": item.jti})).collect();
    #[allow(unused_mut)]
    let mut body = json!({"signedIn": signed_in, "subject": subject, "receiver": receiver, "events": events});
    // The PEP's status holds no secret; its syncToken is the policy's version.
    #[cfg(feature = "pep")]
    if let Some(pep) = provider(app).ok().and_then(|sp| sp.pep()) {
        let s = pep.status();
        body["pep"] = json!({
            "name": s.name, "mode": if s.mode == saml2_sp::pep::Mode::Local { "local" } else { "central" }, "application": s.application,
            "registered": s.registered, "running": s.running, "holdsPolicy": s.holds_policy,
            "policyCount": s.policy_count, "syncToken": s.sync_token, "eventStream": s.event_stream.as_str(),
            "eventsReceived": s.events_received, "decisions": s.decisions, "lastError": s.last_error,
        });
    }
    text(200, "application/json", &body.to_string())
}

/// `GET /pep-status` (JSON) and `/pep-status.html` (the Policy enforcement
/// tab's fragment): what the embedded PEP holds and has done. For a signed-in
/// browser only, like the page that shows it. Nothing in it is secret:
/// counts, times, tokens naming policy versions, the key's public thumbprint.
fn pep_status_page(app: &App, req: &Request, html: bool) -> Response {
    if current_session(app, req).is_none() {
        return text(401, "text/plain; charset=utf-8", "sign in first");
    }
    let sp = provider(app).ok();
    if html {
        text(200, "text/html; charset=utf-8", &pep_fragment(sp))
    } else {
        text(200, "application/json", &pep_json(sp).to_string())
    }
}

#[cfg(feature = "pep")]
fn pep_json(sp: Option<&ServiceProvider>) -> Value {
    let Some(pep) = sp.and_then(|sp| sp.pep()) else {
        return json!({"enabled": false, "why": "no pep section is configured"});
    };
    let s = pep.status();
    let ms = |d: Option<Duration>| d.map(|d| d.as_millis() as u64);
    json!({
        "enabled": true,
        "name": s.name, "mode": s.mode.as_str(), "application": s.application, "pdpUrl": s.pdp_url,
        "protocolVersion": s.protocol_version, "registered": s.registered, "running": s.running,
        "eventStream": s.event_stream.as_str(), "keyThumbprint": s.key_thumbprint, "problems": s.last_error,
        "policy": {
            "held": s.holds_policy, "count": s.policy_count, "syncToken": s.sync_token,
            "catalogueToken": s.catalogue_token, "catalogueSubjectClaims": s.catalogue_subject_properties,
            "sinceUpdateMs": ms(s.since_policy_update), "sinceLastPullMs": ms(s.since_last_pull),
            "untilNextPullMs": ms(s.until_next_pull), "pulls": s.pulls, "pullsChanged": s.pulls_changed,
            "pullFailures": s.pull_failures, "eventsReceived": s.events_received, "eventsIgnored": s.events_ignored,
            "sinceLastEventMs": ms(s.since_last_event),
        },
        "decisions": {
            "total": s.decisions, "allowed": s.allowed, "denied": s.refused, "unavailable": s.unavailable,
            "undischargeable": s.undischargeable, "meanMicros": s.mean_decision_micros, "maxMicros": s.max_decision_micros,
            "permitCacheEntries": s.permit_cache_entries, "permitCacheHits": s.permit_cache_hits,
        },
        "controlPlane": {
            "uptimeMs": ms(s.uptime), "registrations": s.registrations, "heartbeats": s.heartbeats,
            "heartbeatFailures": s.heartbeat_failures, "sinceLastHeartbeatMs": ms(s.since_last_heartbeat),
            "untilNextHeartbeatMs": ms(s.until_next_heartbeat), "recordsQueued": s.records_queued,
            "recordsShipped": s.records_shipped, "recordsDropped": s.records_dropped,
        },
    })
}

#[cfg(not(feature = "pep"))]
fn pep_json(_sp: Option<&ServiceProvider>) -> Value {
    json!({"enabled": false, "why": "this demo was built without the pep feature"})
}

/// A duration as a person reads it: `ago` for one that has passed, else `in`.
fn human(d: Option<Duration>, ago: bool) -> String {
    let Some(d) = d else { return "—".into() };
    let s = d.as_secs();
    if s == 0 {
        return if ago { "just now".into() } else { "now".into() };
    }
    let text = if s < 120 {
        format!("{s} s")
    } else if s < 7200 {
        format!("{} min {} s", s / 60, s % 60)
    } else {
        format!("{} h {} min", s / 3600, s % 3600 / 60)
    };
    if ago { format!("{text} ago") } else { format!("in {text}") }
}

/// The Policy enforcement tab: four collapsible panes drawn from the PEP's
/// `status()`, every value escaped. `demo/public/pep.js` fetches it again
/// every 2 s.
fn pep_fragment(sp: Option<&ServiceProvider>) -> String {
    let v = pep_json(sp);
    if v["enabled"] != json!(true) {
        return pane("pep-none", "No embedded PEP", "", &format!(
            "<p class=\"notice\">No embedded PEP: {}. Add a <code>pep</code> section to the configuration (<code>scripts/configure_iya_sts.py --pep local</code> writes one) and build with the <code>local</code> (or <code>pep</code>) feature; see <code>docs/remote-pep.md</code>.</p>",
            escape(v["why"].as_str().unwrap_or(""))
        ));
    }
    let text = |x: &Value| match x {
        Value::String(s) if s.is_empty() => "—".to_string(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => if *b { "yes".into() } else { "no".into() },
        Value::Null => "—".into(),
        other => other.to_string(),
    };
    let dur = |x: &Value, ago: bool| human(x.as_u64().map(Duration::from_millis), ago);
    let micros = |x: &Value| x.as_u64().map(|m| if m >= 1000 { format!("{:.1} ms", m as f64 / 1000.0) } else { format!("{m} µs") }).unwrap_or_else(|| "—".into());
    let (p, d, c) = (&v["policy"], &v["decisions"], &v["controlPlane"]);
    let local = v["mode"] == json!("local");
    let mut decisions = vec![
        ("Decisions".to_string(), text(&d["total"])),
        ("Allowed".into(), text(&d["allowed"])),
        ("Denied".into(), text(&d["denied"])),
        ("Unavailable (no decision; refused)".into(), text(&d["unavailable"])),
        ("Stopped by an obligation".into(), text(&d["undischargeable"])),
        ("Mean time per decision".into(), micros(&d["meanMicros"])),
        ("Slowest decision".into(), micros(&d["maxMicros"])),
    ];
    if !local {
        decisions.push(("Permit cache".into(), format!("{} held, {} answered from it", text(&d["permitCacheEntries"]), text(&d["permitCacheHits"]))));
    }
    let mut policy = vec![
        ("Policies held".to_string(), if local { text(&p["count"]) } else { "— (central mode: iya-sts decides)".into() }),
        ("Last policy update".into(), dur(&p["sinceUpdateMs"], true)),
        ("Last pull (changed or not)".into(), dur(&p["sinceLastPullMs"], true)),
        ("Next scheduled pull".into(), dur(&p["untilNextPullMs"], false)),
        ("Pulls".into(), format!("{} ({} brought changes, {} failed)", text(&p["pulls"]), text(&p["pullsChanged"]), text(&p["pullFailures"]))),
        ("Policy-change events".into(), format!("{} acted on, {} for another PEP; last {}", text(&p["eventsReceived"]), text(&p["eventsIgnored"]), dur(&p["sinceLastEventMs"], true))),
        ("Catalogue claims sent".into(), text(&p["catalogueSubjectClaims"])),
    ];
    if local {
        policy.push(("Policy set version".into(), text(&p["syncToken"])));
    }
    policy.push(("Catalogue version".into(), text(&p["catalogueToken"])));
    let the_pep = vec![
        ("Name".to_string(), text(&v["name"])),
        ("Mode".into(), text(&v["mode"])),
        ("Application".into(), text(&v["application"])),
        ("iya-sts".into(), text(&v["pdpUrl"])),
        ("Registered".into(), text(&v["registered"])),
        ("Running".into(), format!("{} (up {})", text(&v["running"]), dur(&c["uptimeMs"], false).trim_start_matches("in "))),
        ("Policy-change events on the stream".into(), text(&v["eventStream"])),
        ("Protocol version".into(), text(&v["protocolVersion"])),
        ("Key thumbprint".into(), text(&v["keyThumbprint"])),
    ];
    let control = vec![
        ("Heartbeats".to_string(), format!("{} ({} failed)", text(&c["heartbeats"]), text(&c["heartbeatFailures"]))),
        ("Last heartbeat".into(), dur(&c["sinceLastHeartbeatMs"], true)),
        ("Next heartbeat".into(), dur(&c["untilNextHeartbeatMs"], false)),
        ("Registrations".into(), text(&c["registrations"])),
        ("Decision records".into(), format!("{} queued, {} sent, {} dropped", text(&c["recordsQueued"]), text(&c["recordsShipped"]), text(&c["recordsDropped"]))),
    ];
    let mut out = String::new();
    let problems = v["problems"].as_str().unwrap_or("");
    if !problems.is_empty() {
        out.push_str(&pane("pep-problems", "Problems", "", &format!("<p class=\"problem\">{}</p>", escape(problems))));
    }
    for (title, rows) in [("Decisions", decisions), ("Cached policy", policy), ("The PEP", the_pep), ("Control plane", control)] {
        // Collapsible; the stable id lets pep.js keep a pane the person closed closed.
        let id: String = title.to_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect();
        out.push_str(&format!("<details class=\"card pane\" id=\"pep-{id}\" open><summary><h2>{}</h2></summary><table class=\"facts\">", escape(title)));
        for (k, val) in rows {
            out.push_str(&format!("<tr><th>{}</th><td>{}</td></tr>", escape(&k), escape(&val)));
        }
        out.push_str("</table></details>");
    }
    out.push_str(&pane("pep-try", "Try it", "", "<ul class=\"checks\">\
<li><a href=\"/orders/42\">/orders/42</a> <span class=\"muted\">read an order: permitted when your sign-in carried an AuthnContextClassRef</span></li>\
<li><a href=\"/attribute-protected\">/attribute-protected</a> <span class=\"muted\">permitted when your directory attribute attr1 is abc123, which the PEP asks iya-sts's PIP for</span></li>\
</ul><p><small>Each is decided by this PEP against the demo application's own policy; the counters above move as you try them.</small></p>"));
    out.push_str("<p><small>Refreshed every 2 seconds. <a href=\"/pep-status\">As JSON</a>.</small></p>");
    out
}

fn page(app: &App, req: &Request) -> Response {
    let mut problem = String::new();
    if let Err(error) = provider(app) {
        problem = format!("The service provider is not configured yet: {error}. Run the setup script (python scripts/configure_iya_sts.py).");
    }
    let state = app.receiver_state.lock().expect("state").clone();
    if let Some(current) = current_session(app, req) {
        let sid = cookie_value(req, "sid");
        // Three tabs: Session, CAEP & RISC events, and Policy enforcement.
        let tab = match query_value(&req.query, "tab").as_str() {
            "pep" => "pep",
            "events" => "events",
            _ => "session",
        };
        let events = app.events.lock().expect("events").clone();
        let last_id = events.last().map(|e| e.id).unwrap_or(0);
        // Every tab's blocks are collapsible panes; one toggle opens or
        // closes all of a tab's panes (panes.js shows it).
        let toggle = "<p class=\"pane-tools\"><button type=\"button\" class=\"secondary small\" id=\"panes-toggle\" hidden>Collapse all</button></p>";
        let content = match tab {
            "pep" => format!("{toggle}<div id=\"pep-panel\" aria-live=\"polite\">{}</div><script src=\"/pep.js\" defer></script>", pep_fragment(provider(app).ok())),
            "events" => {
                let notice = match query_value(&req.query, "verify").as_str() {
                    "sent" => "A verification event was requested; it appears below when the transmitter sends it.",
                    "refused" => "The transmitter refused the verification request.",
                    _ => "",
                };
                format!("{toggle}{}", events_panel(&events, &state, notice))
            }
            _ => {
                let session = match provider(app) {
                    Ok(sp) => {
                        let (held, tracked) = {
                            let sessions = app.sessions.lock().expect("sessions");
                            let receiver = app.receiver.lock().expect("receiver");
                            (sessions.len(), receiver.as_ref().map(|r| r.session_index().contains(&sid)))
                        };
                        let facts = SessionFacts { sid: &sid, expires_ms: current.expires_ms, held, tracked, secure_cookies: app.secure_cookies };
                        session_panes(sp, &current.login, &facts, &state)
                    }
                    Err(error) => format!("<p class=\"problem\">{}</p>", escape(&error)),
                };
                format!("{toggle}{session}")
            }
        };
        let tab_link = |id: &str, href: &str, label: &str| {
            let on = id == tab;
            format!("<a class=\"page-tab\" role=\"tab\" href=\"{href}\" aria-selected=\"{on}\"{}>{label}</a>", if on { " aria-current=\"page\"" } else { "" })
        };
        let count = if events.is_empty() { String::new() } else { events.len().to_string() };
        let body = format!(
            "<h1>Signed in as {}</h1><nav class=\"page-tabs\" role=\"tablist\" aria-label=\"Sections\">{}{}{}</nav><p id=\"signal-banner\" class=\"problem\" hidden></p><p id=\"signal-toast\" class=\"notice\" hidden></p><div role=\"tabpanel\" id=\"panel\" data-base=\"\" data-tab=\"{tab}\" data-last-id=\"{last_id}\">{content}</div><script src=\"/app.js\" defer></script><script src=\"/panes.js\" defer></script>",
            escape(&display_name(&current.login)),
            tab_link("session", "/", "Session"),
            tab_link("events", "/?tab=events", &format!("CAEP &amp; RISC events <span class=\"count\" id=\"signal-count\">{count}</span>")),
            tab_link("pep", "/?tab=pep", "Policy enforcement"),
        );
        return page_for("saml2-sp", &body, 200, Some(&current.login));
    }
    let mut body = "<h1>Sign in with SAML 2.0</h1>".to_string();
    if !problem.is_empty() { body.push_str(&format!("<p class=\"problem\">{}</p>", escape(&problem))); }
    body.push_str(&format!("<p>This application is a SAML 2.0 service provider. It sends the browser to the identity provider with a signed AuthnRequest and accepts the signed (and encrypted) assertion at its assertion consumer service.</p><p>Shared Signals: {}</p>", escape(&state)));
    if problem.is_empty() {
        body.push_str("<p class=\"buttons\"><a class=\"button primary\" href=\"/login\">Sign in with SAML 2.0</a></p>");
    }
    page_html("saml2-sp", &body, 200)
}

/// What the Session tab says about the demo's own session, beside what the
/// library took from the assertion.
struct SessionFacts<'a> {
    sid: &'a str,
    expires_ms: i64,
    /// Sessions this process holds.
    held: usize,
    /// Whether the Shared Signals receiver tracks this one (None: no receiver).
    tracked: Option<bool>,
    secure_cookies: bool,
}

/// A collapsible pane. The id is stable, so pep.js can keep a pane the
/// person closed closed across a redraw.
fn pane(id: &str, title: &str, aside: &str, body: &str) -> String {
    let aside = if aside.is_empty() { String::new() } else { format!(" <span class=\"aside\">{}</span>", escape(aside)) };
    format!("<details class=\"card pane\" id=\"{id}\" open><summary><h2>{}</h2>{aside}</summary>{body}</details>", escape(title))
}

fn facts_table(rows: &[(String, String)]) -> String {
    let rows: String = rows.iter().map(|(k, v)| format!("<tr><th>{}</th><td>{}</td></tr>", escape(k), escape(v))).collect();
    format!("<table class=\"facts\">{rows}</table>")
}

/// A short, non-reversible name for a value this page must not show (a
/// session cookie, a SessionIndex, a certificate): its SHA-256, shortened.
fn fingerprint(value: &[u8]) -> String {
    let digest = <Sha256 as sha2::Digest>::digest(value);
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("sha256 {hex}…")
}

/// A UTC timestamp, `YYYY-MM-DD HH:MM:SS UTC`, from epoch milliseconds.
fn utc(ms: i64) -> String {
    let t = ms.max(0) / 1000;
    let (days, rem) = (t.div_euclid(86_400), t.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// A span of milliseconds in words: `ago` when it is negative.
fn in_words(ms: i64) -> String {
    let s = (ms.abs() + 500) / 1000;
    let text = if s >= 3600 { format!("{}h {}m", s / 3600, s % 3600 / 60) } else if s >= 60 { format!("{}m {}s", s / 60, s % 60) } else { format!("{s}s") };
    if ms < 0 { format!("{text} ago") } else { text }
}

/// The attributes the person's email address is read from.
const MAIL_ATTRIBUTES: &[&str] = &["mail", "email", "urn:oid:0.9.2342.19200300.100.1.3", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"];
/// The attributes the person's display name is read from.
const NAME_ATTRIBUTES: &[&str] = &["displayName", "urn:oid:2.16.840.1.113730.3.1.241", "cn", "urn:oid:2.5.4.3"];

fn first_of(login: &SamlLogin, names: &[&str]) -> String {
    names.iter().find_map(|n| login.attributes.get(*n).and_then(|v| v.iter().find(|s| !s.is_empty()))).cloned().unwrap_or_default()
}

/// Who a sign-in is, as the heading, the menu and /live-status name them:
/// the username from the assertion's attributes (`SamlLogin::username()`:
/// username, preferred_username, uid, the AD FS name claim), else the email
/// address, and the NameID only when the assertion carries neither.
fn display_name(login: &SamlLogin) -> String {
    login.username().map(str::to_string).into_iter().chain([first_of(login, MAIL_ATTRIBUTES), login.name_id.clone()]).find(|v| !v.is_empty()).unwrap_or_default()
}

/// The top bar's user menu: the signed-in account, signing in with another
/// account (ForceAuthn, so the identity provider asks again), and signing
/// out. This demo keeps one sign-in per browser, so another account
/// replaces this one rather than being switched to.
fn user_menu(login: &SamlLogin) -> String {
    let name = display_name(login);
    let initial = name.chars().find(|c| c.is_alphanumeric()).map(|c| c.to_uppercase().to_string()).unwrap_or_else(|| "?".into());
    let detail = [first_of(login, NAME_ATTRIBUTES), first_of(login, MAIL_ATTRIBUTES)].into_iter().find(|v| !v.is_empty() && *v != name).unwrap_or_default();
    let detail = if detail.is_empty() { String::new() } else { format!("<span class=\"muted small\">{}</span>", escape(&detail)) };
    format!(
        "<details class=\"acct-menu\"><summary aria-label=\"Account menu\"><span class=\"avatar\" aria-hidden=\"true\">{i}</span><span class=\"menu-name\" title=\"{n}\">{n}</span><span class=\"caret\" aria-hidden=\"true\">▾</span></summary>\
<div class=\"menu\" role=\"menu\"><p class=\"menu-head\">Signed in</p>\
<div class=\"menu-row static\"><span class=\"avatar\" aria-hidden=\"true\">{i}</span><span class=\"menu-who\"><span>{n}</span>{detail}</span></div>\
<div class=\"menu-sep\"></div>\
<a class=\"menu-row\" role=\"menuitem\" href=\"/login?force=1\"><span class=\"avatar plus\" aria-hidden=\"true\">+</span>Sign in with another account</a>\
<p class=\"muted small menu-note\">The identity provider asks who you are (ForceAuthn), even if it already knows. This demo keeps one sign-in per browser: the new account replaces this one.</p>\
<div class=\"menu-sep\"></div>\
<form method=\"post\" action=\"/logout\"><button class=\"menu-row\" type=\"submit\" role=\"menuitem\">Sign out {n}</button></form></div></details>",
        i = escape(&initial),
        n = escape(&name)
    )
}

/// The top bar's links between the demo's pages, for a signed-in person:
/// the demo itself, and (with the embedded PEP) the two pages the PEP
/// decides, so each is one click from the others.
fn site_nav() -> String {
    #[allow(unused_mut)]
    let mut links = vec![("/", "Demo home")];
    #[cfg(feature = "pep")]
    links.extend([("/attribute-protected", "Attribute-protected"), ("/orders/42", "Order 42")]);
    let items: Vec<String> = links.iter().map(|(href, label)| format!("<a href=\"{href}\">{label}</a>")).collect();
    format!("<nav class=\"site-nav\" aria-label=\"Demo pages\">{}</nav>", items.join(""))
}

/// The Session tab: what protects the sign-in, who signed in (the
/// assertion's attributes), the demo's session cache and the credentials.
/// The assertion itself is not kept (only what the library took from it),
/// and the values that act as credentials (the session cookie, the
/// SessionIndex) are shown by a fingerprint, never as they are.
fn session_panes(sp: &ServiceProvider, login: &SamlLogin, facts: &SessionFacts, stream: &str) -> String {
    let c = &sp.config;
    let certs: Vec<String> = sp.idp.certs.iter().map(|der| fingerprint(der)).collect();
    let signature = if c.want_assertions_signed { "the assertion's own signature is required (wantAssertionsSigned)" } else { "the Response's or the assertion's signature is required" };
    let encryption = match (c.want_assertions_encrypted, login.encrypted) {
        (true, _) => "required (wantAssertionsEncrypted): an EncryptedAssertion, decrypted with privateKey",
        (false, true) => "this one was encrypted (an EncryptedAssertion, decrypted with privateKey); not required",
        (false, false) => "not required, and this one was not encrypted",
    };
    let protections = [
        ("AuthnRequest", format!("signed with privateKey (RSA-SHA256), sent by HTTP-{}", if c.request_binding == "post" { "POST" } else { "Redirect" })),
        ("Signature", format!("{signature}, checked against the identity provider's {} signing certificate(s) ({})", certs.len(), certs.join(", "))),
        ("Encryption", encryption.to_string()),
        ("InResponseTo", if c.allow_unsolicited { "unsolicited responses are allowed".to_string() } else { "must name an AuthnRequest this browser sent (the saml_pending cookie)".to_string() }),
        ("Audience and recipient", format!("AudienceRestriction must name {}, SubjectConfirmationData's Recipient {}", c.entity_id, c.acs_url)),
        ("Validity", format!("Conditions NotBefore / NotOnOrAfter and the bearer confirmation's NotOnOrAfter are checked with {} ms of clock skew", c.clock_skew_ms)),
        ("Replay", "each assertion ID is accepted once (the replay cache)".to_string()),
        ("TLS", if c.idp_ca.is_empty() { "the identity provider is verified against the system's roots".to_string() } else { "the identity provider is verified against idpCa's trust chain".to_string() }),
        ("Session", format!("server-side, in this process; the browser holds only the sid cookie (HttpOnly, SameSite=Lax{})", if facts.secure_cookies { ", Secure" } else { "" })),
        ("Shared Signals", if stream.is_empty() { "not running".to_string() } else {
            format!("{stream}; authenticated to the transmitter by mutual TLS with {}", if c.ssf_client_is_separate() { "its own client certificate (ssf.clientCertificate)" } else { "the SP key pair" })
        }),
    ];
    let list: String = protections.iter().map(|(k, v)| format!("<li><strong>{}</strong> <span class=\"muted\">{}</span></li>", escape(k), escape(v))).collect();
    let mut out = pane("security-card", "Protections in effect", "", &format!("<ul class=\"checks\">{list}</ul>"));

    let now = now_ms();
    let signed_in = if login.authn_instant_ms > 0 { format!("signed in {}", in_words(login.authn_instant_ms - now)) } else { String::new() };
    let when = |ms: i64| format!("{} ({})", utc(ms), in_words(ms - now));
    let mut who = vec![
        ("NameID".to_string(), login.name_id.clone()),
        ("NameID format".into(), login.name_id_format.clone()),
        ("Issuer".into(), login.issuer.clone()),
        ("AuthnInstant".into(), if login.authn_instant_ms > 0 { when(login.authn_instant_ms) } else { "not stated".into() }),
        ("AuthnContextClassRef".into(), login.authn_context_class_ref.clone()),
        ("SessionNotOnOrAfter".into(), login.session_not_on_or_after_ms.map(when).unwrap_or_else(|| "not stated".into())),
    ];
    if !login.name_qualifier.is_empty() { who.push(("NameQualifier".into(), login.name_qualifier.clone())); }
    if !login.sp_name_qualifier.is_empty() { who.push(("SPNameQualifier".into(), login.sp_name_qualifier.clone())); }
    let who: Vec<(String, String)> = who.into_iter().map(|(k, v)| (k, if v.is_empty() { "—".into() } else { v })).collect();
    let mut names: Vec<&String> = login.attributes.keys().collect();
    names.sort();
    let attributes: String = names.iter().map(|n| {
        let friendly = login.attribute_friendly_names.get(*n).filter(|f| !f.is_empty()).map(|f| format!(" <small>({})</small>", escape(f))).unwrap_or_default();
        format!("<tr><th>{}{friendly}</th><td>{}</td></tr>", escape(n), escape(&login.attributes[*n].join(", ")))
    }).collect();
    let attributes = if names.is_empty() { "<p><small>The assertion carried no attributes.</small></p>".to_string() } else { format!("<table class=\"facts\">{attributes}</table>") };
    out.push_str(&pane("session-card", "Session", &signed_in, &format!(
        "{}<h3>Attributes</h3><p><small>Every attribute of the assertion's AttributeStatement, as the library accepted it (by Name, with its FriendlyName).</small></p>{attributes}",
        facts_table(&who)
    )));

    let tracked = match facts.tracked {
        Some(true) => "yes: a CAEP or RISC event about this person or session ends it",
        Some(false) => "no",
        None => "no receiver is running",
    };
    let ends = if login.session_not_on_or_after_ms.is_some_and(|limit| limit <= facts.expires_ms) { "the assertion's SessionNotOnOrAfter" } else { "the demo's 8-hour limit" };
    let cache = vec![
        ("Expires".to_string(), when(facts.expires_ms)),
        ("Set by".into(), ends.into()),
        ("Sessions in this process".into(), facts.held.to_string()),
        ("Tracked for Shared Signals".into(), tracked.into()),
        ("Kept".into(), "in this process's memory: the validated sign-in, never the assertion's XML".into()),
    ];
    out.push_str(&pane("cache-card", "Session cache", &format!("expires in {}", in_words(facts.expires_ms - now).trim_end_matches(" ago")), &facts_table(&cache)));

    let encrypted = if login.encrypted { "yes (EncryptedAssertion)" } else { "no" };
    let assertion = vec![
        ("Assertion ID".to_string(), login.assertion_id.clone()),
        ("Response ID".into(), login.response_id.clone()),
        ("Binding".into(), login.binding.clone()),
        ("Encrypted".into(), encrypted.into()),
        ("Signature".into(), format!("verified before anything in it was read ({signature})")),
        ("InResponseTo".into(), login.in_response_to.clone().unwrap_or_else(|| "— (unsolicited)".into())),
    ];
    let secrets = vec![
        ("Session cookie (sid)".to_string(), fingerprint(facts.sid.as_bytes())),
        ("SessionIndex".into(), if login.session_index.is_empty() { "none was sent".into() } else { fingerprint(login.session_index.as_bytes()) }),
    ];
    out.push_str(&pane("credentials-card", "Credentials", "", &format!(
        "<p><small>The values stay in this process: each is shown by a fingerprint. The assertion's XML is not kept; this is what the library took from it.</small></p><h3>SAML assertion</h3>{}<h3>Session</h3>{}",
        facts_table(&assertion),
        facts_table(&secrets)
    )));
    out
}

fn family_of(event_type: &str) -> &'static str {
    if event_type.contains("/caep/") {
        "CAEP"
    } else if event_type.contains("/risc/") {
        "RISC"
    } else if event_type.contains("/ssf/") {
        "SSF"
    } else {
        "STS"
    }
}

fn remember_live_event(events: &Mutex<Vec<LiveEvent>>, seq: &std::sync::atomic::AtomicU64, signal: &SignalEvent) {
    let mut subject: Vec<String> = signal.subject.iter().map(|(k, v)| format!("{k} {v}")).collect();
    subject.sort();
    let live = LiveEvent {
        id: seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
        event_type: signal.event_type.clone(),
        jti: signal.jti.clone(),
        family: family_of(&signal.event_type).to_string(),
        at: utc(signal.iat.map(|t| (t * 1000.0) as i64).unwrap_or_else(now_ms)),
        subject: subject.join(", "),
        members: Value::Object(signal.payload.clone()),
        ended: signal.ended,
    };
    let mut events = events.lock().expect("events");
    events.push(live);
    let over = events.len().saturating_sub(MAX_EVENTS);
    events.drain(..over);
}

fn event_json(event: &LiveEvent) -> Value {
    json!({
        "id": event.id, "type": event.event_type, "jti": event.jti, "family": event.family,
        "at": event.at, "subject": event.subject, "members": event.members, "ended": event.ended,
        "about": if event.family == "SSF" { "stream" } else { "subject" },
    })
}

/// One log entry: the same markup `app.js`'s `entryNode()` draws.
fn event_item(event: &LiveEvent) -> String {
    let short = event.event_type.rsplit("/event-type/").next().unwrap_or(&event.event_type);
    let outcome = if event.family == "SSF" {
        "about the stream: the verification this session asked for"
    } else if event.ended {
        "ended this session"
    } else {
        "recorded; this session continues"
    };
    let mut out = format!(
        "<li class=\"log-item\" data-id=\"{}\"><div class=\"log-top\"><span class=\"badge {}\">{}</span> <strong>{}</strong> <time>{}</time></div><p class=\"log-outcome{}\">{}</p>",
        event.id,
        escape(&event.family.to_lowercase()),
        escape(&event.family),
        escape(short),
        escape(&event.at),
        if event.ended { " ended" } else { "" },
        outcome
    );
    if !event.subject.is_empty() {
        out.push_str(&format!("<p><small>Subject: {}</small></p>", escape(&event.subject)));
    }
    if let Some(members) = event.members.as_object().filter(|m| m.keys().any(|k| k != "subject")) {
        out.push_str("<table class=\"facts members\">");
        for (name, value) in members {
            if name == "subject" {
                continue;
            }
            let text = match value {
                Value::String(s) => s.clone(),
                Value::Object(o) if !o.is_empty() && o.values().all(|v| v.is_string()) => o.values().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(" / "),
                other => other.to_string(),
            };
            out.push_str(&format!("<tr><th>{}</th><td>{}</td></tr>", escape(name), escape(&text)));
        }
        out.push_str("</table>");
    }
    out.push_str(&format!("<p><small>jti {}</small></p></li>", escape(&event.jti)));
    out
}

/// The CAEP & RISC events tab: whose events these are, the stream and the
/// verification request, and the log, newest first, each a collapsible
/// pane. `app.js` adds what arrives without reloading.
fn events_panel(events: &[LiveEvent], stream: &str, notice: &str) -> String {
    let items: String = events.iter().rev().map(event_item).collect();
    let notice = if notice.is_empty() { String::new() } else { format!("<p class=\"notice\">{}</p>", escape(notice)) };
    // The one stream is the service provider's, so the log is too: a real
    // application shows a person only the events about their own session
    // or account, and keeps the rest from them.
    let scope = pane("events-scope", "Whose events these are", "", "<p class=\"warning\"><strong>Every event this application received, for every user.</strong> This tab lists all the CAEP and RISC events the service provider's Shared Signals stream delivered: events about other people's sessions and accounts as well as yours. That is for this demonstration only. A real application must take additional safeguards: show a person only the events about their own session or account, and keep the others to the people whose job is to see them.</p>");
    let stream_pane = pane("events-stream", "Shared Signals stream", "", &format!(
        "<table class=\"facts\"><tr><th>Stream status</th><td id=\"stream-status\">{}</td></tr><tr><th>Live</th><td id=\"live-state\">connecting…</td></tr></table>\
<form id=\"verify-form\" method=\"post\" action=\"/signals/verify\"><button type=\"submit\">Ask for a verification event</button></form>",
        escape(stream)
    ));
    let count = if events.is_empty() { String::new() } else { format!("{} event(s)", events.len()) };
    let log_pane = pane("events-log", "Event log", &count, &format!(
        "<p><small>The CAEP and RISC events this service provider's receiver has accepted, about anybody, newest first, and the verification events it asked for. Each appears here within moments of the receiver getting it.</small></p>\
<ol class=\"log\" id=\"log\">{items}</ol>\
<p class=\"empty\" id=\"log-empty\"{}>No CAEP or RISC event yet. At iya-sts, change this person's password (credential-change), sign them out (session-revoked), or disable them (account-disabled), and watch this tab.</p>",
        if events.is_empty() { "" } else { " hidden" }
    ));
    format!("{notice}{scope}{stream_pane}{log_pane}")
}

/// `GET /api/signals?after=<id>`: what arrived after the last event the
/// page shows, and the stream's state. 401 once the session is gone, which
/// `app.js` reads as signed out.
fn signals_api(app: &App, req: &Request) -> Response {
    if current_session(app, req).is_none() {
        return text(401, "application/json", &json!({"signedIn": false}).to_string());
    }
    let after = query_value(&req.query, "after").parse::<u64>().unwrap_or(0);
    let events: Vec<Value> = app.events.lock().expect("events").iter().filter(|e| e.id > after).map(event_json).collect();
    let body = json!({"events": events, "streamStatus": {"status": app.receiver_state.lock().expect("state").clone(), "at": utc(now_ms())}});
    text(200, "application/json", &body.to_string())
}

/// `POST /signals/verify`: asks the transmitter for a verification event on
/// the stream. JSON for `app.js`, a redirect back to the tab without it.
fn verify_signals(app: &App, req: &Request) -> Response {
    if current_session(app, req).is_none() {
        return Response { status: 303, headers: vec![("location".into(), "/".into())], body: Vec::new() };
    }
    let state = format!("demo-{}", app.event_seq.load(std::sync::atomic::Ordering::Relaxed) + 1);
    let outcome = match app.receiver.lock().expect("receiver").as_ref().map(|r| r.verify(&state)) {
        Some(Ok(())) => "sent",
        Some(Err(error)) => {
            println!("ssf: verification request refused: {error}");
            "refused"
        }
        None => "refused",
    };
    if req.headers.get("accept").is_some_and(|a| a.contains("application/json")) {
        text(200, "application/json", &json!({"outcome": outcome}).to_string())
    } else {
        Response { status: 303, headers: vec![("location".into(), format!("/?tab=events&verify={outcome}"))], body: Vec::new() }
    }
}

fn login(app: &App, req: &Request) -> Response {
    let sp = match provider(app) {
        Ok(sp) => sp,
        Err(error) => return page_html("Sign-in", &format!("<h1>Sign-in is not available</h1><p class=\"problem\">{}</p>", escape(&error)), 500),
    };
    let asked = query_value(&req.query, "binding");
    let response_binding = if asked == "post" || asked == "redirect" || asked == "artifact" { asked } else { String::new() };
    let nonce = b64url(&random(16));
    // The user menu's "Sign in with another account": ForceAuthn, so the
    // identity provider asks who it is even if it already knows.
    let force_authn = query_value(&req.query, "force") == "1";
    let made = sp.login(&LoginOptions { relay_state: Some("/".into()), nonce: nonce.clone(), response_binding, force_authn, ..LoginOptions::default() });
    let made = match made {
        Ok(made) => made,
        Err(error) => return page_html("Sign-in", &format!("<h1>Sign-in failed</h1><p class=\"problem\">{}</p>", escape(&error.to_string())), 400),
    };
    let pending = seal(app, &json!({"ids": [made.id]}));
    let cookie = cookie("saml_pending", &pending, &acs_path(sp), 600, "None", app.secure_cookies);
    if made.binding == "redirect" {
        return Response { status: 302, headers: vec![("location".into(), made.url), ("referrer-policy".into(), "no-referrer".into()), ("set-cookie".into(), cookie)], body: Vec::new() };
    }
    let (scheme, host, _) = split_origin(&made.url).unwrap_or_else(|| ("https".into(), "idp".into(), String::new()));
    let csp = format!("default-src 'none'; script-src 'nonce-{nonce}'; form-action {scheme}://{host}; frame-ancestors 'none'; base-uri 'none'");
    Response { status: 200, headers: vec![("content-type".into(), "text/html; charset=utf-8".into()), ("content-security-policy".into(), csp), ("set-cookie".into(), cookie)], body: made.html.into_bytes() }
}

fn acs(app: &App, req: &Request) -> Response {
    let sp = match provider(app) {
        Ok(sp) => sp,
        Err(error) => return page_html("Sign-in failed", &format!("<h1>Sign-in failed</h1><p class=\"problem\">{}</p>", escape(&error)), 400),
    };
    let body = if req.method == "POST" { AcsBody::Text(req.body.clone()) } else { AcsBody::None };
    let pending = unseal(app, &cookie_value(req, "saml_pending"));
    let mut ids = Vec::new();
    if let Some(list) = pending.get("ids").and_then(|v| v.as_array()) {
        for item in list { if let Some(text) = item.as_str() { ids.push(text.to_string()); } }
    }
    let target = if req.query.is_empty() { req.path.clone() } else { format!("{}?{}", req.path, req.query) };
    let clear = cookie("saml_pending", "", &acs_path(sp), 0, "None", app.secure_cookies);
    match sp.acs(&req.method, &target, &body, &ids) {
        Err(error) => {
            let mut response = page_html("Sign-in failed", &format!("<h1>Sign-in failed</h1><p class=\"problem\">{}</p><p><a href=\"/\">Start again</a></p>", escape(&error.to_string())), 400);
            response.headers.push(("set-cookie".into(), clear));
            response
        }
        Ok(login) => {
            let (sid, until) = remember_sign_in(app, &login);
            println!("signed in {} by {} (assertion {})", login.name_id, login.binding, login.assertion_id);
            let max_age = ((until - now_ms()) / 1000).max(0) as i64;
            Response { status: 303, headers: vec![("location".into(), "/".into()), ("set-cookie".into(), clear), ("set-cookie".into(), cookie("sid", &sid, "/", max_age, "Lax", app.secure_cookies))], body: Vec::new() }
        }
    }
}

/// A new local session for a validated sign-in: EVERY sign-in is tracked by
/// the receiver (so an event about that person can end it, and Add Subject
/// tells the transmitter about them), not only the one that started it.
fn remember_sign_in(app: &App, login: &SamlLogin) -> (String, i64) {
    let sid = b64url(&random(32));
    let mut until = now_ms() + SESSION_MS;
    if let Some(limit) = login.session_not_on_or_after_ms {
        if limit < until { until = limit; }
    }
    app.sessions.lock().expect("sessions").insert(sid.clone(), Held { login: login.clone(), expires_ms: until });
    if let Some(receiver) = app.receiver.lock().expect("receiver").as_ref() { receiver.track(&sid, login, Some(until)); }
    (sid, until)
}

fn logout(app: &App, req: &Request) -> Response {
    let sid = cookie_value(req, "sid");
    if !sid.is_empty() {
        app.sessions.lock().expect("sessions").remove(&sid);
        if let Some(receiver) = app.receiver.lock().expect("receiver").as_ref() { receiver.untrack(&sid); }
    }
    Response { status: 303, headers: vec![("location".into(), "/".into()), ("set-cookie".into(), cookie("sid", "", "/", 0, "Lax", app.secure_cookies))], body: Vec::new() }
}

fn current_session(app: &App, req: &Request) -> Option<Held> {
    let sid = cookie_value(req, "sid");
    if sid.is_empty() { return None; }
    let mut sessions = app.sessions.lock().expect("sessions");
    let found = sessions.get(&sid)?;
    if now_ms() > found.expires_ms { sessions.remove(&sid); return None; }
    Some(Held { login: found.login.clone(), expires_ms: found.expires_ms })
}

fn acs_path(sp: &ServiceProvider) -> String {
    split_origin(&sp.config.acs_url).map(|(_, _, path)| if path.is_empty() { "/".into() } else { path }).unwrap_or_else(|| "/".into())
}

fn cookie(name: &str, value: &str, path: &str, max_age: i64, same_site: &str, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("{name}={value}; Path={path}; Max-Age={max_age}; HttpOnly{secure}; SameSite={same_site}")
}

fn seal(app: &App, value: &Value) -> String {
    let raw = serde_json::to_vec(value).unwrap_or_default();
    let mut mac = Hmac::<Sha256>::new_from_slice(&app.secret).expect("hmac");
    mac.update(&raw);
    format!("{}.{}", b64url(&raw), b64url(&mac.finalize().into_bytes()))
}

fn unseal(app: &App, value: &str) -> Map<String, Value> {
    let Some((raw_b64, sig_b64)) = value.split_once('.') else { return Map::new() };
    let Ok(raw) = b64url_decode(raw_b64) else { return Map::new() };
    let Ok(sig) = b64url_decode(sig_b64) else { return Map::new() };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(&app.secret) else { return Map::new() };
    mac.update(&raw);
    if mac.verify_slice(&sig).is_err() { return Map::new(); }
    serde_json::from_slice::<Value>(&raw).ok().and_then(|v| v.as_object().cloned()).unwrap_or_default()
}

fn page_html(title: &str, body: &str, status: u16) -> Response {
    page_for(title, body, status, None)
}

/// A page, with the demo's links and the user menu in the top bar when
/// someone is signed in.
fn page_for(title: &str, body: &str, status: u16, who: Option<&SamlLogin>) -> Response {
    let menu = who.map(user_menu).unwrap_or_default();
    let nav = if who.is_some() { site_nav() } else { String::new() };
    let script = if who.is_some() { "<script src=\"/menu.js\" defer></script>" } else { "" };
    let html = format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{}</title><link rel=\"stylesheet\" href=\"/styles.css\"></head><body><header class=\"topbar\"><a href=\"/\">saml2-sp demo</a>{nav}{menu}</header><main>{body}</main><footer>A web application signing in with SAML 2.0 through saml2-sp.</footer>{script}</body></html>",
        escape(title)
    );
    let mut response = text(status, "text/html; charset=utf-8", &html);
    // connect-src 'self' is what lets pep.js fetch the tab's fragment.
    response.headers.push(("content-security-policy".into(), PAGE_CSP.into()));
    response
}

fn text(status: u16, ctype: &str, body: &str) -> Response {
    Response { status, headers: vec![("content-type".into(), ctype.to_string())], body: body.as_bytes().to_vec() }
}

fn file_response(path: &str, ctype: &str) -> Response {
    let full = std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join(path);
    match std::fs::read(full) {
        Ok(body) => Response { status: 200, headers: vec![("content-type".into(), ctype.to_string())], body },
        Err(_) => text(404, "text/plain", "not found"),
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let header_end = loop {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 { return None; }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") { break pos; }
        if buf.len() > 1024 * 1024 { return None; }
    };
    let header = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut body = buf[header_end + 4..].to_vec();
    let mut length = 0usize;
    let mut headers = HashMap::new();
    for (i, line) in header.lines().enumerate() {
        if i == 0 { continue; }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    if let Some(raw) = headers.get("content-length") { length = raw.parse().unwrap_or(0).min(512 * 1024); }
    while body.len() < length {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 { break; }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(length);
    let mut parts = header.lines().next().unwrap_or("").split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let target = parts.next().unwrap_or("/").to_string();
    let (path, query) = match target.split_once('?') { Some((p, q)) => (p.to_string(), q.to_string()), None => (target.clone(), String::new()) };
    Some(Request { method, path, query, headers, body: String::from_utf8_lossy(&body).into_owned() })
}

fn write_response(stream: &mut TcpStream, response: &Response) -> std::io::Result<()> {
    let reason = match response.status { 200 => "OK", 302 => "Found", 303 => "See Other", 400 => "Bad Request", 401 => "Unauthorized", 403 => "Forbidden", 404 => "Not Found", 500 => "Internal Server Error", 503 => "Service Unavailable", _ => "OK" };
    let mut head = format!("HTTP/1.1 {} {reason}\r\n", response.status);
    let mut saw_length = false;
    for (name, value) in &response.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
        if name.eq_ignore_ascii_case("content-length") { saw_length = true; }
    }
    if !saw_length { head.push_str(&format!("content-length: {}\r\n", response.body.len())); }
    head.push_str("connection: close\r\n\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(&response.body)?;
    stream.flush()
}

fn cookie_value(req: &Request, name: &str) -> String {
    let Some(raw) = req.headers.get("cookie") else { return String::new() };
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{name}=")) { return value.to_string(); }
    }
    String::new()
}

fn query_value(query: &str, name: &str) -> String {
    for part in query.split('&') {
        if let Some((key, value)) = part.split_once('=') {
            if key == name { return value.to_string(); }
        }
    }
    String::new()
}

fn escape(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn b64url(data: &[u8]) -> String { base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data) }

fn b64url_decode(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value)
}

fn random(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
    buf
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        App {
            port: 0, public_url: String::new(), public_given: false, config_path: "/nonexistent/saml.json".into(), secret: vec![7; 32],
            secure_cookies: false, ssf_transmitter: String::new(), ssf_poll_ms: 0, ssf_add_subjects: true, receiver: Arc::new(Mutex::new(None)),
            receiver_state: Arc::new(Mutex::new(String::new())), sessions: Arc::new(Mutex::new(HashMap::new())), events: Arc::new(Mutex::new(Vec::new())),
            event_seq: Arc::new(std::sync::atomic::AtomicU64::new(0)), sp: OnceLock::new(),
        }
    }

    /// A sign-in as iya-sts writes one: a transient NameID, and the
    /// username under uid, its OID and the AD FS name claim.
    fn alice() -> SamlLogin {
        let mut attributes = HashMap::new();
        for name in ["uid", "urn:oid:0.9.2342.19200300.100.1.1", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"] {
            attributes.insert(name.to_string(), vec!["alice".to_string()]);
        }
        attributes.insert("mail".into(), vec!["alice@example.com".into()]);
        attributes.insert("displayName".into(), vec!["<Alice> Admin".into()]);
        attributes.insert("groups".into(), vec!["staff".into(), "<admins>".into()]);
        let mut friendly = HashMap::new();
        friendly.insert("urn:oid:0.9.2342.19200300.100.1.1".to_string(), "uid".to_string());
        SamlLogin {
            name_id: "_transient-7f3a".into(), name_id_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient".into(),
            name_qualifier: String::new(), sp_name_qualifier: String::new(), session_index: "idp-session-secret-1".into(),
            session_not_on_or_after_ms: Some(now_ms() + 3_600_000), authn_instant_ms: now_ms() - 60_000,
            authn_context_class_ref: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport".into(),
            attributes, attribute_friendly_names: friendly, issuer: "https://idp.test/realm/r1".into(), in_response_to: Some("_req1".into()),
            relay_state: None, binding: "post".into(), encrypted: true, response_id: "_resp1".into(), assertion_id: "_assert1".into(),
        }
    }

    fn live(id: u64, event_type: &str, ended: bool) -> LiveEvent {
        LiveEvent {
            id, event_type: event_type.into(), jti: format!("j<{id}>"), family: family_of(event_type).into(),
            at: utc(1_795_000_000_000), subject: "format email, email <a@x>".into(),
            members: json!({"reason_admin": {"en": "<b>gone</b>"}, "subject": {"x": 1}}), ended,
        }
    }

    /// A service provider on throwaway keys, with an optional `pep` section.
    fn sp_with(pep: Option<Value>) -> ServiceProvider {
        let sp_keys = saml2_sp::create_self_signed_key_pair("sp.demo.test", 1, 2048).unwrap();
        let idp_keys = saml2_sp::create_self_signed_key_pair("idp.demo.test", 1, 2048).unwrap();
        let body: String = idp_keys.certificate_pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let metadata = format!("<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"http://127.0.0.1:9\"><md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{body}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://127.0.0.1:9/sso\"/></md:IDPSSODescriptor></md:EntityDescriptor>");
        let mut config: Map<String, Value> = serde_json::from_value(json!({
            "entityId": "http://127.0.0.1:9/saml/metadata", "acsUrl": "http://127.0.0.1:9/saml/acs",
            "privateKey": sp_keys.private_key_pem, "certificate": sp_keys.certificate_pem, "idpMetadata": metadata,
            "signals": false,
        })).unwrap();
        if let Some(pep) = pep { config.insert("pep".into(), pep); }
        ServiceProvider::create(&config, "", None).unwrap()
    }

    fn get(path: &str) -> Request {
        Request { method: "GET".into(), path: path.into(), query: String::new(), headers: HashMap::new(), body: String::new() }
    }

    #[test]
    fn the_status_routes_need_a_session() {
        let app = app();
        for path in ["/pep-status", "/pep-status.html"] {
            assert_eq!(route(&app, &get(path)).status, 401, "{path} without a session");
        }
        let page = route(&app, &get("/"));
        let csp = page.headers.iter().find(|(k, _)| k == "content-security-policy").map(|(_, v)| v.clone()).unwrap_or_default();
        assert!(csp.contains("connect-src 'self'"), "pep.js may fetch the fragment: {csp}");
    }

    #[test]
    fn signals_off_starts_no_receiver_so_no_subject_is_added() {
        // A transmitter that would be reached (and counted) if anything were sent.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut app = app();
        app.ssf_transmitter = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        start_receiver(&app, &sp_with(None));
        assert!(app.receiver.lock().unwrap().is_none(), "signals: false builds no receiver");
        assert_eq!(*app.receiver_state.lock().unwrap(), "not configured (signals are off)");
        std::thread::sleep(Duration::from_millis(200));
        assert!(listener.accept().is_err(), "nothing dialled the transmitter");
        assert!(saml2_sp::ssf_add_subjects(Some(&json!({"addSubjects": "yes"}))).is_err());
        assert_eq!(saml2_sp::ssf_add_subjects(Some(&json!({"addSubjects": false}))).ok(), Some(false));
        assert_eq!(saml2_sp::ssf_add_subjects(None).ok(), Some(true));
    }

    #[test]
    fn every_sign_in_is_tracked_by_the_receiver_and_sign_out_untracks_it() {
        let app = app();
        let receiver = SignalsReceiver::new(ReceiverOptions {
            transmitter: "http://127.0.0.1:1".into(), on_end_sessions: Some(Arc::new(|_, _| Ok(()))), ..ReceiverOptions::default()
        }).unwrap();
        *app.receiver.lock().unwrap() = Some(receiver.clone());
        let mut bob = alice();
        for values in bob.attributes.values_mut() { *values = values.iter().map(|v| v.replace("alice", "bob")).collect(); }
        bob.attributes.insert(saml2_sp::DEFAULT_SUBJECT_ATTRIBUTE.into(), vec!["urn:uuid:bob".into()]);
        let mut alice = alice();
        alice.attributes.insert(saml2_sp::DEFAULT_SUBJECT_ATTRIBUTE.into(), vec!["urn:uuid:alice".into()]);
        let (first, _) = remember_sign_in(&app, &alice);
        let (second, _) = remember_sign_in(&app, &bob);
        let (third, _) = remember_sign_in(&app, &alice);
        let index = receiver.session_index();
        for sid in [&first, &second, &third] {
            assert!(index.contains(sid), "every sign-in is tracked, not only the first");
        }
        assert_eq!(index.by_person("urn:uuid:alice").len(), 2);
        assert_eq!(index.by_email("bob@example.com"), vec![second.clone()]);
        let mut out = get("/logout");
        out.method = "POST".into();
        out.headers.insert("cookie".into(), format!("sid={second}"));
        assert_eq!(route(&app, &out).status, 303);
        assert!(!index.contains(&second) && index.contains(&first) && index.contains(&third), "sign-out untracks that session only");
    }

    #[test]
    fn durations_read_as_a_person_reads_them() {
        assert_eq!(human(None, true), "—");
        assert_eq!(human(Some(Duration::from_millis(400)), true), "just now");
        assert_eq!(human(Some(Duration::from_millis(400)), false), "now");
        assert_eq!(human(Some(Duration::from_secs(42)), true), "42 s ago");
        assert_eq!(human(Some(Duration::from_secs(300)), false), "in 5 min 0 s");
        assert_eq!(human(Some(Duration::from_secs(7300)), true), "2 h 1 min ago");
    }

    #[test]
    fn no_service_provider_or_no_pep_says_so() {
        assert!(pep_fragment(None).contains("No embedded PEP"));
        assert_eq!(pep_json(None)["enabled"], false);
    }

    #[cfg(feature = "pep")]
    #[test]
    fn the_tab_draws_every_pane_and_escapes() {
        let key = std::env::temp_dir().join(format!("saml-demo-pep-{}.pem", std::process::id()));
        std::fs::write(&key, rcgen::KeyPair::generate().unwrap().serialize_pem()).unwrap();
        let sp = sp_with(Some(json!({"name": "pep-demo", "application": "orders<&\"app\">", "mode": "central", "assertionKey": key.to_string_lossy(), "timeoutMs": 300})));
        let _ = std::fs::remove_file(&key);
        let login = SamlLogin {
            name_id: "alice".into(), name_id_format: String::new(), name_qualifier: String::new(), sp_name_qualifier: String::new(),
            session_index: String::new(), session_not_on_or_after_ms: None, authn_instant_ms: 0, authn_context_class_ref: String::new(),
            attributes: HashMap::new(), attribute_friendly_names: HashMap::new(), issuer: String::new(), in_response_to: None,
            relay_state: None, binding: "post".into(), encrypted: false, response_id: String::new(), assertion_id: String::new(),
        };
        sp.decide(&login, &saml2_sp::pep::Access::new("read", "order", "1"));
        let html = pep_fragment(Some(&sp));
        for (title, id) in [("Decisions", "pep-decisions"), ("Cached policy", "pep-cached-policy"), ("The PEP", "pep-the-pep"), ("Control plane", "pep-control-plane")] {
            assert!(html.contains(&format!("<details class=\"card pane\" id=\"{id}\" open><summary><h2>{title}</h2></summary>")), "{title} is a collapsible pane with the id pep.js keeps it closed by");
        }
        assert!(html.contains("<th>Decisions</th><td>1</td>"), "the decision was counted");
        assert!(html.contains("<th>Unavailable (no decision; refused)</th><td>1</td>"));
        assert!(html.contains("class=\"problem\""), "iya-sts is unreachable, and the tab says so");
        assert!(html.contains("Permit cache"), "central mode shows the cache");
        assert!(html.contains("<td>orders&lt;&amp;&quot;app&quot;&gt;</td>") && !html.contains("orders<&"), "the application is escaped");
        assert!(!html.contains("<script"), "the fragment carries no script");
        assert!(html.contains("<details class=\"card pane\" id=\"pep-problems\" open>"), "the problem is a pane too");
        assert!(html.contains("<details class=\"card pane\" id=\"pep-try\" open>") && html.contains("href=\"/attribute-protected\"") && html.contains("href=\"/orders/42\""), "Try it links the two protected pages");
        let v = pep_json(Some(&sp));
        assert_eq!((v["enabled"].clone(), v["mode"].clone(), v["decisions"]["unavailable"].clone()), (json!(true), json!("central"), json!(1)));
    }

    #[test]
    fn the_events_tab_draws_each_event_newest_first_and_escapes() {
        let caep = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
        let risc = "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
        let html = events_panel(&[live(1, caep, true), live(2, risc, false)], "polling <s>", "");
        assert!(html.find("data-id=\"2\"").unwrap() < html.find("data-id=\"1\"").unwrap(), "newest first");
        assert!(html.contains("<span class=\"badge caep\">CAEP</span> <strong>session-revoked</strong>"));
        assert!(html.contains("<span class=\"badge risc\">RISC</span>"));
        assert!(html.contains("ended this session") && html.contains("recorded; this session continues"));
        assert!(html.contains("&lt;b&gt;gone&lt;/b&gt;") && !html.contains("<b>gone"), "members escaped");
        assert!(html.contains("polling &lt;s&gt;") && html.contains("j&lt;1&gt;") && html.contains("&lt;a@x&gt;"));
        assert!(!html.contains("<th>subject</th>"), "the subject member is the Subject line, not a row");
        assert!(html.contains("id=\"log-empty\" hidden"), "the empty note hidden once there are events");
        assert!(events_panel(&[], "", "").contains("id=\"log-empty\">"), "and shown when there are none");
        let empty = events_panel(&[], "", "refused <x>");
        assert!(empty.contains("<p class=\"warning\"><strong>Every event this application received, for every user.</strong>") && empty.contains("additional safeguards"), "it says whose events these are, with or without any");
        assert!(empty.contains("refused &lt;x&gt;"));
        for id in ["events-scope", "events-stream", "events-log"] {
            assert!(html.contains(&format!("<details class=\"card pane\" id=\"{id}\" open>")), "{id} is a collapsible pane");
        }
        assert!(html.contains("id=\"live-state\"") && html.contains("id=\"stream-status\"") && html.contains("id=\"verify-form\"") && html.contains("id=\"log\""), "app.js finds what it updates");
    }

    #[test]
    fn a_received_event_is_kept_and_handed_to_app_js_in_the_shape_it_reads() {
        let events = Mutex::new(Vec::new());
        let seq = std::sync::atomic::AtomicU64::new(0);
        let mut payload = Map::new();
        payload.insert("reason_admin".into(), json!({"en": "x"}));
        let mut subject = HashMap::new();
        subject.insert("format".to_string(), "email".to_string());
        let signal = SignalEvent { event_type: "https://schemas.openid.net/secevent/ssf/event-type/verification".into(), payload, subject, jti: "j1".into(), sessions: Vec::new(), ended: false, iat: Some(1_795_000_000.0), txn: None };
        for _ in 0..(MAX_EVENTS + 3) {
            remember_live_event(&events, &seq, &signal);
        }
        let kept = events.lock().unwrap();
        assert_eq!(kept.len(), MAX_EVENTS, "the oldest go first");
        assert_eq!(kept.last().unwrap().id, MAX_EVENTS as u64 + 3, "ids keep counting");
        let e = event_json(kept.last().unwrap());
        assert_eq!((e["family"].clone(), e["about"].clone(), e["jti"].clone()), (json!("SSF"), json!("stream"), json!("j1")));
        assert_eq!(e["at"], "2026-11-18 11:06:40 UTC");
        assert_eq!(e["subject"], "format email");
        assert_eq!(family_of("urn:iya:sts:secevent:event-type:pep-policies-changed"), "STS");
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!((in_words(90_000), in_words(-3_700_000)), ("1m 30s".to_string(), "1h 1m ago".to_string()));
    }

    #[test]
    fn the_signals_routes_need_a_session() {
        let app = app();
        assert_eq!(route(&app, &get("/api/signals")).status, 401);
        let mut post = get("/signals/verify");
        post.method = "POST".into();
        let answer = route(&app, &post);
        assert_eq!((answer.status, answer.headers.iter().find(|(k, _)| k == "location").map(|(_, v)| v.as_str())), (303, Some("/")));
        assert_eq!(route(&app, &get("/events")).status, 204, "no SSE: app.js polls instead");
        #[cfg(feature = "pep")]
        assert_eq!(route(&app, &get("/attribute-protected")).status, 401, "the PEP's pages need a sign-in first");
    }

    #[test]
    fn the_name_shown_is_the_username_never_the_nameid_when_there_is_one() {
        let login = alice();
        assert_eq!(display_name(&login), "alice", "the uid attribute, not the transient NameID");
        let menu = user_menu(&login);
        assert!(menu.contains("title=\"alice\">alice</span>") && menu.contains("Sign out alice"), "{menu}");
        assert!(menu.contains("<span class=\"avatar\" aria-hidden=\"true\">A</span>"));
        assert!(menu.contains("&lt;Alice&gt; Admin") && !menu.contains("<Alice>"), "the display name is the detail line, escaped");
        assert!(menu.contains("href=\"/login?force=1\""), "another account: ForceAuthn");
        assert!(menu.contains("<form method=\"post\" action=\"/logout\"><button class=\"menu-row\""), "sign out is a POST, in the menu");
        let mut mail_only = alice();
        mail_only.attributes.retain(|k, _| k == "mail");
        assert_eq!(display_name(&mail_only), "alice@example.com", "no username: the email");
        mail_only.attributes.clear();
        assert_eq!(display_name(&mail_only), "_transient-7f3a", "the NameID only when nothing else names them");
        let mut preferred = alice();
        preferred.attributes.insert("preferred_username".into(), vec!["al".into()]);
        assert_eq!(display_name(&preferred), "al", "preferred_username before uid");
    }

    #[test]
    fn the_top_bar_links_the_demo_pages_and_holds_the_menu_once_signed_in() {
        let html = |r: Response| String::from_utf8(r.body).unwrap();
        let signed_in = html(page_for("t", "", 200, Some(&alice())));
        assert!(signed_in.contains("class=\"site-nav\"") && signed_in.contains("href=\"/\">Demo home</a>"), "{signed_in}");
        #[cfg(feature = "pep")]
        assert!(signed_in.contains("href=\"/attribute-protected\"") && signed_in.contains("href=\"/orders/42\""), "{signed_in}");
        assert!(signed_in.contains("acct-menu") && signed_in.contains("/menu.js"));
        let anonymous = html(page_html("t", "", 200));
        assert!(!anonymous.contains("site-nav") && !anonymous.contains("acct-menu") && !anonymous.contains("/logout"), "nothing to link to before a sign-in");
        let home = html(route(&app(), &get("/")));
        assert!(!home.contains("action=\"/logout\""), "sign-out is only in the menu");
    }

    #[test]
    fn the_session_tab_shows_the_assertion_never_its_secrets() {
        let sp = sp_with(None);
        let login = alice();
        let facts = SessionFacts { sid: "the-session-cookie-value", expires_ms: now_ms() + 3_600_000, held: 1, tracked: Some(true), secure_cookies: true };
        let html = session_panes(&sp, &login, &facts, "polling <stream>");
        for id in ["security-card", "session-card", "cache-card", "credentials-card"] {
            assert!(html.contains(&format!("<details class=\"card pane\" id=\"{id}\" open>")), "{id} is a collapsible pane");
        }
        assert!(!html.contains("the-session-cookie-value") && html.contains(&fingerprint(b"the-session-cookie-value")), "the cookie by its fingerprint");
        assert!(!html.contains("idp-session-secret-1") && html.contains(&fingerprint(b"idp-session-secret-1")), "the SessionIndex by its fingerprint");
        assert!(html.contains(&fingerprint(&sp.idp.certs[0])), "the identity provider's signing certificate, by fingerprint");
        assert!(html.contains("<th>groups</th><td>staff, &lt;admins&gt;</td>"), "every attribute, escaped: {html}");
        assert!(html.contains("<th>urn:oid:0.9.2342.19200300.100.1.1 <small>(uid)</small></th>"), "with its FriendlyName");
        assert!(html.contains("_assert1") && html.contains("_resp1") && html.contains("yes (EncryptedAssertion)"));
        assert!(html.contains("AudienceRestriction must name http://127.0.0.1:9/saml/metadata"));
        assert!(html.contains("polling &lt;stream&gt;") && html.contains("HttpOnly, SameSite=Lax, Secure"));
        assert!(html.contains("the assertion&#39;s SessionNotOnOrAfter") || html.contains("the assertion's SessionNotOnOrAfter"), "the session ends with the assertion's limit");
        assert!(html.find(">groups<").unwrap() < html.find(">mail<").unwrap(), "attributes sorted by name");
    }

    #[test]
    fn the_panes_toggle_ships_hidden_and_every_script_keeps_its_names_to_itself() {
        let main = include_str!("demo.rs");
        assert!(main.contains("id=\\\"panes-toggle\\\" hidden>Collapse all"), "hidden until panes.js shows it");
        let panes = include_str!("../../demo/public/panes.js");
        assert!(panes.contains("panes-toggle") && panes.contains("Expand all") && panes.contains("panes-redrawn"));
        assert!(include_str!("../../demo/public/pep.js").contains("panes-redrawn"), "pep.js tells the toggle when it redrew");
        // The page's scripts share one global scope: two top-level `const`s of
        // one name make the later script fail to load. Each is its own function.
        for (name, src) in [("app.js", include_str!("../../demo/public/app.js")), ("pep.js", include_str!("../../demo/public/pep.js")), ("panes.js", panes), ("menu.js", include_str!("../../demo/public/menu.js"))] {
            let code: Vec<&str> = src.lines().filter(|l| !l.trim_start().starts_with("//") && !l.trim().is_empty()).collect();
            assert_eq!(code.first().copied(), Some("(() => {"), "{name} opens its own scope");
            assert_eq!(code.last().copied(), Some("})();"), "{name} closes it");
        }
        assert!(include_str!("../../demo/public/styles.css").contains("[hidden] { display: none !important; }"), "hidden hides a button too");
    }

    /// The demo's two PEP-protected pages through `route()`, decided by a
    /// `local` PEP holding the demo application's own policy: the XACML
    /// iya-sts stores for the install script's `orders_policy()` ALFA
    /// (`src/authzen/demo-orders.xml`; the live `--pep` run checks it is
    /// what iya-sts stored). The stub PDP below is iya-sts's side for one
    /// realm: the PEP's token, registration and heartbeat, the catalogue
    /// (the install script's one row, `subject.acr` -> `urn:example:acr`),
    /// the bound-application pull, and the PIP, which answers `attr1` per
    /// person from its own directory: the assertion never carries it.
    #[cfg(feature = "local")]
    mod protected_pages {
        use super::*;
        use saml2_sp::pep::Access;

        const ORDERS_XML: &str = include_str!("../authzen/demo-orders.xml");
        const ATTR1: &str = "urn:sts:xacml:attribute:attr1";

        /// The PIP's directory: attr1 per username (none for carol).
        fn attr1_of(user: &str) -> Option<&'static str> {
            match user {
                "alice" => Some("abc123"),
                "bob" => Some("not-abc123"),
                _ => None,
            }
        }

        struct Stub {
            url: String,
            /// Each PIP query: the subject and the attribute ids asked for.
            pip: Arc<Mutex<Vec<(String, Vec<String>)>>>,
        }

        fn answer(req: &Request, policies_up: bool, pip: &Mutex<Vec<(String, Vec<String>)>>) -> Response {
            let path = req.path.trim_start_matches("/realm/demo");
            let write = |status: u16, value: Value| text(status, "application/json", &value.to_string());
            if path != "/oauth2/token" && !req.headers.get("authorization").is_some_and(|a| a.starts_with("DPoP ")) {
                return write(401, json!({"error": "invalid_token"}));
            }
            match path {
                "/oauth2/token" => write(200, json!({"access_token": "demo-pep-token", "token_type": "DPoP", "expires_in": 300})),
                "/xacml/pep/register" => write(201, json!({"registered": true, "identity": "uid=pep-saml-demo,ou=users,dc=demo"})),
                "/xacml/pep/heartbeat" => write(200, json!({"acknowledged": true, "current": true})),
                "/xacml/pep/authzen-catalogue" => write(200, json!({"syncToken": "c1", "realm": "demo",
                    "rows": [{"object": "subject", "property": "acr", "attributeId": "urn:example:acr"}],
                    "fgaApplications": ["http://127.0.0.1:9/saml/metadata"], "settings": {"obligationsProfile": false}})),
                "/xacml/pep/policies" if policies_up => write(200, json!({"syncToken": "p1", "scope": "bound-application", "source": "application",
                    "policies": [{"name": "saml2-sp demo", "policyId": "urn:saml-sp-demo:samlspdemo:orders", "kind": "Policy", "version": "1.0",
                        "isRoot": true, "description": "", "document": ORDERS_XML}], "withheld": [], "note": ""})),
                "/xacml/pep/policies" => write(503, json!({"error": "server_error", "error_description": "not now"})),
                "/xacml/pip" => {
                    let subject = regex::Regex::new(r#"subject-id"[^>]*>\s*<AttributeValue[^>]*>([^<]*)<"#).unwrap();
                    let designator = regex::Regex::new(r#"<AttributeDesignator[^>]*Category="([^"]*)"[^>]*AttributeId="([^"]*)"[^>]*DataType="([^"]*)""#).unwrap();
                    let user = subject.captures(&req.body).map(|c| c[1].to_string()).unwrap_or_default();
                    let asked: Vec<_> = designator.captures_iter(&req.body).map(|c| (c[1].to_string(), c[2].to_string(), c[3].to_string())).collect();
                    pip.lock().unwrap().push((user.clone(), asked.iter().map(|a| a.1.clone()).collect()));
                    let mut out = String::from("<PIPResponse xmlns=\"urn:sts:xacml:pip:1.0\">");
                    for (category, id, data_type) in &asked {
                        if let (true, Some(value)) = (id == ATTR1, attr1_of(&user)) {
                            out.push_str(&format!("<Attributes xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" Category=\"{category}\"><Attribute AttributeId=\"{id}\" IncludeInResult=\"false\"><AttributeValue DataType=\"{data_type}\">{value}</AttributeValue></Attribute></Attributes>"));
                        }
                    }
                    out.push_str("</PIPResponse>");
                    text(200, "application/xml", &out)
                }
                "/admin-api/pep-audit" => write(200, json!({"acknowledged": 0})),
                _ => write(404, json!({"error": "not_found"})),
            }
        }

        fn stub(policies_up: bool) -> Stub {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://127.0.0.1:{}/realm/demo", listener.local_addr().unwrap().port());
            let pip = Arc::new(Mutex::new(Vec::new()));
            let log = pip.clone();
            std::thread::spawn(move || {
                for conn in listener.incoming() {
                    let Ok(mut stream) = conn else { continue };
                    let log = log.clone();
                    std::thread::spawn(move || {
                        if let Some(req) = read_request(&mut stream) {
                            let _ = write_response(&mut stream, &answer(&req, policies_up, &log));
                        }
                    });
                }
            });
            Stub { url, pip }
        }

        /// The demo with a `local` PEP on the stub, as the install script's
        /// `--pep local` configures it (the PEP's own key, `application` = entityId).
        fn demo(policies_up: bool) -> (App, Stub) {
            let stub = stub(policies_up);
            let key = std::env::temp_dir().join(format!("saml-demo-pages-{}-{}.pem", std::process::id(), b64url(&random(9))));
            std::fs::write(&key, rcgen::KeyPair::generate().unwrap().serialize_pem()).unwrap();
            let sp = sp_with(Some(json!({"name": "pep-saml-demo", "mode": "local", "assertionKey": key.to_string_lossy(), "pdpUrl": stub.url,
                "heartbeatIntervalMs": 60000, "pollIntervalMs": 60000, "decisionRecords": false})));
            let _ = std::fs::remove_file(&key);
            if policies_up {
                let pep = sp.pep().expect("a pep section makes a PEP");
                let deadline = std::time::Instant::now() + Duration::from_secs(20);
                while !pep.status().holds_policy {
                    assert!(std::time::Instant::now() < deadline, "the local PEP never held the demo's policy: {}", pep.status().last_error);
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            let app = app();
            assert!(app.sp.set(Ok(sp)).is_ok());
            (app, stub)
        }

        /// A sign-in as iya-sts writes one, for `user`, with or without an
        /// AuthnContextClassRef. attr1 is never in it.
        fn person(user: &str, with_acr: bool) -> SamlLogin {
            let mut login = alice();
            for values in login.attributes.values_mut() {
                *values = values.iter().map(|v| v.replace("alice", user)).collect();
            }
            if !with_acr {
                login.authn_context_class_ref.clear();
            }
            assert!(!login.attributes.keys().any(|k| k.contains("attr1")));
            login
        }

        /// A browser holding a session for `login`.
        fn signed_in(app: &App, login: &SamlLogin) -> String {
            let sid = b64url(&random(16));
            app.sessions.lock().unwrap().insert(sid.clone(), Held { login: login.clone(), expires_ms: now_ms() + 3_600_000 });
            sid
        }

        fn request(method: &str, path: &str, sid: Option<&str>) -> Request {
            let mut req = get(path);
            req.method = method.into();
            if let Some(sid) = sid {
                req.headers.insert("cookie".into(), format!("sid={sid}"));
            }
            req
        }

        /// One request through the demo's router; the status must be what
        /// the PEP's decision maps to (`http_status()`) and `want`.
        fn check(app: &App, method: &str, path: &str, login: &SamlLogin, access: Access, want: u16) -> String {
            let sid = signed_in(app, login);
            let answer = route(app, &request(method, path, Some(&sid)));
            let body = String::from_utf8(answer.body).unwrap();
            let decided = provider(app).unwrap().decide(login, &access).http_status();
            assert_eq!(answer.status, decided, "{method} {path}: the page's status is the decision's http_status()");
            assert_eq!(answer.status, want, "{method} {path} for {}: {body}", display_name(login));
            assert!(body.contains("class=\"site-nav\"") && body.contains("acct-menu"), "a signed-in page, with the top bar");
            body
        }

        fn read_order() -> Access { Access::new("read", "order", "42") }
        fn write_order() -> Access { Access::new("write", "order", "42") }
        fn read_attribute() -> Access { Access::new("read", "attribute-protected", "attr1") }

        #[test]
        fn an_allowed_user_reads_both_protected_pages() {
            let (app, stub) = demo(true);
            let alice = person("alice", true);
            let page = check(&app, "GET", "/attribute-protected", &alice, read_attribute(), 200);
            assert!(page.contains("<title>Attribute-protected</title>") && page.contains("<h1>Allowed</h1>") && page.contains("The PEP permitted it: your <code>attr1</code> is <code>abc123</code>."), "{page}");
            let order = check(&app, "GET", "/orders/42", &alice, read_order(), 200);
            assert!(order.contains("<h1>Order 42</h1>") && order.contains("The PEP permitted <code>read</code>."), "{order}");
            let asked = stub.pip.lock().unwrap().clone();
            assert!(asked.iter().any(|(user, ids)| user == "alice" && ids.iter().any(|id| id == ATTR1)), "attr1 came from the PIP, for alice: {asked:?}");
        }

        #[test]
        fn a_denied_user_is_403_on_attribute_protected_whatever_else_attr1_is_or_without_it() {
            let (app, _stub) = demo(true);
            for user in ["bob", "carol"] {
                let login = person(user, true);
                let page = check(&app, "GET", "/attribute-protected", &login, read_attribute(), 403);
                assert!(page.contains("<title>Forbidden</title>") && page.contains("<h1>Not allowed</h1>") && page.contains("The PEP denied it"), "{user}: {page}");
                assert!(!page.contains("<h1>Allowed</h1>"));
                // attr1 has nothing to do with orders: reading one is still allowed.
                let order = check(&app, "GET", "/orders/42", &login, read_order(), 200);
                assert!(order.contains("<h1>Order 42</h1>"), "{user}: {order}");
            }
        }

        #[test]
        fn writing_an_order_is_403_even_for_the_allowed_user() {
            let (app, _stub) = demo(true);
            let alice = person("alice", true);
            let page = check(&app, "POST", "/orders/42", &alice, write_order(), 403);
            assert!(page.contains("<title>Forbidden</title>") && page.contains("The PEP denied <code>write</code> on order 42"), "{page}");
            // Any method but GET is write.
            check(&app, "DELETE", "/orders/42", &alice, write_order(), 403);
        }

        #[test]
        fn a_sign_in_without_an_authn_context_class_ref_cannot_read_an_order() {
            let (app, _stub) = demo(true);
            let alice = person("alice", false);
            let order = check(&app, "GET", "/orders/42", &alice, read_order(), 403);
            assert!(order.contains("The PEP denied <code>read</code> on order 42"), "{order}");
            // attr1 is still abc123, and that page does not need the claim.
            check(&app, "GET", "/attribute-protected", &alice, read_attribute(), 200);
        }

        #[test]
        fn signed_out_is_401_on_both_protected_pages() {
            let (app, _stub) = demo(true);
            for (method, path) in [("GET", "/attribute-protected"), ("GET", "/orders/42"), ("POST", "/orders/42")] {
                for sid in [None, Some("no-such-session")] {
                    let answer = route(&app, &request(method, path, sid));
                    let body = String::from_utf8(answer.body).unwrap();
                    assert_eq!(answer.status, 401, "{method} {path} without a sign-in: {body}");
                    assert!(body.contains("<h1>Sign in first</h1>") && body.contains("href=\"/login\""), "{body}");
                    assert!(!body.contains("acct-menu"), "no one to name");
                }
            }
            // Signing out ends it: the same browser is 401 again.
            let sid = signed_in(&app, &person("alice", true));
            assert_eq!(route(&app, &request("GET", "/attribute-protected", Some(&sid))).status, 200);
            assert_eq!(route(&app, &request("POST", "/logout", Some(&sid))).status, 303);
            assert_eq!(route(&app, &request("GET", "/attribute-protected", Some(&sid))).status, 401);
            assert_eq!(route(&app, &request("GET", "/orders/42", Some(&sid))).status, 401);
        }

        #[test]
        fn a_pep_that_cannot_decide_is_403_on_both_pages() {
            // The pull fails, so the local PEP holds no policy: Unavailable.
            let (app, _stub) = demo(false);
            let alice = person("alice", true);
            for (path, access) in [("/attribute-protected", read_attribute()), ("/orders/42", read_order())] {
                let page = check(&app, "GET", path, &alice, access, 403);
                assert!(page.contains("<h1>No decision</h1>") && page.contains("The PEP could not decide"), "{path}: {page}");
            }
        }

        #[test]
        fn the_policy_document_is_the_install_scripts_policy() {
            let script = include_str!("../../scripts/configure_iya_sts.py");
            for (constant, value) in [("ACR_ATTRIBUTE", "urn:example:acr"), ("TEST_ATTRIBUTE_VALUE", "abc123"), ("ATTRIBUTE_PROTECTED", "attribute-protected")] {
                assert!(script.contains(&format!("{constant} = \"{value}\"")), "{constant} is still {value} in the install script");
                assert!(ORDERS_XML.contains(&format!(">{value}<")) || ORDERS_XML.contains(&format!("\"{value}\"")), "{value} is in the policy document");
            }
            assert!(script.contains("OWN_POLICY_IDS = (\"urn:saml-sp-demo:samlspdemo:orders\",)") && ORDERS_XML.contains("PolicyId=\"urn:saml-sp-demo:samlspdemo:orders\""));
            assert!(ORDERS_XML.contains(ATTR1) && ORDERS_XML.contains("string-bag-size"));
        }
    }
}
