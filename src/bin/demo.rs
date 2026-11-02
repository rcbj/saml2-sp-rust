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
use saml2_sp::{AcsBody, LoginOptions, ReceiverOptions, SamlLogin, ServiceProvider, SignalsReceiver, TlsOptions};
use serde_json::{json, Map, Value};
use sha2::Sha256;

const SESSION_MS: i64 = 8 * 60 * 60 * 1000;

struct Held { login: SamlLogin, expires_ms: i64 }

struct App {
    port: u16,
    public_url: String,
    public_given: bool,
    config_path: String,
    secret: Vec<u8>,
    secure_cookies: bool,
    ssf_transmitter: String,
    ssf_poll_ms: u64,
    receiver: Arc<Mutex<Option<SignalsReceiver>>>,
    receiver_state: Arc<Mutex<String>>,
    sessions: Arc<Mutex<HashMap<String, Held>>>,
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
        port, public_url, public_given, config_path, secret, secure_cookies, ssf_transmitter, ssf_poll_ms,
        receiver: Arc::new(Mutex::new(None)), receiver_state: Arc::new(Mutex::new(receiver_state)), sessions: Arc::new(Mutex::new(HashMap::new())),
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

fn provider(app: &App) -> Result<&'static ServiceProvider, String> {
    static SP: OnceLock<Result<ServiceProvider, String>> = OnceLock::new();
    SP.get_or_init(|| {
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
    let mut tls = TlsOptions { cert: sp.config.certificate_pem.clone(), key: sp.config.private_key_pem.clone(), ca: String::new() };
    if !sp.config.idp_ca.is_empty() { tls.ca = sp.config.idp_ca.clone(); }
    let entity = sp.config.entity_id.clone();
    let sessions = app.sessions.clone();
    let built = SignalsReceiver::new(ReceiverOptions {
        transmitter: app.ssf_transmitter.clone(),
        tls: Some(tls),
        description: format!("saml2-sp demo ({entity})"),
        poll_interval_ms: app.ssf_poll_ms,
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
    match req.path.as_str() {
        "/styles.css" => return file_response("demo/public/styles.css", "text/css"),
        "/app.js" => return file_response("demo/public/app.js", "text/javascript"),
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
    text(404, "text/plain", "not found")
}

fn page(app: &App, req: &Request) -> Response {
    let mut problem = String::new();
    if let Err(error) = provider(app) {
        problem = format!("The service provider is not configured yet: {error}. Run the setup script (python scripts/configure_iya_sts.py).");
    }
    let current = current_session(app, req);
    let mut body = "<h1>SAML service provider</h1>".to_string();
    if !problem.is_empty() && current.is_none() { body.push_str(&format!("<p class=\"problem\">{}</p>", escape(&problem))); }
    let state = app.receiver_state.lock().expect("state").clone();
    body.push_str(&format!("<p>Shared Signals: {}</p>", escape(&state)));
    if let Some(current) = current {
        body.push_str(&format!("<p>Signed in as <strong>{}</strong> ({}).</p>", escape(&current.login.name_id), escape(&current.login.binding)));
        body.push_str("<form method=\"post\" action=\"/logout\"><button type=\"submit\">Log out</button></form>");
    } else if problem.is_empty() {
        body.push_str("<p><a href=\"/login\">Sign in</a></p>");
    }
    page_html("saml2-sp", &body, 200)
}

fn login(app: &App, req: &Request) -> Response {
    let sp = match provider(app) {
        Ok(sp) => sp,
        Err(error) => return page_html("Sign-in", &format!("<h1>Sign-in is not available</h1><p class=\"problem\">{}</p>", escape(&error)), 500),
    };
    let asked = query_value(&req.query, "binding");
    let response_binding = if asked == "post" || asked == "redirect" || asked == "artifact" { asked } else { String::new() };
    let nonce = b64url(&random(16));
    let made = sp.login(&LoginOptions { relay_state: Some("/".into()), nonce: nonce.clone(), response_binding, ..LoginOptions::default() });
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
            let sid = b64url(&random(32));
            let mut until = now_ms() + SESSION_MS;
            if let Some(limit) = login.session_not_on_or_after_ms {
                if limit < until { until = limit; }
            }
            app.sessions.lock().expect("sessions").insert(sid.clone(), Held { login: login.clone(), expires_ms: until });
            if let Some(receiver) = app.receiver.lock().expect("receiver").as_ref() { receiver.track(&sid, &login, Some(until)); }
            println!("signed in {} by {} (assertion {})", login.name_id, login.binding, login.assertion_id);
            let max_age = ((until - now_ms()) / 1000).max(0) as i64;
            Response { status: 303, headers: vec![("location".into(), "/".into()), ("set-cookie".into(), clear), ("set-cookie".into(), cookie("sid", &sid, "/", max_age, "Lax", app.secure_cookies))], body: Vec::new() }
        }
    }
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
    let html = format!("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{}</title><link rel=\"stylesheet\" href=\"/styles.css\"></head><body>{body}</body></html>", escape(title));
    text(status, "text/html; charset=utf-8", &html)
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
    let reason = match response.status { 200 => "OK", 302 => "Found", 303 => "See Other", 400 => "Bad Request", 404 => "Not Found", 500 => "Internal Server Error", _ => "OK" };
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
