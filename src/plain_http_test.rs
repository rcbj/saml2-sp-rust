// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! Plain http is refused for every fetch (metadata, ArtifactResolve, the
//! Shared Signals transmitter) unless the host is loopback, before any
//! connection is opened, and the refusal names only the scheme and host.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde_json::{json, Map};

use crate::error::SamlError;
use crate::receiver::{Logger, ReceiverOptions, SignalsReceiver};
use crate::{AcsBody, ServiceProvider};

use super::support::*;

const REFUSED: &str = "is refused: plain http is allowed only to a loopback host";

struct Quiet;
impl Logger for Quiet {
    fn info(&self, _: &str) {}
    fn warn(&self, _: &str) {}
    fn error(&self, _: &str) {}
}

fn sp_from(metadata_url: &str) -> Result<ServiceProvider, SamlError> {
    let mut config = test_config(Map::new(), "");
    config.insert("idpMetadata".into(), json!(metadata_url));
    ServiceProvider::create(&config, "", None)
}

fn resolve(ars_url: &str) -> Result<(), SamlError> {
    let sp = must_sp(Map::new(), ars_url);
    let artifact = artifact_for("");
    sp.acs("GET", &format!("/saml/acs?SAMLart={}", crate::bindings::uri_escape(&artifact)), &AcsBody::None, &["_r".into()]).map(|_| ())
}

fn start_receiver(transmitter: &str) -> Result<(), SamlError> {
    let rx = SignalsReceiver::new(ReceiverOptions {
        transmitter: transmitter.to_string(),
        on_end_sessions: Some(Arc::new(|_, _| Ok(()))),
        poll_interval_ms: 60_000,
        log: Some(Arc::new(Quiet)),
        ..ReceiverOptions::default()
    })?;
    let result = rx.start();
    rx.stop();
    result
}

fn failure<T>(result: Result<T, SamlError>) -> SamlError {
    match result {
        Err(err) => err,
        Ok(_) => panic!("expected an error"),
    }
}

fn refused<T>(result: Result<T, SamlError>, code: &str, shown: &str) -> SamlError {
    let err = failure(result);
    assert_eq!(err.code, code, "{}", err.message);
    assert!(err.message.starts_with(&format!("{shown} {REFUSED}")), "{}", err.message);
    assert!(!err.message.contains("s3cret"), "{}", err.message);
    for part in ["/md", "/ars", "/ssf", "token="] {
        assert!(!err.message.contains(part), "{}", err.message);
    }
    err
}

/// A loopback server that counts requests and answers each path's fixed way.
fn counting_server(hits: Arc<AtomicUsize>) -> TestServer {
    serve(Arc::new(move |req| {
        hits.fetch_add(1, Ordering::SeqCst);
        if req.path == "/md" {
            (200, "application/samlmetadata+xml", idp_metadata("").into_bytes())
        } else {
            (404, "text/plain", Vec::new())
        }
    }))
}

#[test]
fn refuses_plain_http_metadata_off_loopback() {
    refused(sp_from("http://example.com/saml2/metadata?token=s3cret"), "metadata", "http://example.com");
}

#[test]
fn refuses_a_plain_http_artifact_resolution_service_off_loopback() {
    refused(resolve("http://example.com/saml2/ars"), "artifact", "http://example.com");
}

#[test]
fn refuses_a_plain_http_transmitter_off_loopback() {
    refused(start_receiver("http://example.com/ssf"), "ssf", "http://example.com");
}

#[test]
fn refuses_before_connecting() {
    // On Linux http://0.0.0.0:<port> reaches a listener on 127.0.0.1, so an
    // empty backlog on this listener proves no connection was opened.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let plain = format!("http://0.0.0.0:{}", listener.local_addr().unwrap().port());
    refused(sp_from(&format!("{plain}/md")), "metadata", &plain);
    refused(resolve(&format!("{plain}/ars")), "artifact", &plain);
    refused(start_receiver(&plain), "ssf", &plain);
    listener.set_nonblocking(true).unwrap();
    thread::sleep(Duration::from_millis(200));
    assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock), "a refused fetch opened a connection");
}

#[test]
fn userinfo_is_never_loopback_and_never_shown() {
    let hits = Arc::new(AtomicUsize::new(0));
    let server = counting_server(hits.clone());
    let origin = server.url.trim_start_matches("http://").to_string();
    let err = refused(sp_from(&format!("http://alice:s3cret@{origin}/md")), "metadata", &format!("http://{origin}"));
    assert!(!err.message.contains("alice"), "{}", err.message);
    refused(sp_from("http://localhost:80@example.com/md"), "metadata", "http://example.com");
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[test]
fn refuses_a_redirect_to_plain_http_off_loopback() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"HTTP/1.1 302 Found\r\nlocation: http://example.com/md\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        }
    });
    refused(sp_from(&format!("http://127.0.0.1:{port}/away")), "metadata", "http://example.com");
}

#[test]
fn refuses_whitespace_or_control_characters() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    for url in [
        format!("http://127.0.0.1:{port}/m\td"),
        format!("http://127.0.0.1:{port}/m d"),
        format!("http://local\nhost:{port}/md"),
        format!("https://127.0.0.1:{port}/m\r\nd"),
        format!("http://127.0.0.1:{port}/md\u{7f}"),
    ] {
        let err = failure(sp_from(&url));
        assert_eq!(err.code, "metadata", "{}", err.message);
        assert!(err.message.contains("whitespace or a control character"), "{}", err.message);
    }
    for transmitter in [format!("http://127.0.0.1:{port}/s\tsf"), format!("http://127.0.0.1:{port}/s sf")] {
        let err = failure(start_receiver(&transmitter));
        assert_eq!(err.code, "ssf", "{}", err.message);
    }
    let err = failure(resolve(&format!("http://127.0.0.1:{port}/a\nrs")));
    assert_eq!(err.code, "artifact", "{}", err.message);
    listener.set_nonblocking(true).unwrap();
    thread::sleep(Duration::from_millis(200));
    assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock), "a refused fetch opened a connection");
}

#[test]
fn refuses_a_redirect_holding_whitespace() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(b"HTTP/1.1 302 Found\r\nlocation: http://local\thost.example.com/md\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        }
    });
    let err = failure(sp_from(&format!("http://127.0.0.1:{port}/away")));
    assert_eq!(err.code, "metadata", "{}", err.message);
    assert!(err.message.contains("whitespace or a control character"), "{}", err.message);
}

#[test]
fn plain_http_to_loopback_still_works() {
    let hits = Arc::new(AtomicUsize::new(0));
    let server = counting_server(hits.clone());
    let port = server.url.rsplit(':').next().unwrap().to_string();
    for host in ["127.0.0.1", "localhost"] {
        let sp = sp_from(&format!("http://{host}:{port}/md")).unwrap_or_else(|e| panic!("{host}: {e}"));
        assert_eq!(sp.idp.entity_id, IDP_ENTITY);
    }
    let ars = start_ars();
    for location in [ars.url.clone(), ars.url.replace("127.0.0.1", "localhost")] {
        let sp = must_sp(Map::new(), &location);
        let artifact = artifact_for("");
        ars.put(&artifact, &response_xml(&ResponseOpt { in_response_to: "_r".into(), ..ResponseOpt::default() }));
        let who = sp.acs("GET", &format!("/saml/acs?SAMLart={}", crate::bindings::uri_escape(&artifact)), &AcsBody::None, &["_r".into()]).unwrap_or_else(|e| panic!("{location}: {e}"));
        assert_eq!(who.binding, "artifact");
    }
    for host in ["127.0.0.1", "localhost"] {
        let before = hits.load(Ordering::SeqCst);
        let err = failure(start_receiver(&format!("http://{host}:{port}/ssf")));
        assert_eq!(err.code, "ssf", "{}", err.message);
        assert!(!err.message.contains(REFUSED), "{}", err.message);
        assert!(hits.load(Ordering::SeqCst) > before, "the transmitter on {host} was not reached");
    }
}

#[test]
fn https_to_an_unreachable_host_is_a_connection_error_not_this_refusal() {
    let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let https = format!("https://127.0.0.1:{closed}");
    for err in [
        failure(sp_from(&format!("{https}/md"))),
        failure(resolve(&format!("{https}/ars"))),
        failure(start_receiver(&https)),
    ] {
        assert!(!err.message.contains(REFUSED), "{}", err.message);
        assert!(err.message.starts_with(&https), "{}", err.message);
    }
}
