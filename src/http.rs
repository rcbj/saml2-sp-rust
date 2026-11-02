// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::io::Read;
use std::time::Duration;

use crate::error::{err, SamlError};

const MAX_BYTES: u64 = 2 * 1024 * 1024;

/// Trust and client certificate for the back channel.
#[derive(Clone, Default)]
pub struct TlsOptions {
    pub ca: String,
    pub cert: String,
    pub key: String,
}

pub(crate) struct HttpAnswer {
    pub status: u16,
    pub body: String,
}

pub(crate) fn send(raw_url: &str, method: &str, headers: &[(&str, &str)], body: &str, tls: Option<&TlsOptions>, code: &str) -> Result<HttpAnswer, SamlError> {
    if !(raw_url.starts_with("https://") || raw_url.starts_with("http://")) {
        return Err(err(code, format!("{raw_url} is not an http(s) URL")));
    }
    // Every fetch this library makes comes through here: the identity
    // provider's metadata (its signing keys), the ArtifactResolve (the signed
    // request out, the assertion back) and the Shared Signals transmitter
    // (SETs and the bearer token). None of them may travel in the clear off
    // this machine, so plain http is refused before any DNS lookup or
    // connection unless the host is loopback, and so is every redirect, which
    // is why redirects are followed here rather than by ureq.
    let agent = agent(tls, code)?;
    let mut target = raw_url.to_string();
    let mut method = method.to_string();
    let mut body = body.to_string();
    let mut hop = 0;
    let (status, response) = loop {
        let mut request = agent.request(&method, &target);
        let url = request.request_url().map_err(|e| err(code, format!("{raw_url}: {e}")))?;
        refuse_plain_http_off_loopback(&url, code)?;
        for (key, value) in headers {
            request = request.set(key, value);
        }
        let result = if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD") || (body.is_empty() && !method.eq_ignore_ascii_case("POST") && !method.eq_ignore_ascii_case("PUT")) {
            request.call()
        } else {
            request.send_string(&body)
        };
        let (status, response) = match result {
            Ok(response) => (response.status(), response),
            Err(ureq::Error::Status(status, response)) => (status, response),
            Err(ureq::Error::Transport(transport)) => {
                let message = transport.to_string();
                let lower = message.to_ascii_lowercase();
                if lower.contains("timeout") || lower.contains("timed out") {
                    return Err(err(code, format!("{raw_url} did not answer within 15 s")));
                }
                return Err(err(code, format!("{raw_url}: {message}")));
            }
        };
        if matches!(status, 301 | 302 | 303 | 307 | 308) && hop < MAX_REDIRECTS {
            if let Some(next) = response.header("location").and_then(|location| url.as_url().join(location).ok()) {
                // As ureq does: never from https down to http, and never to
                // anything but http(s); then the 3xx is the answer.
                let downgrade = url.as_url().scheme() == "https" && next.scheme() == "http";
                if !downgrade && (next.scheme() == "http" || next.scheme() == "https") {
                    if status == 303 && !method.eq_ignore_ascii_case("HEAD") || matches!(status, 301 | 302) && method.eq_ignore_ascii_case("POST") {
                        method = "GET".to_string();
                        body.clear();
                    }
                    target = next.to_string();
                    hop += 1;
                    continue;
                }
            }
        }
        break (status, response);
    };
    let mut payload = Vec::new();
    response.into_reader().take(MAX_BYTES + 1).read_to_end(&mut payload)
        .map_err(|e| err(code, format!("{raw_url}: {e}")))?;
    if payload.len() as u64 > MAX_BYTES {
        return Err(err(code, format!("{raw_url} answered more than {MAX_BYTES} bytes")));
    }
    let body = String::from_utf8_lossy(&payload).into_owned();
    Ok(HttpAnswer { status, body })
}

const MAX_REDIRECTS: u32 = 5;

/// Refuses a plain http URL unless its host is loopback: 127.0.0.0/8, ::1 or
/// the name localhost, where the bytes never leave the machine. The URL is the
/// one ureq would dial, parsed the same way, and nothing here resolves a name.
/// A URL with userinfo is never loopback, so `http://localhost:80@host/` cannot
/// pass as localhost. The message names the scheme and host[:port] only: never
/// userinfo, path, query or a secret.
fn refuse_plain_http_off_loopback(request_url: &ureq::RequestUrl, code: &str) -> Result<(), SamlError> {
    let url = request_url.as_url();
    if url.scheme() != "http" {
        return Ok(());
    }
    let host = url.host_str().unwrap_or("");
    if url.username().is_empty() && url.password().is_none() && is_loopback_host(host) {
        return Ok(());
    }
    let shown = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    Err(err(code, format!("http://{shown} is refused: plain http is allowed only to a loopback host (127.0.0.0/8, ::1, localhost); use https")))
}

pub(crate) fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return v4.octets()[0] == 127;
    }
    if let Some(literal) = host.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
        return literal.parse::<std::net::Ipv6Addr>().map(|v6| v6 == std::net::Ipv6Addr::LOCALHOST).unwrap_or(false);
    }
    false
}

/// Every certificate in `ca`, each one a root of the trust store.
///
/// `ca` is a PEM file that may hold a whole chain, as iya-sts publishes it at
/// `GET /tls/server-certificate`: leaf, TLS Issuing CA, Intermediate, Root.
/// `native_tls::Certificate::from_pem` reads only the first block, which is the
/// leaf; OpenSSL then cannot end the path at a self-signed certificate and
/// refuses the handshake. So each block is read and added, and the Root is
/// among them.
pub(crate) fn trust_anchors(ca: &str) -> Result<Vec<native_tls::Certificate>, String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut rest = ca;
    while let Some(start) = rest.find(BEGIN) {
        let Some(length) = rest[start..].find(END) else {
            return Err("the CA certificate cannot be read: a PEM block has no END line".to_string());
        };
        let block = &rest[start..start + length + END.len()];
        let certificate = native_tls::Certificate::from_pem(block.as_bytes())
            .map_err(|e| format!("the CA certificate cannot be read: {e}"))?;
        out.push(certificate);
        rest = &rest[start + length + END.len()..];
    }
    if out.is_empty() {
        return Err("the CA certificate cannot be read: it holds no PEM certificate".to_string());
    }
    Ok(out)
}

fn agent(tls: Option<&TlsOptions>, code: &str) -> Result<ureq::Agent, SamlError> {
    let mut builder = ureq::AgentBuilder::new().timeout(Duration::from_secs(15)).redirects(0);
    if let Some(opt) = tls {
        if !opt.ca.is_empty() || (!opt.cert.is_empty() && !opt.key.is_empty()) {
            let mut tls_builder = native_tls::TlsConnector::builder();
            tls_builder.min_protocol_version(Some(native_tls::Protocol::Tlsv12));
            if !opt.ca.is_empty() {
                for ca in trust_anchors(&opt.ca).map_err(|message| err(code, message))? {
                    tls_builder.add_root_certificate(ca);
                }
            }
            if !opt.cert.is_empty() && !opt.key.is_empty() {
                let identity = native_tls::Identity::from_pkcs8(opt.cert.as_bytes(), opt.key.as_bytes()).map_err(|e| err(code, format!("the client certificate cannot be read: {e}")))?;
                tls_builder.identity(identity);
            }
            let connector = tls_builder.build().map_err(|e| err(code, format!("the TLS configuration cannot be used: {e}")))?;
            builder = builder.tls_connector(std::sync::Arc::new(connector));
        }
    }
    Ok(builder.build())
}
