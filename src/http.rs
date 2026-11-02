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
    let agent = agent(tls, code)?;
    let mut request = agent.request(method, raw_url);
    for (key, value) in headers {
        request = request.set(key, value);
    }
    let result = if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD") || (body.is_empty() && !method.eq_ignore_ascii_case("POST") && !method.eq_ignore_ascii_case("PUT")) {
        request.call()
    } else {
        request.send_string(body)
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
    let mut payload = Vec::new();
    response.into_reader().take(MAX_BYTES + 1).read_to_end(&mut payload)
        .map_err(|e| err(code, format!("{raw_url}: {e}")))?;
    if payload.len() as u64 > MAX_BYTES {
        return Err(err(code, format!("{raw_url} answered more than {MAX_BYTES} bytes")));
    }
    let body = String::from_utf8_lossy(&payload).into_owned();
    Ok(HttpAnswer { status, body })
}

fn agent(tls: Option<&TlsOptions>, code: &str) -> Result<ureq::Agent, SamlError> {
    let mut builder = ureq::AgentBuilder::new().timeout(Duration::from_secs(15));
    if let Some(opt) = tls {
        if !opt.ca.is_empty() || (!opt.cert.is_empty() && !opt.key.is_empty()) {
            let mut tls_builder = native_tls::TlsConnector::builder();
            tls_builder.min_protocol_version(Some(native_tls::Protocol::Tlsv12));
            if !opt.ca.is_empty() {
                let ca = native_tls::Certificate::from_pem(opt.ca.as_bytes()).map_err(|_| err(code, "the CA certificate cannot be read"))?;
                tls_builder.add_root_certificate(ca);
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
