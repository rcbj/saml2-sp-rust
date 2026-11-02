// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::io::{Read, Write};

use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::error::{err, SamlError};
use crate::keys::{b64_decode, b64_standard, public_from_cert};
use crate::xml::{escape_xml, RSA_SHA256, RSA_SHA384, RSA_SHA512};

const MAX_INFLATED: usize = 1024 * 1024;

pub(crate) fn uri_escape(value: &str) -> String {
    const HEX: &[u8] = b"0123456789ABCDEF";
    let mut out = String::new();
    for &c in value.as_bytes() {
        let safe = c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')');
        if safe {
            out.push(c as char);
        } else {
            out.push('%');
            out.push(HEX[(c >> 4) as usize] as char);
            out.push(HEX[(c & 15) as usize] as char);
        }
    }
    out
}

fn bad_percent(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }
        if i + 2 >= bytes.len() || !bytes[i + 1].is_ascii_hexdigit() || !bytes[i + 2].is_ascii_hexdigit() {
            return true;
        }
        i += 3;
    }
    false
}

pub(crate) fn uri_unescape(value: &str) -> Result<String, SamlError> {
    let text = value.replace('+', "%20");
    if bad_percent(&text) {
        return Err(err("binding", "the query string is not validly percent-encoded"));
    }
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let h = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00"), 16).unwrap_or(0);
            out.push(h);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| err("binding", "the query string is not validly percent-encoded"))
}

pub(crate) fn deflate_raw(data: &[u8]) -> Result<Vec<u8>, SamlError> {
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).map_err(|e| err("binding", format!("the message could not be deflated: {e}")))?;
    enc.finish().map_err(|e| err("binding", format!("the message could not be deflated: {e}")))
}

pub(crate) fn inflate_raw(data: &[u8]) -> Result<Vec<u8>, SamlError> {
    let mut dec = DeflateDecoder::new(data);
    let mut buf = Vec::new();
    let mut limited = (&mut dec).take(MAX_INFLATED as u64 + 1);
    limited.read_to_end(&mut buf).map_err(|_| err("binding", "the message inflates past the limit"))?;
    if buf.len() > MAX_INFLATED {
        return Err(err("binding", "the message inflates past the limit"));
    }
    Ok(buf)
}

pub(crate) fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

fn hash_of(alg: &str, data: &[u8]) -> Result<Vec<u8>, SamlError> {
    Ok(match alg {
        RSA_SHA256 => Sha256::digest(data).to_vec(),
        RSA_SHA384 => Sha384::digest(data).to_vec(),
        RSA_SHA512 => Sha512::digest(data).to_vec(),
        _ => return Err(err("signature", format!("the query is signed with {alg}, which is refused"))),
    })
}

fn sign_pkcs1(key: &RsaPrivateKey, alg: &str, digest: &[u8]) -> Result<Vec<u8>, SamlError> {
    let signed = match alg {
        RSA_SHA256 => key.sign(Pkcs1v15Sign::new::<Sha256>(), digest),
        RSA_SHA384 => key.sign(Pkcs1v15Sign::new::<Sha384>(), digest),
        RSA_SHA512 => key.sign(Pkcs1v15Sign::new::<Sha512>(), digest),
        _ => return Err(err("signature", format!("the query is signed with {alg}, which is refused"))),
    };
    signed.map_err(|e| err("signature", format!("the query string could not be signed: {e}")))
}

fn verify_pkcs1(public: &rsa::RsaPublicKey, alg: &str, digest: &[u8], sig: &[u8]) -> bool {
    match alg {
        RSA_SHA256 => public.verify(Pkcs1v15Sign::new::<Sha256>(), digest, sig).is_ok(),
        RSA_SHA384 => public.verify(Pkcs1v15Sign::new::<Sha384>(), digest, sig).is_ok(),
        RSA_SHA512 => public.verify(Pkcs1v15Sign::new::<Sha512>(), digest, sig).is_ok(),
        _ => false,
    }
}

pub(crate) fn redirect_query(param: &str, xml: &str, relay_state: Option<&str>, key: &RsaPrivateKey) -> Result<String, SamlError> {
    let deflated = deflate_raw(xml.as_bytes())?;
    let encoded = b64_standard(&deflated);
    let mut parts = vec![format!("{param}={}", uri_escape(&encoded))];
    if let Some(relay) = relay_state {
        parts.push(format!("RelayState={}", uri_escape(relay)));
    }
    parts.push(format!("SigAlg={}", uri_escape(RSA_SHA256)));
    let signed = parts.join("&");
    let digest = sha256(signed.as_bytes());
    let sig = sign_pkcs1(key, RSA_SHA256, &digest)?;
    Ok(format!("{signed}&Signature={}", uri_escape(&b64_standard(&sig))))
}

pub(crate) struct RedirectMessage {
    pub xml: String,
    pub relay_state: Option<String>,
    pub signed: bool,
}

pub(crate) fn read_redirect(raw_query: &str, param: &str, certs: &[Vec<u8>]) -> Result<RedirectMessage, SamlError> {
    let query = raw_query.strip_prefix('?').unwrap_or(raw_query);
    let mut raw: Vec<(String, String)> = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name_part, value) = match pair.find('=') {
            Some(eq) => (&pair[..eq], &pair[eq + 1..]),
            None => (pair, ""),
        };
        let name = uri_unescape(name_part)?;
        if raw.iter().any(|(k, _)| k == &name) {
            return Err(err("binding", format!("the query string carries {name} twice")));
        }
        raw.push((name, value.to_string()));
    }
    let get = |name: &str| raw.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
    let message = get(param).ok_or_else(|| err("binding", format!("the query string carries no {param}")))?;
    let unescaped = uri_unescape(&message)?;
    let decoded = b64_decode(&unescaped).map_err(|e| err("binding", format!("{param} is not a DEFLATE-encoded message: {e}")))?;
    let inflated = inflate_raw(&decoded).map_err(|e| {
        if e.code == "binding" && e.message.contains("inflates past") {
            e
        } else {
            err("binding", format!("{param} is not a DEFLATE-encoded message"))
        }
    })?;
    let xml = String::from_utf8(inflated).map_err(|_| err("binding", format!("{param} is not a DEFLATE-encoded message")))?;
    let relay = match get("RelayState") {
        Some(raw_relay) => Some(uri_unescape(&raw_relay)?),
        None => None,
    };
    let Some(signature_raw) = get("Signature") else {
        return Ok(RedirectMessage { xml, relay_state: relay, signed: false });
    };
    let sig_alg = uri_unescape(&get("SigAlg").unwrap_or_default())?;
    if !matches!(sig_alg.as_str(), RSA_SHA256 | RSA_SHA384 | RSA_SHA512) {
        let shown = if sig_alg.is_empty() { "(no SigAlg)".to_string() } else { sig_alg };
        return Err(err("signature", format!("the query is signed with {shown}, which is refused")));
    }
    let mut signed_parts = vec![format!("{param}={message}")];
    if let Some(raw_relay) = get("RelayState") {
        signed_parts.push(format!("RelayState={raw_relay}"));
    }
    signed_parts.push(format!("SigAlg={}", get("SigAlg").unwrap_or_default()));
    let data = signed_parts.join("&");
    let sig_text = uri_unescape(&signature_raw).map_err(|_| err("signature", "the query string signature does not verify against the identity provider's certificate"))?;
    let sig_bytes = b64_decode(&sig_text).map_err(|_| err("signature", "the query string signature does not verify against the identity provider's certificate"))?;
    let digest = hash_of(&sig_alg, data.as_bytes())?;
    for der in certs {
        let Ok(public) = public_from_cert(der) else { continue };
        if verify_pkcs1(&public, &sig_alg, &digest, &sig_bytes) {
            return Ok(RedirectMessage { xml, relay_state: relay, signed: true });
        }
    }
    Err(err("signature", "the query string signature does not verify against the identity provider's certificate"))
}

fn is_b64(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() && matches!(bytes[i], b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/') {
        i += 1;
    }
    let rest = &bytes[i..];
    rest.len() <= 2 && rest.iter().all(|c| *c == b'=')
}

pub(crate) fn read_post(value: &str, param: &str) -> Result<String, SamlError> {
    let compact: String = value.split_whitespace().collect();
    if compact.is_empty() || !is_b64(&compact) {
        return Err(err("binding", format!("{param} is not base64")));
    }
    let raw = b64_decode(&compact).map_err(|_| err("binding", format!("{param} is not base64")))?;
    String::from_utf8(raw).map_err(|_| err("binding", format!("{param} is not base64")))
}

/// The browser form that carries an HTTP-POST SAML message.
/// Fields are emitted in the order given.
pub fn post_form_html(action: &str, fields: &[(&str, &str)], nonce: &str, title: &str) -> String {
    let title = if title.is_empty() { "Signing in" } else { title };
    let mut lines = Vec::new();
    for (name, value) in fields {
        lines.push(format!(
            "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
            escape_xml(name),
            escape_xml(value)
        ));
    }
    let script = if nonce.is_empty() {
        String::new()
    } else {
        format!("\n    <script nonce=\"{}\">document.forms[0].submit();</script>", escape_xml(nonce))
    };
    format!(
        "<!doctype html>\n<html lang=\"en\">\n  <head><meta charset=\"utf-8\"><title>{}</title></head>\n  <body>\n    <form method=\"post\" action=\"{}\">\n      {}\n      <noscript><p>Your browser is not running scripts. Press Continue to go on.</p></noscript>\n      <button type=\"submit\">Continue</button>\n    </form>{script}\n  </body>\n</html>\n",
        escape_xml(title),
        escape_xml(action),
        lines.join("\n      ")
    )
}

pub(crate) fn query_pairs(raw: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if raw.is_empty() {
        return out;
    }
    for part in raw.split('&') {
        if part.is_empty() {
            continue;
        }
        let (key, val) = match part.find('=') {
            Some(eq) => (&part[..eq], &part[eq + 1..]),
            None => (part, ""),
        };
        let key = query_unescape(key);
        let val = query_unescape(val);
        if !out.iter().any(|(k, _)| k == &key) {
            out.push((key, val));
        }
    }
    out
}

fn query_unescape(value: &str) -> String {
    let text = value.replace('+', " ");
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() && bytes[i + 1].is_ascii_hexdigit() && bytes[i + 2].is_ascii_hexdigit() {
            let h = u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("00"), 16).unwrap_or(0);
            out.push(h);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}
