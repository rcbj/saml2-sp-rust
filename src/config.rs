// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::path::{Path, PathBuf};

use rsa::RsaPrivateKey;
use serde_json::{Map, Value};

use crate::error::{err, SamlError};
use crate::keys::{certificate_pem, load_certificate_der, load_private_key, private_pem, same_public};

/// Configuration with its files read and its defaults filled in.
/// `signals` is present only when CAEP and RISC are off. `None` means on.
pub struct Config {
    pub entity_id: String,
    pub acs_url: String,
    pub private_key_pem: String,
    pub certificate_pem: String,
    pub idp_metadata: String,
    pub request_binding: String,
    pub response_binding: String,
    pub clock_skew_ms: i64,
    pub want_assertions_signed: bool,
    pub want_assertions_encrypted: bool,
    pub allow_unsolicited: bool,
    pub signals: Option<bool>,
    pub idp_ca: String,
    pub idp_entity_id: String,
    pub name_id_format: String,
    pub(crate) private_key: RsaPrivateKey,
    pub(crate) certificate_der: Vec<u8>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("entity_id", &self.entity_id)
            .field("acs_url", &self.acs_url)
            .field("request_binding", &self.request_binding)
            .field("response_binding", &self.response_binding)
            .field("clock_skew_ms", &self.clock_skew_ms)
            .field("want_assertions_signed", &self.want_assertions_signed)
            .field("want_assertions_encrypted", &self.want_assertions_encrypted)
            .field("allow_unsolicited", &self.allow_unsolicited)
            .field("signals", &self.signals)
            .finish()
    }
}

impl Config {
    pub fn has(&self, key: &str) -> bool {
        key == "signals" && self.signals.is_some()
    }
}

fn expand(value: &str) -> Result<String, SamlError> {
    let mut value = value.to_string();
    let mut seen = 0;
    loop {
        if value.starts_with("env:") || value.starts_with("file:") {
            seen += 1;
            if seen > 4 {
                return Err(err("config", format!("the placeholder {value} is nested too deeply")));
            }
            if let Some(name) = value.strip_prefix("env:") {
                let got = std::env::var(name).ok();
                if name.is_empty() || got.is_none() {
                    let shown = if name.is_empty() { value.clone() } else { name.to_string() };
                    return Err(err("config", format!("environment variable {shown} is not set")));
                }
                value = got.unwrap();
                continue;
            }
            value = value[5..].to_string();
            continue;
        }
        return Ok(value);
    }
}

fn looks_like_pem(value: &str) -> bool {
    value.contains("-----BEGIN ")
}

fn material(value: &str, base_dir: &Path, what: &str) -> Result<String, SamlError> {
    let value = expand(value)?;
    if looks_like_pem(&value) {
        return Ok(value);
    }
    let path = if Path::new(&value).is_absolute() {
        PathBuf::from(&value)
    } else {
        base_dir.join(&value)
    };
    let path = path.canonicalize().unwrap_or(path);
    std::fs::read_to_string(&path).map_err(|e| err("config", format!("{what} is neither a PEM nor a readable file ({}): {e}", path.display())))
}

fn absolute(value: Option<&Value>, what: &str) -> Result<String, SamlError> {
    let text = value.and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if text.is_empty() {
        return Err(err("config", format!("{what} is required")));
    }
    if !(text.starts_with("https://") || text.starts_with("http://")) {
        return Err(err("config", format!("{what} must be an absolute http(s) URL, not {text}")));
    }
    Ok(text)
}

fn stringify(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn one_of(value: Option<&Value>, allowed: &[&str], fallback: &str, what: &str) -> Result<String, SamlError> {
    let Some(value) = value else { return Ok(fallback.to_string()) };
    if value.is_null() || value.as_str() == Some("") {
        return Ok(fallback.to_string());
    }
    let Some(text) = value.as_str() else {
        return Err(err("config", format!("{what} must be one of {}, not {}", allowed.join(", "), stringify(value))));
    };
    if allowed.contains(&text) {
        Ok(text.to_string())
    } else {
        Err(err("config", format!("{what} must be one of {}, not {text}", allowed.join(", "))))
    }
}

fn as_number(value: &Value) -> Option<f64> {
    value.as_f64().filter(|n| n.is_finite())
}

fn bool_or(value: &Value, fallback: bool) -> bool {
    value.as_bool().unwrap_or(fallback)
}

/// Reads files named by the configuration and fills in defaults.
pub fn resolve_config(config: &Map<String, Value>, base_dir: &str) -> Result<Config, SamlError> {
    let base = if base_dir.is_empty() {
        std::env::current_dir().map_err(|e| err("config", e.to_string()))?
    } else {
        PathBuf::from(base_dir)
    };
    let entity_id = config.get("entityId").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if entity_id.is_empty() {
        return Err(err("config", "entityId is required"));
    }
    let acs_url = absolute(config.get("acsUrl"), "acsUrl")?;
    let key_text = config.get("privateKey").and_then(|v| v.as_str());
    let cert_text = config.get("certificate").and_then(|v| v.as_str());
    let (Some(key_text), Some(cert_text)) = (key_text, cert_text) else {
        return Err(err("config", "privateKey and certificate are required: every AuthnRequest is signed"));
    };
    let key_pem = material(key_text, &base, "privateKey")?;
    let cert_pem = material(cert_text, &base, "certificate")?;
    let private_key = load_private_key(&key_pem).map_err(|e| {
        if e.message.starts_with("the private key is ") {
            e
        } else if e.message.contains("cannot be read") {
            e
        } else {
            err("config", format!("the private key or certificate cannot be read: {}", e.message))
        }
    })?;
    let certificate_der = load_certificate_der(&cert_pem)?;
    if !same_public(&private_key, &certificate_der) {
        return Err(err("config", "the certificate is not for the private key"));
    }
    let mut idp_meta = config.get("idpMetadata").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if idp_meta.is_empty() {
        return Err(err("config", "idpMetadata is required"));
    }
    idp_meta = expand(&idp_meta)?;
    if !(idp_meta.starts_with("http://") || idp_meta.starts_with("https://") || idp_meta.starts_with('<')) {
        let path = if Path::new(&idp_meta).is_absolute() { PathBuf::from(&idp_meta) } else { base.join(&idp_meta) };
        idp_meta = path.to_string_lossy().to_string();
    }
    let mut skew = 60.0;
    if let Some(raw) = config.get("clockSkewSeconds") {
        if !raw.is_null() {
            let Some(n) = as_number(raw) else {
                return Err(err("config", "clockSkewSeconds must be a number from 0 to 600"));
            };
            if !(0.0..=600.0).contains(&n) {
                return Err(err("config", "clockSkewSeconds must be a number from 0 to 600"));
            }
            skew = n;
        }
    }
    if let Some(raw) = config.get("signals") {
        if !raw.is_boolean() {
            return Err(err("config", "signals must be true or false"));
        }
    }
    let request = one_of(config.get("requestBinding"), &["redirect", "post"], "redirect", "requestBinding")?;
    let response = one_of(config.get("responseBinding"), &["post", "redirect", "artifact"], "post", "responseBinding")?;
    let signals = if config.get("signals").and_then(|v| v.as_bool()) == Some(false) { Some(false) } else { None };
    let mut idp_ca = String::new();
    if let Some(text) = config.get("idpCa").and_then(|v| v.as_str()) {
        if !text.is_empty() {
            idp_ca = material(text, &base, "idpCa")?;
        }
    }
    let idp_entity_id = config.get("idpEntityId").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let name_id_format = config.get("nameIdFormat").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let want_assertions_signed = config.get("wantAssertionsSigned").map(|v| if v.is_null() { true } else { bool_or(v, true) }).unwrap_or(true);
    let want_assertions_encrypted = config.get("wantAssertionsEncrypted").map(|v| if v.is_null() { false } else { bool_or(v, false) }).unwrap_or(false);
    let allow_unsolicited = config.get("allowUnsolicited").map(|v| if v.is_null() { false } else { bool_or(v, false) }).unwrap_or(false);
    let private_key_pem = private_pem(&private_key);
    Ok(Config {
        entity_id,
        acs_url,
        private_key_pem,
        certificate_pem: certificate_pem(&certificate_der),
        idp_metadata: idp_meta,
        request_binding: request,
        response_binding: response,
        clock_skew_ms: (skew as i64) * 1000,
        want_assertions_signed,
        want_assertions_encrypted,
        allow_unsolicited,
        signals,
        idp_ca,
        idp_entity_id,
        name_id_format,
        private_key,
        certificate_der,
    })
}

pub(crate) fn read_config_file(path: &str, overrides: Option<&Map<String, Value>>) -> Result<Config, SamlError> {
    let raw = std::fs::read(path).map_err(|e| err("config", format!("{path} cannot be read as JSON: {e}")))?;
    let parsed: Value = serde_json::from_slice(&raw).map_err(|e| err("config", format!("{path} cannot be read as JSON: {e}")))?;
    let mut obj = parsed.as_object().cloned().ok_or_else(|| err("config", "the configuration must be an object"))?;
    if let Some(overrides) = overrides {
        for (k, v) in overrides {
            if !v.is_null() {
                obj.insert(k.clone(), v.clone());
            }
        }
    }
    let dir = Path::new(path).parent().map(|p| {
        std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf()).to_string_lossy().to_string()
    }).unwrap_or_default();
    let abs_dir = if Path::new(path).is_absolute() {
        dir
    } else {
        std::env::current_dir().ok().and_then(|cwd| {
            let full = cwd.join(path);
            full.parent().map(|p| p.to_string_lossy().to_string())
        }).unwrap_or(dir)
    };
    resolve_config(&obj, &abs_dir)
}
