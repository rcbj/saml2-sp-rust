// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use serde_json::Value;

const CAEP: &str = "https://schemas.openid.net/secevent/caep/event-type/";
const RISC: &str = "https://schemas.openid.net/secevent/risc/event-type/";
const SSF: &str = "https://schemas.openid.net/secevent/ssf/event-type/";

const ORDER: &[(&str, &str)] = &[
    ("session_revoked", "https://schemas.openid.net/secevent/caep/event-type/session-revoked"),
    ("token_claims_change", "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"),
    ("credential_change", "https://schemas.openid.net/secevent/caep/event-type/credential-change"),
    ("assurance_level_change", "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"),
    ("device_compliance_change", "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"),
    ("session_established", "https://schemas.openid.net/secevent/caep/event-type/session-established"),
    ("session_presented", "https://schemas.openid.net/secevent/caep/event-type/session-presented"),
    ("risk_level_change", "https://schemas.openid.net/secevent/caep/event-type/risk-level-change"),
    ("account_credential_change_required", "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required"),
    ("account_purged", "https://schemas.openid.net/secevent/risc/event-type/account-purged"),
    ("account_disabled", "https://schemas.openid.net/secevent/risc/event-type/account-disabled"),
    ("account_enabled", "https://schemas.openid.net/secevent/risc/event-type/account-enabled"),
    ("identifier_changed", "https://schemas.openid.net/secevent/risc/event-type/identifier-changed"),
    ("identifier_recycled", "https://schemas.openid.net/secevent/risc/event-type/identifier-recycled"),
    ("credential_compromise", "https://schemas.openid.net/secevent/risc/event-type/credential-compromise"),
    ("opt_in", "https://schemas.openid.net/secevent/risc/event-type/opt-in"),
    ("opt_out_initiated", "https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated"),
    ("opt_out_cancelled", "https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled"),
    ("opt_out_effective", "https://schemas.openid.net/secevent/risc/event-type/opt-out-effective"),
    ("recovery_activated", "https://schemas.openid.net/secevent/risc/event-type/recovery-activated"),
    ("recovery_information_changed", "https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed"),
    ("sessions_revoked", "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked"),
    ("verification", "https://schemas.openid.net/secevent/ssf/event-type/verification"),
    ("stream_updated", "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"),
];

/// The URI of a named CAEP, RISC, or SSF event. Unknown names are empty.
pub fn event(name: &str) -> &'static str {
    ORDER.iter().find(|(key, _)| *key == name).map(|(_, uri)| *uri).unwrap_or("")
}

fn with_prefix(prefix: &str) -> Vec<String> {
    ORDER.iter().filter(|(_, uri)| uri.starts_with(prefix)).map(|(_, uri)| (*uri).to_string()).collect()
}

/// Every CAEP event type, in declaration order.
pub fn caep_events() -> Vec<String> { with_prefix(CAEP) }

/// Every RISC event type, in declaration order.
pub fn risc_events() -> Vec<String> { with_prefix(RISC) }

/// The receiver's default subscription.
pub fn default_events_requested() -> Vec<String> {
    ["session_revoked", "credential_change", "assurance_level_change", "token_claims_change",
     "account_disabled", "account_enabled", "account_purged", "credential_compromise",
     "sessions_revoked", "account_credential_change_required"]
        .into_iter().map(event).map(str::to_string).collect()
}

/// Events that end the local sessions they name.
pub fn default_ending_events() -> Vec<String> {
    ["session_revoked", "account_disabled", "account_purged", "credential_compromise", "sessions_revoked"]
        .into_iter().map(event).map(str::to_string).collect()
}

pub(crate) fn string_of(value: &Value) -> String {
    value.as_str().unwrap_or("").to_string()
}

pub(crate) fn string_of_opt(value: Option<&Value>) -> String {
    value.and_then(|v| v.as_str()).unwrap_or("").to_string()
}

fn simple_subject(identifier: &Value, issuer: &str) -> std::collections::HashMap<String, String> {
    let Some(obj) = identifier.as_object() else { return std::collections::HashMap::new() };
    let mut form = string_of_opt(obj.get("format"));
    if form.is_empty() {
        form = string_of_opt(obj.get("subject_type"));
    }
    let mut out = std::collections::HashMap::new();
    match form.as_str() {
        "iss_sub" => {
            let sub = string_of_opt(obj.get("sub"));
            let iss = obj.get("iss");
            if !sub.is_empty() && (iss.is_none() || iss.unwrap().is_null() || string_of(iss.unwrap()) == issuer) {
                out.insert("sub".to_string(), sub);
            }
        }
        "email" => {
            let email = string_of_opt(obj.get("email"));
            if !email.is_empty() {
                out.insert("email".to_string(), email);
            }
        }
        "opaque" => {
            let id = string_of_opt(obj.get("id"));
            if !id.is_empty() {
                out.insert("opaque".to_string(), id);
            }
        }
        "aliases" => {
            if let Some(items) = obj.get("identifiers").and_then(|v| v.as_array()) {
                for item in items {
                    for (k, v) in simple_subject(item, issuer) {
                        out.insert(k, v);
                    }
                }
            }
        }
        _ => {}
    }
    out
}

/// Who an event's `sub_id` names: `person`, `email`, and `idp_session`.
pub fn subject_of(sub_id: &Value, issuer: &str) -> std::collections::HashMap<String, String> {
    let Some(obj) = sub_id.as_object() else { return std::collections::HashMap::new() };
    let mut form = string_of_opt(obj.get("format"));
    if form.is_empty() {
        form = string_of_opt(obj.get("subject_type"));
    }
    let complex = form == "complex" || (form.is_empty() && (obj.get("user").is_some() || obj.get("session").is_some()));
    if complex {
        let user = simple_subject(obj.get("user").unwrap_or(&Value::Null), issuer);
        let session = simple_subject(obj.get("session").unwrap_or(&Value::Null), issuer);
        let mut out = std::collections::HashMap::new();
        if let Some(sub) = user.get("sub") {
            if !sub.is_empty() {
                out.insert("person".to_string(), sub.clone());
            }
        }
        if let Some(email) = user.get("email") {
            if !email.is_empty() {
                out.insert("email".to_string(), email.clone());
            }
        }
        let session_id = session.get("opaque").cloned().filter(|s| !s.is_empty())
            .or_else(|| session.get("sub").cloned().filter(|s| !s.is_empty()));
        if let Some(session_id) = session_id {
            out.insert("idp_session".to_string(), session_id);
        }
        return out;
    }
    let one = simple_subject(sub_id, issuer);
    let mut out = std::collections::HashMap::new();
    if let Some(sub) = one.get("sub").filter(|s| !s.is_empty()) {
        out.insert("person".to_string(), sub.clone());
    }
    if let Some(email) = one.get("email").filter(|s| !s.is_empty()) {
        out.insert("email".to_string(), email.clone());
    }
    out
}

#[allow(dead_code)]
const _SSF: &str = SSF;
