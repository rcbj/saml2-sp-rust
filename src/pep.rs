// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! The embedded iya-sts PEP (the `pep` feature; rcbj/iya-sts#1206, this
//! repository's #40). The PEP itself is the shared `iya-pep` crate. This
//! library only wires it in, as `oidc-caep-risc` does (its #46):
//!
//! - **Configuration.** A `pep` section in `saml.json`, off unless present.
//!   `pdpUrl` defaults to the identity provider's entityID: iya-sts's SAML
//!   entityID is the realm's OAuth issuer (iya-sts #523), so it is the
//!   service's base URL with the realm prefix. `application` defaults to
//!   this service provider's `entityId`, the identifier iya-sts registers it
//!   under. `tlsCa` defaults to `idpCa`, and `signals` to whether this
//!   library's receiver runs (an `ssf` block, and `signals` not `false`). A
//!   relative `assertionKey` is read from the configuration's directory.
//! - **Keys (D1).** The PEP's assertion key must differ from the service
//!   provider's key (`privateKey`: it signs requests, decrypts assertions and
//!   is the receiver's TLS client key). `ServiceProvider` refuses a
//!   configuration where the two have the same JWK thumbprint.
//! - **The subject.** A validated `SamlLogin` becomes the PEP's subject (see
//!   [`subject_of`]). No request header is read.
//! - **Signals (D4).** A `SignalsReceiver` given the PEP asks for
//!   `pep-policies-changed` too (in `local` mode, or `central` with a Permit
//!   cache), verifies its SET like any other, and hands the event to the PEP.

use std::path::Path;
use std::sync::Arc;

use rsa::traits::PublicKeyParts;
use serde_json::{json, Map, Value};

use crate::error::{err, SamlError};
use crate::response::SamlLogin;

pub use iya_pep::{Access, Decision, EventStream, Mode, Obligation, Pep, PepConfig, Status, Subject, POLICIES_CHANGED_EVENT};

/// The attributes the subject's id is read from, in order. iya-sts's
/// assertions carry the username under all three (`saml/saml2_sso.ts`
/// `attributesFor()`): the X.500/LDAP profile's `uid` OID, the bare `uid`, and
/// the AD FS `name` claim. The username is what the service's PIP resolves.
pub const SUBJECT_ID_ATTRIBUTES: &[&str] = &[
    "urn:oid:0.9.2342.19200300.100.1.1",
    "uid",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
];

/// Attributes that carry the authentication methods, read as `amr`.
const AMR_ATTRIBUTES: &[&str] = &["amr", "http://schemas.microsoft.com/claims/authnmethodsreferences"];

/// The `pep` section with this library's defaults filled in, or `None` when
/// there is none. Called while the configuration is resolved; the identity
/// provider's entityID (the `pdpUrl` default) is only known later.
pub(crate) fn section(config: &Map<String, Value>, base: &Path, idp_ca: &str) -> Result<Option<Map<String, Value>>, SamlError> {
    let Some(raw) = config.get("pep").filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let Some(map) = raw.as_object() else {
        return Err(err("config", "pep must be an object"));
    };
    let mut map = map.clone();
    // The PEP reads its key file itself (and again when it rotates), so it
    // gets a path: relative to the configuration file, as `privateKey` is.
    if let Some(Value::String(key)) = map.get("assertionKey") {
        let expanded = crate::config::expand(key)?;
        if !expanded.is_empty() && !Path::new(&expanded).is_absolute() {
            map.insert("assertionKey".into(), Value::String(base.join(&expanded).to_string_lossy().into_owned()));
        } else {
            map.insert("assertionKey".into(), Value::String(expanded));
        }
    }
    if !map.contains_key("signals") {
        let receiver = config.get("ssf").is_some_and(Value::is_object) && config.get("signals").and_then(Value::as_bool) != Some(false);
        map.insert("signals".into(), Value::Bool(receiver));
    }
    if !map.contains_key("tlsCa") && !idp_ca.is_empty() {
        map.insert("tlsCa".into(), Value::String(idp_ca.to_string()));
    }
    Ok(Some(map))
}

/// Builds the PEP from the resolved section. Checks that its key is not the
/// service provider's. Sends nothing; `start` does.
pub(crate) fn build(section: &Map<String, Value>, idp_entity_id: &str, entity_id: &str, sp_key: &rsa::RsaPrivateKey) -> Result<Arc<Pep>, SamlError> {
    let config = PepConfig::from_json(&Value::Object(section.clone()), idp_entity_id, entity_id).map_err(|e| {
        if !section.contains_key("pdpUrl") && e.message.starts_with("pep.pdpUrl") {
            err("config", format!("{}: the identity provider's entityID is not iya-sts's URL, so name the service in pep.pdpUrl", e.message))
        } else {
            err("config", e.message)
        }
    })?;
    let pep = Pep::new(config).map_err(|e| err("config", e.message))?;
    if iya_pep::jwk_thumbprint(&rsa_jwk(sp_key)).as_deref() == Some(pep.key_thumbprint().as_str()) {
        return Err(err("config", "pep.assertionKey is the service provider's privateKey (its signing, decryption and TLS client key); the PEP needs a key of its own"));
    }
    Ok(Arc::new(pep))
}

fn rsa_jwk(key: &rsa::RsaPrivateKey) -> Value {
    use base64::Engine as _;
    let b64 = |bytes: Vec<u8>| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    json!({"kty": "RSA", "n": b64(key.n().to_bytes_be()), "e": b64(key.e().to_bytes_be())})
}

/// The PEP's subject for a validated SAML sign-in.
///
/// The id is the username, read from the first of [`SUBJECT_ID_ATTRIBUTES`]
/// the assertion carries, else the NameID. The username comes first because
/// the PIP resolves a username (or a DN or certificate subject), and the
/// NameID isn't always one: iya-sts answers a `transient` NameID with a
/// per-session handle and an `emailAddress` one with the mail address. Its
/// `unspecified` and `persistent` NameIDs are the username, so the fallback
/// still resolves for an identity provider that sends no `uid`.
///
/// The properties are every attribute under its Name (and its FriendlyName,
/// where that is not also a Name): one value as a string, several as an
/// array. `AuthnContextClassRef` is `acr`, the `amr` attribute (if any) is
/// `amr`, and `AuthnInstant` is `auth_time` in epoch seconds. The PEP sends
/// only the properties the realm's AuthZEN catalogue declares.
pub fn subject_of(login: &SamlLogin) -> Subject {
    let first = |name: &str| login.attributes.get(name).and_then(|v| v.iter().find(|s| !s.is_empty())).cloned();
    let id = SUBJECT_ID_ATTRIBUTES.iter().find_map(|name| first(name)).unwrap_or_else(|| login.name_id.clone());
    let mut properties = Map::new();
    let mut names: Vec<&String> = login.attributes.keys().collect();
    names.sort();
    let value_of = |values: &Vec<String>| if values.len() == 1 { Value::String(values[0].clone()) } else { json!(values) };
    for name in &names {
        properties.insert((*name).clone(), value_of(&login.attributes[*name]));
    }
    for name in &names {
        if let Some(friendly) = login.attribute_friendly_names.get(*name) {
            if !friendly.is_empty() && !properties.contains_key(friendly) {
                properties.insert(friendly.clone(), value_of(&login.attributes[*name]));
            }
        }
    }
    if let Some(amr) = AMR_ATTRIBUTES.iter().find_map(|name| login.attributes.get(*name)) {
        properties.insert("amr".into(), json!(amr));
    }
    if !login.authn_context_class_ref.is_empty() {
        properties.insert("acr".into(), Value::String(login.authn_context_class_ref.clone()));
    }
    if login.authn_instant_ms > 0 {
        properties.insert("auth_time".into(), json!(login.authn_instant_ms / 1000));
    }
    Subject::user(id, properties)
}

/// Whether a receiver built with this PEP asks for `pep-policies-changed`.
pub(crate) fn wants_events(pep: &Pep) -> bool {
    pep.config().mode == Mode::Local || pep.config().permit_cache_ms > 0
}
