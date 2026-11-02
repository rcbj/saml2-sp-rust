// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rsa::BigUint;
use p256::ecdsa::signature::hazmat::PrehashVerifier as P256Prehash;
use p256::ecdsa::Signature as P256Signature;
use p256::ecdsa::VerifyingKey as P256Key;
use p384::ecdsa::signature::hazmat::PrehashVerifier as P384Prehash;
use p384::ecdsa::Signature as P384Signature;
use p384::ecdsa::VerifyingKey as P384Key;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pss::Pss;
use rsa::RsaPublicKey;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::error::{err, SamlError};
use crate::events::string_of;

struct JwsAlg {
    hash: &'static str,
    kty: &'static str,
    pss: bool,
    p1363: bool,
    size: usize,
}

fn alg_of(name: &str) -> Option<JwsAlg> {
    Some(match name {
        "RS256" => JwsAlg { hash: "sha256", kty: "RSA", pss: false, p1363: false, size: 0 },
        "RS384" => JwsAlg { hash: "sha384", kty: "RSA", pss: false, p1363: false, size: 0 },
        "RS512" => JwsAlg { hash: "sha512", kty: "RSA", pss: false, p1363: false, size: 0 },
        "PS256" => JwsAlg { hash: "sha256", kty: "RSA", pss: true, p1363: false, size: 0 },
        "PS384" => JwsAlg { hash: "sha384", kty: "RSA", pss: true, p1363: false, size: 0 },
        "PS512" => JwsAlg { hash: "sha512", kty: "RSA", pss: true, p1363: false, size: 0 },
        "ES256" => JwsAlg { hash: "sha256", kty: "EC", pss: false, p1363: true, size: 32 },
        "ES384" => JwsAlg { hash: "sha384", kty: "EC", pss: false, p1363: true, size: 48 },
        "ES512" => JwsAlg { hash: "sha512", kty: "EC", pss: false, p1363: true, size: 66 },
        "EdDSA" | "Ed25519" => JwsAlg { hash: "eddsa", kty: "OKP", pss: false, p1363: false, size: 0 },
        _ => return None,
    })
}

const SUPPORTED: &str = "RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA, Ed25519";

fn b64url_decode(value: &str, what: &str) -> Result<Vec<u8>, SamlError> {
    if !value.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
        return Err(err("signature", format!("the SET's {what} is not base64url")));
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(value)
        .or_else(|_| {
            let mut padded = value.to_string();
            while padded.len() % 4 != 0 { padded.push('='); }
            base64::engine::general_purpose::URL_SAFE.decode(padded)
        })
        .map_err(|_| err("signature", format!("the SET's {what} is not base64url")))
}

enum Public {
    Rsa(RsaPublicKey),
    P256(P256Key),
    P384(P384Key),
    Ed(VerifyingKey),
}

fn key_for_jwk(jwk: &Map<String, Value>) -> Result<Public, SamlError> {
    let kty = string_of(jwk.get("kty").unwrap_or(&Value::Null));
    let kid = string_of(jwk.get("kid").unwrap_or(&Value::Null));
    match kty.as_str() {
        "RSA" => {
            let n = b64url_decode(&string_of(jwk.get("n").unwrap_or(&Value::Null)), "key")?;
            let e = b64url_decode(&string_of(jwk.get("e").unwrap_or(&Value::Null)), "key")?;
            let public = RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e))
                .map_err(|e| err("signature", format!("the transmitter's key {kid} cannot be read: {e}")))?;
            Ok(Public::Rsa(public))
        }
        "EC" => {
            let x = b64url_decode(&string_of(jwk.get("x").unwrap_or(&Value::Null)), "key")?;
            let y = b64url_decode(&string_of(jwk.get("y").unwrap_or(&Value::Null)), "key")?;
            let mut point = vec![0x04];
            point.extend(x);
            point.extend(y);
            match string_of(jwk.get("crv").unwrap_or(&Value::Null)).as_str() {
                "P-256" => P256Key::from_sec1_bytes(&point).map(Public::P256).map_err(|e| err("signature", format!("the transmitter's key {kid} cannot be read: {e}"))),
                "P-384" => P384Key::from_sec1_bytes(&point).map(Public::P384).map_err(|e| err("signature", format!("the transmitter's key {kid} cannot be read: {e}"))),
                _ => Err(err("signature", format!("the transmitter's key {kid} cannot be read: unsupported curve"))),
            }
        }
        "OKP" => {
            let raw = b64url_decode(&string_of(jwk.get("x").unwrap_or(&Value::Null)), "key")?;
            let bytes: [u8; 32] = raw.as_slice().try_into().map_err(|_| err("signature", format!("the transmitter's key {kid} cannot be read: bad OKP length")))?;
            VerifyingKey::from_bytes(&bytes).map(Public::Ed).map_err(|e| err("signature", format!("the transmitter's key {kid} cannot be read: {e}")))
        }
        _ => Err(err("signature", format!("the transmitter's key {kid} cannot be read: unsupported kty {kty}"))),
    }
}

fn hash_bytes(name: &str, data: &[u8]) -> Vec<u8> {
    match name {
        "sha384" => Sha384::digest(data).to_vec(),
        "sha512" => Sha512::digest(data).to_vec(),
        _ => Sha256::digest(data).to_vec(),
    }
}

fn verify_jws(key: &Public, spec: &JwsAlg, data: &[u8], sig: &[u8]) -> bool {
    if spec.hash == "eddsa" {
        let Public::Ed(key) = key else { return false };
        let Ok(signature) = Signature::from_slice(sig) else { return false };
        return key.verify(data, &signature).is_ok();
    }
    let digest = hash_bytes(spec.hash, data);
    if spec.pss {
        let Public::Rsa(key) = key else { return false };
        return match spec.hash {
            "sha384" => key.verify(Pss::new::<Sha384>(), &digest, sig).is_ok(),
            "sha512" => key.verify(Pss::new::<Sha512>(), &digest, sig).is_ok(),
            _ => key.verify(Pss::new::<Sha256>(), &digest, sig).is_ok(),
        };
    }
    if spec.p1363 {
        if sig.len() != spec.size * 2 {
            return false;
        }
        return match (spec.hash, key) {
            ("sha256", Public::P256(key)) => {
                let Ok(signature) = P256Signature::from_slice(sig) else { return false };
                P256Prehash::verify_prehash(key, &digest, &signature).is_ok()
            }
            ("sha384", Public::P384(key)) => {
                let Ok(signature) = P384Signature::from_slice(sig) else { return false };
                P384Prehash::verify_prehash(key, &digest, &signature).is_ok()
            }
            _ => false,
        };
    }
    let Public::Rsa(key) = key else { return false };
    match spec.hash {
        "sha384" => key.verify(Pkcs1v15Sign::new::<Sha384>(), &digest, sig).is_ok(),
        "sha512" => key.verify(Pkcs1v15Sign::new::<Sha512>(), &digest, sig).is_ok(),
        _ => key.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, sig).is_ok(),
    }
}

/// Checks a Security Event Token against the transmitter's keys.
pub fn verify_compact_jws(token: &str, keys: &[Map<String, Value>]) -> Result<(Map<String, Value>, Map<String, Value>), SamlError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(err("signature", "the SET is not a compact JWS"));
    }
    let header_raw = b64url_decode(parts[0], "header")?;
    let payload_raw = b64url_decode(parts[1], "payload")?;
    let header: Value = serde_json::from_slice(&header_raw).map_err(|_| err("signature", "the SET's header or payload is not JSON"))?;
    let payload: Value = serde_json::from_slice(&payload_raw).map_err(|_| err("signature", "the SET's header or payload is not JSON"))?;
    let (Some(header), Some(payload)) = (header.as_object().cloned(), payload.as_object().cloned()) else {
        return Err(err("signature", "the SET's header or payload is not a JSON object"));
    };
    let alg = string_of(header.get("alg").unwrap_or(&Value::Null));
    let Some(spec) = alg_of(&alg) else {
        let shown = if alg.is_empty() { "(no alg)".to_string() } else { alg };
        return Err(err("signature", format!("the SET is signed with {shown}, which this receiver does not verify ({SUPPORTED})")));
    };
    if header.contains_key("crit") {
        return Err(err("signature", "the SET's header has a crit member this receiver does not understand"));
    }
    let kid = header.get("kid").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let mut candidates = Vec::new();
    for key in keys {
        if !kid.is_empty() && string_of(key.get("kid").unwrap_or(&Value::Null)) != kid {
            continue;
        }
        if string_of(key.get("kty").unwrap_or(&Value::Null)) != spec.kty {
            continue;
        }
        let use_name = string_of(key.get("use").unwrap_or(&Value::Null));
        if !use_name.is_empty() && use_name != "sig" {
            continue;
        }
        let key_alg = string_of(key.get("alg").unwrap_or(&Value::Null));
        if !key_alg.is_empty() && key_alg != alg {
            continue;
        }
        candidates.push(key);
    }
    if candidates.is_empty() {
        let which = if kid.is_empty() { String::new() } else { format!(" with kid {kid}") };
        return Err(err("signature", format!("the transmitter publishes no {} signing key{which}", spec.kty)));
    }
    let data = format!("{}.{}", parts[0], parts[1]);
    let signature = b64url_decode(parts[2], "signature")?;
    for jwk in candidates {
        let Ok(key) = key_for_jwk(jwk) else { continue };
        if verify_jws(&key, &spec, data.as_bytes(), &signature) {
            return Ok((header, payload));
        }
    }
    Err(err("signature", "the SET's signature does not verify against the transmitter's keys"))
}
