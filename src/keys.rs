// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use base64::Engine as _;
use rsa::BigUint;
use rand::rngs::OsRng;
use rcgen::{CertificateParams, DnType, IsCa, KeyPair as RcKeyPair, KeyUsagePurpose, ExtendedKeyUsagePurpose};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use x509_parser::public_key::PublicKey;

use crate::clock::format_valid_to;
use crate::error::{err, SamlError};

/// A self-signed certificate and the RSA key it names.
pub struct KeyMaterial {
    pub private_key_pem: String,
    pub certificate_pem: String,
    pub private_key: RsaPrivateKey,
    pub certificate_der: Vec<u8>,
}

impl KeyMaterial {
    pub fn fingerprint256(&self) -> String {
        let sum = Sha256::digest(&self.certificate_der);
        sum.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
    }

    pub fn valid_to(&self) -> String {
        let Ok((_, cert)) = X509Certificate::from_der(&self.certificate_der) else {
            return String::new();
        };
        format_valid_to(cert.validity().not_after.to_datetime())
    }

    pub fn public_key(&self) -> rsa::RsaPublicKey {
        rsa::RsaPublicKey::from(&self.private_key)
    }
}

/// An RSA key and a self-signed certificate. `bits` is 2048, 3072, or 4096.
pub fn create_self_signed_key_pair(common_name: &str, days: i64, bits: usize) -> Result<KeyMaterial, SamlError> {
    let days = if days <= 0 { 1095 } else { days };
    let bits = if bits == 0 { 3072 } else { bits };
    let private_key = RsaPrivateKey::new(&mut OsRng, bits).map_err(|e| err("config", format!("the key could not be generated: {e}")))?;
    let pkcs8 = private_key.to_pkcs8_der().map_err(|e| err("config", format!("the key could not be encoded: {e}")))?;
    let rc_key = RcKeyPair::try_from(pkcs8.as_bytes()).map_err(|e| err("config", format!("the key could not be read for the certificate: {e}")))?;
    let not_before = OffsetDateTime::now_utc() - Duration::seconds(60);
    let not_after = not_before + Duration::days(days);
    let mut params = CertificateParams::default();
    params.not_before = not_before;
    params.not_after = not_after;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, common_name);
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.self_signed(&rc_key).map_err(|e| err("config", format!("the certificate could not be signed: {e}")))?;
    let der = cert.der().to_vec();
    let certificate_pem = cert.pem();
    let private_key_pem = private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| err("config", format!("the key could not be encoded: {e}")))?
        .to_string();
    Ok(KeyMaterial { private_key_pem, certificate_pem, private_key, certificate_der: der })
}

pub(crate) fn load_private_key(pem_text: &str) -> Result<RsaPrivateKey, SamlError> {
    if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(pem_text) {
        return Ok(key);
    }
    if let Ok(key) = RsaPrivateKey::from_pkcs1_pem(pem_text) {
        return Ok(key);
    }
    let kind = if pem_text.contains("EC PRIVATE KEY") {
        "ec"
    } else if pem_text.contains("OPENSSH") {
        "openssh"
    } else {
        "unrecognized"
    };
    if pem_text.contains("BEGIN") && kind != "unrecognized" {
        return Err(err("config", format!("the private key is {kind}; an RSA key is required")));
    }
    Err(err("config", format!("the private key or certificate cannot be read: unrecognized private key")))
}

pub(crate) fn load_certificate_der(pem_text: &str) -> Result<Vec<u8>, SamlError> {
    pem_der(pem_text).map_err(|e| err("config", format!("the private key or certificate cannot be read: {e}")))
}

pub(crate) fn pem_der(pem_text: &str) -> Result<Vec<u8>, String> {
    let mut body = String::new();
    for line in pem_text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("-----") {
            continue;
        }
        body.push_str(line);
    }
    if body.is_empty() {
        return Err("no PEM block".to_string());
    }
    base64::engine::general_purpose::STANDARD.decode(body).map_err(|e| e.to_string())
}

pub(crate) fn private_pem(key: &RsaPrivateKey) -> String {
    key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).map(|pem| pem.to_string()).unwrap_or_default()
}

pub(crate) fn certificate_pem(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut lines = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        lines.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        lines.push('\n');
    }
    lines.push_str("-----END CERTIFICATE-----\n");
    lines
}

pub(crate) fn pem_body(pem_text: &str) -> String {
    let mut body = String::new();
    for line in pem_text.replace('\r', "\n").lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("-----") {
            continue;
        }
        body.push_str(line);
    }
    body
}

pub(crate) fn public_from_cert(der: &[u8]) -> Result<rsa::RsaPublicKey, SamlError> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| err("metadata", format!("a certificate cannot be read: {e}")))?;
    let parsed = cert.public_key().parsed().map_err(|e| err("metadata", format!("a certificate cannot be read: {e}")))?;
    match parsed {
        PublicKey::RSA(key) => {
            let n = BigUint::from_bytes_be(key.modulus);
            let e = BigUint::from_bytes_be(key.exponent);
            rsa::RsaPublicKey::new(n, e).map_err(|e| err("metadata", format!("a certificate cannot be read: {e}")))
        }
        _ => Err(err("metadata", "a certificate is not an RSA key")),
    }
}

pub(crate) fn same_public(key: &RsaPrivateKey, der: &[u8]) -> bool {
    let Ok(public) = public_from_cert(der) else { return false };
    key.n() == public.n() && key.e() == public.e()
}

pub(crate) fn b64_standard(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub(crate) fn b64_decode(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let compact: String = value.split_whitespace().collect();
    base64::engine::general_purpose::STANDARD.decode(compact)
}
