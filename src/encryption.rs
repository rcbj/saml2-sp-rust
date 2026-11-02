// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use aes::Aes192;
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm, KeyInit};

type Aes192Gcm = AesGcm<Aes192, U12>;
use cipher::{BlockDecryptMut, KeyIvInit};
use rsa::oaep::Oaep;
use rsa::RsaPrivateKey;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};

use crate::error::{err, SamlError};
use crate::keys::b64_decode;
use crate::xml::{one, Elem, NS_DSIG, NS_XENC, NS_XENC11};

struct CipherSpec {
    name: &'static str,
    gcm: bool,
    key_len: usize,
}

fn cipher_of(alg: &str) -> Option<CipherSpec> {
    Some(match alg {
        "http://www.w3.org/2009/xmlenc11#aes128-gcm" => CipherSpec { name: "aes-128-gcm", gcm: true, key_len: 16 },
        "http://www.w3.org/2009/xmlenc11#aes192-gcm" => CipherSpec { name: "aes-192-gcm", gcm: true, key_len: 24 },
        "http://www.w3.org/2009/xmlenc11#aes256-gcm" => CipherSpec { name: "aes-256-gcm", gcm: true, key_len: 32 },
        "http://www.w3.org/2001/04/xmlenc#aes128-cbc" => CipherSpec { name: "aes-128-cbc", gcm: false, key_len: 16 },
        "http://www.w3.org/2001/04/xmlenc#aes192-cbc" => CipherSpec { name: "aes-192-cbc", gcm: false, key_len: 24 },
        "http://www.w3.org/2001/04/xmlenc#aes256-cbc" => CipherSpec { name: "aes-256-cbc", gcm: false, key_len: 32 },
        _ => return None,
    })
}

const OAEP_MGF1P: &str = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
const OAEP11: &str = "http://www.w3.org/2009/xmlenc11#rsa-oaep";

fn oaep_digest(alg: &str) -> Option<&'static str> {
    Some(match alg {
        "http://www.w3.org/2000/09/xmldsig#sha1" => "sha1",
        "http://www.w3.org/2001/04/xmlenc#sha256" => "sha256",
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => "sha384",
        "http://www.w3.org/2001/04/xmlenc#sha512" => "sha512",
        _ => return None,
    })
}

fn oaep_mgf(alg: &str) -> Option<&'static str> {
    Some(match alg {
        "http://www.w3.org/2009/xmlenc11#mgf1sha1" => "sha1",
        "http://www.w3.org/2009/xmlenc11#mgf1sha256" => "sha256",
        "http://www.w3.org/2009/xmlenc11#mgf1sha384" => "sha384",
        "http://www.w3.org/2009/xmlenc11#mgf1sha512" => "sha512",
        _ => return None,
    })
}

fn decrypt_fail(message: impl Into<String>) -> SamlError {
    err("decryption", message)
}

fn unwrap_key(encrypted_key: &Elem, key: &RsaPrivateKey) -> Result<Vec<u8>, SamlError> {
    let method = one(encrypted_key, NS_XENC, "EncryptionMethod")?;
    let alg = method.map(|m| m.attr_or("Algorithm")).unwrap_or("");
    if alg != OAEP_MGF1P && alg != OAEP11 {
        return Err(decrypt_fail(format!("the content key is wrapped with {}; only RSA-OAEP is accepted", if alg.is_empty() { "(none)" } else { alg })));
    }
    let mut digest = "sha1";
    if let Some(method) = method {
        if let Some(digest_method) = one(method, NS_DSIG, "DigestMethod")? {
            let digest_alg = digest_method.attr_or("Algorithm");
            digest = oaep_digest(digest_alg).ok_or_else(|| decrypt_fail(format!("the OAEP digest {digest_alg} is not supported")))?;
        }
    }
    let mut mgf = "sha1";
    if alg == OAEP11 {
        if let Some(method) = method {
            if let Some(mgf_el) = one(method, NS_XENC11, "MGF")? {
                let mgf_alg = mgf_el.attr_or("Algorithm");
                if !mgf_alg.is_empty() {
                    mgf = oaep_mgf(mgf_alg).ok_or_else(|| decrypt_fail(format!("the OAEP mask generation function {mgf_alg} is not supported")))?;
                }
            }
        }
    }
    if mgf != digest {
        return Err(decrypt_fail(format!("OAEP with digest {digest} and MGF1 {mgf} is not supported; one hash is used for both")));
    }
    let values = crate::xml::descendants(encrypted_key, NS_XENC, "CipherValue");
    let raw = values.first().map(|v| v.text.trim()).unwrap_or("");
    let blob = b64_decode(raw).map_err(|_| decrypt_fail("the content key could not be unwrapped with this service provider's key"))?;
    let plain = match digest {
        "sha1" => key.decrypt(Oaep::new::<Sha1>(), &blob),
        "sha256" => key.decrypt(Oaep::new::<Sha256>(), &blob),
        "sha384" => key.decrypt(Oaep::new::<Sha384>(), &blob),
        "sha512" => key.decrypt(Oaep::new::<Sha512>(), &blob),
        _ => return Err(decrypt_fail(format!("the OAEP digest {digest} is not supported"))),
    };
    plain.map_err(|_| decrypt_fail("the content key could not be unwrapped with this service provider's key"))
}

pub(crate) fn decrypt_element(encrypted: &Elem, key: &RsaPrivateKey) -> Result<String, SamlError> {
    let data = one(encrypted, NS_XENC, "EncryptedData")?.ok_or_else(|| decrypt_fail(format!("<{}> has no EncryptedData", encrypted.name)))?;
    let method = one(data, NS_XENC, "EncryptionMethod")?;
    let alg = method.map(|m| m.attr_or("Algorithm")).unwrap_or("");
    let spec = cipher_of(alg).ok_or_else(|| decrypt_fail(format!("the content is encrypted with {}, which is not supported", if alg.is_empty() { "(none)" } else { alg })))?;
    let keys = crate::xml::descendants(encrypted, NS_XENC, "EncryptedKey");
    let encrypted_key = keys.first().ok_or_else(|| decrypt_fail(format!("<{}> carries no EncryptedKey", encrypted.name)))?;
    let content_key = unwrap_key(encrypted_key, key)?;
    if content_key.len() != spec.key_len {
        return Err(decrypt_fail(format!("the content key is {} bytes; {} needs {}", content_key.len(), spec.name, spec.key_len)));
    }
    let cipher_data = one(data, NS_XENC, "CipherData")?;
    let cipher_value = match cipher_data {
        Some(node) => one(node, NS_XENC, "CipherValue")?,
        None => None,
    };
    let blob = b64_decode(cipher_value.map(|v| v.text.as_str()).unwrap_or("")).map_err(|_| decrypt_fail("the content could not be decrypted"))?;
    if spec.gcm {
        if blob.len() < 12 + 16 {
            return Err(decrypt_fail("the ciphertext is too short"));
        }
        let nonce = aes_gcm::Nonce::from_slice(&blob[..12]);
        let ct = &blob[12..];
        let plain = match spec.key_len {
            16 => Aes128Gcm::new_from_slice(&content_key).ok().and_then(|c| c.decrypt(nonce, Payload { msg: ct, aad: b"" }).ok()),
            24 => Aes192Gcm::new_from_slice(&content_key).ok().and_then(|c| c.decrypt(nonce, Payload { msg: ct, aad: b"" }).ok()),
            _ => Aes256Gcm::new_from_slice(&content_key).ok().and_then(|c| c.decrypt(nonce, Payload { msg: ct, aad: b"" }).ok()),
        };
        let plain = plain.ok_or_else(|| decrypt_fail("the content could not be decrypted"))?;
        return String::from_utf8(plain).map_err(|_| decrypt_fail("the content could not be decrypted"));
    }
    if blob.len() < 32 || blob.len() % 16 != 0 {
        return Err(decrypt_fail("the ciphertext is not a whole number of blocks"));
    }
    let mut plain = blob[16..].to_vec();
    let opened = match spec.key_len {
        16 => cbc::Decryptor::<aes::Aes128>::new_from_slices(&content_key, &blob[..16]).ok().and_then(|d| d.decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut plain).ok()),
        24 => cbc::Decryptor::<aes::Aes192>::new_from_slices(&content_key, &blob[..16]).ok().and_then(|d| d.decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut plain).ok()),
        _ => cbc::Decryptor::<aes::Aes256>::new_from_slices(&content_key, &blob[..16]).ok().and_then(|d| d.decrypt_padded_mut::<cipher::block_padding::NoPadding>(&mut plain).ok()),
    };
    let plain = opened.ok_or_else(|| decrypt_fail("the content could not be decrypted"))?;
    if plain.is_empty() {
        return Err(decrypt_fail("the decrypted content is not padded as XML Encryption pads it"));
    }
    let pad = *plain.last().unwrap() as usize;
    if pad < 1 || pad > 16 || pad > plain.len() || plain[plain.len() - pad..].iter().any(|b| *b as usize != pad) {
        return Err(decrypt_fail("the decrypted content is not padded as XML Encryption pads it"));
    }
    String::from_utf8(plain[..plain.len() - pad].to_vec()).map_err(|_| decrypt_fail("the content could not be decrypted"))
}

