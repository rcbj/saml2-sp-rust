// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap;

use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::RsaPublicKey;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::bindings::{inflate_raw, query_pairs, uri_unescape};
use crate::canon::parse_tree;
use crate::keys::{b64_decode, b64_standard};
use crate::xml::{descendants, NS_MD};
use crate::{AcsBody, LoginOptions, ServiceProvider};

use super::support::*;

fn field<'a>(fields: &'a [(String, String)], name: &str) -> &'a str {
    fields.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str()).unwrap_or("")
}

#[test]
fn refuses_a_configuration_without_a_key_or_with_another_certificate() {
    let mut bad = test_config(HashMap::new().into_iter().collect(), "");
    bad.insert("privateKey".into(), serde_json::Value::Null);
    rejects(ServiceProvider::create(&bad, "", None).map(|_| ()), "config", "privateKey");
    let mut extra = serde_json::Map::new();
    extra.insert("certificate".into(), json!(idp_key().certificate_pem));
    rejects(ServiceProvider::create(&test_config(extra, ""), "", None).map(|_| ()), "config", "not for the private key");
}

#[test]
fn reads_the_identity_provider_from_its_metadata() {
    let sp = must_sp(serde_json::Map::new(), "");
    assert_eq!(sp.idp.entity_id, IDP_ENTITY);
    assert_eq!(sp.idp.sso.get("redirect").map(String::as_str), Some(SSO_URL));
    assert_eq!(sp.idp.certs.len(), 1);
}

#[test]
fn writes_metadata_with_a_signed_requests_key_and_the_acs_on_all_three_bindings() {
    let sp = must_sp(serde_json::Map::new(), "");
    let xml = sp.metadata();
    let root = parse_tree(&xml, "metadata").unwrap();
    let acs = descendants(&root, NS_MD, "AssertionConsumerService");
    let bindings: Vec<&str> = acs.iter().map(|item| {
        let binding = item.attr_or("Binding");
        assert_eq!(item.attr_or("Location"), ACS_URL);
        binding.rsplit(':').next().unwrap_or("")
    }).collect();
    assert_eq!(bindings.join(","), "HTTP-POST,HTTP-Redirect,HTTP-Artifact");
    assert!(regex::Regex::new(r#"AuthnRequestsSigned="true""#).unwrap().is_match(&xml));
    assert!(regex::Regex::new(r#"<md:KeyDescriptor use="encryption">[\s\S]*xmlenc11#aes256-gcm[\s\S]*</md:KeyDescriptor>"#).unwrap().is_match(&xml));
}

#[test]
fn omits_signals_unless_it_is_false() {
    let sp = must_sp(serde_json::Map::new(), "");
    assert!(!sp.config.has("signals"));
    assert_eq!(sp.config.entity_id, SP_ENTITY);
    assert_eq!(sp.config.acs_url, ACS_URL);
    assert_eq!(sp.config.request_binding, "redirect");
    assert_eq!(sp.config.response_binding, "post");
    let mut extra = serde_json::Map::new();
    extra.insert("signals".into(), json!(true));
    let explicit = must_sp(extra, "");
    assert!(!explicit.config.has("signals"));
    assert_eq!(explicit.config.entity_id, sp.config.entity_id);
    assert_eq!(explicit.config.acs_url, sp.config.acs_url);
}

#[test]
fn records_signals_false_and_still_resolves_the_saml_fields() {
    let mut extra = serde_json::Map::new();
    extra.insert("signals".into(), json!(false));
    extra.insert("wantAssertionsEncrypted".into(), json!(true));
    let sp = must_sp(extra, "");
    assert_eq!(sp.config.signals, Some(false));
    assert_eq!(sp.config.entity_id, SP_ENTITY);
    assert_eq!(sp.config.acs_url, ACS_URL);
    assert_eq!(sp.config.request_binding, "redirect");
    assert_eq!(sp.config.response_binding, "post");
    assert!(sp.config.want_assertions_signed && sp.config.want_assertions_encrypted && !sp.config.allow_unsolicited);
    assert_eq!(sp.config.clock_skew_ms, 60_000);
    assert_eq!(sp.idp.entity_id, IDP_ENTITY);
}

#[test]
fn refuses_a_signals_value_that_is_not_true_or_false() {
    let mut extra = serde_json::Map::new();
    extra.insert("signals".into(), json!("no"));
    rejects(ServiceProvider::create(&test_config(extra, ""), "", None).map(|_| ()), "config", "^signals must be true or false$");
}

#[test]
fn redirect_authn_request_is_deflated_and_signed() {
    let sp = must_sp(serde_json::Map::new(), "");
    let req = sp.login(&LoginOptions { relay_state: Some("/home".into()), ..login_options() }).unwrap();
    assert_eq!(req.binding, "redirect");
    assert!(req.url.starts_with(&format!("{SSO_URL}?")));
    let raw = req.url.split_once('?').unwrap().1;
    let (signed, sig) = raw.split_once("&Signature=").unwrap();
    let sig = uri_unescape(sig).unwrap();
    let digest = Sha256::digest(signed.as_bytes());
    let public = RsaPublicKey::from(&sp_key().private_key);
    assert!(public.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &b64_decode(&sig).unwrap()).is_ok());
    let query = query_pairs(raw);
    let saml = query.iter().find(|(k, _)| k == "SAMLRequest").unwrap().1.clone();
    let xml = String::from_utf8(inflate_raw(&b64_decode(&saml).unwrap()).unwrap()).unwrap();
    assert!(xml.contains(&format!("ID=\"{}\"", req.id)));
    assert!(xml.contains("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\""));
    assert!(xml.contains(&format!("Destination=\"{SSO_URL}\"")));
    assert_eq!(query.iter().find(|(k, _)| k == "RelayState").map(|(_, v)| v.as_str()), Some("/home"));
}

#[test]
fn post_authn_request_is_an_enveloped_signature_in_a_form() {
    let mut extra = serde_json::Map::new();
    extra.insert("requestBinding".into(), json!("post"));
    let sp = must_sp(extra, "");
    let req = sp.login(&LoginOptions { response_binding: "artifact".into(), nonce: "abc".into(), ..login_options() }).unwrap();
    assert_eq!(req.binding, "post");
    let xml = String::from_utf8(b64_decode(field(&req.fields, "SAMLRequest")).unwrap()).unwrap();
    assert!(regex::Regex::new(r"<saml:Issuer>[^<]+</saml:Issuer><ds:Signature").unwrap().is_match(&xml), "{xml}");
    assert!(xml.contains("HTTP-Artifact"), "{xml}");
    assert!(verify_ok(&xml, &sp_key().certificate_der), "{xml}");
    assert!(regex::Regex::new(r#"<script nonce="abc">"#).unwrap().is_match(&req.html));
    assert!(regex::Regex::new(r#"<button type="submit">"#).unwrap().is_match(&req.html));
}

#[test]
fn subject_hint_follows_the_issuer_and_its_signature() {
    let mut extra = serde_json::Map::new();
    extra.insert("requestBinding".into(), json!("post"));
    let sp = must_sp(extra, "");
    let req = sp.login(&LoginOptions {
        subject_hint: Some("alice<&>".into()),
        subject_hint_format: Some("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".into()),
        force_authn: true,
        ..login_options()
    }).unwrap();
    let xml = String::from_utf8(b64_decode(field(&req.fields, "SAMLRequest")).unwrap()).unwrap();
    let re = regex::Regex::new(r#"</ds:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">alice&lt;&amp;&gt;</saml:NameID></saml:Subject><samlp:NameIDPolicy"#).unwrap();
    assert!(re.is_match(&xml), "{xml}");
    assert!(xml.contains("ForceAuthn=\"true\""));
    assert!(verify_ok(&xml, &sp_key().certificate_der));
    let plain = sp.login(&login_options()).unwrap();
    assert!(!plain.xml.contains("<saml:Subject>"));
}

#[test]
fn refuses_a_relay_state_over_80_bytes() {
    let sp = must_sp(serde_json::Map::new(), "");
    let err = sp.login(&LoginOptions { relay_state: Some("x".repeat(81)), ..login_options() }).unwrap_err();
    assert!(err.to_string().contains("80 bytes"), "{err}");
}

#[test]
fn signed_response_and_signed_assertion() {
    let sp = must_sp(serde_json::Map::new(), "");
    let who = post_acs(&sp, &response_xml(&ResponseOpt { in_response_to: "_req1".into(), sign: true, ..ResponseOpt::default() }), "_req1", Some("/home")).unwrap();
    assert_eq!(who.name_id, "alice-1234");
    assert_eq!(who.name_id_format, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
    assert_eq!(who.session_index, "_session1");
    assert_eq!(who.relay_state.as_deref(), Some("/home"));
    assert_eq!(who.binding, "post");
    assert_eq!(who.attributes.get("groups").map(|v| v.join(",")).as_deref(), Some("staff,admins"));
    let mail = "urn:oid:0.9.2342.19200300.100.1.3";
    assert_eq!(who.attributes.get(mail).map(|v| v.join(",")).as_deref(), Some("alice@example.com"));
    assert_eq!(who.attribute_friendly_names.get(mail).map(String::as_str), Some("mail"));
    assert_eq!(who.authn_context_class_ref, "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
}

#[test]
fn accepts_a_signed_assertion_in_an_unsigned_response() {
    let sp = must_sp(serde_json::Map::new(), "");
    let who = post_acs(&sp, &response_xml(&ResponseOpt { in_response_to: "_req1".into(), ..ResponseOpt::default() }), "_req1", None).unwrap();
    assert_eq!(who.name_id, "alice-1234");
}

#[test]
fn refuses_an_unsigned_assertion_by_default() {
    let sp = must_sp(serde_json::Map::new(), "");
    let (raw, _) = assertion_xml(&AssertionOpt { in_response_to: "_r".into(), ..AssertionOpt::default() });
    let xml = response_xml(&ResponseOpt { in_response_to: "_r".into(), sign: true, assertion: raw.clone(), has_assertion: true, ..ResponseOpt::default() });
    rejects(post_acs(&sp, &xml, "_r", None), "validation", "not signed");
    let mut extra = serde_json::Map::new();
    extra.insert("wantAssertionsSigned".into(), json!(false));
    let lax = must_sp(extra, "");
    let who = post_acs(&lax, &xml, "_r", None).unwrap();
    assert_eq!(who.name_id, "alice-1234");
}

#[test]
fn refuses_a_response_with_nothing_signed() {
    let mut extra = serde_json::Map::new();
    extra.insert("wantAssertionsSigned".into(), json!(false));
    let sp = must_sp(extra, "");
    let (raw, _) = assertion_xml(&AssertionOpt { in_response_to: "_r".into(), ..AssertionOpt::default() });
    let xml = response_xml(&ResponseOpt { in_response_to: "_r".into(), assertion: raw, has_assertion: true, ..ResponseOpt::default() });
    rejects(post_acs(&sp, &xml, "_r", None), "validation", "neither");
}

#[test]
fn refuses_an_assertion_altered_after_it_was_signed() {
    let sp = must_sp(serde_json::Map::new(), "");
    let xml = response_xml(&ResponseOpt { in_response_to: "_r".into(), ..ResponseOpt::default() }).replacen("alice-1234", "mallory", 1);
    rejects(post_acs(&sp, &xml, "_r", None), "signature", "");
}

#[test]
fn refuses_a_signature_by_another_key() {
    let sp = must_sp(serde_json::Map::new(), "");
    let (raw, id) = assertion_xml(&AssertionOpt { in_response_to: "_r".into(), ..AssertionOpt::default() });
    let signed = sign_xml(&raw, &id, Some(&sp_key().private_key), Some(&sp_key().certificate_der));
    let xml = response_xml(&ResponseOpt { in_response_to: "_r".into(), assertion: signed, has_assertion: true, ..ResponseOpt::default() });
    rejects(post_acs(&sp, &xml, "_r", None), "signature", "does not verify");
}

#[test]
fn is_not_fooled_by_signature_wrapping() {
    let sp = must_sp(serde_json::Map::new(), "");
    let (signed, id) = signed_assertion(&AssertionOpt { in_response_to: "_r".into(), ..AssertionOpt::default() });
    let (forged, _) = assertion_xml(&AssertionOpt { in_response_to: "_r".into(), name_id: "mallory".into(), ..AssertionOpt::default() });
    let doubled = response_xml(&ResponseOpt { in_response_to: "_r".into(), assertion: format!("{forged}{signed}"), has_assertion: true, ..ResponseOpt::default() });
    rejects(post_acs(&sp, &doubled, "_r", None), "validation", "exactly one");
    let hidden = regex::Regex::new(r#"ID="[^"]+""#).unwrap().replace(&forged, format!("ID=\"{id}\"")).to_string();
    let hidden = hidden.replacen("</saml:Assertion>", &format!("<saml:Advice>{signed}</saml:Advice></saml:Assertion>"), 1);
    let hidden_xml = response_xml(&ResponseOpt { in_response_to: "_r".into(), assertion: hidden, has_assertion: true, ..ResponseOpt::default() });
    rejects(post_acs(&sp, &hidden_xml, "_r", None), "signature", "two elements");
    let sig = regex::Regex::new(r"<ds:Signature[\s\S]*</ds:Signature>").unwrap().find(&signed).unwrap().as_str().to_string();
    let moved = regex::Regex::new(r"(</saml:Issuer>)").unwrap().replace(&forged, format!("${{1}}{sig}")).to_string();
    let moved_xml = response_xml(&ResponseOpt { in_response_to: "_r".into(), assertion: moved, has_assertion: true, ..ResponseOpt::default() });
    rejects(post_acs(&sp, &moved_xml, "_r", None), "signature", "refers to");
}

#[test]
fn refuses_a_response_for_another_audience_acs_or_that_has_expired() {
    let sp = must_sp(serde_json::Map::new(), "");
    let (audience, _) = signed_assertion(&AssertionOpt { in_response_to: "_r".into(), audience: "https://other.test".into(), ..AssertionOpt::default() });
    rejects(post_acs(&sp, &response_xml(&ResponseOpt { in_response_to: "_r".into(), assertion: audience, has_assertion: true, ..ResponseOpt::default() }), "_r", None), "validation", "not for");
    let (recipient, _) = signed_assertion(&AssertionOpt { in_response_to: "_r".into(), recipient: "https://other.test/acs".into(), ..AssertionOpt::default() });
    rejects(post_acs(&sp, &response_xml(&ResponseOpt { in_response_to: "_r".into(), assertion: recipient, has_assertion: true, ..ResponseOpt::default() }), "_r", None), "validation", "Recipient");
    let (expired, _) = signed_assertion(&AssertionOpt { in_response_to: "_r".into(), has_expiry: true, not_on_or_after_ms: -120_000, ..AssertionOpt::default() });
    rejects(post_acs(&sp, &response_xml(&ResponseOpt { in_response_to: "_r".into(), assertion: expired, has_assertion: true, ..ResponseOpt::default() }), "_r", None), "validation", "expired");
    rejects(post_acs(&sp, &response_xml(&ResponseOpt { in_response_to: "_r".into(), has_destination: true, destination: "https://other.test/acs".into(), ..ResponseOpt::default() }), "_r", None), "validation", "addressed to");
    let (issuer, _) = signed_assertion(&AssertionOpt { in_response_to: "_r".into(), issuer: "https://evil.test".into(), ..AssertionOpt::default() });
    rejects(post_acs(&sp, &response_xml(&ResponseOpt { in_response_to: "_r".into(), assertion: issuer, has_assertion: true, ..ResponseOpt::default() }), "_r", None), "validation", "issued by");
}

#[test]
fn refuses_an_answer_to_another_request_and_an_unsolicited_one() {
    let sp = must_sp(serde_json::Map::new(), "");
    rejects(post_acs(&sp, &response_xml(&ResponseOpt { in_response_to: "_r".into(), ..ResponseOpt::default() }), "_other", None), "validation", "not a request this browser");
    rejects(post_acs(&sp, &response_xml(&ResponseOpt { in_response_to: "_r".into(), ..ResponseOpt::default() }), "", None), "validation", "not a request this browser");
    rejects(post_acs(&sp, &response_xml(&ResponseOpt::default()), "", None), "validation", "unsolicited");
    let mut extra = serde_json::Map::new();
    extra.insert("allowUnsolicited".into(), json!(true));
    let open = must_sp(extra, "");
    let who = post_acs(&open, &response_xml(&ResponseOpt::default()), "", None).unwrap();
    assert!(who.in_response_to.is_none());
}

#[test]
fn refuses_the_same_assertion_twice() {
    let sp = must_sp(serde_json::Map::new(), "");
    let xml = response_xml(&ResponseOpt { in_response_to: "_r".into(), sign: true, ..ResponseOpt::default() });
    post_acs(&sp, &xml, "_r", None).unwrap();
    rejects(post_acs(&sp, &xml, "_r", None), "replay", "");
}

#[test]
fn reports_a_non_success_status() {
    let sp = must_sp(serde_json::Map::new(), "");
    let err = post_acs(&sp, &response_xml(&ResponseOpt { in_response_to: "_r".into(), status: "urn:oasis:names:tc:SAML:2.0:status:Responder".into(), ..ResponseOpt::default() }), "_r", None).unwrap_err();
    assert_eq!(err.code, "status");
    assert_eq!(err.status.as_ref().map(|s| s.code.as_str()), Some("urn:oasis:names:tc:SAML:2.0:status:Responder"));
}

#[test]
fn refuses_a_doctype() {
    let sp = must_sp(serde_json::Map::new(), "");
    let xml = format!("<!DOCTYPE x [<!ENTITY e \"x\">]>{}", response_xml(&ResponseOpt { in_response_to: "_r".into(), ..ResponseOpt::default() }));
    rejects(post_acs(&sp, &xml, "_r", None), "xml", "DOCTYPE");
}

#[test]
fn decrypts_an_encrypted_assertion() {
    let sp = must_sp(serde_json::Map::new(), "");
    for cipher_name in ["aes-256-gcm", "aes-128-cbc"] {
        let (made, _) = signed_assertion(&AssertionOpt { in_response_to: "_r".into(), ..AssertionOpt::default() });
        let enc = encrypt_assertion(&made, cipher_name, "", "");
        let who = post_acs(&sp, &response_xml(&ResponseOpt { in_response_to: "_r".into(), sign: true, assertion: enc, has_assertion: true, ..ResponseOpt::default() }), "_r", None).unwrap_or_else(|e| panic!("{cipher_name} {e}"));
        assert_eq!(who.name_id, "alice-1234");
        assert!(who.encrypted, "{cipher_name}");
    }
    let (made, _) = signed_assertion(&AssertionOpt { in_response_to: "_r".into(), ..AssertionOpt::default() });
    let enc = encrypt_assertion(&made, "aes-256-gcm", "oaep256", "");
    let who = post_acs(&sp, &response_xml(&ResponseOpt { in_response_to: "_r".into(), assertion: enc, has_assertion: true, ..ResponseOpt::default() }), "_r", None).unwrap();
    assert_eq!(who.name_id, "alice-1234");
}

#[test]
fn refuses_a_plaintext_assertion_when_encryption_is_required() {
    let mut extra = serde_json::Map::new();
    extra.insert("wantAssertionsEncrypted".into(), json!(true));
    let sp = must_sp(extra, "");
    rejects(post_acs(&sp, &response_xml(&ResponseOpt { in_response_to: "_r".into(), sign: true, ..ResponseOpt::default() }), "_r", None), "validation", "not encrypted");
    let (made, _) = signed_assertion(&AssertionOpt { in_response_to: "_r".into(), ..AssertionOpt::default() });
    let who = post_acs(&sp, &response_xml(&ResponseOpt { in_response_to: "_r".into(), assertion: encrypt_assertion(&made, "", "", ""), has_assertion: true, ..ResponseOpt::default() }), "_r", None).unwrap();
    assert!(who.encrypted);
}

#[test]
fn refuses_an_encrypted_assertion_whose_ciphertext_was_altered() {
    let sp = must_sp(serde_json::Map::new(), "");
    let (made, _) = signed_assertion(&AssertionOpt { in_response_to: "_r".into(), ..AssertionOpt::default() });
    let enc = encrypt_assertion(&made, "", "", "");
    let re = regex::Regex::new(r"<xenc:CipherValue>([^<]+)</xenc:CipherValue>").unwrap();
    let last = re.captures_iter(&enc).last().unwrap().get(1).unwrap().as_str().to_string();
    let mut blob = b64_decode(&last).unwrap();
    blob[20] ^= 1;
    let altered = enc.replacen(&last, &b64_standard(&blob), 1);
    rejects(post_acs(&sp, &response_xml(&ResponseOpt { in_response_to: "_r".into(), assertion: altered, has_assertion: true, ..ResponseOpt::default() }), "_r", None), "decryption", "");
}

#[test]
fn decrypts_an_encrypted_attribute() {
    let sp = must_sp(serde_json::Map::new(), "");
    let secret = encrypt_assertion("<saml:Attribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Name=\"employeeNumber\"><saml:AttributeValue>E-42</saml:AttributeValue></saml:Attribute>", "aes-256-gcm", "oaep256", "EncryptedAttribute");
    let (raw, id) = assertion_xml(&AssertionOpt { in_response_to: "_r".into(), extra: secret, ..AssertionOpt::default() });
    let who = post_acs(&sp, &response_xml(&ResponseOpt { in_response_to: "_r".into(), assertion: sign_xml(&raw, &id, None, None), has_assertion: true, ..ResponseOpt::default() }), "_r", None).unwrap();
    assert_eq!(who.attributes.get("employeeNumber").map(|v| v.join(",")).as_deref(), Some("E-42"));
}

#[test]
fn redirect_response_verifies_the_query_signature() {
    let sp = must_sp(serde_json::Map::new(), "");
    let query = redirect_response_query(&response_xml(&ResponseOpt { in_response_to: "_r".into(), ..ResponseOpt::default() }), "/there", None);
    let who = sp.acs("GET", &format!("/saml/acs?{query}"), &AcsBody::None, &["_r".into()]).unwrap();
    assert_eq!(who.binding, "redirect");
    assert_eq!(who.relay_state.as_deref(), Some("/there"));
}

#[test]
fn refuses_a_query_signature_by_another_key_and_a_changed_relay_state() {
    let sp = must_sp(serde_json::Map::new(), "");
    let forged = redirect_response_query(&response_xml(&ResponseOpt { in_response_to: "_r".into(), ..ResponseOpt::default() }), "/x", Some(&sp_key().private_key));
    rejects(sp.acs("GET", &format!("/saml/acs?{forged}"), &AcsBody::None, &["_r".into()]), "signature", "");
    let changed = redirect_response_query(&response_xml(&ResponseOpt { in_response_to: "_r".into(), ..ResponseOpt::default() }), "/x", None).replacen("RelayState=%2Fx", "RelayState=%2Fy", 1);
    rejects(sp.acs("GET", &format!("/saml/acs?{changed}"), &AcsBody::None, &["_r".into()]), "signature", "");
}

#[test]
fn resolves_the_artifact() {
    let ars = start_ars();
    let mut extra = serde_json::Map::new();
    extra.insert("responseBinding".into(), json!("artifact"));
    let sp = must_sp(extra, &ars.url);
    let req = sp.login(&login_options()).unwrap();
    assert!(req.xml.contains("HTTP-Artifact"), "{}", req.xml);
    let artifact = artifact_for("");
    ars.put(&artifact, &response_xml(&ResponseOpt { in_response_to: req.id.clone(), ..ResponseOpt::default() }));
    let who = sp.acs("GET", &format!("/saml/acs?SAMLart={}&RelayState=%2Fa", crate::bindings::uri_escape(&artifact)), &AcsBody::None, &[req.id]).unwrap();
    assert_eq!(who.binding, "artifact");
    assert_eq!(who.relay_state.as_deref(), Some("/a"));
    assert_eq!(who.name_id, "alice-1234");
    assert_eq!(ars.resolved().join(","), artifact);
}

#[test]
fn accepts_the_artifact_on_a_post_and_fails_when_already_used() {
    let ars = start_ars();
    let sp = must_sp(serde_json::Map::new(), &ars.url);
    let artifact = artifact_for("");
    ars.put(&artifact, &response_xml(&ResponseOpt { in_response_to: "_r".into(), ..ResponseOpt::default() }));
    let body = format!("SAMLart={}", crate::bindings::uri_escape(&artifact));
    let who = sp.acs("POST", "/saml/acs", &AcsBody::Text(body), &["_r".into()]).unwrap();
    assert_eq!(who.binding, "artifact");
    rejects(sp.acs("POST", "/saml/acs", &AcsBody::Map(vec![("SAMLart".into(), artifact)]), &["_r".into()]), "artifact", "did not resolve");
}

#[test]
fn refuses_an_artifact_from_another_identity_provider() {
    let sp = must_sp(serde_json::Map::new(), "https://idp.test/saml2/ars");
    let art = crate::bindings::uri_escape(&artifact_for("https://evil.test"));
    rejects(sp.acs("GET", &format!("/saml/acs?SAMLart={art}"), &AcsBody::None, &["_r".into()]), "artifact", "not issued by");
}

#[test]
fn refuses_a_request_with_no_saml_message() {
    let sp = must_sp(serde_json::Map::new(), "");
    rejects(sp.acs("GET", "/saml/acs", &AcsBody::None, &[]), "binding", "");
}

#[test]
fn parse_xml_helper_stays_available() {
    parse_tree("<a/>", "a").unwrap();
}


