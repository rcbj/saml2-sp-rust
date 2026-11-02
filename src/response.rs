// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap;

use rsa::RsaPrivateKey;

use crate::canon::{parse_tree, verify_signed_id};
use crate::clock::{iso_ms, parse_instant};
use crate::encryption::decrypt_element;
use crate::error::{err, err_status, SamlError, SamlStatus};
use crate::replay::{now_ms, MemoryReplayCache};
use crate::xml::{assert_unique_ids, kids, one, Elem, CM_BEARER, NS_SAML, NS_SAMLP, STATUS_SUCCESS};

/// A person the assertion consumer accepted.
#[derive(Clone, Debug)]
pub struct SamlLogin {
    pub name_id: String,
    pub name_id_format: String,
    pub name_qualifier: String,
    pub sp_name_qualifier: String,
    pub session_index: String,
    pub session_not_on_or_after_ms: Option<i64>,
    pub authn_instant_ms: i64,
    pub authn_context_class_ref: String,
    pub attributes: HashMap<String, Vec<String>>,
    pub attribute_friendly_names: HashMap<String, String>,
    pub issuer: String,
    pub in_response_to: Option<String>,
    pub relay_state: Option<String>,
    pub binding: String,
    pub encrypted: bool,
    pub response_id: String,
    pub assertion_id: String,
}

pub(crate) struct Received {
    pub xml: String,
    pub binding: String,
    pub relay_state: Option<String>,
    pub authenticated_by_binding: bool,
    pub response_id: String,
}

pub(crate) struct ValidationContext<'a> {
    pub entity_id: &'a str,
    pub acs_url: &'a str,
    pub idp_entity_id: &'a str,
    pub idp_certificates: &'a [Vec<u8>],
    pub decryption_key: &'a RsaPrivateKey,
    pub clock_skew_ms: i64,
    pub want_assertions_signed: bool,
    pub want_assertions_encrypted: bool,
    pub allow_unsolicited: bool,
    pub replay: &'a MemoryReplayCache,
    pub expected_request_ids: &'a [String],
}

fn invalid(message: impl Into<String>) -> SamlError {
    err("validation", message)
}

fn issuer_of(el: &Elem, required: bool, expected: &str, what: &str) -> Result<(), SamlError> {
    let issuer = one(el, NS_SAML, "Issuer")?;
    let Some(issuer) = issuer else {
        if required {
            return Err(invalid(format!("{what} has no Issuer")));
        }
        return Ok(());
    };
    let form = issuer.attr_or("Format");
    if !form.is_empty() && form != "urn:oasis:names:tc:SAML:2.0:nameid-format:entity" {
        return Err(invalid(format!("{what}'s Issuer has the Format {form}")));
    }
    let text = issuer.text.trim();
    if text != expected {
        return Err(invalid(format!("{what} was issued by {text}, not by {expected}")));
    }
    Ok(())
}

fn status_of(response: &Elem) -> Result<SamlStatus, SamlError> {
    let status = one(response, NS_SAMLP, "Status")?.ok_or_else(|| invalid("the Response has no Status"))?;
    let top = one(status, NS_SAMLP, "StatusCode")?.ok_or_else(|| invalid("the Response has no StatusCode"))?;
    let mut out = SamlStatus { code: top.attr_or("Value").to_string(), sub_code: String::new(), message: String::new() };
    if let Some(sub) = one(top, NS_SAMLP, "StatusCode")? {
        if !sub.attr_or("Value").is_empty() {
            out.sub_code = sub.attr_or("Value").to_string();
        }
    }
    if let Some(message) = one(status, NS_SAMLP, "StatusMessage")? {
        let text = message.text.trim();
        if !text.is_empty() {
            out.message = text.to_string();
        }
    }
    Ok(out)
}

pub(crate) fn validate_response(received: &Received, ctx: &ValidationContext<'_>) -> Result<SamlLogin, SamlError> {
    let now = now_ms();
    let skew = ctx.clock_skew_ms;
    let mut xml = received.xml.clone();
    let mut doc = parse_tree(&xml, "the Response")?;
    assert_unique_ids(&doc)?;
    if doc.ns != NS_SAMLP || doc.name != "Response" {
        let found = crate::xml::descendants(&doc, NS_SAMLP, "Response");
        if let Some(response) = found.into_iter().find(|el| el.attr_or("ID") == received.response_id) {
            doc = response.clone();
        } else if doc.name != "Response" {
            return Err(invalid(format!("the message is a <{}>, not a Response", doc.name)));
        }
    }
    if doc.ns != NS_SAMLP || doc.name != "Response" {
        return Err(invalid(format!("the message is a <{}>, not a Response", doc.name)));
    }
    let response_id = doc.attr("ID").filter(|v| !v.is_empty()).ok_or_else(|| invalid("the Response has no ID"))?.to_string();
    let signed = verify_signed_id(&xml, &response_id, ctx.idp_certificates, "the Response")?;
    let response_authenticated = signed.is_some() || received.authenticated_by_binding;
    if let Some(stripped) = signed {
        xml = stripped;
        doc = parse_tree(&xml, "the signed Response")?;
    }
    let version = doc.attr_or("Version");
    if version != "2.0" {
        let shown = if version.is_empty() { "(none)" } else { version };
        return Err(invalid(format!("the Response is version {shown}, not 2.0")));
    }
    let response_id = doc.attr("ID").filter(|v| !v.is_empty()).ok_or_else(|| invalid("the Response has no ID"))?.to_string();
    issuer_of(&doc, false, ctx.idp_entity_id, "the Response")?;
    let has_dest = doc.has_attr("Destination");
    let destination = doc.attr_or("Destination");
    if has_dest && destination != ctx.acs_url {
        return Err(invalid(format!("the Response is addressed to {destination}, not to {}", ctx.acs_url)));
    }
    if !has_dest && response_authenticated && received.binding != "artifact" {
        return Err(invalid("the Response is signed but has no Destination"));
    }
    let has_in = doc.has_attr("InResponseTo");
    let in_response_to = doc.attr_or("InResponseTo").to_string();
    let in_ptr = if has_in {
        if !ctx.expected_request_ids.iter().any(|id| id == &in_response_to) {
            return Err(invalid(format!("the Response answers {in_response_to}, which is not a request this browser has outstanding")));
        }
        Some(in_response_to.clone())
    } else if !ctx.allow_unsolicited {
        return Err(invalid("the Response is unsolicited (it has no InResponseTo), and unsolicited Responses are not accepted"));
    } else {
        None
    };
    let status = status_of(&doc)?;
    if status.code != STATUS_SUCCESS {
        let detail = if status.sub_code.is_empty() { status.code.clone() } else { status.sub_code.clone() };
        let suffix = if status.message.is_empty() { String::new() } else { format!(": {}", status.message) };
        return Err(err_status(format!("the identity provider answered {detail}{suffix}"), status));
    }
    let plain = kids(&doc, NS_SAML, "Assertion");
    let encrypted = kids(&doc, NS_SAML, "EncryptedAssertion");
    if plain.len() + encrypted.len() != 1 {
        return Err(invalid(format!("the Response holds {} assertions; exactly one is accepted", plain.len() + encrypted.len())));
    }
    let (mut assertion, was_encrypted) = if encrypted.len() == 1 {
        let assertion_xml = decrypt_element(encrypted[0], ctx.decryption_key)?;
        let parsed = parse_tree(&assertion_xml, "the decrypted assertion")?;
        assert_unique_ids(&parsed)?;
        if parsed.ns != NS_SAML || parsed.name != "Assertion" {
            return Err(invalid("the EncryptedAssertion does not hold an Assertion"));
        }
        (parsed, true)
    } else {
        if ctx.want_assertions_encrypted {
            return Err(invalid("the assertion is not encrypted, and wantAssertionsEncrypted is on"));
        }
        (plain[0].clone(), false)
    };
    let assertion_id_for_sig = assertion.attr("ID").unwrap_or("").to_string();
    let assertion_xml = if was_encrypted {
        // The decrypted document is the assertion itself.
        // Rebuild is unnecessary: verify against the decrypted XML.
        // parse_tree dropped the original string; decrypt_element returned it.
        // Re-decrypt is wasteful; keep the string above.
        String::new()
    } else {
        xml.clone()
    };
    let signed_assertion = if was_encrypted {
        let assertion_xml = decrypt_element(encrypted[0], ctx.decryption_key)?;
        verify_signed_id(&assertion_xml, &assertion_id_for_sig, ctx.idp_certificates, "the assertion")?
    } else {
        verify_signed_id(&assertion_xml, &assertion_id_for_sig, ctx.idp_certificates, "the assertion")?
    };
    if let Some(stripped) = signed_assertion {
        assertion = parse_tree(&stripped, "the signed assertion")?;
    } else if ctx.want_assertions_signed {
        return Err(invalid("the assertion is not signed, and wantAssertionsSigned is on"));
    } else if !response_authenticated {
        return Err(invalid("neither the Response nor its assertion is signed"));
    }
    if assertion.attr_or("Version") != "2.0" {
        return Err(invalid("the assertion is not version 2.0"));
    }
    let assertion_id = assertion.attr("ID").filter(|v| !v.is_empty()).ok_or_else(|| invalid("the assertion has no ID"))?.to_string();
    issuer_of(&assertion, true, ctx.idp_entity_id, "the assertion")?;
    let subject = one(&assertion, NS_SAML, "Subject")?.ok_or_else(|| invalid("the assertion has no Subject"))?;
    let mut name_id = one(subject, NS_SAML, "NameID")?.cloned();
    if name_id.is_none() {
        if let Some(encrypted_id) = one(subject, NS_SAML, "EncryptedID")? {
            let xml = decrypt_element(encrypted_id, ctx.decryption_key)?;
            let parsed = parse_tree(&xml, "the decrypted NameID")?;
            if parsed.ns != NS_SAML || parsed.name != "NameID" {
                return Err(invalid("the EncryptedID does not hold a NameID"));
            }
            name_id = Some(parsed);
        }
    }
    let name_id = name_id.ok_or_else(|| invalid("the assertion's Subject has no NameID"))?;
    if name_id.text.trim().is_empty() {
        return Err(invalid("the assertion's Subject has no NameID"));
    }
    let mut reasons = Vec::new();
    let mut confirmed_until = None;
    for confirmation in kids(subject, NS_SAML, "SubjectConfirmation") {
        if confirmation.attr_or("Method") != CM_BEARER {
            reasons.push(format!("method {}", confirmation.attr_or("Method")));
            continue;
        }
        let Some(data) = one(confirmation, NS_SAML, "SubjectConfirmationData")? else {
            reasons.push("no SubjectConfirmationData".to_string());
            continue;
        };
        let recipient = data.attr_or("Recipient");
        let not_on_or_after = parse_instant(data.attr_or("NotOnOrAfter"), "SubjectConfirmationData NotOnOrAfter")?;
        let has_not_before = data.has_attr("NotBefore");
        let has_sc = data.has_attr("InResponseTo");
        let sc_in = data.attr_or("InResponseTo");
        if recipient != ctx.acs_url {
            let shown = if recipient.is_empty() { "(none)" } else { recipient };
            reasons.push(format!("Recipient {shown}"));
        } else if not_on_or_after.is_none() {
            reasons.push("no NotOnOrAfter".to_string());
        } else if not_on_or_after.unwrap() <= now - skew {
            reasons.push(format!("expired at {}", iso_ms(not_on_or_after.unwrap())));
        } else if has_not_before {
            reasons.push("a NotBefore, which a bearer confirmation must not have".to_string());
        } else if (has_sc && in_ptr.as_deref() != Some(sc_in)) || (!has_sc && in_ptr.is_some()) {
            let shown = if !has_sc || sc_in.is_empty() { "(none)" } else { sc_in };
            reasons.push(format!("InResponseTo {shown}"));
        } else {
            confirmed_until = not_on_or_after;
            break;
        }
    }
    let confirmed_until = confirmed_until.ok_or_else(|| {
        let why = if reasons.is_empty() { "there is none".to_string() } else { reasons.join("; ") };
        invalid(format!("no bearer SubjectConfirmation of the assertion fits: {why}"))
    })?;
    let conditions = one(&assertion, NS_SAML, "Conditions")?.ok_or_else(|| invalid("the assertion has no Conditions, so it names no audience"))?;
    let not_before_c = parse_instant(conditions.attr_or("NotBefore"), "Conditions NotBefore")?;
    let not_on_or_after_c = parse_instant(conditions.attr_or("NotOnOrAfter"), "Conditions NotOnOrAfter")?;
    if let Some(start) = not_before_c {
        if start > now + skew {
            return Err(invalid(format!("the assertion is not valid before {}", iso_ms(start))));
        }
    }
    if let Some(end) = not_on_or_after_c {
        if end <= now - skew {
            return Err(invalid(format!("the assertion expired at {}", iso_ms(end))));
        }
    }
    let restrictions = kids(conditions, NS_SAML, "AudienceRestriction");
    if restrictions.is_empty() {
        return Err(invalid("the assertion has no AudienceRestriction"));
    }
    for restriction in restrictions {
        let ok_aud = kids(restriction, NS_SAML, "Audience").iter().any(|a| a.text.trim() == ctx.entity_id);
        if !ok_aud {
            return Err(invalid(format!("the assertion is not for {}", ctx.entity_id)));
        }
    }
    let authn_statements = kids(&assertion, NS_SAML, "AuthnStatement");
    if authn_statements.is_empty() {
        return Err(invalid("the assertion has no AuthnStatement"));
    }
    let authn = authn_statements[0];
    let authn_instant = parse_instant(authn.attr_or("AuthnInstant"), "AuthnInstant")?.ok_or_else(|| invalid("the AuthnStatement has no AuthnInstant"))?;
    let session_not = parse_instant(authn.attr_or("SessionNotOnOrAfter"), "SessionNotOnOrAfter")?;
    if let Some(end) = session_not {
        if end <= now - skew {
            return Err(invalid("the identity provider's session has already ended"));
        }
    }
    let mut class_ref = String::new();
    if let Some(context) = one(authn, NS_SAML, "AuthnContext")? {
        if let Some(refer) = one(context, NS_SAML, "AuthnContextClassRef")? {
            class_ref = refer.text.trim().to_string();
        }
    }
    let mut attributes: HashMap<String, Vec<String>> = HashMap::new();
    let mut friendly = HashMap::new();
    for statement in kids(&assertion, NS_SAML, "AttributeStatement") {
        let mut decrypted = Vec::new();
        for enc in kids(statement, NS_SAML, "EncryptedAttribute") {
            let xml = decrypt_element(enc, ctx.decryption_key)?;
            let element = parse_tree(&xml, "the decrypted attribute")?;
            if element.ns != NS_SAML || element.name != "Attribute" {
                return Err(invalid("an EncryptedAttribute does not hold an Attribute"));
            }
            decrypted.push(element);
        }
        let mut attrs: Vec<&Elem> = kids(statement, NS_SAML, "Attribute");
        let decrypted_refs: Vec<&Elem> = decrypted.iter().collect();
        attrs.extend(decrypted_refs);
        for attribute in attrs {
            let name = attribute.attr_or("Name");
            if name.is_empty() {
                continue;
            }
            let mut values = Vec::new();
            for value in kids(attribute, NS_SAML, "AttributeValue") {
                values.push(value.text.clone());
            }
            attributes.entry(name.to_string()).or_default().extend(values);
            if let Some(friend) = attribute.attr("FriendlyName") {
                if !friend.is_empty() {
                    friendly.insert(name.to_string(), friend.to_string());
                }
            }
        }
    }
    let mut keep = confirmed_until;
    if let Some(end) = not_on_or_after_c {
        if end > keep {
            keep = end;
        }
    }
    keep += skew;
    let replay_key = format!("{} {assertion_id}", ctx.idp_entity_id);
    if ctx.replay.check_and_record(&replay_key, keep)? {
        return Err(err("replay", format!("the assertion {assertion_id} has been accepted before")));
    }
    Ok(SamlLogin {
        name_id: name_id.text.trim().to_string(),
        name_id_format: name_id.attr_or("Format").to_string(),
        name_qualifier: name_id.attr_or("NameQualifier").to_string(),
        sp_name_qualifier: name_id.attr_or("SPNameQualifier").to_string(),
        session_index: authn.attr_or("SessionIndex").to_string(),
        session_not_on_or_after_ms: session_not,
        authn_instant_ms: authn_instant,
        authn_context_class_ref: class_ref,
        attributes,
        attribute_friendly_names: friendly,
        issuer: ctx.idp_entity_id.to_string(),
        in_response_to: in_ptr,
        relay_state: received.relay_state.clone(),
        binding: received.binding.clone(),
        encrypted: was_encrypted,
        response_id,
        assertion_id,
    })
}
