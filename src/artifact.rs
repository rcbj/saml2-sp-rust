// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use rand::RngCore;
use rsa::RsaPrivateKey;
use sha1::{Digest, Sha1};

use crate::canon::{parse_tree, sign_enveloped, verify_signed_id};
use crate::clock::iso_now;
use crate::error::{err, SamlError};
use crate::http::{send, TlsOptions};
use crate::keys::b64_decode;
use crate::xml::{escape_xml, kids, one, NS_SAML, NS_SAMLP, NS_SOAP, STATUS_SUCCESS};
use crate::xml::BINDING_SOAP;

pub(crate) fn new_id() -> String {
    let mut buf = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let mut out = String::from("_");
    for byte in buf {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

struct ParsedArtifact {
    endpoint_index: i32,
    source_id: [u8; 20],
}

fn parse_artifact(saml_art: &str) -> Result<ParsedArtifact, SamlError> {
    let raw = b64_decode(saml_art).unwrap_or_default();
    if raw.len() != 44 || raw[0] != 0 || raw[1] != 4 {
        return Err(err("artifact", "SAMLart is not a SAML 2.0 type 0x0004 artifact"));
    }
    let mut source_id = [0u8; 20];
    source_id.copy_from_slice(&raw[4..24]);
    let endpoint_index = i32::from(u16::from_be_bytes([raw[2], raw[3]]));
    Ok(ParsedArtifact { endpoint_index, source_id })
}

pub(crate) struct ArtifactInput<'a> {
    pub artifact: &'a str,
    pub entity_id: &'a str,
    pub idp_entity_id: &'a str,
    pub services: &'a std::collections::HashMap<i32, String>,
    pub first_ars: &'a str,
    pub idp_certificates: &'a [Vec<u8>],
    pub key: &'a RsaPrivateKey,
    pub certificate_der: &'a [u8],
    pub tls: Option<&'a TlsOptions>,
}

pub(crate) fn resolve_artifact(data: ArtifactInput<'_>) -> Result<(String, String), SamlError> {
    let parsed = parse_artifact(data.artifact)?;
    let sum = Sha1::digest(data.idp_entity_id.as_bytes());
    if parsed.source_id.as_slice() != sum.as_slice() {
        return Err(err("artifact", format!("the artifact was not issued by {}", data.idp_entity_id)));
    }
    let mut location = data.services.get(&parsed.endpoint_index).cloned().unwrap_or_default();
    if location.is_empty() && parsed.endpoint_index == 0 && !data.services.is_empty() {
        location = data.first_ars.to_string();
    }
    if location.is_empty() {
        return Err(err("artifact", format!("the identity provider's metadata has no SOAP ArtifactResolutionService with index {}", parsed.endpoint_index)));
    }
    let element_id = new_id();
    let unsigned = format!(
        "<samlp:ArtifactResolve xmlns:samlp=\"{NS_SAMLP}\" xmlns:saml=\"{NS_SAML}\" ID=\"{element_id}\" Version=\"2.0\" IssueInstant=\"{}\" Destination=\"{}\"><saml:Issuer>{}</saml:Issuer><samlp:Artifact>{}</samlp:Artifact></samlp:ArtifactResolve>",
        iso_now(),
        escape_xml(&location),
        escape_xml(data.entity_id),
        escape_xml(data.artifact)
    );
    let signed = sign_enveloped(&unsigned, &element_id, data.key, data.certificate_der)?;
    let envelope = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><soap:Envelope xmlns:soap=\"{NS_SOAP}\"><soap:Body>{signed}</soap:Body></soap:Envelope>");
    let answer = send(
        &location,
        "POST",
        &[
            ("content-type", "text/xml; charset=utf-8"),
            ("soapaction", "\"http://www.oasis-open.org/committees/security\""),
            ("accept", "text/xml"),
        ],
        &envelope,
        data.tls,
        "artifact",
    )?;
    if answer.status != 200 {
        return Err(err("artifact", format!("the artifact resolution service answered HTTP {}", answer.status)));
    }
    let root = parse_tree(&answer.body, "the ArtifactResponse")?;
    crate::xml::assert_unique_ids(&root)?;
    let body = if root.ns == NS_SOAP && root.name == "Envelope" { one(&root, NS_SOAP, "Body")? } else { None };
    let preliminary = match body {
        Some(body) => one(body, NS_SAMLP, "ArtifactResponse")?,
        None => None,
    };
    let Some(preliminary) = preliminary else {
        return Err(err("artifact", "the artifact resolution service did not answer with a SOAP ArtifactResponse"));
    };
    let ar_id = preliminary.attr_or("ID").to_string();
    let mut xml = answer.body;
    if let Some(stripped) = verify_signed_id(&xml, &ar_id, data.idp_certificates, "the ArtifactResponse")? {
        xml = stripped;
    }
    let parsed = parse_tree(&xml, "the signed ArtifactResponse")?;
    let nested = crate::xml::descendants(&parsed, NS_SAMLP, "ArtifactResponse");
    let artifact_response = if parsed.ns == NS_SAMLP && parsed.name == "ArtifactResponse" {
        &parsed
    } else if let Some(found) = nested.first() {
        *found
    } else {
        return Err(err("artifact", "the artifact resolution service did not answer with a SOAP ArtifactResponse"));
    };
    if artifact_response.attr_or("InResponseTo") != element_id {
        return Err(err("artifact", "the ArtifactResponse does not answer this ArtifactResolve"));
    }
    if let Some(issuer) = one(artifact_response, NS_SAML, "Issuer")? {
        let text = issuer.text.trim();
        if text != data.idp_entity_id {
            return Err(err("artifact", format!("the ArtifactResponse was issued by {text}")));
        }
    }
    let status = one(artifact_response, NS_SAMLP, "Status")?;
    let mut code = String::new();
    if let Some(status) = status {
        if let Some(code_el) = one(status, NS_SAMLP, "StatusCode")? {
            code = code_el.attr_or("Value").to_string();
        } else {
            code = status.attr_or("Value").to_string();
        }
    }
    if code != STATUS_SUCCESS {
        let shown = if code.is_empty() { "no status".to_string() } else { code };
        return Err(err("artifact", format!("the artifact resolution failed: {shown}")));
    }
    let responses = kids(artifact_response, NS_SAMLP, "Response");
    if responses.is_empty() {
        return Err(err("artifact", "the identity provider did not resolve the artifact (unknown, expired, or already used)"));
    }
    let response_id = responses[0].attr_or("ID").to_string();
    let _ = BINDING_SOAP;
    Ok((xml, response_id))
}
