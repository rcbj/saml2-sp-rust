// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap;

use crate::canon::parse_tree;
use crate::config::Config;
use crate::error::{err, SamlError};
use crate::keys::{load_certificate_der, pem_body, public_from_cert, certificate_pem};
use crate::xml::{
    descendants, escape_xml, kids, Elem, BINDING_ARTIFACT, BINDING_POST, BINDING_REDIRECT, BINDING_SOAP, NS_DSIG, NS_MD,
    NS_SAMLP,
};

const ENCRYPTION_METHODS: &[&str] = &[
    "http://www.w3.org/2009/xmlenc11#aes256-gcm",
    "http://www.w3.org/2009/xmlenc11#aes128-gcm",
    "http://www.w3.org/2009/xmlenc11#rsa-oaep",
    "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
];

/// The identity provider material this service provider needs.
pub struct IdpMetadata {
    pub entity_id: String,
    pub sso: HashMap<String, String>,
    pub artifact_resolution_services: HashMap<i32, String>,
    pub(crate) first_ars: String,
    pub certs: Vec<Vec<u8>>,
    pub want_authn_requests_signed: bool,
}

fn certificates_of(role: &Elem, use_name: &str) -> Result<Vec<Vec<u8>>, SamlError> {
    let mut out = Vec::new();
    for descriptor in kids(role, NS_MD, "KeyDescriptor") {
        let declared = descriptor.attr_or("use");
        if !declared.is_empty() && declared != use_name {
            continue;
        }
        for data in descendants(descriptor, NS_DSIG, "X509Data") {
            let first = kids(data, NS_DSIG, "X509Certificate");
            if first.is_empty() {
                continue;
            }
            let pem = to_pem(first[0].text.trim());
            let der = load_certificate_der(&pem).map_err(|e| err("metadata", format!("a {use_name} certificate in the identity provider's metadata cannot be read: {}", e.message)))?;
            public_from_cert(&der).map_err(|e| err("metadata", format!("a {use_name} certificate in the identity provider's metadata cannot be read: {}", e.message)))?;
            out.push(der);
        }
    }
    Ok(out)
}

fn to_pem(b64: &str) -> String {
    let b64: String = b64.split_whitespace().collect();
    let mut lines = Vec::new();
    let bytes = b64.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let j = (i + 64).min(bytes.len());
        lines.push(std::str::from_utf8(&bytes[i..j]).unwrap_or("").to_string());
        i = j;
    }
    format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", lines.join("\n"))
}

pub(crate) fn read_idp_metadata_filtered(xml: &str, entity_id: &str) -> Result<IdpMetadata, SamlError> {
    let root = parse_tree(xml, "the identity provider metadata")?;
    let entity = if root.ns == NS_MD && root.name == "EntityDescriptor" {
        root
    } else if root.ns == NS_MD && root.name == "EntitiesDescriptor" {
        let all: Vec<&Elem> = descendants(&root, NS_MD, "EntityDescriptor").into_iter()
            .filter(|e| !descendants(e, NS_MD, "IDPSSODescriptor").is_empty()).collect();
        let chosen = if !entity_id.is_empty() {
            all.iter().find(|e| e.attr_or("entityID") == entity_id).copied()
        } else if all.len() == 1 {
            Some(all[0])
        } else {
            None
        };
        let Some(chosen) = chosen else {
            if !entity_id.is_empty() {
                return Err(err("metadata", format!("the metadata aggregate has no identity provider {entity_id}")));
            }
            return Err(err("metadata", format!("the metadata aggregate holds {} identity providers; name one with idpEntityId", all.len())));
        };
        chosen.clone()
    } else {
        return Err(err("metadata", "the identity provider metadata is not an EntityDescriptor"));
    };
    let identifier = entity.attr_or("entityID").to_string();
    if identifier.is_empty() {
        return Err(err("metadata", "the identity provider metadata has no entityID"));
    }
    if !entity_id.is_empty() && identifier != entity_id {
        return Err(err("metadata", format!("the metadata describes {identifier}, not {entity_id}")));
    }
    let roles = kids(&entity, NS_MD, "IDPSSODescriptor");
    if roles.is_empty() {
        return Err(err("metadata", format!("{identifier}'s metadata has no IDPSSODescriptor")));
    }
    let role = roles[0];
    let mut sso = HashMap::new();
    for item in kids(role, NS_MD, "SingleSignOnService") {
        let location = item.attr_or("Location");
        if location.is_empty() {
            continue;
        }
        let binding = item.attr_or("Binding");
        if binding == BINDING_REDIRECT && !sso.contains_key("redirect") {
            sso.insert("redirect".to_string(), location.to_string());
        }
        if binding == BINDING_POST && !sso.contains_key("post") {
            sso.insert("post".to_string(), location.to_string());
        }
    }
    let mut services = HashMap::new();
    let mut first = String::new();
    for ars in kids(role, NS_MD, "ArtifactResolutionService") {
        let location = ars.attr_or("Location");
        if ars.attr_or("Binding") == BINDING_SOAP && !location.is_empty() {
            let index = ars.attr_or("index").parse::<i32>().unwrap_or(0);
            if !services.contains_key(&index) {
                services.insert(index, location.to_string());
                if first.is_empty() {
                    first = location.to_string();
                }
            }
        }
    }
    let signing = certificates_of(role, "signing")?;
    if signing.is_empty() {
        return Err(err("metadata", format!("{identifier}'s metadata names no signing certificate")));
    }
    if !sso.contains_key("redirect") && !sso.contains_key("post") {
        return Err(err("metadata", format!("{identifier}'s metadata has no HTTP-Redirect or HTTP-POST SingleSignOnService")));
    }
    Ok(IdpMetadata {
        entity_id: identifier,
        sso,
        artifact_resolution_services: services,
        first_ars: first,
        certs: signing,
        want_authn_requests_signed: role.attr_or("WantAuthnRequestsSigned") == "true",
    })
}

/// Reads an identity provider's metadata document.
pub fn read_idp_metadata(xml: &str) -> Result<IdpMetadata, SamlError> {
    read_idp_metadata_filtered(xml, "")
}

/// This service provider's metadata, without contacting the identity provider.
pub fn metadata_document(cfg: &Config) -> String {
    write_sp_metadata(&cfg.entity_id, &cfg.acs_url, &cfg.certificate_der, cfg.want_assertions_signed, &cfg.name_id_format)
}

fn write_sp_metadata(entity_id: &str, acs_url: &str, cert: &[u8], want_assertions_signed: bool, name_id_format: &str) -> String {
    let cert_body = pem_body(&certificate_pem(cert));
    let key_info = format!("<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_body}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>");
    let mut methods = String::new();
    for method in ENCRYPTION_METHODS {
        methods.push_str(&format!("\n      <md:EncryptionMethod Algorithm=\"{method}\"/>"));
    }
    let key = |use_name: &str| {
        let extra = if use_name == "encryption" { methods.clone() } else { String::new() };
        format!("    <md:KeyDescriptor use=\"{use_name}\">\n      {key_info}{extra}\n    </md:KeyDescriptor>")
    };
    let name_id = if name_id_format.is_empty() {
        String::new()
    } else {
        format!("\n    <md:NameIDFormat>{}</md:NameIDFormat>", escape_xml(name_id_format))
    };
    let want = if want_assertions_signed { "true" } else { "false" };
    let acs = escape_xml(acs_url);
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<md:EntityDescriptor xmlns:md=\"{NS_MD}\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"{}\">\n  <md:SPSSODescriptor protocolSupportEnumeration=\"{NS_SAMLP}\" AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"{want}\">\n{}\n{}{}\n    <md:AssertionConsumerService Binding=\"{BINDING_POST}\" Location=\"{acs}\" index=\"0\" isDefault=\"true\"/>\n    <md:AssertionConsumerService Binding=\"{BINDING_REDIRECT}\" Location=\"{acs}\" index=\"1\"/>\n    <md:AssertionConsumerService Binding=\"{BINDING_ARTIFACT}\" Location=\"{acs}\" index=\"2\"/>\n  </md:SPSSODescriptor>\n</md:EntityDescriptor>\n",
        escape_xml(entity_id),
        key("signing"),
        key("encryption"),
        name_id
    )
}

