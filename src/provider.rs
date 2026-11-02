// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::artifact::{new_id, resolve_artifact, ArtifactInput};
use crate::bindings::{post_form_html, query_pairs, read_post, read_redirect, redirect_query};
use crate::canon::sign_enveloped;
use crate::clock::iso_now;
use crate::config::{read_config_file, resolve_config, Config};
use crate::error::{err, SamlError};
use crate::http::{send, TlsOptions};
use crate::keys::b64_standard;
use crate::metadata::{metadata_document, read_idp_metadata_filtered, IdpMetadata};
use crate::replay::MemoryReplayCache;
use crate::response::{validate_response, Received, SamlLogin, ValidationContext};
use crate::xml::{escape_xml, BINDING_ARTIFACT, BINDING_POST, BINDING_REDIRECT, NS_SAML, NS_SAMLP};

/// How an AuthnRequest is built. A missing relay state is omitted.
#[derive(Default)]
pub struct LoginOptions {
    pub relay_state: Option<String>,
    pub force_authn: bool,
    pub is_passive: bool,
    pub subject_hint: Option<String>,
    pub subject_hint_format: Option<String>,
    pub request_binding: String,
    pub response_binding: String,
    pub nonce: String,
}

/// The signed AuthnRequest, as a redirect or a POST form.
#[derive(Debug)]
pub struct LoginRequest {
    pub id: String,
    pub binding: String,
    pub response_binding: String,
    pub url: String,
    pub xml: String,
    pub fields: Vec<(String, String)>,
    pub html: String,
}

/// What `acs` reads from a POST body.
pub enum AcsBody {
    None,
    Text(String),
    Map(Vec<(String, String)>),
}

/// The SAML 2.0 service provider.
pub struct ServiceProvider {
    pub config: Config,
    pub idp: IdpMetadata,
    replay: MemoryReplayCache,
}

impl ServiceProvider {
    /// Resolves `config` and loads the identity provider's metadata.
    pub fn create(config: &Map<String, Value>, base_dir: &str, replay: Option<MemoryReplayCache>) -> Result<Self, SamlError> {
        let resolved = resolve_config(config, base_dir)?;
        let mut sp = Self { config: resolved, idp: empty_idp(), replay: replay.unwrap_or_else(|| MemoryReplayCache::new(0)) };
        sp.refresh_metadata()?;
        Ok(sp)
    }

    /// Loads saml.json. Null override values are ignored.
    pub fn from_file(path: &str, overrides: Option<&Map<String, Value>>, replay: Option<MemoryReplayCache>) -> Result<Self, SamlError> {
        let resolved = read_config_file(path, overrides)?;
        let mut sp = Self { config: resolved, idp: empty_idp(), replay: replay.unwrap_or_else(|| MemoryReplayCache::new(0)) };
        sp.refresh_metadata()?;
        Ok(sp)
    }

    fn tls(&self) -> Option<TlsOptions> {
        if self.config.idp_ca.is_empty() {
            None
        } else {
            Some(TlsOptions { ca: self.config.idp_ca.clone(), cert: String::new(), key: String::new() })
        }
    }

    /// Reads the identity provider metadata again.
    pub fn refresh_metadata(&mut self) -> Result<(), SamlError> {
        let source = self.config.idp_metadata.clone();
        let xml = if source.starts_with('<') {
            source
        } else if source.starts_with("http://") || source.starts_with("https://") {
            let answer = send(&source, "GET", &[("accept", "application/samlmetadata+xml, application/xml, text/xml")], "", self.tls().as_ref(), "metadata")?;
            if answer.status != 200 {
                return Err(err("metadata", format!("{source} answered HTTP {}", answer.status)));
            }
            answer.body
        } else {
            std::fs::read_to_string(&source).map_err(|_| err("metadata", format!("the identity provider metadata file {source} cannot be read")))?
        };
        self.idp = read_idp_metadata_filtered(&xml, &self.config.idp_entity_id)?;
        Ok(())
    }

    /// This service provider's metadata.
    pub fn metadata(&self) -> String {
        metadata_document(&self.config)
    }

    /// Builds a signed AuthnRequest.
    pub fn login(&self, opt: &LoginOptions) -> Result<LoginRequest, SamlError> {
        let binding = if opt.request_binding.is_empty() { self.config.request_binding.as_str() } else { opt.request_binding.as_str() };
        let response = if opt.response_binding.is_empty() { self.config.response_binding.as_str() } else { opt.response_binding.as_str() };
        if response == "artifact" && self.idp.artifact_resolution_services.is_empty() {
            return Err(err("config", "the identity provider has no SOAP ArtifactResolutionService, so the Response cannot come by artifact"));
        }
        let destination = self.idp.sso.get(binding).cloned().unwrap_or_default();
        if destination.is_empty() {
            let which = if binding == "post" { "POST" } else { "Redirect" };
            return Err(err("config", format!("the identity provider has no SingleSignOnService on HTTP-{which}")));
        }
        if let Some(relay) = &opt.relay_state {
            if relay.len() > 80 {
                return Err(err("config", "relayState is longer than the 80 bytes the bindings allow"));
            }
        }
        let element_id = new_id();
        let force = if opt.force_authn { " ForceAuthn=\"true\"" } else { "" };
        let passive = if opt.is_passive { " Is passive=\"true\"" } else { "" };
        let subject = if let Some(hint) = &opt.subject_hint {
            let form = match &opt.subject_hint_format {
                Some(format) if !format.is_empty() => format!(" Format=\"{}\"", escape_xml(format)),
                _ => String::new(),
            };
            format!("<saml:Subject><saml:NameID{form}>{}</saml:NameID></saml:Subject>", escape_xml(hint))
        } else {
            String::new()
        };
        let policy = if self.config.name_id_format.is_empty() {
            "<samlp:NameIDPolicy AllowCreate=\"true\"/>".to_string()
        } else {
            format!("<samlp:NameIDPolicy Format=\"{}\" AllowCreate=\"true\"/>", escape_xml(&self.config.name_id_format))
        };
        let protocol = match response {
            "post" => BINDING_POST,
            "redirect" => BINDING_REDIRECT,
            "artifact" => BINDING_ARTIFACT,
            _ => BINDING_POST,
        };
        let xml = format!(
            "<samlp:AuthnRequest xmlns:samlp=\"{NS_SAMLP}\" xmlns:saml=\"{NS_SAML}\" ID=\"{element_id}\" Version=\"2.0\" IssueInstant=\"{}\" Destination=\"{}\" AssertionConsumerServiceURL=\"{}\" ProtocolBinding=\"{protocol}\"{force}{passive}><saml:Issuer>{}</saml:Issuer>{subject}{policy}</samlp:AuthnRequest>",
            iso_now(),
            escape_xml(&destination),
            escape_xml(&self.config.acs_url),
            escape_xml(&self.config.entity_id)
        );
        if binding == "redirect" {
            let query = redirect_query("SAMLRequest", &xml, opt.relay_state.as_deref(), &self.config.private_key)?;
            let join = if destination.contains('?') { "&" } else { "?" };
            return Ok(LoginRequest {
                id: element_id,
                binding: binding.to_string(),
                response_binding: response.to_string(),
                url: format!("{destination}{join}{query}"),
                xml,
                fields: Vec::new(),
                html: String::new(),
            });
        }
        let signed = sign_enveloped(&xml, &element_id, &self.config.private_key, &self.config.certificate_der)?;
        let mut fields = vec![("SAMLRequest".to_string(), b64_standard(signed.as_bytes()))];
        if let Some(relay) = &opt.relay_state {
            fields.push(("RelayState".to_string(), relay.clone()));
        }
        let pairs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let html = post_form_html(&destination, &pairs, &opt.nonce, "");
        Ok(LoginRequest {
            id: element_id,
            binding: binding.to_string(),
            response_binding: response.to_string(),
            url: destination,
            xml: signed,
            fields,
            html,
        })
    }

    /// Consumes a Response on POST, redirect, or artifact.
    pub fn acs(&self, method: &str, raw_url: &str, body: &AcsBody, request_ids: &[String]) -> Result<SamlLogin, SamlError> {
        let verb = method.to_ascii_uppercase();
        let mut raw_query = String::new();
        if let Some(index) = raw_url.find('?') {
            raw_query = raw_url[index + 1..].to_string();
            if let Some(hash) = raw_query.find('#') {
                raw_query.truncate(hash);
            }
        }
        let query = query_pairs(&raw_query);
        let form = if verb == "POST" { form_of(body) } else { Vec::new() };
        let q = |name: &str| query.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
        let f = |name: &str| form.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
        let ctx = ValidationContext {
            entity_id: &self.config.entity_id,
            acs_url: &self.config.acs_url,
            idp_entity_id: &self.idp.entity_id,
            idp_certificates: &self.idp.certs,
            decryption_key: &self.config.private_key,
            clock_skew_ms: self.config.clock_skew_ms,
            want_assertions_signed: self.config.want_assertions_signed,
            want_assertions_encrypted: self.config.want_assertions_encrypted,
            allow_unsolicited: self.config.allow_unsolicited,
            replay: &self.replay,
            expected_request_ids: request_ids,
        };
        let art = f("SAMLart").filter(|v| !v.is_empty()).or_else(|| q("SAMLart").filter(|v| !v.is_empty()));
        if let Some(art) = art {
            let tls = self.tls();
            let (xml, response_id) = resolve_artifact(ArtifactInput {
                artifact: &art,
                entity_id: &self.config.entity_id,
                idp_entity_id: &self.idp.entity_id,
                services: &self.idp.artifact_resolution_services,
                first_ars: &self.idp.first_ars,
                idp_certificates: &self.idp.certs,
                key: &self.config.private_key,
                certificate_der: &self.config.certificate_der,
                tls: tls.as_ref(),
            })?;
            let relay = if f("SAMLart").is_some() { f("RelayState") } else { q("RelayState") };
            return validate_response(&Received { xml, binding: "artifact".to_string(), relay_state: relay, authenticated_by_binding: true, response_id }, &ctx);
        }
        if verb == "POST" {
            if let Some(value) = f("SAMLResponse").filter(|v| !v.is_empty()) {
                let xml = read_post(&value, "SAMLResponse")?;
                let root = crate::canon::parse_tree(&xml, "the Response")?;
                let response_id = root.attr_or("ID").to_string();
                return validate_response(&Received {
                    xml,
                    binding: "post".to_string(),
                    relay_state: f("RelayState"),
                    authenticated_by_binding: false,
                    response_id,
                }, &ctx);
            }
        }
        if q("SAMLResponse").is_some_and(|v| !v.is_empty()) {
            let message = read_redirect(&raw_query, "SAMLResponse", &self.idp.certs)?;
            let root = crate::canon::parse_tree(&message.xml, "the Response")?;
            let response_id = root.attr_or("ID").to_string();
            return validate_response(&Received {
                xml: message.xml,
                binding: "redirect".to_string(),
                relay_state: message.relay_state,
                authenticated_by_binding: message.signed,
                response_id,
            }, &ctx);
        }
        Err(err("binding", "the request carries no SAMLResponse or SAMLart"))
    }
}

fn form_of(body: &AcsBody) -> Vec<(String, String)> {
    match body {
        AcsBody::None => Vec::new(),
        AcsBody::Text(text) => query_pairs(text),
        AcsBody::Map(pairs) => pairs.clone(),
    }
}

fn empty_idp() -> IdpMetadata {
    IdpMetadata {
        entity_id: String::new(),
        sso: HashMap::new(),
        artifact_resolution_services: HashMap::new(),
        first_ars: String::new(),
        certs: Vec::new(),
        want_authn_requests_signed: false,
    }
}
