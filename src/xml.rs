// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

pub(crate) const NS_SAMLP: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub(crate) const NS_SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
pub(crate) const NS_MD: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
pub(crate) const NS_DSIG: &str = "http://www.w3.org/2000/09/xmldsig#";
pub(crate) const NS_XENC: &str = "http://www.w3.org/2001/04/xmlenc#";
pub(crate) const NS_XENC11: &str = "http://www.w3.org/2009/xmlenc11#";
pub(crate) const NS_SOAP: &str = "http://schemas.xmlsoap.org/soap/envelope/";

pub(crate) const BINDING_REDIRECT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
pub(crate) const BINDING_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
pub(crate) const BINDING_ARTIFACT: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
pub(crate) const BINDING_SOAP: &str = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";

pub(crate) const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
pub(crate) const CM_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

pub(crate) const EXC_C14N: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub(crate) const EXC_C14N_COMMENTS: &str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
pub(crate) const C14N10: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
pub(crate) const C14N10_COMMENTS: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
pub(crate) const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

pub(crate) const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
pub(crate) const RSA_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
pub(crate) const RSA_SHA512: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
pub(crate) const DIGEST_256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub(crate) const DIGEST_384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
pub(crate) const DIGEST_512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";

pub(crate) fn escape_xml(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

pub(crate) fn or_none(value: &str) -> String {
    if value.is_empty() { "(none)".to_string() } else { value.to_string() }
}

pub(crate) fn or_nothing(value: &str) -> String {
    if value.is_empty() { "(nothing)".to_string() } else { value.to_string() }
}

pub(crate) fn has_doctype(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("<!doctype") || lower.contains("<!entity")
}

/// An element copied out of a document so callers can drop the parser borrow.
#[derive(Clone, Debug)]
pub(crate) struct Elem {
    pub ns: String,
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Elem>,
    pub text: String,
}

impl Elem {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    pub fn attr_or(&self, name: &str) -> &str {
        self.attr(name).unwrap_or("")
    }

    pub fn has_attr(&self, name: &str) -> bool {
        self.attr(name).is_some()
    }
}

pub(crate) fn kids<'a>(el: &'a Elem, ns: &str, local: &str) -> Vec<&'a Elem> {
    el.children.iter().filter(|c| c.ns == ns && c.name == local).collect()
}

pub(crate) fn one<'a>(el: &'a Elem, ns: &str, local: &str) -> Result<Option<&'a Elem>, super::error::SamlError> {
    let found = kids(el, ns, local);
    if found.len() > 1 {
        return Err(super::error::err("validation", format!("<{}> has more than one <{local}>", el.name)));
    }
    Ok(found.into_iter().next())
}

pub(crate) fn descendants<'a>(el: &'a Elem, ns: &str, local: &str) -> Vec<&'a Elem> {
    let mut out = Vec::new();
    fn walk<'a>(el: &'a Elem, ns: &str, local: &str, out: &mut Vec<&'a Elem>) {
        for child in &el.children {
            if child.ns == ns && child.name == local {
                out.push(child);
            }
            walk(child, ns, local, out);
        }
    }
    walk(el, ns, local, &mut out);
    out
}

pub(crate) fn assert_unique_ids(root: &Elem) -> Result<(), super::error::SamlError> {
    let mut seen = std::collections::HashSet::new();
    fn walk(el: &Elem, seen: &mut std::collections::HashSet<String>) -> Result<(), super::error::SamlError> {
        for name in ["ID", "Id", "id"] {
            if let Some(value) = el.attr(name) {
                if value.is_empty() {
                    continue;
                }
                if !seen.insert(value.to_string()) {
                    return Err(super::error::err("signature", format!("two elements carry the ID {value}")));
                }
            }
        }
        for child in &el.children {
            walk(child, seen)?;
        }
        Ok(())
    }
    walk(root, &mut seen)
}
