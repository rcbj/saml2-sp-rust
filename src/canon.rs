// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256, Sha384, Sha512};
use ua_cryptography_xml_c14n::roxmltree::{Document, Node};
use ua_cryptography_xml_c14n::{canonicalize, Algorithm, DocumentText};

use crate::bindings::sha256;
use crate::error::{err, SamlError};
use crate::keys::{b64_decode, b64_standard, certificate_pem, pem_body, public_from_cert};
use crate::xml::{
    escape_xml, has_doctype, or_none, or_nothing, Elem, C14N10, C14N10_COMMENTS, DIGEST_256, DIGEST_384, DIGEST_512,
    ENVELOPED, EXC_C14N, EXC_C14N_COMMENTS, NS_DSIG, NS_SAML, RSA_SHA256, RSA_SHA384, RSA_SHA512,
};

pub(crate) fn parse_tree(text: &str, what: &str) -> Result<Elem, SamlError> {
    if has_doctype(text) {
        return Err(err("xml", format!("{what} carries a DOCTYPE or an entity declaration, which SAML never needs")));
    }
    let decoded = DocumentText::decode(text.as_bytes()).map_err(|e| err("xml", format!("{what} is not well-formed XML: {e}")))?;
    let doc = decoded.parse().map_err(|e| err("xml", format!("{what} is not well-formed XML: {e}")))?;
    let root = doc.root_element();
    Ok(owned(root))
}

fn owned(node: Node<'_, '_>) -> Elem {
    let mut text = String::new();
    let mut children = Vec::new();
    for child in node.children() {
        if child.is_element() {
            let element = owned(child);
            text.push_str(&element.text);
            children.push(element);
        } else if let Some(piece) = child.text() {
            text.push_str(piece);
        }
    }
    let mut attrs = Vec::new();
    for attr in node.attributes() {
        if attr.namespace().is_some() {
            continue;
        }
        attrs.push((attr.name().to_string(), attr.value().to_string()));
    }
    Elem {
        ns: node.tag_name().namespace().unwrap_or("").to_string(),
        name: node.tag_name().name().to_string(),
        attrs,
        children,
        text,
    }
}

fn same(node: Node<'_, '_>, ns: &str, local: &str) -> bool {
    node.is_element() && node.tag_name().name() == local && node.tag_name().namespace().unwrap_or("") == ns
}

fn direct_children<'a, 'b>(node: Node<'a, 'b>, ns: &str, local: &str) -> Vec<Node<'a, 'b>> {
    node.children().filter(|c| same(*c, ns, local)).collect()
}

fn algorithm_of(parent: Node<'_, '_>, local: &str) -> String {
    direct_children(parent, NS_DSIG, local).first().and_then(|n| n.attribute("Algorithm")).unwrap_or("").to_string()
}

fn compact_text(node: Node<'_, '_>) -> String {
    let mut out = String::new();
    for desc in node.descendants() {
        if desc.is_text() {
            if let Some(text) = desc.text() {
                out.push_str(text);
            }
        }
    }
    out.split_whitespace().collect()
}

fn inclusive_prefixes(transform: Node<'_, '_>) -> Vec<String> {
    for child in transform.children() {
        if child.is_element() && child.tag_name().name() == "InclusiveNamespaces" {
            return child.attribute("PrefixList").unwrap_or("").split_whitespace().map(str::to_string).collect();
        }
    }
    Vec::new()
}

fn c14n_alg(uri: &str) -> Result<Algorithm, SamlError> {
    Algorithm::from_uri(uri).ok_or_else(|| err("signature", format!("the signature uses the canonicalization {}, which is refused", or_none(uri))))
}

fn find_id<'a, 'b>(doc: &'a Document<'b>, id: &str) -> Option<Node<'a, 'b>> {
    doc.descendants().find(|n| {
        n.is_element() && ["ID", "Id", "id"].iter().any(|name| n.attribute(*name) == Some(id))
    })
}

fn digest_bytes(alg: &str, data: &[u8]) -> Result<Vec<u8>, SamlError> {
    Ok(match alg {
        DIGEST_256 => Sha256::digest(data).to_vec(),
        DIGEST_384 => Sha384::digest(data).to_vec(),
        DIGEST_512 => Sha512::digest(data).to_vec(),
        _ => return Err(err("signature", format!("a signature digests with {}, which is refused", or_none(alg)))),
    })
}

fn sig_hash(alg: &str, data: &[u8]) -> Result<Vec<u8>, SamlError> {
    Ok(match alg {
        RSA_SHA256 => Sha256::digest(data).to_vec(),
        RSA_SHA384 => Sha384::digest(data).to_vec(),
        RSA_SHA512 => Sha512::digest(data).to_vec(),
        _ => return Err(err("signature", "refused signature algorithm")),
    })
}

/// Verifies the enveloped signature of the element with `element_id`.
/// `Ok(None)` means the element is not signed. `Ok(Some(xml))` is its exclusive
/// canonical form with that signature removed, so a nested signature remains.
pub(crate) fn verify_signed_id(xml: &str, element_id: &str, certs: &[Vec<u8>], what: &str) -> Result<Option<String>, SamlError> {
    if has_doctype(xml) {
        return Err(err("xml", format!("{what} carries a DOCTYPE or an entity declaration, which SAML never needs")));
    }
    let text = DocumentText::decode(xml.as_bytes()).map_err(|e| err("xml", format!("{what} is not well-formed XML: {e}")))?;
    let doc = text.parse().map_err(|e| err("xml", format!("{what} is not well-formed XML: {e}")))?;
    let Some(element) = find_id(&doc, element_id) else {
        return Err(err("signature", format!("no element has ID {element_id}")));
    };
    let signatures = direct_children(element, NS_DSIG, "Signature");
    if signatures.is_empty() {
        return Ok(None);
    }
    if signatures.len() > 1 {
        return Err(err("validation", format!("<{}> has more than one <Signature>", element.tag_name().name())));
    }
    let signature = signatures[0];
    let signed_info = direct_children(signature, NS_DSIG, "SignedInfo");
    if signed_info.len() != 1 {
        return Err(err("signature", format!("{what}'s signature has no SignedInfo")));
    }
    let signed_info = signed_info[0];
    let c14n_method = algorithm_of(signed_info, "CanonicalizationMethod");
    if !matches!(c14n_method.as_str(), EXC_C14N | EXC_C14N_COMMENTS | C14N10 | C14N10_COMMENTS) {
        return Err(err("signature", format!("{what}'s signature uses the canonicalization {}, which is refused", or_none(&c14n_method))));
    }
    let sig_alg = algorithm_of(signed_info, "SignatureMethod");
    if !matches!(sig_alg.as_str(), RSA_SHA256 | RSA_SHA384 | RSA_SHA512) {
        return Err(err("signature", format!("{what}'s signature uses {}, which is refused (SHA-1 and non-RSA algorithms are not accepted)", or_none(&sig_alg))));
    }
    let refs = direct_children(signed_info, NS_DSIG, "Reference");
    if refs.len() != 1 {
        return Err(err("signature", format!("{what}'s signature has {} references; exactly one is accepted", refs.len())));
    }
    let reference = refs[0];
    let uri = reference.attribute("URI").unwrap_or("");
    if uri != format!("#{element_id}") {
        return Err(err("signature", format!("{what}'s signature refers to {}, not to {what} itself (#{element_id})", or_nothing(uri))));
    }
    let digest_alg = algorithm_of(reference, "DigestMethod");
    if !matches!(digest_alg.as_str(), DIGEST_256 | DIGEST_384 | DIGEST_512) {
        return Err(err("signature", format!("{what}'s signature digests with {}, which is refused", or_none(&digest_alg))));
    }
    let mut transforms = Vec::new();
    if let Some(transforms_el) = direct_children(reference, NS_DSIG, "Transforms").into_iter().next() {
        transforms = direct_children(transforms_el, NS_DSIG, "Transform");
    }
    let mut saw_enveloped = false;
    let mut final_alg = String::new();
    let mut prefixes = Vec::new();
    if transforms.is_empty() {
        final_alg = C14N10.to_string();
    }
    for transform in &transforms {
        let alg = transform.attribute("Algorithm").unwrap_or("");
        if alg == ENVELOPED {
            saw_enveloped = true;
            continue;
        }
        if matches!(alg, EXC_C14N | EXC_C14N_COMMENTS | C14N10 | C14N10_COMMENTS) {
            final_alg = alg.to_string();
            prefixes = inclusive_prefixes(*transform);
            continue;
        }
        return Err(err("signature", format!("{what}'s signature uses the transform {}, which is refused", or_none(alg))));
    }
    if certs.is_empty() {
        return Err(err("signature", format!("no signing certificate is known for the identity provider, so {what} cannot be verified")));
    }
    let prefix_refs: Vec<&str> = prefixes.iter().map(String::as_str).collect();
    let excluded = if saw_enveloped { Some(signature) } else { None };
    let reference_bytes = canonicalize(element, c14n_alg(&final_alg)?, &prefix_refs, excluded);
    let digest_value = direct_children(reference, NS_DSIG, "DigestValue");
    let got = b64_decode(digest_value.first().map(|n| compact_text(*n)).unwrap_or_default().as_str())
        .map_err(|_| err("signature", format!("{what}'s signature does not verify against the identity provider's certificate: the digest is not base64")))?;
    let want = digest_bytes(&digest_alg, &reference_bytes)?;
    if got != want {
        return Err(err("signature", format!("{what}'s signature does not verify against the identity provider's certificate: the signature does not verify")));
    }
    let info_method = direct_children(signed_info, NS_DSIG, "CanonicalizationMethod");
    let info_prefixes = info_method.first().map(|n| inclusive_prefixes(*n)).unwrap_or_default();
    let info_refs: Vec<&str> = info_prefixes.iter().map(String::as_str).collect();
    let signed_bytes = canonicalize(signed_info, c14n_alg(&c14n_method)?, &info_refs, None);
    let signature_value = direct_children(signature, NS_DSIG, "SignatureValue");
    let sig_bytes = b64_decode(signature_value.first().map(|n| compact_text(*n)).unwrap_or_default().as_str())
        .map_err(|_| err("signature", format!("{what}'s signature does not verify against the identity provider's certificate: the signature value is not base64")))?;
    let digest = sig_hash(&sig_alg, &signed_bytes)?;
    let mut verified = false;
    for der in certs {
        let Ok(public) = public_from_cert(der) else { continue };
        let ok = match sig_alg.as_str() {
            RSA_SHA256 => public.verify(Pkcs1v15Sign::new::<Sha256>(), &digest, &sig_bytes).is_ok(),
            RSA_SHA384 => public.verify(Pkcs1v15Sign::new::<Sha384>(), &digest, &sig_bytes).is_ok(),
            RSA_SHA512 => public.verify(Pkcs1v15Sign::new::<Sha512>(), &digest, &sig_bytes).is_ok(),
            _ => false,
        };
        if ok {
            verified = true;
            break;
        }
    }
    if !verified {
        return Err(err("signature", format!("{what}'s signature does not verify against the identity provider's certificate: the signature does not verify")));
    }
    let stripped = canonicalize(element, Algorithm::Exclusive, &[], Some(signature));
    String::from_utf8(stripped).map(Some).map_err(|_| err("signature", format!("{what}'s signature does not verify against the identity provider's certificate: the signature does not verify")))
}


pub(crate) fn sign_enveloped(xml: &str, element_id: &str, key: &RsaPrivateKey, cert_der: &[u8]) -> Result<String, SamlError> {
    let text = DocumentText::decode(xml.as_bytes()).map_err(|e| err("xml", format!("the message to sign is not well-formed XML: {e}")))?;
    let doc = text.parse().map_err(|e| err("xml", format!("the message to sign is not well-formed XML: {e}")))?;
    let Some(target) = find_id(&doc, element_id) else {
        return Err(err("signature", format!("no element has ID {element_id}")));
    };
    let reference = canonicalize(target, Algorithm::Exclusive, &[], None);
    let digest = b64_standard(&Sha256::digest(&reference));
    let signature = signature_xml(element_id, &digest, cert_der);
    let insert_at = issuer_end(text.as_str(), target);
    let mut with_sig = text.as_str().to_string();
    with_sig.insert_str(insert_at, &signature);
    let text2 = DocumentText::decode(with_sig.as_bytes()).map_err(|e| err("xml", format!("the message to sign is not well-formed XML: {e}")))?;
    let doc2 = text2.parse().map_err(|e| err("xml", format!("the message to sign is not well-formed XML: {e}")))?;
    let signed_info = find_signed_info(&doc2, element_id).ok_or_else(|| err("signature", "the message could not be signed"))?;
    let signed_bytes = canonicalize(signed_info, Algorithm::Exclusive, &[], None);
    let hashed = sha256(&signed_bytes);
    let sig = key.sign(Pkcs1v15Sign::new::<Sha256>(), &hashed).map_err(|e| err("signature", format!("the message could not be signed: {e}")))?;
    let b64 = b64_standard(&sig);
    Ok(with_sig.replacen("@@SIG@@", &b64, 1))
}

fn find_signed_info<'a, 'b>(doc: &'a Document<'b>, element_id: &str) -> Option<Node<'a, 'b>> {
    let want = format!("#{element_id}");
    for node in doc.descendants() {
        if !same(node, NS_DSIG, "Reference") {
            continue;
        }
        if node.attribute("URI") != Some(want.as_str()) {
            continue;
        }
        let mut parent = node.parent();
        while let Some(current) = parent {
            if same(current, NS_DSIG, "SignedInfo") {
                return Some(current);
            }
            parent = current.parent();
        }
    }
    None
}

fn issuer_end(text: &str, target: Node<'_, '_>) -> usize {
    for child in target.children() {
        if same(child, NS_SAML, "Issuer") {
            return child.range().end;
        }
    }
    let start = target.range().start;
    text[start..].find('>').map(|i| start + i + 1).unwrap_or(start)
}

fn signature_xml(element_id: &str, digest: &str, cert_der: &[u8]) -> String {
    let body = pem_body(&certificate_pem(cert_der));
    format!(
        "<ds:Signature xmlns:ds=\"{NS_DSIG}\"><ds:SignedInfo xmlns:ds=\"{NS_DSIG}\"><ds:CanonicalizationMethod Algorithm=\"{EXC_C14N}\"/><ds:SignatureMethod Algorithm=\"{RSA_SHA256}\"/><ds:Reference URI=\"#{id}\"><ds:Transforms><ds:Transform Algorithm=\"{ENVELOPED}\"/><ds:Transform Algorithm=\"{EXC_C14N}\"/></ds:Transforms><ds:DigestMethod Algorithm=\"{DIGEST_256}\"/><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>@@SIG@@</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{body}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>",
        id = escape_xml(element_id),
    )
}

