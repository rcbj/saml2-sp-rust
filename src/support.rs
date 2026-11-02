// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

use aes_gcm::aead::Aead;
use base64::Engine as _;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use rsa::oaep::Oaep;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Map, Value};
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::artifact::new_id;
use crate::bindings::{deflate_raw, sha256, uri_escape};
use crate::canon::{parse_tree, sign_enveloped, verify_signed_id};
use crate::clock::iso_ms;
use crate::error::SamlError;
use crate::keys::{b64_standard, pem_body, KeyMaterial};
use crate::replay::now_ms;
use crate::xml::{descendants, kids, NS_SAMLP, RSA_SHA256};
use crate::{create_self_signed_key_pair, AcsBody, LoginOptions, ServiceProvider};

pub const IDP_ENTITY: &str = "https://idp.test/saml2";
pub const SP_ENTITY: &str = "https://sp.test/saml/metadata";
pub const ACS_URL: &str = "https://sp.test/saml/acs";
pub const SSO_URL: &str = "https://idp.test/saml2/sso";

struct Keys {
    sp: KeyMaterial,
    idp: KeyMaterial,
    tx: RsaPrivateKey,
    other: RsaPrivateKey,
}

fn keys() -> &'static Keys {
    static KEYS: OnceLock<Keys> = OnceLock::new();
    KEYS.get_or_init(|| Keys {
        sp: create_self_signed_key_pair("sp.test", 30, 2048).expect("sp key"),
        idp: create_self_signed_key_pair("idp.test", 30, 2048).expect("idp key"),
        tx: RsaPrivateKey::new(&mut OsRng, 2048).expect("tx key"),
        other: RsaPrivateKey::new(&mut OsRng, 2048).expect("other key"),
    })
}

pub fn sp_key() -> &'static KeyMaterial { &keys().sp }
pub fn idp_key() -> &'static KeyMaterial { &keys().idp }
pub fn tx_key() -> &'static RsaPrivateKey { &keys().tx }
pub fn other_key() -> &'static RsaPrivateKey { &keys().other }

fn iso_off(ms: i64) -> String { iso_ms(now_ms() + ms) }

pub fn idp_metadata(ars: &str) -> String {
    let ars = if ars.is_empty() { "https://idp.test/saml2/ars" } else { ars };
    format!(
        "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"{IDP_ENTITY}\"><md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"true\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:ArtifactResolutionService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:SOAP\" Location=\"{ars}\" index=\"0\" isDefault=\"true\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"{SSO_URL}\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"{SSO_URL}\"/></md:IDPSSODescriptor></md:EntityDescriptor>",
        pem_body(&idp_key().certificate_pem)
    )
}

pub fn test_config(extra: Map<String, Value>, ars: &str) -> Map<String, Value> {
    let mut out = Map::new();
    out.insert("entityId".into(), json!(SP_ENTITY));
    out.insert("acsUrl".into(), json!(ACS_URL));
    out.insert("privateKey".into(), json!(sp_key().private_key_pem));
    out.insert("certificate".into(), json!(sp_key().certificate_pem));
    out.insert("idpMetadata".into(), json!(idp_metadata(ars)));
    for (key, value) in extra { out.insert(key, value); }
    out
}

pub fn must_sp(extra: Map<String, Value>, ars: &str) -> ServiceProvider {
    ServiceProvider::create(&test_config(extra, ars), "", None).unwrap_or_else(|e| panic!("create: {e}"))
}

pub fn rejects(result: Result<impl std::fmt::Debug, SamlError>, code: &str, pattern: &str) {
    let err = match result { Err(err) => err, Ok(value) => panic!("expected {code}, got {value:?}") };
    assert_eq!(err.code, code, "{}", err.message);
    if !pattern.is_empty() {
        let re = regex::Regex::new(pattern).unwrap_or_else(|_| panic!("bad pattern {pattern}"));
        assert!(re.is_match(&err.message), "message {:?} does not match {pattern}", err.message);
    }
}

pub struct AssertionOpt {
    pub in_response_to: String,
    pub name_id: String,
    pub audience: String,
    pub recipient: String,
    pub not_on_or_after_ms: i64,
    pub has_expiry: bool,
    pub issuer: String,
    pub extra: String,
}

impl Default for AssertionOpt {
    fn default() -> Self {
        Self {
            in_response_to: String::new(), name_id: String::new(), audience: String::new(), recipient: String::new(),
            not_on_or_after_ms: 0, has_expiry: false, issuer: String::new(), extra: String::new(),
        }
    }
}

pub fn assertion_xml(o: &AssertionOpt) -> (String, String) {
    let aid = new_id();
    let irt = if o.in_response_to.is_empty() { String::new() } else { format!(" InResponseTo=\"{}\"", o.in_response_to) };
    let name = if o.name_id.is_empty() { "alice-1234" } else { o.name_id.as_str() };
    let audience = if o.audience.is_empty() { SP_ENTITY } else { o.audience.as_str() };
    let recipient = if o.recipient.is_empty() { ACS_URL } else { o.recipient.as_str() };
    let expiry = if o.has_expiry { o.not_on_or_after_ms } else { 300_000 };
    let issuer = if o.issuer.is_empty() { IDP_ENTITY } else { o.issuer.as_str() };
    let xml = format!(
        "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{aid}\" Version=\"2.0\" IssueInstant=\"{}\"><saml:Issuer>{issuer}</saml:Issuer><saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">{name}</saml:NameID><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData Recipient=\"{recipient}\" NotOnOrAfter=\"{}\"{irt}/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"{}\" NotOnOrAfter=\"{}\"><saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant=\"{}\" SessionIndex=\"_session1\"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name=\"urn:oid:0.9.2342.19200300.100.1.3\" FriendlyName=\"mail\"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"groups\"><saml:AttributeValue>staff</saml:AttributeValue><saml:AttributeValue>admins</saml:AttributeValue></saml:Attribute>{}</saml:AttributeStatement></saml:Assertion>",
        iso_off(0), iso_off(expiry), iso_off(-5000), iso_off(expiry), iso_off(-1000), o.extra
    );
    (xml, aid)
}

pub fn sign_xml(xml: &str, id: &str, key: Option<&RsaPrivateKey>, cert: Option<&[u8]>) -> String {
    let key = key.unwrap_or(&idp_key().private_key);
    let cert = cert.unwrap_or(&idp_key().certificate_der);
    sign_enveloped(xml, id, key, cert).unwrap_or_else(|e| panic!("{e} :: {}", &xml[..xml.len().min(180)]))
}

pub fn signed_assertion(o: &AssertionOpt) -> (String, String) {
    let (xml, id) = assertion_xml(o);
    (sign_xml(&xml, &id, None, None), id)
}

pub struct ResponseOpt {
    pub in_response_to: String,
    pub sign: bool,
    pub assertion: String,
    pub has_assertion: bool,
    pub status: String,
    pub destination: String,
    pub has_destination: bool,
    pub omit_destination: bool,
    pub issuer: String,
}

impl Default for ResponseOpt {
    fn default() -> Self {
        Self {
            in_response_to: String::new(), sign: false, assertion: String::new(), has_assertion: false, status: String::new(),
            destination: String::new(), has_destination: false, omit_destination: false, issuer: String::new(),
        }
    }
}

pub fn response_xml(o: &ResponseOpt) -> String {
    let rid = new_id();
    let irt = if o.in_response_to.is_empty() { String::new() } else { format!(" InResponseTo=\"{}\"", o.in_response_to) };
    let dest = if o.omit_destination {
        String::new()
    } else {
        let value = if o.has_destination { o.destination.as_str() } else { ACS_URL };
        format!(" Destination=\"{value}\"")
    };
    let status = if o.status.is_empty() { "urn:oasis:names:tc:SAML:2.0:status:Success" } else { o.status.as_str() };
    let assertion = if o.has_assertion {
        o.assertion.clone()
    } else if status.ends_with("Success") {
        signed_assertion(&AssertionOpt { in_response_to: o.in_response_to.clone(), ..AssertionOpt::default() }).0
    } else {
        String::new()
    };
    let issuer = if o.issuer.is_empty() { IDP_ENTITY } else { o.issuer.as_str() };
    let xml = format!(
        "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{rid}\" Version=\"2.0\" IssueInstant=\"{}\"{dest}{irt}><saml:Issuer>{issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"{status}\"/></samlp:Status>{assertion}</samlp:Response>",
        iso_off(0)
    );
    if o.sign { sign_xml(&xml, &rid, None, None) } else { xml }
}

pub fn encrypt_assertion(assertion: &str, cipher_name: &str, transport: &str, wrapper: &str) -> String {
    let cipher_name = if cipher_name.is_empty() { "aes-256-gcm" } else { cipher_name };
    let transport = if transport.is_empty() { "mgf1p" } else { transport };
    let wrapper = if wrapper.is_empty() { "EncryptedAssertion" } else { wrapper };
    let key_len = if cipher_name == "aes-256-gcm" { 32 } else { 16 };
    let mut content_key = vec![0u8; key_len];
    OsRng.fill_bytes(&mut content_key);
    let (blob, alg) = if cipher_name == "aes-256-gcm" {
        let mut iv = [0u8; 12];
        OsRng.fill_bytes(&mut iv);
        let cipher = Aes256Gcm::new_from_slice(&content_key).expect("gcm");
        let sealed = cipher.encrypt(Nonce::from_slice(&iv), assertion.as_bytes()).expect("seal");
        let mut blob = iv.to_vec();
        blob.extend(sealed);
        (blob, "http://www.w3.org/2009/xmlenc11#aes256-gcm")
    } else {
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);
        let mut buf = vec![0u8; assertion.len() + 16];
        buf[..assertion.len()].copy_from_slice(assertion.as_bytes());
        use cipher::{BlockEncryptMut, KeyIvInit};
        let enc = cbc::Encryptor::<aes::Aes128>::new_from_slices(&content_key, &iv).expect("cbc");
        let sealed = enc.encrypt_padded_mut::<cipher::block_padding::Pkcs7>(&mut buf, assertion.len()).expect("pad").to_vec();
        let mut blob = iv.to_vec();
        blob.extend(sealed);
        (blob, "http://www.w3.org/2001/04/xmlenc#aes128-cbc")
    };
    let public = RsaPublicKey::from(&sp_key().private_key);
    let wrapped = if transport == "mgf1p" {
        public.encrypt(&mut OsRng, Oaep::new::<sha1::Sha1>(), &content_key).expect("oaep")
    } else {
        public.encrypt(&mut OsRng, Oaep::new::<Sha256>(), &content_key).expect("oaep256")
    };
    let key_method = if transport == "mgf1p" {
        "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"/>".to_string()
    } else {
        "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#rsa-oaep\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><xenc11:MGF xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" Algorithm=\"http://www.w3.org/2009/xmlenc11#mgf1sha256\"/></xenc:EncryptionMethod>".to_string()
    };
    format!(
        "<saml:{wrapper} xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod Algorithm=\"{alg}\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><xenc:EncryptedKey>{key_method}<xenc:CipherData><xenc:CipherValue>{}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>{}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:{wrapper}>",
        b64_standard(&wrapped), b64_standard(&blob)
    )
}

pub fn redirect_response_query(xml: &str, relay: &str, key: Option<&RsaPrivateKey>) -> String {
    let key = key.unwrap_or(&idp_key().private_key);
    let mut parts = vec![format!("SAMLResponse={}", uri_escape(&b64_standard(&deflate_raw(xml.as_bytes()).unwrap())))];
    if !relay.is_empty() { parts.push(format!("RelayState={}", uri_escape(relay))); }
    parts.push(format!("SigAlg={}", uri_escape(RSA_SHA256)));
    let signed = parts.join("&");
    let digest = sha256(signed.as_bytes());
    let sig = key.sign(Pkcs1v15Sign::new::<Sha256>(), &digest).unwrap();
    format!("{signed}&Signature={}", uri_escape(&b64_standard(&sig)))
}

pub fn artifact_for(entity: &str) -> String {
    let entity = if entity.is_empty() { IDP_ENTITY } else { entity };
    let mut out = [0u8; 44];
    out[1] = 4;
    let sum = Sha1::digest(entity.as_bytes());
    out[4..24].copy_from_slice(&sum);
    OsRng.fill_bytes(&mut out[24..]);
    b64_standard(&out)
}

pub struct HttpRequest { pub method: String, pub path: String, pub body: Vec<u8> }

pub struct TestServer {
    pub url: String,
    addr: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

pub fn serve(handler: Arc<dyn Fn(&HttpRequest) -> (u16, &'static str, Vec<u8>) + Send + Sync>) -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    thread::spawn(move || {
        for conn in listener.incoming() {
            if flag.load(Ordering::SeqCst) { break; }
            let Ok(mut stream) = conn else { break; };
            if flag.load(Ordering::SeqCst) { break; }
            let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
            let Some(req) = read_http(&mut stream) else { continue };
            let (status, ctype, body) = handler(&req);
            let _ = write_http(&mut stream, status, ctype, &body);
        }
    });
    TestServer { url: format!("http://{addr}"), addr, stop }
}

fn read_http(stream: &mut TcpStream) -> Option<HttpRequest> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 { return None; }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") { break pos; }
        if buf.len() > 1_000_000 { return None; }
    };
    let header = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut body = buf[header_end + 4..].to_vec();
    let mut length = 0usize;
    for line in header.lines() {
        if let Some(rest) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = rest.trim().parse().unwrap_or(0);
        }
    }
    while body.len() < length {
        let n = stream.read(&mut tmp).ok()?;
        if n == 0 { break; }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(length);
    let mut parts = header.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").split('?').next().unwrap_or("/").to_string();
    Some(HttpRequest { method, path, body })
}

fn write_http(stream: &mut TcpStream, status: u16, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    let reason = match status { 200 => "OK", 201 => "Created", _ => "Error" };
    let head = format!("HTTP/1.1 {status} {reason}\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len());
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    let _ = stream.flush();
    Ok(())
}

pub struct Ars {
    pub server: TestServer,
    pub url: String,
    state: Arc<Mutex<ArsState>>,
}

struct ArsState { store: HashMap<String, String>, resolved: Vec<String> }

impl Ars {
    pub fn put(&self, artifact: &str, response: &str) {
        self.state.lock().unwrap().store.insert(artifact.to_string(), response.to_string());
    }
    pub fn resolved(&self) -> Vec<String> { self.state.lock().unwrap().resolved.clone() }
}

pub fn start_ars() -> Ars {
    let state = Arc::new(Mutex::new(ArsState { store: HashMap::new(), resolved: Vec::new() }));
    let shared = state.clone();
    let server = serve(Arc::new(move |req| {
        let text = String::from_utf8_lossy(&req.body).to_string();
        let mut ok = false;
        let mut resolve_id = String::new();
        let mut artifact = String::new();
        if let Ok(root) = parse_tree(&text, "the ArtifactResolve") {
            let found = descendants(&root, NS_SAMLP, "ArtifactResolve");
            if let Some(body) = found.first() {
                resolve_id = body.attr_or("ID").to_string();
                if let Some(art) = kids(body, NS_SAMLP, "Artifact").first() {
                    artifact = art.text.trim().to_string();
                }
                ok = verify_signed_id(&text, &resolve_id, &[sp_key().certificate_der.clone()], "the ArtifactResolve").ok().flatten().is_some();
            }
        }
        let mut guard = shared.lock().unwrap();
        let message = if ok {
            let message = guard.store.remove(&artifact).unwrap_or_default();
            if !message.is_empty() { guard.resolved.push(artifact.clone()); }
            message
        } else {
            String::new()
        };
        drop(guard);
        let answer = format!(
            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><samlp:ArtifactResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{}\" Version=\"2.0\" IssueInstant=\"{}\" InResponseTo=\"{resolve_id}\"><saml:Issuer>{IDP_ENTITY}</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>{message}</samlp:ArtifactResponse></soap:Body></soap:Envelope>",
            new_id(), iso_off(0)
        );
        (200, "text/xml", answer.into_bytes())
    }));
    let url = format!("{}/ars", server.url);
    Ars { server, url, state }
}

pub fn post_acs(sp: &ServiceProvider, xml: &str, request_id: &str, relay: Option<&str>) -> Result<crate::SamlLogin, SamlError> {
    let mut pairs = vec![("SAMLResponse".to_string(), b64_standard(xml.as_bytes()))];
    if let Some(relay) = relay { pairs.push(("RelayState".to_string(), relay.to_string())); }
    let ids: Vec<String> = if request_id.is_empty() { Vec::new() } else { vec![request_id.to_string()] };
    sp.acs("POST", "/saml/acs", &AcsBody::Map(pairs), &ids)
}

pub fn verify_ok(xml: &str, cert: &[u8]) -> bool {
    let Ok(root) = parse_tree(xml, "the message") else { return false };
    let id = root.attr_or("ID");
    verify_signed_id(xml, id, &[cert.to_vec()], "the message").ok().flatten().is_some()
}

pub fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

pub fn jwk_of(key: &RsaPrivateKey, kid: &str) -> Map<String, Value> {
    let public = RsaPublicKey::from(key);
    let mut out = Map::new();
    out.insert("kty".into(), json!("RSA"));
    out.insert("n".into(), json!(b64url(&public.n().to_bytes_be())));
    out.insert("e".into(), json!(b64url(&public.e().to_bytes_be())));
    out.insert("kid".into(), json!(kid));
    out.insert("alg".into(), json!("RS256"));
    out.insert("use".into(), json!("sig"));
    out
}

pub fn sign_jws(payload: &Value, key: &RsaPrivateKey, header: Option<Map<String, Value>>) -> String {
    let header = header.unwrap_or_else(|| {
        let mut h = Map::new();
        h.insert("alg".into(), json!("RS256"));
        h.insert("kid".into(), json!("k1"));
        h.insert("typ".into(), json!("secevent+jwt"));
        h
    });
    let h = b64url(&serde_json::to_vec(&header).unwrap());
    let p = b64url(&serde_json::to_vec(payload).unwrap());
    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    let sig = if alg.is_empty() || alg == "none" || alg == "HS256" {
        String::new()
    } else {
        let digest = sha256(format!("{h}.{p}").as_bytes());
        b64url(&key.sign(Pkcs1v15Sign::new::<Sha256>(), &digest).unwrap())
    };
    format!("{h}.{p}.{sig}")
}

pub fn login_options() -> LoginOptions { LoginOptions::default() }
