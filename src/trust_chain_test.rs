// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! idpCa holds iya-sts's whole listener CA trust chain (leaf, TLS Issuing CA,
//! Intermediate, Root). These tests serve HTTPS from such a chain, check that
//! scripts/configure_iya_sts.py writes all of it to the file idpCa names (from
//! GET /tls/server-certificate, and from the handshake when that is missing),
//! and that the library takes that file as its trust store.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::Arc;
use std::thread;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use serde_json::{json, Map};

use crate::support::idp_metadata;
use crate::ServiceProvider;

struct Chain {
    /// Leaf first, Root last: what iya-sts publishes and presents.
    pem: String,
    leaf_key: String,
}

fn ca_params(name: &str) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    params
}

fn chain() -> Chain {
    let root_key = KeyPair::generate().expect("key");
    let root_params = ca_params("test Root CA");
    let root = root_params.self_signed(&root_key).expect("root");
    let root_issuer = Issuer::from_params(&root_params, &root_key);

    let intermediate_key = KeyPair::generate().expect("key");
    let intermediate_params = ca_params("test Intermediate CA");
    let intermediate = intermediate_params.signed_by(&intermediate_key, &root_issuer).expect("intermediate");
    let intermediate_issuer = Issuer::from_params(&intermediate_params, &intermediate_key);

    let issuing_key = KeyPair::generate().expect("key");
    let issuing_params = ca_params("test TLS Issuing CA");
    let issuing = issuing_params.signed_by(&issuing_key, &intermediate_issuer).expect("issuing");
    let issuing_issuer = Issuer::from_params(&issuing_params, &issuing_key);

    let leaf_key = KeyPair::generate().expect("key");
    let mut leaf_params = CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()]).expect("params");
    leaf_params.distinguished_name = rcgen::DistinguishedName::new();
    leaf_params.distinguished_name.push(DnType::CommonName, "127.0.0.1");
    leaf_params.is_ca = IsCa::NoCa;
    let leaf = leaf_params.signed_by(&leaf_key, &issuing_issuer).expect("leaf");

    Chain {
        pem: format!("{}{}{}{}", leaf.pem(), issuing.pem(), intermediate.pem(), root.pem()),
        leaf_key: leaf_key.serialize_pem(),
    }
}

/// HTTPS on 127.0.0.1 presenting the whole chain. `published` decides whether
/// GET /tls/server-certificate answers the chain or 404.
fn serve_tls(chain: &Chain, published: bool) -> String {
    let identity = native_tls::Identity::from_pkcs8(chain.pem.as_bytes(), chain.leaf_key.as_bytes()).expect("identity");
    let acceptor = Arc::new(native_tls::TlsAcceptor::new(identity).expect("acceptor"));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let chain_pem = chain.pem.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { break };
            let acceptor = acceptor.clone();
            let chain_pem = chain_pem.clone();
            thread::spawn(move || {
                let Ok(mut tls) = acceptor.accept(stream) else { return };
                let mut request = Vec::new();
                let mut buffer = [0u8; 2048];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut buffer) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buffer[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&request);
                let path = text.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (status, body) = if path == "/tls/server-certificate" && published {
                    ("200 OK", chain_pem)
                } else if path == "/metadata" {
                    ("200 OK", idp_metadata(""))
                } else {
                    ("404 Not Found", String::new())
                };
                let _ = write!(tls, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                let _ = tls.flush();
                let _ = tls.shutdown();
            });
        }
    });
    format!("https://127.0.0.1:{port}")
}

fn blocks(pem: &str) -> usize {
    pem.matches("-----BEGIN CERTIFICATE-----").count()
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("saml2-sp-rust-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Runs the registrar's own save step on the file idpCa names, as it runs it.
fn save_with_registrar(dir: &std::path::Path, origin: &str) -> String {
    std::fs::write(dir.join("saml.json"), r#"{
        "entityId": "http://localhost:3000/saml/metadata",
        "acsUrl": "http://localhost:3000/saml/acs",
        "privateKey": "file:generated/sp.key",
        "certificate": "file:generated/sp.crt",
        "idpMetadata": "file:generated/idp-metadata.xml",
        "idpCa": "file:generated/idp-ca.pem"
    }"#).unwrap();
    let script = r#"import importlib.util, json, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("configure_iya_sts", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
files = mod.files_of(str(Path(sys.argv[2]) / "saml.json"))
assert files.idp_ca == str((Path(sys.argv[2]) / "generated" / "idp-ca.pem").resolve()), files.idp_ca
saved = mod.save_trust_chain(sys.argv[3], files.idp_ca)
print(json.dumps({"count": saved["count"], "anchor": saved["anchor"].subject.rfc4514_string(), "path": saved["path"]}))
"#;
    let script_path = format!("{}/scripts/configure_iya_sts.py", env!("CARGO_MANIFEST_DIR"));
    let out = Command::new("python3").arg("-c").arg(script).arg(&script_path).arg(dir).arg(origin).output().unwrap();
    assert!(out.status.success(), "{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn registrar_writes_the_published_chain_to_idp_ca() {
    let chain = chain();
    let origin = serve_tls(&chain, true);
    let dir = scratch("chain-published");
    let printed = save_with_registrar(&dir, &origin);
    let written = std::fs::read_to_string(dir.join("generated/idp-ca.pem")).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(blocks(&written), 4, "{written}");
    assert_eq!(written.trim(), chain.pem.trim());
    assert!(printed.contains("\"count\": 4"), "{printed}");
    assert!(printed.contains("CN=test Root CA"), "{printed}");
}

#[test]
fn registrar_falls_back_to_the_handshake_chain() {
    let chain = chain();
    let origin = serve_tls(&chain, false);
    let dir = scratch("chain-handshake");
    let printed = save_with_registrar(&dir, &origin);
    let written = std::fs::read_to_string(dir.join("generated/idp-ca.pem")).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(blocks(&written), 4, "{written}");
    assert!(printed.contains("CN=test Root CA"), "{printed}");
}

#[test]
fn library_trusts_the_whole_chain_file_as_idp_ca() {
    let chain = chain();
    let origin = serve_tls(&chain, true);
    let dir = scratch("chain-trust");
    let ca_path = dir.join("idp-ca.pem");
    std::fs::write(&ca_path, &chain.pem).unwrap();
    let mut extra = Map::new();
    extra.insert("idpCa".into(), json!(format!("file:{}", ca_path.display())));
    extra.insert("idpMetadata".into(), json!(format!("{origin}/metadata")));
    let config = crate::support::test_config(extra, "");
    let made = ServiceProvider::create(&config, "", None);
    let _ = std::fs::remove_dir_all(&dir);
    let sp = made.unwrap_or_else(|e| panic!("the chain file was not a usable trust store: {e}"));
    assert_eq!(sp.config.idp_ca.trim(), chain.pem.trim());
    assert_eq!(crate::http::trust_anchors(&chain.pem).unwrap().len(), 4);
}

#[test]
fn library_refuses_a_ca_file_with_no_certificate() {
    assert!(crate::http::trust_anchors("not a certificate").is_err());
    let unterminated = "-----BEGIN CERTIFICATE-----\nAAAA\n";
    assert!(crate::http::trust_anchors(unterminated).is_err());
}
