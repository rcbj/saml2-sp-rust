// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::process::Command;

#[test]
fn configure_script_signals() {
    let dir = std::env::temp_dir().join(format!("saml2-sp-rust-configure-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let base = dir.join("saml.json");
    std::fs::write(&base, r#"{
        "entityId": "http://localhost:3000/saml/metadata",
        "acsUrl": "http://localhost:3000/saml/acs",
        "privateKey": "generated/sp.key",
        "certificate": "generated/sp.crt",
        "idpMetadata": "generated/idp-metadata.xml",
        "idpCa": "generated/idp-ca.pem"
    }"#).unwrap();
    let script = r#"import importlib.util, json, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("configure_iya_sts", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
folder = Path(sys.argv[2])
raw = json.loads((folder / "saml.json").read_text())
with_ssf = folder / "saml-ssf.json"
with_ssf.write_text(json.dumps({**raw, "ssf": {"transmitter": "https://localhost:8081"}}))
files = mod.files_of(str(with_ssf))
assert files.ssf_transmitter == "https://localhost:8081", files.ssf_transmitter
calls = mod.ssf_calls(files, "https://localhost:8081")
paths = [call["path"].replace("https://localhost:8081/admin-api", "") for call in calls]
# No truststore anchor and no stored SP certificate any more: the realm issues the receiver its own.
assert paths == ["/applications/add", "/roles/add-member"], paths
assert calls[0]["body"] == {"application": "http://localhost:3000/saml/metadata", "attribute": "oauthAllowedScope", "value": "ssf.manage"}
assert calls[1]["body"] == {"role": "SSF_MANAGE", "kind": "application", "member": "http://localhost:3000/saml/metadata"}
planned = [call["path"] for call in mod.plan_for(files, "https://localhost:8081", "", "x")]
assert any(p.endswith("/applications/issue-tls-client-certificate") for p in planned) and any(p.endswith("/tls/trust/remove") for p in planned), planned
assert not any(p.endswith("/tls/trust/add") or p.endswith("/applications/add-certificate") for p in planned), planned
plain = mod.files_of(str(folder / "saml.json"))
assert not any(call["path"].endswith("/applications/issue-tls-client-certificate") for call in mod.plan_for(plain, "https://localhost:8081", "", "x"))
off = folder / "saml-signals-off.json"
off.write_text(json.dumps({**raw, "signals": False, "ssf": {"transmitter": "https://localhost:8081"}}))
files = mod.files_of(str(off))
assert files.ssf_transmitter is None
assert files.entity_id == "http://localhost:3000/saml/metadata"
import re
def re_path(path):
    return re.search(r"/applications/add$|/roles/add-member|/tls/trust|/applications/(add|remove)-certificate|issue-tls-client-certificate", path) is not None
assert not any(re_path(call["path"]) for call in mod.plan_for(files, "https://localhost:8081", "", "x"))
bare = folder / "saml-signals-off-no-tx.json"
bare.write_text(json.dumps({**raw, "signals": False, "ssf": {}}))
assert mod.files_of(str(bare)).ssf_transmitter is None
bad = folder / "saml-signals-bad.json"
bad.write_text(json.dumps({**raw, "signals": "no", "ssf": {"transmitter": "https://localhost:8081"}}))
try:
    mod.files_of(str(bad))
except SystemExit as err:
    assert "signals must be true or false" in str(err)
else:
    raise SystemExit("signals no was accepted")
"#;
    let script_path = format!("{}/scripts/configure_iya_sts.py", env!("CARGO_MANIFEST_DIR"));
    let out = Command::new("python3").arg("-c").arg(script).arg(&script_path).arg(&dir).output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(out.status.success(), "{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
}

/// The demo's attribute-protected resource (#40, as oidc-caep-risc's 5199429, 97eec15, 86e67e2):
/// the policy's rule, the PolicyIds the script may rewrite, attr1 defined with a security token
/// and the operator told only when the value cannot be set, and the policy step's three cases.
#[test]
fn configure_script_attribute_protected() {
    let dir = std::env::temp_dir().join(format!("saml2-sp-rust-configure-attr-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("saml.json");
    std::fs::write(&config, r#"{"entityId": "http://localhost:3000/saml/metadata", "acsUrl": "http://localhost:3000/saml/acs",
        "privateKey": "generated/sp.key", "certificate": "generated/sp.crt", "idpMetadata": "generated/idp-metadata.xml"}"#).unwrap();
    let script = r#"import importlib.util, io, contextlib, sys
spec = importlib.util.spec_from_file_location("configure_iya_sts", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
alfa = mod.orders_policy()
assert "rule readAttributeProtected" in alfa and 'target clause kind == "attribute-protected"' in alfa, alfa
assert 'target clause attr1 == "abc123"' in alfa and 'id = "urn:sts:xacml:attribute:attr1"' in alfa, alfa
assert alfa.index("readAttributeProtected") < alfa.index("nothingElse"), "before the deny-all"
own = [line.split('"')[1] for line in alfa.splitlines() if line.strip().startswith("id = ")]
assert own and own[0] in mod.OWN_POLICY_IDS, (own, mod.OWN_POLICY_IDS)
assert mod.orders_policy("samlspdemolocked", "deny").count("readAttributeProtected") == 1

def run(answers):
    sent = []
    def call(path, body, security=False):
        sent.append((path, security))
        return answers[path]
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        held = mod.set_test_attribute(call, "saml-demo-user")
    return held, sent, out.getvalue()

ok = {"status": 200, "body": {"ok": True}}
held, sent, said = run({"/policies/define-person-attribute": ok, "/users/set-attribute": ok})
assert held and sent == [("/policies/define-person-attribute", True), ("/users/set-attribute", False)], sent
assert "attr1=abc123" in said and "Security Administrator" not in said
denied = {"status": 403, "body": {"errors": ["Only a Security Administrator may make this change"]}}
held, _, said = run({"/policies/define-person-attribute": denied, "/users/set-attribute": ok})
assert held and "not defined" not in said, "defined already: the refusal says nothing"
held, _, said = run({"/policies/define-person-attribute": denied, "/users/set-attribute": {"status": 400, "body": {"ok": False, "errors": ["unknown attribute attr1"]}}})
assert not held and "is not defined, and this credential cannot define it" in said and "SECURITY_ADMIN" in said, said
held, _, said = run({"/policies/define-person-attribute": {"status": 200, "body": {"ok": False, "errors": ["attr1 already exists"]}}, "/users/set-attribute": ok})
assert held
try:
    run({"/policies/define-person-attribute": {"status": 500, "body": {"ok": False, "errors": ["boom"]}}, "/users/set-attribute": ok})
except SystemExit as err:
    assert "attr1" in str(err)
else:
    raise SystemExit("an unexpected refusal was ignored")

def policy_run(fga):
    writes = []
    def api(path, body):
        writes.append(path)
        return ok
    def get(path):
        return {"status": 200, "body": {"page": {"fga": fga}}}
    with contextlib.redirect_stdout(io.StringIO()):
        mod.own_policy(api, get, "http://localhost:3000/saml/metadata")
    return writes
assert policy_run({"enforced": True, "policy": {"name": "p", "policyId": mod.OWN_POLICY_IDS[0]}}) == ["/xacml/import-alfa"], "its own: the current version"
assert policy_run({"enforced": True, "policy": {"name": "p", "policyId": "urn:someone:else"}}) == [], "an administrator's: left alone"
assert policy_run({"enforced": False, "policy": {"name": "p"}}) == ["/applications/fga-create-policy", "/xacml/import-alfa", "/applications/fga-enable"]
files = mod.files_of(sys.argv[2])
paths = [call["path"] for call in mod.plan_for(files, "https://sts.test", "saml-demo-user", "x")]
assert paths[-2:] == ["https://sts.test/admin-api/policies/define-person-attribute", "https://sts.test/admin-api/users/set-attribute"], paths
assert not any("set-attribute" in p for p in [call["path"] for call in mod.plan_for(files, "https://sts.test", "", "x")]), "no test user, no attribute"
"#;
    let script_path = format!("{}/scripts/configure_iya_sts.py", env!("CARGO_MANIFEST_DIR"));
    let out = Command::new("python3").arg("-c").arg(script).arg(&script_path).arg(&config).output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(out.status.success(), "{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
}

/// The receiver's realm-issued TLS client certificate (issue once, keep while the realm lists
/// it), the SP certificate's old trust anchor and stored copy taken off, --new-sp-keys, and the
/// SP key pair's generated name, with fakes for iya-sts, openssl and the saml2-sp binary.
#[test]
fn configure_script_ssf_client_certificate() {
    use sha2::{Digest, Sha256};
    let dir = std::env::temp_dir().join(format!("saml2-sp-rust-configure-ssf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("generated")).unwrap();
    // Two real certificates: the SP's (self-signed, the old way) and one the realm "issued".
    let sp = crate::create_self_signed_key_pair("localhost", 1, 2048).unwrap();
    std::fs::write(dir.join("generated/sp.crt"), &sp.certificate_pem).unwrap();
    std::fs::write(dir.join("generated/sp.key"), &sp.private_key_pem).unwrap();
    let sp_sha: String = Sha256::digest(&sp.certificate_der).iter().map(|b| format!("{b:02x}")).collect();
    let ec = rcgen::KeyPair::generate().unwrap();
    let issued = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap().self_signed(&ec).unwrap().pem();
    std::fs::write(dir.join("issued.pem"), &issued).unwrap();
    std::fs::write(dir.join("saml.json"), r#"{"entityId": "http://localhost:3000/saml/metadata", "acsUrl": "http://localhost:3000/saml/acs",
        "privateKey": "generated/sp.key", "certificate": "generated/sp.crt", "idpMetadata": "generated/idp-metadata.xml",
        "ssf": {"transmitter": "https://localhost:8081", "pollIntervalMs": 3000}}"#).unwrap();
    let script = r#"import importlib.util, io, contextlib, json, os, stat, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("configure_iya_sts", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
folder = Path(sys.argv[2]); sp_sha = sys.argv[3]
config = str(folder / "saml.json")
issued = (folder / "issued.pem").read_text()
files = mod.files_of(config)
assert mod.certificate_sha256((folder / "generated/sp.crt").read_text()) == sp_sha

sent = []
def api(path, body):
    sent.append((path, body))
    return {"status": 200, "body": {"ok": True, "certificate": {"serialHex": "0A1B", "certificatePem": issued, "chainPem": ["-----BEGIN CERTIFICATE-----\nQ0E=\n-----END CERTIFICATE-----\n"],
            "implicitName": "urn:sts:application:" + body["application"]}, "files": {"key": {"text": "-----BEGIN ENCRYPTED PRIVATE KEY-----\nx\n-----END ENCRYPTED PRIVATE KEY-----\n"}}}}
listed = []
def get(path):
    assert path.startswith("/applications?application="), path
    return {"status": 200, "body": {"page": {"mtls": {"certificates": listed}}}}
opened = []
def decrypt(encrypted, password, key_path):
    assert "ENCRYPTED" in encrypted and len(password) >= 24
    opened.append(key_path)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600); os.write(fd, b"KEY"); os.close(fd)

out = io.StringIO()
with contextlib.redirect_stdout(out):
    assert mod.issue_ssf_client_certificate(api, get, files, config, decrypt) is True
assert [p for p, _ in sent] == ["/applications/issue-tls-client-certificate"], sent
body = sent[0][1]
assert body["application"] == "http://localhost:3000/saml/metadata" and body["keyAlg"] == "ec-p256" and body["label"] == mod.SSF_CLIENT_LABEL
assert body["password"] not in out.getvalue(), "the one-time password is never printed"
key = folder / "generated/ssf-client.key"; crt = folder / "generated/ssf-client.crt"
assert opened == [str(key)] and stat.S_IMODE(key.stat().st_mode) == 0o600
assert crt.read_text().startswith(issued.strip()[:40]) and crt.read_text().count("BEGIN CERTIFICATE") == 2, "leaf then chain"
raw = json.loads(Path(config).read_text())
assert raw["ssf"] == {"transmitter": "https://localhost:8081", "pollIntervalMs": 3000, "clientCertificate": "generated/ssf-client.crt", "clientKey": "generated/ssf-client.key"}, raw["ssf"]
assert raw["certificate"] == "generated/sp.crt", "the SAML key pair stays the SAML key pair"

# Run again: the realm still lists it, valid, so it is kept and nothing is issued.
sent.clear(); listed.append({"serialHex": "0A1B", "state": "valid", "certificatePem": issued})
with contextlib.redirect_stdout(io.StringIO()):
    assert mod.issue_ssf_client_certificate(api, get, files, config, decrypt) is False
assert sent == []
# Revoked there, or another iya-sts that never issued it: issued again.
listed[0]["state"] = "revoked"
with contextlib.redirect_stdout(io.StringIO()):
    assert mod.issue_ssf_client_certificate(api, get, files, config, decrypt) is True
listed.clear()
with contextlib.redirect_stdout(io.StringIO()):
    assert mod.issue_ssf_client_certificate(api, get, files, config, decrypt) is True
# A refusal stops the script and never echoes the key file.
def refusing(path, body):
    return {"status": 400, "body": {"ok": False, "errors": ["no CA"], "files": {"key": {"text": "SECRET"}}}}
try:
    mod.issue_ssf_client_certificate(refusing, get, files, config, decrypt)
except SystemExit as err:
    assert "refused" in str(err) and "SECRET" not in str(err)
else:
    raise SystemExit("a refusal was accepted")

# The old anchor and stored copy go, by the SP certificate's SHA-256; not held is fine.
mod.retire_current_sp_certificate(config, str(folder / "generated/old.crt"))  # no such file: nothing
(folder / mod.RETIRED_SP_CERTS).write_text("ab" * 32 + "\n")
calls = []
def call(path, body, security=False):
    calls.append((path, body))
    if path == "/tls/trust/remove" and body["fingerprint"] == sp_sha:
        return {"status": 200, "body": {"ok": True}}
    if path == "/tls/trust/remove":
        return {"status": 400, "body": {"ok": False, "errors": ["This truststore holds no anchor with the SHA-256 fingerprint x. Nothing was removed."]}}
    return {"status": 400, "body": {"ok": False, "errors": ["The entry of \"x\" stores no certificate with the SHA-256 \"y\"."]}}
with contextlib.redirect_stdout(io.StringIO()):
    removed = mod.retire_sp_trust(call, files, config)
assert removed == ["/tls/trust/remove:" + sp_sha], removed
assert [c[0] for c in calls] == ["/tls/trust/remove", "/applications/remove-certificate"] * 2, calls
assert calls[0][1] == {"fingerprint": sp_sha} and calls[1][1] == {"application": files.entity_id, "sha256": sp_sha}
assert (folder / mod.RETIRED_SP_CERTS).read_text() == "", "settled fingerprints leave the file"
# A refusal other than "not held" keeps a retired fingerprint for the next run.
(folder / mod.RETIRED_SP_CERTS).write_text("cd" * 32 + "\n")
def angry(path, body, security=False):
    return {"status": 500, "body": {"ok": False, "errors": ["down"]}}
with contextlib.redirect_stdout(io.StringIO()):
    mod.retire_sp_trust(angry, files, config)
assert (folder / mod.RETIRED_SP_CERTS).read_text() == "cd" * 32 + "\n"

# --new-sp-keys: the current certificate is retired, then the pair regenerated with its name.
(folder / mod.RETIRED_SP_CERTS).write_text("")
mod.retire_current_sp_certificate(config, str(folder / "generated/sp.crt"))
assert (folder / mod.RETIRED_SP_CERTS).read_text() == sp_sha + "\n"
mod.retire_current_sp_certificate(config, str(folder / "generated/sp.crt"))
assert (folder / mod.RETIRED_SP_CERTS).read_text() == sp_sha + "\n", "once"
ran = []
mod._cli = lambda args, input_text=None: ran.append(args) or ""
mod._generate_keys(config, "http://localhost:3000/saml/metadata", force=True)
assert ran == [["generate-keys", "--config", config, "--cn", "saml2-sp-rust demo SP", "--entity-id", "http://localhost:3000/saml/metadata", "--force"]], ran
assert mod.parse_args(["--new-sp-keys"], {}).new_sp_keys is True and mod.parse_args([], {}).new_sp_keys is False
"#;
    let script_path = format!("{}/scripts/configure_iya_sts.py", env!("CARGO_MANIFEST_DIR"));
    let out = Command::new("python3").arg("-c").arg(script).arg(&script_path).arg(&dir).arg(&sp_sha).output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(out.status.success(), "{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
}
