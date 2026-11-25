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
calls = mod.ssf_calls(files, "https://localhost:8081", "PEM")
paths = [call["path"].replace("https://localhost:8081/admin-api", "") for call in calls]
assert paths == ["/applications/add", "/roles/add-member", "/tls/trust/add", "/applications/add-certificate"], paths
assert calls[0]["body"] == {"application": "http://localhost:3000/saml/metadata", "attribute": "oauthAllowedScope", "value": "ssf.manage"}
assert calls[1]["body"] == {"role": "SSF_MANAGE", "kind": "application", "member": "http://localhost:3000/saml/metadata"}
assert any(call["path"].endswith("/applications/add-certificate") for call in mod.plan_for(files, "https://localhost:8081", "", "x"))
plain = mod.files_of(str(folder / "saml.json"))
assert not any(call["path"].endswith("/applications/add-certificate") for call in mod.plan_for(plain, "https://localhost:8081", "", "x"))
off = folder / "saml-signals-off.json"
off.write_text(json.dumps({**raw, "signals": False, "ssf": {"transmitter": "https://localhost:8081"}}))
files = mod.files_of(str(off))
assert files.ssf_transmitter is None
assert files.entity_id == "http://localhost:3000/saml/metadata"
import re
def re_path(path):
    return re.search(r"/applications/add$|/roles/add-member|/tls/trust/add|/applications/add-certificate", path) is not None
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
