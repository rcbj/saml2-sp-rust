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
