#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""The embedded PEP's AuthZEN cases, central against local, on a fresh iya-sts.

src/authzen/cases.json is this library's case table. This script provisions
what the table describes on a fresh iya-sts and then runs src/authzen_test.rs's
env-gated live test (`live_central_equals_local`), which asks every case of a
phase through two ServiceProviders, one with a `central` pep section and one
with a `local` one, and requires central == local == the table's answer.

The order:
  1. iya-sts from IYA_STS_IMAGE (or IYA_STS_URL, or main, as live_iya_sts.py).
  2. scripts/configure_iya_sts.py registers this SP (signals off) INSIDE a
     rust:1 container, falling back to `cargo run --bin saml2-sp` there, and
     writes the IdP metadata and the listener's trust chain. Cargo never runs
     on the host.
  3. Through /admin-api: the directory person the table names, two PEP service
     accounts in remote-peps (one per mode), each with its own P-256 key made
     here (0600, never printed) and certified with issue-pep-credential bound
     to the SP's application; the table's catalogue rows; the root policy and
     the shared policy from their ALFA.
  4. Phase `root`: the live test, in a rust:1 container.
  5. Phase `application`: the application's own policy written from its ALFA,
     the reference to the shared policy added in the editor, fine-grained
     authorization enforced; the live test again.
The XACML iya-sts stored for each ALFA document must equal the table's .xml
file (what the offline runner serves); --write-xml rewrites the files instead.

The final JSON reports the cases run, how many central == local and how many
equal the table, and every mismatch (case, central, local, expected). Any
mismatch exits 1. Ports: LIVE_STS_PORT (18518) for iya-sts; LIVE_DEMO_PORT
(18618) only names the SP's entityID, nothing binds it. 3000, 8081 and 18481
to 18495 are refused. No secret, key or URL is printed.
"""

import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import live_iya_sts as live  # noqa: E402  (this directory's own helpers)

ROOT = live.ROOT
TABLE_DIR = ROOT / "src" / "authzen"
RUST_IMAGE = os.environ.get("AUTHZEN_RUST_IMAGE") or "rust:1"
CARGO_VOLUME = os.environ.get("AUTHZEN_CARGO_VOLUME") or "iya-pep-cargo"
PEPS = {"central": "pep-saml-azn-central", "local": "pep-saml-azn-local"}


def table():
    return json.loads((TABLE_DIR / "cases.json").read_text(encoding="utf-8"))


def rust(work, env_names, *command, env=None):
    """One command in rust:1 as this user, the checkout at /src and the
    scratch directory at /work. The target directory is inside the checkout."""
    return live.docker(
        "run", "--rm", "--network", "host",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "-e", "HOME=/tmp", "-e", "CARGO_HOME=/cargo",
        "-e", "CARGO_TARGET_DIR=/src/target/authzen-live",
        *[part for name in env_names for part in ("-e", name)],
        "-v", f"{CARGO_VOLUME}:/cargo",
        "-v", f"{ROOT}:/src",
        "-v", f"{work}:/work",
        "-w", "/src",
        RUST_IMAGE, *command,
        env=env,
    )


def register_sp(work, sts_origin, demo_origin, demo_port, secret):
    demo = work / "demo"
    (demo / "generated").mkdir(parents=True, exist_ok=True)
    config = {
        "entityId": f"{demo_origin}/saml/metadata",
        "acsUrl": f"{demo_origin}/saml/acs",
        "privateKey": "file:generated/sp.key",
        "certificate": "file:generated/sp.crt",
        "idpMetadata": "file:generated/idp-metadata.xml",
        "idpCa": "file:generated/idp-ca.pem",
        "responseBinding": "post",
        "signals": False,
    }
    (demo / "saml.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    env = {**os.environ, "ADMIN_API_CLIENT_SECRET": secret, "PORT": str(demo_port)}
    rust(work, ["ADMIN_API_CLIENT_SECRET", "PORT"],
         "python3", "scripts/configure_iya_sts.py",
         "--config", "/work/demo/saml.json", "--idp", sts_origin, "--public-url", demo_origin,
         "--no-test-user", env=env)
    for name in ("sp.key", "sp.crt", "idp-metadata.xml", "idp-ca.pem"):
        if not (demo / "generated" / name).exists():
            raise RuntimeError(f"the registrar did not write generated/{name}")
    return json.loads((demo / "saml.json").read_text(encoding="utf-8"))["entityId"]


def admin(client, sts_origin, token, path, body, what, allow=None):
    status, parsed = live.admin_json(client, sts_origin, token, "POST", path, body)
    if status != 200 or parsed.get("ok") is False:
        text = json.dumps(parsed)
        if allow and allow in text:
            print(f"{what}: already so", flush=True)
            return parsed
        raise RuntimeError(f"{what}: answered {status}: {text[:600]}")
    print(f"{what}: {status}", flush=True)
    return parsed


def make_key(path, name, work):
    path.parent.mkdir(parents=True, exist_ok=True)
    old = os.umask(0o077)
    try:
        made = subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(path)],
                              check=False, capture_output=True, text=True)
    finally:
        os.umask(old)
    if made.returncode != 0:
        raise RuntimeError("openssl could not make a PEP key")
    os.chmod(path, 0o600)
    csr = work / f"{name}.csr"
    asked = subprocess.run(["openssl", "req", "-new", "-key", str(path), "-subj", f"/CN={name}", "-out", str(csr)],
                           check=False, capture_output=True, text=True)
    if asked.returncode != 0:
        raise RuntimeError("openssl could not make a PEP certificate request")
    return csr.read_text(encoding="utf-8")


def provision(client, sts_origin, token, application, work, cases):
    for username, attributes in cases["directory"].items():
        # The generated password is in the answer and is dropped: nobody signs in.
        admin(client, sts_origin, token, "/admin-api/users/create",
              {"username": username, "invent": False, "credential": "generate", "attributes": attributes},
              f"the directory person {username}")
    keys = {}
    for mode, name in PEPS.items():
        admin(client, sts_origin, token, "/admin-api/users/create", {
            "username": name, "invent": False, "credential": "none", "serviceAccount": True,
            "owners": ["admin-write"], "attributes": {"cn": name, "displayName": name},
        }, f"the {mode} PEP's service account")
        admin(client, sts_origin, token, "/admin-api/groups/add-member", {"group": "remote-peps", "member": name},
              f"the {mode} PEP in remote-peps")
        key = work / "keys" / f"{mode}.pem"
        csr = make_key(key, name, work)
        admin(client, sts_origin, token, "/admin-api/xacml/issue-pep-credential",
              {"name": name, "csr": csr, "application": application}, f"the {mode} PEP's key certified and bound")
        keys[mode] = key
    for row in cases["catalogue"]:
        admin(client, sts_origin, token, "/admin-api/xacml/authzen/set-attribute", row,
              f"catalogue row {row['object']}.{row['property']}")
    root, shared = cases["policies"]["root"], cases["policies"]["shared"]
    for policy in (root, shared):
        admin(client, sts_origin, token, "/admin-api/xacml/import-alfa",
              {"name": policy["name"], "alfa": (TABLE_DIR / policy["alfa"]).read_text(encoding="utf-8")},
              f"policy {policy['name']} from {policy['alfa']}")
    admin(client, sts_origin, token, "/admin-api/xacml/set-root", {"name": root["name"]}, f"{root['name']} is the root")
    return keys


def stored_document(client, sts_origin, token, name):
    status, parsed = live.admin_json(client, sts_origin, token, "GET", "/admin-api/xacml/editor?policy=" + urllib.parse.quote(name))
    if status != 200:
        raise RuntimeError(f"the editor view of {name} answered {status}")
    found = []

    def walk(value):
        if isinstance(value, dict):
            for key, inner in value.items():
                if key in ("document", "xml") and isinstance(inner, str) and "<" in inner:
                    found.append(inner)
                walk(inner)
        elif isinstance(value, list):
            for inner in value:
                walk(inner)

    walk(parsed)
    if not found:
        raise RuntimeError(f"the editor view of {name} carries no document; its members: {sorted(parsed)[:40]}")
    return found[0]


def check_xml(document, file_name, write, problems):
    path = TABLE_DIR / file_name
    if write:
        path.write_text(document.rstrip("\n") + "\n", encoding="utf-8")
        print(f"wrote src/authzen/{file_name} from what iya-sts stored", flush=True)
        return
    held = path.read_text(encoding="utf-8") if path.exists() else ""
    if held.strip() != document.strip():
        problems.append(f"src/authzen/{file_name} is not what iya-sts stored for its ALFA (run with --write-xml)")


def enforce_application(client, sts_origin, token, application, cases):
    policy = cases["policies"]["application"]
    admin(client, sts_origin, token, "/admin-api/applications/fga-create-policy", {"application": application},
          "the application's own policy", allow="already")
    status, page = live.admin_json(client, sts_origin, token, "GET",
                                   "/admin-api/applications?application=" + urllib.parse.quote(application, safe=""))
    fga = ((page.get("page") or {}).get("fga") or {}) if status == 200 else {}
    name = (fga.get("policy") or {}).get("name") or fga.get("reference")
    if not name:
        raise RuntimeError(f"the application page names no policy of its own: {json.dumps(fga)[:400]}")
    admin(client, sts_origin, token, "/admin-api/xacml/import-alfa",
          {"name": name, "alfa": (TABLE_DIR / policy["alfa"]).read_text(encoding="utf-8")},
          f"the application's policy from {policy['alfa']}")
    for ref in policy.get("references") or []:
        admin(client, sts_origin, token, "/admin-api/xacml/add-policy-reference", {"policy": name, "path": "", "ref": ref},
              f"its PolicyIdReference to {ref}")
    admin(client, sts_origin, token, "/admin-api/applications/fga-enable", {"application": application},
          "fine-grained authorization enforced")
    return name


def run_phase(work, phase, settings):
    out = work / f"results-{phase}.json"
    settings = {**settings, "phase": phase, "out": f"/work/{out.name}"}
    (work / f"live-{phase}.json").write_text(json.dumps(settings, indent=2), encoding="utf-8")
    env = {**os.environ, "AUTHZEN_LIVE": f"/work/live-{phase}.json"}
    try:
        rust(work, ["AUTHZEN_LIVE"], "cargo", "test", "--features", "local", "--lib",
             "authzen_test::live_central_equals_local", "--", "--nocapture", env=env)
    except RuntimeError as err:
        print(f"phase {phase}: {err}", file=sys.stderr, flush=True)
    if not out.exists():
        raise RuntimeError(f"phase {phase} wrote no results")
    return json.loads(out.read_text(encoding="utf-8"))


def main():
    write_xml = "--write-xml" in sys.argv[1:]
    sts_port = int(os.environ.get("LIVE_STS_PORT") or 18518)
    demo_port = int(os.environ.get("LIVE_DEMO_PORT") or 18618)
    if sts_port in live.FORBIDDEN_PORTS or demo_port in live.FORBIDDEN_PORTS or sts_port == demo_port:
        raise SystemExit("LIVE_STS_PORT and LIVE_DEMO_PORT must differ and must not be 3000, 8081, or 18481 to 18495")
    secret = os.environ.get("ADMIN_API_CLIENT_SECRET") or os.environ.get("STS_ADMIN_API_CLIENT_SECRET") or secrets.token_urlsafe(24)
    cases = table()
    sts_origin, sts_name = live.prepare_sts(sts_port, secret)
    demo_origin = f"http://127.0.0.1:{demo_port}"
    work = Path(tempfile.mkdtemp(prefix="saml2-sp-rust-authzen-"))
    try:
        live.wait_port(urllib.parse.urlsplit(sts_origin).port or 443, 120)
        live.wait_ready(sts_origin, 90)
        application = register_sp(work, sts_origin, demo_origin, demo_port, secret)
        generated = work / "demo" / "generated"
        client = live.Client(generated / "idp-ca.pem")
        token = live.mint_admin(client, sts_origin, secret)
        keys = provision(client, sts_origin, token, application, work, cases)
        problems = []
        for policy in (cases["policies"]["root"], cases["policies"]["shared"]):
            check_xml(stored_document(client, sts_origin, token, policy["name"]), policy["xacml"], write_xml, problems)
        settings = {
            "saml": {
                "entityId": application,
                "acsUrl": f"{demo_origin}/saml/acs",
                "privateKey": "/work/demo/generated/sp.key",
                "certificate": "/work/demo/generated/sp.crt",
                "idpMetadata": "/work/demo/generated/idp-metadata.xml",
                "idpCa": "/work/demo/generated/idp-ca.pem",
                "signals": False,
            },
            "peps": {mode: {"name": PEPS[mode], "assertionKey": f"/work/keys/{mode}.pem"} for mode in keys},
        }
        results = [run_phase(work, "root", settings)]
        token = live.mint_admin(client, sts_origin, secret)
        name = enforce_application(client, sts_origin, token, application, cases)
        check_xml(stored_document(client, sts_origin, token, name), cases["policies"]["application"]["xacml"], write_xml, problems)
        results.append(run_phase(work, "application", settings))
        mismatches = [m for r in results for m in r.get("mismatches", [])]
        summary = {
            "ok": not mismatches and not problems,
            "casesRun": sum(r.get("casesRun", 0) for r in results),
            "centralEqualsLocal": sum(r.get("centralEqualsLocal", 0) for r in results),
            "equalExpected": sum(r.get("equalExpected", 0) for r in results),
            "phases": {r.get("phase"): {k: r.get(k) for k in ("casesRun", "centralEqualsLocal", "equalExpected")} for r in results},
            "mismatches": mismatches,
            "tableProblems": problems,
        }
        print(json.dumps(summary, indent=2))
        if not summary["ok"]:
            sys.exit(1)
    finally:
        if sts_name:
            live.docker_rm(sts_name)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(str(err), file=sys.stderr)
        sys.exit(1)
