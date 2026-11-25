#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""A real headless browser through the demo's own pages, against a fresh iya-sts.

The UI half of the embedded PEP's checks. Provisioning is live_iya_sts.py's:
a FRESH iya-sts container from IYA_STS_IMAGE (one with #2026-#2028), the
checkout copied to a scratch build context, the demo image built there, the
install script run INSIDE that image with --pep local (it registers the demo,
makes the PEP's key, defines attr1 and gives the test user attr1=abc123, and
writes the application's own policy), the image built again with the chain,
then a second user given attr1=not-abc123, and the demo run with the key pair,
the IdP metadata and the PEP's key mounted file by file. Nothing runs Cargo,
pip or node on the host.

Then scripts/ui_browser.py runs in Playwright's official image
(PLAYWRIGHT_IMAGE, mcr.microsoft.com/playwright/python:v1.49.0-noble), on the
host network, and drives Chromium as a person would: open the demo, click
Sign in, follow the SAML redirect to iya-sts's sign-in page, type the username
and password and press Sign in, come back to the demo through the POST
binding, and open /attribute-protected and /orders/42, by address and by the
top bar's links, checking each page response's status and its visible text:
the test user 200 and 200. Then Sign out from the user menu, sign in as the
second user (through "Sign in with another account", ForceAuthn, when
iya-sts's session for the first one lingers): /attribute-protected 403,
GET /orders/42 200, and a POST /orders/42 sent with the browser's cookies 403.

Screenshots go to LIVE_UI_OUT, else a new scratch directory (printed, never in
the checkout). The JSON summary is printed last; any mismatch exits 1.

Ports: LIVE_UI_STS_PORT (18519) and LIVE_UI_DEMO_PORT (18619); never 3000,
8081, or 18481 to 18495. Containers: iya-sts-ui-saml2-sp-rust and
saml2-sp-rust-ui-demo, both removed at the end; nothing else is touched.
The passwords are generated, reach containers as -e NAME, and are never
printed. The browser does not verify iya-sts's TLS certificate: it is the
loopback iya-sts this script just started (the demo itself verifies it with
the chain the install script saved).
"""

import http.client
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import live_iya_sts as live  # noqa: E402
from live_iya_sts import DENIED_USER, PEP_KEY, PROFILE  # noqa: E402

PLAYWRIGHT_IMAGE = os.environ.get("PLAYWRIGHT_IMAGE") or "mcr.microsoft.com/playwright/python:v1.49.0-noble"
STS_NAME = "iya-sts-ui-" + PROFILE["repo"]
DEMO_NAME = PROFILE["repo"] + "-ui-demo"
IMAGE = PROFILE["repo"] + "-ui:demo"


def wait_pep(demo_origin, timeout=90):
    """The demo's local PEP registered and holding the application's policy."""
    parts = urllib.parse.urlsplit(demo_origin)
    deadline = time.time() + timeout
    state = {}
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=5)
            conn.request("GET", "/live-status")
            state = json.loads(conn.getresponse().read() or b"{}").get("pep") or {}
            conn.close()
            if state.get("registered") and state.get("holdsPolicy"):
                return state
        except (OSError, ValueError):
            pass
        time.sleep(1)
    raise RuntimeError(f"the demo's local PEP did not get ready: {json.dumps(state)[:600]}")


def browser_image():
    """Playwright's image carries the browsers but not the Python package: an
    image of its own adds it (in Docker, never on the host), built once."""
    tag = "saml2-sp-rust-ui:playwright-" + PLAYWRIGHT_IMAGE.rsplit(":", 1)[-1]
    if subprocess.run(["docker", "image", "inspect", tag], capture_output=True, check=False).returncode == 0:
        return tag
    version = PLAYWRIGHT_IMAGE.rsplit(":v", 1)[-1].split("-")[0]
    dockerfile = (f"FROM {PLAYWRIGHT_IMAGE}\n"
                  f"RUN python3 -m pip install --no-cache-dir --break-system-packages playwright=={version}\n")
    live.run(["docker", "build", "-t", tag, "-"], input=dockerfile, capture_output=True)
    return tag


def main():
    if not os.environ.get("IYA_STS_IMAGE") and not os.environ.get("IYA_STS_URL"):
        raise SystemExit("set IYA_STS_IMAGE to an iya-sts image with #2026-#2028 (or IYA_STS_URL)")
    sts_port = int(os.environ.get("LIVE_UI_STS_PORT") or 18519)
    demo_port = int(os.environ.get("LIVE_UI_DEMO_PORT") or 18619)
    sts_given = bool(os.environ.get("IYA_STS_URL", "").strip())
    bound = [demo_port] if sts_given else [sts_port, demo_port]
    if any(port in live.FORBIDDEN_PORTS for port in bound) or len(set(bound)) != len(bound):
        raise SystemExit("LIVE_UI_STS_PORT and LIVE_UI_DEMO_PORT must differ and must not bind 3000, 8081, or 18481 to 18495")
    out = Path(os.environ.get("LIVE_UI_OUT") or tempfile.mkdtemp(prefix=PROFILE["repo"] + "-ui-out-"))
    out.mkdir(parents=True, exist_ok=True)
    print(f"screenshots and the browser's summary go to {out}", flush=True)
    secret = os.environ.get("ADMIN_API_CLIENT_SECRET") or os.environ.get("STS_ADMIN_API_CLIENT_SECRET") or secrets.token_urlsafe(24)
    password = secrets.token_urlsafe(18)
    denied_password = secrets.token_urlsafe(18)
    username = PROFILE["test_user"]
    sts_origin, sts_name = live.prepare_sts(sts_port, secret, STS_NAME)
    demo_origin = f"http://127.0.0.1:{demo_port}"
    work = Path(tempfile.mkdtemp(prefix=PROFILE["repo"] + "-ui-"))
    summary = {"ok": False}
    try:
        live.wait_port(urllib.parse.urlsplit(sts_origin).port or 443, 120)
        live.wait_ready(sts_origin, 90)
        context = work / "context"
        live.copy_context(context)
        demo_dir = context / "demo"
        live.rewrite_config(live.ROOT / PROFILE["config_file"], demo_dir / "saml.json", sts_origin, demo_origin)
        # The demo image first (the install script's saml2-sp runs in it), then the
        # install script with --pep local, then the image again with the chain.
        live.docker("build", "-t", IMAGE, str(context))
        live.configure_demo(demo_dir, sts_origin, demo_origin, demo_port, username, password, secret, IMAGE, pep="local")
        ca_file = demo_dir / "generated" / "idp-ca.pem"
        pep_key = demo_dir / PEP_KEY
        config = json.loads((demo_dir / "saml.json").read_text(encoding="utf-8"))
        if not ca_file.exists() or not pep_key.exists() or (config.get("pep") or {}).get("mode") != "local":
            raise RuntimeError("the install script did not write the chain, the PEP's key and a local pep section")
        live.docker("build", "-t", IMAGE, str(context))
        listed = live.docker("run", "--rm", IMAGE, "ls", "-A", "demo/generated", capture_output=True).stdout.split()
        if listed != ["idp-ca.pem"]:
            raise RuntimeError(f"the demo image's demo/generated holds {listed}, not only the trust chain")
        client = live.Client(ca_file)
        token = live.mint_admin(client, sts_origin, secret)
        live.make_denied_user(client, sts_origin, token, denied_password)
        # The receiver's realm-issued TLS client certificate (the install script's, with signals on).
        mounts = [(demo_dir / "generated" / name, f"/app/demo/generated/{name}") for name in ("sp.key", "sp.crt", "idp-metadata.xml", "ssf-client.key", "ssf-client.crt")
                  if name not in ("ssf-client.key", "ssf-client.crt") or (demo_dir / "generated" / name).exists()]
        mounts.append((pep_key, "/app/demo/" + PEP_KEY))
        live.start_demo(IMAGE, DEMO_NAME, demo_port, demo_origin, mounts)
        pep = wait_pep(demo_origin)
        print(f"the demo's PEP is {pep.get('mode')}, holding {pep.get('policyCount')} policy(ies)", flush=True)
        image = browser_image()
        os.chmod(out, 0o777)
        env = {**os.environ, "UI_ALLOWED_PASSWORD": password, "UI_DENIED_PASSWORD": denied_password}
        completed = subprocess.run([
            "docker", "run", "--rm", "--network", "host", "--ipc=host",
            "--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp",
            "-v", f"{Path(__file__).resolve().parent / 'ui_browser.py'}:/ui/ui_browser.py:ro",
            "-v", f"{out}:/out",
            "-e", f"UI_DEMO={demo_origin}", "-e", f"UI_STS={sts_origin}",
            "-e", f"UI_ALLOWED_USER={username}", "-e", f"UI_DENIED_USER={DENIED_USER}",
            "-e", "UI_ALLOWED_PASSWORD", "-e", "UI_DENIED_PASSWORD", "-e", "UI_OUT=/out",
            image, "python3", "/ui/ui_browser.py",
        ], env=env, text=True, capture_output=True, check=False)
        print(completed.stdout, flush=True)
        if completed.stderr:
            print(completed.stderr, file=sys.stderr, flush=True)
        lines = [line for line in completed.stdout.splitlines() if line.startswith("{")]
        browser = json.loads(lines[-1]) if lines else {"ok": False, "error": f"the browser printed no summary (exit {completed.returncode})"}
        summary = {"ok": bool(browser.get("ok")) and completed.returncode == 0, "pep": {"mode": pep.get("mode"), "policyCount": pep.get("policyCount")},
                   "screenshots": str(out), "browser": browser}
    except Exception as err:
        summary = {"ok": False, "error": str(err)}
        logs = subprocess.run(["docker", "logs", DEMO_NAME], check=False, text=True, capture_output=True)
        if logs.stdout:
            print(logs.stdout[-4000:], flush=True)
    finally:
        live.docker_rm(DEMO_NAME)
        if sts_name:
            live.docker_rm(sts_name)
        shutil.rmtree(work, ignore_errors=True)
    print(json.dumps(summary, indent=2))
    return 0 if summary.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
