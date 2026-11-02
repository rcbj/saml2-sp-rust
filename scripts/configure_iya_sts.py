#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Register the demo with a running iya-sts. The metadata documents do the SAML work.

This copy asks the Rust saml2-sp command for keys, metadata, and a summary of the identity provider.
"""

from __future__ import annotations

import base64
import json
import os
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

LOOPBACK = {"localhost", "127.0.0.1", "::1"}

ENCRYPTION = {
    "saml2EncryptAssertion": "TRUE",
    "saml2EncryptionAlgorithm": "aes256-gcm",
    "saml2KeyTransportAlgorithm": "rsa-oaep",
}
MULTIPLE_ACCOUNTS = {"key": "authn.multipleAccounts", "value": True}


def usage() -> str:
    return """Usage: python scripts/configure_iya_sts.py [--config path] [--idp url] [--public-url url]
                                        [--test-user name | --no-test-user] [--dry-run]

  --config        The demo's SAML configuration (default: demo/saml.json)
  --idp           iya-sts's base URL; the realm's, e.g. https://host/realm/acme, for a trust realm
                  (default: $IYA_STS_URL or https://localhost:8081)
  --public-url    Replace the origin of the file's entityID and assertion consumer URL with this URL,
                  and keep their paths (default: unset; $PUBLIC_URL). Without it, a loopback entityID
                  and ACS follow the running demo's PORT, then $PORT. A non-loopback URL is left as written.
  --test-user     The test user to create (default: saml-demo-user). Its password is
                  $SAML_DEMO_USER_PASSWORD, or one is generated and printed once. With
                  $SAML_DEMO_USER_PASSWORD set, an existing user's password is replaced.
  --no-test-user  Do not create a test user.
  --dry-run       Print what would be done, and send nothing.

The management API secret is ADMIN_API_CLIENT_SECRET or STS_ADMIN_API_CLIENT_SECRET."""


class Args:
    def __init__(self, **fields):
        self.__dict__.update(fields)


class DemoFiles:
    def __init__(self, **fields):
        self.__dict__.update(fields)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def on_port(url: str, port: int) -> str:
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ""
    if host not in LOOPBACK:
        return url
    hostname = f"[{host}]" if ":" in host else host
    user = ""
    if parsed.username:
        user = parsed.username
        if parsed.password:
            user += f":{parsed.password}"
        user += "@"
    netloc = f"{user}{hostname}:{port}"
    return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def endpoints_for(entity_id: str, acs_url: str, options: dict) -> dict:
    if options.get("public_url_given") and options.get("public_url"):
        public = options["public_url"]
        base = urllib.parse.urlsplit(public if public.endswith("/") else f"{public}/")

        def move(value: str) -> str:
            parsed = urllib.parse.urlsplit(value)
            hostname = base.hostname or ""
            if ":" in hostname:
                hostname = f"[{hostname}]"
            netloc = hostname
            if base.port:
                netloc = f"{hostname}:{base.port}"
            return urllib.parse.urlunsplit((base.scheme, netloc, parsed.path, parsed.query, parsed.fragment))

        return {"entityId": move(entity_id), "acsUrl": move(acs_url)}
    if options.get("port"):
        return {"entityId": on_port(entity_id, options["port"]), "acsUrl": on_port(acs_url, options["port"])}
    return {"entityId": entity_id, "acsUrl": acs_url}


def _parse_port(value) -> int | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        port = int(raw)
    except ValueError:
        return None
    if port < 1 or port > 65535:
        return None
    return port


def demo_port(env_port, container_port_value) -> int | None:
    return _parse_port(container_port_value) or _parse_port(env_port)


def parse_args(argv: list[str], env: dict | None = None) -> Args:
    env = os.environ if env is None else env
    out = Args(
        config=str(repo_root() / "demo" / "saml.json"),
        idp=str(env.get("IYA_STS_URL") or "https://localhost:8081").rstrip("/"),
        public_url=str(env.get("PUBLIC_URL") or "http://localhost:3000").rstrip("/"),
        public_url_given=bool(env.get("PUBLIC_URL")),
        test_user="saml-demo-user",
        dry_run=False,
        help=False,
    )
    index = 0
    while index < len(argv):
        arg = argv[index]

        def value() -> str:
            nonlocal index
            if index + 1 >= len(argv):
                raise SystemExit(f"{arg} needs a value\n{usage()}")
            index += 1
            return argv[index]

        if arg in ("--help", "-h"):
            out.help = True
        elif arg == "--config":
            out.config = str(Path(value()).resolve())
        elif arg == "--idp":
            out.idp = value().rstrip("/")
        elif arg == "--public-url":
            out.public_url = value().rstrip("/")
            out.public_url_given = True
        elif arg == "--test-user":
            out.test_user = value().strip()
        elif arg == "--no-test-user":
            out.test_user = ""
        elif arg == "--dry-run":
            out.dry_run = True
        else:
            raise SystemExit(f"Unknown argument {arg}\n{usage()}")
        index += 1
    parsed = urllib.parse.urlsplit(out.idp)
    if parsed.scheme != "https":
        raise SystemExit(f"--idp must be https, not {out.idp}")
    if not out.public_url:
        raise SystemExit("--public-url is empty")
    return out


def _expand_path(value: str) -> str:
    if value.startswith("file:"):
        return value[5:]
    if value.startswith("env:"):
        name = value[4:]
        if name not in os.environ:
            raise SystemExit(f"environment variable {name or value} is not set")
        return os.environ[name]
    return value


def files_of(config_path: str) -> DemoFiles:
    raw = json.loads(Path(config_path).read_text(encoding="utf-8"))
    base = Path(config_path).resolve().parent

    def at(path, what: str) -> str:
        if not isinstance(path, str) or not path or "-----BEGIN" in path or re.match(r"https?:", path) or path.startswith("<"):
            raise SystemExit(f"{config_path}'s {what} must be a file path for this script to write")
        value = _expand_path(path)
        candidate = Path(value)
        return str(candidate if candidate.is_absolute() else (base / candidate).resolve())

    if not raw.get("entityId"):
        raise SystemExit(f"{config_path} has no entityId")
    if not raw.get("acsUrl"):
        raise SystemExit(f"{config_path} has no acsUrl")
    if "signals" in raw and not isinstance(raw.get("signals"), bool):
        raise SystemExit(f"{config_path}: signals must be true or false")
    key = at(raw.get("privateKey"), "privateKey")
    ssf = raw.get("ssf") if isinstance(raw.get("ssf"), dict) else {}
    return DemoFiles(
        entity_id=raw["entityId"],
        acs_url=raw["acsUrl"],
        key=key,
        cert=at(raw.get("certificate"), "certificate"),
        idp_metadata=at(raw.get("idpMetadata"), "idpMetadata"),
        idp_ca=at(raw.get("idpCa"), "idpCa") if raw.get("idpCa") else None,
        sp_metadata=str(Path(key).parent / "sp-metadata.xml"),
        ssf_transmitter=None if raw.get("signals") is False else ssf.get("transmitter"),
    )


def _cli(args: list[str], input_text: str | None = None) -> str:
    proc = subprocess.run(
        ["cargo", "run", "--quiet", "--bin", "saml2-sp", "--", *args],
        cwd=repo_root(), input=input_text, capture_output=True, text=True, check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(proc.stderr.strip() or proc.stdout.strip() or "saml2-sp failed")
    return proc.stdout


def metadata_for(config_path: str, entity_id: str, acs_url: str) -> str:
    return _cli(["metadata", "--config", config_path, "--entity-id", entity_id, "--acs-url", acs_url])


def realm_of(idp: str) -> dict:
    parsed = urllib.parse.urlsplit(idp)
    path = parsed.path.rstrip("/")
    if path and not re.fullmatch(r"/realm/[^/]+", path):
        raise SystemExit(f"--idp must be iya-sts's base URL or a realm's (/realm/<id>), not {idp}")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return {"origin": origin, "base": f"{origin}{path}"}


def idp_metadata_url(base: str, entity_id: str) -> str:
    return f"{base}/saml2/metadata/{urllib.parse.quote(entity_id, safe='')}"


def plan_for(files: DemoFiles, base: str, test_user: str, sp_metadata_xml: str) -> list[dict]:
    calls = [
        {"method": "POST", "path": f"{base}/admin-api/applications/create", "why": f"register {files.entity_id} from its metadata",
         "body": {"identifier": files.entity_id, "name": "saml2-sp demo", "protocols": ["saml2"], "fields": {"samlSpMetadata": sp_metadata_xml}}},
        {"method": "POST", "path": f"{base}/admin-api/saml2/upload-metadata", "why": "(only if it already exists) consume the metadata again",
         "body": {"sp": files.entity_id, "family": "saml2", "document": sp_metadata_xml}},
        {"method": "GET", "path": idp_metadata_url(base, files.entity_id), "body": None, "why": f"fetch the IdP metadata into {files.idp_metadata}"},
    ]
    calls.insert(2, {"method": "POST", "path": f"{base}/admin-api/config/set", "why": "let one browser hold several accounts", "body": MULTIPLE_ACCOUNTS})
    for attribute, value in ENCRYPTION.items():
        calls.insert(2, {"method": "POST", "path": f"{base}/admin-api/applications/set", "why": f"encrypt the assertion: {attribute}",
                         "body": {"application": files.entity_id, "attribute": attribute, "value": value}})
    if files.ssf_transmitter:
        calls[-1:-1] = ssf_calls(files, base, "<the SP certificate>")
    if test_user:
        calls.append({"method": "POST", "path": f"{base}/admin-api/users/create", "why": f"create the test user {test_user}", "body": {"username": test_user}})
    return calls


def ssf_calls(files: DemoFiles, base: str, certificate_pem: str) -> list[dict]:
    return [
        {"method": "POST", "path": f"{base}/admin-api/applications/add", "why": "declare the Shared Signals write scope",
         "body": {"application": files.entity_id, "attribute": "oauthAllowedScope", "value": "ssf.manage"}},
        {"method": "POST", "path": f"{base}/admin-api/roles/add-member", "why": "hold SSF_MANAGE, which authorizes it",
         "body": {"role": "SSF_MANAGE", "kind": "application", "member": files.entity_id}},
        {"method": "POST", "path": f"{base}/admin-api/tls/trust/add", "why": "trust the SP certificate at the TLS handshake",
         "body": {"certificates": certificate_pem}},
        {"method": "POST", "path": f"{base}/admin-api/applications/add-certificate", "why": "store the SP certificate on the application",
         "body": {"application": files.entity_id, "certificate": certificate_pem}},
    ]


def container_port(cwd: str | None = None) -> str | None:
    try:
        identity = subprocess.run(
            ["docker", "compose", "ps", "-q", "saml-demo"],
            cwd=cwd or str(repo_root()), check=False, capture_output=True, text=True,
        )
        if identity.returncode != 0:
            return None
        container = identity.stdout.strip().split("\n")[0]
        if not container:
            return None
        env = subprocess.run(
            ["docker", "inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}", container],
            check=False, capture_output=True, text=True,
        )
        if env.returncode != 0:
            return None
        for line in env.stdout.splitlines():
            if line.startswith("PORT="):
                return line[len("PORT="):]
    except OSError:
        return None
    return None


def fetch_tls_root(origin: str) -> tuple[str, str, str]:
    parsed = urllib.parse.urlsplit(origin)
    host = parsed.hostname or ""
    port = parsed.port or 443
    proc = subprocess.run(
        ["openssl", "s_client", "-showcerts", "-servername", host, "-connect", f"{host}:{port}"],
        input=b"", capture_output=True, timeout=20, check=False,
    )
    pems = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", proc.stdout.decode("utf-8", "replace"), re.S)
    if not pems:
        raise SystemExit(f"could not read a TLS certificate from {origin}")
    return pems[-1] + "\n", "the last certificate openssl presented", ""


def _request(url: str, method: str, headers: dict, body: bytes | None, ca: str | None):
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    context = None
    if url.startswith("https://"):
        context = ssl.create_default_context()
        if ca:
            context.load_verify_locations(cadata=ca)
    try:
        with urllib.request.urlopen(request, timeout=15, context=context) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


def _json(url: str, ca: str | None, method: str = "GET", headers: dict | None = None, body: str | None = None) -> dict:
    raw_headers = dict(headers or {})
    payload = None if body is None else body.encode()
    status, data = _request(url, method, raw_headers, payload, ca)
    text = data.decode("utf-8", "replace")
    try:
        parsed = json.loads(text) if text else {}
    except json.JSONDecodeError as err:
        raise SystemExit(f"{method} {url} answered {status} with non-JSON: {text[:300]}") from err
    if status in (401, 403):
        raise SystemExit(f"{method} {url} answered {status}: {json.dumps(parsed)[:300]}")
    return {"status": status, "body": parsed}


def _errors_of(body: dict) -> list[str]:
    return [str(item) for item in (body.get("errors") or [])]


def mint_admin_token(origin: str, base: str, ca: str | None, secret: str) -> str:
    form = urllib.parse.urlencode({"grant_type": "client_credentials", "scope": "admin:read admin:write", "resource": f"{base}/admin-api"})
    basic = base64.b64encode(f"sts-api-client:{secret}".encode()).decode()
    reply = _json(f"{base}/oauth2/token", ca, "POST", {"content-type": "application/x-www-form-urlencoded", "authorization": f"Basic {basic}"}, form)
    token = reply["body"].get("access_token") if isinstance(reply["body"], dict) else None
    if reply["status"] != 200 or not isinstance(token, str):
        raise SystemExit(f"the token endpoint at {origin} answered {reply['status']} {json.dumps(reply['body'])[:300]}")
    return token


def _summarize(xml: str):
    lines = _cli(["summarize-idp"], xml).splitlines()
    return lines[0], lines[1] if len(lines) > 1 else "", [item for item in lines[2:] if item]


def main(argv: list[str] | None = None) -> None:
    args = parse_args(list(sys.argv[1:] if argv is None else argv))
    if args.help:
        print(usage())
        return
    files = files_of(args.config)
    port = demo_port(os.environ.get("PORT"), container_port())
    endpoints = endpoints_for(files.entity_id, files.acs_url, {
        "public_url": args.public_url, "public_url_given": args.public_url_given, "port": port,
    })
    files.entity_id = endpoints["entityId"]
    files.acs_url = endpoints["acsUrl"]
    realm = realm_of(args.idp)
    origin, base = realm["origin"], realm["base"]
    if args.dry_run:
        xml = "<the SP metadata from the configuration>" if Path(files.cert).exists() else "<the SP metadata, once the key pair exists>"
        if not Path(files.key).exists():
            print(f"# would generate the key pair {files.key}, {files.cert}")
        if files.idp_ca and not Path(files.idp_ca).exists():
            print(f"# would save {origin}'s TLS root to {files.idp_ca}")
        print(f"# would write {files.sp_metadata}")
        for call in plan_for(files, base, args.test_user, xml):
            body = f"\n{json.dumps(call['body'], indent=2)}" if call.get("body") is not None else ""
            print(f"{call['method']} {call['path']}  # {call['why']}{body}")
        return
    if not Path(files.key).exists() and not Path(files.cert).exists():
        print("No key pair yet; generating one.")
        _generate_keys(args.config)
    ca = None
    if files.idp_ca:
        if not Path(files.idp_ca).exists():
            pem, subject, fingerprint = fetch_tls_root(origin)
            Path(files.idp_ca).parent.mkdir(parents=True, exist_ok=True)
            Path(files.idp_ca).write_text(pem, encoding="utf-8")
            print(f"Saved {origin}'s TLS root to {files.idp_ca} (trusted on first use):")
            print(f"  {subject}\n  sha256 {fingerprint}")
            print("  Compare it with the Root CA on iya-sts's Server configuration → PKI page.")
        ca = Path(files.idp_ca).read_text(encoding="utf-8")
    sp_metadata_xml = metadata_for(args.config, files.entity_id, files.acs_url)
    Path(files.sp_metadata).parent.mkdir(parents=True, exist_ok=True)
    Path(files.sp_metadata).write_text(sp_metadata_xml, encoding="utf-8")
    print(f"Wrote the service provider metadata to {files.sp_metadata}")
    secret = os.environ.get("ADMIN_API_CLIENT_SECRET") or os.environ.get("STS_ADMIN_API_CLIENT_SECRET") or ""
    if not secret:
        raise SystemExit("neither ADMIN_API_CLIENT_SECRET nor STS_ADMIN_API_CLIENT_SECRET is set, so no /admin-api token can be minted.")
    token = mint_admin_token(origin, base, ca, secret)

    def api(path: str, body) -> dict:
        return _json(f"{base}/admin-api{path}", ca, "POST", {
            "accept": "application/json", "content-type": "application/json", "authorization": f"Bearer {token}",
        }, json.dumps(body))

    create, upload = plan_for(files, base, args.test_user, sp_metadata_xml)[:2]
    created = api("/applications/create", create["body"])
    if created["body"].get("ok"):
        print(f"Registered {files.entity_id} from its metadata.")
        message = created["body"].get("message")
        if isinstance(message, str) and "NOT consumed" in message:
            raise SystemExit(f"iya-sts created the application but refused its metadata: {message}")
    elif any(re.search(r"already in this registry", item, re.I) for item in _errors_of(created["body"])):
        consumed = api("/saml2/upload-metadata", upload["body"])
        if not consumed["body"].get("ok"):
            raise SystemExit(f"iya-sts refused the metadata: {json.dumps(consumed['body'])[:500]}")
        print(f"{files.entity_id} was registered already; its metadata was consumed again.")
    else:
        raise SystemExit(f"iya-sts refused to create {files.entity_id}: {json.dumps(created['body'])[:500]}")
    for attribute, value in ENCRYPTION.items():
        written = api("/applications/set", {"application": files.entity_id, "attribute": attribute, "value": value})
        if not written["body"].get("ok"):
            raise SystemExit(f"setting {attribute}={value} was refused: {json.dumps(written['body'])[:300]}")
    print("Assertions to it are encrypted: AES-256-GCM, the key wrapped with RSA-OAEP (SHA-256).")
    multiple = api("/config/set", MULTIPLE_ACCOUNTS)
    if not multiple["body"].get("ok"):
        raise SystemExit(f"setting authn.multipleAccounts was refused: {json.dumps(multiple['body'])[:300]}")
    print("authn.multipleAccounts is on: one browser may hold several signed-in people.")
    if files.ssf_transmitter:
        certificate_pem = Path(files.cert).read_text(encoding="utf-8")
        for call in ssf_calls(files, base, certificate_pem):
            path = call["path"][len(f"{base}/admin-api"):]
            reply = api(path, call["body"])
            errors = " ".join(_errors_of(reply["body"]))
            if not reply["body"].get("ok") and not re.search(r"already", errors, re.I):
                raise SystemExit(f"{call['why']}: refused: {json.dumps(reply['body'])[:400]}")
            if not reply["body"].get("ok"):
                print(f"  {call['why']}: already so ({errors[:160]})")
        print(f"Shared Signals: {files.entity_id} holds SSF_MANAGE and authenticates to /ssf/* with its own certificate (mutual TLS).")
    url = idp_metadata_url(base, files.entity_id)
    status, data = _request(url, "GET", {"accept": "application/samlmetadata+xml"}, None, ca)
    if status != 200:
        raise SystemExit(f"{url} answered {status}")
    fetched = data.decode("utf-8", "replace")
    entity_id, sso, artifacts = _summarize(fetched)
    Path(files.idp_metadata).parent.mkdir(parents=True, exist_ok=True)
    Path(files.idp_metadata).write_text(fetched, encoding="utf-8")
    print(f"Saved the IdP metadata to {files.idp_metadata}:")
    print(f"  entityID   {entity_id}")
    print(f"  SSO        {sso}")
    print(f"  artifacts  {', '.join(artifacts) or '(none)'}")
    if args.test_user:
        found = _json(
            f"{base}/admin-api/users?user={urllib.parse.quote(args.test_user)}", ca, "GET",
            {"accept": "application/json", "authorization": f"Bearer {token}"},
        )
        password = os.environ.get("SAML_DEMO_USER_PASSWORD") or ""
        if found["body"].get("known") is True and password:
            written = api("/users/set-password", {"user": args.test_user, "password": password, "passwordConfirm": password})
            if not written["body"].get("ok"):
                raise SystemExit(f"setting {args.test_user}'s password was refused: {json.dumps(written['body'])[:300]}")
            print(f"User {args.test_user} already exists; its password is now SAML_DEMO_USER_PASSWORD.")
        elif found["body"].get("known") is True:
            print(f"User {args.test_user} already exists; its password is unchanged (set SAML_DEMO_USER_PASSWORD to replace it).")
        else:
            attributes = {
                "cn": f"SAML Demo {args.test_user}", "givenName": "SAML", "sn": "Demo",
                "displayName": f"SAML Demo {args.test_user}", "mail": f"{args.test_user}@saml-demo.test",
            }
            body = {"username": args.test_user, "invent": False, "credential": "password", "password": password, "passwordConfirm": password, "attributes": attributes} if password else {
                "username": args.test_user, "invent": False, "credential": "generate", "attributes": attributes,
            }
            made = api("/users/create", body)
            if not made["body"].get("ok"):
                raise SystemExit(f"creating {args.test_user} was refused: {json.dumps(made['body'])[:300]}")
            print(f"Created user {args.test_user}.")
            if made["body"].get("password"):
                print(f"Generated password for {args.test_user} (shown once): {made['body']['password']}")
    print("Done. Start the demo with: docker compose up --build")


def _generate_keys(config_path: str) -> None:
    proc = subprocess.run(
        ["go", "run", "./cmd/saml2-sp", "generate-keys", "--config", config_path],
        cwd=repo_root(), check=False,
    )
    if proc.returncode != 0:
        raise SystemExit("generate-keys failed")


if __name__ == "__main__":
    try:
        main()
    except SystemExit as err:
        if err.code not in (None, 0):
            sys.stderr.write(f"{err.code if isinstance(err.code, str) else err}\n")
            raise SystemExit(1) from None
        raise
