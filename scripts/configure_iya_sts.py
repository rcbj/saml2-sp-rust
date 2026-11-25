#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Register the demo with a running iya-sts. The metadata documents do the SAML work.

This copy asks the Rust saml2-sp command for keys, metadata, and a summary of the identity provider.
It uses the saml2-sp binary on PATH (the demo image installs one), and falls back to `cargo run`.

It writes iya-sts's listener CA trust chain (leaf, TLS Issuing CA, Intermediate, Root) to the file
idpCa names, every run. The demo image build copies that file in, so rebuild the image after running
this against a different iya-sts.

--pep [local|central] (local when left out) also sets the demo up with its embedded PEP (docs/remote-pep.md, steps 2 to 6):
the PEP's service account in remote-peps; a P-256 key made here with openssl in generated/pep-key.pem
beside the configuration (0600, never printed, kept out of the image by .dockerignore), certified from
its own request with the PEP bound to the demo's application; the catalogue row the demo's policy reads;
and the demo application's OWN policy, which it then enforces, so the realm root is never touched. It
writes the `pep` section into the configuration. Run again against the same iya-sts, it keeps the
account, the key and the policy (an administrator's edits survive), binds the PEP again and switches
the mode.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from trust_chain import save_trust_chain  # noqa: E402

LOOPBACK = {"localhost", "127.0.0.1", "::1"}

ENCRYPTION = {
    "saml2EncryptAssertion": "TRUE",
    "saml2EncryptionAlgorithm": "aes256-gcm",
    "saml2KeyTransportAlgorithm": "rsa-oaep",
}
MULTIPLE_ACCOUNTS = {"key": "authn.multipleAccounts", "value": True}

# The embedded PEP (--pep). PEP_KEY is relative to the configuration's directory, and the `pep`
# section names it that way too: this library reads a relative assertionKey from there, as it reads
# privateKey.
# The SP key pair's certificate subject: a name a person recognises in iya-sts's console,
# with the entityID as its subjectAltName URI (saml2-sp generate-keys adds O=saml2-sp).
SP_CERT_CN = "saml2-sp-rust demo SP"
# The Shared Signals receiver's own TLS client identity: a certificate the realm issues the
# application (urn:sts:application:<entityID>), beside the configuration, written into its
# ssf block as clientCertificate / clientKey. Separate from the SAML signing/encryption key.
SSF_CLIENT_KEY = "generated/ssf-client.key"
SSF_CLIENT_CERT = "generated/ssf-client.crt"
SSF_CLIENT_LABEL = "saml2-sp demo SSF"
# SHA-256 fingerprints of SP certificates --new-sp-keys replaced: their old trust anchors and
# stored copies are taken off iya-sts once the realm-issued certificate is in place.
RETIRED_SP_CERTS = "generated/retired-sp-certificates.txt"

PEP_MODES = ("central", "local")
PEP_NAME = "pep-saml-demo"
PEP_KEY = "generated/pep-key.pem"
PEP_GROUP = "remote-peps"
PEP_EVENT = "urn:iya:sts:secevent:event-type:pep-policies-changed"
# The realm's AuthZEN catalogue has ONE subject.acr row, shared by every
# application in the realm, and each sibling demo's install script writes it.
# So all four Rust demos use the same attribute id: a different one here was
# overwritten by the next demo's run, after which this demo's policy found no
# acr and denied every order.
ACR_ATTRIBUTE = "urn:example:acr"
# The demo's attribute-protected resource (GET /attribute-protected): the test user carries a custom
# directory attribute, and the demo application's own policy permits the resource only to a person
# whose attr1 is abc123. The PEP asks iya-sts's PIP for it (POST /xacml/pip): it is a directory
# attribute, not something the assertion carries.
TEST_ATTRIBUTE = "attr1"
TEST_ATTRIBUTE_VALUE = "abc123"
TEST_ATTRIBUTE_ID = "urn:sts:xacml:attribute:" + TEST_ATTRIBUTE
ATTRIBUTE_PROTECTED = "attribute-protected"
# The PolicyIds of the policies this script writes. While the demo application enforces one of
# these, a run writes the current version over it; a policy an administrator wrote under another
# PolicyId is left alone.
OWN_POLICY_IDS = ("urn:saml-sp-demo:samlspdemo:orders",)


def orders_policy(namespace: str = "samlspdemo", read_effect: str = "permit") -> str:
    """The demo application's own policy, in ALFA, the one its fine-grained authorization decisions
    are made with:
    - `read` on an `order` is `read_effect`; a Permit also needs the sign-in's AuthnContextClassRef,
      which reaches the policy only through the catalogue row, so a 200 shows the claim arrived;
    - `read` on the `attribute-protected` resource is permitted when the person's directory
      attribute attr1 is abc123, which the PEP asks iya-sts's PIP for;
    - everything else (the demo's `write`) is denied."""
    needs_acr = "                condition integerGreaterThan(stringBagSize(acr), 0)\n" if read_effect == "permit" else ""
    return (
        f"namespace {namespace} {{\n"
        '    attribute action { category = actionCat id = "urn:oasis:names:tc:xacml:1.0:action:action-id" type = string }\n'
        '    attribute kind { category = resourceCat id = "urn:sts:xacml:authzen:resource-type" type = string }\n'
        f'    attribute acr {{ category = subjectCat id = "{ACR_ATTRIBUTE}" type = string }}\n'
        f'    attribute {TEST_ATTRIBUTE} {{ category = subjectCat id = "{TEST_ATTRIBUTE_ID}" type = string }}\n'
        f"    policy {namespace}Orders {{\n"
        f'        id = "urn:saml-sp-demo:{namespace}:orders"\n'
        "        apply firstApplicable\n"
        "        rule readAnOrder {\n"
        f"            {read_effect}\n"
        '            target clause action == "read"\n'
        '            target clause kind == "order"\n'
        f"{needs_acr}"
        "        }\n"
        "        rule readAttributeProtected {\n"
        "            permit\n"
        '            target clause action == "read"\n'
        f'            target clause kind == "{ATTRIBUTE_PROTECTED}"\n'
        f'            target clause {TEST_ATTRIBUTE} == "{TEST_ATTRIBUTE_VALUE}"\n'
        "        }\n"
        "        rule nothingElse {\n"
        "            deny\n"
        "        }\n"
        "    }\n"
        "}\n"
    )


def usage() -> str:
    return """Usage: python scripts/configure_iya_sts.py [--config path] [--idp url] [--public-url url]
                                        [--test-user name | --no-test-user]
                                        [--pep [local|central]] [--pep-name name] [--new-sp-keys]
                                        [--dry-run]

  --config        The demo's SAML configuration (default: demo/saml.json)
  --idp           iya-sts's base URL; the realm's, e.g. https://host/realm/acme, for a trust realm
                  (default: $IYA_STS_URL or https://localhost:8081)
  --public-url    Replace the origin of the file's entityID and assertion consumer URL with this URL,
                  and keep their paths (default: unset; $PUBLIC_URL). Without it, a loopback entityID
                  and ACS follow the running demo's PORT, then $PORT. A non-loopback URL is left as written.
  --test-user     The test user to create (default: saml-demo-user). Its password is
                  $SAML_DEMO_USER_PASSWORD, or one is generated and written to
                  generated/<user>.password beside the configuration (mode 0600); only the
                  path is printed. With $SAML_DEMO_USER_PASSWORD set, an existing user's
                  password is replaced.
  --no-test-user  Do not create a test user.
  --pep [MODE]    Also set up the demo's embedded PEP in this mode, local (the default: it caches
                  the application's policies and decides in process) or central: its service
                  account, a key of its own in generated/pep-key.pem (0600), its certificate and
                  binding, the catalogue row, the demo application's own policy (enforced), and the
                  `pep` section in the configuration. Safe to run again; the mode is switched.
  --pep-name      The PEP's service account (default: pep-saml-demo).
  --new-sp-keys   Replace the SP key pair (signing and encryption) with a new one named
                  CN=saml2-sp-rust demo SP, O=saml2-sp, URI:<entityID>, and register the new
                  metadata. The old certificate's fingerprint is kept in
                  generated/retired-sp-certificates.txt so its trust anchor and stored copy are
                  taken off iya-sts.

With an ssf block (signals on), the Shared Signals receiver authenticates to iya-sts's /ssf/*
with a TLS client certificate the realm issues the application (issue-tls-client-certificate,
urn:sts:application:<entityID>): generated/ssf-client.key (0600, never printed) and
generated/ssf-client.crt, named in the configuration's ssf.clientKey / ssf.clientCertificate.
A certificate the realm still lists for the application is kept on later runs. The SP's own
certificate is no longer added to iya-sts's client-certificate truststore; an anchor an
earlier run added (and the copy stored on the application) is removed once the new
certificate is in place.
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
        pep="",
        pep_name=PEP_NAME,
        new_sp_keys=False,
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
        elif arg == "--pep":
            # The mode may be left out: then local, iya-pep's default (the
            # PEP caches the application's policies and decides in process).
            if index + 1 < len(argv) and not argv[index + 1].startswith("--"):
                out.pep = value().strip()
            else:
                out.pep = "local"
            if out.pep not in PEP_MODES:
                raise SystemExit(f"--pep must be central or local, not {out.pep}")
        elif arg == "--pep-name":
            out.pep_name = value().strip()
            if not out.pep_name:
                raise SystemExit("--pep-name is empty")
        elif arg == "--new-sp-keys":
            out.new_sp_keys = True
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


DEMO_IMAGE = "saml2-sp-rust-demo"


def _cli(args: list[str], input_text: str | None = None) -> str:
    """Runs the saml2-sp command: the one on PATH, else the demo image's
    (built with the embedded PEP, so a configuration with a `pep` section is
    read), with the checkout mounted as its working directory. Never Cargo on
    the host: that built a binary without the `pep` feature, which then
    refused the configuration this script writes."""
    binary = shutil.which("saml2-sp")
    if binary:
        command = [binary, *args]
    else:
        docker = shutil.which("docker")
        image_there = docker and subprocess.run([docker, "image", "inspect", DEMO_IMAGE], capture_output=True, check=False).returncode == 0
        if not image_there:
            raise SystemExit(f"saml2-sp is not on PATH and the demo image {DEMO_IMAGE} is not built: run `docker compose build` first.")
        root = str(repo_root())
        command = [docker, "run", "--rm", "-i", "--user", f"{os.getuid()}:{os.getgid()}", "--network", "host",
                   "-v", f"{root}:{root}", "-w", root, "--entrypoint", "saml2-sp", DEMO_IMAGE, *args]
    proc = subprocess.run(
        command,
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
        calls[-1:-1] = ssf_calls(files, base) + ssf_client_plan(files, base)
    if test_user:
        calls.append({"method": "POST", "path": f"{base}/admin-api/users/create", "why": f"create the test user {test_user}", "body": {"username": test_user}})
        calls.append({"method": "POST", "path": f"{base}/admin-api/policies/define-person-attribute",
                      "why": f"define the realm's custom attribute {TEST_ATTRIBUTE} (unless it is), with an admin:security token",
                      "body": define_attribute_body()})
        calls.append({"method": "POST", "path": f"{base}/admin-api/users/set-attribute",
                      "why": f"give {test_user} {TEST_ATTRIBUTE}={TEST_ATTRIBUTE_VALUE}",
                      "body": {"user": test_user, "attribute": TEST_ATTRIBUTE, "value": TEST_ATTRIBUTE_VALUE}})
    return calls


def define_attribute_body() -> dict:
    return {"name": TEST_ATTRIBUTE, "label": "Attribute 1", "syntax": "string", "multiValued": False,
            "description": "The demo's attribute-protected resource is permitted when this is abc123."}


def set_test_attribute(call, user: str) -> bool:
    """The realm's custom attribute attr1, and the test user's value of it, which
    GET /attribute-protected is decided on. `call(path, body, security)` answers
    {"status", "body"} and never stops the script on a refusal.

    Defining a custom attribute changes the realm's attribute policy, a Security Administrator's
    change: it needs a token carrying admin:security whose subject holds SECURITY_ADMIN. iya-sts
    seeds sts-api-client in that role, so the definition goes with a token minted for that call
    alone (`security`). Where an operator took the client out of the role, iya-sts issues the token
    without the scope and refuses the definition. That is not fatal: the value is tried anyway (the
    attribute may be defined already), and only when it is refused too does the script say what a
    Security Administrator does instead. Answers whether the test user now holds the value."""
    defined = call("/policies/define-person-attribute", define_attribute_body(), True)
    body = defined["body"] if isinstance(defined["body"], dict) else {}
    words = (" ".join(_errors_of(body)) + " " + str(body.get("error_description") or body.get("error") or "")).lower()
    not_allowed = defined["status"] in (401, 403) or "security administrator" in words or "insufficient_scope" in words
    if not not_allowed and not (defined["status"] == 200 and body.get("ok") is not False):
        if "already" not in words and "exists" not in words:
            raise SystemExit(f"defining the custom attribute {TEST_ATTRIBUTE}: refused ({defined['status']}): {json.dumps(body)[:400]}")
    answered = call("/users/set-attribute", {"user": user, "attribute": TEST_ATTRIBUTE, "value": TEST_ATTRIBUTE_VALUE}, False)
    reply = answered["body"] if isinstance(answered["body"], dict) else {}
    if answered["status"] == 200 and reply.get("ok") is not False:
        print(f"{user} has {TEST_ATTRIBUTE}={TEST_ATTRIBUTE_VALUE} (a custom attribute of the realm).")
        return True
    if not_allowed:
        # Only now does the refusal matter: the attribute is not defined, and this credential
        # cannot define it.
        print(f"The custom attribute {TEST_ATTRIBUTE} is not defined, and this credential cannot define it:")
        print("sts-api-client no longer holds SECURITY_ADMIN here (iya-sts seeds it there; an operator took it")
        print("out). Put it back on Roles, or sign in to the console as a Security Administrator")
        print("(the bootstrap administrator is), open Directory > Policies > Attribute policy > Custom")
        print(f"attributes, and add {TEST_ATTRIBUTE} (label \"Attribute 1\", syntax string, one value). Then run")
        print(f"this script again to give {user} {TEST_ATTRIBUTE}={TEST_ATTRIBUTE_VALUE}.")
    else:
        print(f"{user} does not have {TEST_ATTRIBUTE} yet: {' '.join(_errors_of(reply))[:300]}")
    return False


def ssf_calls(files: DemoFiles, base: str) -> list[dict]:
    """What lets the application manage its Shared Signals stream: the scope it declares and
    SSF_MANAGE, which authorizes it. Its TLS client certificate is the realm's
    (`issue_ssf_client_certificate`); nothing goes into the process-wide truststore."""
    return [
        {"method": "POST", "path": f"{base}/admin-api/applications/add", "why": "declare the Shared Signals write scope",
         "body": {"application": files.entity_id, "attribute": "oauthAllowedScope", "value": "ssf.manage"}},
        {"method": "POST", "path": f"{base}/admin-api/roles/add-member", "why": "hold SSF_MANAGE, which authorizes it",
         "body": {"role": "SSF_MANAGE", "kind": "application", "member": files.entity_id}},
    ]


def ssf_client_plan(files: DemoFiles, base: str) -> list[dict]:
    """--dry-run's view of the receiver's TLS client certificate and the clean-up after it."""
    return [
        {"method": "GET", "path": f"{base}/admin-api/applications?application={urllib.parse.quote(files.entity_id, safe='')}",
         "why": f"keep {SSF_CLIENT_CERT} when the realm still lists it for the application", "body": None},
        {"method": "POST", "path": f"{base}/admin-api/applications/issue-tls-client-certificate",
         "why": f"(otherwise) the realm issues the receiver its TLS client certificate: {SSF_CLIENT_KEY} (0600), {SSF_CLIENT_CERT}",
         "body": {"application": files.entity_id, "password": "<one-time>", "keyAlg": "ec-p256", "label": SSF_CLIENT_LABEL}},
        {"method": "POST", "path": f"{base}/admin-api/tls/trust/remove",
         "why": "take off the SP certificate's trust anchor an earlier run added (if held)", "body": {"fingerprint": "<the SP certificate's SHA-256>"}},
        {"method": "POST", "path": f"{base}/admin-api/applications/remove-certificate",
         "why": "and its copy stored on the application (if stored)", "body": {"application": files.entity_id, "sha256": "<the SP certificate's SHA-256>"}},
    ]


def _pem_blocks(text: str) -> list[str]:
    return re.findall(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----", text or "")


def _same_pem(a: str, b: str) -> bool:
    return re.sub(r"\s+", "", a or "") == re.sub(r"\s+", "", b or "") and bool(a)


def certificate_sha256(pem_text: str) -> str:
    """The SHA-256 of the first certificate's DER, lowercase hex: what iya-sts's truststore
    and stored-certificate removals take."""
    import hashlib
    blocks = _pem_blocks(pem_text)
    if not blocks:
        return ""
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(blocks[0])).hexdigest()


def ssf_client_paths(config_path: str) -> dict:
    """Where the receiver's own key and certificate go: the configuration's ssf.clientKey /
    ssf.clientCertificate when it names them, else generated/ssf-client.*, beside it."""
    raw = json.loads(Path(config_path).read_text(encoding="utf-8"))
    ssf = raw.get("ssf") if isinstance(raw.get("ssf"), dict) else {}
    base = Path(config_path).resolve().parent
    out = {}
    for name, member, default in (("key", "clientKey", SSF_CLIENT_KEY), ("cert", "clientCertificate", SSF_CLIENT_CERT)):
        value = ssf.get(member) if isinstance(ssf.get(member), str) and ssf.get(member) else default
        if "-----BEGIN" in value or value.startswith("env:"):
            raise SystemExit(f"{config_path}'s ssf.{member} must be a file path for this script to write")
        path = Path(_expand_path(value))
        out[name] = str(path if path.is_absolute() else (base / path).resolve())
        out[name + "_value"] = value
    return out


def held_tls_certificates(get, app: str) -> list[dict]:
    """The TLS client certificates the realm lists for the application (its page's mTLS state)."""
    page = get("/applications?application=" + urllib.parse.quote(app, safe=""))["body"]
    found = []

    def walk(value):
        if isinstance(value, dict):
            if value.get("serialHex") and value.get("certificatePem"):
                found.append(value)
            for inner in value.values():
                walk(inner)
        elif isinstance(value, list):
            for inner in value:
                walk(inner)

    walk(page)
    return found


def _decrypt_key(encrypted: str, password: str, key_path: str) -> None:
    """The one-time encrypted PKCS#8 PEM, opened with openssl into key_path (created 0600).
    The password reaches openssl through its environment, never its command line."""
    descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.close(descriptor)
    env = dict(os.environ, SAML_SSF_CLIENT_KEY_PASSWORD=password)
    done = subprocess.run(["openssl", "pkey", "-passin", "env:SAML_SSF_CLIENT_KEY_PASSWORD", "-out", key_path],
                          input=encrypted, capture_output=True, text=True, env=env, check=False)
    if done.returncode != 0:
        raise SystemExit(f"the issued key could not be opened: {done.stderr.strip()[:200]}")
    os.chmod(key_path, 0o600)


def write_ssf_client_section(config_path: str, paths: dict) -> None:
    """ssf.clientKey and ssf.clientCertificate name the receiver's files; the rest of the ssf
    block and of the file is kept."""
    path = Path(config_path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    ssf = raw.get("ssf") if isinstance(raw.get("ssf"), dict) else {}
    ssf["clientCertificate"] = paths["cert_value"]
    ssf["clientKey"] = paths["key_value"]
    raw["ssf"] = ssf
    path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")


def issue_ssf_client_certificate(api, get, files: DemoFiles, config_path: str, decrypt=_decrypt_key) -> bool:
    """The receiver's TLS client certificate for /ssf/*, issued by the realm to the application
    (the realm's tls-client Issuing CA, urn:sts:application:<entityID>, bound to the entry that
    holds SSF_MANAGE). A certificate on disk that the realm still lists, valid, for the
    application is kept; otherwise (none yet, or another iya-sts) one is issued. The key is
    written 0600 and never printed. Answers whether one was issued."""
    import secrets
    paths = ssf_client_paths(config_path)
    on_disk = Path(paths["cert"]).read_text(encoding="utf-8") if Path(paths["cert"]).exists() else ""
    leaf = (_pem_blocks(on_disk) or [""])[0]
    if leaf and Path(paths["key"]).exists():
        for held in held_tls_certificates(get, files.entity_id):
            if str(held.get("state") or "valid") == "valid" and _same_pem(held.get("certificatePem") or "", leaf):
                write_ssf_client_section(config_path, paths)
                print(f"The receiver's TLS client certificate (serial {held.get('serialHex')}) is one the realm issued to "
                      f"{files.entity_id} and still lists; kept.")
                return False
    password = secrets.token_urlsafe(24)
    answered = api("/applications/issue-tls-client-certificate", {
        "application": files.entity_id, "password": password, "keyAlg": "ec-p256", "label": SSF_CLIENT_LABEL,
    })
    body = answered["body"] if isinstance(answered["body"], dict) else {}
    if not body.get("ok"):
        shown = {k: v for k, v in body.items() if k != "files"}
        raise SystemExit(f"issuing {files.entity_id} a TLS client certificate was refused: {json.dumps(shown)[:400]}")
    encrypted = ((body.get("files") or {}).get("key") or {}).get("text") or ""
    issued = body.get("certificate") or {}
    leaf = issued.get("certificatePem") or ""
    chain = issued.get("chainPem") or []
    if not encrypted or not leaf:
        raise SystemExit("the issued certificate's answer carried no key or certificate")
    Path(paths["key"]).parent.mkdir(parents=True, exist_ok=True)
    decrypt(encrypted, password, paths["key"])
    pems = [leaf] + [pem for pem in (chain if isinstance(chain, list) else [chain]) if pem and not _same_pem(pem, leaf)]
    Path(paths["cert"]).write_text("".join(pem if pem.endswith("\n") else pem + "\n" for pem in pems), encoding="utf-8")
    write_ssf_client_section(config_path, paths)
    print(f"Issued {files.entity_id} a TLS client certificate from the realm's CA (serial {issued.get('serialHex')}, "
          f"{issued.get('implicitName') or 'urn:sts:application:' + files.entity_id}) for Shared Signals mutual TLS;")
    print(f"  wrote {paths['key']} (0600) and {paths['cert']}, named in ssf.clientKey / ssf.clientCertificate.")
    return True


def retire_sp_trust(call, files: DemoFiles, config_path: str) -> list[str]:
    """Once the receiver has its realm-issued certificate: take off iya-sts the trust anchor and
    the stored copy that earlier runs added for the SP certificate (the current one, and any
    --new-sp-keys retired). Not held is fine. Answers the fingerprints taken off."""
    retired_file = Path(config_path).resolve().parent / RETIRED_SP_CERTS
    prints = [line.strip() for line in (retired_file.read_text(encoding="utf-8").splitlines() if retired_file.exists() else []) if line.strip()]
    current = certificate_sha256(Path(files.cert).read_text(encoding="utf-8")) if Path(files.cert).exists() else ""
    if current and current not in prints:
        prints.insert(0, current)
    removed, keep = [], []
    for fingerprint in prints:
        settled = True
        for path, body, absent in (("/tls/trust/remove", {"fingerprint": fingerprint}, "holds no anchor"),
                                   ("/applications/remove-certificate", {"application": files.entity_id, "sha256": fingerprint}, "stores no certificate")):
            answer = call(path, body)
            reply = answer["body"] if isinstance(answer["body"], dict) else {}
            if answer["status"] == 200 and reply.get("ok") is not False:
                removed.append(f"{path}:{fingerprint}")
                continue
            if absent in " ".join(_errors_of(reply)).lower():
                continue
            settled = False
            print(f"  {path} for {fingerprint[:16]}…: refused ({answer['status']}): {' '.join(_errors_of(reply))[:200]}")
        if not settled and fingerprint != current:
            keep.append(fingerprint)
    if retired_file.exists() or keep:
        retired_file.write_text("".join(f"{line}\n" for line in keep), encoding="utf-8")
    for item in removed:
        what, fingerprint = item.split(":", 1)
        print(f"Removed the SP certificate {fingerprint[:16]}… from iya-sts ({'trust anchor' if 'trust' in what else 'stored on the application'}).")
    return removed


def retire_current_sp_certificate(config_path: str, cert_path: str) -> None:
    """--new-sp-keys: remember the certificate being replaced, so its anchor is taken off."""
    if not Path(cert_path).exists():
        return
    fingerprint = certificate_sha256(Path(cert_path).read_text(encoding="utf-8"))
    if not fingerprint:
        return
    retired_file = Path(config_path).resolve().parent / RETIRED_SP_CERTS
    retired_file.parent.mkdir(parents=True, exist_ok=True)
    lines = retired_file.read_text(encoding="utf-8").splitlines() if retired_file.exists() else []
    if fingerprint not in lines:
        lines.append(fingerprint)
    retired_file.write_text("".join(f"{line}\n" for line in lines), encoding="utf-8")


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


def _request(url: str, method: str, headers: dict, body: bytes | None, ca: str | None):
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    context = None
    if url.startswith("https://"):
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if ca:
            context.load_verify_locations(cadata=ca)
    try:
        with urllib.request.urlopen(request, timeout=15, context=context) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


def _json(url: str, ca: str | None, method: str = "GET", headers: dict | None = None, body: str | None = None, refuse_denied: bool = True) -> dict:
    raw_headers = dict(headers or {})
    payload = None if body is None else body.encode()
    status, data = _request(url, method, raw_headers, payload, ca)
    text = data.decode("utf-8", "replace")
    try:
        parsed = json.loads(text) if text else {}
    except json.JSONDecodeError as err:
        raise SystemExit(f"{method} {url} answered {status} with non-JSON: {text[:300]}") from err
    if refuse_denied and status in (401, 403):
        raise SystemExit(f"{method} {url} answered {status}: {json.dumps(parsed)[:300]}")
    return {"status": status, "body": parsed}


def _errors_of(body: dict) -> list[str]:
    return [str(item) for item in (body.get("errors") or [])]


def mint_admin_token(origin: str, base: str, ca: str | None, secret: str, scope: str = "admin:read admin:write") -> str:
    form = urllib.parse.urlencode({"grant_type": "client_credentials", "scope": scope, "resource": f"{base}/admin-api"})
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
        if files.idp_ca:
            print(f"# would save {origin}'s listener CA trust chain to {files.idp_ca}")
        print(f"# would write {files.sp_metadata}")
        for call in plan_for(files, base, args.test_user, xml):
            body = f"\n{json.dumps(call['body'], indent=2)}" if call.get("body") is not None else ""
            print(f"{call['method']} {call['path']}  # {call['why']}{body}")
        if args.pep:
            for line in pep_plan(files, base, args.pep_name, args.pep):
                print(line)
        return
    if args.new_sp_keys and (Path(files.key).exists() or Path(files.cert).exists()):
        retire_current_sp_certificate(args.config, files.cert)
        print(f"Replacing the SP key pair (--new-sp-keys); the old certificate's fingerprint is kept in {RETIRED_SP_CERTS}.")
        _generate_keys(args.config, files.entity_id, force=True)
    elif not Path(files.key).exists() and not Path(files.cert).exists():
        print("No key pair yet; generating one.")
        _generate_keys(args.config, files.entity_id)
    ca = None
    if files.idp_ca:
        try:
            chain = save_trust_chain(origin, files.idp_ca)
        except Exception as error:
            raise SystemExit(f"could not read {origin}'s listener CA trust chain: {error}") from error
        ca = chain["pem"]
        subject = chain["anchor"].subject.rfc4514_string().replace("\n", ", ")
        print(f"Saved {origin}'s listener CA trust chain ({chain['count']} certificate(s)) to {files.idp_ca}")
        print(f"  trust anchor {subject}")
        print(f"  sha256 {chain['fingerprint']}")
        print("  Compare the anchor with the Root CA on iya-sts's Server configuration, PKI page.")
        print("  The demo image copies this file in when it is built: rebuild it (docker compose up --build).")
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

    security_token: list[str] = []

    def call(path: str, body, security: bool = False) -> dict:
        # A change iya-sts counts as security (a Directory > Policies policy, such as the realm's
        # custom attributes) needs admin:security, held through SECURITY_ADMIN, which iya-sts seeds
        # sts-api-client in. That token is minted only when such a call is made, and used for it
        # alone; every other call carries admin:read and admin:write. A refusal is answered, not
        # raised: set_test_attribute decides what it means.
        bearer = token
        if security:
            if not security_token:
                security_token.append(mint_admin_token(origin, base, ca, secret, "admin:read admin:security"))
            bearer = security_token[0]
        return _json(f"{base}/admin-api{path}", ca, "POST", {
            "accept": "application/json", "content-type": "application/json", "authorization": f"Bearer {bearer}",
        }, json.dumps(body), refuse_denied=False)

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
        for step in ssf_calls(files, base):
            path = step["path"][len(f"{base}/admin-api"):]
            reply = api(path, step["body"])
            errors = " ".join(_errors_of(reply["body"]))
            if not reply["body"].get("ok") and not re.search(r"already", errors, re.I):
                raise SystemExit(f"{step['why']}: refused: {json.dumps(reply['body'])[:400]}")
            if not reply["body"].get("ok"):
                print(f"  {step['why']}: already so ({errors[:160]})")
        def get_page(path: str) -> dict:
            return _json(f"{base}/admin-api{path}", ca, "GET", {"accept": "application/json", "authorization": f"Bearer {token}"})
        issue_ssf_client_certificate(api, get_page, files, args.config)
        retire_sp_trust(call, files, args.config)
        print(f"Shared Signals: {files.entity_id} holds SSF_MANAGE and authenticates to /ssf/* by mutual TLS with the "
              "TLS client certificate the realm issued it (ssf.clientCertificate), not the SAML key pair.")
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
                # Never printed: a password does not belong in a log. It goes to a
                # file only its owner can read, created 0600, in demo/generated,
                # which never enters an image (.dockerignore admits only idpCa's chain).
                saved = Path(args.config).resolve().parent / "generated" / f"{args.test_user}.password"
                saved.parent.mkdir(parents=True, exist_ok=True)
                descriptor = os.open(saved, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as out:
                    os.fchmod(out.fileno(), 0o600)
                    out.write(f"{made['body']['password']}\n")
                print(f"Generated a password for {args.test_user}; it is in {saved} (readable by you only).")
        set_test_attribute(call, args.test_user)
    if args.pep:
        def get(path: str) -> dict:
            return _json(f"{base}/admin-api{path}", ca, "GET", {"accept": "application/json", "authorization": f"Bearer {token}"})
        setup_pep(api, get, files, args.config, args.pep_name, args.pep)
        print(f"pep: {args.pep_name}, {args.pep} (GET /orders/42 and GET /{ATTRIBUTE_PROTECTED} need a sign-in; any other method is denied)")
    print("Done. Start the demo with: docker compose up --build")


def pep_plan(files: DemoFiles, base: str, name: str, mode: str) -> list[str]:
    """What --pep does, for --dry-run. No key is made and nothing is sent."""
    app = files.entity_id
    return [
        f"GET  {base}/admin-api/users?user={name}  # the PEP's service account: created only if unknown",
        f"POST {base}/admin-api/users/create  # {name}: a service account owned by admin-write, no credential",
        f"POST {base}/admin-api/groups/add-member  # {name} in {PEP_GROUP}",
        f"# make a P-256 key at {PEP_KEY} beside the configuration (0600), unless one is there",
        f"POST {base}/admin-api/xacml/issue-pep-credential  # its certificate request, bound to {app} (a new key or account)",
        f"POST {base}/admin-api/xacml/set-pep-application  # or, with both kept, bind {name} to {app} again",
        f"POST {base}/admin-api/xacml/authzen/set-attribute  # subject.acr -> {ACR_ATTRIBUTE}",
        f"POST {base}/admin-api/applications/fga-create-policy  # {app}'s own policy, unless it has one",
        f"POST {base}/admin-api/xacml/import-alfa  # the demo policy into it (when {app} enforces none yet, or this script's own)",
        f"POST {base}/admin-api/applications/fga-enable  # {app} enforces its own policy (the realm root is untouched)",
        f"POST {base}/admin-api/applications/add  # {PEP_EVENT} in ssfAllowedEvents, only if {app} restricts them",
        f"# write \"pep\": {{\"name\": \"{name}\", \"mode\": \"{mode}\", \"assertionKey\": \"{PEP_KEY}\"}} into the configuration",
    ]


def make_pep_key(key_file: Path) -> None:
    """A P-256 key made with openssl, created 0600. Neither the key nor anything read from it is
    printed; only its certificate request (pep_csr) leaves this machine."""
    key_file.parent.mkdir(parents=True, exist_ok=True)
    old = os.umask(0o077)
    try:
        made = subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(key_file)],
                              check=False, capture_output=True, text=True)
    finally:
        os.umask(old)
    if made.returncode != 0:
        raise SystemExit("openssl could not make the PEP's key (is openssl installed?)")
    os.chmod(key_file, 0o600)


def pep_csr(key_file: Path, name: str) -> str:
    """The certificate request for the PEP's key."""
    made = subprocess.run(["openssl", "req", "-new", "-key", str(key_file), "-subj", f"/CN={name}"],
                          check=False, capture_output=True, text=True)
    if made.returncode != 0 or "BEGIN CERTIFICATE REQUEST" not in made.stdout:
        raise SystemExit("openssl could not make the PEP's certificate request from its key")
    return made.stdout


def _ok(answer: dict, what: str, allow: str = "") -> bool:
    """True for an /admin-api act that worked, False for one refused only because it is already so
    (`allow`, found in the refusal's words); anything else stops the script."""
    body = answer["body"] if isinstance(answer["body"], dict) else {}
    if answer["status"] == 200 and body.get("ok") is not False:
        return True
    words = (" ".join(_errors_of(body)) + " " + str(body.get("why") or "")).lower()
    if allow and allow in words:
        return False
    raise SystemExit(f"{what}: refused ({answer['status']}): {json.dumps(body)[:400]}")


def write_pep_section(config_path: str, name: str, mode: str) -> None:
    """The configuration's `pep` section gets the name, the mode and the key; any other member
    already in it is kept, and so is the rest of the file."""
    path = Path(config_path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    section = raw.get("pep") if isinstance(raw.get("pep"), dict) else {}
    section.update({"name": name, "mode": mode, "assertionKey": PEP_KEY})
    raw["pep"] = section
    path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")


def own_policy(api, get, app: str) -> dict:
    """Step 5, and the application's page after it."""
    # Step 5: the application's own policy. Written while it enforces none, and rewritten with the
    # current version while it enforces this script's own (a PolicyId in OWN_POLICY_IDS), so a new
    # rule reaches an existing install; a policy under any other PolicyId is an administrator's and
    # is left alone. The realm root is never set.
    page_path = f"/applications?application={urllib.parse.quote(app, safe='')}"
    page = get(page_path)["body"].get("page") or {}
    fga = page.get("fga") or {}
    current_id = (fga.get("policy") or {}).get("policyId") or ""
    if fga.get("enforced") is True and current_id not in OWN_POLICY_IDS:
        print(f"{app} already enforces a policy of its own ({current_id or 'unnamed'}); it is left as it is.")
    elif fga.get("enforced") is True:
        policy = (fga.get("policy") or {}).get("name") or fga.get("reference")
        _ok(api("/xacml/import-alfa", {"name": policy, "alfa": orders_policy()}), f"writing {policy}")
        print(f"{app} enforces this script's policy {policy}; it now holds the current version.")
    else:
        _ok(api("/applications/fga-create-policy", {"application": app}), f"{app}'s own policy", allow="already")
        page = get(page_path)["body"].get("page") or {}
        fga = page.get("fga") or {}
        policy = (fga.get("policy") or {}).get("name") or fga.get("reference")
        if not policy:
            raise SystemExit(f"{app}'s page names no policy of its own: {json.dumps(fga)[:300]}")
        _ok(api("/xacml/import-alfa", {"name": policy, "alfa": orders_policy()}), f"writing {policy}")
        _ok(api("/applications/fga-enable", {"application": app}), f"enforcing {app}'s own policy")
        print(f"{app} now enforces its own policy {policy}: read on an order needs an AuthnContextClassRef; "
              f"read on {ATTRIBUTE_PROTECTED} needs {TEST_ATTRIBUTE}={TEST_ATTRIBUTE_VALUE}; anything else is denied.")
    return page


def setup_pep(api, get, files: DemoFiles, config_path: str, name: str, mode: str) -> None:
    """docs/remote-pep.md's steps 2 to 6 for the demo. Safe to run again."""
    app = files.entity_id
    # Step 2: the service account, in remote-peps.
    made_account = get(f"/users?user={urllib.parse.quote(name)}")["body"].get("known") is not True
    if made_account:
        _ok(api("/users/create", {"username": name, "invent": False, "credential": "none", "serviceAccount": True,
                                  "owners": ["admin-write"], "attributes": {"cn": name, "displayName": name}}),
            f"creating the service account {name}")
        print(f"Created the PEP's service account {name}.")
    else:
        print(f"The PEP's service account {name} already exists.")
    _ok(api("/groups/add-member", {"group": PEP_GROUP, "member": name}), f"adding {name} to {PEP_GROUP}")
    # Step 3: the key, certified from its own request, and the binding.
    key_file = Path(config_path).resolve().parent / PEP_KEY
    made_key = not key_file.exists()
    if made_key:
        make_pep_key(key_file)
        print(f"Generated the PEP's P-256 key in {key_file} (readable by you only).")
    if made_key or made_account:
        _ok(api("/xacml/issue-pep-credential", {"name": name, "csr": pep_csr(key_file, name), "application": app}),
            "certifying the PEP's key")
        print(f"Certified the PEP's key and bound {name} to {app}.")
    else:
        _ok(api("/xacml/set-pep-application", {"name": name, "application": app}), f"binding {name} to {app}")
        print(f"Kept the PEP's key; {name} is bound to {app}.")
    # Step 4: the claim the policy reads.
    _ok(api("/xacml/authzen/set-attribute", {"object": "subject", "property": "acr", "attributeId": ACR_ATTRIBUTE}),
        "the catalogue row subject.acr")
    page = own_policy(api, get, app)
    # Step 6: only an application that restricts its streams needs the event named.
    allowed = (page.get("attributes") or {}).get("ssfAllowedEvents") or []
    if isinstance(allowed, str):
        allowed = [allowed]
    if allowed and PEP_EVENT not in allowed:
        _ok(api("/applications/add", {"application": app, "attribute": "ssfAllowedEvents", "value": PEP_EVENT}),
            "letting pep-policies-changed through ssfAllowedEvents", allow="already")
        print(f"Added {PEP_EVENT} to {app}'s ssfAllowedEvents.")
    write_pep_section(config_path, name, mode)
    print(f"Wrote a {mode} pep section into {config_path}.")


def _generate_keys(config_path: str, entity_id: str = "", force: bool = False) -> None:
    args = ["generate-keys", "--config", config_path, "--cn", SP_CERT_CN]
    if entity_id:
        args += ["--entity-id", entity_id]
    if force:
        args.append("--force")
    print(_cli(args), end="")


if __name__ == "__main__":
    try:
        main()
    except SystemExit as err:
        if err.code not in (None, 0):
            sys.stderr.write(f"{err.code if isinstance(err.code, str) else err}\n")
            raise SystemExit(1) from None
        raise
