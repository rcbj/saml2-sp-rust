# saml2-sp

Server-side SAML 2.0 service provider for Rust. It sends a signed `AuthnRequest` on HTTP-Redirect or HTTP-POST, accepts a `Response` on HTTP-POST, HTTP-Redirect, or HTTP-Artifact, verifies XML signatures, decrypts encrypted assertions, and can poll a Shared Signals transmitter for CAEP and RISC events.

License: MIT. `develop` and `main` are one commit. A pull request merged into `main` publishes the crate to crates.io after the test workflow succeeds on that commit. A direct push does not. The token is the `CARGO_REGISTRY_TOKEN` repository secret. A release happens when the library's files changed since the last release's tag: `publish.yml` takes one patch above the highest published version, publishes it, and creates the matching tag and GitHub Release. A change to tests, the demo, or the docs releases nothing. To choose a version or start a new minor, raise `VERSION`; the version is stamped in CI and is not committed, so the manifests can trail what is published.

## Usage

```rust
let sp = saml2_sp::ServiceProvider::from_file("saml.json", None, None)?;
let request = sp.login(&saml2_sp::LoginOptions { relay_state: Some("/home".into()), ..Default::default() })?;
let who = sp.acs(method, raw_url, &saml2_sp::AcsBody::Text(body), &[request.id])?;
```

The crate is `saml2-sp`. `saml.json` uses the same keys as the Python service provider: `entityId`, `acsUrl`, `privateKey`, `certificate`, `idpMetadata`, and the optional `requestBinding`, `responseBinding`, `idpCa`, `idpEntityId`, `nameIdFormat`, `clockSkewSeconds`, `wantAssertionsSigned`, `wantAssertionsEncrypted`, `allowUnsolicited`, `signals`, and (with the `pep` feature) `pep`. A value may be PEM text, a file path, or an `env:` / `file:` placeholder. `signals` omitted or `true` leaves the Shared Signals receiver available and is omitted from the resolved configuration. `false` turns it off, does not require transmitter metadata, and is stored as `signals: false`. Any other value is a configuration error: `signals must be true or false`. SAML does not send OAuth scopes, so the flag does not change the `AuthnRequest`.

`login` returns a redirect URL or `post_form_html` fields. `acs` accepts a POST body as text or a list of fields. Artifact resolution is a signed SOAP `ArtifactResolve`. HTTP-Redirect query signatures use RSA-SHA256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`). Success is `urn:oasis:names:tc:SAML:2.0:status:Success`.

```sh
docker compose build
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  saml2-sp-rust-demo \
  saml2-sp generate-keys --config demo/saml.json
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/demo:/app/demo" \
  saml2-sp-rust-demo \
  saml2-sp metadata --config demo/saml.json
```

## Shared Signals

```rust
let receiver = saml2_sp::SignalsReceiver::new(saml2_sp::ReceiverOptions {
    transmitter: "https://idp.example".into(),
    on_end_sessions: Some(std::sync::Arc::new(|_ids, _event| Ok(()))),
    ..Default::default()
})?;
receiver.track(local_id, &login, None);
receiver.start()?;
receiver.stop();
```

The receiver discovers the transmitter, keeps one poll stream (`urn:ietf:rfc:8936`), and verifies each Security Event Token against the published JWKS. `stop` waits until a poll already running has finished. By default a session ends on `session-revoked`, `account-disabled`, `account-purged`, `credential-compromise`, and `sessions-revoked`.

**Subjects (SSF 1.0 Add Subject / Remove Subject).** A transmitter may send a stream only events about the subjects it was told of (`default_subjects` NONE), and iya-sts sends an application's stream only events about people with an active session at that application (iya-sts#2234). So `track` (every sign-in) queues an Add Subject for each identifier events are matched on: `{"format": "iss_sub", "iss": <the transmitter's issuer>, "sub": <the subject attribute>}` and `{"format": "email", ...}` (with `verified: true`). Ending a local session (`untrack` at sign-out or single logout, or a CAEP/RISC event that ends it) queues Remove Subject for each identifier no other local session still holds, so the last session for a person removes them. The calls go to the metadata's `add_subject_endpoint` / `remove_subject_endpoint`, with the stream's TLS client certificate and headers, from the receiver's own poll thread just before each poll (no new timer; sign-in never waits on the transmitter; before `start` they wait for the first poll). Each is sent once: a refusal is reported and never retried (a 403 is expected when the transmitter knows no active session for the person yet, a race; it goes to the logger at `warn`, any other failure at `error`, and the latest to `SignalsReceiver::subject_error()`). Nothing is sent when the metadata has no such endpoint, with `ReceiverOptions::add_subjects` false (`"ssf": {"addSubjects": false}` in a configuration file, read by `ssf_add_subjects()`; default true, a non-boolean is a configuration error), or with signals off (no receiver). A session that only expires sends no Remove Subject. The demo tracks every sign-in (`remember_sign_in`) and untracks it at Sign out; it has no SAML single logout endpoint.

## Embedded PEP (features `pep` and `local`)

Ask iya-sts's authorization policy whether a signed-in person may act on a resource, through the embedded Remote PEP (the shared [`iya-pep`](https://github.com/rcbj/iya-pep-rust) crate; iya-sts [#1206](https://github.com/rcbj/iya-sts/issues/1206)). **[docs/remote-pep.md](docs/remote-pep.md) is the full guide**: setting up iya-sts, choosing `central` or `local`, every configuration member, obligations, policy-change events, operating it and troubleshooting.

```toml
saml2-sp = { version = "…", features = ["pep"] }    # central: AuthZEN at iya-sts
saml2-sp = { version = "…", features = ["local"] }  # local too: decided in process
```

```json
"pep": { "name": "pep-orders", "mode": "local", "assertionKey": "pep-key.pem" }
```

```rust
let decision = sp.decide_session(&receiver.session_index(), &local_id, &login, &Access::new("read", "order", "42"));
let status = decision.http_status(); // 200 for a Permit, 403 for anything else
match decision {
    Decision::Permit { obligations, .. } => { /* discharge them, then serve */ }
    Decision::Deny { .. } => { /* 403 */ }
    Decision::Unavailable { .. } => { /* 403: fail closed, never a Permit */ }
}
```

The section is off unless present, and a build without the feature refuses it. A section that names no `mode` is `local`; a build with `pep` alone must name `"mode": "central"`. The PEP's key must be its own, and only the claims the realm's AuthZEN catalogue declares are sent. The subject's id is the username from the assertion's attributes (`SamlLogin::username()`), else the NameID. Every PEP failure is a 403: a panic while deciding is `Unavailable`, `http_status()` is 403 for it as for a Deny, and in `central` mode a failed evaluation or heartbeat empties the Permit cache. The receiver, given the PEP (`ReceiverOptions::pep`), asks its stream for `pep-policies-changed` and tells the PEP whether the stream is up, so a `local` PEP polls while it cannot hear. The demo protects `GET /orders/<id>` and `GET /attribute-protected` with the PEP.

## The demo with its embedded PEP

With iya-sts running (one with #2026–#2028, the embedded-PEP support), one run of the install script registers the demo and sets up its PEP, then the demo starts with it:

```sh
docker compose build
docker run --rm --network host --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD/demo:/app/demo" -e ADMIN_API_CLIENT_SECRET -e IYA_STS_URL \
  saml2-sp-rust-demo python3 scripts/configure_iya_sts.py --pep local
docker compose up --build
```

`--pep local` (or a bare `--pep`: local is the default) or `--pep central` picks the mode, and running it again switches it, keeping the PEP's account, its key (`demo/generated/pep-key.pem`, 0600, never in the image) and the demo application's own policy. It never changes the realm's root policy. Sign in, then `GET /orders/42` is allowed and any other method is denied. `GET /attribute-protected` is allowed when your directory attribute `attr1` is `abc123`: the install script gives the test user that value (defining the realm's custom attribute `attr1` with an `admin:security` token) and the application's own policy a rule for it, and the PEP asks iya-sts's PIP for the value, which the assertion does not carry. Every PEP failure is a 403, as a Deny is. The signed-in page has three tabs, and every block of text on them is a collapsible pane (a **Collapse all** / **Expand all** toggle on each tab opens or closes them together): **Session** (`/`): the protections in effect, the sign-in (NameID, issuer, AuthnInstant, AuthnContextClassRef, SessionNotOnOrAfter and every attribute of the assertion), the demo's session cache, and the credentials (the assertion's ID, binding, encryption and signature; the session cookie and the SessionIndex by a SHA-256 fingerprint, never their values; the assertion's XML is not kept); **CAEP & RISC events** (`/?tab=events`): every event the service provider's stream delivered, for every user (a demonstration only: a real application shows a person only their own), live from `GET /api/signals`, and a button that asks the transmitter for a verification event (`POST /signals/verify`); **Policy enforcement** (`/?tab=pep`): the embedded PEP's `status()` as four panes (Decisions, Cached policy, The PEP, Control plane), redrawn every 2 s by `demo/public/pep.js` from `GET /pep-status.html`, which keeps a pane you closed closed, and a **Try it** pane linking the two pages the PEP decides; `GET /pep-status` is the same as JSON. All of these need a sign-in and carry nothing secret. The top bar links **Demo home**, **Attribute-protected** and **Order 42**, and a user menu at its right names the person (the username from the assertion's attributes, the NameID only when there is none) and holds **Sign in with another account** (ForceAuthn) and **Sign out**. [docs/remote-pep.md](docs/remote-pep.md#the-demo) lists what it does.

## Tests

```bash
docker build --target test .
```

The suite runs in a container: `cargo test`, then `cargo test --all-features` (the embedded PEP). It includes the demo's own tests (`src/bin/demo.rs`) and the install script's (`src/configure_test.rs`, which runs the script's functions with fakes under `python3`).

**AuthZEN cases (the embedded PEP).** `src/authzen/cases.json` is this library's own table: catalogue rows, policies (`src/authzen/*.alfa`, given to iya-sts, and `*.xml`, what iya-sts stored for them), a directory person, and 45 cases, each a `SamlLogin`, an `Access` and the answer the host must see (Permit with its obligations, Deny or Unavailable). `src/authzen_test.rs` runs them in the suite through a `local` ServiceProvider against a stub PDP. `IYA_STS_IMAGE=<image> python3 scripts/live_authzen.py` runs them live: it registers this SP on a fresh iya-sts, provisions a `central` and a `local` PEP (each its own key, bound to the SP), the rows and the policies, and requires every case to answer the same in both modes and as the table says. On 2026-11-24 all 45 answered the same in both modes and as the table says (see [docs/remote-pep.md](docs/remote-pep.md#testing-central-against-local)).

**The demo's protected pages.** `src/bin/demo.rs`'s `protected_pages` tests (feature `local`) send requests through the demo's own router (`route()`) to `GET /attribute-protected` and `/orders/42`, decided by a `local` PEP that holds the demo application's own policy: `src/authzen/demo-orders.xml`, the XACML iya-sts stores for the install script's `orders_policy()` ALFA (the live `--pep` run checks it still is, and `--write-xml` rewrites it from iya-sts). A stub iya-sts in the test serves the PEP's token, registration, catalogue (the `subject.acr` row), the policy pull and the PIP, which answers `attr1` per person (the assertion never carries it). They check: a person with `attr1=abc123` and an AuthnContextClassRef gets 200 on both pages, and `attr1` came from the PIP; `attr1=not-abc123`, and no `attr1` at all, get 403 on `/attribute-protected` (and 200 on `/orders/42`); `POST` (and `DELETE`) `/orders/42` is 403; a sign-in without an AuthnContextClassRef gets 403 on `/orders/42`; signed out (or after Sign out) is 401 on both; a PEP that holds no policy (the pull fails) is 403 on both with "No decision". Every status is compared with the decision's `http_status()` as well as the expected number, and each page's text is checked. The App now holds its service provider (`App::sp`, built on first use as before) instead of a process-wide static, so a test can hand it one.

Signatures and decryption are real (RSA, exclusive XML canonicalization). The stub identity provider is in the test files. No live iya-sts. Keys are generated in the test.

`python3 scripts/live_iya_sts.py` is the live half. It builds this demo image, starts the latest main branch of iya-sts in memory mode with persistence and clustering off when `IYA_STS_URL` is unset (`IYA_STS_IMAGE` uses an image already built), copies the checkout (without `demo/generated`) to a scratch build context, runs `scripts/configure_iya_sts.py` inside the demo image there (which writes the trust chain where `idpCa` names it), builds the demo image again so it carries that chain, checks the image's copy matches, runs the demo with only the key pair and the IdP metadata mounted, signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. It needs only Docker and the host's standard-library `python3`; Cargo never runs on the host. No script prints a password or secret, or a URL (trace lines carry fixed labels). Secrets reach `docker run` as `-e NAME`, the value in the child's environment. A generated test-user password goes to `demo/generated/<user>.password` (created 0600) and only that path is printed. Every `ssl` context in `scripts/` sets TLS 1.2 as the minimum. Its ports are 18518 (iya-sts) and 18618 (the demo), replaced by `LIVE_STS_PORT` and `LIVE_DEMO_PORT`; it never binds 3000, 8081, or 18481 to 18495. With `--pep` (`IYA_STS_IMAGE` with #2026–#2028) it also sets up the embedded PEP through the install script and, in both modes, checks `GET /orders/42` 200 and `POST` 403 and `GET /attribute-protected` 200 for the test user (`attr1=abc123`) and 403 for a second user, `saml-demo-denied`, whom it creates after the install script defines `attr1` and gives `attr1=not-abc123` (`/admin-api/users/set-attribute`); that user signs in with a client of their own, also reads `/orders/42` (200), and signs out. The result JSON carries both statuses under `pep.<mode>.attributeProtected`. On 2026-11-25 against `iya-sts:local` (iya-sts feature/2028) every check passed, the policy flip took 1.1 s by event, and `demo-orders.xml` matched what iya-sts stored. The nightly workflow (`.github/workflows/nightly.yml`, 07:10 UTC) runs the unit suite and `live_iya_sts.py` once every 24 hours. Push CI stays the unit suite.

**A real browser.** `IYA_STS_IMAGE=<image> python3 scripts/live_ui.py` provisions the same way (a fresh iya-sts `iya-sts-ui-saml2-sp-rust` on 18519, the demo `saml2-sp-rust-ui-demo` on 18619, `LIVE_UI_STS_PORT` / `LIVE_UI_DEMO_PORT`; the install script with `--pep local`; both users), then runs `scripts/ui_browser.py` in Playwright's official image (`mcr.microsoft.com/playwright/python:v1.49.0-noble`, `PLAYWRIGHT_IMAGE`, with the `playwright` package added in a derived image built once; nothing is installed on the host) on the host network. Headless Chromium opens the demo, clicks Sign in, follows the SAML redirect to iya-sts's sign-in page, types the username and password and presses Sign in, returns through the POST binding (the ACS answers 303), and opens `/attribute-protected` and `/orders/42` by address and by the top bar's links, checking each page response's status and visible text: 200 and 200. It signs out from the user menu (then `/attribute-protected` is 401), clicks Sign in again, is signed straight back in by iya-sts's lingering session, so uses **Sign in with another account** (ForceAuthn) and signs in as `saml-demo-denied`: `/attribute-protected` 403, `GET /orders/42` 200, and `POST /orders/42` 403 both by `page.request` with the browser's cookies and by `fetch()` from the page. Playwright's request sender leaves out a Secure cookie on plain http, which the browser itself sends on loopback, so `page.request` is given the browser's cookies for the demo's host explicitly. Screenshots go to `LIVE_UI_OUT` (else a new scratch directory), never into the checkout; the JSON summary is printed last and any mismatch exits 1. The browser does not verify the throwaway iya-sts's certificate (the demo does, with the saved chain). On 2026-11-25 against `iya-sts:local`: 16 of 16 checks passed.

## Demo

`docker compose up --build`. `GET /healthz` is `200` with body `ok` and does not dial an identity provider. Pages: sign-in, `/login` (redirect or POST form), `/saml/acs`, and logout. `GET /live-status` is JSON: `signedIn` (true when any local session exists), `subject` (the person's username, as the page names them), the receiver state, and the Shared Signals events this process has accepted (`type` and `jti` only). No assertions. If the assertion SessionIndex is not the CAEP session id, the event handler ends this demo's one session and says so, so `session-revoked` leaves `signedIn` false. Loopback entityID and assertion-consumer URLs follow `PORT` (default 3000). Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL. `demo/saml.json` uses `file:` placeholders and omits `signals`. Do not commit `demo/generated/`.

`scripts/configure_iya_sts.py` is standard-library Python. It calls the `saml2-sp` binary on `PATH` (the demo image has one) for keys, metadata, and the identity-provider summary, and falls back to `cargo run --bin saml2-sp`. In the image: `docker run --rm --network host -v "$PWD/demo:/app/demo" -e ADMIN_API_CLIENT_SECRET -e IYA_STS_URL saml2-sp-rust-demo python3 scripts/configure_iya_sts.py`. The container `PORT` wins over the shell `PORT`.

## iya-sts trust chain (`idpCa`)

`idpCa` names iya-sts's TLS listener CA trust chain; in `demo/saml.json` it is `file:generated/idp-ca.pem` (relative to `demo/`). The library adds every certificate in that file to its trust store, so a whole chain works and OpenSSL ends the path at the self-signed Root. The library reads it for the metadata fetch, artifact resolution, and the Shared Signals receiver.

`scripts/configure_iya_sts.py` writes it on every run: the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain the TLS handshake presents when that endpoint is missing. It prints the path, the trust anchor's subject, and its SHA-256; compare the anchor with the Root CA on iya-sts's Server configuration, PKI page. The fetch itself is not verified (trust on first use).

**Plain http.** Identity-provider metadata from a URL, artifact resolution and every Shared Signals transmitter call use https. A plain `http://` URL is refused before any connection unless its host is loopback (`127.0.0.0/8`, `::1`, `localhost`), because metadata carries the signing keys, an `ArtifactResolve` returns the assertion, and Shared Signals carry SETs and the bearer token. A redirect gets the same check. A URL with userinfo is never loopback, and a URL (or redirect target) holding whitespace or a control character is refused outright, so no two parsers can disagree about its host. The `SamlError` keeps the fetch's code (`metadata`, `artifact`, `ssf`) and its message names the scheme and host only. There is no opt-out, as in saml2-sp-nodejs, saml2-sp-go, saml2-sp-c and saml2-sp-java. The SP's own entityID and ACS URL may stay http: they are never fetched.

The demo image build copies that file in: `.dockerignore` admits only `demo/generated/idp-ca.pem` from `demo/generated/` (keys and metadata stay out), and `COPY demo demo` puts it at `/app/demo/generated/idp-ca.pem`, where `idpCa` names it. A build with no chain file yet (a fresh clone, CI) still succeeds and carries none. Run the install script, then build the image; after running it against a different iya-sts, rebuild (`docker compose up --build`). Compose also mounts `demo/generated`, which holds the same file.
