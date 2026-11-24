# saml2-sp

Server-side SAML 2.0 service provider for Rust. It sends a signed `AuthnRequest` on HTTP-Redirect or HTTP-POST, accepts a `Response` on HTTP-POST, HTTP-Redirect, or HTTP-Artifact, verifies XML signatures, decrypts encrypted assertions, and can poll a Shared Signals transmitter for CAEP and RISC events.

License: MIT. `develop` and `main` are one commit. A pull request merged into `main` publishes the crate to crates.io after the test workflow succeeds on that commit. A direct push does not. The token is the `CARGO_REGISTRY_TOKEN` repository secret. A release happens when the library's files changed since the last release's tag: `publish.yml` takes one patch above the highest published version, publishes it, and creates the matching tag and GitHub Release. A change to tests, the demo, or the docs releases nothing. To choose a version or start a new minor, raise `VERSION`; the version is stamped in CI and is not committed, so the manifests can trail what is published.

## Usage

```rust
let sp = saml2_sp::ServiceProvider::from_file("saml.json", None, None)?;
let request = sp.login(&saml2_sp::LoginOptions { relay_state: Some("/home".into()), ..Default::default() })?;
let who = sp.acs(method, raw_url, &saml2_sp::AcsBody::Text(body), &[request.id])?;
```

The crate is `saml2-sp`. `saml.json` uses the same keys as the Python service provider: `entityId`, `acsUrl`, `privateKey`, `certificate`, `idpMetadata`, and the optional `requestBinding`, `responseBinding`, `idpCa`, `idpEntityId`, `nameIdFormat`, `clockSkewSeconds`, `wantAssertionsSigned`, `wantAssertionsEncrypted`, `allowUnsolicited`, and `signals`. A value may be PEM text, a file path, or an `env:` / `file:` placeholder. `signals` omitted or `true` leaves the Shared Signals receiver available and is omitted from the resolved configuration. `false` turns it off, does not require transmitter metadata, and is stored as `signals: false`. Any other value is a configuration error: `signals must be true or false`. SAML does not send OAuth scopes, so the flag does not change the `AuthnRequest`.

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

## Embedded PEP (features `pep` and `local`)

The [iya-pep](https://github.com/rcbj/iya-pep-rust) crate, wired in (iya-sts [#1206](https://github.com/rcbj/iya-sts/issues/1206)): an application asks iya-sts's policy whether a signed-in person may act on a resource.

```toml
saml2-sp = { version = "…", features = ["pep"] }    # central: AuthZEN at iya-sts
saml2-sp = { version = "…", features = ["local"] }  # local too: decided in process
```

Add a `pep` section to the configuration. It is off unless present, and a build without the `pep` feature refuses it rather than ignoring it:

```json
"pep": { "name": "pep-orders", "mode": "local", "assertionKey": "generated/pep-key.pem" }
```

- **Defaults from this library:**
  - `pdpUrl` is the identity provider's entityID. iya-sts's SAML entityID is the realm's issuer, so this is the service's URL with the realm prefix. Name `pdpUrl` for an identity provider whose entityID is not iya-sts's URL.
  - `application` is `entityId`, the identifier iya-sts registers this service provider under.
  - `tlsCa` is `idpCa`.
  - `signals` is on when this library's receiver runs: an `ssf` block, and `signals` not `false`.
  - A relative `assertionKey` is read from the configuration's directory, like `privateKey`.
  - iya-pep's README lists every member.
- **The PEP's key is its own.** `ServiceProvider::create` refuses a configuration where the assertion key is `privateKey` (the key that signs requests, decrypts assertions and authenticates the receiver), compared by JWK thumbprint. Certify the key and bind the PEP to the application with iya-sts's `issue-pep-credential`.
- **Deciding:**
  - `sp.decide(&login, &Access::new("read", "order", "42"))` for a validated `SamlLogin`, or `sp.decide_session(&receiver.session_index(), local_id, &login, …)`. A session that is no longer tracked (signed out, expired, or ended by CAEP `session-revoked` or another ending event) is a Deny, and nothing is asked.
  - The subject's id is the username: the first of `urn:oid:0.9.2342.19200300.100.1.1`, `uid` and `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name` the assertion carries (iya-sts sends all three), else the NameID. A transient NameID names nobody the PIP can resolve. The properties are the attributes (by Name, and by FriendlyName), `AuthnContextClassRef` as `acr`, an `amr` attribute as `amr`, and `AuthnInstant` as `auth_time` in epoch seconds. Only the claims the realm's AuthZEN catalogue declares are sent. No request header is read.
  - The answer is `Permit { obligations, advice }`, `Deny` or `Unavailable`. `Unavailable` means no policy is held yet, the service can't be reached, or there is no `pep` section. It is never a Permit.
- **Signals.** A `SignalsReceiver` given the PEP (`ReceiverOptions { pep: sp.pep().cloned(), .. }`) asks its stream for `urn:iya:sts:secevent:event-type:pep-policies-changed`: always in `local` mode, and in `central` when `permitCacheMs` is set. It verifies the SET like any other and hands the event to the PEP, which pulls with its own token. Without a receiver, a `local` PEP polls at `pollIntervalMs`.
- **The demo** protects `GET /orders/<id>` with the PEP when the image is built with `local` (the Dockerfile does) and `demo/saml.json` has a `pep` section.

## Tests

```bash
docker build --target test .
```

The suite runs in a container.

Signatures and decryption are real (RSA, exclusive XML canonicalization). The stub identity provider is in the test files. No live iya-sts. Keys are generated in the test.

`python3 scripts/live_iya_sts.py` is the live half. It builds this demo image, starts the latest main branch of iya-sts in memory mode with persistence and clustering off when `IYA_STS_URL` is unset (`IYA_STS_IMAGE` uses an image already built), copies the checkout (without `demo/generated`) to a scratch build context, runs `scripts/configure_iya_sts.py` inside the demo image there (which writes the trust chain where `idpCa` names it), builds the demo image again so it carries that chain, checks the image's copy matches, runs the demo with only the key pair and the IdP metadata mounted, signs in, and requires a credential-change event and a session-revoked event on `GET /live-status`. The second event ends the local session. It needs only Docker and the host's standard-library `python3`; Cargo never runs on the host. No script prints a password or secret, or a URL (trace lines carry fixed labels). Secrets reach `docker run` as `-e NAME`, the value in the child's environment. A generated test-user password goes to `demo/generated/<user>.password` (created 0600) and only that path is printed. Every `ssl` context in `scripts/` sets TLS 1.2 as the minimum. Its ports are 18518 (iya-sts) and 18618 (the demo), replaced by `LIVE_STS_PORT` and `LIVE_DEMO_PORT`; it never binds 3000, 8081, or 18481 to 18495. The nightly workflow (`.github/workflows/nightly.yml`, 07:10 UTC) runs the unit suite and this script once every 24 hours. Push CI stays the unit suite.

## Demo

`docker compose up --build`. `GET /healthz` is `200` with body `ok` and does not dial an identity provider. Pages: sign-in, `/login` (redirect or POST form), `/saml/acs`, and logout. `GET /live-status` is JSON: `signedIn` (true when any local session exists), `subject`, the receiver state, and the Shared Signals events this process has accepted (`type` and `jti` only). No assertions. If the assertion SessionIndex is not the CAEP session id, the event handler ends this demo's one session and says so, so `session-revoked` leaves `signedIn` false. Loopback entityID and assertion-consumer URLs follow `PORT` (default 3000). Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL. `demo/saml.json` uses `file:` placeholders and omits `signals`. Do not commit `demo/generated/`.

`scripts/configure_iya_sts.py` is standard-library Python. It calls the `saml2-sp` binary on `PATH` (the demo image has one) for keys, metadata, and the identity-provider summary, and falls back to `cargo run --bin saml2-sp`. In the image: `docker run --rm --network host -v "$PWD/demo:/app/demo" -e ADMIN_API_CLIENT_SECRET -e IYA_STS_URL saml2-sp-rust-demo python3 scripts/configure_iya_sts.py`. The container `PORT` wins over the shell `PORT`.

## iya-sts trust chain (`idpCa`)

`idpCa` names iya-sts's TLS listener CA trust chain; in `demo/saml.json` it is `file:generated/idp-ca.pem` (relative to `demo/`). The library adds every certificate in that file to its trust store, so a whole chain works and OpenSSL ends the path at the self-signed Root. The library reads it for the metadata fetch, artifact resolution, and the Shared Signals receiver.

`scripts/configure_iya_sts.py` writes it on every run: the whole chain iya-sts publishes at `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), or the chain the TLS handshake presents when that endpoint is missing. It prints the path, the trust anchor's subject, and its SHA-256; compare the anchor with the Root CA on iya-sts's Server configuration, PKI page. The fetch itself is not verified (trust on first use).

**Plain http.** Identity-provider metadata from a URL, artifact resolution and every Shared Signals transmitter call use https. A plain `http://` URL is refused before any connection unless its host is loopback (`127.0.0.0/8`, `::1`, `localhost`), because metadata carries the signing keys, an `ArtifactResolve` returns the assertion, and Shared Signals carry SETs and the bearer token. A redirect gets the same check. A URL with userinfo is never loopback, and a URL (or redirect target) holding whitespace or a control character is refused outright, so no two parsers can disagree about its host. The `SamlError` keeps the fetch's code (`metadata`, `artifact`, `ssf`) and its message names the scheme and host only. There is no opt-out, as in saml2-sp-nodejs, saml2-sp-go, saml2-sp-c and saml2-sp-java. The SP's own entityID and ACS URL may stay http: they are never fetched.

The demo image build copies that file in: `.dockerignore` admits only `demo/generated/idp-ca.pem` from `demo/generated/` (keys and metadata stay out), and `COPY demo demo` puts it at `/app/demo/generated/idp-ca.pem`, where `idpCa` names it. A build with no chain file yet (a fresh clone, CI) still succeeds and carries none. Run the install script, then build the image; after running it against a different iya-sts, rebuild (`docker compose up --build`). Compose also mounts `demo/generated`, which holds the same file.
