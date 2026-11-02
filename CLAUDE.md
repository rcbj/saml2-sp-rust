# saml2-sp

Rust service provider for SAML 2.0 Web Browser SSO, plus a Shared Signals poll receiver. Version 0.1.0. MIT. `develop` and `main` are one commit. A pull request merged into `main` publishes the crate to crates.io after the test workflow succeeds on that commit. A direct push does not. The token is the `CARGO_REGISTRY_TOKEN` repository secret. A version already on crates.io stays there; the next release is a new `version` in `Cargo.toml`.

## Usage

`ServiceProvider::from_file("saml.json", None, None)`, then `login` and `acs`. JSON keys match the Python configuration (`entityId`, `acsUrl`, `privateKey`, `certificate`, `idpMetadata`, bindings, `signals`, `ssf`). Exported names are `from_file`, `login`, `acs`, and `post_form_html`.

`signals` omitted or `true` keeps the receiver available and is omitted from the resolved configuration. `false` does not start a receiver and does not require transmitter metadata, and the resolved configuration includes `signals: false`. A non-boolean fails with `signals must be true or false`. The flag does not change the AuthnRequest: SAML does not send OAuth scopes.

Request bindings are `redirect` and `post`. Response bindings are `post`, `redirect`, and `artifact`. Artifact resolution is a signed SOAP `ArtifactResolve`. HTTP-Redirect query signatures use RSA-SHA256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`). Success is `urn:oasis:names:tc:SAML:2.0:status:Success`. `saml2-sp generate-keys` writes a self-signed RSA certificate.

## Tests

```bash
docker build --target test .
```

The `test` stage runs `cargo test` in `rust:1`. GitHub Actions uses that command. Do not run Cargo on the host. The demo image does not run the suite.

Signatures and decryption are real. The stub identity provider signs with this crate's exclusive canonicalization and is created inside the tests.

`python3 scripts/live_iya_sts.py` signs the demo in to a fresh iya-sts (main, memory mode, no persistence, no clustering) and checks credential-change and session-revoked on `GET /live-status`. `IYA_STS_URL` uses a running iya-sts; `IYA_STS_IMAGE` starts one from an image; otherwise it clones and builds main. The registrar runs inside the demo image, never with Cargo on the host. Default ports 18518 (iya-sts) and 18618 (demo), `LIVE_STS_PORT` / `LIVE_DEMO_PORT`; it refuses 3000, 8081, and 18481 to 18495. Always a fresh iya-sts: a second registration of the same SP fails. Its order is install script, then demo image build, then run: it copies the checkout (no `demo/generated`, `.git`, `target`) to a scratch context, builds the image there once, runs the registrar in it (which writes the chain), builds again (only the `demo/` layer changes), checks the image's `demo/generated/idp-ca.pem` equals the saved file, and runs the demo with `sp.key`, `sp.crt` and `idp-metadata.xml` mounted file by file. It never fetches the CA for the demo, rewrites `idpCa`, or mounts a CA; it reads the saved chain only for its own HTTPS client. No script prints a password or secret, or a URL (trace lines carry fixed labels). Secrets reach `docker run` as `-e NAME`, the value in the child's environment. A generated test-user password goes to `demo/generated/<user>.password` (created 0600) and only that path is printed. Every `ssl` context in `scripts/` sets TLS 1.2 as the minimum. `.github/workflows/nightly.yml` runs the unit suite and that script at 07:10 UTC (`10 7 * * *`) and on `workflow_dispatch`. Push CI stays the unit suite.

## Layout

Crate `saml2-sp` (edition 2021), binaries `saml2-sp` and `demo`, `scripts/configure_iya_sts.py`, `scripts/trust_chain.py`, `scripts/live_iya_sts.py`, `.github/workflows/nightly.yml`, `Dockerfile`, `docker-compose.yml`. The image name is `saml2-sp-rust-demo`. Compose uses `network_mode: host`, service `saml-demo`, and `ENV PORT=3000` in the image. The health check is `http://127.0.0.1:${PORT}/healthz`.

## Demo

`docker compose up --build`. `GET /healthz` is `200` with body `ok`. Pages: sign-in, `/login` (redirect or POST form), `/saml/acs`, and logout, plus metadata. `GET /live-status` is JSON `{signedIn, subject, receiver, events: [{type, jti}]}`, never an assertion. When `session-revoked` matched no tracked session (the assertion SessionIndex was the assertion id), the demo ends its one local session and untracks it; that is demo code, not the library. Loopback entityID and assertion-consumer URLs follow `PORT`. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL. `demo/saml.json` uses `file:` placeholders and omits `signals`. Do not commit `demo/generated/`.

## Signals

With an `ssf` block and without `"signals": false`, the demo starts one poll receiver on the service provider's certificate (mutual TLS). `stop` waits for an in-flight poll. `scripts/configure_iya_sts.py` uses the `saml2-sp` binary on `PATH` (falling back to `cargo run`), registers the SP metadata, pins AES-256-GCM / RSA-OAEP, turns on multiple accounts, and, unless signals are off, grants `ssf.manage`. The container `PORT` wins over the shell `PORT` at registration.

## Trust chain (`idpCa`)

`idpCa` (default `file:generated/idp-ca.pem`, relative to `demo/`) is iya-sts's TLS listener CA trust chain. `scripts/configure_iya_sts.py` writes it on every run through `scripts/trust_chain.py`'s `save_trust_chain()` (the copy the OIDC and GNAP repos carry; its CLI here reads `--config`/`SAML_CONFIG` and `--idp`/`IYA_STS_URL`): the whole chain from `GET /tls/server-certificate` (leaf, TLS Issuing CA, Intermediate, Root), falling back to the handshake's chain, and prints the path, the anchor's subject and SHA-256. It used to keep only the root from the handshake, and only when the file was missing. `src/http.rs`'s `trust_anchors()` adds every PEM block as a root: `native_tls::Certificate::from_pem` reads only the first (the leaf), and OpenSSL then fails with "self-signed certificate in certificate chain". The demo image carries the chain from build time: `.dockerignore` is `demo/generated/*` then `!demo/generated/idp-ca.pem`, and the demo stage's `COPY demo demo` (after `cargo build`, so a new chain does not rebuild the binaries) lands it at `/app/demo/generated/idp-ca.pem`. With no chain file the same COPY carries nothing from `demo/generated` and the build succeeds. Rebuild the image after re-running the install script against a different iya-sts. `src/trust_chain_test.rs` serves HTTPS from an rcgen four-certificate chain and checks the registrar writes all four (published and handshake) and that `ServiceProvider` fetches metadata trusting the file.

**Plain http (#12).** `http::send` is the one place every fetch goes through (metadata URL, `ArtifactResolve`, SSF configuration, JWKS, stream and poll). `refuse_plain_http_off_loopback` checks the URL ureq itself parsed (`Request::request_url`), before connecting and without resolving a name: plain `http://` to a host that is not loopback (`127.0.0.0/8`, `::1`, `localhost`) is refused, naming only the scheme and host[:port]; userinfo is never loopback. Redirects are followed by hand (`redirects(0)` and at most five hops, never https to http) so each hop gets the same check. No opt-out. `src/plain_http_test.rs` covers it; `http://0.0.0.0:<port>` reaches a 127.0.0.1 listener on Linux, so an empty backlog proves no connection was opened.
