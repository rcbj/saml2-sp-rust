# saml2-sp

Rust service provider for SAML 2.0 Web Browser SSO, plus a Shared Signals poll receiver. Version 0.1.0. MIT. `develop` and `main` are one commit. Publishing is not set up.

## Usage

`ServiceProvider::from_file("saml.json", None, None)`, then `login` and `acs`. JSON keys match the Python configuration (`entityId`, `acsUrl`, `privateKey`, `certificate`, `idpMetadata`, bindings, `signals`, `ssf`). Exported names are `from_file`, `login`, `acs`, and `post_form_html`.

`signals` omitted or `true` keeps the receiver available and is omitted from the resolved configuration. `false` does not start a receiver and does not require transmitter metadata, and the resolved configuration includes `signals: false`. A non-boolean fails with `signals must be true or false`. The flag does not change the AuthnRequest: SAML does not send OAuth scopes.

Request bindings are `redirect` and `post`. Response bindings are `post`, `redirect`, and `artifact`. Artifact resolution is a signed SOAP `ArtifactResolve`. HTTP-Redirect query signatures use RSA-SHA256 (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`). Success is `urn:oasis:names:tc:SAML:2.0:status:Success`. `saml2-sp generate-keys` writes a self-signed RSA certificate.

## Tests

```bash
cargo test
```

Signatures and decryption are real. The stub identity provider signs with this crate's exclusive canonicalization and is created inside the tests. No live iya-sts.

## Layout

Crate `saml2-sp` (edition 2021), binaries `saml2-sp` and `demo`, `scripts/configure_iya_sts.py`, `Dockerfile`, `docker-compose.yml`. The image name is `saml2-sp-rust-demo`. Compose uses `network_mode: host`, service `saml-demo`, and `ENV PORT=3000` in the image. The health check is `http://127.0.0.1:${PORT}/healthz`.

## Demo

`cargo run --bin demo`. `GET /healthz` is `200` with body `ok`. Pages: sign-in, `/login` (redirect or POST form), `/saml/acs`, and logout, plus metadata. Loopback entityID and assertion-consumer URLs follow `PORT`. Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL. `demo/saml.json` uses `file:` placeholders and omits `signals`. Do not commit `demo/generated/`.

## Signals

With an `ssf` block and without `"signals": false`, the demo starts one poll receiver on the service provider's certificate (mutual TLS). `stop` waits for an in-flight poll. `scripts/configure_iya_sts.py` registers the SP metadata, pins AES-256-GCM / RSA-OAEP, turns on multiple accounts, and, unless signals are off, grants `ssf.manage`. The container `PORT` wins over the shell `PORT` at registration.
