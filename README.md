# saml2-sp

Server-side SAML 2.0 service provider for Rust. It sends a signed `AuthnRequest` on HTTP-Redirect or HTTP-POST, accepts a `Response` on HTTP-POST, HTTP-Redirect, or HTTP-Artifact, verifies XML signatures, decrypts encrypted assertions, and can poll a Shared Signals transmitter for CAEP and RISC events.

Version 0.1.0. License: MIT. `develop` and `main` are one commit. Publishing is not set up.

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

## Tests

```bash
docker build --target test .
```

The suite runs in a container.

Signatures and decryption are real (RSA, exclusive XML canonicalization). The stub identity provider is in the test files. No live iya-sts. Keys are generated in the test.

## Demo

`docker compose up --build`. `GET /healthz` is `200` with body `ok` and does not dial an identity provider. Pages: sign-in, `/login` (redirect or POST form), `/saml/acs`, and logout. Loopback entityID and assertion-consumer URLs follow `PORT` (default 3000). Other hosts stay as written. `PUBLIC_URL` or `--public-url` replaces the origin and keeps the path. The default `http://localhost:3000` is not an explicit public URL. `demo/saml.json` uses `file:` placeholders and omits `signals`. Do not commit `demo/generated/`.

`scripts/configure_iya_sts.py` is standard-library Python. It calls `cargo run --bin saml2-sp` for keys, metadata, and the identity-provider summary. The container `PORT` wins over the shell `PORT`.
