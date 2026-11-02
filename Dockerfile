# syntax=docker/dockerfile:1
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
FROM rust:1
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY demo demo
COPY scripts scripts
COPY README.md LICENSE VERSION ./
RUN cargo build --release --bin saml2-sp --bin demo \
 && cp target/release/saml2-sp /usr/local/bin/saml2-sp \
 && cp target/release/demo /usr/local/bin/saml-demo
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/${PORT} && printf 'GET /healthz HTTP/1.0\\r\\nHost: 127.0.0.1\\r\\n\\r\\n' >&3 && grep -q '^ok' <&3"]
CMD ["saml-demo"]
