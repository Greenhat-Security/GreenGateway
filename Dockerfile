# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

FROM node:26.8.1-bookworm-slim@sha256:367679cf9792759492a486e4aa4b421764d71a9546a6dae8aab81a99eb797b3e AS node

FROM rust:1.88.0-slim-bookworm@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS builder

COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

WORKDIR /app

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .node-version .npm-version build-tools.json npm-script-policy.json ./
COPY scripts/npm-script-policy.mjs scripts/npm-script-policy.mjs
RUN test "$(node --version)" = "v$(cat .node-version)" \
    && test "$(npm --version)" = "$(cat .npm-version)" \
    && rustc --version | grep -E '^rustc 1\.88\.0 '
COPY gateway/Cargo.toml gateway/Cargo.toml

RUN mkdir -p gateway/src \
    && printf 'fn main() {}\n' > gateway/src/main.rs \
    && cargo build --locked --release -p gateway \
    && rm -rf gateway/src

COPY admin-ui admin-ui
COPY docs/schemas docs/schemas
COPY gateway gateway

RUN cargo build --locked --release -p gateway

# Preserve the deployed UID/GID and home without shipping account-management
# tools. These are data files only; no builder libraries enter the runtime.
RUN printf 'root:x:0:0:root:/root:/sbin/nologin\ngreengateway:x:10001:10001::/nonexistent:/sbin/nologin\n' > /tmp/runtime-passwd \
    && printf 'root:x:0:\ngreengateway:x:10001:\n' > /tmp/runtime-group

# Debian/glibc stays compatible with the production compiler. Distroless keeps
# CA roots, NSS/DNS, timezone data and libgcc, but omits curl, Perl, mount tools,
# shells and apt. Keep its Debian package metadata for the final-image scanner.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS runtime

COPY --from=builder /app/target/release/gateway /usr/local/bin/gateway
COPY --from=builder /tmp/runtime-passwd /etc/passwd
COPY --from=builder /tmp/runtime-group /etc/group

ENV LISTEN_ADDR=0.0.0.0:8080
ENV HOME=/nonexistent
WORKDIR /

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/gateway", "healthcheck", "http://127.0.0.1:8080/livez"]

USER 10001:10001

ENTRYPOINT ["/usr/local/bin/gateway"]
