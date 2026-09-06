# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

FROM node:24-bookworm-slim@sha256:ba849c60be29959425b8734d57b8b4b7d56f98edd9504c9af091d5281095a71e AS node

FROM rust:1.98-slim-bookworm@sha256:1469a27c125cb5a3aebfa4f4e4665d935b02fb72cc093b2c974b3d740e43f157 AS builder

COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY gateway/Cargo.toml gateway/Cargo.toml

RUN mkdir -p gateway/src \
    && printf 'fn main() {}\n' > gateway/src/main.rs \
    && cargo build --release -p gateway \
    && rm -rf gateway/src

COPY admin-ui admin-ui
COPY docs/schemas docs/schemas
COPY gateway gateway

RUN cargo build --release -p gateway

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 greengateway \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin greengateway

COPY --from=builder /app/target/release/gateway /usr/local/bin/gateway

ENV LISTEN_ADDR=0.0.0.0:8080

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["curl", "--fail", "--silent", "--show-error", "http://127.0.0.1:8080/livez"]

USER 10001:10001

ENTRYPOINT ["/usr/local/bin/gateway"]
