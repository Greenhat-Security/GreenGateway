# syntax=docker/dockerfile:1

FROM node:24-bookworm-slim AS node

FROM rust:1.88-slim-bookworm AS builder

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
COPY gateway gateway

RUN cargo build --release -p gateway

FROM debian:bookworm-slim AS runtime

RUN groupadd --system greengateway \
    && useradd --system --gid greengateway --home-dir /nonexistent --shell /usr/sbin/nologin greengateway

COPY --from=builder /app/target/release/gateway /usr/local/bin/gateway

ENV LISTEN_ADDR=0.0.0.0:8080

EXPOSE 8080

USER greengateway:greengateway

ENTRYPOINT ["/usr/local/bin/gateway"]
