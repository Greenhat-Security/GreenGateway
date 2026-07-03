# syntax=docker/dockerfile:1

FROM rust:1.88-slim-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY gateway/Cargo.toml gateway/Cargo.toml

RUN mkdir -p gateway/src \
    && printf 'fn main() {}\n' > gateway/src/main.rs \
    && cargo build --release -p gateway \
    && rm -rf gateway/src

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
