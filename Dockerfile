# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

FROM node:26.8.2-bookworm-slim@sha256:cd9f682fa2885cd1056e830424764158570061c59736a1da836bc3d73df095ae AS node

FROM rust:1.98.0-slim-bookworm@sha256:1469a27c125cb5a3aebfa4f4e4665d935b02fb72cc093b2c974b3d740e43f157 AS builder

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
    && rustc --version | grep -E '^rustc 1\.98\.0 '
COPY gateway/Cargo.toml gateway/Cargo.toml

RUN mkdir -p gateway/src \
    && printf 'fn main() {}\n' > gateway/src/main.rs \
    && cargo build --locked --release -p gateway \
    && rm -rf gateway/src

COPY admin-ui admin-ui
COPY docs/schemas docs/schemas
COPY gateway gateway

RUN cargo build --locked --release -p gateway

# DLA-4792-1: the current official distroless digest still carries tzdata 2026b.
# Overlay only Debian's fixed data package, pinned to its official SHA-256.
# Extracting the archive does not run maintainer scripts or add runtime tools.
ADD --checksum=sha256:c6bdac9aa03e89a112c8d900cb60321889cfec535e0397b74383bd10c8b3cb44 \
    https://security.debian.org/debian-security/pool/updates/main/t/tzdata/tzdata_2026c-0+deb12u1_all.deb /tmp/runtime-tzdata.deb
RUN test "$(dpkg-deb --field /tmp/runtime-tzdata.deb Package)" = tzdata \
    && test "$(dpkg-deb --field /tmp/runtime-tzdata.deb Version)" = 2026c-0+deb12u1 \
    && test "$(dpkg-deb --field /tmp/runtime-tzdata.deb Architecture)" = all \
    && dpkg-deb --extract /tmp/runtime-tzdata.deb /tmp/runtime-tzdata \
    && dpkg-deb --control /tmp/runtime-tzdata.deb /tmp/runtime-tzdata-control \
    && mkdir -p /tmp/runtime-tzdata/var/lib/dpkg/status.d \
    && cp /tmp/runtime-tzdata-control/control /tmp/runtime-tzdata/var/lib/dpkg/status.d/tzdata \
    && cp /tmp/runtime-tzdata-control/md5sums /tmp/runtime-tzdata/var/lib/dpkg/status.d/tzdata.md5sums

# Preserve the deployed UID/GID and home without shipping account-management
# tools. These are data files only; no builder libraries enter the runtime.
RUN printf 'root:x:0:0:root:/root:/sbin/nologin\ngreengateway:x:10001:10001::/nonexistent:/sbin/nologin\n' > /tmp/runtime-passwd \
    && printf 'root:x:0:\ngreengateway:x:10001:\n' > /tmp/runtime-group

# Debian/glibc stays compatible with the production compiler. Distroless keeps
# CA roots, NSS/DNS, timezone data and libgcc, but omits curl, Perl, mount tools,
# shells and apt. Keep its Debian package metadata for the final-image scanner.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS runtime

COPY --from=builder /tmp/runtime-tzdata/ /
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
