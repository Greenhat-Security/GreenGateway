# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

FROM node:26.8.2-bookworm-slim@sha256:cd9f682fa2885cd1056e830424764158570061c59736a1da836bc3d73df095ae AS node

FROM rust:1.98.1-slim-bookworm@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730 AS builder

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

# Rustls handles TLS; Gateway links only glibc and libgcc on Linux. Extract
# the two official Debian 13 GCC runtime packages into a data-only overlay,
# including their complete package metadata. No maintainer scripts execute.
ADD --checksum=sha256:3c71917b490d1a17aed43196a2787a256ecf060526cdb20216a74bedc061b150 \
    https://deb.debian.org/debian/pool/main/g/gcc-14/libgcc-s1_14.2.0-19_amd64.deb /tmp/libgcc-s1.deb
ADD --checksum=sha256:5b6825de4263824b78c4c51f6476414f3b4e89c2ab63e81dc8b9b5501e867cf6 \
    https://deb.debian.org/debian/pool/main/g/gcc-14/gcc-14-base_14.2.0-19_amd64.deb /tmp/gcc-14-base.deb
RUN mkdir -p /tmp/runtime-gcc/var/lib/dpkg/status.d \
    && for package in libgcc-s1 gcc-14-base; do \
        test "$(dpkg-deb --field /tmp/$package.deb Package)" = "$package" \
        && test "$(dpkg-deb --field /tmp/$package.deb Version)" = 14.2.0-19 \
        && test "$(dpkg-deb --field /tmp/$package.deb Architecture)" = amd64 \
        && dpkg-deb --extract /tmp/$package.deb /tmp/runtime-gcc \
        && dpkg-deb --control /tmp/$package.deb /tmp/control-$package \
        && cp /tmp/control-$package/control /tmp/runtime-gcc/var/lib/dpkg/status.d/$package \
        && cp /tmp/control-$package/md5sums /tmp/runtime-gcc/var/lib/dpkg/status.d/$package.md5sums \
        || exit 1; \
    done

# Preserve the deployed UID/GID and home without shipping account-management
# tools. These are data files only; no builder libraries enter the runtime.
RUN printf 'root:x:0:0:root:/root:/sbin/nologin\ngreengateway:x:10001:10001::/nonexistent:/sbin/nologin\n' > /tmp/runtime-passwd \
    && printf 'root:x:0:\ngreengateway:x:10001:\n' > /tmp/runtime-group

# Debian 13 glibc supports the older builder ABI. The supported no-SSL base
# keeps CA roots, NSS/DNS, fixed timezone data and scanner-visible metadata.
# Shells, apt, curl, Perl, mount tools and unused OpenSSL are absent.
FROM gcr.io/distroless/base-nossl-debian13:nonroot@sha256:8c563c1fb5e120606f0d85733049775faed6192e2bd2223ef283a5393eec22b9 AS runtime

COPY --from=builder /tmp/runtime-gcc/ /
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
