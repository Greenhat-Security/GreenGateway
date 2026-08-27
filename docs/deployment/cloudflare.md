# Deploy GreenGateway on Cloudflare

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Greenhat-Security/GreenGateway)

This button deploys GreenGateway as a Cloudflare Workers application backed by a Cloudflare Container. The Worker entrypoint lives in `cloudflare/src/index.ts`; the container image is built from the repository `Dockerfile`.

## Requirements

- A Cloudflare account on a Workers Paid plan with Containers available.
- A public GitHub or GitLab source repository. Cloudflare Deploy buttons do not support private source repositories.
- For manual deploys from your own machine, Docker or another Docker-compatible engine must be running because Wrangler builds and pushes the container image.

## What Cloudflare Creates

Wrangler uses `wrangler.jsonc` as the deployment source of truth. It defines:

- Worker name: `greengateway`.
- Worker entrypoint: `cloudflare/src/index.ts`.
- Container class: `GreenGatewayContainer`.
- Durable Object binding: `GREENGATEWAY_CONTAINER`.
- Container image: `./Dockerfile`.
- Preview URLs enabled for PR/version previews.

The Worker sends every request to a singleton GreenGateway container on port `8080`. GreenGateway's `LISTEN_ADDR` is forced to `0.0.0.0:8080` so the Cloudflare container supervisor can reach it. Container supervision pings `/livez`; application traffic should use `/readyz` when deciding whether required upstream capacity is available.

## Runtime Configuration

The default deploy is intentionally conservative:

- `AUTH_ENABLED=true`
- `AUTH_MODE=required`
- `AUTH_EXEMPT_PATHS` unset, so probe paths and the effective `ADMIN_PREFIX` are exempt
- `RBAC_EXEMPT_PATHS` unset, so probe paths and the effective `ADMIN_PREFIX` are exempt
- `ADMIN_PREFIX=/admin`
- `EGRESS_DENY_PRIVATE_IPS=true`
- `UPSTREAM_URL=` left blank

Set `UPSTREAM_URL` or `UPSTREAM_ROUTES` during deploy, or later in the Cloudflare dashboard, when you want GreenGateway to proxy to origin APIs. Pool JSON is forwarded unchanged after the normal GreenGateway startup validation. After the first deploy, set `GATEWAY_PUBLIC_URL` to the deployed Worker URL if you use MCP OAuth protected-resource metadata.

The wrapper forwards non-empty string Worker variables and secrets whose names match GreenGateway configuration keys from `.env.example`, except:

- `LISTEN_ADDR`, because Cloudflare must reach the container on port `8080`.
- `ADMIN_LISTEN_ADDR`, because this one-click Worker exposes a single container port. Leave the admin surface on `ADMIN_PREFIX` for Cloudflare deploys.
- the inbound TLS settings (`TLS_CERT_FILE`, `TLS_KEY_FILE`, `ADMIN_TLS_CERT_FILE`, `ADMIN_TLS_KEY_FILE`, `TLS_MIN_VERSION`, `TLS_HANDSHAKE_TIMEOUT_MS`, `TLS_MAX_CONCURRENT_HANDSHAKES`), because Cloudflare terminates TLS at its edge and reaches the container over plain HTTP/1.1. There is also nowhere to mount a certificate and key in this deployment shape.
- the gRPC settings (`GRPC_LISTEN_ADDR`, `GRPC_MAX_CONCURRENT_STREAMS`, `GRPC_MAX_METADATA_BYTES`), because **Cloudflare Containers can never carry gRPC**. See [gRPC cannot work on Cloudflare Containers](#grpc-cannot-work-on-cloudflare-containers) below.

An automated parity test compares this forwarding allowlist to GreenGateway's runtime environment reads, so a newly supported key cannot silently be omitted. `SHUTDOWN_DRAIN_DELAY_MS`, `SHUTDOWN_TIMEOUT_MS`, and `AUDIT_DRAIN_TIMEOUT_MS` are forwarded; keep their sum within the Cloudflare container termination budget used by the selected platform plan.

Secrets such as OIDC client secrets should be configured as Worker secrets or embedded inside a secret-backed `AUTH_PROVIDERS` value, not committed to the repository.

These values are passed to the container when it starts. If you change a Worker variable after the container is already running, redeploy or restart the container before relying on the new value.

### Client IP attribution

A caller's connection terminates at Cloudflare's edge, so the connection the container accepts is opened by the Durable Object. Every request therefore reaches the gateway from the same peer address.

The Worker recovers the real caller by translating Cloudflare's `cf-connecting-ip` into `x-forwarded-for` and `x-real-ip` on the container subrequest. It **sets** both rather than appending, and strips them when the edge supplies no address, so a caller-supplied value can never be mistaken for one Cloudflare vouched for.

That is necessary but not sufficient. GreenGateway ignores forwarded headers unless the connection peer is inside a configured trusted CIDR, and `TRUST_PROXY_HEADERS` is `false` by default. **Until you set `TRUST_PROXY_HEADERS=true` and a `TRUSTED_PROXY_CIDRS` value covering the container-runtime peer address, every caller shares one client identity.** The consequences are concrete:

- Pre-auth rate limiting keys on `ip:{client_ip}`, so all callers share a single bucket. One client exceeding `RATE_LIMIT_WRITE_RPS` returns HTTP 429 to everyone else — an unauthenticated, whole-deployment denial of service that the per-IP design exists to prevent.
- The pending-login store's per-IP cap is likewise shared, so one client can exhaust admin SSO logins for all operators.
- Audit and observation records attribute every request to the same address.

Both variables are forwarded by the wrapper. Determine the peer CIDR for your deployment rather than copying one: read the `client_ip` recorded in an audit event from a known caller, and confirm it changes per caller once the CIDR is set. Setting `TRUSTED_PROXY_CIDRS` wider than the actual peer range would let a caller that can reach the container directly spoof its own identity, so keep it as narrow as the observed peer address allows.

### Connections storage and secret providers

The wrapper recognizes all four Connections storage and secret settings:

- `CONNECTIONS_SQLITE_PATH`
- `CONNECTION_SECRETS_ROOT`
- `CONNECTION_SECRET_ALIASES`
- `CONNECTION_LOCAL_SECRET_KEYRING`

It forwards each setting unchanged only when the corresponding Worker binding is a non-empty string. Unset, empty, whitespace-only, and non-string bindings are omitted, so GreenGateway's fail-closed startup validation and disabled defaults remain authoritative.

Forwarding a path does not create storage or a mount. The one-click deployment provides neither a durable filesystem location for `CONNECTIONS_SQLITE_PATH` nor a secure secret mount for `CONNECTION_SECRETS_ROOT`. Therefore, leave `CONNECTIONS_SQLITE_PATH`, `CONNECTION_SECRETS_ROOT`, and `CONNECTION_LOCAL_SECRET_KEYRING` unset on the standard one-click deployment. In that state, managed Connection mutations and encrypted-local-secret operations remain unavailable, while legacy upstream configuration is exposed only through its read-only Connection projections. Do not enable managed mutations until the deployment supplies a durable SQLite location whose database, WAL, and SHM files survive container replacement. Do not enable encrypted local secrets until it also supplies a private mount for every keyring file and a tested backup/restore procedure.

`CONNECTION_SECRET_ALIASES` contains locators, not secret values. File aliases have the same secure-mount requirement. Environment aliases have an additional wrapper limitation: the forwarding allowlist is exact and does not dynamically forward an arbitrary variable named by an alias, such as `GGW_BILLING_TOKEN`. Setting that Worker secret alongside the alias does not make it available inside the container. Keep environment aliases disabled on this wrapper unless a future deployment integration explicitly and safely maps the referenced secret binding into the container. Never place the resolved secret value inside `CONNECTION_SECRET_ALIASES`, `wrangler.jsonc`, a public Worker variable, an image layer, or source control.

If a custom Cloudflare deployment supplies durable storage or a secure mount outside this repository's one-click wrapper, validate its lifecycle against container replacement and rollback before configuring the corresponding paths. A redeploy, restart, eviction, platform replacement, or the configured automatic sleep after 10 minutes of idleness starts the next container with a fresh writable disk. Losing `connections.sqlite` loses managed configuration; losing a keyring file while encrypted rows remain causes startup or secret resolution to fail closed.

### gRPC cannot work on Cloudflare Containers

This is a structural limitation of the deployment shape, not a configuration gap, and no setting changes it.

gRPC over HTTP/2 requires the client's HTTP/2 connection preface to reach the gateway. On this deployment it never can. Cloudflare terminates the client connection at its edge, and the Durable Object opens its own connection to the container over plain HTTP/1.1 — the same reason the inbound TLS settings are not forwarded. The gRPC listener would sit on a port nothing ever speaks HTTP/2 to.

So `GRPC_LISTEN_ADDR` is deliberately **not** forwarded by the wrapper, alongside `LISTEN_ADDR` and the inbound TLS settings. A forwarding entry that cannot work is worse than an absent one: it invites the configuration it silently breaks. Setting the variable in the Cloudflare dashboard has no effect.

To proxy gRPC through GreenGateway, run it somewhere the container is reached over HTTP/2 directly — behind nginx `grpc_pass`, Envoy, or an equivalent terminator that re-originates h2c. See [docs/deployment/grpc.md](grpc.md).

## Important Limitations

- Cloudflare Containers use an ephemeral container filesystem by default. GreenGateway settings such as `AUDIT_SQLITE_PATH`, `DISCOVERY_SQLITE_PATH`, `PRINCIPAL_SQLITE_PATH`, `SERVICE_TOKEN_SQLITE_PATH`, and `CONNECTIONS_SQLITE_PATH` can work for evaluation, but their contents are lost on container replacement unless the deployment explicitly supplies durable storage. A redeploy must be treated as potential state loss, not as a persistence mechanism.
- File-backed settings such as `POLICY_FILE`, `TOOLS_FILE`, `OPENAPI_SPEC_PATH`, `CONNECTION_SECRETS_ROOT`, CA bundles, and mTLS client identities must point at files that exist inside the image or are otherwise created at runtime. The one-click wrapper does not create a secure mount. A plain or secret Worker variable is not a mounted private-key file; do not put PEM key material, local encryption keys, or resolved Connection secrets in `wrangler.jsonc`, public variables, image layers, or inline route JSON.
- The one-click wrapper does not expose `ADMIN_LISTEN_ADDR`; use the shared `ADMIN_PREFIX` surface with normal authentication/RBAC.
- The one-click wrapper does not expose the inbound TLS settings; TLS is terminated by Cloudflare and the container is reached over HTTP/1.1.
- **gRPC cannot work on this deployment at all.** The container is reached over HTTP/1.1, so no HTTP/2 connection preface ever arrives. `GRPC_LISTEN_ADDR` is not forwarded and setting it has no effect.
- Per-IP limits are inert until proxy-header trust is configured. See [Client IP attribution](#client-ip-attribution); without it a single caller can rate-limit the whole deployment.
- This project is still alpha software. Treat the one-click deploy path as a fast evaluation path, not a production hardening guide.
- The first container deploy may return Worker errors for several minutes while Cloudflare finishes provisioning container capacity.

## Manual Deploy

```sh
npm ci
npx wrangler login
npm run deploy
```

Check the deployed gateway:

```sh
curl https://<worker-name>.<your-workers-subdomain>.workers.dev/startupz
curl https://<worker-name>.<your-workers-subdomain>.workers.dev/readyz
```

Expected response:

```json
{"status":"started"}
{"status":"ready"}
```

The embedded admin UI is available at:

```text
https://<worker-name>.<your-workers-subdomain>.workers.dev/admin
```

## References

- [Cloudflare Deploy buttons](https://developers.cloudflare.com/workers/platform/deploy-buttons/)
- [Cloudflare Containers getting started](https://developers.cloudflare.com/containers/get-started/)
- [Cloudflare Container interface](https://developers.cloudflare.com/containers/container-class/)
- [Cloudflare container environment variables and secrets](https://developers.cloudflare.com/containers/examples/env-vars-and-secrets/)
- [Cloudflare Container lifecycle and ephemeral disk](https://developers.cloudflare.com/containers/platform-details/architecture/)
