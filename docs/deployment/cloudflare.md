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

The Worker sends every request to a singleton GreenGateway container on port `8080`. GreenGateway's `LISTEN_ADDR` is forced to `0.0.0.0:8080` so the Cloudflare container supervisor can reach it.

## Runtime Configuration

The default deploy is intentionally conservative:

- `AUTH_ENABLED=true`
- `AUTH_MODE=required`
- `AUTH_EXEMPT_PATHS=/health,/version,/metrics,/admin`
- `RBAC_EXEMPT_PATHS=/health,/version,/metrics,/admin`
- `ADMIN_PREFIX=/admin`
- `EGRESS_DENY_PRIVATE_IPS=true`
- `UPSTREAM_URL=` left blank

Set `UPSTREAM_URL` during deploy, or later in the Cloudflare dashboard, when you want GreenGateway to proxy to an origin API. After the first deploy, set `GATEWAY_PUBLIC_URL` to the deployed Worker URL if you use MCP OAuth protected-resource metadata.

The wrapper forwards non-empty string Worker variables and secrets whose names match GreenGateway configuration keys from `.env.example`, except:

- `LISTEN_ADDR`, because Cloudflare must reach the container on port `8080`.
- `ADMIN_LISTEN_ADDR`, because this one-click Worker exposes a single container port. Leave the admin surface on `ADMIN_PREFIX` for Cloudflare deploys.

Secrets such as OIDC client secrets should be configured as Worker secrets or embedded inside a secret-backed `AUTH_PROVIDERS` value, not committed to the repository.

These values are passed to the container when it starts. If you change a Worker variable after the container is already running, redeploy or restart the container before relying on the new value.

## Important Limitations

- Cloudflare Containers use an ephemeral container filesystem by default. GreenGateway settings such as `AUDIT_SQLITE_PATH`, `DISCOVERY_SQLITE_PATH`, `PRINCIPAL_SQLITE_PATH`, and `SERVICE_TOKEN_SQLITE_PATH` can work for evaluation, but they are not durable storage across container replacement.
- File-backed settings such as `POLICY_FILE`, `TOOLS_FILE`, and `OPENAPI_SPEC_PATH` must point at files that exist inside the image or are otherwise created at runtime.
- This project is still pre-alpha. Treat the one-click deploy path as a fast evaluation path, not a production hardening guide.
- The first container deploy may return Worker errors for several minutes while Cloudflare finishes provisioning container capacity.

## Manual Deploy

```sh
npm install
npx wrangler login
npm run deploy
```

Check the deployed gateway:

```sh
curl https://<worker-name>.<your-workers-subdomain>.workers.dev/health
```

Expected response:

```json
{"status":"ok"}
```

The embedded admin UI is available at:

```text
https://<worker-name>.<your-workers-subdomain>.workers.dev/admin
```

## References

- [Cloudflare Deploy buttons](https://developers.cloudflare.com/workers/platform/deploy-buttons/)
- [Cloudflare Containers getting started](https://developers.cloudflare.com/containers/get-started/)
- [Cloudflare Container interface](https://developers.cloudflare.com/containers/container-class/)
