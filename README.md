# GreenGateway

GreenGateway is an open-source, self-hosted universal MCP and API gateway for teams that want authentication, authorization, traffic visibility, and a visual firewall in front of any API or MCP server without hand-rolling that control plane themselves.

It is designed to sit between clients and existing HTTP backends or MCP servers, learn what is being used, and turn that traffic into enforceable, reviewable rules.

## Project Status

GreenGateway is **pre-alpha** and under active initial development. It is not production ready yet.

Most capabilities described below are the roadmap and vision, not shipped functionality. Progress is tracked in the pinned roadmap issue: [Roadmap / project plan](https://github.com/Greenhat-Security/GreenGateway/issues/44).

## Planned Scope

GreenGateway is being built around these core capabilities:

- **Universal HTTP reverse proxy**: place GreenGateway in front of any HTTP backend, start with a default-allow-on-install posture for discovery, then tighten access through policy over time.
- **Authentication and authorization on every request**: authenticate users and bots through pluggable OIDC, JWT, JWKS, and cookie-session integrations; authorize requests through a deny-by-default RBAC engine with rules stored as data.
- **Native MCP support**: speak the real MCP protocol rather than exposing a bespoke REST facade, with a dynamic tool registry, JSON Schema validation, and OpenAPI-to-tools generation.
- **Traffic discovery**: build an automatic endpoint inventory, check observed traffic against schemas, and surface anomaly signals.
- **Visual firewall-style rule builder**: inspect discovered traffic, create rules in one click, review policy behavior in shadow mode before enforcing it, and roll back through versioned policy history.
- **Identity directory**: maintain a Layer 7 firewall-style directory of every user and bot from any identity provider that has traversed the gateway.

## Architecture Sketch

```text
client
  |
  v
GreenGateway
  |-- auth: authenticate the caller
  |-- authz/policy: evaluate RBAC and rules-as-data
  |-- proxy/MCP: forward HTTP traffic or handle MCP protocol flows
  |-- audit: record identity, request, decision, and outcome
  |
  v
your backend API or MCP server
```

## Quick Start

GreenGateway currently includes a minimal gateway server with `GET /health`, `GET /version`, and `GET /metrics` endpoints. The broader gateway, auth, policy, and discovery capabilities described in Planned Scope are still pre-alpha roadmap work.

For the full list of environment variables, see [docs/configuration.md](docs/configuration.md). As more variables land, that document and [.env.example](.env.example) are kept in sync with the code by an automated test.

### Option 1: Cargo (for development)

`.env.example` documents the available environment variables and defaults; to override one today, set it in the real shell/process environment rather than sourcing a `.env` file.

```sh
cargo build --workspace
cargo run

# Or, with a non-default listen address:
LISTEN_ADDR=127.0.0.1:9090 cargo run
```

In another terminal:

```sh
curl http://localhost:8080/health
```

Expected response:

```json
{"status":"ok"}
```

### Option 2: Docker Compose

```sh
docker compose up --build
```

In another terminal:

```sh
curl http://localhost:8080/health
```

Expected response:

```json
{"status":"ok"}
```

## Contributing

Contribution guidelines will live in [CONTRIBUTING.md](CONTRIBUTING.md). CONTRIBUTING.md will land in a follow-up PR (PR 2 of #1).

Until then, use the roadmap issue to understand project direction and open work: [Roadmap / project plan](https://github.com/Greenhat-Security/GreenGateway/issues/44).

## License

GreenGateway is licensed under GPL-3.0. See [LICENSE](LICENSE).
