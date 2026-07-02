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

There is no working quickstart yet because the repository is in pre-alpha and does not contain buildable gateway code.

A working quickstart, including Docker Compose and `cargo build` instructions, is planned for the Phase 1 open-source-readiness milestone: [Phase 1 - Open-source ready](https://github.com/Greenhat-Security/GreenGateway/milestones).

## Contributing

Contribution guidelines will live in [CONTRIBUTING.md](CONTRIBUTING.md). That file is expected to land in a follow-up PR for the same initial README and project setup work.

Until then, use the roadmap issue to understand project direction and open work: [Roadmap / project plan](https://github.com/Greenhat-Security/GreenGateway/issues/44).

## License

GreenGateway is licensed under GPL-3.0. See [LICENSE](LICENSE).
