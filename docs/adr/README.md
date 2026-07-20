# Architecture Decision Records

Architecture Decision Records record significant architectural and scope decisions for GreenGateway, especially decisions that are hard to reverse. They keep those choices visible so they do not have to be relitigated in every subsequent design discussion.

ADR files use the naming convention `NNNN-short-title.md`, where `NNNN` is a sequential, zero-padded four-digit number.

## Index

- [ADR-0001: HTTP Upstreams Only](0001-http-upstreams-only.md): GreenGateway fronts HTTP upstreams only, not raw database wire protocols or generic TCP/UDP traffic.
- [ADR-0002: Single-Tenant Per Deployment](0002-single-tenant-per-deployment.md): Each deployment protects one trust domain; organization and role claims are rule-matching inputs, not tenant isolation boundaries.
- [ADR-0003: Admin UI Stack And Embedding](0003-admin-ui-stack.md): The admin UI uses Vite, React, and TypeScript, is embedded with `rust-embed`, and uses Vite's dev-server proxy for local development.
- [ADR-0004: Policy Studio Authority and Evidence](0004-policy-studio-authority-and-evidence.md): Policy Studio and live authorization share one fail-closed evaluator, versioned resource snapshots, bounded privacy-safe analysis, and evidence that never overstates source completeness or publication authority.
