# Architecture Decision Records

Architecture Decision Records record significant architectural and scope decisions for GreenGateway, especially decisions that are hard to reverse. They keep those choices visible so they do not have to be relitigated in every subsequent design discussion.

ADR files use the naming convention `NNNN-short-title.md`, where `NNNN` is a sequential, zero-padded four-digit number.

## Index

- [ADR-0001: HTTP Upstreams Only](0001-http-upstreams-only.md): GreenGateway fronts HTTP upstreams only, not raw database wire protocols or generic TCP/UDP traffic.
- [ADR-0002: Single-Tenant Per Deployment](0002-single-tenant-per-deployment.md): Each deployment protects one trust domain; organization and role claims are rule-matching inputs, not tenant isolation boundaries. Includes cluster mode's one-primary authority (`DEPLOYMENT_ID` is a deployment identifier, not a tenant key), the standalone-versus-cluster feature matrix, and the explicitly unsupported mixed configurations.
- [ADR-0003: Admin UI Stack And Embedding](0003-admin-ui-stack.md): The admin UI uses Vite, React, and TypeScript, is embedded with `rust-embed`, and uses Vite's dev-server proxy for local development.
- [ADR-0004: Policy Studio Authority and Evidence](0004-policy-studio-authority-and-evidence.md): Defines the target in which Policy Studio and live authorization use one fail-closed evaluator, versioned resource snapshots, bounded privacy-safe analysis, and evidence that never overstates source completeness or publication authority.
- [ADR-0005: Production Proxy Data Plane Security Boundaries](0005-production-proxy-data-plane.md): Defines logical-route versus physical-endpoint identity, SSRF-safe DNS generations and pooled transport isolation, bounded resilience, lifecycle, streaming, and mTLS constraints for issue #239.
- [ADR-0006: First-Class Connections And Credential Authority](0006-first-class-connections-and-credentials.md): Defines connection authority, credential and TLS binding, URL/path rules, secret confidentiality, permissions, resource bounds, typed tool provenance, and the dependency on issue #239 transport primitives.
