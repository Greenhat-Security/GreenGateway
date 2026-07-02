# Architecture Decision Records

Architecture Decision Records record significant architectural and scope decisions for GreenGateway, especially decisions that are hard to reverse. They keep those choices visible so they do not have to be relitigated in every subsequent design discussion.

ADR files use the naming convention `NNNN-short-title.md`, where `NNNN` is a sequential, zero-padded four-digit number.

## Index

- [ADR-0001: HTTP Upstreams Only](0001-http-upstreams-only.md): GreenGateway fronts HTTP upstreams only, not raw database wire protocols or generic TCP/UDP traffic.
- [ADR-0002: Single-Tenant Per Deployment](0002-single-tenant-per-deployment.md): Each deployment protects one trust domain; organization and role claims are rule-matching inputs, not tenant isolation boundaries.
