# Security Policy

GreenGateway is a security-focused gateway, and vulnerability reports are
taken seriously.

## Reporting a Vulnerability

Do not open a public GitHub issue for a suspected security vulnerability.

Use GitHub's private vulnerability reporting feature for this repository:

1. Open the repository on GitHub.
2. Go to the Security tab.
3. Select **Report a vulnerability**.

This is the current reporting mechanism because the project does not publish a
dedicated security email address. Include the affected revision, deployment
shape, impact, and the smallest safe reproduction you can provide. Do not put
real credentials, tokens, private keys, customer payloads, or production
database copies in the report.

## Supported Versions

GreenGateway is alpha software and has no supported release line yet. Security
fixes target the current `main` branch. Older commits, forks, and deployment
images are not maintained automatically; operators must track and evaluate
upstream changes.

## Scope and Security Boundaries

The attack surface includes the HTTP and MCP data planes, admin APIs and UI,
authentication and policy reload, outbound egress, managed Connections,
credential and TLS providers, OAuth token exchange, catalog refresh, SQLite
state, audit sinks, and deployment wrappers.

The implemented security order is documented in
[the architecture](docs/architecture.md). In particular:

- an initial authentication, RBAC, direct-rule, tool-policy, or admin-permission
  denial occurs before Connection provider reads, DNS, client acquisition, or
  upstream bytes;
- every outbound destination passes host/port policy, complete DNS-answer
  validation, and exact-address pinning with redirects and ambient proxies
  disabled;
- Connection TLS material and credentials are resolved only after that egress
  preflight, caller credentials are removed, and the configured credential is
  injected last;
- an OAuth token URL uses its own egress check and transport partition; it
  cannot inherit an upstream Connection's custom roots or client identity;
- Connection, catalog, transport, and token-cache keys include revisions or
  local-secret versions so a new invocation cannot silently reuse authority
  from a superseded revision; and
- public/admin DTOs, logs, metrics, errors, and audit events use bounded safe
  metadata rather than secret values, provider locators, raw transport errors,
  DNS answers, or upstream credential challenges.

These controls do not make an alpha deployment production-ready. The operator
still controls trusted configuration, the host and process boundary, egress
allowlists, key files, database and key backups, identity-provider policy,
certificate trust, and audit access. A privileged host/process compromise can
read material while it is in memory. Legacy literal route headers remain a
migration risk. Multi-instance managed-Connection coordination is not provided
by the current SQLite control plane.

Authorization is a decision for an invocation, not a recall mechanism. A call
denied at its first security gate performs no Connection-specific or network
side effects. The admin tool playground also rechecks its live execute
permission, execution ETag, rendered HTTP rule, and Connection/catalog revision
after queueing and before egress. An ordinary proxy or MCP invocation already
authorized and admitted under a snapshot, or bytes already dispatched before a
later policy/Connection change, are not retroactively recalled. New work uses
the new state. This time-of-check/time-of-use boundary should be included in
incident response and revocation planning.

## Safe Security Evidence

Connection security events include stable IDs, revision numbers, action,
bounded reason/outcome categories, latency, and counts where applicable.
Security evidence must not contain secret IDs when they would reveal a binding,
secret values, environment or file locators, key IDs or paths, ciphertext,
nonces, access or refresh tokens, authorization/cookie headers, certificate or
private-key contents, tool arguments/results, raw URLs with queries, resolved
addresses, DNS answers, raw errors, or upstream response bodies/challenges.

See [ADR-0005](docs/adr/0005-production-proxy-data-plane.md) and
[ADR-0006](docs/adr/0006-first-class-connections-and-credentials.md) for the
data-plane and Connection threat models.

## Disclosure Expectations

The maintainers aim to acknowledge vulnerability reports within a few business
days.

Coordinated disclosure is preferred once a fix is available. Please avoid
public disclosure before the maintainers have had a reasonable opportunity to
assess the report and prepare a fix.
