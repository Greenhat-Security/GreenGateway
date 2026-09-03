# ADR-0007: Shared State, High Availability Modes, and the PostgreSQL Trust Boundary

## Status

Accepted (implements the design required by issue #241; the release gate that proves it is `ha-release-gate` in `.github/workflows/ci.yml`, and the boundary of what it proves is "Supported cluster operation" in `docs/deployment/postgres.md`)

## Context

GreenGateway is, today, single-process by construction: SQLite stores opened per component, process-local rate-limit buckets and semaphores, `ArcSwap` policy snapshots with process-local write mutexes, per-process OIDC login state, and a Kubernetes example pinned to `replicas: 1`. That is a defensible single-node product — the SQLite layer is careful (WAL, `synchronous = FULL`, migrations, busy timeouts) — but it is *single-node-first*, and production review said so plainly.

Two failure modes of pretending otherwise are well understood here: putting SQLite on a shared filesystem (corruption, not HA), and scaling replicas without shared state (every limit, cache, revocation, and login silently multiplies by replica count). Neither is a path to HA.

Issue #241 defines what real cluster operation requires. This ADR records the architectural decisions those sixteen PRs implement, so each of them has one place to defer to instead of re-deriving the model.

## Decision

### Two supported deployment modes, operator-selected, one at a time

**Standalone mode** (`STATE_BACKEND=sqlite`, the default and today's behavior): one active gateway process with local files, local SQLite, and process-local enforcement. It remains a fully supported product shape, not a legacy fallback. Fast restart and failover come from durable local storage plus the graceful-drain and lifecycle primitives of #239; it is the right choice for single-instance deployments and for operators who do not want to operate PostgreSQL.

**Cluster mode** (`STATE_BACKEND=postgres`): two or more replicas behind a load balancer, one PostgreSQL primary as the single authority for shared mutable state, security revisions, distributed enforcement, durable events, and singleton-job coordination. Replicas hold immutable compiled snapshots and bounded derived caches only. A replica that cannot prove it is acting on current authoritative security state stops being ready and rejects protected traffic — fail closed, never stale-allow.

There is deliberately no third mode, no hybrid, and no gradual middle ground: a deployment is one or the other, because every correctness argument below is mode-scoped. Mixing modes across replicas of one logical deployment is an unsupported configuration that readiness checks reject via the static-configuration fingerprint.

### Mode selection and re-configuration semantics

Mode is a startup-time, statically-validated setting carried in the environment with all the existing configuration discipline (validated at startup, documented in `.env.example`/`docs/configuration.md`/the Cloudflare forwarding list, never read from a dynamically-built name). It is **not hot-swappable**: it is part of the security-relevant static-configuration fingerprint, because a replica that disagrees with its deployment about where authority lives must not become ready.

Changing mode after first setup is supported as an operator workflow, not a runtime toggle:

- **Standalone to cluster** is a deliberate, one-way, offline import: quiesce control-plane writes, back up everything, migrate, import authoritative rows into the deployment's namespace, verify counts/checksums/ETags, then start one cluster replica and scale out. Idempotent into an empty namespace; never dual-writes.
- **Cluster back to standalone** has no automatic reverse migration, on purpose. The rollback path is: stop cluster replicas and restore the pre-cutover standalone snapshot. The runbook (PR 15) documents exactly when that remains safe — the honest boundary being that events observed by the cluster after cutover are not retrojected into the restored standalone store.

This asymmetry is a security decision, not a convenience gap: a reverse "migration" that reconstructs local authority from shared state would have to decide which replica's view wins, and every such decision is an opportunity for a stale allow.

### One PostgreSQL primary is the trust boundary

All security decisions in cluster mode — revision checks, revocation lookups, token verification state, distributed limits, execution leases, and control-plane mutations — read and write the writable primary. Asynchronous read replicas are never consulted for them. `LISTEN/NOTIFY` is a latency hint; correctness comes from durable revisions and change rows plus periodic reconciliation. No Redis, no second coordinator, no application-level consensus in the first implementation: one consistency domain, one failure domain to reason about.

### Strict per-request revision discipline

A protected request in cluster mode captures one immutable security snapshot, records its revision in audit, and may finish under it. But the snapshot it captures must be *current at request start*: every protected request checks the authoritative security revision, may use a compiled cache only when keyed by that exact revision, and returns a bounded-wait-then-`503` if it cannot reconcile — never a stale allow, and dependency failure is `503`, never `401`/`403`, so that "cannot check" is never confused with "checked and denied".

### Configuration identity is part of the trust model

A deployment carries a stable non-secret `DEPLOYMENT_ID` scoping every row, lock, lease, and notification; every replica carries an instance ID plus a per-boot ID so restarted processes cannot inherit stale ownership; and a security-relevant static-configuration fingerprint (auth, proxies, cookie/exemption, routing, egress, key-generation settings — never secret-derived values) must match for a replica to become ready.

## Consequences

- Standalone mode keeps its current shape and test suite; every PR in the sequence must leave it green and unchanged in observable behavior.
- Cluster mode gains real costs: a PostgreSQL dependency operators must run, back up, and fail over themselves (documented, not delegated); per-request authority checks with explicit blocking budgets (defined in the companion state model); and a migration/compatibility discipline (expand/contract, checksummed, no auto-downgrade).
- The state taxonomy, transaction and ordering rules, failure matrix, leader/fencing semantics, privacy model, and blocking budgets that implement this decision are normative and live in [the HA state model](../architecture/ha-state-model.md); PRs cite rather than restate them.
- ADR-0002 is unchanged: a cluster is still one tenant and one trust domain. Two logical deployments pointing at one database must remain isolated by deployment ID, and that isolation is tested, not assumed.
- Until the multi-replica release gate (PR 16) passes, no documentation anywhere claims supported cluster operation.

## Alternatives considered

- **SQLite on a shared volume with more replicas:** rejected; it converts a durability guarantee into a corruption risk and solves none of the enforcement multiplication.
- **Redis/Valkey as the coordination layer:** rejected for now; it would add a second failure and consistency domain to a security problem, and this project does not take vendor-specific required dependencies. Focused coordination traits may permit another backend later, with PostgreSQL still the sole authority.
- **Single-active with an automatic standby (leader-election-only HA):** a legitimate pattern, but it does not remove the need for shared authoritative state (the standby must not serve stale policy or revoked tokens after failover), so it is subsumed: standalone mode provides single-active operation with durable local state, and anything beyond it lands in cluster mode where the real shared-state work lives.
- **Multi-writer/multi-region active-active PostgreSQL:** rejected as a non-goal of the first implementation; one writable primary.
