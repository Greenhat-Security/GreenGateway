# ADR-0002: Single-Tenant Per Deployment

## Status

Accepted. Amended by issue #241 to state how the decision holds in cluster mode; the decision itself is unchanged.

## Context

The Principal and identity model carries organization and role claims from JWTs or IdP tokens. It would be easy to assume this means GreenGateway supports multi-tenant SaaS-style deployment, with one gateway instance serving multiple isolated customer organizations and providing data and policy isolation between them.

That is a much larger and harder feature than what is currently being built. It would require isolation guarantees, per-tenant rate limits and quotas, tenant-scoped storage, and related design and testing work. Conflating those concerns with the current identity model leads to incorrectly scoped policy and identity work.

Issue #241 adds a second deployment mode in which shared mutable state lives in PostgreSQL and several gateway replicas serve at once. That introduces a second thing that could be mistaken for multi-tenancy — a schema with a `DEPLOYMENT_ID` scoping its rows looks, at a glance, like a tenant column — and so this ADR now says explicitly what that identifier is and is not.

## Decision

GreenGateway is **single-tenant per deployment**. One running deployment of GreenGateway protects one trust domain: one operator's backend or backends.

Organization and role claims extracted from identity tokens are **rule-matching inputs**. For example, an operator can write a rule that allows one role and denies another. They are not **isolation boundaries**. GreenGateway does not promise to keep two different customer organizations' data or traffic cryptographically or architecturally separated within one deployment.

An operator who needs to serve genuinely separate trust domains runs separate GreenGateway deployments.

### Cluster mode: one primary is the authority, and it is still one tenant

In cluster mode (`STATE_BACKEND=postgres`) a deployment is two or more replicas behind a load balancer with one writable PostgreSQL primary as the single authority for shared mutable state. The unit of the decision above moves from "one process" to "one deployment", and nothing else about it changes.

Specifically:

- **One deployment, one database, one primary.** Every authoritative pointer and revision counter in the schema is a singleton, so a database holds exactly one deployment's state. The first boot records the deployment's `DEPLOYMENT_ID` in `greengateway.deployment_binding`, and every later boot and every one-shot command refuses a database bound to another.
- **`DEPLOYMENT_ID` is not a tenant key.** It is a deployment identifier: a domain separator for digests, sealed envelopes, and lock namespaces, and the thing that makes it an error for two deployments to share a database. It does not partition rows within a database into isolated groups, it is not derived from any caller's identity, and no request-time authorization decision consults it. Two deployments do not coexist in one database; they are refused.
- **Replicas are not tenants either.** Every replica of one deployment serves the same trust domain under the same policy, from the same authority. A replica that disagrees with its deployment about the security-relevant static configuration does not serve a variant — it refuses to become ready.
- **Multi-tenancy was not smuggled in by the shared database.** A database is not an isolation mechanism; it is shared state for one trust domain. Making that state shared between replicas of one deployment says nothing about whether two organizations can safely share a deployment, and the answer to that is still no.

An operator serving separate trust domains runs separate deployments: separate `DEPLOYMENT_ID`s, separate databases, separate replicas. That the deployments could sit on one PostgreSQL *server* in separate databases is an operational convenience with the usual server-level caveats (one failure domain, shared `max_connections`, one backup target); it is not tenancy, and it does not make the two deployments one.

### Standalone versus cluster: what each mode provides

Both are supported product shapes, chosen at startup, one at a time. Standalone is the default and remains the right choice for a single instance. Neither is a subset of the other in the way people expect: cluster mode gains shared enforcement and loses every local-authority feature.

| | Standalone (`STATE_BACKEND=sqlite`) | Cluster (`STATE_BACKEND=postgres`) |
| --- | --- | --- |
| Tenancy | one trust domain | one trust domain |
| Replicas serving at once | one | two or more |
| Authority for shared mutable state | local files and SQLite in that process | one writable PostgreSQL primary |
| Policy authority | `POLICY_FILE`, written in place | versioned control plane in the database; no writable `POLICY_FILE` exists |
| Tools and Connections authority | `TOOLS_FILE`, connections SQLite | versioned control planes in the database |
| Enforcement scope of rate limits and concurrency | process-local | deployment-wide, at the authority |
| Audit record | local SQLite sink | durable event store with a cross-replica stream |
| Discovery | per-process aggregator over local traffic | one fenced projector over the durable audit stream, identical on every replica |
| Singleton housekeeping | in-process | one leased leader, fenced on the database clock |
| Credential secrets | external providers, or a local-secret keyring | external providers only; the local keyring is rejected |
| Principal directory | local SQLite | none — cluster mode has no principal directory |
| Behaviour when the authority cannot be reached | not applicable | fail closed: `503`, never a stale allow, never `401`/`403` |
| Schema migrations | not applicable | checksummed ledger, applied by a migration job under a DDL-capable role; serving replicas validate only |
| Support status | fully supported | experimental until the #241 release gate passes |

Moving between them is an operator workflow, not a runtime toggle. Standalone to cluster is a deliberate, one-way, offline, verified import (`gateway import-standalone`). Cluster back to standalone has no automatic reverse migration on purpose: reconstructing local authority from shared state would have to decide which replica's view wins, and every such decision is an opportunity for a stale allow. The rollback path is to restore the pre-cutover standalone snapshot, and the point after which that stops being free is documented in `docs/deployment/rollback-boundary.md`.

### Explicitly unsupported configurations

Each of the following is rejected, not merely discouraged. They are listed because each one is a plausible-sounding thing to try, and each one silently breaks the single-tenant, single-authority model rather than failing in an obvious way.

- **Two logical deployments sharing one database.** Every authoritative pointer in the schema is a singleton. The deployment binding refuses the second deployment; it is not an isolation mechanism that would make sharing safe.
- **One deployment writing to two databases.** There is one authority. Two writable primaries under one `DEPLOYMENT_ID` is split brain, and nothing in the gateway detects or reconciles it.
- **Mixed-mode replicas of one deployment.** A `STATE_BACKEND=sqlite` replica beside a `STATE_BACKEND=postgres` replica is two deployments wearing one name. The mode is part of the security-relevant static-configuration fingerprint, and a replica that disagrees with a live member cannot become ready.
- **Local authority alongside cluster mode.** `POLICY_FILE`, `TOOLS_FILE`, any `*_SQLITE_PATH`, or `CONNECTION_LOCAL_SECRET_KEYRING` set with `STATE_BACKEND=postgres` is refused at startup. In cluster mode the database is the single authority, and a local store beside it is a fallback path, not a leftover.
- **Cluster-only settings in standalone mode.** `DEPLOYMENT_ID`, `DATABASE_URL_FILE`, `DATABASE_TLS_CA_FILE`, the `CLUSTER_*` settings and the `DISCOVERY_PROJECTOR_*` settings are refused with `STATE_BACKEND=sqlite`. Material a mode will never read is rejected rather than ignored.
- **SQLite on a shared filesystem with several replicas.** This is not a supported HA shape and never will be. It converts a durability guarantee into a corruption risk and solves none of the enforcement multiplication.
- **Pointing the gateway at a read replica, a read endpoint, or a transaction-pooling connection pooler.** Security decisions read the writable primary. A lagging replica answers with stale revocations, stale policy and stale limits, each of which is a stale allow; transaction pooling breaks the session-scoped advisory locks and connection-time session settings the correctness argument depends on.
- **Using organization or role claims as an isolation boundary in either mode.** They are rule-matching inputs. This is the original decision, and cluster mode does not change it.

## Consequences

Policy, identity, and storage design can stay simple. There is no per-tenant partitioning and no cross-tenant isolation guarantee to design or test for.

Cluster mode's shared schema is scoped by deployment, not by tenant, and the isolation it provides is between *deployments* — enforced by refusal, and tested rather than assumed. It provides no isolation between organizations within one deployment, and none is claimed.

The mode matrix above is a scoping statement as much as a feature list: a capability that exists in one mode and not the other is a deliberate consequence of where authority lives, not a backlog item, and a request to have a local authority in cluster mode is a request to leave this ADR's model.

If true multi-tenant SaaS hosting of GreenGateway becomes a goal later, that is a significant separate effort warranting its own ADR that would supersede or amend this one. It is not assumed as a natural extension of today's organization and role fields, and it is not something cluster mode has quietly delivered.

## Related

- [ADR-0007: Shared State, High Availability Modes, and the PostgreSQL Trust Boundary](0007-shared-state-and-ha-modes.md) — the mode selection, the one-primary trust boundary, and the per-request revision discipline this ADR's cluster-mode wording rests on.
- [The PostgreSQL deployment guide](../deployment/postgres.md) and the runbooks beside it.
