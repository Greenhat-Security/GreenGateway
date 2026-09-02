# HA State Model — taxonomy, transactions, failure semantics, budgets

This document is the normative companion to [ADR-0007](../adr/0007-shared-state-and-ha-modes.md). It defines the state taxonomy, transaction and ordering rules, failure matrix, leader/fencing semantics, privacy model, and blocking budgets for issue #241's implementation PRs. Each PR cites this document rather than restating it; changes here are review-blocking for any PR that depends on the changed section.

## 1. State taxonomy

Every piece of mutable state is classified into exactly one row. A PR that introduces new shared state must add it here first.

| State | Standalone authority | Cluster authority | Consistency requirement |
| --- | --- | --- | --- |
| Policy document, ETag, history | Local file + compiled snapshot + SQLite history | Versioned PostgreSQL document; CAS by revision/ETag; document + history + audit outbox commit atomically | Linearizable; strict per-request revision |
| Tool definitions (and Connections per #240) | Local file/process snapshot | Same versioned CAS/revision/outbox contract as policy | Linearizable; strict per-request revision |
| Service tokens | SQLite + per-process caches | PostgreSQL rows; atomic create/rotate/revoke; authoritative check on every request | Revocation effective on next request cluster-wide |
| JWT revocations | Production no-op store today | PostgreSQL rows keyed by normalized issuer + hashed `jti`, with expiry | Required-check failure is `503` |
| OIDC pending login (state/nonce/PKCE) | Process-local map in standalone mode (sticky sessions); PostgreSQL in cluster mode since PR 9 | Hashed lookup + AEAD-encrypted fields; single atomic consume; DB-time expiry and quotas | Exactly one callback consumes a login, on any replica |
| Rate-limit buckets | Process-local bounded store (per #338) | Atomic PostgreSQL operation on database time; HMAC'd keys; bounded cardinality | One burst of N permits N across the cluster |
| Tool/global concurrency | Process-local semaphores | PostgreSQL leases: expiry, renewal, cancellation, fencing | A stale holder cannot commit after a successor fences |
| Audit events | stdout/file/SQLite sinks | Idempotent PostgreSQL event log; commit-safe durable cursor | At-least-once with exactly-once storage via `event_id` |
| Discovery/principals/signals/suggestions | Local working sets + SQLite snapshots | Idempotent observation ingestion; one checkpointed, fenced global projector | Replays never inflate counts; projector failover loses nothing |
| Membership/revisions/job ownership | None | PostgreSQL heartbeat, fingerprint, revision acknowledgement, advisory locks, fencing tokens | Unfenced singleton work is a defect |
| JWKS/introspection caches, upstream health/clients/pools | Process-local | Remain process-local, bounded, with explicit freshness contracts | Never shared; staleness bounds are configuration |

Classification rule: if incorrect or stale values for a field could produce a stale **allow** (authorization, revocation, replay, admission, limit), the field is *security state* and follows the strict revision discipline. Everything else is *observational state* and may lag visibly without blocking protected traffic.

## 2. Transactions, ordering, and revisions

1. **Control-plane mutations** (policy, tools, connections, token lifecycle, revocation, review/signal/suggestion transitions) run as one transaction: lock/read expected revision → reject stale `If-Match` with `412` → fully validate the candidate → write the immutable new version → advance the active pointer and the monotonic **security revision** → write history/lifecycle rows → write the audit outbox row → commit. If any step fails, nothing commits; two writers with the same expected revision produce exactly one winner.
2. **A mutation is not successful unless its audit is durable.** Outbox insertion failure rolls back the mutation.
3. **Read path:** every protected request reads the current security revision from the primary after the request starts; a compiled snapshot is usable only keyed by that exact revision; un-reconciled means bounded wait then `503`. The request records the revision it served under in audit.
4. **Notifications are hints.** `LISTEN/NOTIFY` reduces latency; durable revision/change rows plus periodic reconciliation provide correctness, including across listener loss and replica restart.
5. **Database time is authoritative** for expiry, retention, rate math, leases, heartbeats, and fencing. Wall-clock skew is monitored (JWT validation still uses it) but never decides shared-state expiry.
6. **Audit cursor ordering must be commit-safe.** A bare sequence assigned pre-commit can be skipped by a late-abort; the cursor design (serialized post-commit sequencing or equivalent) must prove no permanent gap under concurrent and aborted transactions.
7. **Suggestion acceptance is one transaction**: the still-open suggestion transitions, exactly one policy rule/version is added, history appends, and both lifecycle audit records commit together. No partial success exists.

## 3. Failure semantics (normative matrix)

| Condition | Readiness | Protected request / admin write | Recovery |
| --- | --- | --- | --- |
| Invalid/missing cluster config; dirty/incompatible schema; fingerprint mismatch | Never ready; startup fails where deterministic | No serving | Operator correction; no fallback |
| PostgreSQL unavailable at startup | Live-not-ready for transient failure, or exit per bounded startup policy | No protected serving | Bounded-backoff retry |
| Primary lost / read-only / pool exhausted at runtime | Not ready by the authority deadline | `503`, zero upstream attempts, no partial mutation | Reconnect, reconcile exact revision, then ready |
| Notification lost / listener reconnect | Ready while per-request revision checks still succeed | Correctness unchanged; polling catches up | Durable reconciliation |
| New security revision not locally compiled | Not ready for affected protected work | Bounded reconcile wait, then `503`; never stale allow | Fetch, validate, atomic swap |
| Non-security projector lag/failure | Degraded; unrelated protected traffic unaffected | Discovery views show lag | Fenced leader resumes from checkpoint |
| Audit outbox failure during a control mutation | May remain ready | Mutation rolls back; `503` | Retry the whole mutation with the same precondition |
| Data-plane audit queue saturation | Degraded/observable; `strict` mode becomes unready | Per configured mode; never unbounded or silent | Retry/drain; alert on age/drop |
| Leader connection/lease lost | Replica may stay request-ready if no security prerequisite is affected | Stale job stops before its fence can be superseded | Successor elected with jitter |
| Replica partitioned from authority | Not ready; load balancer removes it | `503`, not stale local dispatch | Full revision/config/lease reconciliation |
| Rolling version/schema incompatibility | Incompatible replica never ready | Compatible replicas continue | Complete expand/contract sequence |
| Shutdown/drain | Not ready immediately | No new admissions; in-flight contract per #239 | Bounded flush/join and exit |

Two rows deserve emphasis because they are the ones reviewers will probe hardest: dependency failure is always `503` (never `401`/`403`, so "cannot check" is never laundered into "checked and denied"), and a partitioned replica never dispatches under a stale allow state — it stops.

## 4. Leadership, fencing, and singleton work

- No leader serves requests or control-plane writes; PostgreSQL transactions and CAS coordinate those. Leadership exists only for singleton maintenance jobs (migration, retention/partitioning, pending-login/revocation/limiter cleanup, discovery projection/compaction, scheduled suggestion generation).
- Short database-only work uses transaction-scoped advisory locks. Long jobs own a lease row with a monotonically increasing **fencing token**, renewed on database time; results are accepted only while owner-and-fence still match.
- Losing the dedicated session or the lease cancels local work *before* the lease can be reclaimed; a crashed holder's lease expires on database time; a stale holder's late write is rejected by the fence.
- Projector crash between read and commit yields neither loss nor double application: the successor resumes from the committed checkpoint, and observation ingestion is idempotent by event ID.
- Endpoint cardinality admission/eviction is global and fenced: one replica cannot evict an endpoint another replica's traffic still evidences.

## 5. Privacy model

- Notifications carry only deployment/resource identifiers and revisions — never payloads, principals, tokens, or paths.
- Rate-limit and quota keys are stored as HMAC digests, never raw tokens, IPs, principals, cookies, OIDC state, or JTIs.
- Plaintext service tokens appear exactly once (create/rotate response) and never enter logs, audit, traces, DB logs, or errors. OIDC state is stored as a hash; the PKCE verifier and nonce are AEAD-encrypted under operator-supplied keys with deployment/row/purpose bound as associated data.
- The DSN, database user/host/name, and secret-derived fingerprint values never appear in `Debug`, status, metrics, panics, or HTTP errors. SQL parameters never appear in error classes.
- No metric is labelled with instance IDs, principals, routes/hosts, token IDs, URLs, query text, or error strings.

## 6. Blocking budgets

These budgets bound what a protected request may spend talking to the authority. They are targets the release gate (PR 16) measures; a PR that cannot meet its budget redesigns, not re-baselines.

| Operation | Budget (p99, per request, warm pool) | Notes |
| --- | --- | --- |
| Security-revision check (read primary) | ≤ 5 ms | One round statement, prepared; this is the floor added to every protected request |
| Service-token authoritative check | ≤ 8 ms | May combine with the revision check in one round |
| Revocation lookup | ≤ 5 ms | Batched per issuer where possible |
| Distributed rate-limit decision | ≤ 8 ms | One atomic statement per lane; policy lane may add one more |
| Lease acquire/renew (tool admission) | ≤ 10 ms acquire; renew off the critical path where possible | Queue wait is admission, not blocking |
| Reconcile wait after a new revision | ≤ 250 ms bounded, then `503` | Compile happens off the request path; the wait is for fetch+validate+swap |
| Audit enqueue (data-plane, async batches) | 0 ms on the request path | Bounded queue; backpressure/strictness per the failure matrix |
| Control-plane mutation (admin write) | ≤ 500 ms p99 including validation and outbox | Not request-path |
| Connection acquire (pool, warm) | ≤ 50 ms | Pool sizing documented as replicas × per-replica pools + headroom |

Aggregate rule: the authority adds no more than **25 ms p99** to a protected request's pre-upstream critical path in cluster mode, and **0 ms** in standalone mode.

## 7. Compatibility

- Checked-in, ordered, checksummed migrations; expand/contract so version N and N+1 binaries coexist; no automatic downgrade; a dirty, unknown, or too-new schema never serves.
- One logical deployment per database. Every authoritative pointer and revision counter in the schema is a singleton by construction, so a database holds exactly one deployment's state; the first boot binds the database to its `DEPLOYMENT_ID` (`greengateway.deployment_binding`) and every later boot and one-shot command refuses another. The deployment ID remains the domain separator for every digest, sealed envelope, and lock namespace, so state restored under another ID cannot be mistaken for it.
- ADR-0002 holds: one cluster is one tenant and one trust domain. Multi-region active/active and multiple writable primaries are non-goals.
