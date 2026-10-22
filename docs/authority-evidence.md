# Durable authority-change evidence inventory and contract

Part of [#425](https://github.com/Greenhat-Security/GreenGateway/issues/425), PR 1,
the first two PR 2 slices (PostgreSQL Connection deletion evidence; service-token
rotate/revoke and JWT revocation evidence), the keyed safe-reference derivation
([Keyed safe references](#keyed-safe-references)) and PR 3's durable delivery
([Durable delivery](#durable-delivery)).
Reviewed source: `146d5063801270fe23852fb6caa946862fb4390f`.

This inventory identifies existing atomic records and the work needed for required
authority-change evidence. PR 1 added the inventory and the proposed event
contract. The first PR 2 slice adds migration 16's
`greengateway.connection_change_evidence`, written by PostgreSQL Connection
deletes. The second adds migration 18's `greengateway.service_token_change_evidence`
and `greengateway.jwt_revocation_evidence`, written by PostgreSQL token rotate/revoke
and JWT revokes, and the same token evidence table inside the standalone SQLite token
database. PR 3 adds migration 21's authority-event journal, which every PostgreSQL
producer of those three evidence tables appends to in the same transaction, and an
opt-in dispatcher that delivers it behind a persisted cursor. None of them
implements or enables the authority-evidence required-durability mode or a standalone
revision ledger, and no row is qualified for that future mode. Storage selection is
unchanged.

`AUDIT_DURABILITY=required`, the default since the request-path slice of this issue,
is a different and narrower guarantee: the authentication and authorization stages
wait for their own decision records to commit to the audit store of record, and
refuse the request with `503 audit_unavailable` when they cannot (see
[the configuration reference](configuration.md#audit_durability)). It does not
make any authority-change row below qualified, which is why the inventory's
`required_durability_mode` stays `not_implemented`: an admin mutation's evidence is
still its own transaction's rows, its journal entry, or the ordinary audit event its
handler emits after the commit.

Run the executable inventory and proposed event-contract tests with the pinned
Node version from `build-tools.json`:

```sh
node scripts/check-authority-evidence.mjs
node --test scripts/test-authority-evidence.mjs
```

The existing CI `supply-chain` job runs both commands. The checker covers 31
operations in both storage modes, checks live source/test anchors, rejects
missing/duplicate dispositions, and discovers unreviewed mutation endpoints in
the four reviewed admin modules. It checks source traceability and contract
shape, not transaction behavior. Adding a command, scheduler or storage writer
outside those modules still requires explicit inventory review. Tests cited in
the inventory are existing regression anchors, not a statement that they were
run by the inventory checker.

## Coverage and existing foundations

The complete, machine-readable
[inventory](authority-evidence-inventory.json) gives each operation's transaction,
durable record, actor linkage, operation/result/revision identity, delivery
boundary, follow-up and concrete test entry points. Grouped operations share the
described storage boundary; each operation/mode pair occurs exactly once.
`standalone` means the existing SQLite/file configuration, including optional
or unconfigured individual stores.

| Authority | Already atomic in PostgreSQL | Remaining evidence work |
| --- | --- | --- |
| Policy publish, rollback, rule edits and suggestion acceptance | Immutable document/history, actor subject, action/diff, active pointer, shared revision and outbox; suggestion acceptance composes its own state in the same transaction | Stable operation/event identity, scoped actor context, durable delivery |
| Tools publication | Shared document transaction plus name reservations | Same metadata/delivery extension as policy |
| Connection and credential binding changes | Record, bindings, immutable version, shared revision and outbox | Actor/history must survive Connection deletion; safe per-operation metadata and delivery |
| Connection deletion | Outbox tombstone with prior version and shared revision, plus a non-cascading `connection_change_evidence` row (actor, action, event/operation UUIDs, prior version, the tombstone's shared revision, database-clock time) and its journal row in the same transaction; delivered with keyed safe references since PR 3 | Issuer/auth mode and a caller-bound operation identity, without which the delivered record cannot be `authority_event.v1` |
| Managed MCP/OpenAPI catalog and overlay publication | Catalog/overlay CAS, entries, dependencies, reservations, revision and outbox | Current actor rows are replaced or cascaded; retain per-change evidence |
| Service-token issue | Token row with creator, row/shared revisions and outbox | Creation retains only `created_by`; no issue evidence row, operation identity or delivery |
| Service-token rotate/revoke | Token change, row/shared revisions and outbox, plus a non-cascading `service_token_change_evidence` row (actor, action, event/operation UUIDs, prior/new row revision, the outbox row's shared revision, database-clock time) in the same transaction; repeated revoke and refused rotate write none. Standalone writes the same evidence in the token database's own transaction. In PostgreSQL the change also journals its evidence and is delivered since PR 3 | Issuer/auth mode and a caller-bound operation identity; standalone evidence is not delivered |
| JWT revocation | Scoped JTI digest, actor row, shared revision and outbox, plus one non-cascading `jwt_revocation_evidence` row per effective revoke (actor, JTI digest, resulting expiry, shared revision) that extension, reactivation and expiry cleanup never rewrite, journaled in the same transaction and delivered since PR 3 | CLI actor is system provenance, not a named human; no actor kind or issuer/auth mode |
| Admin session grant/withdrawal (#424) | With `ADMIN_SESSION_MODE=cluster_postgres`, the session row and one non-cascading `admin_session_evidence` row (event/operation UUIDs, session ID, action, reason, subject and issuer, absolute deadline, database-clock time) commit together for each grant and each withdrawal; a replacement's withdrawal and grant share one operation ID | Actor kind/auth mode, keyed safe actor reference, a session revision axis, and delivery: these rows are not journaled (see [Durable delivery](#durable-delivery)). Standalone sessions are process-local memory with no durable record and stay `unsupported_future_operation` |

These foundations are already sufficient for their **existing atomic change-record
purpose**. The inventory uses `missing_metadata` and `missing_delivery` for
remaining requirements of the proposed event contract. It does not label all
control-plane writes lossy or ask for a second reconciliation outbox.
`already_sufficient` is reserved for a fully qualified row; no current row
has demonstrated all required-mode metadata and delivery requirements.

Important standalone and operator boundaries:

- Policy file persistence, runtime reload and optional SQLite history are
  separate steps. A history append can fail after the mutation succeeds, as the
  existing API regression tests explicitly require. File watcher/SIGHUP
  activation has no common ledger transaction. These operations stay
  `unsupported_future_operation` for required durability until #242 lands.
- Tools registration writes a file and installs registry state. File
  watcher/SIGHUP reload and legacy MCP rediscovery can also change its published
  contents. Include those paths in #242 integration; they have no atomic
  publication/evidence record.
- Connections, local secrets and service tokens each have an owning SQLite
  store. Required evidence must join that same store's mutation transaction.
  A separate audit SQLite database is not an atomic alternative. Service-token
  rotate/revoke now does: the token store writes its evidence row in the same
  IMMEDIATE transaction as the change. `import-standalone` does not carry those
  rows; the cluster's evidence starts with its first change.
- Local-secret CRUD/rotation and master-key re-encryption are standalone-only.
  PostgreSQL configuration rejects the local keyring. External secret providers
  own their rotations; a gateway transaction cannot certify an independent
  provider write. Gateway credential **binding** changes are separate rows.
- Startup configuration activation has no whole-configuration revision ledger.
  A unified, redacted configuration-export/release operation is not shipped.
  Canonical projections used internally by `import-standalone` are not such
  an export API and contain state that must never enter authority events.
- Offline import is shipped and resumable **by section**, with policy/tools
  sections reusing existing commit paths. Its report is printed to stdout.
  Token/Connection import intentionally does not replay prior outbox entries.
  Whole-import evidence therefore needs section-level ownership, not a claim
  that the entire import/report is one transaction.

Status observations, enum-source value caching, token verification/last-use
updates, principal/discovery projections and expired-row cleanup do not newly
grant authority. They are outside the operation matrix; their cleanup can still
affect evidence retention. The inventory includes JWT expiry and Connection
cascade consequences explicitly.

Admin sessions (#424) are in the matrix as `admin_session.grant` and
`admin_session.withdraw`. In standalone mode, `ADMIN_SESSION_MODE=standalone_memory`
keeps each session in a bounded process-local map: a grant follows a successful
cookie completion, and withdrawal is logout, the absolute or idle deadline, a
rejected access token, an identity change or a restart. Nothing about it is
durable, and the `admin_login.transaction` event the handler emits after a grant
or logout carries no actor or session identity; implicit withdrawals emit
nothing. That row stays `unsupported_future_operation`: required-durability mode
must refuse in-memory sessions rather than relabel that event durable.

In cluster mode, `ADMIN_SESSION_MODE=cluster_postgres` ([ADR-0009](adr/0009-shared-admin-sessions.md))
is the durable session authority, and it ships with its own transactional
evidence (migration 19). Every grant writes the session row and an
`admin_session_evidence` row in one statement inside the grant's transaction;
every withdrawal (logout by cookie or login binding, replacement by a new
sign-in, a provider rejection or identity change, and expiry when the bounded
prune removes the row) deletes the row and inserts its evidence in one
statement. An evidence failure rolls the change back and answers `503`. The
rows carry the session's random ID, never the cookie, CSRF token, binding or
access token, and an expiry's commit time is the prune's, not the deadline's.
The row is `missing_metadata` and `missing_delivery`: it has no actor kind or
auth mode, no keyed safe actor reference and no session revision axis, and
nothing dispatches the rows yet.

## Proposed authority event v1

[The closed JSON schema](schemas/authority_event.v1.schema.json) and the checker
define a **proposed** safe projection. Current `security_outbox` rows,
`connection_change_evidence` rows and `audit_event.v0` events do not already
satisfy this schema, and neither do migration 18's `service_token_change_evidence`
and `jwt_revocation_evidence` rows, migration 19's `admin_session_evidence` rows or
the standalone token evidence rows: the evidence rows hold the internal actor
ID, not a keyed safe reference, and no `authority_id`. Since PR 3 the dispatcher
delivers the journaled evidence with keyed references under a persisted
`authority_id`, but as `authority_event_delivery.v1` ([Durable delivery](#durable-delivery)),
not as this schema: the evidence records neither the actor's issuer nor its auth
mode, and a v1 event cannot be produced faithfully without both.

Revision transitions are operation-specific. Resource creation (`connection.create`,
`secret.create`, `service_token.issue`, `admin_session.grant`) has no prior revision; replacement,
rotation, revocation and edits to existing authority require one. In particular,
creating a policy rule advances its containing policy rather than creating a new
policy authority. Publication and activation may initialize or advance a snapshot.
Deletion (including `admin_session.withdraw`) requires a positive prior revision and a
null successor, export binds
an unchanged revision, and re-encryption uses the maintenance shape. The checker
assigns every operation exactly one transition contract.

| Field | Contract |
| --- | --- |
| `schema_version` | Exact `authority_event.v1`; future changes require explicit compatibility handling |
| `authority_id` | Persisted opaque UUID for the evidence authority; preserved through restart/restore, deliberately re-namespaced for an independent clone |
| `event_id` | Generated UUID stored with the committed change; never regenerate on delivery retry |
| `operation_id` | Persisted UUID binding one authenticated logical operation and its authoritative result; repeated delivery or an identical reconciled request keeps it |
| `operation` / `result` | Closed operation code; `committed` means the mutation or export-evidence record committed. Failed CAS, rollback, denial and ineffective no-op do not create success records |
| `committed_at` | Store-authored UTC timestamp retained unchanged across delivery; transaction acceptance time, not a claim to measure the physical instant of COMMIT |
| `actor` | Principal/system kind, safe subject/issuer references and known auth mode (including client certificates); a CLI system actor must not masquerade as an authenticated human |
| `resource` | Closed resource kind plus safe, stable opaque reference; no raw secret IDs or binding identifiers |
| `revision` | Named revision axis, previous/new revision, and optional shared security revision, encoded as decimal strings to preserve exact 64-bit values |

Safe references are 64-character lowercase hexadecimal pseudonyms, **not**
arbitrary hashes of input payloads. Producers must use the domain-separated,
authority-scoped keyed derivation described under
[Keyed safe references](#keyed-safe-references) for principal and sensitive
resource correlation; a schema cannot prove that a digest was safely derived. That
derivation, its key source and its rotation and backup policy are implemented and
tested, and the dispatcher derives every delivered reference through it. Non-sensitive
identities may also use the same reference format for one closed projection.

The operation record must bind authenticated actor, operation, payload digest and
conditional revision/ETag tuple in the owning transaction. The schema is the
downstream safe event, not the whole internal operation/idempotency record.
A retry with the same operation ID and different input must conflict. An
ambiguous transport response must be resolved from authoritative identity/state;
it must not imply rollback or cause a blind second mutation.

Each revision axis has explicit semantics. Connection/secret deletion projects
`after: null` with its previous revision; preserve the existing outbox's
`to_version=0` tombstone unchanged. Overlay removal advances the catalog
revision rather than deleting the Connection. Master-key re-encryption uses
`maintenance` with null semantic revisions and never fabricates a credential
change. JWT revocation should use the committed shared revision for its event
axis; the current outbox's constant `to_version=1` is not a JWT version chain.
The event validator checks these mappings, closed shapes and monotonic
transitions. Configuration export instead binds an unchanged existing revision
(`before` equals `after`): it accepts durable export evidence before artifact
release and never invents a configuration mutation. Its committed result does
not claim that a client received the artifact. The internal operation record
must bind the redacted artifact digest before release.

The checker validates the entire schema definition before inspecting events,
including branches and properties absent from a given event. All objects reject
unknown fields. There is no free-form payload, message, error,
URL, header, policy document or credentials field. Tests reject secret/token,
ciphertext, nonce, provider/key locator and raw-response field injections at
every object boundary. They also reject malformed categories, actor modes,
timestamps, imprecise numeric revisions and invalid transitions. These tests do
not prove runtime redaction; future producer tests must construct events from
real safe mutation inputs with synthetic sensitive markers and inspect stored
records, logs and metrics.

## Keyed safe references

`gateway/src/authority_events/pseudonym.rs` derives the `subject_ref`, `issuer_ref`
and `resource.ref` values of the proposed event, and the `actor.recorded_ref` and
`resource.ref` values the dispatcher delivers today. Its runtime caller is the
authority-event dispatcher: a cluster replica with `AUTHORITY_EVENT_SINK` set
resolves the keyring named by `AUTHORITY_PSEUDONYM_KEY_ALIAS` at startup and derives
each delivered reference at delivery time. No stored record carries a reference: the
journal and the evidence hold identifiers, and references exist only in what is
delivered.

### Derivation

A reference is HMAC-SHA256 under the authority's pseudonym key, laid out as 64
lowercase hexadecimal characters so it matches the schema's `^[0-9a-f]{64}$`:

- **Key ID** (first 8 characters): the leftmost 4 bytes of HMAC-SHA256 under the key
  over the framed label `greengateway.authority_pseudonym.key_id.v1`. It depends on
  the key alone, so replicas holding the same key agree on it without configuration,
  and after a rotation it says which key made a reference. It reveals nothing about
  the key.
- **Tag** (remaining 56 characters): the leftmost 28 bytes (224 bits) of HMAC-SHA256
  under the same key over the framed derivation input.

Every field is framed as an 8-byte big-endian length followed by its bytes, so no
identifier, whatever bytes it contains, can run into the next. The derivation input
is the label `greengateway.authority_pseudonym.v1`, the 16 bytes of the
`authority_id`, the domain label, the component count, then each component:

| Domain label | Components |
| --- | --- |
| `actor.subject` | Exactly two: the canonical issuer, then the subject. A subject is never referenced without the issuer that vouched for it, as `Principal` and caller assertions already scope it |
| `actor.issuer` | Exactly one: the canonical issuer |
| `actor.recorded` | Exactly one: an actor identifier exactly as an evidence row recorded it, with no issuer. Migrations 16 and 18 record only the acting principal's subject, or a command's fixed system label (`operator:revoke-jwt`), so this is how the dispatcher names their actors. It is its own domain, so it never yields the reference `actor.subject` gives the same subject |
| `resource.<kind>` for each schema `resource.kind` | One to four: the resource identifier, optionally preceded by the identifiers of the resources that own it |

A component is the identifier's canonical text exactly as its store keeps it, at most
4,096 bytes (the largest subject or issuer a principal may carry) and never empty.
The same identifier in two domains, under two authority IDs (for example, a clone
deliberately re-namespaced from its source) or under two keys gives unrelated
references. The labels and the framing are fixed for v1: changing either would
orphan every committed reference, and a unit test recomputes the construction
from this description to catch that. A test also keeps the resource domains equal
to the schema's `resource.kind` enum.

Without the key a reference can only be compared with other references. With it, a
guessed identity can be confirmed against any reference the key produced. That is
why the key is held like a credential and never leaves the gateway, and why a plain
digest was rejected: subjects, Connection IDs and token IDs are guessable.

### Key source

The key is resolved through the existing secret providers under the dedicated
`authority_pseudonym_key` secret purpose: an operator environment or file alias,
Vault KV v2, GCP Secret Manager, Azure Key Vault, AWS Secrets Manager or Kubernetes
Secrets. The encrypted local store can neither hold it (a local create under the
purpose is refused before anything is written) nor resolve it (a local alias
resolves only under the purpose it was stored with). The key is never written to
PostgreSQL or SQLite, so a database reader or a database backup never holds it.
The Connection admin API does not list the purpose among an alias's compatible
purposes, because no Connection field resolves it.

The material is exactly 64 hexadecimal characters encoding 32 random bytes, with
no trailing newline. The purpose's byte bound is that exact length, so a
newline-terminated file is refused rather than trimmed. Generate it inside the
secret provider or a private staging directory, for example
`(umask 077 && printf '%s' "$(openssl rand -hex 32)" > pseudonym.key)`, and never
print or commit it. Material resolved under any other purpose, of any other length, with
non-hexadecimal characters, or with every byte equal (a placeholder) is refused.
Every resolution or parse failure is fatal: there is no unkeyed mode, no fallback
key, and no key generated on the fly.

### Rotation: a dual-key verify window

A keyring holds the **current** key, which derives every new reference, and at most
one **previous** key, which only verifies. The two must be different keys (their
key IDs must differ) and different aliases.

1. Provision a new key under a new alias. Make it current and the old key previous
   on every replica of the authority.
2. From then on, new events carry references under the new key ID. References in
   committed evidence are never rewritten.
3. During the window the gateway recognises a reference made under either key from
   the identity it names, comparing tags in constant time. Downstream consumers
   without the key see a new reference for the same identity: rotation
   deliberately breaks linkability at the boundary, and the key ID change shows
   where it happened.
4. Close the window by removing the previous key. Its references stay valid opaque
   identifiers, but the gateway can no longer recompute or match them from an
   identity.

Keep the window open for as long as pre-rotation evidence must still be matched
to live identities, such as an open investigation or the period over which an
event consumer correlates. A second rotation inside a window retires the oldest
key. On suspected key compromise, rotate at once. Rotation limits future exposure
only: whoever holds a compromised key can still confirm guessed identities against
every reference that key produced, and evidence already delivered cannot be
recalled.

### Backup

- Back up the current key, and the previous key for as long as its window is open,
  in the secret provider on the same schedule and with the same protection as the
  gateway's other secrets. Never store it with the database backup, in version
  control, or in an event stream.
- Decide explicitly whether to escrow a retired key once its window closes. By
  default, destroy it once no evidence still needs matching. An escrowed key keeps
  every reference it made re-identifiable by anyone who can restore it.
- Losing the current key loses no evidence: references are self-contained opaque
  values. It loses correlation, because new references for the same identities no
  longer match old ones. Recover by provisioning a new key, which is an unplanned
  rotation with no previous key to verify against.
- A restore of the same authority (same `authority_id`) needs the same key for
  continuity. A clone re-namespaced under a new `authority_id` derives unrelated
  references even with the same key, by design.

### Integration with the dispatcher

What the producer slice was required to add, and where PR 3 stands on each:

- **Configured aliases, refusing startup (done).** `AUTHORITY_PSEUDONYM_KEY_ALIAS`
  and `AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS` are validated startup settings in
  `.env.example` and the [configuration reference](configuration.md#authority_pseudonym_key_alias).
  A replica with a sink configured resolves both before any listener binds, and a
  missing alias, a provider failure or rejected material refuses startup.
- **Every replica holds the same keys (partly).** Both aliases are part of the static
  configuration fingerprint, so replicas naming different aliases are held at the
  fingerprint door. The key IDs are not in the fingerprint: the fingerprint is
  computed before the network secret providers that may hold the key exist. Every
  replica therefore logs and audits the key ID it loaded, and an operator must make
  each alias resolve to the same material everywhere.
- **No Connection may bind a pseudonym-key alias (done).** A create or replace that
  binds a configured alias under any field is refused with `422`
  `secret_purpose_conflict`, naming the field and not the alias, and a replica
  refuses to start while a stored Connection binds one.
- **A structured audit event when the keyring loads (done).**
  `authority_event.keyring_loaded` carries the authority ID, the current and previous
  key IDs and the sink kind. A rotation is a restart with new aliases, so it emits the
  same event with the new key IDs.
- **References only through this module, with synthetic-marker tests (done for what
  is delivered).** The delivery tests put marker identifiers into every evidence
  column the projection reads and assert none reaches a delivered record, and the
  metric registry audit covers the new series.

## Durable delivery

Ordinary request audit is bounded asynchronous telemetry, with one exception.
Its PostgreSQL sink retries a bounded number of times, then drops/counts failed
batches or overflow. The SQLite sink is also separate from authority mutation
transactions. Neither delivery path establishes required evidence by accepting an
event into memory after the mutation commits, and PR 3 changes neither. The
exception is `AUDIT_DURABILITY=required` (the default): the request path's
authentication and authorization records are acknowledged by the same sinks only
once the transaction carrying them commits, and the request is not acted on until
then. That is write-ahead evidence of a request's admission decision, not
authority-change evidence: the records an admin handler emits after its mutation
commits keep the bounded asynchronous delivery described here. `security_outbox`
and its `outbox_after` reader remain the security runtime's reconciliation
mechanism, not a downstream evidence cursor.

PR 3 delivers authority evidence through its own journal (cluster mode only,
migration 21; `gateway/src/storage/postgres_authority_events.rs` and
`gateway/src/authority_events/`):

- **Journal, in the mutation's transaction.** Every PostgreSQL producer of
  `connection_change_evidence`, `service_token_change_evidence` and
  `jwt_revocation_evidence` appends one `authority_event_journal` row in the same
  transaction as its evidence row, under the evidence row's `event_id`. The row
  holds identifiers only. Its position is reserved from the
  `authority_event_state` row, whose lock is held to COMMIT, so position order is
  commit order and the committed journal has no gaps. Evidence committed before
  migration 21 is journaled by the migration in commit order.
- **Bounded capacity, failing closed.** The same reservation succeeds only while
  fewer than `AUTHORITY_EVENT_JOURNAL_CAPACITY` rows are retained. When the
  journal is full, the mutation rolls back as a whole and is answered `503` (a CLI
  `revoke-jwt` exits with a store error); nothing is committed and no accepted
  event is evicted. This applies whatever `AUTHORITY_EVENT_SINK` says. The cost is
  deliberate and has to be watched: a refused service-token revoke or JWT revoke
  leaves the credential live until the change can commit.
- **Dispatch, outside every authority transaction.** With `AUTHORITY_EVENT_SINK`
  set, one replica at a time (the holder of the `authority-event-dispatcher`
  execution lease) claims the cursor at its lease fence, reads at most 100 rows
  after it, projects each into an `authority_event_delivery.v1` record
  ([schema](schemas/authority_event_delivery.v1.schema.json)), offers the batch to
  the sink, and only then advances the cursor with a compare-and-set on
  `(fence, position)`. A fenced-out leader's advance commits nothing. A refused
  batch is offered again after an exponential backoff from 0.5 s to 60 s and is
  never skipped; a row whose evidence cannot be projected faithfully stalls
  delivery at that row. A crash between the sink's acceptance and the cursor
  advance delivers the batch again with the same event IDs and, under the same
  key, identical records: delivery is at least once, and consumers deduplicate on
  `(authority_id, event_id)`. Exactly-once network delivery is not promised.
- **Sinks.** `log` writes one structured `INFO` line per record (target
  `greengateway::authority_event`, the JSON in the `authority_event` field);
  accepted means handed to the process's log writer, so it is a reference for a log
  pipeline rather than a durable store. `file` appends JSON lines to
  `AUTHORITY_EVENT_FILE` and calls `fsync` before a batch counts as accepted; a
  crash mid-write leaves at most one partial final line, which a reader skips and
  whose records are delivered again. Neither opens a network connection. A sink is
  a small trait (`authority_events::sink::AuthorityEventSink`); a network sink is
  future work and would carry its own transport review.
- **Retention floors.** The maintenance leader's `authority_event_retention` job
  deletes, one bounded step per pass, journal rows at or below the dispatcher's
  cursor and journaled at least `AUTHORITY_EVENT_RETENTION_HOURS` ago (default 168),
  and gives their capacity back. Once a dispatcher has claimed the cursor, no
  undelivered row is ever pruned, whatever its age. Before any dispatcher has run
  there is no required consumer, and rows are pruned by age alone. Retention never
  touches an evidence table: the evidence rows remain the append-only record.
- **What is delivered.** Each record carries the persisted `authority_id`, the
  evidence row's `event_id` and `operation_id`, the journal position as
  `sequence`, the operation, `result: committed`, the evidence row's
  database-clock `committed_at`, `actor.recorded_ref` (the `actor.recorded`
  reference of the recorded actor), the resource kind and its keyed reference (a
  JWT revocation's under its issuer and `jti` digest), and the v1 revision
  transition as decimal strings. No identifier, token material, `jti`, issuer or
  secret reaches it.
- **Signals.** `greengateway_authority_event_journal_retained` and `_capacity`,
  `_undelivered`, `_oldest_undelivered_age_seconds`, `_delivered_total`,
  `_delivery_failures_total{kind}` and `_capacity_refusals_total`, every label from
  a fixed vocabulary ([metrics](deployment/postgres.md#metrics)). No shipped alert
  rule covers them yet; the [threshold inventory](deployment/postgres.md#alert-thresholds)
  lists the conditions to alert on.

Operator actions at capacity, in order of preference: restore delivery (fix the
sink, or the dispatcher's key, so the cursor advances and retention can free
room), shorten `AUTHORITY_EVENT_RETENTION_HOURS`, or raise
`AUTHORITY_EVENT_JOURNAL_CAPACITY` on every replica. A dispatcher that has claimed
the cursor stays a required consumer when the sink is later turned off: its
cursor keeps holding undelivered rows. To stop delivering deliberately, remove the
cursor as the migration role (`DELETE FROM greengateway.authority_event_cursors WHERE
consumer = 'dispatcher'`) after the sink is off on every replica; retention then
prunes by age.

A database restore rewinds the journal, the cursor and the evidence together. Events
committed after the backup are gone with the changes they describe; events delivered
after the backup are delivered again under the same event IDs, which consumers
already deduplicate. The persisted `authority_id` survives the restore, so the same
key derives the same references.

Not covered by PR 3, and still open:

- **Required-durability mode.** Nothing makes a sink mandatory, so a deployment
  with `AUTHORITY_EVENT_SINK=none` journals and retains evidence but delivers none.
- **Admin sessions.** Migration 19's `admin_session_evidence` is not journaled and
  not delivered. A withdrawal must stay possible when the journal is full, so
  journaling it needs its own capacity decision first.
- **Standalone mode.** There is no journal and no dispatcher; the SQLite token
  evidence is not delivered.
- **The v1 contract.** Issuer, auth mode, actor kind and caller-bound operation
  identity at the store boundary, after which the delivered record can become
  `authority_event.v1`.
- **Every other operation.** Policy, tools, catalogs, Connection create/replace,
  credential bindings and token issue have no evidence rows to journal yet.

## Next reviewable slices and validation gates

1. **PostgreSQL Connection deletion evidence (landed).** The delete transaction
   now writes non-cascading actor/action/event/operation metadata to migration
   16's `connection_change_evidence`, beside the unchanged outbox tombstone and
   carrying its shared revision. Migration 16 moves the serving contract from
   exactly schema 15 to exactly schema 16, a coordinated drain/migrate/restart.
   PostgreSQL-gated store tests cover actor survival after delete and restart,
   stale ETag, dependency rejection, a missing record, two writers, a forced
   evidence-insert failure and its rollback, and reconciling a lost response
   from the evidence row; CI runs them against its disposable loopback database,
   not verified TLS. Still open for this row: issuer/auth mode and a
   caller-bound operation identity at the store boundary.
2. **Service-token and JWT metadata (landed).** `ServiceTokenStore` rotate and
   revoke now take the mutating actor, and both adapters write one evidence row
   per committed change in the change's own transaction: migration 18's
   `service_token_change_evidence` beside the PostgreSQL outbox row (same shared
   revision, same row-revision step), and the same table inside the standalone
   token database's IMMEDIATE transaction. JWT revokes append
   `jwt_revocation_evidence`, copied from the row they wrote, so an extension or
   reactivation adds a row instead of overwriting the actor and expiry cleanup
   leaves it. A failed evidence insert rolls the change back and is never
   reported as the rotate conflict; repeat revoke, refused rotate and refused
   JWT revokes write nothing. Migration 18 moves the serving contract from
   exactly schema 17 to exactly schema 18, a coordinated drain/migrate/restart.
   Tests cover both adapters through one shared contract, repeat revoke,
   rotate/revoke races, actor survival after token deletion and restart, a
   forced evidence-insert failure and its rollback, extension, reactivation and
   cleanup, and synthetic token-material exclusion; the PostgreSQL ones run in
   CI against its disposable loopback database, not verified TLS. Still open:
   issuer/auth mode, an actor kind for the CLI's system label, a caller-bound
   operation identity, and token issue evidence (`created_by` remains its only
   actor record).
3. **Shared documents/catalog metadata.** Extend the existing document core once
   for policy/tools, retaining suggestion transaction composition. Add immutable
   catalog/overlay evidence before replacement/cascade. Cover CAS rollback, name
   conflicts, system refresh, and commit followed by local installation failure.
4. **Durable dispatch (landed for the journaled evidence).** Migration 21's
   journal, capacity reservation and dispatcher cursor, the leased dispatcher and
   the log and file sinks, as described under [Durable delivery](#durable-delivery).
   Migration 21 moves the serving contract from exactly schema 20 to exactly schema
   21, a coordinated drain/migrate/restart. PostgreSQL-gated tests cover commit
   order under the evidence rows' own event IDs, a rolled-back append leaving no
   gap, concurrent producers on two pools, a crash between sink acceptance and the
   cursor advance redelivering identical records, a sink outage retried without
   advancing, bounded batches, a fenced-out leader refused, a missing evidence row
   stalling delivery rather than being skipped, retention never pruning an
   undelivered row, capacity exhaustion refusing every producer while committing
   nothing, the running dispatcher's lease and shutdown, and migration 21's
   backfill; the request-audit sink regressions are unchanged. CI runs them against
   its disposable loopback database, not verified TLS. Still open: the items listed
   at the end of that section.
5. **Standalone evidence and #242 ledger integration.** Add evidence only within
   each owning SQLite store transaction; test forced insert failure and restart.
   For policy/tools/configuration, require ledger-owned safe manifest/digest,
   parent revision/CAS, actor/operation intent, atomic activation/evidence or
   recoverable staging, authoritative replay after interruption, and export
   intent accepted before artifact release. Until all are demonstrated,
   required mode must reject unsupported configurations/operations.

The inventory's source anchors can become stale as those slices land; update the
classification, proofs and reviewed revision in the same PR. Do not close #425
from this PR 1 contract or from passing these lightweight checks.
