# Durable authority-change evidence inventory and contract

Part of [#425](https://github.com/Greenhat-Security/GreenGateway/issues/425), PR 1.
Reviewed source: `4314d63373539700dffb303bc4e2d385ceb53295`.

This inventory identifies existing atomic records and the work needed for required
authority-change evidence. It does **not** implement or enable required-durability
mode, a new database table, a dispatcher, or a standalone revision ledger. No row
is qualified for that future mode by this change. Current application behavior
and storage selection are unchanged.

Run the executable inventory and proposed event-contract tests with the pinned
Node version from `build-tools.json`:

```sh
node scripts/check-authority-evidence.mjs
node --test scripts/test-authority-evidence.mjs
```

The existing CI `supply-chain` job runs both commands. The checker covers 29
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
| Connection deletion | Outbox tombstone with prior version and shared revision | Deletion actor is currently ignored by the store; version history cascades |
| Managed MCP/OpenAPI catalog and overlay publication | Catalog/overlay CAS, entries, dependencies, reservations, revision and outbox | Current actor rows are replaced or cascaded; retain per-change evidence |
| Service-token issue/rotate/revoke | Token change, row/shared revisions and outbox; repeated revoke is a no-op | Creation retains original creator, but rotate/revoke store APIs receive no mutation actor; preserve action and operation identity |
| JWT revocation | Scoped JTI digest, actor row, shared revision and outbox | Extension/reactivation overwrites actor; expiry cleanup removes row. CLI actor is system provenance, not a named human |

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
  A separate audit SQLite database is not an atomic alternative.
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
cascade consequences explicitly. Authentication sessions belong to #424; when a
new session authority ships, add its grant/withdrawal operations to this contract
before asserting required durability for them.

## Proposed authority event v1

[The closed JSON schema](schemas/authority_event.v1.schema.json) and the checker
define a **proposed** safe projection. Current `security_outbox` rows and
`audit_event.v0` events do not already satisfy this schema. Runtime producer,
identity derivation, persistence and dispatcher integration belong to later
slices.

Revision transitions are operation-specific. Resource creation (`connection.create`,
`secret.create`, `service_token.issue`) has no prior revision; replacement,
rotation, revocation and edits to existing authority require one. In particular,
creating a policy rule advances its containing policy rather than creating a new
policy authority. Publication and activation may initialize or advance a snapshot.
Deletion requires a positive prior revision and a null successor, export binds
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
arbitrary hashes of input payloads. The producer design must use domain-separated,
authority-scoped keyed derivation for principal and sensitive resource
correlation, with a documented stable key/rotation/backup policy; a schema cannot
prove that a digest was safely derived. Do not add another secret store or choose
an unreviewed key source in this inventory-only slice. This derivation contract
must be implemented and tested before runtime adoption. Non-sensitive identities
may also use the same reference format for one closed projection.

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

## Delivery, retention and recovery contract

`security_outbox` already has `outbox_after`, a bounded read helper.
The reviewed production paths do not call it from an authority-event dispatcher.
The security runtime reconciles authority revisions. That reconciliation
mechanism is not a durable downstream evidence cursor.

Ordinary request audit remains bounded asynchronous telemetry. Its PostgreSQL
sink retries a bounded number of times, then drops/counts failed batches or
overflow. The SQLite sink is also separate from authority mutation transactions.
Neither delivery path establishes required evidence by accepting an event into
memory after the mutation commits.

PR 3 must persist a consumer cursor and deduplication identity independently of
ordinary request telemetry. Read bounded committed batches, deliver outside the
mutation transaction, and advance the cursor only after an accepted downstream
batch. A crash after downstream acceptance and before cursor commit produces a
duplicate with the **same event ID**. Consumers deduplicate on
`(authority_id, event_id)`; exactly-once network delivery is not promised.

Keep events until every required consumer's durable cursor has passed them and
the configured minimum retention has elapsed. Connection/JWT authority cleanup
must not erase required evidence. Reserve bounded capacity within the mutation
transaction: if evidence cannot be accepted, required-mode mutation fails without
committing or releasing an artifact. Existing accepted events must never be
evicted to admit new work. Emit low-cardinality lag, oldest-undelivered age,
capacity and retry/failure signals; operators restore delivery, archive accepted
evidence or increase capacity. No subject/resource/operation ID or secret
material belongs in metric labels. Downstream network availability must never
become a call inside the authority transaction.

## Next reviewable slices and validation gates

1. **PostgreSQL Connection deletion evidence.** Extend its existing transaction
   with non-cascading actor/action/event/operation metadata, using an immutable
   additive migration and current coordinated-upgrade rules. Preserve outbox
   resource identity and tombstone. Verified-TLS database tests must cover actor
   survival after delete/restart, stale ETag, dependency rejection, two writers,
   forced evidence-insert failure, rollback and ambiguous-result reconciliation.
2. **Service-token and JWT metadata.** Carry mutation actor/action through
   `ServiceTokenStore` and both adapters; retain rotate/revoke history and JWT
   extension/cleanup provenance. Exercise repeat revoke, rotate/revoke races,
   expired cleanup and synthetic-secret exclusion. Do not recover the changing
   actor from `created_by`.
3. **Shared documents/catalog metadata.** Extend the existing document core once
   for policy/tools, retaining suggestion transaction composition. Add immutable
   catalog/overlay evidence before replacement/cascade. Cover CAS rollback, name
   conflicts, system refresh, and commit followed by local installation failure.
4. **Durable dispatch.** Test crash before commit, crash after commit before
   dispatch, downstream acceptance before cursor commit, restart, duplicates,
   bounded batches/backoff, retention floors and capacity rejection. Keep
   request-audit sink regressions separate.
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
