# Durable authority-change evidence inventory and contract

Part of [#425](https://github.com/Greenhat-Security/GreenGateway/issues/425), PR 1,
the first three PR 2 slices (PostgreSQL Connection deletion evidence; service-token
rotate/revoke and JWT revocation evidence; policy, tools and catalog publication
evidence), the keyed safe-reference derivation
([Keyed safe references](#keyed-safe-references)), PR 3's durable delivery
([Durable delivery](#durable-delivery)), the journaled evidence's actor metadata
([Actor metadata](#actor-metadata)), the cluster admin session evidence in the
journal ([Admin session withdrawals and journal capacity](#admin-session-withdrawals-and-journal-capacity))
and the first PR 4 slice (standalone Connection and local-secret evidence,
[Standalone evidence](#standalone-evidence)).
Reviewed source: `ebb579e6444d437bf477d0617b8841d1eea34cfc`.

This inventory identifies existing atomic records and the work needed for required
authority-change evidence. PR 1 added the inventory and the proposed event
contract. The first PR 2 slice adds migration 16's
`greengateway.connection_change_evidence`, written by PostgreSQL Connection
deletes. The second adds migration 18's `greengateway.service_token_change_evidence`
and `greengateway.jwt_revocation_evidence`, written by PostgreSQL token rotate/revoke
and JWT revokes, and the same token evidence table inside the standalone SQLite token
database. PR 3 adds migration 21's authority-event journal, which every PostgreSQL
producer of those three evidence tables appends to in the same transaction, and an
opt-in dispatcher that delivers it behind a persisted cursor. The third PR 2 slice
adds migration 23's `greengateway.document_change_evidence`, written by every
PostgreSQL policy and tools document commit, and `greengateway.catalog_change_evidence`,
written by every managed MCP and OpenAPI catalog publication; neither is a journal
source yet, so the dispatcher does not deliver them. Migration 24 adds the actor's
kind, auth mode and issuer to the three journaled tables, and the standalone token
database gains the same columns. Migration 26 makes migration 19's
`greengateway.admin_session_evidence` the fourth journal source, with journal
capacity held for every session's withdrawal so that a full journal never refuses a
logout. The first PR 4 slice adds migration 12 of the
standalone Connections database: Connection create/replace/delete and local-secret
create/rotate/delete/re-encryption write its `connection_change_evidence` and
`connection_local_secret_change_evidence` rows, with the whole actor, in their own
SQLite transactions. None of them implements or enables the authority-evidence
required-durability mode or a standalone revision ledger, and no row is qualified
for that future mode. Storage selection is unchanged.

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
| Policy publish, rollback, rule edits and suggestion acceptance | Immutable document/history, actor subject, action/diff, active pointer, shared revision and outbox, plus one non-cascading `document_change_evidence` row (operation code, event/operation UUIDs, actor kind, subject, issuer and auth mode, prior/new version, the outbox row's shared revision, database-clock time) in the same transaction; suggestion acceptance composes its own state, and so its evidence, in the same transaction | Caller-bound operation identity, safe-reference projection, durable delivery and retention |
| Tools publication | Shared document transaction plus name reservations and the same `document_change_evidence` row; the first-boot seed and the import's activation are recorded as system actors | Same as policy |
| Connection and credential binding changes | Record, bindings, immutable version, shared revision and outbox | Actor/history must survive Connection deletion; safe per-operation metadata and delivery. Standalone writes non-cascading create, replace and `credential.binding_change` evidence, with the whole actor, in the Connections database's own transaction ([Standalone evidence](#standalone-evidence)); PostgreSQL does not yet |
| Connection deletion | Outbox tombstone with prior version and shared revision, plus a non-cascading `connection_change_evidence` row (actor, action, event/operation UUIDs, prior version, the tombstone's shared revision, database-clock time) and its journal row in the same transaction; delivered with keyed safe references since PR 3; since migration 24 the actor's kind, auth mode and canonical issuer too. Standalone writes the same deletion evidence, without a shared revision, in the Connections database's own transaction | A caller-bound operation identity and an issuer-scoped subject reference, without which the delivered record cannot be `authority_event.v1`; standalone evidence is not delivered |
| Managed MCP/OpenAPI catalog and overlay publication | Catalog/overlay CAS, entries, dependencies, reservations, revision and outbox, plus one non-cascading `catalog_change_evidence` row (action derived from the write, event/operation UUIDs, actor subject, catalog revision transition, compiled overlay revision, shared revision, database-clock time) that outlives the replacement and the Connection's deletion | Issuer/auth mode, caller-bound operation identity, journaling for delivery |
| Service-token issue | Token row with creator, row/shared revisions and outbox | Creation retains only `created_by`; no issue evidence row, operation identity or delivery |
| Service-token rotate/revoke | Token change, row/shared revisions and outbox, plus a non-cascading `service_token_change_evidence` row (actor, action, event/operation UUIDs, prior/new row revision, the outbox row's shared revision, database-clock time) in the same transaction; repeated revoke and refused rotate write none. Standalone writes the same evidence in the token database's own transaction. In PostgreSQL the change also journals its evidence and is delivered since PR 3. Both stores record the actor's kind, auth mode and canonical issuer (migration 24 and the token database's own columns) | A caller-bound operation identity and an issuer-scoped subject reference; standalone evidence is not delivered |
| JWT revocation | Scoped JTI digest, actor row, shared revision and outbox, plus one non-cascading `jwt_revocation_evidence` row per effective revoke (actor, JTI digest, resulting expiry, shared revision) that extension, reactivation and expiry cleanup never rewrite, journaled in the same transaction and delivered since PR 3; since migration 24 the CLI's actor is recorded as kind `system`, auth mode `system` and no issuer | The CLI actor stays system provenance, not a named human; a caller-bound operation identity |
| Admin session grant/withdrawal (#424) | With `ADMIN_SESSION_MODE=cluster_postgres`, the session row, one non-cascading `admin_session_evidence` row (event/operation UUIDs, session ID, action, reason, subject and issuer, absolute deadline, database-clock time) and, since migration 26, its journal row commit together in one statement for each grant and each withdrawal; a replacement's withdrawal and grant share one operation ID. Delivered since migration 26 on the `session` axis with keyed safe references; a grant holds journal capacity for its withdrawal, so no withdrawal is refused at capacity ([Admin session withdrawals and journal capacity](#admin-session-withdrawals-and-journal-capacity)) | Actor kind and auth mode (the evidence records neither, so a withdrawal by the prune or a provider rejection is named by the session's subject, not as a system actor), an issuer-scoped subject reference, the withdrawal reason in the delivered record, and a caller-bound operation identity. Standalone sessions are process-local memory with no durable record and stay `unsupported_future_operation` |

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
- Connections and local secrets (one database) and service tokens each have an
  owning SQLite store. Required evidence must join that same store's mutation
  transaction. A separate audit SQLite database is not an atomic alternative.
  Service-token rotate/revoke, Connection create/replace/delete and local-secret
  create/rotate/delete/re-encryption now do: each store writes its evidence row
  in the same IMMEDIATE transaction as the change
  ([Standalone evidence](#standalone-evidence)). `import-standalone` does not
  carry those rows; the cluster's evidence starts with its first change.
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

Server-side policy drafts (#243) are outside the matrix for the same reason:
creating, editing, re-pinning or deleting one changes no enforcement, advances
no revision and writes no outbox row. Publishing one does change authority, and
it is `policy.publish`: `policy_draft_publish_endpoint` commits through
`persist_policy_mutation` exactly as `PUT /policy` does, so it is listed as an
entrypoint of both policy rows and inherits their boundaries and gaps. Marking
the draft published afterwards is a separate draft-store write, not part of the
authority transaction.

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
Since migration 26 the same statement journals each row, and the dispatcher
delivers it ([Admin session withdrawals and journal capacity](#admin-session-withdrawals-and-journal-capacity)).
The row stays `missing_metadata`: it has no actor kind or auth mode, so the
delivered record names the session's own subject and says `null` for the kind,
the auth mode and the issuer reference, even for an expiry or a provider
rejection, which no person made; and the reason is not delivered.

## Proposed authority event v1

[The closed JSON schema](schemas/authority_event.v1.schema.json) and the checker
define a **proposed** safe projection. Current `security_outbox` rows,
`connection_change_evidence` rows and `audit_event.v0` events do not already
satisfy this schema, and neither do migration 18's `service_token_change_evidence`
and `jwt_revocation_evidence` rows, migration 19's `admin_session_evidence` rows,
migration 23's `document_change_evidence` and `catalog_change_evidence` rows or
the standalone token, Connection and local-secret evidence rows: the evidence rows hold the internal actor
ID, not a keyed safe reference, and no `authority_id`. Since PR 3 the dispatcher
delivers the journaled evidence with keyed references under a persisted
`authority_id`, but as `authority_event_delivery.v1` ([Durable delivery](#durable-delivery)),
not as this schema. Since migration 24 the journaled evidence records the actor's kind, auth
mode and, for a principal that has one, canonical issuer
([Actor metadata](#actor-metadata)), but a v1 event still cannot be produced
faithfully: its `subject_ref` binds the subject to its issuer and its `issuer_ref`
is required, while a service token, an operator command, an issuer-less principal and
every row committed before migration 24 have no issuer to bind, and the operation
identity is not yet caller-bound. Migration 23's document rows also carry an actor
kind, issuer and auth mode, in their own vocabulary, but they are not journaled
yet.

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
| `actor` | Principal, service-token or system kind, safe subject/issuer references and known auth mode (including client certificates); a CLI system actor must not masquerade as an authenticated human, and a service token's `service-token:<id>` subject must not read as a person's |
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
and `resource.ref` values of the proposed event, and the `actor.recorded_ref`,
`actor.issuer_ref` and `resource.ref` values the dispatcher delivers today. Its runtime caller is the
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
| `actor.issuer` | Exactly one: the canonical issuer. The dispatcher derives it from the acting principal's issuer as migration 24's evidence records it |
| `actor.recorded` | Exactly one: an actor identifier exactly as an evidence row recorded it, with no issuer. Migrations 16 and 18 record the acting principal's subject, or a command's fixed system label (`operator:revoke-jwt`), with no issuer beside it in older rows and none at all for a service token or a command, so this is how the dispatcher names their actors, before and after migration 24 alike. It is its own domain, so it never yields the reference `actor.subject` gives the same subject |
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
  transaction as its evidence row, under the evidence row's `event_id`, and since
  migration 26 every cluster admin session grant and withdrawal journals its
  `admin_session_evidence` row in the statement that writes it. The row
  holds identifiers only. Its position is reserved from the
  `authority_event_state` row, whose lock is held to COMMIT, so position order is
  commit order and the committed journal has no gaps. Evidence committed before
  migration 21 is journaled by the migration in commit order; admin session
  evidence committed before migration 26 is journaled by that migration, in its
  own commit order, after everything already journaled.
- **Bounded capacity, failing closed.** The same reservation succeeds only while
  fewer than `AUTHORITY_EVENT_JOURNAL_CAPACITY` units are in use: one per retained
  row, plus one held for the withdrawal of every admin session granted and not yet
  withdrawn. When the journal is full, the mutation rolls back as a whole and is
  answered `503` (a CLI `revoke-jwt` exits with a store error); nothing is
  committed and no accepted event is evicted. The one exception is an admin
  session withdrawal, which spends the unit its grant held and is never refused for
  capacity ([below](#admin-session-withdrawals-and-journal-capacity)). This applies
  whatever `AUTHORITY_EVENT_SINK` says. The capacity
  is one value for the deployment, written by a replica only when the membership
  admits it, so a replica held at the fingerprint door with another value never
  changes the one the serving replicas enforce. The cost is deliberate and has to
  be watched: a refused service-token revoke or JWT revoke
  leaves the credential live until the change can commit.
- **Dispatch, outside every authority transaction.** With `AUTHORITY_EVENT_SINK`
  set, one replica at a time (the holder of the `authority-event-dispatcher`
  execution lease) claims the cursor at its lease fence, reads at most 100 rows
  after it, projects each into an `authority_event_delivery.v1` record
  ([schema](schemas/authority_event_delivery.v1.schema.json)), offers the batch to
  the sink, and only then advances the cursor with a compare-and-set on
  `(fence, position)`. A fenced-out leader's advance commits nothing. Only a
  replica the cluster membership has admitted contends for the lease: one held at
  the fingerprint door (`config_fingerprint_mismatch`), whose sink kind, key
  aliases or journal settings differ from the serving fleet's, or one the durable
  contract fence excludes, never takes the lease or claims the cursor, and a leader
  the fence excludes ends its term before its next batch. A refused
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
  whose records are delivered again. The path is not part of the fingerprint, and
  whichever replica leads appends to its own, so every replica's file must be
  shared storage or shipped to the same consumer; a pod-local file nothing collects
  keeps the batches delivered while that replica led. Neither opens a network connection. A sink is
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
  reference of the recorded actor), `actor.kind`, `actor.auth_mode` and
  `actor.issuer_ref` (the `actor.issuer` reference) as the evidence recorded them
  since migration 24, each `null` where the row recorded none, the resource kind
  and its keyed reference (a
  JWT revocation's under its issuer and `jti` digest, an admin session's under its
  random session ID), and the v1 revision transition as decimal strings. An admin
  session record carries `null` for the shared security revision, which a session
  does not take. No identifier, token material, `jti`, issuer or secret reaches
  it.
- **Signals.** `greengateway_authority_event_journal_retained` (the units in
  use), `_reserved` (the units of those held for admin session withdrawals) and
  `_capacity`,
  `_undelivered`, `_oldest_undelivered_age_seconds`, `_delivered_total`,
  `_delivery_failures_total{kind}`, `_capacity_refusals_total` and
  `_evidence_failures_total` (a change refused because the database refused its
  evidence row or journal entry for any other reason), every label from a fixed
  vocabulary ([metrics](deployment/postgres.md#metrics)). The
  [operational rule pack](deployment/operational-alerts.md#alert-policy) pages on
  either refusal counter and on a full journal, warns on a filling journal,
  sustained delivery lag or dispatcher failures, and reports a journal no current
  maintenance leader is observing. Its tests are synthetic; they do not show that a
  downstream system received anything.

Operator actions at capacity, in order of preference: restore delivery (fix the
sink, or the dispatcher's key, so the cursor advances and retention can free
room), shorten `AUTHORITY_EVENT_RETENTION_HOURS`, or raise
`AUTHORITY_EVENT_JOURNAL_CAPACITY` on every replica. Units held for admin session
withdrawals (`_reserved`) are not freed by retention: each comes back as its
session ends, by logout, replacement, rejection or expiry, and there are never
more of them than session rows (at most `ADMIN_SESSION_MAX_ENTRIES` live sessions,
plus expired ones the prune has not reached). A dispatcher that has claimed
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
- **Admin session metadata.** Admin session evidence is journaled and delivered
  since migration 26, but records no actor kind or auth mode, and the delivered
  record has no field for the withdrawal's reason.
- **Standalone mode.** There is no journal and no dispatcher; the SQLite token,
  Connection and local-secret evidence is not delivered.
- **The v1 contract.** A caller-bound operation identity at the store boundary and
  an issuer-scoped subject reference, after which the delivered record can become
  `authority_event.v1` for the actors that have an issuer. Kind, auth mode and
  issuer are recorded since migration 24 ([Actor metadata](#actor-metadata)).
- **Policy, tools and catalog evidence.** Migration 23's `document_change_evidence`
  and `catalog_change_evidence` rows exist but are not journal sources, so they are
  retained and not delivered. Journaling them adds the journal's capacity
  reservation to every policy, tools and catalog commit, and to the first-boot
  tools seed. A change refused because its evidence insert failed is logged with
  its classified store error but is not counted by `_evidence_failures_total`, so
  the rule pack does not page on it.
- **Every other operation.** PostgreSQL Connection create/replace, credential
  bindings and token issue have no evidence rows to journal yet.

### Admin session withdrawals and journal capacity

Migration 26 (`admin_session_evidence_journal`) journals every cluster admin session
grant and withdrawal, and decides what a full journal does to them. **The default,
reversible decision: a session withdrawal is never blocked by journal capacity.** A
logout the gateway cannot commit would keep a session the operator asked to end, so
capacity is held for the withdrawal at the moment the session is created, instead
of being looked for when it ends:

- **A grant takes two units**, one for its own event and one held for the
  session's withdrawal (`authority_event_state.reserved_withdrawals`), and only
  while both fit under `AUTHORITY_EVENT_JOURNAL_CAPACITY`. When they do not, the
  grant is refused: the OIDC completion answers `503` (`session_authority_unavailable`),
  nothing is committed, the pending login stays pending, and
  `greengateway_authority_event_capacity_refusals_total` counts it. A replacement's
  grant is refused the same way and leaves the session it would have replaced in
  place.
- **A withdrawal spends its grant's unit and checks no capacity.** Logout (by cookie
  or login binding), replacement by a new sign-in, a provider rejection or identity
  change, and the expiry prune (per admission and in the `admin_session_prune`
  maintenance job) each delete the session, insert its evidence row and journal it
  in one statement, whatever the journal holds. A session is withdrawn at most once,
  so its held unit is always enough; a withdrawal that finds fewer held units than
  sessions takes fresh ones rather than being refused. A withdrawal is still refused,
  and changes nothing, when its evidence or journal row cannot be written at all
  (the database refuses or does not answer the statement): that is an outage, not
  capacity, and is counted by `_evidence_failures_total`.
- **Every other producer keeps its rule** (one unit, only while fewer than the
  capacity are in use), and the held units count as in use, so no Connection
  delete, token rotate or revoke, or JWT revoke can spend a unit a session holds.
- **Retention is unchanged.** It deletes delivered rows and gives back exactly their
  units, never a held one; held units come back only as sessions end.
- **Migration 26 holds a unit for every session row that exists** when it runs,
  live or past a deadline the prune has not reached, and journals the admin session
  evidence already committed, after every event already journaled and in its own
  commit order, each row at its own commit time. It does not change the capacity: a
  deployment whose units in use now exceed it refuses grants and every other
  journaled change until retention frees room, and still records every withdrawal.

The delivered record ([schema](schemas/authority_event_delivery.v1.schema.json)) of a
session event is `admin_session.grant` or `admin_session.withdraw` on resource kind
`admin_session`, keyed by the session's random ID under the `resource.admin_session`
domain. Its actor is the session's own subject, the only identity the evidence
records, under `actor.recorded`, with `null` kind, auth mode and issuer reference.
Its revision is the v1 `session` axis: a session is granted once and withdrawn once,
so its one revision, `1`, is created by the grant (`before: null`, `after: "1"`) and
deleted by the withdrawal (`before: "1"`, `after: null`), and its shared security
revision is `null` because session changes take none. The withdrawal's reason stays
in the evidence row.

Why this is a default and not a contract: the journal rows and the evidence rows do
not depend on it. A later release could decide otherwise (for example, refuse every
change at capacity, withdrawals included, or reserve a fixed share of the capacity
instead of a unit per session) by changing the producer statements in
`gateway/src/storage/postgres_admin_sessions.rs` and returning the held units with
one statement (`retained_events - reserved_withdrawals`, `reserved_withdrawals = 0`)
in its migration. The cost of this default is that, with the journal near capacity,
signing in is refused one unit before other changes are, and every live session
keeps one unit of the capacity out of reach of other producers.

Tests: `storage::postgres_admin_sessions`' `a_full_journal_refuses_grants_but_never_a_withdrawal`
(three sessions and a token rotate fill a journal of seven units; a grant and a token
revoke are refused and commit nothing; a logout, a provider rejection and the expiry
prune each commit, journaled; the dispatcher delivers every session event in commit
order without an identifier; retention frees the delivered rows and the refused grant
completes), `a_withdrawal_whose_journal_row_cannot_be_written_does_not_happen` and
`every_grant_and_withdrawal_leaves_one_evidence_row` (every evidence row journaled,
every held unit spent); `storage::migrations`' `migration_twenty_six_journals_session_evidence_and_holds_withdrawals`;
and the delivery projection tests in `gateway/src/authority_events/delivery_tests.rs`.
The PostgreSQL ones run in CI against its disposable loopback database, not verified
TLS.

## Actor metadata

Migration 24 (`authority_evidence_actor_metadata`) adds three nullable columns to
`connection_change_evidence`, `service_token_change_evidence` and
`jwt_revocation_evidence`, and the standalone token database adds the same three
columns to its own `service_token_change_evidence` when it is opened. The standalone
Connections database's two evidence tables ([Standalone evidence](#standalone-evidence))
were created with them, so there `actor_kind` and `actor_auth_mode` are required on
every row:

| Column | Contract |
| --- | --- |
| `actor_kind` | `principal` (a session cookie, bearer JWT or client certificate that an identity provider or the inbound TLS handshake vouched for), `service_token` (a gateway-issued service token, whose `service-token:<id>` subject an identity provider could also assert for a person) or `system` (an operator command under its fixed label, such as `operator:revoke-jwt`; nobody authenticated it) |
| `actor_auth_mode` | The audit vocabulary of the principal's authentication (`session_cookie`, `bearer_token`, `client_certificate`, `service_token`), or `system`; it always agrees with the kind |
| `actor_issuer` | The canonical issuer, in the form audit and policy use, of a principal that has one; never for a service token or a command. On `jwt_revocation_evidence` this is the acting principal's issuer, and the existing `issuer` column stays the revoked token's |

The admin endpoints build the actor (`auth::change_actor::ChangeActor`) from the
authenticated `Principal` and pass it to the store, which records it in the
change's own transaction: Connection delete (`connection_delete_endpoint`), token
rotate and revoke (`token_rotate_endpoint`, `token_revoke_endpoint`), and the
`revoke-jwt` command, which passes a `system` actor. Each field is bounded by
exactly the bound authentication enforces (`MAX_PRINCIPAL_SUBJECT_BYTES` and
`MAX_PRINCIPAL_ISSUER_BYTES`, 4,096 bytes each), so no principal a validator
accepted is refused. A store refuses any other actor before it changes anything,
rather than truncate it or commit the change anonymously, and a CHECK on each
table is the backstop: a row records all three or none, in a pairing
authentication produces, with an issuer only for a principal. Only the subject,
issuer, kind and auth mode are recorded; never a credential, session ID, role,
organization or email address. Nothing is backfilled: a row committed before
migration 24 (or before the token database gained the columns) records none of the
three, and is delivered with `null` there rather than a guess. The dispatcher
refuses to project a row whose metadata is out of shape, which stalls delivery at
that row as any other unprojectable row does.

Tests: the shared service-token change-evidence contract and the JWT revocation
evidence tests in `gateway/src/storage/contract_tests.rs` (both token stores), the
Connection deletion evidence tests in `gateway/src/connections/pg_store_tests.rs`,
`migration_twenty_four_adds_actor_metadata_and_guesses_none_for_existing_evidence`,
the standalone column upgrade in `gateway/src/auth/tokens.rs`, the delivery
projection tests in `gateway/src/authority_events/delivery_tests.rs`, the
commit-order dispatcher test, and the app-level
`admin_token_rotate_and_revoke_record_the_authenticated_subject_and_issuer_sqlite`
and `_postgres`, which drive the admin endpoints with principals from two identity
providers and a service token and read the evidence rows back. The PostgreSQL ones
run in CI against its disposable loopback database, not verified TLS.

Migration 23's two tables are outside this contract, and migration 24 leaves them
unchanged. `document_change_evidence` records an actor kind, issuer and auth mode
in its own vocabulary: kind `principal` for every authenticated caller, a service
token included (only its `service_token` auth mode tells it apart), or `system`,
and the issuer as the principal carried it rather than in canonical form.
`catalog_change_evidence` records the publishing subject alone, with no kind,
issuer or auth mode. Neither table is a journal source, so nothing delivers either
row; aligning both with this section's columns is a later #425 slice (the
inventory's `policy_postgres`, `tools_postgres`, `configuration_import` and
`catalog_postgres` rows keep `missing_metadata`). For `catalog_change_evidence`
that slice starts with migration 25, which adds this section's three columns under
the same CHECK. This release applies it, as a rolling step from the release that
approved it ([schema 24 to 25](deployment/postgres.md#rolling-upgrade-schema-24-to-25)),
but still writes no metadata into it: catalog publications record the subject
alone, and every row says "not recorded" until a later #425 slice fills them.

## Standalone evidence

A standalone gateway has no shared database, so its evidence lives in the SQLite
store that owns each authority and is written in the same IMMEDIATE transaction
as the change it describes. Nothing is written to the audit database instead: a
second SQLite file cannot commit atomically with the first.

| Store | Table | Written by | Each row holds |
| --- | --- | --- | --- |
| `SERVICE_TOKEN_SQLITE_PATH` | `service_token_change_evidence`, created on open | service-token rotate and revoke | actor, action, event and operation UUIDs, token ID, commit time |
| `CONNECTIONS_SQLITE_PATH` | `connection_change_evidence`, Connections schema migration 12 | Connection create, replace and delete | actor, action, event and operation UUIDs, Connection ID, the revision before and after on the action's axis, commit time. A replace that advances the credential revision adds a `credential.binding_change` row on the credential axis under the same operation ID |
| `CONNECTIONS_SQLITE_PATH` | `connection_local_secret_change_evidence`, Connections schema migration 12 | local-secret create, rotate and delete, and each re-encryption batch that rewrote at least one envelope | actor, action, event and operation UUIDs, the gateway-minted secret ID and its version before and after; a batch records only how many envelopes it rewrote |

In each table the actor is the whole `auth::change_actor::ChangeActor`: subject,
kind, auth mode and, for a principal that has one, canonical issuer, in the columns
and with the pairing CHECK of [Actor metadata](#actor-metadata). The token table
gained those columns on open and keeps older rows without them; the two Connections
tables were created with them and require kind and auth mode on every row.

All three follow the same rules:

- A change whose evidence cannot be inserted rolls back with it and fails as a
  store failure (`503` from the Connection and secret admin API, an internal or
  unavailable error from the token admin API by the failure's class, a failed
  exit from the maintenance command). A refused change
  (stale ETag, dependency conflict, missing record, purpose mismatch) and an
  ineffective one (an identical replace, a batch with nothing to rewrite, a
  repeat revoke) write nothing. A change whose actor evidence cannot record
  exactly (no subject, a subject or issuer past the principal bounds, or an issuer
  on a service token or command) is refused before anything is written.
- No foreign key: a row outlives the deletion it records, so a lost delete
  response is answered from the evidence rather than by a blind retry.
- Identifiers, revisions, counts and the actor only: never a specification,
  endpoint, label, purpose, credential binding, bound secret ID, plaintext,
  ciphertext, nonce, key ID or token material. The tests put synthetic markers in
  each of these and inspect the stored rows.
- The actor is the authenticated principal the admin endpoint passes to the store.
  The `connection-secrets reencrypt` command records the fixed label
  `operator:connection-secrets-reencrypt` as a `system` actor with no issuer, which
  names the command, not a person.
- `sequence` is commit order: every writer holds the database's write lock and
  `AUTOINCREMENT` never reuses a value. A row's action is the proposed
  authority-event operation code, and its revisions follow that operation's axis
  (connection, credential or secret version; none for re-encryption).

What standalone evidence lacks compared with cluster mode:

- **No shared security revision and no database clock.** `committed_at` is the
  gateway process's clock (the change's own `updated_at`, or a rotation's
  `rotated_at`), and each revision is per record.
- **No delivery.** There is no journal or dispatcher; the rows are read from the
  file. The change's only delivered record is still the post-commit admin audit
  event (or the maintenance command's printed counts), which stays bounded
  telemetry.
- **No retention and no capacity bound.** Rows are never pruned, so each table
  grows by one small row per change. A restore of the file rewinds the evidence
  with the state it describes.
- **No caller-bound operation identity**, the same gap as in cluster mode. An
  operation ID is minted per store call. The actor's kind, auth mode and issuer
  are recorded, as in cluster mode since migration 24.
- **Not carried across a cutover.** `import-standalone` leaves these rows in the
  standalone files and names them in its report.
- **No evidence for changes made before migration 12.** The migration creates
  empty tables and fabricates nothing. A gateway built before it refuses to open a
  Connections database that has been migrated, so a rollback needs the database
  backup taken before the upgrade.
- **Not covered:** managed catalog, overlay and enum-source publication in the
  same database, service-token issue, and the file-backed policy, tools and
  configuration authorities, which wait for #242's ledger.

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
   not verified TLS. Migration 24 adds the deleting actor's kind, auth mode and
   canonical issuer ([Actor metadata](#actor-metadata)). Still open for this row: a
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
   CI against its disposable loopback database, not verified TLS. Migration 24
   (and the standalone token database's own columns) adds the actor's kind, auth
   mode and canonical issuer, and records the CLI's system label as kind `system`
   ([Actor metadata](#actor-metadata)). Still open: a caller-bound operation
   identity, and token issue evidence (`created_by` remains its only actor
   record).
3. **Shared documents/catalog metadata (landed).** The shared document core
   (`postgres_documents::commit_in`) now writes one migration 23
   `document_change_evidence` row beside the outbox row of every policy and tools
   commit, so suggestion acceptance, which runs it inside its own transaction,
   records its evidence there too. Each handler names its operation explicitly
   (`policy.publish`, `policy.rollback`, `policy.rule.create`/`update`/`delete`/`reorder`,
   `policy.suggestion.accept`, `tools.publish`), the import's activations are
   `configuration.import`, and the actor is recorded as the principal presented it --
   kind, subject, issuer and auth mode, within the principal bounds -- or as the
   gateway (`bootstrap` for the first-boot tools seed, `import-standalone` for the
   import). The Connection store's MCP and OpenAPI catalog replacement writes one
   `catalog_change_evidence` row per publication, naming registration and refresh
   `catalog.openapi.publish` or `catalog.mcp.publish` and overlay writes
   `catalog.overlay.replace` or `catalog.overlay.delete`; it has no foreign key, so
   it outlives the next replacement and the Connection's deletion. A failed
   evidence insert rolls the change back and is reported as a store failure; a
   stale ETag or catalog revision, a lost initialize race and a tool name another
   lane holds write nothing; an empty or oversized actor, or an action that cannot
   describe the resource, is refused before anything is written. A tools commit
   followed by a failed local install keeps its evidence, because the commit is
   durable. Migration 23 moves the serving contract from exactly schema 22 to
   exactly schema 23, a coordinated drain/migrate/restart. PostgreSQL-gated tests
   cover attribution of each operation and the system actors, outbox agreement,
   refusals that write nothing, forced evidence-insert failure and its rollback
   (including inside a suggestion acceptance), principal bounds, survival after
   catalog replacement, Connection deletion and restart, and the overlay
   vocabulary; CI runs them against its disposable loopback database, not
   verified TLS. Still open: issuer and auth mode for catalog publications (their
   writers carry the subject only; Connection deletion records both since
   migration 24), the alignment of the document rows' actor vocabulary with
   migration 24's ([Actor metadata](#actor-metadata)), a caller-bound
   operation identity, and journaling: neither table is a migration 21 journal
   source, so the dispatcher does not deliver their rows yet. No scheduled
   catalog refresh ships, so no system catalog actor is needed yet.
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
   its disposable loopback database, not verified TLS. Migration 26 adds the
   cluster admin session evidence as a journal source, with a unit of capacity held
   for each session's withdrawal ([Admin session withdrawals and journal capacity](#admin-session-withdrawals-and-journal-capacity)),
   moving the serving contract from exactly schema 25 to exactly schema 26, a
   coordinated drain/migrate/restart. Still open: the items listed at the end of
   that section.
5. **Standalone evidence and #242 ledger integration.** Add evidence only within
   each owning SQLite store transaction; test forced insert failure and restart.
   Connections and local secrets have landed in the Connections database
   (migration 12 of that store, [Standalone evidence](#standalone-evidence)), with
   tests for each change's forced insert failure and rollback, survival of deletion
   and restart, refused and ineffective changes writing nothing, unrecordable actors
   refused, the migration onto an existing database fabricating nothing, the actor
   CHECKs pinned to migration 24's, synthetic-marker exclusion, and the admin
   endpoints and maintenance command recording their whole actors. Still open here:
   catalog and overlay publication in that database, token issue evidence, a
   caller-bound operation identity, and delivery of any standalone evidence.
   For policy/tools/configuration, require ledger-owned safe manifest/digest,
   parent revision/CAS, actor/operation intent, atomic activation/evidence or
   recoverable staging, authoritative replay after interruption, and export
   intent accepted before artifact release. Until all are demonstrated,
   required mode must reject unsupported configurations/operations.

The inventory's source anchors can become stale as those slices land; update the
classification, proofs and reviewed revision in the same PR. Do not close #425
from this PR 1 contract or from passing these lightweight checks.
