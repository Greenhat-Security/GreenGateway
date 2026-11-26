# Durable authority-change evidence inventory and contract

Part of [#425](https://github.com/Greenhat-Security/GreenGateway/issues/425), PR 1,
the first three PR 2 slices (PostgreSQL Connection deletion evidence; service-token
rotate/revoke and JWT revocation evidence; policy, tools and catalog publication
evidence), PostgreSQL service-token issue and Connection create, replace and
credential binding change evidence, the keyed safe-reference derivation
([Keyed safe references](#keyed-safe-references)), PR 3's durable delivery
([Durable delivery](#durable-delivery)), the journaled evidence's actor metadata
([Actor metadata](#actor-metadata)), the cluster admin session evidence in the
journal ([Admin session withdrawals and journal capacity](#admin-session-withdrawals-and-journal-capacity)),
the PR 4 standalone slices (Connection, local-secret, and catalog and overlay
evidence, [Standalone evidence](#standalone-evidence)), standalone delivery from the
stores that own that evidence ([Standalone delivery](#standalone-delivery)) and PR 4's
refusal of unsupported changes ([Required-durability mode](#required-durability-mode)),
the caller operation keys of every keyed family
([Keyed authority changes](#keyed-authority-changes)) and the closing
reconciliation of this inventory
([Next reviewable slices](#next-reviewable-slices-and-validation-gates)).
Reviewed source: `5da986d6c915c15fdd1f6aa2e490c3157ce9bf1c`.

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
written by every managed MCP and OpenAPI catalog publication; neither was a journal
source until migration 32. Migration 24 adds the actor's
kind, auth mode and issuer to the three journaled tables, and the standalone token
database gains the same columns. Migration 25 adds the same three columns to
`catalog_change_evidence`, and every catalog publication records them. Migration 26 makes migration 19's
`greengateway.admin_session_evidence` the fourth journal source, with journal
capacity held for every session's withdrawal so that a full journal never refuses a
logout. Migration 27 lets migration 18's token table record the issue of a
service token too, written and journaled in the create's transaction, and the
standalone token database rebuilds its own table once to admit it. Migration 28 lets
migration 16's Connection table record a create, a replace and, when a replace
changes credential authority, a `credential.binding_change` on the credential
revision axis, each written and journaled in the change's transaction. Migration 32
makes migration 23's two tables the fifth and sixth journal sources, so every
policy, tools and catalog change is journaled in its own transaction and
delivered, and records the document actor in migration 24's vocabulary
([Policy, tools and catalog delivery](#policy-tools-and-catalog-delivery)). The first PR 4
slice adds migration 12 of the
standalone Connections database: Connection create/replace/delete and local-secret
create/rotate/delete/re-encryption write its `connection_change_evidence` and
`connection_local_secret_change_evidence` rows, with the whole actor, in their own
SQLite transactions, and migration 13 of the same database adds
`catalog_change_evidence` for managed catalog and overlay publication. Migration 14
of the same database, and the token database's open-time schema, add the delivery
state those tables are delivered after, so a standalone gateway with a sink delivers
them without a journal. Migration 35 adds a seventh PostgreSQL journal source
for keyed approval preparations. The required-mode contract for preparation
admits only an issuer-bound caller using the negotiated format.
[Approval preparation](#postgresql-approval-preparation)

`AUDIT_DURABILITY=required`, the default since the request-path slice of this issue,
is a different and narrower guarantee: the authentication and authorization stages
wait for their own decision records to commit to the audit store of record, and
refuse the request with `503 audit_unavailable` when they cannot (see
[the configuration reference](configuration.md#audit_durability)). It does not
make any authority-change row below qualified: an admin mutation's evidence is
still its own transaction's rows, its journal entry, or the ordinary audit event its
handler emits after the commit. The inventory's `required_durability_mode` is
`refuses_unsupported`: the separate, opt-in `AUTHORITY_EVIDENCE_DURABILITY=required`
checks each reachable mutation against its storage authority and refuses writes
that lack the required evidence. PostgreSQL approval preparation has a separate
`caller_key_required` admission rule.

Run the executable inventory and proposed event-contract tests with the pinned
Node version from `build-tools.json`:

```sh
node scripts/check-authority-evidence.mjs
node --test scripts/test-authority-evidence.mjs
```

The CI `supply-chain` job runs both commands. The checker covers every listed
operation in both storage modes, checks live source and test anchors, rejects
missing or duplicate coverage, and detects new mutation endpoints in the reviewed
admin modules. It checks source traceability and contract
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
| Policy publish, rollback, rule edits and suggestion acceptance | Immutable document/history, actor subject, action/diff, active pointer, shared revision and outbox, plus one non-cascading `document_change_evidence` row (operation code, event/operation UUIDs, actor kind, subject, issuer and auth mode, prior/new version, the outbox row's shared revision, database-clock time) in the same transaction, journaled and delivered since migration 32, its actor in migration 24's vocabulary; suggestion acceptance composes its own state, and so its evidence, in the same transaction | Since #425 a keyed change (draft publication included) binds the caller's UUIDv7 in the change's transaction and is delivered as `authority_event.v1` under `qualified_v1` ([Keyed policy, tools and policy test changes](#keyed-policy-tools-and-policy-test-changes)); unkeyed changes keep a generated operation identity. Standalone policy writes record no caller key, refuse a key and are refused under `required` until #242 |
| Tools publication | Shared document transaction plus name reservations and the same `document_change_evidence` row, journaled and delivered since migration 32; the first-boot seed and the import's activation are recorded as system actors | Since #425 a keyed OpenAPI registration binds the caller's UUIDv7 in the change's transaction and is delivered as `authority_event.v1` under `qualified_v1`; unkeyed changes keep a generated operation identity. Standalone publication (admin API and file reloads) is refused under `required` until #242 |
| Stored policy test suite (`policy_tests.publish`, migration 29) | Shared document transaction over its own versions and active pointer, plus the same `document_change_evidence` row, with resource type `policy_tests` | Since #425 a keyed suite write binds the caller's UUIDv7 in the change's transaction and is delivered as `authority_event.v1` under `qualified_v1`, as a `policy` resource on its own `policy_tests` revision axis, because its versions are not policy versions; unkeyed writes keep a generated operation identity. Standalone records only the writer's subject on the version row, so `required` refuses the write there until #242 |
| Connection and credential binding changes | Record, bindings, immutable version, shared revision and outbox, plus since migration 28 a non-cascading `connection_change_evidence` row per committed create (`connection.create`, no prior version and version 1) and replace (`connection.replace`, prior and new specification version), and a `credential.binding_change` row on the credential axis (prior and new credential revision) under the same operation ID and shared revision when a replace advances the credential revision: actor (subject, kind, auth mode, canonical issuer), event/operation UUIDs, the outbox row's shared revision, database-clock time, journaled and delivered in the change's transaction. An identical replace records nothing. No binding, secret ID or locator enters a row. Standalone writes the same rows, without a shared revision, in the Connections database's own transaction ([Standalone evidence](#standalone-evidence)) | Since #425 a keyed create or replace binds the caller's UUIDv7 in the change's transaction and is delivered as `authority_event.v1` under `qualified_v1` ([Keyed Connection changes](#keyed-connection-create-replace-and-delete)); unkeyed changes keep a generated operation identity. Connections created or replaced before migration 28 keep only their cascading version history; standalone records are delivered without a shared security revision |
| Connection deletion | Outbox tombstone with prior version and shared revision, plus a non-cascading `connection_change_evidence` row (actor, action, event/operation UUIDs, prior version, the tombstone's shared revision, database-clock time) and its journal row in the same transaction; delivered with keyed safe references since PR 3; since migration 24 the actor's kind, auth mode and canonical issuer too. Standalone writes the same deletion evidence, without a shared revision, in the Connections database's own transaction | Since #425 a keyed delete binds the caller's UUIDv7 in the deletion's transaction and is delivered as `authority_event.v1` under `qualified_v1`; unkeyed and service-token deletions stay admitted and keep a generated operation identity ([Keyed Connection changes](#keyed-connection-create-replace-and-delete)); standalone records are delivered without a shared security revision |
| Managed MCP/OpenAPI catalog and overlay publication | Catalog/overlay CAS, entries, dependencies, reservations, revision and outbox, plus one non-cascading `catalog_change_evidence` row (action derived from the write, event/operation UUIDs, the actor's subject, kind, auth mode and canonical issuer, catalog revision transition, compiled overlay revision, shared revision, database-clock time) that outlives the replacement and the Connection's deletion, journaled and delivered since migration 32. Standalone writes the same evidence, without a shared revision, in the Connections database's own transaction (its migration 13) | Since #425 a keyed refresh, OpenAPI registration, overlay put or overlay delete binds the caller's UUIDv7 in the change's transaction and is delivered as `authority_event.v1` under `qualified_v1`, in both modes ([Keyed catalog publication and overlay changes](#keyed-catalog-publication-and-overlay-changes)); unkeyed changes keep a generated operation identity and are refused under `required`. Standalone records are delivered without a shared security revision |
| Service-token issue | Token row with creator, row/shared revisions and outbox, plus since migration 27 a `service_token_change_evidence` row with action `service_token.issue` (actor, event/operation UUIDs, no prior revision and row revision 1, the create outbox row's shared revision, database-clock time) in the create's transaction, journaled and delivered. Standalone writes the same row in the token database's own create transaction. Neither store records the returned plaintext or its hash | Since #425 a keyed issue binds the caller's UUIDv7 in the create's transaction and is delivered as `authority_event.v1` under `qualified_v1`, in both modes ([Keyed service-token issue and rotation](#keyed-service-token-issue-and-rotation)); unkeyed issues keep a generated operation identity and are refused under `required`. Tokens issued before the evidence existed keep only `created_by`; standalone records are delivered without a shared security revision |
| Service-token rotate/revoke | Token change, row/shared revisions and outbox, plus a non-cascading `service_token_change_evidence` row (actor, action, event/operation UUIDs, prior/new row revision, the outbox row's shared revision, database-clock time) in the same transaction; repeated revoke and refused rotate write none. Standalone writes the same evidence in the token database's own transaction. In PostgreSQL the change also journals its evidence and is delivered since PR 3. Both stores record the actor's kind, auth mode and canonical issuer (migration 24 and the token database's own columns). The keyed revoke endpoint binds the caller, action and target to the supplied operation UUID in that same transaction | Since #425 a keyed rotation binds the caller's UUIDv7 in the change's transaction and is delivered as `authority_event.v1` under `qualified_v1`, in both modes; an unkeyed rotation keeps a generated operation identity and is refused under `required`. Revocation is a withdrawal: the keyed revoke binds its key in both modes, and the unkeyed `DELETE` stays admitted with a generated operation identity ([Rows admitted without qualification](#rows-admitted-without-qualification)). Standalone records are delivered without a shared security revision |
| Approval preparation | The PostgreSQL keyed PUT commits a pending occurrence, its caller-bound receipt, and its journal record in one transaction. Required mode admits this operation with `qualified_v1`. | The ordinary POST is available in best-effort mode. Standalone preparation and subsequent review, revocation and consumption in either backend have no durable authority journal. |
| JWT revocation | Scoped JTI digest, actor row, shared revision and outbox, plus one non-cascading `jwt_revocation_evidence` row per effective revoke (actor, JTI digest, resulting expiry, shared revision) that extension, reactivation and expiry cleanup never rewrite, journaled in the same transaction and delivered since PR 3; since migration 24 the CLI's actor is recorded as kind `system`, auth mode `system` and no issuer | The CLI actor stays system provenance, not a named human; a caller-bound operation identity |
| Admin session grant/withdrawal (#424) | With `ADMIN_SESSION_MODE=cluster_postgres`, the session row, one non-cascading `admin_session_evidence` row (event/operation UUIDs, session ID, action, reason, subject and issuer, absolute deadline, database-clock time) and, since migration 26, its journal row commit together in one statement for each grant and each withdrawal; a replacement's withdrawal and grant share one operation ID. Delivered since migration 26 on the `session` axis with keyed safe references; a grant holds journal capacity for its withdrawal, so no withdrawal is refused at capacity ([Admin session withdrawals and journal capacity](#admin-session-withdrawals-and-journal-capacity)) | Migration 33 records and delivers the verified login on grant and replacement and the system on rejection and expiry. Logout accepts a cookie or login binding without authenticating a caller. An issuer-scoped subject reference, delivery of the withdrawal reason and a caller-bound operation identity remain open. Standalone sessions are process-local memory with no durable record and stay `unsupported_future_operation` |

These foundations are already sufficient for their **existing atomic change-record
purpose**. The inventory does not label all control-plane writes lossy or ask for a second
reconciliation outbox. Thirteen inventory rows are `already_sufficient` and
qualified: each admits a keyed request whose caller-bound receipt and journaled
or file-delivered `authority_event.v1` commit with the change. They are
`policy_postgres`, `tools_postgres` and `policy_tests_postgres` (cluster mode
only); `connection_postgres`, `connection_standalone`, `catalog_postgres` and
`catalog_standalone`; `token_issue_postgres`, `token_issue_standalone`,
`token_rotate_postgres` and `token_rotate_standalone`; `local_secrets`
(standalone only); and `mutation_approval_prepare_postgres`.
`missing_metadata` and `missing_delivery` now appear only on rows required mode
refuses: `configuration_import`, `mutation_approvals` and
`mutation_approval_prepare_standalone`. The inventory also records the specific
Unix file delivery guarantees for the qualified rows and the keyed revoke path.
[Authority event v1](#authority-event-v1)

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
- Startup configuration activation has no whole-configuration revision ledger,
  so `AUTHORITY_EVIDENCE_DURABILITY=required` refuses to start in either mode
  until #242 provides one ([Required-durability mode](#required-durability-mode)).
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
Migration 33 records and delivers the acting login for a grant or replacement
and the system actor for expiry or rejection. The row stays incomplete while
the operation ID lacks caller binding and delivery omits the withdrawal reason.

## Authority event v1

With `AUTHORITY_EVENT_FORMAT=qualified_v1`, both dispatchers apply one
qualification rule to every evidence row they deliver: every PostgreSQL
journal source, and the standalone Connection, local-secret and catalog
tables.

1. A caller UUIDv7 `operation_id`, an actor that is a provider-authenticated
   principal with a canonical issuer, and revisions that satisfy the
   operation's v1 transition: the row is delivered as `authority_event.v1`.
2. A caller UUIDv7 with a gateway service-token actor, which has no provider
   issuer to scope its subject: `authority_event_delivery.v1`.
3. A UUIDv4, which the store minted for an unkeyed change:
   `authority_event_delivery.v1`.
4. A caller UUIDv7 with any other actor (a system actor, a principal without
   a canonical issuer, or no recorded actor), or with revisions outside the
   operation's transition: delivery stalls at that row. No writer binds a
   caller key to such a row, so it must not pass as a legacy record.

Two routes bind a caller key today: the keyed service-token revocation
`POST /v1{ADMIN_PREFIX}/tokens/{id}/revoke` and the keyed approval preparation
below. Every other store still mints UUIDv4 IDs, so the rule delivers no other
operation as `authority_event.v1` until its own route is keyed. The UUIDv7 in
the request binds the action, target and caller. A token row's revision
advances by exactly one per change, and projection checks that for a keyed
rotation or revocation, beside the row's shared security revision. The actor's
`subject_ref` is a keyed reference over the canonical issuer and subject
together. The issuer and the resource also have their own domain-separated
references. The wire record contains those references, the event and operation
IDs, authority ID, commit time and revision transition.
[Event schema](schemas/authority_event.v1.schema.json)

A `credential.binding_change` is delivered in v1 with resource kind
`credential_binding`, referenced in the `resource.credential_binding` domain
from its Connection's ID. It carries the operation ID of the Connection create
or replace that changed the binding, which is how a consumer joins the two.
The binding identifier, secret IDs and locators stay out of the record. Its
`authority_event_delivery.v1` form still names the Connection, as before.

A standalone token row is judged by its `revised` marker (plan P5). A revised
row carries the token's revision (an issue NULL to 1, a rotation or revocation
one step up) and follows the caller-bound rule above. A row with `revised = 0`
records no revision, and v1 requires one, so it carries nulls and keeps
`authority_event_delivery.v1` whatever its operation ID. That includes the keyed
revocations SQLite recorded since #765 before the token table recorded
revisions, whose delivered bytes do not change. A revised row without a valid
transition, or a row with `revised = 0` that records a revision, is out of shape
and stalls. A standalone re-encryption batch, which no caller starts, also keeps
its delivery record.

Both keyed paths support durable delivery through the file sink on a Unix
filesystem that honors file and directory sync, using shared
storage or storage shipped to the same durable consumer. The file and its
parent directory are synced before the cursor advances. A sync failure leaves
the batch pending. An interrupted cursor update
can redeliver the event. Consumers deduplicate on the authority and event IDs.
The opt-in log sink writes the same representation with process-log acceptance.

Consumers select the parser for each record by its `schema_version`. Under the
default format every row keeps `authority_event_delivery.v1`, and a caller key
never stalls delivery; only a preparation receipt, which has no legacy form,
holds the cursor (below). Unkeyed changes, gateway service-token actors and
standalone token rows also keep that representation on an opted-in stream.
Historical UUIDv4 rows remain eligible for delivery in their existing format.
No actor or operation identity is backfilled.
[Format configuration](configuration.md#authority_event_format)

Revision transitions are operation-specific. Resource creation (`connection.create`,
`secret.create`, `service_token.issue`, `admin_session.grant`, `mutation_approval.prepare`) has no prior revision; replacement,
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

For keyed service-token revocation, the only inputs are the target token and
the authenticated actor. The dedicated POST route refuses bodies, query
parameters and conditional headers. Both stores check the existing service-token
evidence for the operation UUID under the same write lock that serializes the
change. The committed evidence binds that UUID to the target, revoke action,
actor kind, subject, canonical issuer and authentication method. A matching
retry returns the same receipt (operation UUID, target token ID and revocation time)
and emits no second evidence row.
A different binding conflicts. Caller IDs use UUIDv7. Earlier and unkeyed
changes use generated UUIDv4 IDs and cannot be claimed as keyed operations.
Both negotiated representations carry the supplied UUID as their operation ID. [Service token admin API](configuration.md#service_token_cache_ttl_ms)

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
timestamps, imprecise numeric revisions and invalid transitions. These schema
tests alone do not prove runtime redaction. The producer tests of each keyed
family drive real keyed changes whose inputs carry synthetic sensitive markers
and inspect what the gateway stores. Router-level marker tests also capture, while
the handlers run, every `tracing` log line at every level and every metric, and
check that no marker or binding digest reaches a log line, a metric name or label,
an answer or (where the test has it) the audit stream. Their capture
(`admin_tokens_app_tests::capture_logs_and_metrics_on_every_runtime_thread`)
covers the test's thread and the runtime's blocking pool, where the SQLite stores
run, and checks itself before it returns: a log line and a metric label it plants
on each of those threads must both be captured, so a test that searches the
rendering for a marker cannot pass by missing a metric label emitted on the pool
(`the_capture_sees_logs_and_metrics_on_the_blocking_pool` pins it). It does not see
`log`-crate records from dependencies or threads the code spawns itself, such as
the audit log writer. Log-line and metric-label redaction (I5) is therefore tested
for each keyed family, for the operations listed here and no others:

- Service tokens: `a_replayed_token_issue_or_rotation_repeats_no_side_effect_and_never_returns_the_plaintext`
  (keyed issue and rotation with their retries, conflicts, `403` refusals and a
  failed reservation, standalone; no plaintext or binding digest in a log line or
  a metric) and the store test
  `storage::contract_tests::sqlite_a_failed_token_reservation_is_counted_and_no_secret_reaches_logs_or_metrics`.
- Local secrets: `a_keyed_secret_change_keeps_synthetic_markers_out_of_the_reservation_receipt_evidence_and_file`
  and, through the router,
  `a_keyed_secret_change_keeps_synthetic_markers_out_of_the_receipt_audit_logs_and_metrics`
  (keyed create, rotation and, through the router, delete, with their retries and
  conflicts, standalone; the values, the label and the digests reach no answer,
  audit event, log line or metric, and the values reach neither the database
  file nor its WAL). Both also
  read back the nonce and ciphertext each change stored and search for them as
  hex, base64 and the `Debug` form of their first eight bytes: the store test in
  the reservations, receipts and evidence columns, the router test in every
  answer (the secret's own view included), the audit events, the logs and the
  metrics.
- Connections: `the_binding_digest_is_stored_only_in_the_reservation_row`, run
  against both stores, for the receipts and evidence rows;
  `marker_keys::a_keyed_connection_change_keeps_synthetic_markers_out_of_the_receipt_audit_logs_and_metrics`
  (standalone) and
  `cluster_connection_keys::postgres_keyed_connection_and_catalog_changes_keep_synthetic_markers_out_of_the_logs_and_metrics`
  (PostgreSQL) for logs, metrics, answers and audit. The credential aliases of
  bearer, additional-header and TLS client authentication, a delegated issuer,
  caller assertions and OAuth client credentials are marked. The OAuth
  client-credentials replacement and the keyed Connection delete are driven in
  the SQLite form only.
- Catalogs: `a_keyed_catalog_change_keeps_synthetic_markers_out_of_the_reservation_receipt_and_record`
  (both stores), and for logs, metrics, answers and audit
  `marker_keys::a_keyed_catalog_change_keeps_synthetic_markers_out_of_the_receipt_audit_logs_and_metrics`
  (standalone) and the PostgreSQL test above. They drive the OpenAPI
  registration, refreshes, overlay replacements (one with a marked enum source)
  and an overlay delete on a credentialed Connection whose secret IDs, file
  locators and values are markers. One refresh resolves both credentials and
  sends them to a recording HTTPS upstream the test runs, and one fails after
  sending them. That upstream requires a TLS client certificate, which the
  enabled Connection names through two operator aliases whose IDs and file
  locators are markers too; each fetch records that the certificate presented
  is the one issued for the run, and no line of the client private key reaches
  a log line, a metric, an answer or the audit stream. `catalog.mcp.publish` is
  not driven.
- Policy, tools and policy tests:
  `a_keyed_document_commit_keeps_synthetic_markers_out_of_the_reservation_receipt_and_record`,
  and for logs, metrics, answers and audit
  `cluster_document_keys::a_keyed_document_change_keeps_its_digest_and_key_out_of_the_receipt_audit_logs_and_metrics`
  (PostgreSQL). That test drives `policy.publish`, `tools.publish` and
  `policy_tests.publish` only. Rule create, update, delete and reorder, rollback
  and suggestion acceptance share the binding and commit path but are not driven,
  so they have no log and metric test.

The family sections below describe each.

### PostgreSQL approval preparation

Creating an occurrence with `PUT /v1{ADMIN_PREFIX}/tools/{id}/mutation-approvals` requires PostgreSQL,
`AUTHORITY_EVENT_FORMAT=qualified_v1`, an authorized principal with a canonical
issuer, one strong `If-Match` ETag and one caller-supplied RFC UUIDv7
`Idempotency-Key`. Under `AUTHORITY_EVIDENCE_DURABILITY=required` it also needs
`AUTHORITY_EVENT_SINK=file` and a Unix build ([Keyed authority changes](#keyed-authority-changes)). Schema 35 reserves that key across this operation and keyed
service-token revocations. The transaction writes the pending occurrence, its
immutable receipt and a journal entry. A journal capacity or evidence-write
failure rolls back all three and the key reservation. The receipt survives
approval expiry, cleanup and deletion of the Connection.

After losing a response, the caller can repeat the PUT with the same identity
and auth mode, key, tool ID, ETag and exact request body. The stored receipt
identifies the original occurrence and its original expiry. An exact receipt remains
readable after a downgrade to `delivery_v1`. Replaying the receipt
does not extend its life or prepare another action. Reusing the key with a
different binding returns a conflict. The ordinary best-effort POST continues to
create a fresh occurrence on each request. Required mode refuses that POST.

The event carries the persisted operation and event IDs, issuer-scoped caller
reference, issuer reference, occurrence reference and database timestamp.
Preparing a new occurrence sets its `mutation_approval` revision to 1, with
a null prior and shared security revision. Request bytes, the ETag, digests,
tool details and raw caller or occurrence identifiers stay out of the event.
A dispatcher reconfigured to `delivery_v1` holds its cursor on an existing
prepare receipt until an operator restores `qualified_v1`. In best-effort mode
with the sink disabled, the first keyed prepare starts holding journal capacity
until a dispatcher checkpoints the records. File delivery has
the Unix sync and shared-storage conditions above. The log sink provides only
local tracing acceptance.

Every distinct committed keyed prepare permanently adds one row to
`greengateway.authority_caller_operation_ids` and one to
`greengateway.mutation_approval_prepare_evidence`. A keyed token revocation
also adds one operation reservation. Exact retries add zero rows. The 15-minute
approval lifetime, the active-approval limits and journal retention leave these
tables intact. PostgreSQL storage capacity limits their growth. The gateway
provides no receipt quota, expiry, size watermark or supported manual purge.
Monitor the free space on the database volume and track both tables and their
indexes, for example with this read-only size query.

```sql
SELECT pg_total_relation_size('greengateway.authority_caller_operation_ids') AS reservation_bytes,
       pg_total_relation_size('greengateway.mutation_approval_prepare_evidence') AS receipt_bytes;
```

Provision more database capacity before the volume fills. From schema 36 the
reservation table holds the keys of every keyed action, not only these two, and
the same query measures it. A full journal has a
separate limit, `AUTHORITY_EVENT_JOURNAL_CAPACITY` (default 1,000,000
units, range 1 to 1,000,000,000). Monitor
`greengateway_authority_event_journal_retained` against
`greengateway_authority_event_journal_capacity`. Restore a working
`qualified_v1` consumer, allow delivered entries to age out, shorten journal
retention, or raise the capacity across the cluster. Removing a cursor cannot
reclaim space after the first keyed preparation.

### Caller operation keys bound to a request

Schema 36 (PostgreSQL migration 36) and the standalone reservation table prepare
caller operation IDs for every admin change that will take an `Idempotency-Key`.
Connection create, replace and delete bind keys through them
([Keyed Connection changes](#keyed-connection-create-replace-and-delete)); each other
operation family does so in its own change, through the contract in
[Keyed authority changes](#keyed-authority-changes).
A key belongs to exactly one request: its binding digest is a
domain-separated, length-prefixed SHA-256 over the action, the recorded actor
(kind, canonical issuer, subject and auth mode), the target, the `If-Match` value
and the request with secret values removed
(`gateway/src/authority_events/caller_operation.rs`). Only an issuer-bound
principal or a service token can own a key; a system actor cannot, and a
gateway-assigned v4 ID is never a key. The digest is stored only in the key's
reservation row, beside the key and its action, in the transaction that commits
the change and its evidence. It never appears in a receipt, a delivered record, a
log line or a metric.

- PostgreSQL: migration 36 widens `greengateway.authority_caller_operation_ids`
  to every action a key will be reserved for (`CALLER_OPERATION_ACTIONS` in
  `storage::postgres_authority_events`) and adds a nullable `binding_digest`.
  Every new action must store one. The keyed revoke and keyed prepare keep their
  reservations with no digest, and their own replay checks, unchanged.
  `read_caller_operation` looks a key up without a transaction, so a handler can
  answer an exact retry before any external work; `reserve_bound_operation`
  reserves it in the change's own transaction, where a second writer competing
  for the key waits on it and then reads the winner's row.
- Standalone: each SQLite file that owns authority evidence keeps the same table,
  created from one definition by both owners (the token database on open, the
  Connections database in its migration 16), so a token store and a Connections
  store on one file share one table. Its action list is fixed for every keyable
  standalone action now, because SQLite cannot widen a CHECK in place. A keyed
  service-token revoke now reserves its key with its evidence, so no later keyed
  issue, rotation or Connection change in that file can reuse it, and a key
  another action reserved refuses the revoke. Every open of the token database
  reserves any keyed revoke an older build committed without a reservation; the
  older build itself never reads the table, so it can still serve the file, but
  it does not enforce reservations the newer build made.
- Standalone upgrades: the Connections database upgrade is one-way. An older
  build refuses a version-16 Connections file, and there is no downgrade: recover
  forward with a build that knows Connections version 16. Restoring the
  pre-upgrade file copy brings back every Connection and secret deleted since and
  undoes every rotation, so it is disaster recovery, not rollback. The token
  database needs no restore to run an older build, at the cost above.
- The token database's revision columns (plan P5) are added on open in the
  same way and need no restore either. An older build serving the file inserts
  by its own column list, so its tokens start at revision 1 and its evidence rows
  take NULL revisions and `revised = 0` and stay legacy delivery records; but it
  does not advance `service_tokens.revision` when it rotates or revokes, so after
  such a rollback the next revised row of that token can name a prior revision
  older than the token's real history. Nothing is backfilled or rewritten. An
  older build serving the file also delivers it: its evidence query reads no
  revision, so every row this build wrote that is not yet delivered, keyed
  principal issues, rotations and revocations included, goes out as an unrevised
  `authority_event_delivery.v1` record instead of `authority_event.v1`. Let
  standalone delivery catch up
  (`greengateway_standalone_authority_event_undelivered{store="service_tokens"}`
  at 0) before rolling back; a
  roll-back between the sink accepting a batch and the cursor commit delivers the
  same `(authority_id, event_id)` in both forms, and a consumer that deduplicates
  on that pair keeps whichever arrived first.
- Each SQLite file is its own authority, so a key is unique within one file, as
  consumers deduplicate events on `(authority_id, event_id)`: the token database
  and a separate Connections database each accept a key once.

Rows are never removed. A reservation exists exactly when a keyed evidence row
with that operation ID and action exists, in both stores, with two exceptions,
both written by an older build serving a token database:

- a keyed revoke it committed since this build last opened the file, which the
  next open reserves;
- a keyed revoke whose key this file had already reserved for another action
  (the older build checks only the evidence table). That cannot be repaired: the
  key stays with the action that reserved it and the revoke keeps no
  reservation. Every open counts such revokes and logs the count with a fixed
  message, never the key, token or actor. It cannot happen before an operation
  family reserves keys for another action in the token database or the
  Connections database on a shared file.

`a_keyed_revoke_reserves_its_key_with_its_evidence`,
`reopening_reserves_keyed_revocations_an_older_build_wrote` and
`reopening_counts_a_keyed_revocation_whose_key_another_action_holds` assert
these cases.

### Keyed authority changes

Every admin change that binds an `Idempotency-Key` through the shared helpers
in `gateway/src/admin_responses.rs` follows one contract. Connection create,
replace and delete do ([below](#keyed-connection-create-replace-and-delete)), and
so do service-token issue and rotation
([below](#keyed-service-token-issue-and-rotation)), managed catalog publication
and overlay changes ([below](#keyed-catalog-publication-and-overlay-changes)),
standalone local-secret create, rotation and delete
([below](#keyed-local-secret-create-rotation-and-delete)) and, in cluster mode,
policy, tools and policy test changes
([below](#keyed-policy-tools-and-policy-test-changes)); each
other operation family
adopts the contract in its own change, and the inventory qualifies its rows when
it does. The two routes that took a key first, the
keyed service-token revoke and the keyed approval preparation, predate the
contract. They are listed in `KEYED_ROUTES` and follow the first rule below,
but they keep their own receipts (the preparation answers
`{operation_id, occurrence_id, prepared_at, expires_at}`), their own conflict
answers, and their own order of work, and they do not ask the operation gate.
The generic receipt and `409 caller_operation_conflict` below apply to routes
that bind keys through the shared helpers.

**A key is honoured or refused, never ignored.** The router keeps a reviewed table
of the routes that honour a key, `KEYED_ROUTES` in `gateway/src/routing.rs`
(today `POST /v1{ADMIN_PREFIX}/tokens/{id}/revoke`,
`PUT /v1{ADMIN_PREFIX}/tools/{id}/mutation-approvals`,
`POST /v1{ADMIN_PREFIX}/connections`, `PUT` and `DELETE`
`/v1{ADMIN_PREFIX}/connections/{id}`, `POST /v1{ADMIN_PREFIX}/tokens` and
`POST /v1{ADMIN_PREFIX}/tokens/{id}/rotate`). Any other admin request
that carries the header with a method other than `GET`, `HEAD` or `OPTIONS` is
answered `400 {"error":"...","reason":"idempotency_key_unsupported"}` before its
handler runs, so nothing is read or written. That includes the unkeyed
`DELETE /v1{ADMIN_PREFIX}/tokens/{id}` and the ordinary preparation `POST`, which
before this change ignored the header. The checker holds `KEYED_ROUTES` and its
table of reviewed qualified paths (`QUALIFIED_PATHS`) to the same methods and
routes.

The refusal applies to withdrawals and to the admin session routes too: the
unkeyed token `DELETE`, secret deletion, the delegated-token purge, `POST .../auth/logout` and `POST .../auth/callback`. A client that
attaches `Idempotency-Key` to every mutation can therefore not revoke, delete or
log out until it drops the header from those requests. This is deliberate: a
key is honoured or refused on every admin mutation, so that once a later change
makes a withdrawal keyed, no build that serves beside it answers the same key
differently. The answer is immediate and names the header, so the client can
retry without it at once.

**A key is honoured only once the whole cluster honours it.** In cluster mode a
keyed request asks the operation gate for `authority.caller_operation_keys`
(capability `caller_operation_keys`, schema 36, durable fence; see
[Gated operations](deployment/postgres.md#gated-operations)) before the store is
called. It is refused, `409 capability_not_advertised` or `503` when the gate
cannot answer, while any live member lacks the capability. The first admission
raises the durable contract fence, so a build that would ignore the key, or
deliver a caller-bound change as `authority_event_delivery.v1` from the
dispatcher's lease, can no longer start or rejoin. That admission is the
[rollback cutoff](deployment/postgres.md#the-rollback-cutoff) for such builds.
The store confirms the same fence inside the change's transaction before it
reserves the key (`reserve_bound_operation`). Once the fence carries the
capability, the gate answers from an unlocked read of the fence and the roster
and takes no exclusive lock, so keyed requests running at the same time, exact
retries included, admit each other; only a migrator holding the schema lock
refuses them (`503 migration_in_progress`). A refusal is answered from the same
unlocked read, so while the gate refuses, keyed requests do not queue on the
fence row or hold up heartbeats. The keyed revoke and keyed
preparation predate the capability and do not ask the gate.

**The request.** The method and route are the route's own, plus one
`Idempotency-Key` holding a canonical lowercase RFC UUIDv7. Under `best_effort`
the header is optional, and a request without it behaves exactly as before. A
malformed or repeated header is `400`. A principal without a canonical issuer
cannot own a key (`403`, as for the keyed revoke), and a system actor never
can. The key is bound to the action, the recorded actor, the target, the
`If-Match` value and the request with secret values removed
([above](#caller-operation-keys-bound-to-a-request)).

**The answers.** The first commit answers as the route does today. An exact retry
is answered `200` with the receipt read from the committed evidence row,
`{operation_id, operation, resource_id, revision, committed_at}`, which never
carries a secret or the binding digest. The same key with any other binding,
action or actor is `409 caller_operation_conflict`, and nothing changes. A
keyed request that would change nothing writes no evidence and reserves
nothing, so it cannot be reconciled by its key: if its response is lost and the
resource then changes, the retry gets `412`, and the caller reads the resource
again.

**The order of work.** The handler first authorizes the caller for the change
and validates the request, as it does today. Only then does it bind the key
(`caller_operation`), ask the gates (`admit_keyed_authority_change`), and answer
an exact retry from a read-only pre-check (`replayed_receipt`, from
`read_caller_operation`) before any external I/O or post-commit side effect.
Authorization comes first because admission can raise the durable contract
fence, which is irreversible, applies to the whole fleet and is the rollback
cutoff: admin routes authorize themselves, so a handler that asked the gates
first would let any authenticated caller without the route's permission cut off
rollback with one keyed request answered `403`. The gates come before the
pre-check, an exact retry included, because the pre-check reads the authority:
required mode refuses a form it does not admit before anything is read, and a
key is answered only while the whole fleet honours keys. Inside the one transaction the store
then looks the key up, reads the target (a stale ETag is `412`, a no-op rolls
back), confirms the fence and reserves the key, makes the change, inserts the
evidence rows under the caller's operation ID, appends to the journal last
(PostgreSQL), and commits. These helpers are in `gateway/src/admin_responses.rs`;
`operation_receipt` and `caller_operation_conflict` build the two answers above.
A handler names its change to the gate as `KeyedChange::Gated(operation)` or,
for one of the three withdrawals, `KeyedChange::Withdrawal(...)`. The key must
be bound to that operation's or withdrawal's code; a key bound to anything else
is refused as a handler defect (`500`) before any gate is asked. Each family's tests include
a keyed request from a caller without the route's permission, which is `403`
and leaves the contract fence unchanged.

**Required mode.** Under `AUTHORITY_EVIDENCE_DURABILITY=required` a
`caller_key_required` change is admitted only when all of these hold, checked in
this order, and its `409 authority_evidence_unsupported` names the first that
does not (`KeyedAdmission` in `gateway/src/authority_events/required.rs`):

1. the request is keyed;
2. the actor is a provider-authenticated principal with a canonical issuer;
3. `AUTHORITY_EVENT_FORMAT=qualified_v1`;
4. `AUTHORITY_EVENT_SINK=file`: the log sink only hands an event to the log
   writer, which is not a durable store;
5. the build is a Unix build, where the file sink syncs the file and its
   directory.

The last three are the criteria every qualified path in the inventory records
(`format`, `durable_sink`, `filesystem`), so the gate now enforces what the
qualified rows claim. This tightens the keyed preparation: under `required` with
the log sink, or on a Windows build, it is refused. The keyed preparation reads
its receipt before it asks this gate, as it did before: an exact retry of a
preparation that already committed is still answered from its receipt after the
deployment stops meeting the criteria (a format or sink downgrade), because the
answer changes nothing and is how a caller reconciles a lost response; a new
preparation is refused. The ordinary preparation `POST` is refused with a
message that points at the keyed `PUT`. A change that only removes
authority and that a remote caller starts (token revocation, Connection
deletion, local-secret deletion) never asks the evidence gate: every form of it
stays admitted ([Rows admitted without qualification](#rows-admitted-without-qualification)).

`required_tests::caller_key_required_admits_only_a_keyed_issuer_bound_principal_under_qualified_v1_with_the_file_sink`,
`a_keyed_request_with_the_log_sink_is_refused_and_the_refusal_names_the_sink` and
`withdrawals_never_ask_the_evidence_gate` prove the gate;
`routing_app_tests::an_idempotency_key_on_a_route_that_does_not_honour_it_is_refused_and_changes_nothing`
sends a key to every mutating method of every admin API route;
`compatibility_tests::caller_operation_keys_waits_for_every_live_member_and_raises_the_fence`
and `contract_tests::postgres_audit_tests::a_bound_reservation_below_the_fence_is_refused`
prove the capability, the fence and the store's check;
`contract_tests::postgres_audit_tests::the_caller_key_gate_raises_the_fence_once_and_then_admits_concurrent_keyed_changes`
proves the chain end to end against PostgreSQL (refused while a live member
lacks the capability, the first admission raises the fence and the store then
reserves, later admissions write nothing and admit each other while another
admission holds the fence row); and `authority_evidence_app_tests` proves the
helpers.

### Keyed Connection create, replace and delete

The first operation family on the contract above (issue #425). Rows
`connection_postgres` and `connection_standalone` (`connection.create`,
`connection.replace`, `credential.binding_change`) are qualified, and
`connection_delete_postgres` and `connection_delete_standalone` are
`withdrawal_admitted` with their keyed path
([below](#rows-admitted-without-qualification)).

- **Routes.** `POST /v1{ADMIN_PREFIX}/connections`, and `PUT` and `DELETE`
  `/v1{ADMIN_PREFIX}/connections/{id}`, each with an optional `Idempotency-Key`.
  They are in `KEYED_ROUTES`, and the checker's `QUALIFIED_PATHS` names the same
  methods and routes for both modes (a credential binding change's path is the
  replacement's `PUT`).
- **Binding.** The key is bound to the action, the recorded actor, the Connection ID
  (empty for a create), the `If-Match` value as received, and the body as
  canonical JSON (object keys sorted, whitespace dropped; empty for a delete). A
  Connection body holds no secret value, only credential aliases (`secret_id`,
  `client_secret_id`, an additional header's `secret_id`, TLS and caller-assertion
  key aliases) and provider locators; they stay in, so a retry that points the
  Connection at another credential under the same key is `409` and the stored
  binding stays. The digest is stored only in the key's reservation row.
- **Order of work.** The handler authorizes the caller (`admin:connections:write`,
  and `admin:connections:secrets:write` for credential authority) and validates the
  body, then binds the key, asks the gates (create and replace ask the evidence gate
  as `connection.create` and `connection.replace`; a delete is a withdrawal and asks
  only the operation gate when keyed), and answers an exact retry from the
  read-only pre-check, all before the `If-Match` comparison against the replica's
  snapshot, which a committed change has since moved, and before any secret
  provider is consulted. Under the mutation lock the control plane asks the key
  again before its own checks against the snapshot. Inside the store's one
  transaction (PostgreSQL after its `connection_state_revision` lock, SQLite under
  `IMMEDIATE`) the key is looked up first, then the record is read and its ETag,
  capacity and dependencies checked, then the key is reserved (PostgreSQL confirms
  the fence carries `caller_operation_keys`), then the change and its evidence rows
  are written under the caller's key, and the journal entry last.
- **Answers.** The first commit answers as the route always has (`201` with the
  detail, `200` with the detail, `200` with the deleted ID). An exact retry is `200`
  with the receipt `{operation_id, operation, resource_id, revision, committed_at}`
  and repeats no change and no audit event. A replacement's receipt is its
  `connection.replace` row; a deletion's carries the revision it removed. Both are
  answered after the record is gone, because the evidence outlives the record (a
  keyed `PUT` or `DELETE` for a missing Connection binds its key and asks the
  pre-check before it answers `404`). An identical replacement is answered before
  the key is reserved, so it records and reserves nothing and is not reconcilable
  by its key.
- **Completion.** Once admitted, a create, replace or delete runs on a task of its
  own, so a client that disconnects while the store commits does not cut the
  change short: the replica still publishes it to its runtime snapshot, reconciles
  or removes its catalogs and emits its audit event. A retry's receipt therefore
  never describes a change the replica is not serving. (A process that stops
  between the commit and the publish reloads the record from its store when it
  starts, and in cluster mode the Connections reconciler installs it.)
- **A replacement that changes credentials** writes the `connection.replace` row and
  a `credential.binding_change` row under the one caller key; under `qualified_v1`
  both are delivered as `authority_event.v1` sharing `operation_id`, the second
  naming a `credential_binding` resource derived from the Connection ID.
- **Required mode.** Create and replace are `caller_key_required` in both modes:
  only the keyed request of an issuer-bound principal with `qualified_v1`, the file
  sink and a Unix build is admitted, and every other form, service-token callers
  included, is `409 authority_evidence_unsupported` before anything is read or
  written. Deletion is admitted in every form. The admin UI sends no key, so under
  `required` it can delete a Connection but not create or replace one (#242 tracks
  adding keys to it).

Tests. The store contract is written once in
`gateway/src/connections/caller_operation_contract.rs` and run against both stores
(`sqlite_*` there, `postgres_*` in `connections::pg_store::tests`); every case ends
by asserting that a Connection action's reservation exists exactly when its
evidence row does: `connection_caller_operation_contract` (exact retries answered
from the receipt with no second change),
`a_reused_key_with_a_different_binding_conflicts_and_changes_nothing`,
`a_key_reserved_by_another_action_cannot_take_effect_here` (another Connection
action and a keyed revoke's key),
`a_failed_evidence_insert_rolls_back_the_keyed_change_and_its_reservation`,
`a_stale_etag_under_a_key_writes_no_change_evidence_or_reservation`,
`an_identical_keyed_replace_records_and_reserves_nothing`,
`two_writers_racing_one_key_commit_one_change`,
`two_keys_racing_one_revision_leave_only_the_winners_rows` and
`the_binding_digest_is_stored_only_in_the_reservation_row`. PostgreSQL adds
`a_full_journal_refuses_the_keyed_connection_change_and_reserves_nothing` and
`a_keyed_connection_change_below_the_fence_is_refused_and_changes_nothing`.
`a_keyed_connection_change_is_redelivered_identically_after_a_crash_before_the_cursor_commit`
(in both `authority_events::dispatcher::tests` and
`authority_events::standalone::tests`) delivers a real keyed create, credential
change and delete as closed v1 events through the file sink and redelivers them
byte for byte. Through the admin handlers, `authority_evidence_app_tests` proves
`a_replayed_connection_change_repeats_no_side_effect`,
`a_different_credential_reference_under_the_same_key_conflicts_and_keeps_the_old_binding`,
`required_mode_refuses_the_unkeyed_connection_create_and_replace_and_admits_the_keyed_principal`
(Unix builds),
`required_mode_refuses_a_keyed_connection_change_by_a_service_token_or_under_delivery_v1_or_with_the_log_sink`,
`required_mode_admits_every_form_of_connection_delete`,
`a_keyed_connection_change_without_the_routes_permission_is_forbidden_and_reserves_nothing`
(each key first committed by an authorized caller, so a handler that consulted the
key before authorizing would answer `409`),
`required_mode_authorizes_a_connection_change_before_it_asks_the_evidence_gate` and
`an_admitted_connection_change_finishes_after_its_client_goes_away`. In cluster
mode, against PostgreSQL and a real roster,
`authority_evidence_app_tests::cluster_connection_keys::postgres_keyed_connection_changes_wait_for_the_fleet_and_authorize_before_the_fence`
proves that a keyed create, replace and delete are `409 capability_not_advertised`
and reserve nothing while a live member lacks `caller_operation_keys` (the unkeyed
forms still commit), that a keyed request from a caller without the route's
permission is `403` and leaves `contract_fence` unchanged, and that once the
lacking member is stale the first keyed change raises the fence once and each
exact retry, a deletion's included, is answered from its receipt. A reservation
that cannot be written is counted on the evidence failure counters
(`sqlite_a_failed_reservation_rolls_back_the_keyed_change_and_is_counted`, and the
PostgreSQL fence test).

### Keyed service-token issue and rotation

An operation family on the contract above (issue #425, plan P5). Rows
`token_issue_postgres`, `token_issue_standalone`, `token_rotate_postgres` and
`token_rotate_standalone` are qualified, and `token_revoke_standalone` joins
`token_revoke_postgres` as `withdrawal_admitted` with its keyed path
([below](#rows-admitted-without-qualification)). These are the first standalone
qualifications.

- **Routes.** `POST /v1{ADMIN_PREFIX}/tokens` and
  `POST /v1{ADMIN_PREFIX}/tokens/{id}/rotate`, each with an optional
  `Idempotency-Key`. They are in `KEYED_ROUTES`, and the checker's
  `QUALIFIED_PATHS` names the same methods and routes for both modes. The keyed
  revoke keeps its own route, receipt and replay check (issue #765); its
  standalone form now also has a reviewed path.
- **Binding.** An issue's key is bound to `service_token.issue`, the recorded actor
  and the request as canonical JSON (`{"expires_at":...,"scopes":[...]}`, the scopes
  in the order given; an issue has no target). A rotation's key is bound to
  `service_token.rotate`, the actor and the token ID; it has no body. Neither route
  takes a precondition, so the `If-Match` field of the binding is empty. A token
  request holds no secret: the plaintext does not exist until the store mints it.
- **Order of work.** The handler authorizes the caller (`admin:tokens:write`), checks
  the scope bounds and the caller's delegation authority over the scopes, and for an
  issue validates `expires_at` and the creator's length, so a malformed request is
  `400` before anything is admitted. A rotation reads the stored token's scopes for
  the delegation check, so it asks the evidence gate first: that gate reads
  configuration only and cannot raise the fence, and required mode refuses a form it
  does not admit before anything is read. Then the handler binds the key, asks the
  gates (as `service_token.issue` or `service_token.rotate`) and answers an exact
  retry from the read-only pre-check. Once past the router, the issue or rotation
  runs on a task of its own, as a Connection change does, so it finishes, audit event
  and cache invalidation included, when its client goes away. Inside the store's one transaction
  (PostgreSQL after its `service_token_state_revision` lock, SQLite under
  `IMMEDIATE`) the key is looked up first, then a rotation reads its token (an
  unknown token is `404` and a revoked one `409`, and neither reserves anything),
  then the key is reserved (PostgreSQL confirms the fence carries
  `caller_operation_keys`, before the shared revision), then the change and its
  evidence row are written under the caller's key, and the journal entry last.
- **Answers.** The first commit answers as the route always has: `201` or `200` with
  the token and its plaintext, returned this once. An exact retry is `200` with
  `Cache-Control: no-store` and the receipt
  `{operation_id, operation, resource_id, revision, committed_at, secret_returned}`,
  where `resource_id` is the token ID, `revision` the token's revision after the
  change and `secret_returned` always `false`. The plaintext is never stored, so a
  retry cannot return it, and it repeats no change and no audit event. A rotation's
  retry still drops the replaced plaintext from the answering process's validator
  cache, which is idempotent: a first attempt committed by another process sharing
  the token file may have left it cached there. A rotation's retry is answered
  whatever happened to the token since. Any other use of the key is
  `409 caller_operation_conflict`.
- **A lost response.** If the first response was lost, a live token exists whose
  plaintext nobody holds, and which may have been seen in transit. The caller
  revokes it by the ID in the receipt (`DELETE .../tokens/{id}` or the keyed
  `POST .../tokens/{id}/revoke`) and issues again with a new key; a lost rotation
  is answered the same way, by rotating again with a new key or revoking.
- **Revisions.** Every committed issue, rotation and revocation records the token's
  revision before and after it. PostgreSQL always has (`service_tokens.revision`).
  The standalone token database gains it on open: `service_tokens.revision`
  (`DEFAULT 1`) and the evidence columns `prior_version`, `new_version` and the
  per-row marker `revised`. Rows written before then, and rows an older build still
  writes into the upgraded file (it inserts by its own column list), keep NULL
  revisions and `revised = 0` and are delivered as the unrevised
  `authority_event_delivery.v1` records they always were. Every row this build
  writes has `revised = 1` and a transition (issue NULL to 1, rotation and
  revocation one step up), and the table's CHECK refuses a revised row without its
  action's transition, as PostgreSQL migration 27 does, so under `qualified_v1` a keyed principal issue,
  rotation or revocation in the token database is delivered as `authority_event.v1`
  ([Standalone delivery](#standalone-delivery)).
- **Required mode.** Issue and rotation are `caller_key_required` in both modes: only
  the keyed request of an issuer-bound principal with `qualified_v1`, the file sink
  and a Unix build is admitted, and every other form, service-token callers
  included, is `409 authority_evidence_unsupported` before anything is written.
  Revocation is a withdrawal and stays admitted in every form. The admin UI sends no
  key, so under `required` it can revoke a token but not issue or rotate one (#242
  tracks adding keys to it).

Tests. The store contract is written once in `gateway/src/storage/contract_tests.rs`
and run against both stores (`sqlite_*` there, `postgres_*` in
`postgres_audit_tests::keyed_token_changes`); each case ends by asserting that a
token action's reservation exists exactly when its keyed evidence row does:
`service_token_caller_operation_contract` (exact retries answered from the receipt
with no second token, row or plaintext; another body or actor under the key, an
issue's key on a rotation, a rotation's key on another token and a keyed revoke's
key on an issue all `409`, and a revoke cannot take an issue's key; an unknown or
revoked token reserves nothing; the token a receipt names can be revoked by its ID;
the revision chain; no plaintext or binding digest outside the reservation),
`keyed_token_writers_racing_commit_one_change_and_never_leave_a_live_plaintext` and
`a_failed_evidence_insert_rolls_back_the_keyed_issue_and_rotation_and_their_reservations`.
PostgreSQL adds `a_full_journal_refuses_the_keyed_token_change_and_reserves_nothing`
and `a_keyed_token_change_below_the_fence_is_refused_and_changes_nothing`. Delivery:
`authority_events::dispatcher::tests::a_keyed_token_change_is_redelivered_identically_after_a_crash_before_the_cursor_commit`
and its standalone twin in `authority_events::standalone::tests`, which deliver real
keyed changes through the file sink as schema-valid `authority_event.v1` events and
redeliver them byte for byte; `standalone_delivery::tests` proves the `revised` rule
(`a_revised_token_row_with_a_null_revision_stalls`,
`a_row_an_older_build_writes_after_the_upgrade_stays_a_legacy_record`, and a #765
keyed revoke written by the older insert staying a legacy record); and
`auth::tokens::tests::standalone_token_revisions_start_at_one_and_legacy_evidence_stays_unrevised`
proves the open-time columns. Through the router, `admin_tokens_app_tests`:
`a_replayed_token_issue_or_rotation_repeats_no_side_effect_and_never_returns_the_plaintext`
(including `403` for a caller without `admin:tokens:write` before its key is
consulted),
`required_mode_refuses_the_unkeyed_token_issue_and_rotation_and_admits_the_keyed_principal`
(Unix),
`required_mode_refuses_a_keyed_token_issue_by_a_service_token_or_under_delivery_v1_or_with_the_log_sink`,
`required_mode_admits_every_form_of_token_revocation`,
`required_mode_validates_an_issue_and_refuses_an_unkeyed_rotation_before_reading_the_token`,
`a_keyed_rotation_retry_drops_the_replaced_plaintext_from_the_answering_cache` and
`an_admitted_token_rotation_finishes_after_its_client_goes_away`; and
`required_tests::service_token_issue_and_rotation_admit_only_their_keyed_issuer_bound_form_in_both_modes`.
The replay test also captures every log line and metric written on the test's
thread and the runtime's blocking pool, where the SQLite token store runs, and finds
neither plaintext nor a binding digest in them, a failed reservation included, and
`storage::contract_tests::sqlite_a_failed_token_reservation_is_counted_and_no_secret_reaches_logs_or_metrics`
proves that a reservation the SQLite store cannot write rolls the issue back, is
counted once on `greengateway_standalone_evidence_failures_total{store="service_tokens"}`,
and leaves no plaintext or digest in the store's log lines or the rendered metrics; the
PostgreSQL fence test counts its refused reservations on
`greengateway_authority_event_evidence_failures_total`. The race contract runs its two
writers through two handles (in SQLite, two connections to one file) and includes two
attempts of one keyed rotation. In cluster mode, against PostgreSQL and a real roster,
`authority_evidence_app_tests::cluster_token_keys::postgres_keyed_token_changes_wait_for_the_fleet_and_authorize_and_validate_before_the_fence`
proves that a keyed issue and rotation are `409 capability_not_advertised` and reserve
nothing while a live member lacks `caller_operation_keys` (the unkeyed forms still
commit); that once the lacking member is stale a keyed issue or rotation from a caller
without `admin:tokens:write`, or from a writer the delegation check refuses, is `403`,
and a keyed issue with a malformed `expires_at` is `400`, all leaving `contract_fence`
unchanged; and that the first keyed issue then raises the fence once and the exact
retries of the issue and of a keyed rotation are answered from their receipts with
`secret_returned: false`.

### Keyed catalog publication and overlay changes

Another operation family on the contract above (issue #425). Rows
`catalog_postgres` and `catalog_standalone` (`catalog.mcp.publish`,
`catalog.openapi.publish`, `catalog.overlay.replace`, `catalog.overlay.delete`)
are qualified. The family has no withdrawal: removing an overlay republishes the
bare catalog, so `catalog.overlay.delete` is a publication and admits only its
keyed form, like the others.

- **Routes.** `POST /v1{ADMIN_PREFIX}/connections/{id}/refresh`,
  `POST /v1{ADMIN_PREFIX}/connections/{id}/openapi/register`, and `PUT` and
  `DELETE` `/v1{ADMIN_PREFIX}/connections/{id}/overlay`, each with an optional
  `Idempotency-Key`. They are in `KEYED_ROUTES`. The checker's `QUALIFIED_PATHS`
  holds one path per operation and mode: the refresh route for
  `catalog.mcp.publish`, the registration route for `catalog.openapi.publish`,
  and the overlay routes for the overlay operations. A refresh of a managed
  OpenAPI Connection is also `catalog.openapi.publish`, under the same admission,
  gate and store contract; it is named in that path's guarantee, sources and tests
  rather than by a second path, since the table holds one route per pair.
- **Binding.** The key is bound to the action (a refresh binds
  `catalog.mcp.publish` or `catalog.openapi.publish` by the Connection's discovery
  kind), the recorded actor, the Connection ID, the `If-Match` value as received
  (the Connection ETag for a refresh or registration, the overlay ETag for an
  overlay change), and the body as canonical JSON: the specification and its
  selection for a registration, the overlay document for an overlay put, and
  nothing for a refresh or an overlay delete. An overlay put that sets
  `allow_unresolved_enum_sources=true` binds the document and the flag together,
  so the same key with the flag flipped is a conflict. The digest is stored only
  in the key's reservation row.
- **Order of work.** Each handler authorizes the caller and validates the request
  before it binds the key, asks the gates (the evidence gate as the operation's own
  code, and in cluster mode the operation gate) and answers an exact retry from the
  read-only pre-check. Validation covers what can be judged without the upstream:
  the Connection exists and, for a registration or an overlay change, is an HTTP
  API Connection with managed OpenAPI discovery; a registration's specification
  size and preview digest; an overlay put's document and the secret authority its
  sources need. Whether a registration's specification parses is judged after
  admission, when the catalog is generated. All of this happens before the
  upstream is fetched or a catalog is generated, so a replayed refresh or
  registration contacts no upstream. A refresh or registration compares its
  `If-Match` with the Connection's current ETag only after the pre-check, as a
  keyed replacement does, so a committed retry is answered with its receipt even
  after another writer replaced the Connection, and an unused key with a stale
  `If-Match` is still `412`. A retry after the Connection was deleted is `404`:
  a refresh's action is the deleted record's discovery kind, and every catalog
  route judges the Connection before it binds the key.
  Two first attempts that race both fetch; only one commits. Inside the store's one
  transaction (PostgreSQL after its Connection state lock, SQLite under
  `IMMEDIATE`) the key is looked up first, then the Connection ETag and the catalog
  (and, for OpenAPI, spec and overlay) revisions are checked, then the key is
  reserved (PostgreSQL confirms the fence carries `caller_operation_keys`), then the
  catalog and its `catalog_change_evidence` row are written under the caller's key,
  and the journal entry last.
- **Answers.** The first commit answers as the route always has (`200` with the
  publication summary, `201` for a registration). An exact retry is `200` with the
  receipt `{operation_id, operation, resource_id, revision, committed_at}`, read from
  the `catalog_change_evidence` row of the key's action (the store's receipt reader
  picks the evidence table by the action); `revision` is the catalog revision the
  publication made. It repeats no fetch, no publication and no audit event. The same
  key with any other request is `409 caller_operation_conflict`. A stale catalog or
  overlay revision writes and reserves nothing.
- **Required mode.** All four operations are `caller_key_required` in both modes:
  only the keyed request of an issuer-bound principal with `qualified_v1`, the file
  sink and a Unix build is admitted, and every other form, service-token callers
  included, is `409 authority_evidence_unsupported` before anything is read or
  written. The admin UI sends no key, so under `required` it cannot refresh,
  register or change an overlay (#242 tracks adding keys to it).

Tests. The store contract is written once in
`gateway/src/connections/catalog_operation_contract.rs` and run against both stores
(`sqlite_*` there, `postgres_*` in `connections::pg_store::tests`); every case ends
by asserting that a catalog action's reservation exists exactly when its evidence
row does: `catalog_caller_operation_contract`,
`a_reused_catalog_key_with_a_different_binding_conflicts_and_changes_nothing`,
`a_key_reserved_by_another_action_cannot_take_effect_on_a_catalog`,
`a_failed_evidence_insert_rolls_back_the_keyed_publication_and_its_reservation`,
`a_stale_catalog_precondition_under_a_key_writes_no_change_evidence_or_reservation`,
`two_writers_racing_one_catalog_key_commit_one_change`,
`two_catalog_keys_racing_one_revision_leave_only_the_winners_rows` and
`a_keyed_catalog_change_keeps_synthetic_markers_out_of_the_reservation_receipt_and_record`.
PostgreSQL adds `a_full_journal_refuses_the_keyed_catalog_publication_and_reserves_nothing`.
`a_keyed_catalog_change_is_redelivered_identically_after_a_crash_before_the_cursor_commit`
(in both `authority_events::dispatcher::tests` and
`authority_events::standalone::tests`) delivers a real keyed registration, overlay
put, overlay delete and MCP publication as closed v1 events through the file sink
and redelivers them byte for byte. Through the admin handlers,
`authority_evidence_app_tests` proves `a_replayed_catalog_change_repeats_no_side_effect`,
`a_replayed_refresh_does_not_fetch_the_upstream_again_or_audit_a_second_change`,
`a_replayed_openapi_registration_does_not_fetch_the_upstream_again_or_audit_a_second_change`,
`required_evidence_refuses_every_unkeyed_standalone_catalog_publication`,
`required_mode_refuses_the_unkeyed_catalog_publication_and_admits_the_keyed_principal`
(Unix builds),
`required_mode_refuses_a_keyed_catalog_publication_by_a_service_token_or_under_delivery_v1_or_with_the_log_sink`
and `a_keyed_catalog_change_without_the_routes_permission_is_forbidden_and_reserves_nothing`.
In cluster mode, against PostgreSQL and a real roster,
`authority_evidence_app_tests::cluster_connection_keys::postgres_keyed_catalog_changes_wait_for_the_fleet_and_authorize_before_the_fence`
proves that a keyed catalog change is `409 capability_not_advertised` and reserves
nothing while a live member lacks `caller_operation_keys`, that a keyed request from
a caller without the route's permission is `403` and leaves `contract_fence`
unchanged, and that the first keyed change raises the fence once.

### Keyed local-secret create, rotation and delete

Another operation family on the contract above (issue #425). Local secrets exist
only in standalone mode (cluster mode has no local-secret keyring, so
`local_secrets_postgres` stays `unavailable`). Row `local_secrets`
(`secret.create`, `secret.rotate`) is qualified, and `local_secret_delete` is
`withdrawal_admitted` with its keyed path
([below](#rows-admitted-without-qualification)). The `connection-secrets
reencrypt` command (`secret.reencrypt`) is unchanged: a fixed system actor and
no caller key.

- **Routes.** `POST /v1{ADMIN_PREFIX}/connection-secrets`, and `PUT` and `DELETE`
  `/v1{ADMIN_PREFIX}/connection-secrets/{id}`, each with an optional
  `Idempotency-Key`. They are in `KEYED_ROUTES`, and the checker's
  `QUALIFIED_PATHS` names the same methods and routes for standalone mode.
- **Binding.** The key is bound to the action, the recorded actor, the secret ID
  (empty for a create), the `If-Match` value as received (the secret collection
  ETag for a create, the item ETag for a rotation or delete), and the canonical
  request, which is the label (create only) and the purpose
  (`SecretChangeBinding::canonical_request`, the same bytes in the handler and the
  store). The secret value is never bound: nothing derived from it enters the
  digest, the reservation, the receipt, the evidence row or the delivered record.
  The digest is stored only in the key's reservation row in the Connections
  database's `authority_caller_operation_ids`.
- **A retry with another value.** Because the value is not bound, the store tells
  a retry with a different value apart by comparing values. On an exact retry of a
  create or rotation, while the secret is still at the revision the receipt
  names, the store decrypts the committed envelope in memory and compares it with
  the retried value (and purpose) in constant time; a mismatch is
  `409 caller_operation_conflict` and the stored value stays. Once the secret was
  rotated again or deleted, the value of the replayed change no longer exists and
  cannot be compared, so the receipt is returned as it is; its `revision` shows
  that it is no longer current. Nothing derived from either value is stored.
  The comparison does tell whoever holds both the key and the same principal
  (actor kind, issuer, subject and auth mode are bound) whether a value they
  send equals the stored one, `200` or `409`, for as long as the secret stays at
  that revision. The key is not secret (it is the `operation_id` of the receipt
  and of the delivered record), so this matters for a shared automation identity
  and a low-entropy value; a replay and a replay conflict record no audit event.
- **Order of work.** Each handler authorizes the caller
  (`admin:connections:secrets:write`) and first answers a gateway without a
  local-secret store, keyed or not, as it always has: a create is judged by its
  collection `If-Match` and is then `503`, and a rotation or delete is judged by
  its `If-Match` alone (`428`, `400`, or `412` since there is no stored secret to
  match). The routes are mounted on every
  cluster replica, which never has a store, so this comes before any key is
  bound or gate asked: a keyed request there never raises the contract fence
  for an operation the replica cannot perform. Then the handler validates the
  body (its JSON, and the purpose and value of a create or rotation) and binds
  the key
  through `caller_operation()`, asks the evidence gate (as `secret.create` or
  `secret.rotate`; a delete is a withdrawal and never asks it) and answers an exact
  retry from the read-only pre-check. All of this happens before `If-Match` is
  compared with the current ETag and before a rotation's client-identity preflight
  fetches the other half of the pair from a network provider, so an exact retry
  makes no network call. A committed retry is answered with its receipt even after
  another writer moved the ETag, or after the secret was deleted; an unused key
  with a stale `If-Match` is still `412`. Inside the store's one `IMMEDIATE`
  transaction the key is looked up first, then the item or collection ETag is
  checked, then the key is reserved, then the envelope and its
  `connection_local_secret_change_evidence` row are written under the caller's
  key. A reservation that cannot be written rolls the change back, is `503`, and is
  counted on the standalone evidence failure counter.
- **Answers.** The first commit answers as the route always has (`201` with the
  alias metadata, `200` with the rotated metadata, `200` with the deleted ID). An
  exact retry is `200` with the receipt `{operation_id, operation, resource_id,
  revision, committed_at}` read from the change's evidence row (`revision` is the
  version after a create or rotation and the version a delete removed) with
  `Cache-Control: no-store`, and repeats no change and no audit event. The first
  commit published the new secret version to the runtime in the same synchronous
  call as its store write, so a replay has nothing left to publish. The same key
  with another label, purpose, target, `If-Match`, action or caller is
  `409 caller_operation_conflict` and changes nothing.
- **Completion.** Once admitted, a change runs on a task of its own
  (`connection_change_to_completion`), so a client that disconnects while the
  store commits does not cut it short.
- **Required mode.** Create and rotation are `caller_key_required`: only the keyed
  request of an issuer-bound principal with `qualified_v1`, the file sink and a
  Unix build is admitted, and every other form, service-token callers included,
  is `409 authority_evidence_unsupported` before anything is written or a key
  is read (a rotation has read the stored secret's metadata by then).
  Deletion is admitted in every form. The admin UI sends no key, so under
  `required` it can delete a local secret but not create or rotate one (#242
  tracks adding keys to it).

Tests. The store contract is in
`gateway/src/connections/local_secret_operation_tests.rs`
(`connections::local_secret::operation_tests`); every case ends by asserting that a
local-secret action's reservation exists exactly when its evidence row does:
`local_secret_caller_operation_contract`,
`a_reused_key_with_a_different_binding_conflicts_and_changes_nothing`,
`a_key_reserved_by_another_action_cannot_take_effect_here`,
`a_key_bound_to_another_operation_is_refused_by_the_store`,
`a_failed_evidence_insert_rolls_back_the_keyed_secret_change_and_its_reservation`,
`a_failed_reservation_rolls_back_the_keyed_secret_change_and_is_counted`,
`a_stale_etag_under_a_key_writes_no_change_evidence_or_reservation`,
`two_writers_racing_one_key_commit_one_change`,
`two_keys_racing_one_revision_leave_only_the_winners_rows`,
`the_secret_value_never_enters_the_binding_digest` (two values, one digest),
`a_different_value_under_the_same_key_conflicts_and_keeps_the_stored_value`,
`a_replay_after_a_later_rotation_returns_the_superseded_receipt` and
`a_keyed_secret_change_keeps_synthetic_markers_out_of_the_reservation_receipt_evidence_and_file`
(which also reads the SQLite file's bytes).
`authority_events::standalone::tests::a_keyed_secret_change_is_redelivered_identically_after_a_crash_before_the_cursor_commit`
delivers a real keyed create, rotation and delete as closed v1 events through the
file sink and redelivers them byte for byte. Through the admin handlers,
`authority_evidence_app_tests::local_secret_keys` proves
`a_replayed_secret_change_repeats_no_side_effect`,
`required_mode_refuses_the_unkeyed_secret_create_and_rotate_and_admits_the_keyed_principal`
(Unix builds),
`required_mode_refuses_a_keyed_secret_change_by_a_service_token_or_under_delivery_v1_or_with_the_log_sink`,
`required_mode_admits_every_form_of_secret_delete`,
`a_keyed_secret_change_that_is_forbidden_or_malformed_reserves_nothing` (`403`,
`400` and `428`, each leaving no reservation),
`a_keyed_secret_change_without_a_local_secret_store_is_answered_like_the_unkeyed_one`
(no keyring: keyed answers as unkeyed, the precondition before `503`, under
best_effort and required),
`an_admitted_secret_change_finishes_after_its_client_goes_away` and
`a_keyed_secret_change_keeps_synthetic_markers_out_of_the_receipt_audit_logs_and_metrics`
(markers in the value, the label and a conflicting retry's value, checked against
the answers, the audit events, the logs and metrics captured on the test's thread
and the runtime's blocking pool, where the SQLite store runs, the SQLite file and
its WAL; the stored nonce and ciphertext of the create and the rotation are
checked against the same answers, audit events, logs and metrics).
The one PostgreSQL test,
`authority_evidence_app_tests::cluster_connection_keys::postgres_keyed_secret_changes_in_cluster_mode_leave_the_fence_alone`,
proves that a keyed rotation and delete on a cluster replica, once the operation
gate would raise the fence, answer as their unkeyed forms, leave the contract
fence unchanged and reserve nothing.

### Keyed policy, tools and policy test changes

Another operation family on the contract above (issue #425), in cluster mode
only. Rows `policy_postgres` (`policy.publish`, `policy.rollback`,
`policy.rule.create`, `policy.rule.update`, `policy.rule.delete`,
`policy.rule.reorder`, `policy.suggestion.accept`), `tools_postgres`
(`tools.publish`) and `policy_tests_postgres` (`policy_tests.publish`) are
qualified. The standalone rows stay refused: the standalone policy files and suite
store record no caller key, so a standalone route refuses a key with
`400 standalone_caller_key_unsupported` before anything is read, and #242 tracks
standalone evidence for them. The family has no withdrawal: deleting a rule
publishes the policy without it.

- **Routes.** `PUT /v1{ADMIN_PREFIX}/policy`,
  `POST /v1{ADMIN_PREFIX}/policy/rollback/{version}`,
  `POST /v1{ADMIN_PREFIX}/policy/rules`, `PATCH` and `DELETE`
  `/v1{ADMIN_PREFIX}/policy/rules/{id}`, `PUT /v1{ADMIN_PREFIX}/policy/rules/order`,
  `POST /v1{ADMIN_PREFIX}/suggestions/{id}/accept`,
  `POST /v1{ADMIN_PREFIX}/policy/drafts/{id}/publish`,
  `POST /v1{ADMIN_PREFIX}/tools/openapi/register` and
  `PUT /v1{ADMIN_PREFIX}/policy/tests`, each with an optional `Idempotency-Key`.
  They are in `KEYED_ROUTES`. The checker's `QUALIFIED_PATHS` holds one path per
  operation: the policy `PUT` for `policy.publish`, the suggestion route for
  `policy.suggestion.accept`, and each other route for its own operation. A draft
  publication commits `policy.publish`, or `policy.suggestion.accept` when the draft
  names a suggestion, under the same admission, gate and store contract; its route
  is in the checker's `SHARED_KEYED_ROUTES`, which names the pairs a route commits
  when it is not a reviewed path's own route, and the checker holds every such pair
  to its reviewed path.
- **Binding.** The key is bound to the action, the recorded actor, the target (the
  version for a rollback, the rule ID for a rule update or delete, the suggestion ID
  for an acceptance, the draft ID for a draft publication, empty otherwise), the
  precondition headers as received (for the policy routes `If-Match` and the
  resource snapshot header; for an acceptance those and the suggestion revision
  header; for a draft publication the draft ETag, `If-Match` and resource snapshot
  headers; for a tools registration `If-Match`; for the policy test suite `If-Match`
  and `If-None-Match`), and the request: a JSON body as canonical JSON, a YAML policy
  as received, nothing for a rollback, a rule delete or an acceptance. A draft
  publication binds its body as received and the action it will commit. An
  acceptance's generation binding (issue #243) is not in the digest: it is
  server-side state, judged afresh on every attempt. The digest is stored only in
  the key's reservation row.
- **Order of work.** Each handler authorizes the caller and validates the request
  before it binds the key, asks the gates (the evidence gate as the operation's own
  code, and the operation gate) and answers an exact retry from the read-only
  pre-check. All of this happens before the handler reads the authority, compares
  `If-Match` with the current ETag, reads the suggestion or the draft, or fetches
  an OpenAPI specification, so a committed keyed retry is answered with its receipt
  after another writer has moved the ETag, and a replayed registration fetches
  nothing; an unused key with a stale `If-Match` is still `412`. Inside the commit's
  one PostgreSQL transaction the key is looked up first, then the active document's
  ETag is checked, then the key is reserved (after confirming the fence carries
  `caller_operation_keys`), then the version, its `document_change_evidence` row
  under the caller's key and the journal entry are written. An acceptance does all
  of this inside the acceptance transaction, and looks the key up before its
  open-suggestion predicate. An unkeyed draft publication asks the evidence gate in
  its unkeyed form at the same point, before the draft is read or the suggestion
  lifecycle reconciled; its refusal is also recorded as
  `policy.draft_publish_refused` naming the draft ID from the path, with the fields
  that need the draft null. Each admitted
  change runs on a task of its own (`document_change_to_completion`), so a client
  disconnect cannot separate the commit from its install and audit event.
- **Answers.** The first commit answers as the route always has. An exact retry is
  `200` with the receipt `{operation_id, operation, resource_id, revision, committed_at}`,
  read from the change's `document_change_evidence` row; `resource_id` is the
  document (`policy`, `tools` or `policy_tests`) and `revision` the version the
  change committed. This holds for an acceptance after its suggestion is no longer
  open and for a draft publication after the policy ETag has moved. A replay writes and
  audits nothing. A policy, acceptance or suite replay answered by the pre-check
  changes nothing on the replica; one answered inside the commit transaction (a
  writer that raced the original) reinstalls the active policy. A tools replay
  reconciles the replica's tools lane either way. A replayed draft publication does
  not mark the draft published: if the original's process stopped after its commit
  and before that step, the draft stays open on a stale base (its later publication
  is `policy_draft_base_stale`) and can be deleted. The same key with any other
  request is `409 caller_operation_conflict`. Two writers racing on one key commit
  one change. Across replicas the loser gets the receipt from the commit
  transaction; on one replica the loser waits on the policy write lane and may then
  be answered `412` (or `409 suggestion_not_open` for an acceptance), and a retry
  under the same key gets the receipt.
- **Required mode.** The nine operations are `caller_key_required` in cluster mode:
  only the keyed request of an issuer-bound principal with `qualified_v1`, the file
  sink and a Unix build is admitted, and every other form, service-token callers
  included, is `409 authority_evidence_unsupported` before anything is read or
  written (an unkeyed draft publication included). The admin UI sends no key, so
  under `required` it cannot change policy, register tools or store a policy test suite (#242 tracks adding keys to it). The
  first-boot tools seed is an unkeyed system-actor `tools.publish`: when the tools
  document does not exist, cluster preflight asks the gate for that form before
  seeding, so under `required` it refuses to start and says how to provision the
  document (start once, or run the import, with `best_effort`). When the document
  exists the seed is a no-op and nothing is asked.

Tests. The store contract is in
`gateway/src/storage/postgres_documents_caller_tests.rs` (run under
`storage::postgres_documents::tests::`), and every case ends by asserting that a
document action's reservation exists exactly when its evidence row does:
`policy_tools_and_policy_tests_caller_operation_contract` (every action of the
family), `a_reused_key_with_a_different_binding_conflicts_and_changes_nothing`,
`a_key_reserved_by_another_action_cannot_take_effect_here`,
`a_failed_evidence_insert_rolls_back_the_keyed_document_commit_and_its_reservation`,
`a_full_journal_refuses_the_keyed_document_commit_and_reserves_nothing`,
`a_stale_etag_under_a_key_writes_no_change_evidence_or_reservation`,
`two_writers_racing_one_key_commit_one_change`,
`two_keys_racing_one_revision_leave_only_the_winners_rows`,
`a_keyed_document_commit_keeps_synthetic_markers_out_of_the_reservation_receipt_and_record`,
`a_keyed_suggestion_acceptance_reserves_inside_the_acceptance_transaction` and
`the_first_boot_seed_stays_a_system_record_and_reserves_nothing`.
`authority_events::dispatcher::tests::a_keyed_document_change_is_redelivered_identically_after_a_crash_before_the_cursor_commit`
delivers real keyed policy, tools and policy test suite commits (the suite's first
write, with no prior version) as closed v1 events through the file sink and
redelivers them byte for byte. Through the admin handlers of a cluster
replica, against PostgreSQL and a real roster,
`document_keys_app_tests::cluster_document_keys::` proves
`a_keyed_policy_change_is_refused_while_a_live_member_lacks_the_capability` (with
the `403` and malformed-request `400` cases that leave `contract_fence` unchanged),
`a_replayed_policy_change_repeats_no_side_effect` (the six policy routes and the
policy test suite: the receipt after the ETag moved, `409` on another binding,
`412` for an unused key with a stale `If-Match`),
`a_replayed_tools_registration_fetches_no_specification_again`,
`required_mode_refuses_the_unkeyed_policy_change_and_admits_the_keyed_principal`
(the unkeyed rollback, rule create, update, delete and reorder, tools
registration and suite write refused, and admission on Unix builds),
`required_mode_refuses_a_keyed_policy_change_by_a_service_token_or_under_delivery_v1_or_with_the_log_sink`,
`required_mode_preflight_refuses_to_seed_an_empty_tools_document`,
`required_mode_preflight_passes_when_the_tools_document_exists` and
`an_admitted_policy_change_finishes_after_its_client_goes_away` (a keyed
`PUT .../policy` whose client disconnects commits, and its retry gets the receipt;
the test fails if the request was answered before its commit was observed, so it
cannot pass without a disconnect).
The acceptance and draft publication routes are proved through the suggestion
admin handlers of a cluster replica, against PostgreSQL, by
`admin_observability_app_tests::cluster_discovery_tests::`
`a_keyed_cluster_acceptance_is_answered_from_its_receipt_once_the_suggestion_is_closed`
(the receipt after the suggestion closed, `409` on another revision, `If-Match` or
resource snapshot binding),
`a_keyed_cluster_draft_publication_reserves_policy_publish_and_replays_its_receipt`,
`a_keyed_cluster_bound_draft_publication_reserves_the_acceptance_and_replays_its_receipt`
and
`required_mode_refuses_the_unkeyed_cluster_acceptance_and_draft_publication_before_reading`.
`document_keys_app_tests::a_keyed_standalone_policy_change_is_refused_and_writes_nothing`
covers the standalone refusal, and
`authority_events::required::tests::policy_tools_and_policy_test_changes_admit_only_their_keyed_issuer_bound_form_in_cluster_mode`
the gate.

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
  `admin_session_evidence` row in the statement that writes it, and since
  migration 32 every producer of `document_change_evidence` and
  `catalog_change_evidence` journals its row in the same transaction too. The row
  holds identifiers only. Its position is reserved from the
  `authority_event_state` row, whose lock is held to COMMIT, so position order is
  commit order and the committed journal has no gaps. Evidence committed before
  migration 21 is journaled by the migration in commit order; admin session
  evidence committed before migration 26, and document and catalog evidence
  committed before migration 32, is journaled by that migration, in its own
  commit order, after everything already journaled.
- **Bounded capacity, failing closed.** The same reservation succeeds only while
  fewer than `AUTHORITY_EVENT_JOURNAL_CAPACITY` units are in use: one per retained
  row, plus one held for the withdrawal of every admin session granted and not yet
  withdrawn. When the journal is full, the mutation rolls back as a whole and is
  answered `503` (a CLI `revoke-jwt` and the offline import exit with a store error,
  and a first boot whose tools seed is refused does not start); nothing is
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
  undelivered row is ever pruned, whatever its age. With no cursor, retention
  holds the entire journal under `AUTHORITY_EVIDENCE_DURABILITY=required`: its
  events have reached no consumer, and required mode always configures a sink,
  so the hold lasts only while delivery has not established its cursor (or
  after an operator removed it). Under `best_effort`, age-only pruning applies
  with no cursor until the first keyed approval preparation commits. That
  receipt protects the entire journal until the dispatcher checkpoints it. The
  hold does not depend on whether a keyed row exists, so a best-effort
  deployment with no sink does not start filling its journal when one client
  sends a key. The hold follows the durability of the process that runs the
  maintenance pass, including `gateway maintenance-run`, which is not checked
  against the cluster fingerprint: run it with the replicas' environment.
  Retention preserves all evidence rows, including the preparation receipt.
- **Default delivery format.** Each legacy record carries the persisted `authority_id`, the
  evidence row's `event_id` and `operation_id`, the journal position as
  `sequence`, the operation, `result: committed`, the evidence row's
  database-clock `committed_at`, `actor.recorded_ref` (the `actor.recorded`
  reference of the recorded actor), `actor.kind`, `actor.auth_mode` and
  `actor.issuer_ref` (the `actor.issuer` reference) as the evidence recorded them
  since migration 24, each `null` where the row recorded none, the resource kind
  and its keyed reference (a
  JWT revocation's under its issuer and `jti` digest, an admin session's under its
  random session ID), and the v1 revision transition as decimal strings. A
  service-token issue (since migration 27) is the token's first revision: `null`
  before and `1` after, beside its create's shared revision. A Connection create
  (since migration 28) is likewise `null` before and `1` after on the `connection`
  axis, and a replace advances it; a `credential.binding_change` is on the
  `credential` axis, where `0` before means the Connection had no credential
  authority, and names the Connection as its resource, as every Connection change
  does. Policy, tools and catalog changes (since migration 32) are described
  [below](#policy-tools-and-catalog-delivery). An admin
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
resumes age-only pruning if the deployment runs `best_effort` and has never
committed a keyed approval prepare. Under `required`, or once a prepare receipt
exists, removing the cursor holds the entire journal: restore a working
dispatcher to free capacity.

A database restore rewinds the journal, the cursor and the evidence together. Events
committed after the backup are gone with the changes they describe; events delivered
after the backup are delivered again under the same event IDs, which consumers
already deduplicate. The persisted `authority_id` survives the restore, so the same
key derives the same references.

Not covered by PR 3, and still open:

- **Delivery by default.** Under `AUTHORITY_EVIDENCE_DURABILITY=best_effort`, the
  default, a deployment with `AUTHORITY_EVENT_SINK=none` journals and retains
  evidence but delivers none. `required` refuses to start such a replica
  ([Required-durability mode](#required-durability-mode)).
- **Admin session metadata.** Admin session evidence is journaled and delivered
  since migration 26, with actor attribution since migration 33. The delivered
  record has no field for the withdrawal's reason.
- **Standalone mode** has no journal; its evidence is delivered straight from the
  SQLite stores that own it, after a cursor in each
  ([Standalone delivery](#standalone-delivery)).
- **The v1 contract.** The dispatcher qualifies any row with a caller UUIDv7 and
  an issuer-bound principal ([Authority event v1](#authority-event-v1)). Token
  revocation and approval preparation bound a caller key first; keyed token issue
  and rotation, Connection, catalog and local-secret changes, and cluster policy,
  tools and policy test changes do too since #833 to #840
  ([Keyed authority changes](#keyed-authority-changes)). An operation without a
  keyed route, and the unkeyed form of one with a keyed route, are delivered as
  `authority_event_delivery.v1`.
  Kind, auth mode and issuer are recorded since migration 24
  ([Actor metadata](#actor-metadata)).
- **Service-token issue (migration 27).** A create writes its
  `service_token_change_evidence` row with action `service_token.issue` after the
  token row and the create outbox row, under the outbox row's shared revision, and
  journals it in the same transaction. A full journal refuses the create with
  `503` and mints nothing. The dispatcher delivers it on the token axis with no
  revision before it and revision `1` after it. Tokens created before migration 27
  have no issue row, and nothing is backfilled for them.
- **Connection create, replace and credential binding change (migration 28).** A
  create writes its `connection.create` row, and a replace its `connection.replace`
  row, after the outbox row and under its shared revision, and journals it in the
  same transaction; a replace that advances the credential revision also writes and
  journals a `credential.binding_change` row under the same operation ID and shared
  revision. A full journal refuses the create or the replace with `503` and commits
  nothing of it; an identical replace commits nothing and journals nothing.
  Connections created or replaced before migration 28 have no such rows, and
  nothing is backfilled for them.

### Policy, tools and catalog delivery

Migration 32 (`document_and_catalog_evidence_journal`) makes migration 23's
`document_change_evidence` and `catalog_change_evidence` the fifth and sixth journal
sources:

- **Every producer journals in its own transaction.** `postgres_documents::commit_in`,
  which every policy and tools commit, suggestion acceptance, stored policy test
  suite write, the first-boot tools seed (system actor `bootstrap`) and the offline
  import's policy and tools activations (system actor `import-standalone`) run,
  appends the commit's journal row right after its evidence row. Both Connection
  store catalog replacements, which every MCP refresh, OpenAPI registration and
  refresh and overlay put or delete reach, do the same after their catalog evidence
  row. Each takes one unit of capacity under the rule every producer follows; a full
  journal refuses the change (`503` from the admin API, a store error from the import,
  a failed first boot for the seed), commits nothing of it, and is counted by
  `_capacity_refusals_total`. A failed append is counted by `_evidence_failures_total`
  and rolls the change back.
- **Backfill.** The migration journals the evidence both tables already hold, after
  everything already journaled, in their own commit order (`committed_at`, then event
  ID) across the two tables, each row at its own commit time, one unit each. It leaves
  the capacity as it was.
- **Delivered records.** A document is a singleton, so its resource is the document
  itself, referenced under its own domain: a `policy` resource on the `policy` axis,
  a `tools` resource on the `tools` axis, and the stored policy test suite a `policy`
  resource of its own on the `policy_tests` axis, as the proposed event names it. The
  import's `configuration.import` is on the axis of the document it activated. A
  catalog is a `catalog` resource referenced by its Connection under the
  `resource.catalog` domain, so its reference is never the Connection's, on the
  `catalog` axis; the overlay revision it was compiled from stays in the evidence row.
  Each activates a version: `before` is `null` for a document's initialization or a
  Connection's first catalog of its kind, and `after` is strictly greater (a document's
  first version is an identity value and need not be `1`). The shared revision is the
  outbox row's. A pairing of action and document that migration 29's CHECK refuses is
  refused by the projection too, and stalls delivery at that row.
- **The document actor in migration 24's vocabulary.** Migration 23 recorded a
  service-token caller as kind `principal` with auth mode `service_token`, and the
  issuer as the principal carried it. Since migration 32 `actor_kind` admits
  `service_token`, and every writer records `auth::change_actor::ChangeActor`: the
  service token as its own kind and the canonical issuer, as every other evidence
  table does. A new CHECK, `document_change_evidence_actor_metadata`, pairs each new
  row's kind with its auth mode exactly as migration 24's tables do. It is `NOT VALID`
  on purpose and never validated: evidence is append-only, so a row committed before
  the migration keeps the vocabulary it was written in. The dispatcher reads such a
  row in the new vocabulary, delivering (`principal`, `service_token`) as kind
  `service_token` and referencing the issuer after the same canonicalization
  authentication applies, so the same principal has one issuer reference across every
  table. The stored row does not change.

Tests: the delivery projection tests in `gateway/src/authority_events/delivery_tests.rs`
(`document_changes_project_on_the_axis_of_their_document`,
`catalog_publications_project_on_the_catalog_axis`,
`legacy_document_actors_are_read_in_migration_24s_vocabulary`, every operation against
the published schema and synthetic-marker exclusion); the dispatcher's
`committed_events_are_delivered_in_commit_order_under_their_evidence_ids` (policy,
Connection, catalog and tools events interleaved with token, JWT and Connection ones,
in commit order under their evidence IDs) and
`a_full_journal_refuses_policy_and_catalog_publications_and_commits_nothing` (a policy
publication, the tools seed and a catalog publication refused at capacity with nothing
committed, counted once each, then committed once retention frees room); the document
core's `committed_document_changes_record_attributed_evidence_and_refusals_record_none`;
the catalog store's `catalog_evidence_survives_replacement_cascade_and_restart`; the
import's journal rows in `import::tests`; and
`migration_thirty_two_journals_document_and_catalog_evidence_and_aligns_the_actor`. The
PostgreSQL ones run in CI against its disposable loopback database, and the
dispatcher, migration and evidence suites again over verified TLS
([Verified-TLS storage tests](#verified-tls-storage-tests)).

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
domain. Migration 33 records the acting subject separately from the session owner.
A grant and the session it replaces both name the principal that completed the new
login, including its canonical issuer when available and its bearer authentication
mode. A provider rejection or deadline expiry names the gateway's fixed system
actor. An authentication-exempt logout, whether by cookie or pending-login binding,
and every row committed before migration 33 retain the session owner's keyed
reference with null actor kind, mode and issuer.
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
The PostgreSQL ones run in CI against its disposable loopback database, and again
over verified TLS ([Verified-TLS storage tests](#verified-tls-storage-tests)).

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
change's own transaction: Connection create, replace and delete
(`connection_create_endpoint`, `connection_put_endpoint`, `connection_delete_endpoint`;
the PostgreSQL create and replace since migration 28), token issue, rotate and revoke (`token_rotate_endpoint`, `token_revoke_endpoint`), every managed
catalog publication (`connection_refresh_endpoint`,
`connection_openapi_register_endpoint`, `connection_openapi_overlay_put_endpoint`,
`connection_openapi_overlay_delete_endpoint`, into migration 25's columns of
`catalog_change_evidence`), and the `revoke-jwt` command, which passes a `system`
actor. Each field is bounded by
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
Connection deletion, create and replace evidence tests in
`gateway/src/connections/pg_store_tests.rs` and its catalog evidence tests
`catalog_evidence_records_the_whole_actor_for_every_catalog_action` (each of the
four catalog actions by an issuer-less principal, a service token and a principal
with an issuer, under the same CHECK as migration 24's tables) and
`refused_and_stale_catalog_writes_record_no_evidence`,
`migration_twenty_four_adds_actor_metadata_and_guesses_none_for_existing_evidence`,
the standalone column upgrade in `gateway/src/auth/tokens.rs`, the delivery
projection tests in `gateway/src/authority_events/delivery_tests.rs`, the
commit-order dispatcher test, and the app-level
`admin_token_rotate_and_revoke_record_the_authenticated_subject_and_issuer_sqlite`
and `_postgres` in `gateway/src/admin_tokens_app_tests.rs`, which drive the admin endpoints with principals from two identity
providers and a service token and read the evidence rows back. The PostgreSQL ones
run in CI against its disposable loopback database, and again over verified TLS
([Verified-TLS storage tests](#verified-tls-storage-tests)).

Migration 24 leaves migration 23's two tables unchanged. `catalog_change_evidence`
joins this contract with migration 25, which adds this section's three columns
under the same CHECK. The schema-25 release applied it, as a rolling step from the
release that approved it ([schema 24 to 25](deployment/postgres.md#rolling-upgrade-schema-24-to-25)),
and recorded nothing in them; this release records the whole actor on every
catalog publication, refusing before the transaction opens an actor it cannot
record exactly. A catalog row committed before this release records none of the
three, and nothing is backfilled. `document_change_evidence` joins the contract
with migration 32 ([Policy, tools and catalog delivery](#policy-tools-and-catalog-delivery)):
its writers record the same kind, auth mode and canonical issuer, and its rows
committed before then, which recorded a service token as kind `principal` and the
issuer as the principal carried it, are delivered in this vocabulary without being
rewritten. Both tables are journal sources since then. The inventory's
`configuration_import` row keeps `missing_metadata` for its caller-bound operation
identity and issuer-scoped subject reference (`catalog_postgres` is qualified since
its keyed paths shipped, [above](#keyed-catalog-publication-and-overlay-changes),
and `policy_postgres`, `tools_postgres` and `policy_tests_postgres` since theirs did,
[above](#keyed-policy-tools-and-policy-test-changes)); required mode refuses the
`configuration_import` row's writing form.

A `system` actor never authenticated anybody, so it can never bind a caller key.
The rows whose changes are started only by a command under a fixed system label or
by a browser completing or ending a session (`revoke-jwt`, master-key
re-encryption, and admin session grant and withdrawal) are `no_caller_key` rather
than `missing_metadata`: they stay unqualified and are reconciled by their natural
key ([Rows admitted without qualification](#rows-admitted-without-qualification)).

## Standalone evidence

A standalone gateway has no shared database, so its evidence lives in the SQLite
store that owns each authority and is written in the same IMMEDIATE transaction
as the change it describes. Nothing is written to the audit database instead: a
second SQLite file cannot commit atomically with the first.

| Store | Table | Written by | Each row holds |
| --- | --- | --- | --- |
| `SERVICE_TOKEN_SQLITE_PATH` | `service_token_change_evidence`, created on open (a table created before the issue action existed is rebuilt once on open to admit it, keeping every row, its sequence and the sequence counter) | service-token issue, rotate and revoke | actor, action, event and operation UUIDs, token ID, commit time (an issue's is the token's own `created_at`), and since plan P5 of #425 the token's revision before and after with the `revised` marker (columns added on open; older rows keep NULL revisions and `revised = 0`) |
| `CONNECTIONS_SQLITE_PATH` | `connection_change_evidence`, Connections schema migration 12 | Connection create, replace and delete | actor, action, event and operation UUIDs, Connection ID, the revision before and after on the action's axis, commit time. A replace that advances the credential revision adds a `credential.binding_change` row on the credential axis under the same operation ID |
| `CONNECTIONS_SQLITE_PATH` | `connection_local_secret_change_evidence`, Connections schema migration 12 | local-secret create, rotate and delete, and each re-encryption batch that rewrote at least one envelope | actor, action, event and operation UUIDs, the gateway-minted secret ID and its version before and after; a batch records only how many envelopes it rewrote |
| `CONNECTIONS_SQLITE_PATH` | `catalog_change_evidence`, Connections schema migration 13 | managed MCP and OpenAPI catalog publication: an MCP refresh, an OpenAPI registration or refresh, and an overlay put or delete | actor, action, event and operation UUIDs, Connection ID, the catalog revision before and after, the overlay revision the published OpenAPI catalog was compiled from, commit time (the catalog's `refreshed_at`) |

In each table the actor is the whole `auth::change_actor::ChangeActor`: subject,
kind, auth mode and, for a principal that has one, canonical issuer, in the columns
and with the pairing CHECK of [Actor metadata](#actor-metadata). The token table
gained those columns on open and keeps older rows without them; the three Connections
tables were created with them and require kind and auth mode on every row.

The catalog table mirrors the cluster's `greengateway.catalog_change_evidence`
(migration 23, with migration 25's actor columns): the same four actions, named by
what the write did to the overlay exactly as the PostgreSQL writer names them
(`catalog.overlay.replace` for an overlay put, `catalog.overlay.delete` for an overlay
delete, `catalog.mcp.publish` for an MCP publication and `catalog.openapi.publish` for
an OpenAPI registration or a refresh, which at most rewrites the overlay's source
reports), and the same revision CHECKs: a first catalog has no prior revision, an MCP
row has no overlay revision, an overlay put records at least 1 and an overlay delete
0. It has no shared security revision. An enum-value refresh and a status
observation publish no catalog and write no row.

All three follow the same rules:

- A change whose evidence cannot be inserted rolls back with it and fails as a
  store failure (`503` from the Connection and secret admin API, an internal or
  unavailable error from the token admin API by the failure's class, a failed
  exit from the maintenance command). In the gateway process each such refusal
  is counted once by `greengateway_standalone_evidence_failures_total{store}`,
  where `store` is `service_tokens` or `connections`, and the operational rule
  pack pages on it ([standalone evidence failures](deployment/operational-alerts.md#standalone-evidence-failures)). A catalog
  publication whose evidence failed is a store failure too (`503`), even where
  SQLite reports the failure as a constraint. A refused change (stale ETag, stale
  catalog, spec or overlay revision, dependency conflict, missing record, purpose
  mismatch) and an ineffective one (an identical replace, a batch with nothing to
  rewrite, a repeat revoke) write nothing. A change whose actor evidence cannot record
  exactly (no subject, a subject or issuer past the principal bounds, or an issuer
  on a service token or command) is refused before anything is written.
- No foreign key: a row outlives the deletion it records, so a lost delete
  response is answered from the evidence rather than by a blind retry, and a
  catalog row outlives the catalog it replaced and the Connection whose deletion
  cascades the current one.
- Identifiers, revisions, counts and the actor only: never a specification or its
  digest, tool or resource name, definition, overlay document, source report, enum
  value, endpoint, label, purpose, credential binding, bound secret ID, plaintext,
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
- **No journal.** With `AUTHORITY_EVENT_SINK` set, the rows are delivered from the
  tables themselves, after a cursor kept in the same file
  ([Standalone delivery](#standalone-delivery)). With no sink, the change's only
  delivered record is still the post-commit admin audit event (or the maintenance
  command's printed counts), which stays bounded telemetry.
- **No retention and no capacity bound.** Rows are never pruned, so each table
  grows by one small row per change. A restore of the file rewinds the evidence
  with the state it describes.
- **Operation identity.** Both modes accept a caller-bound UUIDv7 for a keyed
  service-token issue, rotation and revoke ([Keyed service-token issue and
  rotation](#keyed-service-token-issue-and-rotation)). Other mutations generate their
  operation IDs in the store, as unkeyed ones do. The actor's kind, auth mode and issuer
  are recorded, as in cluster mode since migration 24.
- **Not carried across a cutover.** `import-standalone` leaves these rows in the
  standalone files and names them in its report.
- **No evidence for changes made before migrations 12 and 13.** Each migration
  creates empty tables and fabricates nothing; in particular a stored overlay's
  last writer is not turned into an evidence row. A gateway built before a
  migration refuses to open a Connections database that has been migrated with it,
  so a rollback needs the database backup taken before the upgrade.
- **Not covered:** enum-source value refreshes (they change no publication), and
  the file-backed policy, tools and configuration authorities, which wait for
  #242's ledger. A token issued before the token table admitted the issue action
  has no issue row; `created_by` stays its only record.

## Standalone delivery

A standalone gateway has no journal and needs none: each SQLite store that owns an
authority already keeps that authority's evidence in tables whose `sequence` is an
`AUTOINCREMENT` assigned while the writer holds the file's write lock. Within one
table, sequence order is therefore commit order, a sequence is never reused, and no
sequence below a committed one can commit later, so a cursor over the table itself
never skips a row. The dispatcher (`gateway/src/authority_events/standalone.rs`)
delivers those tables directly; nothing is copied anywhere inside the change's
transaction.

**Each store is its own evidence authority.** This is a design decision, not an
accident of layout: the token database and the Connections database are separate
files that cannot commit atomically with each other, and either can be restored or
moved alone. Each therefore has its own persisted `authority_id` in its own
`authority_event_state` table, written once by the first dispatcher start and never
changed, and its references are derived under it. A consumer that receives both
sees two authorities, and deduplicates on `(authority_id, event_id)` exactly as for
cluster delivery. If an operator points `SERVICE_TOKEN_SQLITE_PATH` and
`CONNECTIONS_SQLITE_PATH` at the same file, that file is one authority with one
`authority_id`, and every table still has its own cursor.

| Store | Delivery state created by | Sources (one cursor each) |
| --- | --- | --- |
| `SERVICE_TOKEN_SQLITE_PATH` | the token store's open-time schema | `service_token_change_evidence` |
| `CONNECTIONS_SQLITE_PATH` | Connections schema migration 14 | `connection_change_evidence`, `connection_local_secret_change_evidence`, `catalog_change_evidence` |

Both create the same two tables: `authority_event_state` (the authority ID and when
it was written) and `authority_event_cursors` (per source, the last sequence a sink
accepted and how many events it accepted in total). Both start empty and fabricate
nothing: the first start delivers every row the tables already hold, from sequence 1.

**Delivery.** With `AUTHORITY_EVENT_SINK=log` or `file`, startup resolves the pseudonym
keyring once per store under that store's authority ID, through the same aliases and
secret providers as cluster mode, opens each source's cursor (creating it at 0), and
audits each load as `authority_event.keyring_loaded` with the store's name, its
authority ID and the key IDs. Any failure refuses startup. Then one task, outside every
authority transaction, delivers every source in turn: it reads at most 100 rows after
the cursor, projects them into records in the sink's format
(`gateway/src/authority_events/standalone_delivery.rs`), offers them to the sink and
only after the sink accepted advances the cursor with a compare-and-set in an IMMEDIATE
transaction. A sink failure is retried with the same 0.5 s to 60 s backoff and the
same batch; an advance that fails after acceptance is retried alone; a crash between
acceptance and the advance offers the batch again after restart with the same event
IDs and, under the same key, identical bytes. A row that cannot be projected
faithfully stalls its own table at that row, counted and logged; the other tables
keep delivering, and nothing is ever skipped. Delivery delays no change: a sink outage
costs only disk, because standalone evidence has no capacity bound and no retention.

**What a standalone record says differently.** `sequence` is the row's sequence in its
own table, so it orders events within an operation family (`service_token.*`;
`connection.*` and `credential.*`; `secret.*`; `catalog.*`), not across them.
`revision.security` is `null`: a standalone store has no shared security revision.
Service-token records carry the token's revision before and after (issue #425,
plan P5): an issue creates revision 1, a rotation or revocation advances it. A token
row whose writer recorded no revision (`revised = 0`: written before the token table
recorded revisions, or by an older build since) carries `null` before and after, and
nothing is invented. Local-secret changes sit on the `secret` axis with
the secret's version, referenced by its gateway-minted ID. A re-encryption batch names
no secret and changes no version, so it sits on the `maintenance` axis with no
revisions, and its resource is the local-secret store as a whole, referenced from the
fixed component `connection_local_secrets`, which no secret ID (a UUID) can equal.
Catalog publications sit on the `catalog` axis with the catalog revision before (none
for a first catalog) and after, referenced as the Connection's catalog; the compiled
overlay revision stays in the evidence row. A credential binding change is the
Connection's, on the `credential` axis, exactly as cluster mode delivers it.

**Format.** Every record is `authority_event_delivery.v1` under the default
`AUTHORITY_EVENT_FORMAT=delivery_v1`. Under `qualified_v1` a Connection,
local-secret or catalog row follows the cluster rule in
[Authority event v1](#authority-event-v1): a caller UUIDv7 with an issuer-bound
principal is delivered as `authority_event.v1` with `revision.security` `null`,
and a caller UUIDv7 with any other actor that is not a service token stalls its
table. A revised token row follows the same rule, so a keyed principal issue,
rotation or revocation is delivered as `authority_event.v1`. A token row that is
not revised records no revision, so it keeps `authority_event_delivery.v1`
whatever its operation ID, including the keyed revocations recorded since #765
before the token table recorded revisions, and so does a re-encryption batch. A
revised token row without its transition stalls its table, as an unprojectable row
of any table does.

**Signals.** `greengateway_standalone_authority_event_undelivered{store}` (rows above
the cursors, summed per store) and
`greengateway_standalone_authority_event_oldest_undelivered_age_seconds{store}` are
published after every pass, so they exist only where a sink is configured, and
`greengateway_standalone_authority_event_delivery_failures_total{store,kind}` counts
failed steps by `evidence_read`, `projection`, `sink` or `cursor_advance`. The
[operational rule pack](deployment/operational-alerts.md#standalone-authority-event-delivery)
warns on sustained lag and on repeated failures.

**Operations.** A restore of a file rewinds its evidence and its cursor together, so
events delivered after the backup are delivered again under the same event IDs, and
the authority ID survives. To stop delivering, unset the sink; the cursors stay, and a
later sink resumes after them. To deliver a file's evidence again from the start,
delete its `authority_event_cursors` rows while the gateway is stopped. A second
process on the same file would deliver the same rows too; the cursor's
compare-and-set keeps it from moving backwards or counting a batch twice, and a
dispatcher whose cursor moved under it re-reads it. `import-standalone` carries
neither the evidence nor its delivery state: let the standalone gateway catch up
(both undelivered gauges at 0) before a cutover.

Tests: `gateway/src/authority_events/standalone_tests.rs` (delivery in commit order
under each store's own authority from the real stores, a crash between acceptance and
the advance redelivering identical records, a sink outage, a restart resuming after
the cursor, a stalled table, the file sink, startup keying and auditing, the running
task), `standalone_delivery_tests.rs` (every action against the published schema
and the tables' CHECK vocabularies, every revision transition, refusals, and
synthetic markers in every identifier the projection reads, none of which reaches a
record), and `gateway/src/storage/standalone_authority_events.rs` for the cursor
protocol.

## Required-durability mode

`AUTHORITY_EVIDENCE_DURABILITY=required` ([configuration](configuration.md#authority_evidence_durability))
is the mode PR 4 asks for: it refuses the authority changes a deployment mode cannot
evidence. **Until #242 provides evidence of configuration activation, a gateway in
this mode refuses to start, in both deployment modes** (owner decision of
2026-11-19); the rest of this section describes what the mode does once a gateway
can start in it, and what the tests that build the application directly prove.
Each row states which requests the mode admits. The 13 qualified rows (PostgreSQL
keyed approval preparation, and the keyed forms of the service-token, Connection,
catalog, local-secret and cluster policy, tools and policy test changes) have the
complete caller-bound event and its tested delivery path. Other rows list their
remaining gaps. The default is `best_effort`. The setting is separate from
`AUDIT_DURABILITY`, whose `required` default covers request decisions only: tying
this contract to that default would have stopped every standalone gateway from
editing its policy and every cluster replica without a pseudonym key from starting.

The contract is the inventory's `required_mode` for each row, and
`gateway/src/authority_events/required.rs` enforces it. A change is `admitted` only
where the row's record shows that the change's own transaction durably names who
made it, beside the change. An admitted row carries exactly one of the two
reviewed unqualified dispositions, `no_caller_key` or `withdrawal_admitted`; its
evidence is atomic with the change and delivered as `authority_event_delivery.v1`,
and the checker refuses any other disposition on an admitted row. A `caller_key_required` row admits
only a keyed request by an issuer-bound principal with `qualified_v1`, the file
sink and a Unix build, and names the first of these that fails
([Keyed authority changes](#keyed-authority-changes)).

| `required_mode` | Rows | What required mode does |
| --- | --- | --- |
| `admitted` | Cluster Connection delete, token revocation, JWT revocation, and admin session grant and withdrawal, and standalone Connection delete, local-secret delete and re-encryption, and token revocation | Runs it. Its evidence is the row's `record`. Nine of these pairs stay admitted without qualification on purpose ([below](#rows-admitted-without-qualification)) |
| `caller_key_required` | PostgreSQL mutation approval preparation, and in both modes Connection create and replace (with the credential binding change a replacement makes), managed catalog publication and overlay put and delete, and service-token issue and rotation, and standalone local-secret create and rotation, and in cluster mode policy mutations, OpenAPI tools registration and stored policy test suite writes | Admits only the issuer-bound keyed request with `qualified_v1`, `AUTHORITY_EVENT_SINK=file` and a Unix build. Required mode refuses the ordinary preparation POST, the unkeyed Connection create and replace, the unkeyed refresh, OpenAPI registration and overlay put and delete, the unkeyed token issue and rotation, the unkeyed standalone local-secret create and rotation, and the unkeyed cluster policy, tools and policy test changes. |
| `refused` | Standalone mutation approval preparation and mutation approval review, revocation and consumption in both modes. Standalone policy mutations, policy file reloads, stored policy test suite writes, and tools publication (admin API and file reloads), which stay with #242. The writing form of the offline import (`import-standalone --apply`, with or without `--resume`) in cluster mode | Refuses it when asked, before anything is written |
| `refused_at_startup` | Standalone admin sessions (`ADMIN_SESSION_MODE=standalone_memory`), and configuration activation in both modes | Refuses to start |
| `unavailable` | Cluster policy file reload and local secrets, standalone JWT revocation and import, configuration export | Nothing to refuse: the mode or the build has no such operation. A gate that is asked anyway refuses it |
| `outside_gateway` | External secret-provider rotation | Not covered: the provider owns the write and the gateway cannot refuse it |

Enforcement:

- **Startup.** The configuration compiler refuses `required` with
  `AUTHORITY_EVENT_SINK=none` in either mode (rule
  `AuthorityEvidenceDeliveryRequired`): a cluster replica would journal evidence that
  is retained but never delivered, and a standalone gateway's stores would record
  evidence that is never delivered. It refuses `required` with
  `ADMIN_SESSION_MODE=standalone_memory` (rule
  `AuthorityEvidenceUnsupportedConfiguration`). Both problems name
  `AUTHORITY_EVIDENCE_DURABILITY`, so the value-free diagnostics attribute them to it.
  A configuration the compiler accepts is then refused by serving startup, after
  the compiler and before preflight: nothing records the activation of the
  configuration the gateway would serve, so no stage runs (no database connection,
  migration, membership row, tools seed or listener), and the gateway prints
  `authority_evidence_activation_unevidenced: AUTHORITY_EVIDENCE_DURABILITY=required
  refuses configuration.activate: ...`, naming the deployment mode and no configured
  value, and exits non-zero. The compiler's refusals are reported first.
  `ActivationProof` in `gateway/src/authority_events/required.rs` has no value: #242
  lifts the refusal only by giving it a constructor that verifies, inside the
  activation stage and atomically with it, that a ledger or activation record
  matches the exact configuration being activated (same digest, same revision),
  and the inventory checker holds the `configuration_activation` row at
  `refused_at_startup` until then. Offline commands do not ask this startup
  check: `revoke-jwt` still runs and records its own evidence, and the offline
  import asks its own question (below). Bundle mode stops before this point with
  `source.mode_unavailable`; bundle serving must pass the same check when it
  ships. `ggctl validate` and `ggctl doctor` accept a configuration the gateway
  then refuses to serve, and the Cloudflare Worker refuses the setting before
  it starts a container (`authority_evidence.activation_unevidenced`).
- **Admin API.** Each endpoint of a `refused` row asks the gate once the
  caller is authorized. A refusal is `409 {"error":"...","reason":"authority_evidence_unsupported","operation":"<code>"}`,
  naming the inventory operation code and nothing from the request. Every policy
  mutation, suggestion acceptance, OpenAPI tools registration and stored policy
  test suite write (`PUT .../policy/tests`) asks once the caller is authorized and
  the request validated, before the authority is read, with the request's form
  ([Keyed policy, tools and policy test changes](#keyed-policy-tools-and-policy-test-changes)).
  Every draft publication, keyed or not, asks before the draft, the policy or
  the suggestion is read: as `policy.publish`, or as `policy.suggestion.accept`
  when it is bound to a suggestion. An unkeyed refusal is also recorded as the
  draft's own `policy.draft_publish_refused` with the same reason.
  `commit_policy_mutation`, the commit path the policy mutations share, asks a
  second time. Connection create and replace ask as `connection.create` and
  `connection.replace` once the caller is authorized and the body validated, with
  the request's form ([Keyed Connection changes](#keyed-connection-create-replace-and-delete)).
  Local-secret create and rotation ask as `secret.create` and `secret.rotate` in
  the same place ([Keyed local-secret changes](#keyed-local-secret-create-rotation-and-delete)).
  A catalog refresh, an OpenAPI catalog registration and an overlay put and
  delete ask as `catalog.mcp.publish` or `catalog.openapi.publish` (a refresh
  publishes the catalog kind the Connection has), `catalog.overlay.replace` and
  `catalog.overlay.delete`, with the request's form
  ([Keyed catalog publication and overlay changes](#keyed-catalog-publication-and-overlay-changes)).
  Service-token issue and rotation ask as `service_token.issue` and
  `service_token.rotate`, with the request's form
  ([Keyed service-token issue and rotation](#keyed-service-token-issue-and-rotation)).
  Connection deletion, local-secret deletion, token revocation and the
  `connection-secrets reencrypt` command never ask: they are withdrawals or
  unqualified system changes that stay admitted
  ([Rows admitted without qualification](#rows-admitted-without-qualification)),
  and the store records each of them in the change's own transaction
  ([Standalone evidence](#standalone-evidence)).
- **Background activations.** A watched or `SIGHUP` reload of `POLICY_FILE` or
  `TOOLS_FILE` asks the gate first; a refused reload keeps the active policy or
  registry, MCP proxy tools included, until a restart activates the file.
- **Offline import.** `gateway import-standalone --apply` (and `--apply --resume`)
  asks the gate as `configuration.import` first thing, before it reads the
  `--from` file or opens the target, and under `required` stops with
  `authority_evidence_unsupported: AUTHORITY_EVIDENCE_DURABILITY=required refuses
  configuration.import: cluster mode records evidence for only part of it; nothing
  was changed` and a non-zero exit. Only its policy and tools activations record
  evidence; its Connections, audit, discovery and token sections commit none, and
  the owner ruled (2026-11-20) that the writing form is refused rather than given
  per-section evidence. The default `--dry-run` writes nothing and still runs. Only
  a cluster target asks: one that is not cluster mode still gets `target_not_postgres`. An
  offline command's gate follows that command's own environment: the import is
  refused when the environment it runs with sets `required`, and not because the
  fleet's replicas run with it.
- **Audit.** Every refusal of a request or a background activation is logged and audited as
  `authority_evidence.operation_refused` with `operation`, `deployment_mode`,
  `trigger` (`admin_api`, `file_watch`, `signal`) and `reason`; an admin API
  refusal also carries the request ID, source address and caller.

The gate reads configuration and nothing else: the durability, the deployment
mode, and for a keyed change the event format, whether the sink is the file sink,
and whether this is a Unix build. It never waits on a
store, the dispatcher or a sink, so proxy admission and every admin change still
wait only on their own local commits, never on a downstream acknowledgement. In
either mode the dispatcher delivers after the commit, outside every authority
transaction, exactly as under `best_effort`; required mode only makes sure a sink is
configured to deliver to. In cluster mode `required` is part of the static configuration
fingerprint (absent under `best_effort`, so the default leaves fingerprints
unchanged), and a replica with a different value is not ready in that deployment.

What required mode does not do:

- It refuses no `admitted` row, and each of them is delivered: every cluster
  evidence table is a journal source (admin-session evidence since migration 26,
  policy, tools and catalog evidence since migration 32), and the standalone token,
  Connection, local-secret and catalog evidence is delivered from its own stores,
  which required mode makes sure a sink is configured for
  ([Standalone delivery](#standalone-delivery)). A cluster Connection's version
  history still cascades with the Connection; its create, replace, credential binding
  change (since migration 28) and deletion evidence rows do not.
- It does not refuse external provider rotation or
  anything outside the inventory's matrix (status observations, verification and
  last-use updates, cleanup).
- It does not qualify every row it admits. The nine pairs in
  [Rows admitted without qualification](#rows-admitted-without-qualification) are
  atomic and delivered, but carry no caller key.
- A standalone gateway in required mode therefore changes its policy and tools only
  through its startup files (those rows stay refused until #242, see
  [Next reviewable slices](#next-reviewable-slices-and-validation-gates), item 5),
  and issues and rotates service tokens, creates and replaces Connections,
  publishes managed catalogs and overlays, and creates and rotates local secrets
  only with a caller key. Token revocation, Connection and local-secret deletion and
  master-key re-encryption are changed as usual.

Tests: `gateway/src/authority_events/required_tests.rs` holds the gate's table to the
inventory (every `refused` row has a gate that refuses it in that mode, every gate
agrees with its row, and the only operations refused at startup are standalone admin
sessions and configuration activation in both modes; the compiler also refuses
`required` with no sink), checks both
modes and the refusal's audit event, refuses the offline import in cluster mode with
its own reason (`required_refuses_the_offline_import_in_cluster_mode`), holds the evidenced standalone Connection
deletion, local-secret deletion and catalog rows `admitted` and ungated, Connection create
and replace `caller_key_required` in both modes, and local-secret create and rotation
`caller_key_required` in standalone mode
(`connection_create_and_replace_admit_only_their_keyed_issuer_bound_form_in_both_modes`); `authority_evidence_app_tests.rs`
drives every refused standalone admin endpoint through the real handlers and asserts
the `409`, the audit event and that nothing changed, that an unkeyed Connection
create and an unkeyed local-secret create are refused, and that Connection and
local-secret deletion and catalog, overlay and token changes are admitted and write their evidence rows; the
reload helpers in `middleware/rbac_tests.rs` and `tools/definitions.rs` refuse a
reload and keep the active document; `config_tests.rs`,
`gateway-config/src/compiler/stage_tests.rs` and `ha.rs` cover the startup rules,
their diagnostics and the fingerprint; `bootstrap_tests.rs` shows that serving
startup refuses required mode in both modes before any stage runs, with a
value-free message, that the compiler's refusals are reported instead when they
apply, and that `best_effort` startup runs every stage as before;
`gateway/tests/audit_durability_startup.rs` runs the real binary under `required`
in both modes and shows that it exits with status 1, prints the refusal and writes
nothing; and `gateway/src/import/tests.rs` shows that the import's writing forms are
refused under `required` before the `--from` file is read or the target opened
(`a_writing_import_under_required_exits_before_opening_the_target_store`), that the
dry run still runs (`a_dry_run_import_under_required_still_runs`), and, against a
real PostgreSQL target, that the dry run plans every section and the refused apply
writes nothing (`a_dry_run_under_required_plans_every_section_and_writes_nothing`);
`the_import_writes_nothing_under_required_and_its_dry_run_still_runs` in
`gateway/tests/audit_durability_startup.rs` shows the same through the real binary:
the refusal line, status 1 and nothing written.

### Remaining limits

These hold when issue #425 closes:

- Required mode cannot serve in either deployment mode until #242 provides
  per-activation evidence. The qualified rows are proven by tests that build the
  application directly; no deployment has run them in required mode.
- Required mode admits keyed non-withdrawal changes only from provider-authenticated
  principals, with `qualified_v1`, the file sink and a Unix build. Admin callers
  authenticated by a gateway service token are refused for those changes; in
  `best_effort` their keyed changes are recorded and delivered as
  `authority_event_delivery.v1`.
- Token revocation, Connection delete and local-secret delete are admitted in every
  form in required mode. Their unkeyed and service-token forms are atomic and
  delivered at least once as `authority_event_delivery.v1`, but are not caller-keyed.
- JWT revocation, admin session grant and withdrawal, and local-secret re-encryption
  have no caller key. They are atomic, delivered at least once as
  `authority_event_delivery.v1`, reconciled by natural key, and not qualified.
- The admin session withdrawal reason is recorded in `admin_session_evidence` and
  not delivered.
- The offline import's writing form and all mutation-approval operations except
  PostgreSQL keyed preparation are refused in required mode.
- A keyed request that changes nothing is not reconcilable by key.
- A replayed token issue or rotation never returns the secret; the caller revokes
  and issues again.
- A changed secret value under a reused key is detected only while the secret is
  still at the replayed revision.
- Keys are honoured only once every live member advertises `caller_operation_keys`.
  The first honoured key is a rollback cutoff for earlier builds.
- Evidence committed before each family's evidence migration carries no actor
  metadata and never qualifies. Nothing is backfilled.
- Delivery is at least once. The durable file-sink guarantee is stated for Unix
  only.
- Log-line and metric-label redaction (I5) is tested for the operations
  [Authority event v1](#authority-event-v1) lists per family, not for every keyed
  operation in both modes (issue #844). Service-token issue and rotation, which
  are qualified rows in PostgreSQL, are driven in the SQLite form only, as are
  the OAuth client-credentials replacement and the keyed Connection delete. Each
  of these leaves this list when its test lands.

The family changes recorded these further limits:

- Connections: under required mode the admin UI, which sends no `Idempotency-Key`,
  cannot create or replace a Connection (or issue or rotate a token, or publish).
  Keys in the admin UI are handed to #242.
- Catalogs: a keyed refresh or OpenAPI registration retried after its Connection
  was deleted answers `404`, not the receipt.
- Local secrets exist only in standalone mode. On a replayed create or rotation the
  retried value is compared with the stored one, so the same principal holding the
  key can confirm a guessed value; mismatches are not counted, audited or
  rate-limited. The constant-time comparison is hand-written.
- Policy, tools and policy test keys are honoured in cluster mode only; a
  standalone gateway answers a keyed request `400 standalone_caller_key_unsupported`.
  A replayed draft publication does not mark the draft published. Keyed admission
  in required mode on the draft publication and suggestion acceptance routes is
  exercised through `PUT .../policy` only.
- `admit_keyed_authority_change` compares a `Gated` operation with the key's
  action, but nothing in it checks an unkeyed request labelled `Withdrawal`. The
  guard is the route-enumerating test
  `required_mode_refuses_the_unkeyed_form_of_every_gated_keyed_route`
  (`gateway/src/authority_evidence_route_app_tests.rs`), which drives every route in
  `KEYED_ROUTES` on a standalone gateway in required mode: each gated route but the
  keyed preparation (which takes no unkeyed request and answers `400` naming the
  key) must refuse its unkeyed form with `409` and write nothing to any store, and
  each of the three withdrawals is named with the test that covers it. In
  standalone mode the policy, tools and policy test routes are refused in every
  form, so for their cluster rows the unkeyed form is covered instead by
  `document_keys_app_tests::cluster_document_keys::required_mode_refuses_the_unkeyed_policy_change_and_admits_the_keyed_principal`
  (policy `PUT`, rollback, every rule edit, tools registration and suite write)
  and, for suggestion acceptance and draft publication,
  `required_mode_refuses_the_unkeyed_cluster_acceptance_and_draft_publication_before_reading`.
- Log-line and metric-label redaction (I5) is tested only for the operations the
  router-level marker tests drive
  ([Authority event v1](#authority-event-v1) lists them). The policy
  rule create, update, delete and reorder, policy rollback and suggestion
  acceptance, and `catalog.mcp.publish`, have no log and metric test. The OAuth
  client-credentials replacement and the keyed Connection delete are driven in
  the SQLite form only. The capture sees `tracing` events on the runtime's own
  threads, not `log`-crate records from dependencies or threads the code spawns
  itself, such as the audit log writer.

### Rows admitted without qualification

Two kinds of inventory row stay `admitted` in required mode with
`required_durability_supported: false`, by owner ruling (2026-11-20). Each has its
own disposition, and `scripts/check-authority-evidence.mjs` allows each only alone,
only on the pairs below, and only on an admitted, unqualified row, so neither can
relabel a gap.

`no_caller_key`: no authenticated remote caller starts the change, so nothing
outside the gateway holds a request to retry and no key can be bound to it. Each is
atomic, delivered at least once as `authority_event_delivery.v1`, and reconciled by
its natural key:

| Row | Pair | Natural key |
| --- | --- | --- |
| `jwt_postgres` | `jwt.revoke`, cluster (`gateway revoke-jwt`, fixed system actor) | The deployment- and issuer-scoped JTI digest. An exact repeat of an effective revoke (the same or an earlier expiry, or any repeat over an entry with no expiry) reports `already revoked`, writes nothing and spends no revision. A repeat that extends the entry (a later expiry, no expiry, or an entry already past its expiry and the retention leeway) updates the denylist in place and records exactly one more evidence row |
| `admin_session_withdraw_postgres` | `admin_session.withdraw`, cluster (logout, rejection, replacement, expiry) | The session ID: one withdrawal per session (`UNIQUE (session_id, action)`); a repeated logout, on any replica, writes nothing |
| `local_secret_reencrypt` | `secret.reencrypt`, standalone (`connection-secrets reencrypt`, fixed system actor) | The maintenance batch: a repeat re-encrypts nothing already under the active key, and an empty batch writes no row |
| `admin_session_grant_postgres` | `admin_session.grant`, cluster (a browser completing OIDC login) | The session ID: one grant per session (`UNIQUE (session_id, action)`) |

The first three withdraw authority or are maintenance; refusing them would fail
open. A grant gives authority, so that argument does not cover it. It stays
admitted by its own ruling: the grant, its evidence and its journal entry are one
SQL statement, it is reconciled by session ID, and refusing it would block the OIDC
login through which the principals that required mode's keyed changes need use the
admin UI.

`withdrawal_admitted`: a remote caller starts a change that only removes authority.
Every form stays admitted in required mode, including the unkeyed `DELETE` the admin
UI sends and service-token callers, because refusing a withdrawal would leave a
leaked token, a Connection or a secret live. Those forms commit their evidence row in
the change's transaction and are delivered as `authority_event_delivery.v1`, but are
not caller-keyed. Only the keyed principal form is qualified, so a
`withdrawal_admitted` row carries exactly one reviewed `qualified_delivery_paths`
entry for each of its pairs. The pairs are `service_token.revoke` in both modes,
`connection.delete` in both modes and standalone `secret.delete`. Today
`token_revoke_postgres` and `token_revoke_standalone` (`POST .../tokens/{id}/revoke`;
the standalone one since the token database records the token's revision, plan P5),
`connection_delete_postgres` and `connection_delete_standalone`
(`DELETE .../connections/{id}`), and `local_secret_delete`
(`DELETE .../connection-secrets/{id}`, plan P8) have their reviewed paths.

`catalog.overlay.delete` is not a withdrawal: removing an overlay publishes a new
catalog revision. The session withdrawal reason stays in `admin_session_evidence`;
the delivered record has no field for it, and delivering it needs a new schema
version.

Tests: the checker's "no_caller_key is limited to its reviewed pairs",
"withdrawal_admitted is limited to its reviewed pairs and needs a reviewed keyed
path" and "neither disposition can claim required durability". The natural-key
behaviour is characterized, not changed, by
`repeating_an_effective_jwt_revoke_records_no_second_evidence_row` and
`extending_a_jwt_revocation_records_exactly_one_more_evidence_row` in
`storage::contract_tests` (with
`jwt_revocation_evidence_survives_extension_reactivation_and_cleanup` for the
reactivation of an expired entry), `a_repeated_withdrawal_records_one_withdrawal` in
`storage::postgres_admin_sessions`, and the re-encryption batch tests in
`connections::local_secret` and `connection_secret_maintenance`.

## Changes the inventory does not cover

The delegated-token purge (`POST /v1{ADMIN_PREFIX}/principal/delegated-tokens/revoke`,
`principal_delegated_tokens_revoke_endpoint` in `gateway/src/admin_observability.rs`)
withdraws authority: it drops every delegated issuer token the gateway caches for one
principal, under every `delegated_issuer_token` Connection, and revokes each at its
issuer where the Connection names a `revocation_url`
([configuration](configuration.md)). It is audited, and in cluster mode it is
recorded as a shared security revision through the operation gate so that every
replica purges its own cache. It has no authority evidence row: it is not one of the
inventory's operations, and giving it one would need a new operation code and a new
schema version of the delivered record. The owner ruled (decision 8 on #425,
2026-11-20) that it stays outside the inventory. `scripts/check-authority-evidence.mjs`
records it, with that reason, in its table of endpoints that are not inventory
authority changes (`NOT_AUTHORITY_CHANGES`), so the scan does not report it as
unclassified. Required mode does not ask the evidence gate for it, and like every
route outside `KEYED_ROUTES` it refuses an `Idempotency-Key`.

## Verified-TLS storage tests

The PostgreSQL evidence suites run twice in CI, in two shards of the required
`postgres-foundation` check. `postgres-foundation-pg` runs the whole gateway suite
against a service container over loopback plaintext, under the documented
`loopback-dev` exception. `postgres-foundation-tls` runs these suites again against a
disposable PostgreSQL 16, the same pinned image, that accepts TLS and nothing else:

- in `storage::contract_tests`, the caller operation key contract
  (`postgres_caller_operation_reservation_contract`,
  `postgres_a_rolled_back_transaction_leaves_no_reservation`,
  `postgres_two_transactions_racing_one_key_reserve_it_once`) and its contract
  fence check (`a_bound_reservation_below_the_fence_is_refused`), the service-token
  and JWT revocation evidence tests
  (`postgres_service_token_change_evidence_satisfies_the_contract`,
  `service_token_change_evidence_matches_the_outbox_and_survives_deletion_and_restart`,
  `a_failed_token_evidence_insert_rolls_back_the_rotate_and_the_revoke`,
  `revoke_and_rotate_race_never_leaves_a_live_plaintext`,
  `jwt_revocation_evidence_survives_extension_reactivation_and_cleanup`,
  `a_failed_jwt_evidence_insert_rolls_back_the_revoke`,
  `repeating_an_effective_jwt_revoke_records_no_second_evidence_row`,
  `extending_a_jwt_revocation_records_exactly_one_more_evidence_row`), the keyed
  service-token issue and rotation (`postgres_audit_tests::keyed_token_changes::`, and
  through the handlers of a cluster replica
  `authority_evidence_app_tests::cluster_token_keys::`), the keyed policy, tools and
  policy test changes through the handlers of a cluster replica
  (`document_keys_app_tests::cluster_document_keys::`), the suggestion acceptance's
  document evidence (`an_accepted_suggestion_records_its_evidence_in_the_acceptance_transaction`)
  and `a_replica_held_at_the_fingerprint_door_never_rewrites_the_journal_capacity`;
- the whole PostgreSQL Connection store suite (`connections::pg_store`), its create,
  replace, credential binding change, deletion and catalog evidence and the keyed
  Connection contract included;
- the keyed Connection, catalog and local-secret changes through the handlers of a
  cluster replica (`authority_evidence_app_tests::cluster_connection_keys::`), the
  PostgreSQL marker test of Connections and catalogs included;
- the PostgreSQL mutation-approval tests (`issue_757_mutation_approvals::postgres::`);
- all 17 tests of `admin_observability_app_tests::cluster_discovery_tests::`, among
  them the keyed suggestion acceptance and draft publication tests that anchor the
  `policy_postgres` row for `policy.publish` and `policy.suggestion.accept`
  (`a_keyed_cluster_draft_publication_reserves_policy_publish_and_replays_its_receipt`,
  `a_keyed_cluster_acceptance_is_answered_from_its_receipt_once_the_suggestion_is_closed`,
  `a_keyed_cluster_bound_draft_publication_reserves_the_acceptance_and_replays_its_receipt`,
  `required_mode_refuses_the_unkeyed_cluster_acceptance_and_draft_publication_before_reading`)
  and `cluster_accept_after_only_a_security_revision_advance_still_succeeds`;
- `storage::postgres_documents`, the keyed policy, tools and policy test contract
  included, and `storage::postgres_admin_sessions`;
- the dispatcher (`authority_events::dispatcher`);
- journal retention without a cursor, in `storage::postgres_authority_events`:
  `retention_under_required_never_prunes_a_journal_with_no_cursor`,
  `best_effort_without_a_cursor_still_prunes_by_age` and
  `the_maintenance_retention_job_takes_its_cursorless_hold_from_durability`;
- `storage::migrations`' evidence and journal migrations: 12 through 16, 18, 21,
  24 through 29, 32, 33, 35 and 36;
- the app-level `admin_token_rotate_and_revoke_record_the_authenticated_subject_and_issuer_postgres`.

Each run generates a throwaway CA and a server certificate for `127.0.0.1` and
`localhost` in the runner's temporary directory, and deletes the CA key once it has
signed; no key is committed or kept. The server runs with `ssl=on` and a `pg_hba`
that admits `hostssl` and rejects `hostnossl`. The suites reach it through the test
harness, `storage::postgres::test_support`: with `GATEWAY_TEST_POSTGRES_TLS_CA_FILE`
naming the CA, every pool and session it builds runs in `DATABASE_TLS_MODE=verify`
with that file as `DATABASE_TLS_CA_FILE`, through the gateway's own DSN validation,
`enforce_tls_policy`, session settings and rustls connector, so the certificate's
chain and the name dialled are verified on every connection.

What this proves:

- The evidence writes, rollbacks, journal appends, capacity refusals and deliveries
  those tests assert hold on verified-TLS sessions exactly as on plaintext ones.
- No suite in the shard can have passed over plaintext or by skipping.
  `a_verified_tls_run_reaches_its_database_only_over_tls` asserts that the harness's
  sessions are TLS (`pg_stat_ssl`) and that the server refuses a plaintext one. With
  the CA locator set, a missing DSN locator panics instead of skipping, and the shard
  fails when one of its filters selects no test.
- A server certificate from another CA
  (`a_server_certificate_from_another_authority_is_unavailable_and_names_no_dsn`) and
  one that does not name the address dialled, reached through a relay on `127.0.0.2`
  (`a_server_certificate_for_another_name_is_unavailable_and_names_no_dsn`), are both
  refused. The connectivity check every store shares classifies the refusal as
  `unavailable`, startup reports it as the cause of exhausting its retry budget, and
  neither error renders any part of the DSN.

What it does not prove: password or client-certificate authentication (the test
server trusts every TLS client), certificate rotation, a managed provider's server,
or anything about the rest of the gateway suite, whose PostgreSQL tests still run
only against the loopback database.

## Next reviewable slices and validation gates

Issue #425 shipped in these pull requests: configuration activation refused at
startup in required mode (#826); the rows admitted without qualification named and
the offline import's writing form refused (#831); caller operation IDs bound to a
request digest in both stores, with PostgreSQL migration 36 (#828); every
caller-bound principal change delivered as `authority_event.v1` (#827); one gate for
keyed changes, the `KEYED_ROUTES` guard and the `caller_operation_keys` capability
(#833, with #838); keyed service-token issue and rotation (#836), Connection create,
replace and delete (#834), catalog publication and overlay changes (#837), local
secret changes (#839), and cluster policy, tools and policy test changes (#840); log
and metric marker tests for Connections, catalogs, and policy, tools and policy
tests (#842); the suggestion and draft publication handler tests on the
verified-TLS shard (#843); and the closing reconciliation of this inventory and these docs. Items 1 to 4 below are
the evidence and delivery slices those changes built on, and say where each gained
its caller-bound form. Item 5 is what stays open, handed to #242. The limits that remain are listed under
[Remaining limits](#remaining-limits).

1. **PostgreSQL Connection deletion evidence (landed).** The delete transaction
   now writes non-cascading actor/action/event/operation metadata to migration
   16's `connection_change_evidence`, beside the unchanged outbox tombstone and
   carrying its shared revision. Migration 16 moves the serving contract from
   exactly schema 15 to exactly schema 16, a coordinated drain/migrate/restart.
   PostgreSQL-gated store tests cover actor survival after delete and restart,
   stale ETag, dependency rejection, a missing record, two writers, a forced
   evidence-insert failure and its rollback, and reconciling a lost response
   from the evidence row; CI runs them against its disposable loopback database,
   and again over verified TLS ([Verified-TLS storage tests](#verified-tls-storage-tests)).
   Migration 24 adds the deleting actor's kind, auth mode and
   canonical issuer ([Actor metadata](#actor-metadata)). Migration 28 extends the
   table to Connection create and replace, and to the credential binding change a
   replace records on the credential axis when it advances the credential revision,
   each written and journaled in the change's own transaction with the whole actor;
   PostgreSQL-gated store tests cover attribution, a stale ETag, a moved collection,
   the capacity bound and an unrecordable actor writing nothing, racing writers
   leaving only the winner's rows, forced evidence and journal failures rolling the
   change back, a full journal refused with `503`, survival after delete and
   restart, and the absence of specification, binding and secret material.
   Connections created or replaced before migration 28 keep only their cascading
   version history. A caller-bound operation identity at the store boundary landed
   with #834 for create, replace and delete in both modes
   ([Keyed Connection create, replace and delete](#keyed-connection-create-replace-and-delete)).
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
   CI against its disposable loopback database, and again over verified TLS
   ([Verified-TLS storage tests](#verified-tls-storage-tests)). Migration 24
   (and the standalone token database's own columns) adds the actor's kind, auth
   mode and canonical issuer, and records the CLI's system label as kind `system`
   ([Actor metadata](#actor-metadata)). Migration 27 adds token issue evidence
   to the same table in both stores, written in the create's transaction (and
   journaled in PostgreSQL), with the shared contract extended to the issue's
   actor, its forced insert failure and rollback, plaintext and hash exclusion,
   restart and the contiguous issue, rotate and revoke chain; tokens issued
   before it keep `created_by` as their only record. Both stores bind the caller's
   operation ID for the keyed revocation route, and since #836 for keyed issue and
   rotation too ([Keyed service-token issue and rotation](#keyed-service-token-issue-and-rotation));
   an unkeyed issue or rotation still generates its operation ID internally.
3. **Shared documents/catalog metadata (landed).** The shared document core
   (`postgres_documents::commit_in`) now writes one migration 23
   `document_change_evidence` row beside the outbox row of every policy and tools
   commit, so suggestion acceptance, which runs it inside its own transaction,
   records its evidence there too. Each handler names its operation explicitly
   (`policy.publish`, `policy.rollback`, `policy.rule.create`/`update`/`delete`/`reorder`,
   `policy.suggestion.accept`, `tools.publish`, and since migration 29
   `policy_tests.publish` for the stored policy test suite), the import's activations are
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
   lane holds write nothing; an actor evidence cannot record exactly, or an action
   that cannot describe the resource, is refused before anything is written. A tools commit
   followed by a failed local install keeps its evidence, because the commit is
   durable. Migration 23 moves the serving contract from exactly schema 22 to
   exactly schema 23, a coordinated drain/migrate/restart. PostgreSQL-gated tests
   cover attribution of each operation and the system actors, outbox agreement,
   refusals that write nothing, forced evidence-insert failure and its rollback
   (including inside a suggestion acceptance), principal bounds, survival after
   catalog replacement, Connection deletion and restart, and the overlay
   vocabulary; CI runs them against its disposable loopback database, and all but
   the import's (`import::tests`) again over verified TLS
   ([Verified-TLS storage tests](#verified-tls-storage-tests)). Since migration 25
   every catalog publication records the whole actor, kind, auth mode and
   canonical issuer as Connection deletion does ([Actor metadata](#actor-metadata)).
   Migration 32 journals both tables and aligns the document rows' actor vocabulary
   with migration 24's ([Policy, tools and catalog delivery](#policy-tools-and-catalog-delivery)).
   A caller-bound operation identity landed for catalog publication and overlay
   changes in both modes with #837, and for cluster policy, tools and policy test
   changes with #840 ([Keyed policy, tools and policy test changes](#keyed-policy-tools-and-policy-test-changes));
   standalone policy and tools changes stay with #242 (item 5). No scheduled catalog
   refresh ships, so no system catalog actor is recorded yet.
4. **Durable dispatch and standalone evidence (landed).** Migration 21's
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
   its disposable loopback database, and runs the dispatcher and migration tests
   again over verified TLS ([Verified-TLS storage tests](#verified-tls-storage-tests)).
   Migration 26 adds the
   cluster admin session evidence as a journal source, with a unit of capacity held
   for each session's withdrawal ([Admin session withdrawals and journal capacity](#admin-session-withdrawals-and-journal-capacity)),
   moving the serving contract from exactly schema 25 to exactly schema 26, a
   coordinated drain/migrate/restart. Still open: the items listed at the end of
   that section. Standalone evidence landed in the stores that own it: Connections
   and local secrets in the Connections database (its migration 12), managed
   catalog and overlay publication in the same database (its migration 13), and
   service-token changes in the token database, each written in the change's own
   transaction ([Standalone evidence](#standalone-evidence)), and delivered from
   those stores through a cursor in each ([Standalone delivery](#standalone-delivery)).
   Since #827, under `AUTHORITY_EVENT_FORMAT=qualified_v1`, every caller-bound
   principal change of both modes is delivered as `authority_event.v1`
   ([Authority event v1](#authority-event-v1)).
5. **#242 hand-off: the standalone revision ledger and configuration activation.**
   By owner decision (recorded 2026-11-19), the rows that depend on the standalone
   revision ledger and bundle activation are not part of #425 and are tracked in
   #242: `policy_standalone`, `policy_reload`, `tools_standalone` and
   `policy_tests_standalone` (refused in required mode), `configuration_activation`
   (refused at startup, in both modes) and `configuration_export` (unavailable).
   Each row's `follow_up` in the inventory says so. Required mode keeps each of them
   as it is until #242 demonstrates, with tests: a ledger-owned safe manifest and
   digest; parent revision and compare-and-swap; actor and operation intent;
   activation and evidence that are atomic or recoverably staged; authoritative
   replay after interruption; and export intent accepted before an artifact is
   released. Raw secrets are never hashed or exported as a substitute for redaction.
   Six further points carry over from #425:
   1. `AUTHORITY_EVIDENCE_DURABILITY=required` refuses to start until an
      `ActivationProof` exists for the exact configuration being activated. The
      proof must be checked per activation, inside the activation stage, and never
      granted per backend; #242 changes the type, the place of the check and the
      `configuration_activation` row in one reviewed change.
   2. Bundle-mode serving must pass the same check when it ships.
   3. In cluster mode, required-mode preflight refuses to seed an empty tools
      document, because the seed is an unkeyed system write; the activation must
      cover it or the document must be provisioned beforehand.
   4. The Cloudflare Worker refuses `required` up front; lift that with the same
      change that makes a mode start.
   5. Every qualified row is proven by tests that build the application directly;
      no deployment has run them in required mode.
   6. The admin UI sends no `Idempotency-Key`, so in required mode it can revoke and
      delete but cannot issue, rotate, create, replace or publish; it needs to send a
      UUIDv7 key on those mutations before required mode is offered to operators.

The inventory's source anchors can become stale as code changes; update the
classification, proofs and reviewed revision in the same pull request.
`scripts/check-authority-evidence.mjs` holds the end state: an admitted row is
`no_caller_key` or `withdrawal_admitted`, `missing_metadata` appears only on a row
that required mode refuses, and `configuration_activation` stays
`refused_at_startup` while `ActivationProof` has no value.
