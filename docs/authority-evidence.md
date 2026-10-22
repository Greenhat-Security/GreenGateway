# Durable authority-change evidence inventory and contract

Part of [#425](https://github.com/Greenhat-Security/GreenGateway/issues/425), PR 1
and the first two PR 2 slices (PostgreSQL Connection deletion evidence; service-token
rotate/revoke and JWT revocation evidence), plus the keyed safe-reference derivation
every future event producer needs ([Keyed safe references](#keyed-safe-references)).
Reviewed source: `4a32d10e38d2ac36d6bcbee627443b1fbb80d059`.

This inventory identifies existing atomic records and the work needed for required
authority-change evidence. PR 1 added the inventory and the proposed event
contract. The first PR 2 slice adds migration 16's
`greengateway.connection_change_evidence`, written by PostgreSQL Connection
deletes. The second adds migration 18's `greengateway.service_token_change_evidence`
and `greengateway.jwt_revocation_evidence`, written by PostgreSQL token rotate/revoke
and JWT revokes, and the same token evidence table inside the standalone SQLite token
database. None of them implements or enables required-durability mode, a dispatcher,
or a standalone revision ledger, and no row is qualified for that future mode.
Storage selection is unchanged.

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
| Connection deletion | Outbox tombstone with prior version and shared revision, plus a non-cascading `connection_change_evidence` row (actor, action, event/operation UUIDs, prior version, the tombstone's shared revision, database-clock time) in the same transaction | Issuer/auth mode, caller-bound operation identity, safe-reference projection, durable delivery and retention |
| Managed MCP/OpenAPI catalog and overlay publication | Catalog/overlay CAS, entries, dependencies, reservations, revision and outbox | Current actor rows are replaced or cascaded; retain per-change evidence |
| Service-token issue | Token row with creator, row/shared revisions and outbox | Creation retains only `created_by`; no issue evidence row, operation identity or delivery |
| Service-token rotate/revoke | Token change, row/shared revisions and outbox, plus a non-cascading `service_token_change_evidence` row (actor, action, event/operation UUIDs, prior/new row revision, the outbox row's shared revision, database-clock time) in the same transaction; repeated revoke and refused rotate write none. Standalone writes the same evidence in the token database's own transaction | Issuer/auth mode, caller-bound operation identity, safe-reference projection, durable delivery and retention |
| JWT revocation | Scoped JTI digest, actor row, shared revision and outbox, plus one non-cascading `jwt_revocation_evidence` row per effective revoke (actor, JTI digest, resulting expiry, shared revision) that extension, reactivation and expiry cleanup never rewrite | CLI actor is system provenance, not a named human; no actor kind, issuer/auth mode or delivery |
| Admin session grant/withdrawal (#424) | Not shipped in this mode: configuration refuses `ADMIN_SESSION_MODE=standalone_memory` | Standalone sessions are process-local memory with no durable record; both modes stay `unsupported_future_operation` |

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
`admin_session.withdraw`. The shipped authority, `ADMIN_SESSION_MODE=standalone_memory`,
keeps each session in a bounded process-local map: a grant follows a successful
cookie completion, and withdrawal is logout, expiry, a rejected access token, an
identity change or a restart. Nothing about it is durable, and the
`admin_login.transaction` event the handler emits after a grant or logout carries
no actor or session identity; implicit withdrawals emit nothing. Cluster mode
refuses the setting, so no session authority exists there. Both rows are
`unsupported_future_operation`: required-durability mode must refuse in-memory
sessions rather than relabel that event durable, and a durable session authority
must ship with its own transactional evidence.

## Proposed authority event v1

[The closed JSON schema](schemas/authority_event.v1.schema.json) and the checker
define a **proposed** safe projection. Current `security_outbox` rows,
`connection_change_evidence` rows and `audit_event.v0` events do not already
satisfy this schema, and neither do migration 18's `service_token_change_evidence`
and `jwt_revocation_evidence` rows or the standalone token evidence rows: the
evidence rows hold the internal actor ID, not a keyed safe reference, and no
`authority_id`. The keyed reference derivation exists (see
[Keyed safe references](#keyed-safe-references)) but nothing calls it yet; runtime
producer and dispatcher integration belong to later slices.

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
tested, but no runtime producer calls it yet. Non-sensitive identities may also
use the same reference format for one closed projection.

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
and `resource.ref` values of the proposed event. It is a pure module with tests and
no runtime caller: nothing reads a pseudonym key at startup, no setting names one,
and no stored record carries a reference yet. The producer slice that adopts it
must also deliver the integration requirements listed at the end of this section.

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

### Integration requirements for the producer slice

- Name the current and previous aliases in validated startup configuration, with
  `.env.example` and the configuration reference, and refuse startup, not degrade,
  when either fails to resolve or parse.
- Require every replica of one authority to hold the same keys, for example by
  including the key IDs in the replica configuration fingerprint. Two replicas
  deriving under different keys would emit unrelated references for one identity.
- Refuse any Connection binding of a pseudonym-key alias, as the store already
  refuses binding a token-exchange client secret's alias under any other field. An
  operator or provider alias is not tied to a purpose, so a Connection bound to it
  would otherwise send the key upstream.
- Emit a structured audit event when the keyring loads or rotates, with key IDs and
  roles only.
- Build event references only through this module, and extend the
  synthetic-marker tests to stored records, logs and metrics.

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
