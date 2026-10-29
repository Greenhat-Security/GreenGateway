# Standalone configuration revision ledger

Status: alpha, not yet selectable (issue #242, PRs 10 and 11; [ADR-0008](adr/0008-setup-cli-and-configuration-bundles.md#ledger-mode-standalone)).

The revision ledger is how a standalone deployment will record every
configuration bundle it applies: an append-only, hash-chained history of
immutable revisions in one SQLite database beneath the state directory. It
lives in the shared `gateway-config` library (`gateway_config::ledger`) so the
gateway and `ggctl` use the same code.

What exists today is the ledger, the conditional plan, apply, history and
rollback service over it ([Plans and conditional apply](#plans-and-conditional-apply),
`gateway_config::revisions`), and their tests. Nothing creates or reads a
ledger yet: there is no ledger startup mode, no `GATEWAY_STATE_DIR`, no `ggctl
ledger` or `ggctl plan`/`apply` command and no admin route. Environment
configuration and startup are unchanged.

## Layout

The ledger is the file `config-ledger.sqlite3` in the state directory, with
SQLite's `-wal` and `-shm` files beside it while it is open. The database
identifies itself with `PRAGMA application_id` `0x47474C47` ("GGLG") and
`PRAGMA user_version` `1`, and uses the discipline of the existing standalone
stores: WAL journaling, `synchronous = FULL`, immediate write transactions,
foreign keys on, SQLite's defensive mode and an untrusted schema.

It holds four tables, all `STRICT`:

| Table | Holds |
| --- | --- |
| `config_revisions` | One row per revision: its sequence (1 for the seed, then contiguous), opaque revision ID, record hash and canonical record bytes. |
| `config_ledger_documents` | The exact bytes of every bundle file any revision records, once each, keyed by their SHA-256 pin. |
| `config_ledger_requests` | One row per revision applied online: the digest of its request's idempotency key, unique, and the revision's sequence. An index of what the records already hold. |
| `config_ledger_pointer` | One row: the desired revision (always the newest) with its record hash, and the active revision, if a gateway has activated one. |

Triggers refuse every update and delete of revisions, documents and request
rows, an insert out of sequence, deleting the pointer, and moving either
pointer backwards. A rollback is therefore always a new forward revision.

## Records

A revision's record is RFC 8785 canonical JSON. Every member is always present
(an absent optional value is `null`) and unknown members are refused, so one
record has exactly one stored spelling:

| Member | Content |
| --- | --- |
| `sequence` | The revision's position, from 1. |
| `parent` | `null` for the seed; otherwise the parent's `revision` ID and `record_hash`. |
| `recorded_at_ms` | Milliseconds since the Unix epoch, as the caller stamped it. The ledger reads no clock. |
| `operation`, `rollback_of` | `seed`, `apply`, or `rollback` with the target revision ID. |
| `actor` | `kind` (`principal`, `service_token`, `system`), `subject`, `issuer` (a principal's only) and `auth_mode`, in the vocabulary and bounds of the authority-evidence tables. Never a credential, session ID, role or email address. |
| `activation` | `live` or `restart`. |
| `changed_sections`, `risk_codes`, `required_permissions` | Sorted, unique codes, at most 64 each, each a lowercase letter followed by lowercase letters, digits, `_`, `.`, `:` or `-`, at most 128 bytes. Codes only, never values. A seed records none. |
| `request` | `null` for the seed and for offline operator commands. For a revision applied online, the request it was applied under: `plan` (its `plan-` ID), `idempotency_key` (the `GGDIGEST` source frame of the key, never the key), `binding` (the digest of the whole request, [below](#idempotency)), `acknowledged_risks` (the risk codes the actor acknowledged, always exactly `risk_codes`) and `stage_only`. |
| `bundle` | `api_version`, `name`, `profile`, `source_digest`, where `policy` and `tools` come from (`bundle`, `server` or `absent`), and `files`: the manifest, the deployment document, then the bundled policy and tools documents, each with its `role`, `name`, `sha256` pin and, for policy and tools, `schema_version`. |

A record is at most 64 KiB. Its **record hash** is the
[ADR-0004 `GGDIGEST` frame](configuration-bundles.md#digests) of its canonical
bytes, with media type `application/vnd.greengateway.config-revision+json` and
schema version `v1`, written `sha256:` and 64 lowercase hex digits. The
**revision ID** is `rev-` and the first 32 hex digits of that hash. Because
each record carries its parent's hash, changing, removing, inserting or
reordering any revision changes every later hash.

## Writing

- **Seed.** A ledger is created only with its first revision, from a bundle
  the bundle reader accepted. Seeding refuses a state directory that already
  holds the ledger or any of its `-wal`, `-shm` or `-journal` files (a leftover
  journal could be replayed into a new database of the same name). It builds
  the ledger in `config-ledger.sqlite3.seed` (owner-only on Unix), commits and
  flushes it, then hard-links it to the ledger's name, which never replaces an
  existing file, and flushes the directory where the platform allows. An
  interrupted seed therefore never leaves anything under the ledger's name,
  and the next seed discards the temporary file. The seed is desired and not
  active: the next start activates it.
- **Append.** One immediate transaction reads the pointer and the head,
  verifies the head's record, looks up the request's idempotency key
  (`ledger.idempotency_key_used` with the revision that recorded it, whatever
  the head is now, writing nothing), compares the head with the one the
  caller expected (`ledger.stale` with the actual head otherwise, writing
  nothing), stores any new documents,
  inserts the record and its request row and moves the pointer. The desired
  pointer always moves to the new revision. The active pointer moves with it
  only for a `live` revision whose request did not ask to stage only, and only
  when no restart is pending, that is when the head being replaced was active;
  a `restart` revision, a staged one, or any revision while a restart is
  pending, moves only the desired pointer. Two writers appending on the same
  head, in one process or two, get exactly one winner. A request whose
  acknowledged risk codes are not the revision's is refused
  (`acknowledgement_mismatch`).
- **Rollback** appends a new revision whose bundle must have the target's
  source digest; the target must be an earlier revision, not the head.
- **Activate** records that a gateway compiled the desired revision, and only
  that one.
- **Bounds.** At most 1,024 revisions (`ledger.full` beyond that; pruning is a
  later slice and will never remove the desired or active revision) and pages
  of at most 100 revisions, newest first.

## Verification

Opening a ledger verifies all of it before anything else is read or written,
and fails closed:

1. The state directory must be a directory, not a link or reparse point, and
   on Unix not writable by group or other; the ledger must be a regular file,
   not a link or reparse point, and on Unix not writable by group or other.
2. The header must name a version-1 ledger (a newer one is
   `ledger.unsupported`), and `PRAGMA quick_check` must pass.
3. The schema must be exactly the ledger's tables and triggers, with nothing
   added or dropped.
4. Every document must hash to its pin, and every document must be referenced
   by some revision.
5. Every record must be canonical, hash to its stored record hash and ID, and
   be a valid record. A record naming a document version this binary does not
   know is `ledger.unsupported`.
6. Sequences must be contiguous from 1, the first revision a seed and every
   other one linked to its predecessor by ID and record hash, every rollback's
   target an earlier revision with the same source digest, and every manifest's
   bytes must reproduce the recorded source digest.
7. The request index must hold exactly one row for each revision whose record
   carries a request, with that record's key digest, and no other row.
8. The pointer must name the newest revision and its hash, and the active
   revision, if any, must be in the chain.

Any discrepancy is `ledger.corrupt` with a class (`integrity`, `format`,
`schema`, `record`, `record_hash`, `chain`, `document`, `request`,
`pointer`). Reads after
opening verify what they read again: each record's hash, and each returned
document's pin and source digest. A handle that has reported corruption refuses
every later call. Errors carry stable codes only, never a path, document value,
actor or SQLite message; a stale head is reported by its opaque revision ID.

A hash chain is integrity evidence, not authentication. It detects an edit made
outside the ledger that does not rewrite every later revision and the pointer
consistently, and SQLite page damage. It cannot detect a whole ledger replaced
by a consistent one: whoever can write the state directory controls a
standalone deployment, as ADR-0008 states.

## Plans and conditional apply

`gateway_config::revisions::RevisionService` is how a revision is added
online ([ADR-0008, "Plan, risk acknowledgment, and conditional
apply"](adr/0008-setup-cli-and-configuration-bundles.md#plan-risk-acknowledgment-and-conditional-apply)).
It owns one ledger and the plans made against it, and a caller supplies how
bundles are compiled: the gateway passes its production policy and tools
validators (`config::revisions::ProductionCompiler`), and the
published-schemas compiler is what `ggctl` could run. A client's preview never
authorizes anything; every decision below is made from what the service
compiles itself, and nothing is written unless every check passes.

### Plans

A plan is made from a candidate, either a bundle (the files of one flat
bundle directory, by name, read by the same reader as a directory and held to
it strictly: a file the manifest does not reference is refused) or a rollback
target (a prior revision's stored files). The service compiles the candidate
and the head's stored content with the caller's validators, diffs them with
the [semantic diff](semantic-diff.md), and keeps a plan holding:

- its `plan-` ID (32 random hexadecimal digits the caller draws) and owner;
- the operation, `apply` or `rollback` with its target;
- the base revision and its strong ETag, the head's record hash quoted;
- the candidate's source digest and semantic digest. The semantic digest is
  the `GGDIGEST` semantic frame (media type
  `application/vnd.greengateway.config-candidate+json`, version `v1`) of the
  candidate's normalized form: document version, name, profile, the
  deployment document, where each resource comes from with the document its
  validator built, and the Connections source. Formatting, member order and
  spelled-out defaults do not change it;
- the redacted diff, its sorted risk codes and changed sections;
- the sorted union of permissions an apply needs: `admin:config:write`
  always; `admin:policy:write` for any change to the policy resource, its
  source or its content (its egress members included); `admin:tools:write`
  likewise for tools; and `admin:config:secrets:write` for a change shown as a
  reference, or carrying `risk.credential_binding_changed` or
  `risk.auth_trust_changed`;
- the activation class: `live` when every change is live, `restart` when any
  is, none when nothing changed;
- its expiry, 15 minutes after it was made.

A plan is refused when the candidate fails the reader or validators
(`plan.candidate_invalid`, with the reader's value-free diagnostics), when the
head no longer passes them (`plan.base_invalid`; recovery is the deployment
channel), when a change has a class no revision can carry, that is
`bootstrap`, `connection_or_secret`, `cluster_operation`,
`coordinated_cutover` or `unsupported` (`plan.change_not_applicable`), when a
rollback target is unknown or the head, and when the two compile to different
semantic digests that the diff did not classify (`plan.change_unclassified`).
An actor holds at most 8 live plans and a deployment 64
(`plan.quota_exceeded`). Plans are owner-scoped: another actor cannot read,
acknowledge or apply one, and an expired plan is gone. The same identity
authenticated another way is the same owner.

### Acknowledgements

A plan with any risk code applies only after its owner acknowledges exactly
that set of codes: no more, no fewer (`plan.acknowledgement_mismatch`). The
acknowledgement lasts 10 minutes and never beyond its plan. There is no
force flag and no blanket acknowledgement. `risk.admin_access_path_removed`
cannot be acknowledged online (`plan.risk_not_acknowledgeable`): the
deployment channel is the remedy.

### Apply

An apply names the plan, sends `If-Match` and an idempotency key (1 to 128
ASCII letters, digits, `.`, `_`, `:` or `-`), the candidate again (the bundle
or the rollback target), and whether to stage only. In order:

1. A missing `If-Match` or key is `apply.if_match_required` or
   `apply.idempotency_key_required` (`428`); a malformed key is
   `apply.idempotency_key_invalid`.
2. <a id="idempotency"></a>A key some revision already records answers before
   anything else: when the request's binding (the `GGDIGEST` semantic frame,
   media type `application/vnd.greengateway.config-apply-request+json`, of
   the plan ID, the `If-Match` value, the stage-only flag, the actor's kind,
   subject and issuer, and each submitted file's name and SHA-256 or the
   rollback target) is the recorded one, the answer is that revision, marked
   as a replay, and nothing is written; otherwise `apply.idempotency_conflict`.
   A retry after an ambiguous outcome therefore never applies twice, even
   after the plan is consumed and the head has moved.
3. The plan must be a live plan of the actor's (`plan.unknown`).
4. `If-Match` must be exactly the current head's ETag
   (`apply.precondition_failed`, `412`, with the current ETag). A weak ETag
   or `*` never matches.
5. The plan must have been made against that head, for that kind of subject
   and target, and the candidate is compiled again: its digests, risk codes,
   permissions and activation class must all still be the plan's
   (`plan.stale`).
6. A candidate that changes nothing is `apply.no_change`.
7. Risk codes need a live acknowledgement of exactly them
   (`apply.acknowledgement_required`).
8. Every permission of the union must be held (`apply.permission_denied`,
   naming the missing ones).
9. Unless the request asks to stage only, a `restart`-class change is
   `apply.restart_required`, and while a restart is pending any change is
   `apply.restart_pending`.
10. The ledger appends the revision with its request in one transaction that
    compares the head and the key again: a writer that lost the race gets
    `apply.precondition_failed`, and one that sent a key another writer just
    recorded gets that writer's answer or the conflict. The plan is then
    consumed.

The answer says whether the revision is now desired and active and whether a
restart is pending. A `live` revision applied unstaged with no restart pending
is active at commit; the caller must then publish its runtime snapshot or stop
serving, never keep serving the old one while the ledger says the new one is
active (ADR-0008, commit protocol step 6). A staged revision, of either class,
moves only the desired pointer and is activated by the next start.

What a request with a given key made can be read back
(`RevisionService::operation`): that is how a client resolves an ambiguous
outcome, instead of sending the request again.

### Rollback and history

A rollback is a plan whose candidate is a prior revision's stored content,
compiled with the current validators: content they now refuse is refused
(`plan.candidate_invalid`). It is acknowledged and applied like any plan and
appended as a new forward revision recording its target; history is never
rewritten. It restores configuration only, never database schema, secret
material, Connections or revoked credentials, none of which a ledger holds.
Rolling back to content equal to the head is `apply.no_change`.

History is the ledger's revisions, newest first, in pages of at most 100.

### Evidence

The revision record is the change's evidence, committed in the same
transaction as the pointer move: the actor, the operation and target, the
plan, the request's binding and key digests, the risk codes acknowledged and
the stage-only flag, with the changed sections, risk codes and permissions.
A refused or failed apply writes neither the revision nor any evidence, and a
committed one cannot lose its evidence. Delivering that evidence to the
gateway's audit pipeline as `config.revision_staged`, `config.activated` and
`config.rolled_back` events is part of the admin routes and ledger startup
slices.

## Not yet

Selecting ledger mode at startup (and refusing to start on an empty, unreadable
or unverifiable ledger), publishing a live revision's runtime snapshot, the
state-directory lock that keeps offline `ggctl ledger` commands and a running
gateway apart, `ggctl ledger seed`, `verify` and `rollback`, the admin routes
and `ggctl plan`, `apply`, `history` and `rollback` that will serve the
service above, online activation of a staged revision, delivery of the
revisions' evidence to the audit pipeline, protected status, and pruning are
later #242 slices. Until then the ledger and its service are a library with
tests, and nothing in a running gateway depends on them.
