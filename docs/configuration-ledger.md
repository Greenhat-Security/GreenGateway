# Standalone configuration revision ledger

Status: alpha, not yet selectable (issue #242, PR 10; [ADR-0008](adr/0008-setup-cli-and-configuration-bundles.md#ledger-mode-standalone)).

The revision ledger is how a standalone deployment will record every
configuration bundle it applies: an append-only, hash-chained history of
immutable revisions in one SQLite database beneath the state directory. It
lives in the shared `gateway-config` library (`gateway_config::ledger`) so the
gateway and `ggctl` use the same code.

What exists today is the ledger itself and its tests. Nothing creates or reads
a ledger yet: there is no ledger startup mode, no `GATEWAY_STATE_DIR`, no
`ggctl ledger` command and no admin route. Environment configuration and
startup are unchanged.

## Layout

The ledger is the file `config-ledger.sqlite3` in the state directory, with
SQLite's `-wal` and `-shm` files beside it while it is open. The database
identifies itself with `PRAGMA application_id` `0x47474C47` ("GGLG") and
`PRAGMA user_version` `1`, and uses the discipline of the existing standalone
stores: WAL journaling, `synchronous = FULL`, immediate write transactions,
foreign keys on, SQLite's defensive mode and an untrusted schema.

It holds three tables, all `STRICT`:

| Table | Holds |
| --- | --- |
| `config_revisions` | One row per revision: its sequence (1 for the seed, then contiguous), opaque revision ID, record hash and canonical record bytes. |
| `config_ledger_documents` | The exact bytes of every bundle file any revision records, once each, keyed by their SHA-256 pin. |
| `config_ledger_pointer` | One row: the desired revision (always the newest) with its record hash, and the active revision, if a gateway has activated one. |

Triggers refuse every update and delete of revisions and documents, an insert
out of sequence, deleting the pointer, and moving either pointer backwards. A
rollback is therefore always a new forward revision.

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
  verifies the head's record, compares it with the head the caller expected
  (`ledger.stale` with the actual head otherwise, writing nothing), stores any
  new documents, inserts the record and moves the pointer. The desired pointer
  always moves to the new revision. The active pointer moves with it only for
  a `live` revision and only when no restart is pending, that is when the head
  being replaced was active; a `restart` revision, or any revision while a
  restart is pending, moves only the desired pointer. Two writers appending on
  the same head, in one process or two, get exactly one winner.
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
7. The pointer must name the newest revision and its hash, and the active
   revision, if any, must be in the chain.

Any discrepancy is `ledger.corrupt` with a class (`integrity`, `format`,
`schema`, `record`, `record_hash`, `chain`, `document`, `pointer`). Reads after
opening verify what they read again: each record's hash, and each returned
document's pin and source digest. A handle that has reported corruption refuses
every later call. Errors carry stable codes only, never a path, document value,
actor or SQLite message; a stale head is reported by its opaque revision ID.

A hash chain is integrity evidence, not authentication. It detects an edit made
outside the ledger that does not rewrite every later revision and the pointer
consistently, and SQLite page damage. It cannot detect a whole ledger replaced
by a consistent one: whoever can write the state directory controls a
standalone deployment, as ADR-0008 states.

## Not yet

Selecting ledger mode at startup (and refusing to start on an empty, unreadable
or unverifiable ledger), the state-directory lock that keeps offline `ggctl
ledger` commands and a running gateway apart, `ggctl ledger seed`, `verify` and
`rollback`, plans and conditional online apply, evidence and outbox rows in the
revision's transaction, protected status, and pruning are later #242 slices.
Until then the ledger is a library with tests, and nothing in a running gateway
depends on it.
