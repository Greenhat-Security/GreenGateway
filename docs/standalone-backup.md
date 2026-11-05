# Standalone backups

**Status: alpha.** `ggctl backup create` and `ggctl backup verify` (issue #242,
[ADR-0008](adr/0008-setup-cli-and-configuration-bundles.md)) back up and check
the stores beneath a standalone [state directory](configuration-bundles.md#the-state-directory).
`ggctl backup restore` is the next #242 slice: until it lands, nothing restores
an archive, and no gateway reads `GATEWAY_STATE_DIR` yet, so these commands
apply to a state directory a later release will start from. PostgreSQL and
cluster state is never backed up this way: that is #241's
[PostgreSQL backup and point-in-time recovery](deployment/postgres.md). A
Cloudflare Worker deployment has no durable local state to back up.

A backup is **sensitive recovery material, not configuration**. It holds the
audit trail, the principal directory, discovery data, the service token
store, the Connections store, policy history and the configuration revision
ledger, whichever of them the state directory holds. Keep it where only its
owner can read and change it, and do not commit it to version control: a
[configuration bundle](configuration-bundles.md) is what belongs there.

## What a backup holds, and what it never holds

A backup holds exactly the stores of the state-directory layout that exist
(`audit.sqlite3`, `discovery.sqlite3`, `principals.sqlite3`,
`connections.sqlite3`, `service-tokens.sqlite3`, `policy-history.sqlite3` and
`config-ledger.sqlite3`), each as a consistent SQLite snapshot. Nothing else in
the directory is read: not `state.lock`, not a store's `-wal`, `-shm` or
`-journal` file (whatever a write-ahead log holds is in the snapshot), and not
any other file or directory.

It never holds:

- **Pending OIDC logins, admin sessions or caches.** A standalone gateway keeps
  pending logins and admin sessions in process memory
  (`ADMIN_SESSION_MODE=standalone_memory`), and caches are rebuilt on start;
  none is in a store.
- **Plaintext tokens.** The service token store keeps each token's hash and
  prefix, never the token.
- **Secret values or master keys.** The Connections store keeps local secrets
  only as #240 ciphertext. The key files that decrypt them stay under
  `CONNECTION_SECRETS_ROOT`, outside the state directory, and a backup never
  reads them. **They are a separate recovery artifact**: back them up
  separately, under their own protection, or the restored Connections store's
  secrets cannot be decrypted. `ggctl backup create` says so whenever the
  Connections store is included (`backup.secret_keys_not_included`).
- **Bootstrap configuration.** Environment files, alias files and the bundle a
  deployment started from are not in the state directory. Back up the bundle
  where it is reviewed, and its secret references' targets with the secret
  manager that holds them.

## Creating a backup

```sh
# The gateway must be stopped: ggctl takes the state directory's lock and never waits.
ggctl backup create --state-dir /var/lib/greengateway --output /backups/greengateway-2026-11-05.ggbk
```

1. **Quiescence.** `ggctl` takes the state directory's exclusive lock, so the
   backup runs only while no gateway or other `ggctl` holds it
   (`state_dir.locked`, exit `5`, otherwise). The lock keeps the gateway and
   `ggctl` apart; it is advisory, and whoever can write the state directory
   controls the deployment.
2. **Admission.** Each store that exists must be a regular file, not a
   symbolic link, junction or other reparse point, and on Unix not writable by
   group or other. Each is identified by its device and file number, so two
   names for one file are snapshotted once and the second store refers to the
   first one's entry. The configuration revision ledger must be its own file.
   A state directory with none of the stores is refused
   (`backup.nothing_to_back_up`).
3. **Snapshots.** Each file is snapshotted with SQLite's `VACUUM INTO` from a
   read-only connection, as `gateway import-standalone` takes its copies:
   SQLite writes one consistent database from a single read transaction, with
   whatever the write-ahead log holds folded in. The store's files are never
   copied, and its main file and write-ahead log are never written; like any
   reader, SQLite may create or update the `-shm` index beside a write-ahead
   store, which holds no data. Snapshots go into a new private
   working directory beside `--output` (`.NAME.ggbk-work-PID-N`, `0700` on
   Unix), are put in rollback-journal mode, and must pass SQLite's
   `PRAGMA integrity_check`. The ledger snapshot must also pass the ledger's
   [full verification](configuration-ledger.md#verification).
4. **Manifest.** The `GatewayBackup` manifest records the versions, inventory,
   counts and checksums described [below](#the-manifest).
5. **Write, verify, publish.** The archive is written to a new hidden file
   beside `--output` (`.NAME.ggbk-partial-PID-N`, created exclusively, `0600`
   on Unix), flushed to storage, and read back with every check of
   `ggctl backup verify`. Only then is it linked to `--output`, which must not
   exist and is never replaced (`backup.output_exists`, exit `5`), and the
   hidden name removed. Any failure leaves nothing at `--output`; a process
   killed midway can leave only the hidden entries beside it, which are safe to
   delete. Linking needs a filesystem with hard links: write the backup to a
   local filesystem and copy it from there.

A backup is never written to standard output (`--output -` is
`backup.stdout_refused`, exit `2`), so it cannot end up in a terminal, a log or
a pipe by accident. While it runs, the backup needs free space for the
snapshots and the archive, and then for the archive and its verification copy.

## Verifying a backup

```sh
ggctl backup verify /backups/greengateway-2026-11-05.ggbk
```

`ggctl backup verify FILE` reads the archive completely into a new hidden
staging directory beside it (`.NAME.ggbk-verify-PID-N`, `0700` on Unix), which
it removes whatever the outcome. It writes nothing else and never changes the
archive. Every failure is exit `7`, except an archive that is a link or not a
regular file (exit `3`), and an archive that cannot be read or a staging
directory that cannot be written (exit `1`):

- **Admission.** Every entry passes the shared [archive admission
  rules](archive-admission.md) before any of its data is read: portable,
  single-segment names; no absolute path, `..`, alternate data stream or
  device name; no link, hard link, device, FIFO, socket or directory; no
  duplicate or case-colliding names; at most eight entries (the manifest and
  one per store); each entry at most 64 GiB and all of them at most 256 GiB;
  and every declared size must fit in what is left of the archive file.
  Nothing is compressed, so an archive never extracts to more than its own
  length, and a longer archive than any backup can be is refused before it is
  read (`backup.archive_too_large`).
- **Container.** The archive must start as a backup archive
  (`backup.not_a_backup`) of a container version this `ggctl` reads, end with
  its end record, record count and the SHA-256 of everything before it
  (`backup.archive_digest_mismatch`), and have nothing after that. An archive
  cut short anywhere is `archive.truncated`.
- **Manifest.** The first entry must be the manifest
  (`backup.manifest_missing`), at most 1 MiB, of exactly the document version
  `greengateway.dev/v1alpha1` (`backup.unsupported_manifest_version`), and a
  closed document whose inventory, entries and counts agree
  (`backup.manifest_invalid`).
- **Entries.** Exactly the entries the manifest lists follow, in its order
  (`backup.unexpected_entry`, `backup.entry_missing`), each with the length and
  SHA-256 it records (`backup.checksum_mismatch`).
- **Databases.** Each extracted database must be a SQLite database in
  rollback-journal mode that passes `PRAGMA integrity_check`
  (`backup.store_integrity_failed`) and has the header versions, pages, schema
  digest and table rows the manifest records (`backup.store_mismatch`). The
  ledger must pass the ledger's full verification
  (`backup.ledger_verification_failed`) and hold the revisions the manifest
  names (`backup.ledger_mismatch`).

A digest is integrity evidence, not authenticity: verification detects an
archive that was damaged, cut short or edited, but whoever can write an archive
can write a consistent one. Only where a backup is kept protects it from that.

## The manifest

The manifest is the archive's first entry, `gateway-backup.json`
([schema](schemas/gateway-backup.v1alpha1.schema.json); `ggctl schema
GatewayBackup` prints it). It records:

- `apiVersion` `greengateway.dev/v1alpha1`, `kind` `GatewayBackup`, the
  container (`archive.format` `ggbk`, `archive.version` `1`) and the `source`,
  `standalone_state_directory`;
- the **binary versions**: `createdBy` (the program and its version, `ggctl`
  and its release) and `sqliteVersion`, the SQLite library that took the
  snapshots;
- the **logical inventory**: every store of the layout once, in the layout's
  order, with whether it is `included` and which `entry` holds it;
- one **entry** per physical database: its name, exact length and SHA-256,
  and the **store version** as SQLite describes it: `applicationId` and
  `userVersion` from its header (`GGLG` and the format version for the ledger,
  `0` for the gateway's stores), page size and pages, `schemaSha256` (the
  SHA-256 of every `sqlite_schema` row with SQL, as `[type, name, tbl_name,
  sql]` sorted, which is the store's schema as the gateway's migrations leave
  it), and each table's row count;
- the **document versions** of the ledger when it is included: its revision
  count, desired and active revisions and the desired bundle's `apiVersion`;
- the **counts** the inventory and entries imply: stores, included stores,
  entries, bytes, tables and rows.

The manifest holds no path, no store content and no secret.

## The archive container

The archive is GreenGateway's own framed format rather than tar or zip, so the
build takes no archive library
([dependency policy](deployment/cargo-dependency-policy.md)): what tar can
express beyond a regular file (long-name and PAX extensions, links, sparse
files, devices) is what the admission rules refuse anyway, and a fixed record
grammar is simpler to bound. Integers are big-endian:

```text
archive  = preamble record* end
preamble = "GGBACKUP" version:u16 flags:u16        version 1, flags 0
record   = kind:u8 name_length:u16 name size:u64 data
end      = 0x00 records:u32 digest:32 bytes
```

`kind` is `1` for a regular file; `2` (directory), `3` (symbolic link), `4`
(hard link), `5` and `6` (character and block devices), `7` (FIFO), `8`
(socket) and any other non-zero byte are read only to be refused. `data` is
exactly `size` bytes, `records` counts the records, and `digest` is the SHA-256
of every byte before it. A writer writes the manifest first, then one regular
file per database, named after the first store it holds.
