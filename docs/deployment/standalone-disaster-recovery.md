# Runbook: standalone disaster recovery

Companion to [standalone backups](../standalone-backup.md). This runbook is for a
**standalone** deployment: one gateway process whose stores live beneath one
[state directory](../configuration-bundles.md#the-state-directory) on local disk.
For cluster mode, where the database is the deployment, use the PostgreSQL
runbooks instead: [backup, point-in-time recovery and restore
verification](backup-and-recovery.md) and [disaster recovery](disaster-recovery.md).
`ggctl` refuses to restore a PostgreSQL dump (`backup.postgres_unsupported`).
A Cloudflare Worker deployment keeps no durable local state, so there is
nothing to back up or restore there: redeploy from the bundle or environment
in version control.

**Status: alpha.** `ggctl backup create`, `verify` and `restore` work today on
a state directory. No gateway starts from a state directory yet: the bundle and
ledger startup modes (`GATEWAY_CONFIG_SOURCE`) are later #242 slices, and step 7
below applies once they land.

**The rule: a standalone deployment is its state directory, its bundle, its
Connections key files and its bootstrap secrets. A backup holds only the first.**
Rebuild all four or you have not rebuilt the deployment.

## What must exist to rebuild

| Component | Where it lives | Recreated from | If you do not have it |
| --- | --- | --- | --- |
| The stores: audit trail, principals, discovery, Connections, service tokens, policy history, configuration ledger | the state directory | a `ggctl backup create` archive | Everything below is moot: this is the deployment's history and its authority. |
| Connections key files | `CONNECTION_SECRETS_ROOT`, outside the state directory | their own backup, under their own protection | Restored Connections exist but their local secrets cannot be decrypted. A backup never holds them. |
| The bundle | version control | the repository | A ledger-mode gateway still starts from its ledger; a bundle-mode gateway has nothing to start from. |
| Bootstrap environment and the secrets its references name | the deployment's environment and secret manager | that manager's backup | The gateway refuses to start, as it does for any missing secret. |
| The `ggctl` and gateway releases | your artifact store | the release | A backup is read only by a `ggctl` that reads its manifest version; keep the release that wrote it. |

Pending OIDC logins, admin sessions and caches are never in a backup: admin
sessions end at every restart anyway, and caches rebuild.

## Before you need it

1. **Lay out the state directory one level below its volume.** A restore
   renames the state directory within the directory holding it, so the state
   directory cannot be a mount point (`restore.target_mount_point`), and its
   parent must be writable by the account that runs the gateway. Mount the
   volume at, say, `/var/lib/greengateway`, owned by that account, and set the
   state directory to `/var/lib/greengateway/state`.
2. **Take backups with the gateway stopped.** `ggctl` takes the state
   directory's lock and never waits, so `backup create` exits `5` while the
   gateway runs:

   ```sh
   systemctl stop greengateway
   ggctl backup create --state-dir /var/lib/greengateway/state \
     --output /backups/greengateway-$(date -u +%Y%m%dT%H%M%SZ).ggbk
   systemctl start greengateway
   ```

   Expected output: `created a backup of N stores`, the stores with their rows,
   and exit `0`. Write the archive to a local filesystem and copy it off the host
   from there; it is owner-only and is sensitive recovery material, not
   configuration.
3. **Verify every copy where it is kept**, not only where it was written:
   `ggctl backup verify FILE` exits `0`, and `7` for an archive that was damaged,
   cut short or edited.
4. **Back up the Connections key files** under `CONNECTION_SECRETS_ROOT` on
   their own schedule and protection. `backup create` reminds you whenever the
   Connections store is included (`backup.secret_keys_not_included`).
5. **Rehearse** the procedure below on a spare host at least once per release.

## The order

### 1. Stop everything that could write

Stop the gateway, and anything else that might run `ggctl` against the state
directory. A restore takes the state directory's lock and exits `5`
(`state_dir.locked`) while anything holds it; it never waits.

### 2. Choose the backup and verify it

Pick the newest backup from before the incident, then check it on the host that
will restore it:

```sh
ggctl backup verify /backups/greengateway-20261105T020000Z.ggbk
```

Expected output: `verified a backup of N stores, created at Unix time ...`
and exit `0`. Exit `7` means this copy is damaged: take an older one or another
copy. Write down its creation time and, for the ledger, its desired and active
revisions; they are the recovery point.

### 3. Prepare the target

Either restore into a **new, empty directory** in the state directory's place
(the safer choice: the damaged state is kept aside until you remove it):

```sh
mv /var/lib/greengateway/state /var/lib/greengateway/state-damaged
install -d -m 0700 -o greengateway -g greengateway /var/lib/greengateway/state
```

or replace the **stopped state directory itself**. That needs the explicit
`--replace-existing-state`, and the directory must hold nothing but the layout's
entries (stores, their `-wal`, `-shm` and `-journal` files, `state.lock`,
`restore-marker.json`). If you might need the damaged state later, copy it aside
first; `ggctl backup create` refuses a corrupt store, so a damaged directory may
not back up.

### 4. Restore

Run the restore as the account the gateway runs as: the restored files belong
to the account that ran `ggctl`.

```sh
ggctl backup restore /backups/greengateway-20261105T020000Z.ggbk \
  --state-dir /var/lib/greengateway/state
# or, replacing a stopped state directory's stores:
ggctl backup restore /backups/greengateway-20261105T020000Z.ggbk \
  --state-dir /var/lib/greengateway/state --replace-existing-state
```

Expected output: `restored a backup of N stores, created at Unix time ...`, the
restore ID (`restore rst-...`), the stores with their rows, and exit `0`. Add
`--format json` to keep the report: `result.restoreId` is the ID the gateway's
`config.restore_detected` event will carry.

Any non-zero exit except `restore.rollback_failed` means **nothing changed**:
the state directory is exactly as it was and no hidden directory is left beside
it. See [when a step fails](#when-a-step-fails).

### 5. Put the Connections key files back

If the report includes `restore.secret_keys_required`, restore the key files
under `CONNECTION_SECRETS_ROOT` from their own backup now, with their original
owner and mode. The restored Connections store holds its secrets as ciphertext
only.

### 6. Check the restored state

```sh
ggctl ledger verify --state-dir /var/lib/greengateway/state
```

Expected output, when the backup held a ledger: the desired and active
revisions you wrote down in step 2, and exit `0`. `restore-marker.json` is
present beside the stores; leave it there.

### 7. Start the gateway and confirm the restore was recorded

Once a gateway starts from a state directory (bundle or ledger mode), its first
start records the restore as the audit event `config.restore_detected`, with the
restore ID, the backup's creation time and the restored stores, and then removes
`restore-marker.json`. Query the audit log for the event and check its
`restore_id` against step 4. A start that cannot record the event durably, or
cannot remove the marker, refuses to start and keeps the marker for the next
attempt; one that finds a marker that is unsafe or invalid
(`restore.marker_unsafe`, `restore.marker_invalid`) refuses to start because
something other than a restore wrote it. Find out what before you remove it.

### 8. Write down what the recovery point was

Record the backup's creation time, the ledger revisions, the restore ID and the
time the gateway served again. Everything the stores recorded after the backup
was taken, audit events included, is gone; that gap is the recovery point.

## When a step fails

| Code | Exit | What it means | What to do |
| --- | --- | --- | --- |
| `state_dir.locked` | 5 | A gateway or another `ggctl` holds the lock. | Stop it (step 1). |
| `state_dir.missing` | 3 | The state directory does not exist. | Create it empty, owner-only (step 3). |
| `restore.target_not_empty` | 5 | The state directory holds stores. | Restore into a new directory, or give `--replace-existing-state` deliberately. |
| `restore.target_not_state_dir` | 3 | It holds something the layout does not name. | Wrong directory, or move the extra entries away first. |
| `restore.target_mount_point` | 3 | It is a mount point. | Restore one level below the mount (see [before you need it](#before-you-need-it)). |
| `restore.staging_unavailable` | 1 | Nothing could be written beside the state directory. | Check the parent's owner, mode and free space. |
| `restore.switch_failed` | 1 | The rename did not happen; on Windows, usually a process holding a file open beneath the state directory. | Stop it and run the restore again. |
| `restore.target_changed` | 5 | Something changed the state directory during the restore. | Stop it and run the restore again. |
| `restore.rollback_failed` | 1 | The state directory was moved aside and could not be put back. | Its content is beside it as `.NAME.ggrestore-previous-HEX`: rename that back to the state directory's name, then retry. |
| `restore.store_identity_mismatch` and the `backup` and `archive` codes that exit `7` | 7 | The archive does not verify. | Use another copy or an older backup (step 2). |
| `backup.unsupported_manifest_version`, `backup.unsupported_archive_version`, `backup.ledger_verification_failed` | 7 | The archive is a version this `ggctl` does not read, or is damaged. | Restore with the `ggctl` release that wrote it. |
| `backup.postgres_unsupported` | 3 | The file is a PostgreSQL dump. | Cluster state: use the [PostgreSQL runbooks](backup-and-recovery.md). |
| `restore.previous_not_removed` | 0 | The restore is in place; the replaced stores were not all removed. | Delete `.NAME.ggrestore-previous-HEX` beside the state directory. |

The complete list is in [`ggctl` restore diagnostics](../ggctl.md#restore-diagnostics).

## Rehearsing

On a spare host: restore the newest backup into an empty directory, put the key
files back, run `ggctl ledger verify`, and record how long each step took. A
rehearsal that never restored the Connections key files has not tested whether
the Connections work.
