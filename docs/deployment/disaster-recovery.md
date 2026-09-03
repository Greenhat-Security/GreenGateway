# Runbook: disaster recovery

Companion to [the PostgreSQL deployment guide](postgres.md). Cluster mode is a supported multi-replica configuration within the boundary [Supported cluster operation](postgres.md#supported-cluster-operation) draws, which names the release-gate suite behind each guarantee and states the non-goals just as explicitly.

**The rule: the deployment is the database plus the secret store plus the static configuration. Rebuild all three or you have not rebuilt the deployment.** Gateway replicas are disposable and hold nothing durable; they are the easy part and they are not the part that fails.

This runbook is for the case where the primary is gone and is not coming back — a destroyed instance, a lost region, a database whose data is unrecoverable. For a primary that is merely down or has failed over to a standby, use [the failover runbook](failover.md). For rewinding a database that is intact but wrong, use [the backup and recovery runbook](backup-and-recovery.md).

## What must exist to rebuild

| Component | Where it lives | Recreated from | If you do not have it |
| --- | --- | --- | --- |
| The deployment's shared state | PostgreSQL | base backup + WAL, or a logical dump | Everything below is moot. This is the deployment. |
| Credential secrets | your external secret provider | that provider's own backup | Connections exist but resolve to nothing; every upstream needing credentials fails |
| The static configuration | version control | the repository | Replicas boot with a different fingerprint and refuse to become ready together |
| The login keyring | your secret manager | that manager's backup | Admin OIDC logins cannot complete; in-flight pending-login rows are undecryptable |
| The rate-limit HMAC key | your secret manager | that manager's backup | Every rate-limit bucket is retired at once; each caller gets one fresh burst |
| TLS material | your CA | reissue | Replicas cannot connect to the database at all |
| `DEPLOYMENT_ID` | the static configuration | the repository | See the warning below |

**`DEPLOYMENT_ID` is not cosmetic and must not be changed during a recovery.** It is the domain separator for every digest, sealed envelope and lock namespace in the schema, and it is recorded in `greengateway.deployment_binding`. Restore under a different ID and the gateway refuses the database (`target_deployment_mismatch`, or a startup refusal); change the ID to match a restored database and every sealed value and keyed digest computed under the old ID becomes unreadable. Recover under the ID the backup was taken with.

## The order

Rebuilding in the wrong order is the most common way to turn a four-hour recovery into a twelve-hour one. Nothing below is optional and nothing can be usefully parallelized past step 4.

### 1. Stop everything that could write

If any gateway replica survived the disaster, stop it. A replica writing to a half-recovered database produces state that does not belong to any coherent point in time.

```sh
docker compose -f docs/deployment/docker-compose.ha.yml stop gateway-1 gateway-2 lb
```

### 2. Stand up a PostgreSQL primary

One writable primary. Same major version as the backup, or newer only if you have verified the dump restores into it. Provision the two roles ([roles and grants](roles-and-grants.md)) and TLS ([TLS](tls.md)) before restoring — a restored database you cannot connect to securely is not progress.

### 3. Restore the data

Physical restore plus WAL replay, or `pg_restore` of the logical dump. See [backup and recovery](backup-and-recovery.md).

For the logical path:

```sh
createdb greengateway
pg_restore --dbname=greengateway --no-owner --role=greengateway_migrator \
  --exit-on-error /backups/greengateway-<stamp>.dump
```

Expected output: no output, exit `0`. `--exit-on-error` is deliberate — a restore that reports errors and continues leaves you deciding, at 3am, which of them mattered.

### 4. Verify the restore before anything connects

Run all five checks from [backup and recovery](backup-and-recovery.md) with the migration role: schema current (`gateway migrate check` exits `0`), the deployment binding names your `DEPLOYMENT_ID`, `greengateway.policy_active` has a row, the audit stream is contiguous and `discovery_projector_state.checkpoint_position` is not ahead of the stream head, and the counts match your last snapshot.

**The projector checkpoint is the one to look at hardest after a disaster restore.** If it is ahead of the stream head, the projector would skip every event between the head and the checkpoint, forever, and discovery would silently stop seeing new traffic. Set it back to the head before starting a replica:

```sql
SELECT checkpoint_position FROM greengateway.discovery_projector_state;
SELECT max(position) FROM greengateway.audit_stream;
```

If the first exceeds the second, correct it deliberately, with the replicas still stopped, and record that you did.

### 5. Restore the secret store, and prove one credential resolves

Do this **before** starting a replica, not after. A gateway that starts with an empty secret store will mark every credential-bearing Connection failed, generate status history saying so, and give you a page full of alarming red that has nothing to do with the database recovery you just completed.

### 6. Reconstruct the static configuration from version control

Every replica of the deployment must boot with byte-identical security-relevant static configuration or they will not agree to become ready together. Pull it from the repository, not from a surviving replica's environment (which may itself be the thing that was wrong) and not from memory.

### 7. Start exactly one replica

```sh
docker compose -f docs/deployment/docker-compose.ha.yml up -d gateway-1
curl -sS http://gateway-1:8080/readyz
```

Expected output: `{"status":"ready"}`, HTTP `200`.

A `503` names its reason, and each reason points somewhere different:

| Reason | Look at |
| --- | --- |
| `starting`, persisting | the replica's startup logs — cluster mode fails closed on schema, binding, and policy problems, and says which |
| `config_fingerprint_mismatch` | step 6; another replica is running with a different configuration |
| `required_upstream_unavailable` | your upstreams, not the recovery |

A replica that exits with `STATE_BACKEND=postgres requires an initialized deployment` found no active policy document — step 4's third check would have caught it. You restored to a point before the deployment was initialized, or restored the wrong database.

```sh
gateway cluster-members
```

Expected output: `members=1 live=1` and one `ready` line.

### 8. Verify the deployment, not the database

- [ ] The policy view shows the policy you expect, at the version you expect.
- [ ] Connections resolve their credentials and report healthy status.
- [ ] Audit history is present up to the recovery point.
- [ ] One real protected request is decided correctly — allowed where it should be allowed, denied where it should be denied.
- [ ] One request that should be denied **is** denied. Verifying only the allow path after a policy restore is how a deployment comes back with the wrong policy and nobody notices.

### 9. Scale out and restore traffic

```sh
docker compose -f docs/deployment/docker-compose.ha.yml up -d gateway-2 lb
gateway cluster-members
```

Expected output: `members=2 live=2`, both `ready`, **identical** `fingerprint=` values. Then return the deployment to the load balancer.

### 10. Write down what the recovery point actually was

```sql
SELECT max(occurred_at) FROM greengateway.audit_events;
SELECT active_version, security_revision, activated_at FROM greengateway.policy_active;
```

Everything after that timestamp is lost, and somebody will ask. Answer with the query, not an estimate.

## Losing the database with no usable backup

Be honest about what this is: the deployment's state is gone. Policy history, audit record, Connection definitions, discovery findings and token hashes are not reconstructible from the replicas, because the replicas held none of them.

What can be rebuilt, and what cannot:

- **The policy** can be rebuilt from your last exported policy document, if you keep one in version control. Keeping the active policy document exported to version control on every change is cheap insurance and it is the single highest-value thing on this page.
- **Connections** can be recreated from their definitions if you hold them elsewhere; their credentials are already in the secret store and survive.
- **Service tokens** cannot be recovered — the plaintext never existed anywhere after issue. Every one must be re-issued.
- **Audit history** cannot be recovered. It is the compliance record and it is gone.
- **Discovery history** cannot be recovered, but it rebuilds itself from new traffic.

If a standalone deployment preceded this cluster and its pre-cutover backup still exists, that backup is a valid starting point: restore it, and re-run the cutover from [the cutover runbook](cutover.md) into a fresh empty namespace. You lose everything between the cutover and the disaster, and you have a working deployment. This is another reason not to delete the standalone backup once the cutover succeeds.

## Rehearsing

A disaster recovery you have not rehearsed is a plan, not a capability. The drill in [backup and recovery](backup-and-recovery.md) covers the database half; extend it once a year to the whole thing:

1. Restore into a scratch environment with a **different** `DEPLOYMENT_ID` from production, so a mis-pointed replica is refused by the binding rather than joining production.
2. Restore the secret store into that environment too.
3. Build the static configuration from version control alone. If you find yourself copying an environment variable from a running production replica, you have found the gap this drill exists to find.
4. Start one replica, run step 8's checks.
5. Record the wall-clock time from step 1 to a passing step 8. That is your recovery time objective. Compare it to the one you have promised.
6. Destroy the scratch environment.

## When a step fails

**`pg_restore` reports errors on ownership or roles.** Expected if the roles differ between the source and the target. `--no-owner` handles it; the grants are re-applied afterwards from [roles and grants](roles-and-grants.md).

**`gateway migrate check` reports a checksum mismatch.** The ledger does not match the binary's manifest. Either the restored database is from a different lineage, or the binary is not the one that ran against it. This refusal is tamper detection; do not run `migrate up` to clear it. Identify which of the two is wrong.

**Replicas will not agree on a fingerprint after recovery.** Step 6 was done from more than one source. Take the configuration from version control for all of them and restart. See [failover](failover.md).

**Everything is up and every Connection is failing.** The secret store. Step 5.

**`target_deployment_mismatch` from every command.** The restored database is bound to a different `DEPLOYMENT_ID` than the one you are running under. Do not edit `greengateway.deployment_binding` to make it match: the ID is the domain separator for every sealed envelope and keyed digest in the schema, and changing it makes that material unreadable rather than portable. Run under the ID the backup was taken with.
