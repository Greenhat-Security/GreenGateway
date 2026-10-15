# Runbook: security incident rehearsal

Companion to [operational alerts](operational-alerts.md), which identifies the signal and the responder, and to the runbooks this one reuses rather than restates: [failover](failover.md) for draining and replacing a replica, [the rollback boundary](rollback-boundary.md) for what a recovery may never undo, and [disaster recovery](disaster-recovery.md) for rebuilding an authority that is gone. This page adds only the cross-cutting steps none of them owns — withdrawing identities, rotating a Connection's secret reference, and proving that both held on every replica, in the audit evidence, and across a replica replacement — and the disposable rehearsal of those steps that the release gate runs. It is part of [issue #440](https://github.com/Greenhat-Security/GreenGateway/issues/440).

**The rule: a withdrawal binds every new admission on every replica at once, and recalls nothing that was already admitted.** Everything below follows from the two halves of that sentence. The first is what cluster mode guarantees and what the rehearsal proves. The second is a limit no procedure on this page removes.

## What a withdrawal does not do

Read this before you tell anyone the incident is contained.

- **It does not recall bytes already admitted.** Authorization is decided per invocation, against the security revision current when the request was admitted (see [ADR-0006](../adr/0006-first-class-connections-and-credentials.md) and [the revocation boundary](../architecture.md#authorization-queueing-and-revocation)). A request, stream, tool invocation or upstream call that was admitted before a revocation committed runs to completion under the snapshot it was admitted with. Bytes it has already sent upstream, or returned to the caller, cannot be recalled by the gateway or by anything else. A withdrawn JWT or service token is refused by the next request on every replica; it is not chased into requests that are already running.
- **It does not revoke anything at the upstream.** A Connection's credential is the upstream's credential. Rebinding the Connection stops the gateway from *sending* the old material; it does not stop the upstream from *accepting* it from whoever else holds a copy. Revoke the old credential at its issuer.
- **A hard stop is a drain plus an upstream or network revocation, not a setting.** When admitted work must stop now — a long-lived stream, a slow upstream call, a transfer in progress — take the affected replicas out with a controlled drain ([deliberate replica maintenance](failover.md#deliberate-replica-maintenance)). The drain is bounded by `SHUTDOWN_DRAIN_DELAY_MS + SHUTDOWN_TIMEOUT_MS + AUDIT_DRAIN_TIMEOUT_MS` plus supervisor overhead ([graceful termination budget](production-data-plane.md#graceful-termination-budget)); a second signal forces the request drain but still attempts the bounded audit flush. Where the drain is not fast enough, or an upstream must stop honouring a credential the gateway no longer controls, revoke the credential at its issuer and withdraw the network path to the upstream. A hard kill (`SIGKILL`, `TerminateProcess`) leaves no draining stamp and no terminal audit record; use it only when the bounded drain itself must be cut short, and record that you did.
- **`revoke-jwt` needs a `jti`.** The shared denylist names a JWT by its issuer and `jti`. A token without a `jti` cannot be named: set `require_jti: true` on every provider whose tokens you may need to withdraw one at a time (the rehearsal runs with it). A token that cannot be named can only be withdrawn by removing its signing key at the IdP, which every replica stops accepting within `jwks_max_key_age_secs` plus one refresh interval — the release gate proves that window in `withdrawing_a_signing_key_stops_acceptance_on_every_replica`.
- **A stale security database is not a rollback.** Restoring a backup taken before the incident brings every withdrawal you made back to life. See [the rollback boundary](rollback-boundary.md): a revocation is on the wrong side of it, and that is the point of having made it.

## The procedure

Steps 2 to 5 and 7 are what the release gate rehearses; steps 1, 6 and 8 are the parts only a real deployment can do.

### 1. Triage and record the starting revision

Use [readiness diagnosis](operational-alerts.md#readiness-diagnosis) on the affected replicas directly, not through the load balancer. Record replica IDs and times in restricted incident evidence, and read the authority's revision before you change anything:

```sql
SELECT last_revision FROM greengateway.security_revision_state WHERE singleton;
```

Every decision you make from here advances that counter exactly once, which is what step 5 checks.

### 2. Withdraw the identities

- **A JWT**, by the operator's break-glass command, run with a replica's environment against the deployment's writable primary ([JWT revocations](postgres.md#jwt-revocations)). Pass the token's own `exp` as the third argument so the denylist row does not outlive the token:

  ```sh
  gateway revoke-jwt https://issuer.example/ <jti> 2026-12-31T00:00:00Z
  ```

  Expected output: `revoked: issuer=... security_revision=N`. The command digests the `jti` before it reaches the database and never echoes it; keep `N`.

- **A service token**, through the admin API on any replica ([service tokens](postgres.md#service-tokens)): `DELETE /v1/admin/tokens/{id}`. Expected: `200`, and a `service_token.changed` audit record with `action` `token_revoked`.

Verify on each replica directly that the withdrawn credential is now refused with `401` and that your own credential still works. A `503` is a replica that could not consult the authority, not a refusal: ask again, and follow [failover](failover.md) if it persists.

### 3. Rotate the Connection's secret reference

Cluster mode has no writable secret store — the encrypted local provider is standalone-only — so rotation is the operator's sequence, and its first half has to be in place before the incident:

1. **Keep a standby alias declared.** `CONNECTION_SECRET_ALIASES` is static configuration, and its alias IDs are part of the static-configuration fingerprint. Adding an alias during an incident is therefore a fingerprint change, and a readiness-gated rollout of it stalls at `config_fingerprint_mismatch` until the old replicas drain ([gateway replica failure](failover.md#gateway-replica-failure)). Declare a second alias for each credential you may need to rotate in a hurry, with nothing mounted behind it ([configure operator aliases](../connections/operator-guide.md#configure-operator-aliases)).
2. **Mount the replacement material** behind the standby alias, as the [secrets root](../connections/operator-guide.md#protect-the-canonical-secrets-root) requires: a regular, owner-only file.
3. **Rebind the Connection** with a conditional replace, `PUT /v1/admin/connections/{id}` with the Connection's current `ETag` in `If-Match` and the standby alias as `authentication.secret_id`. An enabled binding is resolved for its purpose before it is persisted and again by every replica before that replica publishes it, so a rebind to material that is missing or malformed is refused rather than committed. Expected: `200`, a new `ETag`, an advanced `revisions.credential`, and a `connection.credential_changed` audit record naming the Connection with `authentication` among its `changed_fields`.
4. **Run the Connection's Test** ([tests and catalog refreshes](../connections/operator-guide.md#tests-and-catalog-refreshes)).
5. **Retire the old material**: revoke it at its issuer, then unmount it. `GET /v1/admin/connection-secrets` on every replica should report the old alias with `dependency_count` `0`.

A file alias can also be rotated in place, by atomically replacing the mounted leaf; the next resolution reads the new bytes. That is faster, and it is invisible to the authority: no revision moves and no audit record says who rotated what. The rebind is the path that leaves the decision on the record. Network providers rotate at the provider, with the visibility delays in [secret authority](../connections/operator-guide.md#secret-authority).

### 4. Verify the revision converged

On every replica, directly:

```sh
curl -sS -H "Authorization: Bearer $TOKEN" http://<replica>:8080/v1/admin/cluster
```

Expected: `local.compiled_security_revision` at or above the authority's `last_revision`, and `local.revision_lag` `0`. `GET /v1/admin/cluster/replicas` shows the same watermark for every live member from the deployment's side, because each member writes it with its heartbeat ([the cluster status API](postgres.md#the-cluster-status-api)). A replica that cannot compile a revision does not keep serving the previous one: it answers `503` and, past the reconcile grace, reports `security_revision_not_compiled`. `GreenGatewaySecurityRevisionLag` is the alert for a lag that persists on a serving replica ([cluster authority](operational-alerts.md#cluster-authority)).

### 5. Collect the evidence, sanitized

The authority records each decision once, in order, and names what it decided:

```sql
-- Substitute :start, the revision step 1 recorded.
SELECT revision, resource_type, resource_id, created_at
FROM greengateway.security_outbox WHERE revision > :start ORDER BY revision;

SELECT actor_user_id, security_revision, revoked_at, expires_at
FROM greengateway.jwt_revocations ORDER BY revoked_at;
```

Expected for the incident above: one `jwt_revocation` row (its `resource_id` is a digest, never the `jti`), one `service_token` row naming the token, one `connection` row naming the Connection, and a denylist row attributed to `operator:revoke-jwt` at the revision the command printed. The admin decisions are in `greengateway.audit_events` as `service_token.changed` and `connection.credential_changed`; each refusal of a withdrawn credential is an `auth.failure` record on the replica that refused it.

Keep tokens, `jti` values, secret material, secret locators, request IDs, hostnames and raw audit payloads out of shared incident summaries and alert annotations, as [audit delivery](operational-alerts.md#audit-delivery) already requires. Record counts, revisions, event types and times; keep the raw records in restricted storage.

### 6. Hard stop, where required

If admitted work must not finish, drain the affected replicas and revoke upstream credentials or network paths, as described [above](#what-a-withdrawal-does-not-do). The drain is a supported operation; the revocation at the upstream is outside the gateway.

### 7. Replace a suspect replica with a known-good image

1. **Verify the image before it runs**: its digest, provenance and SBOM, by [verifying image provenance](../RELEASING.md#verifying-image-provenance-and-retrieving-the-sbom). An unavailable verification result is not permission to skip it.
2. **Confirm it is compatible**: it must accept the current schema ledger (`gateway migrate check` exits `0`) and carry the deployment's static configuration from version control, or it will be held at `schema_incompatible` or `config_fingerprint_mismatch` — correctly.
3. **Drain the suspect replica** ([deliberate replica maintenance](failover.md#deliberate-replica-maintenance)) and start the replacement against **the same database**. Never against a restored copy: see the rule at the top of this page.
4. **Verify on the replacement**: it is `ready` as a new member in `gateway cluster-members`; the withdrawn credentials are refused; the Connection is served at the rotated `ETag` with the old alias at `dependency_count` `0`; its compiled revision is at or above step 4's; and the authority's `last_revision` did not move when it joined. A replacement that needed a write of its own to come up is a replacement that could have rewound one.

### 8. Close

Record the starting and final revisions, the decisions in step 5's order, and the times. If the authority itself was lost or is suspect, this page is the wrong one: go to [disaster recovery](disaster-recovery.md).

## What the release gate rehearses

`a_security_incident_rehearsal_holds_through_a_replica_replacement`, in [`gateway/tests/ha/security_two_replica.rs`](../../gateway/tests/ha/security_two_replica.rs), runs in the `ha-release-gate (ha_security_two_replica)` leg of [`ci.yml`](../../.github/workflows/ci.yml) on every pull request. It is in that existing leg on purpose: the leg's name is a required check, and a new matrix leg would be a new check name that branch protection does not require until someone adds it — a rehearsal that could be merged past while red. On two real gateway processes against a disposable PostgreSQL database it asserts:

| Step | Asserted |
| --- | --- |
| 2. Withdraw | A session JWT withdrawn by `revoke-jwt`, and a service token created on one replica and withdrawn on the other, are refused by both replicas on the very next request; the responder's own credential still authenticates on both. |
| 3. Rotate | A credentialed, enabled Connection is rebound on the replica that did not create it, from one operator file alias to a standby alias, under `If-Match`; its credential revision and `ETag` advance; the old material is then unmounted; both replicas serve the new `ETag` and report the old alias with no dependents; the authority's binding row names only the standby alias. |
| 4. Converge | The authority's revision advanced exactly once per decision, in order (`jwt_revocation`, `service_token`, `connection`), the first at the revision `revoke-jwt` printed; both replicas report that revision compiled with zero lag, and so does the roster for every live member. |
| 5. Evidence | The audit of record holds exactly one `service_token.changed` withdrawal and one `connection.credential_changed` rebind for the subjects involved; the denylist holds one withdrawal attributed to `operator:revoke-jwt`; each replica audited its refusals. Every replica's audit file and process output, the command's output, and every row of `audit_events`, `security_outbox`, `jwt_revocations`, `service_tokens` and `connection_credential_bindings` are then swept: no JWT, `jti`, service-token plaintext, Connection material or file-alias locator appears in any of them, nor any compact-JWS prefix. |
| 7. Replace | One replica takes the controlled drain and writes both shutdown records; a new process of the same binary joins the same database as a new member with the survivor's binary version and fingerprint, becomes ready although the old material is gone, refuses both withdrawn credentials, serves the rotated Connection, and compiles the incident's revision — while the authority's revision stays exactly where the incident left it and both withdrawals remain recorded. |

What the rehearsal substitutes, and what it leaves to other gates:

- **The known-good binary is the one the commit under test built.** The replacement is a fresh process of the same binary the survivor runs; there is no image in a test harness, so digest, provenance and SBOM verification are not exercised here. They belong to the release workflow's own verification jobs and to [the release runbook](../RELEASING.md#verifying-image-provenance-and-retrieving-the-sbom).
- **Revoking at the issuer is unmounting.** The rehearsal has no upstream credential issuer and no network path to withdraw, so retirement is removing the mounted file — which is what makes the replacement's readiness meaningful, since it can only come up if nothing it enforces still resolves the retired material.
- **No admitted work is recalled, because nothing can be.** The harness pins `SHUTDOWN_DRAIN_DELAY_MS=0`, so the drain it exercises has no window in which to observe in-flight requests; see [what the gate does not prove](postgres.md#what-the-gate-does-not-prove).
- **No alert is delivered.** Rule behaviour is tested by the operational-alerts job's synthetic fixtures; real delivery to a responder, and measured detection, acknowledgement and recovery times, remain [issue #389](https://github.com/Greenhat-Security/GreenGateway/issues/389). Durable-event alerts are a later part of #440 and are not rehearsed here.

The leg's evidence is its runner log, as [required CI test evidence](test-evidence.md) records for every HA suite; the rehearsal uploads no artifact of its own.

## Running the rehearsal locally

Against a disposable PostgreSQL 16 on loopback with trust authentication — the shape the CI service uses. The harness creates and drops its own database and role per run, so point it at a server that holds nothing you need:

```sh
printf 'postgres://greengateway_ci@127.0.0.1:5432/greengateway_ci\n' > "$HOME/ha-database-url"
chmod 0600 "$HOME/ha-database-url"
export GATEWAY_TEST_POSTGRES_URL_FILE="$HOME/ha-database-url" GATEWAY_TEST_HA_GATE=1
cargo test -p gateway --test ha_security_two_replica \
  a_security_incident_rehearsal_holds_through_a_replica_replacement -- --nocapture
```

Expected output: `test result: ok. 1 passed`, preceded by one line beginning `security incident rehearsal:` — a JSON summary of revisions, decision types, counts and the harness's replica letters. The rehearsal sweeps that line for every credential, secret value and locator it used before printing it, so it is the drill's secret-free record; keep it with the drill's notes. The replicas' own logs and audit files are swept too, but they still name principals and addresses: they stay in restricted storage, not in a shared ticket. On Windows, run from a console, because the harness drains a replica with Ctrl-Break.
