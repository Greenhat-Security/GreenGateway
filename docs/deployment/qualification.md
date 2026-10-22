# Production qualification kit

Repository tests and local rehearsals show how a GreenGateway build behaves on
disposable infrastructure. They cannot show that a deployment meets its
objectives on the platform it will actually run on. [Issue #389](https://github.com/Greenhat-Security/GreenGateway/issues/389)
lists the checks that must pass on the target before rollout. This kit is the
procedure and tooling for running them on any conformant Kubernetes cluster
(EKS, GKE, AKS, k3s and others alike) and recording the results without
recording secrets.

**The kit does not qualify anything by itself, and nothing in this repository
records a qualification result.** CI checks the kit only with fixtures,
loopback servers and the shipped example manifests. A drill counts when it has
run in your environment, against your identity provider, CNI, database
platform, alerting and SLOs, and its record says it passed.

## What you need

| Tool | Used for |
| --- | --- |
| `kubectl` with a context for the target cluster | every Kubernetes read; the probe Jobs of the NetworkPolicy drill; your own fault and upgrade commands |
| Python, the version in `build-tools.json` | `scripts/qualification.py` (standard library only) |
| Node, the version in `build-tools.json` | the load run (`scripts/run-load-suite.mjs` and `scripts/proxy-load.mjs`) |
| `psql`, or your platform's query console | the audit-marker query of the recovery drills |
| Your database platform's own tooling | failover, backup and point-in-time restore; the kit never drives them itself |
| Access to Alertmanager's v2 API | the alert-delivery drill |

The kit uses only the Kubernetes API, so no cloud CLI is assumed. It reads
cluster state and creates nothing but the short-lived probe Jobs of the
NetworkPolicy drill, which it deletes again. Faults, failovers, restores and
upgrades happen only through a command you pass after `--`, or by hand.

| File | What it is |
| --- | --- |
| `scripts/qualification.py` | the drill CLI: `deploy`, `netpol`, `observe`, `reconcile`, `alert` and `evidence` |
| `scripts/run-load-suite.mjs` | with `--profile`, the representative load and SLO run; without it, the unchanged development suite |
| `docs/deployment/qualification/netpol-cases.example.json` | NetworkPolicy probe cases matching the shipped example policy |
| `docs/deployment/qualification/load-profile.example.json` | a load profile shape; its targets are placeholders, not SLOs |
| `docs/deployment/qualification/evidence-template.json` | the evidence record to copy, fill in and check |

## Ground rules

- **Run the drills on the target platform before rollout**: a qualification
  environment built from the same manifests, identity configuration, CNI,
  database platform and monitoring as production, or production itself before
  it carries traffic. Record which one in the evidence.
- **Use a dedicated, short-lived drill identity.** The load and observer drills
  send real authenticated requests. Issue a caller credential for the drills
  only, hand it over in `GREENGATEWAY_BEARER_TOKEN`, and withdraw it afterwards
  (see [the security incident runbook](incident-rehearsal.md) for withdrawing a
  JWT or service token). The kit never takes a token as an argument and never
  writes one. It refuses to send a token over plain HTTP to a non-loopback
  host; use HTTPS or a `kubectl port-forward`, or pass `--allow-plain-http`
  only inside a reviewed private network.
- **Records hold identifiers, not secrets.** Each command writes JSON under
  `artifacts/qualification/<run-id>/` (git-ignored; `--output-dir` to change).
  A record holds digests, check names, counts, timestamps and durations. Every
  record `scripts/qualification.py` writes is scanned first, for private keys,
  JWT-shaped values, URLs with user information, PostgreSQL connection strings,
  credential assignments, bearer values, common cloud and SaaS keys,
  high-entropy strings and keys that name a secret, and is refused if anything
  matches. The load run's summary is built from an allowlist of fields instead,
  and the final evidence check scans every listed record again. Secrets are
  never read, and no environment value is copied into a record.
- **Exit status is the verdict.** `0` passed (or, for a pure measurement,
  measured), `1` failed or inconclusive, `2` invalid input or environment:
  nothing was decided. An inconclusive probe never counts as a pass.
- **Tell the affected owners first.** Load reaches real upstreams, failovers
  page database on-call, and the alert drill pages a responder.

## 0. Open the evidence record

Copy `docs/deployment/qualification/evidence-template.json` beside the drill
records, outside the repository if it will hold environment names. Fill in
`environment`, `release` and `slo_source` (where the agreed SLOs, RTO and RPO
are written down). Before anything else, verify the release itself as
[the release guide](../RELEASING.md#verifying-image-provenance-and-retrieving-the-sbom)
describes: resolve the approved tag to its OCI index digest, run
`python scripts/image_evidence.py verify`, and record the verification output's
file name as `release.provenance_record`. Every later drill takes that digest.

Each drill below fills one entry of `drills`. A drill's `status` is `not_run`,
`passed`, `failed` or `waived`; `passed` needs `completed_at`, at least one
record file and every `measured` value; `waived` needs notes saying why and who
accepted it.

## 1. Deploy verification

Check what will be applied before applying it, then check what runs.

```sh
kubectl kustomize deploy/kubernetes > rendered.yaml   # or your overlay
python scripts/qualification.py deploy --manifest rendered.yaml \
  --expected-digest sha256:<verified-index-digest> \
  --repository ghcr.io/greenhat-security/greengateway

python scripts/qualification.py deploy --namespace <namespace> \
  --expected-digest sha256:<verified-index-digest> \
  --repository ghcr.io/greenhat-security/greengateway --min-replicas 2
```

The checks, each recorded by name:

| Area | Required (failing any fails the drill) |
| --- | --- |
| Identity | the gateway container's image is pinned by digest, the digest and repository are the verified ones, every live pod's spec keeps that digest (no admission webhook rewrote it), and every pod's runtime `imageID` reports an accepted digest |
| Hardening | `runAsNonRoot` with a non-root user, `allowPrivilegeEscalation: false`, not privileged, read-only root filesystem, all capabilities dropped and none added, no service-account token mounted, no host namespaces, no `hostPath` volume |
| Lifecycle | startup, liveness and readiness probes on `/startupz`, `/livez` and `/readyz` |
| Management separation | `ADMIN_LISTEN_ADDR` is set where it can be verified without reading a Secret, listens on loopback (or, with `--admin-exposure cluster` for the [management overlay](../../deploy/kubernetes-management), on its own address with ingress to it restricted to named peers), and the data Service does not reach the admin port |
| Network boundary | NetworkPolicies select the pods for ingress and egress, none of them allows every peer on every port, and no egress rule beyond DNS allows any destination |
| Rollout (live only) | the rollout completed, the live pod count matches the replicas, every pod is Ready, and the replica count meets `--min-replicas` |

Advisory findings (seccomp profile, resource limits, the image user,
`linux/amd64` node selection, a non-`ClusterIP` data Service, container
restarts, ingress rules open to any source) are recorded but do not fail the
drill. Some runtimes report a platform manifest or configuration digest as
`imageID` instead of the index digest; pass the digests recorded in the
release's `subjects.json` with `--runtime-digest`. Static checks read policy
objects, not enforcement; enforcement is the next drill. Run
[the pool-sizing check](pool-sizing.md#checking-a-deployment-before-rollout)
against the same rendered manifests for cluster mode.

## 2. NetworkPolicy enforcement

A NetworkPolicy object proves nothing until the CNI enforces it. The `netpol`
drill starts one short-lived Job per case. The Job's pod carries the case's
labels in the case's namespace, so the same policies select it as would select
the workload it imitates, and it tries one TCP connection (`nc -z`) or one DNS
lookup. The pod:

- is never Ready (its readiness probe always fails), so no Service routes
  traffic to a probe that borrows the gateway's labels, and it is owned by its
  Job, so no ReplicaSet adopts it;
- runs as a non-root user with no service-account token, no privilege
  escalation, a read-only root filesystem and every capability dropped, which
  passes the Pod Security `restricted` profile;
- is deleted with its Job as soon as the case finishes, and every Job of the
  run is deleted again at the end, by the `greengateway-qualification-run` label.

Write the cases for your environment, starting from
`docs/deployment/qualification/netpol-cases.example.json`, which matches the
shipped example policy. Replace the placeholder upstream with the real IdP and
JWKS host, upstream APIs, the database, the secret store, node-local DNS if you
use it, and the destinations that must stay unreachable (the Kubernetes API,
other namespaces, the cloud instance metadata endpoint, the public internet).
For the management overlay, add an allow case from a pod labelled
`greengateway-admin-client: "true"` in a namespace labelled
`greengateway-management: "true"` to port 9090 of the management Service, and
deny cases without those labels.

**A denial counts only with a control.** A probe that cannot connect looks the
same whether a policy dropped it or the target name was wrong. So each deny case
names a `control`: an allow case to the same host and port, which must connect
in the same run. If the control fails, the denial is inconclusive. Where no
allowed path to the target exists anywhere (instance metadata on a platform
that does not serve it, for example), the case states `unattributed_reason`
instead, and the record lists it under `unattributed_denials` for review. At
least one allow case is required.

```sh
python scripts/qualification.py netpol --cases cases.json --plan   # review the Jobs; nothing is applied
python scripts/qualification.py netpol --cases cases.json --context <context>
```

The drill needs permission to create, read and delete Jobs and to read pods in
each probe namespace, and a probe image pinned by digest that the cluster can
pull (mirror it if nodes cannot reach Docker Hub). The default commands suit
BusyBox; set `commands` in the cases file for another image. While a probe that
imitates the gateway runs, a PodDisruptionBudget or autoscaler that selects the
same labels counts one extra, never-ready pod for a few seconds. NetworkPolicy
is layer 3 and 4: the drill tests reachability, not TLS identity or HTTP paths,
and a standard policy cannot select external destinations by hostname (see
[the Kubernetes deployment notes](../../deploy/kubernetes/README.md)).

## 3. Representative load and SLO

Run a load profile that represents production traffic against the real
deployment, with SLO targets taken from your agreed objectives.

```sh
node scripts/run-load-suite.mjs --profile profile.json --validate-only   # no traffic
GREENGATEWAY_BASE_URL=https://gateway.example.test \
GREENGATEWAY_BEARER_TOKEN="$(cat /path/to/drill-token)" \
  node scripts/run-load-suite.mjs --profile profile.json
```

A profile names one route, its method and body size, the statuses that count
as served, an optional warm-up, and scenarios. Each scenario either carries an
`slo` (a p95 or p99 latency target and a maximum error rate, optionally p50 and
a minimum throughput) or is `observe_only`, for a saturation ramp that records
where latency bends without claiming a target. A profile with no SLO at all is
refused, as are unknown keys. Each scenario runs `scripts/proxy-load.mjs` with
`--exact-path`, so the route is sent exactly as written, without the
development upstream's query. The error rate counts client errors and
unexpected statuses over completed requests.

The run writes each scenario's `proxy-load` report and an `slo-summary.json`
under `artifacts/qualification/`. The summary records the profile's SHA-256,
the transport, the path without its query, and each scenario's measurements and
verdict; it holds no URL or token. The per-scenario reports name the target
URL, so share the summary. Exit status `0` means every SLO scenario met its
targets.

The example profile's numbers are placeholders. During the run, watch
saturation where it happens: the gateway pods' CPU and memory, and
`greengateway_inflight_requests`, `greengateway_database_pool_waiting`,
`greengateway_database_pool_timeouts_total` and
`greengateway_audit_queue_depth` per replica (see
[operational alerts](operational-alerts.md#signal-contract)). Set
`gateway_metrics: true` only when the base URL reaches one replica's data
listener directly; through a load balancer the metric deltas mix processes.
Rate limits stay on: give the drill identity the limits a representative caller
has, or run several identities, rather than relaxing them. One `proxy-load`
process has its own ceiling; check the generator host's CPU, and run it close
to where real clients connect from.

## 4. Replica loss

The observer drill is the same for every disruption: it samples pod readiness
and runtime digests through the Kubernetes API, sends one audited request per
interval to a protected route, injects the fault (the command after `--`, or
`--manual-fault` and Enter), and waits until both signals have been healthy for
`--stable-seconds` after the last unhealthy sample.

```sh
GREENGATEWAY_PROBE_URL=https://gateway.example.test/<audited-route> \
GREENGATEWAY_BEARER_TOKEN="$(cat /path/to/drill-token)" \
  python scripts/qualification.py observe --drill replica-loss --namespace <namespace> \
  -- kubectl --namespace <namespace> delete pod <one-gateway-pod>
```

It refuses to inject anything if the baseline (`--baseline-seconds`, default
60) was not healthy. The record holds the fault time, detection and recovery
seconds (`rto_seconds`), the longest traffic outage, the status mix before,
during and after, readiness and restart counts, and every request marker. The
drill fails if the fault command did not exit `0`, if recovery did not happen
within `--timeout-seconds`, or if `401` or `403` responses appeared after the
fault: a replica that cannot check answers `503`, never denies. The resolution
is the larger of `--interval` and `--cluster-interval`.

## 5. Database failover (cluster mode)

Rehearse a failover of the writable primary the way your platform performs it,
following [the failover runbook](failover.md#database-primary-failure). The
command is your platform's, for example `aws rds failover-db-cluster` (Aurora),
`aws rds reboot-db-instance --force-failover` (RDS Multi-AZ),
`gcloud sql instances failover`, `az postgres flexible-server restart --failover Forced`,
`kubectl cnpg promote` (CloudNativePG) or `patronictl failover`. Check the exact
form in your platform's documentation.

```sh
python scripts/qualification.py observe --drill db-failover --namespace <namespace> \
  --expect-disruption --stable-seconds 120 --timeout-seconds 1800 \
  -- <your platform's failover command>
```

`--expect-disruption` keeps the drill from declaring recovery before the
failover has visibly happened; choose `--stable-seconds` longer than the
platform's own failover time. While the primary is unavailable every replica
should answer `503` and `/readyz` should report `storage_unavailable`.

**Recovery point.** Every probe request carries an `x-request-id` marker
(`<run-id>-<sequence>`), and the gateway records it as the audit event's
`request_id`. Confirm once, before the drill, that your ingress passes a client
`x-request-id` through unchanged. After recovery, wait until
`greengateway_audit_queue_depth` is back to zero on every replica, run the
`audit-markers.sql` the observer wrote against the new primary with a read-only
or the migration role, and reconcile:

```sh
psql -At -f artifacts/qualification/<run-id>/audit-markers.sql > recorded.txt
python scripts/qualification.py reconcile \
  --observation artifacts/qualification/<run-id>/observe-db-failover.json \
  --recorded recorded.txt --rpo-target-seconds <agreed RPO>
```

`rpo_seconds` is the window of requests that were acknowledged before the fault
but whose audit events did not survive it, to the probe interval's resolution.
The audit log stands in for the database here because every authoritative write
goes to the same primary; it is not a proof for every table. `during_outage`
counts markers sent while the deployment was disrupted and how many of them the
database holds: the input to the decision in section 9. After the drill, run the
five checks in [backup and recovery](backup-and-recovery.md#verify-the-restore-before-you-point-anything-at-it)
against the promoted primary and record that they passed.

## 6. Backup and point-in-time restore

Follow [the restore drill](backup-and-recovery.md#restore-drills): restore into
an isolated scratch database under the backup's own `DEPLOYMENT_ID`, with
separate credentials and network rules, and never point a scratch replica at
the production database.

1. **Mark a window.** Against the source deployment, run
   `observe --drill pitr-markers --duration-seconds 900` (no fault). Choose a
   recovery target time inside the window and write it down in UTC.
2. **Restore and time it.** Run your platform's restore-to-timestamp into the
   scratch environment. To time it from start to a serving replica, wrap the
   restore, the five verification checks and the start of one scratch replica
   in a script and run it under the observer, pointed at the scratch deployment:
   `observe --drill pitr-restore --namespace <scratch> --baseline-seconds 0 --replicas 1 -- ./restore-to-target.sh`.
   Its `rto_seconds` is the restore duration. Otherwise, record the start and
   ready times from the platform's own log.
3. **Verify** with the five checks in
   [backup and recovery](backup-and-recovery.md#verify-the-restore-before-you-point-anything-at-it)
   and record the result as `restore_checks_passed`.
4. **Reconcile against the target** with the marker query from step 1, run
   against the scratch database:
   `reconcile --observation <pitr-markers record> --recorded recorded.txt --cutoff <target time> --rpo-target-seconds <agreed RPO>`.
   `recovery_point_gap_seconds` is how far before the target the last surviving
   acknowledged marker lies, and `restored_past_target` counts markers sent after
   the target that the restore nevertheless holds; either beyond expectation
   fails the drill.
5. **Destroy** the scratch environment and record that you did.

## 7. Upgrade

Qualify the exact pair of releases you will run, by the procedure that pair
allows ([the supported upgrade matrix](postgres.md#the-supported-matrix) says
which, and [Upgrading a cluster](postgres.md#upgrading-a-cluster) has both
Kubernetes procedures); do not infer mixed-version or zero-downtime support
from another pair.

- **Is there a schema change?** If the newer release's changelog says
  *Coordinated upgrade required*, or its schema contract differs from the
  running one ([schema migrations](postgres.md#schema-migrations)), the only
  supported procedure is coordinated: drain and stop the old fleet, run
  `gateway migrate up`, start the new fleet. Put those steps in a script and run
  it under the observer with `--expect-digest <new digest>`; its `rto_seconds`
  is the unavailable window, which is expected to be greater than zero.
- **No schema change, and the document, feature and configuration contracts
  agree?** A rolling update may be rehearsed:
  `observe --drill upgrade --expect-digest <new digest> -- kubectl --namespace <namespace> set image deployment/greengateway gateway=<repository>@<new digest>`.
  A changed static configuration stalls a readiness-gated rollout by design
  ([failover](failover.md#gateway-replica-failure)); that stall is a finding to
  record, not something to work around.

Run the deploy verification against the new digest afterwards. Back up before
every `migrate up` and read [the rollback boundary](rollback-boundary.md) before
the drill: there is no schema downgrade, and a backup is not permission to
rewind security state.

## 8. Alert delivery

Validated rules are not delivered alerts. Prove both halves.

**Routing.** Post a synthetic `GreenGatewayQualificationDrill` alert carrying
the rules' `owner` and `severity` labels, and require that Alertmanager routes
it to the receiver that should page:

```sh
ALERTMANAGER_URL=https://alertmanager.example.test \
  python scripts/qualification.py alert --synthetic --severity critical \
  --expect-receiver <receiver-name>
```

`ALERTMANAGER_BEARER_TOKEN` supplies a bearer credential where Alertmanager
requires one. The alert resolves itself after `--hold-minutes`.

**A real rule, end to end.** In the qualification environment, cause a real
condition and wait for the real rule, for example a missing scrape target
against the reviewed target inventory:

```sh
python scripts/qualification.py alert --expect GreenGatewayMetricsTargetDown --wait-resolved \
  -- kubectl --namespace <namespace> scale deployment/greengateway --replicas=1
```

Restore the replica count once the alert is seen. The record holds the fault
time, the rule's own `startsAt`, when the alert was seen active, its receivers
and whether it resolved. **Delivery to a person is proved only by the paging
system's own record**: copy its notification and acknowledgement times into the
record's `notified_at` and `acknowledged_at` and the evidence's
`alert_delivery.measured`. See [operational alerts](operational-alerts.md) for
the rules and their owners.

## 9. Audit delivery during a sustained database outage

Audit delivery is bounded and best-effort while the database is unavailable:
events wait in a queue of fixed capacity (`greengateway_audit_queue_capacity`),
and admission or delivery failures are counted in `audit_events_dropped_total`
rather than blocking traffic. Whether that meets your requirements is a
decision for the audit or security owner, not a test result. Supply it with evidence: the failover
drill's `during_outage` counts, the increase of `audit_events_dropped_total`
over the drill window, and, if your requirements concern longer outages, a
separate observer run (`--manual-fault`) while the qualification database stays
unavailable for the duration you must tolerate. Record the decision and the
deciding role in `audit_outage_decision`.

## 10. Check and sign off

```sh
python scripts/qualification.py evidence evidence.json --records-dir artifacts/qualification
```

The check refuses secret-shaped content in the evidence and in every record it
lists, record paths that are absolute or climb out of the records directory, a
`passed` drill without its measurements or records, a waiver without notes, and
a sign-off while any drill is neither `passed` nor `waived` or while the
environment, release digest or SLO source is missing. Keep the evidence and the
records in your restricted evidence store. A sanitized summary of which drills
passed, with their measured times, is what belongs in a release record or issue.

## What CI checks

The required `dev-traffic-smoke` job runs `scripts/test_qualification.py`,
validates the example load profile, renders the example probe Jobs with
`--plan`, and checks the evidence template. The tests exercise the deploy checks
against the shipped base and management manifests and against hardening
regressions, the probe-Job shape and outcome rules, recovery and
recovery-point arithmetic, the observer and alert commands against loopback
servers, the load profile mode end to end against a loopback target, and the
secret scan. None of it contacts a cluster, so none of it is qualification
evidence.

## Limits

- The NetworkPolicy drill tests TCP reachability and DNS resolution from
  imitating pods; it does not test layer-7 policy, TLS identity or FQDN rules
  beyond what reachability shows.
- Observer times are measured to the sampling interval. Pod readiness comes from
  the Kubernetes API, so a control-plane outage during a drill shows as API
  errors rather than as replica health.
- The recovery point comes from the probe route's audit events; it measures
  what the database kept of those writes, not every table.
- The alert drill proves routing to Alertmanager's receivers; delivery to a
  responder is proved by the paging system's record.
- The load run is one generator process per invocation and judges one route per
  profile; run one profile per representative route.
