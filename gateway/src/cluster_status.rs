//! The read-only cluster status view behind `GET /v1{ADMIN_PREFIX}/cluster`
//! and `GET /v1{ADMIN_PREFIX}/cluster/replicas` (issue #241, PR 14).
//!
//! `/readyz` answers one bit about one replica. An operator asking *why* a
//! deployment is unhealthy needs the deployment: which replicas are live,
//! what versions they run, whether the schema still matches, how far this
//! replica's security watermark is behind the authority, whether the
//! projector is keeping up, and whether the singleton's background jobs
//! are actually running. That is what these two endpoints report, and
//! nothing else: there are no mutation routes here, and there is no
//! surface on which one replica can act on another.
//!
//! ## What this module is, structurally
//!
//! Three layers, deliberately separated:
//!
//! 1. **Facts.** [`LocalFacts`] is what this process knows about itself
//!    without a database read; [`ClusterReadout`] is what one read of the
//!    shared authority returned. Every field of the readout is optional,
//!    because a status view must degrade to "unknown" rather than fail --
//!    the operator asking why the deployment is sick is exactly the person
//!    whose database read may not answer.
//! 2. **Assembly.** [`cluster_status`] and [`cluster_replicas`] are pure
//!    functions from those facts to the response types. No I/O, no clock
//!    reads, no globals: every state, reason, and count in the API has a
//!    test that fixes the facts and asserts the shape.
//! 3. **The source.** [`ClusterStatusSource`] is the one seam that touches
//!    PostgreSQL, implemented in `main.rs` over the anchors that already
//!    exist -- `PostgresMembershipStore::{members, maintenance_jobs}`,
//!    `PostgresDiscoveryStore::checkpoint`, the audit store's stream head,
//!    the maintenance runner's leadership flag, and deadpool's
//!    `Pool::status()`. Nothing here opens a connection of its own.
//!
//! The fact structs mirror the store rows rather than re-using
//! `storage::ClusterMember` and friends directly, for one reason: those
//! types live behind the `postgres` feature, and standalone mode -- which
//! serves the same two endpoints -- must report itself in a build that has
//! no PostgreSQL client compiled in at all. The mapping is a field-for-field
//! copy (`From` impls below, under the feature) and holds the raw column
//! values; redaction happens in the assembly, which is what makes the
//! redaction tests meaningful.
//!
//! ## Redaction is a boundary, not a habit
//!
//! Every string in these responses is written by *some other replica* into
//! a shared table. A replica that is misconfigured, compromised, or simply
//! running a build nobody remembers can put anything in its
//! `binary_version` or `last_error_code`, and an admin API that echoed it
//! would be a way to move data -- a DSN, a hostname, an address -- from a
//! database row into an operator's browser.
//!
//! So this module does not filter strings; it *recognizes* them. Each
//! string field has a known shape (a semantic version, 64 hex characters,
//! a UTC timestamp, one of the classifier's fixed error kinds, one of the
//! singleton's fixed job names) and a value that is not of that shape is
//! replaced whole by `unknown` -- never trimmed, never partially escaped,
//! because a filtered `postgres://u:p@10.0.0.5:5432/db` is still a dotted
//! quad and a leaked host. Instance and boot identifiers are `Uuid`
//! values, which cannot carry text at all.
//!
//! Everything else in the response is a number or a fixed enum. There is
//! no field here through which a DSN, a database host or user, an IP
//! address, policy or tool content, query text, or a raw error string can
//! travel.
//!
//! Hostnames are the single exception, and they are opt-in. `local.hostname`
//! is `null` unless the deployment sets `CLUSTER_STATUS_EXPOSE_HOSTNAMES=true`,
//! and even then it carries only *this* process's own hostname, read once at
//! startup and bounded by [`safe_hostname`] -- never another replica's, which
//! no roster column holds. An operator who needs to map a roster UUID onto a
//! pod turns it on; a deployment that would rather not publish its topology
//! leaves it off and loses nothing else on this surface.

use std::time::Duration;

use serde::Serialize;
use uuid::Uuid;

use crate::storage::RepositoryErrorKind;

/// What replaces any string that is not recognizably of its field's shape.
const UNKNOWN: &str = "unknown";

/// The longest hostname `local.hostname` will report: a fully qualified
/// domain name's maximum, which is also longer than any pod name.
const MAX_HOSTNAME_LEN: usize = 253;

/// The `mode` values.
pub(crate) const MODE_STANDALONE: &str = "standalone";
pub(crate) const MODE_CLUSTER: &str = "cluster";

/// The `state` values.
pub(crate) const STATE_READY: &str = "ready";
pub(crate) const STATE_DEGRADED: &str = "degraded";
pub(crate) const STATE_DRAINING: &str = "draining";
pub(crate) const STATE_NOT_READY: &str = "not_ready";

/// The `reason` values a *serving* replica can report. The not-ready
/// reasons are `/readyz`'s own strings, passed through unchanged so one
/// word means one thing on both surfaces; these four name conditions a
/// replica can serve traffic in but an operator should look at.
pub(crate) const REASON_REPLICAS_UNAVAILABLE: &str = "replicas_unavailable";
pub(crate) const REASON_SECURITY_REVISION_LAGGING: &str = "security_revision_lagging";
pub(crate) const REASON_MAINTENANCE_JOB_FAILING: &str = "maintenance_job_failing";
pub(crate) const REASON_MEMBER_ERROR_REPORTED: &str = "member_error_reported";

/// The singleton's job names, which are the only values `leader_tasks[].name`
/// can take. Any other name in the ledger -- a job a newer gateway runs, a
/// row written by hand -- is reported as `unknown` rather than echoed.
/// `the_leader_task_vocabulary_is_the_singletons_job_names` keeps this
/// list and `cluster_maintenance`'s constants in step.
pub(crate) const KNOWN_LEADER_TASKS: [&str; 6] = [
    "audit_retention",
    "execution_lease_reaper",
    "jwt_revocation_cleanup",
    "pending_login_prune",
    "rate_limit_idle_sweep",
    "stale_member_sweep",
];

// --- facts -------------------------------------------------------------------

/// One roster row, exactly as the membership store read it back.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct ReplicaFacts {
    pub instance_id: Uuid,
    pub boot_id: Uuid,
    pub binary_version: String,
    pub schema_version_min: i32,
    pub schema_version_max: i32,
    pub document_version_min: i32,
    pub document_version_max: i32,
    pub fingerprint: String,
    pub started_at: Option<String>,
    pub last_heartbeat_at: Option<String>,
    pub heartbeat_age_secs: Option<f64>,
    pub ready_at: Option<String>,
    pub draining_at: Option<String>,
    pub compiled_security_revision: i64,
    pub observed_security_revision: i64,
    pub last_error_code: Option<String>,
    pub live: bool,
}

/// One singleton job's ledger row, plus its age on the database clock.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct LeaderTaskFacts {
    pub job: String,
    pub fence: i64,
    pub last_success_age_secs: Option<f64>,
    pub last_failure_code: Option<String>,
}

/// The discovery projector's singleton row.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct ProjectorFacts {
    pub fence: i64,
    pub checkpoint_position: i64,
    pub projected_events: i64,
    /// The instance the row names as leader, if any.
    pub leader_instance: Option<Uuid>,
    /// Seconds since the row was last claimed or flushed, on the database
    /// clock.
    pub updated_age_secs: f64,
}

/// deadpool's `Pool::status()` plus the process's checkout-timeout count.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PoolFacts {
    pub size: usize,
    pub available: usize,
    pub waiting: usize,
    pub timeouts_total: u64,
}

/// The audit writer's queue as the process sees it.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct AuditQueueFacts {
    pub queue_depth: usize,
    pub queue_capacity: usize,
    /// How long the oldest event the writer has not finished delivering
    /// has been waiting. Zero when the writer is idle.
    pub oldest_age_secs: f64,
    pub dropped_total: u64,
}

/// One read of the shared authority. Every field is `None` when the read
/// did not answer -- and in standalone mode, where there is no authority
/// to read: the view reports what it knows and says nothing about what it
/// does not.
#[derive(Clone, Debug, Default)]
pub(crate) struct ClusterReadout {
    pub members: Option<Vec<ReplicaFacts>>,
    pub leader_tasks: Option<Vec<LeaderTaskFacts>>,
    pub projector: Option<ProjectorFacts>,
    /// The highest assigned audit stream position.
    pub audit_stream_head: Option<i64>,
    /// Whether this replica holds the maintenance lease right now.
    pub leading: bool,
    pub pool: Option<PoolFacts>,
    /// How many migrations the authority's ledger carries, as the
    /// readiness probe last observed it.
    pub schema_ledger_version: Option<i32>,
}

/// What this process knows about itself without reading anything.
#[derive(Clone, Debug)]
pub(crate) struct LocalFacts {
    pub cluster_mode: bool,
    pub instance_id: Uuid,
    pub boot_id: Uuid,
    pub binary_version: String,
    /// The static-configuration fingerprint, 64 lowercase hex characters.
    pub fingerprint: String,
    /// The migration-manifest range this binary serves on.
    pub schema_versions: (i32, i32),
    /// The policy/tools document major range this binary enforces.
    pub document_versions: (i32, i32),
    pub boot_age_secs: u64,
    /// This replica's own hostname, and the one field on this surface that
    /// is deployment topology rather than a shape-checked value. `None`
    /// unless `CLUSTER_STATUS_EXPOSE_HOSTNAMES=true`, which is the whole
    /// point of that variable: an operator who needs to map a roster UUID
    /// onto a pod asks for it, and a deployment that would rather not
    /// publish its topology never does. It is this process's own hostname,
    /// read once at startup -- never another replica's, which no roster
    /// column carries.
    pub hostname: Option<String>,
    pub instance_ready: bool,
    pub draining: bool,
    /// The reason `/readyz` would refuse, evaluated by the same chain in
    /// the same order. `None` means `/readyz` answers `200`.
    pub blocked_reason: Option<&'static str>,
    pub compiled_security_revision: i64,
    pub observed_security_revision: i64,
    pub reconcile_last_pass_age: Option<Duration>,
    pub reconcile_failures_total: u64,
    pub audit: AuditQueueFacts,
}

/// The security runtime as the status view reads it: the two watermarks
/// (through the readiness probe's own trait, so there is one definition
/// of "compiled" and "observed") plus the background reconciler's health.
pub(crate) trait SecurityStatus: crate::ha_status::SecurityRevisionHealth {
    /// How long ago the background reconciler last completed a pass;
    /// `None` before the first one.
    fn last_reconcile_pass_age(&self) -> Option<Duration>;
    /// Background reconcile passes that failed since boot.
    fn reconcile_failures_total(&self) -> u64;
}

/// The one seam that reads the shared authority, so the assembly and its
/// shapes are testable without a database -- the same fault-injection
/// pattern `ha_status::ReadinessAuthority` uses.
#[async_trait::async_trait]
pub(crate) trait ClusterStatusSource: Send + Sync {
    async fn read(&self) -> ClusterReadout;
}

// --- responses ---------------------------------------------------------------

#[derive(Debug, Serialize)]
pub(crate) struct ClusterStatusResponse {
    pub mode: &'static str,
    /// Whether `/readyz` would answer `200` right now.
    pub ready: bool,
    pub state: &'static str,
    pub reason: Option<&'static str>,
    pub schema: SchemaView,
    pub replicas: ReplicaCounts,
    pub binary_versions: Vec<BinaryVersionCount>,
    pub local: LocalView,
    pub reconcile: ReconcileView,
    /// `null` in standalone mode, which has no projector, and when the
    /// projector row could not be read.
    pub projector: Option<ProjectorView>,
    /// `null` in standalone mode, which has no singleton, and when the
    /// job ledger could not be read.
    pub leader_tasks: Option<Vec<LeaderTaskView>>,
    pub audit: AuditQueueView,
    pub pools: PoolsView,
}

#[derive(Debug, Serialize)]
pub(crate) struct SchemaView {
    /// How many migrations the authority's ledger carries. `null` in
    /// standalone mode, which has no shared ledger, and when the
    /// authority could not be read.
    pub current_version: Option<i32>,
    pub binary_min: i32,
    pub binary_max: i32,
    pub compatible: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReplicaCounts {
    /// Live members that have been stamped ready and are not draining.
    pub ready: usize,
    /// Live members.
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct BinaryVersionCount {
    pub version: String,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct LocalView {
    /// Rendered rather than typed as a `Uuid` because the driver is built
    /// without uuid support and the crate without serde: a hyphenated
    /// lowercase hex string is what both ends already agree on.
    pub instance_id: String,
    pub boot_id: String,
    pub boot_age_secs: u64,
    /// `null` unless `CLUSTER_STATUS_EXPOSE_HOSTNAMES=true`. Bounded to
    /// [`MAX_HOSTNAME_LEN`] so an opted-in deployment still cannot turn
    /// this field into a channel for arbitrary text.
    pub hostname: Option<String>,
    pub instance_ready: bool,
    pub draining: bool,
    pub compiled_security_revision: i64,
    pub observed_security_revision: i64,
    /// `observed - compiled`, never negative.
    pub revision_lag: i64,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReconcileView {
    pub last_pass_age_secs: Option<u64>,
    pub failures_total: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct ProjectorView {
    pub fence: i64,
    pub checkpoint_position: i64,
    /// The highest assigned audit stream position, or `null` when it
    /// could not be read.
    pub stream_head: Option<i64>,
    /// `stream_head - checkpoint_position`, never negative; `null` when
    /// the head is unknown.
    pub lag_events: Option<i64>,
    /// Whether the instance the projector row names as leader is a live
    /// member of the roster.
    pub leader_present: bool,
    pub last_flush_age_secs: f64,
}

#[derive(Debug, Serialize)]
pub(crate) struct LeaderTaskView {
    pub name: String,
    pub held_by_this_instance: bool,
    pub fence: i64,
    pub last_success_age_secs: Option<f64>,
    pub last_failure_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AuditQueueView {
    pub queue_depth: usize,
    pub queue_capacity: usize,
    pub oldest_age_secs: f64,
    pub dropped_total: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct PoolsView {
    /// `null` in standalone mode, which has no shared database pool.
    pub database: Option<PoolView>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PoolView {
    pub size: usize,
    pub available: usize,
    pub waiting: usize,
    pub timeouts_total: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct ClusterReplicasResponse {
    pub replicas: Vec<ReplicaView>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReplicaView {
    pub instance_id: String,
    pub boot_id: String,
    pub binary_version: String,
    pub schema_version_min: i32,
    pub schema_version_max: i32,
    pub document_version_min: i32,
    pub document_version_max: i32,
    pub fingerprint: String,
    pub started_at: Option<String>,
    pub last_heartbeat_at: Option<String>,
    pub heartbeat_age_secs: Option<f64>,
    pub ready_at: Option<String>,
    pub draining_at: Option<String>,
    pub compiled_security_revision: i64,
    pub observed_security_revision: i64,
    pub last_error_code: Option<String>,
    pub live: bool,
}

// --- assembly ----------------------------------------------------------------

/// The roster the two endpoints report over: the authority's rows in
/// cluster mode, and this process alone in standalone mode, where there is
/// no roster and this replica is the deployment.
fn roster(local: &LocalFacts, readout: &ClusterReadout) -> Vec<ReplicaFacts> {
    match readout.members.as_ref() {
        Some(members) => members.clone(),
        // Cluster mode with an unreadable roster reports no members and
        // says so through `replicas_unavailable`; inventing a row would
        // make an outage look like a healthy single-replica deployment.
        None if local.cluster_mode => Vec::new(),
        None => vec![local_replica(local)],
    }
}

/// Standalone mode's single self-report. The roster timestamps are `null`
/// because there is no roster row to have been written at a time: what a
/// standalone deployment knows about its own age is `local.boot_age_secs`.
fn local_replica(local: &LocalFacts) -> ReplicaFacts {
    ReplicaFacts {
        instance_id: local.instance_id,
        boot_id: local.boot_id,
        binary_version: local.binary_version.clone(),
        schema_version_min: local.schema_versions.0,
        schema_version_max: local.schema_versions.1,
        document_version_min: local.document_versions.0,
        document_version_max: local.document_versions.1,
        fingerprint: local.fingerprint.clone(),
        started_at: None,
        last_heartbeat_at: None,
        heartbeat_age_secs: None,
        ready_at: None,
        draining_at: None,
        compiled_security_revision: local.compiled_security_revision,
        observed_security_revision: local.observed_security_revision,
        last_error_code: None,
        live: true,
    }
}

/// `GET /v1{ADMIN_PREFIX}/cluster`.
pub(crate) fn cluster_status(
    local: &LocalFacts,
    readout: &ClusterReadout,
) -> ClusterStatusResponse {
    let members = roster(local, readout);
    let live: Vec<&ReplicaFacts> = members.iter().filter(|member| member.live).collect();
    let ready_count = live
        .iter()
        .filter(|member| member.ready_at.is_some() && member.draining_at.is_none())
        .count();
    // Standalone's single row carries no `ready_at` stamp (nothing writes
    // one), so its readiness is the lifecycle's, not the roster's.
    let ready_count = if local.cluster_mode {
        ready_count
    } else {
        usize::from(local.instance_ready)
    };
    let revision_lag = local
        .observed_security_revision
        .saturating_sub(local.compiled_security_revision)
        .max(0);

    let (state, reason) = state_and_reason(local, readout, &live, revision_lag);

    ClusterStatusResponse {
        mode: if local.cluster_mode {
            MODE_CLUSTER
        } else {
            MODE_STANDALONE
        },
        ready: local.blocked_reason.is_none(),
        state,
        reason,
        schema: SchemaView {
            current_version: readout.schema_ledger_version,
            binary_min: local.schema_versions.0,
            binary_max: local.schema_versions.1,
            compatible: match readout.schema_ledger_version {
                Some(version) => {
                    version >= local.schema_versions.0 && version <= local.schema_versions.1
                }
                // Standalone has no shared ledger to disagree with, and a
                // ledger this replica could not read is not evidence of
                // disagreement -- `storage_unavailable` is what reports
                // that, on `/readyz` and in `reason`.
                None => true,
            },
        },
        replicas: ReplicaCounts {
            ready: ready_count,
            total: live.len(),
        },
        binary_versions: binary_versions(&live),
        local: LocalView {
            instance_id: local.instance_id.to_string(),
            boot_id: local.boot_id.to_string(),
            boot_age_secs: local.boot_age_secs,
            hostname: local.hostname.as_deref().and_then(safe_hostname),
            instance_ready: local.instance_ready,
            draining: local.draining,
            compiled_security_revision: local.compiled_security_revision,
            observed_security_revision: local.observed_security_revision,
            revision_lag,
        },
        reconcile: ReconcileView {
            last_pass_age_secs: local.reconcile_last_pass_age.map(|age| age.as_secs()),
            failures_total: local.reconcile_failures_total,
        },
        projector: readout
            .projector
            .map(|projector| projector_view(&projector, readout.audit_stream_head, &live)),
        leader_tasks: readout.leader_tasks.as_ref().map(|tasks| {
            tasks
                .iter()
                .map(|task| leader_task_view(task, readout.leading))
                .collect()
        }),
        audit: AuditQueueView {
            queue_depth: local.audit.queue_depth,
            queue_capacity: local.audit.queue_capacity,
            oldest_age_secs: local.audit.oldest_age_secs,
            dropped_total: local.audit.dropped_total,
        },
        pools: PoolsView {
            database: readout.pool.map(|pool| PoolView {
                size: pool.size,
                available: pool.available,
                waiting: pool.waiting,
                timeouts_total: pool.timeouts_total,
            }),
        },
    }
}

/// `GET /v1{ADMIN_PREFIX}/cluster/replicas`, live members first and, within
/// each group, in the order the store returned (oldest boot first).
pub(crate) fn cluster_replicas(
    local: &LocalFacts,
    readout: &ClusterReadout,
) -> ClusterReplicasResponse {
    let mut members = roster(local, readout);
    members.sort_by_key(|member| !member.live);
    ClusterReplicasResponse {
        replicas: members.iter().map(replica_view).collect(),
    }
}

/// The state machine, in one place.
///
/// Not-ready and draining come from the readiness chain itself, so this
/// surface can never disagree with `/readyz` about whether the replica is
/// serving. Degraded is the addition: the replica *is* serving, and one of
/// four specific things is nonetheless wrong. The order is worst-first --
/// a roster that cannot be read makes every other judgement below it
/// unreliable, and a security watermark behind the authority is failing
/// protected requests closed right now.
fn state_and_reason(
    local: &LocalFacts,
    readout: &ClusterReadout,
    live: &[&ReplicaFacts],
    revision_lag: i64,
) -> (&'static str, Option<&'static str>) {
    if let Some(reason) = local.blocked_reason {
        let state = if local.draining {
            STATE_DRAINING
        } else {
            STATE_NOT_READY
        };
        return (state, Some(reason));
    }
    if local.cluster_mode && readout.members.is_none() {
        return (STATE_DEGRADED, Some(REASON_REPLICAS_UNAVAILABLE));
    }
    if revision_lag > 0 {
        return (STATE_DEGRADED, Some(REASON_SECURITY_REVISION_LAGGING));
    }
    if readout
        .leader_tasks
        .as_ref()
        .is_some_and(|tasks| tasks.iter().any(|task| task.last_failure_code.is_some()))
    {
        return (STATE_DEGRADED, Some(REASON_MAINTENANCE_JOB_FAILING));
    }
    if live.iter().any(|member| member.last_error_code.is_some()) {
        return (STATE_DEGRADED, Some(REASON_MEMBER_ERROR_REPORTED));
    }
    (STATE_READY, None)
}

/// Live members grouped by the version they run, so a rollout that has
/// stalled halfway is one line of the response. Versions are sanitized
/// before grouping, so an unrecognizable one is counted under `unknown`
/// rather than becoming its own row per replica.
fn binary_versions(live: &[&ReplicaFacts]) -> Vec<BinaryVersionCount> {
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for member in live {
        *counts
            .entry(safe_version(&member.binary_version))
            .or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(version, count)| BinaryVersionCount { version, count })
        .collect()
}

fn projector_view(
    projector: &ProjectorFacts,
    stream_head: Option<i64>,
    live: &[&ReplicaFacts],
) -> ProjectorView {
    ProjectorView {
        fence: projector.fence,
        checkpoint_position: projector.checkpoint_position,
        stream_head,
        lag_events: stream_head
            .map(|head| head.saturating_sub(projector.checkpoint_position).max(0)),
        // The row names its leader even after that leader is gone (the
        // claim is only ever overwritten by a successor), so a name alone
        // proves nothing. The roster is what proves it: a leader that is
        // a live member is present, and one that is not is a projector
        // waiting for a successor to claim.
        leader_present: projector
            .leader_instance
            .is_some_and(|leader| live.iter().any(|member| member.instance_id == leader)),
        last_flush_age_secs: projector.updated_age_secs,
    }
}

fn leader_task_view(task: &LeaderTaskFacts, leading: bool) -> LeaderTaskView {
    LeaderTaskView {
        name: safe_job_name(&task.job),
        held_by_this_instance: leading,
        fence: task.fence,
        last_success_age_secs: task.last_success_age_secs,
        last_failure_code: task.last_failure_code.as_deref().map(safe_error_code),
    }
}

fn replica_view(member: &ReplicaFacts) -> ReplicaView {
    ReplicaView {
        instance_id: member.instance_id.to_string(),
        boot_id: member.boot_id.to_string(),
        binary_version: safe_version(&member.binary_version),
        schema_version_min: member.schema_version_min,
        schema_version_max: member.schema_version_max,
        document_version_min: member.document_version_min,
        document_version_max: member.document_version_max,
        fingerprint: safe_fingerprint(&member.fingerprint),
        started_at: member.started_at.as_deref().and_then(safe_timestamp),
        last_heartbeat_at: member.last_heartbeat_at.as_deref().and_then(safe_timestamp),
        heartbeat_age_secs: member.heartbeat_age_secs,
        ready_at: member.ready_at.as_deref().and_then(safe_timestamp),
        draining_at: member.draining_at.as_deref().and_then(safe_timestamp),
        compiled_security_revision: member.compiled_security_revision,
        observed_security_revision: member.observed_security_revision,
        last_error_code: member.last_error_code.as_deref().map(safe_error_code),
        live: member.live,
    }
}

// --- redaction ---------------------------------------------------------------

/// A semantic version and nothing else: three numeric components, with an
/// optional pre-release or build suffix of one identifier and at most one
/// numeric part after it (`-rc.1`, `+build.7`, `-alpha`).
///
/// The three-component rule is load-bearing rather than pedantic: a
/// four-component "version" is a dotted quad, and a dotted quad is an
/// address. A value that does not match is reported as `unknown`, whole --
/// stripping the offending characters from `postgres://u:p@10.0.0.5/db`
/// would leave the address behind, which is the leak this is here to
/// prevent.
///
/// The suffix is held to the same standard, and that is why it is not
/// simply "the characters semver allows": the accepted value is returned
/// whole, so a suffix free to carry dots is a free-text channel out of
/// the roster onto both cluster routes. `1.0.0+10.0.0.5` passes any check
/// that only looks at what is in front of the `+`, and what reaches the
/// operator's screen is an address. One identifier and at most one
/// numeric part keeps every real version this gateway can be built at
/// (`0.5.0`, `1.0.0-rc.1`, `1.0.0+build.7`) and admits neither a dotted
/// quad nor a hostname, both of which need a dot before a non-numeric
/// part.
fn safe_version(value: &str) -> String {
    let mut parts = value.splitn(3, '.');
    let (Some(major), Some(minor), Some(patch)) = (parts.next(), parts.next(), parts.next()) else {
        return UNKNOWN.to_owned();
    };
    let numeric = |part: &str| {
        !part.is_empty() && part.len() <= 8 && part.bytes().all(|byte| byte.is_ascii_digit())
    };
    let (patch, suffix) = match patch.find(['-', '+']) {
        Some(index) => (&patch[..index], Some(&patch[index + 1..])),
        None => (patch, None),
    };
    let suffix_ok = suffix.is_none_or(|suffix| {
        if suffix.is_empty() || suffix.len() > 24 {
            return false;
        }
        let (identifier, rest) = match suffix.split_once('.') {
            Some((identifier, rest)) => (identifier, Some(rest)),
            None => (suffix, None),
        };
        let identifier_ok = !identifier.is_empty()
            && identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
        identifier_ok && rest.is_none_or(numeric)
    });
    if numeric(major) && numeric(minor) && numeric(patch) && suffix_ok {
        return value.to_owned();
    }
    UNKNOWN.to_owned()
}

/// Exactly 64 lowercase hexadecimal characters, the shape the membership
/// store enforces on write; anything else is `unknown`.
fn safe_fingerprint(value: &str) -> String {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return value.to_owned();
    }
    UNKNOWN.to_owned()
}

/// A UTC timestamp as the database renders it (`to_char`, microseconds,
/// `Z`) or as RFC 3339 writes it. Anything else becomes `null`: a
/// timestamp is the one field whose absence reads correctly, so there is
/// no need for a placeholder string.
fn safe_timestamp(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    if bytes.len() < 20 || bytes.len() > 30 || bytes[bytes.len() - 1] != b'Z' {
        return None;
    }
    let digits = |range: std::ops::Range<usize>| bytes[range].iter().all(u8::is_ascii_digit);
    let shaped = digits(0..4)
        && bytes[4] == b'-'
        && digits(5..7)
        && bytes[7] == b'-'
        && digits(8..10)
        && bytes[10] == b'T'
        && digits(11..13)
        && bytes[13] == b':'
        && digits(14..16)
        && bytes[16] == b':'
        && digits(17..19);
    if !shaped {
        return None;
    }
    let fraction = &bytes[19..bytes.len() - 1];
    let fraction_ok = fraction.is_empty()
        || (fraction[0] == b'.'
            && fraction.len() > 1
            && fraction[1..].iter().all(u8::is_ascii_digit));
    fraction_ok.then(|| value.to_owned())
}

/// One of the repository classifier's fixed kinds. Every error code that
/// reaches a member row or a job row is a `RepositoryErrorKind::as_str()`
/// value written by a gateway; anything else did not come from one.
fn safe_error_code(value: &str) -> String {
    RepositoryErrorKind::KNOWN
        .iter()
        .find(|kind| kind.as_str() == value)
        .map_or_else(|| UNKNOWN.to_owned(), |kind| kind.as_str().to_owned())
}

/// A hostname, when the deployment has opted into publishing one.
///
/// This is the only string on the surface whose *value* is not drawn from
/// a fixed vocabulary, so the shape is what bounds it: the characters a
/// DNS label or a container's `HOSTNAME` can hold (letters, digits, `-`,
/// `.`, `_`), at most [`MAX_HOSTNAME_LEN`] of them, and no empty string.
/// A value outside that is dropped whole rather than trimmed -- the same
/// rule the rest of the module follows, and for the same reason: an
/// operator asked for a hostname, not for whatever else the environment
/// happened to be carrying.
fn safe_hostname(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_HOSTNAME_LEN {
        return None;
    }
    trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
        .then(|| trimmed.to_owned())
}

/// One of the singleton's job names.
fn safe_job_name(value: &str) -> String {
    KNOWN_LEADER_TASKS
        .iter()
        .find(|known| **known == value)
        .map_or_else(|| UNKNOWN.to_owned(), |known| (*known).to_owned())
}

// --- mapping from the store rows ---------------------------------------------

#[cfg(feature = "postgres")]
impl From<&crate::storage::ClusterMember> for ReplicaFacts {
    fn from(member: &crate::storage::ClusterMember) -> Self {
        Self {
            instance_id: member.instance_id,
            boot_id: member.boot_id,
            binary_version: member.binary_version.clone(),
            schema_version_min: member.schema_version_min,
            schema_version_max: member.schema_version_max,
            document_version_min: member.document_version_min,
            document_version_max: member.document_version_max,
            fingerprint: member.fingerprint.clone(),
            started_at: Some(member.started_at.clone()),
            last_heartbeat_at: Some(member.last_heartbeat_at.clone()),
            heartbeat_age_secs: Some(member.heartbeat_age_secs),
            ready_at: member.ready_at.clone(),
            draining_at: member.draining_at.clone(),
            compiled_security_revision: member.compiled_security_revision,
            observed_security_revision: member.observed_security_revision,
            last_error_code: member.last_error_code.clone(),
            live: member.live,
        }
    }
}

#[cfg(feature = "postgres")]
impl From<&crate::storage::MaintenanceJobRecord> for LeaderTaskFacts {
    fn from(record: &crate::storage::MaintenanceJobRecord) -> Self {
        Self {
            job: record.job.clone(),
            fence: record.fence,
            last_success_age_secs: record.last_success_age_secs,
            last_failure_code: record.last_failure_code.clone(),
        }
    }
}

#[cfg(feature = "postgres")]
impl From<&crate::storage::postgres_discovery::ProjectorCheckpoint> for ProjectorFacts {
    fn from(checkpoint: &crate::storage::postgres_discovery::ProjectorCheckpoint) -> Self {
        Self {
            fence: checkpoint.fence,
            checkpoint_position: checkpoint.checkpoint_position,
            projected_events: checkpoint.projected_events,
            leader_instance: checkpoint.leader_instance,
            updated_age_secs: checkpoint.updated_age_secs,
        }
    }
}

/// The production source: one read of each anchor PR 11 and PR 13
/// already own, over the handles the app builder already holds.
///
/// The reads are issued together and each is independent: a roster that
/// answers while the job ledger does not still fills in the sections it
/// can. Nothing here retries, and nothing here writes.
#[cfg(feature = "postgres")]
pub(crate) struct PostgresClusterStatusSource {
    membership: std::sync::Arc<crate::storage::PostgresMembershipStore>,
    discovery: crate::storage::postgres_discovery::PostgresDiscoveryStore,
    /// The durable audit store, whose stream head the projector's lag is
    /// measured against. Absent when cluster mode runs without it.
    audit: Option<std::sync::Arc<crate::storage::postgres_audit::PostgresAuditEventStore>>,
    /// The maintenance singleton's runner, for whether this replica is
    /// the one holding the lease.
    maintenance: Option<std::sync::Arc<crate::cluster_maintenance::MaintenanceRunner>>,
    pool: deadpool_postgres::Pool,
    /// The window liveness is judged against (`CLUSTER_MEMBER_STALE_MS`),
    /// the same one the heartbeat task and the singleton's sweep use.
    stale_window: Duration,
}

#[cfg(feature = "postgres")]
impl PostgresClusterStatusSource {
    pub(crate) fn new(
        membership: std::sync::Arc<crate::storage::PostgresMembershipStore>,
        audit: Option<std::sync::Arc<crate::storage::postgres_audit::PostgresAuditEventStore>>,
        maintenance: Option<std::sync::Arc<crate::cluster_maintenance::MaintenanceRunner>>,
        pool: deadpool_postgres::Pool,
        stale_window: Duration,
    ) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            membership,
            discovery: crate::storage::postgres_discovery::PostgresDiscoveryStore::new(
                pool.clone(),
            ),
            audit,
            maintenance,
            pool,
            stale_window,
        })
    }
}

#[cfg(feature = "postgres")]
#[async_trait::async_trait]
impl ClusterStatusSource for PostgresClusterStatusSource {
    async fn read(&self) -> ClusterReadout {
        // Each read is already classified and logged by its store; the
        // status view turns a failure into an absent section, because an
        // operator asking why the deployment is unhealthy must not be
        // answered with a 500 for the one part that could not be read.
        let members = self
            .membership
            .members(self.stale_window)
            .await
            .ok()
            .map(|members| members.iter().map(ReplicaFacts::from).collect());
        let leader_tasks = self
            .membership
            .maintenance_jobs()
            .await
            .ok()
            .map(|jobs| jobs.iter().map(LeaderTaskFacts::from).collect());
        let projector = self
            .discovery
            .checkpoint()
            .await
            .ok()
            .map(|checkpoint| ProjectorFacts::from(&checkpoint));
        let audit_stream_head = match self.audit.as_ref() {
            Some(audit) => audit.stream_head().await.ok(),
            None => None,
        };
        let status = self.pool.status();
        ClusterReadout {
            members,
            leader_tasks,
            projector,
            audit_stream_head,
            leading: self
                .maintenance
                .as_ref()
                .is_some_and(|runner| runner.is_leading()),
            pool: Some(PoolFacts {
                size: status.size,
                available: status.available,
                waiting: status.waiting,
                timeouts_total: crate::storage::postgres::pool_timeouts_total(),
            }),
            // Filled in by the caller from the readiness probe's cached
            // observation, not by a second query of our own.
            schema_ledger_version: None,
        }
    }
}

/// The fault-injection seam: a readout a test writes by hand, so the
/// cluster shape of both endpoints is reachable from a handler test
/// without a database.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) struct ScriptedClusterStatusSource {
        readout: ClusterReadout,
    }

    impl ScriptedClusterStatusSource {
        pub(crate) fn new(readout: ClusterReadout) -> std::sync::Arc<Self> {
            std::sync::Arc::new(Self { readout })
        }
    }

    #[async_trait::async_trait]
    impl ClusterStatusSource for ScriptedClusterStatusSource {
        async fn read(&self) -> ClusterReadout {
            self.readout.clone()
        }
    }

    /// A two-replica deployment in which nothing is wrong: both members
    /// live and ready on the same version, a projector caught up behind
    /// one live leader, one succeeding singleton job, and a healthy pool.
    pub(crate) fn two_ready_members(first: Uuid, second: Uuid) -> ClusterReadout {
        let member = |instance: Uuid, boot: Uuid| ReplicaFacts {
            instance_id: instance,
            boot_id: boot,
            binary_version: "1.0.1".to_owned(),
            schema_version_min: 10,
            schema_version_max: 10,
            document_version_min: 0,
            document_version_max: 0,
            fingerprint: "b".repeat(64),
            started_at: Some("2026-09-01T10:00:00.000000Z".to_owned()),
            last_heartbeat_at: Some("2026-09-01T10:00:05.000000Z".to_owned()),
            heartbeat_age_secs: Some(1.0),
            ready_at: Some("2026-09-01T10:00:01.000000Z".to_owned()),
            draining_at: None,
            compiled_security_revision: 7,
            observed_security_revision: 7,
            last_error_code: None,
            live: true,
        };
        ClusterReadout {
            members: Some(vec![
                member(first, Uuid::from_u128(11)),
                member(second, Uuid::from_u128(12)),
            ]),
            leader_tasks: Some(vec![LeaderTaskFacts {
                job: "stale_member_sweep".to_owned(),
                fence: 3,
                last_success_age_secs: Some(2.0),
                last_failure_code: None,
            }]),
            projector: Some(ProjectorFacts {
                fence: 3,
                checkpoint_position: 40,
                projected_events: 400,
                leader_instance: Some(second),
                updated_age_secs: 0.25,
            }),
            audit_stream_head: Some(42),
            leading: false,
            pool: Some(PoolFacts {
                size: 4,
                available: 4,
                waiting: 0,
                timeouts_total: 0,
            }),
            schema_ledger_version: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Strings a compromised or misconfigured replica could have written
    /// into its row: a DSN, a host, an address, a query, a raw error --
    /// and the same topology hidden inside a value shaped like something
    /// this surface accepts. The last three matter because every check
    /// here returns the accepted value *whole*: a corpus of bare hostile
    /// strings only ever exercises the outright rejection, never the
    /// branch where a shape check passes and carries its input out with
    /// it.
    const ADVERSARIAL: [&str; 9] = [
        "postgres://gateway:hunter2@db.internal.example:5432/greengateway",
        "10.0.0.5",
        "db-primary.internal.example",
        "SELECT * FROM greengateway.service_tokens",
        "connection to server at \"192.168.1.7\", port 5432 failed",
        "admin@example.com",
        "1.0.0-10.0.0.5",
        "1.0.0+10.0.0.5",
        "0.0.0+db-primary.internal",
    ];

    /// The adversarial values that are also shaped like a hostname.
    /// `safe_hostname` is a shape check and not an address check -- the
    /// field carries this process's own hostname, never a roster value --
    /// so these are excluded from the hostname test and asserted there
    /// separately.
    const HOSTNAME_SHAPED: [&str; 3] =
        ["db-primary.internal.example", "10.0.0.5", "1.0.0-10.0.0.5"];

    fn local_facts() -> LocalFacts {
        LocalFacts {
            cluster_mode: true,
            instance_id: Uuid::from_u128(1),
            boot_id: Uuid::from_u128(2),
            binary_version: "1.0.1".to_owned(),
            fingerprint: "a".repeat(64),
            schema_versions: (10, 10),
            document_versions: (0, 0),
            boot_age_secs: 42,
            // The default: the flag is off, so no hostname is carried.
            hostname: None,
            instance_ready: true,
            draining: false,
            blocked_reason: None,
            compiled_security_revision: 7,
            observed_security_revision: 7,
            reconcile_last_pass_age: Some(Duration::from_secs(1)),
            reconcile_failures_total: 0,
            audit: AuditQueueFacts {
                queue_depth: 3,
                queue_capacity: 8192,
                oldest_age_secs: 0.25,
                dropped_total: 0,
            },
        }
    }

    fn member(instance: u128, live: bool, ready: bool) -> ReplicaFacts {
        ReplicaFacts {
            instance_id: Uuid::from_u128(instance),
            boot_id: Uuid::from_u128(instance + 100),
            binary_version: "1.0.1".to_owned(),
            schema_version_min: 10,
            schema_version_max: 10,
            document_version_min: 0,
            document_version_max: 0,
            fingerprint: "a".repeat(64),
            started_at: Some("2026-09-01T10:00:00.000000Z".to_owned()),
            last_heartbeat_at: Some("2026-09-01T10:00:05.000000Z".to_owned()),
            heartbeat_age_secs: Some(1.5),
            ready_at: ready.then(|| "2026-09-01T10:00:01.000000Z".to_owned()),
            draining_at: None,
            compiled_security_revision: 7,
            observed_security_revision: 7,
            last_error_code: None,
            live,
        }
    }

    fn two_live_members() -> ClusterReadout {
        ClusterReadout {
            members: Some(vec![member(1, true, true), member(2, true, true)]),
            leader_tasks: Some(vec![LeaderTaskFacts {
                job: "audit_retention".to_owned(),
                fence: 4,
                last_success_age_secs: Some(3.5),
                last_failure_code: None,
            }]),
            projector: Some(ProjectorFacts {
                fence: 4,
                checkpoint_position: 120,
                projected_events: 900,
                leader_instance: Some(Uuid::from_u128(2)),
                updated_age_secs: 0.5,
            }),
            audit_stream_head: Some(128),
            leading: true,
            pool: Some(PoolFacts {
                size: 8,
                available: 6,
                waiting: 0,
                timeouts_total: 0,
            }),
            schema_ledger_version: Some(10),
        }
    }

    fn json(value: &impl Serialize) -> String {
        serde_json::to_string(value).expect("the status types must serialize")
    }

    // --- shape ---

    /// Standalone mode serves the same two shapes: it reports itself as
    /// the only replica, says so in `mode`, and leaves the sections that
    /// describe a cluster (the projector, the singleton's jobs, the shared
    /// pool, the shared ledger) `null` rather than inventing them.
    #[test]
    fn standalone_reports_itself_as_the_only_replica_with_no_cluster_sections() {
        let local = LocalFacts {
            cluster_mode: false,
            ..local_facts()
        };
        let status = cluster_status(&local, &ClusterReadout::default());
        assert_eq!(status.mode, MODE_STANDALONE);
        assert!(status.ready);
        assert_eq!(status.state, STATE_READY);
        assert_eq!(status.reason, None);
        assert_eq!(status.replicas.ready, 1);
        assert_eq!(status.replicas.total, 1);
        assert_eq!(status.binary_versions.len(), 1);
        assert_eq!(status.binary_versions[0].version, "1.0.1");
        assert_eq!(status.binary_versions[0].count, 1);
        assert!(status.projector.is_none());
        assert!(status.leader_tasks.is_none());
        assert!(status.pools.database.is_none());
        assert_eq!(status.schema.current_version, None);
        assert_eq!(status.schema.binary_min, 10);
        assert_eq!(status.schema.binary_max, 10);
        assert!(status.schema.compatible);
        assert_eq!(status.local.boot_age_secs, 42);
        assert_eq!(status.local.revision_lag, 0);
        assert_eq!(status.audit.queue_capacity, 8192);

        let replicas = cluster_replicas(&local, &ClusterReadout::default());
        assert_eq!(replicas.replicas.len(), 1);
        let only = &replicas.replicas[0];
        assert_eq!(only.instance_id, local.instance_id.to_string());
        assert_eq!(only.boot_id, local.boot_id.to_string());
        assert!(only.live);
        assert_eq!(only.started_at, None);
        assert_eq!(only.last_heartbeat_at, None);
    }

    /// Cluster mode with two live members: the counts, the version
    /// grouping, the projector lag, the leader table, and the pool all
    /// come from the readout.
    #[test]
    fn cluster_mode_reports_every_section_from_the_readout() {
        let readout = two_live_members();
        let status = cluster_status(&local_facts(), &readout);
        assert_eq!(status.mode, MODE_CLUSTER);
        assert_eq!(status.state, STATE_READY);
        assert_eq!(status.replicas.ready, 2);
        assert_eq!(status.replicas.total, 2);
        assert_eq!(status.binary_versions.len(), 1);
        assert_eq!(status.binary_versions[0].count, 2);
        assert_eq!(status.schema.current_version, Some(10));
        assert!(status.schema.compatible);

        let projector = status.projector.expect("cluster mode reports a projector");
        assert_eq!(projector.fence, 4);
        assert_eq!(projector.checkpoint_position, 120);
        assert_eq!(projector.stream_head, Some(128));
        assert_eq!(projector.lag_events, Some(8));
        assert!(
            projector.leader_present,
            "the row's leader is a live member of the roster"
        );

        let tasks = status
            .leader_tasks
            .expect("cluster mode reports the ledger");
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].name, "audit_retention");
        assert!(tasks[0].held_by_this_instance);
        assert_eq!(tasks[0].fence, 4);
        assert_eq!(tasks[0].last_failure_code, None);

        let pool = status
            .pools
            .database
            .expect("cluster mode reports the pool");
        assert_eq!((pool.size, pool.available, pool.waiting), (8, 6, 0));

        let replicas = cluster_replicas(&local_facts(), &readout);
        assert_eq!(replicas.replicas.len(), 2);
        assert!(replicas.replicas.iter().all(|replica| replica.live));
    }

    /// A projector whose row names a leader that is no longer a live
    /// member is a projector with no leader, whatever the row says.
    #[test]
    fn a_projector_leader_that_is_not_a_live_member_is_not_present() {
        let mut readout = two_live_members();
        readout.projector = Some(ProjectorFacts {
            leader_instance: Some(Uuid::from_u128(999)),
            ..readout.projector.expect("fixture")
        });
        let status = cluster_status(&local_facts(), &readout);
        assert!(!status.projector.expect("projector").leader_present);
    }

    /// Stale rows are not counted as replicas, and the live ones sort
    /// first in the replica list.
    #[test]
    fn stale_members_do_not_count_and_live_members_sort_first() {
        let readout = ClusterReadout {
            members: Some(vec![
                member(1, false, true),
                member(2, true, true),
                member(3, false, false),
            ]),
            ..ClusterReadout::default()
        };
        let status = cluster_status(&local_facts(), &readout);
        assert_eq!(status.replicas.total, 1);
        assert_eq!(status.replicas.ready, 1);

        let replicas = cluster_replicas(&local_facts(), &readout);
        assert_eq!(replicas.replicas.len(), 3);
        assert!(replicas.replicas[0].live);
        assert!(!replicas.replicas[1].live);
        assert!(!replicas.replicas[2].live);
    }

    // --- state and reason ---

    /// The not-ready reasons are the readiness chain's own, unchanged, so
    /// this surface can never disagree with `/readyz`.
    #[test]
    fn the_readiness_chains_reason_is_reported_verbatim() {
        for (reason, draining, expected_state) in [
            ("starting", false, STATE_NOT_READY),
            ("draining", true, STATE_DRAINING),
            ("config_fingerprint_mismatch", false, STATE_NOT_READY),
            ("storage_unavailable", false, STATE_NOT_READY),
            ("schema_incompatible", false, STATE_NOT_READY),
            ("instance_lease_invalid", false, STATE_NOT_READY),
            ("security_revision_not_compiled", false, STATE_NOT_READY),
            ("required_upstream_unavailable", false, STATE_NOT_READY),
        ] {
            let local = LocalFacts {
                blocked_reason: Some(reason),
                draining,
                instance_ready: false,
                ..local_facts()
            };
            let status = cluster_status(&local, &two_live_members());
            assert!(!status.ready, "{reason} must not report ready");
            assert_eq!(status.state, expected_state, "{reason}");
            assert_eq!(status.reason, Some(reason));
        }
    }

    /// Degraded is for a replica that is serving while something is
    /// nonetheless wrong, worst first.
    #[test]
    fn degraded_reasons_are_reported_worst_first() {
        // An unreadable roster.
        let unreadable = ClusterReadout {
            members: None,
            ..two_live_members()
        };
        let status = cluster_status(&local_facts(), &unreadable);
        assert!(status.ready, "the replica itself is still serving");
        assert_eq!(status.state, STATE_DEGRADED);
        assert_eq!(status.reason, Some(REASON_REPLICAS_UNAVAILABLE));
        assert_eq!(status.replicas.total, 0);

        // A watermark behind the authority.
        let lagging = LocalFacts {
            compiled_security_revision: 4,
            observed_security_revision: 9,
            ..local_facts()
        };
        let status = cluster_status(&lagging, &two_live_members());
        assert_eq!(status.state, STATE_DEGRADED);
        assert_eq!(status.reason, Some(REASON_SECURITY_REVISION_LAGGING));
        assert_eq!(status.local.revision_lag, 5);

        // A singleton job that last failed.
        let mut failing = two_live_members();
        failing.leader_tasks = Some(vec![LeaderTaskFacts {
            job: "audit_retention".to_owned(),
            fence: 4,
            last_success_age_secs: Some(600.0),
            last_failure_code: Some("timeout".to_owned()),
        }]);
        let status = cluster_status(&local_facts(), &failing);
        assert_eq!(status.state, STATE_DEGRADED);
        assert_eq!(status.reason, Some(REASON_MAINTENANCE_JOB_FAILING));

        // A member carrying a classified failure on its row.
        let mut erroring = two_live_members();
        erroring.members = Some(vec![
            member(1, true, true),
            ReplicaFacts {
                last_error_code: Some("unavailable".to_owned()),
                ..member(2, true, true)
            },
        ]);
        let status = cluster_status(&local_facts(), &erroring);
        assert_eq!(status.state, STATE_DEGRADED);
        assert_eq!(status.reason, Some(REASON_MEMBER_ERROR_REPORTED));
    }

    /// A ledger outside this binary's manifest range is reported as
    /// incompatible even when the replica has not yet been taken out of
    /// rotation for it.
    #[test]
    fn a_ledger_outside_the_binary_range_is_not_compatible() {
        for ledger in [9, 11] {
            let readout = ClusterReadout {
                schema_ledger_version: Some(ledger),
                ..two_live_members()
            };
            let status = cluster_status(&local_facts(), &readout);
            assert_eq!(status.schema.current_version, Some(ledger));
            assert!(
                !status.schema.compatible,
                "a ledger of {ledger} is outside 10..=10"
            );
        }
    }

    // --- redaction ---

    /// Every string field of both responses, filled with a DSN, a host, an
    /// address, a query, and a raw error: none of it reaches the wire.
    #[test]
    fn adversarial_strings_in_every_string_field_are_replaced_whole() {
        for hostile in ADVERSARIAL {
            let local = LocalFacts {
                binary_version: hostile.to_owned(),
                fingerprint: hostile.to_owned(),
                ..local_facts()
            };
            let readout = ClusterReadout {
                members: Some(vec![ReplicaFacts {
                    binary_version: hostile.to_owned(),
                    fingerprint: hostile.to_owned(),
                    started_at: Some(hostile.to_owned()),
                    last_heartbeat_at: Some(hostile.to_owned()),
                    ready_at: Some(hostile.to_owned()),
                    draining_at: Some(hostile.to_owned()),
                    last_error_code: Some(hostile.to_owned()),
                    ..member(1, true, true)
                }]),
                leader_tasks: Some(vec![LeaderTaskFacts {
                    job: hostile.to_owned(),
                    fence: 1,
                    last_success_age_secs: None,
                    last_failure_code: Some(hostile.to_owned()),
                }]),
                ..two_live_members()
            };

            let status = cluster_status(&local, &readout);
            let replicas = cluster_replicas(&local, &readout);
            for body in [json(&status), json(&replicas)] {
                assert!(
                    !body.contains(hostile),
                    "{hostile} reached the response body: {body}"
                );
                assert_no_secrets(&body);
            }

            // And the same again for the standalone shape, whose replica
            // row is built from the local facts rather than a store row.
            let standalone = LocalFacts {
                cluster_mode: false,
                ..local.clone()
            };
            let empty = ClusterReadout::default();
            for body in [
                json(&cluster_status(&standalone, &empty)),
                json(&cluster_replicas(&standalone, &empty)),
            ] {
                assert!(!body.contains(hostile), "{hostile} reached {body}");
                assert_no_secrets(&body);
            }
        }
    }

    /// The default answer for the one opt-in field: with
    /// `CLUSTER_STATUS_EXPOSE_HOSTNAMES` off, `local.hostname` is `null`
    /// in both modes and the whole-response grep still holds.
    #[test]
    fn no_hostname_is_reported_unless_the_deployment_asked_for_one() {
        for cluster_mode in [true, false] {
            let local = LocalFacts {
                cluster_mode,
                ..local_facts()
            };
            let readout = if cluster_mode {
                two_live_members()
            } else {
                ClusterReadout::default()
            };

            let status = cluster_status(&local, &readout);
            assert_eq!(status.local.hostname, None);
            let body = json(&status);
            assert!(
                body.contains("\"hostname\":null"),
                "the field is present and null rather than absent: {body}"
            );
            assert_no_secrets(&body);
        }
    }

    /// With the flag on, a hostname is reported -- and only a hostname.
    /// Every adversarial value is still dropped whole, so opting in buys
    /// exactly one field of topology and not a free-text channel.
    #[test]
    fn an_opted_in_hostname_is_reported_but_only_when_it_is_shaped_like_one() {
        let named = LocalFacts {
            hostname: Some("greengateway-7d9f6c-abcde".to_owned()),
            ..local_facts()
        };
        let status = cluster_status(&named, &two_live_members());
        assert_eq!(
            status.local.hostname.as_deref(),
            Some("greengateway-7d9f6c-abcde")
        );
        assert!(json(&status).contains("greengateway-7d9f6c-abcde"));

        // A fully qualified name is a hostname too, and survives.
        let fqdn = LocalFacts {
            hostname: Some("gw-3.pods.svc.cluster.local".to_owned()),
            ..local_facts()
        };
        assert_eq!(
            cluster_status(&fqdn, &two_live_members())
                .local
                .hostname
                .as_deref(),
            Some("gw-3.pods.svc.cluster.local")
        );

        // Everything a hostname is not: dropped, and the replicas route
        // never carries the field at all.
        for hostile in ADVERSARIAL
            .iter()
            .copied()
            // A bare hostname *is* a hostname; the rest are not. The
            // address is excluded here and asserted below, because
            // `safe_hostname` is a shape check, not an address check.
            .filter(|value| !HOSTNAME_SHAPED.contains(value))
            .chain([
                "",
                "   ",
                "host name",
                "gw\nX-Injected: 1",
                &"a".repeat(MAX_HOSTNAME_LEN + 1),
            ])
        {
            let local = LocalFacts {
                hostname: Some(hostile.to_owned()),
                ..local_facts()
            };
            let status = cluster_status(&local, &two_live_members());
            assert_eq!(status.local.hostname, None, "{hostile} survived");
            let body = json(&status);
            assert!(
                hostile.trim().is_empty() || !body.contains(hostile),
                "{hostile} reached {body}"
            );
            assert_no_secrets(&body);
            assert!(!json(&cluster_replicas(&local, &two_live_members())).contains("hostname"));
        }

        // The length bound is exact, not approximate.
        let longest = LocalFacts {
            hostname: Some("a".repeat(MAX_HOSTNAME_LEN)),
            ..local_facts()
        };
        assert_eq!(
            cluster_status(&longest, &two_live_members())
                .local
                .hostname
                .map(|value| value.len()),
            Some(MAX_HOSTNAME_LEN)
        );
    }

    /// The second, blunter check the contract names: grep the serialized
    /// JSON for a DSN scheme, an `@`, and a dotted quad.
    fn assert_no_secrets(body: &str) {
        assert!(!body.contains("postgres://"), "a DSN scheme in {body}");
        assert!(!body.contains("postgresql://"), "a DSN scheme in {body}");
        assert!(!body.contains('@'), "an `@` in {body}");
        assert!(
            !contains_dotted_quad(body),
            "something shaped like an IP address in {body}"
        );
    }

    /// Four dot-separated runs of digits anywhere in the text.
    fn contains_dotted_quad(body: &str) -> bool {
        let bytes = body.as_bytes();
        let mut start = 0;
        while start < bytes.len() {
            if !bytes[start].is_ascii_digit()
                || (start > 0 && (bytes[start - 1].is_ascii_digit() || bytes[start - 1] == b'.'))
            {
                start += 1;
                continue;
            }
            let mut index = start;
            let mut components = 0;
            loop {
                let digits_from = index;
                while index < bytes.len() && bytes[index].is_ascii_digit() {
                    index += 1;
                }
                if index == digits_from {
                    break;
                }
                components += 1;
                if components == 4 {
                    return true;
                }
                if index < bytes.len() && bytes[index] == b'.' {
                    index += 1;
                } else {
                    break;
                }
            }
            start += 1;
        }
        false
    }

    #[test]
    fn the_dotted_quad_detector_finds_addresses_and_not_versions() {
        assert!(contains_dotted_quad("host 10.0.0.5 refused"));
        assert!(contains_dotted_quad("\"192.168.1.7\""));
        assert!(!contains_dotted_quad("version 1.0.1"));
        assert!(!contains_dotted_quad("2026-09-01T10:00:00.000000Z"));
        assert!(!contains_dotted_quad("no digits here"));
    }

    #[test]
    fn only_semantic_versions_survive_the_version_check() {
        for accepted in ["1.0.1", "0.0.0", "12.4.98", "1.0.0-rc.1", "1.0.0+build.7"] {
            assert_eq!(safe_version(accepted), accepted);
        }
        for rejected in [
            "10.0.0.1",
            "1.0",
            "",
            "v1.0.1",
            "1.0.1 (db.internal.example)",
            "postgres://u:p@h:5432/d",
            "1.0.1-<script>",
            // The suffix is the part of this value that is free text if
            // nothing checks it, and the whole value is what gets
            // returned: an address or a hostname parked behind the `-`
            // or the `+` reaches both cluster routes and the Cluster
            // page verbatim.
            "1.0.0-10.0.0.5",
            "1.0.0+10.0.0.5",
            "0.5.0+192.168.1.7",
            "1.0.0+db-primary.internal",
            "1.0.0-db.internal.example",
            "0.0.0-172.31.255.254",
        ] {
            assert_eq!(safe_version(rejected), UNKNOWN, "{rejected}");
        }
    }

    /// The dotted-quad predicate the whole-body grep uses, applied to the
    /// version check on its own: whatever `safe_version` returns for any
    /// of the corpus, an address never comes back out of it.
    #[test]
    fn no_accepted_version_carries_an_address() {
        for hostile in ADVERSARIAL {
            let accepted = safe_version(hostile);
            assert!(
                !contains_dotted_quad(&accepted),
                "{hostile} was returned as {accepted}"
            );
        }
    }

    #[test]
    fn only_sixty_four_lowercase_hex_characters_survive_the_fingerprint_check() {
        assert_eq!(safe_fingerprint(&"a".repeat(64)), "a".repeat(64));
        for rejected in [
            "a".repeat(63),
            "A".repeat(64),
            "g".repeat(64),
            String::new(),
            "a".repeat(65),
        ] {
            assert_eq!(safe_fingerprint(&rejected), UNKNOWN);
        }
    }

    #[test]
    fn only_utc_timestamps_survive_the_timestamp_check() {
        for accepted in [
            "2026-09-01T10:00:00.000000Z",
            "2026-09-01T10:00:00Z",
            "2026-09-01T10:00:00.123456789Z",
        ] {
            assert_eq!(safe_timestamp(accepted), Some(accepted.to_owned()));
        }
        for rejected in [
            "2026-09-01 10:00:00Z",
            "2026-09-01T10:00:00+01:00",
            "10.0.0.5",
            "",
            "2026-09-01T10:00:00.Z",
        ] {
            assert_eq!(safe_timestamp(rejected), None, "{rejected}");
        }
    }

    #[test]
    fn only_classified_error_kinds_survive_the_error_code_check() {
        for kind in RepositoryErrorKind::KNOWN {
            assert_eq!(safe_error_code(kind.as_str()), kind.as_str());
        }
        assert_eq!(safe_error_code("connection refused to 10.0.0.5"), UNKNOWN);
        assert_eq!(safe_error_code(""), UNKNOWN);
    }

    #[test]
    fn only_the_singletons_job_names_survive_the_job_name_check() {
        for job in KNOWN_LEADER_TASKS {
            assert_eq!(safe_job_name(job), job);
        }
        assert_eq!(safe_job_name("DROP TABLE greengateway.audit"), UNKNOWN);
    }

    /// The vocabulary this module redacts against must be the singleton's
    /// actual job names, or a real job would be reported as `unknown`.
    #[cfg(feature = "postgres")]
    #[test]
    fn the_leader_task_vocabulary_is_the_singletons_job_names() {
        use crate::cluster_maintenance;
        let mut names = [
            cluster_maintenance::JOB_JWT_REVOCATION_CLEANUP,
            cluster_maintenance::JOB_RATE_LIMIT_IDLE_SWEEP,
            cluster_maintenance::JOB_PENDING_LOGIN_PRUNE,
            cluster_maintenance::JOB_STALE_MEMBER_SWEEP,
            cluster_maintenance::JOB_AUDIT_RETENTION,
            cluster_maintenance::JOB_EXECUTION_LEASE_REAPER,
        ];
        names.sort_unstable();
        assert_eq!(names, KNOWN_LEADER_TASKS);
    }
}
