//! The cluster replay worker (issue #243) against a real PostgreSQL: a
//! takeover after a lost lease resumes from the last checkpoint and counts
//! every record exactly once, a job whose pins cannot be rebuilt is
//! interrupted, and a cancellation a running job's holder never saw ends the
//! job when it is taken over. Gated on the test harness locator: CI sets it,
//! a checkout without a database skips.

use std::{cell::Cell, time::Duration};

use time::format_description::well_known::Rfc3339;

use super::*;
use crate::{
    audit::sink::tests::CaptureSink,
    policy_replay::job::{run, ReplayControl as Control},
    storage::{
        contract_tests::postgres_audit_tests::{
            create_test_database, locator, write_dsn_file, TestDatabase, DATABASE,
        },
        migrations,
        postgres::PostgresFoundation,
        postgres_audit::PostgresAuditEventStore,
        AuditEventStore,
    },
};

/// 2026-01-01T00:00:00Z in audit epoch microseconds.
const BASE_US: i64 = 1_767_225_600_000_000;
const WINDOW: (i64, i64) = (BASE_US, BASE_US + 86_400_000_000);
/// More than two pages of records.
const RECORDS: i64 = 1_100;

fn policy() -> rbac::Policy {
    rbac::Policy::validate_json_value(json!({
        "schema_version": "0.1.0",
        "id": "cluster-replay-jobs",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": { "reader": { "permissions": ["orders:read"] } },
        "rules": [
            { "id": "public-allow", "methods": ["GET"], "path": "/public/**", "action": "allow" }
        ],
        "routes": [
            { "methods": ["GET"], "path_prefix": "/orders", "permission": "orders:read" }
        ]
    }))
    .expect("the test policy validates")
}

fn timestamp(epoch_us: i64) -> String {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(epoch_us) * 1_000)
        .expect("a test timestamp is representable")
        .format(&Rfc3339)
        .expect("a test timestamp formats")
}

fn request_at(epoch_us: i64, path: &str) -> audit::AuditEvent {
    let mut event = audit::AuditEvent::new(
        "http.request_observed",
        "cluster-replay-worker-request",
        "198.51.100.42",
        None,
        json!({
            "method": "GET",
            "path": path,
            "status": 200,
            "policy_decision": if path.starts_with("/public") { "allowed" } else { "denied" },
            "routing_context_known": true,
        }),
    );
    event.timestamp = timestamp(epoch_us);
    event
}

/// One migrated database with a retained window in its audit stream, and
/// two replicas' replay jobs over it.
struct Cluster {
    pool: deadpool_postgres::Pool,
    settings: config::DatabaseSettings,
    replica_a: ClusterPolicyReplays,
    replica_b: ClusterPolicyReplays,
    capture: CaptureSink,
    audit: audit::AuditLog,
    _database: TestDatabase,
}

impl Cluster {
    async fn new(database: TestDatabase) -> Self {
        let dsn_file = write_dsn_file(&database.dsn);
        let mut config = crate::config::Config::test_defaults();
        config.state_backend = crate::config::StateBackend::Postgres;
        config.deployment_id = Some("deploy-replay-worker".to_owned());
        config.database.url_file = Some(dsn_file.path.clone());
        config.database.tls_mode = crate::config::DatabaseTlsMode::LoopbackDev;
        let foundation = PostgresFoundation::establish(&config)
            .await
            .expect("the test database should establish");
        migrations::apply_missing_for_startup(foundation.pool(), &config.database)
            .await
            .expect("the schema should migrate");
        let pool = foundation.pool().clone();
        let events = (0..RECORDS)
            .map(|index| {
                let path = if index % 3 == 0 {
                    "/orders/1"
                } else {
                    "/public/a"
                };
                request_at(BASE_US + index * 1_000_000, path)
            })
            .collect::<Vec<_>>();
        PostgresAuditEventStore::new(pool.clone(), None)
            .insert_events(&events)
            .await
            .expect("the audit batch commits");
        let replica =
            || ClusterPolicyReplays::new(pool.clone(), &config.database, uuid::Uuid::new_v4());
        let capture = CaptureSink::new();
        Self {
            replica_a: replica(),
            replica_b: replica(),
            audit: audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>),
            capture,
            pool,
            settings: config.database,
            _database: database,
        }
    }

    async fn execute(&self, sql: &str) {
        self.pool
            .get()
            .await
            .expect("checkout")
            .batch_execute(sql)
            .await
            .expect("fixture statement");
    }

    fn scope(&self, cutoff: audit::query::ReplayCutoff) -> ReplayScope {
        ReplayScope {
            from: timestamp(WINDOW.0),
            to: timestamp(WINDOW.1),
            from_epoch_us: WINDOW.0,
            to_epoch_us: WINDOW.1,
            cutoff,
            max_records: policy_replay::job::MAX_REPLAY_RECORDS,
        }
    }

    /// Admit and queue one job of `subject`'s over the window, with the
    /// active policy as its candidate.
    async fn admit(&self, n: u8, engine: &str, base_json: Option<&str>) -> PolicyReplayJobSpec {
        let cutoff = self
            .replica_a
            .reader()
            .cutoff(WINDOW.0, WINDOW.1)
            .await
            .expect("the cutoff reads");
        let scope = self.scope(cutoff);
        let policy = policy();
        let etag = crate::policy_etag(&policy).expect("the policy has an ETag");
        let mut documents = pinned_documents(&policy, None).expect("the policy pins");
        if let Some(base_json) = base_json {
            documents.base_json = base_json.to_owned();
        }
        let spec = PolicyReplayJobSpec {
            job_id: format!("rpl_{}", format!("{n:02x}").repeat(16)),
            owner: PolicyReplayOwner {
                issuer: String::new(),
                subject: format!("replayer-{n}"),
            },
            idempotency_key: None,
            request_digest: format!("sha256:{}", "e".repeat(64)),
            actor_json: r#"{"user_id":"replayer","auth_mode":"bearer_token"}"#.to_owned(),
            request_id: "cluster-replay-worker-admission".to_owned(),
            source_ip: "198.51.100.43".to_owned(),
            base_etag: etag.clone(),
            candidate_source: "active".to_owned(),
            candidate_etag: etag,
            edit_count: 0,
            projections: "as_authored".to_owned(),
            engine_version: engine.to_owned(),
            window_from: scope.from.clone(),
            window_to: scope.to.clone(),
            from_epoch_us: scope.from_epoch_us,
            to_epoch_us: scope.to_epoch_us,
            high_water: scope.cutoff.high_water,
            selected_records: i64::try_from(scope.cutoff.selected).expect("fits"),
            first_position: scope.cutoff.first_id,
            last_position: scope.cutoff.last_id,
            max_records: i32::try_from(scope.max_records).expect("fits"),
        };
        assert!(matches!(
            self.replica_a.store().create(&spec, &documents).await,
            Ok(PolicyReplayCreated::Created(_))
        ));
        assert!(self
            .replica_a
            .store()
            .admit(&spec.job_id)
            .await
            .expect("admit"));
        spec
    }

    async fn record(&self, spec: &PolicyReplayJobSpec) -> PolicyReplayJobRecord {
        self.replica_a
            .store()
            .get(&spec.owner, &spec.job_id)
            .await
            .expect("get")
            .expect("the job exists")
    }

    /// The uninterrupted run over the same cutoff and policy: what any
    /// number of takeovers must reproduce byte for byte.
    async fn uninterrupted(&self, spec: &PolicyReplayJobSpec) -> ReplayOutcome {
        let reader = PostgresReplayReader::new(
            self.pool.clone(),
            &self.settings,
            tokio::runtime::Handle::current(),
        );
        let scope = scope_from(spec).expect("the spec reads back");
        tokio::task::spawn_blocking(move || {
            let policies = ReplayPolicies::compile(&policy(), None, &[Projection::AsAuthored])
                .expect("the policy compiles");
            run(
                &reader,
                &policies,
                &scope,
                Instant::now() + Duration::from_secs(60),
                &Control::default(),
            )
        })
        .await
        .expect("the run joins")
        .expect("the run completes")
    }

    /// The payloads of the `event_type` events, once at least `count` have
    /// been delivered: the audit writer delivers on its own thread.
    async fn events(&self, event_type: &str, count: usize) -> Vec<Value> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let events = self
                .capture
                .events()
                .into_iter()
                .filter(|event| event.event_type == event_type)
                .map(|event| event.payload)
                .collect::<Vec<_>>();
            if events.len() >= count {
                return events;
            }
            assert!(
                Instant::now() < deadline,
                "the audit writer should deliver {count} {event_type} event(s)"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

/// A sink that stores its first checkpoint, then reports the lease lost, as
/// a replica that stalled past its lease would see at its next page.
struct LoseLeaseAfterOnePage {
    inner: StoredCheckpoints,
    pages: Cell<usize>,
}

impl ReplayCheckpoints for LoseLeaseAfterOnePage {
    fn page_done(&self, after_id: i64, scanned: u64, checkpoint: &Value) -> Result<(), ReplayStop> {
        self.pages.set(self.pages.get() + 1);
        self.inner.page_done(after_id, scanned, checkpoint)?;
        Err(ReplayStop::Released)
    }
}

macro_rules! cluster {
    () => {{
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let guard = DATABASE.lock().await;
        (
            Cluster::new(create_test_database(&admin_dsn).await).await,
            guard,
        )
    }};
}

/// The acceptance criterion of #243's cluster replay: replica A reads one
/// page, checkpoints it under its fence, and loses its lease; replica B
/// takes the job over, resumes from A's checkpoint, and publishes a result
/// byte-identical to an uninterrupted run's -- every record counted once,
/// none twice and none skipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_takeover_after_a_lost_lease_counts_every_record_exactly_once() {
    let (cluster, _guard) = cluster!();
    let spec = cluster.admit(1, &engine_version(), None).await;
    let expected = cluster.uninterrupted(&spec).await;
    assert!(expected.complete);
    assert_eq!(expected.scanned, u64::try_from(RECORDS).expect("fits"));

    // Replica A: one page, checkpointed, then the lease is gone.
    let claim = cluster
        .replica_a
        .store()
        .claim(REPLAY_RUN_DEADLINE)
        .await
        .expect("claim")
        .expect("the job is claimable");
    let sink = LoseLeaseAfterOnePage {
        inner: StoredCheckpoints {
            store: cluster.replica_a.store().clone(),
            lease: claim.lease.clone(),
            runtime: tokio::runtime::Handle::current(),
        },
        pages: Cell::new(0),
    };
    let reader = cluster.replica_a.reader();
    let scope = scope_from(&spec).expect("the spec reads back");
    let stopped = tokio::task::spawn_blocking(move || {
        let policies = ReplayPolicies::compile(&policy(), None, &[Projection::AsAuthored])
            .expect("the policy compiles");
        let stop = run_resumable(
            &reader,
            &policies,
            &scope,
            Instant::now() + Duration::from_secs(60),
            &Control::default(),
            None,
            Some(&sink),
        );
        (stop.err(), sink.pages.get())
    })
    .await
    .expect("the run joins");
    assert_eq!(stopped, (Some(ReplayStop::Released), 1));
    let checkpointed = cluster.record(&spec).await;
    assert_eq!(checkpointed.status.state, "running");
    assert_eq!(
        checkpointed.status.scanned_records,
        i64::try_from(policy_replay::job::REPLAY_PAGE_RECORDS).expect("fits"),
        "one whole page is on the record"
    );
    cluster
        .execute(&format!(
            "UPDATE greengateway.policy_replay_jobs \
             SET lease_expires_at = now() - interval '1 second' WHERE job_id = '{}'",
            spec.job_id
        ))
        .await;

    // Replica B takes it over and finishes it.
    assert!(cluster.replica_b.run_one(&cluster.audit).await);
    let finished = cluster.record(&spec).await;
    assert_eq!(finished.status.state, "completed");
    assert_eq!(
        finished.status.scanned_records,
        i64::try_from(RECORDS).expect("fits"),
        "no record read twice"
    );
    let (document, digest) = finished.status.result.expect("the result is served");
    assert_eq!(
        digest, expected.digest,
        "byte-identical to an uninterrupted run"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&document).expect("the result parses"),
        expected.result
    );
    let completed = cluster
        .events(audit::event::POLICY_REPLAY_COMPLETED, 1)
        .await;
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0]["result_digest"], json!(expected.digest));
    assert_eq!(completed[0]["scanned_records"], json!(RECORDS));
    // The old holder can no longer change anything.
    assert!(!cluster
        .replica_a
        .store()
        .finish(
            &claim.lease,
            &PolicyReplayEnding {
                state: "failed",
                failure: Some("internal"),
                scanned_records: 0,
                result: None,
            },
        )
        .await
        .expect("the stale ending runs"));
    assert_eq!(cluster.record(&spec).await.status.state, "completed");
}

/// A job admitted under another engine, or whose pinned base no longer
/// reproduces its ETag, is never run here: it is interrupted with a stable
/// reason and no result.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_job_whose_pins_cannot_be_rebuilt_is_interrupted() {
    let (cluster, _guard) = cluster!();
    let other_engine = cluster
        .admit(1, "gg-http-alias-v0 1 older-engine", None)
        .await;
    assert!(cluster.replica_b.run_one(&cluster.audit).await);
    let record = cluster.record(&other_engine).await;
    assert_eq!(record.status.state, "interrupted");
    assert_eq!(
        record.status.failure.as_deref(),
        Some("engine_version_changed")
    );
    assert_eq!(record.status.result, None);

    let tampered = cluster
        .admit(
            2,
            &engine_version(),
            Some(r#"{"schema_version":"0.1.0","id":"other","default_action":"allow","enforcement_mode":"enforce"}"#),
        )
        .await;
    assert!(cluster.replica_b.run_one(&cluster.audit).await);
    let record = cluster.record(&tampered).await;
    assert_eq!(record.status.state, "interrupted");
    assert_eq!(record.status.failure.as_deref(), Some("pins_unreadable"));

    let interrupted = cluster
        .events(audit::event::POLICY_REPLAY_INTERRUPTED, 2)
        .await;
    assert_eq!(interrupted.len(), 2);
    assert_eq!(interrupted[0]["reason"], json!("engine_version_changed"));
    assert_eq!(interrupted[1]["reason"], json!("pins_unreadable"));
    assert!(cluster
        .events(audit::event::POLICY_REPLAY_COMPLETED, 0)
        .await
        .is_empty());
    let view = ClusterJob::from_record(&record).expect("the record reads");
    assert_eq!(job_view(&view.view(), None)["state"], json!("interrupted"));
}

/// A job claimed past its takeover limit is interrupted rather than run
/// again; a running job's cancellation, requested while its holder was
/// gone, ends it at the takeover without reading a record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_takeover_honours_cancellation_and_the_takeover_limit() {
    let (cluster, _guard) = cluster!();
    let cancelled = cluster.admit(1, &engine_version(), None).await;
    let claim = cluster
        .replica_a
        .store()
        .claim(REPLAY_RUN_DEADLINE)
        .await
        .expect("claim")
        .expect("the job is claimable");
    assert!(matches!(
        cluster
            .replica_a
            .store()
            .cancel(&cancelled.owner, &cancelled.job_id)
            .await,
        Ok(PolicyReplayCancel::Requested(_))
    ));
    cluster
        .execute(&format!(
            "UPDATE greengateway.policy_replay_jobs \
             SET lease_expires_at = now() - interval '1 second' WHERE job_id = '{}'",
            claim.lease.job_id
        ))
        .await;
    assert!(cluster.replica_b.run_one(&cluster.audit).await);
    let record = cluster.record(&cancelled).await;
    assert_eq!(record.status.state, "cancelled");
    assert_eq!(record.status.scanned_records, 0);
    assert_eq!(
        cluster
            .events(audit::event::POLICY_REPLAY_CANCELLED, 1)
            .await
            .len(),
        1
    );

    let limited = cluster.admit(2, &engine_version(), None).await;
    cluster
        .execute(&format!(
            "UPDATE greengateway.policy_replay_jobs SET claims = {CLUSTER_REPLAY_MAX_CLAIMS} \
             WHERE job_id = '{}'",
            limited.job_id
        ))
        .await;
    assert!(cluster.replica_b.run_one(&cluster.audit).await);
    let record = cluster.record(&limited).await;
    assert_eq!(record.status.state, "interrupted");
    assert_eq!(record.status.failure.as_deref(), Some("takeover_limit"));
}

/// The deadline a takeover resumes under is what is left of the job's:
/// a job whose deadline has passed reads no further and is incomplete,
/// never complete.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_takeover_keeps_the_jobs_deadline() {
    let (cluster, _guard) = cluster!();
    let spec = cluster.admit(1, &engine_version(), None).await;
    cluster
        .execute(&format!(
            "UPDATE greengateway.policy_replay_jobs \
             SET run_deadline_at = now() - interval '1 second' WHERE job_id = '{}'",
            spec.job_id
        ))
        .await;
    assert!(cluster.replica_b.run_one(&cluster.audit).await);
    let record = cluster.record(&spec).await;
    assert_eq!(record.status.state, "completed_incomplete");
    let (document, _) = record.status.result.expect("the result is served");
    let result = serde_json::from_str::<Value>(&document).expect("the result parses");
    assert_eq!(result["complete"], json!(false));
    assert!(result["limitations"]
        .as_array()
        .expect("limitations")
        .contains(&json!("deadline_exceeded")));
}
