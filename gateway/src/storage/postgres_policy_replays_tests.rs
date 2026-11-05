//! The cluster replay job store (issue #243) against a real PostgreSQL:
//! admission and its quotas, idempotency, claims and takeovers under fenced
//! leases, checkpoints, cancellation, endings and retention. Gated on the
//! test harness locator: CI sets it, a checkout without a database skips.

use std::time::Duration;

use super::*;
use crate::storage::{
    contract_tests::postgres_audit_tests::{
        create_test_database, locator, write_dsn_file, TestDatabase, DATABASE,
    },
    migrations,
    postgres::PostgresFoundation,
};

const TTL: Duration = Duration::from_secs(30);
const DEADLINE: Duration = Duration::from_secs(60);
const DIGEST_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ETAG: &str = "\"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"";
const RESULT_DIGEST: &str =
    "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

fn limits() -> PolicyReplayLimits {
    PolicyReplayLimits {
        max_pending: 3,
        max_pending_per_owner: 1,
        max_retained: 5,
        max_retained_per_owner: 3,
        result_ttl: Duration::from_secs(900),
        expired_retention: Duration::from_secs(3600),
        admission_grace: Duration::from_secs(60),
        prune_batch: 64,
    }
}

/// One migrated test database and a store over it, as replica `A`.
struct Jobs {
    pool: deadpool_postgres::Pool,
    store: PostgresPolicyReplayStore,
    _database: TestDatabase,
}

impl Jobs {
    async fn new(database: TestDatabase) -> Self {
        let dsn_file = write_dsn_file(&database.dsn);
        let mut config = crate::config::Config::test_defaults();
        config.state_backend = crate::config::StateBackend::Postgres;
        config.deployment_id = Some("deploy-replay-jobs".to_owned());
        config.database.url_file = Some(dsn_file.path.clone());
        config.database.tls_mode = crate::config::DatabaseTlsMode::LoopbackDev;
        let foundation = PostgresFoundation::establish(&config)
            .await
            .expect("the test database should establish");
        migrations::apply_missing_for_startup(foundation.pool(), &config.database)
            .await
            .expect("the schema should migrate");
        let pool = foundation.pool().clone();
        Self {
            store: PostgresPolicyReplayStore::new(
                pool.clone(),
                uuid::Uuid::new_v4(),
                TTL,
                limits(),
            ),
            pool,
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

    async fn count(&self) -> i64 {
        self.pool
            .get()
            .await
            .expect("checkout")
            .query_one("SELECT count(*) FROM greengateway.policy_replay_jobs", &[])
            .await
            .expect("count")
            .get(0)
    }

    /// Expire `job_id`'s lease now, as a holder that stopped renewing would
    /// leave it.
    async fn lapse(&self, job_id: &str) {
        self.execute(&format!(
            "UPDATE greengateway.policy_replay_jobs \
             SET lease_expires_at = now() - interval '1 second' WHERE job_id = '{job_id}'"
        ))
        .await;
    }

    /// Admit and queue a job of `owner`'s.
    async fn queued(&self, spec: &PolicyReplayJobSpec) -> PolicyReplayJobRecord {
        let record = match self.store.create(spec, &documents()).await {
            Ok(PolicyReplayCreated::Created(record)) => *record,
            other => panic!("the job should be admitted: {other:?}"),
        };
        assert!(self.store.admit(&spec.job_id).await.expect("admit"));
        record
    }
}

fn owner(subject: &str) -> PolicyReplayOwner {
    PolicyReplayOwner {
        issuer: "https://issuer.example".to_owned(),
        subject: subject.to_owned(),
    }
}

fn job_id(n: u8) -> String {
    format!("rpl_{}", format!("{n:02x}").repeat(16))
}

fn spec(n: u8, owner: PolicyReplayOwner, key: Option<&str>, digest: &str) -> PolicyReplayJobSpec {
    PolicyReplayJobSpec {
        job_id: job_id(n),
        owner,
        idempotency_key: key.map(str::to_owned),
        request_digest: digest.to_owned(),
        actor_json: r#"{"user_id":"replayer","auth_mode":"bearer_token"}"#.to_owned(),
        request_id: "replay-job-store-request".to_owned(),
        source_ip: "198.51.100.7".to_owned(),
        base_etag: ETAG.to_owned(),
        candidate_source: "active".to_owned(),
        candidate_etag: ETAG.to_owned(),
        edit_count: 0,
        candidate_draft: None,
        candidate_version: None,
        projections: "as_authored".to_owned(),
        engine_version: "test-engine".to_owned(),
        window_from: "2026-01-01T00:00:00Z".to_owned(),
        window_to: "2026-01-02T00:00:00Z".to_owned(),
        from_epoch_us: 1_767_225_600_000_000,
        to_epoch_us: 1_767_312_000_000_000,
        high_water: 9,
        selected_records: 3,
        first_position: Some(2),
        last_position: Some(4),
        max_records: 100_000,
    }
}

fn documents() -> PolicyReplayDocuments {
    PolicyReplayDocuments {
        base_json: r#"{"schema_version":"0.1.0"}"#.to_owned(),
        candidate_json: None,
    }
}

fn ending(state: &'static str, result: bool) -> PolicyReplayEnding {
    PolicyReplayEnding {
        state,
        failure: None,
        scanned_records: 3,
        result: result.then(|| (r#"{"complete":true}"#.to_owned(), RESULT_DIGEST.to_owned())),
    }
}

async fn claim(store: &PostgresPolicyReplayStore) -> PolicyReplayClaim {
    store
        .claim(DEADLINE)
        .await
        .expect("the claim runs")
        .expect("a job is claimable")
}

macro_rules! database {
    () => {{
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let guard = DATABASE.lock().await;
        (
            Jobs::new(create_test_database(&admin_dsn).await).await,
            guard,
        )
    }};
}

/// The same key and the same request are the same job, whichever replica
/// answers; the same key with another request is a conflict; and neither
/// inserts a row.
#[tokio::test]
async fn an_idempotency_key_names_one_job_per_owner() {
    let (jobs, _guard) = database!();
    let first = jobs
        .queued(&spec(1, owner("alice"), Some("nightly"), DIGEST_A))
        .await;
    let replica_b = jobs.store.as_holder(uuid::Uuid::new_v4());
    let retried = replica_b
        .create(
            &spec(2, owner("alice"), Some("nightly"), DIGEST_A),
            &documents(),
        )
        .await
        .expect("the retry runs");
    match retried {
        PolicyReplayCreated::Existing(existing) => {
            assert_eq!(existing.spec.job_id, first.spec.job_id);
        }
        other => panic!("a retry names the existing job: {other:?}"),
    }
    assert_eq!(
        replica_b
            .create(
                &spec(3, owner("alice"), Some("nightly"), DIGEST_B),
                &documents()
            )
            .await
            .expect("the conflicting request runs"),
        PolicyReplayCreated::IdempotencyConflict
    );
    let found = jobs
        .store
        .find_idempotent(&owner("alice"), "nightly")
        .await
        .expect("the lookup runs")
        .expect("the key names a job");
    assert_eq!(found.spec.job_id, first.spec.job_id);
    // Another owner's key is its own.
    assert!(jobs
        .store
        .find_idempotent(&owner("bob"), "nightly")
        .await
        .expect("the lookup runs")
        .is_none());
    assert_eq!(jobs.count().await, 1, "neither retry inserted a row");
}

/// Pending and retained jobs are bounded per owner and per deployment in
/// SQL; a refusal never ends, deletes or evicts another job.
#[tokio::test]
async fn quotas_refuse_without_evicting_any_job() {
    let (jobs, _guard) = database!();
    jobs.queued(&spec(1, owner("alice"), None, DIGEST_A)).await;
    assert_eq!(
        jobs.store
            .create(&spec(2, owner("alice"), None, DIGEST_A), &documents())
            .await
            .expect("the admission runs"),
        PolicyReplayCreated::Busy,
        "one pending job per owner"
    );
    jobs.queued(&spec(3, owner("bob"), None, DIGEST_A)).await;
    jobs.queued(&spec(4, owner("carol"), None, DIGEST_A)).await;
    assert_eq!(
        jobs.store
            .create(&spec(5, owner("dave"), None, DIGEST_A), &documents())
            .await
            .expect("the admission runs"),
        PolicyReplayCreated::Busy,
        "three pending jobs per deployment"
    );
    assert_eq!(
        jobs.store
            .precheck(&owner("dave"))
            .await
            .expect("the precheck runs"),
        Some(PolicyReplayCreated::Busy)
    );
    // Finish alice's job: it no longer counts as pending, but is retained.
    let claimed = claim(&jobs.store).await;
    assert_eq!(claimed.record.spec.job_id, job_id(1), "oldest first");
    assert!(jobs
        .store
        .finish(&claimed.lease, &ending("completed", true))
        .await
        .expect("the ending runs"));
    jobs.queued(&spec(6, owner("alice"), None, DIGEST_A)).await;
    let claimed = claim(&jobs.store).await;
    assert_eq!(claimed.record.spec.job_id, job_id(3));
    assert!(jobs
        .store
        .finish(&claimed.lease, &ending("failed", false))
        .await
        .expect("the ending runs"));
    // Five unexpired jobs: the deployment's retained bound.
    jobs.queued(&spec(7, owner("erin"), None, DIGEST_A)).await;
    assert_eq!(
        jobs.store
            .create(&spec(8, owner("frank"), None, DIGEST_A), &documents())
            .await
            .expect("the admission runs"),
        PolicyReplayCreated::Busy,
        "still three pending"
    );
    let claimed = claim(&jobs.store).await;
    assert!(jobs
        .store
        .finish(&claimed.lease, &ending("cancelled", false))
        .await
        .expect("the ending runs"));
    assert_eq!(
        jobs.store
            .create(&spec(8, owner("frank"), None, DIGEST_A), &documents())
            .await
            .expect("the admission runs"),
        PolicyReplayCreated::QuotaExhausted,
        "five unexpired jobs per deployment"
    );
    assert_eq!(jobs.count().await, 5, "no job was evicted to make room");
    // An expired result frees its slot; nothing else does.
    jobs.execute(
        "UPDATE greengateway.policy_replay_jobs SET result_expires_at = now() - interval '1 second', \
         finished_at = now() - interval '2 seconds' WHERE state = 'completed'",
    )
    .await;
    assert!(matches!(
        jobs.store
            .create(&spec(8, owner("frank"), None, DIGEST_A), &documents())
            .await
            .expect("the admission runs"),
        PolicyReplayCreated::Created(_)
    ));
}

/// A takeover after a lost lease: the next claim carries a larger fence and
/// the last checkpoint, and the old holder's checkpoint, renewal, ending and
/// release all match nothing.
#[tokio::test]
async fn a_lapsed_lease_is_taken_over_and_the_old_holder_is_fenced_out() {
    let (jobs, _guard) = database!();
    jobs.queued(&spec(1, owner("alice"), None, DIGEST_A)).await;
    let replica_a = &jobs.store;
    let replica_b = jobs.store.as_holder(uuid::Uuid::new_v4());
    let first = claim(replica_a).await;
    assert_eq!(first.claims, 1);
    assert_eq!(first.checkpoint, None);
    assert!(first.remaining_deadline > Duration::from_secs(50));
    assert!(
        replica_b.claim(DEADLINE).await.expect("claim").is_none(),
        "a live lease is never taken"
    );
    assert_eq!(
        replica_a
            .checkpoint(&first.lease, 3, 2, r#"{"after_id":3}"#)
            .await
            .expect("checkpoint"),
        PolicyReplayLeaseStatus::Held {
            cancel_requested: false
        }
    );

    jobs.lapse(&first.record.spec.job_id).await;
    let second = claim(&replica_b).await;
    assert!(
        second.lease.fence > first.lease.fence,
        "a takeover's fence is larger"
    );
    assert_eq!(second.claims, 2);
    assert_eq!(
        second
            .checkpoint
            .as_deref()
            .map(serde_json::from_str::<serde_json::Value>),
        Some(Ok(serde_json::json!({ "after_id": 3 }))),
        "the takeover resumes from the last checkpoint"
    );
    assert_eq!(second.record.status.scanned_records, 2);
    assert!(
        second.remaining_deadline <= first.remaining_deadline,
        "the run deadline is the job's, kept across takeovers"
    );

    assert_eq!(
        replica_a
            .checkpoint(&first.lease, 4, 3, r#"{"after_id":4}"#)
            .await
            .expect("checkpoint"),
        PolicyReplayLeaseStatus::Lost
    );
    assert_eq!(
        replica_a.renew(&first.lease).await.expect("renew"),
        PolicyReplayLeaseStatus::Lost
    );
    assert!(!replica_a
        .finish(&first.lease, &ending("completed", true))
        .await
        .expect("the stale ending runs"));
    replica_a.release(&first.lease).await.expect("release");
    let still_b = replica_b.claim(DEADLINE).await.expect("claim");
    assert!(still_b.is_none(), "the old holder's release freed nothing");

    assert!(replica_b
        .finish(&second.lease, &ending("completed", true))
        .await
        .expect("the ending runs"));
    let record = replica_b
        .get(&owner("alice"), &job_id(1))
        .await
        .expect("get")
        .expect("the job exists");
    assert_eq!(record.status.state, "completed");
    assert_eq!(
        record.status.result,
        Some((r#"{"complete": true}"#.to_owned(), RESULT_DIGEST.to_owned()))
    );
}

/// A job given back at shutdown is claimed at once and the claim does not
/// count toward its takeovers.
#[tokio::test]
async fn a_job_given_back_at_shutdown_is_resumed_without_counting_a_takeover() {
    let (jobs, _guard) = database!();
    jobs.queued(&spec(1, owner("alice"), None, DIGEST_A)).await;
    let first = claim(&jobs.store).await;
    jobs.store.release(&first.lease).await.expect("release");
    let replica_b = jobs.store.as_holder(uuid::Uuid::new_v4());
    let second = claim(&replica_b).await;
    assert_eq!(second.claims, 1, "a release gives its claim back");
    assert!(second.lease.fence > first.lease.fence);
}

/// `DELETE` ends a queued job, asks a running one to stop -- which its next
/// checkpoint or renewal reports -- and discards a finished one; another
/// owner's job is not found.
#[tokio::test]
async fn cancellation_ends_a_queued_job_and_signals_a_running_one() {
    let (jobs, _guard) = database!();
    jobs.queued(&spec(1, owner("alice"), None, DIGEST_A)).await;
    assert_eq!(
        jobs.store
            .cancel(&owner("bob"), &job_id(1))
            .await
            .expect("cancel"),
        PolicyReplayCancel::NotFound,
        "another owner's job is a missing one"
    );
    match jobs
        .store
        .cancel(&owner("alice"), &job_id(1))
        .await
        .expect("cancel")
    {
        PolicyReplayCancel::Cancelled(record) => {
            assert_eq!(record.status.state, "cancelled");
            assert!(record.status.finished_at_us.is_some());
        }
        other => panic!("a queued job ends at once: {other:?}"),
    }
    assert!(
        jobs.store.claim(DEADLINE).await.expect("claim").is_none(),
        "a cancelled job is never claimed"
    );
    assert_eq!(
        jobs.store
            .cancel(&owner("alice"), &job_id(1))
            .await
            .expect("cancel"),
        PolicyReplayCancel::Discarded
    );
    assert_eq!(jobs.count().await, 0);

    jobs.queued(&spec(2, owner("alice"), None, DIGEST_A)).await;
    let running = claim(&jobs.store).await;
    assert!(matches!(
        jobs.store
            .cancel(&owner("alice"), &job_id(2))
            .await
            .expect("cancel"),
        PolicyReplayCancel::Requested(_)
    ));
    assert_eq!(
        jobs.store
            .checkpoint(&running.lease, 3, 1, r#"{"after_id":3}"#)
            .await
            .expect("checkpoint"),
        PolicyReplayLeaseStatus::Held {
            cancel_requested: true
        },
        "the running job learns of it at its next page"
    );
    assert_eq!(
        jobs.store.renew(&running.lease).await.expect("renew"),
        PolicyReplayLeaseStatus::Held {
            cancel_requested: true
        }
    );
    // A takeover sees it too, before running anything.
    jobs.lapse(&job_id(2)).await;
    let taken = claim(&jobs.store.as_holder(uuid::Uuid::new_v4())).await;
    assert!(taken.record.status.cancel_requested);
}

/// A finished job serves its result until its TTL, then reads expired with
/// no result, and retention deletes it after its retention -- a bounded
/// batch at a time. A pending job is never pruned; an admission whose start
/// was never recorded is, after the grace.
#[tokio::test]
async fn results_expire_and_retention_never_touches_a_pending_job() {
    let (jobs, _guard) = database!();
    jobs.queued(&spec(1, owner("alice"), None, DIGEST_A)).await;
    let claimed = claim(&jobs.store).await;
    assert!(jobs
        .store
        .finish(&claimed.lease, &ending("completed", true))
        .await
        .expect("the ending runs"));
    let served = jobs
        .store
        .get(&owner("alice"), &job_id(1))
        .await
        .expect("get")
        .expect("the job exists");
    assert!(!served.status.result_expired);
    assert!(served.status.result.is_some());

    jobs.execute(
        "UPDATE greengateway.policy_replay_jobs SET finished_at = now() - interval '2 hours', \
         result_expires_at = now() - interval '1 hour', expires_at = now() + interval '1 hour'",
    )
    .await;
    let expired = jobs
        .store
        .get(&owner("alice"), &job_id(1))
        .await
        .expect("get")
        .expect("the job is still retained");
    assert!(expired.status.result_expired);
    assert_eq!(
        expired.status.result, None,
        "an expired result is never served"
    );
    assert_eq!(
        jobs.store.prune().await.expect("prune"),
        1,
        "its result is cleared"
    );

    // Pending jobs, and an admission still inside its grace, stay.
    jobs.queued(&spec(2, owner("bob"), None, DIGEST_A)).await;
    let _ = jobs
        .store
        .create(&spec(3, owner("carol"), None, DIGEST_A), &documents())
        .await
        .expect("the admission runs");
    jobs.execute(
        "UPDATE greengateway.policy_replay_jobs SET expires_at = now() - interval '1 second' \
         WHERE job_id = 'rpl_01010101010101010101010101010101'",
    )
    .await;
    assert_eq!(
        jobs.store.prune().await.expect("prune"),
        1,
        "the finished job goes"
    );
    assert_eq!(jobs.count().await, 2, "the pending ones stay");
    jobs.execute(
        "UPDATE greengateway.policy_replay_jobs SET created_at = now() - interval '2 minutes' \
         WHERE state = 'admitting'",
    )
    .await;
    assert_eq!(
        jobs.store.prune().await.expect("prune"),
        1,
        "an admission never recorded is abandoned after its grace"
    );
    let remaining = jobs
        .store
        .get(&owner("bob"), &job_id(2))
        .await
        .expect("get")
        .expect("the queued job remains");
    assert_eq!(remaining.status.state, "queued");
    assert!(!jobs.store.admit(&job_id(3)).await.expect("admit"));
}

/// A job is claimable only once its start is recorded, and withdrawing an
/// unrecorded admission leaves nothing behind.
#[tokio::test]
async fn an_admitting_job_is_never_claimed() {
    let (jobs, _guard) = database!();
    let created = jobs
        .store
        .create(&spec(1, owner("alice"), None, DIGEST_A), &documents())
        .await
        .expect("the admission runs");
    assert!(matches!(created, PolicyReplayCreated::Created(_)));
    assert!(jobs.store.claim(DEADLINE).await.expect("claim").is_none());
    jobs.store.withdraw(&job_id(1)).await.expect("withdraw");
    assert_eq!(jobs.count().await, 0);
}
