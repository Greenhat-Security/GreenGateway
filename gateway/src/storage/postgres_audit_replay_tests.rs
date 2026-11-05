//! The cluster audit stream's replay reader (issue #243): its cutoff, its
//! pages, its pruning and gap check and its errors, against a real
//! PostgreSQL. Gated on the test harness locator: CI sets it, a checkout
//! without a database skips. The span arithmetic and the timeout bounds are
//! checked without one.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::*;
use crate::{
    audit::{query::ReplayCutoff, AuditEvent},
    config::DatabaseSettings,
    policy_replay::{
        impact::ReplayPolicies,
        job::{
            run, ReplayControl, ReplayOutcome, ReplayStop, MAX_REPLAY_PAGE_BYTES,
            MAX_REPLAY_RECORDS, MAX_REPLAY_RECORD_BYTES, REPLAY_PAGE_RECORDS,
        },
    },
    policy_simulation::Projection,
    rbac::Policy,
    storage::{
        contract_tests::postgres_audit_tests::{
            create_test_database, locator, write_dsn_file, TestDatabase, DATABASE,
        },
        migrations,
        postgres::PostgresFoundation,
        postgres_audit::{PostgresAuditEventStore, AUDIT_STREAM_LOCK_KEY},
        AuditEventStore,
    },
};

/// 2026-01-01T00:00:00Z in audit epoch microseconds: the start of every
/// test window. In the past, so real retention can reach it.
const BASE_US: i64 = 1_767_225_600_000_000;
const HOUR_US: i64 = 3_600_000_000;
/// Every test window: `[BASE, BASE + 24h)`.
const WINDOW: (i64, i64) = (BASE_US, BASE_US + 24 * HOUR_US);
const REQUEST_ID_CANARY: &str = "cluster-replay-request-id-canary-7c21";
const SOURCE_IP_CANARY: &str = "198.51.100.41";
const PATH_CANARY: &str = "/public/cluster-replay-path-canary-e3b9";

#[test]
fn the_replay_timeouts_never_loosen_the_session() {
    let mut settings = crate::config::Config::test_defaults().database;
    settings.statement_timeout_ms = 15_000;
    settings.lock_timeout_ms = 5_000;
    let defaults = ReplayTimeouts::for_settings(&settings);
    assert_eq!(
        defaults,
        ReplayTimeouts {
            statement_ms: 10_000,
            lock_ms: 1_000
        },
        "the replay's own bounds are tighter than the session defaults"
    );
    settings.statement_timeout_ms = 2_000;
    settings.lock_timeout_ms = 250;
    assert_eq!(
        ReplayTimeouts::for_settings(&settings),
        ReplayTimeouts {
            statement_ms: 2_000,
            lock_ms: 250
        },
        "an operator's shorter session bounds win"
    );
    settings.statement_timeout_ms = 0;
    settings.lock_timeout_ms = 0;
    assert_eq!(
        ReplayTimeouts::for_settings(&settings),
        defaults,
        "a session without a bound still gets the replay's"
    );
    assert_eq!(
        defaults.set_local(),
        "SET LOCAL statement_timeout = 10000; SET LOCAL lock_timeout = 1000;"
    );
}

fn cutoff(high_water: i64, first_id: Option<i64>, last_id: Option<i64>) -> ReplayCutoff {
    let selected = match (first_id, last_id) {
        (Some(first), Some(last)) => u64::try_from(last - first + 1).unwrap_or(0),
        _ => 0,
    };
    ReplayCutoff {
        high_water,
        selected,
        first_id,
        last_id,
    }
}

#[test]
fn the_checked_span_runs_between_the_events_that_bracket_the_window() {
    // Nothing assigned yet: nothing can be missing.
    assert_eq!(bracketed_span(&cutoff(0, None, None), None, None), None);
    // A whole window between a retained event on each side.
    assert_eq!(
        bracketed_span(&cutoff(9, Some(4), Some(6)), Some(3), Some(7)),
        Some((3, 7))
    );
    // No retained event before the window: the span reaches position 1, so
    // retention that went past the window's start is inside it.
    assert_eq!(
        bracketed_span(&cutoff(9, Some(4), Some(6)), None, Some(7)),
        Some((1, 7))
    );
    // No retained event after the window: the span reaches the cutoff.
    assert_eq!(
        bracketed_span(&cutoff(9, Some(4), Some(6)), Some(3), None),
        Some((3, 9))
    );
    // An empty window still has a place in commit order.
    assert_eq!(
        bracketed_span(&cutoff(9, None, None), Some(3), Some(4)),
        Some((3, 4))
    );
    // Bracketing events committed out of order widen the span.
    assert_eq!(
        bracketed_span(&cutoff(9, None, None), Some(8), Some(5)),
        Some((5, 8))
    );
    // A window row the cutoff selected is always inside it.
    assert_eq!(
        bracketed_span(&cutoff(9, Some(2), Some(8)), Some(4), Some(5)),
        Some((2, 8))
    );
    // An empty stream at the cutoff that later events filled: never past it.
    assert_eq!(
        bracketed_span(&cutoff(5, None, None), None, None),
        Some((1, 5))
    );
}

#[test]
fn a_window_bound_is_the_exact_microsecond() {
    assert_eq!(epoch_time(0, PAGE_OPERATION), Ok(UNIX_EPOCH));
    assert_eq!(
        epoch_time(BASE_US + 1, PAGE_OPERATION),
        Ok(UNIX_EPOCH + Duration::from_micros(1_767_225_600_000_001))
    );
    assert_eq!(
        epoch_time(-1, PAGE_OPERATION),
        Ok(UNIX_EPOCH - Duration::from_micros(1))
    );
}

fn timestamp(epoch_us: i64) -> String {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(epoch_us) * 1_000)
        .expect("a test timestamp is representable")
        .format(&Rfc3339)
        .expect("a test timestamp formats")
}

fn event_at(event_type: &str, epoch_us: i64, payload: Value) -> AuditEvent {
    let mut event = AuditEvent::new(
        event_type,
        REQUEST_ID_CANARY,
        SOURCE_IP_CANARY,
        None,
        payload,
    );
    event.timestamp = timestamp(epoch_us);
    event
}

/// An unauthenticated `GET` the policy allows: replayable, and decided.
fn request_at(epoch_us: i64) -> AuditEvent {
    event_at(
        "http.request_observed",
        epoch_us,
        json!({
            "method": "GET",
            "path": PATH_CANARY,
            "status": 200,
            "policy_decision": "allowed",
            "routing_context_known": true,
        }),
    )
}

fn policies() -> ReplayPolicies {
    let policy = Policy::validate_json_value(json!({
        "schema_version": "0.1.0",
        "id": "cluster-replay",
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
    .expect("the test policy validates");
    ReplayPolicies::compile(&policy, None, &[Projection::AsAuthored])
        .expect("the test policy compiles")
}

/// One migrated test database, its pool, its audit store and the settings
/// the pool was built with.
struct Cluster {
    pool: deadpool_postgres::Pool,
    store: PostgresAuditEventStore,
    settings: DatabaseSettings,
    _database: TestDatabase,
}

impl Cluster {
    async fn new(database: TestDatabase, configure: impl FnOnce(&mut DatabaseSettings)) -> Self {
        let dsn_file = write_dsn_file(&database.dsn);
        let mut config = crate::config::Config::test_defaults();
        config.state_backend = crate::config::StateBackend::Postgres;
        config.deployment_id = Some("deploy-replay-reader".to_owned());
        config.database.url_file = Some(dsn_file.path.clone());
        config.database.tls_mode = crate::config::DatabaseTlsMode::LoopbackDev;
        configure(&mut config.database);
        let foundation = PostgresFoundation::establish(&config)
            .await
            .expect("the test database should establish");
        migrations::apply_missing_for_startup(foundation.pool(), &config.database)
            .await
            .expect("the audit schema should migrate");
        let pool = foundation.pool().clone();
        Self {
            store: PostgresAuditEventStore::new(pool.clone(), None),
            pool,
            settings: config.database,
            _database: database,
        }
    }

    fn reader(&self) -> PostgresReplayReader {
        PostgresReplayReader::new(
            self.pool.clone(),
            &self.settings,
            tokio::runtime::Handle::current(),
        )
    }

    async fn insert(&self, events: &[AuditEvent]) {
        self.store
            .insert_events(events)
            .await
            .expect("the audit batch commits");
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

    /// Real retention: delete every event that occurred at or before
    /// `horizon_us`, through the store's own bounded step. Test rows sit at
    /// least half an hour from any horizon, far beyond any clock skew
    /// between the test and the database.
    async fn prune_through(&self, horizon_us: i64) -> u64 {
        let horizon =
            UNIX_EPOCH + Duration::from_micros(u64::try_from(horizon_us).expect("a past horizon"));
        let retention = SystemTime::now()
            .duration_since(horizon)
            .expect("the horizon is in the past");
        self.store
            .prune_older_than(retention, None, 1_000)
            .await
            .expect("retention runs")
    }
}

async fn scope(reader: &PostgresReplayReader) -> ReplayScope {
    ReplayScope {
        from: timestamp(WINDOW.0),
        to: timestamp(WINDOW.1),
        from_epoch_us: WINDOW.0,
        to_epoch_us: WINDOW.1,
        cutoff: reader
            .cutoff(WINDOW.0, WINDOW.1)
            .await
            .expect("the cutoff reads"),
        max_records: MAX_REPLAY_RECORDS,
    }
}

/// Run one job on a blocking thread, as the admin endpoint does.
async fn run_job(
    reader: PostgresReplayReader,
    scope: ReplayScope,
) -> Result<ReplayOutcome, ReplayStop> {
    tokio::task::spawn_blocking(move || {
        run(
            &reader,
            &policies(),
            &scope,
            Instant::now() + Duration::from_secs(60),
            &ReplayControl::default(),
        )
    })
    .await
    .expect("the blocking run joins")
}

fn page_query(after_id: i64, through_id: i64, max_page_bytes: usize) -> ReplayPageQuery {
    ReplayPageQuery {
        from_epoch_us: WINDOW.0,
        to_epoch_us: WINDOW.1,
        after_id,
        through_id,
        limit: REPLAY_PAGE_RECORDS,
        max_record_bytes: MAX_REPLAY_RECORD_BYTES,
        max_page_bytes,
    }
}

fn kinds(page: &[(i64, ReplayRow)]) -> Vec<(i64, &'static str)> {
    page.iter()
        .map(|(position, row)| {
            let kind = match row {
                ReplayRow::Event(_) => "event",
                ReplayRow::Unreadable => "unreadable",
                ReplayRow::Oversized => "oversized",
            };
            (*position, kind)
        })
        .collect()
}

/// Every position at or below `cutoff` holding a window row, read through
/// the reader's own pages.
async fn walk(reader: &PostgresReplayReader, cutoff: &ReplayCutoff) -> Vec<i64> {
    let mut positions = Vec::new();
    let mut after = 0;
    loop {
        let page = reader
            .read_page(&page_query(after, cutoff.high_water, MAX_REPLAY_PAGE_BYTES))
            .await
            .expect("the page reads");
        let Some((last, _)) = page.last() else {
            return positions;
        };
        after = *last;
        positions.extend(page.iter().map(|(position, _)| *position));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cluster_job_reads_its_window_by_position_at_or_below_a_fixed_cutoff() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let _guard = DATABASE.lock().await;
    let cluster = Cluster::new(create_test_database(&admin_dsn).await, |_| {}).await;
    cluster
        .insert(&[
            request_at(BASE_US - HOUR_US),
            request_at(BASE_US),
            request_at(BASE_US + HOUR_US),
            request_at(BASE_US + 2 * HOUR_US),
            request_at(WINDOW.1),
        ])
        .await;
    let reader = cluster.reader();
    let scope = scope(&reader).await;
    assert_eq!(
        scope.cutoff,
        ReplayCutoff {
            high_water: 5,
            selected: 3,
            first_id: Some(2),
            last_id: Some(4),
        }
    );

    // Committed after the cutoff with timestamps inside the window, as a
    // late flush from another replica would be: above the high-water
    // position, so no page of this job reaches them.
    cluster
        .insert(&[request_at(BASE_US + 3 * HOUR_US), request_at(BASE_US)])
        .await;
    assert_eq!(walk(&reader, &scope.cutoff).await, [2, 3, 4]);

    let outcome = run_job(cluster.reader(), scope.clone())
        .await
        .expect("the run completes");
    assert!(outcome.complete, "{:?}", outcome.limitations);
    assert_eq!(outcome.scanned, 3);
    assert_eq!(outcome.replayed, 3);
    assert_eq!(
        outcome.result["source"]["kind"],
        json!("cluster_audit_stream")
    );
    assert_eq!(outcome.result["source"]["high_water"], json!(5));
    assert_eq!(outcome.result["records"]["selected"], json!(3));
    let rendered = outcome.result.to_string();
    for canary in [REQUEST_ID_CANARY, SOURCE_IP_CANARY, PATH_CANARY] {
        assert!(
            !rendered.contains(canary),
            "a cluster result repeats no record value: {canary}"
        );
    }

    // Every read is a checkout of the replay's own class. The recorder is a
    // thread-local, so this cutoff runs on a thread of its own; the pool's
    // idle connections stay driven by this test's runtime.
    let recorder = crate::audit::sink::tests::CountingRecorder::default();
    let recorded = std::thread::scope(|threads| {
        threads
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("a runtime for the recording thread");
                ::metrics::with_local_recorder(&recorder, || {
                    runtime.block_on(reader.cutoff(WINDOW.0, WINDOW.1))
                })
            })
            .join()
            .expect("the recording thread")
    });
    assert_eq!(recorded.expect("the cutoff reads").high_water, 7);
    assert_eq!(
        recorder
            .histogram_values(
                crate::metrics::DATABASE_POOL_ACQUIRE_SECONDS,
                &[
                    ("operation_class", "policy_replay"),
                    ("error_class", "none")
                ],
            )
            .len(),
        1,
        "a replay read is timed under its own checkout class"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn events_committed_after_the_cutoff_never_enter_a_job_whenever_they_began() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let _guard = DATABASE.lock().await;
    let cluster = Cluster::new(create_test_database(&admin_dsn).await, |_| {}).await;
    cluster
        .insert(&[
            request_at(BASE_US),
            request_at(BASE_US + 1),
            request_at(BASE_US + 2),
        ])
        .await;

    // A writer whose batch is already inserted but not committed: it waits
    // for the stream lock, which a second session holds, so it has not
    // reserved a position. The cutoff taken now must not count it.
    let blocker = cluster.pool.get().await.expect("blocker checkout");
    blocker
        .execute("SELECT pg_advisory_lock($1)", &[&*AUDIT_STREAM_LOCK_KEY])
        .await
        .expect("the stream lock is held");
    let writer = {
        let store = PostgresAuditEventStore::new(cluster.pool.clone(), None);
        let batch = vec![request_at(BASE_US + 3), request_at(BASE_US + 4)];
        tokio::spawn(async move { store.insert_events(&batch).await })
    };
    let waiting = Instant::now();
    loop {
        let row = cluster
            .pool
            .get()
            .await
            .expect("probe checkout")
            .query_one(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted",
                &[],
            )
            .await
            .expect("the lock probe reads");
        if row.get::<_, i64>(0) > 0 {
            break;
        }
        assert!(
            waiting.elapsed() < Duration::from_secs(20),
            "the writer never reached the stream lock"
        );
        tokio::task::yield_now().await;
    }
    let reader = cluster.reader();
    let pinned = scope(&reader).await;
    assert_eq!(pinned.cutoff.high_water, 3);
    assert_eq!(pinned.cutoff.selected, 3);
    blocker
        .execute("SELECT pg_advisory_unlock($1)", &[&*AUDIT_STREAM_LOCK_KEY])
        .await
        .expect("the stream lock is released");
    drop(blocker);
    writer
        .await
        .expect("the writer joins")
        .expect("the blocked batch commits once the lock is free");
    assert_eq!(cluster.store.stream_head().await.expect("head"), 5);
    let outcome = run_job(cluster.reader(), pinned)
        .await
        .expect("the run completes");
    assert!(outcome.complete, "{:?}", outcome.limitations);
    assert_eq!(outcome.scanned, 3);

    // Under a race of committing writers, every cutoff's count is exactly
    // what its pages later read at or below it: nothing at or below a
    // high-water position was still uncommitted when it was read.
    let writers = (0..4)
        .map(|writer| {
            let store = PostgresAuditEventStore::new(cluster.pool.clone(), None);
            tokio::spawn(async move {
                for batch in 0..5 {
                    let offset = writer * 100 + batch * 10;
                    store
                        .insert_events(&[
                            request_at(BASE_US + offset),
                            request_at(BASE_US + offset + 1),
                            request_at(BASE_US + offset + 2),
                        ])
                        .await
                        .expect("a racing batch commits");
                }
            })
        })
        .collect::<Vec<_>>();
    let mut cutoffs = Vec::new();
    for _ in 0..6 {
        cutoffs.push(
            reader
                .cutoff(WINDOW.0, WINDOW.1)
                .await
                .expect("a racing cutoff reads"),
        );
        tokio::task::yield_now().await;
    }
    for writer in writers {
        writer.await.expect("a racing writer joins");
    }
    for cutoff in &cutoffs {
        let read = walk(&reader, cutoff).await;
        assert_eq!(
            u64::try_from(read.len()).expect("a test count fits"),
            cutoff.selected,
            "{cutoff:?}"
        );
        assert!(read.iter().all(|position| *position <= cutoff.high_water));
        assert_eq!(read.first().copied(), cutoff.first_id);
        assert_eq!(read.last().copied(), cutoff.last_id);
    }
}

/// Two events before the window, three inside it, one after it.
async fn retained_history(cluster: &Cluster) {
    cluster
        .insert(&[
            request_at(BASE_US - 2 * HOUR_US),
            request_at(BASE_US - HOUR_US),
            request_at(BASE_US),
            request_at(BASE_US + HOUR_US),
            request_at(BASE_US + 2 * HOUR_US),
            request_at(WINDOW.1 + HOUR_US),
        ])
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retention_before_the_window_leaves_a_job_complete() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let _guard = DATABASE.lock().await;
    let cluster = Cluster::new(create_test_database(&admin_dsn).await, |_| {}).await;
    retained_history(&cluster).await;
    // Retention removes the oldest event only; one event before the window
    // still stands between what was pruned and the window.
    assert_eq!(cluster.prune_through(BASE_US - 90 * 60_000_000).await, 1);
    let reader = cluster.reader();
    let scope = scope(&reader).await;
    assert_eq!(scope.cutoff.selected, 3);
    let outcome = run_job(reader, scope).await.expect("the run completes");
    assert!(outcome.complete, "{:?}", outcome.limitations);
    assert_eq!(outcome.scanned, 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retention_past_the_window_start_is_source_pruned_never_a_short_result() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let _guard = DATABASE.lock().await;
    let cluster = Cluster::new(create_test_database(&admin_dsn).await, |_| {}).await;
    retained_history(&cluster).await;
    // Retention reaches into the window before the job is created: the
    // cutoff counts only what is left, so only the stream can say the
    // window is not whole.
    assert_eq!(cluster.prune_through(BASE_US + 90 * 60_000_000).await, 4);
    let reader = cluster.reader();
    let scope = scope(&reader).await;
    assert_eq!(scope.cutoff.selected, 1);
    let outcome = run_job(reader, scope).await.expect("the run completes");
    assert!(!outcome.complete);
    assert_eq!(outcome.limitations, ["source_pruned"]);
    assert_eq!(outcome.scanned, 1);
    assert_eq!(outcome.result["limitations"], json!(["source_pruned"]));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retention_while_a_job_runs_is_source_changed_and_source_pruned() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let _guard = DATABASE.lock().await;
    let cluster = Cluster::new(create_test_database(&admin_dsn).await, |_| {}).await;
    retained_history(&cluster).await;
    let reader = cluster.reader();
    let scope = scope(&reader).await;
    assert_eq!(scope.cutoff.selected, 3);
    // Between the job's creation and its run.
    assert_eq!(cluster.prune_through(BASE_US + 90 * 60_000_000).await, 4);
    let outcome = run_job(reader, scope).await.expect("the run completes");
    assert!(!outcome.complete);
    assert_eq!(outcome.limitations, ["source_changed", "source_pruned"]);
    assert_eq!(outcome.scanned, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_gap_in_the_stream_is_source_pruned() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let _guard = DATABASE.lock().await;
    let cluster = Cluster::new(create_test_database(&admin_dsn).await, |_| {}).await;
    let middle = request_at(BASE_US + HOUR_US);
    cluster
        .insert(&[
            request_at(BASE_US - HOUR_US),
            request_at(BASE_US),
            middle.clone(),
            request_at(BASE_US + 2 * HOUR_US),
            request_at(WINDOW.1),
        ])
        .await;
    // One event removed from the middle of the window, not by age: the
    // stream's positions are gapless, so the hole shows.
    cluster
        .execute(&format!(
            "DELETE FROM greengateway.audit_events WHERE event_id = '{}'",
            middle.event_id
        ))
        .await;
    let reader = cluster.reader();
    let scope = scope(&reader).await;
    assert_eq!(scope.cutoff.selected, 2);
    let outcome = run_job(reader, scope).await.expect("the run completes");
    assert_eq!(outcome.limitations, ["source_pruned"]);
    assert_eq!(outcome.scanned, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_window_retention_emptied_is_source_pruned_not_just_no_data() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let _guard = DATABASE.lock().await;
    let cluster = Cluster::new(create_test_database(&admin_dsn).await, |_| {}).await;
    // An empty window over an intact stream is only `no_data`.
    cluster
        .insert(&[request_at(BASE_US - HOUR_US), request_at(WINDOW.1)])
        .await;
    let reader = cluster.reader();
    let empty = scope(&reader).await;
    assert_eq!(empty.cutoff.selected, 0);
    let outcome = run_job(cluster.reader(), empty)
        .await
        .expect("the run completes");
    assert_eq!(outcome.limitations, ["no_data"]);

    // A window whose every event retention removed reads the same, except
    // that the stream shows where they were.
    cluster
        .insert(&[
            request_at(BASE_US + HOUR_US),
            request_at(BASE_US + 2 * HOUR_US),
            request_at(WINDOW.1 + HOUR_US),
        ])
        .await;
    assert_eq!(cluster.prune_through(BASE_US + 150 * 60_000_000).await, 3);
    let emptied = scope(&reader).await;
    assert_eq!(emptied.cutoff.selected, 0);
    let outcome = run_job(reader, emptied).await.expect("the run completes");
    assert_eq!(outcome.limitations, ["no_data", "source_pruned"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_legacy_and_oversized_rows_are_counted_never_loaded() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let _guard = DATABASE.lock().await;
    let cluster = Cluster::new(create_test_database(&admin_dsn).await, |_| {}).await;
    let mut oversized = request_at(BASE_US + 1);
    oversized.payload["padding"] = json!("x".repeat(MAX_REPLAY_RECORD_BYTES));
    let unreadable = request_at(BASE_US + 2);
    let mut legacy = request_at(BASE_US + 3);
    legacy.schema_version = "0.0.1".to_owned();
    cluster
        .insert(&[
            request_at(BASE_US),
            oversized,
            unreadable.clone(),
            legacy,
            event_at(
                "http.request_observed",
                BASE_US + 4,
                json!(["not", "an", "object"]),
            ),
            event_at("admin.session_created", BASE_US + 5, json!({})),
        ])
        .await;
    // Valid JSON in a shape the audit sink never writes for an actor.
    cluster
        .execute(&format!(
            "UPDATE greengateway.audit_events SET actor_json = '{{\"unexpected\": true}}'::jsonb \
             WHERE event_id = '{}'",
            unreadable.event_id
        ))
        .await;
    let reader = cluster.reader();
    let page = reader
        .read_page(&page_query(0, 6, MAX_REPLAY_PAGE_BYTES))
        .await
        .expect("the page reads");
    assert_eq!(
        kinds(&page),
        [
            (1, "event"),
            (2, "oversized"),
            (3, "unreadable"),
            (4, "event"),
            (5, "event"),
            (6, "event"),
        ]
    );
    // The page's byte budget ends a page after its first row, never before;
    // an oversized row costs it nothing, since none of it is read.
    let page = reader
        .read_page(&page_query(0, 6, 1))
        .await
        .expect("the page reads");
    assert_eq!(kinds(&page), [(1, "event"), (2, "oversized")]);

    let scope = scope(&reader).await;
    let outcome = run_job(reader, scope).await.expect("the run completes");
    assert!(outcome.complete, "{:?}", outcome.limitations);
    let records = &outcome.result["records"];
    assert_eq!(records["scanned"], json!(6));
    assert_eq!(records["replayable"], json!(1));
    assert_eq!(records["unsupported"], json!(1));
    assert_eq!(records["malformed"], json!(1));
    assert_eq!(records["unreadable"], json!(1));
    assert_eq!(records["oversized"], json!(1));
    assert_eq!(records["not_request_record"], json!(1));
    assert_eq!(
        records["by_code"],
        json!({
            "malformed_payload": 1,
            "not_request_record": 1,
            "oversized_record": 1,
            "replayable": 1,
            "unreadable_record": 1,
            "unsupported_envelope_version": 1,
        })
    );
}

/// What may never appear in an error that crosses the reader's boundary:
/// SQL, schema names, the driver's message, window bounds and record values.
fn assert_redacted(rendered: &str, event_id: &str) {
    for leak in [
        "SELECT",
        "select",
        "greengateway",
        "audit_stream",
        "audit_events",
        "relation",
        "lock timeout",
        "canceling",
        "2026",
        BASE_US.to_string().as_str(),
        event_id,
        REQUEST_ID_CANARY,
        SOURCE_IP_CANARY,
        PATH_CANARY,
    ] {
        assert!(
            !rendered.contains(leak),
            "a replay error carries {leak:?}: {rendered}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replay_errors_are_bounded_classified_and_carry_no_sql_or_values() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let _guard = DATABASE.lock().await;
    // The session waits a minute for a lock; the replay must not.
    let cluster = Cluster::new(create_test_database(&admin_dsn).await, |settings| {
        settings.lock_timeout_ms = 60_000;
    })
    .await;
    let stored = request_at(BASE_US);
    cluster.insert(std::slice::from_ref(&stored)).await;
    let reader = cluster.reader();

    // A migration's lock on the stream: the replay gives its connection
    // back within its own bound instead of queueing behind it.
    let mut holder = cluster.pool.get().await.expect("holder checkout");
    let holding = holder.transaction().await.expect("holder transaction");
    holding
        .batch_execute("LOCK TABLE greengateway.audit_stream IN ACCESS EXCLUSIVE MODE")
        .await
        .expect("the stream is locked");
    let started = Instant::now();
    let error = reader
        .cutoff(WINDOW.0, WINDOW.1)
        .await
        .expect_err("a locked stream refuses the cutoff");
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the replay waited {:?} for a lock",
        started.elapsed()
    );
    assert_eq!(error.kind(), RepositoryErrorKind::Timeout);
    assert_eq!(error.to_string(), "audit_replay_cutoff failed: timeout");
    assert_redacted(&format!("{error} {error:?}"), &stored.event_id);

    // Through the job engine, from its blocking thread: the source's error
    // is opaque and the job fails without a result.
    let pinned = ReplayScope {
        from: timestamp(WINDOW.0),
        to: timestamp(WINDOW.1),
        from_epoch_us: WINDOW.0,
        to_epoch_us: WINDOW.1,
        cutoff: ReplayCutoff {
            high_water: 1,
            selected: 1,
            first_id: Some(1),
            last_id: Some(1),
        },
        max_records: MAX_REPLAY_RECORDS,
    };
    let source_error = {
        let reader = cluster.reader();
        tokio::task::spawn_blocking(move || {
            ReplaySource::page(&reader, &page_query(0, 1, MAX_REPLAY_PAGE_BYTES))
                .map(|page| page.len())
        })
        .await
        .expect("the blocking read joins")
        .expect_err("a locked stream refuses a page")
    };
    assert_eq!(format!("{source_error:?}"), "ReplaySourceError");
    assert_eq!(
        run_job(cluster.reader(), pinned.clone())
            .await
            .expect_err("a locked stream fails the job"),
        ReplayStop::Failed("source_unavailable")
    );
    holding.rollback().await.expect("the lock is released");
    drop(holder);

    // A schema this reader does not recognise: classified, and nothing of
    // the driver's message crosses.
    cluster
        .execute("ALTER TABLE greengateway.audit_stream RENAME TO audit_stream_moved")
        .await;
    let error = reader
        .read_page(&page_query(0, 1, MAX_REPLAY_PAGE_BYTES))
        .await
        .map(|page| page.len())
        .expect_err("a missing stream refuses a page");
    assert_eq!(error.kind(), RepositoryErrorKind::Internal);
    assert_eq!(error.to_string(), "audit_replay_page failed: internal");
    assert_redacted(&format!("{error} {error:?}"), &stored.event_id);
    let error = reader
        .check_window(&pinned)
        .await
        .expect_err("a missing stream refuses the check");
    assert_eq!(error.to_string(), "audit_replay_check failed: internal");
    assert_redacted(&format!("{error} {error:?}"), &stored.event_id);
}
