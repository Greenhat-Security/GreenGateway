//! The nightly performance gate (issue #241, PR 16 part 2).
//!
//! `docs/architecture/ha-state-model.md` §6 publishes nine per-operation
//! p99 budgets and one aggregate rule, and says what they are for: "they
//! are targets the release gate (PR 16) measures; a PR that cannot meet
//! its budget redesigns, not re-baselines." This file measures them, emits
//! one JSON artifact, and fails when a number is outside its budget or has
//! slid materially toward one since the previous night.
//!
//! Every test here is `#[ignore]`d. The `ha-release-gate` job must not run
//! it — a benchmark on a shared hosted runner is a flake generator in a
//! required merge check — and the nightly job runs it with `--release
//! --test-threads 1 --ignored`, both of which are load-bearing: a debug
//! build measures the wrong thing and a parallel run measures contention
//! the budgets do not describe.
//!
//! ## Where each number comes from, and why that is stated in the artifact
//!
//! A benchmark that does not say what it measured is a number without a
//! claim attached. Every entry in the report therefore carries a `method`
//! and, where one exists, a `source_anchor`:
//!
//! * `end_to_end` — driven through the running gateway over HTTP. The
//!   honest measurement, used wherever the operation has a surface:
//!   `control_plane_mutation` and `reconcile_wait_after_new_revision`.
//! * `authority_statement` — the store's own statement, **copied verbatim**
//!   from the file named in `source_anchor` and run over a warm connection
//!   as the deployment's runtime role. Used for the five operations that
//!   have no surface of their own because they happen inside a request:
//!   the revision check, the service-token check, the revocation lookup,
//!   the rate-limit decision and the lease acquire. A verbatim copy with
//!   an anchor is a claim a reviewer can diff; a paraphrase would not be.
//! * `pool_checkout` — `connection_acquire_warm`, timed on a
//!   `deadpool_postgres` pool built exactly as
//!   `storage/postgres.rs::build_pool` builds the deployment's, down to
//!   the `ROLLBACK` recycling statement that is most of what a checkout
//!   costs. No product series isolates this: the stores time the checkout
//!   together with the statement that follows it.
//! * `stall_experiment` — `audit_enqueue` is budgeted at "0 ms on the
//!   request path", which is a claim about where work happens rather than
//!   a latency. Since issue #11 every serving replica writes its audit
//!   events to `greengateway.audit_events` through a sink of its own, so
//!   the experiment that settles the claim is available:
//!   [`the_audit_enqueue_stays_off_the_request_path`] stalls that sink with
//!   a table lock, shows the request p99 does not move, and shows one row
//!   per request lands once the lock goes.
//!
//! ## Why the product's own timing series is not the source
//!
//! `greengateway_database_operation_seconds` looks like exactly the right
//! series — the gateway timing its own store operations, labelled by a
//! fixed `operation` vocabulary — and it would be, except that only
//! `storage/postgres_membership.rs` calls `storage::postgres::timed_operation`
//! today. Every other `OPERATION_*` constant is an error-classification
//! label with no timing behind it, so the histogram carries the membership
//! and maintenance operations and none of the nine budgeted ones. Adopting
//! the series in each store is a production change, and it is the change
//! that would let this file delete its `authority_statement` tier
//! altogether. Recorded here rather than in a commit message because the
//! `method` field is where a reader will ask the question.
//!
//! ## What the artifact is for
//!
//! `GATEWAY_TEST_PERF_REPORT` names the file. It is rewritten after every
//! measurement is taken and **before** that measurement's budget is
//! asserted, so the artifact exists on a failing run — which is the run it
//! is most useful on. `GATEWAY_TEST_PERF_BASELINE`, when set, names the
//! previous night's report: a p99 that has grown by more than 25 % *and*
//! sits within 20 % of its budget fails the job, which catches a slide
//! toward a ceiling before it hits one. A missing baseline is a pass, and
//! says so in the log.
//!
//! Skips silently without `GATEWAY_TEST_POSTGRES_URL_FILE`, and without
//! `GATEWAY_TEST_HA_GATE`, like every other suite under `tests/ha/`.

#![cfg(feature = "postgres")]

mod harness;

use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use serde_json::{json, Value};

use harness::{AuthShape, Cluster, ClusterOptions, FakeOidcIssuer, ADMIN_API_PREFIX};

// ---------------------------------------------------------------------
// The budgets, quoted from the document that owns them
// ---------------------------------------------------------------------

/// The document the budgets live in. Cited in every measurement so a
/// reader can check the number against its source rather than against
/// this file's memory of it.
const BUDGET_SOURCE: &str = "docs/architecture/ha-state-model.md#6-blocking-budgets";

/// One budgeted operation: the name the artifact publishes, the p99 in
/// milliseconds `ha-state-model.md` §6 gives it, how this file measures
/// it, and where the measured statement was copied from.
struct Budget {
    name: &'static str,
    p99_ms: f64,
    method: &'static str,
    source_anchor: &'static str,
}

/// The eight budgeted operations this file produces a measurement for.
///
/// `audit_enqueue` is the ninth row of the document's table and is
/// deliberately absent here: its budget is "0 ms on the request path",
/// which is a claim about where the work happens rather than a latency of
/// its own, and [`the_audit_enqueue_stays_off_the_request_path`] tests it
/// by stalling the sink under a measured run rather than by timing one
/// operation. [`the_report_covers_every_budget_the_state_model_publishes`]
/// is what keeps that from becoming a silent omission.
const BUDGETS: &[Budget] = &[
    Budget {
        name: "security_revision_check",
        p99_ms: 5.0,
        method: "authority_statement",
        source_anchor: "gateway/src/storage/postgres_policy.rs::SecurityRevisionSource::current",
    },
    Budget {
        name: "service_token_authoritative_check",
        p99_ms: 8.0,
        method: "authority_statement",
        source_anchor: "gateway/src/storage/postgres_service_tokens.rs::verify (the live path)",
    },
    Budget {
        name: "revocation_lookup",
        p99_ms: 5.0,
        method: "authority_statement",
        source_anchor:
            "gateway/src/storage/postgres_jwt_revocations.rs::RevocationStore::is_revoked",
    },
    Budget {
        name: "distributed_rate_limit_decision",
        p99_ms: 8.0,
        method: "authority_statement",
        source_anchor: "gateway/src/storage/postgres_rate_limits.rs::decide",
    },
    Budget {
        name: "lease_acquire",
        p99_ms: 10.0,
        method: "authority_statement",
        source_anchor: "gateway/src/storage/postgres_execution_leases.rs::try_acquire",
    },
    Budget {
        name: "reconcile_wait_after_new_revision",
        p99_ms: 250.0,
        method: "end_to_end",
        source_anchor: "PUT /v1/admin/policy on one replica, observed on another",
    },
    Budget {
        name: "control_plane_mutation",
        p99_ms: 500.0,
        method: "end_to_end",
        source_anchor: "PUT /v1/admin/policy",
    },
    Budget {
        name: "connection_acquire_warm",
        p99_ms: 50.0,
        method: "pool_checkout",
        source_anchor: "deadpool_postgres::Pool::get, built as gateway/src/storage/postgres.rs \
                        builds it (RecyclingMethod::Custom(\"ROLLBACK\"), Runtime::Tokio1)",
    },
];

fn budget(name: &str) -> &'static Budget {
    BUDGETS
        .iter()
        .find(|budget| budget.name == name)
        .unwrap_or_else(|| panic!("{name} is not one of the budgets this file publishes"))
}

/// The audit query benchmark: the parent contract's "filtered query at one
/// million rows under 500 ms".
const AUDIT_QUERY_ROWS: i64 = 1_000_000;
const AUDIT_QUERY_BUDGET_MS: f64 = 500.0;

/// `ha-state-model.md:100` — "the authority adds no more than 25 ms p99 to
/// a protected request's pre-upstream critical path in cluster mode, and
/// 0 ms in standalone mode."
const AGGREGATE_BUDGET_MS: f64 = 25.0;

/// A p99 that has grown by more than this since the baseline, *and* is
/// within [`REGRESSION_HEADROOM`] of its budget, fails the job.
const REGRESSION_GROWTH: f64 = 0.25;
const REGRESSION_HEADROOM: f64 = 0.80;

/// How many samples each latency measurement takes.
///
/// Enough that a p99 is a hundred-sample tail rather than a single
/// observation, and few enough that eight of them fit inside a nightly
/// job's budget alongside a million-row load. Override with
/// `GATEWAY_TEST_PERF_SAMPLES` when investigating a specific number.
fn samples() -> usize {
    std::env::var("GATEWAY_TEST_PERF_SAMPLES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2_000)
}

const ADMIN_ROLE: &str = "ha-admin";
const PROXIED_PATH: &str = "/echo/performance";

fn policy_route() -> String {
    format!("{ADMIN_API_PREFIX}/policy")
}

fn skipped() {
    eprintln!(
        "skipping: no test database locator, or this run is not the gate; the \
         nightly-performance workflow runs this suite"
    );
}

// ---------------------------------------------------------------------
// Samples and quantiles
// ---------------------------------------------------------------------

/// A sorted sample set and the three quantiles the report publishes.
struct Quantiles {
    samples: usize,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
}

/// Nearest-rank quantiles over milliseconds.
///
/// Nearest-rank rather than an interpolation because the claim is "the
/// 99th slowest percent of requests were no slower than this", and an
/// interpolated value is not an observation any request made.
fn quantiles(mut milliseconds: Vec<f64>) -> Quantiles {
    assert!(
        !milliseconds.is_empty(),
        "a measurement needs at least one sample"
    );
    milliseconds.sort_by(|left, right| left.partial_cmp(right).expect("no NaN latencies"));
    let at = |quantile: f64| -> f64 {
        let rank = (quantile * milliseconds.len() as f64).ceil() as usize;
        milliseconds[rank.clamp(1, milliseconds.len()) - 1]
    };
    Quantiles {
        samples: milliseconds.len(),
        p50_ms: at(0.50),
        p95_ms: at(0.95),
        p99_ms: at(0.99),
    }
}

/// Time one asynchronous operation, `count` times, and answer its
/// quantiles.
///
/// The first `warmup` iterations are discarded: a pool that has not opened
/// a connection yet, or a statement PostgreSQL has not planned yet, is not
/// what "warm pool" in the budget table means.
async fn measure<F, Fut>(count: usize, warmup: usize, mut operation: F) -> Quantiles
where
    F: FnMut(usize) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    for index in 0..warmup {
        operation(index).await;
    }
    let mut milliseconds = Vec::with_capacity(count);
    for index in 0..count {
        let started = Instant::now();
        operation(warmup + index).await;
        milliseconds.push(started.elapsed().as_secs_f64() * 1_000.0);
    }
    quantiles(milliseconds)
}

// ---------------------------------------------------------------------
// The artifact
// ---------------------------------------------------------------------

/// The report, rewritten to disk after every append.
///
/// Rewriting the whole file each time, rather than appending at the end of
/// the run, is what makes the artifact exist on a failing run: a budget
/// assertion panics *after* its measurement has already been written.
struct Report {
    path: std::path::PathBuf,
    document: Value,
}

static REPORT: OnceLock<Mutex<Report>> = OnceLock::new();

fn report() -> &'static Mutex<Report> {
    REPORT.get_or_init(|| {
        let path = std::env::var("GATEWAY_TEST_PERF_REPORT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("ha-performance.json"));
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let document = json!({
            "schema_version": 1,
            "recorded_at": now_rfc3339(),
            "git_sha": git_sha(),
            "binary_version": env!("CARGO_PKG_VERSION"),
            "runner": {
                "os": std::env::consts::OS,
                "cores": std::thread::available_parallelism()
                    .map(|count| count.get())
                    .unwrap_or(0),
            },
            "database": Value::Null,
            "measurements": [],
            "audit_query": Value::Null,
            "aggregate": Value::Null,
        });
        Mutex::new(Report { path, document })
    })
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_owned())
}

fn git_sha() -> String {
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(std::path::Path::to_owned);
    let Some(repository) = repository else {
        return "unknown".to_owned();
    };
    std::process::Command::new("git")
        .arg("-C")
        .arg(&repository)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// The previous night's report, keyed by measurement name, when
/// `GATEWAY_TEST_PERF_BASELINE` names one.
fn baseline() -> &'static Option<BTreeMap<String, f64>> {
    static BASELINE: OnceLock<Option<BTreeMap<String, f64>>> = OnceLock::new();
    BASELINE.get_or_init(|| {
        let path = std::env::var("GATEWAY_TEST_PERF_BASELINE").ok()?;
        let contents = std::fs::read_to_string(&path).ok()?;
        let document: Value = serde_json::from_str(&contents).ok()?;
        let measurements = document["measurements"].as_array()?;
        Some(
            measurements
                .iter()
                .filter_map(|entry| {
                    Some((
                        entry["name"].as_str()?.to_owned(),
                        entry["p99_ms"].as_f64()?,
                    ))
                })
                .collect(),
        )
    })
}

fn write_report(report: &Report) {
    let rendered = serde_json::to_string_pretty(&report.document)
        .unwrap_or_else(|error| panic!("the performance report should serialize: {error}"));
    std::fs::write(&report.path, format!("{rendered}\n")).unwrap_or_else(|error| {
        panic!(
            "the performance report should be writable at {}: {error}",
            report.path.display()
        )
    });
}

fn set_field(key: &str, value: Value) {
    let mut report = report()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    report.document[key] = value;
    write_report(&report);
}

/// Record one measurement, write the artifact, then assert its budget and
/// its regression rule.
///
/// The order is the point: the artifact is on disk before anything can
/// panic, so a failing night still publishes the numbers that failed.
fn record(name: &str, observed: &Quantiles) {
    let budget = budget(name);
    let within_budget = observed.p99_ms <= budget.p99_ms;
    let previous = baseline().as_ref().and_then(|map| map.get(name)).copied();
    // A p99 that grew materially AND is close to its ceiling. Either half
    // alone is noise on a shared runner: a 40 % growth from 0.2 ms to
    // 0.28 ms against a 5 ms budget says nothing, and a number that has
    // always sat near its budget is a design question rather than a
    // regression.
    let regressed = previous.is_some_and(|previous| {
        previous > 0.0
            && observed.p99_ms > previous * (1.0 + REGRESSION_GROWTH)
            && observed.p99_ms > budget.p99_ms * REGRESSION_HEADROOM
    });

    {
        let mut report = report()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = json!({
            "name": name,
            "budget_source": BUDGET_SOURCE,
            "budget_p99_ms": budget.p99_ms,
            "method": budget.method,
            "source_anchor": budget.source_anchor,
            "samples": observed.samples,
            "p50_ms": rounded(observed.p50_ms),
            "p95_ms": rounded(observed.p95_ms),
            "p99_ms": rounded(observed.p99_ms),
            "within_budget": within_budget,
            "baseline_p99_ms": previous,
            "regressed": regressed,
        });
        report.document["measurements"]
            .as_array_mut()
            .expect("the report's measurements are an array")
            .push(entry);
        write_report(&report);
    }

    eprintln!(
        "{name}: p50 {:.3} ms, p95 {:.3} ms, p99 {:.3} ms against a budget of {:.1} ms \
         ({} samples, {})",
        observed.p50_ms,
        observed.p95_ms,
        observed.p99_ms,
        budget.p99_ms,
        observed.samples,
        budget.method
    );
    if previous.is_none() {
        eprintln!("{name}: no baseline to compare against; the regression rule passes by default");
    }

    assert!(
        within_budget,
        "{name} spent {:.3} ms at p99 against its budget of {:.1} ms ({BUDGET_SOURCE}). The \
         document is normative: a PR that cannot meet its budget redesigns, it does not \
         re-baseline.",
        observed.p99_ms, budget.p99_ms
    );
    assert!(
        !regressed,
        "{name} grew from {:.3} ms to {:.3} ms at p99 — more than {:.0} % — and is now within \
         {:.0} % of its {:.1} ms budget",
        previous.unwrap_or_default(),
        observed.p99_ms,
        REGRESSION_GROWTH * 100.0,
        REGRESSION_HEADROOM * 100.0,
        budget.p99_ms
    );
}

fn rounded(milliseconds: f64) -> f64 {
    (milliseconds * 1_000.0).round() / 1_000.0
}

// ---------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------

fn admin_policy() -> String {
    json!({
        "default_action": "allow",
        "enforcement_mode": "enforce",
        "roles": { ADMIN_ROLE: { "permissions": ["*"] } },
        "routes": [],
        "rules": [],
        "schema_version": "0.1.0",
    })
    .to_string()
}

fn marked_policy(marker: &str) -> Value {
    json!({
        "default_action": "allow",
        "enforcement_mode": "enforce",
        "roles": {
            ADMIN_ROLE: { "permissions": ["*"] },
            marker: { "permissions": [] },
        },
        "routes": [],
        "rules": [],
        "schema_version": "0.1.0",
    })
}

fn admin_token(issuer: &FakeOidcIssuer, subject: &str) -> String {
    issuer.mint_role_token(
        harness::oidc::PRIMARY_KID,
        subject,
        &format!("jti-{}", uuid::Uuid::new_v4().simple()),
        &[ADMIN_ROLE],
        3_600,
    )
}

fn performance_options(replicas: usize) -> ClusterOptions {
    ClusterOptions {
        replicas,
        auth: AuthShape::Oidc,
        seed_policy: Some(admin_policy()),
        // A pool the budgets' "warm pool" language actually describes:
        // large enough that a checkout is never a wait for a peer's
        // statement to finish.
        pool_max: 8,
        // The limiter still runs on every request measured here — its
        // decision is one of the round trips the aggregate budget counts —
        // but its configured ceiling is raised out of the way. A benchmark
        // that refused its own traffic would be measuring
        // `RATE_LIMIT_WRITE_RPS`, which is an operator's choice and not a
        // property of the deployment.
        shared_env: vec![
            ("RATE_LIMIT_READ_RPS".to_owned(), "100000".to_owned()),
            ("RATE_LIMIT_READ_BURST".to_owned(), "100000".to_owned()),
            ("RATE_LIMIT_WRITE_RPS".to_owned(), "100000".to_owned()),
            ("RATE_LIMIT_WRITE_BURST".to_owned(), "100000".to_owned()),
        ],
        ..ClusterOptions::default()
    }
}

async fn start_performance_cluster(replicas: usize) -> Option<Cluster> {
    let mut cluster = Cluster::start(performance_options(replicas)).await?;
    cluster.wait_until_all_ready().await;
    record_database_facts(&cluster).await;
    Some(cluster)
}

/// Put the server's own description into the artifact. A latency number
/// without the machine it was measured on is not comparable with
/// tomorrow's.
async fn record_database_facts(cluster: &Cluster) {
    let version: String = cluster
        .database
        .query_one("SELECT current_setting('server_version')")
        .await
        .get(0);
    let max_connections: String = cluster
        .database
        .query_one("SELECT current_setting('max_connections')")
        .await
        .get(0);
    set_field(
        "database",
        json!({
            "server_version": version,
            "max_connections": max_connections,
            "pool_max": 8,
        }),
    );
}

/// A warm client on the deployment's **runtime** role — the role a replica
/// runs as, so a measurement cannot accidentally profile the superuser.
struct RuntimeSession {
    client: Option<tokio_postgres::Client>,
    pump: Option<tokio::task::JoinHandle<()>>,
}

impl RuntimeSession {
    async fn connect(dsn: &str) -> Self {
        let (client, connection) = tokio_postgres::connect(dsn, tokio_postgres::NoTls)
            .await
            .unwrap_or_else(|error| panic!("the runtime session should establish: {error}"));
        let pump = tokio::spawn(async move {
            let _ = connection.await;
        });
        Self {
            client: Some(client),
            pump: Some(pump),
        }
    }

    fn client(&self) -> &tokio_postgres::Client {
        self.client.as_ref().expect("the session is still open")
    }
}

impl Drop for RuntimeSession {
    fn drop(&mut self) {
        self.client.take();
        if let Some(pump) = self.pump.take() {
            pump.abort();
        }
    }
}

/// A connection pool built the way `storage/postgres.rs` builds the
/// deployment's, filled to `size` before it is returned.
///
/// The recycling statement matters and is copied deliberately: the
/// product recycles with `ROLLBACK` rather than `DISCARD ALL`, which is
/// most of what a warm checkout costs. A pool that recycled differently
/// would produce a number that is not the budgeted one.
async fn warm_pool(dsn: &str, size: usize) -> deadpool_postgres::Pool {
    let config: tokio_postgres::Config = dsn
        .parse()
        .unwrap_or_else(|error| panic!("the runtime DSN should parse: {error}"));
    let manager = deadpool_postgres::Manager::from_config(
        config,
        tokio_postgres::NoTls,
        deadpool_postgres::ManagerConfig {
            recycling_method: deadpool_postgres::RecyclingMethod::Custom("ROLLBACK".to_owned()),
        },
    );
    let pool = deadpool_postgres::Pool::builder(manager)
        .config(deadpool_postgres::PoolConfig::new(size))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .build()
        .expect("the measurement pool should build");
    // Fill it: `size` simultaneous checkouts force `size` connections to
    // exist, and dropping them all returns them for the samples to reuse.
    let mut held = Vec::with_capacity(size);
    for _ in 0..size {
        held.push(
            pool.get()
                .await
                .expect("the measurement pool should open a connection"),
        );
    }
    drop(held);
    pool
}

/// 64 lowercase hex characters, which is the shape both `service_tokens`
/// and `jwt_revocations` constrain their hash columns to.
///
/// Derived from a per-run UUID rather than written as a literal: nothing
/// in this repository's history should look like a leaked digest.
fn hex64() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

// =====================================================================
// The per-operation budgets
// =====================================================================

/// **The five authority round trips a protected request makes, plus the
/// connection acquire that precedes each.**
///
/// Each statement below is a verbatim copy from the store named in its
/// `source_anchor`, run over a warm connection as the runtime role. They
/// are copies rather than calls because the stores are crate-private and
/// an integration test links only the binary's public surface; the anchor
/// is what makes the copy checkable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "nightly benchmark; run by the nightly-performance workflow"]
async fn the_authority_operations_are_within_their_per_operation_budgets() {
    let Some(mut cluster) = start_performance_cluster(1).await else {
        return skipped();
    };
    let session = RuntimeSession::connect(&cluster.database.runtime_dsn).await;
    let client = session.client();
    let count = samples();
    let warmup = 50;

    // --- security_revision_check ------------------------------------
    //
    // The floor added to every protected request. Also the one
    // measurement here with an independent cross-check: the value this
    // statement reads is the same number the deployment's own status
    // surface reports, so a statement that had drifted from the product's
    // would be caught rather than merely timed.
    let revision_statement = client
        .prepare("SELECT last_revision FROM greengateway.security_revision_state WHERE singleton")
        .await
        .expect("the revision statement should prepare");
    let observed = measure(count, warmup, |_| async {
        let row = client
            .query_opt(&revision_statement, &[])
            .await
            .expect("the revision read should succeed");
        assert!(row.is_some(), "the counter row is seeded by migration 4");
    })
    .await;
    let statement_revision: i64 = client
        .query_one(&revision_statement, &[])
        .await
        .expect("the revision read should succeed")
        .get(0);
    let admin = admin_token(&cluster.oidc, "admin@ha.test");
    let (status, body) = cluster
        .get("a", "/v1/admin/cluster")
        .bearer(&admin)
        .send()
        .await;
    assert_eq!(status, 200, "the cluster status should answer: {body}");
    assert_eq!(
        body["local"]["observed_security_revision"].as_i64(),
        Some(statement_revision),
        "the statement this file times must read the same counter the product reads; it does \
         not, so the copy in this test has drifted from \
         storage/postgres_policy.rs::SecurityRevisionSource::current"
    );
    record("security_revision_check", &observed);

    // --- service_token_authoritative_check --------------------------
    //
    // The live path: the `UPDATE ... RETURNING` that stamps `last_used_at`
    // and returns the record in one round trip. Measured against a real
    // live row, because the not-found path is a second statement and a
    // cheaper one.
    let token_hash = hex64();
    client
        .execute(
            "INSERT INTO greengateway.service_tokens \
               (id, token_hash, token_prefix, scopes_json, created_by, expires_at, \
                security_revision) \
             VALUES ($1, $2, 'ggw_perf', '[]', 'performance-suite', now() + interval '1 day', 1)",
            &[
                &format!("perf-{}", uuid::Uuid::new_v4().simple()),
                &token_hash,
            ],
        )
        .await
        .expect("the performance fixture token should insert");
    // `select_columns()` from postgres_service_tokens.rs, expanded.
    let verify_statement = client
        .prepare(
            r#"
            UPDATE greengateway.service_tokens
            SET last_used_at = now()
            WHERE token_hash = $1
              AND revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > now())
            RETURNING id, token_prefix, scopes_json, created_by,
              to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
              to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
              to_char(last_used_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
              to_char(revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
              revision,
              CASE WHEN expires_at IS NULL THEN NULL
                   ELSE GREATEST(EXTRACT(EPOCH FROM (expires_at - now())), 0)::double precision
              END
            "#,
        )
        .await
        .expect("the token verification statement should prepare");
    let observed = measure(count, warmup, |_| async {
        let row = client
            .query_opt(&verify_statement, &[&token_hash])
            .await
            .expect("the token verification should succeed");
        assert!(row.is_some(), "the fixture token is live");
    })
    .await;
    record("service_token_authoritative_check", &observed);

    // --- revocation_lookup ------------------------------------------
    //
    // The common case, which is the one the budget is about: a `jti` that
    // is NOT on the denylist. A hit would short-circuit the index scan and
    // measure the cheaper half.
    let issuer = "https://issuer.performance.test";
    let leeway = 60.0_f64;
    let absent = hex64();
    let revocation_statement = client
        .prepare(
            r#"
            SELECT EXISTS (
                SELECT 1 FROM greengateway.jwt_revocations
                WHERE issuer = $1 AND jti_hash = $2
                  AND (expires_at IS NULL OR expires_at > now() - make_interval(secs => $3))
            )
            "#,
        )
        .await
        .expect("the revocation statement should prepare");
    let observed = measure(count, warmup, |_| async {
        let revoked: bool = client
            .query_one(&revocation_statement, &[&issuer, &absent, &leeway])
            .await
            .expect("the revocation lookup should succeed")
            .get(0);
        assert!(!revoked, "the fixture jti is not on the denylist");
    })
    .await;
    record("revocation_lookup", &observed);

    // --- distributed_rate_limit_decision ----------------------------
    //
    // One key, hit repeatedly: the bucket exists after the first
    // iteration, so this measures the `ON CONFLICT DO UPDATE` arm the
    // steady state takes, not the insert. The limit is generous so every
    // decision is an allow and the statement does the same work each time.
    let digest: Vec<u8> = (0..32u8).collect();
    let deployment = cluster.deployment_id.clone();
    let emission = 0.000_1_f64;
    let tolerance = 10.0_f64;
    let limit_statement = client
        .prepare(
            "WITH upsert AS (
                 INSERT INTO greengateway.rate_limit_buckets AS b
                     (deployment_id, lane, key_digest, tat, allowed, updated_at)
                 VALUES ($1, $2, $3,
                     now() + CASE WHEN $5::double precision >= 0
                                  THEN make_interval(secs => $4::double precision)
                                  ELSE interval '0' END,
                     $5::double precision >= 0,
                     now())
                 ON CONFLICT (deployment_id, lane, key_digest) DO UPDATE SET
                     allowed = (GREATEST(b.tat, now()) - now())
                         <= make_interval(secs => $5::double precision),
                     tat = CASE WHEN (GREATEST(b.tat, now()) - now())
                                     <= make_interval(secs => $5::double precision)
                                THEN GREATEST(b.tat, now())
                                     + make_interval(secs => $4::double precision)
                                ELSE b.tat END,
                     updated_at = now()
                 RETURNING b.allowed AS allowed, (b.xmax = 0) AS inserted
             ),
             counted AS (
                 INSERT INTO greengateway.rate_limit_cardinality AS c (deployment_id, live)
                 SELECT $1, 1 FROM upsert WHERE upsert.inserted
                 ON CONFLICT (deployment_id) DO UPDATE SET live = c.live + 1
                 RETURNING c.live AS live
             )
             SELECT upsert.allowed, upsert.inserted,
                    (SELECT live FROM counted) AS live
             FROM upsert",
        )
        .await
        .expect("the rate-limit statement should prepare");
    let observed = measure(count, warmup, |_| async {
        let allowed: bool = client
            .query_one(
                &limit_statement,
                &[&deployment, &"read", &digest, &emission, &tolerance],
            )
            .await
            .expect("the rate-limit decision should succeed")
            .get("allowed");
        assert!(allowed, "the fixture limit is generous enough to allow");
    })
    .await;
    record("distributed_rate_limit_decision", &observed);

    // --- lease_acquire ----------------------------------------------
    //
    // A fresh scope per sample, so every iteration is a real acquisition
    // rather than the cheaper "no slot free" arm. Capacity 1: the budget
    // is for taking a slot, not for scanning a large one.
    let holder = uuid::Uuid::new_v4().to_string();
    let ttl = 30.0_f64;
    let lease_statement = client
        .prepare(
            "INSERT INTO greengateway.execution_leases AS l
                 (deployment_id, scope, slot, fence, holder_instance, invocation,
                  acquired_at, renewed_at, expires_at)
             SELECT $1, $2, s.slot, nextval('greengateway.execution_lease_fence'),
                    $4::text::uuid, $5, now(), now(), now() + make_interval(secs => $6::double precision)
             FROM generate_series(0, $3::integer - 1) AS s(slot)
             WHERE NOT EXISTS (
                 SELECT 1 FROM greengateway.execution_leases e
                 WHERE e.deployment_id = $1 AND e.scope = $2 AND e.slot = s.slot
                   AND e.expires_at > now())
             ORDER BY s.slot
             LIMIT 1
             ON CONFLICT (deployment_id, scope, slot) DO UPDATE SET
                 fence = EXCLUDED.fence,
                 holder_instance = EXCLUDED.holder_instance,
                 invocation = EXCLUDED.invocation,
                 acquired_at = now(),
                 renewed_at = now(),
                 expires_at = EXCLUDED.expires_at
             WHERE l.expires_at <= now()
             RETURNING l.slot, l.fence",
        )
        .await
        .expect("the lease statement should prepare");
    let capacity = 1_i32;
    let observed = measure(count, warmup, |index| {
        let scope = format!("performance-{index}");
        let holder = holder.clone();
        let deployment = deployment.clone();
        let lease_statement = lease_statement.clone();
        async move {
            let row = client
                .query_opt(
                    &lease_statement,
                    &[
                        &deployment,
                        &scope,
                        &capacity,
                        &holder,
                        &"performance",
                        &ttl,
                    ],
                )
                .await
                .expect("the lease acquisition should succeed");
            assert!(row.is_some(), "a fresh scope always has a free slot");
        }
    })
    .await;
    record("lease_acquire", &observed);

    // --- connection_acquire_warm ------------------------------------
    //
    // The checkout itself, from a pool built the way
    // `storage/postgres.rs::build_pool` builds one — same manager, same
    // recycling statement (`ROLLBACK`, which is what makes a checkout cost
    // anything at all), same runtime. `deadpool_postgres` is the product's
    // pool, so the thing being timed here is the product's checkout even
    // though the pool was constructed by this file.
    //
    // "Warm" is made true rather than assumed: the pool is filled to its
    // maximum before the first sample, so no measurement pays for opening
    // a connection. That is the budget's own qualifier — a cold connect on
    // a loaded machine costs tens of milliseconds and is a different
    // number about a different thing.
    let pool = warm_pool(&cluster.database.runtime_dsn, 8).await;
    let observed = measure(count, warmup, |_| {
        let pool = pool.clone();
        async move {
            let connection = pool.get().await.expect("a warm checkout should succeed");
            drop(connection);
        }
    })
    .await;
    record("connection_acquire_warm", &observed);

    cluster.shutdown();
}

// =====================================================================
// The end-to-end budgets
// =====================================================================

/// **The two budgets that have a surface of their own.**
///
/// `control_plane_mutation` is a conditional policy write through the
/// admin API, timed end to end — validation, the six-step commit
/// transaction and the outbox row included, which is what the document's
/// "≤ 500 ms p99 including validation and outbox" names.
///
/// `reconcile_wait_after_new_revision` is the wait a *second* replica
/// makes a request pay after that write: the time from the commit
/// returning on replica `a` to replica `b` serving the new document. The
/// document budgets it at "≤ 250 ms bounded, then `503`", and the number
/// worth having is how long the bounded wait actually is, not that the
/// bound exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "nightly benchmark; run by the nightly-performance workflow"]
async fn the_control_plane_budgets_are_met_end_to_end() {
    let Some(mut cluster) = start_performance_cluster(2).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    // A commit chain: each iteration writes, records its own latency, and
    // hands its ETag to the next. Fewer samples than a statement
    // measurement takes, because each one is a real transaction against a
    // shared server and 2 000 of them would be a load test rather than a
    // latency measurement.
    let commits = samples().clamp(50, 200);
    let mut etag = cluster.seed_policy_etag.clone();
    let mut mutation_ms = Vec::with_capacity(commits);
    let mut reconcile_ms = Vec::with_capacity(commits);

    for index in 0..commits {
        let marker = format!("perf-{index}");
        let started = Instant::now();
        let (status, headers, body) = cluster
            .put("a", &policy_route())
            .bearer(&admin)
            .if_match(&etag)
            .json(&marked_policy(&marker))
            .send_with_headers()
            .await;
        let elapsed = started.elapsed();
        assert_eq!(status, 200, "the control-plane write should commit: {body}");
        mutation_ms.push(elapsed.as_secs_f64() * 1_000.0);
        etag = headers
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_else(|| panic!("a policy commit should answer with its ETag"))
            .to_owned();

        // The reconcile wait, measured from the commit's return: how long
        // until the OTHER replica serves it. Polled tightly, because a
        // coarse poll would measure the poll interval.
        let started = Instant::now();
        let deadline = started + Duration::from_secs(30);
        loop {
            let (status, _, body) = cluster
                .get("b", &policy_route())
                .bearer(&admin)
                .send_with_headers()
                .await;
            if status == 200 && body["roles"].get(&marker).is_some() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "replica b never observed commit {index}; it last said {status} {body}"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        reconcile_ms.push(started.elapsed().as_secs_f64() * 1_000.0);
    }

    record("control_plane_mutation", &quantiles(mutation_ms));
    record(
        "reconcile_wait_after_new_revision",
        &quantiles(reconcile_ms),
    );

    cluster.shutdown();
}

// =====================================================================
// The aggregate rule
// =====================================================================

/// **`ha-state-model.md:100`: the authority adds no more than 25 ms p99 to
/// a protected request's pre-upstream critical path in cluster mode, and
/// 0 ms in standalone mode.**
///
/// The only way to measure "what the authority added" is to measure the
/// same request without it, so this starts a **standalone** gateway beside
/// the cluster — same binary, same fake issuer, same fake upstream, same
/// policy, no PostgreSQL — and subtracts. Everything else about the two
/// processes is held equal so the difference is the authority and not the
/// harness.
///
/// The subtraction is p99 minus p99 rather than a per-request difference,
/// which is what the document's wording ("adds no more than 25 ms p99")
/// describes: two tails compared, not one request measured twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "nightly benchmark; run by the nightly-performance workflow"]
async fn cluster_mode_adds_less_than_the_aggregate_budget_to_a_protected_request() {
    let Some(mut cluster) = start_performance_cluster(1).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");
    let count = samples().min(1_000);

    // Cluster mode: the full authority path — revision check, revocation
    // lookup, shared rate-limit decision, pool checkout — in front of the
    // proxy.
    let clustered =
        measure_protected_requests(&cluster.replica("a").base_url(), &admin, count).await;

    // Standalone: the same binary, the same request, no authority.
    let mut standalone = Standalone::start(&cluster).await;
    let alone = measure_protected_requests(&standalone.base_url(), &admin, count).await;
    standalone.replica.stop();

    let added = (clustered.p99_ms - alone.p99_ms).max(0.0);
    let within_budget = added <= AGGREGATE_BUDGET_MS;
    set_field(
        "aggregate",
        json!({
            "budget_source": BUDGET_SOURCE,
            "budget_added_p99_ms": AGGREGATE_BUDGET_MS,
            "cluster_p99_ms": rounded(clustered.p99_ms),
            "standalone_p99_ms": rounded(alone.p99_ms),
            "observed_added_p99_ms": rounded(added),
            "samples": clustered.samples,
            "within_budget": within_budget,
        }),
    );
    eprintln!(
        "aggregate: cluster p99 {:.3} ms, standalone p99 {:.3} ms, added {:.3} ms against a \
         budget of {AGGREGATE_BUDGET_MS:.0} ms",
        clustered.p99_ms, alone.p99_ms, added
    );
    assert!(
        within_budget,
        "cluster mode added {added:.3} ms at p99 to a protected request against a budget of \
         {AGGREGATE_BUDGET_MS:.0} ms ({BUDGET_SOURCE})"
    );

    cluster.shutdown();
}

/// The same binary, serving the same policy to the same principals
/// against the same upstream, with **no authority at all**.
///
/// The baseline the aggregate rule is defined against. Built here rather
/// than in the harness because only this suite wants it, and built by
/// subtraction from a real replica's environment rather than from scratch:
/// every setting the two processes share is then shared by construction,
/// and the difference between them is exactly the list below.
struct Standalone {
    replica: harness::replica::Replica,
    #[allow(dead_code)] // held for its Drop: the policy and audit files live here
    files: harness::TempDir,
}

impl Standalone {
    /// Settings that select or configure the shared authority. Removing
    /// exactly these turns a cluster replica's environment into a
    /// standalone one; `Config::from_env` refuses a configuration that
    /// names a local authority while `STATE_BACKEND=postgres`, so the two
    /// shapes cannot be merged and the removal has to be explicit.
    const AUTHORITY_SETTINGS: &'static [&'static str] = &[
        "STATE_BACKEND",
        "DEPLOYMENT_ID",
        "DATABASE_URL_FILE",
        "DATABASE_TLS_MODE",
        "DATABASE_POOL_MAX",
        "DATABASE_STATEMENT_TIMEOUT_MS",
        "CLUSTER_HEARTBEAT_MS",
        "CLUSTER_MEMBER_STALE_MS",
        "READINESS_PROBE_CACHE_MS",
        "RATE_LIMIT_KEYRING",
        "ADMIN_LOGIN_KEYRING",
        "ADMIN_LOGIN_PROVIDER",
        "AUDIT_LOG_FILE",
        "POLICY_FILE",
    ];

    async fn start(cluster: &Cluster) -> Self {
        let files = harness::TempDir::new("performance-standalone");
        let policy_path = files.write_private("policy.json", admin_policy().as_bytes());
        let audit_path = files.path().join("audit-standalone.jsonl");

        let mut env: Vec<(String, String)> = cluster
            .replica("a")
            .environment()
            .into_iter()
            .filter(|(key, _)| !Self::AUTHORITY_SETTINGS.contains(&key.as_str()))
            .collect();
        env.push(("POLICY_FILE".to_owned(), policy_path.display().to_string()));
        env.push((
            "AUDIT_LOG_FILE".to_owned(),
            audit_path.display().to_string(),
        ));

        let mut replica =
            harness::replica::Replica::spawn("standalone", cluster.binary(), env, audit_path);
        replica
            .wait_until_listening(harness::replica::LISTEN_BUDGET)
            .await;
        replica
            .wait_until_ready(harness::replica::READY_BUDGET)
            .await;
        Self { replica, files }
    }

    fn base_url(&self) -> String {
        self.replica.base_url()
    }
}

/// Requests [`measure_protected_requests`] issues and discards before it
/// starts timing. Named because the audit-enqueue row counts the rows every
/// request leaves, warm-up included.
const PROTECTED_WARMUP: usize = 50;

/// Time `count` protected proxied requests against one base URL.
async fn measure_protected_requests(base_url: &str, token: &str, count: usize) -> Quantiles {
    measure(count, PROTECTED_WARMUP, |_| {
        protected_request(base_url, token)
    })
    .await
}

async fn protected_request(base_url: &str, token: &str) {
    let response = harness::http_client()
        .get(format!("{base_url}{PROXIED_PATH}"))
        .bearer_auth(token)
        .send()
        .await
        .expect("the gateway should answer");
    assert_eq!(
        response.status().as_u16(),
        200,
        "a measured protected request must be served"
    );
    response
        .bytes()
        .await
        .expect("the measured response body must complete");
}

// =====================================================================
// The audit query
// =====================================================================

/// **The parent contract's headline number: a filtered audit query over a
/// million rows, under 500 ms.**
///
/// Two things about this one are worth knowing before reading the number.
///
/// First, the query is the PostgreSQL audit store's own
/// (`storage/postgres_audit.rs::query_events`, whose projection is the
/// `QUERY_EVENTS_SQL` constant), copied verbatim with a filter set an
/// operator would actually use — an event type, a time window, a status —
/// and the keyset `ORDER BY id DESC LIMIT n` the store always applies.
///
/// The admin audit route now reaches this store in cluster mode. This
/// benchmark still measures the statement directly: loading a million
/// synthetic rows in one statement isolates database query cost from
/// ingestion and HTTP overhead. Handler wiring is covered separately by
/// the PostgreSQL app integration test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "nightly benchmark; run by the nightly-performance workflow"]
async fn the_audit_filtered_query_answers_a_million_rows_within_its_budget() {
    let Some(mut cluster) = start_performance_cluster(1).await else {
        return skipped();
    };
    let session = RuntimeSession::connect(&cluster.database.migrator_dsn).await;
    let client = session.client();

    // One statement, because a million single-row inserts would measure
    // the harness. The shape is a realistic mix: twenty event types, a
    // thousand actors, fifty paths, spread across a day.
    let loaded = Instant::now();
    client
        .execute(
            "INSERT INTO greengateway.audit_events
               (event_id, event_type, occurred_at, schema_version, request_id, source_ip,
                actor_user_id, actor_issuer, actor_auth_mode, payload_method, payload_path,
                payload_status, payload_json)
             SELECT
               'perf-' || g,
               'http.request_observed',
               now() - make_interval(secs => (g % 86400)),
               '0.1.0',
               'req-' || g,
               '127.0.0.1',
               'user-' || (g % 1000),
               'https://issuer.performance.test',
               'jwt',
               'GET',
               '/api/resource/' || (g % 50),
               CASE WHEN g % 20 = 0 THEN 403 ELSE 200 END,
               '{\"status\":200}'::jsonb
             FROM generate_series(1, $1::bigint) AS g",
            &[&AUDIT_QUERY_ROWS],
        )
        .await
        .expect("the audit fixture should load");
    client
        .batch_execute("ANALYZE greengateway.audit_events")
        .await
        .expect("the audit fixture should analyze");
    eprintln!(
        "audit fixture: {AUDIT_QUERY_ROWS} rows loaded and analyzed in {:?}",
        loaded.elapsed()
    );

    let rows: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM greengateway.audit_events WHERE event_id LIKE 'perf-%'",
            &[],
        )
        .await
        .expect("the audit row count should read")
        .get(0);
    assert_eq!(
        rows, AUDIT_QUERY_ROWS,
        "the benchmark is only meaningful at the row count it claims"
    );

    // `QUERY_EVENTS_SQL` verbatim, with the filter set assembled the way
    // `query_events` assembles it and the keyset limit it always appends.
    //
    // The filters are `event_type` and `payload_status`, and the omission
    // of the time window is not a simplification — it is a defect this
    // transcription found. `query_events` renders the `from`/`to` clauses
    // as `occurred_at >= $N::timestamptz` and binds a `String` for them
    // (`params.push(Box::new(from.to_owned()))`). PostgreSQL resolves an
    // explicitly cast parameter to the cast's target type, so the
    // parameter is `timestamptz` and `tokio_postgres` refuses the bind
    // with `WrongType { postgres: Timestamptz, rust: "&str" }` before the
    // statement ever runs. Every filtered query carrying a time window is
    // therefore an error rather than a page. It is unreachable today
    // because no HTTP route reaches this store (see the doc comment), and
    // it is why this benchmark measures the two clauses that do bind.
    let statement = client
        .prepare(
            r#"
SELECT
    id,
    event_id,
    event_type,
    to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    schema_version,
    request_id,
    source_ip,
    user_agent,
    actor_json::text,
    payload_json::text
FROM greengateway.audit_events
WHERE event_type = $1 AND payload_status = $2 ORDER BY id DESC LIMIT $3"#,
        )
        .await
        .expect("the audit query should prepare");
    let event_type = "http.request_observed";
    let status = 403_i32;
    let limit = 51_i64; // the store fetches limit + 1 to decide `has_more`

    let observed = measure(50, 5, |_| async {
        let page = client
            .query(&statement, &[&event_type, &status, &limit])
            .await
            .expect("the audit query should succeed");
        assert_eq!(
            page.len(),
            limit as usize,
            "the fixture holds far more matching rows than one page"
        );
    })
    .await;

    let within_budget = observed.p99_ms <= AUDIT_QUERY_BUDGET_MS;
    set_field(
        "audit_query",
        json!({
            "rows": AUDIT_QUERY_ROWS,
            "budget_ms": AUDIT_QUERY_BUDGET_MS,
            "budget_source": "the #241 verification matrix: \"the audit filtered-query \
                              benchmark at one million rows under 500 ms\"",
            "source_anchor": "gateway/src/storage/postgres_audit.rs::query_events",
            "method": "authority_statement",
            "exposed_over_http": false,
            "samples": observed.samples,
            "p50_ms": rounded(observed.p50_ms),
            "p95_ms": rounded(observed.p95_ms),
            "p99_ms": rounded(observed.p99_ms),
            "observed_ms": rounded(observed.p99_ms),
            "within_budget": within_budget,
        }),
    );
    eprintln!(
        "audit_query: p50 {:.3} ms, p99 {:.3} ms over {AUDIT_QUERY_ROWS} rows against a budget \
         of {AUDIT_QUERY_BUDGET_MS:.0} ms",
        observed.p50_ms, observed.p99_ms
    );
    assert!(
        within_budget,
        "the filtered audit query spent {:.3} ms at p99 over {AUDIT_QUERY_ROWS} rows against a \
         budget of {AUDIT_QUERY_BUDGET_MS:.0} ms",
        observed.p99_ms
    );

    cluster.shutdown();
}

// =====================================================================
// The audit-enqueue budget, under a stalled sink
// =====================================================================

/// How long the durable rows are given to land once the stall is lifted,
/// and how long the sink is given to wedge behind the lock before it.
const AUDIT_ROWS_BUDGET: Duration = Duration::from_secs(30);
/// Timed requests in the primer run that gives the stalled sink a batch to
/// get stuck on (plus its [`PROTECTED_WARMUP`]).
const STALL_PRIMER: usize = 8;

/// **`audit_enqueue`: 0 ms on the request path — measured, since issue
/// #11's PostgreSQL audit sink gave cluster mode a durable writer to
/// stall.**
///
/// The document's ninth budget is not a latency, it is a claim about where
/// the work happens: "Bounded queue; backpressure/strictness per the
/// failure matrix." Before #11 no serving replica wrote a durable audit
/// row, so there was no sink to stall and this row could only assert the
/// claim structurally — it was a tripwire asserting `greengateway.audit_events`
/// stayed EMPTY under traffic, to fail the day a sink arrived. It did, and
/// this is the rewrite that tripwire asked for.
///
/// Every serving replica now composes `audit/postgres_sink.rs`: `emit`
/// pushes onto a bounded buffer and returns, and a flusher task of the
/// sink's own batches the buffer into `AuditEventStore::insert_events`. So
/// the experiment is: hold `ACCESS EXCLUSIVE` on the table for the whole of
/// a second measured run, so every batch the sink tries to land blocks,
/// and show the request p99 does not move. Then release it and show the
/// rows land — one per request served, none missing, none twice.
///
/// What this row asserts, all of it observable:
///
/// 1. The queue is bounded and its bound is published — a queue whose
///    capacity nobody can see is not a bounded queue in any operational
///    sense.
/// 2. With the sink stalled, the request p99 stays within the aggregate
///    budget of the unstalled p99 (or twice it, whichever is looser). A
///    request path that waited for the sink would carry the stall itself:
///    seconds, not milliseconds.
/// 3. Nothing is dropped, on either counter: the stall is far shorter
///    than the sink's retry budget, so the buffered batches land once the
///    lock goes.
/// 4. The queue drains, and `greengateway.audit_events` holds exactly one
///    row per request served, warm-up included — the inverse of the old
///    tripwire. The non-ignored twin of that assertion is
///    `ha_smoke::every_served_request_leaves_exactly_one_durable_audit_row`,
///    so a pull request fails on it rather than a nightly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "nightly benchmark; run by the nightly-performance workflow"]
async fn the_audit_enqueue_stays_off_the_request_path() {
    let Some(mut cluster) = start_performance_cluster(1).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");
    let count = samples().min(500);
    let base_url = cluster.replica("a").base_url();
    // The counter every shed event lands on, whichever sink shed it, read
    // off `/metrics` the way an operator reads it. Baselined, because a
    // replica may drop a handful of events during a cold start on a loaded
    // machine, and those are not this row's.
    let dropped_before =
        harness::metric_sum(&cluster.metrics("a").await, "audit_events_dropped_total");

    // The unstalled run, then the same run with the sink's batch insert
    // blocked for the duration. The stall is made real before it is
    // measured — a short primer run gives the sink a batch, and the lock
    // holder waits until that batch is observed wedged behind it — because
    // a lock nobody is waiting on stalls nothing.
    let unstalled = measure_protected_requests(&base_url, &admin, count).await;
    // Preserve the full sample count, but divide it into independently
    // bounded stalls. A slow hosted runner must not stretch the fixture past
    // the product's retry budget and misreport expected shedding as a bug.
    let mut stalled_samples = Vec::with_capacity(count);
    let mut stall = Duration::ZERO;
    let mut windows = 0;
    let mut blocked_writers = 0;
    while stalled_samples.len() < count {
        let lock = cluster.database.hold_audit_events_exclusively().await;
        let started = Instant::now();
        let remaining = (count - stalled_samples.len()).min(20);
        let measured = tokio::time::timeout(Duration::from_secs(5), async {
            for _ in 0..STALL_PRIMER {
                protected_request(&base_url, &admin).await;
            }
            cluster
                .database
                .wait_for_blocked_audit_writer(Duration::from_secs(2))
                .await;
            blocked_writers += cluster.database.blocked_audit_writers().await;
            for _ in 0..remaining {
                let request_started = Instant::now();
                protected_request(&base_url, &admin).await;
                stalled_samples.push(request_started.elapsed().as_secs_f64() * 1000.0);
            }
        })
        .await;
        lock.release().await;
        measured.expect("the benchmark could not finish a 20-request stall window in 5s; investigate runner capacity before interpreting audit-loss results");
        stall = stall.max(started.elapsed());
        windows += 1;
        // Let a committed batch become visible before taking another lock.
        // Otherwise repeated short stalls can form one long outage.
        let expected = PROTECTED_WARMUP + count + stalled_samples.len() + windows * STALL_PRIMER;
        let deadline = Instant::now() + AUDIT_ROWS_BUDGET;
        loop {
            let rows = cluster.database.count(&format!(
                "SELECT count(*)::bigint FROM greengateway.audit_events WHERE event_type = 'http.request_observed' AND payload_path = '{PROXIED_PATH}' AND payload_status = 200"
            )).await;
            if rows >= expected as i64 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "a stall window must drain before the next one starts"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    let stalled = quantiles(stalled_samples);
    let served = PROTECTED_WARMUP + 2 * count + windows * STALL_PRIMER;

    // The queue's own account of itself, from the surface an operator
    // reads.
    let (status, body) = cluster
        .get("a", "/v1/admin/cluster")
        .bearer(&admin)
        .send()
        .await;
    assert_eq!(status, 200, "the cluster status should answer: {body}");
    let capacity = body["audit"]["queue_capacity"]
        .as_i64()
        .unwrap_or_else(|| panic!("the audit queue's capacity should be reported: {body}"));
    let queue_dropped = body["audit"]["dropped_total"]
        .as_i64()
        .unwrap_or_else(|| panic!("the audit drop counter should be reported: {body}"));

    // Drained: depth back to zero and the oldest queued record young
    // again once the sink has caught up. Polled, because "has the sink
    // caught up" is an observable and not a duration to guess at.
    let deadline = Instant::now() + AUDIT_ROWS_BUDGET;
    let drained = loop {
        // An authenticated status request enqueues its own auth events before
        // reading status. Use the exempt metrics probe to observe quiescence.
        let metrics = cluster.metrics("a").await;
        assert!(metrics.contains("greengateway_audit_queue_depth"));
        assert!(metrics.contains("greengateway_audit_queue_oldest_age_seconds"));
        let depth = harness::metric_sum(&metrics, "greengateway_audit_queue_depth");
        let oldest = harness::metric_sum(&metrics, "greengateway_audit_queue_oldest_age_seconds");
        if depth == 0.0 && oldest < 1.0 {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    // The rows: every request the measurement made, served `200`, as one
    // observation row each. Polled up to the same budget, because the
    // sink's last batch lands a flush interval after the last request.
    let deadline = Instant::now() + AUDIT_ROWS_BUDGET;
    let durable_rows = loop {
        let rows = cluster
            .database
            .count(&format!(
                "SELECT count(*)::bigint FROM greengateway.audit_events \
                 WHERE event_type = 'http.request_observed' \
                   AND payload_path = '{PROXIED_PATH}' AND payload_status = 200"
            ))
            .await;
        if rows >= served as i64 || Instant::now() >= deadline {
            break rows;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    let sink_dropped =
        harness::metric_sum(&cluster.metrics("a").await, "audit_events_dropped_total")
            - dropped_before;

    let stalled_budget_ms = (2.0 * unstalled.p99_ms).max(unstalled.p99_ms + AGGREGATE_BUDGET_MS);
    let latency_held = stalled.p99_ms <= stalled_budget_ms;
    let within_budget = capacity > 0
        && queue_dropped == 0
        && sink_dropped < 1.0
        && drained
        && durable_rows == served as i64
        && latency_held;
    {
        let mut report = report()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        report.document["measurements"]
            .as_array_mut()
            .expect("the report's measurements are an array")
            .push(json!({
                "name": "audit_enqueue",
                "budget_source": BUDGET_SOURCE,
                "budget_p99_ms": 0.0,
                "method": "stall_experiment",
                "source_anchor": "gateway/src/audit/postgres_sink.rs (emit and the flusher) \
                                  under ACCESS EXCLUSIVE on greengateway.audit_events, and \
                                  the audit block of GET /v1/admin/cluster",
                "samples": stalled.samples,
                "unstalled_p50_ms": rounded(unstalled.p50_ms),
                "unstalled_p95_ms": rounded(unstalled.p95_ms),
                "unstalled_p99_ms": rounded(unstalled.p99_ms),
                "stalled_p50_ms": rounded(stalled.p50_ms),
                "stalled_p95_ms": rounded(stalled.p95_ms),
                "stalled_p99_ms": rounded(stalled.p99_ms),
                "stall_ms": rounded(stall.as_secs_f64() * 1_000.0),
                "stall_windows": windows,
                "stall_ms_meaning": "longest bounded window",
                "blocked_batch_inserts_at_start": blocked_writers,
                "stalled_budget_p99_ms": rounded(stalled_budget_ms),
                "p99_ms": rounded(stalled.p99_ms),
                "queue_capacity": capacity,
                "dropped_total": queue_dropped,
                "sink_dropped_total": sink_dropped,
                "queue_drained": drained,
                "requests_served": served,
                "durable_audit_rows": durable_rows,
                "within_budget": within_budget,
                "regressed": false,
            }));
        write_report(&report);
    }
    eprintln!(
        "audit_enqueue: {count} requests at p99 {:.3} ms unstalled and {:.3} ms with the sink \
         stalled for {stall:?} ({blocked_writers} batch insert(s) blocked when the stalled \
         run began); queue capacity {capacity}, dropped {queue_dropped} (sink {sink_dropped}), \
         drained {drained}, durable rows {durable_rows} for {served} served",
        unstalled.p99_ms, stalled.p99_ms
    );

    assert!(
        capacity > 0,
        "the audit queue must publish a bound; an unbounded queue is not the design the state \
         model budgets"
    );
    assert!(
        latency_held,
        "with the audit sink stalled for {stall:?} the request p99 went from {:.3} ms to \
         {:.3} ms against a bound of {stalled_budget_ms:.3} ms: the enqueue is on the request \
         path",
        unstalled.p99_ms, stalled.p99_ms
    );
    assert_eq!(
        queue_dropped, 0,
        "no audit record may be dropped at this load; the writer queue dropped {queue_dropped}"
    );
    assert!(
        sink_dropped < 1.0,
        "no audit record may be dropped by a stall this short; the sinks dropped {sink_dropped}"
    );
    assert!(
        drained,
        "the audit queue never drained after {served} requests, so the sink is not keeping up \
         with a load this small"
    );
    assert_eq!(
        durable_rows, served as i64,
        "greengateway.audit_events holds {durable_rows} observation rows for the {served} \
         requests served: fewer is a lost batch, more is a duplicated one"
    );

    cluster.shutdown();
}

// =====================================================================
// The completeness gate
// =====================================================================

/// **Every budget the document publishes is either measured here or
/// declared unmeasurable here.**
///
/// The failure this exists for is quiet: a budget row added to
/// `ha-state-model.md` §6 that nothing measures, in an artifact that still
/// says `within_budget: true` for everything it happens to contain. So
/// this reads the document's own table and asserts its row count against
/// what this file covers.
///
/// It needs no database and is not `#[ignore]`d: a documentation change
/// that outruns the benchmark should fail on the pull request that makes
/// it, not on a nightly nobody is watching.
#[tokio::test]
async fn the_report_covers_every_budget_the_state_model_publishes() {
    let document = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the gateway crate has a parent directory")
        .join("docs/architecture/ha-state-model.md");
    let contents = std::fs::read_to_string(&document).unwrap_or_else(|error| {
        panic!(
            "the budgets document should be readable at {}: {error}",
            document.display()
        )
    });

    let mut in_section = false;
    let mut rows = Vec::new();
    let mut aggregate_stated = false;
    for line in contents.lines() {
        if line.starts_with("## ") {
            in_section = line.contains("Blocking budgets");
            continue;
        }
        if !in_section {
            continue;
        }
        if line.contains("25 ms p99") {
            aggregate_stated = true;
        }
        let trimmed = line.trim();
        if !trimmed.starts_with('|') {
            continue;
        }
        // Skip the header and its separator.
        if trimmed.contains("Operation |") || trimmed.starts_with("| ---") {
            continue;
        }
        let cell = trimmed
            .trim_start_matches('|')
            .split('|')
            .next()
            .unwrap_or_default()
            .trim()
            .to_owned();
        if !cell.is_empty() {
            rows.push(cell);
        }
    }

    assert!(
        aggregate_stated,
        "the aggregate rule (25 ms p99) is no longer stated in §6; this file's \
         AGGREGATE_BUDGET_MS is now uncited"
    );
    // Eight measured plus `audit_enqueue`, which is a stall experiment
    // rather than a timed operation.
    assert_eq!(
        rows.len(),
        BUDGETS.len() + 1,
        "§6 of {} publishes {} budgets and this file covers {} plus audit_enqueue. The rows \
         it publishes are {rows:?}. Add the new one to BUDGETS with a measurement, or — if it \
         is not a latency — add it the way audit_enqueue is added, with a test of its own \
         and a comment saying why.",
        document.display(),
        rows.len(),
        BUDGETS.len()
    );
    assert!(
        rows.iter().any(|row| row.contains("Audit enqueue")),
        "the audit-enqueue row is what this file covers by a stall experiment rather than by \
         a timed operation; §6 no longer publishes it, so that coverage is now unattached: \
         {rows:?}"
    );
}
