//! The capacity matrix (issue #439, PR 2).
//!
//! The rest of `performance.rs` asks whether each authority call is inside
//! the budget `docs/architecture/ha-state-model.md` §6 gives it. This module
//! asks the question an operator sizing a deployment asks instead: as the
//! replica count, the pool ceiling and the request mix change, how long do
//! requests wait for a database connection, how often do they give up, and
//! what does the database see while they do? `docs/performance/authority-cost.md`
//! counts the checkouts each request path makes; this runs those paths under
//! load and records what the product's own series say about them.
//!
//! ## What it gates, and what it does not
//!
//! **Only the harness's own validity.** There are no capacity budgets in
//! this repository and this file does not invent any. Every number is
//! recorded and published; nothing is compared with a threshold. The one
//! assertion is that every cell of the matrix produced complete evidence:
//! enough requests, at least one of them served, only the outcomes a
//! capacity run can legitimately produce (`200`, or `503` from a
//! dependency the gateway could not consult), the acquisition series and
//! pool gauges scraped from every replica, the classes the mix exercises
//! present in it, and the database sampled while the load ran. A cell
//! that falls short is recorded with fixed reason codes and the test fails
//! after the whole matrix has run, so the report shows every cell rather
//! than only the first that broke.
//!
//! The numbers come from one shared, hosted runner with the database, the
//! replicas and the load generator on the same machine. They identify how
//! this harness degrades as the matrix moves, on the hardware the report
//! names; they are not production SLOs, and target-environment capacity
//! approval stays with issue #389.
//!
//! ## The matrix
//!
//! Two replica counts, two pool ceilings and two request mixes, crossed,
//! plus one contention cell (see [`matrix`]). Every cell starts its own
//! cluster on a fresh database, so no cell inherits another's pool, buckets
//! or audit backlog, and every cell offers the same closed-loop load:
//! [`CONCURRENCY`] workers, spread evenly over the replicas, each sending
//! its next request as soon as the last one answers, for the measured
//! window ([`MEASURED_SECONDS_ENV`], 20 s by default).
//!
//! Each worker is its own client: it sends a documentation-range
//! `X-Forwarded-For` address of its own, which the replicas honour from
//! the loopback proxy the load generator stands in for. The global
//! limiter's shared bucket is keyed by client address, so one generator on
//! one address would queue every request in the deployment on a single
//! bucket row and measure that row rather than the deployment.
//!
//! * `jwt_proxy`: a proxied `GET` with a JWT carrying a `jti`. Three
//!   checkouts per request: `rate_limit`, `credential_check`,
//!   `revision_check`.
//! * `mixed_credentials`: per ten requests, six of those, three proxied
//!   `GET`s with a service token, and one admin policy read, which adds a
//!   `security_state_read` checkout for the authoritative document.
//! * The contention cell runs `mixed_credentials` while a writer commits
//!   policy documents on alternating replicas (each commit invalidates every
//!   replica's compiled state and every cached service-token verification)
//!   and a feeder appends observation batches to the audit stream for the
//!   discovery projector, on top of the audit rows every request writes.
//!
//! ## Where each number comes from
//!
//! * **Request latency, outcomes and throughput** are measured by the load
//!   generator, per request, with nearest-rank quantiles.
//! * **Pool acquisition** is `greengateway_database_pool_acquire_seconds`,
//!   scraped from each replica's `/metrics` before and after the measured
//!   window. Counts and sums are exact deltas over the window. The
//!   quantiles are the exporter's own: no buckets are configured, so it
//!   renders a summary over a rolling window of about a minute, and the
//!   scrape after the load covers the whole cell, cluster start and warm-up
//!   included. Its p50, p95 and p99 are DDSketch bucket representatives,
//!   within 0.01 % of the true value, while its maximum is exact, so a p99
//!   that shares the maximum's bucket can sit just above it (one sample in
//!   the window renders p50 = p95 = p99 above `max`); the validator orders
//!   those three against each other only. A series is reported only when
//!   its count moved during the window, and the deployment-wide counts
//!   list every class and outcome, so a zero `cancelled` is stated rather
//!   than implied by absence.
//! * **Pool gauges** (`size`, `available`, `waiting`) are sampled from the
//!   same endpoint every [`SAMPLE_INTERVAL`] while the load runs.
//! * **The database** is sampled on the same cadence from
//!   `pg_stat_activity` and `pg_locks`, as aggregate counts only, and
//!   `pg_stat_database` counters are differenced across the window. The
//!   harness reads them as the CI superuser; `authority-cost.md` says what
//!   a monitoring role needs to read the same thing in a deployment
//!   (nothing on the gateway's runtime role). Database CPU is not readable
//!   through SQL without an extension or host access, so it is not
//!   collected.
//!
//! ## What the report never carries
//!
//! No URL, port, DSN, role or database name, token, `jti`, request ID,
//! statement text, response body or error message. Labels are read only
//! when they belong to the fixed vocabularies below; anything else marks
//! the cell incomplete and is not copied. `scripts/check-test-evidence.py
//! capacity` re-checks all of this and rebuilds the uploaded file from an
//! allowlist, so a field this file starts emitting by mistake does not
//! reach the `ha-capacity` artifact. The `ha-capacity-diagnostics`
//! artifact, kept only when that report is incomplete or rejected, is this
//! file's report as written: it relies on the rules above alone.
//!
//! This is a module of the `ha_performance` target, not a target of its
//! own: it shares that target's harness, fixtures and nearest-rank
//! quantiles, and `tests/release_gate_workflow.rs` expects every `ha_*`
//! target other than `ha_performance` to be a release-gate leg. The
//! nightly workflow runs it in its own step (`--exact`), and the budget
//! step skips it, so a capacity cell can never fail a budget and a budget
//! can never hide a capacity cell.

use std::{
    collections::BTreeMap,
    path::PathBuf,
    time::{Duration, Instant},
};

use serde_json::{json, Value};

use crate::harness::{self, AuditEventSeed, Cluster, ClusterOptions, SeedActor, ADMIN_API_PREFIX};

// ---------------------------------------------------------------------
// The shape of a run
// ---------------------------------------------------------------------

/// Where the report is written. The nightly validates it into the
/// uploaded artifact; it is never uploaded as written unless the run
/// failed (as a diagnostic).
const REPORT_ENV: &str = "GATEWAY_TEST_CAPACITY_REPORT";

/// The measured window per cell, in seconds. 20 by default, clamped to
/// 5..=120 so a typo cannot stretch the nightly past its timeout.
const MEASURED_SECONDS_ENV: &str = "GATEWAY_TEST_CAPACITY_SECONDS";
const DEFAULT_MEASURED_SECONDS: u64 = 20;

/// Closed-loop workers per cell. Divisible by every replica count in
/// [`matrix`], so each replica is offered the same share of the load.
const CONCURRENCY: usize = 24;

/// The discarded run before the measured window: pools open their
/// connections and the first statements are planned here, not in the
/// numbers.
const WARMUP: Duration = Duration::from_secs(2);

/// How long a warm-up probe re-asks a replica that answered `503`.
const AUTHORITY_RETRY: Duration = Duration::from_secs(30);

/// A request the gateway has not answered in this long is recorded as a
/// client timeout. Twice the pool's own default wait
/// (`DATABASE_ACQUIRE_TIMEOUT_MS`, 5 s), so the gateway's bound fires
/// first unless something is wrong.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

/// The database and pool-gauge sampling cadence.
const SAMPLE_INTERVAL: Duration = Duration::from_millis(500);

/// The fewest database samples a measured window must have.
const MIN_ACTIVITY_SAMPLES: u64 = 3;

/// The contention cell's control-plane writer: the pause between commits,
/// and how long one commit is given to reach every replica.
const COMMIT_INTERVAL: Duration = Duration::from_millis(250);
const CONVERGENCE_BOUND: Duration = Duration::from_secs(10);
const CONVERGENCE_POLL: Duration = Duration::from_millis(10);

/// The contention cell's audit feeder: observations per batch, distinct
/// endpoint templates they spread over, and the pause between batches.
const AUDIT_BATCH: usize = 200;
const AUDIT_ENDPOINTS: usize = 20;
const AUDIT_INTERVAL: Duration = Duration::from_secs(1);

/// The proxied path every data-plane request in the matrix asks for.
const PROXIED_PATH: &str = "/echo/capacity";

/// The address worker `n` presents: TEST-NET-2 (RFC 5737), so no real
/// client can be named in an audit row this run writes.
fn client_address(worker: usize) -> String {
    format!("198.51.100.{}", worker % 250 + 1)
}

/// The cluster a cell runs on: the budget suite's options, the cell's pool
/// ceiling, and proxy headers trusted from loopback only, where the load
/// generator is.
fn cell_options(plan: &CellPlan) -> ClusterOptions {
    let mut options = ClusterOptions {
        pool_max: plan.pool_max,
        ..super::performance_options(plan.replicas)
    };
    options.shared_env.extend([
        ("TRUST_PROXY_HEADERS".to_owned(), "true".to_owned()),
        ("TRUSTED_PROXY_CIDRS".to_owned(), "127.0.0.1/32".to_owned()),
    ]);
    options
}

/// The acquisition family, as the exporter names it.
const ACQUIRE_FAMILY: &str = "greengateway_database_pool_acquire_seconds";

/// `storage::postgres::CheckoutClass`'s seven labels, in its order.
const OPERATION_CLASSES: [&str; 7] = [
    "revision_check",
    "credential_check",
    "rate_limit",
    "execution_lease",
    "security_state_read",
    "control_plane_write",
    "maintenance",
];

/// The acquisition series' outcomes: `none`, the six classified kinds
/// (`RepositoryErrorKind::metric_label`), and `cancelled`.
const ERROR_CLASSES: [&str; 8] = [
    "none",
    "unavailable",
    "timeout",
    "conflict",
    "invalid_data",
    "incompatible_schema",
    "internal",
    "cancelled",
];

/// The only statuses a complete cell may carry: served, or refused
/// because a dependency could not be consulted. Anything else is a
/// harness or configuration failure, not a capacity result.
const CAPACITY_STATUSES: [u16; 2] = [200, 503];

fn measured_window() -> Duration {
    let seconds = std::env::var(MEASURED_SECONDS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_MEASURED_SECONDS)
        .clamp(5, 120);
    Duration::from_secs(seconds)
}

// ---------------------------------------------------------------------
// The matrix
// ---------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestKind {
    JwtProxy,
    ServiceTokenProxy,
    AdminPolicyRead,
}

impl RequestKind {
    fn name(self) -> &'static str {
        match self {
            Self::JwtProxy => "jwt_proxy",
            Self::ServiceTokenProxy => "service_token_proxy",
            Self::AdminPolicyRead => "admin_policy_read",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mix {
    JwtProxy,
    MixedCredentials,
}

impl Mix {
    fn name(self) -> &'static str {
        match self {
            Self::JwtProxy => "jwt_proxy",
            Self::MixedCredentials => "mixed_credentials",
        }
    }

    fn kinds(self) -> &'static [RequestKind] {
        match self {
            Self::JwtProxy => &[RequestKind::JwtProxy],
            Self::MixedCredentials => &[
                RequestKind::JwtProxy,
                RequestKind::ServiceTokenProxy,
                RequestKind::AdminPolicyRead,
            ],
        }
    }

    /// The request a worker sends at its `sequence`th turn: a fixed
    /// rotation rather than a random draw, so two runs of a cell send the
    /// same mix.
    fn kind(self, sequence: usize) -> RequestKind {
        match self {
            Self::JwtProxy => RequestKind::JwtProxy,
            Self::MixedCredentials => match sequence % 10 {
                0..=5 => RequestKind::JwtProxy,
                6..=8 => RequestKind::ServiceTokenProxy,
                _ => RequestKind::AdminPolicyRead,
            },
        }
    }

    /// The checkout classes this mix must leave in the acquisition series
    /// (`authority-cost.md`'s summary table).
    fn classes(self) -> &'static [&'static str] {
        match self {
            Self::JwtProxy => &["rate_limit", "credential_check", "revision_check"],
            Self::MixedCredentials => &[
                "rate_limit",
                "credential_check",
                "revision_check",
                "security_state_read",
            ],
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct CellPlan {
    replicas: usize,
    pool_max: u32,
    mix: Mix,
    /// Concurrent policy commits and audit-stream batches.
    contention: bool,
}

impl CellPlan {
    fn name(&self) -> String {
        format!(
            "r{}-p{}-{}{}",
            self.replicas,
            self.pool_max,
            self.mix.name(),
            if self.contention { "-contention" } else { "" }
        )
    }

    fn required_classes(&self) -> Vec<&'static str> {
        let mut classes = self.mix.classes().to_vec();
        if self.contention {
            classes.push("control_plane_write");
        }
        classes
    }
}

/// Two replica counts x two pool ceilings x two mixes, then the contention
/// cell.
///
/// Two and three replicas, because one replica is not a cluster and every
/// added replica is another full pool against the same primary. Pool
/// ceilings of 2, where the leader's maintenance session can hold half the
/// pool, and 10, the product default `docs/deployment/pool-sizing.md`'s
/// arithmetic starts from. The contention cell runs at the default
/// ceiling, so what it adds is the concurrent work rather than a smaller
/// pool.
fn matrix() -> Vec<CellPlan> {
    let mut cells = Vec::new();
    for replicas in [2, 3] {
        for pool_max in [2, 10] {
            for mix in [Mix::JwtProxy, Mix::MixedCredentials] {
                cells.push(CellPlan {
                    replicas,
                    pool_max,
                    mix,
                    contention: false,
                });
            }
        }
    }
    cells.push(CellPlan {
        replicas: 2,
        pool_max: 10,
        mix: Mix::MixedCredentials,
        contention: true,
    });
    cells
}

/// Record `reason` once.
fn flag(reasons: &mut Vec<&'static str>, reason: &'static str) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

// ---------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------

/// The report, rewritten after every cell so a run that fails part-way
/// still leaves the cells it finished.
struct CapacityReport {
    path: PathBuf,
    document: Value,
}

impl CapacityReport {
    fn new(plans: &[CellPlan], measured: Duration) -> Self {
        let path = std::env::var(REPORT_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("ha-capacity.json"));
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let document = json!({
            "schema_version": 1,
            "producer": "ha-capacity",
            "recorded_at": super::now_rfc3339(),
            "git_sha": super::git_sha(),
            "binary_version": env!("CARGO_PKG_VERSION"),
            "runner": {
                "os": std::env::consts::OS,
                "cores": std::thread::available_parallelism()
                    .map(|count| count.get())
                    .unwrap_or(0),
            },
            "database": Value::Null,
            "method": {
                "concurrency": CONCURRENCY,
                "measured_seconds": measured.as_secs(),
                "warmup_seconds": WARMUP.as_secs(),
                "client_timeout_ms": CLIENT_TIMEOUT.as_millis() as u64,
                "sample_interval_ms": SAMPLE_INTERVAL.as_millis() as u64,
            },
            "matrix": plans.iter().map(CellPlan::name).collect::<Vec<_>>(),
            "cells": [],
        });
        let report = Self { path, document };
        report.write();
        report
    }

    fn write(&self) {
        let rendered = serde_json::to_string_pretty(&self.document)
            .unwrap_or_else(|error| panic!("the capacity report should serialize: {error}"));
        std::fs::write(&self.path, format!("{rendered}\n")).unwrap_or_else(|error| {
            panic!(
                "the capacity report should be writable at {}: {error}",
                self.path.display()
            )
        });
    }

    fn needs_database_facts(&self) -> bool {
        self.document["database"].is_null()
    }

    fn set_database_facts(&mut self, facts: Value) {
        self.document["database"] = facts;
        self.write();
    }

    fn push(&mut self, cell: Value) {
        self.document["cells"]
            .as_array_mut()
            .expect("the report's cells are an array")
            .push(cell);
        self.write();
    }
}

/// The server's description, as numbers: the version string is free text
/// the report has no reason to carry.
async fn database_facts(cluster: &Cluster) -> Value {
    let row = cluster
        .database
        .query_one(
            "SELECT current_setting('server_version_num')::bigint, \
                    current_setting('max_connections')::bigint, \
                    current_setting('superuser_reserved_connections')::bigint",
        )
        .await;
    json!({
        "server_version_num": row.get::<_, i64>(0),
        "max_connections": row.get::<_, i64>(1),
        "superuser_reserved_connections": row.get::<_, i64>(2),
    })
}

// ---------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------

/// The credentials a cell's requests carry. Held in memory only; nothing
/// here is written to the report or to a panic message.
struct Credentials {
    /// One JWT per worker, each with its own `jti`, so every request makes
    /// the revocation lookup a real deployment makes.
    jwts: Vec<String>,
    service_token: Option<String>,
}

impl Credentials {
    fn token(&self, kind: RequestKind, worker: usize) -> &str {
        match kind {
            RequestKind::ServiceTokenProxy => self
                .service_token
                .as_deref()
                .expect("a mix that sends service-token requests creates its token first"),
            RequestKind::JwtProxy | RequestKind::AdminPolicyRead => {
                &self.jwts[worker % self.jwts.len()]
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ended {
    Status(u16),
    ClientTimeout,
    ClientError,
}

#[derive(Clone, Copy, Debug)]
struct Outcome {
    kind: RequestKind,
    ended: Ended,
    millis: f64,
}

async fn send(base_url: &str, kind: RequestKind, token: &str, worker: usize) -> Outcome {
    let path = match kind {
        RequestKind::JwtProxy | RequestKind::ServiceTokenProxy => PROXIED_PATH.to_owned(),
        RequestKind::AdminPolicyRead => super::policy_route(),
    };
    let started = Instant::now();
    let ended = match harness::http_client()
        .get(format!("{base_url}{path}"))
        .bearer_auth(token)
        .header("x-forwarded-for", client_address(worker))
        .timeout(CLIENT_TIMEOUT)
        .send()
        .await
    {
        Ok(response) => {
            let status = response.status().as_u16();
            match response.bytes().await {
                Ok(_) => Ended::Status(status),
                Err(error) if error.is_timeout() => Ended::ClientTimeout,
                Err(_) => Ended::ClientError,
            }
        }
        Err(error) if error.is_timeout() => Ended::ClientTimeout,
        Err(_) => Ended::ClientError,
    };
    Outcome {
        kind,
        ended,
        millis: started.elapsed().as_secs_f64() * 1_000.0,
    }
}

/// [`CONCURRENCY`] closed-loop workers until `stop_at`. Worker `n` talks
/// to replica `n % replicas` directly, not through the harness balancer,
/// so the load each replica is offered is fixed and the balancer's own
/// proxying is not in the numbers.
async fn drive(
    targets: &[String],
    credentials: &Credentials,
    mix: Mix,
    stop_at: Instant,
) -> Vec<Outcome> {
    let workers = (0..CONCURRENCY).map(|worker| {
        let base_url = &targets[worker % targets.len()];
        async move {
            let mut outcomes = Vec::new();
            // Started at the worker's index so the workers are not all on
            // the same turn of the rotation at once.
            let mut sequence = worker;
            while Instant::now() < stop_at {
                let kind = mix.kind(sequence);
                sequence += 1;
                let token = credentials.token(kind, worker);
                outcomes.push(send(base_url, kind, token, worker).await);
            }
            outcomes
        }
    });
    futures_util::future::join_all(workers)
        .await
        .into_iter()
        .flatten()
        .collect()
}

/// Every request kind served once by every replica, then a discarded run.
///
/// A `503` while a replica finishes starting is re-asked; any other
/// refusal means the cell is misconfigured and answers `false`.
async fn warm_up(targets: &[String], credentials: &Credentials, mix: Mix) -> bool {
    for base_url in targets {
        for kind in mix.kinds() {
            let deadline = Instant::now() + AUTHORITY_RETRY;
            loop {
                let outcome = send(base_url, *kind, credentials.token(*kind, 0), 0).await;
                match outcome.ended {
                    Ended::Status(200) => break,
                    Ended::Status(503) | Ended::ClientTimeout if Instant::now() < deadline => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    _ => return false,
                }
            }
        }
    }
    drive(targets, credentials, mix, Instant::now() + WARMUP).await;
    true
}

async fn create_service_token(cluster: &Cluster, admin: &str) -> String {
    let deadline = Instant::now() + AUTHORITY_RETRY;
    loop {
        let (status, body) = cluster
            .post("a", &format!("{ADMIN_API_PREFIX}/tokens"))
            .bearer(admin)
            .json(&json!({ "scopes": [super::ADMIN_ROLE] }))
            .send()
            .await;
        if status == 201 {
            // The body is the one-time plaintext: never echoed, even here.
            return body["plaintext_token"]
                .as_str()
                .unwrap_or_else(|| panic!("the created service token carried no plaintext"))
                .to_owned();
        }
        assert!(
            status == 503 && Instant::now() < deadline,
            "creating the capacity service token answered {status}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

// ---------------------------------------------------------------------
// Sampling while the load runs
// ---------------------------------------------------------------------

/// The largest and the mean of one sampled count.
#[derive(Default)]
struct Spread {
    max: i64,
    sum: i64,
    samples: u64,
}

impl Spread {
    fn add(&mut self, value: i64) {
        self.max = self.max.max(value);
        self.sum += value;
        self.samples += 1;
    }

    fn json(&self) -> Value {
        let mean = if self.samples == 0 {
            0.0
        } else {
            self.sum as f64 / self.samples as f64
        };
        json!({ "max": self.max, "mean": super::rounded(mean) })
    }
}

/// What `pg_stat_activity` and `pg_locks` said, as counts, across the
/// window. Never a query text, a role name or an application name.
#[derive(Default)]
struct Activity {
    samples: u64,
    runtime_backends: Spread,
    active: Spread,
    idle: Spread,
    idle_in_transaction: Spread,
    lock_waiting: Spread,
    lwlock_waiting: Spread,
    io_waiting: Spread,
    ungranted_locks: Spread,
    longest_lock_wait_ms: f64,
}

/// One replica's pool gauges, sampled from `/metrics`.
#[derive(Clone, Copy)]
struct PoolGauges {
    size_max: f64,
    available_min: f64,
    waiting_max: f64,
}

impl Default for PoolGauges {
    fn default() -> Self {
        Self {
            size_max: 0.0,
            available_min: f64::MAX,
            waiting_max: 0.0,
        }
    }
}

/// One sample: the runtime role's sessions by state, every session in
/// this run's database that is waiting by wait type, and ungranted locks.
/// The role name is the harness's own (`ggw_ha_r_<uuid>`), never input.
fn activity_sql(role: &str) -> String {
    format!(
        "SELECT \
           count(*) FILTER (WHERE usename = '{role}')::bigint, \
           count(*) FILTER (WHERE usename = '{role}' AND state = 'active')::bigint, \
           count(*) FILTER (WHERE usename = '{role}' AND state = 'idle')::bigint, \
           count(*) FILTER (WHERE usename = '{role}' AND state LIKE 'idle in transaction%')::bigint, \
           count(*) FILTER (WHERE wait_event_type = 'Lock')::bigint, \
           count(*) FILTER (WHERE wait_event_type = 'LWLock')::bigint, \
           count(*) FILTER (WHERE wait_event_type = 'IO')::bigint, \
           coalesce(max(extract(epoch FROM clock_timestamp() - query_start)) \
             FILTER (WHERE wait_event_type = 'Lock'), 0)::float8, \
           (SELECT count(*) FROM pg_locks l JOIN pg_stat_activity w ON w.pid = l.pid \
             WHERE NOT l.granted AND w.datname = current_database())::bigint \
         FROM pg_stat_activity \
         WHERE datname = current_database() AND pid <> pg_backend_pid()"
    )
}

/// Sample the database and every replica's pool gauges until `stop_at`,
/// at least once.
///
/// Also empties the fake upstream's request log on every tick: it records
/// every proxied request, and a capacity run is exactly the workload that
/// would turn that log into the test process's largest allocation.
async fn sample(
    cluster: &Cluster,
    names: &[String],
    stop_at: Instant,
) -> (Activity, Vec<PoolGauges>) {
    let sql = activity_sql(&cluster.database.role);
    let mut activity = Activity::default();
    let mut gauges = vec![PoolGauges::default(); names.len()];
    loop {
        let row = cluster.database.query_one(&sql).await;
        activity.samples += 1;
        activity.runtime_backends.add(row.get::<_, i64>(0));
        activity.active.add(row.get::<_, i64>(1));
        activity.idle.add(row.get::<_, i64>(2));
        activity.idle_in_transaction.add(row.get::<_, i64>(3));
        activity.lock_waiting.add(row.get::<_, i64>(4));
        activity.lwlock_waiting.add(row.get::<_, i64>(5));
        activity.io_waiting.add(row.get::<_, i64>(6));
        activity.longest_lock_wait_ms = activity
            .longest_lock_wait_ms
            .max(row.get::<_, f64>(7) * 1_000.0);
        activity.ungranted_locks.add(row.get::<_, i64>(8));

        for (index, name) in names.iter().enumerate() {
            let text = cluster.metrics(name).await;
            let replica = &mut gauges[index];
            replica.size_max = replica.size_max.max(harness::metric_sum(
                &text,
                "greengateway_database_pool_size",
            ));
            replica.available_min = replica.available_min.min(harness::metric_sum(
                &text,
                "greengateway_database_pool_available",
            ));
            replica.waiting_max = replica.waiting_max.max(harness::metric_sum(
                &text,
                "greengateway_database_pool_waiting",
            ));
        }
        cluster.upstream.clear();

        if Instant::now() >= stop_at {
            return (activity, gauges);
        }
        tokio::time::sleep(SAMPLE_INTERVAL).await;
    }
}

/// `pg_stat_database`'s work counters for this run's database. Each
/// backend flushes its own counts at most about once a second, so a delta
/// can trail its window by about that much.
async fn database_counters(cluster: &Cluster) -> [i64; 6] {
    let row = cluster
        .database
        .query_one(
            "SELECT xact_commit, xact_rollback, deadlocks, blks_hit, blks_read, temp_files \
             FROM pg_stat_database WHERE datname = current_database()",
        )
        .await;
    [
        row.get::<_, i64>(0),
        row.get::<_, i64>(1),
        row.get::<_, i64>(2),
        row.get::<_, i64>(3),
        row.get::<_, i64>(4),
        row.get::<_, i64>(5),
    ]
}

const DATABASE_COUNTERS: [&str; 6] = [
    "xact_commit",
    "xact_rollback",
    "deadlocks",
    "blks_hit",
    "blks_read",
    "temp_files",
];

// ---------------------------------------------------------------------
// The contention cell's concurrent work
// ---------------------------------------------------------------------

#[derive(Default)]
struct ControlPlane {
    statuses: BTreeMap<u16, u64>,
    commit_ms: Vec<f64>,
    convergence_ms: Vec<f64>,
    convergence_timeouts: u64,
}

/// The security revision the authority holds now.
async fn authority_revision(cluster: &Cluster) -> i64 {
    cluster
        .database
        .query_one("SELECT last_revision FROM greengateway.security_revision_state WHERE singleton")
        .await
        .get::<_, i64>(0)
}

/// How long until every replica's compiled security revision reaches
/// `revision`, read from the gauge each replica publishes; `None` past
/// [`CONVERGENCE_BOUND`].
async fn convergence(cluster: &Cluster, names: &[String], revision: i64) -> Option<f64> {
    let started = Instant::now();
    loop {
        let mut current = true;
        for name in names {
            let compiled = harness::metric_sum(
                &cluster.metrics(name).await,
                "greengateway_security_revision_compiled",
            );
            if compiled < revision as f64 {
                current = false;
                break;
            }
        }
        if current {
            return Some(started.elapsed().as_secs_f64() * 1_000.0);
        }
        if started.elapsed() >= CONVERGENCE_BOUND {
            return None;
        }
        tokio::time::sleep(CONVERGENCE_POLL).await;
    }
}

/// Commit policy documents on alternating replicas until `stop_at`, timing
/// each commit and how long every replica takes to compile it. The next
/// commit starts [`COMMIT_INTERVAL`] after the last one converged (or gave
/// up after [`CONVERGENCE_BOUND`]), so commits are at most four a second.
async fn churn_control_plane(
    cluster: &Cluster,
    names: &[String],
    admin: &str,
    stop_at: Instant,
) -> ControlPlane {
    let mut churn = ControlPlane::default();
    let mut etag = cluster.database.active_policy_etag().await;
    let mut index = 0_usize;
    while Instant::now() < stop_at {
        let replica = &names[index % names.len()];
        let marker = format!("capacity-{index}");
        index += 1;
        let started = Instant::now();
        let (status, headers, _) = cluster
            .put(replica, &super::policy_route())
            .bearer(admin)
            .if_match(&etag)
            .json(&super::marked_policy(&marker))
            .send_with_headers()
            .await;
        churn
            .commit_ms
            .push(started.elapsed().as_secs_f64() * 1_000.0);
        *churn.statuses.entry(status).or_default() += 1;
        if status == 200 {
            etag = match headers
                .get(reqwest::header::ETAG)
                .and_then(|value| value.to_str().ok())
            {
                Some(value) => value.to_owned(),
                None => cluster.database.active_policy_etag().await,
            };
            let revision = authority_revision(cluster).await;
            match convergence(cluster, names, revision).await {
                Some(milliseconds) => churn.convergence_ms.push(milliseconds),
                None => churn.convergence_timeouts += 1,
            }
        } else {
            // Whatever happened, the next commit is made against what the
            // authority holds, not against a guess.
            etag = cluster.database.active_policy_etag().await;
        }
        tokio::time::sleep(COMMIT_INTERVAL).await;
    }
    churn
}

/// Whole seconds: the audit store's timestamps need no more, and a fixed
/// shape keeps the seeded rows boring.
fn audit_timestamp() -> String {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    time::OffsetDateTime::from_unix_timestamp(now)
        .ok()
        .and_then(|instant| {
            instant
                .format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| "2026-01-01T00:00:00Z".to_owned())
}

/// Append an observation batch to the audit stream every
/// [`AUDIT_INTERVAL`] until `stop_at`, through the production statements
/// and lock ([`harness::Database::ingest_audit_events`]), attributed to
/// the live members. Answers how many it appended.
async fn feed_audit_backlog(cluster: &Cluster, stop_at: Instant) -> u64 {
    let members = cluster.member_identities().await;
    if members.is_empty() {
        return 0;
    }
    let mut ingested = 0_u64;
    while Instant::now() < stop_at {
        let occurred_at = audit_timestamp();
        let batch: Vec<AuditEventSeed> = (0..AUDIT_BATCH)
            .map(|index| {
                let member = members[index % members.len()];
                AuditEventSeed::observation(
                    "GET",
                    &format!("/capacity/backlog/{}", index % AUDIT_ENDPOINTS),
                    &occurred_at,
                    Some(SeedActor::bearer("capacity-backlog")),
                )
                .attributed_to(member.instance_id, member.boot_id)
            })
            .collect();
        cluster.database.ingest_audit_events(&batch).await;
        ingested += batch.len() as u64;
        tokio::time::sleep(AUDIT_INTERVAL).await;
    }
    ingested
}

/// The projector's committed checkpoint and applied-observation count.
async fn projector_position(cluster: &Cluster) -> (i64, i64) {
    let row = cluster
        .database
        .query_one(
            "SELECT checkpoint_position, projected_events \
             FROM greengateway.discovery_projector_state WHERE singleton",
        )
        .await;
    (row.get::<_, i64>(0), row.get::<_, i64>(1))
}

// ---------------------------------------------------------------------
// Reading the acquisition series
// ---------------------------------------------------------------------

/// One acquisition series as one scrape renders it.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Series {
    count: f64,
    sum_seconds: f64,
    p50: f64,
    p95: f64,
    p99: f64,
    max: f64,
}

/// The acquisition family from one exposition, keyed by the fixed
/// vocabularies. `malformed` is set by any line of the family whose labels
/// or value this cannot read; such a line is never copied.
#[derive(Debug, Default)]
struct Acquisition {
    series: BTreeMap<(&'static str, &'static str), Series>,
    malformed: bool,
}

/// `key="value",...` as the exporter renders it, with the text format's
/// three escapes. `None` for anything else.
fn parse_labels(text: &str) -> Option<BTreeMap<String, String>> {
    let mut labels = BTreeMap::new();
    let mut rest = text;
    while !rest.is_empty() {
        let (key, after) = rest.split_once("=\"")?;
        let mut value = String::new();
        let mut characters = after.char_indices();
        let end = loop {
            match characters.next()? {
                (index, '"') => break index,
                (_, '\\') => match characters.next()?.1 {
                    'n' => value.push('\n'),
                    other => value.push(other),
                },
                (_, character) => value.push(character),
            }
        };
        labels.insert(key.trim().to_owned(), value);
        rest = &after[end + 1..];
        rest = rest.strip_prefix(',').unwrap_or(rest);
    }
    Some(labels)
}

fn known(vocabulary: &[&'static str], value: Option<&String>) -> Option<&'static str> {
    let value = value?;
    vocabulary.iter().copied().find(|known| *known == value)
}

fn parse_acquisition(exposition: &str) -> Acquisition {
    let mut parsed = Acquisition::default();
    for line in exposition.lines() {
        let Some(rest) = line.strip_prefix(ACQUIRE_FAMILY) else {
            continue;
        };
        enum Part {
            Quantile,
            Sum,
            Count,
        }
        let (part, rest) = if let Some(rest) = rest.strip_prefix("_count") {
            (Part::Count, rest)
        } else if let Some(rest) = rest.strip_prefix("_sum") {
            (Part::Sum, rest)
        } else {
            (Part::Quantile, rest)
        };
        // Every sample of this family is labelled; anything else that
        // merely starts with these bytes is a different family.
        let Some(rest) = rest.strip_prefix('{') else {
            continue;
        };
        let parsed_line = rest.rsplit_once('}').and_then(|(labels, value)| {
            let value = value.trim().parse::<f64>().ok().filter(|v| v.is_finite())?;
            let labels = parse_labels(labels)?;
            let class = known(&OPERATION_CLASSES, labels.get("operation_class"))?;
            let error = known(&ERROR_CLASSES, labels.get("error_class"))?;
            Some((class, error, labels.get("quantile").cloned(), value))
        });
        let Some((class, error, quantile, value)) = parsed_line else {
            parsed.malformed = true;
            continue;
        };
        let series = parsed.series.entry((class, error)).or_default();
        match part {
            Part::Count => series.count = value,
            Part::Sum => series.sum_seconds = value,
            Part::Quantile => match quantile.as_deref() {
                Some("0.5") => series.p50 = value,
                Some("0.95") => series.p95 = value,
                Some("0.99") => series.p99 = value,
                Some("1") => series.max = value,
                Some(_) => {}
                None => parsed.malformed = true,
            },
        }
    }
    parsed
}

fn seconds_to_ms(seconds: f64) -> f64 {
    super::rounded(seconds * 1_000.0)
}

fn delta(after: f64, before: f64) -> u64 {
    (after - before).max(0.0).round() as u64
}

// ---------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------

/// Nearest-rank quantiles and the maximum, or `null` for no samples.
fn latency(milliseconds: Vec<f64>) -> Value {
    if milliseconds.is_empty() {
        return Value::Null;
    }
    let max = milliseconds.iter().copied().fold(0.0_f64, f64::max);
    let observed = super::quantiles(milliseconds);
    json!({
        "p50_ms": super::rounded(observed.p50_ms),
        "p95_ms": super::rounded(observed.p95_ms),
        "p99_ms": super::rounded(observed.p99_ms),
        "max_ms": super::rounded(max),
    })
}

fn rate(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    (part as f64 / whole as f64 * 1_000_000.0).round() / 1_000_000.0
}

/// Outcome counts for one set of requests.
struct Tally {
    completed: u64,
    statuses: BTreeMap<String, u64>,
    client_timeouts: u64,
    client_errors: u64,
    all_ms: Vec<f64>,
    served_ms: Vec<f64>,
}

fn tally<'a>(outcomes: impl Iterator<Item = &'a Outcome>) -> Tally {
    let mut tally = Tally {
        completed: 0,
        statuses: BTreeMap::new(),
        client_timeouts: 0,
        client_errors: 0,
        all_ms: Vec::new(),
        served_ms: Vec::new(),
    };
    for outcome in outcomes {
        tally.completed += 1;
        tally.all_ms.push(outcome.millis);
        match outcome.ended {
            Ended::Status(status) => {
                *tally.statuses.entry(status.to_string()).or_default() += 1;
                if status == 200 {
                    tally.served_ms.push(outcome.millis);
                }
            }
            Ended::ClientTimeout => tally.client_timeouts += 1,
            Ended::ClientError => tally.client_errors += 1,
        }
    }
    tally
}

fn request_evidence(
    outcomes: &[Outcome],
    mix: Mix,
    elapsed: Duration,
    reasons: &mut Vec<&'static str>,
) -> Value {
    let mut by_kind = serde_json::Map::new();
    for kind in mix.kinds() {
        let counted = tally(outcomes.iter().filter(|outcome| outcome.kind == *kind));
        if counted.completed == 0 {
            flag(reasons, "request_kind_not_completed");
        }
        by_kind.insert(
            kind.name().to_owned(),
            json!({
                "completed": counted.completed,
                "status_counts": counted.statuses,
                "client_timeouts": counted.client_timeouts,
                "latency_ms": latency(counted.all_ms),
            }),
        );
    }

    let counted = tally(outcomes.iter());
    if counted.completed < CONCURRENCY as u64 {
        flag(reasons, "too_few_requests");
    }
    let allowed: Vec<String> = CAPACITY_STATUSES.iter().map(u16::to_string).collect();
    if counted
        .statuses
        .keys()
        .any(|status| !allowed.contains(status))
    {
        flag(reasons, "unexpected_status");
    }
    if counted.client_errors > 0 {
        flag(reasons, "client_errors");
    }
    // Refusals are results, but a cell that served nothing at all, for
    // example one whose every request timed out against a hung upstream,
    // measured a broken harness rather than the pool.
    if !counted.statuses.contains_key("200") {
        flag(reasons, "no_request_served");
    }
    let refused = counted.statuses.get("503").copied().unwrap_or(0);
    let seconds = elapsed.as_secs_f64().max(f64::EPSILON);
    json!({
        "completed": counted.completed,
        "duration_ms": super::rounded(elapsed.as_secs_f64() * 1_000.0),
        "throughput_rps": super::rounded(counted.completed as f64 / seconds),
        "status_counts": counted.statuses,
        "client_timeouts": counted.client_timeouts,
        "client_errors": counted.client_errors,
        "rate_503": rate(refused, counted.completed),
        "rate_client_timeout": rate(counted.client_timeouts, counted.completed),
        "latency_ms": latency(counted.all_ms),
        "served_latency_ms": latency(counted.served_ms),
        "by_kind": by_kind,
    })
}

/// The acquisition series and pool counters, per replica and for the
/// deployment, from the scrapes either side of the window.
fn pool_evidence(
    plan: &CellPlan,
    names: &[String],
    before: &[String],
    after: &[String],
    gauges: &[PoolGauges],
    reasons: &mut Vec<&'static str>,
) -> Value {
    let mut totals: BTreeMap<(&'static str, &'static str), u64> = BTreeMap::new();
    let mut replicas = Vec::with_capacity(names.len());
    for (index, name) in names.iter().enumerate() {
        let earlier = parse_acquisition(&before[index]);
        let later = parse_acquisition(&after[index]);
        if earlier.malformed || later.malformed {
            flag(reasons, "unrecognised_metric_series");
        }
        let mut rows = Vec::new();
        for (key, series) in &later.series {
            let previous = earlier.series.get(key).copied().unwrap_or_default();
            let count = delta(series.count, previous.count);
            if count == 0 {
                continue;
            }
            *totals.entry(*key).or_default() += count;
            rows.push(json!({
                "operation_class": key.0,
                "error_class": key.1,
                "count": count,
                "sum_seconds": ((series.sum_seconds - previous.sum_seconds).max(0.0)
                    * 1_000_000.0).round() / 1_000_000.0,
                "p50_ms": seconds_to_ms(series.p50),
                "p95_ms": seconds_to_ms(series.p95),
                "p99_ms": seconds_to_ms(series.p99),
                "max_ms": seconds_to_ms(series.max),
            }));
        }
        // Every replica's poller and gates read the revision, so a scrape
        // without a `revision_check` row did not read this replica's
        // series. How those checkouts ended is the result, not the check: a
        // saturated replica whose every read was cancelled is still a
        // replica that was measured.
        if !rows
            .iter()
            .any(|row| row["operation_class"] == "revision_check")
        {
            flag(reasons, "replica_metrics_missing");
        }
        let counter = |text: &str, name: &str| harness::metric_sum(text, name);
        let gauge = gauges[index];
        // A replica that served a checkout holds at least one connection.
        // `metric_sum` reads a missing gauge as zero, so zero here means the
        // gauge was not read, not that the pool was empty.
        if gauge.size_max < 1.0 {
            flag(reasons, "pool_gauges_missing");
        }
        replicas.push(json!({
            "replica": name,
            "pool_timeouts": delta(
                counter(&after[index], "greengateway_database_pool_timeouts_total"),
                counter(&before[index], "greengateway_database_pool_timeouts_total"),
            ),
            "audit_events_dropped": delta(
                counter(&after[index], "audit_events_dropped_total"),
                counter(&before[index], "audit_events_dropped_total"),
            ),
            "size_max": gauge.size_max.max(0.0).round() as u64,
            "available_min": if gauge.available_min == f64::MAX {
                0
            } else {
                gauge.available_min.max(0.0).round() as u64
            },
            "waiting_max": gauge.waiting_max.max(0.0).round() as u64,
            "acquire": rows,
        }));
    }

    for class in plan.required_classes() {
        let exercised: u64 = ERROR_CLASSES
            .iter()
            .map(|error| totals.get(&(class, *error)).copied().unwrap_or(0))
            .sum();
        if exercised == 0 {
            flag(reasons, "operation_class_not_exercised");
        }
    }
    // Every class and outcome, zeros included: a zero `cancelled` is a
    // finding, and absence would not say so.
    let mut acquire_counts = Vec::with_capacity(OPERATION_CLASSES.len() * ERROR_CLASSES.len());
    for class in OPERATION_CLASSES {
        for error in ERROR_CLASSES {
            acquire_counts.push(json!({
                "operation_class": class,
                "error_class": error,
                "count": totals.get(&(class, error)).copied().unwrap_or(0),
            }));
        }
    }
    json!({
        "connection_ceiling": plan.replicas as u64 * u64::from(plan.pool_max),
        "replicas": replicas,
        "acquire_counts": acquire_counts,
    })
}

fn database_evidence(
    activity: &Activity,
    before: [i64; 6],
    after: [i64; 6],
    reasons: &mut Vec<&'static str>,
) -> Value {
    if activity.samples < MIN_ACTIVITY_SAMPLES || activity.runtime_backends.max < 1 {
        flag(reasons, "activity_not_sampled");
    }
    let mut counters = serde_json::Map::new();
    for (index, name) in DATABASE_COUNTERS.iter().enumerate() {
        counters.insert(
            (*name).to_owned(),
            json!((after[index] - before[index]).max(0)),
        );
    }
    json!({
        "activity_samples": activity.samples,
        "runtime_backends": activity.runtime_backends.json(),
        "active": activity.active.json(),
        "idle": activity.idle.json(),
        "idle_in_transaction": activity.idle_in_transaction.json(),
        "lock_waiting": activity.lock_waiting.json(),
        "lwlock_waiting": activity.lwlock_waiting.json(),
        "io_waiting": activity.io_waiting.json(),
        "ungranted_locks": activity.ungranted_locks.json(),
        "longest_lock_wait_ms": super::rounded(activity.longest_lock_wait_ms),
        "stat_delta": counters,
    })
}

fn control_plane_evidence(churn: ControlPlane, reasons: &mut Vec<&'static str>) -> Value {
    let committed = churn.statuses.get(&200).copied().unwrap_or(0);
    if committed == 0 {
        flag(reasons, "no_control_plane_commit");
    }
    if churn
        .statuses
        .keys()
        .any(|status| !CAPACITY_STATUSES.contains(status))
    {
        flag(reasons, "unexpected_commit_status");
    }
    if churn.convergence_ms.is_empty() {
        flag(reasons, "no_convergence_measured");
    }
    let statuses: BTreeMap<String, u64> = churn
        .statuses
        .iter()
        .map(|(status, count)| (status.to_string(), *count))
        .collect();
    json!({
        "commits_attempted": churn.commit_ms.len(),
        "status_counts": statuses,
        "commit_latency_ms": latency(churn.commit_ms),
        "convergence_samples": churn.convergence_ms.len(),
        "convergence_timeouts": churn.convergence_timeouts,
        "convergence_ms": latency(churn.convergence_ms),
    })
}

// ---------------------------------------------------------------------
// One cell
// ---------------------------------------------------------------------

/// The outcome of one cell: its report entry and, when incomplete, why.
struct CellResult {
    name: String,
    evidence: Value,
    reasons: Vec<&'static str>,
}

/// Run one cell on a cluster of its own. `None` is the harness's skip
/// path: no database here, or this run is not the gate.
async fn run_cell(
    plan: &CellPlan,
    measured: Duration,
    report: &mut CapacityReport,
) -> Option<CellResult> {
    let mut cluster = Cluster::start(cell_options(plan)).await?;
    cluster.wait_until_all_ready().await;
    if report.needs_database_facts() {
        report.set_database_facts(database_facts(&cluster).await);
    }

    let names: Vec<String> = cluster
        .replicas
        .iter()
        .map(|replica| replica.name.clone())
        .collect();
    let targets: Vec<String> = cluster
        .replicas
        .iter()
        .map(|replica| replica.base_url())
        .collect();
    let admin = super::admin_token(&cluster.oidc, "capacity-admin@ha.test");
    let credentials = Credentials {
        jwts: (0..CONCURRENCY)
            .map(|worker| super::admin_token(&cluster.oidc, &format!("capacity-{worker}@ha.test")))
            .collect(),
        service_token: match plan.mix.kinds().contains(&RequestKind::ServiceTokenProxy) {
            true => Some(create_service_token(&cluster, &admin).await),
            false => None,
        },
    };

    let mut reasons = Vec::new();
    if !warm_up(&targets, &credentials, plan.mix).await {
        flag(&mut reasons, "warmup_not_served");
    }

    let mut before = Vec::with_capacity(names.len());
    for name in &names {
        before.push(cluster.metrics(name).await);
    }
    let counters_before = database_counters(&cluster).await;
    let projector_before = projector_position(&cluster).await;

    let started = Instant::now();
    let stop_at = started + measured;
    let (outcomes, (activity, gauges), churn, ingested) = tokio::join!(
        drive(&targets, &credentials, plan.mix, stop_at),
        sample(&cluster, &names, stop_at),
        async {
            match plan.contention {
                true => Some(churn_control_plane(&cluster, &names, &admin, stop_at).await),
                false => None,
            }
        },
        async {
            match plan.contention {
                true => Some(feed_audit_backlog(&cluster, stop_at).await),
                false => None,
            }
        },
    );
    let elapsed = started.elapsed();

    let mut after = Vec::with_capacity(names.len());
    for name in &names {
        after.push(cluster.metrics(name).await);
    }
    let counters_after = database_counters(&cluster).await;
    let projector_after = projector_position(&cluster).await;
    let stream_head = cluster.database.stream_head().await;

    let requests = request_evidence(&outcomes, plan.mix, elapsed, &mut reasons);
    let pool = pool_evidence(plan, &names, &before, &after, &gauges, &mut reasons);
    let database = database_evidence(&activity, counters_before, counters_after, &mut reasons);
    let control_plane = match churn {
        Some(churn) => control_plane_evidence(churn, &mut reasons),
        None => Value::Null,
    };
    let projector = match ingested {
        Some(ingested) => {
            let checkpoint_delta = (projector_after.0 - projector_before.0).max(0);
            let projected_delta = (projector_after.1 - projector_before.1).max(0);
            if ingested == 0 || checkpoint_delta == 0 || projected_delta == 0 {
                flag(&mut reasons, "projector_idle");
            }
            json!({
                "events_ingested": ingested,
                "checkpoint_delta": checkpoint_delta,
                "projected_events_delta": projected_delta,
                "lag_events_after": (stream_head - projector_after.0).max(0),
            })
        }
        None => Value::Null,
    };

    cluster.shutdown();

    let name = plan.name();
    let evidence = json!({
        "name": name,
        "replicas": plan.replicas,
        "pool_max": plan.pool_max,
        "mix": plan.mix.name(),
        "contention": plan.contention,
        "requests": requests,
        "pool": pool,
        "database": database,
        "control_plane": control_plane,
        "projector": projector,
        "complete": reasons.is_empty(),
        "incomplete_reasons": reasons,
    });
    eprintln!(
        "{name}: {} requests at {} rps, p99 {} ms, 503 rate {}, peak runtime backends {}{}",
        evidence["requests"]["completed"],
        evidence["requests"]["throughput_rps"],
        evidence["requests"]["latency_ms"]["p99_ms"],
        evidence["requests"]["rate_503"],
        evidence["database"]["runtime_backends"]["max"],
        if reasons.is_empty() {
            String::new()
        } else {
            format!("; INCOMPLETE: {}", reasons.join(", "))
        }
    );
    Some(CellResult {
        name,
        evidence,
        reasons,
    })
}

// =====================================================================
// The test
// =====================================================================

/// **Every cell of the capacity matrix leaves complete evidence.**
///
/// The only assertion is completeness (see the module notes). Latency,
/// throughput, refusals and pool waits are recorded in
/// `GATEWAY_TEST_CAPACITY_REPORT` and judged by nothing here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "nightly capacity matrix; run by the nightly-performance workflow"]
async fn the_capacity_matrix_records_complete_evidence_for_every_cell() {
    let plans = matrix();
    let measured = measured_window();
    let mut report = CapacityReport::new(&plans, measured);
    let mut incomplete = Vec::new();
    for plan in &plans {
        let Some(cell) = run_cell(plan, measured, &mut report).await else {
            return super::skipped();
        };
        if !cell.reasons.is_empty() {
            incomplete.push(format!("{} ({})", cell.name, cell.reasons.join(", ")));
        }
        report.push(cell.evidence);
    }
    assert!(
        incomplete.is_empty(),
        "these capacity cells did not produce complete evidence, so their numbers cannot be \
         compared with the others': {}. The report at {} records what each one did collect.",
        incomplete.join("; "),
        report.path.display()
    );
}

// =====================================================================
// The pieces that need no database, on every pull request
// =====================================================================

#[test]
fn the_matrix_crosses_two_replica_counts_two_ceilings_and_both_mixes_plus_contention() {
    let plans = matrix();
    let names: Vec<String> = plans.iter().map(CellPlan::name).collect();
    let unique: std::collections::BTreeSet<&String> = names.iter().collect();
    assert_eq!(
        unique.len(),
        names.len(),
        "cell names must be unique: {names:?}"
    );
    assert_eq!(plans.iter().filter(|plan| plan.contention).count(), 1);
    let plain: Vec<&CellPlan> = plans.iter().filter(|plan| !plan.contention).collect();
    assert_eq!(plain.len(), 8);
    for plan in &plain {
        assert_eq!(
            CONCURRENCY % plan.replicas,
            0,
            "every replica must be offered the same share of the load"
        );
    }
    assert_eq!(names[0], "r2-p2-jwt_proxy");
    assert_eq!(names[8], "r2-p10-mixed_credentials-contention");
}

#[test]
fn the_mixed_rotation_is_six_jwt_three_service_token_one_admin_read() {
    let mut counts = BTreeMap::new();
    for sequence in 0..1_000 {
        *counts
            .entry(Mix::MixedCredentials.kind(sequence).name())
            .or_insert(0) += 1;
    }
    assert_eq!(counts["jwt_proxy"], 600);
    assert_eq!(counts["service_token_proxy"], 300);
    assert_eq!(counts["admin_policy_read"], 100);
    assert!((0..100).all(|sequence| Mix::JwtProxy.kind(sequence) == RequestKind::JwtProxy));
}

#[test]
fn the_acquisition_family_is_read_only_through_its_vocabularies() {
    let exposition = "\
# TYPE greengateway_database_pool_acquire_seconds summary
greengateway_database_pool_acquire_seconds{operation_class=\"revision_check\",error_class=\"none\",quantile=\"0\"} 0.0001
greengateway_database_pool_acquire_seconds{operation_class=\"revision_check\",error_class=\"none\",quantile=\"0.5\"} 0.0002
greengateway_database_pool_acquire_seconds{operation_class=\"revision_check\",error_class=\"none\",quantile=\"0.95\"} 0.0004
greengateway_database_pool_acquire_seconds{operation_class=\"revision_check\",error_class=\"none\",quantile=\"0.99\"} 0.0009
greengateway_database_pool_acquire_seconds{operation_class=\"revision_check\",error_class=\"none\",quantile=\"1\"} 0.003
greengateway_database_pool_acquire_seconds_sum{operation_class=\"revision_check\",error_class=\"none\"} 0.25
greengateway_database_pool_acquire_seconds_count{operation_class=\"revision_check\",error_class=\"none\"} 1200
greengateway_database_pool_acquire_seconds_count{operation_class=\"rate_limit\",error_class=\"cancelled\"} 3
greengateway_database_pool_acquire_seconds_count_other{operation_class=\"rate_limit\",error_class=\"none\"} 9
greengateway_database_pool_size 10
";
    let parsed = parse_acquisition(exposition);
    assert!(!parsed.malformed);
    let revision = parsed.series[&("revision_check", "none")];
    assert_eq!(revision.count, 1200.0);
    assert_eq!(revision.sum_seconds, 0.25);
    assert_eq!(
        (revision.p50, revision.p95, revision.p99, revision.max),
        (0.0002, 0.0004, 0.0009, 0.003)
    );
    assert_eq!(parsed.series[&("rate_limit", "cancelled")].count, 3.0);
    assert_eq!(parsed.series.len(), 2, "a different family is not this one");

    // A label outside the vocabulary is never copied, and says so.
    let hostile = "greengateway_database_pool_acquire_seconds_count{operation_class=\"/v1/admin/tokens\",error_class=\"none\"} 1\n";
    let parsed = parse_acquisition(hostile);
    assert!(parsed.malformed);
    assert!(parsed.series.is_empty());
    let unterminated =
        "greengateway_database_pool_acquire_seconds_count{operation_class=\"revision_check} 1\n";
    assert!(parse_acquisition(unterminated).malformed);
}

#[test]
fn labels_parse_with_the_text_formats_escapes() {
    let labels = parse_labels(r#"a="x",b="say \"hi\"",c="back\\slash",d="line\nbreak""#)
        .expect("well-formed labels parse");
    assert_eq!(labels["a"], "x");
    assert_eq!(labels["b"], "say \"hi\"");
    assert_eq!(labels["c"], "back\\slash");
    assert_eq!(labels["d"], "line\nbreak");
    assert!(parse_labels(r#"a="unterminated"#).is_none());
    assert!(parse_labels("a=bare").is_none());
}

#[test]
fn request_evidence_flags_only_what_a_capacity_run_cannot_produce() {
    let outcome = |kind, ended, millis| Outcome {
        kind,
        ended,
        millis,
    };
    let mut outcomes: Vec<Outcome> = (0..CONCURRENCY)
        .map(|index| outcome(RequestKind::JwtProxy, Ended::Status(200), index as f64))
        .collect();
    outcomes.push(outcome(RequestKind::JwtProxy, Ended::Status(503), 250.0));
    outcomes.push(outcome(
        RequestKind::JwtProxy,
        Ended::ClientTimeout,
        10_000.0,
    ));
    let mut reasons = Vec::new();
    let evidence = request_evidence(
        &outcomes,
        Mix::JwtProxy,
        Duration::from_secs(2),
        &mut reasons,
    );
    assert!(
        reasons.is_empty(),
        "a 503 and a timeout are results: {reasons:?}"
    );
    assert_eq!(evidence["completed"], 26);
    assert_eq!(evidence["status_counts"]["503"], 1);
    assert_eq!(evidence["client_timeouts"], 1);
    assert_eq!(evidence["rate_503"], json!(rate(1, 26)));
    assert_eq!(evidence["served_latency_ms"]["max_ms"], json!(23.0));
    assert_eq!(evidence["latency_ms"]["max_ms"], json!(10_000.0));

    outcomes.push(outcome(RequestKind::JwtProxy, Ended::Status(401), 1.0));
    outcomes.push(outcome(RequestKind::JwtProxy, Ended::ClientError, 1.0));
    let mut reasons = Vec::new();
    request_evidence(
        &outcomes,
        Mix::MixedCredentials,
        Duration::from_secs(2),
        &mut reasons,
    );
    assert_eq!(
        reasons,
        vec![
            "request_kind_not_completed",
            "unexpected_status",
            "client_errors"
        ]
    );

    let mut reasons = Vec::new();
    request_evidence(
        &outcomes[..3],
        Mix::JwtProxy,
        Duration::from_secs(2),
        &mut reasons,
    );
    assert_eq!(reasons, vec!["too_few_requests"]);

    // Refusals and timeouts are results, but a cell that served nothing at
    // all measured a broken harness, not the pool.
    let unserved: Vec<Outcome> = (0..CONCURRENCY)
        .map(|index| match index % 2 {
            0 => outcome(RequestKind::JwtProxy, Ended::Status(503), 250.0),
            _ => outcome(RequestKind::JwtProxy, Ended::ClientTimeout, 10_000.0),
        })
        .collect();
    let mut reasons = Vec::new();
    let evidence = request_evidence(
        &unserved,
        Mix::JwtProxy,
        Duration::from_secs(2),
        &mut reasons,
    );
    assert_eq!(reasons, vec!["no_request_served"]);
    assert_eq!(evidence["served_latency_ms"], Value::Null);
}

#[test]
fn pool_evidence_needs_every_replicas_revision_reads_and_gauges_but_not_their_outcome() {
    let plan = matrix()[0];
    assert_eq!(plan.name(), "r2-p2-jwt_proxy");
    let names = vec!["a".to_owned(), "b".to_owned()];
    // One sample: the sketch renders p99 as its bucket's representative,
    // just above the exact maximum.
    let series = |class: &str, error: &str| {
        let labels = format!("operation_class=\"{class}\",error_class=\"{error}\"");
        format!(
            "{ACQUIRE_FAMILY}{{{labels},quantile=\"0.99\"}} 0.2580251\n\
             {ACQUIRE_FAMILY}{{{labels},quantile=\"1\"}} 0.258\n\
             {ACQUIRE_FAMILY}_sum{{{labels}}} 0.258\n\
             {ACQUIRE_FAMILY}_count{{{labels}}} 1\n"
        )
    };
    let before = vec![String::new(), String::new()];
    let front = series("rate_limit", "none") + &series("credential_check", "none");
    // Replica b is saturated: every revision read it made was cancelled.
    let after = vec![
        front.clone() + &series("revision_check", "none"),
        front.clone() + &series("revision_check", "cancelled"),
    ];
    let read = PoolGauges {
        size_max: 2.0,
        available_min: 0.0,
        waiting_max: 3.0,
    };

    let mut reasons = Vec::new();
    let evidence = pool_evidence(&plan, &names, &before, &after, &[read, read], &mut reasons);
    assert!(
        reasons.is_empty(),
        "a cancelled read is a result: {reasons:?}"
    );
    let cancelled = evidence["replicas"][1]["acquire"]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|row| row["operation_class"] == "revision_check")
        })
        .expect("replica b's revision reads are reported");
    assert_eq!(cancelled["error_class"], "cancelled");
    assert_eq!(cancelled["p99_ms"], json!(258.025));
    assert_eq!(cancelled["max_ms"], json!(258.0));

    // `metric_sum` reads a gauge that is not there as zero.
    let mut reasons = Vec::new();
    pool_evidence(
        &plan,
        &names,
        &before,
        &after,
        &[read, PoolGauges::default()],
        &mut reasons,
    );
    assert_eq!(reasons, vec!["pool_gauges_missing"]);

    let silent = vec![after[0].clone(), front];
    let mut reasons = Vec::new();
    pool_evidence(&plan, &names, &before, &silent, &[read, read], &mut reasons);
    assert_eq!(reasons, vec!["replica_metrics_missing"]);
}
