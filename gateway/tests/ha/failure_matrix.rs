//! The failure matrix, row by row (issue #241, PR 16 part 2).
//!
//! `docs/architecture/ha-state-model.md` §3 is a table of conditions and
//! what a replica is supposed to do in each. PR 14 turned the "what" into
//! four `/readyz` reason strings. This file is the executable form of that
//! table: for every fault it can actually inject, it asserts **the reason
//! string**, **what a request gets while the fault holds**, and **the
//! recovery once it clears** — in that order, in every row.
//!
//! ## What makes a row a test rather than a ritual
//!
//! A row that asserted only "`/readyz` is `503`" would pass whatever
//! reason came back, and the whole point of PR 14 is that the reasons are
//! *different words for different conditions*. So three rows here exist
//! purely to prove the words are distinguishable:
//!
//! * [`the_reason_chain_is_reported_in_the_documented_order`] stacks three
//!   faults, then lifts them one at a time, and asserts the reported
//!   reason walks `storage_unavailable` → `schema_incompatible` →
//!   `instance_lease_invalid` → ready. Any implementation that collapsed
//!   two reasons into one, or evaluated them in a different order, fails
//!   it.
//! * [`a_lock_on_the_ledger_blocks_readiness_and_a_lock_elsewhere_does_not`]
//!   applies the *same* fault shape (`LOCK TABLE ... ACCESS EXCLUSIVE`) to
//!   two different tables and asserts opposite outcomes.
//! * [`a_missing_ledger_is_schema_incompatible_not_storage_unavailable`]
//!   pins the deliberate `42P01`/`3F000` special case in
//!   `ha_status::observe_once`: a database that is simply not migrated for
//!   this binary must not masquerade as an outage.
//!
//! Every poll helper here also checks the observed reason against
//! [`REASON_VOCABULARY`], so a reason string this suite has never heard of
//! fails the row that produced it rather than passing silently.
//!
//! That check runs in one direction only — it catches a word that should
//! not exist, not a word that exists and cannot be produced — so the other
//! direction is covered row by row. Four of the eight reasons are produced
//! by the authority rows below, `required_upstream_unavailable` by
//! [`an_unhealthy_required_upstream_is_required_upstream_unavailable_and_recovers`],
//! and the remaining three (`draining`, `starting`,
//! `config_fingerprint_mismatch`) are named absences with `#[ignore]`d rows
//! at the foot of this file or, for `starting`, covered in-crate.
//!
//! ## What is injectable here, and what is not
//!
//! The faults are the ones a plain client on the *admin* DSN can apply to
//! a role and a database this run created: revoking `CONNECT`, terminating
//! backends, `default_transaction_read_only`, `CONNECTION LIMIT 0`,
//! `statement_timeout`, table-level `REVOKE`, `LOCK TABLE`, and edits to
//! the migration ledger. No `sudo`, no `docker exec`, no privileged
//! container — which is what makes them deterministic on a hosted runner.
//!
//! Four things are **not** injectable here, and each is a named,
//! documented row rather than an absence:
//!
//! * [`iptables_network_partition_is_substituted_not_injected`] — a `DROP`
//!   rule that severs the PostgreSQL service container without severing
//!   the runner's own control plane is not something to bet a required
//!   merge gate on. Substituted by the two faults that produce the same
//!   observable state, and asserted in
//!   [`losing_the_authority_is_storage_unavailable_and_recovers`] and
//!   [`a_paused_replica_stops_answering_while_the_deployment_holds_its_roster`].
//! * [`disk_exhaustion_is_covered_by_classification_not_by_injection`] —
//!   a real `53100` needs a size-capped filesystem inside the PostgreSQL
//!   container. Substituted by
//!   [`connection_exhaustion_is_storage_unavailable_and_recovers`], which
//!   provokes a **real** `53300` and therefore travels the identical
//!   `53*` arm of `classify_postgres_error` that `53100` would.
//! * [`draining_is_not_observable_through_this_harness`] — the harness
//!   pins `SHUTDOWN_DRAIN_DELAY_MS=0` on every replica
//!   (`harness/mod.rs::replica_environment`), so the drain window a
//!   `503 draining` would be observed in does not exist. Fixing that is a
//!   harness change, not a row.
//! * [`config_fingerprint_mismatch_needs_a_third_replica_the_harness_cannot_vary`]
//!   — `ClusterOptions` has no per-replica environment hook, by design:
//!   every setting the fingerprint reads is shared so the replicas agree.
//!
//! ## What writing this suite found
//!
//! Every reason below was unobservable when this file was first run.
//! `middleware::rate_limit::rate_limit_request` is layered over the whole
//! router, probes included, and in `STATE_BACKEND=postgres` it consults
//! the shared, database-backed limiter, which fails closed. So a replica
//! whose authority had gone away answered `/readyz` with
//! `503 {"error":"rate limiter unavailable"}` — never with a reason — in
//! exactly the outage PR 14's reasons exist to name, and `/metrics`, the
//! scrape an operator reaches for during that outage, was refused with it.
//!
//! The fix is in this PR: `AUTHORITY_INDEPENDENT_PATHS` in
//! `middleware/rate_limit.rs` keeps `/livez`, `/readyz`, `/startupz` and
//! `/metrics` on the local bucket only. They stay bounded; they simply
//! stop being gated on the authority they report on. Every row here that
//! waits for a reason is the regression test for it.
//!
//! ## One runtime role, one deployment
//!
//! The harness creates **one** disposable runtime role per cluster, shared
//! by both replicas (`harness/database.rs::create_with_password`). Every
//! database-level fault below therefore reaches the whole deployment, not
//! one replica — which for these assertions is the harder case, not the
//! easier one: both replicas are blind and neither may serve. The one
//! genuinely per-replica fault available is `SIGSTOP`, and that is what
//! the partition row uses.
//!
//! Skips silently without `GATEWAY_TEST_POSTGRES_URL_FILE`, and without
//! `GATEWAY_TEST_HA_GATE`, like every other suite under `tests/ha/`.

#![cfg(feature = "postgres")]

mod harness;

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use harness::{
    replica::Replica, AuthShape, Cluster, ClusterOptions, FakeOidcIssuer, ADMIN_API_PREFIX,
};

// ---------------------------------------------------------------------
// The vocabulary
// ---------------------------------------------------------------------

/// Every reason string `/readyz` is allowed to answer with, and the only
/// ones this suite will accept from it.
///
/// Four come from `main.rs::readiness_blocked_reason`'s own arms
/// (`draining`, `starting`, `required_upstream_unavailable`, and PR 13's
/// `config_fingerprint_mismatch` through `ClusterReadiness`), and four
/// from `ha_status`'s constants. A reason outside this list reaching a
/// probe is a widened public contract, and
/// [`assert_reason_is_in_the_vocabulary`] fails the row that produced it.
const REASON_VOCABULARY: [&str; 8] = [
    "draining",
    "starting",
    "config_fingerprint_mismatch",
    "storage_unavailable",
    "schema_incompatible",
    "instance_lease_invalid",
    "security_revision_not_compiled",
    "required_upstream_unavailable",
];

const STORAGE_UNAVAILABLE: &str = "storage_unavailable";
const SCHEMA_INCOMPATIBLE: &str = "schema_incompatible";
const INSTANCE_LEASE_INVALID: &str = "instance_lease_invalid";
const SECURITY_REVISION_NOT_COMPILED: &str = "security_revision_not_compiled";

/// The migration ledger, spelled as `storage::migrations::LEDGER_TABLE`
/// spells it. The schema rows edit this table directly, which is the only
/// way to move a *serving* replica's ledger out from under it.
const LEDGER_TABLE: &str = "greengateway.schema_migrations";

/// The roster table whose write grant the lease row takes away.
const MEMBERS_TABLE: &str = "greengateway.cluster_members";

/// The counter `SecurityRevisionSource::current` reads, and the one table
/// whose unreadability produces `security_revision_not_compiled` *without*
/// also producing `storage_unavailable`: the readiness probe's own
/// statement never touches it.
const REVISION_STATE_TABLE: &str = "greengateway.security_revision_state";

/// A table the readiness probe's statement does not touch, used by the
/// lock row as the control against the ledger.
const POLICY_DOCUMENTS_TABLE: &str = "greengateway.policy_documents";

// ---------------------------------------------------------------------
// Budgets — derived, never invented
// ---------------------------------------------------------------------

/// A readiness transition caused by an authority fault is observable
/// within `READINESS_PROBE_CACHE_MS` plus one probe round trip. Generous
/// against a machine running other builds; every wait is a bounded poll
/// that returns the moment the condition holds.
const AUTHORITY_BUDGET: Duration = Duration::from_secs(30);

/// `instance_lease_invalid` needs `CLUSTER_MEMBER_STALE_MS` to elapse
/// since the last successful heartbeat, which the matrix clusters set to
/// [`STALE_WINDOW_MS`].
const LEASE_BUDGET: Duration = Duration::from_secs(45);

/// `security_revision_not_compiled` needs `RECONCILE_BACKGROUND_DEADLINE`
/// to elapse — a hard-coded `Duration::from_secs(30)` in
/// `security_cluster.rs` with no environment variable, so this row costs
/// 30 s of real time and nothing here can shorten it.
const REVISION_BUDGET: Duration = Duration::from_secs(75);

/// `CLUSTER_MEMBER_STALE_MS` the matrix clusters run with. Short enough
/// that the lease row is not the suite's cost centre, and comfortably
/// above the configured floor of `3 × CLUSTER_HEARTBEAT_MS`.
const STALE_WINDOW_MS: u64 = 9_000;
const HEARTBEAT_MS: u64 = 1_000;

/// `READINESS_PROBE_CACHE_MS` for these clusters. Shrunk from the 1 000 ms
/// default so a transition is observed within a probe or two rather than
/// within a cache window plus a probe — the *condition* is what is under
/// test here, not the cache.
const PROBE_CACHE_MS: u64 = 250;

/// `DATABASE_STATEMENT_TIMEOUT_MS` for the lock rows. The gateway sets
/// this as a connection **startup parameter**, which outranks any role
/// default — which is the whole point of
/// [`a_role_statement_timeout_never_reaches_the_gateway`] — so it is the
/// only lever that bounds the probe's own statement.
const STATEMENT_TIMEOUT_MS: u64 = 3_000;

const ADMIN_ROLE: &str = "ha-admin";
const PROXIED_PATH: &str = "/echo/failure-matrix";
const CLUSTER_ROUTE: &str = "/v1/admin/cluster";

fn policy_route() -> String {
    format!("{ADMIN_API_PREFIX}/policy")
}

fn skipped() {
    eprintln!(
        "skipping: no test database locator, or this run is not the gate; the ha-release-gate \
         CI job runs this suite"
    );
}

/// A policy that grants [`ADMIN_ROLE`] everything and leaves the data
/// plane open: this suite is about readiness reasons, not about which
/// permission guards which route.
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

fn admin_token(issuer: &FakeOidcIssuer, subject: &str) -> String {
    issuer.mint_role_token(
        harness::oidc::PRIMARY_KID,
        subject,
        &format!("jti-{}", uuid::Uuid::new_v4().simple()),
        &[ADMIN_ROLE],
        3_600,
    )
}

/// The matrix's cluster shape: two replicas, authentication on (the
/// cluster status API and the security gate both need a principal), a
/// short probe cache and a short stale window.
fn matrix_options() -> ClusterOptions {
    ClusterOptions {
        auth: AuthShape::Oidc,
        seed_policy: Some(admin_policy()),
        heartbeat_ms: HEARTBEAT_MS,
        member_stale_ms: STALE_WINDOW_MS,
        shared_env: vec![(
            "READINESS_PROBE_CACHE_MS".to_owned(),
            PROBE_CACHE_MS.to_string(),
        )],
        ..ClusterOptions::default()
    }
}

async fn start_matrix_cluster(options: ClusterOptions) -> Option<Cluster> {
    let mut cluster = Cluster::start(options).await?;
    cluster.wait_until_all_ready().await;
    Some(cluster)
}

// ---------------------------------------------------------------------
// Probing
// ---------------------------------------------------------------------

/// Fail if `/readyz` answered a reason outside the published vocabulary.
///
/// This runs on every sample every row takes, so a widened contract is
/// caught by whichever row first sees it rather than by a separate test
/// that would have to reproduce all of them.
fn assert_reason_is_in_the_vocabulary(replica: &str, body: &Value) {
    let Some(reason) = body["reason"].as_str() else {
        return;
    };
    assert!(
        REASON_VOCABULARY.contains(&reason),
        "replica {replica} answered /readyz with {reason:?}, which is not one of the eight \
         published reasons {REASON_VOCABULARY:?}; a new reason is a widened public contract"
    );
}

/// Poll `/readyz` until it answers `503` with exactly `expected`.
///
/// Every sample is checked against the vocabulary on the way past, so a
/// row waiting for one reason still fails loudly on an unpublished one.
async fn wait_for_reason(replica: &Replica, expected: &str, budget: Duration) {
    assert!(
        REASON_VOCABULARY.contains(&expected),
        "{expected:?} is not a published /readyz reason; this row is asserting a word that \
         cannot be produced"
    );
    let deadline = Instant::now() + budget;
    loop {
        let (status, body) = replica.readyz().await;
        assert_reason_is_in_the_vocabulary(&replica.name, &body);
        if status == 503 && body["reason"] == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "replica {} never reported {expected:?} within {budget:?}; last /readyz said \
             {status} {body}",
            replica.name
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

/// Poll `/readyz` until it answers `200`, which is the recovery half of
/// every row.
async fn wait_until_ready(replica: &Replica, budget: Duration) {
    let deadline = Instant::now() + budget;
    loop {
        let (status, body) = replica.readyz().await;
        assert_reason_is_in_the_vocabulary(&replica.name, &body);
        if status == 200 {
            assert_eq!(
                body["reason"],
                Value::Null,
                "a ready replica must report no reason"
            );
            return;
        }
        assert!(
            Instant::now() < deadline,
            "replica {} did not recover within {budget:?}; last /readyz said {status} {body}",
            replica.name
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

/// The reason `/readyz` reports right now, or `None` when it is ready.
async fn reason_now(replica: &Replica) -> Option<String> {
    let (status, body) = replica.readyz().await;
    assert_reason_is_in_the_vocabulary(&replica.name, &body);
    match status {
        200 => None,
        _ => Some(
            body["reason"]
                .as_str()
                .unwrap_or_else(|| panic!("a 503 /readyz must carry a reason, said {body}"))
                .to_owned(),
        ),
    }
}

/// Assert every replica answers `200 ready` at this instant. The
/// "unaffected sibling" half of a row that only means something if the
/// sibling really was fine.
async fn assert_all_ready_now(cluster: &Cluster, context: &str) {
    for replica in &cluster.replicas {
        let (status, body) = replica.readyz().await;
        assert_reason_is_in_the_vocabulary(&replica.name, &body);
        assert_eq!(
            status, 200,
            "{context}: replica {} should still be ready, said {body}",
            replica.name
        );
    }
}

/// Sample `/readyz` on every replica across a window, and fail on the
/// first sample that is not `200`.
///
/// The subject of a "stays ready" row is the whole window, not one
/// sample: a probe that flapped once in the middle is exactly the defect
/// such a row exists to catch.
async fn assert_ready_across(cluster: &Cluster, window: Duration, context: &str) {
    let deadline = Instant::now() + window;
    let mut samples = 0_usize;
    while Instant::now() < deadline {
        assert_all_ready_now(cluster, context).await;
        samples += 1;
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        samples >= 2,
        "{context}: the window was too short to have sampled anything"
    );
}

/// How long a read of the cluster status API re-asks a replica that
/// answered `503`.
///
/// `GET /v1/admin/cluster` is a protected route, so cluster mode's revision
/// gate re-reads the authority for it on every request within its own
/// bounded budget. Under exactly the faults this suite injects that read
/// can miss and the route answers `503 {"error":"policy state
/// unavailable"}` — a documented transient the import drill tolerates the
/// same way (`import_drill.rs::settled`). One unlucky sample must not fail
/// a row on a required merge gate, and tolerating it costs nothing that
/// matters: a `503` reports nothing, so every caller below still asserts
/// the answer the route settles on.
const CLUSTER_STATUS_SETTLE: Duration = Duration::from_secs(20);

/// `GET /v1/admin/cluster`, which reports `state` and `reason` and must
/// agree with `/readyz` word for word.
///
/// Re-asks past a transient `503` up to [`CLUSTER_STATUS_SETTLE`], then
/// answers whatever the last attempt said so the caller's own assertion is
/// what fails, with the body in the message.
async fn cluster_status(cluster: &Cluster, replica: &str, admin: &str) -> (u16, Value) {
    let deadline = Instant::now() + CLUSTER_STATUS_SETTLE;
    loop {
        let answer = cluster
            .get(replica, CLUSTER_ROUTE)
            .bearer(admin)
            .send()
            .await;
        if answer.0 != 503 || Instant::now() >= deadline {
            return answer;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Poll `GET /v1/admin/cluster` until it reports `expected` replicas
/// stamped ready out of `expected` live.
///
/// The roster's `ready_at` is written by a heartbeat, so it trails a
/// replica's own `/readyz` by up to one heartbeat interval. That lag is
/// the deployment converging, not a defect, and it is what this polls
/// through.
async fn wait_for_ready_replicas(
    cluster: &Cluster,
    replica: &str,
    admin: &str,
    expected: u64,
    budget: Duration,
) {
    let deadline = Instant::now() + budget;
    loop {
        let (status, body) = cluster_status(cluster, replica, admin).await;
        assert_eq!(status, 200, "the cluster status API should answer: {body}");
        if body["state"] == "ready"
            && body["replicas"]["ready"] == expected
            && body["replicas"]["total"] == expected
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the roster never converged on {expected} ready replicas within {budget:?}; \
             replica {replica} last said {body}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Assert the two surfaces agree: `/readyz`'s reason passed through
/// verbatim, with `state` `not_ready` (`cluster_status.rs::state_and_reason`).
async fn assert_cluster_status_agrees(cluster: &Cluster, replica: &str, admin: &str, reason: &str) {
    let (status, body) = cluster_status(cluster, replica, admin).await;
    assert_eq!(
        status, 200,
        "the cluster status API should answer while the replica is unready: {body}"
    );
    assert_eq!(
        body["reason"], reason,
        "the cluster status reason must be /readyz's own word: {body}"
    );
    assert_eq!(
        body["state"], "not_ready",
        "a blocked, non-draining replica is not_ready: {body}"
    );
    assert_eq!(body["ready"], false, "ready must agree with the reason");
}

// ---------------------------------------------------------------------
// Fault injection
// ---------------------------------------------------------------------

/// Open a connection, run a batch, close it.
///
/// A fresh connection per statement rather than a pool: the faults below
/// terminate backends and revoke `CONNECT`, and a pooled client held
/// across one of those is a connection the next fault has to think about.
async fn run_sql(dsn: &str, sql: &str) {
    let (client, connection) = tokio_postgres::connect(dsn, tokio_postgres::NoTls)
        .await
        .unwrap_or_else(|error| panic!("the fault-injection connection should establish: {error}"));
    let pump = tokio::spawn(async move {
        let _ = connection.await;
    });
    let outcome = client.batch_execute(sql).await;
    drop(client);
    pump.abort();
    outcome.unwrap_or_else(|error| panic!("fault-injection statement failed: {error}\nsql: {sql}"));
}

/// [`run_sql`] from a `Drop`, which cannot be async.
///
/// Its own thread and its own current-thread runtime, exactly as the
/// harness's database reaper does it, because a panicking test's runtime
/// may already be shutting down. Failures are reported, never swallowed:
/// a reversal that did not happen poisons whatever runs next.
fn run_sql_blocking(dsn: &str, sql: &str) {
    let dsn = dsn.to_owned();
    let sql = sql.to_owned();
    let _ = std::thread::spawn(move || {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            eprintln!("the fault reversal could not build a runtime; {sql} was not reversed");
            return;
        };
        runtime.block_on(async move {
            let connected = tokio_postgres::connect(&dsn, tokio_postgres::NoTls).await;
            let Ok((client, connection)) = connected else {
                eprintln!("the fault reversal could not connect; {sql} was not reversed");
                return;
            };
            let pump = tokio::spawn(async move {
                let _ = connection.await;
            });
            if let Err(error) = client.batch_execute(&sql).await {
                eprintln!("the fault reversal failed ({error}); {sql} was not reversed");
            }
            drop(client);
            pump.abort();
        });
    })
    .join();
}

/// One injected fault and the statement that undoes it.
///
/// The reversal is a `Drop`, so a row that panics half-way through still
/// hands the next row a clean database. The happy path calls
/// [`Fault::revert`] explicitly and awaits it, because the recovery
/// assertion that follows has to observe the reversal having happened.
struct Fault {
    dsn: String,
    reverse: String,
    armed: bool,
}

impl Fault {
    async fn inject(dsn: &str, apply: &str, reverse: &str) -> Self {
        run_sql(dsn, apply).await;
        Self {
            dsn: dsn.to_owned(),
            reverse: reverse.to_owned(),
            armed: true,
        }
    }

    async fn revert(&mut self) {
        if self.armed {
            self.armed = false;
            run_sql(&self.dsn, &self.reverse).await;
        }
    }
}

impl Drop for Fault {
    fn drop(&mut self) {
        if self.armed {
            run_sql_blocking(&self.dsn, &self.reverse);
        }
    }
}

/// A session holding `ACCESS EXCLUSIVE` on one table until it is released.
///
/// Dropping the client closes the socket, which aborts the open
/// transaction server-side — so the `Drop` path needs no runtime and no
/// statement, and a panicking row cannot leave a table locked.
struct HeldLock {
    client: Option<tokio_postgres::Client>,
    pump: Option<tokio::task::JoinHandle<()>>,
    table: String,
}

impl HeldLock {
    async fn take(dsn: &str, table: &str) -> Self {
        let (client, connection) = tokio_postgres::connect(dsn, tokio_postgres::NoTls)
            .await
            .unwrap_or_else(|error| {
                panic!("the lock-holding connection should establish: {error}")
            });
        let pump = tokio::spawn(async move {
            let _ = connection.await;
        });
        client
            .batch_execute(&format!(
                "BEGIN; LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE"
            ))
            .await
            .unwrap_or_else(|error| panic!("the {table} lock should be taken: {error}"));
        Self {
            client: Some(client),
            pump: Some(pump),
            table: table.to_owned(),
        }
    }

    async fn release(&mut self) {
        if let Some(client) = self.client.take() {
            client
                .batch_execute("ROLLBACK")
                .await
                .unwrap_or_else(|error| panic!("the {} lock should release: {error}", self.table));
        }
        if let Some(pump) = self.pump.take() {
            pump.abort();
        }
    }
}

impl Drop for HeldLock {
    fn drop(&mut self) {
        // Closing the client's socket is the release: the server rolls the
        // open transaction back when the connection goes.
        self.client.take();
        if let Some(pump) = self.pump.take() {
            pump.abort();
        }
    }
}

/// Revoke a table privilege from the run's runtime role, and give it back
/// on reversal.
async fn revoke_table_privilege(cluster: &Cluster, privileges: &str, table: &str) -> Fault {
    let role = &cluster.database.role;
    Fault::inject(
        &cluster.database.migrator_dsn,
        &format!("REVOKE {privileges} ON {table} FROM {role}"),
        &format!("GRANT {privileges} ON {table} TO {role}"),
    )
    .await
}

/// How many *proxied* requests have reached the fake upstream.
///
/// Not `FakeUpstream::request_count`, which also counts the proxy's own
/// upstream health check — a `HEAD /` the pool issues on its own schedule
/// to decide `required_upstream_unavailable`. Counting those would make
/// "nothing was dispatched" a race against a background probe, and would
/// let a real dispatch hide inside the noise.
fn proxied_count(cluster: &Cluster) -> usize {
    cluster
        .upstream
        .requests()
        .iter()
        .filter(|request| request.path.starts_with("/echo"))
        .count()
}

/// The proxied requests, for a failure message that names what got through.
fn proxied_requests(cluster: &Cluster) -> Vec<String> {
    cluster
        .upstream
        .requests()
        .iter()
        .filter(|request| request.path.starts_with("/echo"))
        .map(|request| {
            format!(
                "{} {} via {:?}",
                request.method, request.path, request.replica
            )
        })
        .collect()
}

/// Every string the readiness surfaces must never carry, whatever the
/// fault: the same predicate `secret_leak.rs` applies, restated here
/// because that suite's `Haystack` is private to it.
///
/// A `/readyz` reason is a fixed word and a cluster-status field is a
/// number or a shape-checked string, so anything below appearing on
/// either is a widened surface, not a formatting accident.
///
/// The needles are **this run's own** connection details rather than
/// generic shapes. An earlier version of this helper grepped for the bare
/// string `"5432"`, which a Prometheus exposition contains by coincidence:
/// a scrape is roughly 15 KB carrying some 900 overlapping four-digit
/// windows, so any given four-digit pattern turns up in about one scrape in
/// forty — and when it did, the gate failed with a message accusing the
/// gateway of leaking a DSN it had never printed. A port number alone is
/// not a leak; the DSN, its authority, the disposable database and the
/// disposable role are, and each of those is unique to this run and cannot
/// be produced by a float.
fn assert_no_connection_detail(cluster: &Cluster, context: &str, text: &str) {
    let database = &cluster.database;
    let mut needles = vec![
        "postgres://".to_owned(),
        "@".to_owned(),
        "password".to_owned(),
        "sqlstate".to_owned(),
        "SQLSTATE".to_owned(),
        database.runtime_dsn.clone(),
        database.name.clone(),
        database.role.clone(),
    ];
    // `host:port` as a DSN renders it, taken from the run's own DSN rather
    // than assumed: the authority is the half of a connection string that
    // maps the deployment for a caller who should not be able to.
    if let Some(authority) = database
        .runtime_dsn
        .split_once("://")
        .and_then(|(_, rest)| rest.split(['/', '?']).next())
        .and_then(|rest| rest.rsplit('@').next())
        .filter(|authority| !authority.is_empty())
    {
        needles.push(authority.to_owned());
    }
    for needle in &needles {
        assert!(
            !text.contains(needle.as_str()),
            "{context} carried {needle:?}, which is a connection detail no readiness surface \
             may report: {text}"
        );
    }
}

// =====================================================================
// Row 1 / row 4 — the authority goes away
// =====================================================================

/// **State-model row: "PostgreSQL unavailable at runtime".** The runtime
/// role loses `CONNECT` and its established backends are terminated, so
/// the replicas can neither use nor reopen a connection.
///
/// This is also the substitute the matrix prescribes for an `iptables`
/// partition on a hosted runner, and it is the harder case: the harness
/// creates one runtime role per cluster, so *both* replicas are blind and
/// neither may serve. The assertion that matters is the last one — the
/// upstream is never contacted, so no replica dispatched under the allow
/// it was holding when the authority went away.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn losing_the_authority_is_storage_unavailable_and_recovers() {
    let Some(mut cluster) = start_matrix_cluster(matrix_options()).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    // Baseline: a protected request is served and reaches the upstream, so
    // the refusal below is the fault rather than a deployment that never
    // worked.
    cluster.upstream.clear();
    let (status, body) = cluster.get("a", PROXIED_PATH).bearer(&admin).send().await;
    assert_eq!(status, 200, "the warm-up request should be served: {body}");
    assert_eq!(
        proxied_count(&cluster),
        1,
        "the warm-up request should have reached the upstream"
    );

    // The fault.
    cluster.upstream.clear();
    cluster.database.revoke_connect().await;
    let terminated = cluster.database.terminate_runtime_backends().await;
    assert!(
        terminated > 0,
        "the replicas should have held backends to terminate; with none, this row would be \
         asserting about a deployment that was already disconnected"
    );

    // 1. The reason, on both replicas.
    for replica in &cluster.replicas {
        wait_for_reason(replica, STORAGE_UNAVAILABLE, AUTHORITY_BUDGET).await;
    }

    // 2. The request behaviour: refused, and never dispatched. The window
    //    is sampled rather than probed once, because a replica that fell
    //    back to a cached allow would do so at some point in it.
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut refusals = 0_usize;
    while Instant::now() < deadline {
        let (status, body) = cluster.get("b", PROXIED_PATH).bearer(&admin).send().await;
        assert_ne!(
            status, 200,
            "a replica that cannot reach the authority must not serve a protected path: {body}"
        );
        if status >= 500 {
            refusals += 1;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        refusals > 0,
        "the blind replica answered nothing recognisable as a refusal"
    );
    assert_eq!(
        proxied_count(&cluster),
        0,
        "a replica with no authority dispatched to the upstream under the allow it last saw"
    );

    // 3. The refusal says nothing about the database.
    let (_, body) = cluster.replica("a").readyz().await;
    assert_no_connection_detail(
        &cluster,
        "the /readyz body during a storage outage",
        &body.to_string(),
    );

    // 4. Recovery, with no restart: the same processes, the same ports.
    let ports: Vec<_> = cluster.replicas.iter().map(Replica::addr).collect();
    cluster.database.restore_connect().await;
    for replica in &cluster.replicas {
        wait_until_ready(replica, AUTHORITY_BUDGET).await;
    }
    let ports_after: Vec<_> = cluster.replicas.iter().map(Replica::addr).collect();
    assert_eq!(
        ports, ports_after,
        "recovery must not have needed a restart"
    );

    cluster.upstream.clear();
    let (status, body) = cluster.get("a", PROXIED_PATH).bearer(&admin).send().await;
    assert_eq!(status, 200, "the recovered replica should serve: {body}");
    assert_eq!(
        proxied_count(&cluster),
        1,
        "the recovered request should reach the upstream"
    );

    cluster.shutdown();
}

// =====================================================================
// Rows 2 and 3 — the primary went read-only
// =====================================================================

/// **State-model rows: "primary lost — failover to a new primary" and
/// "read-only target".**
///
/// One container is one primary, so a real failover cannot be staged here.
/// `default_transaction_read_only` on the role is not an approximation of
/// it: `authority_check_statement` tests
/// `pg_is_in_recovery() OR current_setting('transaction_read_only') = 'on'`,
/// so a demoted primary and a session that cannot write are *the same
/// observation* to the gateway by construction.
///
/// The promotion half is asserted too: resetting the flag returns both
/// replicas to `ready` without a restart, which is what a deployment
/// behind a failover-managing database layer depends on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_only_authority_is_storage_unavailable_and_recovers() {
    let Some(mut cluster) = start_matrix_cluster(matrix_options()).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    // The state a control-plane write must not move while the target is
    // read-only.
    let versions_before = cluster
        .database
        .count(&format!(
            "SELECT count(*)::bigint FROM {POLICY_DOCUMENTS_TABLE}"
        ))
        .await;

    // Role-and-database settings apply at session start, so the pool has
    // to reopen before the fault is live.
    cluster.database.set_read_only(true).await;
    cluster.database.terminate_runtime_backends().await;

    // 1. The reason.
    for replica in &cluster.replicas {
        wait_for_reason(replica, STORAGE_UNAVAILABLE, AUTHORITY_BUDGET).await;
    }

    // 2. The request behaviour: an admin write is refused with a 5xx and
    //    NOT laundered into a 4xx. A `409` or `403` here would tell an
    //    operator their request was wrong when the deployment was.
    let (status, body) = cluster
        .put("a", &policy_route())
        .bearer(&admin)
        .if_match(&cluster.seed_policy_etag)
        .json(&serde_json::from_str::<Value>(&admin_policy()).expect("the admin policy is JSON"))
        .send()
        .await;
    assert!(
        status >= 500,
        "a write against a read-only authority must be a server-side refusal, not {status}: \
         {body}"
    );

    // 3. And it moved nothing.
    let versions_during = cluster
        .database
        .count(&format!(
            "SELECT count(*)::bigint FROM {POLICY_DOCUMENTS_TABLE}"
        ))
        .await;
    assert_eq!(
        versions_before, versions_during,
        "a refused write must leave no partial version behind"
    );

    // 4. Promotion: the flag clears and the replicas return, no restart.
    cluster.database.set_read_only(false).await;
    cluster.database.terminate_runtime_backends().await;
    for replica in &cluster.replicas {
        wait_until_ready(replica, AUTHORITY_BUDGET).await;
    }

    // And the deployment is whole again: both replicas back in one roster,
    // both stamped ready.
    //
    // Polled rather than sampled once, and this is not a courtesy. A
    // replica's `/readyz` is its own answer, evaluated on the spot; the
    // roster's `ready_at` is a column another replica reads, written by
    // the next successful heartbeat. The two are allowed to disagree for
    // one heartbeat interval, and a row that asserted them equal at one
    // instant would be asserting the heartbeat had already fired.
    wait_for_ready_replicas(&cluster, "b", &admin, 2, LEASE_BUDGET).await;

    cluster.shutdown();
}

// =====================================================================
// Row 7 — the pool cannot be filled
// =====================================================================

/// **State-model row: "pool exhausted at runtime".**
///
/// `CONNECTION LIMIT 0` makes every new checkout fail with SQLSTATE
/// `53300` (`too_many_connections`), which `classify_postgres_error` maps
/// to `Unavailable` through its `53*` arm — the *same* arm a disk-full
/// `53100` travels. That is why this row is the honest substitute for the
/// disk-full row rather than a unit test asserting a match arm reads the
/// way it reads (see
/// [`disk_exhaustion_is_covered_by_classification_not_by_injection`]).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_exhaustion_is_storage_unavailable_and_recovers() {
    let Some(mut cluster) = start_matrix_cluster(matrix_options()).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");
    let role = cluster.database.role.clone();

    let mut fault = Fault::inject(
        &cluster.database.admin_dsn,
        &format!("ALTER ROLE {role} CONNECTION LIMIT 0"),
        &format!("ALTER ROLE {role} CONNECTION LIMIT -1"),
    )
    .await;
    cluster.database.terminate_runtime_backends().await;

    // 1. The reason.
    for replica in &cluster.replicas {
        wait_for_reason(replica, STORAGE_UNAVAILABLE, AUTHORITY_BUDGET).await;
    }

    // 2. The request behaviour: refused, nothing dispatched.
    cluster.upstream.clear();
    let (status, body) = cluster.get("a", PROXIED_PATH).bearer(&admin).send().await;
    assert!(
        status >= 500,
        "a replica that cannot open a connection must refuse, not answer {status}: {body}"
    );
    assert_eq!(
        proxied_count(&cluster),
        0,
        "nothing may be dispatched while the pool cannot be filled"
    );

    // 3. The metrics say which of the two `storage_unavailable` causes it
    //    is. `/metrics` is scrapable without a credential and while
    //    unready, which is exactly when an operator needs it.
    let metrics = cluster.metrics("a").await;
    assert!(
        metrics.contains("greengateway_database_pool_available"),
        "the pool gauges should be published while the pool is unusable"
    );
    assert_no_connection_detail(
        &cluster,
        "replica a's /metrics during pool exhaustion",
        &metrics,
    );

    // 4. Recovery.
    fault.revert().await;
    for replica in &cluster.replicas {
        wait_until_ready(replica, AUTHORITY_BUDGET).await;
    }

    cluster.shutdown();
}

// =====================================================================
// Row 8a — the statement timeout that is not the gateway's
// =====================================================================

/// **State-model row: "statement timeout" — and the precedence trap under
/// it.**
///
/// `ALTER ROLE ... SET statement_timeout` does **not** reach the gateway.
/// The gateway sets `statement_timeout` as a connection *startup
/// parameter* (`storage/postgres.rs`), and a startup parameter outranks a
/// role default, so `DATABASE_STATEMENT_TIMEOUT_MS` is the only lever that
/// bounds a gateway statement.
///
/// A row that merely asserted "the replicas stayed ready" would pass on a
/// fault that never took effect, so this one proves the fault is live
/// first: a plain session as the same role, in the same database, is
/// cancelled with `57014` on a statement the gateway runs longer ones
/// than. Only then is the gateway's indifference to it evidence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_role_statement_timeout_never_reaches_the_gateway() {
    let Some(mut cluster) = start_matrix_cluster(matrix_options()).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    cluster.database.set_role_statement_timeout(Some(1)).await;
    cluster.database.terminate_runtime_backends().await;

    // The fault is live: a session that does not set its own timeout is
    // cancelled well inside a statement the gateway would complete.
    let runtime_dsn = cluster.database.runtime_dsn.clone();
    let (client, connection) = tokio_postgres::connect(&runtime_dsn, tokio_postgres::NoTls)
        .await
        .expect("a plain runtime-role session should still connect");
    let pump = tokio::spawn(async move {
        let _ = connection.await;
    });
    let cancelled = client.query_one("SELECT pg_sleep(0.5)", &[]).await;
    let error = cancelled.expect_err(
        "a 1 ms role statement_timeout should have cancelled this statement; if it did not, \
         the fault never took effect and the rest of this row proves nothing",
    );
    assert_eq!(
        error.code().map(|state| state.code()),
        Some("57014"),
        "the cancellation should be query_canceled, not {error}"
    );
    drop(client);
    pump.abort();

    // And the gateway is untouched by it, across a window rather than at
    // one instant.
    assert_ready_across(
        &cluster,
        Duration::from_secs(3),
        "a role statement_timeout must not reach the gateway",
    )
    .await;

    cluster.upstream.clear();
    let (status, body) = cluster.get("b", PROXIED_PATH).bearer(&admin).send().await;
    assert_eq!(
        status, 200,
        "the gateway's own startup parameter outranks the role default: {body}"
    );
    assert_eq!(proxied_count(&cluster), 1);

    cluster.database.set_role_statement_timeout(None).await;
    cluster.database.terminate_runtime_backends().await;
    for replica in &cluster.replicas {
        wait_until_ready(replica, AUTHORITY_BUDGET).await;
    }

    cluster.shutdown();
}

// =====================================================================
// Rows 8b, 8c and 10 — locks, and which ones readiness can see
// =====================================================================

/// **State-model rows: "lock timeout" (readiness affected and not) and
/// "slow query".**
///
/// The same fault shape applied to two tables, with opposite outcomes,
/// which is what makes this a test rather than a ritual: a probe that read
/// more of the database than it needs to would fail the first half, and a
/// probe that read less than the ledger would fail the second.
///
/// * `ACCESS EXCLUSIVE` on `policy_documents` — the probe's statement
///   touches `pg_is_in_recovery()` and `count(*)` on the ledger, neither
///   of which conflicts, so the replicas stay `200 ready` and every
///   `/readyz` answers promptly. An admin *write* is refused with a 5xx,
///   never laundered into a `409`.
/// * `ACCESS EXCLUSIVE` on the ledger — now the probe's own statement
///   blocks, its `DATABASE_STATEMENT_TIMEOUT_MS` cancels it (`57014`), and
///   readiness is refused as `storage_unavailable`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lock_on_the_ledger_blocks_readiness_and_a_lock_elsewhere_does_not() {
    let mut options = matrix_options();
    // The only lever that bounds a gateway statement; see
    // `a_role_statement_timeout_never_reaches_the_gateway`.
    options.statement_timeout_ms = Some(STATEMENT_TIMEOUT_MS);
    let Some(mut cluster) = start_matrix_cluster(options).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");
    let etag = cluster.seed_policy_etag.clone();

    // --- half one: a lock the probe does not care about ---------------
    let mut held = HeldLock::take(&cluster.database.migrator_dsn, POLICY_DOCUMENTS_TABLE).await;

    assert_ready_across(
        &cluster,
        Duration::from_secs(2),
        "a lock on policy_documents must not make a replica unready",
    )
    .await;

    // Every answer came back well inside the statement timeout: an
    // orchestrator's health check has a deadline, and a probe that starts
    // blocking on a slow authority breaks it long before it reports
    // anything.
    for replica in &cluster.replicas {
        let started = Instant::now();
        let (status, _) = replica.readyz().await;
        let elapsed = started.elapsed();
        assert_eq!(status, 200, "replica {}", replica.name);
        assert!(
            elapsed < Duration::from_millis(1_500),
            "replica {} answered /readyz in {elapsed:?}; the cache is what keeps this bounded",
            replica.name
        );
    }

    // The write that DOES contend is refused as a server-side condition.
    let (status, body) = cluster
        .put("a", &policy_route())
        .bearer(&admin)
        .if_match(&etag)
        .json(&serde_json::from_str::<Value>(&admin_policy()).expect("the admin policy is JSON"))
        .send()
        .await;
    assert!(
        status >= 500,
        "a write blocked behind a lock is a timeout, not a conflict or a denial; got {status}: \
         {body}"
    );

    held.release().await;
    assert_all_ready_now(&cluster, "after releasing the policy_documents lock").await;

    // --- half two: a lock the probe cannot avoid ----------------------
    let mut held = HeldLock::take(&cluster.database.migrator_dsn, LEDGER_TABLE).await;

    for replica in &cluster.replicas {
        wait_for_reason(replica, STORAGE_UNAVAILABLE, AUTHORITY_BUDGET).await;
    }

    held.release().await;
    for replica in &cluster.replicas {
        wait_until_ready(replica, AUTHORITY_BUDGET).await;
    }

    cluster.shutdown();
}

// =====================================================================
// Rows 11a, 11b, 11c — the ledger
// =====================================================================

/// **State-model row: "dirty/incompatible schema", ledger *behind*.**
///
/// Another gateway rolled a migration back, or a restore replaced the
/// database with an older one. The ledger no longer covers this binary's
/// manifest, and the replica must refuse **readiness**.
///
/// It is a readiness refusal and nothing more: the authority is perfectly
/// reachable, the security gate still compiles, and a request still routed
/// to this replica is still served. That is the behaviour the deployment
/// guide's load-balancer advice rests on — a health check wired to
/// `/livez`, to a proxied route or to a TCP connect keeps a replica in
/// rotation that has declared it does not understand its own schema — so
/// step 2 below asserts it rather than leaving it to review.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ledger_behind_the_manifest_is_schema_incompatible() {
    let Some(mut cluster) = start_matrix_cluster(matrix_options()).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    // Capture the row before deleting it: the reversal must restore the
    // ledger byte for byte, or the recovery half proves nothing.
    let row = cluster
        .database
        .query_one(&format!(
            "SELECT version, name, checksum FROM {LEDGER_TABLE} \
             ORDER BY version DESC LIMIT 1"
        ))
        .await;
    let version: i64 = row.get(0);
    let name: String = row.get(1);
    let checksum: String = row.get(2);
    let escaped_name = name.replace('\'', "''");
    let escaped_checksum = checksum.replace('\'', "''");

    let mut fault = Fault::inject(
        &cluster.database.migrator_dsn,
        &format!("DELETE FROM {LEDGER_TABLE} WHERE version = {version}"),
        &format!(
            "INSERT INTO {LEDGER_TABLE} (version, name, checksum) \
             VALUES ({version}, '{escaped_name}', '{escaped_checksum}') \
             ON CONFLICT (version) DO NOTHING"
        ),
    )
    .await;

    // 1. The reason.
    for replica in &cluster.replicas {
        wait_for_reason(replica, SCHEMA_INCOMPATIBLE, AUTHORITY_BUDGET).await;
    }

    // 2. The request behaviour, which for this reason is "unchanged".
    //    `schema_incompatible` takes the replica out of `/readyz` and does
    //    nothing else: a caller a load balancer still routes here is
    //    served, and the request reaches the upstream. Asserted because
    //    two pieces of operator advice hang off it — pull the replica by
    //    hand, and wire the health check to `/readyz` — and advice nothing
    //    asserts is advice that can quietly stop being true.
    //
    //    Re-asked past a transient `503` on the same budget the cluster
    //    status read uses, and the upstream counter is cleared before each
    //    attempt so the count below is the attempt that was served.
    let deadline = Instant::now() + CLUSTER_STATUS_SETTLE;
    let (status, body) = loop {
        cluster.upstream.clear();
        let answer = cluster.get("a", PROXIED_PATH).bearer(&admin).send().await;
        if answer.0 != 503 || Instant::now() >= deadline {
            break answer;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(
        status, 200,
        "schema_incompatible is a readiness refusal, not a request refusal: a replica whose \
         ledger it does not accept keeps serving what is still routed to it: {body}"
    );
    assert_eq!(
        proxied_count(&cluster),
        1,
        "the request a schema-incompatible replica served should have reached the upstream: {:?}",
        proxied_requests(&cluster)
    );

    // 3. The two surfaces agree, word for word. This is the one family of
    //    faults where the cluster status API is still answerable — the
    //    authority is perfectly reachable, it is the *ledger* that is
    //    wrong — so it is where the agreement is asserted.
    assert_cluster_status_agrees(&cluster, "a", &admin, SCHEMA_INCOMPATIBLE).await;
    let (_, body) = cluster_status(&cluster, "a", &admin).await;
    assert_eq!(
        body["schema"]["compatible"], false,
        "the schema view must agree with the reason: {body}"
    );
    let current = body["schema"]["current_version"]
        .as_i64()
        .unwrap_or_else(|| panic!("the ledger version should be reported: {body}"));
    let minimum = body["schema"]["binary_min"]
        .as_i64()
        .unwrap_or_else(|| panic!("the manifest minimum should be reported: {body}"));
    assert!(
        current < minimum,
        "a ledger behind the manifest should report a version below the binary minimum: {body}"
    );
    assert_no_connection_detail(&cluster, "the cluster status body", &body.to_string());

    // 4. `greengateway_schema_compatible` is the alert an operator pages
    //    on, and the probe is the only thing that re-writes it under a
    //    serving replica.
    let metrics = cluster.metrics("a").await;
    assert!(
        metrics.contains("greengateway_schema_compatible 0"),
        "greengateway_schema_compatible should have been re-written to 0 by the probe"
    );

    // 5. Recovery.
    fault.revert().await;
    for replica in &cluster.replicas {
        wait_until_ready(replica, AUTHORITY_BUDGET).await;
    }

    cluster.shutdown();
}

/// **State-model row: "dirty/incompatible schema", ledger *ahead*.**
///
/// The other direction, and the one a rolling upgrade produces: a newer
/// gateway migrated the shared database and this binary can no longer
/// serve on it. Asserted separately from the behind case because a naive
/// comparison (`version < minimum`) passes one and fails the other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ledger_ahead_of_the_manifest_is_schema_incompatible() {
    let Some(mut cluster) = start_matrix_cluster(matrix_options()).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    let highest: i64 = cluster
        .database
        .query_one(&format!(
            "SELECT coalesce(max(version), 0)::bigint FROM {LEDGER_TABLE}"
        ))
        .await
        .get(0);
    // Far enough above the manifest that no future migration count can
    // accidentally make this compatible.
    let synthetic = highest + 1_000;

    let mut fault = Fault::inject(
        &cluster.database.migrator_dsn,
        &format!(
            "INSERT INTO {LEDGER_TABLE} (version, name, checksum) \
             VALUES ({synthetic}, 'ha-failure-matrix-synthetic', 'ha-failure-matrix-synthetic')"
        ),
        &format!("DELETE FROM {LEDGER_TABLE} WHERE version = {synthetic}"),
    )
    .await;

    for replica in &cluster.replicas {
        wait_for_reason(replica, SCHEMA_INCOMPATIBLE, AUTHORITY_BUDGET).await;
    }

    let (_, body) = cluster_status(&cluster, "b", &admin).await;
    let current = body["schema"]["current_version"]
        .as_i64()
        .unwrap_or_else(|| panic!("the ledger version should be reported: {body}"));
    let maximum = body["schema"]["binary_max"]
        .as_i64()
        .unwrap_or_else(|| panic!("the manifest maximum should be reported: {body}"));
    assert!(
        current > maximum,
        "a ledger ahead of the manifest should report a version above the binary maximum: \
         {body}"
    );

    fault.revert().await;
    for replica in &cluster.replicas {
        wait_until_ready(replica, AUTHORITY_BUDGET).await;
    }

    cluster.shutdown();
}

/// **State-model row: "no ledger at all".**
///
/// This row exists to pin one deliberate decision in
/// `ha_status::observe_once`: `42P01`/`3F000` — the ledger table or its
/// schema not existing — is reported as `Writable { schema_version: 0 }`,
/// which no accepted range contains, and therefore as
/// `schema_incompatible`.
///
/// The distinguishing part is what it must **not** say. Every other query
/// error on the same statement is `storage_unavailable`, so an
/// implementation that dropped the special case would still fail
/// `/readyz` — with the wrong word, sending an operator to look at a
/// database that is answering perfectly well instead of at a database
/// nobody migrated.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_missing_ledger_is_schema_incompatible_not_storage_unavailable() {
    let Some(mut cluster) = start_matrix_cluster(matrix_options()).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    let mut fault = Fault::inject(
        &cluster.database.migrator_dsn,
        &format!("ALTER TABLE {LEDGER_TABLE} RENAME TO schema_migrations_hidden"),
        "ALTER TABLE greengateway.schema_migrations_hidden RENAME TO schema_migrations",
    )
    .await;

    for replica in &cluster.replicas {
        wait_for_reason(replica, SCHEMA_INCOMPATIBLE, AUTHORITY_BUDGET).await;
        // Said explicitly, because "not the other word" is this row's
        // entire subject.
        assert_eq!(
            reason_now(replica).await.as_deref(),
            Some(SCHEMA_INCOMPATIBLE),
            "a database that is not migrated for this binary must not masquerade as an outage"
        );
    }

    let (_, body) = cluster_status(&cluster, "a", &admin).await;
    assert_eq!(
        body["schema"]["current_version"], 0,
        "a ledger that does not exist covers no migrations: {body}"
    );

    fault.revert().await;
    for replica in &cluster.replicas {
        wait_until_ready(replica, AUTHORITY_BUDGET).await;
    }

    cluster.shutdown();
}

// =====================================================================
// Row 12 — the membership lease
// =====================================================================

/// **State-model row: "instance lease invalid".**
///
/// The roster write grant is taken away, so the heartbeat starts failing
/// while every other query keeps working. Two assertions, and the first
/// one is the one that makes this a test: the replica stays `200 ready`
/// through the early failures, because **one failed heartbeat is not this
/// condition** — a probe that flipped on the first failure would be
/// unusable behind a load balancer.
///
/// Only after `CLUSTER_MEMBER_STALE_MS` has elapsed since the last
/// *successful* heartbeat does the reason appear.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failing_heartbeat_becomes_instance_lease_invalid_only_after_the_stale_window() {
    let Some(mut cluster) = start_matrix_cluster(matrix_options()).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    let mut fault = revoke_table_privilege(&cluster, "INSERT, UPDATE", MEMBERS_TABLE).await;

    // The grace. Sampled across several heartbeat intervals — the
    // heartbeat is 1 s and the stale window 9 s, so a replica that
    // reported the lease invalid here would be reporting it on one missed
    // beat.
    assert_ready_across(
        &cluster,
        Duration::from_secs(3),
        "one failed heartbeat is not instance_lease_invalid",
    )
    .await;

    // Then the condition.
    for replica in &cluster.replicas {
        wait_for_reason(replica, INSTANCE_LEASE_INVALID, LEASE_BUDGET).await;
    }

    // The two surfaces agree. The authority is reachable throughout this
    // row, so the cluster status API answers and can be checked.
    assert_cluster_status_agrees(&cluster, "a", &admin, INSTANCE_LEASE_INVALID).await;

    let metrics = cluster.metrics("a").await;
    assert!(
        metrics.contains("greengateway_cluster_heartbeat_age_seconds"),
        "the heartbeat age gauge is the series an operator alerts on for this reason"
    );

    // Recovery: the next successful heartbeat clears it.
    fault.revert().await;
    for replica in &cluster.replicas {
        wait_until_ready(replica, LEASE_BUDGET).await;
    }

    cluster.shutdown();
}

// =====================================================================
// Row 13 — the security watermark
// =====================================================================

/// **State-model row: "new security revision not locally compiled".**
///
/// The runtime role loses `SELECT` on the security revision counter. That
/// is a surgical fault: the readiness probe's own statement touches
/// `pg_is_in_recovery()` and the migration ledger and is unaffected, so
/// `storage_unavailable` — which outranks this reason — cannot fire and
/// mask it. Only the gate is blind, which is precisely the condition this
/// reason names.
///
/// Two assertions, in this order:
///
/// 1. **During the grace, protected requests are already `503`.** The gate
///    fails closed the moment it cannot confirm its watermark; it does not
///    serve one more request under the revision it last compiled. This is
///    the assertion the whole reason exists for.
/// 2. **Readiness holds for the reconcile deadline, then goes.**
///    `RECONCILE_BACKGROUND_DEADLINE` is a hard-coded 30 s in
///    `security_cluster.rs` with no environment variable, so this row
///    costs 30 s of wall clock and nothing here can shorten it.
///
/// The cluster runs with a long stale window so the lease reason, which
/// outranks this one, cannot fire inside the 30 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blind_security_gate_becomes_security_revision_not_compiled() {
    let mut options = matrix_options();
    // Comfortably longer than RECONCILE_BACKGROUND_DEADLINE, so
    // instance_lease_invalid cannot pre-empt the reason under test.
    options.member_stale_ms = 120_000;
    options.heartbeat_ms = 2_000;
    let Some(mut cluster) = start_matrix_cluster(options).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    cluster.upstream.clear();
    let (status, body) = cluster.get("a", PROXIED_PATH).bearer(&admin).send().await;
    assert_eq!(status, 200, "the warm-up request should be served: {body}");

    let mut fault = revoke_table_privilege(&cluster, "SELECT", REVISION_STATE_TABLE).await;

    // 1. The gate fails closed. The poll bounds how long the revocation
    //    may take to become visible to a session already in the pool — a
    //    request served in that window was served under a revision the
    //    gate genuinely confirmed, which is not the defect this row is
    //    about. What must never happen is a request served AFTER the gate
    //    has started refusing, and that is asserted below.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut refused = false;
    while Instant::now() < deadline {
        let (status, _) = cluster.get("a", PROXIED_PATH).bearer(&admin).send().await;
        if status >= 500 {
            refused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        refused,
        "a replica that cannot read the revision counter must refuse protected traffic rather \
         than serve under the revision it last compiled"
    );
    // From here on, nothing may reach the upstream.
    cluster.upstream.clear();

    // Readiness is still `200` here — the replica is refusing, but not for
    // long enough yet — which is what the reconcile grace is for.
    let early = reason_now(cluster.replica("a")).await;
    assert!(
        early.is_none() || early.as_deref() == Some(SECURITY_REVISION_NOT_COMPILED),
        "during the grace the replica is either ready or already past the deadline, never \
         some other reason; it said {early:?}"
    );

    // 2. Then the reason, after the reconcile deadline — and protected
    //    traffic is refused at every sample on the way there. Driving
    //    requests through the whole grace is the point: a replica that
    //    gave up and fell back to its last compiled allow would do so
    //    somewhere in this window, not necessarily at its start.
    let deadline = Instant::now() + REVISION_BUDGET;
    let mut saw_reason = false;
    let mut samples = 0_usize;
    while Instant::now() < deadline {
        let (status, body) = cluster.get("a", PROXIED_PATH).bearer(&admin).send().await;
        assert_ne!(
            status, 200,
            "a replica whose gate cannot confirm its watermark must never serve: {body}"
        );
        samples += 1;
        if reason_now(cluster.replica("a")).await.as_deref() == Some(SECURITY_REVISION_NOT_COMPILED)
        {
            saw_reason = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        saw_reason,
        "the replica never reported {SECURITY_REVISION_NOT_COMPILED:?} within {REVISION_BUDGET:?} \
         over {samples} samples"
    );

    // Nothing reached the upstream through the whole window.
    assert_eq!(
        proxied_count(&cluster),
        0,
        "a replica whose gate is blind dispatched under a stale allow: {:?}",
        proxied_requests(&cluster)
    );

    // 3. Recovery: the background poller's next pass admits, the streak
    //    clears, and the replica serves again.
    fault.revert().await;
    for replica in &cluster.replicas {
        wait_until_ready(replica, AUTHORITY_BUDGET).await;
    }
    cluster.upstream.clear();
    let (status, body) = cluster.get("a", PROXIED_PATH).bearer(&admin).send().await;
    assert_eq!(
        status, 200,
        "the recovered replica should serve protected traffic again: {body}"
    );
    assert_eq!(proxied_count(&cluster), 1);

    cluster.shutdown();
}

// =====================================================================
// Row 16 — the order
// =====================================================================

/// **State-model row: "ordering".** The reason chain is total, and this
/// row is the proof.
///
/// Three faults are stacked so that three conditions hold at once, and
/// then lifted one at a time. The reported reason must walk:
///
/// ```text
/// storage_unavailable → schema_incompatible → instance_lease_invalid → ready
/// ```
///
/// Nothing else passes this. An implementation that evaluated the schema
/// before storage reports the wrong word at step 1. One that collapsed two
/// reasons into a single "not ready" reports the same word twice. One that
/// re-evaluated the chain out of order reports a word out of sequence.
/// This is the row that makes every other row's single-reason assertion
/// mean something.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_reason_chain_is_reported_in_the_documented_order() {
    let Some(mut cluster) = start_matrix_cluster(matrix_options()).await else {
        return skipped();
    };

    // --- build the stack, innermost condition first -------------------

    // Condition 3: the lease. Applied first because it is the slowest to
    // become true, and it must be *already* true when the two faster ones
    // are stacked on top of it — otherwise the walk back down would be
    // measuring how long a heartbeat takes to go stale rather than the
    // order of the chain.
    let mut lease = revoke_table_privilege(&cluster, "INSERT, UPDATE", MEMBERS_TABLE).await;
    wait_for_reason(cluster.replica("a"), INSTANCE_LEASE_INVALID, LEASE_BUDGET).await;

    // Condition 2: the schema. It must now outrank the lease.
    let row = cluster
        .database
        .query_one(&format!(
            "SELECT version, name, checksum FROM {LEDGER_TABLE} ORDER BY version DESC LIMIT 1"
        ))
        .await;
    let version: i64 = row.get(0);
    let name: String = row.get::<_, String>(1).replace('\'', "''");
    let checksum: String = row.get::<_, String>(2).replace('\'', "''");
    let mut schema = Fault::inject(
        &cluster.database.migrator_dsn,
        &format!("DELETE FROM {LEDGER_TABLE} WHERE version = {version}"),
        &format!(
            "INSERT INTO {LEDGER_TABLE} (version, name, checksum) \
             VALUES ({version}, '{name}', '{checksum}') ON CONFLICT (version) DO NOTHING"
        ),
    )
    .await;
    wait_for_reason(cluster.replica("a"), SCHEMA_INCOMPATIBLE, AUTHORITY_BUDGET).await;

    // Condition 1: storage. It must now outrank both.
    cluster.database.revoke_connect().await;
    cluster.database.terminate_runtime_backends().await;
    wait_for_reason(cluster.replica("a"), STORAGE_UNAVAILABLE, AUTHORITY_BUDGET).await;

    // --- and walk back down -------------------------------------------

    // Lift storage: the schema is next, not ready and not the lease.
    cluster.database.restore_connect().await;
    wait_for_reason(cluster.replica("a"), SCHEMA_INCOMPATIBLE, AUTHORITY_BUDGET).await;

    // Lift the schema: the lease is next.
    schema.revert().await;
    wait_for_reason(
        cluster.replica("a"),
        INSTANCE_LEASE_INVALID,
        AUTHORITY_BUDGET,
    )
    .await;

    // Lift the lease: ready.
    lease.revert().await;
    wait_until_ready(cluster.replica("a"), LEASE_BUDGET).await;
    wait_until_ready(cluster.replica("b"), LEASE_BUDGET).await;

    cluster.shutdown();
}

// =====================================================================
// Row 5 — a replica that stops making progress
// =====================================================================

/// **State-model row: "member stops heartbeating (crash, partition)", and
/// the second half of the `iptables` substitution.**
///
/// `SIGSTOP` is the one genuinely *per-replica* fault this harness has:
/// the process stops answering and stops heartbeating without closing its
/// sockets, which is what a network partition looks like from the other
/// side. The database faults above cannot do this, because the harness
/// creates one runtime role per cluster and both replicas share it.
///
/// Skips on a platform with no such signal (`Replica::pause` answers
/// `false` on Windows, where suspending a process by thread is not the
/// same thing). The gate runs on Linux, where it does not skip.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paused_replica_stops_answering_while_the_deployment_holds_its_roster() {
    let Some(mut cluster) = start_matrix_cluster(matrix_options()).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    if !cluster.replica("a").pause() {
        eprintln!(
            "skipping the paused-replica row: this platform has no SIGSTOP, so the one \
             per-replica fault the harness has is unavailable here"
        );
        cluster.shutdown();
        return;
    }

    // B is unaffected: it keeps serving throughout, which is the half of
    // a partition row that is easy to get wrong.
    cluster.upstream.clear();
    let (status, body) = cluster.get("b", PROXIED_PATH).bearer(&admin).send().await;
    assert_eq!(
        status, 200,
        "the surviving replica must keep serving while its sibling is frozen: {body}"
    );

    // A's roster row ages out of the stale window, judged on DATABASE
    // time: `live_member_count` compares `last_heartbeat_at` against the
    // server's `now()`, never against this process's clock.
    let deadline = Instant::now() + LEASE_BUDGET;
    loop {
        if cluster.live_member_count().await <= 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the frozen replica's roster row never went stale within {LEASE_BUDGET:?}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // B's own view says so.
    let (status, body) = cluster_status(&cluster, "b", &admin).await;
    assert_eq!(status, 200, "the cluster status API should answer: {body}");
    assert_eq!(
        body["replicas"]["total"], 1,
        "the frozen replica should have left the live roster: {body}"
    );

    // Recovery: A resumes, re-registers, and is ready again.
    assert!(cluster.replica("a").resume(), "SIGCONT should be delivered");
    wait_until_ready(cluster.replica("a"), LEASE_BUDGET).await;
    let deadline = Instant::now() + LEASE_BUDGET;
    loop {
        if cluster.live_member_count().await == 2 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the resumed replica never rejoined the roster"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    cluster.shutdown();
}

// =====================================================================
// The last rung — the proxy
// =====================================================================

/// **The chain's last arm: `required_upstream_unavailable`.**
///
/// Every other row in this file drives one of the four *authority* rungs.
/// This one drives the rung below them all, which predates cluster mode and
/// behaves identically in both modes: `readiness_blocked_reason`'s final
/// arm asks `proxy.required_pools_ready()`, and a pool configured with
/// `required_for_readiness` that has fewer than `minimum_healthy` eligible
/// endpoints answers this word.
///
/// It exists because [`REASON_VOCABULARY`] is checked in one direction
/// only: every row proves a reason it produces is in the list, and nothing
/// proved that a word *in* the list is producible at all. Four of the eight
/// are named absences with `#[ignore]`d rows below; this one was neither
/// produced nor named, so a broken rung here would have failed no row. It
/// is cheap to produce for real — the fake upstream simply stops answering
/// `200` — so it is produced rather than documented.
///
/// The fault is the upstream's, not the database's, so the deployment stays
/// otherwise healthy throughout: the cluster status API keeps answering and
/// reports the same word `/readyz` does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unhealthy_required_upstream_is_required_upstream_unavailable_and_recovers() {
    let options = ClusterOptions {
        upstream_required_for_readiness: true,
        ..matrix_options()
    };
    let Some(mut cluster) = start_matrix_cluster(options).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    // The cluster reached ready, which means the health check passed: the
    // rung is wired in and starts satisfied, so the transition below is the
    // fault rather than a pool that was never healthy.
    assert_all_ready_now(&cluster, "before the upstream is broken").await;

    // 1. The reason. The health check asks for `200` and now gets `503`.
    cluster
        .upstream
        .set_behaviour(harness::Behaviour::Status(503));
    for replica in &cluster.replicas {
        wait_for_reason(replica, "required_upstream_unavailable", AUTHORITY_BUDGET).await;
    }

    // 2. The two surfaces agree. Unlike the authority rows, nothing is
    //    wrong with the database here, so this is the cleanest place in the
    //    suite to assert that the cluster view passes a *proxy* reason
    //    through unchanged rather than inventing one of its own.
    assert_cluster_status_agrees(&cluster, "a", &admin, "required_upstream_unavailable").await;

    // 3. Recovery, with no restart: the pool becomes eligible again on its
    //    own next check.
    cluster.upstream.set_behaviour(harness::Behaviour::Ok);
    for replica in &cluster.replicas {
        wait_until_ready(replica, AUTHORITY_BUDGET).await;
    }

    cluster.shutdown();
}

// =====================================================================
// The rows that are NOT injected here, each named rather than absent
// =====================================================================

/// **Not injectable: a network-level partition.**
///
/// The PostgreSQL service container's port reaches a hosted job through
/// Docker's userland proxy and a DNAT rule in the `DOCKER` chain. A `DROP`
/// rule that severs it without severing the runner's own control-plane
/// traffic is not something to bet a required merge gate on, and it is not
/// portable to a self-hosted or container-job runner.
///
/// **Substituted, in two halves, both of which are asserted:**
///
/// * "this replica cannot reach the authority" —
///   [`losing_the_authority_is_storage_unavailable_and_recovers`], which
///   revokes `CONNECT` and terminates the established backends.
/// * "this replica is unreachable and is not heartbeating" —
///   [`a_paused_replica_stops_answering_while_the_deployment_holds_its_roster`],
///   which `SIGSTOP`s the process.
///
/// This row is `#[ignore]`d rather than deleted so the substitution is
/// visible in the test list: a skipped row that says why is evidence, a
/// missing row is not.
#[test]
#[ignore = "iptables is not available on a hosted runner; substituted by \
            losing_the_authority_is_storage_unavailable_and_recovers and \
            a_paused_replica_stops_answering_while_the_deployment_holds_its_roster"]
fn iptables_network_partition_is_substituted_not_injected() {
    panic!("this row documents a substitution and is never run");
}

/// **Not injectable: disk exhaustion.**
///
/// Producing a real `53100` needs a size-capped filesystem under a
/// tablespace inside the PostgreSQL container. A service container is not
/// privileged and cannot mount a `tmpfs`, and creating a tablespace on a
/// directory the runner can fill would fill the runner's own disk.
///
/// **Substituted by**
/// [`connection_exhaustion_is_storage_unavailable_and_recovers`], which
/// provokes a real `53300`. That is not an analogy: `classify_postgres_error`
/// routes both through the same `code.starts_with("53")` arm to
/// `RepositoryErrorKind::Unavailable`, which the readiness probe reports as
/// `storage_unavailable`. The end-to-end path a disk-full error would take
/// is therefore exercised; only the SQLSTATE differs.
#[test]
#[ignore = "a hosted runner cannot produce a real 53100; the identical 53* classification \
            path is exercised by connection_exhaustion_is_storage_unavailable_and_recovers"]
fn disk_exhaustion_is_covered_by_classification_not_by_injection() {
    panic!("this row documents a substitution and is never run");
}

/// **Not observable through this harness: `draining`.**
///
/// `readiness_blocked_reason`'s first arm answers `draining` the moment
/// the lifecycle stops accepting work — before any authority round trip,
/// which is the property worth asserting. Observing it needs a drain
/// window to sample `/readyz` in, and the harness pins
/// `SHUTDOWN_DRAIN_DELAY_MS=0` on every replica
/// (`harness/mod.rs::replica_environment`), after copying `shared_env`, so
/// a suite cannot lengthen it.
///
/// Giving this row a window is a change to part 1's harness, not to this
/// file. Recorded here so the gap is in the test list rather than inferred
/// from the vocabulary having one unasserted word in it.
#[test]
#[ignore = "the harness pins SHUTDOWN_DRAIN_DELAY_MS=0, so there is no drain window to \
            sample /readyz in; lengthening it is a harness change"]
fn draining_is_not_observable_through_this_harness() {
    panic!("this row documents a harness limitation and is never run");
}

/// **Not injectable through this harness: `config_fingerprint_mismatch`.**
///
/// The row needs a third replica started with one security-relevant
/// setting changed. `ClusterOptions` has no per-replica environment hook,
/// and that is deliberate: `harness/mod.rs` puts every setting the
/// fingerprint reads into `shared_environment` precisely so the replicas
/// agree, because a harness that varied the wrong one would produce two
/// processes that are healthy, correct, and permanently `503`.
///
/// The gate's condition is unit-tested in-crate (`ha.rs`'s own tests) and
/// is enforced by PR 13; what is missing here is the end-to-end row, and
/// adding it means a harness API for a deliberately-divergent replica.
#[test]
#[ignore = "the harness has no per-replica environment hook, by design; a divergent replica \
            is a harness change"]
fn config_fingerprint_mismatch_needs_a_third_replica_the_harness_cannot_vary() {
    panic!("this row documents a harness limitation and is never run");
}
