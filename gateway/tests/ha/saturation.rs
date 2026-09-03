//! Saturation: every queue, table, replay window and retry bound stays
//! bounded under sustained overload, and the deployment comes back
//! (issue #241, PR 16).
//!
//! The failure this file is written against is not "the gateway got
//! slow". It is the failure where something the cluster keeps *per
//! caller*, *per event* or *per invocation* has no ceiling, so a burst
//! that ends leaves a deployment that never recovers: a rate-limit table
//! that grows with the key space, a projector that re-reads a backlog it
//! already applied, an execution-lease scope that hands out more slots
//! than it owns, an audit queue that quietly forgets. Each of those is
//! invisible at one request per second and fatal at ten thousand.
//!
//! So every test here does the same three things in the same order:
//!
//! 1. **Overload one bound on purpose**, across *both* replicas, so a
//!    per-replica ceiling could not produce the answer a cluster-wide
//!    ceiling produces.
//! 2. **Assert the bound held** — and, where something had to give,
//!    assert it gave *loudly*: a counted drop, a `429`, an eviction. A
//!    bound that is enforced by silently discarding work is not a bound,
//!    it is a data-loss bug with a nice latency graph.
//! 3. **Assert the deployment returns to normal service** once the load
//!    stops: both replicas ready, the roster intact, a plain request
//!    served.
//!
//! Two rules of the harness apply throughout. Nothing sleeps for a
//! guessed duration: every wait is a bounded poll on something the test
//! can observe (a row count, a checkpoint, a metric, a status), and every
//! wait for *elapsed time* is a wait on database time. And no test binds a
//! port; the harness's servers hold their listeners from bind to serve.
//!
//! Skips silently without `GATEWAY_TEST_POSTGRES_URL_FILE`, like every
//! other PostgreSQL-backed suite in this repository.

#![cfg(feature = "postgres")]

mod harness;

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use harness::{AuthShape, Cluster, ClusterOptions, ProxyShape};

/// How long any cross-replica or background effect may take before the
/// test calls it a failure. Generous because every wait underneath it is
/// a poll that returns the moment its condition holds, and because this
/// machine shares its PostgreSQL server with the rest of the build.
const CONVERGENCE_BUDGET: Duration = Duration::from_secs(90);

/// The gap between two questions in a bounded poll. Never the thing being
/// waited for — only how often the observable is re-read.
const POLL_INTERVAL: Duration = Duration::from_millis(150);

/// How long a request re-asks a replica that answered "the authority is
/// unavailable".
///
/// A `503` from the revision or limiter gate is the replica declining to
/// judge, not an answer, so a step whose *subject* is something else
/// re-issues it within this bound rather than recording a decision that
/// was never made. Nothing whose assertion is about `503` goes through
/// such a retry.
const AUTHORITY_RETRY_BUDGET: Duration = Duration::from_secs(20);

/// The role the suite's tokens carry, and the one every seeded policy
/// grants. These tests are about ceilings, not about which permission
/// guards which route.
const ADMIN_ROLE: &str = "ha-admin";

/// The counter a shed audit event lands on (`audit::AUDIT_EVENTS_DROPPED_TOTAL`).
///
/// Restated here rather than imported: the gateway exports it as a
/// binary, and this suite reads it the way an operator does — off the
/// `/metrics` exposition — so the name it greps for should be the name
/// the exposition carries, not a symbol that could be renamed without
/// this test noticing.
const AUDIT_EVENTS_DROPPED_TOTAL: &str = "audit_events_dropped_total";

fn skipped() {
    eprintln!("skipping: no test database locator, or this run is not the gate; the ha-release-gate CI job runs this suite");
}

// ---------------------------------------------------------------------
// Local helpers.
//
// Everything below is private to this suite on purpose: the harness is
// shared with the other release-gate files and is not the place for a
// load generator or a Prometheus parser that only saturation needs.
// ---------------------------------------------------------------------

/// Poll `probe` until it answers `Ok`, or fail with the state it last
/// reported.
///
/// The closure returns `Err(description)` while the condition does not
/// hold, so the timeout message says what the observable actually was
/// rather than only what it should have been.
async fn poll_for<T, F, Fut>(budget: Duration, probe: F) -> T
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    let deadline = Instant::now() + budget;
    loop {
        let last = match probe().await {
            Ok(value) => return value,
            Err(state) => state,
        };
        assert!(
            Instant::now() < deadline,
            "the condition did not hold within {budget:?}; last observed: {last}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// The sum of every Prometheus sample whose name is `name`, across all
/// label sets.
///
/// Written against the exposition rather than against a particular label
/// set on purpose: `audit_events_dropped_total` is emitted with a
/// `reason` label whose values are the drop causes, and a test that named
/// one reason would miss a drop for another.
fn metric_sum(exposition: &str, name: &str) -> f64 {
    exposition
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let rest = line.strip_prefix(name)?;
            // Either `name value` or `name{labels} value`, and either of
            // those with the exposition's `_total` suffix already on it —
            // anything else is a different metric that merely starts with
            // these bytes.
            let rest = rest.strip_prefix("_total").unwrap_or(rest);
            if !(rest.starts_with(' ') || rest.starts_with('{')) {
                return None;
            }
            rest.rsplit_once(char::is_whitespace)
                .and_then(|(_, value)| value.parse::<f64>().ok())
        })
        .sum()
}

/// Every replica's value of `name`, added up: the deployment's total.
async fn cluster_metric_sum(cluster: &Cluster, name: &str) -> f64 {
    let mut total = 0.0;
    for replica in &cluster.replicas {
        total += metric_sum(&cluster.metrics(&replica.name).await, name);
    }
    total
}

/// Issue `total` unauthenticated requests through the balancer, at most
/// `concurrency` at a time, and answer the status of each.
///
/// Round robin is the balancer's default, so the load lands on both
/// replicas without this test choosing which — which is the point: a
/// bound that is really per replica would be twice as generous here and
/// the assertions would still pass if the load were pinned.
async fn burst_through_balancer(
    cluster: &Cluster,
    path: &str,
    total: usize,
    concurrency: usize,
) -> Vec<u16> {
    let mut statuses = Vec::with_capacity(total);
    let mut issued = 0;
    while issued < total {
        let wave = concurrency.min(total - issued);
        let responses =
            futures_util::future::join_all((0..wave).map(|_| cluster.get_through_balancer(path)))
                .await;
        statuses.extend(responses.iter().map(|response| response.status().as_u16()));
        issued += wave;
    }
    statuses
}

/// How many of `statuses` are not `expected`, rendered for a failure
/// message: the first few offenders and how many there were.
fn unexpected(statuses: &[u16], expected: u16) -> String {
    let offenders: Vec<u16> = statuses
        .iter()
        .copied()
        .filter(|status| *status != expected)
        .collect();
    match offenders.len() {
        0 => "none".to_owned(),
        count => format!(
            "{count} of {} (first few: {:?})",
            statuses.len(),
            &offenders[..count.min(8)]
        ),
    }
}

/// Assert the deployment is serving normally: both replicas ready, both
/// membership rows live, and a plain proxied request answered by the
/// cluster.
///
/// Called at the end of every test here, because "the bound held" is only
/// half the claim — a gateway that survives a burst by wedging has not
/// recovered.
async fn assert_recovered(cluster: &mut Cluster, path: &str) {
    cluster.wait_until_all_ready().await;
    let live = cluster.live_member_count().await;
    assert_eq!(
        live, 2,
        "both replicas should still hold a live membership row after the load stopped"
    );
    for name in ["a", "b"] {
        let response = cluster.get_pinned(name, path).await;
        assert_eq!(
            response.status().as_u16(),
            200,
            "replica {name} should serve a plain request once the load has stopped"
        );
    }
}

// ---------------------------------------------------------------------
// The audit queue.
// ---------------------------------------------------------------------

/// The path the audit burst drives, so the records it produces can be
/// told apart from a probe's.
const AUDIT_BURST_PATH: &str = "/echo/saturation-audit";
/// Requests in the audit burst.
const AUDIT_BURST: usize = 1_200;
/// How many of them are in flight at once.
const BURST_CONCURRENCY: usize = 32;

/// Sustained request load never loses an audit record *silently*.
///
/// The audit queue is bounded by construction (`audit::AUDIT_CHANNEL_CAPACITY`,
/// with a reserve the lifecycle events ride) and a request that finds it
/// full drops its event rather than blocking the request path. That is a
/// deliberate trade and it is the right one — but it is only defensible
/// while every dropped event is *counted*, because an operator reading an
/// audit trail has no other way to learn that the trail has a hole in it.
///
/// So this test does not assert that nothing is dropped, which would be an
/// assertion about how fast this machine's disk is. It asserts the
/// contract: for every request the deployment served, there is either a
/// durable record of it or a tick on `audit_events_dropped_total`. A
/// silent loss fails here; a counted loss does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn sustained_request_load_never_loses_an_audit_record_silently() {
    let Some(mut cluster) = Cluster::start(ClusterOptions {
        // The pre-authentication read lane is keyed by client address, and
        // every request in this burst comes from the same loopback one, so
        // at the shipped default (50 rps, burst 100) most of the burst
        // would be answered `429` and this test would be measuring the
        // rate limiter instead of the audit queue. Lifted well past the
        // burst so the bound under test is the only one that binds.
        shared_env: vec![
            ("RATE_LIMIT_READ_RPS".to_owned(), "100000.0".to_owned()),
            ("RATE_LIMIT_READ_BURST".to_owned(), "100000".to_owned()),
        ],
        ..ClusterOptions::default()
    })
    .await
    else {
        return skipped();
    };
    cluster.wait_until_all_ready().await;

    // The baseline matters: a replica drops a handful of events during a
    // cold start on a loaded machine, and counting those against the
    // burst would make this test's arithmetic a lie.
    let dropped_before = cluster_metric_sum(&cluster, AUDIT_EVENTS_DROPPED_TOTAL).await;

    cluster.balancer.round_robin();
    cluster.upstream.clear();
    let statuses =
        burst_through_balancer(&cluster, AUDIT_BURST_PATH, AUDIT_BURST, BURST_CONCURRENCY).await;
    let served = statuses.iter().filter(|status| **status == 200).count();
    // A burst this size against a small pool on a machine shared with
    // other builds will occasionally find the deployment unable to consult
    // its authority, which it answers `503`. That is the gateway declining
    // to judge, not losing anything, and it is a legitimate answer under
    // overload — so it is admitted, and *only* it: any other status would
    // mean the burst hit a bound this test is not about, and the
    // accounting below would be measuring the wrong thing.
    let declined = statuses.iter().filter(|status| **status == 503).count();
    assert_eq!(
        served + declined,
        AUDIT_BURST,
        "every request must be proxied or declined outright; unexpected statuses: {}",
        unexpected(&statuses, 200)
    );
    // Declining is allowed; declining everything is not. A deployment that
    // shed most of a burst has not stayed in service under it.
    assert!(
        served * 10 >= AUDIT_BURST * 9,
        "the deployment served only {served} of {AUDIT_BURST}; overload should degrade it, \
         not take it out of service"
    );
    // Both replicas took a share of it, so what follows is a claim about
    // the deployment and not about whichever process the balancer
    // happened to favour.
    let mut seen = cluster.upstream.replicas_seen();
    seen.sort();
    assert_eq!(
        seen,
        vec!["a".to_owned(), "b".to_owned()],
        "the burst should have crossed both replicas; the balancer dispatched {} requests",
        cluster.balancer.dispatches().len()
    );

    // The writer thread is behind the requests by design, so the
    // accounting is polled rather than read once. It settles the moment
    // every served request is either on disk or counted as dropped.
    // The accounting is on the requests the deployment actually *served*:
    // a declined one is a decision the gateway is entitled to record or
    // not, and requiring a record for it would be asserting about the
    // decline path rather than the queue. Records are counted by the
    // status they carry so the two populations never mix.
    let (written, written_ok, dropped) = poll_for(CONVERGENCE_BUDGET, || {
        let cluster = &cluster;
        async move {
            let records = cluster.audit_records();
            let observed: Vec<&Value> = records
                .iter()
                .filter(|record| {
                    record["event_type"] == harness::HTTP_REQUEST_OBSERVED
                        && record["payload"]["path"] == AUDIT_BURST_PATH
                })
                .collect();
            let written = observed.len();
            let written_ok = observed
                .iter()
                .filter(|record| record["payload"]["status"] == 200)
                .count();
            let dropped =
                cluster_metric_sum(cluster, AUDIT_EVENTS_DROPPED_TOTAL).await - dropped_before;
            let accounted = written_ok as f64 + dropped;
            if accounted >= served as f64 {
                return Ok((written, written_ok, dropped));
            }
            Err(format!(
                "{written_ok} record(s) written for served requests and {dropped} counted \
                 as dropped, which accounts for {accounted} of the {served} requests served"
            ))
        }
    })
    .await;

    // The queue is bounded, so it may shed. It may not invent: more
    // records than requests would mean an event was emitted twice, which
    // is its own audit-integrity failure.
    assert!(
        written <= served + declined,
        "the deployment wrote {written} observation records for {} requests; \
         an audit trail must not duplicate",
        served + declined
    );
    assert!(
        dropped >= 0.0,
        "audit_events_dropped_total must not run backwards (it moved by {dropped})"
    );
    eprintln!(
        "audit accounting: {served} served ({declined} declined), {written} durable \
         ({written_ok} of them for served requests), {dropped} counted as dropped"
    );

    // Recovery. Nothing about the burst may outlive it.
    assert_recovered(&mut cluster, "/echo/saturation-audit-recovered").await;
    let after = cluster_metric_sum(&cluster, AUDIT_EVENTS_DROPPED_TOTAL).await;
    let recovery_drops = after - dropped_before - dropped;
    assert!(
        recovery_drops < 1.0,
        "the audit queue should stop shedding once the load stops, and instead dropped \
         {recovery_drops} more event(s) while the deployment was idle"
    );
}

// ---------------------------------------------------------------------
// The shared rate-limit bucket table and its cardinality bound.
// ---------------------------------------------------------------------

const RATE_LIMITED_PATH: &str = "/echo/saturation-limited";
/// The deployment's bucket ceiling for this test. Small on purpose: the
/// production default is 65,536, and a test that had to mint 65,537
/// principals to reach it would be a load test, not a bound test.
const MAX_BUCKETS: i64 = 32;
/// Distinct principals the burst invents — many times the ceiling, so an
/// unbounded table would be plainly unbounded.
const DISTINCT_PRINCIPALS: usize = 240;
/// How long a bucket must sit untouched before the maintenance
/// singleton's idle sweep reclaims it.
const BUCKET_IDLE_MS: u64 = 1_000;

/// A policy that grants [`ADMIN_ROLE`] everything and publishes one
/// per-principal rate-limit rule whose limits are deliberately loose.
///
/// The rule exists so that every request opens a *policy-lane bucket* for
/// its principal; it is not meant to deny anything, because this test is
/// about how many buckets the deployment keeps, not about who is
/// throttled. Every field `RateLimitRule` and `PrincipalMatcher`
/// serialize is written out, so the document round-trips to itself and
/// the harness can compute the ETag the gateway will compute.
fn bucket_policy() -> String {
    json!({
        "default_action": "allow",
        "enforcement_mode": "enforce",
        "roles": { ADMIN_ROLE: { "permissions": ["*"] } },
        "routes": [],
        "rules": [],
        "rate_limits": [{
            "principal": {
                "roles": [ADMIN_ROLE],
                "issuers": [],
                "auth_methods": [],
                "principal_ids": [],
            },
            "methods": ["GET"],
            "path": RATE_LIMITED_PATH,
            "requests_per_second": 100.0,
            "burst": 100,
        }],
        "schema_version": "0.1.0",
    })
    .to_string()
}

/// The deployment's live bucket count and the table's actual row count,
/// read in one statement.
///
/// One statement because the claim under test is that the counter cannot
/// *drift* from the table: reading them separately would let a concurrent
/// eviction or idle sweep land between the two and produce a difference
/// that is the test's fault rather than the store's.
async fn bucket_counts(cluster: &Cluster) -> (i64, i64) {
    let deployment = &cluster.deployment_id;
    let row = cluster
        .database
        .query_one(&format!(
            "SELECT \
               (SELECT coalesce(sum(live), 0)::bigint \
                  FROM greengateway.rate_limit_cardinality \
                 WHERE deployment_id = '{deployment}') AS live, \
               (SELECT count(*)::bigint \
                  FROM greengateway.rate_limit_buckets \
                 WHERE deployment_id = '{deployment}') AS rows"
        ))
        .await;
    (row.get::<_, i64>(0), row.get::<_, i64>(1))
}

/// A burst of many distinct callers keeps the shared bucket table at its
/// configured ceiling, and the deployment goes on serving.
///
/// This is the cardinality attack written as a test. The bucket key is a
/// keyed digest of the caller's identity, so a caller who can vary their
/// identity — a token per request, an address per request — can mint
/// rows. Without a ceiling that is an unbounded write amplification on
/// the deployment's authority, reachable by anyone who can authenticate.
/// With one, the store trades the oldest bucket away, which costs the
/// evicted caller their remaining allowance and costs the deployment
/// nothing.
///
/// The two claims are that the table stops growing at the ceiling, and
/// that the counter the ceiling is enforced from cannot drift from the
/// table it counts — a counter that over-reported would evict callers who
/// were fine, and one that under-reported would stop enforcing the
/// ceiling at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_burst_of_distinct_callers_holds_the_bucket_table_at_its_ceiling() {
    let Some(mut cluster) = Cluster::start(ClusterOptions {
        auth: AuthShape::Oidc,
        seed_policy: Some(bucket_policy()),
        shared_env: vec![
            ("RATE_LIMIT_MAX_BUCKETS".to_owned(), MAX_BUCKETS.to_string()),
            (
                "RATE_LIMIT_BUCKET_TTL_MS".to_owned(),
                BUCKET_IDLE_MS.to_string(),
            ),
            // The idle sweep is the maintenance singleton's job, so the
            // singleton has to run often enough for the recovery half of
            // this test to observe it inside its budget.
            (
                "CLUSTER_MAINTENANCE_INTERVAL_MS".to_owned(),
                "1000".to_owned(),
            ),
            (
                "CLUSTER_MAINTENANCE_LEASE_TTL_MS".to_owned(),
                "2000".to_owned(),
            ),
            // Every invented principal arrives from the same loopback
            // address, so the address-keyed read lane would refuse most of
            // the burst at its shipped default and this test would be
            // counting rate-limiter decisions instead of bucket rows. The
            // per-principal policy lane is the bound under test.
            ("RATE_LIMIT_READ_RPS".to_owned(), "100000.0".to_owned()),
            ("RATE_LIMIT_READ_BURST".to_owned(), "100000".to_owned()),
        ],
        ..ClusterOptions::default()
    })
    .await
    else {
        return skipped();
    };
    cluster.wait_until_all_ready().await;

    // One request per invented principal, alternating replicas. Every
    // request is expected to be *allowed*: the rule's burst is generous,
    // so a `429` here would mean two callers were sharing a bucket, which
    // is a worse failure than an unbounded table.
    let mut statuses = Vec::with_capacity(DISTINCT_PRINCIPALS);
    let mut issued = 0;
    while issued < DISTINCT_PRINCIPALS {
        let wave = 8.min(DISTINCT_PRINCIPALS - issued);
        let deployment = &cluster;
        let requests = (0..wave).map(|offset| {
            let index = issued + offset;
            let replica = if index % 2 == 0 { "a" } else { "b" };
            let token = deployment.oidc.mint_role_token(
                harness::oidc::PRIMARY_KID,
                &format!("saturation-{index}@ha.test"),
                &format!("jti-{}", uuid::Uuid::new_v4().simple()),
                &[ADMIN_ROLE],
                3_600,
            );
            async move {
                // A `503` is the replica saying it could not consult the
                // limiter's authority — "cannot judge", which is not an
                // answer to "was this caller allowed?". Re-asking is the
                // honest reading, and because the retry carries the same
                // principal it opens the same bucket, so the arithmetic
                // this test does is untouched by it. The bound keeps a
                // genuinely unreachable authority a failure. On an
                // unloaded machine this never fires.
                let deadline = Instant::now() + AUTHORITY_RETRY_BUDGET;
                loop {
                    let (status, _) = deployment
                        .get(replica, RATE_LIMITED_PATH)
                        .bearer(&token)
                        .send()
                        .await;
                    if status != 503 || Instant::now() >= deadline {
                        return status;
                    }
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
            }
        });
        statuses.extend(futures_util::future::join_all(requests).await);
        issued += wave;
    }
    let allowed = statuses.iter().filter(|status| **status == 200).count();
    assert_eq!(
        allowed,
        DISTINCT_PRINCIPALS,
        "every distinct principal should have been allowed under a burst of 100; \
         unexpected statuses: {}",
        unexpected(&statuses, 200)
    );

    // The ceiling. Eviction happens inside the decision, before the
    // response the test is holding returns, so by here every eviction the
    // burst provoked has already committed and this is not a race.
    let (live, rows) = bucket_counts(&cluster).await;
    assert!(
        rows <= MAX_BUCKETS,
        "{DISTINCT_PRINCIPALS} distinct callers left {rows} bucket rows behind a ceiling of \
         {MAX_BUCKETS}; the shared limiter's table grows with the key space"
    );
    assert_eq!(
        live, rows,
        "the cardinality counter ({live}) and the bucket table ({rows}) must not drift: \
         the ceiling is enforced from the counter"
    );

    // Recovery, in the shape the deployment actually recovers: the
    // maintenance singleton's idle sweep reclaims buckets nobody has
    // touched for their TTL. The wait for the TTL is on database time,
    // which is what the sweep's own predicate is evaluated against.
    cluster
        .database
        .wait_for_elapsed(
            (BUCKET_IDLE_MS as f64 / 1000.0) * 1.5,
            Duration::from_secs(30),
        )
        .await;
    poll_for(CONVERGENCE_BUDGET, || {
        let cluster = &cluster;
        async move {
            let (live, rows) = bucket_counts(cluster).await;
            if rows == 0 && live == 0 {
                return Ok(());
            }
            Err(format!(
                "{rows} idle bucket row(s) remain (counter says {live}); the maintenance \
                 singleton's idle sweep has not reclaimed them"
            ))
        }
    })
    .await;

    // And the sweep is recorded, not merely inferred from an empty table:
    // a table emptied by something else would look identical here.
    let swept: i64 = cluster
        .database
        .count(&format!(
            "SELECT count(*)::bigint FROM greengateway.maintenance_jobs \
             WHERE deployment_id = '{}' AND job = 'rate_limit_idle_sweep' \
               AND last_success_at IS NOT NULL",
            cluster.deployment_id
        ))
        .await;
    assert_eq!(
        swept, 1,
        "the deployment's maintenance ledger should record exactly one successful \
         rate_limit_idle_sweep owner"
    );

    // Recovery is proved with a credential, not without one: this
    // cluster authenticates its data plane, so an anonymous probe would
    // be answered `401` by a perfectly healthy deployment.
    let admin = cluster.oidc.mint_role_token(
        harness::oidc::PRIMARY_KID,
        "saturation-recovery@ha.test",
        &format!("jti-{}", uuid::Uuid::new_v4().simple()),
        &[ADMIN_ROLE],
        3_600,
    );
    assert_recovered_authenticated(&mut cluster, &admin).await;
}

// ---------------------------------------------------------------------
// The durable stream and the discovery projector's batch.
// ---------------------------------------------------------------------

/// Events in the first backlog.
const BACKLOG_EVENTS: usize = 600;
/// Events appended after the first backlog has drained, to prove the
/// projector is in a steady state rather than merely finished.
const FOLLOW_UP_EVENTS: usize = 240;
/// Distinct endpoints the backlog observes — many times the endpoint
/// ceiling below.
const BACKLOG_ENDPOINTS: usize = 120;
/// Stream rows the projector may read in one batch.
const PROJECTOR_BATCH: usize = 50;
/// Endpoints the deployment's discovery aggregates may hold.
const ENDPOINT_LIMIT: i64 = 24;

/// The projector's committed checkpoint and the number of observations it
/// has applied, read in one statement from the singleton it commits both
/// in.
async fn projector_state(cluster: &Cluster) -> (i64, i64) {
    let row = cluster
        .database
        .query_one(
            "SELECT checkpoint_position, projected_events \
             FROM greengateway.discovery_projector_state WHERE singleton",
        )
        .await;
    (row.get::<_, i64>(0), row.get::<_, i64>(1))
}

/// Append `count` observations to the durable stream, spread over
/// `endpoints` distinct endpoint templates.
async fn append_observations(cluster: &Cluster, count: usize, endpoints: usize) {
    // Committed in chunks the way a real ingester would, so the stream
    // gets many commit points rather than one enormous transaction.
    let mut appended = 0;
    while appended < count {
        let chunk = 100.min(count - appended);
        let events: Vec<harness::AuditEventSeed> = (0..chunk)
            .map(|offset| {
                let index = appended + offset;
                harness::AuditEventSeed::observation(
                    "GET",
                    &format!("/saturation/{}", index % endpoints.max(1)),
                    harness::database::SEEDED_SUGGESTION_TIMESTAMP,
                    Some(harness::SeedActor::bearer(&format!(
                        "saturation-{}@ha.test",
                        index % 8
                    ))),
                )
            })
            .collect();
        cluster.database.ingest_audit_events(&events).await;
        appended += chunk;
    }
}

/// A backlogged stream drains under a bounded batch, exactly once, into a
/// bounded set of aggregates — and keeps up once it has caught up.
///
/// Three bounds meet here and each has its own way of failing quietly.
/// The *batch* bounds how much of a backlog one pass holds in memory and
/// commits at once; without it a replica that has been down for an hour
/// comes back and reads the hour. The *checkpoint* bounds how much is
/// re-read after a commit; a projector that advanced its checkpoint
/// before applying loses events, and one that advanced after applying
/// without a fence applies them twice — `projected_events` is the ledger
/// that tells those two apart, and it is asserted exactly, because "about
/// six hundred" is what a double-application looks like from a distance.
/// The *endpoint ceiling* bounds the aggregate table against a caller who
/// can invent paths.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_backlogged_stream_drains_in_bounded_batches_exactly_once() {
    let Some(mut cluster) = Cluster::start(ClusterOptions {
        shared_env: vec![
            (
                "DISCOVERY_PROJECTOR_BATCH".to_owned(),
                PROJECTOR_BATCH.to_string(),
            ),
            ("DISCOVERY_PROJECTOR_POLL_MS".to_owned(), "50".to_owned()),
            (
                "DISCOVERY_ENDPOINT_LIMIT".to_owned(),
                ENDPOINT_LIMIT.to_string(),
            ),
        ],
        ..ClusterOptions::default()
    })
    .await
    else {
        return skipped();
    };
    cluster.wait_until_all_ready().await;

    // A backlog many batches deep, appended while both replicas are up:
    // whichever of them holds the projector lease has to drain it, and
    // the other must not also drain it.
    append_observations(&cluster, BACKLOG_EVENTS, BACKLOG_ENDPOINTS).await;
    let head = cluster.database.stream_head().await;
    assert_eq!(
        head, BACKLOG_EVENTS as i64,
        "the harness should have appended {BACKLOG_EVENTS} positions to the stream"
    );

    poll_for(CONVERGENCE_BUDGET, || {
        let cluster = &cluster;
        async move {
            let (checkpoint, projected) = projector_state(cluster).await;
            if checkpoint >= head {
                return Ok(());
            }
            Err(format!(
                "the projector is at position {checkpoint} of {head} ({projected} applied)"
            ))
        }
    })
    .await;

    let (checkpoint, projected) = projector_state(&cluster).await;
    assert_eq!(
        checkpoint, head,
        "the committed checkpoint must land exactly on the stream head, never past it"
    );
    assert_eq!(
        projected, BACKLOG_EVENTS as i64,
        "the projector applied {projected} observations for a backlog of {BACKLOG_EVENTS}: \
         fewer means events were skipped over a batch boundary, more means a batch was \
         applied twice"
    );

    // The endpoint ceiling. The backlog invented five times as many
    // endpoints as the deployment may keep, and the aggregate table must
    // be the ceiling rather than the invention.
    let aggregates: i64 = cluster
        .database
        .count("SELECT count(*)::bigint FROM greengateway.discovery_endpoint_aggregates")
        .await;
    assert!(
        aggregates <= ENDPOINT_LIMIT,
        "{BACKLOG_ENDPOINTS} distinct endpoints left {aggregates} aggregate rows behind a \
         ceiling of {ENDPOINT_LIMIT}"
    );

    // Steady state: more events after the drain are applied once each, so
    // the ledger moves by exactly what was appended. A projector that
    // re-read its backlog on every pass would move by much more.
    append_observations(&cluster, FOLLOW_UP_EVENTS, BACKLOG_ENDPOINTS).await;
    let second_head = cluster.database.stream_head().await;
    poll_for(CONVERGENCE_BUDGET, || {
        let cluster = &cluster;
        async move {
            let (checkpoint, projected) = projector_state(cluster).await;
            if checkpoint >= second_head {
                return Ok(());
            }
            Err(format!(
                "the projector is at position {checkpoint} of {second_head} \
                 ({projected} applied)"
            ))
        }
    })
    .await;
    let (checkpoint, projected) = projector_state(&cluster).await;
    assert_eq!(checkpoint, second_head);
    assert_eq!(
        projected,
        (BACKLOG_EVENTS + FOLLOW_UP_EVENTS) as i64,
        "a caught-up projector must apply each new observation once and re-apply none"
    );

    // Exactly one replica ever led: the singleton the checkpoint lives in
    // names its leader, and a scope that handed out two slots would show
    // up as more than one live projector lease.
    let projector_leases: i64 = cluster
        .database
        .count(&format!(
            "SELECT count(*)::bigint FROM greengateway.execution_leases \
             WHERE deployment_id = '{}' AND scope NOT IN ('global', 'maintenance')",
            cluster.deployment_id
        ))
        .await;
    assert!(
        projector_leases <= 1,
        "the discovery projector is a singleton and held {projector_leases} leases at once"
    );

    assert_recovered(&mut cluster, "/echo/saturation-projector-recovered").await;
}

// ---------------------------------------------------------------------
// Execution-lease slots and the admission queue.
// ---------------------------------------------------------------------

const TOOLS_ROUTE: &str = "/v1/admin/tools";
const ALPHA_TOOL: &str = "ha_sat_alpha";
const BETA_TOOL: &str = "ha_sat_beta";
/// Slots the whole deployment owns.
const GLOBAL_SLOTS: usize = 2;
/// Waiters one replica will hold before it refuses admission outright.
const QUEUE_DEPTH: usize = 2;
/// How long a waiter may sit before it is refused rather than queued.
const QUEUE_TIMEOUT_MS: u64 = 1_000;
/// How long the upstream holds an admitted invocation open, so the burst
/// measures admission rather than throughput. Comfortably longer than the
/// admission timeout.
const HELD_UPSTREAM: Duration = Duration::from_secs(6);
/// Invocations in the burst — far more than the deployment can admit and
/// queue put together.
const EXECUTION_BURST: usize = 16;

/// A tools document with two legacy HTTP tools pointed at the harness's
/// upstream, written with exactly the fields `ToolDefinition` serializes
/// so the document round-trips and its ETag is computable here.
fn saturation_tools() -> String {
    let tool = |name: &str, path: &str| {
        json!({
            "name": name,
            "description": "a release-gate saturation fixture tool",
            "input_json_schema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false,
            },
            "upstream": { "method": "GET", "path_template": path },
        })
    };
    json!({
        "schema_version": "0.1.0",
        "tools": [tool(ALPHA_TOOL, "/alpha"), tool(BETA_TOOL, "/beta")],
    })
    .to_string()
}

/// A policy that admits both fixture tools generously per tool, so the
/// binding constraint in this test is the deployment's global slot count
/// and its queue, not a per-tool ceiling.
fn saturation_tool_policy() -> String {
    let entry = json!({
        "enabled": true,
        "allowed_roles": [],
        "timeout_ms": 30_000,
        "max_concurrent": 8,
    });
    json!({
        "default_action": "allow",
        "enforcement_mode": "enforce",
        "roles": { ADMIN_ROLE: { "permissions": ["*"] } },
        "routes": [],
        "rules": [],
        "tools": { ALPHA_TOOL: entry, BETA_TOOL: entry },
        "schema_version": "0.1.0",
    })
    .to_string()
}

/// The opaque id and execution ETag an invocation of `tool` must carry.
///
/// The ETag is a precondition rather than an identifier: it binds the
/// invocation to the definition and permissions the caller read. Both are
/// read once, before the burst, so the burst measures admission and not
/// two extra round trips per attempt.
async fn execution_precondition(
    cluster: &Cluster,
    replica: &str,
    admin: &str,
    tool: &str,
) -> (String, String) {
    let (status, _, body) = cluster
        .get(replica, TOOLS_ROUTE)
        .bearer(admin)
        .send_with_headers()
        .await;
    assert_eq!(status, 200, "the capability inventory should list: {body}");
    let id = body["capabilities"]
        .as_array()
        .unwrap_or_else(|| panic!("the inventory should carry capabilities: {body}"))
        .iter()
        .find(|capability| capability["name"].as_str() == Some(tool))
        .and_then(|capability| capability["id"].as_str())
        .unwrap_or_else(|| panic!("replica {replica} does not publish {tool}: {body}"))
        .to_owned();
    let (status, headers, body) = cluster
        .get(replica, &format!("{TOOLS_ROUTE}/{id}"))
        .bearer(admin)
        .send_with_headers()
        .await;
    assert_eq!(status, 200, "the capability detail should read: {body}");
    let etag = headers
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("the capability detail carried no ETag: {body}"))
        .to_owned();
    (id, etag)
}

/// The most slots any one lease scope is holding, and the largest slot
/// index handed out in the global scope.
///
/// The slot index is the sharper of the two: slots are numbered from zero
/// up to the scope's capacity, so a slot at or above the capacity means
/// the authority handed out a slot the scope does not own — which no
/// count of rows would reveal if the extra row replaced an expired one.
async fn global_slot_high_water(cluster: &Cluster) -> (i64, i64) {
    let row = cluster
        .database
        .query_one(&format!(
            "SELECT count(*)::bigint AS held, coalesce(max(slot), -1)::bigint AS top \
             FROM greengateway.execution_leases \
             WHERE deployment_id = '{}' AND scope = 'global'",
            cluster.deployment_id
        ))
        .await;
    (row.get::<_, i64>(0), row.get::<_, i64>(1))
}

/// An execution burst never holds more lease slots than the deployment
/// owns, refuses the overflow loudly, and gives the slots back.
///
/// A process-local semaphore makes this test pass on one replica and fail
/// on two: "two concurrent invocations" becomes two *per replica*, and it
/// scales with the fleet. The fix is a leased slot in a shared scope, and
/// the bound worth asserting is not only how many invocations reached the
/// upstream but how many slots the authority ever handed out — a scope of
/// capacity two that issues slot 2 has already lost, whatever the
/// upstream saw.
///
/// The overflow matters as much as the bound. An invocation that cannot
/// take a slot must be refused with `429` and a reason the caller can act
/// on (`queue_full`, `queue_timeout`), never dropped, never a `5xx`, and
/// never quietly executed anyway.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_execution_burst_never_exceeds_the_deployments_lease_slots() {
    let Some(mut cluster) = Cluster::start(ClusterOptions {
        auth: AuthShape::Oidc,
        proxy: ProxyShape::LegacyUpstream,
        seed_policy: Some(saturation_tool_policy()),
        seed_tools: Some(saturation_tools()),
        shared_env: vec![
            (
                "TOOL_RUNTIME_GLOBAL_CONCURRENCY".to_owned(),
                GLOBAL_SLOTS.to_string(),
            ),
            (
                "TOOL_RUNTIME_QUEUE_DEPTH".to_owned(),
                QUEUE_DEPTH.to_string(),
            ),
            (
                "TOOL_RUNTIME_QUEUE_TIMEOUT_MS".to_owned(),
                QUEUE_TIMEOUT_MS.to_string(),
            ),
            ("TOOL_LEASE_TTL_MS".to_owned(), "5000".to_owned()),
        ],
        ..ClusterOptions::default()
    })
    .await
    else {
        return skipped();
    };
    cluster.wait_until_all_ready().await;

    let admin = cluster.oidc.mint_role_token(
        harness::oidc::PRIMARY_KID,
        "saturation-admin@ha.test",
        &format!("jti-{}", uuid::Uuid::new_v4().simple()),
        &[ADMIN_ROLE],
        3_600,
    );

    // Preconditions read once per (replica, tool), before the load: a
    // burst that spent its time reading capability documents would be
    // measuring the admin API.
    let mut preconditions = Vec::new();
    for replica in ["a", "b"] {
        for tool in [ALPHA_TOOL, BETA_TOOL] {
            let (id, etag) = execution_precondition(&cluster, replica, &admin, tool).await;
            preconditions.push((replica, id, etag));
        }
    }

    // A warm invocation on each replica, so the burst measures admission
    // rather than a cold path.
    for (replica, id, etag) in &preconditions {
        if *replica != "a" {
            continue;
        }
        let (status, body) = cluster
            .post("a", &format!("{TOOLS_ROUTE}/{id}/execute"))
            .bearer(&admin)
            .if_match(etag)
            .json(&json!({ "arguments": {} }))
            .send()
            .await;
        assert_eq!(
            status, 200,
            "a fixture tool should execute before the burst: {body}"
        );
    }

    cluster
        .upstream
        .set_behaviour(harness::Behaviour::Slow(HELD_UPSTREAM));
    cluster.upstream.clear();

    // The burst, and — while it is in flight — a watcher that reads the
    // lease scope's high-water mark. The watcher is what makes this an
    // assertion about the authority rather than about the upstream: it
    // catches a scope that over-issued even for an instant, including
    // slots whose invocation never reached the upstream at all.
    // The burst tells the watcher when to stop, so the sampling window is
    // the burst's own lifetime rather than a guess about how long it will
    // take. The deadline behind it is only a stop for a burst that never
    // returns at all.
    let burst_finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watcher = {
        let deployment = cluster.deployment_id.clone();
        let database = &cluster.database;
        let finished = std::sync::Arc::clone(&burst_finished);
        async move {
            let mut worst = (0_i64, -1_i64);
            let deadline = Instant::now() + HELD_UPSTREAM + Duration::from_secs(30);
            loop {
                let row = database
                    .query_one(&format!(
                        "SELECT count(*)::bigint, coalesce(max(slot), -1)::bigint \
                         FROM greengateway.execution_leases \
                         WHERE deployment_id = '{deployment}' AND scope = 'global'"
                    ))
                    .await;
                let sample = (row.get::<_, i64>(0), row.get::<_, i64>(1));
                worst = (worst.0.max(sample.0), worst.1.max(sample.1));
                // Sampled once more after the burst reported itself done,
                // which the ordering above guarantees: the read happens
                // before the flag is re-tested.
                if finished.load(std::sync::atomic::Ordering::SeqCst) || Instant::now() >= deadline
                {
                    return worst;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    };

    let burst_finished_flag = std::sync::Arc::clone(&burst_finished);
    let burst = async {
        let attempts = (0..EXECUTION_BURST).map(|index| {
            let (replica, id, etag) = &preconditions[index % preconditions.len()];
            let admin = &admin;
            let cluster = &cluster;
            async move {
                cluster
                    .post(replica, &format!("{TOOLS_ROUTE}/{id}/execute"))
                    .bearer(admin)
                    .if_match(etag)
                    .json(&json!({ "arguments": {} }))
                    .send()
                    .await
            }
        });
        let outcomes = futures_util::future::join_all(attempts).await;
        burst_finished_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        outcomes
    };

    let (outcomes, (peak_held, peak_slot)) = tokio::join!(burst, watcher);
    cluster.upstream.set_behaviour(harness::Behaviour::Ok);

    let statuses = || {
        outcomes
            .iter()
            .map(|(status, _)| *status)
            .collect::<Vec<_>>()
    };
    let admitted = outcomes.iter().filter(|(status, _)| *status == 200).count();
    let refused = outcomes.iter().filter(|(status, _)| *status == 429).count();
    // A third outcome, and the only other one admissible: `503`, the
    // replica declining to judge because it could not reach the shared
    // authority under the burst's own database load. It is not an
    // admission decision — such an invocation took no slot and reached no
    // upstream — so it is counted separately rather than folded into
    // either side, and its *body* is checked below so a `503` that means
    // something else still fails. Sixteen invocations at once against a
    // PostgreSQL server this suite shares with the rest of the build make
    // this reachable; treating it as a failure would make the ceiling
    // assertions below hostage to the machine's load.
    let unavailable = outcomes.iter().filter(|(status, _)| *status == 503).count();
    assert_eq!(
        admitted + refused + unavailable,
        EXECUTION_BURST,
        "every invocation must be admitted, refused admission, or fail closed, and instead \
         the burst answered {:?}",
        statuses()
    );
    assert!(
        unavailable * 2 <= EXECUTION_BURST,
        "most of the burst ({unavailable} of {EXECUTION_BURST}) failed closed rather than \
         being admitted or refused, so this measured the authority's availability rather \
         than the deployment's slots (statuses {:?})",
        statuses()
    );
    for (status, body) in &outcomes {
        if *status != 503 {
            continue;
        }
        let error = body["error"].as_str().unwrap_or_default();
        assert!(
            error.contains("unavailable"),
            "a fail-closed invocation should name the authority it could not reach, and \
             said {body}"
        );
    }
    // Both bounds. A ceiling that had collapsed to one slot — a global
    // scope that serialized the whole deployment — satisfies every "no
    // more than" assertion in this test while cutting its throughput by
    // the concurrency factor, so the floor is asserted too: the burst is
    // long enough and deep enough that anything less than full occupancy
    // is a defect.
    assert_eq!(
        admitted,
        GLOBAL_SLOTS,
        "the deployment owns {GLOBAL_SLOTS} slots and admitted {admitted} invocations \
         (statuses {:?})",
        statuses()
    );
    // Every refusal names a bound the caller can act on. A `429` with any
    // other reason would mean the burst hit a limit this test is not
    // about, and the numbers above would be measuring the wrong ceiling.
    for (status, body) in &outcomes {
        if *status != 429 {
            continue;
        }
        let reason = body["reason"].as_str().unwrap_or_default();
        assert!(
            matches!(reason, "queue_full" | "queue_timeout"),
            "a refused invocation should name the admission bound it hit, and said {body}"
        );
    }
    assert!(
        cluster.upstream.peak_in_flight() <= GLOBAL_SLOTS,
        "no more than {GLOBAL_SLOTS} invocations may reach the upstream at once; the peak \
         was {}",
        cluster.upstream.peak_in_flight()
    );

    // The authority's own high-water mark, sampled throughout — again from
    // both sides. The scope must never have held more than it owns, and
    // must have been seen holding all of it: a sampler that observed one
    // lease at a time would mean the slots were never concurrent, which is
    // the same regression the admission floor above refuses.
    assert_eq!(
        peak_held, GLOBAL_SLOTS as i64,
        "the global scope's high-water mark was {peak_held} leases against a capacity of \
         {GLOBAL_SLOTS}"
    );
    assert_eq!(
        peak_slot,
        GLOBAL_SLOTS as i64 - 1,
        "a scope of capacity {GLOBAL_SLOTS} owns slots 0..{}, and the highest issued was \
         {peak_slot}",
        GLOBAL_SLOTS - 1
    );

    // Recovery: the slots come back, and the deployment executes again.
    // A released lease deletes its row, so an empty scope is the
    // observable — not a timer.
    poll_for(CONVERGENCE_BUDGET, || {
        let cluster = &cluster;
        async move {
            let (held, top) = global_slot_high_water(cluster).await;
            if held == 0 {
                return Ok(());
            }
            Err(format!(
                "{held} global lease(s) still held (highest slot {top}) after the burst"
            ))
        }
    })
    .await;
    let (replica, id, etag) = &preconditions[0];
    let (status, body) = cluster
        .post(replica, &format!("{TOOLS_ROUTE}/{id}/execute"))
        .bearer(&admin)
        .if_match(etag)
        .json(&json!({ "arguments": {} }))
        .send()
        .await;
    assert_eq!(
        status, 200,
        "the deployment should execute tools again once the burst has drained: {body}"
    );

    assert_recovered_authenticated(&mut cluster, &admin).await;
}

// ---------------------------------------------------------------------
// The retry bound
// ---------------------------------------------------------------------

/// How many retries the replica under test is given after its first
/// attempt. Small so the bound is countable, and so the test's own budget
/// does not have to cover the production default's five.
const STARTUP_RETRY_LIMIT: u64 = 2;
/// The log message each failed connectivity attempt writes
/// (`storage/postgres.rs::establish_with_bounded_backoff`). Restated here
/// rather than imported for the same reason the metric name above is: this
/// suite reads the process's output the way an operator does.
const CONNECTIVITY_FAILURE_MESSAGE: &str = "PostgreSQL connectivity check failed";

/// A replica whose database never answers gives up inside its configured
/// retry bound instead of retrying forever.
///
/// This is a ceiling like any other in this file, and the one whose absence
/// is quietest: a boot that retried without limit would look, to every
/// other test here, exactly like a boot that was merely slow — a process
/// still alive, a listener that never opens, and an orchestrator restarting
/// something that will never come up rather than reporting a deployment
/// that cannot reach its database. What is asserted is the *count*: one
/// first attempt plus `DATABASE_STARTUP_RETRY_LIMIT` retries, no more,
/// and an exit that says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_boot_against_an_unreachable_database_stops_at_the_configured_retry_bound() {
    let Some(mut cluster) = Cluster::start(ClusterOptions {
        // One replica: this is about a single process's boot, and the
        // database is taken away from every replica at once.
        replicas: 1,
        shared_env: vec![
            (
                "DATABASE_STARTUP_RETRY_LIMIT".to_owned(),
                STARTUP_RETRY_LIMIT.to_string(),
            ),
            // Each attempt must fail rather than hang on the pool's own
            // wait, or the bound under test would be masked by a timeout.
            ("DATABASE_ACQUIRE_TIMEOUT_MS".to_owned(), "2000".to_owned()),
        ],
        ..ClusterOptions::default()
    })
    .await
    else {
        return skipped();
    };
    cluster.wait_until_all_ready().await;

    // Take the database away: the grant first, so nothing can reconnect,
    // then the established sessions.
    cluster.database.revoke_connect().await;
    cluster.database.terminate_runtime_backends().await;

    // Boot into the fault. `relaunch` deliberately does not wait for a
    // listener: there will not be one.
    let replica = cluster.replica_mut("a");
    replica.relaunch();
    let exited = replica.wait_until_exited(CONVERGENCE_BUDGET).await;
    let output = replica.output_since_launch();
    assert!(
        exited,
        "a replica that cannot reach its database must exhaust its bounded retry and exit; \
         it was still running after {CONVERGENCE_BUDGET:?}\n--- output ---\n{output}"
    );

    // The bound, counted. `attempts` is the first try plus the retries, and
    // every one of them logs; a limit that had become unbounded (or had
    // simply been ignored) would show a different number here.
    let attempts = usize::try_from(STARTUP_RETRY_LIMIT + 1).expect("a small retry limit");
    let logged = output.matches(CONNECTIVITY_FAILURE_MESSAGE).count();
    assert_eq!(
        logged, attempts,
        "a startup retry limit of {STARTUP_RETRY_LIMIT} allows {attempts} connectivity \
         attempts, and {logged} were logged\n--- output ---\n{output}"
    );
    assert!(
        output.contains(&format!("in {attempts} attempts")),
        "the exhausted startup should name the bound it hit\n--- output ---\n{output}"
    );

    // Recovery, so the bound is a bound and not a broken deployment: the
    // grant back, the same process's environment, and a replica that comes
    // up and serves.
    cluster.database.restore_connect().await;
    cluster.restart("a").await;
    cluster.wait_until_all_ready().await;
    let (status, _) = cluster.get("a", "/echo/after-the-retry-bound").send().await;
    assert_eq!(
        status, 200,
        "the replica should serve again once its database is reachable"
    );
}

/// [`assert_recovered`] for a cluster whose data plane is the legacy
/// catch-all upstream, where a proxied probe would be indistinguishable
/// from a tool call: readiness and the roster are asserted the same way,
/// and normal service is proved with an authenticated admin read.
async fn assert_recovered_authenticated(cluster: &mut Cluster, admin: &str) {
    cluster.wait_until_all_ready().await;
    let live = cluster.live_member_count().await;
    assert_eq!(
        live, 2,
        "both replicas should still hold a live membership row after the load stopped"
    );
    for name in ["a", "b"] {
        let (status, body): (u16, Value) = cluster
            .get(name, &format!("{}/status", harness::ADMIN_API_PREFIX))
            .bearer(admin)
            .send()
            .await;
        assert_eq!(
            status, 200,
            "replica {name} should serve an admin read once the load has stopped: {body}"
        );
    }
}

// ---------------------------------------------------------------------
// The replay window: audit retention against the stream's cursors.
// ---------------------------------------------------------------------

/// The event type the retention test appends, so its rows can be counted
/// apart from anything else on the stream.
const RETENTION_EVENT_TYPE: &str = "ha.saturation.retention";
/// Events appended old enough to fall out of a one-day window.
const RETAINED_OLD_EVENTS: usize = 60;
/// Events appended afterwards, inside the window.
const RETAINED_NEW_EVENTS: usize = 5;
const EVENTS_STREAM_PATH: &str = "/v1/admin/events/stream";

/// A plain policy that grants [`ADMIN_ROLE`] everything, for the tests
/// whose subject is not the rate limiter.
fn plain_admin_policy() -> String {
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

/// An RFC 3339 instant from an epoch second.
fn format_epoch(seconds: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(seconds)
        .expect("an epoch second should be a valid instant")
        .format(&time::format_description::well_known::Rfc3339)
        .expect("an OffsetDateTime should format as RFC 3339")
}

/// Retention bounds the replayable window without renumbering it, and a
/// cursor that fell out of the window is refused rather than silently
/// resynchronized.
///
/// This is the "replay window" bound, and it has two quiet failures. The
/// first is a stream that numbers positions from `max(position)` of the
/// rows that happen to survive: empty the table and numbering restarts at
/// one, so every durable cursor in the fleet is silently pointing at
/// events that no longer mean what they meant — the exact regression the
/// never-deleted position counter exists to prevent. The second is a
/// reconnect from below the window answered with a stream that starts
/// wherever it can: the client believes it resumed and carries a hole it
/// will never learn about.
///
/// Retention is also the one sweep that can destroy data a consumer still
/// needs, so it runs behind a floor — the projector's committed
/// checkpoint. The projector is allowed to catch up first here, which is
/// what makes the old events deletable at all; that ordering is the
/// contract, not a convenience.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn retention_bounds_the_replay_window_without_renumbering_or_hiding_a_gap() {
    let Some(mut cluster) = Cluster::start(ClusterOptions {
        auth: AuthShape::Oidc,
        seed_policy: Some(plain_admin_policy()),
        shared_env: vec![
            ("AUDIT_POSTGRES_RETENTION_DAYS".to_owned(), "1".to_owned()),
            (
                "CLUSTER_MAINTENANCE_INTERVAL_MS".to_owned(),
                "1000".to_owned(),
            ),
            (
                "CLUSTER_MAINTENANCE_LEASE_TTL_MS".to_owned(),
                "2000".to_owned(),
            ),
            ("DISCOVERY_PROJECTOR_POLL_MS".to_owned(), "50".to_owned()),
        ],
        ..ClusterOptions::default()
    })
    .await
    else {
        return skipped();
    };
    cluster.wait_until_all_ready().await;

    let admin = cluster.oidc.mint_role_token(
        harness::oidc::PRIMARY_KID,
        "saturation-reader@ha.test",
        &format!("jti-{}", uuid::Uuid::new_v4().simple()),
        &[ADMIN_ROLE],
        3_600,
    );
    let members = cluster.member_identities().await;

    // Events old enough for a one-day window. What makes them old is the
    // value stored, and the comparison is the database's; nothing here
    // reads the test process's clock or moves anyone's.
    let old: Vec<harness::AuditEventSeed> = (0..RETAINED_OLD_EVENTS as i64)
        .map(|index| {
            let member = members[index as usize % members.len()];
            // 2026-01-01T00:00:00Z and the seconds after it.
            harness::AuditEventSeed::marker(
                RETENTION_EVENT_TYPE,
                &format!("/retained/{index}"),
                &format_epoch(1_767_225_600 + index),
            )
            .attributed_to(member.instance_id, member.boot_id)
        })
        .collect();
    cluster.database.ingest_audit_events(&old).await;
    let old_head = cluster.database.stream_head().await;

    poll_for(CONVERGENCE_BUDGET, || {
        let cluster = &cluster;
        async move {
            let checkpoint: i64 = cluster
                .database
                .count(
                    "SELECT checkpoint_position::bigint \
                     FROM greengateway.discovery_projector_state WHERE singleton",
                )
                .await;
            if checkpoint >= old_head {
                return Ok(());
            }
            Err(format!(
                "the projector is at {checkpoint} of {old_head}, so retention's floor \
                 still protects the old events"
            ))
        }
    })
    .await;

    poll_for(CONVERGENCE_BUDGET, || {
        let cluster = &cluster;
        async move {
            let remaining: i64 = cluster
                .database
                .count(&format!(
                    "SELECT count(*)::bigint FROM greengateway.audit_events \
                     WHERE event_type = '{RETENTION_EVENT_TYPE}'"
                ))
                .await;
            if remaining == 0 {
                return Ok(());
            }
            Err(format!("{remaining} old event(s) are still retained"))
        }
    })
    .await;

    // The counter is not a `max(position)` read: it survived the delete.
    let counter: i64 = cluster
        .database
        .count("SELECT last_position::bigint FROM greengateway.audit_stream_state WHERE singleton")
        .await;
    assert_eq!(
        counter, old_head,
        "retention must not move the position counter, which it does not own; a counter \
         that fell back to {counter} would renumber every durable cursor in the fleet"
    );

    // Events committed after retention continue the numbering rather than
    // reusing the positions it freed. Their timestamps come from the
    // database's clock, so they are genuinely inside the window.
    let now = cluster.database.epoch_seconds().await;
    let recent: Vec<harness::AuditEventSeed> = (0..RETAINED_NEW_EVENTS as i64)
        .map(|index| {
            harness::AuditEventSeed::marker(
                RETENTION_EVENT_TYPE,
                &format!("/fresh/{index}"),
                &format_epoch(now as i64),
            )
        })
        .collect();
    cluster.database.ingest_audit_events(&recent).await;
    let head = cluster.database.stream_head().await;
    assert_eq!(
        head,
        old_head + RETAINED_NEW_EVENTS as i64,
        "numbering must continue past every position retention freed"
    );

    // The retained window is contiguous: a reader inside it can follow it
    // position by position without ever finding a hole.
    let row = cluster
        .database
        .query_one(
            "SELECT coalesce(min(position), 0)::bigint, count(*)::bigint \
             FROM greengateway.audit_stream",
        )
        .await;
    let (first, retained) = (row.get::<_, i64>(0), row.get::<_, i64>(1));
    assert!(
        first > 1,
        "the window should have moved forward under retention, but still starts at {first}"
    );
    assert_eq!(
        retained,
        head - first + 1,
        "the retained window must have no holes between {first} and {head}"
    );

    // A cursor below the window is refused, not quietly reinterpreted.
    let path = format!("{EVENTS_STREAM_PATH}?event_type={RETENTION_EVENT_TYPE}");
    let (status, body, stream) =
        harness::sse::Request::new(&cluster.replica("a").base_url(), &path, &admin)
            .resume_after(0)
            .open()
            .await;
    assert!(
        stream.is_none() && status == 410,
        "a cursor older than the retained window must be refused with 410 rather than \
         resumed from wherever the server can, and answered {status}: {body}"
    );

    // A cursor inside it still works, from the other replica, and replays
    // the whole retained window exactly once.
    let mut inside = harness::sse::Request::new(&cluster.replica("b").base_url(), &path, &admin)
        .resume_after(first - 1)
        .open_ok()
        .await;
    let frames = inside
        .next_frames(RETAINED_NEW_EVENTS, Duration::from_secs(30))
        .await;
    let mut delivered: Vec<String> = frames
        .iter()
        .map(|frame| frame.event_id().to_owned())
        .collect();
    delivered.sort();
    let mut expected: Vec<String> = recent.iter().map(|event| event.event_id.clone()).collect();
    expected.sort();
    assert_eq!(
        delivered, expected,
        "the retained window must still be replayable in full from either replica"
    );
    drop(inside);

    assert_recovered_authenticated(&mut cluster, &admin).await;
}
