//! The harness's own proof (issue #241, PR 16).
//!
//! Every other suite under `tests/ha/` assumes this file passes: that two
//! real gateway processes come up in cluster mode against one disposable
//! database, agree on the static-configuration fingerprint well enough to
//! report `ready`, can be reached individually and through the balancer,
//! and leave nothing behind. When one of those assumptions breaks, the
//! failure belongs here and not scattered across the matrix.
//!
//! Two rows here are not about the harness but about the audit of record
//! (issue #11's PostgreSQL audit sink), and they live in this leg because
//! it is the cheapest one a pull request pays for:
//! [`every_served_request_leaves_exactly_one_durable_audit_row`] is the
//! non-ignored twin of the nightly `audit_enqueue` experiment, and
//! [`a_stopped_replicas_last_events_land_within_the_drain_budget`] is the
//! shutdown drain against the shared store.
//!
//! Skips silently without `GATEWAY_TEST_POSTGRES_URL_FILE`, like every
//! other PostgreSQL-backed suite in this repository.

#![cfg(feature = "postgres")]

mod harness;

use std::time::{Duration, Instant};

use harness::{
    database::{database_exists, role_exists},
    Cluster, ClusterOptions, HTTP_REQUEST_OBSERVED, PIN_HEADER,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_replicas_serve_one_deployment_and_tear_down() {
    let Some(mut cluster) = Cluster::start(ClusterOptions::default()).await else {
        eprintln!("skipping: no test database locator, or this run is not the gate; the ha-release-gate CI job runs this suite");
        return;
    };

    // 1. Both replicas reach a ready /readyz.
    //
    // This is the fingerprint-agreement gate of PR 13 doing its work: a
    // replica that disagreed with its sibling would answer `503
    // config_fingerprint_mismatch` forever, however healthy it was. Two
    // replicas answering `200` is the harness's claim that it produced
    // agreeing configurations.
    cluster.wait_until_all_ready().await;
    for replica in &cluster.replicas {
        let (status, body) = replica.readyz().await;
        assert_eq!(
            status, 200,
            "replica {} should be ready, said {body}",
            replica.name
        );
        assert_eq!(body["status"], "ready", "replica {}", replica.name);
    }

    // Both registered with the same deployment, which is what makes them
    // one cluster rather than two lonely processes sharing a database.
    let members = cluster.live_member_count().await;
    assert_eq!(
        members, 2,
        "both replicas should hold a live membership row"
    );
    let distinct_fingerprints = cluster
        .database
        .count(
            "SELECT count(DISTINCT fingerprint)::bigint \
             FROM greengateway.cluster_members",
        )
        .await;
    assert_eq!(
        distinct_fingerprints, 1,
        "the replicas must agree on the static-configuration fingerprint; \
         disagreement is what PR 13 refuses readiness for"
    );

    // 2. A request through the balancer reaches each replica.
    //
    // Round robin first: two requests, two different replicas at the
    // upstream. The upstream can tell them apart because each replica
    // injects its own `x-ha-replica` value — a route header whose NAME is
    // in the fingerprint and whose VALUE deliberately is not.
    cluster.balancer.round_robin();
    cluster.upstream.clear();
    for _ in 0..cluster.replicas.len() {
        let response = cluster.get_through_balancer("/echo/smoke").await;
        assert_eq!(
            response.status().as_u16(),
            200,
            "a proxied request through the balancer should succeed"
        );
    }
    let mut seen = cluster.upstream.replicas_seen();
    seen.sort();
    assert_eq!(
        seen,
        vec!["a".to_owned(), "b".to_owned()],
        "round robin should have reached both replicas; the balancer dispatched {:?}",
        cluster.balancer.dispatches()
    );

    // Pinning next: a request the test aims at one named replica arrives
    // through that replica and no other.
    for name in ["a", "b"] {
        cluster.upstream.clear();
        let response = cluster.get_pinned(name, "/echo/pinned").await;
        assert_eq!(response.status().as_u16(), 200, "pinned to {name}");
        let served_by = response
            .headers()
            .get("x-ha-served-by")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        assert_eq!(served_by, name, "the balancer should have pinned to {name}");
        assert_eq!(
            cluster.upstream.replicas_seen(),
            vec![name.to_owned()],
            "only replica {name} should have proxied a request pinned to it"
        );
    }

    // The pin header is the balancer's own protocol and must not be
    // forwarded into the deployment.
    let leaked = cluster
        .upstream
        .requests()
        .iter()
        .any(|request| request.headers.contains_key(PIN_HEADER));
    assert!(
        !leaked,
        "the balancer's pin header must not reach the upstream"
    );

    // 3. Everything tears down, and tears down CLEANLY.
    //
    // `Cluster::shutdown` asks each replica to leave — `SIGTERM` on unix,
    // `Ctrl+Break` on Windows — and `Replica::stop` fails the test if one
    // does not exit within its budget. So by the time it returns, every
    // replica took the coordinated shutdown: stamped its own row
    // `draining_at` before it exited, and wrote both shutdown records to
    // its audit file. Those are asserted here rather than waited for,
    // because a stop that returned without them would be a kill wearing a
    // stop's name, and every suite that calls `stop` is trusting this one
    // to have checked.
    cluster.shutdown();
    for replica in &mut cluster.replicas {
        assert!(
            !replica.is_running(),
            "replica {} should have exited on shutdown",
            replica.name
        );
    }
    let stamped_draining = cluster
        .database
        .count(
            "SELECT count(*)::bigint FROM greengateway.cluster_members \
             WHERE draining_at IS NOT NULL",
        )
        .await;
    assert_eq!(
        stamped_draining,
        i64::try_from(cluster.replicas.len()).expect("a replica count fits in i64"),
        "every stopped replica should have stamped its membership row draining before it \
         exited; a row without the stamp was killed, not drained"
    );
    for replica in &cluster.replicas {
        let event_types: Vec<String> = replica
            .audit_events()
            .iter()
            .filter_map(|event| event["event_type"].as_str().map(str::to_owned))
            .collect();
        for expected in ["gateway.shutdown_started", "gateway.shutdown_completed"] {
            assert!(
                event_types.iter().any(|event_type| event_type == expected),
                "replica {} should have written {expected} on a clean stop; its audit file \
                 holds {event_types:?}\n--- output ---\n{}",
                replica.name,
                replica.output_since_launch()
            );
        }
    }
    // And the roster agrees: a draining row is not a live one, so nothing
    // is left to age out. The budget is the stale window's because that is
    // what a killed replica would have needed, and this wait is shared with
    // rows that kill.
    cluster
        .wait_until_no_live_members(Duration::from_millis(cluster.member_stale_ms * 4))
        .await;

    // The disposable database and role go with the harness: `Drop` runs
    // them down whether this test passed or panicked. The database handle
    // is still answering right up to that point.
    assert!(
        cluster.database.epoch_seconds().await > 0.0,
        "the harness database should still be answering at teardown"
    );
}

/// A restarted replica is discovered at the port it just bound, not at the
/// one the previous boot had.
///
/// The failure this exists for is a wait that returns without ever
/// observing its condition. The audit sink appends, so after a restart the
/// file still holds the DEAD process's `gateway.startup` record; discovery
/// that took the first match would hand back a closed port in
/// milliseconds, and `Cluster::restart` would then point the balancer at
/// nothing. The assertions below are therefore about the *new* listener
/// answering, not about the restart call returning.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_replica_is_discovered_at_its_new_listener() {
    let Some(mut cluster) = Cluster::start(ClusterOptions {
        // One replica: this is about one process's rebirth, and a second
        // would only be another boot to wait for on a shared machine.
        replicas: 1,
        ..ClusterOptions::default()
    })
    .await
    else {
        eprintln!("skipping: no test database locator, or this run is not the gate; the ha-release-gate CI job runs this suite");
        return;
    };
    cluster.wait_until_all_ready().await;

    let before = cluster.replica("a").addr();
    cluster.restart("a").await;
    let after = cluster.replica("a").addr();

    // Two boots, two records: proof that the address above was read from
    // the second and not from the first.
    let startups = cluster
        .replica("a")
        .audit_events()
        .iter()
        .filter(|event| event["event_type"] == "gateway.startup")
        .count();
    assert_eq!(
        startups, 2,
        "the restarted replica should have written a second startup record; it announced \
         {before} then {after}"
    );

    // The reported address is the live one. (Whether the kernel handed back
    // the same ephemeral port is not the point and is not asserted: what
    // matters is that something is listening there now.)
    let (status, body) = cluster.replica("a").livez().await;
    assert_eq!(
        status, 200,
        "the address reported after the restart should be serving, said {body}"
    );
    cluster.wait_until_all_ready().await;

    // And the balancer was pointed at it, which is the thing every suite
    // that restarts a replica actually depends on.
    let response = cluster.get_pinned("a", "/echo/restarted").await;
    assert_eq!(
        response.status().as_u16(),
        200,
        "a request through the balancer should reach the restarted replica"
    );
}

/// Teardown from the ugly side: a killed replica, no clean shutdown, and
/// the cluster handle simply going out of scope — which is what happens
/// while a failing test unwinds. Nothing may survive it, because a harness
/// that leaked a database per failure would fill the shared server in an
/// afternoon.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_a_cluster_removes_its_database_role_and_files() {
    let Some(admin_dsn) = harness::locator() else {
        eprintln!("skipping: no test database locator, or this run is not the gate; the ha-release-gate CI job runs this suite");
        return;
    };

    let (database_name, role, secrets_path, files_path) = {
        // One replica: this test is about teardown, and a second process
        // would only make it slower on a shared machine.
        let Some(mut cluster) = Cluster::start(ClusterOptions {
            replicas: 1,
            ..ClusterOptions::default()
        })
        .await
        else {
            return;
        };
        cluster.wait_until_all_ready().await;
        let (secrets_path, files_path) = cluster.temporary_paths();
        assert!(secrets_path.exists() && files_path.exists());

        // No `shutdown()`. The replica is killed outright and the cluster
        // is dropped where it stands.
        cluster.replicas[0].kill();
        (
            cluster.database.name.clone(),
            cluster.database.role.clone(),
            secrets_path,
            files_path,
        )
    };

    assert!(
        !database_exists(&admin_dsn, &database_name).await,
        "the disposable database {database_name} outlived its cluster"
    );
    assert!(
        !role_exists(&admin_dsn, &role).await,
        "the disposable runtime role {role} outlived its cluster"
    );
    assert!(
        !secrets_path.exists(),
        "the secrets root {} outlived its cluster",
        secrets_path.display()
    );
    assert!(
        !files_path.exists(),
        "the DSN and audit directory {} outlived its cluster",
        files_path.display()
    );
}

// ---------------------------------------------------------------------
// The request-path audit of record (issue #11).
// ---------------------------------------------------------------------

/// The path the audit rows are driven through, so their rows can be told
/// from the probes' and the other tests'.
const AUDIT_PATH: &str = "/echo/smoke-audit";
/// The path the drained replica is driven through.
const DRAIN_PATH: &str = "/echo/smoke-drain";
/// Requests through the balancer with the sink running normally.
const AUDIT_REQUESTS: usize = 240;
/// Requests through the balancer while the sink is stalled.
const STALLED_REQUESTS: usize = 80;
/// Requests issued right after the lock is taken, so the sinks have a batch
/// to try to land — and get stuck on — before the stalled burst is timed.
const STALL_PRIMER: usize = 8;
/// Requests pinned to the replica that is then stopped.
const DRAIN_REQUESTS: usize = 120;
/// How many requests are in flight at once.
const CONCURRENCY: usize = 16;
/// How long the rows may take to land once the sink can write.
const AUDIT_CONVERGENCE: Duration = Duration::from_secs(60);
/// How long the stalled burst may take. The sink offers a batch three
/// times before it drops anything, each offer bounded by the shorter of
/// its own 10 s attempt timeout and the pooled session's
/// `DATABASE_LOCK_TIMEOUT_MS` (5 s here), with 100 ms and then 200 ms of
/// backoff between offers: about 15 s under this lock. A stall shorter
/// than that loses nothing — and a request path that waited for the sink
/// would not finish inside it at all, because the lock is held until the
/// burst completes.
const STALL_BUDGET: Duration = Duration::from_secs(10);
/// The counter every shed audit event lands on, whichever sink shed it,
/// read off `/metrics` the way an operator reads it.
const AUDIT_EVENTS_DROPPED_TOTAL: &str = "audit_events_dropped_total";

/// The pre-authentication read lane is keyed by client address, and every
/// request in these bursts comes from the same loopback one; at the
/// shipped default most of a burst would be `429`s about the limiter, not
/// rows about the sink. Lifted well past the bursts.
fn lifted_rate_limits() -> Vec<(String, String)> {
    vec![
        ("RATE_LIMIT_READ_RPS".to_owned(), "100000.0".to_owned()),
        ("RATE_LIMIT_READ_BURST".to_owned(), "100000".to_owned()),
    ]
}

/// Issue `total` requests for `path`, at most [`CONCURRENCY`] at a time,
/// through the balancer — round robin, or pinned to one replica — and
/// answer the status of each.
async fn burst(cluster: &Cluster, path: &str, total: usize, pin: Option<&str>) -> Vec<u16> {
    let mut statuses = Vec::with_capacity(total);
    let mut issued = 0;
    while issued < total {
        let wave = CONCURRENCY.min(total - issued);
        let responses = futures_util::future::join_all((0..wave).map(|_| async {
            match pin {
                Some(name) => cluster.get_pinned(name, path).await,
                None => cluster.get_through_balancer(path).await,
            }
        }))
        .await;
        statuses.extend(responses.iter().map(|response| response.status().as_u16()));
        issued += wave;
    }
    statuses
}

/// Split a burst's statuses into served (`200`) and declined (`503`), and
/// fail on anything else.
///
/// A `503` is the replica declining to consult its authority under load —
/// a legitimate answer that records nothing, and admitted; any other
/// status would mean the burst hit a bound these rows are not about.
fn served_and_declined(statuses: &[u16], context: &str) -> (usize, usize) {
    let served = statuses.iter().filter(|status| **status == 200).count();
    let declined = statuses.iter().filter(|status| **status == 503).count();
    assert_eq!(
        served + declined,
        statuses.len(),
        "every {context} request must be proxied or declined outright; statuses: {:?}",
        statuses
            .iter()
            .filter(|status| !matches!(**status, 200 | 503))
            .take(8)
            .collect::<Vec<_>>()
    );
    assert!(
        served * 10 >= statuses.len() * 9,
        "the deployment served only {served} of {} {context} requests; load may degrade it, \
         not take it out of service",
        statuses.len()
    );
    (served, declined)
}

/// What the shared store holds for one path, read in one statement so the
/// counts describe one instant.
struct AuditRows {
    /// Observation rows for the path whose recorded status is `200`.
    written_ok: i64,
    /// Observation rows for the path, whatever their status.
    written: i64,
    /// Distinct `event_id`s among them.
    distinct_ids: i64,
    /// How many of them hold a durable stream position.
    streamed: i64,
    /// Distinct writing replicas (`instance_id`).
    writers: i64,
}

async fn audit_rows(cluster: &Cluster, path: &str) -> AuditRows {
    let row = cluster
        .database
        .query_one(&format!(
            "SELECT count(*) FILTER (WHERE e.payload_status = 200)::bigint, \
                    count(*)::bigint, \
                    count(DISTINCT e.event_id)::bigint, \
                    count(s.position)::bigint, \
                    count(DISTINCT e.instance_id)::bigint \
             FROM greengateway.audit_events e \
             LEFT JOIN greengateway.audit_stream s ON s.event_id = e.event_id \
             WHERE e.event_type = '{HTTP_REQUEST_OBSERVED}' AND e.payload_path = '{path}'"
        ))
        .await;
    AuditRows {
        written_ok: row.get(0),
        written: row.get(1),
        distinct_ids: row.get(2),
        streamed: row.get(3),
        writers: row.get(4),
    }
}

/// Every served request leaves exactly one durable audit row, written by
/// the replica that served it — with the sink running, and with the sink
/// stalled.
///
/// The non-ignored twin of `ha_performance`'s `audit_enqueue` experiment,
/// so a pull request fails on it. Before issue #11 no serving replica
/// wrote a durable audit row; now every replica composes
/// `audit/postgres_sink.rs`, and the guide's non-goal became a guarantee
/// this row proves:
///
/// 1. A burst across both replicas leaves one row per served request in
///    `greengateway.audit_events` — no more (a duplicate is an
///    audit-integrity failure of its own), each with its own event id and
///    a durable stream position, written under the identity of one of the
///    two live members, and by both of them.
/// 2. With `ACCESS EXCLUSIVE` held on the table, so no batch can land, a
///    second burst is still served inside a bound: `emit` pushes onto the
///    sink's buffer and returns, and the request path never waits for the
///    store. A request path that did wait would deadlock against a lock
///    this test holds until the burst completes.
/// 3. Nothing was dropped on the way, and both replicas still serve.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_served_request_leaves_exactly_one_durable_audit_row() {
    let Some(mut cluster) = Cluster::start(ClusterOptions {
        shared_env: lifted_rate_limits(),
        ..ClusterOptions::default()
    })
    .await
    else {
        eprintln!("skipping: no test database locator, or this run is not the gate; the ha-release-gate CI job runs this suite");
        return;
    };
    cluster.wait_until_all_ready().await;
    // Baselined: a replica may drop a handful of events during a cold
    // start on a loaded machine, and those are not this row's.
    let dropped_before = cluster.metric_total(AUDIT_EVENTS_DROPPED_TOTAL).await;
    let members = cluster.member_identities().await;
    assert_eq!(members.len(), 2, "both replicas should be live members");

    // The sink running normally.
    cluster.balancer.round_robin();
    cluster.upstream.clear();
    let statuses = burst(&cluster, AUDIT_PATH, AUDIT_REQUESTS, None).await;
    let (served, _) = served_and_declined(&statuses, "unstalled");
    let mut seen = cluster.upstream.replicas_seen();
    seen.sort();
    assert_eq!(
        seen,
        vec!["a".to_owned(), "b".to_owned()],
        "the burst should have crossed both replicas"
    );

    // The sink stalled: every batch insert blocks on the lock for as long
    // as the burst takes, and the burst must not care. The stall is made
    // real before it is measured — a few requests to give the sinks a
    // batch, then a wait until one is observed wedged behind the lock —
    // because a lock nobody is waiting on stalls nothing.
    let lock = cluster.database.hold_audit_events_exclusively().await;
    let stalled_at = Instant::now();
    let primer = burst(&cluster, AUDIT_PATH, STALL_PRIMER, None).await;
    cluster
        .database
        .wait_for_blocked_audit_writer(STALL_BUDGET)
        .await;
    let blocked_writers = cluster.database.blocked_audit_writers().await;
    let stalled = tokio::time::timeout(
        STALL_BUDGET,
        burst(&cluster, AUDIT_PATH, STALLED_REQUESTS, None),
    )
    .await;
    let stall = stalled_at.elapsed();
    lock.release().await;
    let stalled = stalled.map(|stalled| [primer, stalled].concat());
    let stalled = stalled.unwrap_or_else(|_| {
        panic!(
            "{STALLED_REQUESTS} requests did not complete within {STALL_BUDGET:?} while the \
             audit table was locked: the audit enqueue is waiting on the sink, on the \
             request path"
        )
    });
    let (stalled_served, _) = served_and_declined(&stalled, "stalled");
    let served = served + stalled_served;
    eprintln!(
        "audit rows: {served} requests served, {stalled_served} of them with the sink \
         stalled for {stall:?} ({blocked_writers} batch insert(s) were blocked behind the \
         lock when the stalled burst began)"
    );

    // The rows land — the last batch a flush interval after the last
    // request, and the stalled ones once the lock went — so the count is
    // polled to the deployment's total and then asserted exactly.
    let deadline = Instant::now() + AUDIT_CONVERGENCE;
    let rows = loop {
        let rows = audit_rows(&cluster, AUDIT_PATH).await;
        if rows.written_ok >= served as i64 {
            break rows;
        }
        assert!(
            Instant::now() < deadline,
            "only {} of the {served} served requests had a durable audit row after \
             {AUDIT_CONVERGENCE:?}",
            rows.written_ok
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(
        rows.written_ok, served as i64,
        "the deployment stored {} observation rows for {served} served requests: an audit \
         trail must not duplicate",
        rows.written_ok
    );
    assert!(
        rows.written <= statuses.len() as i64 + stalled.len() as i64,
        "the deployment stored {} observation rows for {} requests",
        rows.written,
        statuses.len() + stalled.len()
    );
    assert_eq!(
        rows.distinct_ids, rows.written,
        "every stored observation must carry its own event id"
    );
    assert_eq!(
        rows.streamed, rows.written,
        "every stored observation must hold a durable stream position"
    );
    assert_eq!(
        rows.writers, 2,
        "both replicas served the burst, so both must have written rows under their own \
         identity; {} distinct writer(s) were recorded",
        rows.writers
    );
    let foreign_writers: i64 = cluster
        .database
        .count(&format!(
            "SELECT count(*)::bigint FROM greengateway.audit_events \
             WHERE payload_path = '{AUDIT_PATH}' \
               AND (instance_id IS NULL OR instance_id::text NOT IN ({}))",
            members
                .iter()
                .map(|member| format!("'{}'", member.instance_id))
                .collect::<Vec<_>>()
                .join(", ")
        ))
        .await;
    assert_eq!(
        foreign_writers, 0,
        "every row must carry the identity of the live member that wrote it"
    );
    let dropped = cluster.metric_total(AUDIT_EVENTS_DROPPED_TOTAL).await - dropped_before;
    assert!(
        dropped < 1.0,
        "no audit event may be dropped at this load or by a stall this short; {dropped} were"
    );

    // Both replicas still serve.
    cluster.wait_until_all_ready().await;
    assert_eq!(
        cluster.live_member_count().await,
        2,
        "both replicas should still hold a live membership row"
    );
    for name in ["a", "b"] {
        let response = cluster.get_pinned(name, "/echo/smoke-audit-after").await;
        assert_eq!(
            response.status().as_u16(),
            200,
            "replica {name} should serve after the stall"
        );
    }
}

/// A replica that is stopped cleanly lands its last audit events — the
/// requests it had just served and its own shutdown records — before it
/// exits, and its drain reports success, which is the drain's own clock
/// saying the sink landed them inside `AUDIT_DRAIN_TIMEOUT_MS`.
///
/// The shutdown drain (`lifecycle.rs::drain_audit`) calls the composite's
/// terminal flush with the drain's deadline, and the PostgreSQL sink hands
/// its flusher that deadline and waits: everything buffered must be in
/// the shared store by the time the process is gone, because there is
/// nobody left to write it after. The rows are therefore read ONCE, after
/// the exit, never polled — a row that is not there then is lost, not
/// late. The stop itself is bounded by the listener's shutdown budget
/// plus the drain's; the drain's own verdict is read off the process's
/// output, where a drain that overran (`failed to drain audit events`) or
/// a sink that dropped (`PostgreSQL audit flush`) is printed.
///
/// The last events are the load-bearing ones. `gateway.shutdown_completed`
/// is emitted after the listener has closed and immediately before the
/// drain, so no flush interval could have landed it: only the drain can.
///
/// The harness's `stop` is `SIGTERM` on unix and `Ctrl+Break` on Windows
/// (see `harness/replica.rs::Replica::stop`), so this row runs on both and
/// a stop that does not drain fails loudly rather than skipping.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stopped_replicas_last_events_land_within_the_drain_budget() {
    let Some(mut cluster) = Cluster::start(ClusterOptions {
        shared_env: lifted_rate_limits(),
        ..ClusterOptions::default()
    })
    .await
    else {
        eprintln!("skipping: no test database locator, or this run is not the gate; the ha-release-gate CI job runs this suite");
        return;
    };
    cluster.wait_until_all_ready().await;
    let members = cluster.member_identities().await;
    assert_eq!(members.len(), 2, "both replicas should be live members");
    // Index 0 is `a`: the harness starts replicas one at a time and the
    // roster is read oldest boot first.
    let stopped_instance = members[0].instance_id;
    let environment = cluster.replica("a").environment();
    let drain_budget = Duration::from_millis(
        environment
            .get("AUDIT_DRAIN_TIMEOUT_MS")
            .and_then(|value| value.parse().ok())
            .expect("the harness sets AUDIT_DRAIN_TIMEOUT_MS on every replica"),
    );
    let shutdown_budget = Duration::from_millis(
        environment
            .get("SHUTDOWN_TIMEOUT_MS")
            .and_then(|value| value.parse().ok())
            .expect("the harness sets SHUTDOWN_TIMEOUT_MS on every replica"),
    );

    // Requests the replica has served and whose events its sink may not
    // have flushed yet, then the stop, with nothing in between.
    let statuses = burst(&cluster, DRAIN_PATH, DRAIN_REQUESTS, Some("a")).await;
    let (served, _) = served_and_declined(&statuses, "pre-stop");
    let stopping = Instant::now();
    cluster.stop("a");
    let took = stopping.elapsed();
    assert!(
        !cluster.replica_mut("a").is_running(),
        "replica a should have exited on stop"
    );
    // The drain is bounded, and the bound is the configured one: a stop
    // that took much longer than the listener's shutdown budget plus the
    // audit drain budget was the harness giving up and killing the process.
    let exit_budget = shutdown_budget + drain_budget + Duration::from_secs(5);
    assert!(
        took < exit_budget,
        "replica a took {took:?} to stop against a shutdown budget of {shutdown_budget:?} \
         plus an audit drain budget of {drain_budget:?}; the drain is not bounded by its \
         configuration"
    );

    // Read once. The process is gone; whatever is not here now never will be.
    let row = cluster
        .database
        .query_one(&format!(
            "SELECT count(*) FILTER (WHERE event_type = '{HTTP_REQUEST_OBSERVED}' \
                                       AND payload_path = '{DRAIN_PATH}' \
                                       AND payload_status = 200)::bigint, \
                    count(*) FILTER (WHERE event_type = 'gateway.startup')::bigint, \
                    count(*) FILTER (WHERE event_type = 'gateway.shutdown_started')::bigint, \
                    count(*) FILTER (WHERE event_type = 'gateway.shutdown_completed')::bigint, \
                    count(*) FILTER (WHERE event_type = 'gateway.shutdown_forced')::bigint \
             FROM greengateway.audit_events WHERE instance_id = '{stopped_instance}'::uuid"
        ))
        .await;
    let (observed, startups, started, completed, forced) = (
        row.get::<_, i64>(0),
        row.get::<_, i64>(1),
        row.get::<_, i64>(2),
        row.get::<_, i64>(3),
        row.get::<_, i64>(4),
    );
    eprintln!(
        "drain: replica a served {served} requests, stopped in {took:?}, and left {observed} \
         observation rows, {startups} startup, {started} shutdown_started, {completed} \
         shutdown_completed and {forced} shutdown_forced records in the shared store"
    );
    assert_eq!(
        observed, served as i64,
        "the stopped replica served {served} requests and left {observed} durable rows for \
         them: the drain must land every buffered event before the process exits"
    );
    assert_eq!(
        startups, 1,
        "the stopped replica's startup record should be in the shared store"
    );
    assert_eq!(
        (started, completed, forced),
        (1, 1, 0),
        "the stopped replica's shutdown must be recorded as started and completed, never \
         forced, and the completion record — emitted after the listener closed, just before \
         the drain — is the one only the drain can land"
    );
    // The drain's own verdict: `lifecycle::run` returns the drain's error
    // and `main` prints it, and the sink logs every batch it drops. Rows
    // that are all present but a drain that reported a timeout would mean
    // the sink outlived the drain's budget and landed them on its own
    // clock — the bound this row is named for, unproved.
    let output = cluster.replica("a").output_since_launch();
    assert!(
        !output.contains("failed to drain audit events"),
        "the stopped replica's audit drain reported a failure; its output:\n{output}"
    );
    for needle in [
        "PostgreSQL audit flush",
        "failed to flush PostgreSQL audit events",
    ] {
        assert!(
            !output.contains(needle),
            "the stopped replica's PostgreSQL sink reported a failed or dropped flush \
             ({needle:?}); its output:\n{output}"
        );
    }

    // The survivor is untouched.
    let response = cluster.get_pinned("b", "/echo/smoke-drain-survivor").await;
    assert_eq!(
        response.status().as_u16(),
        200,
        "replica b should still serve after its sibling drained"
    );
}
