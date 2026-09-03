//! The harness's own proof (issue #241, PR 16).
//!
//! Every other suite under `tests/ha/` assumes this file passes: that two
//! real gateway processes come up in cluster mode against one disposable
//! database, agree on the static-configuration fingerprint well enough to
//! report `ready`, can be reached individually and through the balancer,
//! and leave nothing behind. When one of those assumptions breaks, the
//! failure belongs here and not scattered across the matrix.
//!
//! Skips silently without `GATEWAY_TEST_POSTGRES_URL_FILE`, like every
//! other PostgreSQL-backed suite in this repository.

#![cfg(feature = "postgres")]

mod harness;

use std::time::Duration;

use harness::{
    database::{database_exists, role_exists},
    Cluster, ClusterOptions, PIN_HEADER,
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

    // 3. Everything tears down.
    //
    // Both processes exit, and the deployment's roster empties: a replica
    // that drained stamps its row draining immediately, and one that was
    // killed ages out of the stale window on database time. The wait is a
    // bounded poll on that observable, generous enough for the slower of
    // the two paths.
    cluster.shutdown();
    for replica in &mut cluster.replicas {
        assert!(
            !replica.is_running(),
            "replica {} should have exited on shutdown",
            replica.name
        );
    }
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
