use super::*;

/// Cluster mode's fingerprint gate (issue #241, PR 13): a replica that
/// is serving locally but has not yet found every live member on its
/// static-configuration fingerprint answers `503` with
/// `config_fingerprint_mismatch`, and is ready the moment the gate
/// records agreement. Liveness and startup are untouched by the gate.
#[tokio::test]
async fn readiness_is_refused_while_the_cluster_fingerprint_disagrees() {
    let lifecycle = GatewayLifecycle::new();
    let readiness = ha::ClusterReadiness::new();
    let recorder = PrometheusBuilder::new().build_recorder();
    let app = gateway_app_with_process_started_at_and_overrides(
        test_config(Vec::new()),
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
        Instant::now(),
        GatewayAppBuildOverrides {
            lifecycle: Some(lifecycle.clone()),
            cluster_readiness: Some(readiness.clone()),
            disable_proxy_health_checks: true,
            ..GatewayAppBuildOverrides::default()
        },
    )
    .expect("gateway app should build");
    let router = match app.http {
        GatewayApp::Unified(router) => router,
        GatewayApp::Split { .. } => panic!("test app should be unified"),
    };
    lifecycle.mark_ready();

    let probe = |path: &'static str| {
        router.clone().oneshot(
            Request::builder()
                .uri(path)
                .body(Body::empty())
                .expect("request should build"),
        )
    };
    let response = probe("/readyz")
        .await
        .expect("readiness request should complete");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = json_body(response).await;
    assert_eq!(body["status"], "not_ready");
    assert_eq!(body["reason"], "config_fingerprint_mismatch");
    for path in ["/livez", "/startupz"] {
        let response = probe(path).await.expect("probe request should complete");
        assert_eq!(response.status(), StatusCode::OK, "{path} is not gated");
    }

    readiness.record_fingerprint_agreement();
    let response = probe("/readyz")
        .await
        .expect("readiness request should complete");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["status"], "ready");
}

/// A cluster-shaped app whose `/readyz` consults `readiness` for the
/// fingerprint gate and `probe` for the authority-backed reasons.
/// Standalone configuration otherwise: the two seams are what the
/// readiness chain is being tested through, so nothing else has to
/// pretend to be a cluster.
fn cluster_readiness_app(
    lifecycle: &GatewayLifecycle,
    readiness: Arc<ha::ClusterReadiness>,
    probe: Option<Arc<ha_status::ReadinessProbe>>,
) -> axum::Router {
    let recorder = PrometheusBuilder::new().build_recorder();
    let app = gateway_app_with_process_started_at_and_overrides(
        test_config(Vec::new()),
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
        Instant::now(),
        GatewayAppBuildOverrides {
            lifecycle: Some(lifecycle.clone()),
            cluster_readiness: Some(readiness),
            readiness_probe: probe,
            disable_proxy_health_checks: true,
            ..GatewayAppBuildOverrides::default()
        },
    )
    .expect("gateway app should build");
    match app.http {
        GatewayApp::Unified(router) => router,
        GatewayApp::Split { .. } => panic!("test app should be unified"),
    }
}

/// The durable contract fence (issue #426, PR 3): once the membership
/// heartbeat finds that the fence excludes this build, `/readyz` answers
/// `contract_fenced` ahead of every other cluster reason and never ready
/// again, because the fence only moves forward. Liveness and startup are
/// untouched, as for every readiness reason.
#[tokio::test]
async fn readiness_is_refused_for_good_once_the_contract_fence_excludes_this_build() {
    let lifecycle = GatewayLifecycle::new();
    let readiness = ha::ClusterReadiness::new();
    readiness.record_fingerprint_agreement();
    let router = cluster_readiness_app(&lifecycle, readiness.clone(), None);
    lifecycle.mark_ready();
    assert_eq!(readyz_answer(&router).await.0, StatusCode::OK);

    assert!(readiness.record_contract_fenced());
    assert_eq!(
        readyz_answer(&router).await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"status":"not_ready","reason":"contract_fenced"}"#.to_owned()
        )
    );
    readiness.record_fingerprint_agreement();
    assert_eq!(
        readyz_answer(&router).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    for path in ["/livez", "/startupz"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("probe request should complete");
        assert_eq!(response.status(), StatusCode::OK, "{path} is not gated");
    }
}

async fn readyz_answer(router: &axum::Router) -> (StatusCode, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("readiness request should complete");
    let status = response.status();
    (status, body_string(response).await)
}

/// A policy granting `admin:cluster:read` to one role and nothing to
/// another, which is what the permission test needs on both sides.
fn cluster_status_policy() -> TempPolicyFile {
    TempPolicyFile::new(
        &serde_json::to_string(&json!({
            "schema_version": "0.1.0",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {
                "cluster-reader": { "permissions": [ADMIN_CLUSTER_READ_PERMISSION] },
                "status-reader": { "permissions": [ADMIN_STATUS_READ_PERMISSION] }
            },
            "rules": []
        }))
        .expect("cluster policy should serialize"),
    )
}

/// An app serving the cluster status API. `source` is the scripted
/// readout: `Some` puts the state in cluster mode, `None` leaves it in
/// standalone, which is what a deployment with no authority is.
fn cluster_status_app(
    policy: Option<&TempPolicyFile>,
    source: Option<Arc<dyn cluster_status::ClusterStatusSource>>,
    identity: ha::InstanceIdentity,
) -> axum::Router {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    if let Some(policy) = policy {
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        // The handler's own permission check is what these tests are
        // about, so the routes bypass the RBAC layer and the injected
        // principal reaches the handler, exactly as the audit and
        // status admin tests do it.
        config
            .rbac_exempt_paths
            .push(CLUSTER_ADMIN_ROUTE.to_owned());
        config
            .rbac_exempt_paths
            .push(CLUSTER_REPLICAS_ADMIN_ROUTE.to_owned());
    }
    // A serving replica: the lifecycle is what `/readyz` (and so this
    // view's `state`) reads first, and an unmarked one is `starting`.
    let lifecycle = GatewayLifecycle::default();
    lifecycle.mark_ready();
    let recorder = PrometheusBuilder::new().build_recorder();
    let app = gateway_app_with_process_started_at_and_overrides(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
        Instant::now(),
        GatewayAppBuildOverrides {
            lifecycle: Some(lifecycle),
            ha_identity: Some(identity),
            cluster_status_source: source,
            disable_proxy_health_checks: true,
            ..GatewayAppBuildOverrides::default()
        },
    )
    .expect("gateway app should build");
    match app.http {
        GatewayApp::Unified(router) => router,
        GatewayApp::Split { .. } => panic!("test app should be unified"),
    }
}

async fn cluster_status_response(
    router: &axum::Router,
    uri: &str,
    principal: Option<auth::Principal>,
) -> Response {
    router
        .clone()
        .oneshot(audit_query_request(uri, principal))
        .await
        .expect("cluster status request should complete")
}

/// Both cluster routes are gated on `admin:cluster:read` alone, in the
/// same shape `admin:audit:read` is enforced with: no principal is
/// `401`, a principal holding some other admin permission is `403`,
/// and an unconfigured RBAC is `404` rather than an open door.
#[tokio::test]
async fn the_cluster_routes_require_the_cluster_read_permission() {
    let policy = cluster_status_policy();
    let router = cluster_status_app(Some(&policy), None, ha::InstanceIdentity::generate());

    for uri in [CLUSTER_ADMIN_ROUTE, CLUSTER_REPLICAS_ADMIN_ROUTE] {
        let unauthenticated = cluster_status_response(&router, uri, None).await;
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED, "{uri}");

        let wrong_permission =
            cluster_status_response(&router, uri, Some(test_principal(&["status-reader"]))).await;
        assert_eq!(
            wrong_permission.status(),
            StatusCode::FORBIDDEN,
            "{uri}: admin:status:read is not admin:cluster:read"
        );

        let unknown_role =
            cluster_status_response(&router, uri, Some(test_principal(&["nobody"]))).await;
        assert_eq!(unknown_role.status(), StatusCode::FORBIDDEN, "{uri}");

        let permitted =
            cluster_status_response(&router, uri, Some(test_principal(&["cluster-reader"]))).await;
        assert_eq!(permitted.status(), StatusCode::OK, "{uri}");
    }

    // No policy file: RBAC is not configured, so the routes are not
    // reachable at all rather than reachable without a check.
    let unconfigured = cluster_status_app(None, None, ha::InstanceIdentity::generate());
    for uri in [CLUSTER_ADMIN_ROUTE, CLUSTER_REPLICAS_ADMIN_ROUTE] {
        let response =
            cluster_status_response(&unconfigured, uri, Some(test_principal(&["admin"]))).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
        assert_eq!(
            json_body(response).await["error"],
            json!("cluster status API requires POLICY_FILE to be configured")
        );
    }
}

/// Standalone mode serves both shapes: it is the deployment, so it
/// reports itself as the only replica and leaves every section that
/// describes a cluster null.
#[tokio::test]
async fn standalone_cluster_status_reports_this_process_as_the_whole_deployment() {
    let policy = cluster_status_policy();
    let identity = ha::InstanceIdentity::generate();
    let router = cluster_status_app(Some(&policy), None, identity);
    let principal = test_principal(&["cluster-reader"]);

    let status = json_body(
        cluster_status_response(&router, CLUSTER_ADMIN_ROUTE, Some(principal.clone())).await,
    )
    .await;
    assert_eq!(status["mode"], json!("standalone"));
    assert_eq!(status["ready"], json!(true));
    assert_eq!(status["state"], json!("ready"));
    assert_eq!(status["reason"], json!(null));
    assert_eq!(status["replicas"]["ready"], json!(1));
    assert_eq!(status["replicas"]["total"], json!(1));
    assert_eq!(status["binary_versions"][0]["count"], json!(1));
    assert_eq!(
        status["binary_versions"][0]["version"],
        json!(env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(status["projector"], json!(null));
    assert_eq!(status["leader_tasks"], json!(null));
    assert_eq!(status["pools"]["database"], json!(null));
    assert_eq!(status["schema"]["current_version"], json!(null));
    assert_eq!(status["schema"]["compatible"], json!(true));
    assert_eq!(
        status["local"]["instance_id"],
        json!(identity.instance_id().to_string())
    );
    assert_eq!(status["local"]["revision_lag"], json!(0));
    assert_eq!(status["reconcile"]["failures_total"], json!(0));
    assert!(status["audit"]["queue_capacity"].as_u64().unwrap_or(0) > 0);

    let replicas = json_body(
        cluster_status_response(&router, CLUSTER_REPLICAS_ADMIN_ROUTE, Some(principal)).await,
    )
    .await;
    let listed = replicas["replicas"]
        .as_array()
        .expect("replicas should be an array");
    assert_eq!(listed.len(), 1);
    assert_eq!(
        listed[0]["instance_id"],
        json!(identity.instance_id().to_string())
    );
    assert_eq!(listed[0]["boot_id"], json!(identity.boot_id().to_string()));
    assert_eq!(listed[0]["live"], json!(true));
    assert_eq!(listed[0]["started_at"], json!(null));
}

/// Cluster mode with two live members: the roster, the version
/// grouping, the projector's lag and leader, the singleton's ledger,
/// and the pool all reach the response.
#[tokio::test]
async fn cluster_status_reports_a_two_member_roster_from_the_authority() {
    use cluster_status::test_support::{two_ready_members, ScriptedClusterStatusSource};

    let policy = cluster_status_policy();
    let identity = ha::InstanceIdentity::generate();
    let second = uuid::Uuid::new_v4();
    let source =
        ScriptedClusterStatusSource::new(two_ready_members(identity.instance_id(), second));
    let router = cluster_status_app(Some(&policy), Some(source), identity);
    let principal = test_principal(&["cluster-reader"]);

    let status = json_body(
        cluster_status_response(&router, CLUSTER_ADMIN_ROUTE, Some(principal.clone())).await,
    )
    .await;
    assert_eq!(status["mode"], json!("cluster"));
    assert_eq!(status["state"], json!("ready"));
    assert_eq!(status["replicas"]["ready"], json!(2));
    assert_eq!(status["replicas"]["total"], json!(2));
    assert_eq!(status["binary_versions"][0]["version"], json!("1.0.1"));
    assert_eq!(status["binary_versions"][0]["count"], json!(2));
    assert_eq!(status["projector"]["fence"], json!(3));
    assert_eq!(status["projector"]["checkpoint_position"], json!(40));
    assert_eq!(status["projector"]["stream_head"], json!(42));
    assert_eq!(status["projector"]["lag_events"], json!(2));
    assert_eq!(status["projector"]["leader_present"], json!(true));
    assert_eq!(
        status["leader_tasks"][0]["name"],
        json!("stale_member_sweep")
    );
    assert_eq!(
        status["leader_tasks"][0]["held_by_this_instance"],
        json!(false)
    );
    assert_eq!(status["pools"]["database"]["size"], json!(4));
    assert_eq!(status["pools"]["database"]["available"], json!(4));
    assert_eq!(status["pools"]["database"]["timeouts_total"], json!(0));

    let replicas = json_body(
        cluster_status_response(&router, CLUSTER_REPLICAS_ADMIN_ROUTE, Some(principal)).await,
    )
    .await;
    let listed = replicas["replicas"]
        .as_array()
        .expect("replicas should be an array");
    assert_eq!(listed.len(), 2);
    assert_eq!(
        listed[0]["instance_id"],
        json!(identity.instance_id().to_string())
    );
    assert_eq!(listed[1]["instance_id"], json!(second.to_string()));
    assert_eq!(listed[0]["fingerprint"], json!("b".repeat(64)));
    assert_eq!(
        listed[0]["last_heartbeat_at"],
        json!("2026-09-01T10:00:05.000000Z")
    );
}

/// The redaction boundary holds over the wire, not just over the
/// assembly: a roster full of DSNs and addresses reaches the client
/// with none of it, on both routes.
#[tokio::test]
async fn hostile_roster_values_never_reach_the_cluster_endpoints() {
    use cluster_status::test_support::{two_ready_members, ScriptedClusterStatusSource};

    let hostile = "postgres://gateway:hunter2@db.internal.example:5432/greengateway";
    let policy = cluster_status_policy();
    let identity = ha::InstanceIdentity::generate();
    let mut readout = two_ready_members(identity.instance_id(), uuid::Uuid::new_v4());
    readout.members = readout.members.map(|members| {
        members
            .into_iter()
            .map(|member| cluster_status::ReplicaFacts {
                binary_version: hostile.to_owned(),
                fingerprint: hostile.to_owned(),
                started_at: Some(hostile.to_owned()),
                last_heartbeat_at: Some(hostile.to_owned()),
                ready_at: Some(hostile.to_owned()),
                last_error_code: Some(hostile.to_owned()),
                ..member
            })
            .collect()
    });
    readout.leader_tasks = Some(vec![cluster_status::LeaderTaskFacts {
        job: hostile.to_owned(),
        fence: 1,
        last_success_age_secs: None,
        last_failure_code: Some(hostile.to_owned()),
    }]);
    let router = cluster_status_app(
        Some(&policy),
        Some(ScriptedClusterStatusSource::new(readout)),
        identity,
    );
    let principal = test_principal(&["cluster-reader"]);

    for uri in [CLUSTER_ADMIN_ROUTE, CLUSTER_REPLICAS_ADMIN_ROUTE] {
        let response = cluster_status_response(&router, uri, Some(principal.clone())).await;
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        let body = body_string(response).await;
        assert!(!body.contains(hostile), "{uri} leaked the hostile value");
        assert!(!body.contains("postgres://"), "{uri} leaked a DSN scheme");
        assert!(!body.contains('@'), "{uri} leaked an `@`");
        assert!(
            !body.contains("db.internal.example"),
            "{uri} leaked a hostname"
        );
    }
}

/// One case per row of the HA failure matrix (issue #241, PR 14):
/// each authority-backed condition, fault-injected through the
/// probe's seams, reaches `/readyz` as its own stable reason.
#[tokio::test]
async fn readiness_reports_every_authority_backed_failure_matrix_reason() {
    use ha_status::test_support::{healthy_settings, ScriptedAuthority, ScriptedRevisions};
    use ha_status::{AuthorityObservation, ReadinessProbe, ReadinessProbeSettings};

    let agreed = || {
        let readiness = ha::ClusterReadiness::new();
        readiness.record_fingerprint_agreement();
        readiness
    };
    // (what the deployment looks like, what `/readyz` must answer).
    let cases: Vec<(Arc<ha_status::ReadinessProbe>, Option<&str>)> = vec![
        // The pool cannot be checked out: the database is gone, or
        // every connection is in use past the acquire timeout.
        (
            ReadinessProbe::new(
                agreed(),
                ScriptedAuthority::new(AuthorityObservation::Unavailable),
                None,
                healthy_settings(),
            ),
            Some("storage_unavailable"),
        ),
        // The session reached a standby, or the primary was made
        // read-only: a replica that cannot write cannot serve.
        (
            ReadinessProbe::new(
                agreed(),
                ScriptedAuthority::new(AuthorityObservation::ReadOnly),
                None,
                healthy_settings(),
            ),
            Some("storage_unavailable"),
        ),
        // The ledger no longer covers this binary's manifest.
        (
            ReadinessProbe::new(
                agreed(),
                ScriptedAuthority::healthy(3),
                None,
                healthy_settings(),
            ),
            Some("schema_incompatible"),
        ),
        // The membership heartbeat has not landed inside the stale
        // window, so the roster no longer counts this replica live.
        (
            ReadinessProbe::new(
                agreed(),
                ScriptedAuthority::healthy(9),
                None,
                ReadinessProbeSettings {
                    member_stale_window: Duration::ZERO,
                    ..healthy_settings()
                },
            ),
            Some("instance_lease_invalid"),
        ),
        // The security gate has been failing protected traffic
        // closed past the reconcile deadline.
        (
            ReadinessProbe::new(
                agreed(),
                ScriptedAuthority::healthy(9),
                Some(ScriptedRevisions::refusing_for(Duration::ZERO)),
                ReadinessProbeSettings {
                    revision_reconcile_grace: Duration::ZERO,
                    ..healthy_settings()
                },
            ),
            Some("security_revision_not_compiled"),
        ),
        // Everything the authority can tell us is healthy.
        (
            ReadinessProbe::new(
                agreed(),
                ScriptedAuthority::healthy(9),
                Some(ScriptedRevisions::new(5, 5)),
                healthy_settings(),
            ),
            None,
        ),
    ];

    for (probe, expected) in cases {
        let lifecycle = GatewayLifecycle::new();
        let readiness = agreed();
        let router = cluster_readiness_app(&lifecycle, readiness, Some(probe));
        lifecycle.mark_ready();
        let (status, body) = readyz_answer(&router).await;
        match expected {
            Some(reason) => {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{reason}: {body}");
                assert_eq!(
                    body,
                    format!(r#"{{"status":"not_ready","reason":"{reason}"}}"#),
                    "the probe's reason must reach /readyz verbatim"
                );
            }
            None => {
                assert_eq!(status, StatusCode::OK, "{body}");
                assert_eq!(body, r#"{"status":"ready"}"#);
            }
        }
    }
}

/// The reason chain's order: the lifecycle answers before the
/// fingerprint gate, which answers before the probe. A replica that
/// is draining, disagreeing, *and* cut off from its authority all at
/// once reports the condition an operator has to look at first, and
/// the two pre-existing reasons keep their exact strings.
#[tokio::test]
async fn the_probe_is_consulted_after_the_lifecycle_and_the_fingerprint_gate() {
    use ha_status::test_support::{healthy_settings, ScriptedAuthority};
    use ha_status::{AuthorityObservation, ReadinessProbe};

    let lifecycle = GatewayLifecycle::new();
    let readiness = ha::ClusterReadiness::new();
    let probe = ReadinessProbe::new(
        Arc::clone(&readiness),
        ScriptedAuthority::new(AuthorityObservation::Unavailable),
        None,
        healthy_settings(),
    );
    let router = cluster_readiness_app(&lifecycle, Arc::clone(&readiness), Some(probe));

    // Not serving yet: the lifecycle answers first.
    assert_eq!(
        readyz_answer(&router).await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"status":"not_ready","reason":"starting"}"#.to_owned()
        )
    );

    // Serving, but the fingerprint gate is still closed: PR 13's
    // reason outranks the probe's.
    lifecycle.mark_ready();
    assert_eq!(
        readyz_answer(&router).await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"status":"not_ready","reason":"config_fingerprint_mismatch"}"#.to_owned()
        )
    );

    // Agreed: now the probe's reason is what is left.
    readiness.record_fingerprint_agreement();
    assert_eq!(
        readyz_answer(&router).await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"status":"not_ready","reason":"storage_unavailable"}"#.to_owned()
        )
    );

    // Draining outranks everything below it, probe included.
    assert!(lifecycle.begin_draining());
    assert_eq!(
        readyz_answer(&router).await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"status":"not_ready","reason":"draining"}"#.to_owned()
        )
    );
}

/// Standalone mode has no shared authority, so it builds no probe and
/// `/readyz` answers exactly what it answered before this PR --
/// asserted on the response bytes, not on a parsed field, because
/// orchestrator configurations match on them.
#[tokio::test]
async fn standalone_readiness_is_byte_for_byte_unchanged() {
    let lifecycle = GatewayLifecycle::new();
    let recorder = PrometheusBuilder::new().build_recorder();
    let app = gateway_app_with_process_started_at_and_overrides(
        test_config(Vec::new()),
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
        Instant::now(),
        GatewayAppBuildOverrides {
            lifecycle: Some(lifecycle.clone()),
            disable_proxy_health_checks: true,
            ..GatewayAppBuildOverrides::default()
        },
    )
    .expect("gateway app should build");
    let router = match app.http {
        GatewayApp::Unified(router) => router,
        GatewayApp::Split { .. } => panic!("test app should be unified"),
    };

    assert_eq!(
        readyz_answer(&router).await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"status":"not_ready","reason":"starting"}"#.to_owned()
        )
    );
    lifecycle.mark_ready();
    assert_eq!(
        readyz_answer(&router).await,
        (StatusCode::OK, r#"{"status":"ready"}"#.to_owned())
    );
    assert!(lifecycle.begin_draining());
    assert_eq!(
        readyz_answer(&router).await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            r#"{"status":"not_ready","reason":"draining"}"#.to_owned()
        )
    );
}

// ---------------------------------------------------------------------
// The registry label audit (issue #241, PR 14, section 3)
// ---------------------------------------------------------------------

/// Values that must never become a metric label, one per kind of
/// caller-influenced or deployment-identifying string the issue names.
/// Each is distinctive enough that a substring search over the whole
/// render is a real test rather than a coincidence.
const CANARY_INSTANCE_ID: &str = "3f8c1d2e-9b47-4a6f-8e51-c07d2b93a4e6";

const CANARY_PRINCIPAL: &str = "canary-principal-7d31@example.test";

const CANARY_ROUTE: &str = "/canary-route-3f9a/orders/9182";

const CANARY_HOST: &str = "canary-host-9d27.example.test";

const CANARY_URL: &str = "postgres://canary-user:canary-pass@10.11.12.13:5432/canary-db";

const CANARY_TOKEN_ID: &str = "tok_canary_5b2e_never_a_label";

const CANARY_QUERY: &str = "secret=canary-query-8c41";

const CANARY_ERROR: &str =
    "FATAL: password authentication failed for user \"canary-user\" at 10.11.12.13";

const CANARIES: [(&str, &str); 8] = [
    ("an instance id", CANARY_INSTANCE_ID),
    ("a principal", CANARY_PRINCIPAL),
    ("a proxied route", CANARY_ROUTE),
    ("a host", CANARY_HOST),
    ("a URL", CANARY_URL),
    ("a token id", CANARY_TOKEN_ID),
    ("a query string", CANARY_QUERY),
    ("an error string", CANARY_ERROR),
];

/// The only label *names* an HA metric may carry. The exporter adds
/// `quantile` to summaries itself, so it is allowed here without being
/// something the gateway chose.
const ALLOWED_HA_LABEL_NAMES: [&str; 10] = [
    "job",
    "outcome",
    "task",
    "kind",
    "reason",
    "scope",
    "operation",
    "operation_class",
    "error_class",
    "quantile",
];

/// Every metric name section 3 adds. Asserting each one is present
/// keeps the audit from passing vacuously against a render that
/// happens to contain nothing.
fn expected_ha_metric_names() -> Vec<&'static str> {
    // A `--no-default-features` build has no cluster metrics to add,
    // so the list below is already complete there.
    #[cfg_attr(not(feature = "postgres"), allow(unused_mut))]
    let mut names = vec![
        metrics::GATEWAY_READY,
        metrics::GATEWAY_DRAINING,
        metrics::INFLIGHT_REQUESTS,
        metrics::AUDIT_QUEUE_DEPTH,
        metrics::AUDIT_QUEUE_CAPACITY,
        metrics::AUDIT_QUEUE_OLDEST_AGE_SECONDS,
        metrics::AUDIT_FLUSH_TOTAL,
        metrics::AUDIT_DURABILITY_REFUSALS_TOTAL,
        metrics::EXECUTION_LEASE_FAILURES_TOTAL,
    ];
    #[cfg(feature = "postgres")]
    names.extend_from_slice(&[
        metrics::SCHEMA_COMPATIBLE,
        metrics::MIGRATION_LOCK_WAIT_SECONDS,
        metrics::DATABASE_POOL_SIZE,
        metrics::DATABASE_POOL_AVAILABLE,
        metrics::DATABASE_POOL_WAITING,
        metrics::DATABASE_POOL_TIMEOUTS_TOTAL,
        metrics::DATABASE_POOL_ACQUIRE_SECONDS,
        metrics::DATABASE_OPERATION_SECONDS,
        metrics::SECURITY_REVISION_COMPILED,
        metrics::SECURITY_REVISION_CURRENT,
        metrics::SECURITY_REVISION_LAG,
        metrics::RECONCILE_FAILURES_TOTAL,
        metrics::CLUSTER_HEARTBEAT_AGE_SECONDS,
        metrics::CLUSTER_CONFIG_MISMATCH,
        metrics::CLUSTER_LEASE_AGE_SECONDS,
        metrics::LEADER_TASK_LAST_SUCCESS_AGE_SECONDS,
        metrics::DISCOVERY_PROJECTOR_CHECKPOINT,
        metrics::DISCOVERY_PROJECTOR_LAG_EVENTS,
        metrics::DISCOVERY_PROJECTOR_ERRORS_TOTAL,
        metrics::AUDIT_STREAM_CONNECTIONS_TOTAL,
        metrics::AUDIT_STREAM_REPLAY_BACKLOG_EVENTS,
        metrics::AUDIT_STREAM_DUPLICATE_POSITIONS_TOTAL,
        metrics::AUTHORITY_EVENT_JOURNAL_RETAINED,
        metrics::AUTHORITY_EVENT_JOURNAL_CAPACITY,
        metrics::AUTHORITY_EVENT_UNDELIVERED,
        metrics::AUTHORITY_EVENT_OLDEST_UNDELIVERED_AGE_SECONDS,
        metrics::AUTHORITY_EVENT_DELIVERED_TOTAL,
        metrics::AUTHORITY_EVENT_DELIVERY_FAILURES_TOTAL,
        metrics::AUTHORITY_EVENT_CAPACITY_REFUSALS_TOTAL,
        metrics::AUTHORITY_EVENT_EVIDENCE_FAILURES_TOTAL,
    ]);
    names
}

/// The declared vocabulary of every labelled HA metric: a label value
/// outside its family's list is a cardinality leak, whatever it says.
fn ha_label_vocabularies() -> Vec<(&'static str, &'static str, Vec<&'static str>)> {
    #[cfg_attr(not(feature = "postgres"), allow(unused_mut))]
    let mut rules: Vec<(&'static str, &'static str, Vec<&'static str>)> = vec![
        (
            metrics::AUDIT_FLUSH_TOTAL,
            "outcome",
            audit::AUDIT_FLUSH_OUTCOMES.to_vec(),
        ),
        (
            metrics::AUDIT_DURABILITY_REFUSALS_TOTAL,
            "reason",
            audit::durable::AUDIT_DURABILITY_REFUSAL_REASONS.to_vec(),
        ),
        (
            metrics::EXECUTION_LEASE_FAILURES_TOTAL,
            "kind",
            tools::lease::LEASE_FAILURE_KINDS.to_vec(),
        ),
    ];
    #[cfg(feature = "postgres")]
    rules.extend([
        (
            metrics::RECONCILE_FAILURES_TOTAL,
            "reason",
            vec![
                middleware::rbac::SecurityRevisionCheckError::Unavailable.as_str(),
                middleware::rbac::SecurityRevisionCheckError::ReconcileDeadlineExceeded.as_str(),
                middleware::rbac::SecurityRevisionCheckError::InvalidDocument.as_str(),
            ],
        ),
        (
            metrics::CLUSTER_LEASE_AGE_SECONDS,
            "scope",
            tools::lease::LEASE_SCOPE_LABELS.to_vec(),
        ),
        (
            metrics::LEADER_TASK_LAST_SUCCESS_AGE_SECONDS,
            "task",
            cluster_maintenance::JOB_NAMES.to_vec(),
        ),
        (
            metrics::DISCOVERY_PROJECTOR_ERRORS_TOTAL,
            "kind",
            discovery::projector::PROJECTOR_ERROR_KINDS.to_vec(),
        ),
        (
            metrics::AUTHORITY_EVENT_DELIVERY_FAILURES_TOTAL,
            "kind",
            authority_events::dispatcher::FAILURE_KINDS.to_vec(),
        ),
        (
            metrics::AUDIT_STREAM_CONNECTIONS_TOTAL,
            "outcome",
            AUDIT_STREAM_OUTCOMES.to_vec(),
        ),
        (
            metrics::CLUSTER_MAINTENANCE_JOB_RUNS_TOTAL,
            "job",
            cluster_maintenance::JOB_NAMES.to_vec(),
        ),
        // `error_class` is the one label on this surface whose value
        // is chosen at runtime rather than passed in as a `&'static
        // str`, so the type system is not the guard here and the
        // vocabulary has to be declared. It is the classifier's
        // *label* spelling plus the success sentinel -- deliberately
        // not `as_str()`, whose spellings are the ones stored in
        // member and job rows and carry spaces.
        (
            metrics::DATABASE_OPERATION_SECONDS,
            "error_class",
            storage::RepositoryErrorKind::KNOWN
                .iter()
                .map(|kind| kind.metric_label())
                .chain(std::iter::once(
                    storage::postgres::OPERATION_ERROR_CLASS_NONE,
                ))
                .collect(),
        ),
        // The acquisition histogram's two labels are both runtime
        // values -- the class a store names, and the kind a failed
        // checkout was classified as or `cancelled` for one its caller
        // abandoned -- so both are declared (issue #439). Neither list
        // depends on anything a request carries.
        (
            metrics::DATABASE_POOL_ACQUIRE_SECONDS,
            "operation_class",
            storage::postgres::CheckoutClass::KNOWN
                .iter()
                .map(|class| class.metric_label())
                .collect(),
        ),
        (
            metrics::DATABASE_POOL_ACQUIRE_SECONDS,
            "error_class",
            storage::postgres::pool_acquire_error_classes(),
        ),
    ]);
    rules
}

/// Whether `value` looks like a dotted quad, which is how an address
/// gets into a label that was only ever meant to hold a version.
fn looks_like_an_address(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Whether `value` looks like a UUID, which is how an instance id or a
/// boot id gets into a label.
fn looks_like_a_uuid(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    groups.len() == 5
        && [8, 4, 4, 4, 12].iter().zip(&groups).all(|(width, group)| {
            group.len() == *width && group.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

/// Record one pool checkout per class and outcome through the real
/// emitters: the success sentinel, every classified kind, and a wait the
/// caller abandoned.
#[cfg(feature = "postgres")]
fn record_every_pool_acquisition() {
    for class in storage::postgres::CheckoutClass::KNOWN {
        storage::postgres::observe_pool_acquire(class, Duration::from_micros(400), None);
        for kind in storage::RepositoryErrorKind::KNOWN {
            storage::postgres::observe_pool_acquire(class, Duration::from_millis(50), Some(kind));
        }
        storage::postgres::observe_cancelled_pool_acquire(class, Duration::from_millis(250));
    }
}

/// Drive every HA metric this PR adds, with every canary in the
/// process while it happens.
///
/// The request leg is a real one through a real router carrying the
/// hostile host, path, query and bearer token, so the request path's
/// own metrics are recorded against exactly the input an attacker
/// controls. The rest calls the production emitters directly -- the
/// same functions the heartbeat task, the reconciler, the projector
/// and the maintenance leader call -- because standing up a cluster
/// would prove nothing extra about the labels they pass.
async fn synthetic_ha_run() {
    let lifecycle = GatewayLifecycle::new();
    let recorder = PrometheusBuilder::new().build_recorder();
    let app = gateway_app_with_process_started_at_and_overrides(
        test_config(Vec::new()),
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
        Instant::now(),
        GatewayAppBuildOverrides {
            lifecycle: Some(lifecycle.clone()),
            disable_proxy_health_checks: true,
            ..GatewayAppBuildOverrides::default()
        },
    )
    .expect("gateway app should build");
    let router = match app.http {
        GatewayApp::Unified(router) => router,
        GatewayApp::Split { .. } => panic!("test app should be unified"),
    };
    lifecycle.mark_ready();

    // A hostile request: the route, the host, the query and the token
    // are all caller-chosen, and all four are on the wire together.
    let hostile = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("{CANARY_ROUTE}?{CANARY_QUERY}"))
                .header(header::HOST, CANARY_HOST)
                .header(header::AUTHORIZATION, format!("Bearer {CANARY_TOKEN_ID}"))
                .header("x-forwarded-for", "10.11.12.13")
                .body(Body::empty())
                .expect("hostile request should build"),
        )
        .await
        .expect("hostile request should complete");
    // What it answered does not matter; that it was *observed* does.
    let _ = hostile.status();

    // The same hostile request against a gateway that requires durable
    // audit and whose store of record refuses every record (issue #425):
    // it is refused `503`, and the refusal counter it moves must carry
    // nothing of it but a fixed reason.
    let refusing_store = audit::sink::tests::DurableCaptureSink::new();
    refusing_store.set(audit::sink::tests::DurableBehaviour::Refuse);
    let required_app = gateway_app_with_process_started_at_and_overrides(
        test_config(Vec::new()),
        recorder.handle(),
        audit::AuditLog::new_required(
            Arc::new(refusing_store) as Arc<dyn audit::AuditSink>,
            Duration::from_secs(5),
        ),
        test_audit_event_sender(),
        Instant::now(),
        GatewayAppBuildOverrides {
            disable_proxy_health_checks: true,
            ..GatewayAppBuildOverrides::default()
        },
    )
    .expect("required-durability gateway app should build");
    let required_router = match required_app.http {
        GatewayApp::Unified(router) => router,
        GatewayApp::Split { .. } => panic!("test app should be unified"),
    };
    let refused = required_router
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("{CANARY_ROUTE}?{CANARY_QUERY}"))
                .header(header::HOST, CANARY_HOST)
                .header(header::AUTHORIZATION, format!("Bearer {CANARY_TOKEN_ID}"))
                .header("x-forwarded-for", "10.11.12.13")
                .body(Body::empty())
                .expect("hostile request should build"),
        )
        .await
        .expect("hostile request should complete");
    assert_eq!(
        refused.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a decision record the store refuses must refuse the request"
    );

    // A scrape, which is what publishes the sampled gauges.
    let scrape = router
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/metrics")
                .body(Body::empty())
                .expect("scrape request should build"),
        )
        .await
        .expect("scrape should complete");
    assert_eq!(scrape.status(), StatusCode::OK);

    lifecycle.begin_draining();

    // The audit writer's queue and its flushes.
    audit::record_queue_gauges(3, 8192, Duration::from_millis(250));
    audit::record_flush_outcome(true);
    audit::record_flush_outcome(false);

    // Execution leases: every failure kind, none of them carrying the
    // scope (which is `tool:<name>` and would be a series per tool).
    for kind in tools::lease::LEASE_FAILURE_KINDS {
        tools::lease::record_lease_failure(kind);
    }

    #[cfg(feature = "postgres")]
    {
        storage::migrations::record_schema_compatible(false);
        storage::migrations::record_schema_compatible(true);
        storage::migrations::record_migration_lock_wait(Duration::from_millis(120));

        storage::postgres::record_pool_gauges(10, 2, 1);
        storage::postgres::record_pool_timeout();
        // One store operation per classified outcome, including the
        // success class, so the family can be summed across both.
        storage::postgres::observe_operation(
            storage::postgres::OPERATION_CONNECTIVITY_CHECK,
            Duration::from_millis(4),
            None,
        );
        for kind in storage::RepositoryErrorKind::KNOWN {
            storage::postgres::observe_operation(
                storage::postgres::OPERATION_CONNECTIVITY_CHECK,
                Duration::from_millis(9),
                Some(kind),
            );
        }
        // Every checkout class under every outcome a checkout can be
        // classified as (issue #439): the acquisition family's whole
        // label space, so the bound below is checked against all of it
        // rather than against whichever classes a test happened to touch.
        record_every_pool_acquisition();

        security_cluster::record_revision_gauges(41, 44);
        for reason in [
            middleware::rbac::SecurityRevisionCheckError::Unavailable,
            middleware::rbac::SecurityRevisionCheckError::ReconcileDeadlineExceeded,
            middleware::rbac::SecurityRevisionCheckError::InvalidDocument,
        ] {
            security_cluster::record_reconcile_failure(reason);
        }

        cluster_membership::record_membership_gauges(Duration::from_secs(7), false);
        for scope in tools::lease::LEASE_SCOPE_LABELS {
            tools::lease::record_lease_age(scope, Duration::from_secs(93));
        }

        // The ledger's `job` column is database data. A row naming a
        // job this binary does not run must produce no series at all,
        // and a canary in that column is the adversarial case.
        assert!(
            cluster_maintenance::known_job_name(CANARY_ROUTE).is_none(),
            "an unrecognised ledger job name must never be turned into a label"
        );
        for job in cluster_maintenance::JOB_NAMES {
            let name = cluster_maintenance::known_job_name(job)
                .expect("every job this binary runs is recognised by name");
            cluster_maintenance::record_leader_task_age(name, 61.5);
        }

        discovery::projector::record_projector_progress(1_204, 1_311);
        for kind in discovery::projector::PROJECTOR_ERROR_KINDS {
            discovery::projector::record_projector_error(kind);
        }

        for outcome in AUDIT_STREAM_OUTCOMES {
            record_audit_stream_outcome(outcome);
        }
        record_audit_stream_replay_backlog(512);
        record_audit_stream_duplicates(1);

        // Authority-event delivery: the journal gauges, every failure step,
        // a delivered batch and both kinds of refused mutation. None names
        // an event, an actor, a resource or a position.
        authority_events::dispatcher::record_journal_stats(
            &storage::postgres_authority_events::JournalStats {
                retained: 7,
                capacity: 1_000_000,
                head: 41,
                cursor: Some(38),
                first_retained: Some(35),
                oldest_undelivered_age_secs: Some(12.5),
            },
        );
        for kind in authority_events::dispatcher::FAILURE_KINDS {
            authority_events::dispatcher::record_failure(kind);
        }
        authority_events::dispatcher::record_delivered(3);
        storage::postgres_authority_events::record_capacity_refusal();
        storage::postgres_authority_events::record_evidence_failure();
    }
}

/// Section 3's cardinality rule, enforced rather than documented.
///
/// A metric label is unbounded state the process keeps for the life of
/// the registry and hands to every scrape, so a label value derived
/// from an instance id, a principal, a proxied route, a host, a URL, a
/// token id, a query or an error string is two defects at once: a
/// cardinality bomb a caller can detonate, and a disclosure on an
/// endpoint that is routinely less protected than the admin API.
///
/// The test walks the rendered registry after a synthetic run that
/// drives every HA emitter *and* a real request carrying all eight
/// canaries, and asserts three things: no canary appears anywhere in
/// the render; no label value anywhere has the shape of an address, a
/// UUID, a URL, or an email; and every HA metric's labels come from
/// its declared, compile-time vocabulary.
#[test]
fn the_ha_metric_registry_never_labels_by_a_caller_influenced_value() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    // A current-thread runtime inside the local-recorder scope: the
    // recorder is installed per thread, and a current-thread runtime
    // polls every task it owns on this one, so the synthetic run's
    // emissions land in this registry rather than the global one.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime should build");
    ::metrics::with_local_recorder(&recorder, || {
        runtime.block_on(synthetic_ha_run());
    });
    let rendered = handle.render();

    // 1. Not vacuous: every metric section 3 adds is actually here.
    for name in expected_ha_metric_names() {
        assert!(
            rendered
                .lines()
                .any(|line| rendered_metric_name(line) == name),
            "the audit is only meaningful if {name} was recorded:\n{rendered}"
        );
    }

    // 1b. The in-flight gauge exists *because* the hostile request
    //     passed through the observation layer, and it is back at zero
    //     because the guard took its increment back down. A gauge that
    //     only climbs is the failure this guard exists to prevent, and
    //     it would be invisible without asserting the resting value.
    assert!(
        rendered
            .lines()
            .any(|line| line == format!("{} 0", metrics::INFLIGHT_REQUESTS)),
        "the in-flight gauge must return to zero once every request has left:\n{rendered}"
    );

    // 2. No canary reached the registry at all -- not as a label, not
    //    as a metric name, not in a comment.
    for (what, canary) in CANARIES {
        assert!(
            !rendered.contains(canary),
            "{what} must never reach the metrics registry ({canary}):\n{rendered}"
        );
    }

    // 3. No label value anywhere has the shape of something
    //    caller-influenced, whatever metric it is on.
    for line in rendered.lines().filter(|line| !line.starts_with('#')) {
        for (label, value) in rendered_labels(line) {
            assert!(
                !value.contains('@') && !value.contains("://"),
                "a label value that is a URL or an address is never allowed: {line}"
            );
            assert!(
                !looks_like_an_address(&value),
                "a label value shaped like an IP address is never allowed: {line}"
            );
            assert!(
                !looks_like_a_uuid(&value),
                "an instance or boot id must never be a label: {line}"
            );
            assert!(
                value.len() <= 64,
                "a label value longer than any enum member is unbounded text: {line}"
            );
            assert!(
                !label.is_empty(),
                "a rendered label must have a name: {line}"
            );
        }
    }

    // 4. Every HA metric's labels come from its declared vocabulary.
    let vocabularies = ha_label_vocabularies();
    for line in rendered
        .lines()
        .filter(|line| !line.starts_with('#') && line.starts_with("greengateway_"))
    {
        let name = rendered_metric_name(line);
        for (label, value) in rendered_labels(line) {
            assert!(
                ALLOWED_HA_LABEL_NAMES.contains(&label.as_str()),
                "{name} carries an undeclared label name {label}: {line}"
            );
            if let Some((_, _, vocabulary)) = vocabularies
                .iter()
                .find(|(metric, declared, _)| *metric == name && *declared == label)
            {
                assert!(
                    vocabulary.contains(&value.as_str()),
                    "{name}'s {label} label must come from its fixed vocabulary \
                         {vocabulary:?}, not {value:?}: {line}"
                );
            }
        }
    }
}

/// Every counter series a single-event alert reads is exported at `0`
/// right after the recorder is installed, so the first event after a
/// process start moves it `0 -> 1` and `increase(...[5m]) > 0` sees it.
///
/// A series that first appears at `1` has no earlier sample to compare
/// against, so before this a single refused authority change after a
/// restart never paged (issue #440 review). The registry is built and
/// registered exactly as `install_metrics_recorder` does, minus making it
/// process-global. Each family exports exactly its emitters' vocabulary,
/// cluster-only series only in cluster mode, and the dispatcher's failure
/// counter stays lazy because its presence marks a configured sink.
#[test]
fn single_event_alert_counters_are_exported_at_zero_right_after_install() {
    for cluster in [false, true] {
        let recorder = metrics_recorder_builder().build_recorder();
        let handle = recorder.handle();
        ::metrics::with_local_recorder(&recorder, || register_metrics(cluster));
        let rendered = handle.render();
        let samples: Vec<&str> = rendered
            .lines()
            .filter(|line| !line.starts_with('#'))
            .collect();
        let family = |name: &str| {
            samples
                .iter()
                .copied()
                .filter(|line| rendered_metric_name(line) == name)
                .collect::<Vec<&str>>()
        };
        let cluster_seeded = cluster && cfg!(feature = "postgres");

        let mut drop_reasons = audit::LOCAL_DROP_REASONS.to_vec();
        if cluster_seeded {
            drop_reasons.push("postgres");
        }
        let mut drops = family("audit_events_dropped_total");
        drops.sort_unstable();
        let mut expected_drops: Vec<String> = drop_reasons
            .iter()
            .map(|reason| format!("audit_events_dropped_total{{reason=\"{reason}\"}} 0"))
            .collect();
        expected_drops.sort_unstable();
        assert_eq!(drops, expected_drops, "cluster={cluster}:\n{rendered}");
        assert_eq!(
            family("greengateway_audit_flush_total"),
            ["greengateway_audit_flush_total{outcome=\"failure\"} 0"],
            "cluster={cluster}:\n{rendered}"
        );
        // Both modes, and whatever AUDIT_DURABILITY says: a refusal needs
        // only an audit store of record, which standalone mode has too.
        let mut refusals = family("greengateway_audit_durability_refusals_total");
        refusals.sort_unstable();
        let mut expected_refusals: Vec<String> = audit::durable::AUDIT_DURABILITY_REFUSAL_REASONS
            .iter()
            .map(|reason| {
                format!("greengateway_audit_durability_refusals_total{{reason=\"{reason}\"}} 0")
            })
            .collect();
        expected_refusals.sort_unstable();
        assert_eq!(
            refusals, expected_refusals,
            "cluster={cluster}:\n{rendered}"
        );

        for name in [
            "greengateway_database_pool_timeouts_total",
            "greengateway_authority_event_capacity_refusals_total",
            "greengateway_authority_event_evidence_failures_total",
        ] {
            let expected = if cluster_seeded {
                vec![format!("{name} 0")]
            } else {
                Vec::new()
            };
            assert_eq!(family(name), expected, "cluster={cluster}:\n{rendered}");
        }
        assert!(
            family("greengateway_authority_event_delivery_failures_total").is_empty(),
            "a seeded dispatcher failure series would mark every replica as having a sink:\n{rendered}"
        );
    }
}

/// The pool-acquisition histogram's series are the product of two fixed
/// lists and nothing more (issue #439).
///
/// The registry audit above proves each label value comes *from* a
/// declared vocabulary; this proves the family cannot grow past it. The
/// synthetic run records every class under every outcome -- success,
/// each classified kind and `cancelled`, the whole space -- with the
/// hostile request in flight, and the space is then recorded a second
/// time: a label minted from anything a caller sent, or from anything
/// that varies between checkouts, would be one series too many. Today
/// that is seven classes by eight outcomes. The class list is held small
/// on purpose, because it is the multiplier.
#[cfg(feature = "postgres")]
#[test]
fn the_pool_acquisition_series_are_bounded_by_two_fixed_vocabularies() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime should build");
    ::metrics::with_local_recorder(&recorder, || {
        runtime.block_on(synthetic_ha_run());
        record_every_pool_acquisition();
    });
    let rendered = handle.render();

    let classes: Vec<&str> = storage::postgres::CheckoutClass::KNOWN
        .iter()
        .map(|class| class.metric_label())
        .collect();
    let outcomes = storage::postgres::pool_acquire_error_classes();
    assert!(
        outcomes.contains(&storage::postgres::CHECKOUT_ERROR_CLASS_CANCELLED),
        "an abandoned checkout is an outcome of the family, not a missing sample"
    );
    assert!(
        classes.len() <= 8,
        "the operation-class list multiplies every outcome; keep it a short fixed list: \
         {classes:?}"
    );

    let mut series = std::collections::BTreeSet::new();
    for line in rendered.lines().filter(|line| !line.starts_with('#')) {
        // The summary's quantile lines and its `_sum` and `_count`
        // lines all belong to the family.
        if !rendered_metric_name(line).starts_with(metrics::DATABASE_POOL_ACQUIRE_SECONDS) {
            continue;
        }
        for (what, canary) in CANARIES {
            assert!(
                !line.contains(canary),
                "{what} must never reach the acquisition series: {line}"
            );
        }
        let labels: std::collections::BTreeMap<String, String> = rendered_labels(line)
            .into_iter()
            .filter(|(label, _)| label != "quantile")
            .collect();
        assert_eq!(
            labels.keys().map(String::as_str).collect::<Vec<_>>(),
            ["error_class", "operation_class"],
            "the acquisition series carries exactly its two declared labels: {line}"
        );
        assert!(
            classes.contains(&labels["operation_class"].as_str()),
            "operation_class must be a fixed class: {line}"
        );
        assert!(
            outcomes.contains(&labels["error_class"].as_str()),
            "error_class must be a classified kind, none or cancelled: {line}"
        );
        series.insert((
            labels["operation_class"].clone(),
            labels["error_class"].clone(),
        ));
    }
    assert_eq!(
        series.len(),
        classes.len() * outcomes.len(),
        "every class under every outcome, and not one series more:\n{rendered}"
    );
}
