//! Caller keys on the policy, tools and policy test changes (issue #425,
//! plan PR 9), end to end through the admin API. The family is PostgreSQL
//! only: cluster mode binds a key in the document commit's transaction,
//! standalone mode refuses one before anything is read (#242).
use super::*;

fn caller_key(seed: u8) -> String {
    crate::authority_events::caller_operation::test_caller_key(seed).to_string()
}

/// A keyed policy change on a standalone gateway is refused with `400
/// standalone_caller_key_unsupported` before anything is read or written: the
/// standalone policy file records no caller key, so the key is refused,
/// never ignored. The unkeyed form still commits.
#[tokio::test]
async fn a_keyed_standalone_policy_change_is_refused_and_writes_nothing() {
    let policy = TempPolicyFile::new(&policy_document_with_rules_string("standalone", json!([])));
    let router = policy_admin_router(Some(&policy), test_audit_log());
    let (etag, _) = current_policy(&router).await;
    let before = fs::read_to_string(&policy.path).unwrap();
    let mut request = policy_admin_request(
        Method::PUT,
        POLICY_ADMIN_ROUTE,
        Some(test_principal(&["admin"])),
        Some(policy_document_with_rules_string(
            "standalone-keyed",
            json!([]),
        )),
        Some(&etag),
    );
    request
        .headers_mut()
        .insert("idempotency-key", caller_key(1).parse().unwrap());
    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = json_body(response).await;
    assert_eq!(
        body["reason"],
        json!(STANDALONE_CALLER_KEY_UNSUPPORTED_REASON),
        "{body}"
    );
    assert_eq!(fs::read_to_string(&policy.path).unwrap(), before);

    let response = router
        .clone()
        .oneshot(policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
            Some(policy_document_with_rules_string(
                "standalone-unkeyed",
                json!([]),
            )),
            Some(&etag),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[cfg(feature = "postgres")]
mod cluster_document_keys {
    use super::*;
    use storage::postgres::test_support::{locator, test_pool, test_settings};
    use storage::{MemberRegistration, PolicyControlPlane, PostgresMembershipStore};

    const CLUSTER_ISSUER: &str = "https://cluster-document-keys.example.test";
    const DEPLOYMENT: &str = "deploy-cluster-document-keys";

    /// The policy every replica starts from: `policy-admin` may do
    /// anything, `policy-reader` only read the policy, and the HTTP layer
    /// allows every route, so each `403` below is the handler's own check.
    fn cluster_policy(id: &str) -> Value {
        json!({
            "schema_version": "0.1.0",
            "id": id,
            "default_action": "allow",
            "enforcement_mode": "enforce",
            "roles": {
                "policy-admin": { "permissions": ["*"] },
                "policy-reader": { "permissions": [ADMIN_POLICY_READ_PERMISSION] }
            },
            "routes": [],
            "rules": [
                { "id": "first", "path": "/first", "action": "allow" },
                { "id": "second", "path": "/second", "action": "deny" }
            ]
        })
    }

    fn suite_document() -> String {
        json!({
            "schema_version": "policy-tests.v1",
            "cases": [{
                "id": "anonymous-is-allowed",
                "kind": "http",
                "request": { "method": "GET", "path": "/elsewhere" },
                "principal": "anonymous",
                "expect": { "logical": "allow" }
            }]
        })
        .to_string()
    }

    /// A cluster replica over the migrated `pool` whose operation gate asks
    /// `membership`, auditing to `audit_log`.
    async fn replica(
        config: config::Config,
        pool: &deadpool_postgres::Pool,
        membership: Arc<cluster_membership::ClusterMembership>,
        audit_log: audit::AuditLog,
    ) -> Router {
        let policy = Arc::new(storage::PostgresPolicyStore::new(pool.clone()));
        let tools = Arc::new(storage::PostgresToolStore::new(pool.clone()));
        let app = gateway_app_with_process_started_at_and_overrides(
            config,
            PrometheusBuilder::new().build_recorder().handle(),
            audit_log,
            test_audit_event_sender(),
            Instant::now(),
            GatewayAppBuildOverrides {
                pg_policy: Some(ClusterPolicySeed {
                    active: policy.active().await.unwrap().unwrap(),
                    store: policy,
                }),
                pg_tools: Some(ClusterToolsSeed {
                    active: storage::ToolControlPlane::active_tools(&*tools)
                        .await
                        .unwrap()
                        .unwrap(),
                    store: tools,
                }),
                pg_membership: Some(membership),
                disable_proxy_health_checks: true,
                ..Default::default()
            },
        )
        .unwrap();
        match app.http {
            GatewayApp::Unified(router) => router,
            GatewayApp::Split { .. } => panic!("expected a unified test router"),
        }
    }

    /// A migrated throwaway database with the cluster policy, an empty tools
    /// document and room in the journal; `None` without a test database.
    async fn database() -> Option<(
        storage::contract_tests::postgres_audit_tests::TestDatabase,
        storage::postgres::PostgresFoundation,
    )> {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return None;
        };
        let database =
            storage::contract_tests::postgres_audit_tests::create_test_database(&admin_dsn).await;
        let foundation = test_pool(&database.dsn).await;
        let pool = foundation.pool();
        storage::migrations::apply_missing_for_startup(pool, &test_settings())
            .await
            .unwrap();
        storage::postgres_authority_events::PostgresAuthorityEventStore::new(pool.clone())
            .configure_capacity(1000)
            .await
            .unwrap();
        let policy = rbac::Policy::validate_json_value(cluster_policy("cluster-keys")).unwrap();
        storage::PostgresPolicyStore::new(pool.clone())
            .commit(storage::PolicyCommitRequest {
                precondition: storage::PolicyCommitPrecondition::Initialize,
                candidate: &policy,
                change: storage::DocumentChange::test_policy("installer"),
                diff_summary: &json!({}),
            })
            .await
            .unwrap();
        Some((database, foundation))
    }

    /// A replica with `earlier`, a second live member built before caller
    /// keys, when `with_earlier` is set: the router and that member's ID.
    async fn keyed_replica(
        pool: &deadpool_postgres::Pool,
        with_earlier: bool,
        audit_log: audit::AuditLog,
        configure: impl FnOnce(&mut config::Config),
    ) -> (Router, uuid::Uuid) {
        storage::PostgresToolStore::new(pool.clone())
            .seed_empty_document()
            .await
            .unwrap();
        let membership = cluster_membership::ClusterMembership::new(
            PostgresMembershipStore::new(
                pool.clone(),
                DEPLOYMENT,
                crate::ha::InstanceIdentity::generate(),
            ),
            MemberRegistration {
                binary_version: env!("CARGO_PKG_VERSION").to_owned(),
                schema_version: storage::migrations::schema_version_range(),
                document_version: cluster_membership::DOCUMENT_VERSION_RANGE,
                fingerprint: "b".repeat(64),
                capabilities: storage::compatibility::BINARY_CAPABILITIES.to_vec(),
            },
            Duration::from_secs(1),
            Duration::from_secs(30),
        );
        membership.register_boot().await.expect("boot row");
        let earlier = uuid::Uuid::new_v4();
        if with_earlier {
            pool.get()
                .await
                .unwrap()
                .execute(
                    "INSERT INTO greengateway.cluster_members
                     (deployment_id, instance_id, boot_id, binary_version,
                      schema_version_min, schema_version_max,
                      document_version_min, document_version_max, fingerprint,
                      capabilities)
                 VALUES ($1, $2::text::uuid, $3::text::uuid, '1.0.1', 18, 18, 0, 0,
                         repeat('b', 64), 'operation_requirements,policy_role_descriptions')",
                    &[
                        &DEPLOYMENT,
                        &earlier.to_string(),
                        &uuid::Uuid::new_v4().to_string(),
                    ],
                )
                .await
                .expect("an earlier member row inserts");
        }
        let mut config = test_config(Vec::new());
        config.state_backend = config::StateBackend::Postgres;
        config.deployment_id = Some(DEPLOYMENT.into());
        configure_test_jwt_provider(&mut config, spawn_test_jwks_server().await);
        config.auth_providers[0].issuer = Some(CLUSTER_ISSUER.into());
        config.egress_allowed_hosts = vec!["127.0.0.1".into()];
        config.egress_deny_private_ips = false;
        config.rate_limit_write_burst = 1000;
        config.rate_limit_write_rps = 1000.0;
        configure(&mut config);
        (replica(config, pool, membership, audit_log).await, earlier)
    }

    async fn stale(pool: &deadpool_postgres::Pool, instance: uuid::Uuid) {
        let updated = pool
            .get()
            .await
            .unwrap()
            .execute(
                "UPDATE greengateway.cluster_members
                 SET last_heartbeat_at = now() - make_interval(secs => 60)
                 WHERE instance_id = $1::text::uuid",
                &[&instance.to_string()],
            )
            .await
            .unwrap();
        assert_eq!(updated, 1);
    }

    /// One admin request with a bearer token, extra headers and an optional
    /// caller key: its status, headers and JSON body.
    async fn call(
        router: &Router,
        method: Method,
        uri: &str,
        token: &str,
        body: Option<String>,
        headers: &[(&str, &str)],
        key: Option<&str>,
    ) -> (StatusCode, HeaderMap, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json");
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        if let Some(key) = key {
            builder = builder.header("idempotency-key", key);
        }
        let request = builder.body(Body::from(body.unwrap_or_default())).unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, headers, body)
    }

    async fn policy_etag(router: &Router, token: &str) -> String {
        let (status, headers, body) = call(
            router,
            Method::GET,
            POLICY_ADMIN_ROUTE,
            token,
            None,
            &[],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        headers[header::ETAG].to_str().unwrap().to_owned()
    }

    /// Every caller-key reservation of a document action, by key.
    async fn document_reservations(pool: &deadpool_postgres::Pool) -> Vec<(String, String)> {
        pool.get()
            .await
            .unwrap()
            .query(
                "SELECT operation_id::text, action FROM greengateway.authority_caller_operation_ids \
                 WHERE action LIKE 'policy%' OR action LIKE 'tools.%' ORDER BY operation_id",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect()
    }

    async fn document_evidence_count(pool: &deadpool_postgres::Pool) -> i64 {
        pool.get()
            .await
            .unwrap()
            .query_one(
                "SELECT count(*) FROM greengateway.document_change_evidence",
                &[],
            )
            .await
            .unwrap()
            .get(0)
    }

    fn events_of(capture: &audit::sink::tests::CaptureSink, event_type: &str) -> usize {
        capture
            .events()
            .into_iter()
            .filter(|event| event.event_type == event_type)
            .count()
    }

    fn assert_receipt(receipt: &Value, key: &str, operation: &str, resource: &str) {
        assert_eq!(receipt["operation_id"], json!(key), "{receipt}");
        assert_eq!(receipt["operation"], json!(operation), "{receipt}");
        assert_eq!(receipt["resource_id"], json!(resource), "{receipt}");
        assert!(receipt["revision"].as_u64().is_some(), "{receipt}");
        assert!(receipt["committed_at"].is_string(), "{receipt}");
    }

    /// The keyed policy routes in cluster mode, end to end: while a live
    /// member lacks `caller_operation_keys` a keyed change is `409
    /// capability_not_advertised`, changes nothing and reserves nothing,
    /// and the unkeyed form still commits; once that member is stale, a
    /// keyed request from a caller without the route's permission is `403`
    /// and a malformed keyed request `400`, and the contract fence is
    /// unchanged byte for byte: authorization and validation come before
    /// admission. The first authorized keyed change then raises the fence.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_keyed_policy_change_is_refused_while_a_live_member_lacks_the_capability() {
        let Some((_database, foundation)) = database().await else {
            return;
        };
        let pool = foundation.pool();
        let (router, earlier) = keyed_replica(pool, true, test_audit_log(), |_| {}).await;
        let admin = signed_token_with_issuer("operator", &["policy-admin"], CLUSTER_ISSUER);
        let reader = signed_token_with_issuer("reader", &["policy-reader"], CLUSTER_ISSUER);
        let read_fence = || async move { storage::read_contract_fence(pool).await.unwrap() };
        let fence = read_fence().await;

        let etag = policy_etag(&router, &admin).await;
        let candidate = cluster_policy("held").to_string();
        let (status, _, body) = call(
            &router,
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            &admin,
            Some(candidate.clone()),
            &[("if-match", &etag)],
            Some(&caller_key(10)),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["reason"], json!("capability_not_advertised"));
        let (status, _, body) = call(
            &router,
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            &admin,
            Some(cluster_policy("unkeyed").to_string()),
            &[("if-match", &etag)],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(document_reservations(pool).await.is_empty());
        assert_eq!(read_fence().await, fence, "a refused key raises nothing");

        stale(pool, earlier).await;
        let etag = policy_etag(&router, &admin).await;
        let (status, _, body) = call(
            &router,
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            &reader,
            Some(candidate.clone()),
            &[("if-match", &etag)],
            Some(&caller_key(11)),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let (status, _, body) = call(
            &router,
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            &admin,
            Some("{\"schema_version\":".to_owned()),
            &[("if-match", &etag)],
            Some(&caller_key(12)),
        )
        .await;
        assert!(status.is_client_error(), "{status}: {body}");
        assert_ne!(status, StatusCode::CONFLICT, "{body}");
        assert!(document_reservations(pool).await.is_empty());
        assert_eq!(
            read_fence().await,
            fence,
            "a forbidden or malformed keyed request raises nothing"
        );

        let (status, _, body) = call(
            &router,
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            &admin,
            Some(candidate),
            &[("if-match", &etag)],
            Some(&caller_key(13)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_ne!(
            read_fence().await,
            fence,
            "the first keyed change raises the fence"
        );
        assert_eq!(
            document_reservations(pool).await,
            vec![(caller_key(13), "policy.publish".to_owned())]
        );
    }

    /// Every keyed policy route and the policy test suite write: the first
    /// request commits with the route's own answer; an exact retry, whose
    /// `If-Match` the commit has since made stale, is `200` with the receipt
    /// and repeats no side effect (no second evidence row, reservation or
    /// audit event); a key reused for a different request is `409
    /// caller_operation_conflict`; and an unused key with a stale `If-Match`
    /// is still `412`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_replayed_policy_change_repeats_no_side_effect() {
        let Some((_database, foundation)) = database().await else {
            return;
        };
        let pool = foundation.pool();
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let (router, _) = keyed_replica(pool, false, audit_log, |_| {}).await;
        let admin = signed_token_with_issuer("operator", &["policy-admin"], CLUSTER_ISSUER);

        let rule_route = format!("{POLICY_RULES_ADMIN_ROUTE}/created");
        let steps: Vec<(Method, String, Option<String>, &str, &str)> = vec![
            (
                Method::PUT,
                POLICY_ADMIN_ROUTE.to_owned(),
                Some(cluster_policy("replaced").to_string()),
                "policy.publish",
                audit::event::POLICY_CHANGED,
            ),
            (
                Method::POST,
                POLICY_RULES_ADMIN_ROUTE.to_owned(),
                Some(json!({"id": "created", "path": "/created", "action": "allow"}).to_string()),
                "policy.rule.create",
                audit::event::POLICY_CHANGED,
            ),
            (
                Method::PATCH,
                rule_route.clone(),
                Some(json!({"action": "deny"}).to_string()),
                "policy.rule.update",
                audit::event::POLICY_CHANGED,
            ),
            (
                Method::PUT,
                POLICY_RULES_ORDER_ADMIN_ROUTE.to_owned(),
                Some(json!(["created", "second", "first"]).to_string()),
                "policy.rule.reorder",
                audit::event::POLICY_CHANGED,
            ),
            (
                Method::DELETE,
                rule_route.clone(),
                None,
                "policy.rule.delete",
                audit::event::POLICY_CHANGED,
            ),
            (
                Method::POST,
                "/v1/admin/policy/rollback/1".to_owned(),
                None,
                "policy.rollback",
                audit::event::POLICY_CHANGED,
            ),
        ];
        for (seed, (method, uri, body, operation, event)) in (20..).zip(steps) {
            let key = caller_key(seed);
            let etag = policy_etag(&router, &admin).await;
            let events = events_of(&capture, event);
            let (status, headers, committed) = call(
                &router,
                method.clone(),
                &uri,
                &admin,
                body.clone(),
                &[("if-match", &etag)],
                Some(&key),
            )
            .await;
            assert!(status.is_success(), "{operation}: {status} {committed}");
            assert!(headers.contains_key(header::ETAG), "{operation}");
            assert_eventually(Duration::from_secs(5), || {
                events_of(&capture, event) == events + 1
            });
            let evidence = document_evidence_count(pool).await;
            let reservations = document_reservations(pool).await;
            assert!(
                reservations.contains(&(key.clone(), operation.to_owned())),
                "{operation}"
            );

            let (status, _, receipt) = call(
                &router,
                method.clone(),
                &uri,
                &admin,
                body.clone(),
                &[("if-match", &etag)],
                Some(&key),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{operation}: {receipt}");
            assert_receipt(&receipt, &key, operation, "policy");
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(
                events_of(&capture, event),
                events + 1,
                "{operation}: no second event"
            );
            assert_eq!(document_evidence_count(pool).await, evidence, "{operation}");
            assert_eq!(
                document_reservations(pool).await,
                reservations,
                "{operation}"
            );

            // The same key for another target or precondition conflicts.
            let fresh = policy_etag(&router, &admin).await;
            let (status, _, conflict) = call(
                &router,
                method.clone(),
                &uri,
                &admin,
                body.clone(),
                &[("if-match", &fresh)],
                Some(&key),
            )
            .await;
            assert_eq!(status, StatusCode::CONFLICT, "{operation}: {conflict}");
            assert_eq!(conflict["reason"], json!("caller_operation_conflict"));
        }

        // An unused key with a stale If-Match is still a stale write.
        let (status, _, body) = call(
            &router,
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            &admin,
            Some(cluster_policy("stale").to_string()),
            &[("if-match", "\"stale\"")],
            Some(&caller_key(40)),
        )
        .await;
        assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{body}");

        // The stored policy test suite.
        let key = caller_key(41);
        let suite = suite_document();
        let (status, _, stored) = call(
            &router,
            Method::PUT,
            POLICY_TESTS_ADMIN_ROUTE,
            &admin,
            Some(suite.clone()),
            &[("if-none-match", "*")],
            Some(&key),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{stored}");
        assert_eventually(Duration::from_secs(5), || {
            events_of(&capture, audit::event::POLICY_TESTS_CHANGED) == 1
        });
        let (status, _, receipt) = call(
            &router,
            Method::PUT,
            POLICY_TESTS_ADMIN_ROUTE,
            &admin,
            Some(suite),
            &[("if-none-match", "*")],
            Some(&key),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
        assert_receipt(&receipt, &key, "policy_tests.publish", "policy_tests");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(events_of(&capture, audit::event::POLICY_TESTS_CHANGED), 1);
    }

    /// An admitted keyed `PUT /policy` runs to completion when its client
    /// goes away while the store is committing it: the change commits, this
    /// replica installs it (a role only the new policy grants is honoured),
    /// and it is audited exactly once, though nobody waited for the
    /// response. The keyed retry is answered from the receipt and repeats no
    /// audit event. This is the policy family's row of the disconnect tests
    /// for Connections and token rotation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_admitted_policy_change_finishes_after_its_client_goes_away() {
        let Some((_database, foundation)) = database().await else {
            return;
        };
        let pool = foundation.pool();
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let (router, _) = keyed_replica(pool, false, audit_log, |_| {}).await;
        let admin = signed_token_with_issuer("operator", &["policy-admin"], CLUSTER_ISSUER);
        let abandoned_reader =
            signed_token_with_issuer("abandoned", &["abandoned-reader"], CLUSTER_ISSUER);
        let (status, _, _) = call(
            &router,
            Method::GET,
            POLICY_ADMIN_ROUTE,
            &abandoned_reader,
            None,
            &[],
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "the role does not exist yet");

        let mut replacement = cluster_policy("abandoned");
        replacement["roles"]["abandoned-reader"] =
            json!({ "permissions": [ADMIN_POLICY_READ_PERMISSION] });
        let replacement = replacement.to_string();
        let etag = policy_etag(&router, &admin).await;
        let evidence = document_evidence_count(pool).await;
        let key = caller_key(90);
        let put = || {
            Request::builder()
                .method(Method::PUT)
                .uri(POLICY_ADMIN_ROUTE)
                .header(header::AUTHORIZATION, format!("Bearer {admin}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, etag.as_str())
                .header("idempotency-key", key.as_str())
                .body(Body::from(replacement.clone()))
                .unwrap()
        };
        let reserved = || {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(document_reservations(pool))
            })
            .contains(&(key.clone(), "policy.publish".to_owned()))
        };
        // The request is dropped unanswered, or this test proves nothing
        // about a client that goes away.
        assert!(
            super::super::authority_evidence_app_tests::abandon_once_committed(
                &router,
                put(),
                reserved,
            )
            .await,
            "the change was answered before its commit was observed, so nothing was abandoned"
        );

        // The replica installs what committed, and audits it once.
        assert_eventually(Duration::from_secs(5), || {
            events_of(&capture, audit::event::POLICY_CHANGED) == 1
        });
        let started = Instant::now();
        let status = loop {
            let (status, _, _) = call(
                &router,
                Method::GET,
                POLICY_ADMIN_ROUTE,
                &abandoned_reader,
                None,
                &[],
                None,
            )
            .await;
            if status == StatusCode::OK || started.elapsed() > Duration::from_secs(5) {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert_eq!(
            status,
            StatusCode::OK,
            "the replica serves the policy its retry is told committed"
        );
        assert_eq!(document_evidence_count(pool).await, evidence + 1);

        // The retry gets the receipt and repeats nothing.
        let (status, _, receipt) = call(
            &router,
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            &admin,
            Some(replacement.clone()),
            &[("if-match", &etag)],
            Some(&key),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
        assert_receipt(&receipt, &key, "policy.publish", "policy");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(events_of(&capture, audit::event::POLICY_CHANGED), 1);
        assert_eq!(document_evidence_count(pool).await, evidence + 1);
        assert_eq!(
            document_reservations(pool).await,
            vec![(key.clone(), "policy.publish".to_owned())]
        );
    }

    /// An exact retry of a keyed OpenAPI tools registration is answered from
    /// its receipt before the specification is turned into tools again, and
    /// audits no second registry change. The route takes the specification
    /// inline, so there is nothing to fetch. The retry carries the If-Match
    /// its own commit made stale, and the handler compares If-Match only
    /// after generating the tools: a retry that got past the pre-check
    /// would be `412`, so the `200` receipt shows the pre-check answered
    /// before that work (the store's in-transaction replay is never reached).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_replayed_tools_registration_fetches_no_specification_again() {
        let Some((_database, foundation)) = database().await else {
            return;
        };
        let pool = foundation.pool();
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let (router, _) = keyed_replica(pool, false, audit_log, |_| {}).await;
        let admin = signed_token_with_issuer("operator", &["policy-admin"], CLUSTER_ISSUER);
        let tools = storage::PostgresToolStore::new(pool.clone());
        let etag = storage::ToolControlPlane::active_tools(&tools)
            .await
            .unwrap()
            .unwrap()
            .etag;
        let key = caller_key(50);
        let body = json!({
            "spec": widget_openapi_spec(),
            "selected_tool_names": ["createWidget"]
        })
        .to_string();
        let (status, _, registered) = call(
            &router,
            Method::POST,
            TOOLS_OPENAPI_REGISTER_ADMIN_ROUTE,
            &admin,
            Some(body.clone()),
            &[("if-match", &etag)],
            Some(&key),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{registered}");
        assert_eventually(Duration::from_secs(5), || {
            events_of(&capture, audit::event::TOOL_REGISTRY_CHANGED) == 1
        });
        let evidence = document_evidence_count(pool).await;

        let (status, _, receipt) = call(
            &router,
            Method::POST,
            TOOLS_OPENAPI_REGISTER_ADMIN_ROUTE,
            &admin,
            Some(body),
            &[("if-match", &etag)],
            Some(&key),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
        assert_receipt(&receipt, &key, "tools.publish", "tools");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(events_of(&capture, audit::event::TOOL_REGISTRY_CHANGED), 1);
        assert_eq!(document_evidence_count(pool).await, evidence);
    }

    /// One `PUT .../policy` on a fresh replica in required mode with the
    /// given delivery format and sink (`None`: the log sink), keyed or not.
    async fn required_mode_policy_put(
        pool: &deadpool_postgres::Pool,
        seed: u8,
        format: config::AuthorityEventFormat,
        sink: Option<String>,
        keyed: bool,
    ) -> (StatusCode, Value) {
        let (router, _) = keyed_replica(pool, false, test_audit_log(), |config| {
            config.authority_events.durability = config::AuthorityEvidenceDurability::Required;
            config.authority_events.format = format;
            if let Some(path) = sink {
                config.authority_events.sink = config::AuthorityEventSinkSetting::File(path);
            }
        })
        .await;
        let admin = signed_token_with_issuer("operator", &["policy-admin"], CLUSTER_ISSUER);
        let etag = policy_etag(&router, &admin).await;
        let key = caller_key(seed);
        let (status, _, body) = call(
            &router,
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            &admin,
            Some(cluster_policy(&format!("required-{seed}")).to_string()),
            &[("if-match", &etag)],
            keyed.then_some(key.as_str()),
        )
        .await;
        (status, body)
    }

    fn assert_evidence_refusal(status: StatusCode, body: &Value) {
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(
            body["reason"],
            json!("authority_evidence_unsupported"),
            "{body}"
        );
    }

    /// Required mode in cluster mode refuses the unkeyed policy change with
    /// `409 authority_evidence_unsupported` before anything is read, and on
    /// a Unix build (the file sink syncs only there) admits the keyed
    /// request of an issuer-bound principal under `qualified_v1` with the
    /// file sink.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn required_mode_refuses_the_unkeyed_policy_change_and_admits_the_keyed_principal() {
        let Some((_database, foundation)) = database().await else {
            return;
        };
        let pool = foundation.pool();
        let events = TempDb::new("document-keys-required");
        let file = events.path.to_string_lossy().into_owned();
        let qualified = config::AuthorityEventFormat::QualifiedV1;
        let (status, body) =
            required_mode_policy_put(pool, 60, qualified, Some(file.clone()), false).await;
        assert_evidence_refusal(status, &body);

        // The unkeyed form of the other routes is refused the same way, by
        // the gate `admit_keyed_document_change` asks for it, before the
        // authority is read: the rollback, each rule edit, the tools
        // registration and the suite write. These are the cluster form of
        // the policy-family rows of `KEYED_ROUTES`, which the standalone
        // route walk (`authority_evidence_route_app_tests`) sees refused in
        // every form; suggestion acceptance and draft publication are
        // `cluster_discovery_tests`' (they need the discovery store).
        let (router, _) = keyed_replica(pool, false, test_audit_log(), |config| {
            config.authority_events.durability = config::AuthorityEvidenceDurability::Required;
            config.authority_events.format = qualified;
            config.authority_events.sink = config::AuthorityEventSinkSetting::File(file.clone());
        })
        .await;
        let admin = signed_token_with_issuer("operator", &["policy-admin"], CLUSTER_ISSUER);
        let etag = policy_etag(&router, &admin).await;
        let unkeyed: Vec<(Method, &str, Option<String>, &str)> = vec![
            (
                Method::POST,
                "/v1/admin/policy/rollback/1",
                None,
                "policy.rollback",
            ),
            (
                Method::POST,
                POLICY_RULES_ADMIN_ROUTE,
                Some(json!({"id": "unkeyed", "path": "/unkeyed", "action": "allow"}).to_string()),
                "policy.rule.create",
            ),
            (
                Method::PATCH,
                "/v1/admin/policy/rules/unkeyed",
                Some(json!({"action": "deny"}).to_string()),
                "policy.rule.update",
            ),
            (
                Method::DELETE,
                "/v1/admin/policy/rules/unkeyed",
                None,
                "policy.rule.delete",
            ),
            (
                Method::PUT,
                POLICY_RULES_ORDER_ADMIN_ROUTE,
                Some(json!(["unkeyed", "other"]).to_string()),
                "policy.rule.reorder",
            ),
            (
                Method::POST,
                TOOLS_OPENAPI_REGISTER_ADMIN_ROUTE,
                Some(
                    json!({
                        "spec": widget_openapi_spec(),
                        "selected_tool_names": ["createWidget"]
                    })
                    .to_string(),
                ),
                "tools.publish",
            ),
            (
                Method::PUT,
                POLICY_TESTS_ADMIN_ROUTE,
                Some(suite_document()),
                "policy_tests.publish",
            ),
        ];
        for (method, uri, body, operation) in unkeyed {
            let (status, _, refused) = call(
                &router,
                method,
                uri,
                &admin,
                body,
                &[("if-match", &etag)],
                None,
            )
            .await;
            assert_evidence_refusal(status, &refused);
            assert_eq!(refused["operation"], json!(operation), "{refused}");
        }
        assert!(document_reservations(pool).await.is_empty());
        assert_eq!(policy_etag(&router, &admin).await, etag);

        let (status, body) = required_mode_policy_put(pool, 61, qualified, Some(file), true).await;
        if cfg!(unix) {
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(
                document_reservations(pool).await,
                vec![(caller_key(61), "policy.publish".to_owned())]
            );
        } else {
            assert_evidence_refusal(status, &body);
        }
    }

    /// Required mode in cluster mode refuses a keyed policy change under
    /// `delivery_v1` and one with the log sink, each `409
    /// authority_evidence_unsupported` before anything is read or reserved.
    /// The service-token form is refused by the same gate before its key
    /// is bound (`required_tests`).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn required_mode_refuses_a_keyed_policy_change_by_a_service_token_or_under_delivery_v1_or_with_the_log_sink(
    ) {
        let Some((_database, foundation)) = database().await else {
            return;
        };
        let pool = foundation.pool();
        let events = TempDb::new("document-keys-refused");
        let file = events.path.to_string_lossy().into_owned();
        let (status, body) = required_mode_policy_put(
            pool,
            62,
            config::AuthorityEventFormat::DeliveryV1,
            Some(file),
            true,
        )
        .await;
        assert_evidence_refusal(status, &body);
        let (status, body) = required_mode_policy_put(
            pool,
            63,
            config::AuthorityEventFormat::QualifiedV1,
            None,
            true,
        )
        .await;
        assert_evidence_refusal(status, &body);
        assert!(document_reservations(pool).await.is_empty());
    }

    /// Preflight seeds an empty tools document on a first boot only when
    /// required evidence admits the unkeyed system `tools.publish`: under
    /// `required` an empty deployment refuses to start, naming the operation
    /// and how to provision the document, and seeds nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn required_mode_preflight_refuses_to_seed_an_empty_tools_document() {
        let Some((_database, foundation)) = database().await else {
            return;
        };
        let pool = foundation.pool();
        let store = Arc::new(storage::PostgresToolStore::new(pool.clone()));
        let required = authority_events::required::AuthorityEvidenceGate::new(
            config::AuthorityEvidenceDurability::Required,
            config::StateBackend::Postgres,
        );
        let refused = seed_cluster_tools(Arc::clone(&store), &required)
            .await
            .err()
            .expect("required mode refuses the seed");
        let message = refused.to_string();
        assert!(message.contains("tools.publish"), "{message}");
        assert!(message.contains("best_effort"), "{message}");
        assert!(message.contains("import-standalone"), "{message}");
        assert!(
            storage::ToolControlPlane::active_tools(&*store)
                .await
                .unwrap()
                .is_none(),
            "nothing was seeded"
        );
        assert!(document_reservations(pool).await.is_empty());
    }

    /// When the tools document exists, preflight asks nothing and starts,
    /// in required mode too; in best effort a first boot seeds it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn required_mode_preflight_passes_when_the_tools_document_exists() {
        let Some((_database, foundation)) = database().await else {
            return;
        };
        let pool = foundation.pool();
        let store = Arc::new(storage::PostgresToolStore::new(pool.clone()));
        let seeded = seed_cluster_tools(
            Arc::clone(&store),
            &authority_events::required::AuthorityEvidenceGate::best_effort(),
        )
        .await
        .expect("best effort seeds the first document");
        let evidence = document_evidence_count(pool).await;
        let required = authority_events::required::AuthorityEvidenceGate::new(
            config::AuthorityEvidenceDurability::Required,
            config::StateBackend::Postgres,
        );
        let again = seed_cluster_tools(store, &required)
            .await
            .expect("an existing document needs no seed");
        assert_eq!(again.active.etag, seeded.active.etag);
        assert_eq!(document_evidence_count(pool).await, evidence);
        assert!(document_reservations(pool).await.is_empty());
    }

    /// The binding digest the document handlers compute for a keyed change
    /// of the whole document by `actor` (`admit_keyed_document_change`):
    /// the action, the actor, no target, the precondition headers as
    /// `name: value` lines and the canonical JSON body.
    fn document_digest(
        actor: &auth::change_actor::ChangeActor,
        key: &str,
        action: &'static str,
        precondition: (&str, &str),
        body: &str,
    ) -> String {
        let mut headers = HeaderMap::new();
        headers.insert("idempotency-key", key.parse().expect("the key is a header"));
        caller_operation(
            &headers,
            actor,
            action,
            "",
            &format!("{}: {}\n", precondition.0, precondition.1),
            &canonical_connection_request(body.as_bytes()).expect("the body is JSON"),
        )
        .expect("the key binds")
        .expect("the request is keyed")
        .binding_digest()
        .to_owned()
    }

    /// Every binding digest reserved for a document action.
    async fn document_digests(pool: &deadpool_postgres::Pool) -> Vec<String> {
        let mut digests: Vec<String> = pool
            .get()
            .await
            .unwrap()
            .query(
                "SELECT binding_digest FROM greengateway.authority_caller_operation_ids \
                 WHERE action LIKE 'policy%' OR action LIKE 'tools.%'",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|row| row.get::<_, Option<String>>(0).expect("a bound digest"))
            .collect();
        digests.sort();
        digests
    }

    /// I5 for the policy, tools and policy test family through the real
    /// handlers of a cluster replica: a keyed policy publication, tools
    /// registration and policy test suite publication, each with its exact
    /// retry and a conflicting retry under its key, and a keyed policy
    /// publication whose evidence row cannot be inserted. These documents
    /// carry no secret value (a policy, an inline OpenAPI specification, a
    /// suite of test cases), so what must stay out is what the key binds
    /// them with: no binding digest and no caller key reaches a log line at
    /// any level or the rendered metrics, and no digest reaches a receipt, a
    /// conflict or failure answer, or the audit stream. The receipts name
    /// their keys to the caller by design. The documents are not searched
    /// for: the audit stream and the logs may name a rule or a tool, which
    /// is configuration, not a secret.
    #[test]
    fn a_keyed_document_change_keeps_its_digest_and_key_out_of_the_receipt_audit_logs_and_metrics()
    {
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let (outcome, logged, rendered) =
            super::super::admin_tokens_app_tests::capture_logs_and_metrics_on_every_runtime_thread(
                async {
                    let (_database, foundation) = database().await?;
                    let pool = foundation.pool();
                    let (router, _) = keyed_replica(pool, false, audit_log, |_| {}).await;
                    let admin =
                        signed_token_with_issuer("operator", &["policy-admin"], CLUSTER_ISSUER);
                    let actor = auth::change_actor::ChangeActor::for_test_with_issuer(
                        "operator",
                        CLUSTER_ISSUER,
                    );
                    let mut answers = Vec::new();
                    let mut computed = Vec::new();
                    let keys: Vec<String> = (60..64).map(caller_key).collect();

                    // The policy itself.
                    let policy = cluster_policy("marked").to_string();
                    let publish = |key: &str, body: &str, etag: &str| {
                        let (key, body, etag) = (key.to_owned(), body.to_owned(), etag.to_owned());
                        let router = router.clone();
                        let admin = admin.clone();
                        async move {
                            call(
                                &router,
                                Method::PUT,
                                POLICY_ADMIN_ROUTE,
                                &admin,
                                Some(body),
                                &[("if-match", &etag)],
                                Some(&key),
                            )
                            .await
                        }
                    };
                    let etag = policy_etag(&router, &admin).await;
                    let (status, _, published) = publish(&keys[0], &policy, &etag).await;
                    assert!(status.is_success(), "{status}: {published}");
                    let (status, _, receipt) = publish(&keys[0], &policy, &etag).await;
                    assert_eq!(status, StatusCode::OK, "{receipt}");
                    answers.push(receipt);
                    let fresh = policy_etag(&router, &admin).await;
                    let (status, _, conflict) = publish(&keys[0], &policy, &fresh).await;
                    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
                    answers.push(conflict);
                    for etag in [&etag, &fresh] {
                        computed.push(document_digest(
                            &actor,
                            &keys[0],
                            "policy.publish",
                            ("if-match", etag),
                            &policy,
                        ));
                    }

                    // The tools document.
                    let tools = storage::PostgresToolStore::new(pool.clone());
                    let tools_etag = storage::ToolControlPlane::active_tools(&tools)
                        .await
                        .unwrap()
                        .unwrap()
                        .etag;
                    let registration = json!({
                        "spec": widget_openapi_spec(),
                        "selected_tool_names": ["createWidget"]
                    })
                    .to_string();
                    let register = |etag: &str| {
                        let (key, body, etag) =
                            (keys[1].clone(), registration.clone(), etag.to_owned());
                        let router = router.clone();
                        let admin = admin.clone();
                        async move {
                            call(
                                &router,
                                Method::POST,
                                TOOLS_OPENAPI_REGISTER_ADMIN_ROUTE,
                                &admin,
                                Some(body),
                                &[("if-match", &etag)],
                                Some(&key),
                            )
                            .await
                        }
                    };
                    let (status, _, registered) = register(&tools_etag).await;
                    assert_eq!(status, StatusCode::CREATED, "{registered}");
                    let (status, _, receipt) = register(&tools_etag).await;
                    assert_eq!(status, StatusCode::OK, "{receipt}");
                    answers.push(receipt);
                    let registered_etag = storage::ToolControlPlane::active_tools(&tools)
                        .await
                        .unwrap()
                        .unwrap()
                        .etag;
                    let (status, _, conflict) = register(&registered_etag).await;
                    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
                    answers.push(conflict);
                    for etag in [&tools_etag, &registered_etag] {
                        computed.push(document_digest(
                            &actor,
                            &keys[1],
                            "tools.publish",
                            ("if-match", etag),
                            &registration,
                        ));
                    }

                    // The stored policy test suite.
                    let suite = suite_document();
                    let other_suite = suite.replace("anonymous-is-allowed", "anonymous-again");
                    let store_suite = |body: &str| {
                        let (key, body) = (keys[2].clone(), body.to_owned());
                        let router = router.clone();
                        let admin = admin.clone();
                        async move {
                            call(
                                &router,
                                Method::PUT,
                                POLICY_TESTS_ADMIN_ROUTE,
                                &admin,
                                Some(body),
                                &[("if-none-match", "*")],
                                Some(&key),
                            )
                            .await
                        }
                    };
                    let (status, _, stored) = store_suite(&suite).await;
                    assert_eq!(status, StatusCode::CREATED, "{stored}");
                    let (status, _, receipt) = store_suite(&suite).await;
                    assert_eq!(status, StatusCode::OK, "{receipt}");
                    answers.push(receipt);
                    let (status, _, conflict) = store_suite(&other_suite).await;
                    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
                    answers.push(conflict);
                    for body in [&suite, &other_suite] {
                        computed.push(document_digest(
                            &actor,
                            &keys[2],
                            "policy_tests.publish",
                            ("if-none-match", "*"),
                            body,
                        ));
                    }

                    // Test-only fault injection: a publication whose evidence
                    // row cannot be inserted.
                    let client = pool.get().await.unwrap();
                    client
                        .batch_execute(
                            r#"
                            CREATE FUNCTION greengateway.fail_document_change_evidence()
                            RETURNS trigger LANGUAGE plpgsql AS $$
                            BEGIN
                                RAISE EXCEPTION 'injected evidence failure';
                            END;
                            $$;
                            CREATE TRIGGER fail_document_change_evidence
                            BEFORE INSERT ON greengateway.document_change_evidence
                            FOR EACH ROW EXECUTE FUNCTION greengateway.fail_document_change_evidence();
                            "#,
                        )
                        .await
                        .expect("the failure trigger installs");
                    let failing = cluster_policy("failed").to_string();
                    let etag = policy_etag(&router, &admin).await;
                    let (status, _, failed) = publish(&keys[3], &failing, &etag).await;
                    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{failed}");
                    answers.push(failed);
                    computed.push(document_digest(
                        &actor,
                        &keys[3],
                        "policy.publish",
                        ("if-match", &etag),
                        &failing,
                    ));
                    client
                        .batch_execute(
                            "DROP TRIGGER fail_document_change_evidence \
                             ON greengateway.document_change_evidence; \
                             DROP FUNCTION greengateway.fail_document_change_evidence();",
                        )
                        .await
                        .expect("the failure trigger drops");
                    // Retried once the fault is gone, the failed request
                    // commits: its reservation holds the digest it was bound by.
                    let (status, _, retried) = publish(&keys[3], &failing, &etag).await;
                    assert!(status.is_success(), "{status}: {retried}");

                    assert_eventually(Duration::from_secs(5), || {
                        events_of(&capture, audit::event::POLICY_CHANGED) >= 2
                    });
                    let stored = document_digests(pool).await;
                    Some((answers, keys, computed, stored))
                },
            );
        let Some((answers, keys, computed, stored)) = outcome else {
            return;
        };

        // The digests computed here are the ones the handlers bound: each
        // committed request's reservation holds the one computed for it.
        let mut committed = vec![
            computed[0].clone(),
            computed[2].clone(),
            computed[4].clone(),
            computed[6].clone(),
        ];
        committed.sort();
        assert_eq!(stored, committed);

        assert!(!logged.is_empty(), "the handlers' log lines were captured");
        assert!(
            rendered.lines().any(|line| line
                == format!(
                    "{} 1",
                    crate::metrics::AUTHORITY_EVENT_EVIDENCE_FAILURES_TOTAL
                )),
            "the failed evidence insert was counted where the capture saw it"
        );
        let answered = format!("{answers:?}");
        let audited = format!("{:?}", capture.events());
        for digest in &computed {
            assert!(!answered.contains(digest), "a digest reached an answer");
            assert!(
                !audited.contains(digest),
                "a digest reached the audit stream"
            );
            assert!(!logged.contains(digest), "a digest reached the logs");
            assert!(!rendered.contains(digest), "a digest reached the metrics");
        }
        for key in &keys {
            assert!(!logged.contains(key), "a caller key reached the logs");
            assert!(!rendered.contains(key), "a caller key reached the metrics");
        }
    }
}
