use super::*;
use storage::postgres::test_support::{locator, test_pool, test_settings};
use storage::{PolicyControlPlane, ToolControlPlane};

async fn replica(config: config::Config, pool: &deadpool_postgres::Pool) -> Router {
    let policy = Arc::new(storage::PostgresPolicyStore::new(pool.clone()));
    let tools = Arc::new(storage::PostgresToolStore::new(pool.clone()));
    let connections = Arc::new(
        connections::pg_store::PostgresConnectionStore::new(
            pool.clone(),
            connections::model::MAX_CONNECTIONS,
        )
        .unwrap(),
    );
    let revision = connections.state_revision().await.unwrap();
    let records = connections.list().await.unwrap();
    let (openapi_catalogs, openapi_overlays) =
        connections.openapi_catalogs_with_overlays().await.unwrap();
    let boot = Arc::new(connections::managed_store::ClusterConnectionsBoot {
        mcp_catalogs: connections.mcp_catalogs().await.unwrap(),
        openapi_catalogs,
        openapi_inventory_catalogs: connections.openapi_inventory_catalogs().await.unwrap(),
        openapi_overlays,
        enum_source_values: std::sync::Mutex::new(Some(
            connections.enum_source_values().await.unwrap(),
        )),
    });
    let app = gateway_app_with_process_started_at_and_overrides(
        config,
        PrometheusBuilder::new().build_recorder().handle(),
        test_audit_log(),
        test_audit_event_sender(),
        Instant::now(),
        GatewayAppBuildOverrides {
            pg_policy: Some(ClusterPolicySeed {
                active: policy.active().await.unwrap().unwrap(),
                store: policy,
            }),
            pg_tools: Some(ClusterToolsSeed {
                active: tools.active_tools().await.unwrap().unwrap(),
                store: tools,
            }),
            pg_connections: Some(ClusterConnectionsSeed {
                store: connections,
                records,
                boot,
                revision,
            }),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_keyed_mutation_prepare_recovers_the_receipt_after_catalog_drift() {
    let Some(admin_dsn) = locator() else {
        eprintln!("skipping: no test database locator; CI runs this test");
        return;
    };
    let database =
        storage::contract_tests::postgres_audit_tests::create_test_database(&admin_dsn).await;
    let foundation = test_pool(&database.dsn).await;
    let pool = foundation.pool();
    storage::migrations::apply_missing_for_startup(pool, &test_settings())
        .await
        .unwrap();
    let journal =
        storage::postgres_authority_events::PostgresAuthorityEventStore::new(pool.clone());
    journal.configure_capacity(100).await.unwrap();
    let policies = storage::PostgresPolicyStore::new(pool.clone());
    let policy = rbac::Policy::validate_json_value(json!({
            "schema_version":"0.1.0", "default_action":"allow", "enforcement_mode":"enforce",
            "roles": {
                "operator":{"permissions":["*"]},
                "requester":{"permissions":[ADMIN_TOOLS_READ_PERMISSION,ADMIN_TOOLS_EXECUTE_PERMISSION]},
                "reader":{"permissions":[ADMIN_TOOLS_READ_PERMISSION]}
            },
            "tools":{
                "updateWidget":{"allowed_roles":["requester"],"timeout_ms":5000,"max_concurrent":2},
                "getWidget":{"allowed_roles":["requester"],"timeout_ms":5000,"max_concurrent":2}
            }
        })).unwrap();
    policies
        .commit(storage::PolicyCommitRequest {
            precondition: storage::PolicyCommitPrecondition::Initialize,
            candidate: &policy,
            change: storage::DocumentChange::test_policy("installer"),
            diff_summary: &json!({}),
        })
        .await
        .unwrap();
    storage::PostgresToolStore::new(pool.clone())
        .seed_empty_document()
        .await
        .unwrap();

    let destination = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    destination.set_nonblocking(true).unwrap();
    let origin = format!("https://{}", destination.local_addr().unwrap());
    let mut config = test_config(Vec::new());
    config.state_backend = config::StateBackend::Postgres;
    config.deployment_id = Some("approval-receipts".into());
    config.authority_events.format = config::AuthorityEventFormat::QualifiedV1;
    configure_test_jwt_provider(&mut config, spawn_test_jwks_server().await);
    config.auth_providers[0].issuer = Some(ISSUER.into());
    config.egress_allowed_hosts = vec!["127.0.0.1".into()];
    config.egress_deny_private_ips = false;
    config.rate_limit_write_burst = 1000;
    config.rate_limit_write_rps = 1000.0;
    let best_effort = replica(config.clone(), pool).await;
    let operator = signed_token_with_issuer("operator", &["operator"], ISSUER);
    let requester = signed_token_with_issuer("alice", &["requester"], ISSUER);
    let other = signed_token_with_issuer("other", &["requester"], ISSUER);
    let read_only = signed_token_with_issuer("alice", &["reader"], ISSUER);
    let (id, connection_etag, _) = create_widget_connection(&best_effort, &operator, &origin).await;
    let (prepare, etag) = prepare_route(&best_effort, &requester, "updateWidget").await;
    config.authority_events.durability = config::AuthorityEvidenceDurability::Required;
    let required = replica(config.clone(), pool).await;
    let body = json!({"arguments":{"id":PRIVATE_ID,"name":PRIVATE_NAME}});
    let raw = body.to_string();
    let key = auth::tokens::test_revoke_operation_id(2).to_string();
    // A missing or duplicated key and unsupported conditional forms cannot claim this operation.
    for keys in [vec![], vec![key.as_str(), key.as_str()], vec!["invalid"]] {
        let request = keyed_request(&prepare, &requester, Some(&etag), &raw, &keys);
        assert_response(&required, request, &requester, StatusCode::BAD_REQUEST).await;
    }
    for (tag, expected) in [
        (None, StatusCode::PRECONDITION_REQUIRED),
        (Some("W/\"unchanged\""), StatusCode::BAD_REQUEST),
    ] {
        let request = keyed_request(&prepare, &requester, tag, &raw, &[&key]);
        assert_response(&required, request, &requester, expected).await;
    }
    let request = keyed_request(&prepare, &requester, Some(&etag), &raw, &[&key]);
    let (headers, receipt) = assert_response(&required, request, &requester, StatusCode::OK).await;
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(receipt.as_object().unwrap().len(), 4);
    assert_eq!(receipt["operation_id"], key);
    assert!(uuid::Uuid::parse_str(receipt["occurrence_id"].as_str().unwrap()).is_ok());
    assert_eq!(
        receipt["expires_at"].as_i64().unwrap() - receipt["prepared_at"].as_i64().unwrap(),
        connections::mutation_approval::APPROVAL_LIFETIME_SECS
    );

    // A retry must still be authorized, then match principal, path, strong ETag and exact bytes.
    let changed_tool = format!("{TOOLS_ADMIN_ROUTE}/another-tool/mutation-approvals");
    let spaced = format!("{raw} ");
    for (path, token, tag, input, expected) in [
        (
            &prepare,
            &read_only,
            etag.as_str(),
            raw.as_str(),
            StatusCode::FORBIDDEN,
        ),
        (&prepare, &other, &etag, &raw, StatusCode::CONFLICT),
        (&changed_tool, &requester, &etag, &raw, StatusCode::CONFLICT),
        (
            &prepare,
            &requester,
            "\"changed\"",
            &raw,
            StatusCode::CONFLICT,
        ),
        (&prepare, &requester, &etag, &spaced, StatusCode::CONFLICT),
    ] {
        let request = keyed_request(path, token, Some(tag), input, &[&key]);
        assert_response(&required, request, token, expected).await;
    }

    let (_, refused) = call(
        &required,
        Method::POST,
        &prepare,
        &requester,
        Some(&etag),
        Some(body.clone()),
        StatusCode::CONFLICT,
    )
    .await;
    assert_eq!(refused["reason"], "authority_evidence_unsupported");
    let (_, ordinary) = call(
        &best_effort,
        Method::POST,
        &prepare,
        &requester,
        Some(&etag),
        Some(body.clone()),
        StatusCode::CREATED,
    )
    .await;
    let (_, repeated) = call(
        &best_effort,
        Method::POST,
        &prepare,
        &requester,
        Some(&etag),
        Some(body),
        StatusCode::CREATED,
    )
    .await;
    assert_ne!(ordinary["id"], receipt["occurrence_id"]);
    assert_ne!(repeated["id"], ordinary["id"]);

    register_operations(
        &best_effort,
        &operator,
        &id,
        &connection_etag,
        &["getWidget"],
    )
    .await;
    let fresh = replica(config.clone(), pool).await;
    let (_, inventory) = call(
        &fresh,
        Method::GET,
        &format!("{TOOLS_ADMIN_ROUTE}?text=updateWidget"),
        &requester,
        None,
        None,
        StatusCode::OK,
    )
    .await;
    assert!(inventory["capabilities"].as_array().unwrap().is_empty());
    let request = keyed_request(&prepare, &requester, Some(&etag), &raw, &[&key]);
    let (headers, replayed) = assert_response(&fresh, request, &requester, StatusCode::OK).await;
    assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(replayed, receipt);
    // A downgrade still permits reconciliation of previous commits. It refuses a new operation.
    config.authority_events.format = config::AuthorityEventFormat::DeliveryV1;
    let downgraded = replica(config, pool).await;
    let request = keyed_request(&prepare, &requester, Some(&etag), &raw, &[&key]);
    let (_, legacy_replay) =
        assert_response(&downgraded, request, &requester, StatusCode::OK).await;
    assert_eq!(legacy_replay, receipt);
    let new_key = auth::tokens::test_revoke_operation_id(3).to_string();
    let request = keyed_request(&prepare, &requester, Some(&etag), &raw, &[&new_key]);
    let (_, refused) =
        assert_response(&downgraded, request, &requester, StatusCode::CONFLICT).await;
    assert_eq!(refused["reason"], "authority_evidence_unsupported");
    assert_eq!(
        destination.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "preparation and recovery must send no upstream bytes"
    );
}
