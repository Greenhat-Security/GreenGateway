//! The configuration capability route (issue #242, ADR-0008): the server
//! half of `ggctl`'s version handshake.
use super::*;
use gateway_config::{
    capabilities::{self, GatewayCapabilities},
    documents::{published_schema, API_VERSION_V1ALPHA1, CAPABILITIES_KIND},
};

fn config_policy(default_action: &str, routes: Value) -> TempPolicyFile {
    TempPolicyFile::new(
        &json!({
            "schema_version": "0.1.0",
            "id": "config-capabilities-policy",
            "default_action": default_action,
            "roles": {
                "config-reader": {"permissions": [ADMIN_CONFIG_READ_PERMISSION]},
                "status-reader": {"permissions": [ADMIN_STATUS_READ_PERMISSION]}
            },
            "routes": routes
        })
        .to_string(),
    )
}

/// Exempts the route from the RBAC middleware so the handler's own
/// permission check is what decides, as the status tests do.
fn handler_checked_config(policy: &TempPolicyFile) -> config::Config {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config
        .rbac_exempt_paths
        .push(CONFIG_CAPABILITIES_ADMIN_ROUTE.to_owned());
    config
}

async fn capabilities_response(router: Router, uri: &str, roles: Option<&[&str]>) -> Response {
    router
        .oneshot(audit_query_request(uri, roles.map(test_principal)))
        .await
        .expect("request should complete")
}

#[tokio::test]
async fn config_capabilities_require_a_principal_a_policy_and_the_permission() {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    let response = capabilities_response(
        status_router(config.clone(), Instant::now()),
        CONFIG_CAPABILITIES_ADMIN_ROUTE,
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = capabilities_response(
        status_router(config, Instant::now()),
        CONFIG_CAPABILITIES_ADMIN_ROUTE,
        Some(&["config-reader"]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        body_string(response).await,
        r#"{"error":"configuration API requires POLICY_FILE to be configured"}"#
    );

    let policy = config_policy("allow", json!([]));
    let response = capabilities_response(
        status_router(handler_checked_config(&policy), Instant::now()),
        CONFIG_CAPABILITIES_ADMIN_ROUTE,
        Some(&["status-reader"]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_string(response).await, r#"{"error":"forbidden"}"#);
}

#[tokio::test]
async fn config_capabilities_report_environment_mode_through_the_shared_reader() {
    let policy = config_policy("allow", json!([]));
    let response = capabilities_response(
        status_router(handler_checked_config(&policy), Instant::now()),
        CONFIG_CAPABILITIES_ADMIN_ROUTE,
        Some(&["config-reader"]),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should read");
    assert_eq!(
        capabilities::read(&body),
        Ok(GatewayCapabilities::environment(env!("CARGO_PKG_VERSION")))
    );
    let document: Value = serde_json::from_slice(&body).expect("JSON");
    assert_eq!(document["documents"], json!([]));
    assert_eq!(document["operations"], json!([]));
    let schema = published_schema(API_VERSION_V1ALPHA1, CAPABILITIES_KIND)
        .expect("the capabilities schema is published");
    let schema: Value = serde_json::from_str(schema.json).expect("schema JSON");
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    assert!(validator.is_valid(&document), "{document}");
}

#[tokio::test]
async fn config_capabilities_pass_the_documented_policy_route_under_default_deny() {
    let policy = config_policy(
        "deny",
        json!([{
            "methods": ["GET"],
            "path_prefix": "/v1/admin/config",
            "permission": ADMIN_CONFIG_READ_PERMISSION
        }]),
    );
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    for (roles, status) in [
        (&["config-reader"][..], StatusCode::OK),
        (&["status-reader"], StatusCode::FORBIDDEN),
    ] {
        let response = capabilities_response(
            status_router(config.clone(), Instant::now()),
            CONFIG_CAPABILITIES_ADMIN_ROUTE,
            Some(roles),
        )
        .await;
        assert_eq!(response.status(), status, "{roles:?}");
    }
}

#[tokio::test]
async fn config_capabilities_follow_a_custom_prefix_on_the_admin_listener_only() {
    let policy = config_policy("allow", json!([]));
    let mut config = handler_checked_config(&policy);
    config.admin_prefix = "/operations".to_owned();
    config.admin_listen_addr = Some("127.0.0.1:0".parse().expect("address"));
    let route = GatewayRoutes::from_config(&config)
        .admin
        .config_capabilities_route;
    assert_eq!(route, "/v1/operations/config/capabilities");
    config.rbac_exempt_paths.push(route.clone());
    let recorder = PrometheusBuilder::new().build_recorder();
    let apps = gateway_app_with_process_started_at(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
        Instant::now(),
    )
    .expect("apps should build");
    let GatewayApp::Split { admin, data } = apps.http else {
        panic!("a separate admin listener splits the routers");
    };
    for (router, uri, status) in [
        (admin.clone(), route.as_str(), StatusCode::OK),
        (
            admin,
            CONFIG_CAPABILITIES_ADMIN_ROUTE,
            StatusCode::NOT_FOUND,
        ),
        (data, route.as_str(), StatusCode::NOT_FOUND),
    ] {
        let response = capabilities_response(router, uri, Some(&["config-reader"])).await;
        assert_eq!(response.status(), status, "{uri}");
    }
}
