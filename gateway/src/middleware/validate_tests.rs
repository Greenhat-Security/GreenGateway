use super::*;
use axum::{
    body::Body,
    middleware::from_fn_with_state,
    routing::{any, get},
    Router,
};
use tower::ServiceExt;

#[tokio::test]
async fn bodyless_logout_exception_requires_enabled_exact_registered_post() {
    for (enabled, method, path, registered, body, expected) in [
        (
            true,
            Method::POST,
            "/v1/operations/auth/logout",
            true,
            "",
            StatusCode::OK,
        ),
        (
            false,
            Method::POST,
            "/v1/operations/auth/logout",
            true,
            "",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            true,
            Method::PUT,
            "/v1/operations/auth/logout",
            true,
            "",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            true,
            Method::POST,
            "/v1/admin/auth/logout",
            true,
            "",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            true,
            Method::POST,
            "/v1/operations/auth/logout",
            false,
            "",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            true,
            Method::POST,
            "/v1/operations/auth/logout",
            true,
            "nonempty",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
    ] {
        let mut config = test_config(1024, vec!["application/json"]);
        config.admin_prefix = "/operations".to_owned();
        config.admin_session = enabled.then_some(crate::auth::admin_session::AdminSessionConfig {
            ttl: std::time::Duration::from_secs(60),
            max_entries: 8,
        });
        let router = if registered {
            Router::new().route(path, any(|| async { StatusCode::OK }))
        } else {
            Router::new().fallback(|| async { StatusCode::OK })
        }
        .layer(from_fn_with_state(config, validate_request));
        let response = router
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}

fn test_config(max_body_size: usize, validation_allowed_content_types: Vec<&str>) -> Config {
    Config {
        listen_addr: "127.0.0.1:0"
            .parse()
            .expect("test listen address should parse"),
        admin_listen_addr: None,
        grpc_listen_addr: None,
        grpc_max_concurrent_streams: crate::config::DEFAULT_GRPC_MAX_CONCURRENT_STREAMS,
        grpc_max_metadata_bytes: crate::config::DEFAULT_GRPC_MAX_METADATA_BYTES,
        tls_cert_files: None,
        tls_key_files: None,
        admin_tls_cert_files: None,
        admin_tls_key_files: None,
        tls_min_version: crate::config::DEFAULT_TLS_MIN_VERSION,
        tls_handshake_timeout_ms: crate::config::DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS,
        tls_max_concurrent_handshakes: crate::config::DEFAULT_TLS_MAX_CONCURRENT_HANDSHAKES,
        client_cert_auth: None,
        admin_client_cert_auth: None,
        admin_prefix: "/admin".to_owned(),
        admin_login_provider: None,
        admin_session: None,
        admin_login_pending_ttl_secs: crate::config::DEFAULT_ADMIN_LOGIN_PENDING_TTL_SECS,
        admin_login_pending_max_entries: crate::config::DEFAULT_ADMIN_LOGIN_PENDING_MAX_ENTRIES,
        admin_login_pending_max_per_ip: crate::config::DEFAULT_ADMIN_LOGIN_PENDING_MAX_PER_IP,
        admin_login_keyring: Vec::new(),
        rate_limit_keyring: Vec::new(),
        gateway_public_url: None,
        audit_log_file: None,
        audit_sqlite_path: None,
        audit_sqlite_retention_days: None,
        shutdown_drain_delay_ms: crate::config::DEFAULT_SHUTDOWN_DRAIN_DELAY_MS,
        shutdown_timeout_ms: crate::config::DEFAULT_SHUTDOWN_TIMEOUT_MS,
        audit_drain_timeout_ms: crate::config::DEFAULT_AUDIT_DRAIN_TIMEOUT_MS,
        discovery_sqlite_path: None,
        discovery_endpoint_limit: crate::config::DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
        discovery_projector_lease_ttl_ms: crate::config::DEFAULT_DISCOVERY_PROJECTOR_LEASE_TTL_MS,
        discovery_projector_poll_ms: crate::config::DEFAULT_DISCOVERY_PROJECTOR_POLL_MS,
        discovery_projector_batch: crate::config::DEFAULT_DISCOVERY_PROJECTOR_BATCH,
        principal_sqlite_path: None,
        connections_sqlite_path: None,
        connection_local_secret_keyring: Vec::new(),
        connection_vault_provider: crate::connections::vault_secret::VaultProviderConfig::default(),
        connection_gcp_provider: crate::connections::gcp_secret::GcpProviderConfig::default(),
        connection_azure_provider: crate::connections::azure_secret::AzureProviderConfig::default(),
        connection_aws_provider: crate::connections::aws_secret::AwsProviderConfig::default(),
        connection_kubernetes_provider:
            crate::connections::kubernetes_secret::KubernetesProviderConfig::default(),
        connection_secret_aliases: Vec::new(),
        connection_secrets_root: None,
        payload_capture_enabled: false,
        payload_capture_sample_rate: crate::config::DEFAULT_PAYLOAD_CAPTURE_SAMPLE_RATE,
        schema_mismatch_signal_threshold:
            crate::discovery::signals::DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
        error_rate_spike_signal_threshold:
            crate::discovery::signals::DEFAULT_ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
        principal_new_to_endpoint_signal_threshold:
            crate::discovery::signals::DEFAULT_PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
        volume_outlier_signal_threshold:
            crate::discovery::signals::DEFAULT_VOLUME_OUTLIER_SIGNAL_THRESHOLD,
        rule_suggestion_baseline_window_hours:
            crate::discovery::suggestions::DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
        openapi_spec_path: None,
        policy_file: None,
        tools_file: None,
        policy_history_sqlite_path: None,
        cors_allow_origins: Vec::new(),
        max_body_size,
        max_request_path_bytes: crate::config::DEFAULT_MAX_REQUEST_PATH_BYTES,
        rate_limit_read_rps: 50.0,
        rate_limit_read_burst: 100,
        rate_limit_write_rps: 10.0,
        rate_limit_write_burst: 20,
        rate_limit_max_buckets: crate::config::DEFAULT_RATE_LIMIT_MAX_BUCKETS,
        rate_limit_bucket_ttl_ms: crate::config::DEFAULT_RATE_LIMIT_BUCKET_TTL_MS,
        trust_proxy_headers: false,
        trusted_proxy_cidrs: Vec::new(),
        rbac_exempt_paths: vec![
            "/health".to_owned(),
            "/version".to_owned(),
            "/metrics".to_owned(),
        ],
        validation_allowed_content_types: validation_allowed_content_types
            .into_iter()
            .map(str::to_owned)
            .collect(),
        auth_enabled: true,
        auth_mode: crate::config::AuthMode::Required,
        auth_cookie_name: "session".to_owned(),
        auth_exempt_paths: vec![
            "/health".to_owned(),
            "/version".to_owned(),
            "/metrics".to_owned(),
        ],
        auth_providers: Vec::new(),
        jwt_jwks_url: None,
        jwt_issuer: None,
        jwt_audience: None,
        jwt_jwks_timeout_ms: 2000,
        jwt_jwks_max_key_age_secs: 300,
        jwt_require_jti: false,
        roles_claim: "roles".to_owned(),
        service_token_sqlite_path: None,
        service_token_cache_ttl_ms: crate::config::DEFAULT_SERVICE_TOKEN_CACHE_TTL_MS,
        tool_runtime_queue_depth: crate::config::DEFAULT_TOOL_RUNTIME_QUEUE_DEPTH,
        tool_runtime_global_concurrency: crate::config::DEFAULT_TOOL_RUNTIME_GLOBAL_CONCURRENCY,
        tool_runtime_queue_timeout_ms: crate::config::DEFAULT_TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
        tool_lease_ttl_ms: crate::config::DEFAULT_TOOL_LEASE_TTL_MS,
        cluster_heartbeat_ms: crate::config::DEFAULT_CLUSTER_HEARTBEAT_MS,
        cluster_member_stale_ms: crate::config::DEFAULT_CLUSTER_MEMBER_STALE_MS,
        cluster_maintenance_interval_ms: crate::config::DEFAULT_CLUSTER_MAINTENANCE_INTERVAL_MS,
        cluster_maintenance_lease_ttl_ms: crate::config::DEFAULT_CLUSTER_MAINTENANCE_LEASE_TTL_MS,
        readiness_probe_cache_ms: crate::config::DEFAULT_READINESS_PROBE_CACHE_MS,
        cluster_status_expose_hostnames: false,
        audit_postgres_retention_days: None,
        tool_runtime_default_timeout_ms: crate::config::DEFAULT_TOOL_RUNTIME_DEFAULT_TIMEOUT_MS,
        csrf_enabled: true,
        csrf_cookie_name: "csrf_token".to_owned(),
        csrf_header_name: "x-csrf-token".to_owned(),
        csrf_cookie_domain: None,
        csrf_exempt_paths: vec![
            "/health".to_owned(),
            "/version".to_owned(),
            "/metrics".to_owned(),
        ],
        upstream_url: None,
        upstream_routes: Vec::new(),
        mcp_upstream_servers: Vec::new(),
        upstream_timeout_ms: None,
        upstream_response_idle_timeout_ms: None,
        upstream_connect_timeout_ms: None,
        egress_allowed_hosts: Vec::new(),
        egress_timeout_ms: 30_000,
        egress_response_idle_timeout_ms: 30_000,
        egress_connect_timeout_ms: 10_000,
        egress_max_response_bytes: 5_242_880,
        egress_max_request_body_bytes: 1_048_576,
        egress_nat64_prefixes: Vec::new(),
        egress_deny_private_ips: true,
        state_backend: crate::config::StateBackend::Sqlite,
        deployment_id: None,
        database: crate::config::DatabaseSettings::default(),
    }
}

fn test_router(config: Config) -> Router {
    async fn ok() -> &'static str {
        "ok"
    }

    Router::new()
        .route("/", get(ok).post(ok))
        .layer(from_fn_with_state(config, validate_request))
}

/// Mirrors the production router, which registers the proxy fallback with
/// `any` and therefore matches every method including CONNECT.
fn test_router_with_any_fallback(config: Config) -> Router {
    async fn ok() -> &'static str {
        "ok"
    }

    Router::new()
        .fallback(any(ok))
        .layer(from_fn_with_state(config, validate_request))
}

#[tokio::test]
async fn rejects_connect_even_where_the_fallback_would_accept_every_method() {
    let response = test_router_with_any_fallback(test_config(1024, vec!["application/json"]))
        .oneshot(
            Request::builder()
                .method(Method::CONNECT)
                .uri("/anything")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
}

#[tokio::test]
async fn the_any_fallback_really_does_accept_other_methods() {
    // Without this, the CONNECT test above would still pass if the fallback
    // silently stopped matching arbitrary methods, and the guard it is
    // meant to pin would go untested.
    let response = test_router_with_any_fallback(test_config(1024, vec!["application/json"]))
        .oneshot(
            Request::builder()
                .method(Method::TRACE)
                .uri("/anything")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn rejects_content_length_over_configured_max() {
    let response = test_router(test_config(10, vec!["application/json"]))
        .oneshot(
            Request::builder()
                .uri("/")
                .header(CONTENT_LENGTH, "11")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn allows_content_length_within_configured_max() {
    let response = test_router(test_config(10, vec!["application/json"]))
        .oneshot(
            Request::builder()
                .uri("/")
                .header(CONTENT_LENGTH, "10")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_path_over_the_configured_bound_is_414_and_the_response_names_the_limit() {
    let mut config = test_config(1024, vec!["application/json"]);
    config.max_request_path_bytes = 32;

    let at_bound = format!("/{}", "a".repeat(31));
    let response = test_router_with_any_fallback(config.clone())
        .oneshot(
            Request::builder()
                .uri(at_bound)
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::OK);

    // The query is not part of the path and is not measured.
    let response = test_router_with_any_fallback(config.clone())
        .oneshot(
            Request::builder()
                .uri(format!("/{}?{}", "a".repeat(31), "q".repeat(200)))
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::OK);

    let response = test_router_with_any_fallback(config)
        .oneshot(
            Request::builder()
                .uri(format!("/{}", "a".repeat(32)))
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::URI_TOO_LONG);
    assert_eq!(
        body_string(response).await,
        r#"{"error":"request path too long","max_request_path_bytes":32}"#
    );
}

#[tokio::test]
async fn the_default_path_bound_is_the_policy_kernel_bound() {
    let config = test_config(1024, vec!["application/json"]);
    assert_eq!(
        config.max_request_path_bytes,
        crate::request_bounds::MAX_REQUEST_PATH_BYTES
    );

    let response = test_router_with_any_fallback(config.clone())
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/{}",
                    "a".repeat(crate::request_bounds::MAX_REQUEST_PATH_BYTES - 1)
                ))
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::OK);

    let response = test_router_with_any_fallback(config)
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/{}",
                    "a".repeat(crate::request_bounds::MAX_REQUEST_PATH_BYTES)
                ))
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::URI_TOO_LONG);
}

#[tokio::test]
async fn a_method_over_the_bound_is_501_and_is_not_echoed() {
    let config = test_config(1024, vec!["application/json"]);
    let method = |len: usize| Method::from_bytes("M".repeat(len).as_bytes()).unwrap();

    let response = test_router_with_any_fallback(config.clone())
        .oneshot(
            Request::builder()
                .method(method(crate::request_bounds::MAX_REQUEST_METHOD_BYTES))
                .uri("/")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::OK);

    let response = test_router_with_any_fallback(config)
        .oneshot(
            Request::builder()
                .method(method(crate::request_bounds::MAX_REQUEST_METHOD_BYTES + 1))
                .uri("/")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    assert_eq!(
        body_string(response).await,
        r#"{"error":"method too long","max_request_method_bytes":64}"#
    );
}

#[tokio::test]
async fn a_host_that_names_no_host_is_400_and_an_oversized_one_is_431() {
    use http::header::HOST;

    let config = test_config(1024, vec!["application/json"]);
    let at_bound = "h".repeat(crate::request_bounds::MAX_REQUEST_HOST_BYTES);

    for host in [
        "api.example.test",
        "api.example.test:8443",
        "[2001:db8::1]:8443",
        "",
        at_bound.as_str(),
    ] {
        let response = test_router(config.clone())
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(HOST, host)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK, "{host:?}");
    }

    for host in ["[a:b:c]", "api.example.test:x", "api.example.test/data"] {
        let response = test_router(config.clone())
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(HOST, host)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{host:?}");
        assert_eq!(body_string(response).await, r#"{"error":"invalid host"}"#);
    }

    let response = test_router(config.clone())
        .oneshot(
            Request::builder()
                .uri("/")
                .header(HOST, "a.example")
                .header(HOST, "b.example")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST, "two hosts");

    let response = test_router(config)
        .oneshot(
            Request::builder()
                .uri("/")
                .header(HOST, format!("{at_bound}h"))
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");
    assert_eq!(
        response.status(),
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
    );
    assert_eq!(
        body_string(response).await,
        r#"{"error":"host too long","max_request_host_bytes":4096}"#
    );
}

#[test]
fn shape_problems_are_reported_in_request_line_order() {
    use http::header::HOST;

    let long_method = Method::from_bytes("M".repeat(65).as_bytes()).unwrap();
    let long_path = format!("/{}", "a".repeat(64));
    let mut bad_host = HeaderMap::new();
    bad_host.insert(HOST, "[a:b:c]".parse().unwrap());

    assert_eq!(
        request_shape_problem(&long_method, &long_path, &bad_host, 32),
        Some(RequestShapeProblem::MethodTooLong)
    );
    assert_eq!(
        request_shape_problem(&Method::GET, &long_path, &bad_host, 32),
        Some(RequestShapeProblem::PathTooLong)
    );
    assert_eq!(
        request_shape_problem(&Method::GET, "/", &bad_host, 32),
        Some(RequestShapeProblem::HostMalformed)
    );
    assert_eq!(
        request_shape_problem(&Method::GET, "/", &HeaderMap::new(), 32),
        None
    );
}

async fn body_string(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .expect("response body should be readable");
    String::from_utf8(bytes.to_vec()).expect("response body should be UTF-8")
}

#[tokio::test]
async fn allows_post_with_default_json_content_type() {
    let response = test_router(test_config(1024, vec!["application/json"]))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/")
                .header(CONTENT_TYPE, "application/json; charset=utf-8")
                .body(Body::from("{}"))
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn enforces_content_type_token_boundary() {
    for (content_type, expected_status) in [
        ("application/json", StatusCode::OK),
        ("application/json; charset=utf-8", StatusCode::OK),
        ("application/jsonx", StatusCode::UNSUPPORTED_MEDIA_TYPE),
    ] {
        let response = test_router(test_config(1024, vec!["application/json"]))
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header(CONTENT_TYPE, content_type)
                    .body(Body::from("{}"))
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), expected_status);
    }
}

#[tokio::test]
async fn accepts_rfc_valid_media_type_casing() {
    for content_type in [
        "Application/JSON",
        "APPLICATION/JSON",
        "application/Json",
        "Application/json; charset=utf-8",
        "application/json;charset=utf-8",
        "application/json ; charset=utf-8",
    ] {
        let response = test_router(test_config(1024, vec!["application/json"]))
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/")
                    .header(CONTENT_TYPE, content_type)
                    .body(Body::from("{}"))
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK, "{content_type}");
    }
}

#[tokio::test]
async fn media_type_match_is_not_widened_to_neighbouring_types() {
    for content_type in [
        "application/json-patch+json",
        "application/jsonlines",
        "application/jsonx",
        "text/json",
        "application/xml",
        "",
    ] {
        let mut request = Request::builder().method(Method::POST).uri("/");
        if !content_type.is_empty() {
            request = request.header(CONTENT_TYPE, content_type);
        }
        let response = test_router(test_config(1024, vec!["application/json"]))
            .oneshot(
                request
                    .body(Body::from("{}"))
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(
            response.status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{content_type}"
        );
    }
}

#[tokio::test]
async fn openapi_preview_media_type_match_is_case_insensitive() {
    let response = test_router(test_config(1024, vec!["application/json"]))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/admin/tools/openapi/preview")
                .header(CONTENT_TYPE, "Application/YAML")
                .body(Body::from("openapi: 3.0.3"))
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    // The test router has no handler for the preview route, so passing the
    // media-type gate surfaces as the router's own 404 rather than a 415.
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn rejects_post_with_unlisted_content_type() {
    let response = test_router(test_config(1024, vec!["application/json"]))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/")
                .header(CONTENT_TYPE, "text/plain")
                .body(Body::from("hello"))
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn rejects_openapi_preview_suffix_on_non_admin_path() {
    let response = test_router(test_config(1024, vec!["application/json"]))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/some/other/prefix/tools/openapi/preview")
                .header(CONTENT_TYPE, "application/yaml")
                .body(Body::from("openapi: 3.0.3"))
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn allows_post_with_configured_extra_content_type() {
    let response = test_router(test_config(1024, vec!["multipart/form-data"]))
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/")
                .header(CONTENT_TYPE, "multipart/form-data; boundary=upload")
                .body(Body::from("file bytes"))
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn ignores_content_type_for_get_requests() {
    let response = test_router(test_config(1024, vec!["application/json"]))
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .header(CONTENT_TYPE, "text/plain")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}
