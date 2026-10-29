//! Listeners, routing and proxying (`routing.rs`, `probes.rs`, `proxy/`,
//! `middleware/`): the listener split, the admin prefix, admin UI serving,
//! health probes, the routing table, proxying, rate limits, CORS and the
//! middleware order. Shared fixtures stay in `app_tests.rs`.
use super::*;

fn gateway_app_for_test(config: config::Config) -> GatewayApps {
    let recorder = PrometheusBuilder::new().build_recorder();
    gateway_app_with_process_started_at(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
        Instant::now(),
    )
    .expect("gateway app should build")
}

fn split_gateway_routers(config: config::Config) -> (Router, Router) {
    match gateway_app_for_test(config).http {
        GatewayApp::Split { data, admin } => (data, admin),
        GatewayApp::Unified(_) => panic!("gateway app should build split routers"),
    }
}

async fn spawn_split_gateway(
    config: config::Config,
) -> (
    std::net::SocketAddr,
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    let (data, admin) = split_gateway_routers(config);
    let (data_addr, data_server) = spawn_gateway_router(data).await;
    let (admin_addr, admin_server) = spawn_gateway_router(admin).await;

    (data_addr, admin_addr, data_server, admin_server)
}

fn split_config() -> config::Config {
    let mut config = test_config(Vec::new());
    config.admin_listen_addr = Some(
        "127.0.0.1:0"
            .parse()
            .expect("test admin listen address should parse"),
    );
    config
}

#[derive(Debug)]
struct TestHttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl TestHttpResponse {
    fn status(&self) -> StatusCode {
        self.status
    }

    fn headers(&self) -> &HeaderMap {
        &self.headers
    }
}

async fn test_http_request(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    bearer: Option<&str>,
) -> TestHttpResponse {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .unwrap_or_else(|err| panic!("test HTTP client should connect to {addr}: {err}"));
        let mut request =
            format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
        if let Some(token) = bearer {
            request.push_str("Authorization: Bearer ");
            request.push_str(token);
            request.push_str("\r\n");
        }
        request.push_str("\r\n");

        stream
            .write_all(request.as_bytes())
            .await
            .unwrap_or_else(|err| panic!("test HTTP client should write request: {err}"));
        stream
            .flush()
            .await
            .unwrap_or_else(|err| panic!("test HTTP client should flush request: {err}"));

        let mut raw_response = Vec::new();
        stream
            .read_to_end(&mut raw_response)
            .await
            .unwrap_or_else(|err| panic!("test HTTP client should read response: {err}"));

        parse_test_http_response(&raw_response)
    })
    .await
    .unwrap_or_else(|_| panic!("test HTTP request timed out: {method} {path}"))
}

fn parse_test_http_response(raw_response: &[u8]) -> TestHttpResponse {
    let header_end = raw_response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("test HTTP response should contain headers");
    let raw_headers = std::str::from_utf8(&raw_response[..header_end])
        .expect("test HTTP response headers should be UTF-8");
    let raw_body = &raw_response[header_end + 4..];

    let mut lines = raw_headers.split("\r\n");
    let status_line = lines
        .next()
        .expect("test HTTP response should include a status line");
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts
        .next()
        .expect("test HTTP response should include a version");
    assert!(
        version.starts_with("HTTP/"),
        "test HTTP response should use HTTP, got {version}"
    );
    let status = status_parts
        .next()
        .expect("test HTTP response should include a status code")
        .parse::<u16>()
        .expect("test HTTP response status should be numeric");
    let status = StatusCode::from_u16(status).expect("test HTTP response status should be valid");

    let mut headers = HeaderMap::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .unwrap_or_else(|| panic!("test HTTP response header should contain ':': {line}"));
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .expect("test HTTP response header name should be valid");
        let value = HeaderValue::from_str(value.trim())
            .expect("test HTTP response header value should be valid");
        headers.append(name, value);
    }

    let body = if response_is_chunked(&headers) {
        decode_chunked_body(raw_body)
    } else if let Some(content_length) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .parse::<usize>()
                .expect("test HTTP response Content-Length should be numeric")
        })
    {
        assert!(
            raw_body.len() >= content_length,
            "test HTTP response body should contain Content-Length bytes"
        );
        raw_body[..content_length].to_vec()
    } else {
        raw_body.to_vec()
    };

    TestHttpResponse {
        status,
        headers,
        body: String::from_utf8(body).expect("test HTTP response body should be UTF-8"),
    }
}

fn response_is_chunked(headers: &HeaderMap) -> bool {
    headers
        .get(header::TRANSFER_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
        })
}

fn decode_chunked_body(mut encoded: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();

    loop {
        let line_end = encoded
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("test HTTP chunk should include a size line");
        let size_line = std::str::from_utf8(&encoded[..line_end])
            .expect("test HTTP chunk size should be UTF-8");
        let size_text = size_line
            .split_once(';')
            .map_or(size_line, |(size, _extension)| size)
            .trim();
        let size = usize::from_str_radix(size_text, 16)
            .expect("test HTTP chunk size should be hexadecimal");
        encoded = &encoded[line_end + 2..];

        if size == 0 {
            break;
        }

        assert!(
            encoded.len() >= size + 2,
            "test HTTP chunk should contain declared bytes and trailing CRLF"
        );
        decoded.extend_from_slice(&encoded[..size]);
        assert_eq!(
            &encoded[size..size + 2],
            b"\r\n",
            "test HTTP chunk should end with CRLF"
        );
        encoded = &encoded[size + 2..];
    }

    decoded
}

async fn delayed_upstream(State(delay): State<Duration>) -> Response {
    tokio::time::sleep(delay).await;
    (StatusCode::CREATED, "slow upstream").into_response()
}

async fn spawn_delayed_upstream(delay: Duration) -> std::net::SocketAddr {
    spawn_router(
        Router::new()
            .fallback(any(delayed_upstream))
            .with_state(delay),
    )
    .await
}

async fn delayed_stream_upstream() -> Response {
    let chunks = futures_util::stream::unfold(0, |index| async move {
        match index {
            0 => Some((Ok::<_, Infallible>(bytes::Bytes::from_static(b"first")), 1)),
            1 => {
                // Wide enough that the negative "not buffered" check below is
                // still inside the gap even when the earlier awaits are slow.
                tokio::time::sleep(Duration::from_millis(2_000)).await;
                Some((Ok::<_, Infallible>(bytes::Bytes::from_static(b"second")), 2))
            }
            _ => None,
        }
    });

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        Body::from_stream(chunks),
    )
        .into_response()
}

fn https_path_route(
    path_prefix: &str,
    upstream_addr: std::net::SocketAddr,
) -> config::UpstreamRouteConfig {
    let mut route = path_route(path_prefix, upstream_addr);
    route.upstream_url = format!("https://127.0.0.1:{}/ignored-base", upstream_addr.port());
    route
}

fn streaming_proxy_router(config: config::Config) -> Router {
    let recorder = PrometheusBuilder::new().build_recorder();
    let app = gateway_app_with_process_started_at_and_overrides(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
        Instant::now(),
        GatewayAppBuildOverrides {
            stream_proxy_request_bodies: true,
            disable_proxy_health_checks: true,
            ..GatewayAppBuildOverrides::default()
        },
    )
    .expect("streaming proxy app should build");
    match app.http {
        GatewayApp::Unified(router) => router,
        GatewayApp::Split { .. } => panic!("streaming proxy app should be unified"),
    }
}

async fn observe_streamed_request_body(
    State(observed): State<tokio::sync::mpsc::Sender<Result<Vec<u8>, usize>>>,
    body: Body,
) -> Response {
    let mut body = body.into_data_stream();
    let mut received = Vec::new();
    while let Some(chunk) = body.next().await {
        match chunk {
            Ok(chunk) => {
                received.extend_from_slice(&chunk);
                let _ = observed.send(Ok(received.clone())).await;
            }
            Err(_) => {
                let _ = observed.send(Err(received.len())).await;
                return StatusCode::BAD_REQUEST.into_response();
            }
        }
    }

    (StatusCode::CREATED, received.len().to_string()).into_response()
}

async fn spawn_stream_observer_upstream() -> (
    std::net::SocketAddr,
    tokio::sync::mpsc::Receiver<Result<Vec<u8>, usize>>,
) {
    let (observed_tx, observed_rx) = tokio::sync::mpsc::channel(16);
    let router = Router::new()
        .fallback(any(observe_streamed_request_body))
        .with_state(observed_tx);
    (spawn_router(router).await, observed_rx)
}

#[derive(Clone)]
struct ProxyWorkProbe {
    resolver: Arc<CountingDnsResolver>,
    request_selections: Arc<AtomicUsize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProxyWorkSnapshot {
    resolver_calls: usize,
    request_selections: usize,
}

impl ProxyWorkProbe {
    fn snapshot(&self) -> ProxyWorkSnapshot {
        ProxyWorkSnapshot {
            resolver_calls: self.resolver.calls.load(Ordering::SeqCst),
            request_selections: self.request_selections.load(Ordering::SeqCst),
        }
    }

    fn assert_no_work(&self, context: &str) {
        assert_eq!(
            self.snapshot(),
            ProxyWorkSnapshot {
                resolver_calls: 0,
                request_selections: 0,
            },
            "{context}"
        );
    }
}

fn proxy_router_with_work_probe(
    config: config::Config,
    audit_log: audit::AuditLog,
    upstream_ip: IpAddr,
) -> (Router, ProxyWorkProbe) {
    let resolver = Arc::new(CountingDnsResolver {
        calls: AtomicUsize::new(0),
        address_ip: upstream_ip,
    });
    let request_selections = Arc::new(AtomicUsize::new(0));
    let resolver_trait: Arc<dyn egress::DnsResolver> = resolver.clone();
    let recorder = PrometheusBuilder::new().build_recorder();
    let app = gateway_app_with_process_started_at_and_overrides(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
        Instant::now(),
        GatewayAppBuildOverrides {
            egress_resolver: Some(resolver_trait),
            request_selection_count: Some(Arc::clone(&request_selections)),
            disable_proxy_health_checks: true,
            stream_proxy_request_bodies: false,
            ..GatewayAppBuildOverrides::default()
        },
    )
    .expect("instrumented proxy app should build");
    let router = match app.http {
        GatewayApp::Unified(router) => router,
        GatewayApp::Split { .. } => panic!("instrumented proxy app should be unified"),
    };

    (
        router,
        ProxyWorkProbe {
            resolver,
            request_selections,
        },
    )
}

async fn preflight_response_to_path(
    config: config::Config,
    path: &str,
    origin: &str,
) -> axum::response::Response {
    let recorder = PrometheusBuilder::new().build_recorder();

    app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build")
    .oneshot(
        Request::builder()
            .method(Method::OPTIONS)
            .uri(path)
            .header(header::ORIGIN, origin)
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .body(Body::empty())
            .expect("request should build"),
    )
    .await
    .expect("request should complete")
}

async fn preflight_response(config: config::Config, origin: &str) -> axum::response::Response {
    preflight_response_to_path(config, "/health", origin).await
}

async fn wait_for_upstream_health(router: Router, reachable: bool) -> Value {
    let started = Instant::now();

    loop {
        let response = health_response(router.clone()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;

        if body["upstream"]["reachable"] == json!(reachable) {
            return body;
        }

        assert!(
            started.elapsed() < Duration::from_secs(2),
            "upstream health did not become {reachable} before timeout: {body}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_routing_upstream_health(router: Router, reachable: bool) -> Value {
    let started = Instant::now();

    loop {
        let response = health_response(router.clone()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        if body["upstream"]["reachable"] == json!(reachable) {
            return body;
        }

        assert!(
            started.elapsed() < Duration::from_secs(2),
            "routing upstream health did not become {reachable} before timeout: {body}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn health_probe_count(captured: &mut tokio::sync::mpsc::Receiver<CapturedRequest>) -> usize {
    let started = Instant::now();
    let timeout = Duration::from_millis(100);
    let mut count = 0;

    while started.elapsed() < timeout {
        let remaining = timeout.saturating_sub(started.elapsed());
        match tokio::time::timeout(remaining, captured.recv()).await {
            Ok(Some(request)) if is_upstream_health_probe(&request) => count += 1,
            Ok(Some(request)) => panic!(
                "unexpected non-health upstream request while counting probes: {} {}",
                request.method, request.path_and_query
            ),
            Ok(None) | Err(_) => return count,
        }
    }

    count
}

#[tokio::test]
async fn health_without_upstream_returns_original_body() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let response = app(
        test_config(Vec::new()),
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build")
    .oneshot(
        Request::builder()
            .uri("/health")
            .body(Body::empty())
            .expect("request should build"),
    )
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key(REQUEST_ID_HEADER));
    assert_eq!(body_string(response).await, r#"{"status":"ok"}"#);
}

#[tokio::test]
async fn startup_upstream_health_check_reports_reachable_without_blocking_startup() {
    let upstream_addr =
        spawn_router(Router::new().route("/", get(|| async { StatusCode::NO_CONTENT }))).await;
    let config = proxy_config(upstream_addr);
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = tokio::time::timeout(Duration::from_millis(100), async move {
        app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
    })
    .await
    .expect("app startup should not wait for upstream health")
    .expect("app should build");

    let body = wait_for_upstream_health(router, true).await;
    assert_eq!(body["status"], json!("ok"));
    assert_eq!(body["upstream"]["configured"], json!(true));
    assert_eq!(body["upstream"]["reachable"], json!(true));
}

#[tokio::test]
async fn startup_upstream_health_check_reports_unreachable_without_blocking_startup() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let upstream_addr = listener
        .local_addr()
        .expect("listener local address should be available");
    drop(listener);
    let mut config = proxy_config(upstream_addr);
    config.upstream_timeout_ms = Some(100);
    config.upstream_connect_timeout_ms = Some(100);
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = tokio::time::timeout(Duration::from_millis(100), async move {
        app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
    })
    .await
    .expect("app startup should not wait for upstream health")
    .expect("app should build");

    let body = wait_for_upstream_health(router, false).await;
    assert_eq!(body["status"], json!("ok"));
    assert_eq!(body["upstream"]["configured"], json!(true));
    assert_eq!(body["upstream"]["reachable"], json!(false));
}

#[tokio::test]
async fn routing_table_health_is_aggregate_and_each_route_keeps_its_probe_identity() {
    let (first_addr, mut first_captured) = spawn_capture_upstream().await;
    let (second_addr, mut second_captured) = spawn_capture_upstream().await;
    let router = proxy_router(
        routing_proxy_config(vec![
            path_route("/api", first_addr),
            path_route("/api/v2", first_addr),
            path_route("/assets", second_addr),
        ]),
        test_audit_log(),
    );

    let body = wait_for_routing_upstream_health(router, true).await;
    assert_eq!(body["status"], json!("ok"));
    assert_eq!(body["upstream"]["configured"], json!(true));
    assert_eq!(body["upstream"]["reachable"], json!(true));
    assert!(body["upstream"].get("upstreams").is_none());
    assert!(!body.to_string().contains("127.0.0.1"));

    assert_eq!(
        health_probe_count(&mut first_captured).await,
        2,
        "separate route identities sharing an origin must retain separate health workers"
    );
    assert_eq!(health_probe_count(&mut second_captured).await, 1);
}

#[test]
fn admin_routes_keep_default_api_prefix_and_remap_custom_api_under_v1() {
    let default_routes = AdminRoutes::from_prefix(config::DEFAULT_ADMIN_PREFIX);
    assert_eq!(default_routes.api_prefix, DEFAULT_ADMIN_API_PREFIX);
    assert_eq!(default_routes.audit_route, AUDIT_ADMIN_ROUTE);
    assert_eq!(
        default_routes.events_stream_route,
        AUDIT_EVENTS_STREAM_ROUTE
    );
    assert_eq!(default_routes.status_route, STATUS_ADMIN_ROUTE);
    assert_eq!(
        default_routes.config_capabilities_route,
        CONFIG_CAPABILITIES_ADMIN_ROUTE
    );
    assert_eq!(default_routes.cluster_route, CLUSTER_ADMIN_ROUTE);
    assert_eq!(
        default_routes.cluster_replicas_route,
        CLUSTER_REPLICAS_ADMIN_ROUTE
    );
    assert_eq!(default_routes.policy_route, POLICY_ADMIN_ROUTE);
    assert_eq!(
        default_routes.policy_history_route,
        POLICY_HISTORY_ADMIN_ROUTE
    );
    assert_eq!(
        default_routes.policy_rollback_route,
        POLICY_ROLLBACK_ADMIN_ROUTE
    );
    assert_eq!(
        default_routes.policy_rule_preview_route,
        POLICY_RULE_PREVIEW_ADMIN_ROUTE
    );
    assert_eq!(
        default_routes.policy_rule_hits_route,
        POLICY_RULE_HITS_ADMIN_ROUTE
    );
    assert_eq!(
        default_routes.policy_rule_shadow_review_route,
        POLICY_RULE_SHADOW_REVIEW_ADMIN_ROUTE
    );
    assert_eq!(
        default_routes.policy_validate_route,
        POLICY_VALIDATE_ADMIN_ROUTE
    );
    assert_eq!(
        default_routes.policy_convert_route,
        POLICY_CONVERT_ADMIN_ROUTE
    );
    assert_eq!(default_routes.policy_rules_route, POLICY_RULES_ADMIN_ROUTE);
    assert_eq!(default_routes.policy_rule_route, POLICY_RULE_ADMIN_ROUTE);
    assert_eq!(
        default_routes.policy_rules_order_route,
        POLICY_RULES_ORDER_ADMIN_ROUTE
    );
    assert_eq!(
        default_routes.policy_drafts_route,
        POLICY_DRAFTS_ADMIN_ROUTE
    );
    assert_eq!(default_routes.policy_draft_route, POLICY_DRAFT_ADMIN_ROUTE);
    assert_eq!(
        default_routes.policy_draft_publish_route,
        POLICY_DRAFT_PUBLISH_ADMIN_ROUTE
    );
    assert_eq!(default_routes.tokens_route, TOKENS_ADMIN_ROUTE);
    assert_eq!(default_routes.token_route, TOKEN_ADMIN_ROUTE);
    assert_eq!(default_routes.token_rotate_route, TOKEN_ROTATE_ADMIN_ROUTE);
    assert_eq!(default_routes.connections_route, CONNECTIONS_ADMIN_ROUTE);
    assert_eq!(default_routes.connection_route, CONNECTION_ADMIN_ROUTE);
    assert_eq!(
        default_routes.connection_refresh_route,
        CONNECTION_REFRESH_ADMIN_ROUTE
    );
    assert_eq!(
        default_routes.connection_test_route,
        CONNECTION_TEST_ADMIN_ROUTE
    );
    assert_eq!(
        default_routes.connection_openapi_preview_route,
        CONNECTION_OPENAPI_PREVIEW_ADMIN_ROUTE
    );
    assert_eq!(
        default_routes.connection_openapi_register_route,
        CONNECTION_OPENAPI_REGISTER_ADMIN_ROUTE
    );
    assert_eq!(
        default_routes.connection_openapi_overlay_route,
        CONNECTION_OPENAPI_OVERLAY_ADMIN_ROUTE
    );
    assert_eq!(default_routes.tools_route, TOOLS_ADMIN_ROUTE);
    assert_eq!(default_routes.tool_route, TOOL_ADMIN_ROUTE);
    assert_eq!(default_routes.tool_execute_route, TOOL_EXECUTE_ADMIN_ROUTE);
    assert_eq!(
        default_routes.tools_openapi_preview_route,
        TOOLS_OPENAPI_PREVIEW_ADMIN_ROUTE
    );
    assert_eq!(
        default_routes.tools_openapi_register_route,
        TOOLS_OPENAPI_REGISTER_ADMIN_ROUTE
    );
    assert_eq!(
        default_routes.schema_coverage_route,
        SCHEMA_COVERAGE_ADMIN_ROUTE
    );
    assert_eq!(
        default_routes.schema_inferred_route,
        SCHEMA_INFERRED_ADMIN_ROUTE
    );
    assert_eq!(default_routes.suggestions_route, SUGGESTIONS_ADMIN_ROUTE);
    assert_eq!(
        default_routes.suggestions_generate_route,
        SUGGESTIONS_GENERATE_ADMIN_ROUTE
    );
    assert_eq!(
        default_routes.suggestion_accept_route,
        SUGGESTION_ACCEPT_ADMIN_ROUTE
    );
    assert_eq!(
        default_routes.suggestion_dismiss_route,
        SUGGESTION_DISMISS_ADMIN_ROUTE
    );
    assert_eq!(
        default_routes.suggestion_draft_route,
        SUGGESTION_DRAFT_ADMIN_ROUTE
    );
    assert_eq!(
        default_routes.traffic_endpoints_route,
        TRAFFIC_ENDPOINTS_ADMIN_ROUTE
    );
    assert_eq!(
        default_routes.traffic_endpoint_detail_route,
        TRAFFIC_ENDPOINT_DETAIL_ADMIN_ROUTE
    );
    assert_eq!(
        default_routes.traffic_endpoint_review_route,
        TRAFFIC_ENDPOINT_REVIEW_ADMIN_ROUTE
    );
    assert_eq!(default_routes.principals_route, PRINCIPALS_ADMIN_ROUTE);
    assert_eq!(default_routes.principal_detail_route, PRINCIPAL_ADMIN_ROUTE);
    assert_eq!(
        default_routes.principal_delegated_tokens_revoke_route,
        PRINCIPAL_DELEGATED_TOKENS_REVOKE_ADMIN_ROUTE
    );

    let custom_routes = AdminRoutes::from_prefix("/ops");
    assert_eq!(custom_routes.ui_prefix, "/ops");
    assert_eq!(custom_routes.api_prefix, "/v1/ops");
    assert_eq!(custom_routes.audit_route, "/v1/ops/audit");
    assert_eq!(custom_routes.events_stream_route, "/v1/ops/events/stream");
    assert_eq!(custom_routes.status_route, "/v1/ops/status");
    assert_eq!(
        custom_routes.config_capabilities_route,
        "/v1/ops/config/capabilities"
    );
    assert_eq!(custom_routes.cluster_route, "/v1/ops/cluster");
    assert_eq!(
        custom_routes.cluster_replicas_route,
        "/v1/ops/cluster/replicas"
    );
    assert_eq!(custom_routes.policy_route, "/v1/ops/policy");
    assert_eq!(custom_routes.policy_history_route, "/v1/ops/policy/history");
    assert_eq!(
        custom_routes.policy_rollback_route,
        "/v1/ops/policy/rollback/{version}"
    );
    assert_eq!(
        custom_routes.policy_rule_preview_route,
        "/v1/ops/policy/rules/preview"
    );
    assert_eq!(
        custom_routes.policy_rule_hits_route,
        "/v1/ops/policy/rules/hits"
    );
    assert_eq!(
        custom_routes.policy_rule_shadow_review_route,
        "/v1/ops/policy/rules/shadow-review"
    );
    assert_eq!(
        custom_routes.policy_validate_route,
        "/v1/ops/policy/validate"
    );
    assert_eq!(custom_routes.policy_convert_route, "/v1/ops/policy/convert");
    assert_eq!(custom_routes.policy_rules_route, "/v1/ops/policy/rules");
    assert_eq!(custom_routes.policy_rule_route, "/v1/ops/policy/rules/{id}");
    assert_eq!(
        custom_routes.policy_rules_order_route,
        "/v1/ops/policy/rules/order"
    );
    assert_eq!(custom_routes.policy_drafts_route, "/v1/ops/policy/drafts");
    assert_eq!(
        custom_routes.policy_draft_route,
        "/v1/ops/policy/drafts/{id}"
    );
    assert_eq!(
        custom_routes.policy_draft_publish_route,
        "/v1/ops/policy/drafts/{id}/publish"
    );
    assert_eq!(custom_routes.tokens_route, "/v1/ops/tokens");
    assert_eq!(custom_routes.token_route, "/v1/ops/tokens/{id}");
    assert_eq!(
        custom_routes.token_rotate_route,
        "/v1/ops/tokens/{id}/rotate"
    );
    assert_eq!(custom_routes.connections_route, "/v1/ops/connections");
    assert_eq!(custom_routes.connection_route, "/v1/ops/connections/{id}");
    assert_eq!(
        custom_routes.connection_refresh_route,
        "/v1/ops/connections/{id}/refresh"
    );
    assert_eq!(
        custom_routes.connection_test_route,
        "/v1/ops/connections/{id}/test"
    );
    assert_eq!(
        custom_routes.connection_openapi_preview_route,
        "/v1/ops/connections/{id}/openapi/preview"
    );
    assert_eq!(
        custom_routes.connection_openapi_register_route,
        "/v1/ops/connections/{id}/openapi/register"
    );
    assert_eq!(
        custom_routes.connection_openapi_overlay_route,
        "/v1/ops/connections/{id}/overlay"
    );
    assert_eq!(custom_routes.tools_route, "/v1/ops/tools");
    assert_eq!(custom_routes.tool_route, "/v1/ops/tools/{id}");
    assert_eq!(
        custom_routes.tool_execute_route,
        "/v1/ops/tools/{id}/execute"
    );
    assert_eq!(
        custom_routes.tools_openapi_preview_route,
        "/v1/ops/tools/openapi/preview"
    );
    assert_eq!(
        custom_routes.tools_openapi_register_route,
        "/v1/ops/tools/openapi/register"
    );
    assert_eq!(
        custom_routes.schema_coverage_route,
        "/v1/ops/schema/coverage"
    );
    assert_eq!(
        custom_routes.schema_inferred_route,
        "/v1/ops/schema/inferred"
    );
    assert_eq!(custom_routes.suggestions_route, "/v1/ops/suggestions");
    assert_eq!(
        custom_routes.suggestions_generate_route,
        "/v1/ops/suggestions/generate"
    );
    assert_eq!(
        custom_routes.suggestion_accept_route,
        "/v1/ops/suggestions/{id}/accept"
    );
    assert_eq!(
        custom_routes.suggestion_dismiss_route,
        "/v1/ops/suggestions/{id}/dismiss"
    );
    assert_eq!(
        custom_routes.suggestion_draft_route,
        "/v1/ops/suggestions/{id}/draft"
    );
    assert_eq!(
        custom_routes.traffic_endpoints_route,
        "/v1/ops/traffic/endpoints"
    );
    assert_eq!(
        custom_routes.traffic_endpoint_detail_route,
        "/v1/ops/traffic/endpoint"
    );
    assert_eq!(
        custom_routes.traffic_endpoint_review_route,
        "/v1/ops/traffic/endpoints/review"
    );
    assert_eq!(custom_routes.principals_route, "/v1/ops/principals");
    assert_eq!(custom_routes.principal_detail_route, "/v1/ops/principal");
    assert_eq!(
        custom_routes.principal_delegated_tokens_revoke_route,
        "/v1/ops/principal/delegated-tokens/revoke"
    );
}

#[test]
fn capability_inventory_cache_control_matches_inventory_and_exact_execute_paths() {
    for (collection_route, matching_paths) in [
        (
            "/v1/admin/tools",
            [
                "/v1/admin/tools",
                "/v1/admin/tools/cap_123",
                "/v1/admin/tools/cap_123/execute",
            ],
        ),
        (
            "/v1/ops/tools",
            [
                "/v1/ops/tools",
                "/v1/ops/tools/not-yet-valid",
                "/v1/ops/tools/not-yet-valid/execute",
            ],
        ),
    ] {
        for path in matching_paths {
            assert!(
                is_capability_inventory_path(path, collection_route),
                "{path} should be treated as a capability inventory path"
            );
        }
    }

    for path in [
        "/v1/admin/tool",
        "/v1/admin/toolsmith",
        "/v1/admin/tools/",
        "/v1/admin/tools/cap_123/extra",
        "/v1/admin/tools/cap_123/execute/",
        "/v1/admin/tools/cap_123/execute/extra",
        "/v1/admin/tools//execute",
        "/v1/admin/tools/openapi/preview",
        "/v1/ops/tools/cap_123/extra",
        "/v1/ops/tools/cap_123/run",
    ] {
        assert!(
            !is_capability_inventory_path(path, "/v1/admin/tools")
                && !is_capability_inventory_path(path, "/v1/ops/tools"),
            "{path} must not change unrelated cache behavior"
        );
    }
}

#[test]
fn managed_admin_cache_control_matches_only_managed_routes() {
    let state = ManagedAdminCacheControlState {
        connections_route: "/v1/admin/connections".to_owned(),
        connection_secrets_route: "/v1/admin/connection-secrets".to_owned(),
        tools_route: "/v1/admin/tools".to_owned(),
    };

    for path in [
        "/v1/admin/connections",
        "/v1/admin/connections/connection-id",
        "/v1/admin/connections/connection-id/refresh",
        "/v1/admin/connections/connection-id/test",
        "/v1/admin/connections/connection-id/openapi/preview",
        "/v1/admin/connections/connection-id/openapi/register",
        "/v1/admin/connection-secrets",
        "/v1/admin/connection-secrets/secret-id",
        "/v1/admin/tools",
        "/v1/admin/tools/capability-id",
        "/v1/admin/tools/capability-id/execute",
        "/v1/admin/tools/openapi/preview",
        "/v1/admin/tools/openapi/register",
    ] {
        assert!(
            is_managed_admin_path(path, &state),
            "{path} should receive Cache-Control: no-store"
        );
    }

    for path in [
        "/v1/admin/connections/",
        "/v1/admin/connections/connection-id/refresh/",
        "/v1/admin/connections/connection-id/openapi/delete",
        "/v1/admin/connection-secrets/",
        "/v1/admin/connection-secrets/secret-id/extra",
        "/v1/admin/tools/",
        "/v1/admin/tools/capability-id/extra",
        "/v1/admin/tools/openapi/preview/extra",
        "/v1/admin/tokens",
    ] {
        assert!(
            !is_managed_admin_path(path, &state),
            "{path} must not change unrelated cache behavior"
        );
    }

    let custom = ManagedAdminCacheControlState {
        connections_route: "/v1/ops/connections".to_owned(),
        connection_secrets_route: "/v1/ops/connection-secrets".to_owned(),
        tools_route: "/v1/ops/tools".to_owned(),
    };
    for path in [
        "/v1/ops/connections",
        "/v1/ops/connections/connection-id/test",
        "/v1/ops/connection-secrets/secret-id",
        "/v1/ops/tools/capability-id/execute",
        "/v1/ops/tools/openapi/register",
    ] {
        assert!(
            is_managed_admin_path(path, &custom),
            "{path} should follow the configured admin prefix"
        );
    }
}

#[tokio::test]
async fn default_admin_listener_unset_builds_single_router_with_data_and_admin_routes() {
    let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    let config = status_config_with_policy(config, &policy);

    let router = match gateway_app_for_test(config).http {
        GatewayApp::Unified(router) => router,
        GatewayApp::Split { .. } => panic!("ADMIN_LISTEN_ADDR unset should build one router"),
    };

    let health_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("health request should complete");
    assert_eq!(health_response.status(), StatusCode::OK);

    let admin_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("admin UI request should complete");
    assert_eq!(admin_response.status(), StatusCode::OK);
    assert!(body_string(admin_response)
        .await
        .contains(r#"<div id="root"></div>"#));

    let status_response = router
        .oneshot(audit_query_request(
            STATUS_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
        ))
        .await
        .expect("admin status request should complete");
    assert_eq!(status_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn split_listeners_expose_admin_and_data_surfaces_separately() {
    let jwks_addr = spawn_test_jwks_server().await;
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let mut config = split_config();
    config.upstream_url = Some(format!(
        "http://127.0.0.1:{}/ignored-base",
        upstream_addr.port()
    ));
    config.egress_allowed_hosts = vec!["127.0.0.1".to_owned()];
    config.egress_deny_private_ips = false;
    let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
    config = status_config_with_policy(config, &policy);
    configure_test_jwt_provider(&mut config, jwks_addr);
    let token = signed_admin_token();
    let (data_addr, admin_addr, data_server, admin_server) = spawn_split_gateway(config).await;

    let data_admin_response = test_http_request(data_addr, "GET", "/admin", None).await;
    assert_eq!(data_admin_response.status(), StatusCode::NOT_FOUND);

    let data_admin_api_response =
        test_http_request(data_addr, "GET", STATUS_ADMIN_ROUTE, Some(&token)).await;
    assert_eq!(data_admin_api_response.status(), StatusCode::NOT_FOUND);
    assert_upstream_receives_no_request(
        &mut captured,
        "split data listener should reserve admin UI and API paths from proxy fallback",
    )
    .await;

    let admin_ui_response = test_http_request(admin_addr, "GET", "/admin", None).await;
    assert_eq!(admin_ui_response.status(), StatusCode::OK);
    assert!(admin_ui_response.body.contains(r#"<div id="root"></div>"#));

    let admin_status_response =
        test_http_request(admin_addr, "GET", STATUS_ADMIN_ROUTE, Some(&token)).await;
    assert_eq!(admin_status_response.status(), StatusCode::OK);
    let admin_status: Value = serde_json::from_str(&admin_status_response.body)
        .expect("admin status body should be JSON");
    assert_eq!(admin_status["version"], json!(env!("CARGO_PKG_VERSION")));

    for path in [
        "/health",
        "/livez",
        "/startupz",
        "/readyz",
        "/version",
        "/metrics",
    ] {
        let data_response = test_http_request(data_addr, "GET", path, None).await;
        assert!(
            matches!(
                data_response.status(),
                StatusCode::OK | StatusCode::SERVICE_UNAVAILABLE
            ),
            "{path}"
        );

        let admin_response = test_http_request(admin_addr, "GET", path, None).await;
        assert_eq!(admin_response.status(), StatusCode::NOT_FOUND, "{path}");
    }

    let proxied_response = test_http_request(data_addr, "GET", "/proxied?x=1", Some(&token)).await;
    assert_eq!(proxied_response.status(), StatusCode::CREATED);
    assert_eq!(proxied_response.body, "upstream GET /proxied?x=1");
    let proxied_request =
        next_proxied_request(&mut captured, "data listener should proxy unmatched paths").await;
    assert_eq!(proxied_request.method, Method::GET);
    assert_eq!(proxied_request.path_and_query, "/proxied?x=1");

    let admin_proxy_response =
        test_http_request(admin_addr, "GET", "/proxied?x=1", Some(&token)).await;
    assert_eq!(admin_proxy_response.status(), StatusCode::NOT_FOUND);
    assert_upstream_receives_no_request(
        &mut captured,
        "split admin listener should not register proxy fallback",
    )
    .await;

    data_server.abort();
    admin_server.abort();
}

#[tokio::test]
async fn split_listeners_handle_concurrent_requests() {
    let (data_addr, admin_addr, data_server, admin_server) =
        spawn_split_gateway(split_config()).await;

    let (data_response, admin_response) = tokio::join!(
        test_http_request(data_addr, "GET", "/health", None),
        test_http_request(admin_addr, "GET", "/admin", None),
    );

    assert_eq!(data_response.status(), StatusCode::OK);
    assert_eq!(admin_response.status(), StatusCode::OK);

    data_server.abort();
    admin_server.abort();
}

#[tokio::test]
async fn split_admin_listener_enforces_auth_and_rbac_on_admin_api() {
    let jwks_addr = spawn_test_jwks_server().await;
    let policy = TempPolicyFile::new(
        r#"{
                "schema_version": "0.1.0",
                "default_action": "deny",
                "enforcement_mode": "enforce",
                "roles": {
                    "admin": { "permissions": ["admin:read"] }
                }
            }"#,
    );
    let mut config = split_config();
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    configure_test_jwt_provider(&mut config, jwks_addr);
    config.egress_deny_private_ips = false;
    let token = signed_admin_token();
    let (_data_addr, admin_addr, data_server, admin_server) = spawn_split_gateway(config).await;

    let unauthenticated = test_http_request(admin_addr, "GET", STATUS_ADMIN_ROUTE, None).await;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        unauthenticated
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer")
    );
    assert_eq!(unauthenticated.body, r#"{"error":"unauthorized"}"#);

    let rbac_denied = test_http_request(admin_addr, "GET", STATUS_ADMIN_ROUTE, Some(&token)).await;
    assert_eq!(rbac_denied.status(), StatusCode::FORBIDDEN);
    assert_eq!(rbac_denied.body, r#"{"error":"forbidden"}"#);

    data_server.abort();
    admin_server.abort();
}

#[tokio::test]
async fn admin_ui_shell_is_served_without_principal() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let response = app(
        test_config(Vec::new()),
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build")
    .oneshot(
        Request::builder()
            .uri("/admin")
            .body(Body::empty())
            .expect("request should build"),
    )
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_content_type_starts_with(response.headers(), "text/html");
    assert_eq!(
        response.headers()["content-security-policy"],
        ADMIN_UI_CONTENT_SECURITY_POLICY
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let body = body_string(response).await;
    assert!(body.contains(r#"<div id="root"></div>"#));
    assert!(body.contains(r#"greengateway-csrf-cookie-name" content="csrf_token""#));
    assert!(body.contains(r#"greengateway-csrf-header-name" content="x-csrf-token""#));
}

#[tokio::test]
async fn admin_ui_real_embedded_javascript_asset_is_served() {
    let asset_path = AdminUiAssets::iter()
        .find(|path| path.starts_with("assets/") && path.ends_with(".js"))
        .expect("Vite build should embed a JavaScript asset")
        .to_string();
    let uri = format!("/admin/{asset_path}");

    let recorder = PrometheusBuilder::new().build_recorder();
    let response = app(
        test_config(Vec::new()),
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build")
    .oneshot(
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request should build"),
    )
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .expect("content type should be present");
    assert!(
        content_type.starts_with("text/javascript")
            || content_type.starts_with("application/javascript"),
        "unexpected JavaScript content type: {content_type}"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should read");
    assert!(!body.is_empty());
}

#[tokio::test]
async fn admin_ui_client_routes_fall_back_to_index() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let response = app(
        test_config(Vec::new()),
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build")
    .oneshot(
        Request::builder()
            .uri("/admin/logs")
            .body(Body::empty())
            .expect("request should build"),
    )
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_content_type_starts_with(response.headers(), "text/html");
    let body = body_string(response).await;
    assert!(body.contains(r#"<div id="root"></div>"#));
}

#[tokio::test]
async fn admin_ui_traversal_attempts_fall_back_to_index_only() {
    for uri in [
        "/admin/../../../etc/passwd",
        "/admin/%2e%2e/%2e%2e/etc/passwd",
    ] {
        let recorder = PrometheusBuilder::new().build_recorder();
        let response = app(
            test_config(Vec::new()),
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build")
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_content_type_starts_with(response.headers(), "text/html");
        let body = body_string(response).await;
        assert!(body.contains(r#"<div id="root"></div>"#));
        assert!(!body.contains("root:x:0:0"));
    }
}

#[tokio::test]
async fn audit_log_extension_is_available_to_middleware() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let response = app(
        test_config(Vec::new()),
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build")
    .oneshot(
        Request::builder()
            .uri("/health")
            .body(Body::empty())
            .expect("request should build"),
    )
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn proxy_forwards_methods_path_query_headers_and_bodies() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let router = proxy_router(proxy_config(upstream_addr), test_audit_log());

    for method in [Method::GET, Method::POST, Method::PUT, Method::DELETE] {
        let body = if matches!(method, Method::POST | Method::PUT) {
            format!("body for {method}").into_bytes()
        } else {
            Vec::new()
        };
        let mut request = Request::builder()
            .method(method.clone())
            .uri("/api/items/42/?x=1&name=two%20words")
            .header(header::AUTHORIZATION, "Bearer client-token")
            .header(header::COOKIE, "session=client")
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::CONNECTION, "keep-alive, x-hop-by-connection")
            .header("keep-alive", "timeout=5")
            .header("proxy-authorization", "Basic stripped")
            .header("te", "trailers")
            .header("upgrade", "websocket")
            .header(header::CONTENT_LENGTH, "0")
            .header("x-hop-by-connection", "strip me")
            .header("x-end-to-end", "keep me")
            .body(Body::from(body.clone()))
            .expect("request should build");
        request.headers_mut().append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer second-client-token"),
        );
        request.headers_mut().append(
            header::COOKIE,
            HeaderValue::from_static("other-client-cookie=value"),
        );

        let response = router
            .clone()
            .oneshot(request)
            .await
            .expect("proxy request should complete");

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response.headers().get("x-upstream-end-to-end"),
            Some(&HeaderValue::from_static("kept"))
        );
        for stripped in [
            header::CONNECTION.as_str(),
            "keep-alive",
            "proxy-authenticate",
            "transfer-encoding",
            "content-length",
            "x-upstream-hop",
        ] {
            assert!(
                !response.headers().contains_key(stripped),
                "proxied response should strip {stripped}"
            );
        }
        assert!(response.headers().contains_key(REQUEST_ID_HEADER));
        let response_body = body_string(response).await;
        assert_eq!(
            response_body,
            format!("upstream {method} /api/items/42/?x=1&name=two%20words")
        );

        let upstream =
            next_proxied_request(&mut captured, "upstream should receive proxied request").await;
        assert_eq!(upstream.method, method);
        assert_eq!(
            upstream.path_and_query,
            "/api/items/42/?x=1&name=two%20words"
        );
        assert_eq!(upstream.body, body);
        assert_eq!(
            upstream.headers.get("x-end-to-end"),
            Some(&HeaderValue::from_static("keep me"))
        );
        if !body.is_empty() {
            assert_ne!(
                upstream.headers.get(header::CONTENT_LENGTH),
                Some(&HeaderValue::from_static("0")),
                "upstream request should not forward the stale client content-length"
            );
        }
        assert!(
            !upstream.headers.contains_key(REQUEST_ID_HEADER),
            "caller or gateway request IDs must not cross the upstream boundary"
        );
        for stripped in [
            header::CONNECTION.as_str(),
            "keep-alive",
            "proxy-authorization",
            "te",
            "upgrade",
            "x-hop-by-connection",
            header::AUTHORIZATION.as_str(),
            header::COOKIE.as_str(),
        ] {
            assert!(
                !upstream.headers.contains_key(stripped),
                "upstream request should strip {stripped}"
            );
        }
    }
}

#[tokio::test]
async fn proxy_pool_uses_deterministic_weights_without_cross_route_selection() {
    let (first_addr, mut first_captured) = spawn_capture_upstream().await;
    let (second_addr, mut second_captured) = spawn_capture_upstream().await;
    let mut pooled_route = path_route("/pool", first_addr);
    pooled_route.id = Some("pool-route".to_owned());
    pooled_route.upstream_url.clear();
    pooled_route.upstreams = vec![
        config::UpstreamEndpointConfig {
            id: "first".to_owned(),
            url: format!("http://127.0.0.1:{}", first_addr.port()),
            weight: 3,
            tls_ca_bundle_path: None,
            client_identity_pem_path: None,
        },
        config::UpstreamEndpointConfig {
            id: "second".to_owned(),
            url: format!("http://127.0.0.1:{}", second_addr.port()),
            weight: 1,
            tls_ca_bundle_path: None,
            client_identity_pem_path: None,
        },
    ];
    let capture = audit::sink::tests::CaptureSink::default();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = proxy_router(routing_proxy_config(vec![pooled_route]), audit_log);
    let health = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("health request should build"),
        )
        .await
        .expect("health request should complete");
    let health = json_body(health).await;
    assert_eq!(health["upstream"]["configured"], json!(true));
    assert!(health["upstream"].get("upstreams").is_none());
    assert!(!health.to_string().contains("127.0.0.1"));
    assert!(!health.to_string().contains("pool-route"));

    for _ in 0..8 {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/pool/item")
                    .body(Body::empty())
                    .expect("pooled request should build"),
            )
            .await
            .expect("pooled request should complete");
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    for _ in 0..6 {
        let request = next_proxied_request(&mut first_captured, "weighted first endpoint").await;
        assert_eq!(request.path_and_query, "/pool/item");
    }
    for _ in 0..2 {
        let request = next_proxied_request(&mut second_captured, "weighted second endpoint").await;
        assert_eq!(request.path_and_query, "/pool/item");
    }
    assert_upstream_receives_no_request(&mut first_captured, "first endpoint exact weight").await;
    assert_upstream_receives_no_request(&mut second_captured, "second endpoint exact weight").await;
    assert_eventually(Duration::from_secs(1), || {
        capture
            .events()
            .iter()
            .filter(|event| {
                event.event_type == "http.request_observed"
                    && event.payload["path"] == json!("/pool/item")
            })
            .count()
            == 8
    });
    let observations = capture
        .events()
        .into_iter()
        .filter(|event| {
            event.event_type == "http.request_observed"
                && event.payload["path"] == json!("/pool/item")
        })
        .collect::<Vec<_>>();
    assert!(observations.iter().all(|event| {
        event.payload["upstream_route_id"] == json!("pool-route")
            && event.payload["upstream_pool_id"] == json!("pool-route")
            && event.payload["upstream_origin"] == json!("pool:pool-route")
    }));
    let first_count = observations
        .iter()
        .filter(|event| event.payload["upstream_endpoint_id"] == json!("first"))
        .count();
    let second_count = observations
        .iter()
        .filter(|event| event.payload["upstream_endpoint_id"] == json!("second"))
        .count();
    assert_eq!((first_count, second_count), (6, 2));
}

#[tokio::test]
async fn catch_all_pool_route_deny_performs_zero_physical_work() {
    let (first_addr, mut first_captured) = spawn_capture_upstream().await;
    let (second_addr, mut second_captured) = spawn_capture_upstream().await;
    let mut pooled_route = route(None, None, first_addr);
    pooled_route.id = Some("payments".to_owned());
    pooled_route.upstream_url.clear();
    pooled_route.upstreams = vec![
        config::UpstreamEndpointConfig {
            id: "primary".to_owned(),
            url: format!("http://127.0.0.1:{}", first_addr.port()),
            weight: 3,
            tls_ca_bundle_path: None,
            client_identity_pem_path: None,
        },
        config::UpstreamEndpointConfig {
            id: "secondary".to_owned(),
            url: format!("http://127.0.0.1:{}", second_addr.port()),
            weight: 1,
            tls_ca_bundle_path: None,
            client_identity_pem_path: None,
        },
    ];
    let policy = TempPolicyFile::new(
        r#"{
                "schema_version": "0.1.0",
                "default_action": "allow",
                "rules": [{
                    "methods": ["GET"],
                    "path": "/private/**",
                    "dispatch": {
                        "kind": "route",
                        "route_id": "payments"
                    },
                    "action": "deny"
                }]
            }"#,
    );
    let mut config = routing_proxy_config(vec![pooled_route]);
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    let (router, probe) = proxy_router_with_work_probe(config, test_audit_log(), first_addr.ip());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/private/account")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("route-bound denial should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    probe.assert_no_work(
        "route-bound denial must not select a weighted endpoint or resolve a destination",
    );
    assert_upstream_receives_no_request(&mut first_captured, "primary endpoint denial").await;
    assert_upstream_receives_no_request(&mut second_captured, "secondary endpoint denial").await;
}

#[tokio::test]
async fn policy_can_bind_the_derived_route_id_of_an_unnamed_route() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let unnamed_route = path_route("/api", upstream_addr);
    assert!(
        unnamed_route.id.is_none(),
        "fixture must exercise a route with no explicit id"
    );
    // The id the gateway derives for this route, reports as
    // `upstream_route_id` on every observation event, and compares against
    // in the dispatch matcher.
    let route_id = crate::proxy::legacy_route_id(&unnamed_route);
    let policy = TempPolicyFile::new(
        &json!({
            "schema_version": "0.1.0",
            "default_action": "allow",
            "rules": [{
                "methods": ["GET"],
                "path": "/api/**",
                "dispatch": {
                    "kind": "route",
                    "route_id": route_id
                },
                "action": "deny"
            }]
        })
        .to_string(),
    );
    let mut config = routing_proxy_config(vec![unnamed_route]);
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());

    // Building the app runs policy dispatch validation, which previously
    // refused this rule and aborted startup.
    let router = proxy_router(config, test_audit_log());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/orders")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("route-bound denial should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_upstream_receives_no_request(
        &mut captured,
        "a rule bound to the derived route id must deny before proxying",
    )
    .await;
}

#[test]
fn catch_all_pool_migration_rejects_stale_legacy_origin_policy() {
    let upstream_addr: SocketAddr = "127.0.0.1:41001".parse().expect("test address");
    let mut pooled_route = route(None, None, upstream_addr);
    pooled_route.id = Some("payments".to_owned());
    pooled_route.upstream_url.clear();
    pooled_route.upstreams = vec![config::UpstreamEndpointConfig {
        id: "primary".to_owned(),
        url: "http://127.0.0.1:41001".to_owned(),
        weight: 1,
        tls_ca_bundle_path: None,
        client_identity_pem_path: None,
    }];
    let policy = TempPolicyFile::new(
        r#"{
                "schema_version": "0.1.0",
                "default_action": "allow",
                "rules": [{
                    "methods": ["GET"],
                    "path": "/private/**",
                    "dispatch": {
                        "kind": "legacy",
                        "upstream_origin": "http://127.0.0.1:41001"
                    },
                    "action": "deny"
                }]
            }"#,
    );
    let mut config = routing_proxy_config(vec![pooled_route]);
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    let recorder = PrometheusBuilder::new().build_recorder();

    let error = match app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    ) {
        Ok(_) => panic!("stale legacy-origin policy must fail closed during pool migration"),
        Err(error) => error,
    };

    assert!(
        error
            .to_string()
            .contains("replace it with {\"kind\":\"route\",\"route_id\":\"payments\"}"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn proxy_strips_inbound_forwarding_metadata_and_sets_canonical_peer_ip() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let router = proxy_router(proxy_config(upstream_addr), test_audit_log());
    let mut request = Request::builder()
        .uri("/api/forwarded")
        .header("forwarded", "for=198.51.100.12;proto=https")
        .header("x-forwarded-for", "198.51.100.10, 10.0.0.5")
        .header("x-real-ip", "198.51.100.11")
        .header("x-forwarded-host", "attacker.example")
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-port", "8443")
        .header("x-forwarded-prefix", "/attacker")
        .header("x-forwarded-server", "attacker-proxy")
        .header("cf-connecting-ip", "198.51.100.13")
        .header("true-client-ip", "198.51.100.14")
        .header("x-client-ip", "198.51.100.15")
        .header("x-original-forwarded-for", "198.51.100.16")
        .body(Body::empty())
        .expect("proxy request should build");
    request.extensions_mut().insert(axum::extract::ConnectInfo(
        "203.0.113.20:12345"
            .parse::<SocketAddr>()
            .expect("test peer address should parse"),
    ));

    let response = router
        .oneshot(request)
        .await
        .expect("proxy request should complete");

    assert_eq!(response.status(), StatusCode::CREATED);
    let upstream =
        next_proxied_request(&mut captured, "upstream should receive proxied request").await;
    let expected = HeaderValue::from_static("203.0.113.20");
    assert_eq!(
        upstream.headers.get(X_FORWARDED_FOR_HEADER),
        Some(&expected)
    );
    assert_eq!(upstream.headers.get(X_REAL_IP_HEADER), Some(&expected));
    assert_eq!(
        upstream
            .headers
            .get_all(X_FORWARDED_FOR_HEADER)
            .iter()
            .count(),
        1
    );
    assert_eq!(upstream.headers.get_all(X_REAL_IP_HEADER).iter().count(), 1);
    for stripped in [
        "forwarded",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-forwarded-port",
        "x-forwarded-prefix",
        "x-forwarded-server",
        "cf-connecting-ip",
        "true-client-ip",
        "x-client-ip",
        "x-original-forwarded-for",
    ] {
        assert!(
            !upstream.headers.contains_key(stripped),
            "upstream request should strip inbound {stripped}"
        );
    }
}

#[tokio::test]
async fn proxy_omits_client_forwarding_headers_without_a_valid_canonical_ip() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let router = proxy_router(proxy_config(upstream_addr), test_audit_log());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/forwarded")
                .header("x-forwarded-for", "198.51.100.10")
                .header("x-real-ip", "198.51.100.11")
                .body(Body::empty())
                .expect("proxy request should build"),
        )
        .await
        .expect("proxy request should complete");

    assert_eq!(response.status(), StatusCode::CREATED);
    let upstream =
        next_proxied_request(&mut captured, "upstream should receive proxied request").await;
    assert!(!upstream.headers.contains_key(X_FORWARDED_FOR_HEADER));
    assert!(!upstream.headers.contains_key(X_REAL_IP_HEADER));
}

#[tokio::test]
async fn proxy_path_ending_in_openapi_preview_does_not_get_preview_content_type_exception() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let mut config = proxy_config(upstream_addr);
    config.validation_allowed_content_types = vec!["application/json".to_owned()];
    let router = proxy_router(config, test_audit_log());

    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/some/other/prefix/tools/openapi/preview")
                .header(header::CONTENT_TYPE, "application/yaml")
                .body(Body::from("openapi: 3.0.3"))
                .expect("proxy request should build"),
        )
        .await
        .expect("proxy request should complete");

    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_upstream_receives_no_request(
        &mut captured,
        "content-type validation should reject suffix-confused proxy path",
    )
    .await;
}

#[tokio::test]
async fn routing_table_selects_two_upstreams_by_path_prefix() {
    let (api_addr, mut api_captured) = spawn_capture_upstream().await;
    let (assets_addr, mut assets_captured) = spawn_capture_upstream().await;
    let config = routing_proxy_config(vec![
        path_route("/api", api_addr),
        path_route("/assets", assets_addr),
    ]);
    assert!(config.egress_allowed_hosts.is_empty());
    let router = proxy_router(config, test_audit_log());

    let api_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/items?kind=primary")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("API proxy request should complete");
    assert_eq!(api_response.status(), StatusCode::CREATED);
    assert_eq!(
        body_string(api_response).await,
        "upstream GET /api/items?kind=primary"
    );

    let assets_response = router
        .oneshot(
            Request::builder()
                .uri("/assets/logo.svg")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("assets proxy request should complete");
    assert_eq!(assets_response.status(), StatusCode::CREATED);
    assert_eq!(
        body_string(assets_response).await,
        "upstream GET /assets/logo.svg"
    );

    let api_request =
        next_proxied_request(&mut api_captured, "API upstream should receive request").await;
    assert_eq!(api_request.path_and_query, "/api/items?kind=primary");
    let assets_request = next_proxied_request(
        &mut assets_captured,
        "assets upstream should receive request",
    )
    .await;
    assert_eq!(assets_request.path_and_query, "/assets/logo.svg");
}

#[tokio::test]
async fn routing_table_applies_distinct_timeout_per_upstream_route() {
    let short_addr = spawn_delayed_upstream(Duration::from_millis(250)).await;
    let long_addr = spawn_delayed_upstream(Duration::from_millis(250)).await;
    let mut short_route = path_route("/short", short_addr);
    short_route.timeout_ms = Some(75);
    let mut long_route = path_route("/long", long_addr);
    long_route.timeout_ms = Some(1_000);
    let router = proxy_router(
        routing_proxy_config(vec![short_route, long_route]),
        test_audit_log(),
    );

    let short_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/short/slow")
                .body(Body::empty())
                .expect("short-timeout request should build"),
        )
        .await
        .expect("short-timeout proxy request should complete");
    assert_eq!(short_response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(
        body_string(short_response).await,
        r#"{"error":"gateway_timeout"}"#
    );

    let long_response = router
        .oneshot(
            Request::builder()
                .uri("/long/slow")
                .body(Body::empty())
                .expect("long-timeout request should build"),
        )
        .await
        .expect("long-timeout proxy request should complete");
    assert_eq!(long_response.status(), StatusCode::CREATED);
    assert_eq!(body_string(long_response).await, "slow upstream");
}

#[tokio::test]
async fn routing_table_adds_configured_request_headers_per_route() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let mut route = path_route("/api", upstream_addr);
    route.add_request_headers =
        HashMap::from([("x-route-added".to_owned(), "route-added-value".to_owned())]);
    let router = proxy_router(routing_proxy_config(vec![route]), test_audit_log());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/headers")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("proxy request should complete");

    assert_eq!(response.status(), StatusCode::CREATED);
    let upstream =
        next_proxied_request(&mut captured, "upstream should receive proxied request").await;
    assert_eq!(
        upstream.headers.get("x-route-added"),
        Some(&HeaderValue::from_static("route-added-value"))
    );
}

#[tokio::test]
async fn routing_table_can_replace_gateway_forwarding_headers() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let mut route = path_route("/api", upstream_addr);
    route.add_request_headers = HashMap::from([
        ("forwarded".to_owned(), "for=192.0.2.39".to_owned()),
        ("x-forwarded-for".to_owned(), "192.0.2.40".to_owned()),
        ("x-real-ip".to_owned(), "192.0.2.41".to_owned()),
        ("x-forwarded-host".to_owned(), "gateway.example".to_owned()),
        ("x-forwarded-proto".to_owned(), "https".to_owned()),
        ("x-forwarded-port".to_owned(), "443".to_owned()),
        ("x-forwarded-prefix".to_owned(), "/api".to_owned()),
        ("true-client-ip".to_owned(), "192.0.2.42".to_owned()),
    ]);
    let router = proxy_router(routing_proxy_config(vec![route]), test_audit_log());
    let mut request = Request::builder()
        .uri("/api/headers")
        .header("forwarded", "for=198.51.100.10")
        .header("x-forwarded-host", "attacker.example")
        .header("x-forwarded-proto", "http")
        .header("x-forwarded-port", "8080")
        .header("x-forwarded-prefix", "/attacker")
        .header("true-client-ip", "198.51.100.11")
        .body(Body::empty())
        .expect("request should build");
    request.extensions_mut().insert(axum::extract::ConnectInfo(
        "203.0.113.20:12345"
            .parse::<SocketAddr>()
            .expect("test peer address should parse"),
    ));

    let response = router
        .oneshot(request)
        .await
        .expect("proxy request should complete");

    assert_eq!(response.status(), StatusCode::CREATED);
    let upstream =
        next_proxied_request(&mut captured, "upstream should receive proxied request").await;
    assert_eq!(
        upstream.headers.get(X_FORWARDED_FOR_HEADER),
        Some(&HeaderValue::from_static("192.0.2.40"))
    );
    assert_eq!(
        upstream.headers.get(X_REAL_IP_HEADER),
        Some(&HeaderValue::from_static("192.0.2.41"))
    );
    assert_eq!(
        upstream.headers.get("forwarded"),
        Some(&HeaderValue::from_static("for=192.0.2.39"))
    );
    assert_eq!(
        upstream.headers.get("x-forwarded-host"),
        Some(&HeaderValue::from_static("gateway.example"))
    );
    assert_eq!(
        upstream.headers.get("x-forwarded-proto"),
        Some(&HeaderValue::from_static("https"))
    );
    assert_eq!(
        upstream.headers.get("x-forwarded-port"),
        Some(&HeaderValue::from_static("443"))
    );
    assert_eq!(
        upstream.headers.get("x-forwarded-prefix"),
        Some(&HeaderValue::from_static("/api"))
    );
    assert_eq!(
        upstream.headers.get("true-client-ip"),
        Some(&HeaderValue::from_static("192.0.2.42"))
    );
}

#[tokio::test]
async fn routing_table_can_strip_gateway_forwarding_headers() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let mut route = path_route("/api", upstream_addr);
    route.strip_request_headers = vec!["x-forwarded-for".to_owned(), "x-real-ip".to_owned()];
    let router = proxy_router(routing_proxy_config(vec![route]), test_audit_log());
    let mut request = Request::builder()
        .uri("/api/headers")
        .body(Body::empty())
        .expect("request should build");
    request.extensions_mut().insert(axum::extract::ConnectInfo(
        "203.0.113.20:12345"
            .parse::<SocketAddr>()
            .expect("test peer address should parse"),
    ));

    let response = router
        .oneshot(request)
        .await
        .expect("proxy request should complete");

    assert_eq!(response.status(), StatusCode::CREATED);
    let upstream =
        next_proxied_request(&mut captured, "upstream should receive proxied request").await;
    assert!(!upstream.headers.contains_key(X_FORWARDED_FOR_HEADER));
    assert!(!upstream.headers.contains_key(X_REAL_IP_HEADER));
}

#[tokio::test]
async fn routing_table_strips_client_credentials_by_default() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let router = proxy_router(
        routing_proxy_config(vec![path_route("/api", upstream_addr)]),
        test_audit_log(),
    );

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/headers")
                .header(header::AUTHORIZATION, "Bearer client-token")
                .header(header::COOKIE, "session=client")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("proxy request should complete");

    assert_eq!(response.status(), StatusCode::CREATED);
    let upstream =
        next_proxied_request(&mut captured, "upstream should receive proxied request").await;
    assert!(!upstream.headers.contains_key(header::AUTHORIZATION));
    assert!(!upstream.headers.contains_key(header::COOKIE));
}

#[tokio::test]
async fn routing_table_replaces_client_credentials_with_configured_upstream_credentials() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let mut route = path_route("/api", upstream_addr);
    route.add_request_headers = HashMap::from([
        (
            header::AUTHORIZATION.as_str().to_owned(),
            "Bearer configured-upstream-token".to_owned(),
        ),
        (
            header::COOKIE.as_str().to_owned(),
            "upstream-session=configured".to_owned(),
        ),
    ]);
    let router = proxy_router(routing_proxy_config(vec![route]), test_audit_log());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/headers")
                .header(header::AUTHORIZATION, "Bearer client-token")
                .header(header::COOKIE, "session=client")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("proxy request should complete");

    assert_eq!(response.status(), StatusCode::CREATED);
    let upstream =
        next_proxied_request(&mut captured, "upstream should receive proxied request").await;
    assert_eq!(
        upstream.headers.get(header::AUTHORIZATION),
        Some(&HeaderValue::from_static(
            "Bearer configured-upstream-token"
        ))
    );
    assert_eq!(
        upstream.headers.get(header::COOKIE),
        Some(&HeaderValue::from_static("upstream-session=configured"))
    );
}

#[tokio::test]
async fn connection_bound_proxy_uses_stored_destination_and_protects_its_dependency() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let connection_db = TempDb::new("connection-proxy-static-auth");
    let mut config = routing_proxy_config(Vec::new());
    config.connections_sqlite_path = Some(connection_db.path.to_string_lossy().into_owned());
    config.egress_allowed_hosts = vec!["127.0.0.1".to_owned()];
    let control_plane = connections::control_plane::ConnectionControlPlane::from_config(&config)
        .expect("test Connection control plane should build");
    let initial = control_plane.runtime_snapshot();
    let created = control_plane
        .create_managed(
            initial.collection_etag(),
            serde_json::from_value(json!({
                "display_name": "Billing API",
                "enabled": true,
                "kind": "http_api",
                "endpoint": {
                    "base_url": format!("http://127.0.0.1:{}", upstream_addr.port()),
                    "base_path": "/v1"
                },
                "authentication": {
                    "type": "none"
                }
            }))
            .expect("test Connection should deserialize"),
            &crate::auth::change_actor::ChangeActor::for_test("test-admin"),
        )
        .await
        .expect("test Connection should create");
    let mut route = path_route("/billing", upstream_addr);
    route.id = Some("billing-route".to_owned());
    route.connection_id = Some(created.id.to_string());
    route.upstream_url.clear();
    route.add_request_headers = HashMap::from([("x-route-label".to_owned(), "billing".to_owned())]);
    config.upstream_routes = vec![route];
    let router = proxy_router(config, test_audit_log());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/billing/charges?expand=customer")
                .header(header::AUTHORIZATION, "Bearer caller-token")
                .header(header::COOKIE, "session=caller")
                .header("x-end-to-end", "preserved")
                .body(Body::empty())
                .expect("connection-bound proxy request should build"),
        )
        .await
        .expect("connection-bound proxy request should complete");

    assert_eq!(response.status(), StatusCode::CREATED);
    let upstream =
        next_proxied_request(&mut captured, "stored Connection should receive request").await;
    assert_eq!(
        upstream.path_and_query,
        "/v1/billing/charges?expand=customer"
    );
    assert!(!upstream.headers.contains_key(header::AUTHORIZATION));
    assert!(!upstream.headers.contains_key(header::COOKIE));
    assert_eq!(
        upstream.headers.get("x-route-label"),
        Some(&HeaderValue::from_static("billing"))
    );
    assert_eq!(
        upstream.headers.get("x-end-to-end"),
        Some(&HeaderValue::from_static("preserved"))
    );

    let dependency_protected = control_plane
        .delete_managed(
            &created.id,
            &created.etag(),
            &crate::auth::change_actor::ChangeActor::for_test("test-admin"),
        )
        .await;
    assert!(matches!(
        dependency_protected,
        Err(connections::control_plane::ConnectionMutationError::Store(
            connections::store::ConnectionStoreError::DependencyConflict { count: 1, .. }
        ))
    ));
}

#[tokio::test]
async fn routing_table_strips_configured_and_request_id_headers() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let mut route = path_route("/api", upstream_addr);
    route.strip_request_headers = vec!["x-client-secret".to_owned()];
    let router = proxy_router(routing_proxy_config(vec![route]), test_audit_log());
    let request_id = HeaderValue::from_static("route-strip-request-id");

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/headers")
                .header(REQUEST_ID_HEADER, request_id.clone())
                .header("x-client-secret", "remove-me")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("proxy request should complete");

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers().get(REQUEST_ID_HEADER), Some(&request_id));
    let upstream =
        next_proxied_request(&mut captured, "upstream should receive proxied request").await;
    assert!(!upstream.headers.contains_key("x-client-secret"));
    assert!(!upstream.headers.contains_key(REQUEST_ID_HEADER));
}

#[tokio::test]
async fn routing_table_tls_ca_bundle_is_applied_only_to_configured_route() {
    let mut trusted_upstream = spawn_tls_capture_upstream().await;
    let mut untrusted_upstream = spawn_tls_capture_upstream().await;
    let ca_bundle_path =
        std::env::temp_dir().join(format!("greengateway-test-ca-{}.pem", uuid::Uuid::new_v4()));
    fs::write(&ca_bundle_path, trusted_upstream.ca_pem.as_bytes())
        .expect("test CA bundle should be written");

    let mut trusted_route = https_path_route("/trusted", trusted_upstream.addr);
    trusted_route.tls_ca_bundle_path = Some(ca_bundle_path.clone());
    trusted_route.timeout_ms = Some(1_000);
    let mut untrusted_route = https_path_route("/untrusted", untrusted_upstream.addr);
    untrusted_route.timeout_ms = Some(1_000);
    let router = proxy_router(
        routing_proxy_config(vec![trusted_route, untrusted_route]),
        test_audit_log(),
    );

    let trusted_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/trusted/tls")
                .body(Body::empty())
                .expect("trusted TLS request should build"),
        )
        .await
        .expect("trusted TLS proxy request should complete");
    assert_eq!(trusted_response.status(), StatusCode::CREATED);
    assert_eq!(body_string(trusted_response).await, "tls upstream");
    let trusted_request = next_proxied_request(
        &mut trusted_upstream.captured,
        "trusted TLS upstream should receive request",
    )
    .await;
    assert_eq!(trusted_request.path_and_query, "/trusted/tls");

    let untrusted_response = router
        .oneshot(
            Request::builder()
                .uri("/untrusted/tls")
                .body(Body::empty())
                .expect("untrusted TLS request should build"),
        )
        .await
        .expect("untrusted TLS proxy request should complete");
    assert_eq!(untrusted_response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        body_string(untrusted_response).await,
        r#"{"error":"bad_gateway"}"#
    );
    assert_upstream_receives_no_request(
        &mut untrusted_upstream.captured,
        "untrusted TLS route should fail during handshake before HTTP request",
    )
    .await;

    let _ = fs::remove_file(ca_bundle_path);
}

#[tokio::test]
async fn routing_table_uses_longest_matching_path_prefix() {
    let (short_addr, mut short_captured) = spawn_capture_upstream().await;
    let (long_addr, mut long_captured) = spawn_capture_upstream().await;
    let router = proxy_router(
        routing_proxy_config(vec![
            path_route("/api", short_addr),
            path_route("/api/internal", long_addr),
        ]),
        test_audit_log(),
    );

    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/internal/jobs/42")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("proxy request should complete");

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        body_string(response).await,
        "upstream GET /api/internal/jobs/42"
    );
    let long_request = next_proxied_request(
        &mut long_captured,
        "longest-prefix upstream should receive request",
    )
    .await;
    assert_eq!(long_request.path_and_query, "/api/internal/jobs/42");
    assert_upstream_receives_no_request(
        &mut short_captured,
        "shorter prefix should lose to longer prefix",
    )
    .await;
}

#[tokio::test]
async fn routing_table_host_and_path_match_and_host_specific_tie_wins() {
    let (path_only_addr, mut path_only_captured) = spawn_capture_upstream().await;
    let (host_path_addr, mut host_path_captured) = spawn_capture_upstream().await;
    let router = proxy_router(
        routing_proxy_config(vec![
            path_route("/api", path_only_addr),
            host_path_route("api.example.test", "/api", host_path_addr),
        ]),
        test_audit_log(),
    );

    let host_specific_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/items")
                .header(header::HOST, "api.example.test:9443")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("host-specific proxy request should complete");
    assert_eq!(host_specific_response.status(), StatusCode::CREATED);
    assert_eq!(
        body_string(host_specific_response).await,
        "upstream GET /api/items"
    );
    let host_specific_request = next_proxied_request(
        &mut host_path_captured,
        "host-specific upstream should receive request",
    )
    .await;
    assert_eq!(host_specific_request.path_and_query, "/api/items");

    let path_only_response = router
        .oneshot(
            Request::builder()
                .uri("/api/items")
                .header(header::HOST, "other.example.test")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("path-only proxy request should complete");
    assert_eq!(path_only_response.status(), StatusCode::CREATED);
    assert_eq!(
        body_string(path_only_response).await,
        "upstream GET /api/items"
    );
    let path_only_request = next_proxied_request(
        &mut path_only_captured,
        "path-only upstream should receive fallback request",
    )
    .await;
    assert_eq!(path_only_request.path_and_query, "/api/items");
}

#[tokio::test]
async fn routing_table_unmatched_paths_return_404() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let router = proxy_router(
        routing_proxy_config(vec![path_route("/api", upstream_addr)]),
        test_audit_log(),
    );

    let response = router
        .oneshot(
            Request::builder()
                .uri("/other")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_upstream_receives_no_request(&mut captured, "unmatched route should not proxy").await;
}

#[tokio::test]
async fn routing_table_reserved_gateway_paths_never_reach_matching_upstream() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let router = proxy_router(
        routing_proxy_config(vec![path_route("/admin", upstream_addr)]),
        test_audit_log(),
    );

    let response = router
        .oneshot(
            Request::builder()
                .uri("/v1/admin/not-found")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("reserved path request should complete");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_upstream_receives_no_request(
        &mut captured,
        "route table must not override gateway-owned paths",
    )
    .await;
}

#[tokio::test]
async fn host_qualified_fallback_policy_cannot_replace_mcp_route_policy() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let policy = TempPolicyFile::new(
        r#"{
                "schema_version": "0.1.0",
                "default_action": "deny",
                "roles": {},
                "routes": [
                    {
                        "methods": ["POST"],
                        "path_prefix": "/mcp",
                        "permission": "admin:mcp:use"
                    },
                    {
                        "methods": ["POST"],
                        "hosts": ["app.example.test"],
                        "path_prefix": "/",
                        "permission": "app:proxy"
                    }
                ]
            }"#,
    );
    let mut config = routing_proxy_config(vec![host_path_route(
        "app.example.test",
        "/",
        upstream_addr,
    )]);
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = proxy_router(config, audit_log);

    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/mcp")
                .header(header::HOST, "app.example.test")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                ))
                .expect("request should build"),
        )
        .await
        .expect("MCP request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eventually(Duration::from_secs(1), || {
        capture.events().iter().any(|event| {
            event.event_type == "authz.denied"
                && event.payload["permission"] == json!("admin:mcp:use")
        })
    });
    assert!(!capture.events().iter().any(|event| {
        event.event_type.starts_with("authz.") && event.payload["permission"] == json!("app:proxy")
    }));
    assert_upstream_receives_no_request(
        &mut captured,
        "host-qualified fallback must not replace MCP route authorization",
    )
    .await;
}

#[tokio::test]
async fn host_qualified_fallback_policy_cannot_replace_oauth_metadata_route() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let policy = TempPolicyFile::new(
        r#"{
                "schema_version": "0.1.0",
                "default_action": "allow",
                "roles": {},
                "routes": []
            }"#,
    );
    let mut config = routing_proxy_config(vec![host_path_route(
        "app.example.test",
        "/",
        upstream_addr,
    )]);
    config.gateway_public_url = Some("https://gateway.example.test".to_owned());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    let router = proxy_router(config, test_audit_log());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/.well-known/oauth-protected-resource/mcp")
                .header(header::HOST, "app.example.test")
                .body(Body::empty())
                .expect("metadata request should build"),
        )
        .await
        .expect("metadata request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await["resource"],
        json!("https://gateway.example.test/mcp")
    );
    assert_upstream_receives_no_request(
        &mut captured,
        "host-qualified fallback must not replace OAuth metadata",
    )
    .await;
}

#[tokio::test]
async fn host_qualified_fallback_policy_applies_to_custom_rbac_exemption() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let policy = TempPolicyFile::new(
        r#"{
                "schema_version": "0.1.0",
                "default_action": "allow",
                "roles": {},
                "routes": []
            }"#,
    );
    let mut config = routing_proxy_config(vec![host_path_route(
        "app.example.test",
        "/",
        upstream_addr,
    )]);
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.rbac_exempt_paths.push("/public".to_owned());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = proxy_router(config, audit_log);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/public/report")
                .header(header::HOST, "app.example.test")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("host-qualified exempt request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eventually(Duration::from_secs(1), || {
        capture.events().iter().any(|event| {
            event.event_type == "authz.denied"
                && event.payload["reason"] == json!("host_policy_required")
        })
    });
    assert_upstream_receives_no_request(
        &mut captured,
        "custom RBAC exemption must not bypass host-qualified policy",
    )
    .await;
}

#[tokio::test]
async fn proxy_rejects_unsafe_gateway_namespace_paths_without_rbac() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let config = proxy_config(upstream_addr);
    assert!(config.policy_file.is_none());
    let router = proxy_router(config, test_audit_log());

    for path in [
        "/admin%2Fassets/app.js",
        "/v1%2Fadmin%2Faudit",
        "/mcp%2Ftools/call",
        "/public/../admin",
        "/public/..\\admin",
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("unsafe path request should build"),
            )
            .await
            .expect("unsafe path request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_upstream_receives_no_request(
            &mut captured,
            "unsafe path must not reach proxy upstream without RBAC",
        )
        .await;
    }
}

#[tokio::test]
async fn legacy_upstream_url_only_behavior_still_proxies_unmatched_paths() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let config = proxy_config(upstream_addr);
    assert!(config.upstream_routes.is_empty());
    let router = proxy_router(config, test_audit_log());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/legacy?ok=true")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("legacy proxy request should complete");

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(body_string(response).await, "upstream GET /legacy?ok=true");
    let upstream =
        next_proxied_request(&mut captured, "legacy upstream should receive request").await;
    assert_eq!(upstream.path_and_query, "/legacy?ok=true");
}

#[tokio::test]
async fn proxy_auto_seeds_configured_upstream_host_into_egress_allowlist() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let mut config = proxy_config(upstream_addr);
    config.egress_allowed_hosts.clear();
    let router = proxy_router(config, test_audit_log());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/auto-seeded?ok=true")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("proxy request should complete");

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(
        body_string(response).await,
        "upstream GET /auto-seeded?ok=true"
    );
    let upstream =
        next_proxied_request(&mut captured, "upstream should receive proxied request").await;
    assert_eq!(upstream.path_and_query, "/auto-seeded?ok=true");
}

#[tokio::test]
async fn proxy_auto_seeded_private_upstream_still_requires_private_ip_opt_out() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let mut config = proxy_config(upstream_addr);
    config.egress_allowed_hosts.clear();
    config.egress_deny_private_ips = true;
    let egress_config = egress::EgressConfig::from_config(&config);
    assert!(egress_config.allowed_hosts.contains("127.0.0.1"));
    assert!(egress_config.deny_private_ips);
    let router = proxy_router(config, test_audit_log());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/private-blocked")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("proxy request should complete");

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(body_string(response).await, r#"{"error":"bad_gateway"}"#);
    assert_upstream_receives_no_request(
        &mut captured,
        "auto-seeded private upstream should still be blocked before proxying",
    )
    .await;
}

#[tokio::test]
async fn proxy_streams_upstream_response_without_buffering() {
    let upstream_addr =
        spawn_router(Router::new().route("/stream", get(delayed_stream_upstream))).await;
    let router = proxy_router(proxy_config(upstream_addr), test_audit_log());

    // These two guards must sum to well under the upstream's 2s inter-chunk
    // gap, so the negative "not buffered" check below still lands inside the
    // gap on a slow run. Buffering would delay headers to ~2s, so 500ms is
    // ample to detect it.
    let response = tokio::time::timeout(
        Duration::from_millis(500),
        router.oneshot(
            Request::builder()
                .uri("/stream")
                .body(Body::empty())
                .expect("request should build"),
        ),
    )
    .await
    .expect("proxy should return response headers before full body is sent")
    .expect("proxy request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body().into_data_stream();
    let first = tokio::time::timeout(Duration::from_millis(500), body.next())
        .await
        .expect("first proxied chunk should arrive")
        .expect("body should yield first chunk")
        .expect("first chunk should be ok");
    assert_eq!(&first[..], b"first");

    assert!(
        tokio::time::timeout(Duration::from_millis(100), body.next())
            .await
            .is_err(),
        "second chunk should not be buffered before upstream sends it"
    );

    let second = tokio::time::timeout(Duration::from_secs(3), body.next())
        .await
        .expect("second proxied chunk should arrive")
        .expect("body should yield second chunk")
        .expect("second chunk should be ok");
    assert_eq!(&second[..], b"second");
}

#[tokio::test]
async fn streaming_proxy_forwards_the_first_request_chunk_before_body_completion() {
    let (upstream_addr, mut observed) = spawn_stream_observer_upstream().await;
    let mut config = proxy_config(upstream_addr);
    config.egress_max_request_body_bytes = 32;
    let router = streaming_proxy_router(config);
    let (chunks_tx, chunks_rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(2);
    let request_body = Body::from_stream(stream::unfold(chunks_rx, |mut chunks| async move {
        chunks.recv().await.map(|chunk| (chunk, chunks))
    }));
    let request = tokio::spawn(
        router.oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/upload")
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(request_body)
                .expect("streaming request should build"),
        ),
    );

    chunks_tx
        .send(Ok(Bytes::from_static(b"first")))
        .await
        .expect("first client chunk should send");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), observed.recv())
            .await
            .expect("upstream should receive the first chunk before completion"),
        Some(Ok(b"first".to_vec()))
    );
    assert!(
        !request.is_finished(),
        "proxy response must still wait for the unfinished request body"
    );

    chunks_tx
        .send(Ok(Bytes::from_static(b"-second")))
        .await
        .expect("second client chunk should send");
    drop(chunks_tx);
    let response = tokio::time::timeout(Duration::from_secs(2), request)
        .await
        .expect("streamed proxy request should finish")
        .expect("streamed proxy task should join")
        .expect("streamed proxy request should complete");
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(body_string(response).await, "12");
    assert_eq!(observed.recv().await, Some(Ok(b"first-second".to_vec())));
}

#[tokio::test]
async fn streaming_proxy_preflights_known_oversize_body_without_upstream_bytes() {
    let (upstream_addr, mut observed) = spawn_stream_observer_upstream().await;
    let mut config = proxy_config(upstream_addr);
    config.egress_max_request_body_bytes = 4;
    let router = streaming_proxy_router(config);
    let chunks =
        stream::once(async { Ok::<Bytes, std::io::Error>(Bytes::from_static(b"oversize")) });

    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/upload")
                .header(header::CONTENT_LENGTH, "8")
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::from_stream(chunks))
                .expect("known-size streaming request should build"),
        )
        .await
        .expect("known-size streaming request should complete");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = body_string(response).await;
    assert!(!body.contains("upstream"));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), observed.recv())
            .await
            .is_err(),
        "known oversize bodies must be rejected before upstream bytes"
    );
}

#[tokio::test]
async fn streaming_proxy_unknown_overflow_forwards_only_the_bounded_prefix() {
    let (upstream_addr, mut observed) = spawn_stream_observer_upstream().await;
    let mut config = proxy_config(upstream_addr);
    config.egress_max_request_body_bytes = 4;
    let router = streaming_proxy_router(config);
    let (chunks_tx, chunks_rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(2);
    let chunks = stream::unfold(chunks_rx, |mut chunks| async move {
        chunks.recv().await.map(|chunk| (chunk, chunks))
    });
    let request = tokio::spawn(
        router.oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/upload")
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::from_stream(chunks))
                .expect("unknown-size streaming request should build"),
        ),
    );
    chunks_tx
        .send(Ok(Bytes::from_static(b"abc")))
        .await
        .expect("bounded client prefix should send");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), observed.recv())
            .await
            .expect("upstream should receive the bounded prefix"),
        Some(Ok(b"abc".to_vec()))
    );
    chunks_tx
        .send(Ok(Bytes::from_static(b"def")))
        .await
        .expect("overflowing client chunk should send");
    drop(chunks_tx);
    let response = tokio::time::timeout(Duration::from_secs(2), request)
        .await
        .expect("unknown-size overflow should finish")
        .expect("unknown-size overflow task should join")
        .expect("unknown-size streaming request should complete");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        body_string(response).await,
        r#"{"error":"payload_too_large"}"#
    );
    let mut largest_prefix = b"abc".to_vec();
    let mut saw_body_error = false;
    while let Ok(Some(observation)) =
        tokio::time::timeout(Duration::from_millis(100), observed.recv()).await
    {
        match observation {
            Ok(prefix) => largest_prefix = prefix,
            Err(received) => {
                assert!(received <= 4);
                assert_eq!(received, largest_prefix.len());
                saw_body_error = true;
                break;
            }
        }
    }
    assert!(b"abcd".starts_with(&largest_prefix));
    assert!(largest_prefix.len() <= 4);
    assert!(
        saw_body_error,
        "upstream should observe a bounded body abort"
    );
}

#[tokio::test]
async fn proxy_returns_502_for_reset_upstream_without_leaking_details() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let upstream_addr = listener
        .local_addr()
        .expect("listener address should be available");
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .expect("test server should accept a connection");
            drop(stream);
        }
    });
    let mut config = proxy_config(upstream_addr);
    config.egress_timeout_ms = 1000;
    config.egress_connect_timeout_ms = 100;
    let router = proxy_router(config, test_audit_log());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/unmatched")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("proxy request should complete");

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(body_string(response).await, r#"{"error":"bad_gateway"}"#);
    server.abort();
}

#[tokio::test]
async fn proxy_uses_upstream_timeout_override_for_timed_out_upstream() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let upstream_addr = listener
        .local_addr()
        .expect("listener address should be available");
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .expect("test server should accept a connection");
            tokio::spawn(async move {
                let _stream = stream;
                tokio::time::sleep(Duration::from_secs(2)).await;
            });
        }
    });
    let mut config = proxy_config(upstream_addr);
    config.egress_timeout_ms = 5_000;
    config.egress_connect_timeout_ms = 5_000;
    config.upstream_timeout_ms = Some(100);
    config.upstream_connect_timeout_ms = Some(100);
    let router = proxy_router(config, test_audit_log());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/slow")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("proxy request should complete");

    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(
        body_string(response).await,
        r#"{"error":"gateway_timeout"}"#
    );
    server.abort();
}

/// Reads one request head from a raw upstream fixture connection and returns
/// its request line, or `None` when the peer closes or sends no valid head
/// (the fixture then answers nothing). A raw fixture must not answer before
/// this returns: hyper's HTTP/1.1 client rejects bytes that arrive on a
/// connection it has not yet written a request to ("unexpected message"),
/// which the proxy reports as a 502. Since tokio 1.54 an accepted socket starts
/// out writable, so a fixture that writes straight after `accept` wins that
/// race instead of waiting for the reactor's first event.
async fn read_raw_http_request_line(stream: &mut tokio::net::TcpStream) -> Option<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    while buffer.len() <= 16 * 1024 {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = std::str::from_utf8(&buffer[..end]).ok()?;
            return head.split("\r\n").next().map(str::to_owned);
        }
    }
    None
}

#[tokio::test]
async fn proxy_returns_504_when_streaming_upstream_body_idles_before_first_chunk() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test listener should bind");
    let upstream_addr = listener
        .local_addr()
        .expect("listener address should be available");
    let (request_lines, mut received_request_lines) = tokio::sync::mpsc::unbounded_channel();
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("test server should accept a connection");
            let request_lines = request_lines.clone();
            tokio::spawn(async move {
                // Headers go out only once a request head has arrived (the
                // proxied request, or the app's own `HEAD /` health probe),
                // then the body idles before its first chunk.
                let Some(request_line) = read_raw_http_request_line(&mut stream).await else {
                    return;
                };
                let _ = request_lines.send(request_line);
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .expect("test server should write response headers");
                tokio::time::sleep(Duration::from_secs(10)).await;
            });
        }
    });
    let mut config = proxy_config(upstream_addr);
    config.egress_timeout_ms = 5_000;
    config.egress_response_idle_timeout_ms = 5_000;
    config.egress_connect_timeout_ms = 100;
    config.upstream_response_idle_timeout_ms = Some(100);
    let router = proxy_router(config, test_audit_log());

    let response = tokio::time::timeout(
        Duration::from_secs(1),
        router.oneshot(
            Request::builder()
                .uri("/slow-body")
                .body(Body::empty())
                .expect("request should build"),
        ),
    )
    .await
    .expect("proxy should return idle timeout response")
    .expect("proxy request should complete");

    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(
        body_string(response).await,
        r#"{"error":"gateway_timeout"}"#
    );
    // The fixture sends a request's line before answering it, and the 504
    // needs those headers, so the proxied request is already recorded here.
    let mut request_lines = Vec::new();
    while let Ok(request_line) = received_request_lines.try_recv() {
        request_lines.push(request_line);
    }
    assert!(
        request_lines
            .iter()
            .any(|request_line| request_line == "GET /slow-body HTTP/1.1"),
        "the idle response should answer the proxied request: {request_lines:?}"
    );
    server.abort();
}

#[tokio::test]
async fn proxied_documents_are_sandboxed_without_disabling_the_admin_ui() {
    let (address, _captured) = spawn_capture_upstream().await;
    let config = proxy_config(address);
    let routes = GatewayRoutes::from_config(&config);
    let router = proxy_router(config, test_audit_log());
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/document")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response
        .headers()
        .get_all(header::CONTENT_SECURITY_POLICY)
        .iter()
        .any(|value| value == "sandbox; frame-ancestors 'none'"));
    let response = router
        .oneshot(
            Request::builder()
                .uri(routes.admin.ui_prefix.as_str())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response
        .headers()
        .get_all(header::CONTENT_SECURITY_POLICY)
        .iter()
        .any(|value| value == "sandbox; frame-ancestors 'none'"));
}

#[tokio::test]
async fn existing_routes_win_over_proxy_fallback() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let router = proxy_router(proxy_config(upstream_addr), test_audit_log());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("health request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["status"], json!("ok"));
    assert_eq!(body["upstream"]["configured"], json!(true));
    assert_upstream_receives_no_request(&mut captured, "health route should not be proxied").await;
}

#[tokio::test]
async fn reserved_gateway_paths_never_reach_proxy_upstream() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let config = proxy_config(upstream_addr);
    let routes = GatewayRoutes::from_config(&config);
    let router = proxy_router(config, test_audit_log());

    let admin_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(routes.admin.ui_prefix.as_str())
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("admin UI request should complete");

    assert_eq!(admin_response.status(), StatusCode::OK);
    assert!(body_string(admin_response)
        .await
        .contains(r#"<div id="root"></div>"#));

    let audit_response = router
        .oneshot(audit_query_request(&routes.admin.audit_route, None))
        .await
        .expect("audit request should complete");

    assert_eq!(audit_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_string(audit_response).await,
        r#"{"error":"unauthorized"}"#
    );
    assert_upstream_receives_no_request(
        &mut captured,
        "reserved admin UI and audit API paths should not be proxied",
    )
    .await;
}

#[tokio::test]
async fn custom_admin_prefix_moves_admin_surface_and_frees_default_admin_path() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let mut config = proxy_config(upstream_addr);
    let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
    config.admin_prefix = "/ops".to_owned();
    config.csrf_cookie_name = "ops_csrf".to_owned();
    config.csrf_header_name = "x-ops-csrf".to_owned();
    config.auth_exempt_paths = vec![
        "/health".to_owned(),
        "/version".to_owned(),
        "/metrics".to_owned(),
        "/ops".to_owned(),
    ];
    config.rbac_exempt_paths = config.auth_exempt_paths.clone();
    config = status_config_with_policy(config, &policy);
    let routes = GatewayRoutes::from_config(&config);
    let router = proxy_router(config, test_audit_log());

    let admin_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ops")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("custom admin UI request should complete");

    assert_eq!(admin_response.status(), StatusCode::OK);
    let admin_body = body_string(admin_response).await;
    assert!(admin_body.contains(r#"<div id="root"></div>"#));
    assert!(admin_body.contains(r#"greengateway-admin-base" content="/ops""#));
    assert!(admin_body.contains(r#"greengateway-admin-api-base" content="/v1/ops""#));
    assert!(admin_body.contains(r#"greengateway-csrf-cookie-name" content="ops_csrf""#));
    assert!(admin_body.contains(r#"greengateway-csrf-header-name" content="x-ops-csrf""#));
    assert!(admin_body.contains(r#"/ops/assets/"#));

    let status_response = router
        .clone()
        .oneshot(audit_query_request(
            &routes.admin.status_route,
            Some(test_principal(&["admin"])),
        ))
        .await
        .expect("custom admin status request should complete");

    assert_eq!(status_response.status(), StatusCode::OK);
    let status_body = json_body(status_response).await;
    assert_eq!(status_body["version"], json!(env!("CARGO_PKG_VERSION")));

    let old_admin_response = router
        .oneshot(
            Request::builder()
                .uri("/admin")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("old admin path request should complete");

    assert_eq!(old_admin_response.status(), StatusCode::CREATED);
    assert_eq!(body_string(old_admin_response).await, "upstream GET /admin");
    let upstream = next_proxied_request(
        &mut captured,
        "old admin path should fall through to upstream",
    )
    .await;
    assert_eq!(upstream.method, Method::GET);
    assert_eq!(upstream.path_and_query, "/admin");
    assert_upstream_receives_no_request(
        &mut captured,
        "custom admin UI and API paths should not be proxied",
    )
    .await;
}

#[tokio::test]
async fn custom_admin_prefix_api_requires_and_accepts_real_bearer_auth() {
    let jwks_addr = spawn_test_jwks_server().await;
    let db = TempDb::new("custom-admin-real-auth");
    create_audit_schema(&db.path);
    let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
    let mut config = test_config(Vec::new());
    config.admin_prefix = "/ops".to_owned();
    config.auth_exempt_paths = vec![
        "/health".to_owned(),
        "/version".to_owned(),
        "/metrics".to_owned(),
        "/ops".to_owned(),
    ];
    config.rbac_exempt_paths = config.auth_exempt_paths.clone();
    config.audit_sqlite_path = Some(db.path.to_string_lossy().into_owned());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    configure_test_jwt_provider(&mut config, jwks_addr);
    config.egress_deny_private_ips = false;
    let routes = GatewayRoutes::from_config(&config);
    config
        .rbac_exempt_paths
        .push(routes.admin.audit_route.clone());
    assert_eq!(routes.admin.api_prefix, "/v1/ops");
    assert_eq!(routes.admin.audit_route, "/v1/ops/audit");

    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");

    let ui_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ops")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("custom admin UI request should complete");
    assert_eq!(ui_response.status(), StatusCode::OK);

    let missing_token_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(routes.admin.audit_route.as_str())
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("unauthenticated custom audit request should complete");
    assert_eq!(missing_token_response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        body_string(missing_token_response).await,
        r#"{"error":"unauthorized"}"#
    );

    let token = signed_admin_token();
    let authenticated_response = router
        .oneshot(
            Request::builder()
                .uri(routes.admin.audit_route.as_str())
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("authenticated custom audit request should complete");
    assert_eq!(authenticated_response.status(), StatusCode::OK);
    assert_eq!(json_body(authenticated_response).await["events"], json!([]));
}

#[test]
fn unowned_exempt_paths_flags_stale_admin_prefix() {
    let mut config = test_config(Vec::new());
    config.admin_prefix = "/ops".to_owned();
    let routes = GatewayRoutes::from_config(&config);
    let exempt_paths = vec!["/health".to_owned(), "/admin".to_owned()];

    assert_eq!(routes.unowned_exempt_paths(&exempt_paths), vec!["/admin"]);
}

#[test]
fn unowned_exempt_paths_are_empty_for_owned_paths() {
    let config = test_config(Vec::new());
    let routes = GatewayRoutes::from_config(&config);
    let exempt_paths = vec![
        "/health".to_owned(),
        "/admin".to_owned(),
        "/admin/assets/app.js".to_owned(),
        "/v1/admin/auth/login".to_owned(),
    ];

    assert!(routes.unowned_exempt_paths(&exempt_paths).is_empty());
}

#[test]
fn unowned_exempt_paths_respect_custom_admin_api_prefix() {
    let mut config = test_config(Vec::new());
    config.admin_prefix = "/ops".to_owned();
    let routes = GatewayRoutes::from_config(&config);
    let exempt_paths = vec![
        "/v1/ops/auth/login".to_owned(),
        "/v1/admin/auth/login".to_owned(),
    ];

    assert_eq!(
        routes.unowned_exempt_paths(&exempt_paths),
        vec!["/v1/admin/auth/login"]
    );
}

#[tokio::test]
async fn custom_admin_prefix_is_reserved_from_proxy_collisions() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let mut config = proxy_config(upstream_addr);
    config.admin_prefix = "/ops".to_owned();
    config.auth_exempt_paths = vec![
        "/health".to_owned(),
        "/version".to_owned(),
        "/metrics".to_owned(),
        "/ops".to_owned(),
    ];
    config.rbac_exempt_paths = config.auth_exempt_paths.clone();
    let routes = GatewayRoutes::from_config(&config);
    let router = proxy_router(config, test_audit_log());
    assert_eq!(routes.admin.api_prefix, "/v1/ops");
    assert!(routes.is_gateway_owned_path("/ops/assets/app.js"));
    assert!(routes.is_gateway_owned_path("/v1/ops/audit"));
    assert!(!routes.is_gateway_owned_path("/ops-api/audit"));

    let admin_response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(routes.admin.ui_prefix.as_str())
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("custom admin UI request should complete");

    assert_eq!(admin_response.status(), StatusCode::OK);

    let audit_response = router
        .oneshot(audit_query_request(&routes.admin.audit_route, None))
        .await
        .expect("custom audit request should complete");

    assert_eq!(audit_response.status(), StatusCode::UNAUTHORIZED);
    assert_upstream_receives_no_request(
        &mut captured,
        "custom admin prefix collision should not reach upstream",
    )
    .await;
}

#[tokio::test]
async fn fixed_probe_routes_win_over_proxy_with_custom_admin_prefix() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let mut config = proxy_config(upstream_addr);
    config.admin_prefix = "/ops".to_owned();
    let router = proxy_router(config, test_audit_log());

    for (uri, expected_status) in [
        ("/health", StatusCode::OK),
        ("/livez", StatusCode::OK),
        ("/startupz", StatusCode::SERVICE_UNAVAILABLE),
        ("/readyz", StatusCode::SERVICE_UNAVAILABLE),
        ("/version", StatusCode::OK),
        ("/metrics", StatusCode::OK),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("probe route request should complete");

        assert_eq!(response.status(), expected_status, "{uri}");
    }
    assert_upstream_receives_no_request(
        &mut captured,
        "fixed probe routes should not be proxied with custom admin prefix",
    )
    .await;
}

#[tokio::test]
async fn probe_path_subtrees_are_not_exempt_from_authentication() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let mut config = proxy_config(upstream_addr);
    config.auth_enabled = true;
    config.auth_mode = config::AuthMode::Required;
    let router = proxy_router(config, test_audit_log());

    // The probe route itself stays exempt and is still served locally.
    let probe = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("probe request should build"),
        )
        .await
        .expect("probe request should complete");
    assert_eq!(probe.status(), StatusCode::OK);

    // Anything below a probe route is proxy space, so it must be
    // authenticated exactly like any other proxied path.
    for uri in [
        "/health/v1/orders",
        "/livez/v1/orders",
        "/startupz/v1/orders",
        "/readyz/v1/orders",
        "/version/v1/orders",
        "/metrics/jvm.memory.used",
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
    }

    assert_upstream_receives_no_request(
        &mut captured,
        "probe path subtrees must not reach the upstream unauthenticated",
    )
    .await;
}

#[tokio::test]
async fn probe_path_subtrees_are_not_exempt_from_authorization() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let policy = TempPolicyFile::new(
        r#"{
                "schema_version": "0.1.0",
                "default_action": "deny",
                "enforcement_mode": "enforce",
                "roles": {},
                "routes": []
            }"#,
    );
    let mut config = proxy_config(upstream_addr);
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    let router = proxy_router(config, test_audit_log());

    let probe = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("probe request should build"),
        )
        .await
        .expect("probe request should complete");
    assert_eq!(probe.status(), StatusCode::OK);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/health/v1/orders")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_upstream_receives_no_request(
        &mut captured,
        "probe path subtrees must be evaluated against policy before proxying",
    )
    .await;
}

#[tokio::test]
async fn cached_lifecycle_probes_transition_without_auth_or_upstream_io() {
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

    let live = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::HEAD)
                .uri("/livez")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("liveness request should complete");
    assert_eq!(live.status(), StatusCode::OK);

    let startup = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/startupz")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("startup request should complete");
    assert_eq!(startup.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json_body(startup).await["reason"], "starting");

    let readiness = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("readiness request should complete");
    assert_eq!(readiness.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json_body(readiness).await["reason"], "starting");

    lifecycle.mark_ready();
    for path in ["/startupz", "/readyz", "/health"] {
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
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }

    lifecycle.begin_draining();
    let readiness = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::HEAD)
                .uri("/readyz")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("readiness request should complete");
    assert_eq!(readiness.status(), StatusCode::SERVICE_UNAVAILABLE);

    for path in ["/livez", "/startupz", "/health"] {
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
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }
}

#[tokio::test]
async fn unmatched_paths_still_404_when_upstream_url_is_unset() {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.csrf_enabled = false;
    let router = proxy_router(config, test_audit_log());

    let response = router
        .oneshot(
            Request::builder()
                .uri("/unmatched")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn proxy_observation_event_includes_upstream_latency_and_status() {
    let (upstream_addr, _) = spawn_capture_upstream().await;
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = proxy_router(proxy_config(upstream_addr), audit_log);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/observed")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("proxy request should complete");

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eventually(Duration::from_secs(1), || {
        capture
            .events()
            .iter()
            .any(|event| event.event_type == "http.request_observed")
    });
    let observed = capture
        .events()
        .into_iter()
        .find(|event| event.event_type == "http.request_observed")
        .expect("observation event should be captured");
    assert_eq!(observed.payload["path"], json!("/observed"));
    assert_eq!(observed.payload["status"], json!(201));
    assert_eq!(observed.payload["upstream_status"], json!(201));
    assert!(observed.payload["upstream_latency_ms"].as_u64().is_some());
    assert_eq!(observed.payload["upstream_route_id"], json!("legacy"));
    assert_eq!(observed.payload["upstream_pool_id"], json!("legacy"));
    assert_eq!(observed.payload["upstream_endpoint_id"], json!("primary"));
}

#[tokio::test]
async fn an_upstream_the_static_egress_checks_refuse_is_never_resolved_or_contacted() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let router_admitting_port = |port: u16| {
        let policy = TempPolicyFile::new(&format!(
            r#"{{
                "schema_version": "0.1.0",
                "default_action": "allow",
                "roles": {{}},
                "routes": [],
                "egress": {{ "ports": [{port}] }}
            }}"#
        ));
        let mut config = proxy_config(upstream_addr);
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        let (router, probe) =
            proxy_router_with_work_probe(config, test_audit_log(), upstream_addr.ip());
        (policy, router, probe)
    };
    let request = |path: &str| {
        Request::builder()
            .uri(path)
            .body(Body::empty())
            .expect("egress request should build")
    };

    // Control: the same policy shape listing the upstream's port is resolved
    // and forwarded, so the refusal below is the port list's doing.
    let (_admitting, router, probe) = router_admitting_port(upstream_addr.port());
    let response = router
        .oneshot(request("/egress-admitted"))
        .await
        .expect("egress-admitted request should complete");
    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(
        probe.snapshot().resolver_calls > 0,
        "an admitted destination is resolved"
    );
    let _ = next_proxied_request(&mut captured, "egress-admitted request").await;

    // The policy admits egress to one port; the upstream listens on another.
    let admitted_port = if upstream_addr.port() == 443 {
        444
    } else {
        443
    };
    let (_refusing, router, probe) = router_admitting_port(admitted_port);
    let response = router
        .oneshot(request("/egress-refused"))
        .await
        .expect("egress-refused request should complete");

    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        probe.snapshot().resolver_calls,
        0,
        "a destination the static egress checks refuse is never resolved"
    );
    assert_upstream_receives_no_request(&mut captured, "static egress refusal").await;
}

#[tokio::test]
async fn every_pre_forward_denial_performs_zero_physical_proxy_work() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let upstream_ip = upstream_addr.ip();

    let mut auth_config = proxy_config(upstream_addr);
    auth_config.auth_enabled = true;
    let (router, probe) = proxy_router_with_work_probe(auth_config, test_audit_log(), upstream_ip);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/auth-denied")
                .body(Body::empty())
                .expect("auth-denied request should build"),
        )
        .await
        .expect("auth-denied request should complete");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    probe.assert_no_work("auth denial must perform zero proxy work");
    assert_upstream_receives_no_request(&mut captured, "auth denial").await;

    let mut global_rate_config = proxy_config(upstream_addr);
    global_rate_config.rate_limit_read_rps = 0.001;
    global_rate_config.rate_limit_read_burst = 1;
    let (router, probe) =
        proxy_router_with_work_probe(global_rate_config, test_audit_log(), upstream_ip);
    let request = || {
        Request::builder()
            .uri("/global-rate-limited")
            .body(Body::empty())
            .expect("global-rate request should build")
    };
    let first = router
        .clone()
        .oneshot(request())
        .await
        .expect("first global-rate request should complete");
    assert_eq!(first.status(), StatusCode::CREATED);
    let _ = next_proxied_request(&mut captured, "first global-rate request").await;
    let before_denial = probe.snapshot();
    let second = router
        .oneshot(request())
        .await
        .expect("second global-rate request should complete");
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        probe.snapshot(),
        before_denial,
        "global rate denial must add no proxy work"
    );
    assert_upstream_receives_no_request(&mut captured, "global rate denial").await;

    let policy_rate = TempPolicyFile::new(
        r#"{
                "schema_version": "0.1.0",
                "default_action": "allow",
                "roles": {},
                "routes": [],
                "rate_limits": [
                    {
                        "principal": { "auth_methods": ["bearer_token"] },
                        "methods": ["GET"],
                        "path": "/policy-rate-limited",
                        "requests_per_second": 0.000001,
                        "burst": 1
                    }
                ]
            }"#,
    );
    let mut policy_rate_config = proxy_config(upstream_addr);
    policy_rate_config.policy_file = Some(policy_rate.path.to_string_lossy().into_owned());
    let (router, probe) =
        proxy_router_with_work_probe(policy_rate_config, test_audit_log(), upstream_ip);
    let policy_request = || {
        let mut request = Request::builder()
            .uri("/policy-rate-limited")
            .body(Body::empty())
            .expect("policy-rate request should build");
        request.extensions_mut().insert(test_principal(&["member"]));
        request
    };
    let first = router
        .clone()
        .oneshot(policy_request())
        .await
        .expect("first policy-rate request should complete");
    assert_eq!(first.status(), StatusCode::CREATED);
    let _ = next_proxied_request(&mut captured, "first policy-rate request").await;
    let before_denial = probe.snapshot();
    let second = router
        .oneshot(policy_request())
        .await
        .expect("second policy-rate request should complete");
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        probe.snapshot(),
        before_denial,
        "policy rate denial must add no proxy work"
    );
    assert_upstream_receives_no_request(&mut captured, "policy rate denial").await;

    let mut validation_config = proxy_config(upstream_addr);
    validation_config.csrf_enabled = true;
    validation_config.validation_allowed_content_types = vec!["application/json".to_owned()];
    let (router, probe) =
        proxy_router_with_work_probe(validation_config, test_audit_log(), upstream_ip);
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/validation-denied")
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("rejected"))
                .expect("validation-denied request should build"),
        )
        .await
        .expect("validation-denied request should complete");
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    probe.assert_no_work("validation denial must perform zero proxy work");
    assert_upstream_receives_no_request(&mut captured, "validation denial").await;

    let mut csrf_config = proxy_config(upstream_addr);
    csrf_config.csrf_enabled = true;
    csrf_config.validation_allowed_content_types = vec!["application/json".to_owned()];
    let (router, probe) = proxy_router_with_work_probe(csrf_config, test_audit_log(), upstream_ip);
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/csrf-denied")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .expect("CSRF-denied request should build"),
        )
        .await
        .expect("CSRF-denied request should complete");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    probe.assert_no_work("CSRF denial must perform zero proxy work");
    assert_upstream_receives_no_request(&mut captured, "CSRF denial").await;

    let rbac_policy = TempPolicyFile::new(
        r#"{
                "schema_version": "0.1.0",
                "default_action": "deny",
                "enforcement_mode": "enforce",
                "roles": {},
                "routes": [
                    { "path_prefix": "/rbac-denied", "permission": "proxy:use" }
                ]
            }"#,
    );
    let mut rbac_config = proxy_config(upstream_addr);
    rbac_config.policy_file = Some(rbac_policy.path.to_string_lossy().into_owned());
    let (router, probe) = proxy_router_with_work_probe(rbac_config, test_audit_log(), upstream_ip);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/rbac-denied/resource")
                .body(Body::empty())
                .expect("RBAC-denied request should build"),
        )
        .await
        .expect("RBAC-denied request should complete");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    probe.assert_no_work("RBAC denial must perform zero proxy work");
    assert_upstream_receives_no_request(&mut captured, "RBAC denial").await;

    let direct_policy = TempPolicyFile::new(
        r#"{
                "schema_version": "0.1.0",
                "default_action": "allow",
                "enforcement_mode": "enforce",
                "roles": {},
                "routes": [],
                "rules": [
                    { "methods": ["GET"], "path": "/direct-denied/**", "action": "deny" }
                ]
            }"#,
    );
    let mut direct_config = proxy_config(upstream_addr);
    direct_config.policy_file = Some(direct_policy.path.to_string_lossy().into_owned());
    let (router, probe) =
        proxy_router_with_work_probe(direct_config, test_audit_log(), upstream_ip);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/direct-denied/resource")
                .body(Body::empty())
                .expect("direct-rule-denied request should build"),
        )
        .await
        .expect("direct-rule-denied request should complete");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    probe.assert_no_work("direct-rule denial must perform zero proxy work");
    assert_upstream_receives_no_request(&mut captured, "direct-rule denial").await;

    let (router, probe) =
        proxy_router_with_work_probe(proxy_config(upstream_addr), test_audit_log(), upstream_ip);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/public/../admin")
                .body(Body::empty())
                .expect("unsafe-path request should build"),
        )
        .await
        .expect("unsafe-path request should complete");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    probe.assert_no_work("unsafe-path denial must perform zero proxy work");
    assert_upstream_receives_no_request(&mut captured, "unsafe-path denial").await;

    let (router, probe) = proxy_router_with_work_probe(
        routing_proxy_config(vec![path_route("/", upstream_addr)]),
        test_audit_log(),
        upstream_ip,
    );
    let response = router
        .oneshot(
            Request::builder()
                .uri("/v1/admin/not-found")
                .body(Body::empty())
                .expect("gateway-owned request should build"),
        )
        .await
        .expect("gateway-owned request should complete");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    probe.assert_no_work("gateway-owned denial must perform zero proxy work");
    assert_upstream_receives_no_request(&mut captured, "gateway-owned denial").await;
}

#[tokio::test]
async fn auth_rejection_preserves_configured_proxy_routing_context() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let mut config = routing_proxy_config(vec![host_path_route(
        "api.example.test",
        "/private",
        upstream_addr,
    )]);
    config.auth_enabled = true;
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()));
    let router = proxy_router(config, audit_log);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/private/report")
                .header(header::HOST, "api.example.test")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("auth-rejected request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eventually(Duration::from_secs(1), || {
        capture.events().iter().any(|event| {
            event.event_type == "http.request_observed"
                && event.payload["path"] == json!("/private/report")
        })
    });
    let observed = capture
        .events()
        .into_iter()
        .find(|event| {
            event.event_type == "http.request_observed"
                && event.payload["path"] == json!("/private/report")
        })
        .expect("auth rejection observation should exist");
    assert_eq!(observed.payload["routing_context_known"], json!(true));
    assert_eq!(
        observed.payload["upstream_route_host"],
        json!("api.example.test")
    );
    assert_eq!(
        observed.payload["upstream_route_path_prefix"],
        json!("/private")
    );
    assert!(observed.payload["upstream_origin"]
        .as_str()
        .is_some_and(|origin| origin.contains(&upstream_addr.port().to_string())));
    assert_upstream_receives_no_request(
        &mut captured,
        "auth rejection must not reach the selected upstream",
    )
    .await;
}

#[tokio::test]
async fn global_rate_limit_rejection_preserves_configured_proxy_routing_context() {
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let mut config = routing_proxy_config(vec![host_path_route(
        "api.example.test",
        "/limited",
        upstream_addr,
    )]);
    config.rate_limit_read_rps = 0.001;
    config.rate_limit_read_burst = 1;
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()));
    let router = proxy_router(config, audit_log);
    let request = || {
        Request::builder()
            .uri("/limited/report")
            .header(header::HOST, "api.example.test")
            .body(Body::empty())
            .expect("request should build")
    };

    let first = router
        .clone()
        .oneshot(request())
        .await
        .expect("first request should complete");
    assert_eq!(first.status(), StatusCode::CREATED);
    let second = router
        .oneshot(request())
        .await
        .expect("rate-limited request should complete");
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);

    assert_eventually(Duration::from_secs(1), || {
        capture.events().iter().any(|event| {
            event.event_type == "http.request_observed"
                && event.payload["path"] == json!("/limited/report")
                && event.payload["status"] == json!(429)
        })
    });
    let observed = capture
        .events()
        .into_iter()
        .find(|event| {
            event.event_type == "http.request_observed"
                && event.payload["path"] == json!("/limited/report")
                && event.payload["status"] == json!(429)
        })
        .expect("rate-limit rejection observation should exist");
    assert_eq!(observed.payload["routing_context_known"], json!(true));
    assert_eq!(
        observed.payload["upstream_route_host"],
        json!("api.example.test")
    );
    assert_eq!(
        observed.payload["upstream_route_path_prefix"],
        json!("/limited")
    );
    assert!(observed.payload["upstream_origin"]
        .as_str()
        .is_some_and(|origin| origin.contains(&upstream_addr.port().to_string())));

    let proxied = next_proxied_request(
        &mut captured,
        "only the first rate-limit request should reach upstream",
    )
    .await;
    assert_eq!(proxied.path_and_query, "/limited/report");
    assert_upstream_receives_no_request(
        &mut captured,
        "the rejected rate-limit request must not reach upstream",
    )
    .await;
}

#[tokio::test]
async fn policy_rate_limit_uses_real_authenticated_principal_buckets_in_app_stack() {
    let jwks_addr = spawn_test_jwks_server().await;
    let policy = TempPolicyFile::new(
        r#"{
                "schema_version": "0.1.0",
                "default_action": "deny",
                "enforcement_mode": "enforce",
                "roles": {
                    "member": { "permissions": ["test:read"] }
                },
                "routes": [
                    {
                        "path_prefix": "/__test",
                        "permission": "test:read"
                    }
                ],
                "rate_limits": [
                    {
                        "principal": {
                            "auth_methods": ["bearer_token"]
                        },
                        "methods": ["GET"],
                        "path": "/__test/principal",
                        "requests_per_second": 0.000001,
                        "burst": 1
                    }
                ]
            }"#,
    );
    let mut config = test_config(Vec::new());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    configure_test_jwt_provider(&mut config, jwks_addr);
    config.egress_deny_private_ips = false;
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");
    let user_a_token = signed_token("user-a", &["member"]);
    let user_b_token = signed_token("user-b", &["member"]);

    let first_user_a = authenticated_principal_probe(&router, &user_a_token).await;
    assert_eq!(first_user_a.status(), StatusCode::OK);
    assert_eq!(json_body(first_user_a).await["user_id"], json!("user-a"));

    let second_user_a = authenticated_principal_probe(&router, &user_a_token).await;
    assert_eq!(second_user_a.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        body_string(second_user_a).await,
        r#"{"error":"too many requests"}"#
    );

    let first_user_b = authenticated_principal_probe(&router, &user_b_token).await;
    assert_eq!(first_user_b.status(), StatusCode::OK);
    assert_eq!(json_body(first_user_b).await["user_id"], json!("user-b"));
}

#[tokio::test]
async fn authenticated_requests_without_policy_override_use_global_rate_limit_in_app_stack() {
    let jwks_addr = spawn_test_jwks_server().await;
    let policy = TempPolicyFile::new(
        r#"{
                "schema_version": "0.1.0",
                "default_action": "allow",
                "roles": {},
                "rate_limits": [
                    {
                        "methods": ["GET"],
                        "path": "/elsewhere",
                        "requests_per_second": 100.0,
                        "burst": 100
                    }
                ]
            }"#,
    );
    let mut config = test_config(Vec::new());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.rate_limit_read_rps = 0.0;
    config.rate_limit_read_burst = 1;
    configure_test_jwt_provider(&mut config, jwks_addr);
    config.egress_deny_private_ips = false;
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");
    let token = signed_token("user-a", &["member"]);

    let first = authenticated_principal_probe(&router, &token).await;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(json_body(first).await["user_id"], json!("user-a"));

    let second = authenticated_principal_probe(&router, &token).await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn unauthenticated_requests_still_use_pre_auth_global_rate_limit_in_app_stack() {
    let policy = TempPolicyFile::new(
        r#"{
                "schema_version": "0.1.0",
                "default_action": "allow",
                "roles": {},
                "rate_limits": [
                    {
                        "methods": ["GET"],
                        "path": "/__test/principal",
                        "requests_per_second": 100.0,
                        "burst": 100
                    }
                ]
            }"#,
    );
    let mut config = test_config(Vec::new());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.rate_limit_read_rps = 0.0;
    config.rate_limit_read_burst = 1;
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");

    let first = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/__test/principal")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");
    assert_eq!(first.status(), StatusCode::UNAUTHORIZED);

    let second = router
        .oneshot(
            Request::builder()
                .uri("/__test/principal")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn cors_allows_allowlisted_origin() {
    let response = preflight_response(
        test_config(vec!["http://localhost:3000"]),
        "http://localhost:3000",
    )
    .await;

    assert_eq!(
        response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&HeaderValue::from_static("http://localhost:3000"))
    );
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS),
        Some(&HeaderValue::from_static("true"))
    );
}

#[tokio::test]
async fn cors_preflight_to_non_exempt_path_succeeds_without_credential() {
    let response = preflight_response_to_path(
        test_config(vec!["http://localhost:3000"]),
        "/__test/principal",
        "http://localhost:3000",
    )
    .await;

    assert!(response.status().is_success());
    assert_eq!(
        response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
        Some(&HeaderValue::from_static("http://localhost:3000"))
    );
    assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
}

#[tokio::test]
async fn bare_options_without_origin_stops_at_cors_layer_before_handler() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let response = app(
        test_config(vec!["http://localhost:3000"]),
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build")
    .oneshot(
        Request::builder()
            .method(Method::OPTIONS)
            .uri("/__test/principal")
            .body(Body::empty())
            .expect("request should build"),
    )
    .await
    .expect("request should complete");

    // tower-http 0.7.1's CorsLayer handles bare OPTIONS requests before
    // auth. If this reached the unauthenticated test handler, it would
    // return 204; if CorsLayer passed it through to auth, auth would fail
    // closed with 401 as proven by the auth middleware unit test.
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
}

#[tokio::test]
async fn cors_rejects_non_allowlisted_origin() {
    let response = preflight_response(
        test_config(vec!["http://localhost:3000"]),
        "http://localhost:4000",
    )
    .await;

    assert!(!response
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
}

#[tokio::test]
async fn default_cors_origin_list_allows_no_cross_origin_requests() {
    let response = preflight_response(test_config(Vec::new()), "http://localhost:3000").await;

    assert!(!response
        .headers()
        .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
}

#[tokio::test]
async fn outer_layers_wrap_validation_rejections() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let response = app(
        test_config(Vec::new()),
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build")
    .oneshot(
        Request::builder()
            .method(Method::POST)
            .uri("/health")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("hello"))
            .expect("request should build"),
    )
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert!(response.headers().contains_key(REQUEST_ID_HEADER));
}

#[tokio::test]
async fn validation_runs_before_csrf() {
    let config = test_config(Vec::new());
    assert!(config.csrf_enabled);

    let recorder = PrometheusBuilder::new().build_recorder();
    let response = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build")
    .oneshot(
        Request::builder()
            .method(Method::POST)
            .uri("/does-not-exist")
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from("hello"))
            .expect("request should build"),
    )
    .await
    .expect("request should complete");

    // This proves ordering because CSRF is enabled and the path is not exempt.
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn rate_limit_runs_before_validation() {
    let mut config = test_config(Vec::new());
    config.max_body_size = 1;
    config.rate_limit_read_rps = 0.0;
    config.rate_limit_read_burst = 1;

    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/health")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::OK);

    let response = router
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/health")
                .header(header::CONTENT_LENGTH, "2")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

fn signed_admin_token() -> String {
    signed_token("user-123", &["admin"])
}

/// The RBAC lane treats "routing was never classified" as a fact it does not
/// have, and refuses rather than guessing -- a dispatch-scoped rule silently not
/// applying is not the same as it not matching. That refusal is only safe because
/// classification always completes first, which makes it unreachable in
/// production. This holds the half of that guarantee living in the middleware:
/// classification is marked completed unconditionally, for every path, before
/// anything can quietly make it conditional again.
///
/// The other half is layer order in `apply_middleware`, where this middleware is
/// added after the RBAC layer precisely so that it runs before it.
#[tokio::test]
async fn route_classification_is_marked_completed_for_every_path() {
    async fn classified(request: Request<Body>) -> &'static str {
        if request
            .extensions()
            .get::<upstream_route::ProxyRouteClassificationCompleted>()
            .is_some()
        {
            "classified"
        } else {
            "unclassified"
        }
    }

    let config = test_config(Vec::new());
    for path in [
        // A proxy path, which also receives an observation context.
        "/data/items",
        // Gateway-owned paths. Classification skips the route lookup for these,
        // and must still mark itself completed: skipping the work is not the same
        // as never having run, and RBAC can only tell those apart by this marker.
        "/health",
        "/metrics",
        crate::auth::protected_resource::MCP_RESOURCE_PATH,
    ] {
        let router = Router::new()
            .fallback(axum::routing::get(classified))
            .layer(axum::middleware::from_fn_with_state(
                ProxyDispatchState {
                    classifier: None,
                    routes: GatewayRoutes::from_config(&config),
                },
                crate::routing::proxy_dispatch_context_middleware,
            ));
        let response = router
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("request builds"),
            )
            .await
            .expect("router responds");
        let body = axum::body::to_bytes(response.into_body(), 64)
            .await
            .expect("body reads");
        assert_eq!(
            String::from_utf8_lossy(&body),
            "classified",
            "{path} reached the handler without classification being marked"
        );
    }
}

/// Every MCP route path is gateway-owned, so a request can never be both an MCP
/// alias and a classified proxy dispatch.
///
/// The kernel's alias lane depends on this. `HttpTarget::McpAlias` and
/// `HttpTarget::ProxyDispatch` are mutually exclusive variants, and the kernel
/// evaluates an alias under `RuleDispatchContext::contextless()`. The legacy path
/// instead threads the real dispatch context into its alias branch. If a request
/// were ever both, the two would diverge in both directions -- legacy matching
/// dispatch-scoped rules where the kernel matches `kind: contextless` ones -- in
/// live authorization.
///
/// It cannot happen, because `proxy_dispatch_context_middleware` computes an
/// observation context only for paths that are not gateway-owned, and
/// `GatewayRoutes::from_config` puts every `mcp_route_paths` entry into
/// `prefix_owned_paths`. Both lists come from the same function, so they agree by
/// shared derivation and nothing else -- which is worth an assertion rather than
/// a comment, because the derivation is two call sites that could drift.
#[test]
fn every_mcp_route_path_is_gateway_owned_so_an_alias_is_never_a_classified_dispatch() {
    for prefix in ["/admin", "/control", "/admin/nested"] {
        let mut config = test_config(Vec::new());
        config.admin_prefix = prefix.to_owned();
        // A public URL carrying a path gives the gateway a second MCP route
        // path under it -- the alias case -- so vary that too.
        for resource in [
            None,
            Some("https://gateway.example.test"),
            Some("https://gateway.example.test/base"),
            Some("https://gateway.example.test/deep/nested"),
        ] {
            config.gateway_public_url = resource.map(str::to_owned);
            let routes = GatewayRoutes::from_config(&config);
            let mcp_paths = crate::auth::protected_resource::mcp_route_paths(&config);
            assert!(
                !mcp_paths.is_empty(),
                "a gateway always serves at least the canonical MCP path"
            );
            for path in &mcp_paths {
                assert!(
                    routes.is_gateway_owned_path(path),
                    "{path} is an MCP route but not gateway-owned, so it could be \
                     classified as a proxy dispatch while also being an alias \
                     (admin_prefix={prefix}, mcp_resource_path={resource:?})"
                );
            }
        }
    }
}
