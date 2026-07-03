use std::sync::Arc;

use axum::{
    extract::{Query, State},
    response::{IntoResponse, Response},
    routing::get,
    Extension, Json, Router,
};
use http::{header, HeaderName, HeaderValue, Method, Request, StatusCode};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tower_http::{
    cors::CorsLayer,
    request_id::{MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    trace::TraceLayer,
};

mod audit;
mod auth;
mod client_ip;
mod config;
mod egress;
mod metrics;
mod middleware;
mod rbac;

const REQUEST_COUNTER: &str = "gateway_http_requests";
const REQUEST_ID_HEADER: &str = "x-request-id";
const AUDIT_ADMIN_ROUTE: &str = "/v1/admin/audit";
const AUDIT_ADMIN_ROLE: &str = "admin";
const DEFAULT_AUDIT_QUERY_LIMIT: usize = 50;
const MAX_AUDIT_QUERY_LIMIT: usize = 500;

#[derive(Clone)]
struct AppState {
    metrics_handle: PrometheusHandle,
}

#[derive(Clone)]
struct AuditAdminState {
    query_store: Option<Arc<audit::query::AuditQueryStore>>,
}

#[derive(Clone, Copy, Debug)]
struct MakeRequestUuid;

impl MakeRequestId for MakeRequestUuid {
    fn make_request_id<B>(&mut self, _request: &Request<B>) -> Option<RequestId> {
        let id = uuid::Uuid::new_v4().to_string();
        id.parse().ok().map(RequestId::new)
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Serialize)]
struct VersionResponse {
    version: &'static str,
}

#[derive(Deserialize)]
struct AuditQueryParams {
    from: Option<String>,
    to: Option<String>,
    event_type: Option<String>,
    actor: Option<String>,
    path: Option<String>,
    status: Option<String>,
    limit: Option<String>,
    before_id: Option<String>,
}

#[derive(Serialize)]
struct AuditQueryResponse {
    events: Vec<audit::AuditEvent>,
    next_cursor: Option<i64>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();

    let config = match config::Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let metrics_handle = install_metrics_recorder()?;
    let listen_addr = config.listen_addr;
    let audit_log = audit::AuditLog::from_config(&config)?;
    let app = app(config, metrics_handle, audit_log.clone())?;
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    let bound_addr = listener.local_addr()?;

    audit_log.emit(audit::AuditEvent::new(
        "gateway.startup",
        "startup",
        "internal",
        None::<audit::Actor>,
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "listen_addr": bound_addr.to_string(),
        }),
    ));

    tracing::info!(listen_addr = %bound_addr, "gateway listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}

fn app(
    config: config::Config,
    metrics_handle: PrometheusHandle,
    audit_log: audit::AuditLog,
) -> Result<Router, Box<dyn std::error::Error>> {
    let request_id_header = request_id_header();
    let csrf_config = middleware::csrf::CsrfConfig::from_config(&config);
    let rate_limit_state = middleware::rate_limit::RateLimitState::from_config(&config);
    let observation_state =
        middleware::observation::ObservationState::from_config(&config, audit_log.clone());
    let audit_query_store = config
        .audit_sqlite_path
        .as_deref()
        .map(audit::query::AuditQueryStore::open)
        .transpose()?
        .map(Arc::new);
    let egress_client = Arc::new(egress::EgressClient::new(
        egress::EgressConfig::from_config(&config),
    )?);
    let validator = auth::JwtValidator::from_config(&config, egress_client)?
        .map(|validator| Arc::new(validator) as Arc<dyn auth::SessionValidator>);
    let rbac_state = match rbac::Policy::from_config(&config)? {
        Some(policy) => {
            tracing::info!(
                policy_id = policy.id.as_deref().unwrap_or("unnamed"),
                route_rules = policy.routes.len(),
                "RBAC enabled: policy file loaded"
            );
            Some(middleware::rbac::RbacState::from_policy(
                policy,
                &config,
                audit_log.clone(),
            ))
        }
        None => {
            tracing::warn!("RBAC disabled: no policy file configured");
            None
        }
    };

    if config.auth_enabled && validator.is_none() {
        tracing::warn!(
            "authentication is enabled but no session validator is configured; non-exempt requests will be rejected"
        );
    }

    let router = Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/metrics", get(metrics_endpoint))
        .with_state(AppState { metrics_handle })
        .merge(
            Router::new()
                .route(AUDIT_ADMIN_ROUTE, get(audit_query_endpoint))
                .with_state(AuditAdminState {
                    query_store: audit_query_store,
                }),
        );

    #[cfg(test)]
    let router = router.route(
        "/__test/principal",
        get(principal_probe).options(principal_probe),
    );

    // Later axum layers run earlier at runtime. Attach RBAC before auth, then
    // auth before CSRF, so requests flow through CSRF, auth, RBAC, then the
    // route handler.
    let router = if let Some(rbac_state) = rbac_state {
        router.layer(axum::middleware::from_fn_with_state(
            rbac_state,
            middleware::rbac::rbac_middleware,
        ))
    } else {
        router
    };

    let router = if config.auth_enabled {
        router.layer(axum::middleware::from_fn_with_state(
            middleware::auth::AuthState::from_config(&config, validator, audit_log.clone()),
            middleware::auth::auth_middleware,
        ))
    } else {
        router
    };

    let router = router
        .layer(axum::middleware::from_fn_with_state(
            csrf_config,
            middleware::csrf::csrf_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            config.clone(),
            middleware::validate::validate_request,
        ))
        .layer(axum::middleware::from_fn_with_state(
            rate_limit_state,
            middleware::rate_limit::rate_limit_request,
        ))
        .layer(axum::middleware::from_fn_with_state(
            observation_state,
            middleware::observation::observation_middleware,
        ))
        .layer(axum::middleware::from_fn(
            middleware::headers::header_hardening_middleware,
        ))
        .layer(cors_layer(&config))
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(TraceLayer::new_for_http())
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid));

    #[cfg(test)]
    let router = router.layer(axum::middleware::from_fn(audit_extension_probe_middleware));

    Ok(router.layer(Extension(audit_log)))
}

fn install_metrics_recorder() -> Result<PrometheusHandle, metrics_exporter_prometheus::BuildError> {
    let handle = PrometheusBuilder::new()
        .with_recommended_naming(true)
        .install_recorder()?;

    ::metrics::describe_counter!(REQUEST_COUNTER, "HTTP requests served by GreenGateway");
    ::metrics::describe_counter!(
        audit::AUDIT_EVENTS_DROPPED_TOTAL,
        "Audit events dropped by the bounded asynchronous audit channel"
    );
    ::metrics::describe_counter!(
        audit::AUDIT_SQLITE_FLUSH_ERRORS_TOTAL,
        "SQLite audit sink flush or retention prune errors"
    );
    ::metrics::describe_counter!(
        metrics::LOCK_POISON_RECOVERIES_TOTAL,
        "Lock poison recoveries by component and lock"
    );

    Ok(handle)
}

fn cors_layer(config: &config::Config) -> CorsLayer {
    let allowed_origins: Vec<HeaderValue> = config
        .cors_allow_origins
        .iter()
        .map(|origin| {
            origin
                .parse::<HeaderValue>()
                .expect("validated CORS origin should be a valid HTTP header value")
        })
        .collect();
    let allowed_headers = vec![
        header::CONTENT_TYPE,
        header::AUTHORIZATION,
        header::COOKIE,
        header::ACCEPT,
        config
            .csrf_header_name
            .parse::<HeaderName>()
            .expect("validated CSRF header name should be a valid HTTP header name"),
        request_id_header(),
    ];

    CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(allowed_headers)
        .allow_credentials(true)
}

fn request_id_header() -> HeaderName {
    HeaderName::from_static(REQUEST_ID_HEADER)
}

async fn health() -> Json<HealthResponse> {
    record_request("/health");
    Json(HealthResponse { status: "ok" })
}

async fn version() -> Json<VersionResponse> {
    record_request("/version");
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn metrics_endpoint(State(state): State<AppState>) -> impl IntoResponse {
    record_request("/metrics");
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.metrics_handle.render(),
    )
}

async fn audit_query_endpoint(
    State(state): State<AuditAdminState>,
    principal: Option<Extension<auth::Principal>>,
    Query(params): Query<AuditQueryParams>,
) -> Response {
    record_request(AUDIT_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };

    if !principal.roles.iter().any(|role| role == AUDIT_ADMIN_ROLE) {
        return forbidden();
    }

    let Some(query_store) = state.query_store.as_ref() else {
        return service_unavailable("audit query store not configured");
    };

    let filters = match params.into_filters() {
        Ok(filters) => filters,
        Err(parameter) => return bad_request(&format!("invalid query parameter: {parameter}")),
    };

    match query_store.query(&filters) {
        Ok(page) => (
            StatusCode::OK,
            Json(AuditQueryResponse {
                events: page.events,
                next_cursor: page.next_cursor,
            }),
        )
            .into_response(),
        Err(err) => {
            tracing::error!(error = %err, "failed to query audit events");
            internal_server_error("audit query failed")
        }
    }
}

impl AuditQueryParams {
    fn into_filters(self) -> Result<audit::query::AuditQueryFilters, &'static str> {
        let from = validate_rfc3339("from", self.from)?;
        let to = validate_rfc3339("to", self.to)?;
        let status = parse_optional_i64("status", self.status)?;
        let limit = parse_limit(self.limit)?;
        let before_id = parse_before_id(self.before_id)?;

        Ok(audit::query::AuditQueryFilters {
            from,
            to,
            event_type: self.event_type,
            actor: self.actor,
            path: self.path,
            status,
            limit,
            before_id,
        })
    }
}

fn validate_rfc3339(
    parameter: &'static str,
    value: Option<String>,
) -> Result<Option<String>, &'static str> {
    if let Some(value) = value.as_deref() {
        OffsetDateTime::parse(value, &Rfc3339).map_err(|_| parameter)?;
    }

    Ok(value)
}

fn parse_optional_i64(
    parameter: &'static str,
    value: Option<String>,
) -> Result<Option<i64>, &'static str> {
    value
        .map(|value| value.parse::<i64>().map_err(|_| parameter))
        .transpose()
}

fn parse_limit(value: Option<String>) -> Result<usize, &'static str> {
    let Some(value) = value else {
        return Ok(DEFAULT_AUDIT_QUERY_LIMIT);
    };
    let limit = value.parse::<usize>().map_err(|_| "limit")?;
    if limit == 0 {
        return Err("limit");
    }

    Ok(limit.min(MAX_AUDIT_QUERY_LIMIT))
}

fn parse_before_id(value: Option<String>) -> Result<Option<i64>, &'static str> {
    let Some(value) = value else {
        return Ok(None);
    };
    let before_id = value.parse::<i64>().map_err(|_| "before_id")?;
    if before_id < 0 {
        return Err("before_id");
    }

    Ok(Some(before_id))
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        Json(ErrorResponse {
            error: "unauthorized".to_owned(),
        }),
    )
        .into_response()
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorResponse {
            error: "forbidden".to_owned(),
        }),
    )
        .into_response()
}

fn bad_request(error: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: error.to_owned(),
        }),
    )
        .into_response()
}

fn service_unavailable(error: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorResponse {
            error: error.to_owned(),
        }),
    )
        .into_response()
}

fn internal_server_error(error: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: error.to_owned(),
        }),
    )
        .into_response()
}

fn record_request(route: &'static str) {
    ::metrics::counter!(REQUEST_COUNTER, "route" => route).increment(1);
}

#[cfg(test)]
async fn audit_extension_probe_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if req.extensions().get::<audit::AuditLog>().is_none() {
        return http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    next.run(req).await
}

#[cfg(test)]
async fn principal_probe(
    principal: Option<Extension<auth::Principal>>,
) -> axum::response::Response {
    match principal {
        Some(Extension(principal)) => Json(json!({ "user_id": principal.user_id })).into_response(),
        None => http::StatusCode::NO_CONTENT.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::StatusCode};
    use rusqlite::{params, Connection};
    use serde_json::Value;
    use std::{
        collections::HashSet,
        fs,
        path::PathBuf,
        sync::Arc,
        time::{Duration, Instant},
    };
    use tower::ServiceExt;

    fn test_config(cors_allow_origins: Vec<&str>) -> config::Config {
        config::Config {
            listen_addr: "127.0.0.1:0"
                .parse()
                .expect("test listen address should parse"),
            audit_log_file: None,
            audit_sqlite_path: None,
            audit_sqlite_retention_days: None,
            policy_file: None,
            cors_allow_origins: cors_allow_origins.into_iter().map(str::to_owned).collect(),
            max_body_size: 1_048_576,
            rate_limit_read_rps: 50.0,
            rate_limit_read_burst: 100,
            rate_limit_write_rps: 10.0,
            rate_limit_write_burst: 20,
            trust_proxy_headers: false,
            rbac_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
            session_cookie_name: String::new(),
            validation_allowed_content_types: vec!["application/json".to_owned()],
            auth_enabled: true,
            auth_cookie_name: "session".to_owned(),
            auth_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
            jwt_jwks_url: None,
            jwt_issuer: None,
            jwt_audience: None,
            jwt_jwks_timeout_ms: 2000,
            jwt_require_jti: false,
            roles_claim: "roles".to_owned(),
            csrf_enabled: true,
            csrf_cookie_name: "csrf_token".to_owned(),
            csrf_header_name: "x-csrf-token".to_owned(),
            csrf_cookie_domain: None,
            csrf_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
            egress_allowed_hosts: Vec::new(),
            egress_timeout_ms: 30_000,
            egress_connect_timeout_ms: 10_000,
            egress_max_response_bytes: 5_242_880,
            egress_max_request_body_bytes: 1_048_576,
            egress_deny_private_ips: true,
        }
    }

    #[derive(Clone)]
    struct NoopSink;

    impl audit::AuditSink for NoopSink {
        fn emit(&self, _event: &audit::AuditEvent) {}
    }

    fn test_audit_log() -> audit::AuditLog {
        audit::AuditLog::new(Arc::new(NoopSink))
    }

    async fn preflight_response_to_path(
        config: config::Config,
        path: &str,
        origin: &str,
    ) -> axum::response::Response {
        let recorder = PrometheusBuilder::new().build_recorder();

        app(config, recorder.handle(), test_audit_log())
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

    #[tokio::test]
    async fn health_returns_ok() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let response = app(test_config(Vec::new()), recorder.handle(), test_audit_log())
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
    }

    #[tokio::test]
    async fn audit_log_extension_is_available_to_middleware() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let response = app(test_config(Vec::new()), recorder.handle(), test_audit_log())
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
    async fn auth_disabled_skips_non_exempt_route_without_principal() {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let recorder = PrometheusBuilder::new().build_recorder();

        let response = app(config, recorder.handle(), audit_log)
            .expect("app should build")
            .oneshot(
                Request::builder()
                    .uri("/__test/principal")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eventually(Duration::from_secs(1), || !capture.events().is_empty());
        let events = capture.events();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == "http.request_observed")
                .count(),
            1
        );
        assert!(!events
            .iter()
            .any(|event| event.event_type.starts_with("auth.")));
    }

    #[tokio::test]
    async fn audit_query_without_principal_returns_unauthorized() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let response = app(
            audit_query_config(None),
            recorder.handle(),
            test_audit_log(),
        )
        .expect("app should build")
        .oneshot(audit_query_request(AUDIT_ADMIN_ROUTE, None))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_string(response).await, r#"{"error":"unauthorized"}"#);
    }

    #[tokio::test]
    async fn audit_query_non_admin_principal_returns_forbidden_without_store_leak() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let response = app(
            audit_query_config(None),
            recorder.handle(),
            test_audit_log(),
        )
        .expect("app should build")
        .oneshot(audit_query_request(
            AUDIT_ADMIN_ROUTE,
            Some(test_principal(&["reader"])),
        ))
        .await
        .expect("request should complete");

        let body = body_string(response).await;
        assert_eq!(body, r#"{"error":"forbidden"}"#);
        assert!(!body.contains("audit query store"));
    }

    #[tokio::test]
    async fn audit_query_admin_principal_filters_events() {
        let db = TempDb::new("audit-query-filters");
        create_audit_schema(&db.path);
        seed_filter_events(&db.path);
        let router = audit_query_router(Some(&db.path));

        assert_eq!(
            audit_event_ids(router.clone(), "/v1/admin/audit?event_type=audit.policy").await,
            vec!["fractionally-newer-event".to_owned()]
        );
        assert_eq!(
            audit_event_ids(router.clone(), "/v1/admin/audit?actor=bob").await,
            vec!["fractionally-newer-event".to_owned()]
        );
        assert_eq!(
            audit_event_ids(router.clone(), "/v1/admin/audit?path=/admin").await,
            vec!["fractionally-newer-event".to_owned()]
        );
        assert_eq!(
            audit_event_ids(router.clone(), "/v1/admin/audit?status=403").await,
            vec!["fractionally-newer-event".to_owned()]
        );
        assert_eq!(
            audit_event_ids(
                router,
                "/v1/admin/audit?from=2024-06-01T12:00:00Z&to=2024-06-01T12:00:00.5Z",
            )
            .await,
            vec![
                "fractionally-newer-event".to_owned(),
                "cutoff-event".to_owned()
            ]
        );
    }

    #[tokio::test]
    async fn audit_query_paginates_with_keyset_cursor_without_gaps() {
        let db = TempDb::new("audit-query-pagination");
        create_audit_schema(&db.path);
        for index in 0..25 {
            insert_audit_event(
                &db.path,
                SeedAuditEvent {
                    event_id: &format!("page-event-{index:02}"),
                    event_type: "audit.page",
                    timestamp: "2024-06-01T12:00:00Z",
                    actor_user_id: "admin-user",
                    path: "/page",
                    status: 200,
                },
            );
        }
        let router = audit_query_router(Some(&db.path));
        let mut next_cursor = None;
        let mut returned = Vec::new();
        let mut seen = HashSet::new();

        loop {
            let uri = match next_cursor {
                Some(cursor) => format!("/v1/admin/audit?limit=10&before_id={cursor}"),
                None => "/v1/admin/audit?limit=10".to_owned(),
            };
            let response = router
                .clone()
                .oneshot(audit_query_request(&uri, Some(test_principal(&["admin"]))))
                .await
                .expect("request should complete");
            assert_eq!(response.status(), StatusCode::OK);

            let body = json_body(response).await;
            let ids = event_ids_from_body(&body);
            for id in ids {
                assert!(seen.insert(id.clone()), "duplicate event id {id}");
                returned.push(id);
            }

            next_cursor = body["next_cursor"].as_i64();
            if next_cursor.is_none() {
                break;
            }
        }

        let expected = (0..25)
            .rev()
            .map(|index| format!("page-event-{index:02}"))
            .collect::<Vec<_>>();
        assert_eq!(returned, expected);
    }

    #[tokio::test]
    async fn audit_query_admin_principal_without_store_returns_service_unavailable() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let response = app(
            audit_query_config(None),
            recorder.handle(),
            test_audit_log(),
        )
        .expect("app should build")
        .oneshot(audit_query_request(
            AUDIT_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
        ))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body_string(response).await,
            r#"{"error":"audit query store not configured"}"#
        );
    }

    #[tokio::test]
    async fn audit_query_malformed_params_return_bad_request() {
        let db = TempDb::new("audit-query-malformed");
        create_audit_schema(&db.path);
        let router = audit_query_router(Some(&db.path));

        for (uri, parameter) in [
            ("/v1/admin/audit?status=not-a-number", "status"),
            ("/v1/admin/audit?from=not-a-date", "from"),
            ("/v1/admin/audit?before_id=-1", "before_id"),
            ("/v1/admin/audit?before_id=not-a-number", "before_id"),
            ("/v1/admin/audit?limit=0", "limit"),
        ] {
            let response = router
                .clone()
                .oneshot(audit_query_request(uri, Some(test_principal(&["admin"]))))
                .await
                .expect("request should complete");

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                body_string(response).await,
                format!(r#"{{"error":"invalid query parameter: {parameter}"}}"#)
            );
        }
    }

    #[tokio::test]
    async fn auth_runs_before_rbac_for_non_exempt_routes() {
        let policy = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "default_action": "deny",
                "roles": {}
            }"#,
        );
        let mut config = test_config(Vec::new());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        let recorder = PrometheusBuilder::new().build_recorder();

        let response = app(config, recorder.handle(), test_audit_log())
            .expect("app should build")
            .oneshot(
                Request::builder()
                    .uri("/__test/principal")
                    .header(header::AUTHORIZATION, "Bearer token-123")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
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

        // tower-http 0.6.8's CorsLayer handles bare OPTIONS requests before
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
        let response = app(test_config(Vec::new()), recorder.handle(), test_audit_log())
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
        let response = app(config, recorder.handle(), test_audit_log())
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
        let router = app(config, recorder.handle(), test_audit_log()).expect("app should build");

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

    fn audit_query_config(sqlite_path: Option<&PathBuf>) -> config::Config {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.audit_sqlite_path = sqlite_path.map(|path| path.to_string_lossy().into_owned());
        config
    }

    fn audit_query_router(sqlite_path: Option<&PathBuf>) -> Router {
        let recorder = PrometheusBuilder::new().build_recorder();
        app(
            audit_query_config(sqlite_path),
            recorder.handle(),
            test_audit_log(),
        )
        .expect("app should build")
    }

    fn audit_query_request(uri: &str, principal: Option<auth::Principal>) -> Request<Body> {
        let mut request = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request should build");
        if let Some(principal) = principal {
            request.extensions_mut().insert(principal);
        }

        request
    }

    async fn audit_event_ids(router: Router, uri: &str) -> Vec<String> {
        let response = router
            .oneshot(audit_query_request(uri, Some(test_principal(&["admin"]))))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        event_ids_from_body(&json_body(response).await)
    }

    fn event_ids_from_body(body: &Value) -> Vec<String> {
        body["events"]
            .as_array()
            .expect("events should be an array")
            .iter()
            .map(|event| {
                event["event_id"]
                    .as_str()
                    .expect("event_id should be a string")
                    .to_owned()
            })
            .collect()
    }

    async fn json_body(response: axum::response::Response) -> Value {
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body should read"),
        )
        .expect("body should be JSON")
    }

    async fn body_string(response: axum::response::Response) -> String {
        String::from_utf8(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body should read")
                .to_vec(),
        )
        .expect("body should be UTF-8")
    }

    fn test_principal(roles: &[&str]) -> auth::Principal {
        auth::Principal {
            user_id: "user-123".to_owned(),
            email: Some("user@example.com".to_owned()),
            org_id: Some("org-456".to_owned()),
            roles: roles.iter().map(|role| (*role).to_owned()).collect(),
            session_id: "session-789".to_owned(),
            auth_method: auth::AuthMethod::Bearer,
        }
    }

    fn create_audit_schema(path: &PathBuf) {
        drop(
            audit::sqlite_sink::SqliteSink::new(audit::sqlite_sink::SqliteSinkConfig {
                path: path.clone(),
                retention_days: None,
            })
            .expect("SQLite sink should create audit schema"),
        );
    }

    fn seed_filter_events(path: &PathBuf) {
        insert_audit_event(
            path,
            SeedAuditEvent {
                event_id: "older-event",
                event_type: "audit.auth",
                timestamp: "2024-06-01T11:59:59.5Z",
                actor_user_id: "alice",
                path: "/login",
                status: 200,
            },
        );
        insert_audit_event(
            path,
            SeedAuditEvent {
                event_id: "cutoff-event",
                event_type: "audit.auth",
                timestamp: "2024-06-01T12:00:00Z",
                actor_user_id: "alice",
                path: "/login",
                status: 200,
            },
        );
        insert_audit_event(
            path,
            SeedAuditEvent {
                event_id: "fractionally-newer-event",
                event_type: "audit.policy",
                timestamp: "2024-06-01T12:00:00.5Z",
                actor_user_id: "bob",
                path: "/admin",
                status: 403,
            },
        );
        insert_audit_event(
            path,
            SeedAuditEvent {
                event_id: "later-event",
                event_type: "audit.egress",
                timestamp: "2024-06-01T12:00:01Z",
                actor_user_id: "carol",
                path: "/upstream",
                status: 502,
            },
        );
    }

    struct SeedAuditEvent<'a> {
        event_id: &'a str,
        event_type: &'a str,
        timestamp: &'a str,
        actor_user_id: &'a str,
        path: &'a str,
        status: i64,
    }

    fn insert_audit_event(path: &PathBuf, event: SeedAuditEvent<'_>) {
        let connection = Connection::open(path).expect("test database should open");
        let actor_json = json!({
            "user_id": event.actor_user_id,
            "roles": ["admin"],
            "auth_mode": "bearer_token"
        })
        .to_string();
        let payload_json = json!({
            "path": event.path,
            "status": event.status
        })
        .to_string();

        connection
            .execute(
                r#"
                INSERT INTO audit_events (
                    event_id,
                    event_type,
                    timestamp,
                    schema_version,
                    request_id,
                    source_ip,
                    actor_user_id,
                    actor_json,
                    payload_path,
                    payload_status,
                    payload_json
                ) VALUES (?1, ?2, ?3, '0.1.0', 'request-test', '203.0.113.10', ?4, ?5, ?6, ?7, ?8)
                "#,
                params![
                    event.event_id,
                    event.event_type,
                    event.timestamp,
                    event.actor_user_id,
                    actor_json,
                    event.path,
                    event.status,
                    payload_json
                ],
            )
            .expect("event should insert");
    }

    struct TempDb {
        path: PathBuf,
    }

    impl TempDb {
        fn new(test_name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-main-{test_name}-{}.sqlite",
                uuid::Uuid::new_v4()
            ));

            Self { path }
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let path = PathBuf::from(format!("{}{}", self.path.display(), suffix));
                let _ = fs::remove_file(path);
            }
        }
    }

    struct TempPolicyFile {
        path: PathBuf,
    }

    impl TempPolicyFile {
        fn new(contents: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-app-policy-test-{}.json",
                uuid::Uuid::new_v4()
            ));
            fs::write(&path, contents)
                .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));

            Self { path }
        }
    }

    impl Drop for TempPolicyFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    fn assert_eventually(timeout: Duration, condition: impl Fn() -> bool) {
        let started = Instant::now();

        while started.elapsed() < timeout {
            if condition() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(
            condition(),
            "condition did not become true within {timeout:?}"
        );
    }
}
