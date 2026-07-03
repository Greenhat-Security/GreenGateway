use std::sync::Arc;

use axum::{extract::State, response::IntoResponse, routing::get, Extension, Json, Router};
use http::{header, HeaderName, HeaderValue, Method, Request};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use serde::Serialize;
use serde_json::json;
use tower_http::{
    cors::CorsLayer,
    request_id::{MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    trace::TraceLayer,
};

mod audit;
mod auth;
mod client_ip;
mod config;
mod metrics;
mod middleware;

const REQUEST_COUNTER: &str = "gateway_http_requests";
const REQUEST_ID_HEADER: &str = "x-request-id";

#[derive(Clone)]
struct AppState {
    metrics_handle: PrometheusHandle,
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
    let audit_log = audit::AuditLog::from_config(&config);
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
) -> Result<Router, auth::AuthError> {
    let request_id_header = request_id_header();
    let csrf_config = middleware::csrf::CsrfConfig::from_config(&config);
    let rate_limit_state = middleware::rate_limit::RateLimitState::from_config(&config);
    let validator = auth::JwtValidator::from_config(&config)?
        .map(|validator| Arc::new(validator) as Arc<dyn auth::SessionValidator>);

    if config.auth_enabled && validator.is_none() {
        tracing::warn!(
            "authentication is enabled but no session validator is configured; non-exempt requests will be rejected"
        );
    }

    let router = Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/metrics", get(metrics_endpoint))
        .with_state(AppState { metrics_handle });

    #[cfg(test)]
    let router = router.route(
        "/__test/principal",
        get(principal_probe).options(principal_probe),
    );

    // Later axum layers run earlier at runtime. Attach auth before the CSRF
    // layer so requests flow through CSRF, then auth, then the route handler.
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
    use std::sync::Arc;
    use tower::ServiceExt;

    fn test_config(cors_allow_origins: Vec<&str>) -> config::Config {
        config::Config {
            listen_addr: "127.0.0.1:0"
                .parse()
                .expect("test listen address should parse"),
            audit_log_file: None,
            cors_allow_origins: cors_allow_origins.into_iter().map(str::to_owned).collect(),
            max_body_size: 1_048_576,
            rate_limit_read_rps: 50.0,
            rate_limit_read_burst: 100,
            rate_limit_write_rps: 10.0,
            rate_limit_write_burst: 20,
            trust_proxy_headers: false,
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
        assert!(capture.events().is_empty());
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
}
