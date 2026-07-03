use axum::{extract::State, response::IntoResponse, routing::get, Json, Router};
use http::{header, HeaderName, HeaderValue, Method, Request};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use serde::Serialize;
use tower_http::{
    cors::CorsLayer,
    request_id::{MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    trace::TraceLayer,
};

mod client_ip;
mod config;
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
    let app = app(config, metrics_handle);
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;

    tracing::info!(listen_addr = %listener.local_addr()?, "gateway listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}

fn app(config: config::Config, metrics_handle: PrometheusHandle) -> Router {
    let request_id_header = request_id_header();
    let rate_limit_state = middleware::rate_limit::RateLimitState::from_config(&config);

    Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/metrics", get(metrics_endpoint))
        .with_state(AppState { metrics_handle })
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
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid))
}

fn install_metrics_recorder() -> Result<PrometheusHandle, metrics_exporter_prometheus::BuildError> {
    let handle = PrometheusBuilder::new()
        .with_recommended_naming(true)
        .install_recorder()?;

    metrics::describe_counter!(REQUEST_COUNTER, "HTTP requests served by GreenGateway");
    metrics::describe_counter!(
        middleware::rate_limit::LOCK_POISON_RECOVERIES_TOTAL,
        "Rate limiter lock poison recoveries"
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
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::COOKIE,
            header::ACCEPT,
            HeaderName::from_static("x-csrf-token"),
            request_id_header(),
        ])
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
    metrics::counter!(REQUEST_COUNTER, "route" => route).increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::StatusCode};
    use tower::ServiceExt;

    fn test_config(cors_allow_origins: Vec<&str>) -> config::Config {
        config::Config {
            listen_addr: "127.0.0.1:0"
                .parse()
                .expect("test listen address should parse"),
            cors_allow_origins: cors_allow_origins.into_iter().map(str::to_owned).collect(),
            max_body_size: 1_048_576,
            rate_limit_read_rps: 50.0,
            rate_limit_read_burst: 100,
            rate_limit_write_rps: 10.0,
            rate_limit_write_burst: 20,
            trust_proxy_headers: false,
            session_cookie_name: String::new(),
            validation_allowed_content_types: vec!["application/json".to_owned()],
        }
    }

    async fn preflight_response(config: config::Config, origin: &str) -> axum::response::Response {
        let recorder = PrometheusBuilder::new().build_recorder();

        app(config, recorder.handle())
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/health")
                    .header(header::ORIGIN, origin)
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete")
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let response = app(test_config(Vec::new()), recorder.handle())
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
}
