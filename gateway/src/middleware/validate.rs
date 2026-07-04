//! Request validation middleware.
//!
//! Performs cheap edge checks that can reject clearly invalid requests before
//! route handlers run.

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use http::{
    header::{CONTENT_LENGTH, CONTENT_TYPE},
    HeaderMap, Method, StatusCode,
};
use serde::Serialize;

use crate::config::Config;

#[derive(Serialize)]
struct PayloadTooLargeBody {
    error: &'static str,
    max_body_size: usize,
}

#[derive(Serialize)]
struct UnsupportedMediaTypeBody {
    error: &'static str,
    allowed_content_types: Vec<String>,
}

pub async fn validate_request(State(config): State<Config>, req: Request, next: Next) -> Response {
    // This is a header-based guard only; chunked bodies without Content-Length
    // are not enforced by this check.
    if let Some(content_length) = content_length(req.headers()) {
        if content_length > config.max_body_size {
            return payload_too_large(config.max_body_size);
        }
    }

    if is_mutating(req.method()) && !is_allowed_content_type(req.headers(), &config) {
        return unsupported_media_type(&config.validation_allowed_content_types);
    }

    next.run(req).await
}

fn content_length(headers: &HeaderMap) -> Option<usize> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

fn is_allowed_content_type(headers: &HeaderMap, config: &Config) -> bool {
    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    config
        .validation_allowed_content_types
        .iter()
        .any(|allowed| content_type_matches(content_type, allowed))
}

fn content_type_matches(content_type: &str, allowed: &str) -> bool {
    content_type.strip_prefix(allowed).is_some_and(|remainder| {
        remainder.is_empty()
            || remainder
                .as_bytes()
                .first()
                .is_some_and(|byte| *byte == b';' || byte.is_ascii_whitespace())
    })
}

fn payload_too_large(max_body_size: usize) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(PayloadTooLargeBody {
            error: "payload too large",
            max_body_size,
        }),
    )
        .into_response()
}

fn unsupported_media_type(allowed_content_types: &[String]) -> Response {
    (
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        Json(UnsupportedMediaTypeBody {
            error: "unsupported media type",
            allowed_content_types: allowed_content_types.to_vec(),
        }),
    )
        .into_response()
}

fn is_mutating(method: &Method) -> bool {
    matches!(*method, Method::POST | Method::PUT | Method::PATCH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, middleware::from_fn_with_state, routing::get, Router};
    use tower::ServiceExt;

    fn test_config(max_body_size: usize, validation_allowed_content_types: Vec<&str>) -> Config {
        Config {
            listen_addr: "127.0.0.1:0"
                .parse()
                .expect("test listen address should parse"),
            admin_listen_addr: None,
            admin_prefix: "/admin".to_owned(),
            audit_log_file: None,
            audit_sqlite_path: None,
            audit_sqlite_retention_days: None,
            discovery_sqlite_path: None,
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
            cors_allow_origins: Vec::new(),
            max_body_size,
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
            upstream_url: None,
            upstream_routes: Vec::new(),
            upstream_timeout_ms: None,
            upstream_response_idle_timeout_ms: None,
            upstream_connect_timeout_ms: None,
            egress_allowed_hosts: Vec::new(),
            egress_timeout_ms: 30_000,
            egress_response_idle_timeout_ms: 30_000,
            egress_connect_timeout_ms: 10_000,
            egress_max_response_bytes: 5_242_880,
            egress_max_request_body_bytes: 1_048_576,
            egress_deny_private_ips: true,
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
}
