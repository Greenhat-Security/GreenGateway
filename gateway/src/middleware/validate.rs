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
        .any(|allowed| content_type.starts_with(allowed))
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
            cors_allow_origins: Vec::new(),
            max_body_size,
            validation_allowed_content_types: validation_allowed_content_types
                .into_iter()
                .map(str::to_owned)
                .collect(),
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
