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
struct MethodNotSupportedBody {
    error: &'static str,
    method: String,
}

#[derive(Serialize)]
struct UnsupportedMediaTypeBody {
    error: &'static str,
    allowed_content_types: Vec<String>,
}

pub async fn validate_request(State(config): State<Config>, req: Request, next: Next) -> Response {
    // A reverse proxy has no tunnel to offer, so CONNECT is never legitimate
    // here. This has to be an explicit method check rather than a routing
    // concern: the proxy fallback is registered with `any`, which matches every
    // method, so an unhandled CONNECT would be forwarded like an ordinary
    // request rather than refused. Today HTTP/1.1 CONNECT carries an
    // authority-form target that matches no route, but enabling HTTP/2 makes
    // axum advertise the extended CONNECT protocol (RFC 8441), and those
    // requests do carry a real `:path`. Rejecting here keeps turning on HTTP/2
    // from silently turning the gateway into an open tunnel.
    if req.method() == Method::CONNECT {
        return method_not_supported(req.method());
    }

    // This early guard rejects declared oversize bodies before downstream
    // handlers apply their streaming byte limits.
    if let Some(content_length) = content_length(req.headers()) {
        if content_length > config.max_body_size {
            return payload_too_large(config.max_body_size);
        }
    }

    if is_mutating(req.method())
        && !is_allowed_content_type(req.headers(), &config)
        && !is_openapi_preview_content_type(req.uri().path(), req.headers(), &config)
    {
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

fn is_openapi_preview_content_type(path: &str, headers: &HeaderMap, config: &Config) -> bool {
    if path != openapi_preview_admin_route(config) {
        return false;
    }

    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    ["text/plain", "application/yaml", "application/x-yaml"]
        .iter()
        .any(|allowed| content_type_matches(content_type, allowed))
}

fn openapi_preview_admin_route(config: &Config) -> String {
    format!("/v1{}/tools/openapi/preview", config.admin_prefix)
}

/// Whether a request `Content-Type` names the media type of an allow-list entry.
///
/// The match is on the whole media type, not a prefix of it, so
/// `application/json-patch+json` is a different media type from
/// `application/json` and stays rejected. Within that, RFC 9110 section 8.3.1
/// governs: type and subtype are case-insensitive, and `;`-delimited
/// parameters such as `charset` are not part of the media type. Comparing the
/// parsed media types therefore accepts every RFC-valid spelling of an allowed
/// type and nothing else.
fn content_type_matches(content_type: &str, allowed: &str) -> bool {
    let content_type = media_type(content_type);

    !content_type.is_empty() && content_type.eq_ignore_ascii_case(media_type(allowed))
}

/// The `type/subtype` portion of a media type value, without its parameters or
/// the optional whitespace RFC 9110 allows around them.
fn media_type(value: &str) -> &str {
    value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim_matches(|character: char| character.is_ascii_whitespace())
}

/// 501 rather than 405: 405 is for a method the server implements but the
/// target resource does not allow, and it obliges us to send an `Allow` header
/// enumerating what is permitted. The gateway supports CONNECT on no resource
/// at all, and the fallback accepts every other method, so there is no honest
/// `Allow` list to send.
fn method_not_supported(method: &Method) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(MethodNotSupportedBody {
            error: "method not supported",
            method: method.to_string(),
        }),
    )
        .into_response()
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
#[path = "validate_tests.rs"]
mod tests;
