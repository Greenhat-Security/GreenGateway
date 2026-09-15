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

use crate::{
    config::Config,
    request_bounds::{MAX_REQUEST_HOST_BYTES, MAX_REQUEST_METHOD_BYTES},
    upstream_route::{host_header, HostHeader},
};

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
struct MethodTooLongBody {
    error: &'static str,
    max_request_method_bytes: usize,
}

#[derive(Serialize)]
struct RequestPathTooLongBody {
    error: &'static str,
    max_request_path_bytes: usize,
}

#[derive(Serialize)]
struct InvalidHostBody {
    error: &'static str,
}

#[derive(Serialize)]
struct HostTooLongBody {
    error: &'static str,
    max_request_host_bytes: usize,
}

#[derive(Serialize)]
struct UnsupportedMediaTypeBody {
    error: &'static str,
    allowed_content_types: Vec<String>,
}

/// A request-line or `Host` shape admission refuses, judged the same way on
/// every listener.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RequestShapeProblem {
    MethodTooLong,
    PathTooLong,
    HostMalformed,
    HostTooLong,
}

/// The first shape problem with a request, or `None` when its method, path and
/// `Host` are all within the bounds the policy kernel evaluates under.
///
/// Kept free of the request type so that "admitted implies evaluable" is a
/// statement about this function, which the kernel's tests call directly.
pub(crate) fn request_shape_problem(
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    max_request_path_bytes: usize,
) -> Option<RequestShapeProblem> {
    if method.as_str().len() > MAX_REQUEST_METHOD_BYTES {
        return Some(RequestShapeProblem::MethodTooLong);
    }
    if path.len() > max_request_path_bytes {
        return Some(RequestShapeProblem::PathTooLong);
    }
    match host_header(headers) {
        HostHeader::Absent | HostHeader::Present(_) => None,
        HostHeader::Malformed => Some(RequestShapeProblem::HostMalformed),
        HostHeader::TooLong => Some(RequestShapeProblem::HostTooLong),
    }
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

    // The policy kernel evaluates under fixed bounds on the method, path and
    // host (`request_bounds`) and answers an input over them with an internal
    // error. Admission states each limit here, with its own status, so a
    // served request can never reach that answer: the kernel's path bound is
    // the ceiling `MAX_REQUEST_PATH_BYTES` may be raised to, and the method
    // and host bounds are not configurable. See issue #488.
    if let Some(problem) = request_shape_problem(
        req.method(),
        req.uri().path(),
        req.headers(),
        config.max_request_path_bytes,
    ) {
        return match problem {
            RequestShapeProblem::MethodTooLong => method_too_long(),
            RequestShapeProblem::PathTooLong => {
                request_path_too_long(config.max_request_path_bytes)
            }
            RequestShapeProblem::HostMalformed => invalid_host(),
            RequestShapeProblem::HostTooLong => host_too_long(),
        };
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
        && !is_empty_admin_logout(&req, &config)
    {
        return unsupported_media_type(&config.validation_allowed_content_types);
    }

    next.run(req).await
}

fn is_empty_admin_logout(req: &Request, config: &Config) -> bool {
    config.admin_session.is_some()
        && req.method() == Method::POST
        && req.uri().path() == format!("/v1{}/auth/logout", config.admin_prefix)
        && req
            .extensions()
            .get::<axum::extract::MatchedPath>()
            .map(|matched| matched.as_str())
            == Some(req.uri().path())
        && hyper::body::Body::is_end_stream(req.body())
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

/// 501 for the same reason CONNECT is: no resource here implements a method
/// this long, and there is no honest `Allow` list to send with a 405. The
/// method is not echoed; it is the oversized thing.
fn method_too_long() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(MethodTooLongBody {
            error: "method too long",
            max_request_method_bytes: MAX_REQUEST_METHOD_BYTES,
        }),
    )
        .into_response()
}

/// RFC 9110 section 15.5.15: the target is longer than the server is willing
/// to interpret. Only the path is measured; the query is not evaluated by
/// policy and is bounded by the request head limit like every other header.
fn request_path_too_long(max_request_path_bytes: usize) -> Response {
    (
        StatusCode::URI_TOO_LONG,
        Json(RequestPathTooLongBody {
            error: "request path too long",
            max_request_path_bytes,
        }),
    )
        .into_response()
}

/// RFC 9110 section 7.2: a `Host` field with an invalid value is a 400. The
/// value is never echoed.
fn invalid_host() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(InvalidHostBody {
            error: "invalid host",
        }),
    )
        .into_response()
}

/// RFC 6585 section 5: a header field too large to process is a 431.
fn host_too_long() -> Response {
    (
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        Json(HostTooLongBody {
            error: "host too long",
            max_request_host_bytes: MAX_REQUEST_HOST_BYTES,
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
