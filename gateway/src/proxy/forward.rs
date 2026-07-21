use std::{collections::HashSet, net::IpAddr, time::Instant};

use axum::{
    body::Body,
    response::{IntoResponse, Response},
    Json,
};
use futures_util::{stream, StreamExt};
use http::{header, HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use serde_json::json;

use super::{MatchedUpstream, ProxyState, RouteRequestHeaderPolicy};
use crate::{egress, middleware};

const REQUEST_ID_HEADER: &str = "x-request-id";
const X_FORWARDED_FOR_HEADER: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_REAL_IP_HEADER: HeaderName = HeaderName::from_static("x-real-ip");
const COMMON_CLIENT_IP_FORWARDING_HEADERS: &[&str] = &[
    "cf-connecting-ip",
    "client-ip",
    "fastly-client-ip",
    "fly-client-ip",
    "forwarded",
    "forwarded-for",
    "forwarded-for-ip",
    "true-client-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "x-envoy-external-address",
    "x-forwarded",
    "x-original-forwarded-for",
    "x-proxyuser-ip",
    "x-real-ip",
];

pub(super) async fn forward_request(
    proxy: &ProxyState,
    request: Request<Body>,
    source_ip: &str,
) -> Response {
    let path = request.uri().path();
    let Some(upstream) = proxy.upstream_for_request(path, request.headers()) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    forward_to_upstream(proxy, request, upstream, source_ip).await
}

async fn forward_to_upstream(
    proxy: &ProxyState,
    request: Request<Body>,
    upstream: MatchedUpstream,
    source_ip: &str,
) -> Response {
    let (parts, body) = request.into_parts();
    let target_url = proxy_target_url(&upstream.upstream_origin, &parts.uri);
    let mut headers = strip_hop_by_hop_headers(&parts.headers);
    strip_gateway_credentials(&mut headers);
    if let Some(request_id) = parts.headers.get(REQUEST_ID_HEADER) {
        headers.insert(request_id_header(), request_id.clone());
    }
    set_upstream_client_ip(&mut headers, source_ip);
    apply_route_request_header_policy(&mut headers, &upstream.request_header_policy);
    let request_id = parts.headers.get(REQUEST_ID_HEADER).cloned();
    let payload_capture = parts
        .extensions
        .get::<middleware::observation::PayloadCaptureHandle>()
        .cloned();
    let body = match axum::body::to_bytes(body, proxy.max_request_body_bytes).await {
        Ok(body) if body.is_empty() => None,
        Ok(body) => {
            if let Some(payload_capture) = payload_capture.as_ref() {
                payload_capture.capture_json_body(&parts.headers, &body);
            }
            Some(body.to_vec())
        }
        Err(_) => {
            tracing::warn!(
                error_category = "request_body_read_failed",
                max = proxy.max_request_body_bytes,
                "failed to read proxied request body"
            );
            return crate::payload_too_large(proxy.max_request_body_bytes);
        }
    };

    let upstream_started = Instant::now();
    let upstream = match upstream
        .egress_client
        .stream_request_with_headers(parts.method, &target_url, headers, body)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            let latency_ms = crate::duration_millis(upstream_started.elapsed());
            tracing::warn!(
                error_category = err.safe_category(),
                "proxied upstream request failed"
            );
            return error_response_with_outcome(&err, latency_ms, request_id);
        }
    };
    let upstream_latency_ms = crate::duration_millis(upstream_started.elapsed());
    let upstream_status = upstream.status;
    let upstream_headers = strip_hop_by_hop_headers(&upstream.headers);
    let mut upstream_body = upstream.body;
    let first_chunk = match upstream_body.next().await {
        Some(Ok(chunk)) => Some(chunk),
        Some(Err(err)) => {
            let latency_ms = crate::duration_millis(upstream_started.elapsed());
            tracing::warn!(
                error_category = err.safe_category(),
                "proxied upstream response body failed"
            );
            return error_response_with_outcome(&err, latency_ms, request_id);
        }
        None => None,
    };
    let response_body = match first_chunk {
        Some(chunk) => Body::from_stream(
            stream::once(async move { Ok::<_, egress::EgressError>(chunk) }).chain(upstream_body),
        ),
        None => Body::empty(),
    };
    let mut response = Response::new(response_body);
    *response.status_mut() = upstream_status;
    *response.headers_mut() = upstream_headers;
    response
        .extensions_mut()
        .insert(middleware::decision::UpstreamOutcome {
            latency_ms: upstream_latency_ms,
            status: Some(upstream_status.as_u16()),
        });
    if let Some(request_id) = request_id {
        response
            .headers_mut()
            .insert(request_id_header(), request_id);
    }

    response
}

fn error_response_with_outcome(
    error: &egress::EgressError,
    latency_ms: u64,
    request_id: Option<HeaderValue>,
) -> Response {
    let mut response = proxy_error_response(error);
    response
        .extensions_mut()
        .insert(middleware::decision::UpstreamOutcome {
            latency_ms,
            status: None,
        });
    if let Some(request_id) = request_id {
        response
            .headers_mut()
            .insert(request_id_header(), request_id);
    }
    response
}

fn request_id_header() -> HeaderName {
    HeaderName::from_static(REQUEST_ID_HEADER)
}

fn proxy_target_url(upstream_origin: &str, uri: &http::Uri) -> String {
    let path_and_query = uri.path_and_query().map_or("/", |value| value.as_str());
    format!("{upstream_origin}{path_and_query}")
}

fn strip_hop_by_hop_headers(headers: &HeaderMap) -> HeaderMap {
    let connection_named_headers = connection_named_headers(headers);
    let mut forwarded = HeaderMap::new();

    for (name, value) in headers {
        if is_hop_by_hop_header(name) || connection_named_headers.contains(name) {
            continue;
        }
        forwarded.append(name.clone(), value.clone());
    }

    forwarded
}

fn set_upstream_client_ip(headers: &mut HeaderMap, source_ip: &str) {
    let forwarding_headers = headers
        .keys()
        .filter(|name| is_client_forwarding_header(name))
        .cloned()
        .collect::<Vec<_>>();
    for name in forwarding_headers {
        headers.remove(name);
    }

    let Ok(source_ip) = source_ip.parse::<IpAddr>() else {
        return;
    };
    let source_ip = source_ip.to_string();
    let value = HeaderValue::from_bytes(source_ip.as_bytes())
        .expect("normalized IP address should be a valid header value");
    headers.insert(X_FORWARDED_FOR_HEADER, value.clone());
    headers.insert(X_REAL_IP_HEADER, value);
}

fn is_client_forwarding_header(name: &HeaderName) -> bool {
    let name = name.as_str();
    name.starts_with("x-forwarded-") || COMMON_CLIENT_IP_FORWARDING_HEADERS.contains(&name)
}

fn strip_gateway_credentials(headers: &mut HeaderMap) {
    headers.remove(header::AUTHORIZATION);
    headers.remove(header::COOKIE);
}

fn apply_route_request_header_policy(headers: &mut HeaderMap, policy: &RouteRequestHeaderPolicy) {
    for name in &policy.strip_request_headers {
        if name.as_str() == REQUEST_ID_HEADER {
            continue;
        }
        headers.remove(name);
    }

    for (name, value) in &policy.add_request_headers {
        if is_hop_by_hop_header(name) || name.as_str() == REQUEST_ID_HEADER {
            continue;
        }
        headers.insert(name.clone(), value.clone());
    }
}

fn connection_named_headers(headers: &HeaderMap) -> HashSet<HeaderName> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect()
}

fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
    )
}

fn proxy_error_response(error: &egress::EgressError) -> Response {
    let (status, code) = if error.is_timeout() {
        (StatusCode::GATEWAY_TIMEOUT, "gateway_timeout")
    } else {
        (StatusCode::BAD_GATEWAY, "bad_gateway")
    };

    (status, Json(json!({ "error": code }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_url_preserves_path_and_query_and_discards_configured_path() {
        let uri = "/items?cursor=next"
            .parse::<http::Uri>()
            .expect("URI should parse");

        assert_eq!(
            proxy_target_url("https://upstream.example.test", &uri),
            "https://upstream.example.test/items?cursor=next"
        );
    }

    #[test]
    fn request_header_boundary_removes_credentials_and_connection_named_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer secret"),
        );
        headers.insert(header::COOKIE, HeaderValue::from_static("session=secret"));
        headers.insert(header::CONNECTION, HeaderValue::from_static("x-remove"));
        headers.insert("x-remove", HeaderValue::from_static("private"));
        headers.insert("x-keep", HeaderValue::from_static("public"));

        let mut forwarded = strip_hop_by_hop_headers(&headers);
        strip_gateway_credentials(&mut forwarded);

        assert!(!forwarded.contains_key(header::AUTHORIZATION));
        assert!(!forwarded.contains_key(header::COOKIE));
        assert!(!forwarded.contains_key("x-remove"));
        assert_eq!(
            forwarded.get("x-keep"),
            Some(&HeaderValue::from_static("public"))
        );
    }
}
