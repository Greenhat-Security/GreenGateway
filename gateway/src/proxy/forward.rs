use std::{collections::HashSet, error::Error, fmt, net::IpAddr, time::Instant};

use axum::{
    body::Body,
    response::{IntoResponse, Response},
    Json,
};
use futures_util::{stream, StreamExt};
use http::{
    header::{self, CONTENT_LENGTH, CONTENT_TYPE},
    HeaderMap, HeaderName, HeaderValue, Request, StatusCode,
};
use serde_json::json;

use super::{MatchedUpstream, ProxyState, RequestBodyMode, RouteRequestHeaderPolicy};
use crate::{egress, middleware};

const REQUEST_ID_HEADER: &str = "x-request-id";
const STREAMING_DISCOVERY_CAPTURE_MAX_BYTES: usize = 64 * 1024;
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

#[derive(Debug)]
struct RedactedProxyBodyError(&'static str);

impl fmt::Display for RedactedProxyBodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "proxied upstream body error: {}", self.0)
    }
}

impl Error for RedactedProxyBodyError {}

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
    let known_length = match known_request_body_length(&parts.headers) {
        Ok(length) => length,
        Err(()) => return invalid_request_body(),
    };
    let body = match upstream.request_body_mode {
        RequestBodyMode::Buffered => {
            if known_length.is_some_and(|size| size > proxy.max_request_body_bytes as u64) {
                if let Some(payload_capture) = payload_capture.as_ref() {
                    payload_capture.mark_body_capture_incomplete();
                }
                return crate::payload_too_large(proxy.max_request_body_bytes);
            }
            match axum::body::to_bytes(body, proxy.max_request_body_bytes).await {
                Ok(body) => {
                    if let Some(payload_capture) = payload_capture.as_ref() {
                        payload_capture.capture_json_body(&parts.headers, &body);
                    }
                    if body.is_empty() {
                        egress::EgressRequestBody::Empty
                    } else {
                        egress::EgressRequestBody::Buffered(body.to_vec())
                    }
                }
                Err(_) => {
                    if let Some(payload_capture) = payload_capture.as_ref() {
                        payload_capture.mark_body_capture_incomplete();
                    }
                    tracing::warn!(
                        error_category = "request_body_read_failed",
                        max = proxy.max_request_body_bytes,
                        "failed to read proxied request body"
                    );
                    return crate::payload_too_large(proxy.max_request_body_bytes);
                }
            }
        }
        RequestBodyMode::Stream => egress::EgressRequestBody::streaming(
            streamed_request_body(body, &parts.headers, payload_capture),
            known_length,
        ),
    };

    let upstream_started = Instant::now();
    let upstream = match upstream
        .egress_client
        .stream_request_with_body(parts.method, &target_url, headers, body)
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
        Some(chunk) => redacted_response_body(chunk, upstream_body),
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

fn redacted_response_body(
    first_chunk: bytes::Bytes,
    upstream_body: egress::EgressBodyStream,
) -> Body {
    let redacted_tail = upstream_body.map(|result| {
        result.map_err(|error| {
            let category = error.safe_category();
            tracing::warn!(
                error_category = category,
                "proxied upstream response body failed after response commitment"
            );
            RedactedProxyBodyError(category)
        })
    });

    Body::from_stream(
        stream::once(async move { Ok::<_, RedactedProxyBodyError>(first_chunk) })
            .chain(redacted_tail),
    )
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
            | "proxy-connection"
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
    let (status, code) = match error {
        egress::EgressError::RequestBodyTooLarge { .. } => {
            (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large")
        }
        egress::EgressError::RequestBodyReadFailed => {
            (StatusCode::BAD_REQUEST, "invalid_request_body")
        }
        _ if error.is_timeout() => (StatusCode::GATEWAY_TIMEOUT, "gateway_timeout"),
        _ => (StatusCode::BAD_GATEWAY, "bad_gateway"),
    };

    (status, Json(json!({ "error": code }))).into_response()
}

fn known_request_body_length(headers: &HeaderMap) -> Result<Option<u64>, ()> {
    let values = headers.get_all(CONTENT_LENGTH);
    let mut parsed = None;
    for value in values {
        let value = value.to_str().map_err(|_| ())?;
        for value in value.split(',') {
            let value = value.trim().parse::<u64>().map_err(|_| ())?;
            if parsed.is_some_and(|previous| previous != value) {
                return Err(());
            }
            parsed = Some(value);
        }
    }
    Ok(parsed)
}

fn invalid_request_body() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": "invalid_request_body" })),
    )
        .into_response()
}

struct StreamingCapture {
    handle: Option<middleware::observation::PayloadCaptureHandle>,
    headers: HeaderMap,
    bytes: Vec<u8>,
    complete: bool,
    truncated: bool,
}

impl StreamingCapture {
    fn new(
        headers: &HeaderMap,
        handle: Option<middleware::observation::PayloadCaptureHandle>,
    ) -> Self {
        let mut capture_headers = HeaderMap::new();
        if let Some(content_type) = headers.get(CONTENT_TYPE) {
            capture_headers.insert(CONTENT_TYPE, content_type.clone());
        }
        Self {
            handle,
            headers: capture_headers,
            bytes: Vec::new(),
            complete: false,
            truncated: false,
        }
    }

    fn observe(&mut self, chunk: &bytes::Bytes) {
        if self.handle.is_none() || self.truncated {
            return;
        }
        let remaining = STREAMING_DISCOVERY_CAPTURE_MAX_BYTES.saturating_sub(self.bytes.len());
        if chunk.len() > remaining {
            self.bytes.extend_from_slice(&chunk[..remaining]);
            self.truncated = true;
            self.mark_incomplete();
        } else {
            self.bytes.extend_from_slice(chunk);
        }
    }

    fn finish(&mut self) {
        if let Some(handle) = &self.handle {
            if self.truncated {
                handle.mark_body_capture_incomplete();
            } else {
                handle.capture_json_body(&self.headers, &self.bytes);
            }
        }
        self.complete = true;
    }

    fn mark_incomplete(&self) {
        if let Some(handle) = &self.handle {
            handle.mark_body_capture_incomplete();
        }
    }
}

impl Drop for StreamingCapture {
    fn drop(&mut self) {
        if !self.complete {
            self.mark_incomplete();
        }
    }
}

fn streamed_request_body(
    body: Body,
    headers: &HeaderMap,
    payload_capture: Option<middleware::observation::PayloadCaptureHandle>,
) -> egress::EgressRequestBodyStream {
    let stream = body.into_data_stream();
    let capture = StreamingCapture::new(headers, payload_capture);
    Box::pin(stream::unfold(
        (stream, capture),
        |(mut stream, mut capture)| async move {
            match stream.next().await {
                Some(Ok(chunk)) => {
                    capture.observe(&chunk);
                    Some((Ok(chunk), (stream, capture)))
                }
                Some(Err(_)) => {
                    capture.mark_incomplete();
                    capture.complete = true;
                    Some((Err(egress::EgressRequestBodySourceError), (stream, capture)))
                }
                None => {
                    capture.finish();
                    None
                }
            }
        },
    ))
}

#[cfg(test)]
mod tests {
    use std::{io, sync::Arc};

    use std::sync::Mutex;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

    #[test]
    fn content_length_preflight_accepts_equal_duplicates_only() {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("4"));
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("4"));
        assert_eq!(known_request_body_length(&headers), Ok(Some(4)));

        headers.append(CONTENT_LENGTH, HeaderValue::from_static("5"));
        assert_eq!(known_request_body_length(&headers), Err(()));
    }

    #[test]
    fn content_length_preflight_rejects_malformed_values() {
        let headers =
            HeaderMap::from_iter([(CONTENT_LENGTH, HeaderValue::from_static("not-a-length"))]);

        assert_eq!(known_request_body_length(&headers), Err(()));
    }

    #[test]
    fn request_body_failures_use_client_error_responses() {
        let oversized =
            proxy_error_response(&egress::EgressError::RequestBodyTooLarge { size: 5, max: 4 });
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let unreadable = proxy_error_response(&egress::EgressError::RequestBodyReadFailed);
        assert_eq!(unreadable.status(), StatusCode::BAD_REQUEST);
    }

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
        headers.insert(
            HeaderName::from_static("proxy-connection"),
            HeaderValue::from_static("keep-alive"),
        );
        headers.insert("x-remove", HeaderValue::from_static("private"));
        headers.insert("x-keep", HeaderValue::from_static("public"));

        let mut forwarded = strip_hop_by_hop_headers(&headers);
        strip_gateway_credentials(&mut forwarded);

        assert!(!forwarded.contains_key(header::AUTHORIZATION));
        assert!(!forwarded.contains_key(header::COOKIE));
        assert!(!forwarded.contains_key("x-remove"));
        assert!(!forwarded.contains_key("proxy-connection"));
        assert_eq!(
            forwarded.get("x-keep"),
            Some(&HeaderValue::from_static("public"))
        );
    }

    #[test]
    fn response_header_boundary_removes_proxy_connection() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("proxy-connection"),
            HeaderValue::from_static("keep-alive"),
        );
        headers.insert("x-keep", HeaderValue::from_static("public"));

        let forwarded = strip_hop_by_hop_headers(&headers);

        assert!(!forwarded.contains_key("proxy-connection"));
        assert_eq!(
            forwarded.get("x-keep"),
            Some(&HeaderValue::from_static("public"))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn committed_response_tail_errors_are_redacted() {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(logs.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let upstream_body: egress::EgressBodyStream = Box::pin(stream::once(async {
            Err(egress::EgressError::DnsResolutionFailed(
                "https://secret.example/private?token=secret-query at 10.0.0.1".to_owned(),
            ))
        }));
        let body = redacted_response_body(bytes::Bytes::from_static(b"first"), upstream_body);
        let mut body = body.into_data_stream();

        assert_eq!(
            body.next()
                .await
                .expect("first chunk should exist")
                .expect("first chunk should be successful"),
            bytes::Bytes::from_static(b"first")
        );
        let error = body
            .next()
            .await
            .expect("tail error should exist")
            .expect_err("tail error should remain an error");
        drop(_guard);

        let output = format!("{error} {}", logs.contents());
        assert!(output.contains("dns_resolution_failed"));
        for secret in [
            "secret.example",
            "private",
            "secret-query",
            "10.0.0.1",
            "https://",
        ] {
            assert!(
                !output.contains(secret),
                "committed response tail leaked {secret}: {output}"
            );
        }
    }

    #[derive(Clone, Default)]
    struct CapturedLogs {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl CapturedLogs {
        fn contents(&self) -> String {
            String::from_utf8(
                self.buffer
                    .lock()
                    .expect("captured logs should not be poisoned")
                    .clone(),
            )
            .expect("captured logs should be UTF-8")
        }
    }

    impl<'a> MakeWriter<'a> for CapturedLogs {
        type Writer = CapturedLogWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedLogWriter {
                buffer: Arc::clone(&self.buffer),
            }
        }
    }

    struct CapturedLogWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl io::Write for CapturedLogWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.buffer
                .lock()
                .map_err(|_| io::Error::other("captured logs lock poisoned"))?
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
