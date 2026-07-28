use std::{
    collections::HashSet,
    error::Error,
    fmt,
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

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

use super::{retry, MatchedUpstream, ProxyState, RequestBodyMode, RouteRequestHeaderPolicy};
use crate::{
    audit, auth,
    connections::http::{ConnectionHttpError, ConnectionHttpTarget},
    egress, middleware,
};

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

struct ResponseTailDemand {
    response: tokio::sync::oneshot::Sender<ResponseTailEvent>,
}

enum ResponseTailEvent {
    Chunk(bytes::Bytes),
    Error(&'static str),
    Eof,
}

#[derive(Clone, Copy)]
enum ResponseTailTerminal {
    Active,
    Error(&'static str),
    Eof,
}

struct ResponseStreamTelemetry {
    audit: audit::AuditLog,
    lifecycle: crate::lifecycle::GatewayLifecycle,
    request_id: String,
    source_ip: String,
    pool_id: Arc<str>,
    endpoint_id: Arc<str>,
    mode: &'static str,
    status: u16,
    attempt_count: usize,
    request_started: Instant,
    time_to_headers: Duration,
    time_to_first_byte: Option<Duration>,
    bytes_received: u64,
    bytes_sent: u64,
}

impl ResponseStreamTelemetry {
    fn observe_received(&mut self, chunk: &bytes::Bytes) {
        let chunk_bytes = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
        self.bytes_received = self.bytes_received.saturating_add(chunk_bytes);
        self.time_to_first_byte
            .get_or_insert_with(|| self.request_started.elapsed());
    }

    fn observe_received_total(&mut self, total: usize) {
        let total = u64::try_from(total).unwrap_or(u64::MAX);
        self.bytes_received = self.bytes_received.max(total);
        if total > 0 {
            self.time_to_first_byte
                .get_or_insert_with(|| self.request_started.elapsed());
        }
    }

    fn observe_sent(&mut self, chunk: &bytes::Bytes) {
        self.bytes_sent = self
            .bytes_sent
            .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
    }

    fn finish(self, outcome: &'static str) {
        let labels = [
            ("pool_id", self.pool_id.to_string()),
            ("endpoint_id", self.endpoint_id.to_string()),
            ("mode", self.mode.to_owned()),
            ("outcome", outcome.to_owned()),
        ];
        let duration = self.request_started.elapsed();
        ::metrics::counter!(crate::metrics::PROXY_STREAM_TERMINATIONS_TOTAL, &labels).increment(1);
        ::metrics::histogram!(crate::metrics::PROXY_STREAM_DURATION_SECONDS, &labels)
            .record(duration.as_secs_f64());
        ::metrics::histogram!(
            crate::metrics::PROXY_STREAM_TIME_TO_HEADERS_SECONDS,
            &labels
        )
        .record(self.time_to_headers.as_secs_f64());
        if let Some(time_to_first_byte) = self.time_to_first_byte {
            ::metrics::histogram!(
                crate::metrics::PROXY_STREAM_TIME_TO_FIRST_BYTE_SECONDS,
                &labels
            )
            .record(time_to_first_byte.as_secs_f64());
        }
        ::metrics::histogram!(crate::metrics::PROXY_STREAM_BYTES_RECEIVED, &labels)
            .record(self.bytes_received as f64);
        ::metrics::histogram!(crate::metrics::PROXY_STREAM_BYTES_SENT, &labels)
            .record(self.bytes_sent as f64);

        self.audit.emit(audit::AuditEvent::new(
            audit::event::UPSTREAM_STREAM_TERMINATED,
            self.request_id,
            self.source_ip,
            None::<audit::Actor>,
            json!({
                "pool_id": self.pool_id,
                "endpoint_id": self.endpoint_id,
                "mode": self.mode,
                "status": self.status,
                "outcome": outcome,
                "bytes_received": self.bytes_received,
                "bytes_sent": self.bytes_sent,
                "time_to_headers_ms": crate::duration_millis(self.time_to_headers),
                "time_to_first_byte_ms": self.time_to_first_byte.map(crate::duration_millis),
                "duration_ms": crate::duration_millis(duration),
                "attempt_count": self.attempt_count,
            }),
        ));
    }
}

struct ResponsePumpCompletion(Option<tokio::sync::oneshot::Sender<()>>);

struct ResponseTailOptions {
    circuit_permit: Option<super::circuit::CircuitPermit>,
    pump_completed: Option<tokio::sync::oneshot::Sender<()>>,
    telemetry: Option<ResponseStreamTelemetry>,
    timeout_outcome: &'static str,
    registration: Option<tokio_util::task::task_tracker::TaskTrackerToken>,
}

impl Drop for ResponsePumpCompletion {
    fn drop(&mut self) {
        if let Some(completed) = self.0.take() {
            let _ = completed.send(());
        }
    }
}

struct ResponseTailPump {
    pending_chunk: Option<bytes::Bytes>,
    upstream_body: egress::EgressBodyStream,
    demand_receiver: tokio::sync::mpsc::Receiver<ResponseTailDemand>,
    terminal_sender: tokio::sync::watch::Sender<ResponseTailTerminal>,
    admission_permit: super::admission::PoolAdmissionPermit,
    retry_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    deadline: Option<tokio::time::Instant>,
    passive_health: Option<(
        super::health::UpstreamHealthState,
        Arc<crate::config::UpstreamHealthCheckConfig>,
    )>,
    circuit_permit: Option<super::circuit::CircuitPermit>,
    telemetry: Option<ResponseStreamTelemetry>,
    timeout_outcome: &'static str,
    shutdown: tokio_util::sync::CancellationToken,
    registration: Option<tokio_util::task::task_tracker::TaskTrackerToken>,
    completion: ResponsePumpCompletion,
}

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
    let request_id = parts.headers.get(REQUEST_ID_HEADER).cloned();
    let Some(response_stream_registration) = proxy.lifecycle.try_register_response_stream() else {
        tracing::info!(
            pool_id = upstream.pool.id.as_ref(),
            error_category = "shutdown",
            "proxied request rejected because gateway shutdown is draining"
        );
        return admission_unavailable_response(&upstream.pool.id, request_id);
    };
    let mut response_stream_registration = Some(response_stream_registration);
    let forced_shutdown = proxy.lifecycle.response_stream_cancellation();
    let payload_capture = parts
        .extensions
        .get::<middleware::observation::PayloadCaptureHandle>()
        .cloned();
    let known_length = match known_request_body_length(&parts.headers) {
        Ok(length) => length,
        Err(()) => return invalid_request_body(),
    };
    if known_length.is_some_and(|size| size > proxy.max_request_body_bytes as u64) {
        if let Some(payload_capture) = payload_capture.as_ref() {
            payload_capture.mark_body_capture_incomplete();
        }
        return crate::payload_too_large(proxy.max_request_body_bytes);
    }
    if proxy.lifecycle.draining() {
        tracing::info!(
            pool_id = upstream.pool.id.as_ref(),
            error_category = "shutdown",
            "proxied request rejected because gateway shutdown is draining"
        );
        return admission_unavailable_response(&upstream.pool.id, request_id);
    }
    let shutdown = proxy.lifecycle.background_cancellation();
    let admission_result = tokio::select! {
        biased;
        () = shutdown.cancelled_owned() => {
            tracing::info!(
                pool_id = upstream.pool.id.as_ref(),
                error_category = "shutdown",
                "queued proxied request cancelled because gateway shutdown began"
            );
            return admission_unavailable_response(&upstream.pool.id, request_id);
        }
        result = upstream.pool.admission.acquire() => result,
    };
    let admission_permit = match admission_result {
        Ok(permit) => permit,
        Err(error) => {
            let reason = match error {
                super::admission::PoolAdmissionError::QueueFull => "queue_full",
                super::admission::PoolAdmissionError::QueueTimeout => "queue_timeout",
            };
            tracing::warn!(
                pool_id = upstream.pool.id.as_ref(),
                error_category = reason,
                "proxied request rejected by bounded admission"
            );
            return admission_unavailable_response(&upstream.pool.id, request_id);
        }
    };
    if proxy.lifecycle.draining() {
        drop(admission_permit);
        tracing::info!(
            pool_id = upstream.pool.id.as_ref(),
            error_category = "shutdown",
            "proxied request rejected after admission because gateway shutdown began"
        );
        return admission_unavailable_response(&upstream.pool.id, request_id);
    }
    let mut body = match upstream.request_body_mode {
        RequestBodyMode::Buffered => {
            let buffered = tokio::select! {
                biased;
                () = forced_shutdown.cancelled() => {
                    return admission_unavailable_response(&upstream.pool.id, request_id);
                }
                buffered = axum::body::to_bytes(body, proxy.max_request_body_bytes) => buffered,
            };
            match buffered {
                Ok(body) => {
                    if let Some(payload_capture) = payload_capture.as_ref() {
                        payload_capture.capture_json_body(&parts.headers, &body);
                    }
                    if body.is_empty() {
                        PreparedRequestBody::Empty
                    } else {
                        PreparedRequestBody::Buffered(Arc::from(body.to_vec()))
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
        RequestBodyMode::Stream => {
            PreparedRequestBody::Streaming(Some(egress::EgressRequestBody::streaming(
                streamed_request_body(body, &parts.headers, payload_capture),
                known_length,
            )))
        }
    };
    let connection_target = match upstream.connection_id.as_deref() {
        Some(connection_id) => {
            let Some(runtime) = proxy.connection_http.as_ref() else {
                return connection_failure_response(
                    ConnectionHttpError::TransportUnavailable,
                    &upstream.pool.id,
                    request_id,
                    Vec::new(),
                    Duration::ZERO,
                );
            };
            let path_and_query = parts
                .uri
                .path_and_query()
                .map_or("/", http::uri::PathAndQuery::as_str);
            match runtime.target(connection_id, path_and_query) {
                Ok(target) => {
                    if super::validate_connection_header_policy(
                        &upstream.request_header_policy,
                        &target,
                    )
                    .is_err()
                    {
                        return connection_failure_response(
                            ConnectionHttpError::CredentialHeaderConflict,
                            &upstream.pool.id,
                            request_id,
                            Vec::new(),
                            Duration::ZERO,
                        );
                    }
                    Some(target)
                }
                Err(error) => {
                    return connection_failure_response(
                        error,
                        &upstream.pool.id,
                        request_id,
                        Vec::new(),
                        Duration::ZERO,
                    );
                }
            }
        }
        None => None,
    };
    let request_started = Instant::now();
    let request_timeout = connection_target.as_ref().map_or_else(
        || upstream.pool.request_timeout(),
        |target| target.client().request_timeout(),
    );
    let deadline = tokio::time::Instant::now() + request_timeout;
    let (checked_connection_destination, connection_headers) =
        if let Some(target) = connection_target.as_ref() {
            let checked = tokio::select! {
                biased;
                () = forced_shutdown.cancelled() => {
                    return admission_unavailable_response(&upstream.pool.id, request_id);
                }
                checked = tokio::time::timeout_at(
                    deadline,
                    target.client().checked_destination(target.url()),
                ) => checked,
            };
            let checked = match checked {
                Err(_) => {
                    return connection_failure_response(
                        ConnectionHttpError::TransportUnavailable,
                        &upstream.pool.id,
                        request_id,
                        Vec::new(),
                        request_started.elapsed(),
                    );
                }
                Ok(Err(error)) => {
                    return error_response_with_outcome(
                        &error,
                        request_started.elapsed(),
                        request_id,
                        &upstream.pool.id,
                        "primary",
                        Vec::new(),
                        false,
                    );
                }
                Ok(Ok(checked)) => checked,
            };

            let runtime = proxy
                .connection_http
                .as_ref()
                .expect("connection target requires a Connection HTTP runtime");
            let credential = tokio::select! {
                biased;
                () = forced_shutdown.cancelled() => {
                    return admission_unavailable_response(&upstream.pool.id, request_id);
                }
                credential = tokio::time::timeout_at(
                    deadline,
                    runtime.resolve_credential(target),
                ) => credential,
            };
            let credential = match credential {
                Err(_) => {
                    let error = if target.authentication_kind() == "oauth2_client_credentials" {
                        ConnectionHttpError::OAuthTokenUnavailable
                    } else {
                        ConnectionHttpError::CredentialUnavailable
                    };
                    if error.is_secret_resolution_failure() {
                        emit_connection_secret_resolution_failed(
                            proxy,
                            &parts,
                            source_ip,
                            &upstream.pool.id,
                            target,
                            error.safe_reason(),
                        );
                    }
                    return connection_failure_response(
                        error,
                        &upstream.pool.id,
                        request_id,
                        Vec::new(),
                        request_started.elapsed(),
                    );
                }
                Ok(Err(error)) => {
                    if error.is_secret_resolution_failure() {
                        emit_connection_secret_resolution_failed(
                            proxy,
                            &parts,
                            source_ip,
                            &upstream.pool.id,
                            target,
                            error.safe_reason(),
                        );
                    }
                    return connection_failure_response(
                        error,
                        &upstream.pool.id,
                        request_id,
                        Vec::new(),
                        request_started.elapsed(),
                    );
                }
                Ok(Ok(credential)) => credential,
            };
            let mut headers = attempt_headers(
                &parts.headers,
                source_ip,
                &upstream.request_header_policy,
                target.credential_header_name(),
            );
            if let Some(credential) = credential.as_ref() {
                if let Err(error) = credential.inject(&mut headers) {
                    emit_connection_secret_resolution_failed(
                        proxy,
                        &parts,
                        source_ip,
                        &upstream.pool.id,
                        target,
                        error.safe_reason(),
                    );
                    return connection_failure_response(
                        error,
                        &upstream.pool.id,
                        request_id,
                        Vec::new(),
                        request_started.elapsed(),
                    );
                }
            }
            (Some(checked), Some((headers, credential)))
        } else {
            (None, None)
        };
    let max_attempts = upstream
        .pool
        .retry_policy
        .max_attempts_for(&parts.method, body.is_replayable());
    let mut attempted_endpoint_ids = HashSet::new();
    let mut attempts = Vec::with_capacity(usize::from(max_attempts));
    let mut active_retry_permit = None;

    for attempt_number in 1..=max_attempts {
        let Some(selected) = upstream
            .pool
            .select_endpoint_avoiding(&attempted_endpoint_ids)
        else {
            let retry_exhausted = !attempts.is_empty();
            if retry_exhausted {
                emit_retry_exhausted(
                    proxy,
                    request_id.as_ref(),
                    source_ip,
                    &upstream.pool.id,
                    &attempts,
                    "no_eligible_endpoint",
                );
            }
            tracing::warn!(
                pool_id = upstream.pool.id.as_ref(),
                error_category = "no_healthy_endpoint",
                "proxied request found no healthy upstream endpoint"
            );
            return unavailable_response_with_outcome(
                &upstream.pool.id,
                request_id,
                attempts,
                retry_exhausted,
                request_started.elapsed(),
            );
        };
        let endpoint = selected.endpoint;
        let mut circuit_permit = selected.circuit_permit;
        attempted_endpoint_ids.insert(Arc::clone(&endpoint.id));
        ::metrics::counter!(
            crate::metrics::PROXY_ENDPOINT_SELECTIONS_TOTAL,
            "pool_id" => Arc::clone(&upstream.pool.id),
            "endpoint_id" => Arc::clone(&endpoint.id)
        )
        .increment(1);
        tracing::debug!(
            pool_id = upstream.pool.id.as_ref(),
            endpoint_id = endpoint.id.as_ref(),
            attempt = attempt_number,
            "selected configured upstream endpoint"
        );

        let Some(attempt_body) = body.next_attempt() else {
            tracing::error!(
                pool_id = upstream.pool.id.as_ref(),
                error_category = "non_replayable_body",
                "retry planner attempted to replay a non-replayable request body"
            );
            return unavailable_response_with_outcome(
                &upstream.pool.id,
                request_id,
                attempts,
                true,
                request_started.elapsed(),
            );
        };
        let target_url = connection_target.as_ref().map_or_else(
            || proxy_target_url(&endpoint.upstream_origin, &parts.uri),
            |target| target.url().to_owned(),
        );
        let headers = connection_headers.as_ref().map_or_else(
            || {
                attempt_headers(
                    &parts.headers,
                    source_ip,
                    &upstream.request_header_policy,
                    None,
                )
            },
            |(headers, _credential)| headers.clone(),
        );
        let egress_client = connection_target
            .as_ref()
            .map_or(&endpoint.egress_client, ConnectionHttpTarget::client);
        let attempt_started = Instant::now();
        let send = async {
            if let Some(sse) = upstream.sse {
                let max_response_bytes = sse
                    .max_response_bytes
                    .unwrap_or_else(|| Some(egress_client.max_response_bytes()));
                match checked_connection_destination.as_ref() {
                    Some(destination) => {
                        egress_client
                            .stream_request_with_body_for_sse_at_checked_destination(
                                destination,
                                parts.method.clone(),
                                &target_url,
                                headers,
                                attempt_body,
                                max_response_bytes,
                            )
                            .await
                    }
                    None => {
                        egress_client
                            .stream_request_with_body_for_sse(
                                parts.method.clone(),
                                &target_url,
                                headers,
                                attempt_body,
                                max_response_bytes,
                            )
                            .await
                    }
                }
            } else {
                match checked_connection_destination.as_ref() {
                    Some(destination) => {
                        egress_client
                            .stream_request_with_body_at_checked_destination(
                                destination,
                                parts.method.clone(),
                                &target_url,
                                headers,
                                attempt_body,
                            )
                            .await
                    }
                    None => {
                        egress_client
                            .stream_request_with_body(
                                parts.method.clone(),
                                &target_url,
                                headers,
                                attempt_body,
                            )
                            .await
                    }
                }
            }
        };
        let sent = tokio::select! {
            biased;
            () = forced_shutdown.cancelled() => {
                return admission_unavailable_response(&upstream.pool.id, request_id);
            }
            sent = tokio::time::timeout_at(deadline, send) => sent,
        };

        let mut upstream_response = match sent {
            Err(_) => {
                record_circuit_failure(&mut circuit_permit, "request_timeout");
                if let Some(config) = endpoint.health_config.as_deref() {
                    endpoint.health.record_passive_timeout(config).await;
                }
                let duration = attempt_started.elapsed();
                record_attempt(&upstream.pool.id, &endpoint.id, "request_timeout", duration);
                attempts.push(attempt_outcome(&endpoint.id, "request_timeout", duration));
                let retry_exhausted = max_attempts > 1;
                if retry_exhausted {
                    emit_retry_exhausted(
                        proxy,
                        request_id.as_ref(),
                        source_ip,
                        &upstream.pool.id,
                        &attempts,
                        "request_timeout",
                    );
                }
                return gateway_timeout_response(
                    request_id,
                    &upstream.pool.id,
                    &endpoint.id,
                    attempts,
                    retry_exhausted,
                    request_started.elapsed(),
                );
            }
            Ok(Err(error)) => {
                if upstream.pool.retry_policy.retries_error(&error) {
                    record_circuit_failure(&mut circuit_permit, circuit_failure_reason(&error));
                }
                if let Some(config) = endpoint.health_config.as_deref() {
                    endpoint
                        .health
                        .record_passive_proxy_error(&error, config)
                        .await;
                }
                let duration = attempt_started.elapsed();
                let category = proxy_error_category(&error);
                record_attempt(&upstream.pool.id, &endpoint.id, category, duration);
                attempts.push(attempt_outcome(&endpoint.id, category, duration));
                tracing::warn!(
                    error_category = category,
                    attempt = attempt_number,
                    "proxied upstream request attempt failed"
                );
                let can_retry = attempt_number < max_attempts
                    && upstream.pool.retry_policy.retries_error(&error);
                if can_retry {
                    drop(active_retry_permit.take());
                    match reserve_retry(
                        &upstream,
                        &proxy.lifecycle,
                        request_id.as_ref(),
                        attempt_number,
                        deadline,
                        "transport",
                    )
                    .await
                    {
                        Ok(permit) => {
                            active_retry_permit = Some(permit);
                            continue;
                        }
                        Err(reason) => {
                            emit_retry_exhausted(
                                proxy,
                                request_id.as_ref(),
                                source_ip,
                                &upstream.pool.id,
                                &attempts,
                                reason,
                            );
                            return error_response_with_outcome(
                                &error,
                                request_started.elapsed(),
                                request_id,
                                &upstream.pool.id,
                                &endpoint.id,
                                attempts,
                                true,
                            );
                        }
                    }
                }
                let retry_exhausted =
                    upstream.pool.retry_policy.retries_error(&error) && max_attempts > 1;
                if retry_exhausted {
                    emit_retry_exhausted(
                        proxy,
                        request_id.as_ref(),
                        source_ip,
                        &upstream.pool.id,
                        &attempts,
                        "max_attempts",
                    );
                }
                return error_response_with_outcome(
                    &error,
                    request_started.elapsed(),
                    request_id,
                    &upstream.pool.id,
                    &endpoint.id,
                    attempts,
                    retry_exhausted,
                );
            }
            Ok(Ok(response)) => response,
        };

        let upstream_status = upstream_response.status;
        let oauth_unauthorized = oauth_unauthorized_forbids_retry(
            upstream_status,
            connection_target
                .as_ref()
                .map(ConnectionHttpTarget::authentication_kind),
        );
        if oauth_unauthorized {
            if let Some(credential) = connection_headers
                .as_ref()
                .and_then(|(_, credential)| credential.as_ref())
            {
                credential.invalidate_after_unauthorized().await;
            }
        }
        let retryable_status =
            !oauth_unauthorized && upstream.pool.retry_policy.retries_status(upstream_status);
        if endpoint
            .circuit
            .as_ref()
            .is_some_and(|circuit| circuit.is_failure_status(upstream_status.as_u16()))
        {
            record_circuit_failure(&mut circuit_permit, "retryable_status");
        }
        if let Some(config) = endpoint.health_config.as_deref() {
            endpoint
                .health
                .record_passive_status(upstream_status.as_u16(), config)
                .await;
        }
        let mut retry_stop_reason = None;
        if retryable_status && attempt_number < max_attempts {
            let duration = attempt_started.elapsed();
            drop(active_retry_permit.take());
            match reserve_retry(
                &upstream,
                &proxy.lifecycle,
                request_id.as_ref(),
                attempt_number,
                deadline,
                "status",
            )
            .await
            {
                Ok(permit) => {
                    record_attempt(
                        &upstream.pool.id,
                        &endpoint.id,
                        "retryable_status",
                        duration,
                    );
                    attempts.push(attempt_outcome(&endpoint.id, "retryable_status", duration));
                    active_retry_permit = Some(permit);
                    continue;
                }
                Err(reason) => {
                    retry_stop_reason = Some(reason);
                }
            }
        }

        let upstream_headers = strip_hop_by_hop_headers(&upstream_response.headers);
        let time_to_headers = request_started.elapsed();
        let first_chunk = if upstream.sse.is_some() {
            None
        } else {
            let first = tokio::select! {
                biased;
                () = forced_shutdown.cancelled() => {
                    return admission_unavailable_response(&upstream.pool.id, request_id);
                }
                first = tokio::time::timeout_at(deadline, upstream_response.body.next()) => first,
            };
            match first {
                Err(_) => {
                    record_circuit_failure(&mut circuit_permit, "request_timeout");
                    if let Some(config) = endpoint.health_config.as_deref() {
                        endpoint.health.record_passive_timeout(config).await;
                    }
                    let duration = attempt_started.elapsed();
                    record_attempt(&upstream.pool.id, &endpoint.id, "request_timeout", duration);
                    attempts.push(attempt_outcome(&endpoint.id, "request_timeout", duration));
                    let retry_exhausted = max_attempts > 1;
                    if retry_exhausted {
                        emit_retry_exhausted(
                            proxy,
                            request_id.as_ref(),
                            source_ip,
                            &upstream.pool.id,
                            &attempts,
                            "request_timeout",
                        );
                    }
                    return gateway_timeout_response(
                        request_id,
                        &upstream.pool.id,
                        &endpoint.id,
                        attempts,
                        retry_exhausted,
                        request_started.elapsed(),
                    );
                }
                Ok(Some(Err(error))) => {
                    if upstream.pool.retry_policy.retries_error(&error) {
                        record_circuit_failure(&mut circuit_permit, circuit_failure_reason(&error));
                    }
                    if let Some(config) = endpoint.health_config.as_deref() {
                        endpoint
                            .health
                            .record_passive_proxy_error(&error, config)
                            .await;
                    }
                    let duration = attempt_started.elapsed();
                    let category = proxy_error_category(&error);
                    record_attempt(&upstream.pool.id, &endpoint.id, category, duration);
                    attempts.push(attempt_outcome(&endpoint.id, category, duration));
                    let can_retry = attempt_number < max_attempts
                        && retry_stop_reason.is_none()
                        && upstream.pool.retry_policy.retries_error(&error);
                    if can_retry {
                        drop(active_retry_permit.take());
                        match reserve_retry(
                            &upstream,
                            &proxy.lifecycle,
                            request_id.as_ref(),
                            attempt_number,
                            deadline,
                            "response",
                        )
                        .await
                        {
                            Ok(permit) => {
                                active_retry_permit = Some(permit);
                                continue;
                            }
                            Err(reason) => {
                                emit_retry_exhausted(
                                    proxy,
                                    request_id.as_ref(),
                                    source_ip,
                                    &upstream.pool.id,
                                    &attempts,
                                    reason,
                                );
                                return error_response_with_outcome(
                                    &error,
                                    request_started.elapsed(),
                                    request_id,
                                    &upstream.pool.id,
                                    &endpoint.id,
                                    attempts,
                                    true,
                                );
                            }
                        }
                    }
                    let retry_exhausted = retry_stop_reason.is_some()
                        || (upstream.pool.retry_policy.retries_error(&error) && max_attempts > 1);
                    if retry_exhausted {
                        emit_retry_exhausted(
                            proxy,
                            request_id.as_ref(),
                            source_ip,
                            &upstream.pool.id,
                            &attempts,
                            retry_stop_reason.unwrap_or("max_attempts"),
                        );
                    }
                    return error_response_with_outcome(
                        &error,
                        request_started.elapsed(),
                        request_id,
                        &upstream.pool.id,
                        &endpoint.id,
                        attempts,
                        retry_exhausted,
                    );
                }
                Ok(Some(Ok(chunk))) => Some(chunk),
                Ok(None) => None,
            }
        };
        let duration = attempt_started.elapsed();
        let result = if retryable_status {
            "retryable_status"
        } else {
            "response"
        };
        record_attempt(&upstream.pool.id, &endpoint.id, result, duration);
        attempts.push(attempt_outcome(&endpoint.id, result, duration));
        let retry_exhausted = retry_stop_reason.is_some() || (retryable_status && max_attempts > 1);
        if retry_exhausted {
            emit_retry_exhausted(
                proxy,
                request_id.as_ref(),
                source_ip,
                &upstream.pool.id,
                &attempts,
                retry_stop_reason.unwrap_or("max_attempts"),
            );
        }
        if upstream.sse.is_some() {
            drop(active_retry_permit.take());
        }
        let prefetched_bytes = first_chunk
            .as_ref()
            .map_or(0, |chunk| u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        let telemetry = ResponseStreamTelemetry {
            audit: proxy.audit.clone(),
            lifecycle: proxy.lifecycle.clone(),
            request_id: request_id
                .as_ref()
                .and_then(|value| value.to_str().ok())
                .unwrap_or("unknown")
                .to_owned(),
            source_ip: source_ip.to_owned(),
            pool_id: Arc::clone(&upstream.pool.id),
            endpoint_id: Arc::clone(&endpoint.id),
            mode: if upstream.sse.is_some() {
                "sse"
            } else {
                "standard"
            },
            status: upstream_status.as_u16(),
            attempt_count: attempts.len(),
            request_started,
            time_to_headers,
            time_to_first_byte: first_chunk.as_ref().map(|_| request_started.elapsed()),
            bytes_received: prefetched_bytes,
            bytes_sent: 0,
        };
        let stream_terminal_pending = upstream.sse.is_some() || first_chunk.is_some();
        let response_body = if stream_terminal_pending {
            let passive_health = endpoint
                .health_config
                .as_ref()
                .map(|config| (endpoint.health.clone(), Arc::clone(config)));
            let stream_deadline = upstream.sse.map_or(Some(deadline), |sse| {
                sse.max_duration
                    .map(|duration| tokio::time::Instant::now() + duration)
            });
            redacted_response_body_inner(
                first_chunk,
                upstream_response.body,
                admission_permit,
                active_retry_permit.take(),
                stream_deadline,
                passive_health,
                ResponseTailOptions {
                    circuit_permit: circuit_permit.take(),
                    pump_completed: None,
                    telemetry: Some(telemetry),
                    timeout_outcome: if upstream.sse.is_some() {
                        "duration_limit"
                    } else {
                        "request_timeout"
                    },
                    registration: response_stream_registration.take(),
                },
            )
        } else {
            record_circuit_success(&mut circuit_permit);
            Body::empty()
        };
        let mut response = Response::new(response_body);
        *response.status_mut() = upstream_status;
        *response.headers_mut() = upstream_headers;
        response
            .extensions_mut()
            .insert(middleware::decision::UpstreamOutcome {
                latency_ms: crate::duration_millis(request_started.elapsed()),
                status: Some(upstream_status.as_u16()),
                pool_id: Some(upstream.pool.id.to_string()),
                endpoint_id: Some(endpoint.id.to_string()),
                attempts,
                retry_exhausted,
                stream_terminal_pending,
            });
        if let Some(request_id) = request_id {
            response
                .headers_mut()
                .insert(request_id_header(), request_id);
        }
        return response;
    }

    unavailable_response_with_outcome(
        &upstream.pool.id,
        request_id,
        attempts,
        true,
        request_started.elapsed(),
    )
}

enum PreparedRequestBody {
    Empty,
    Buffered(Arc<[u8]>),
    Streaming(Option<egress::EgressRequestBody>),
}

impl PreparedRequestBody {
    fn is_replayable(&self) -> bool {
        !matches!(self, Self::Streaming(_))
    }

    fn next_attempt(&mut self) -> Option<egress::EgressRequestBody> {
        match self {
            Self::Empty => Some(egress::EgressRequestBody::Empty),
            Self::Buffered(bytes) => {
                Some(egress::EgressRequestBody::Buffered(bytes.as_ref().to_vec()))
            }
            Self::Streaming(body) => body.take(),
        }
    }
}

fn attempt_headers(
    inbound: &HeaderMap,
    source_ip: &str,
    policy: &RouteRequestHeaderPolicy,
    credential_header: Option<&HeaderName>,
) -> HeaderMap {
    let mut headers = strip_hop_by_hop_headers(inbound);
    strip_gateway_credentials(&mut headers);
    if let Some(credential_header) = credential_header {
        headers.remove(credential_header);
    }
    if let Some(request_id) = inbound.get(REQUEST_ID_HEADER) {
        headers.insert(request_id_header(), request_id.clone());
    }
    set_upstream_client_ip(&mut headers, source_ip);
    apply_route_request_header_policy(&mut headers, policy);
    headers
}

async fn reserve_retry(
    upstream: &MatchedUpstream,
    lifecycle: &crate::lifecycle::GatewayLifecycle,
    request_id: Option<&HeaderValue>,
    failed_attempt: u8,
    deadline: tokio::time::Instant,
    reason: &'static str,
) -> Result<tokio::sync::OwnedSemaphorePermit, &'static str> {
    if lifecycle.draining() {
        return Err("shutdown");
    }
    let request_id = request_id.map_or(b"missing".as_slice(), HeaderValue::as_bytes);
    let delay = retry::retry_backoff(request_id, failed_attempt);
    if tokio::time::Instant::now()
        .checked_add(delay)
        .is_none_or(|after_backoff| after_backoff >= deadline)
    {
        return Err("request_timeout");
    }
    let Some(permit) = upstream.pool.retry_budget.try_acquire() else {
        ::metrics::counter!(
            crate::metrics::PROXY_RETRY_BUDGET_EXHAUSTED_TOTAL,
            "pool_id" => Arc::clone(&upstream.pool.id)
        )
        .increment(1);
        return Err("retry_budget_exhausted");
    };
    tokio::select! {
        () = tokio::time::sleep(delay) => {}
        () = lifecycle.background_cancellation().cancelled_owned() => return Err("shutdown"),
    }
    if lifecycle.draining() {
        return Err("shutdown");
    }
    if tokio::time::Instant::now() >= deadline {
        return Err("request_timeout");
    }
    ::metrics::counter!(
        crate::metrics::PROXY_UPSTREAM_RETRIES_TOTAL,
        "pool_id" => Arc::clone(&upstream.pool.id),
        "reason" => reason
    )
    .increment(1);
    Ok(permit)
}

fn proxy_error_category(error: &egress::EgressError) -> &'static str {
    if error.is_timeout() {
        "request_timeout"
    } else {
        error.safe_category()
    }
}

fn oauth_unauthorized_forbids_retry(status: StatusCode, authentication_kind: Option<&str>) -> bool {
    status == StatusCode::UNAUTHORIZED && authentication_kind == Some("oauth2_client_credentials")
}

fn circuit_failure_reason(error: &egress::EgressError) -> &'static str {
    if error.is_timeout() {
        "request_timeout"
    } else {
        "transport_failure"
    }
}

fn record_circuit_success(permit: &mut Option<super::circuit::CircuitPermit>) {
    if let Some(permit) = permit.take() {
        permit.success();
    }
}

fn record_circuit_failure(
    permit: &mut Option<super::circuit::CircuitPermit>,
    reason: &'static str,
) {
    if let Some(permit) = permit.take() {
        permit.failure(reason);
    }
}

fn record_attempt(
    pool_id: &Arc<str>,
    endpoint_id: &Arc<str>,
    result: &'static str,
    duration: Duration,
) {
    ::metrics::counter!(
        crate::metrics::PROXY_UPSTREAM_ATTEMPTS_TOTAL,
        "pool_id" => Arc::clone(pool_id),
        "endpoint_id" => Arc::clone(endpoint_id),
        "result" => result
    )
    .increment(1);
    ::metrics::histogram!(
        crate::metrics::PROXY_UPSTREAM_ATTEMPT_DURATION_SECONDS,
        "pool_id" => Arc::clone(pool_id),
        "endpoint_id" => Arc::clone(endpoint_id),
        "result" => result
    )
    .record(duration.as_secs_f64());
}

fn attempt_outcome(
    endpoint_id: &Arc<str>,
    result: &'static str,
    duration: Duration,
) -> middleware::decision::UpstreamAttemptOutcome {
    middleware::decision::UpstreamAttemptOutcome {
        endpoint_id: endpoint_id.to_string(),
        result: result.to_owned(),
        duration_ms: crate::duration_millis(duration),
    }
}

fn emit_retry_exhausted(
    proxy: &ProxyState,
    request_id: Option<&HeaderValue>,
    source_ip: &str,
    pool_id: &str,
    attempts: &[middleware::decision::UpstreamAttemptOutcome],
    reason: &'static str,
) {
    proxy.audit.emit(audit::AuditEvent::new(
        audit::event::UPSTREAM_RETRY_EXHAUSTED,
        request_id
            .and_then(|value| value.to_str().ok())
            .unwrap_or("unknown"),
        source_ip,
        None::<audit::Actor>,
        json!({
            "pool_id": pool_id,
            "reason": reason,
            "attempt_count": attempts.len(),
            "attempts": attempts
                .iter()
                .map(|attempt| json!({
                    "endpoint_id": attempt.endpoint_id,
                    "result": attempt.result,
                    "duration_ms": attempt.duration_ms,
                }))
                .collect::<Vec<_>>(),
        }),
    ));
}

fn redacted_response_body_inner(
    first_chunk: Option<bytes::Bytes>,
    upstream_body: egress::EgressBodyStream,
    admission_permit: super::admission::PoolAdmissionPermit,
    retry_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    deadline: Option<tokio::time::Instant>,
    passive_health: Option<(
        super::health::UpstreamHealthState,
        Arc<crate::config::UpstreamHealthCheckConfig>,
    )>,
    options: ResponseTailOptions,
) -> Body {
    let ResponseTailOptions {
        circuit_permit,
        pump_completed,
        telemetry,
        timeout_outcome,
        registration,
    } = options;
    let shutdown = telemetry
        .as_ref()
        .map_or_else(tokio_util::sync::CancellationToken::new, |telemetry| {
            telemetry.lifecycle.response_stream_cancellation()
        });
    let (demand_sender, demand_receiver) = tokio::sync::mpsc::channel(1);
    let (terminal_sender, terminal_receiver) =
        tokio::sync::watch::channel(ResponseTailTerminal::Active);
    let pump = pump_redacted_response_tail(ResponseTailPump {
        pending_chunk: first_chunk,
        upstream_body,
        demand_receiver,
        terminal_sender,
        admission_permit,
        retry_permit,
        deadline,
        passive_health,
        circuit_permit,
        telemetry,
        timeout_outcome,
        shutdown,
        registration,
        completion: ResponsePumpCompletion(pump_completed),
    });
    tokio::spawn(pump);
    let redacted_tail = stream::unfold(
        (demand_sender, terminal_receiver, false),
        |(demand_sender, terminal_receiver, done)| async move {
            if done {
                return None;
            }
            let terminal = *terminal_receiver.borrow();
            match terminal {
                ResponseTailTerminal::Active => {}
                ResponseTailTerminal::Error(category) => {
                    return Some((
                        Err(RedactedProxyBodyError(category)),
                        (demand_sender, terminal_receiver, true),
                    ));
                }
                ResponseTailTerminal::Eof => return None,
            }
            let (response_sender, response_receiver) = tokio::sync::oneshot::channel();
            if demand_sender
                .send(ResponseTailDemand {
                    response: response_sender,
                })
                .await
                .is_err()
            {
                let terminal = *terminal_receiver.borrow();
                return response_tail_terminal_item(terminal)
                    .map(|item| (item, (demand_sender, terminal_receiver, true)));
            }
            match response_receiver.await {
                Ok(ResponseTailEvent::Chunk(chunk)) => {
                    Some((Ok(chunk), (demand_sender, terminal_receiver, false)))
                }
                Ok(ResponseTailEvent::Error(category)) => Some((
                    Err(RedactedProxyBodyError(category)),
                    (demand_sender, terminal_receiver, true),
                )),
                Ok(ResponseTailEvent::Eof) => None,
                Err(_) => {
                    let terminal = *terminal_receiver.borrow();
                    response_tail_terminal_item(terminal)
                        .map(|item| (item, (demand_sender, terminal_receiver, true)))
                }
            }
        },
    );

    Body::from_stream(redacted_tail)
}

fn response_tail_terminal_item(
    terminal: ResponseTailTerminal,
) -> Option<Result<bytes::Bytes, RedactedProxyBodyError>> {
    match terminal {
        ResponseTailTerminal::Error(category) => Some(Err(RedactedProxyBodyError(category))),
        ResponseTailTerminal::Eof => None,
        ResponseTailTerminal::Active => Some(Err(RedactedProxyBodyError("response_body_failed"))),
    }
}

async fn pump_redacted_response_tail(pump: ResponseTailPump) {
    let ResponseTailPump {
        mut pending_chunk,
        mut upstream_body,
        mut demand_receiver,
        terminal_sender,
        admission_permit,
        retry_permit,
        deadline,
        passive_health,
        circuit_permit,
        mut telemetry,
        timeout_outcome,
        shutdown,
        registration: _registration,
        completion: _completion,
    } = pump;
    let mut admission_permit = Some(admission_permit);
    let mut retry_permit = retry_permit;
    let mut circuit_permit = circuit_permit;
    loop {
        let demand = tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                finish_response_shutdown(
                    upstream_body,
                    &terminal_sender,
                    &mut admission_permit,
                    &mut retry_permit,
                    &mut circuit_permit,
                    &mut telemetry,
                    None,
                );
                return;
            }
            _ = sleep_until_optional(deadline) => {
                finish_response_timeout(
                    upstream_body,
                    ResponseTimeoutContext {
                        terminal_sender: &terminal_sender,
                        admission_permit: &mut admission_permit,
                        retry_permit: &mut retry_permit,
                        passive_health: passive_health.as_ref(),
                        circuit_permit: &mut circuit_permit,
                        telemetry: &mut telemetry,
                        timeout_outcome,
                    },
                    false,
                ).await;
                return;
            }
            demand = demand_receiver.recv() => demand,
        };
        let Some(mut demand) = demand else {
            release_response_permits(&mut admission_permit, &mut retry_permit);
            drop(circuit_permit.take());
            drop(upstream_body);
            if let Some(telemetry) = telemetry.take() {
                telemetry.finish("client_cancelled");
            }
            return;
        };
        let (result, already_received) = if let Some(chunk) = pending_chunk.take() {
            (Some(Ok(chunk)), true)
        } else {
            let result = tokio::select! {
                biased;
                () = shutdown.cancelled() => {
                    finish_response_shutdown(
                        upstream_body,
                        &terminal_sender,
                        &mut admission_permit,
                        &mut retry_permit,
                        &mut circuit_permit,
                        &mut telemetry,
                        Some(demand.response),
                    );
                    return;
                }
                _ = sleep_until_optional(deadline) => {
                    finish_response_timeout(
                        upstream_body,
                        ResponseTimeoutContext {
                            terminal_sender: &terminal_sender,
                            admission_permit: &mut admission_permit,
                            retry_permit: &mut retry_permit,
                            passive_health: passive_health.as_ref(),
                            circuit_permit: &mut circuit_permit,
                            telemetry: &mut telemetry,
                            timeout_outcome,
                        },
                        true,
                    ).await;
                    return;
                }
                () = demand.response.closed() => continue,
                result = upstream_body.next() => result,
            };
            (result, false)
        };
        match result {
            Some(Ok(chunk)) => {
                if !already_received {
                    if let Some(telemetry) = telemetry.as_mut() {
                        telemetry.observe_received(&chunk);
                    }
                }
                let sent_chunk = chunk.clone();
                if demand
                    .response
                    .send(ResponseTailEvent::Chunk(chunk))
                    .is_ok()
                {
                    if let Some(telemetry) = telemetry.as_mut() {
                        telemetry.observe_sent(&sent_chunk);
                    }
                } else {
                    release_response_permits(&mut admission_permit, &mut retry_permit);
                    drop(circuit_permit.take());
                    drop(upstream_body);
                    if let Some(telemetry) = telemetry.take() {
                        telemetry.finish("client_cancelled");
                    }
                    return;
                }
            }
            Some(Err(error)) => {
                if let egress::EgressError::ResponseTooLarge { size, .. } = &error {
                    if let Some(telemetry) = telemetry.as_mut() {
                        telemetry.observe_received_total(*size);
                    }
                }
                let category = stream_body_error_category(&error);
                release_response_permits(&mut admission_permit, &mut retry_permit);
                if error.is_retryable_transport_failure() {
                    record_circuit_failure(&mut circuit_permit, circuit_failure_reason(&error));
                }
                drop(upstream_body);
                terminal_sender.send_replace(ResponseTailTerminal::Error(category));
                if let Some((health, config)) = passive_health.as_ref() {
                    health.record_passive_proxy_error(&error, config).await;
                }
                tracing::warn!(
                    error_category = category,
                    "proxied upstream response body failed after response commitment"
                );
                let _ = demand.response.send(ResponseTailEvent::Error(category));
                if let Some(telemetry) = telemetry.take() {
                    telemetry.finish(stream_error_outcome(&error));
                }
                return;
            }
            None => {
                release_response_permits(&mut admission_permit, &mut retry_permit);
                record_circuit_success(&mut circuit_permit);
                terminal_sender.send_replace(ResponseTailTerminal::Eof);
                let _ = demand.response.send(ResponseTailEvent::Eof);
                if let Some(telemetry) = telemetry.take() {
                    telemetry.finish("completed");
                }
                return;
            }
        }
    }
}

async fn sleep_until_optional(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending::<()>().await,
    }
}

fn stream_error_outcome(error: &egress::EgressError) -> &'static str {
    match error {
        egress::EgressError::ResponseTooLarge { .. } => "size_limit",
        egress::EgressError::ResponseIdleTimeout { .. } => "idle_timeout",
        _ => "upstream_error",
    }
}

fn stream_body_error_category(error: &egress::EgressError) -> &'static str {
    match error {
        egress::EgressError::ResponseTooLarge { .. } => "size_limit",
        egress::EgressError::ResponseIdleTimeout { .. } => "idle_timeout",
        _ => error.safe_category(),
    }
}

struct ResponseTimeoutContext<'a> {
    terminal_sender: &'a tokio::sync::watch::Sender<ResponseTailTerminal>,
    admission_permit: &'a mut Option<super::admission::PoolAdmissionPermit>,
    retry_permit: &'a mut Option<tokio::sync::OwnedSemaphorePermit>,
    passive_health: Option<&'a (
        super::health::UpstreamHealthState,
        Arc<crate::config::UpstreamHealthCheckConfig>,
    )>,
    circuit_permit: &'a mut Option<super::circuit::CircuitPermit>,
    telemetry: &'a mut Option<ResponseStreamTelemetry>,
    timeout_outcome: &'static str,
}

fn finish_response_shutdown(
    upstream_body: egress::EgressBodyStream,
    terminal_sender: &tokio::sync::watch::Sender<ResponseTailTerminal>,
    admission_permit: &mut Option<super::admission::PoolAdmissionPermit>,
    retry_permit: &mut Option<tokio::sync::OwnedSemaphorePermit>,
    circuit_permit: &mut Option<super::circuit::CircuitPermit>,
    telemetry: &mut Option<ResponseStreamTelemetry>,
    demand_response: Option<tokio::sync::oneshot::Sender<ResponseTailEvent>>,
) {
    release_response_permits(admission_permit, retry_permit);
    drop(circuit_permit.take());
    drop(upstream_body);
    terminal_sender.send_replace(ResponseTailTerminal::Error("shutdown"));
    if let Some(response) = demand_response {
        let _ = response.send(ResponseTailEvent::Error("shutdown"));
    }
    if let Some(telemetry) = telemetry.take() {
        telemetry.finish("shutdown");
    }
}

async fn finish_response_timeout(
    upstream_body: egress::EgressBodyStream,
    context: ResponseTimeoutContext<'_>,
    upstream_was_being_polled: bool,
) {
    release_response_permits(context.admission_permit, context.retry_permit);
    let upstream_timed_out =
        upstream_was_being_polled && context.timeout_outcome == "request_timeout";
    if upstream_timed_out {
        record_circuit_failure(context.circuit_permit, "request_timeout");
    } else {
        drop(context.circuit_permit.take());
    }
    drop(upstream_body);
    context
        .terminal_sender
        .send_replace(ResponseTailTerminal::Error(context.timeout_outcome));
    if upstream_timed_out {
        if let Some((health, config)) = context.passive_health {
            health.record_passive_timeout(config).await;
        }
    }
    tracing::warn!(
        error_category = context.timeout_outcome,
        "proxied upstream response body exceeded its stream deadline after response commitment"
    );
    if let Some(telemetry) = context.telemetry.take() {
        telemetry.finish(context.timeout_outcome);
    }
}

fn release_response_permits(
    admission_permit: &mut Option<super::admission::PoolAdmissionPermit>,
    retry_permit: &mut Option<tokio::sync::OwnedSemaphorePermit>,
) {
    drop(admission_permit.take());
    drop(retry_permit.take());
}

fn error_response_with_outcome(
    error: &egress::EgressError,
    latency: Duration,
    request_id: Option<HeaderValue>,
    pool_id: &str,
    endpoint_id: &str,
    attempts: Vec<middleware::decision::UpstreamAttemptOutcome>,
    retry_exhausted: bool,
) -> Response {
    let mut response = proxy_error_response(error);
    response
        .extensions_mut()
        .insert(middleware::decision::UpstreamOutcome {
            latency_ms: crate::duration_millis(latency),
            status: None,
            pool_id: Some(pool_id.to_owned()),
            endpoint_id: Some(endpoint_id.to_owned()),
            attempts,
            retry_exhausted,
            stream_terminal_pending: false,
        });
    if let Some(request_id) = request_id {
        response
            .headers_mut()
            .insert(request_id_header(), request_id);
    }
    response
}

fn connection_failure_response(
    error: ConnectionHttpError,
    pool_id: &str,
    request_id: Option<HeaderValue>,
    attempts: Vec<middleware::decision::UpstreamAttemptOutcome>,
    latency: Duration,
) -> Response {
    let status = match error {
        ConnectionHttpError::ConnectionDisabled
        | ConnectionHttpError::CredentialUnavailable
        | ConnectionHttpError::OAuthTokenUnavailable
        | ConnectionHttpError::TransportUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        ConnectionHttpError::InvalidConnectionId
        | ConnectionHttpError::ConnectionNotFound
        | ConnectionHttpError::WrongConnectionKind
        | ConnectionHttpError::UnsupportedAuthentication
        | ConnectionHttpError::UnsupportedTls
        | ConnectionHttpError::InvalidTargetPath
        | ConnectionHttpError::CredentialHeaderConflict
        | ConnectionHttpError::CredentialInvalid
        | ConnectionHttpError::OAuthTokenEgressDenied
        | ConnectionHttpError::OAuthTokenRejected
        | ConnectionHttpError::OAuthTokenInvalidResponse => StatusCode::BAD_GATEWAY,
    };
    let code = if status == StatusCode::SERVICE_UNAVAILABLE {
        "service_unavailable"
    } else {
        "bad_gateway"
    };
    tracing::warn!(
        pool_id,
        error_category = error.safe_reason(),
        "connection-bound proxied request failed closed"
    );
    let mut response = (status, Json(json!({ "error": code }))).into_response();
    response
        .extensions_mut()
        .insert(middleware::decision::UpstreamOutcome {
            latency_ms: crate::duration_millis(latency),
            status: None,
            pool_id: Some(pool_id.to_owned()),
            endpoint_id: None,
            attempts,
            retry_exhausted: false,
            stream_terminal_pending: false,
        });
    if let Some(request_id) = request_id {
        response
            .headers_mut()
            .insert(request_id_header(), request_id);
    }
    response
}

fn emit_connection_secret_resolution_failed(
    proxy: &ProxyState,
    parts: &http::request::Parts,
    source_ip: &str,
    route_id: &str,
    target: &ConnectionHttpTarget,
    reason: &'static str,
) {
    let request_id = parts
        .headers
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown");
    let actor = parts
        .extensions
        .get::<auth::Principal>()
        .map(auth::actor_from_principal);
    proxy.audit.emit(audit::AuditEvent::new(
        audit::event::CONNECTION_SECRET_RESOLUTION_FAILED,
        request_id,
        source_ip,
        actor,
        json!({
            "connection_id": target.connection_id(),
            "auth_type": target.authentication_kind(),
            "consumer_kind": "proxy_route",
            "consumer_id": route_id,
            "outcome": "failure",
            "reason": reason,
        }),
    ));
}

fn gateway_timeout_response(
    request_id: Option<HeaderValue>,
    pool_id: &str,
    endpoint_id: &str,
    attempts: Vec<middleware::decision::UpstreamAttemptOutcome>,
    retry_exhausted: bool,
    latency: Duration,
) -> Response {
    let mut response = (
        StatusCode::GATEWAY_TIMEOUT,
        Json(json!({ "error": "gateway_timeout" })),
    )
        .into_response();
    response
        .extensions_mut()
        .insert(middleware::decision::UpstreamOutcome {
            latency_ms: crate::duration_millis(latency),
            status: None,
            pool_id: Some(pool_id.to_owned()),
            endpoint_id: Some(endpoint_id.to_owned()),
            attempts,
            retry_exhausted,
            stream_terminal_pending: false,
        });
    if let Some(request_id) = request_id {
        response
            .headers_mut()
            .insert(request_id_header(), request_id);
    }
    response
}

fn admission_unavailable_response(pool_id: &str, request_id: Option<HeaderValue>) -> Response {
    unavailable_response_with_outcome(pool_id, request_id, Vec::new(), false, Duration::ZERO)
}

fn unavailable_response_with_outcome(
    pool_id: &str,
    request_id: Option<HeaderValue>,
    attempts: Vec<middleware::decision::UpstreamAttemptOutcome>,
    retry_exhausted: bool,
    latency: Duration,
) -> Response {
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "error": "service_unavailable" })),
    )
        .into_response();
    response
        .extensions_mut()
        .insert(middleware::decision::UpstreamOutcome {
            latency_ms: crate::duration_millis(latency),
            status: None,
            pool_id: Some(pool_id.to_owned()),
            endpoint_id: None,
            attempts,
            retry_exhausted,
            stream_terminal_pending: false,
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
    use std::{
        collections::{HashMap, HashSet},
        convert::Infallible,
        fs, io,
        net::SocketAddr,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    use axum::Router;
    use std::sync::Mutex;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;
    use crate::{
        audit::sink::tests::CaptureSink,
        config,
        proxy::{health, ProxyEndpoint, ProxyRoute, ProxyRoutes, RequestBodyMode, UpstreamPool},
    };

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
    fn connection_attempt_headers_strip_caller_credentials_before_route_transforms() {
        let mut inbound = HeaderMap::new();
        inbound.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer caller-token"),
        );
        inbound.insert(header::COOKIE, HeaderValue::from_static("session=caller"));
        inbound.insert("x-api-key", HeaderValue::from_static("caller-api-key"));
        inbound.insert("x-end-to-end", HeaderValue::from_static("caller-value"));
        let policy = RouteRequestHeaderPolicy {
            add_request_headers: vec![(
                HeaderName::from_static("x-route-label"),
                HeaderValue::from_static("billing"),
            )],
            strip_request_headers: vec![HeaderName::from_static("x-end-to-end")],
        };

        let forwarded = attempt_headers(
            &inbound,
            "203.0.113.8",
            &policy,
            Some(&HeaderName::from_static("x-api-key")),
        );

        assert!(!forwarded.contains_key(header::AUTHORIZATION));
        assert!(!forwarded.contains_key(header::COOKIE));
        assert!(!forwarded.contains_key("x-api-key"));
        assert!(!forwarded.contains_key("x-end-to-end"));
        assert_eq!(
            forwarded.get("x-route-label"),
            Some(&HeaderValue::from_static("billing"))
        );
    }

    #[test]
    fn oauth_unauthorized_response_never_enters_proxy_retry_path() {
        assert!(oauth_unauthorized_forbids_retry(
            StatusCode::UNAUTHORIZED,
            Some("oauth2_client_credentials")
        ));
        assert!(!oauth_unauthorized_forbids_retry(
            StatusCode::BAD_GATEWAY,
            Some("oauth2_client_credentials")
        ));
        assert!(!oauth_unauthorized_forbids_retry(
            StatusCode::UNAUTHORIZED,
            Some("static_bearer")
        ));
        assert!(!oauth_unauthorized_forbids_retry(
            StatusCode::UNAUTHORIZED,
            None
        ));
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
        let admission = super::super::admission::PoolAdmission::new(
            Arc::from("test"),
            1,
            0,
            std::time::Duration::from_millis(10),
        );
        let permit = admission.acquire().await.expect("test admission");
        let body = redacted_response_body_inner(
            Some(bytes::Bytes::from_static(b"first")),
            upstream_body,
            permit,
            None,
            Some(tokio::time::Instant::now() + Duration::from_secs(1)),
            None,
            ResponseTailOptions {
                circuit_permit: None,
                pump_completed: None,
                telemetry: None,
                timeout_outcome: "request_timeout",
                registration: None,
            },
        );
        let mut body = body.into_data_stream();
        assert!(matches!(
            admission.acquire().await,
            Err(super::super::admission::PoolAdmissionError::QueueFull)
        ));

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
        let released = admission
            .acquire()
            .await
            .expect("terminal response error should release admission immediately");
        drop(released);
        drop(body);
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

    #[tokio::test]
    async fn sse_commits_headers_before_first_event_and_reports_completion() {
        let (addr, server) = spawn_sse_upstream(SseTestBody::Chunks(vec![(
            Duration::from_millis(200),
            "data: ready\n\n",
        )]))
        .await;
        let (proxy, sink, _) = retry_proxy_with_options(
            [addr, addr],
            RetryProxyOptions {
                timeout: Duration::from_millis(75),
                response_idle_timeout: Some(Duration::from_millis(500)),
                sse: Some(config::UpstreamSseConfig {
                    max_duration_ms: 1_000,
                    max_response_bytes: None,
                }),
                ..RetryProxyOptions::default()
            },
        );
        let request = Request::builder()
            .uri("/")
            .header(REQUEST_ID_HEADER, "sse-early-headers")
            .body(Body::empty())
            .expect("SSE request");

        let response = tokio::time::timeout(
            Duration::from_millis(150),
            proxy.forward_request(request, "203.0.113.8"),
        )
        .await
        .expect("SSE headers must not wait for the first event");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE),
            Some(&HeaderValue::from_static("text/event-stream"))
        );
        let outcome = response
            .extensions()
            .get::<middleware::decision::UpstreamOutcome>()
            .expect("SSE upstream outcome");
        assert!(outcome.stream_terminal_pending);

        let mut body = response.into_body().into_data_stream();
        assert_eq!(
            body.next()
                .await
                .expect("SSE event")
                .expect("SSE event should be forwarded"),
            bytes::Bytes::from_static(b"data: ready\n\n")
        );
        assert!(body.next().await.is_none());

        let event = wait_for_stream_audit(&sink, "sse-early-headers").await;
        assert_eq!(event.payload["outcome"], json!("completed"));
        assert_eq!(event.payload["mode"], json!("sse"));
        assert_eq!(event.payload["bytes_received"], json!(13));
        assert_eq!(event.payload["bytes_sent"], json!(13));
        assert!(
            !event.payload.to_string().contains("data: ready"),
            "terminal audit must not contain SSE payloads"
        );
        server.abort();
    }

    #[tokio::test]
    async fn ordinary_stream_still_applies_precommit_first_byte_deadline() {
        let (addr, server) = spawn_sse_upstream(SseTestBody::Chunks(vec![(
            Duration::from_millis(200),
            "late",
        )]))
        .await;
        let (proxy, _, _) = retry_proxy_with_options(
            [addr, addr],
            RetryProxyOptions {
                timeout: Duration::from_millis(50),
                ..RetryProxyOptions::default()
            },
        );
        let request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .expect("ordinary request");

        let response = proxy.forward_request(request, "203.0.113.8").await;

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert!(
            !response
                .extensions()
                .get::<middleware::decision::UpstreamOutcome>()
                .expect("ordinary timeout outcome")
                .stream_terminal_pending
        );
        server.abort();
    }

    #[tokio::test]
    async fn sse_idle_size_and_duration_limits_report_distinct_terminal_outcomes() {
        let cases = [
            (
                "sse-idle",
                SseTestBody::Pending,
                Duration::from_millis(40),
                config::UpstreamSseConfig {
                    max_duration_ms: 500,
                    max_response_bytes: None,
                },
                "idle_timeout",
            ),
            (
                "sse-size",
                SseTestBody::Chunks(vec![(Duration::ZERO, "123456")]),
                Duration::from_millis(500),
                config::UpstreamSseConfig {
                    max_duration_ms: 500,
                    max_response_bytes: Some(5),
                },
                "size_limit",
            ),
            (
                "sse-duration",
                SseTestBody::Pending,
                Duration::from_millis(500),
                config::UpstreamSseConfig {
                    max_duration_ms: 40,
                    max_response_bytes: None,
                },
                "duration_limit",
            ),
        ];

        for (request_id, plan, idle_timeout, sse, expected) in cases {
            let (addr, server) = spawn_sse_upstream(plan).await;
            let (proxy, sink, _) = retry_proxy_with_options(
                [addr, addr],
                RetryProxyOptions {
                    timeout: Duration::from_millis(100),
                    response_idle_timeout: Some(idle_timeout),
                    sse: Some(sse),
                    ..RetryProxyOptions::default()
                },
            );
            let request = Request::builder()
                .uri("/")
                .header(REQUEST_ID_HEADER, request_id)
                .body(Body::empty())
                .expect("limited SSE request");
            let response = proxy.forward_request(request, "203.0.113.8").await;
            assert_eq!(response.status(), StatusCode::OK);
            let mut body = response.into_body().into_data_stream();
            let error = body
                .next()
                .await
                .expect("limited SSE should terminate with a body error")
                .expect_err("limited SSE should return a redacted body error");
            assert!(
                error.to_string().contains(expected)
                    || (expected == "idle_timeout"
                        && error.to_string().contains("response_idle_timeout"))
                    || (expected == "size_limit"
                        && error.to_string().contains("response_too_large")),
                "unexpected {request_id} error: {error}"
            );
            let event = wait_for_stream_audit(&sink, request_id).await;
            assert_eq!(event.payload["outcome"], json!(expected));
            if expected == "size_limit" {
                assert_eq!(event.payload["bytes_received"], json!(6));
                assert!(
                    !event.payload["time_to_first_byte_ms"].is_null(),
                    "an over-limit first chunk still establishes time to first byte"
                );
            }
            server.abort();
        }
    }

    #[tokio::test]
    async fn sse_circuit_permit_stays_pending_until_stream_completion() {
        let (addr, server) = spawn_sse_upstream(SseTestBody::Pending).await;
        let (proxy, sink, _) = retry_proxy_with_options(
            [addr, addr],
            RetryProxyOptions {
                timeout: Duration::from_millis(100),
                response_idle_timeout: Some(Duration::from_millis(30)),
                sse: Some(config::UpstreamSseConfig {
                    max_duration_ms: 1_000,
                    max_response_bytes: None,
                }),
                circuit_config: Some(config::UpstreamCircuitBreakerConfig {
                    failure_threshold: 1,
                    open_ms: 30,
                    half_open_max_requests: 1,
                    recovery_threshold: 1,
                }),
                ..RetryProxyOptions::default()
            },
        );
        let pool = test_pool(&proxy);
        let circuit = pool.endpoints[0].circuit.clone().expect("test circuit");

        let first = Request::builder()
            .uri("/")
            .header(REQUEST_ID_HEADER, "sse-circuit-open")
            .body(Body::empty())
            .expect("first SSE request");
        let first = proxy.forward_request(first, "203.0.113.8").await;
        let first_error = first
            .into_body()
            .into_data_stream()
            .next()
            .await
            .expect("idle stream error")
            .expect_err("idle stream should fail");
        assert!(first_error.to_string().contains("idle_timeout"));
        assert_eq!(
            wait_for_stream_audit(&sink, "sse-circuit-open")
                .await
                .payload["outcome"],
            json!("idle_timeout")
        );
        assert!(
            circuit.try_acquire().is_none(),
            "late SSE idle failure must open the endpoint circuit"
        );

        tokio::time::sleep(Duration::from_millis(40)).await;
        pool.next_selection.store(0, Ordering::Relaxed);
        let half_open = Request::builder()
            .uri("/")
            .header(REQUEST_ID_HEADER, "sse-circuit-half-open")
            .body(Body::empty())
            .expect("half-open SSE request");
        let half_open = proxy.forward_request(half_open, "203.0.113.8").await;
        assert_eq!(half_open.status(), StatusCode::OK);
        assert!(
            circuit.try_acquire().is_none(),
            "receiving SSE headers must not recover or release a half-open permit"
        );
        let half_open_error = half_open
            .into_body()
            .into_data_stream()
            .next()
            .await
            .expect("half-open idle stream error")
            .expect_err("half-open idle stream should fail");
        assert!(half_open_error.to_string().contains("idle_timeout"));
        assert!(
            circuit.try_acquire().is_none(),
            "late half-open SSE failure must reopen the circuit"
        );
        server.abort();
    }

    #[tokio::test]
    async fn sse_duration_limit_is_neutral_to_health_and_circuit_state() {
        let (addr, server) = spawn_sse_upstream(SseTestBody::Pending).await;
        let (proxy, sink, health_states) = retry_proxy_with_options(
            [addr, addr],
            RetryProxyOptions {
                timeout: Duration::from_millis(100),
                response_idle_timeout: Some(Duration::from_millis(500)),
                sse: Some(config::UpstreamSseConfig {
                    max_duration_ms: 30,
                    max_response_bytes: None,
                }),
                health_config: Some(passive_health_config()),
                circuit_config: Some(config::UpstreamCircuitBreakerConfig {
                    failure_threshold: 1,
                    open_ms: 60_000,
                    half_open_max_requests: 1,
                    recovery_threshold: 1,
                }),
                ..RetryProxyOptions::default()
            },
        );
        let pool = test_pool(&proxy);
        let circuit = pool.endpoints[0].circuit.clone().expect("test circuit");
        let request = Request::builder()
            .uri("/")
            .header(REQUEST_ID_HEADER, "sse-duration-neutral")
            .body(Body::empty())
            .expect("duration-limited SSE request");

        let response = proxy.forward_request(request, "203.0.113.8").await;
        let error = response
            .into_body()
            .into_data_stream()
            .next()
            .await
            .expect("duration stream error")
            .expect_err("duration-limited stream should fail");
        assert!(error.to_string().contains("duration_limit"));
        assert_eq!(
            wait_for_stream_audit(&sink, "sse-duration-neutral")
                .await
                .payload["outcome"],
            json!("duration_limit")
        );
        assert!(
            health_states[0].eligible(),
            "an intentional stream duration cap must not evict a healthy endpoint"
        );
        let neutral_permit = circuit
            .try_acquire()
            .expect("an intentional duration cap must not open the circuit");
        drop(neutral_permit);
        server.abort();
    }

    #[tokio::test]
    async fn sse_keepalives_reset_idle_timeout_and_cancellation_outcomes_are_explicit() {
        let (keepalive_addr, keepalive_server) = spawn_sse_upstream(SseTestBody::Chunks(vec![
            (Duration::from_millis(100), ":\n\n"),
            (Duration::from_millis(100), ":\n\n"),
            (Duration::from_millis(100), ":\n\n"),
            (Duration::from_millis(100), ":\n\n"),
            (Duration::from_millis(100), ":\n\n"),
            (Duration::from_millis(100), "data: done\n\n"),
        ]))
        .await;
        let (keepalive_proxy, keepalive_sink, _) = retry_proxy_with_options(
            [keepalive_addr, keepalive_addr],
            RetryProxyOptions {
                timeout: Duration::from_millis(100),
                response_idle_timeout: Some(Duration::from_millis(500)),
                sse: Some(config::UpstreamSseConfig {
                    max_duration_ms: 1_500,
                    max_response_bytes: None,
                }),
                ..RetryProxyOptions::default()
            },
        );
        let keepalive_request = Request::builder()
            .uri("/")
            .header(REQUEST_ID_HEADER, "sse-keepalive")
            .body(Body::empty())
            .expect("keepalive request");
        let keepalive_response = keepalive_proxy
            .forward_request(keepalive_request, "203.0.113.8")
            .await;
        let body = axum::body::to_bytes(keepalive_response.into_body(), 1024)
            .await
            .expect("keepalive SSE body");
        assert_eq!(
            body,
            bytes::Bytes::from_static(b":\n\n:\n\n:\n\n:\n\n:\n\ndata: done\n\n")
        );
        let keepalive_event = wait_for_stream_audit(&keepalive_sink, "sse-keepalive").await;
        assert_eq!(keepalive_event.payload["outcome"], json!("completed"));
        keepalive_server.abort();

        let (pending_addr, pending_server) = spawn_sse_upstream(SseTestBody::Pending).await;
        let (pending_proxy, pending_sink, _) = retry_proxy_with_options(
            [pending_addr, pending_addr],
            RetryProxyOptions {
                timeout: Duration::from_millis(100),
                response_idle_timeout: Some(Duration::from_secs(1)),
                sse: Some(config::UpstreamSseConfig {
                    max_duration_ms: 1_000,
                    max_response_bytes: None,
                }),
                limits: config::UpstreamPoolLimitsConfig {
                    max_in_flight: 1,
                    queue_depth: 0,
                    queue_timeout_ms: 10,
                },
                ..RetryProxyOptions::default()
            },
        );
        let pool = test_pool(&pending_proxy);
        let pending_request = Request::builder()
            .uri("/")
            .header(REQUEST_ID_HEADER, "sse-client-cancelled")
            .body(Body::empty())
            .expect("pending SSE request");
        let pending_response = pending_proxy
            .forward_request(pending_request, "203.0.113.8")
            .await;
        drop(pending_response);
        let released = tokio::time::timeout(Duration::from_millis(200), async {
            loop {
                if let Ok(permit) = pool.admission.acquire().await {
                    return permit;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping the SSE body must promptly release admission");
        drop(released);
        let pending_event = wait_for_stream_audit(&pending_sink, "sse-client-cancelled").await;
        assert_eq!(pending_event.payload["outcome"], json!("client_cancelled"));

        let shutdown_request = Request::builder()
            .uri("/")
            .header(REQUEST_ID_HEADER, "sse-shutdown")
            .body(Body::empty())
            .expect("shutdown SSE request");
        let shutdown_response = pending_proxy
            .forward_request(shutdown_request, "203.0.113.8")
            .await;
        assert!(pending_proxy.lifecycle.begin_draining());
        drop(shutdown_response);
        let shutdown_event = wait_for_stream_audit(&pending_sink, "sse-shutdown").await;
        assert_eq!(
            shutdown_event.payload["outcome"],
            json!("client_cancelled"),
            "an independent disconnect during graceful drain is not a forced shutdown"
        );

        let (forced_proxy, forced_sink, _) = retry_proxy_with_options(
            [pending_addr, pending_addr],
            RetryProxyOptions {
                timeout: Duration::from_millis(100),
                response_idle_timeout: Some(Duration::from_secs(1)),
                sse: Some(config::UpstreamSseConfig {
                    max_duration_ms: 1_000,
                    max_response_bytes: None,
                }),
                ..RetryProxyOptions::default()
            },
        );
        let forced_request = Request::builder()
            .uri("/")
            .header(REQUEST_ID_HEADER, "sse-forced-shutdown")
            .body(Body::empty())
            .expect("forced shutdown SSE request");
        let forced_response = forced_proxy
            .forward_request(forced_request, "203.0.113.8")
            .await;
        assert!(forced_proxy.lifecycle.begin_draining());
        forced_proxy
            .lifecycle
            .force_shutdown_response_streams()
            .await;
        let forced_event = wait_for_stream_audit(&forced_sink, "sse-forced-shutdown").await;
        assert_eq!(forced_event.payload["outcome"], json!("shutdown"));
        drop(forced_response);
        pending_server.abort();
    }

    #[tokio::test]
    async fn forced_shutdown_cancels_registered_sse_request_before_headers() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("delayed SSE listener");
        let addr = listener.local_addr().expect("delayed SSE address");
        let (started_sender, started_receiver) = tokio::sync::oneshot::channel();
        let started_sender = Arc::new(Mutex::new(Some(started_sender)));
        let app = Router::new().fallback(move || {
            let started_sender = Arc::clone(&started_sender);
            async move {
                if let Some(started_sender) = started_sender.lock().expect("start sender").take() {
                    let _ = started_sender.send(());
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "text/event-stream")
                    .body(Body::empty())
                    .expect("delayed SSE response")
            }
        });
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("delayed SSE upstream");
        });
        let (proxy, sink, _) = retry_proxy_with_options(
            [addr, addr],
            RetryProxyOptions {
                timeout: Duration::from_secs(10),
                response_idle_timeout: Some(Duration::from_secs(10)),
                sse: Some(config::UpstreamSseConfig {
                    max_duration_ms: 1_000,
                    max_response_bytes: None,
                }),
                ..RetryProxyOptions::default()
            },
        );
        let lifecycle = proxy.lifecycle.clone();
        let request = Request::builder()
            .uri("/")
            .header(REQUEST_ID_HEADER, "sse-preheader-shutdown")
            .body(Body::empty())
            .expect("pre-header SSE request");
        let request_task =
            tokio::spawn(async move { proxy.forward_request(request, "203.0.113.8").await });
        started_receiver
            .await
            .expect("upstream request should start before forced shutdown");

        assert!(lifecycle.begin_draining());
        tokio::time::timeout(
            Duration::from_millis(250),
            lifecycle.force_shutdown_response_streams(),
        )
        .await
        .expect("forced shutdown must cancel and await a pre-header request");
        let response = request_task.await.expect("pre-header request task");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            lifecycle.try_register_response_stream().is_none(),
            "draining permanently closes late response-stream registration"
        );
        assert!(
            sink.events()
                .iter()
                .all(|event| event.event_type != audit::event::UPSTREAM_STREAM_TERMINATED),
            "a response cancelled before commitment must not create a late terminal stream event"
        );
        server.abort();
    }

    #[tokio::test]
    async fn unpolled_response_deadline_terminates_pump_without_queuing_tail_data() {
        let upstream_body: egress::EgressBodyStream =
            Box::pin(stream::pending::<Result<bytes::Bytes, egress::EgressError>>());
        let admission = super::super::admission::PoolAdmission::new(
            Arc::from("test"),
            1,
            0,
            Duration::from_millis(10),
        );
        let admission_permit = admission.acquire().await.expect("test admission");
        let retry_budget = super::super::retry::RetryBudget::new(1);
        let retry_permit = retry_budget.try_acquire().expect("test retry budget");
        let circuit = super::super::circuit::CircuitBreaker::new(
            Arc::from("test"),
            Arc::from("primary"),
            config::UpstreamCircuitBreakerConfig {
                failure_threshold: 1,
                open_ms: 60_000,
                half_open_max_requests: 1,
                recovery_threshold: 1,
            },
            None,
            None,
        );
        let circuit_permit = circuit.try_acquire().expect("closed circuit permit");
        let (completed_sender, completed_receiver) = tokio::sync::oneshot::channel();
        let body = redacted_response_body_inner(
            Some(bytes::Bytes::from_static(b"first")),
            upstream_body,
            admission_permit,
            Some(retry_permit),
            Some(tokio::time::Instant::now() + Duration::from_millis(50)),
            None,
            ResponseTailOptions {
                circuit_permit: Some(circuit_permit),
                pump_completed: Some(completed_sender),
                telemetry: None,
                timeout_outcome: "request_timeout",
                registration: None,
            },
        );

        tokio::time::timeout(Duration::from_millis(200), completed_receiver)
            .await
            .expect("deadline should terminate the pump while the body remains open")
            .expect("completion observer should remain connected");
        let released_admission = admission
            .acquire()
            .await
            .expect("terminated pump should release admission");
        let released_retry = retry_budget
            .try_acquire()
            .expect("terminated pump should release retry budget");
        let neutral_circuit_permit = circuit
            .try_acquire()
            .expect("downstream no-demand timeout must not open the upstream circuit");
        drop(released_admission);
        drop(released_retry);
        drop(neutral_circuit_permit);
        drop(body);
    }

    #[tokio::test]
    async fn retryable_status_uses_alternate_endpoint_and_replays_buffered_body() {
        let first_requests = Arc::new(Mutex::new(Vec::new()));
        let second_requests = Arc::new(Mutex::new(Vec::new()));
        let (first_addr, first_server) =
            spawn_status_upstream(StatusCode::SERVICE_UNAVAILABLE, Arc::clone(&first_requests))
                .await;
        let (second_addr, second_server) =
            spawn_status_upstream(StatusCode::OK, Arc::clone(&second_requests)).await;
        let (proxy, _) = retry_proxy(
            [first_addr, second_addr],
            Some(config::UpstreamRetryConfig {
                max_attempts: 3,
                methods: vec!["GET".to_owned()],
                statuses: vec![503],
            }),
            Duration::from_secs(2),
        );
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/items")
            .header(REQUEST_ID_HEADER, "request-stable")
            .body(Body::from("bounded-body"))
            .expect("request");

        let response = proxy.forward_request(request, "203.0.113.8").await;
        let outcome = response
            .extensions()
            .get::<middleware::decision::UpstreamOutcome>()
            .expect("upstream outcome")
            .clone();
        let status = response.status();
        let response_body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("response body");

        assert_eq!(status, StatusCode::OK);
        assert_eq!(response_body, "upstream");
        assert_eq!(outcome.endpoint_id.as_deref(), Some("b"));
        assert_eq!(outcome.attempts.len(), 2);
        assert_eq!(outcome.attempts[0].endpoint_id, "a");
        assert_eq!(outcome.attempts[0].result, "retryable_status");
        assert_eq!(outcome.attempts[1].endpoint_id, "b");
        assert_eq!(outcome.attempts[1].result, "response");
        assert!(!outcome.retry_exhausted);
        assert_eq!(
            first_requests.lock().expect("first captures").as_slice(),
            &[CapturedRequest {
                request_id: Some("request-stable".to_owned()),
                body: b"bounded-body".to_vec(),
            }]
        );
        assert_eq!(
            second_requests.lock().expect("second captures").as_slice(),
            &[CapturedRequest {
                request_id: Some("request-stable".to_owned()),
                body: b"bounded-body".to_vec(),
            }]
        );

        first_server.abort();
        second_server.abort();
    }

    #[tokio::test]
    async fn all_open_pool_fails_fast_without_an_extra_attempt() {
        let first_requests = Arc::new(Mutex::new(Vec::new()));
        let second_requests = Arc::new(Mutex::new(Vec::new()));
        let (first_addr, first_server) =
            spawn_status_upstream(StatusCode::SERVICE_UNAVAILABLE, Arc::clone(&first_requests))
                .await;
        let (second_addr, second_server) = spawn_status_upstream(
            StatusCode::SERVICE_UNAVAILABLE,
            Arc::clone(&second_requests),
        )
        .await;
        let (proxy, audit_sink, _) = retry_proxy_with_options(
            [first_addr, second_addr],
            RetryProxyOptions {
                retry: Some(config::UpstreamRetryConfig {
                    max_attempts: 1,
                    methods: vec!["GET".to_owned()],
                    statuses: vec![503],
                }),
                circuit_config: Some(config::UpstreamCircuitBreakerConfig {
                    failure_threshold: 1,
                    open_ms: 60_000,
                    half_open_max_requests: 1,
                    recovery_threshold: 1,
                }),
                ..RetryProxyOptions::default()
            },
        );

        for request_id in ["open-a", "open-b"] {
            let response = proxy
                .forward_request(
                    Request::builder()
                        .method(http::Method::GET)
                        .uri("/items")
                        .header(REQUEST_ID_HEADER, request_id)
                        .body(Body::empty())
                        .expect("request"),
                    "203.0.113.8",
                )
                .await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            axum::body::to_bytes(response.into_body(), 1024)
                .await
                .expect("bounded response body");
        }

        let response = proxy
            .forward_request(
                Request::builder()
                    .method(http::Method::GET)
                    .uri("/items")
                    .header(REQUEST_ID_HEADER, "all-open")
                    .body(Body::empty())
                    .expect("request"),
                "203.0.113.8",
            )
            .await;
        let outcome = response
            .extensions()
            .get::<middleware::decision::UpstreamOutcome>()
            .expect("upstream outcome");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(outcome.attempts.is_empty());
        assert_eq!(first_requests.lock().expect("first captures").len(), 1);
        assert_eq!(second_requests.lock().expect("second captures").len(), 1);
        let transitions = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let transitions = audit_sink
                    .events()
                    .into_iter()
                    .filter(|event| {
                        event.event_type == audit::event::UPSTREAM_CIRCUIT_STATE_CHANGED
                    })
                    .collect::<Vec<_>>();
                if transitions.len() >= 2 {
                    return transitions;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("circuit transition audits should be emitted");
        assert_eq!(transitions.len(), 2);
        assert!(transitions.iter().all(|event| {
            event.payload["state"] == "open"
                && event.payload["from"] == "closed"
                && event.payload["reason"] == "retryable_status"
                && event.payload.get("url").is_none()
        }));

        first_server.abort();
        second_server.abort();
    }

    #[tokio::test]
    async fn retryable_connect_failure_prefers_a_different_endpoint() {
        let unavailable_listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("temporary listener");
        let unavailable_addr = unavailable_listener
            .local_addr()
            .expect("temporary listener address");
        drop(unavailable_listener);
        let second_requests = Arc::new(Mutex::new(Vec::new()));
        let (second_addr, second_server) =
            spawn_status_upstream(StatusCode::OK, Arc::clone(&second_requests)).await;
        let (proxy, _) = retry_proxy(
            [unavailable_addr, second_addr],
            Some(config::UpstreamRetryConfig {
                max_attempts: 2,
                methods: vec!["GET".to_owned()],
                statuses: vec![503],
            }),
            Duration::from_secs(2),
        );
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/items")
            .header(REQUEST_ID_HEADER, "connect-failover")
            .body(Body::empty())
            .expect("request");

        let response = proxy.forward_request(request, "203.0.113.8").await;
        let outcome = response
            .extensions()
            .get::<middleware::decision::UpstreamOutcome>()
            .expect("upstream outcome");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(outcome.attempts.len(), 2);
        assert_eq!(outcome.attempts[0].endpoint_id, "a");
        assert!(matches!(
            outcome.attempts[0].result.as_str(),
            "http_connect" | "request_timeout"
        ));
        assert_eq!(outcome.attempts[1].endpoint_id, "b");
        assert_eq!(second_requests.lock().expect("second captures").len(), 1);

        second_server.abort();
    }

    #[tokio::test]
    async fn tls_certificate_and_hostname_failures_are_never_retried() {
        for case in [
            TlsValidationCase::UntrustedCertificate,
            TlsValidationCase::WrongHostname,
        ] {
            let certificate_name = match case {
                TlsValidationCase::UntrustedCertificate => "127.0.0.1",
                TlsValidationCase::WrongHostname => "wrong-host.test",
            };
            let tls_upstream = spawn_test_tls_upstream(certificate_name).await;
            let alternate_requests = Arc::new(Mutex::new(Vec::new()));
            let (alternate_addr, alternate_server) =
                spawn_status_upstream(StatusCode::OK, Arc::clone(&alternate_requests)).await;
            let mut egress_config = egress::EgressConfig {
                allowed_hosts: HashSet::from(["127.0.0.1".to_owned()]),
                timeout: Duration::from_secs(1),
                connect_timeout: Duration::from_millis(500),
                response_idle_timeout: Duration::from_secs(1),
                deny_private_ips: false,
                ..egress::EgressConfig::default()
            };
            let ca_path = if case == TlsValidationCase::WrongHostname {
                let path = std::env::temp_dir().join(format!(
                    "greengateway-retry-test-ca-{}.pem",
                    uuid::Uuid::new_v4()
                ));
                fs::write(&path, tls_upstream.ca_pem.as_bytes())
                    .expect("test CA bundle should be written");
                egress_config
                    .apply_tls_ca_bundle_path(path.clone())
                    .expect("test CA bundle should load");
                Some(path)
            } else {
                None
            };
            let client = Arc::new(
                egress::EgressClient::new(egress_config)
                    .expect("TLS retry test client should build"),
            );
            let (proxy, _, _) = retry_proxy_with_endpoints(
                [
                    (
                        format!("https://127.0.0.1:{}", tls_upstream.addr.port()),
                        Arc::clone(&client),
                    ),
                    (format!("http://{alternate_addr}"), client),
                ],
                RetryProxyOptions {
                    retry: Some(config::UpstreamRetryConfig {
                        max_attempts: 3,
                        methods: vec!["GET".to_owned()],
                        statuses: vec![502, 503, 504],
                    }),
                    timeout: Duration::from_secs(1),
                    ..RetryProxyOptions::default()
                },
            );
            let request = Request::builder()
                .method(http::Method::GET)
                .uri("/items")
                .header(REQUEST_ID_HEADER, format!("tls-{case:?}"))
                .body(Body::empty())
                .expect("request");

            let response = proxy.forward_request(request, "203.0.113.8").await;
            let outcome = response
                .extensions()
                .get::<middleware::decision::UpstreamOutcome>()
                .expect("TLS outcome");

            assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            assert_eq!(outcome.attempts.len(), 1);
            assert_eq!(outcome.attempts[0].endpoint_id, "a");
            assert!(
                alternate_requests
                    .lock()
                    .expect("alternate captures")
                    .is_empty(),
                "TLS validation failure must not reach an alternate endpoint"
            );
            assert_eq!(tls_upstream.connections.load(Ordering::SeqCst), 1);

            tls_upstream
                .task
                .await
                .expect("TLS test upstream should terminate");
            alternate_server.abort();
            if let Some(path) = ca_path {
                fs::remove_file(path).expect("test CA bundle should be removed");
            }
        }
    }

    #[tokio::test]
    async fn retry_attempt_revalidates_dns_and_dns_failure_stops_retrying() {
        let first_requests = Arc::new(Mutex::new(Vec::new()));
        let alternate_requests = Arc::new(Mutex::new(Vec::new()));
        let (first_addr, first_server) =
            spawn_status_upstream(StatusCode::SERVICE_UNAVAILABLE, Arc::clone(&first_requests))
                .await;
        let (alternate_addr, alternate_server) =
            spawn_status_upstream(StatusCode::OK, Arc::clone(&alternate_requests)).await;
        let resolver = Arc::new(RetryDnsResolver {
            first_addr,
            alternate_calls: AtomicUsize::new(0),
        });
        let egress_config = egress::EgressConfig {
            allowed_hosts: HashSet::from([
                "retry-a.example.test".to_owned(),
                "retry-b.example.test".to_owned(),
            ]),
            timeout: Duration::from_secs(1),
            connect_timeout: Duration::from_millis(250),
            response_idle_timeout: Duration::from_secs(1),
            deny_private_ips: false,
            ..egress::EgressConfig::default()
        };
        let client = Arc::new(
            egress::EgressClient::new_with_resolver(egress_config, resolver.clone())
                .expect("DNS retry test client should build"),
        );
        let (proxy, _, _) = retry_proxy_with_endpoints(
            [
                (
                    format!("http://retry-a.example.test:{}", first_addr.port()),
                    Arc::clone(&client),
                ),
                (
                    format!("http://retry-b.example.test:{}", alternate_addr.port()),
                    client,
                ),
            ],
            RetryProxyOptions {
                retry: Some(config::UpstreamRetryConfig {
                    max_attempts: 3,
                    methods: vec!["GET".to_owned()],
                    statuses: vec![503],
                }),
                timeout: Duration::from_secs(1),
                ..RetryProxyOptions::default()
            },
        );
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/items")
            .header(REQUEST_ID_HEADER, "dns-revalidation")
            .body(Body::empty())
            .expect("request");

        let response = proxy.forward_request(request, "203.0.113.8").await;
        let outcome = response
            .extensions()
            .get::<middleware::decision::UpstreamOutcome>()
            .expect("DNS outcome");

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(outcome.attempts.len(), 2);
        assert_eq!(outcome.attempts[0].result, "retryable_status");
        assert_eq!(outcome.attempts[1].endpoint_id, "b");
        assert_eq!(outcome.attempts[1].result, "dns_resolution_failed");
        assert_eq!(first_requests.lock().expect("first captures").len(), 1);
        assert!(alternate_requests
            .lock()
            .expect("alternate captures")
            .is_empty());
        assert_eq!(resolver.alternate_calls.load(Ordering::SeqCst), 1);

        first_server.abort();
        alternate_server.abort();
    }

    #[tokio::test]
    async fn unconfigured_method_and_default_policy_make_exactly_one_attempt() {
        let first_requests = Arc::new(Mutex::new(Vec::new()));
        let second_requests = Arc::new(Mutex::new(Vec::new()));
        let (first_addr, first_server) =
            spawn_status_upstream(StatusCode::SERVICE_UNAVAILABLE, Arc::clone(&first_requests))
                .await;
        let (second_addr, second_server) =
            spawn_status_upstream(StatusCode::OK, Arc::clone(&second_requests)).await;
        let (proxy, _) = retry_proxy(
            [first_addr, second_addr],
            Some(config::UpstreamRetryConfig {
                max_attempts: 3,
                methods: vec!["GET".to_owned()],
                statuses: vec![503],
            }),
            Duration::from_secs(2),
        );
        let post = Request::builder()
            .method(http::Method::POST)
            .uri("/items")
            .header(REQUEST_ID_HEADER, "post-once")
            .body(Body::from("write"))
            .expect("request");

        let response = proxy.forward_request(post, "203.0.113.8").await;
        let outcome = response
            .extensions()
            .get::<middleware::decision::UpstreamOutcome>()
            .expect("upstream outcome");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(outcome.attempts.len(), 1);
        assert!(!outcome.retry_exhausted);
        assert_eq!(first_requests.lock().expect("first captures").len(), 1);
        assert!(second_requests.lock().expect("second captures").is_empty());

        let (default_proxy, _) =
            retry_proxy([first_addr, second_addr], None, Duration::from_secs(2));
        let get = Request::builder()
            .method(http::Method::GET)
            .uri("/items")
            .header(REQUEST_ID_HEADER, "default-once")
            .body(Body::empty())
            .expect("request");
        let default_response = default_proxy.forward_request(get, "203.0.113.8").await;
        let default_outcome = default_response
            .extensions()
            .get::<middleware::decision::UpstreamOutcome>()
            .expect("upstream outcome");

        assert_eq!(default_response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(default_outcome.attempts.len(), 1);
        assert!(!default_outcome.retry_exhausted);
        assert_eq!(first_requests.lock().expect("first captures").len(), 2);
        assert!(second_requests.lock().expect("second captures").is_empty());

        first_server.abort();
        second_server.abort();
    }

    #[tokio::test]
    async fn exhausted_retries_are_exact_and_emit_bounded_audit_summary() {
        let first_requests = Arc::new(Mutex::new(Vec::new()));
        let second_requests = Arc::new(Mutex::new(Vec::new()));
        let (first_addr, first_server) =
            spawn_status_upstream(StatusCode::BAD_GATEWAY, Arc::clone(&first_requests)).await;
        let (second_addr, second_server) =
            spawn_status_upstream(StatusCode::BAD_GATEWAY, Arc::clone(&second_requests)).await;
        let (proxy, audit_sink) = retry_proxy(
            [first_addr, second_addr],
            Some(config::UpstreamRetryConfig {
                max_attempts: 3,
                methods: vec!["GET".to_owned()],
                statuses: vec![502],
            }),
            Duration::from_secs(2),
        );
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/items?secret=not-audited")
            .header(REQUEST_ID_HEADER, "exhausted-request")
            .body(Body::empty())
            .expect("request");

        let response = proxy.forward_request(request, "203.0.113.8").await;
        let outcome = response
            .extensions()
            .get::<middleware::decision::UpstreamOutcome>()
            .expect("upstream outcome");

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(outcome.attempts.len(), 3);
        assert_eq!(
            outcome
                .attempts
                .iter()
                .map(|attempt| attempt.endpoint_id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b", "a"]
        );
        assert!(outcome.retry_exhausted);
        assert_eq!(first_requests.lock().expect("first captures").len(), 2);
        assert_eq!(second_requests.lock().expect("second captures").len(), 1);

        let event = wait_for_retry_audit(&audit_sink).await;
        assert_eq!(event.request_id, "exhausted-request");
        assert_eq!(event.payload["pool_id"], "payments");
        assert_eq!(event.payload["reason"], "max_attempts");
        assert_eq!(event.payload["attempt_count"], 3);
        let serialized = serde_json::to_string(&event).expect("audit serialization");
        for secret in ["not-audited", "127.0.0.1", "http://"] {
            assert!(
                !serialized.contains(secret),
                "retry audit leaked {secret}: {serialized}"
            );
        }

        first_server.abort();
        second_server.abort();
    }

    #[tokio::test]
    async fn total_deadline_bounds_attempts() {
        let first_requests = Arc::new(Mutex::new(Vec::new()));
        let second_requests = Arc::new(Mutex::new(Vec::new()));
        let (first_addr, first_server) = spawn_status_upstream_after(
            StatusCode::SERVICE_UNAVAILABLE,
            Arc::clone(&first_requests),
            Duration::from_millis(500),
        )
        .await;
        let (second_addr, second_server) =
            spawn_status_upstream(StatusCode::OK, Arc::clone(&second_requests)).await;
        let (proxy, audit_sink, health_states) = retry_proxy_with_options(
            [first_addr, second_addr],
            RetryProxyOptions {
                retry: Some(config::UpstreamRetryConfig {
                    max_attempts: 3,
                    methods: vec!["GET".to_owned()],
                    statuses: vec![503],
                }),
                timeout: Duration::from_millis(225),
                health_config: Some(passive_health_config()),
                ..RetryProxyOptions::default()
            },
        );
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/items")
            .header(REQUEST_ID_HEADER, "deadline-request")
            .body(Body::empty())
            .expect("request");
        let started = Instant::now();

        let response = proxy.forward_request(request, "203.0.113.8").await;
        let elapsed = started.elapsed();
        let outcome = response
            .extensions()
            .get::<middleware::decision::UpstreamOutcome>()
            .expect("upstream outcome");

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(outcome.attempts.len(), 1);
        assert_eq!(outcome.attempts[0].result, "request_timeout");
        assert!(outcome.retry_exhausted);
        assert!(elapsed < Duration::from_millis(350));
        assert!(second_requests.lock().expect("second captures").is_empty());
        assert!(!health_states[0].eligible());
        assert_eq!(
            health_states[0].last_failure_category().await.as_deref(),
            Some("request_timeout")
        );
        assert_eq!(
            wait_for_retry_audit(&audit_sink).await.payload["reason"],
            "request_timeout"
        );

        first_server.abort();
        second_server.abort();
    }

    #[tokio::test]
    async fn logical_deadline_terminates_committed_retry_tail_and_releases_permits() {
        let first_requests = Arc::new(Mutex::new(Vec::new()));
        let second_requests = Arc::new(Mutex::new(Vec::new()));
        let (first_addr, first_server) = spawn_status_upstream_after(
            StatusCode::SERVICE_UNAVAILABLE,
            Arc::clone(&first_requests),
            Duration::from_millis(75),
        )
        .await;
        let (second_addr, second_server) =
            spawn_trickling_upstream(Arc::clone(&second_requests), Duration::from_millis(500))
                .await;
        let (proxy, _, health_states) = retry_proxy_with_options(
            [first_addr, second_addr],
            RetryProxyOptions {
                retry: Some(config::UpstreamRetryConfig {
                    max_attempts: 2,
                    methods: vec!["GET".to_owned()],
                    statuses: vec![503],
                }),
                timeout: Duration::from_millis(250),
                limits: config::UpstreamPoolLimitsConfig {
                    max_in_flight: 1,
                    queue_depth: 0,
                    queue_timeout_ms: 10,
                },
                health_config: Some(passive_health_config()),
                ..RetryProxyOptions::default()
            },
        );
        let pool = test_pool(&proxy);
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/items")
            .header(REQUEST_ID_HEADER, "tail-deadline")
            .body(Body::empty())
            .expect("request");
        let started = Instant::now();

        let response = proxy.forward_request(request, "203.0.113.8").await;
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body().into_data_stream();
        assert_eq!(
            body.next()
                .await
                .expect("first response chunk")
                .expect("first response chunk should succeed"),
            bytes::Bytes::from_static(b"first")
        );
        assert!(matches!(
            pool.admission.acquire().await,
            Err(super::super::admission::PoolAdmissionError::QueueFull)
        ));
        assert!(
            pool.retry_budget.try_acquire().is_none(),
            "retry budget must remain held while the retry response is active"
        );

        let error = body
            .next()
            .await
            .expect("deadline should terminate the response tail")
            .expect_err("deadline tail should be a redacted error");
        assert!(
            started.elapsed() < Duration::from_millis(330),
            "response tail exceeded the original logical deadline"
        );
        assert!(error.to_string().contains("request_timeout"));
        let admission = pool
            .admission
            .acquire()
            .await
            .expect("terminal timeout must release admission immediately");
        let retry_budget = pool
            .retry_budget
            .try_acquire()
            .expect("terminal timeout must release retry budget immediately");
        assert!(!health_states[1].eligible());
        assert_eq!(
            health_states[1].last_failure_category().await.as_deref(),
            Some("request_timeout")
        );
        drop(admission);
        drop(retry_budget);
        drop(body);

        first_server.abort();
        second_server.abort();
    }

    #[tokio::test]
    async fn committed_tail_deadline_releases_capacity_without_downstream_polling() {
        let first_requests = Arc::new(Mutex::new(Vec::new()));
        let second_requests = Arc::new(Mutex::new(Vec::new()));
        let (first_addr, first_server) = spawn_status_upstream_after(
            StatusCode::SERVICE_UNAVAILABLE,
            Arc::clone(&first_requests),
            Duration::from_millis(75),
        )
        .await;
        let (second_addr, second_server) =
            spawn_trickling_upstream(Arc::clone(&second_requests), Duration::ZERO).await;
        let (proxy, _, health_states) = retry_proxy_with_options(
            [first_addr, second_addr],
            RetryProxyOptions {
                retry: Some(config::UpstreamRetryConfig {
                    max_attempts: 2,
                    methods: vec!["GET".to_owned()],
                    statuses: vec![503],
                }),
                timeout: Duration::from_millis(250),
                limits: config::UpstreamPoolLimitsConfig {
                    max_in_flight: 1,
                    queue_depth: 0,
                    queue_timeout_ms: 10,
                },
                health_config: Some(passive_health_config()),
                ..RetryProxyOptions::default()
            },
        );
        let pool = test_pool(&proxy);
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/items")
            .header(REQUEST_ID_HEADER, "unpolled-tail-deadline")
            .body(Body::empty())
            .expect("request");

        let response = proxy.forward_request(request, "203.0.113.8").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(matches!(
            pool.admission.acquire().await,
            Err(super::super::admission::PoolAdmissionError::QueueFull)
        ));
        assert!(
            pool.retry_budget.try_acquire().is_none(),
            "retry budget must be held before the deadline"
        );

        tokio::time::sleep(Duration::from_millis(300)).await;

        let admission = pool
            .admission
            .acquire()
            .await
            .expect("deadline must release admission without downstream polling");
        let retry_budget = pool
            .retry_budget
            .try_acquire()
            .expect("deadline must release retry budget without downstream polling");
        assert!(
            health_states[1].eligible(),
            "a downstream that never requests the response tail must not poison endpoint health"
        );
        assert_eq!(health_states[1].last_failure_category().await, None);
        drop(admission);
        drop(retry_budget);
        drop(response);

        first_server.abort();
        second_server.abort();
    }

    #[tokio::test]
    async fn streamed_request_and_egress_denial_never_retry() {
        let first_requests = Arc::new(Mutex::new(Vec::new()));
        let second_requests = Arc::new(Mutex::new(Vec::new()));
        let (first_addr, first_server) =
            spawn_status_upstream(StatusCode::SERVICE_UNAVAILABLE, Arc::clone(&first_requests))
                .await;
        let (second_addr, second_server) =
            spawn_status_upstream(StatusCode::OK, Arc::clone(&second_requests)).await;
        let retry = config::UpstreamRetryConfig {
            max_attempts: 3,
            methods: vec!["GET".to_owned()],
            statuses: vec![503],
        };
        let (stream_proxy, _, _) = retry_proxy_with_options(
            [first_addr, second_addr],
            RetryProxyOptions {
                retry: Some(retry.clone()),
                request_body_mode: RequestBodyMode::Stream,
                ..RetryProxyOptions::default()
            },
        );
        let streamed = Request::builder()
            .method(http::Method::GET)
            .uri("/items")
            .header(REQUEST_ID_HEADER, "stream-once")
            .body(Body::from_stream(stream::once(async {
                Ok::<_, Infallible>(bytes::Bytes::from_static(b"streamed"))
            })))
            .expect("request");

        let streamed_response = stream_proxy.forward_request(streamed, "203.0.113.8").await;
        let streamed_outcome = streamed_response
            .extensions()
            .get::<middleware::decision::UpstreamOutcome>()
            .expect("streamed outcome");
        assert_eq!(streamed_response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(streamed_outcome.attempts.len(), 1);
        assert_eq!(first_requests.lock().expect("first captures").len(), 1);
        assert!(second_requests.lock().expect("second captures").is_empty());

        let (denied_proxy, _, _) = retry_proxy_with_options(
            [first_addr, second_addr],
            RetryProxyOptions {
                retry: Some(retry),
                allow_loopback_host: false,
                ..RetryProxyOptions::default()
            },
        );
        let denied = Request::builder()
            .method(http::Method::GET)
            .uri("/items")
            .header(REQUEST_ID_HEADER, "egress-denied-once")
            .body(Body::empty())
            .expect("request");
        let denied_response = denied_proxy.forward_request(denied, "203.0.113.8").await;
        let denied_outcome = denied_response
            .extensions()
            .get::<middleware::decision::UpstreamOutcome>()
            .expect("denied outcome");
        assert_eq!(denied_response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(denied_outcome.attempts.len(), 1);
        assert_eq!(denied_outcome.attempts[0].result, "host_not_allowed");
        assert_eq!(first_requests.lock().expect("first captures").len(), 1);
        assert!(second_requests.lock().expect("second captures").is_empty());

        first_server.abort();
        second_server.abort();
    }

    #[tokio::test]
    async fn cancellation_during_retry_releases_admission_and_retry_budget() {
        let first_requests = Arc::new(Mutex::new(Vec::new()));
        let second_requests = Arc::new(Mutex::new(Vec::new()));
        let (first_addr, first_server) =
            spawn_status_upstream(StatusCode::SERVICE_UNAVAILABLE, Arc::clone(&first_requests))
                .await;
        let (second_addr, second_server) = spawn_status_upstream_after(
            StatusCode::OK,
            Arc::clone(&second_requests),
            Duration::from_millis(500),
        )
        .await;
        let (proxy, _, _) = retry_proxy_with_options(
            [first_addr, second_addr],
            RetryProxyOptions {
                retry: Some(config::UpstreamRetryConfig {
                    max_attempts: 3,
                    methods: vec!["GET".to_owned()],
                    statuses: vec![503],
                }),
                limits: config::UpstreamPoolLimitsConfig {
                    max_in_flight: 1,
                    queue_depth: 0,
                    queue_timeout_ms: 10,
                },
                ..RetryProxyOptions::default()
            },
        );
        let proxy = Arc::new(proxy);
        let pool = test_pool(&proxy);
        let task = tokio::spawn({
            let proxy = Arc::clone(&proxy);
            async move {
                let request = Request::builder()
                    .method(http::Method::GET)
                    .uri("/items")
                    .header(REQUEST_ID_HEADER, "cancel-retry")
                    .body(Body::empty())
                    .expect("request");
                proxy.forward_request(request, "203.0.113.8").await
            }
        });
        wait_for_request_count(&second_requests, 1).await;

        task.abort();
        let _ = task.await;
        let admission = pool
            .admission
            .acquire()
            .await
            .expect("cancellation must release admission");
        let retry_budget = pool
            .retry_budget
            .try_acquire()
            .expect("cancellation must release retry budget");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(first_requests.lock().expect("first captures").len(), 1);
        assert_eq!(second_requests.lock().expect("second captures").len(), 1);
        drop(admission);
        drop(retry_budget);

        first_server.abort();
        second_server.abort();
    }

    #[tokio::test]
    async fn draining_lifecycle_prevents_new_admission_and_attempts() {
        let first_requests = Arc::new(Mutex::new(Vec::new()));
        let second_requests = Arc::new(Mutex::new(Vec::new()));
        let (first_addr, first_server) =
            spawn_status_upstream(StatusCode::SERVICE_UNAVAILABLE, Arc::clone(&first_requests))
                .await;
        let (second_addr, second_server) =
            spawn_status_upstream(StatusCode::OK, Arc::clone(&second_requests)).await;
        let (proxy, _, _) = retry_proxy_with_options(
            [first_addr, second_addr],
            RetryProxyOptions {
                retry: Some(config::UpstreamRetryConfig {
                    max_attempts: 2,
                    methods: vec!["GET".to_owned()],
                    statuses: vec![503],
                }),
                ..RetryProxyOptions::default()
            },
        );
        proxy.lifecycle.begin_draining();
        let request = Request::builder()
            .method(http::Method::GET)
            .uri("/items")
            .header(REQUEST_ID_HEADER, "shutdown-no-retry")
            .body(Body::empty())
            .expect("request");

        let response = proxy.forward_request(request, "203.0.113.8").await;
        let outcome = response
            .extensions()
            .get::<middleware::decision::UpstreamOutcome>()
            .expect("upstream outcome");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(outcome.attempts.is_empty());
        assert_eq!(
            first_requests.lock().expect("first captures").len()
                + second_requests.lock().expect("second captures").len(),
            0
        );

        first_server.abort();
        second_server.abort();
    }

    #[tokio::test]
    async fn draining_lifecycle_cancels_queued_admission_before_upstream_work() {
        let first_requests = Arc::new(Mutex::new(Vec::new()));
        let second_requests = Arc::new(Mutex::new(Vec::new()));
        let (first_addr, first_server) =
            spawn_status_upstream(StatusCode::OK, Arc::clone(&first_requests)).await;
        let (second_addr, second_server) =
            spawn_status_upstream(StatusCode::OK, Arc::clone(&second_requests)).await;
        let (proxy, _, _) = retry_proxy_with_options(
            [first_addr, second_addr],
            RetryProxyOptions {
                limits: config::UpstreamPoolLimitsConfig {
                    max_in_flight: 1,
                    queue_depth: 1,
                    queue_timeout_ms: 1_000,
                },
                ..RetryProxyOptions::default()
            },
        );
        let proxy = Arc::new(proxy);
        let held_admission = test_pool(&proxy)
            .admission
            .acquire()
            .await
            .expect("test should hold the only admission permit");
        let request_task = tokio::spawn({
            let proxy = Arc::clone(&proxy);
            async move {
                proxy
                    .forward_request(
                        Request::builder()
                            .method(http::Method::GET)
                            .uri("/items")
                            .header(REQUEST_ID_HEADER, "shutdown-queued-admission")
                            .body(Body::empty())
                            .expect("request"),
                        "203.0.113.8",
                    )
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;

        proxy.lifecycle.begin_draining();
        drop(held_admission);
        let response = tokio::time::timeout(Duration::from_secs(1), request_task)
            .await
            .expect("queued request should be cancelled promptly")
            .expect("queued request task should not panic");
        let outcome = response
            .extensions()
            .get::<middleware::decision::UpstreamOutcome>()
            .expect("upstream outcome");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(outcome.attempts.is_empty());
        assert_eq!(
            first_requests.lock().expect("first captures").len()
                + second_requests.lock().expect("second captures").len(),
            0
        );

        first_server.abort();
        second_server.abort();
    }

    #[tokio::test]
    async fn concurrent_retries_respect_the_non_waiting_pool_budget() {
        let attempts = Arc::new(Mutex::new(HashMap::<String, usize>::new()));
        let (first_addr, first_server) = spawn_attempt_aware_upstream(Arc::clone(&attempts)).await;
        let (second_addr, second_server) =
            spawn_attempt_aware_upstream(Arc::clone(&attempts)).await;
        let (proxy, _, _) = retry_proxy_with_options(
            [first_addr, second_addr],
            RetryProxyOptions {
                retry: Some(config::UpstreamRetryConfig {
                    max_attempts: 2,
                    methods: vec!["GET".to_owned()],
                    statuses: vec![503],
                }),
                timeout: Duration::from_secs(1),
                limits: config::UpstreamPoolLimitsConfig {
                    max_in_flight: 5,
                    queue_depth: 0,
                    queue_timeout_ms: 10,
                },
                ..RetryProxyOptions::default()
            },
        );
        let proxy = Arc::new(proxy);
        let pool = test_pool(&proxy);
        let mut tasks = Vec::new();
        for index in 0..5 {
            let proxy = Arc::clone(&proxy);
            tasks.push(tokio::spawn(async move {
                let request = Request::builder()
                    .method(http::Method::GET)
                    .uri("/items")
                    .header(REQUEST_ID_HEADER, format!("budget-{index}"))
                    .body(Body::empty())
                    .expect("request");
                proxy.forward_request(request, "203.0.113.8").await
            }));
        }
        let mut statuses = Vec::new();
        for task in tasks {
            let response = task.await.expect("request task");
            statuses.push(response.status());
            drop(response);
        }

        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::OK)
                .count(),
            1
        );
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::SERVICE_UNAVAILABLE)
                .count(),
            4
        );
        {
            let attempts = attempts.lock().expect("attempt counts");
            assert_eq!(attempts.len(), 5);
            assert_eq!(attempts.values().filter(|count| **count == 2).count(), 1);
            assert_eq!(attempts.values().filter(|count| **count == 1).count(), 4);
        }
        let admission = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Ok(permit) = pool.admission.acquire().await {
                    return permit;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completed requests must release admission");
        let retry_budget = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Some(permit) = pool.retry_budget.try_acquire() {
                    return permit;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completed retry must release retry budget");
        drop(admission);
        drop(retry_budget);

        first_server.abort();
        second_server.abort();
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct CapturedRequest {
        request_id: Option<String>,
        body: Vec<u8>,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TlsValidationCase {
        UntrustedCertificate,
        WrongHostname,
    }

    struct TestTlsUpstream {
        addr: SocketAddr,
        ca_pem: String,
        connections: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }

    async fn spawn_test_tls_upstream(certificate_name: &str) -> TestTlsUpstream {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.distinguished_name = rcgen::DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "GreenGateway Retry Test CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().expect("test CA key should generate");
        let ca = ca_params
            .self_signed(&ca_key)
            .expect("test CA certificate should build");
        let mut server_params = rcgen::CertificateParams::new(vec![certificate_name.to_owned()])
            .expect("test server name should be valid");
        server_params.distinguished_name = rcgen::DistinguishedName::new();
        server_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, certificate_name);
        let server_key = rcgen::KeyPair::generate().expect("test server key should generate");
        let server = server_params
            .signed_by(&server_key, &ca, &ca_key)
            .expect("test server certificate should build");
        let server_config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![tokio_rustls::rustls::pki_types::CertificateDer::from(
                    server.der().as_ref().to_vec(),
                )],
                tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
                    tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(
                        server_key.serialize_der(),
                    ),
                ),
            )
            .expect("test TLS server config should build");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test TLS listener");
        let addr = listener.local_addr().expect("test TLS listener address");
        let connections = Arc::new(AtomicUsize::new(0));
        let task_connections = Arc::clone(&connections);
        let task = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("TLS test upstream should receive one connection");
            task_connections.fetch_add(1, Ordering::SeqCst);
            let _ = acceptor.accept(stream).await;
        });
        TestTlsUpstream {
            addr,
            ca_pem: ca.pem(),
            connections,
            task,
        }
    }

    struct RetryDnsResolver {
        first_addr: SocketAddr,
        alternate_calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl egress::DnsResolver for RetryDnsResolver {
        async fn resolve(&self, host: &str, _port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
            match host {
                "retry-a.example.test" => Ok(vec![self.first_addr]),
                "retry-b.example.test" => {
                    self.alternate_calls.fetch_add(1, Ordering::SeqCst);
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "synthetic retry DNS failure",
                    ))
                }
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "unexpected retry test host",
                )),
            }
        }
    }

    async fn spawn_status_upstream(
        status: StatusCode,
        requests: Arc<Mutex<Vec<CapturedRequest>>>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        spawn_status_upstream_after(status, requests, Duration::ZERO).await
    }

    async fn spawn_status_upstream_after(
        status: StatusCode,
        requests: Arc<Mutex<Vec<CapturedRequest>>>,
        delay: Duration,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener");
        let addr = listener.local_addr().expect("test listener address");
        let app = Router::new().fallback(move |request: Request<Body>| {
            let requests = Arc::clone(&requests);
            async move {
                let request_id = request
                    .headers()
                    .get(REQUEST_ID_HEADER)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                let body = axum::body::to_bytes(request.into_body(), 1024)
                    .await
                    .expect("bounded test request body");
                requests
                    .lock()
                    .expect("request captures")
                    .push(CapturedRequest {
                        request_id,
                        body: body.to_vec(),
                    });
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                (status, "upstream")
            }
        });
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("test upstream should serve");
        });
        (addr, task)
    }

    async fn spawn_trickling_upstream(
        requests: Arc<Mutex<Vec<CapturedRequest>>>,
        tail_delay: Duration,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener");
        let addr = listener.local_addr().expect("test listener address");
        let app = Router::new().fallback(move |request: Request<Body>| {
            let requests = Arc::clone(&requests);
            async move {
                let request_id = request
                    .headers()
                    .get(REQUEST_ID_HEADER)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                let body = axum::body::to_bytes(request.into_body(), 1024)
                    .await
                    .expect("bounded test request body");
                requests
                    .lock()
                    .expect("request captures")
                    .push(CapturedRequest {
                        request_id,
                        body: body.to_vec(),
                    });
                let response_body = stream::once(async {
                    Ok::<_, Infallible>(bytes::Bytes::from_static(b"first"))
                })
                .chain(stream::once(async move {
                    tokio::time::sleep(tail_delay).await;
                    Ok::<_, Infallible>(bytes::Bytes::from_static(b"tail"))
                }));
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from_stream(response_body))
                    .expect("streaming response")
            }
        });
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("test upstream should serve");
        });
        (addr, task)
    }

    #[derive(Clone)]
    enum SseTestBody {
        Chunks(Vec<(Duration, &'static str)>),
        Pending,
    }

    async fn spawn_sse_upstream(plan: SseTestBody) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test SSE listener");
        let addr = listener.local_addr().expect("test SSE listener address");
        let app = Router::new().fallback(move || {
            let plan = plan.clone();
            async move {
                let body = match plan {
                    SseTestBody::Chunks(chunks) => {
                        let stream = stream::unfold(chunks.into_iter(), |mut chunks| async move {
                            let (delay, chunk) = chunks.next()?;
                            tokio::time::sleep(delay).await;
                            Some((
                                Ok::<_, Infallible>(bytes::Bytes::from_static(chunk.as_bytes())),
                                chunks,
                            ))
                        });
                        Body::from_stream(stream)
                    }
                    SseTestBody::Pending => {
                        Body::from_stream(stream::pending::<Result<bytes::Bytes, Infallible>>())
                    }
                };
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "text/event-stream")
                    .body(body)
                    .expect("SSE response")
            }
        });
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("test SSE upstream should serve");
        });
        (addr, task)
    }

    async fn spawn_attempt_aware_upstream(
        attempts: Arc<Mutex<HashMap<String, usize>>>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener");
        let addr = listener.local_addr().expect("test listener address");
        let app = Router::new().fallback(move |request: Request<Body>| {
            let attempts = Arc::clone(&attempts);
            async move {
                let request_id = request
                    .headers()
                    .get(REQUEST_ID_HEADER)
                    .and_then(|value| value.to_str().ok())
                    .expect("test request ID")
                    .to_owned();
                let attempt = {
                    let mut attempts = attempts.lock().expect("attempt counts");
                    let attempt = attempts.entry(request_id).or_default();
                    *attempt += 1;
                    *attempt
                };
                if attempt == 1 {
                    (StatusCode::SERVICE_UNAVAILABLE, "retry")
                } else {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    (StatusCode::OK, "ok")
                }
            }
        });
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("test upstream should serve");
        });
        (addr, task)
    }

    async fn wait_for_request_count(requests: &Arc<Mutex<Vec<CapturedRequest>>>, expected: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if requests.lock().expect("request captures").len() >= expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("expected upstream request should arrive");
    }

    fn test_pool(proxy: &ProxyState) -> Arc<UpstreamPool> {
        match &proxy.routes {
            ProxyRoutes::Legacy { pool } => Arc::clone(pool),
            ProxyRoutes::RoutingTable { routes } => {
                Arc::clone(&routes.first().expect("test route").pool)
            }
        }
    }

    fn passive_health_config() -> config::UpstreamHealthCheckConfig {
        config::UpstreamHealthCheckConfig {
            method: "GET".to_owned(),
            path: "/".to_owned(),
            interval_ms: 1_000,
            jitter_ms: 0,
            timeout_ms: 100,
            healthy_threshold: 1,
            unhealthy_threshold: 1,
            expected_statuses: vec![200],
            passive_failure_statuses: vec![500, 502, 503, 504],
            required_for_readiness: false,
            minimum_healthy: 1,
        }
    }

    fn retry_proxy(
        addresses: [SocketAddr; 2],
        retry: Option<config::UpstreamRetryConfig>,
        timeout: Duration,
    ) -> (ProxyState, CaptureSink) {
        let (proxy, sink, _) = retry_proxy_with_options(
            addresses,
            RetryProxyOptions {
                retry,
                timeout,
                ..RetryProxyOptions::default()
            },
        );
        (proxy, sink)
    }

    struct RetryProxyOptions {
        retry: Option<config::UpstreamRetryConfig>,
        circuit_config: Option<config::UpstreamCircuitBreakerConfig>,
        timeout: Duration,
        response_idle_timeout: Option<Duration>,
        limits: config::UpstreamPoolLimitsConfig,
        request_body_mode: RequestBodyMode,
        sse: Option<config::UpstreamSseConfig>,
        health_config: Option<config::UpstreamHealthCheckConfig>,
        allow_loopback_host: bool,
    }

    impl Default for RetryProxyOptions {
        fn default() -> Self {
            Self {
                retry: None,
                circuit_config: None,
                timeout: Duration::from_secs(2),
                response_idle_timeout: None,
                limits: config::UpstreamPoolLimitsConfig::default(),
                request_body_mode: RequestBodyMode::Buffered,
                sse: None,
                health_config: None,
                allow_loopback_host: true,
            }
        }
    }

    fn retry_proxy_with_options(
        addresses: [SocketAddr; 2],
        options: RetryProxyOptions,
    ) -> (ProxyState, CaptureSink, [health::UpstreamHealthState; 2]) {
        let allowed_hosts = if options.allow_loopback_host {
            HashSet::from(["127.0.0.1".to_owned()])
        } else {
            HashSet::new()
        };
        let egress_config = egress::EgressConfig {
            allowed_hosts,
            timeout: options.timeout,
            connect_timeout: options.timeout.min(Duration::from_millis(100)),
            response_idle_timeout: options.response_idle_timeout.unwrap_or(options.timeout),
            deny_private_ips: false,
            ..egress::EgressConfig::default()
        };
        let client = Arc::new(
            egress::EgressClient::new(egress_config).expect("test egress client should build"),
        );
        retry_proxy_with_endpoints(
            [
                (format!("http://{}", addresses[0]), Arc::clone(&client)),
                (format!("http://{}", addresses[1]), client),
            ],
            options,
        )
    }

    fn retry_proxy_with_endpoints(
        endpoints: [(String, Arc<egress::EgressClient>); 2],
        options: RetryProxyOptions,
    ) -> (ProxyState, CaptureSink, [health::UpstreamHealthState; 2]) {
        let sink = CaptureSink::new();
        let audit = audit::AuditLog::new(Arc::new(sink.clone()));
        let health_states = [
            health::UpstreamHealthState::new("payments", "a", None),
            health::UpstreamHealthState::new("payments", "b", None),
        ];
        let health_config = options.health_config.map(Arc::new);
        if health_config.is_some() {
            for state in &health_states {
                state.mark_healthy_for_test();
            }
        }
        let circuit_config = options.circuit_config.clone();
        let sse = options.sse.as_ref().map(Into::into);
        let endpoint =
            |index: usize,
             id: &'static str,
             (upstream_origin, egress_client): (String, Arc<egress::EgressClient>)| {
                ProxyEndpoint {
                    id: Arc::from(id),
                    upstream_origin,
                    weight: 1,
                    egress_client,
                    health: health_states[index].clone(),
                    health_config: health_config.clone(),
                    circuit: circuit_config.as_ref().map(|config| {
                        super::super::circuit::CircuitBreaker::new(
                            Arc::from("payments"),
                            Arc::from(id),
                            config.clone(),
                            options.retry.as_ref(),
                            Some(audit.clone()),
                        )
                    }),
                }
            };
        let [endpoint_a, endpoint_b] = endpoints;
        let pool = Arc::new(UpstreamPool::new(
            "payments".to_owned(),
            vec![endpoint(0, "a", endpoint_a), endpoint(1, "b", endpoint_b)],
            &options.limits,
            options.retry.as_ref(),
        ));
        (
            ProxyState {
                routes: ProxyRoutes::RoutingTable {
                    routes: vec![ProxyRoute {
                        route_id: "payments".to_owned(),
                        path_prefix: Some("/".to_owned()),
                        host: None,
                        authorization_origin: "pool:payments".to_owned(),
                        connection_id: None,
                        request_header_policy: RouteRequestHeaderPolicy::default(),
                        pool,
                        request_body_mode: options.request_body_mode,
                        sse,
                    }],
                },
                connection_http: None,
                upstream_health: Vec::new(),
                max_request_body_bytes: 1024,
                health_runtime: health::UpstreamHealthRuntime::default(),
                lifecycle: crate::lifecycle::GatewayLifecycle::new(),
                audit,
                request_selection_count: None,
                request_body_mode_override: None,
            },
            sink,
            health_states,
        )
    }

    async fn wait_for_retry_audit(sink: &CaptureSink) -> audit::AuditEvent {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Some(event) = sink
                    .events()
                    .into_iter()
                    .find(|event| event.event_type == audit::event::UPSTREAM_RETRY_EXHAUSTED)
                {
                    return event;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retry audit should be emitted")
    }

    async fn wait_for_stream_audit(sink: &CaptureSink, request_id: &str) -> audit::AuditEvent {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Some(event) = sink.events().into_iter().find(|event| {
                    event.event_type == audit::event::UPSTREAM_STREAM_TERMINATED
                        && event.request_id == request_id
                }) {
                    return event;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("stream terminal audit should be emitted")
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
