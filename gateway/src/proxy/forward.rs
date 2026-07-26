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
use crate::{audit, egress, middleware};

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

struct ResponsePumpCompletion(Option<tokio::sync::oneshot::Sender<()>>);

struct ResponseTailOptions {
    circuit_permit: Option<super::circuit::CircuitPermit>,
    pump_completed: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for ResponsePumpCompletion {
    fn drop(&mut self) {
        if let Some(completed) = self.0.take() {
            let _ = completed.send(());
        }
    }
}

struct ResponseTailPump {
    upstream_body: egress::EgressBodyStream,
    demand_receiver: tokio::sync::mpsc::Receiver<ResponseTailDemand>,
    terminal_sender: tokio::sync::watch::Sender<ResponseTailTerminal>,
    admission_permit: super::admission::PoolAdmissionPermit,
    retry_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    deadline: tokio::time::Instant,
    passive_health: Option<(
        super::health::UpstreamHealthState,
        Arc<crate::config::UpstreamHealthCheckConfig>,
    )>,
    circuit_permit: Option<super::circuit::CircuitPermit>,
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
    let admission_permit = match upstream.pool.admission.acquire().await {
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
    let mut body = match upstream.request_body_mode {
        RequestBodyMode::Buffered => {
            match axum::body::to_bytes(body, proxy.max_request_body_bytes).await {
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
    let max_attempts = upstream
        .pool
        .retry_policy
        .max_attempts_for(&parts.method, body.is_replayable());
    let request_started = Instant::now();
    let deadline = tokio::time::Instant::now() + upstream.pool.request_timeout();
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
        let target_url = proxy_target_url(&endpoint.upstream_origin, &parts.uri);
        let headers = attempt_headers(&parts.headers, source_ip, &upstream.request_header_policy);
        let attempt_started = Instant::now();
        let sent = tokio::time::timeout_at(
            deadline,
            endpoint.egress_client.stream_request_with_body(
                parts.method.clone(),
                &target_url,
                headers,
                attempt_body,
            ),
        )
        .await;

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
        let retryable_status = upstream.pool.retry_policy.retries_status(upstream_status);
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
        let first_chunk =
            match tokio::time::timeout_at(deadline, upstream_response.body.next()).await {
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
        let response_body = match first_chunk {
            Some(chunk) => {
                let passive_health = endpoint
                    .health_config
                    .as_ref()
                    .map(|config| (endpoint.health.clone(), Arc::clone(config)));
                redacted_response_body(
                    chunk,
                    upstream_response.body,
                    admission_permit,
                    active_retry_permit.take(),
                    deadline,
                    passive_health,
                    circuit_permit.take(),
                )
            }
            None => {
                record_circuit_success(&mut circuit_permit);
                Body::empty()
            }
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
) -> HeaderMap {
    let mut headers = strip_hop_by_hop_headers(inbound);
    strip_gateway_credentials(&mut headers);
    if let Some(request_id) = inbound.get(REQUEST_ID_HEADER) {
        headers.insert(request_id_header(), request_id.clone());
    }
    set_upstream_client_ip(&mut headers, source_ip);
    apply_route_request_header_policy(&mut headers, policy);
    headers
}

async fn reserve_retry(
    upstream: &MatchedUpstream,
    request_id: Option<&HeaderValue>,
    failed_attempt: u8,
    deadline: tokio::time::Instant,
    reason: &'static str,
) -> Result<tokio::sync::OwnedSemaphorePermit, &'static str> {
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
    tokio::time::sleep(delay).await;
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

fn redacted_response_body(
    first_chunk: bytes::Bytes,
    upstream_body: egress::EgressBodyStream,
    admission_permit: super::admission::PoolAdmissionPermit,
    retry_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    deadline: tokio::time::Instant,
    passive_health: Option<(
        super::health::UpstreamHealthState,
        Arc<crate::config::UpstreamHealthCheckConfig>,
    )>,
    circuit_permit: Option<super::circuit::CircuitPermit>,
) -> Body {
    redacted_response_body_inner(
        first_chunk,
        upstream_body,
        admission_permit,
        retry_permit,
        deadline,
        passive_health,
        ResponseTailOptions {
            circuit_permit,
            pump_completed: None,
        },
    )
}

fn redacted_response_body_inner(
    first_chunk: bytes::Bytes,
    upstream_body: egress::EgressBodyStream,
    admission_permit: super::admission::PoolAdmissionPermit,
    retry_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    deadline: tokio::time::Instant,
    passive_health: Option<(
        super::health::UpstreamHealthState,
        Arc<crate::config::UpstreamHealthCheckConfig>,
    )>,
    options: ResponseTailOptions,
) -> Body {
    let (demand_sender, demand_receiver) = tokio::sync::mpsc::channel(1);
    let (terminal_sender, terminal_receiver) =
        tokio::sync::watch::channel(ResponseTailTerminal::Active);
    tokio::spawn(pump_redacted_response_tail(ResponseTailPump {
        upstream_body,
        demand_receiver,
        terminal_sender,
        admission_permit,
        retry_permit,
        deadline,
        passive_health,
        circuit_permit: options.circuit_permit,
        completion: ResponsePumpCompletion(options.pump_completed),
    }));
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

    Body::from_stream(
        stream::once(async move { Ok::<_, RedactedProxyBodyError>(first_chunk) })
            .chain(redacted_tail),
    )
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
        mut upstream_body,
        mut demand_receiver,
        terminal_sender,
        admission_permit,
        retry_permit,
        deadline,
        passive_health,
        circuit_permit,
        completion: _completion,
    } = pump;
    let mut admission_permit = Some(admission_permit);
    let mut retry_permit = retry_permit;
    let mut circuit_permit = circuit_permit;
    loop {
        let demand = tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline) => {
                finish_response_timeout(
                    upstream_body,
                    &terminal_sender,
                    &mut admission_permit,
                    &mut retry_permit,
                    passive_health.as_ref(),
                    &mut circuit_permit,
                ).await;
                return;
            }
            demand = demand_receiver.recv() => demand,
        };
        let Some(mut demand) = demand else {
            return;
        };
        let result = tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline) => {
                finish_response_timeout(
                    upstream_body,
                    &terminal_sender,
                    &mut admission_permit,
                    &mut retry_permit,
                    passive_health.as_ref(),
                    &mut circuit_permit,
                ).await;
                return;
            }
            () = demand.response.closed() => continue,
            result = upstream_body.next() => result,
        };
        match result {
            Some(Ok(chunk)) => {
                let _ = demand.response.send(ResponseTailEvent::Chunk(chunk));
            }
            Some(Err(error)) => {
                let category = proxy_error_category(&error);
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
                return;
            }
            None => {
                record_circuit_success(&mut circuit_permit);
                terminal_sender.send_replace(ResponseTailTerminal::Eof);
                let _ = demand.response.send(ResponseTailEvent::Eof);
                return;
            }
        }
    }
}

async fn finish_response_timeout(
    upstream_body: egress::EgressBodyStream,
    terminal_sender: &tokio::sync::watch::Sender<ResponseTailTerminal>,
    admission_permit: &mut Option<super::admission::PoolAdmissionPermit>,
    retry_permit: &mut Option<tokio::sync::OwnedSemaphorePermit>,
    passive_health: Option<&(
        super::health::UpstreamHealthState,
        Arc<crate::config::UpstreamHealthCheckConfig>,
    )>,
    circuit_permit: &mut Option<super::circuit::CircuitPermit>,
) {
    release_response_permits(admission_permit, retry_permit);
    record_circuit_failure(circuit_permit, "request_timeout");
    drop(upstream_body);
    terminal_sender.send_replace(ResponseTailTerminal::Error("request_timeout"));
    if let Some((health, config)) = passive_health {
        health.record_passive_timeout(config).await;
    }
    tracing::warn!(
        error_category = "request_timeout",
        "proxied upstream response body exceeded the logical request deadline after response commitment"
    );
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
        });
    if let Some(request_id) = request_id {
        response
            .headers_mut()
            .insert(request_id_header(), request_id);
    }
    response
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
        let body = redacted_response_body(
            bytes::Bytes::from_static(b"first"),
            upstream_body,
            permit,
            None,
            tokio::time::Instant::now() + Duration::from_secs(1),
            None,
            None,
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
        let (completed_sender, completed_receiver) = tokio::sync::oneshot::channel();
        let body = redacted_response_body_inner(
            bytes::Bytes::from_static(b"first"),
            upstream_body,
            admission_permit,
            Some(retry_permit),
            tokio::time::Instant::now() + Duration::from_millis(50),
            None,
            ResponseTailOptions {
                circuit_permit: None,
                pump_completed: Some(completed_sender),
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
        drop(released_admission);
        drop(released_retry);
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
        assert!(!health_states[1].eligible());
        assert_eq!(
            health_states[1].last_failure_category().await.as_deref(),
            Some("request_timeout")
        );
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
        limits: config::UpstreamPoolLimitsConfig,
        request_body_mode: RequestBodyMode,
        health_config: Option<config::UpstreamHealthCheckConfig>,
        allow_loopback_host: bool,
    }

    impl Default for RetryProxyOptions {
        fn default() -> Self {
            Self {
                retry: None,
                circuit_config: None,
                timeout: Duration::from_secs(2),
                limits: config::UpstreamPoolLimitsConfig::default(),
                request_body_mode: RequestBodyMode::Buffered,
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
            response_idle_timeout: options.timeout,
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
                        request_header_policy: RouteRequestHeaderPolicy::default(),
                        pool,
                        request_body_mode: options.request_body_mode,
                    }],
                },
                upstream_health: Vec::new(),
                max_request_body_bytes: 1024,
                health_runtime: health::UpstreamHealthRuntime::default(),
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
