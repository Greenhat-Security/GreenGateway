//! Transparent gRPC proxying over HTTP/2, for routes that explicitly opt in.
//!
//! # Where this sits
//!
//! The gRPC listener (see [`listen`]) serves a router built from the same
//! `apply_middleware` call, with the same `MiddlewareStack` value, as the HTTP
//! data listener. Its only route is a fallback into [`handle_call`]. That is
//! the whole structural argument for the zero-bytes invariant: authentication,
//! rate limiting, CSRF, request validation, route classification, RBAC and
//! direct policy are *layers around* this function, so a call that any of them
//! refuses never enters it, and this module is the only thing in the tree that
//! can reach `EgressClient::grpc_call_at_checked_destination`.
//!
//! Within the function the same ordering discipline continues: local protocol
//! validation, route match, deadline, admission, endpoint selection, and only
//! then egress. Every step before the egress call returns a [`Denial`], and a
//! `Denial` becomes a protocol-correct gRPC trailers-only response -- never a
//! successful envelope.
//!
//! # Why the resource model differs from WebSocket
//!
//! `proxy::websocket` counts connections, because a WebSocket connection *is* a
//! conversation. gRPC multiplexes many concurrent streams over one HTTP/2
//! connection in both directions, so counting connections would bound nothing:
//! one accepted socket can carry `GRPC_MAX_CONCURRENT_STREAMS` calls inbound
//! and the upstream's `SETTINGS_MAX_CONCURRENT_STREAMS` outbound. So the unit
//! of admission here is the CALL, and connections are bounded separately at the
//! listener (inbound) and by the h2 client's own `ready()` backpressure
//! (outbound).
//!
//! # What never reaches telemetry
//!
//! Protobuf bytes are counted and forwarded, never read: the only thing this
//! module parses out of a body is the five-byte length-prefix envelope. The
//! upstream's `grpc-message` is forwarded to the client and never recorded --
//! every string this module logs, counts, or audits is a `&'static str` literal
//! from this file or from [`protocol`]. The method identity is recorded as an
//! audit field only after it has passed the grammar in
//! [`protocol::validate_method_path`], and never as a metric label, because its
//! cardinality is chosen by the caller.

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use axum::{body::Body, response::Response};
use bytes::Bytes;
use http::{
    header::{self, CONTENT_TYPE},
    request::Parts,
    HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, Version,
};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use serde_json::json;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::{admission, forward, MatchedUpstream, ProxyState};
use crate::{audit, config, egress, metrics as metric_names, middleware};

pub(crate) mod listen;
pub(crate) mod protocol;

#[cfg(test)]
mod tests;

use protocol::{
    grpc_status_for_http_status, grpc_status_for_upstream_status, parse_grpc_timeout,
    validate_content_type, validate_method_path, validate_te_trailers, FramingError, GrpcStatus,
    MessageFramer, ProtocolRejection, GRPC_CONTENT_TYPE, GRPC_MESSAGE, GRPC_STATUS, GRPC_TIMEOUT,
};

/// Marks a response this module produced.
///
/// The response-shaping layer at the outside of the gRPC listener rewrites
/// anything that is not already gRPC-shaped, and it needs to tell "the gateway's
/// own gRPC answer" from "an HTTP answer some middleware produced". A response
/// extension is the right marker because extensions never come off the wire: a
/// client cannot forge one by sending a header.
#[derive(Clone, Copy, Debug)]
pub(crate) struct GrpcShapedResponse;

/// Per-route gRPC runtime: validated policy with durations already converted,
/// plus the capacity this route may spend on concurrent calls.
pub(super) struct RouteGrpcRuntime {
    /// A separate admission pool from the route's HTTP one, for the reason
    /// `proxy::websocket` records for its own: a streaming call can hold its
    /// slot for an hour, and sharing `max_in_flight` with ordinary requests
    /// would let a handful of streams starve the route's HTTP traffic.
    admission: admission::PoolAdmission,
    endpoint_slots: HashMap<Arc<str>, Arc<Semaphore>>,
    connect_timeout: Duration,
    idle_timeout: Option<Duration>,
    max_duration: Option<Duration>,
    max_message_bytes: usize,
    max_request_bytes: Option<u64>,
    max_response_bytes: Option<u64>,
    max_metadata_entries: usize,
}

impl RouteGrpcRuntime {
    pub(super) fn new(
        route_id: &str,
        grpc: &config::UpstreamGrpcConfig,
        endpoint_ids: impl Iterator<Item = Arc<str>>,
    ) -> Self {
        let admission_pool_id: Arc<str> = Arc::from(format!("{route_id}#grpc"));
        let per_endpoint = grpc
            .max_concurrent_calls_per_endpoint
            .unwrap_or(grpc.max_concurrent_calls);

        Self {
            admission: admission::PoolAdmission::new(
                admission_pool_id,
                grpc.max_concurrent_calls,
                grpc.queue_depth,
                Duration::from_millis(grpc.queue_timeout_ms),
            ),
            endpoint_slots: endpoint_ids
                .map(|id| (id, Arc::new(Semaphore::new(per_endpoint))))
                .collect(),
            connect_timeout: Duration::from_millis(grpc.connect_timeout_ms),
            idle_timeout: (grpc.idle_timeout_ms != 0)
                .then(|| Duration::from_millis(grpc.idle_timeout_ms)),
            max_duration: (grpc.max_duration_ms != 0)
                .then(|| Duration::from_millis(grpc.max_duration_ms)),
            max_message_bytes: grpc.max_message_bytes,
            max_request_bytes: (grpc.max_request_bytes != 0).then_some(grpc.max_request_bytes),
            max_response_bytes: (grpc.max_response_bytes != 0).then_some(grpc.max_response_bytes),
            max_metadata_entries: grpc.max_metadata_entries,
        }
    }

    /// Takes an endpoint slot without ever queueing.
    ///
    /// Probed rather than waited on, exactly as the WebSocket transport does:
    /// the caller reselects around a full endpoint, and waiting here would hold
    /// the route-level admission slot while doing it.
    fn try_acquire_endpoint_slot(&self, endpoint_id: &Arc<str>) -> Option<OwnedSemaphorePermit> {
        Arc::clone(self.endpoint_slots.get(endpoint_id)?)
            .try_acquire_owned()
            .ok()
    }
}

/// A refused call, carrying a bounded category and nothing else.
#[derive(Clone, Copy, Debug)]
struct Denial {
    status: GrpcStatus,
    reason: &'static str,
    /// `denied` is a policy decision about the caller; `failed` is the upstream
    /// or the gateway not completing the call.
    result: &'static str,
}

impl Denial {
    const fn denied(status: GrpcStatus, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            result: "denied",
        }
    }

    const fn failed(status: GrpcStatus, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            result: "failed",
        }
    }
}

impl From<ProtocolRejection> for Denial {
    fn from(rejection: ProtocolRejection) -> Self {
        Self::denied(rejection.status, rejection.reason)
    }
}

/// Facts about one call that are safe to record.
#[derive(Default)]
struct CallTrace {
    pool_id: Option<Arc<str>>,
    endpoint_id: Option<Arc<str>>,
    /// Set only once the path has passed the method grammar. A path that failed
    /// validation is caller-controlled bytes and is never recorded.
    method: Option<String>,
    /// The effective deadline, after capping the client's `grpc-timeout`.
    deadline_ms: Option<u64>,
    /// Whether the client asked for a deadline at all.
    client_deadline: bool,
}

pub(crate) async fn handle_call(
    proxy: &ProxyState,
    request: Request<Body>,
    source_ip: &str,
) -> Response {
    let started = Instant::now();
    let (parts, body) = request.into_parts();
    let request_id = parts
        .headers
        .get(forward::REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown")
        .to_owned();
    let mut trace = CallTrace::default();

    match attempt_call(proxy, parts, body, source_ip, &mut trace, &request_id).await {
        // Telemetry for an accepted call is emitted by `CallGuard::drop`, when
        // the terminal status is actually known.
        Ok(response) => response,
        Err(denial) => {
            let pool_id = trace.pool_id.clone();
            record_call_outcome(
                &proxy.audit,
                &trace,
                &request_id,
                source_ip,
                denial.result,
                denial.reason,
                denial.status,
                CallBytes::default(),
                started.elapsed(),
            );
            tracing::info!(
                pool_id = pool_id.as_deref().unwrap_or("unmatched"),
                error_category = denial.reason,
                grpc_status = denial.status.as_str(),
                "gRPC call refused"
            );
            trailers_only_response(denial.status, denial.reason, &parts_request_id(&request_id))
        }
    }
}

fn parts_request_id(request_id: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(request_id).ok()
}

#[allow(clippy::too_many_lines)] // The ordering IS the security property; splitting it hides it.
async fn attempt_call(
    proxy: &ProxyState,
    parts: Parts,
    body: Body,
    source_ip: &str,
    trace: &mut CallTrace,
    request_id: &str,
) -> Result<Response, Denial> {
    let started = Instant::now();

    // ---------------------------------------------------------------
    // 1. Local protocol validation. Nothing in this block can reach the
    //    network: every input is the request itself and every check is a pure
    //    function in `protocol`.
    // ---------------------------------------------------------------
    if parts.method != Method::POST {
        return Err(Denial::denied(GrpcStatus::Internal, "method_not_post"));
    }
    // The gRPC listener only ever produces HTTP/2, so this is defence against a
    // future caller rather than against a client. Stated anyway: a gRPC call
    // over HTTP/1.1 has no trailers and therefore no way to carry a status.
    if parts.version != Version::HTTP_2 {
        return Err(Denial::denied(GrpcStatus::Internal, "http_version"));
    }
    if parts.uri.query().is_some() {
        return Err(Denial::denied(
            GrpcStatus::InvalidArgument,
            "method_path_query",
        ));
    }
    let path = parts.uri.path();
    let method = validate_method_path(path)?;
    let canonical_method = format!("/{}/{}", method.service, method.method);
    // Belt and braces, and cheap: the forwarded `:path` must be byte-identical
    // to the string RBAC authorized. The grammar admits exactly one spelling,
    // so this can only fail if the grammar and the reconstruction disagree.
    if canonical_method != path {
        return Err(Denial::denied(
            GrpcStatus::InvalidArgument,
            "method_path_not_canonical",
        ));
    }
    trace.method = Some(canonical_method.clone());
    let content_type = validate_content_type(&parts.headers)?;
    validate_te_trailers(&parts.headers)?;

    // ---------------------------------------------------------------
    // 2. Route match. Local: a table lookup over configured prefixes and hosts.
    // ---------------------------------------------------------------
    let Some(upstream) = proxy.upstream_for_request(path, &parts.headers) else {
        return Err(Denial::denied(GrpcStatus::Unimplemented, "no_route"));
    };
    // A route without gRPC policy has no limits to enforce, so it is refused
    // rather than proxied with defaults invented here.
    let Some(runtime) = upstream.grpc.clone() else {
        return Err(Denial::denied(GrpcStatus::Unimplemented, "route_not_grpc"));
    };
    trace.pool_id = Some(Arc::clone(&upstream.pool.id));

    // ---------------------------------------------------------------
    // 3. Metadata bounds. The listener already capped the total decoded header
    //    size (`max_header_list_size`); this caps the COUNT, which a byte
    //    budget does not constrain.
    // ---------------------------------------------------------------
    if parts.headers.iter().count() > runtime.max_metadata_entries {
        return Err(Denial::denied(
            GrpcStatus::ResourceExhausted,
            "request_metadata_entries",
        ));
    }

    // ---------------------------------------------------------------
    // 4. Deadline. The client's `grpc-timeout` is parsed strictly and then
    //    capped by the route ceiling; the value forwarded upstream is the
    //    gateway's, never the client's bytes.
    //
    //    The timer is ARMED HERE, and the same timer is then carried through
    //    admission, the wait for the upstream's response HEADERS, and the
    //    streaming phase. Arming it where the response body is built -- after
    //    the egress call has already returned -- would leave the entire window
    //    between admission and the upstream's first HEADERS frame with no timer
    //    on it, while the admission permit, the endpoint slot and the
    //    response-stream registration are all held; and it would then hand the
    //    streaming phase a fresh full budget, so one call could outlive its own
    //    deadline twice over. That window is not an edge case: grpc-go and
    //    tonic send response HEADERS when the handler returns, so a unary RPC
    //    spends essentially all of its life in it.
    // ---------------------------------------------------------------
    let deadline = match parts.headers.get(GRPC_TIMEOUT) {
        Some(value) => {
            trace.client_deadline = true;
            let requested = parse_grpc_timeout(value)?;
            Some(match runtime.max_duration {
                Some(ceiling) => requested.min(ceiling),
                None => requested,
            })
        }
        None => runtime.max_duration,
    };
    trace.deadline_ms = deadline.map(crate::duration_millis);
    let mut deadline_timer = deadline.map(|deadline| Box::pin(tokio::time::sleep(deadline)));

    // ---------------------------------------------------------------
    // 5. Lifecycle gate, mirroring the ordinary forwarding path.
    // ---------------------------------------------------------------
    let Some(registration) = proxy.lifecycle.try_register_response_stream() else {
        return Err(shutdown_denial());
    };
    if proxy.lifecycle.draining() {
        return Err(shutdown_denial());
    }

    // ---------------------------------------------------------------
    // 6. Admission, raced against background cancellation and against the
    //    call's own deadline. A call whose deadline has already elapsed must
    //    not take a slot: the queue timeout bounds how long the QUEUE will hold
    //    a call, which is a different question from how long the CALLER is
    //    still entitled to wait.
    // ---------------------------------------------------------------
    let shutdown = proxy.lifecycle.background_cancellation();
    let admission_result = tokio::select! {
        biased;
        () = shutdown.cancelled_owned() => return Err(shutdown_denial()),
        () = deadline_elapsed(&mut deadline_timer) => return Err(deadline_denial()),
        result = runtime.admission.acquire() => result,
    };
    let admission_permit = admission_result.map_err(|error| {
        Denial::denied(
            GrpcStatus::ResourceExhausted,
            match error {
                admission::PoolAdmissionError::QueueFull => "queue_full",
                admission::PoolAdmissionError::QueueTimeout => "queue_timeout",
            },
        )
    })?;
    if proxy.lifecycle.draining() {
        drop(admission_permit);
        return Err(shutdown_denial());
    }

    // ---------------------------------------------------------------
    // 7. Endpoint selection with a per-endpoint call slot. Probing for capacity
    //    is pre-egress, so a full endpoint costs no upstream bytes.
    // ---------------------------------------------------------------
    let mut avoided: HashSet<Arc<str>> = HashSet::new();
    let mut saw_full_endpoint = false;
    let (endpoint, mut circuit_permit, endpoint_slot) = loop {
        let Some(selected) = upstream.pool.select_endpoint_avoiding(&avoided) else {
            drop(admission_permit);
            return Err(capacity_denial(saw_full_endpoint));
        };
        if avoided.contains(&selected.endpoint.id) {
            // The pool falls back to already-attempted endpoints once no fresh
            // one is eligible, so a repeat means every endpoint is full.
            drop(admission_permit);
            return Err(capacity_denial(true));
        }
        match runtime.try_acquire_endpoint_slot(&selected.endpoint.id) {
            Some(slot) => break (selected.endpoint, selected.circuit_permit, slot),
            None => {
                saw_full_endpoint = true;
                avoided.insert(Arc::clone(&selected.endpoint.id));
            }
        }
    };
    trace.endpoint_id = Some(Arc::clone(&endpoint.id));
    ::metrics::counter!(
        metric_names::PROXY_ENDPOINT_SELECTIONS_TOTAL,
        "pool_id" => Arc::clone(&upstream.pool.id),
        "endpoint_id" => Arc::clone(&endpoint.id)
    )
    .increment(1);

    // ---------------------------------------------------------------
    // 8. Build the upstream request from validated state only.
    // ---------------------------------------------------------------
    let headers = upstream_call_headers(
        &parts,
        source_ip,
        &upstream,
        &content_type,
        deadline,
        runtime.max_metadata_entries,
    )?;
    let target_url = forward::proxy_target_url(&endpoint.upstream_origin, &parts.uri);

    let counters = Arc::new(CallBytesCounters::default());
    let fault = Arc::new(CallFault::default());
    let request_body = egress::GrpcRequestBody::new(UpstreamRequestBody {
        inner: body,
        framer: MessageFramer::default(),
        max_message_bytes: runtime.max_message_bytes,
        max_bytes: runtime.max_request_bytes,
        sent: 0,
        counters: Arc::clone(&counters),
        fault: Arc::clone(&fault),
    });

    // ---------------------------------------------------------------
    // 9. Egress. THE ONLY POINT IN THIS FUNCTION THAT CAN TOUCH THE NETWORK.
    //    Exactly one attempt: #257 disables retry, and a streaming call is not
    //    replayable in any case.
    // ---------------------------------------------------------------
    let forced_shutdown = proxy.lifecycle.response_stream_cancellation();
    let egress_client = Arc::clone(&endpoint.egress_client);
    let call = async {
        let destination = egress_client.checked_destination(&target_url).await?;
        egress_client
            .grpc_call_at_checked_destination(
                &destination,
                &target_url,
                headers,
                request_body,
                runtime.connect_timeout,
            )
            .await
    };
    // `send_request` inside `call` resolves only when the upstream sends
    // response HEADERS, and nothing inside the egress boundary bounds that: a
    // bidirectional stream has no total duration the transport could know. The
    // deadline armed at step 4 is what bounds it, and it is the SAME timer the
    // streaming phase below inherits.
    let response = tokio::select! {
        biased;
        () = forced_shutdown.cancelled() => return Err(shutdown_denial()),
        () = deadline_elapsed(&mut deadline_timer) => {
            // The endpoint is deliberately not blamed. The circuit permit is
            // dropped without a verdict, exactly as the streaming phase does
            // when the same timer fires there: a caller's half-second deadline
            // against a healthy two-second upstream is a fact about the caller,
            // and opening the breaker on it would let one impatient client take
            // the endpoint out for everyone.
            return Err(deadline_denial());
        }
        response = call => response,
    };
    let response = match response {
        Err(error) => {
            // A bound tripped by the CLIENT's own request body reaches here as
            // an opaque transport error, because failing the body is the only
            // thing a body can do. Reporting that as an upstream failure would
            // tell the caller "the endpoint is unavailable" for what was
            // actually "your message was too large", and -- worse -- would open
            // the endpoint's circuit breaker on the strength of a client
            // mistake. The recorded fault wins, and the endpoint is not blamed.
            if let Some((status, reason)) = fault.take() {
                return Err(Denial::denied(status, reason));
            }
            forward::record_circuit_failure(&mut circuit_permit, error.safe_category());
            if let Some(config) = endpoint.health_config.as_deref() {
                endpoint
                    .health
                    .record_passive_proxy_error(&error, config)
                    .await;
            }
            return Err(egress_denial(&error));
        }
        Ok(response) => response,
    };

    // ---------------------------------------------------------------
    // 10. Validate the upstream's answer, fail closed. A gRPC server answers
    //     every application outcome with HTTP 200; anything else means the peer
    //     is not speaking gRPC and must not be mistaken for an application
    //     answer.
    // ---------------------------------------------------------------
    if response.status != StatusCode::OK {
        forward::record_circuit_failure(&mut circuit_permit, "upstream_status");
        if let Some(config) = endpoint.health_config.as_deref() {
            endpoint
                .health
                .record_passive_status(response.status.as_u16(), config)
                .await;
        }
        return Err(Denial::failed(
            grpc_status_for_upstream_status(response.status),
            "upstream_status",
        ));
    }
    let Some(upstream_content_type) = grpc_response_content_type(&response.headers) else {
        forward::record_circuit_failure(&mut circuit_permit, "upstream_content_type");
        return Err(Denial::failed(
            GrpcStatus::Internal,
            "upstream_content_type",
        ));
    };
    if let Some(config) = endpoint.health_config.as_deref() {
        endpoint
            .health
            .record_passive_status(StatusCode::OK.as_u16(), config)
            .await;
    }
    forward::record_circuit_success(&mut circuit_permit);

    // A Trailers-Only answer: the upstream had an outcome and no messages, and
    // said so in the HEADERS frame. Relayed as-is rather than waited on for
    // trailers that are never coming.
    //
    // Both halves of the condition are load-bearing. `grpc-status` alone is not
    // enough -- an upstream that sends it in the headers of a response that
    // then carries messages is describing an outcome it cannot know yet, and
    // treating that as Trailers-Only would silently discard every message that
    // followed. What makes an answer Trailers-Only is that the stream ENDED on
    // the HEADERS frame, which is what `is_end_stream` reports.
    if response.headers.contains_key(GRPC_STATUS) && response.body.is_end_stream() {
        let status_label = response
            .headers
            .get(GRPC_STATUS)
            .map_or("other", upstream_status_label);
        let mut relayed = upstream_trailers_only_response(
            &response.headers,
            upstream_content_type,
            runtime.max_metadata_entries,
        )?;
        if let Some(value) = parts_request_id(request_id) {
            relayed
                .headers_mut()
                .insert(forward::request_id_header(), value);
        }
        relayed
            .extensions_mut()
            .insert(middleware::decision::UpstreamOutcome {
                latency_ms: 0,
                status: Some(StatusCode::OK.as_u16()),
                pool_id: Some(upstream.pool.id.to_string()),
                endpoint_id: Some(endpoint.id.to_string()),
                attempts: Vec::new(),
                retry_exhausted: false,
                stream_terminal_pending: false,
            });
        record_call_outcome_with_status_label(
            &proxy.audit,
            trace,
            request_id,
            source_ip,
            "allowed",
            "upstream_trailers_only",
            status_label,
            CallBytes::default(),
            started.elapsed(),
        );
        return Ok(relayed);
    }

    let response_headers = sanitized_response_headers(
        &response.headers,
        upstream_content_type,
        runtime.max_metadata_entries,
    )?;

    // ---------------------------------------------------------------
    // 11. Commit. One guard owns every reservation, so a stream that ends and a
    //     client that disappears release identically.
    // ---------------------------------------------------------------
    let guard = CallGuard {
        audit: proxy.audit.clone(),
        request_id: request_id.to_owned(),
        source_ip: source_ip.to_owned(),
        pool_id: Arc::clone(&upstream.pool.id),
        endpoint_id: Arc::clone(&endpoint.id),
        method: canonical_method,
        deadline_ms: trace.deadline_ms,
        client_deadline: trace.client_deadline,
        started: Instant::now(),
        counters: Arc::clone(&counters),
        outcome: Mutex::new(None),
        _admission: admission_permit,
        _endpoint_slot: endpoint_slot,
        _registration: registration,
    };
    ::metrics::gauge!(
        metric_names::PROXY_GRPC_ACTIVE_CALLS,
        "pool_id" => Arc::clone(&upstream.pool.id),
        "endpoint_id" => Arc::clone(&endpoint.id)
    )
    .increment(1.0);

    let client_body = ClientResponseBody {
        inner: Some(response.body),
        framer: MessageFramer::default(),
        max_message_bytes: runtime.max_message_bytes,
        max_bytes: runtime.max_response_bytes,
        received: 0,
        counters,
        fault,
        // The timer armed at step 4, with whatever is left of it. Not a fresh
        // sleep: the headers wait and the streaming phase share one budget.
        deadline: deadline_timer,
        idle: runtime
            .idle_timeout
            .map(|idle| (idle, Box::pin(tokio::time::sleep(idle)))),
        shutdown: Box::pin(forced_shutdown.cancelled_owned()),
        max_metadata_entries: runtime.max_metadata_entries,
        finished: false,
        guard: Some(guard),
    };

    let mut response = Response::new(Body::new(client_body));
    *response.headers_mut() = response_headers;
    if let Some(value) = parts_request_id(request_id) {
        response
            .headers_mut()
            .insert(forward::request_id_header(), value);
    }
    response.extensions_mut().insert(GrpcShapedResponse);
    response
        .extensions_mut()
        .insert(middleware::decision::UpstreamOutcome {
            latency_ms: 0,
            status: Some(StatusCode::OK.as_u16()),
            pool_id: Some(upstream.pool.id.to_string()),
            endpoint_id: Some(endpoint.id.to_string()),
            attempts: Vec::new(),
            retry_exhausted: false,
            stream_terminal_pending: true,
        });

    Ok(response)
}

fn shutdown_denial() -> Denial {
    Denial::denied(GrpcStatus::Unavailable, "shutdown")
}

/// The call's effective deadline elapsed before the upstream answered.
///
/// `failed` rather than `denied`, and the same status and reason literal
/// `ClientResponseBody::terminate` uses when the identical timer fires during
/// the streaming phase. The two halves of one call must not be distinguishable
/// by which side of the HEADERS frame the deadline happened to land on.
fn deadline_denial() -> Denial {
    Denial::failed(GrpcStatus::DeadlineExceeded, "deadline_exceeded")
}

/// Completes when `timer` elapses, and never when the call has no deadline.
///
/// A helper rather than an inline arm in each `select!` so that every wait is
/// against the SAME timer. An arm that constructed its own sleep would give
/// each phase a fresh budget, which is precisely the defect this exists to
/// prevent.
async fn deadline_elapsed(timer: &mut Option<Pin<Box<tokio::time::Sleep>>>) {
    match timer.as_mut() {
        Some(sleep) => sleep.as_mut().await,
        None => std::future::pending::<()>().await,
    }
}

fn capacity_denial(saw_full_endpoint: bool) -> Denial {
    if saw_full_endpoint {
        Denial::denied(GrpcStatus::ResourceExhausted, "endpoint_capacity")
    } else {
        Denial::denied(GrpcStatus::Unavailable, "no_healthy_endpoint")
    }
}

/// Maps an egress failure onto a gRPC status.
///
/// Every input is already a bounded category: `EgressError::Grpc` carries a
/// `GrpcFailure` and nothing else, and the policy variants carry values that are
/// never rendered here. The reason string returned is `error.safe_category()`,
/// which is the same bounded vocabulary the HTTP proxy path records.
fn egress_denial(error: &egress::EgressError) -> Denial {
    let status = match error {
        // A destination the egress policy refuses is a gateway configuration
        // outcome, not something the caller can fix by retrying.
        egress::EgressError::HostNotAllowed(_)
        | egress::EgressError::PortNotAllowed(_)
        | egress::EgressError::NonGlobalIpBlocked(_)
        | egress::EgressError::InvalidPolicy(_)
        | egress::EgressError::InvalidUrl(_)
        | egress::EgressError::SchemeNotAllowed(_)
        | egress::EgressError::InvalidTlsCaBundle { .. }
        | egress::EgressError::InvalidTlsClientIdentity => GrpcStatus::Internal,
        egress::EgressError::RequestBodyTooLarge { .. }
        | egress::EgressError::ResponseTooLarge { .. } => GrpcStatus::ResourceExhausted,
        egress::EgressError::RequestBodyReadFailed => GrpcStatus::InvalidArgument,
        // Every transport failure is UNAVAILABLE, including the connect budget
        // elapsing. `DEADLINE_EXCEEDED` is reserved for the CALLER's deadline,
        // which `ClientResponseBody` owns: a client with a sixty-second
        // deadline that was told `DEADLINE_EXCEEDED` after the gateway's own
        // half-second connect budget would be told something false.
        _ => GrpcStatus::Unavailable,
    };

    Denial::failed(status, error.safe_category())
}

/// The upstream's `content-type`, if it is one this gateway serves.
fn grpc_response_content_type(headers: &HeaderMap) -> Option<HeaderValue> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let value = value.to_str().ok()?;
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim_matches(|character: char| character.is_ascii_whitespace());

    protocol::GRPC_CONTENT_TYPES
        .iter()
        .find(|allowed| media_type.eq_ignore_ascii_case(allowed))
        .map(|allowed| HeaderValue::from_static(allowed))
}

/// Builds the upstream request metadata.
///
/// Starts from `forward::attempt_headers`, which is the same function the HTTP
/// data plane uses, so this transport cannot develop its own idea of what is
/// safe to forward. That already removes every hop-by-hop header, every header
/// nominated by `Connection`, `Host`, `Content-Length`, the client's
/// `Authorization` and `Cookie`, the gateway request ID, and every spoofable
/// client-IP forwarding header, then applies the route's own add/strip policy.
///
/// On top of that:
/// * `content-type` is the canonical constant matched in `protocol`, not the
///   caller's bytes;
/// * `te: trailers` is stated by the gateway rather than forwarded;
/// * `grpc-timeout` is the gateway's capped deadline, never the client's value;
/// * `grpc-status` and `grpc-message` are removed -- they are response metadata
///   and a request carrying them is trying to talk past the gateway;
/// * `:authority` is not here at all. It is derived by `egress::grpc` from the
///   validated destination, which is the only reason the gateway can be said to
///   own it.
fn upstream_call_headers(
    parts: &Parts,
    source_ip: &str,
    upstream: &MatchedUpstream,
    content_type: &HeaderValue,
    deadline: Option<Duration>,
    max_metadata_entries: usize,
) -> Result<HeaderMap, Denial> {
    let mut headers = forward::attempt_headers(
        &parts.headers,
        source_ip,
        &upstream.request_header_policy,
        &[],
    );
    headers.remove(GRPC_STATUS);
    headers.remove(GRPC_MESSAGE);
    headers.remove(GRPC_TIMEOUT);
    headers.insert(CONTENT_TYPE, content_type.clone());
    headers.insert(header::TE, HeaderValue::from_static("trailers"));
    if let Some(deadline) = deadline {
        headers.insert(GRPC_TIMEOUT, grpc_timeout_header(deadline));
    }
    // `grpc-encoding` and `grpc-accept-encoding` are deliberately NOT touched.
    // Compression is end-to-end in gRPC: the gateway neither compresses nor
    // decompresses, so whatever the client negotiated crosses opaquely. Both
    // survive `attempt_headers` on their own; there is nothing to do here.

    // Route policy can ADD headers, so the count is rechecked after it runs.
    // Checking only the inbound count would let a route configuration push the
    // upstream over a limit the operator believed was enforced.
    if headers.iter().count() > max_metadata_entries {
        return Err(Denial::denied(
            GrpcStatus::ResourceExhausted,
            "request_metadata_entries",
        ));
    }

    Ok(headers)
}

/// The `grpc-timeout` units, coarsest first, with their nanosecond size.
const TIMEOUT_UNITS: [(u128, &str); 6] = [
    (3_600_000_000_000, "H"),
    (60_000_000_000, "M"),
    (1_000_000_000, "S"),
    (1_000_000, "m"),
    (1_000, "u"),
    (1, "n"),
];

/// Renders a duration as a `grpc-timeout` value.
///
/// The specification allows at most eight digits and one unit character, so not
/// every duration can be expressed in every unit. The unit chosen is the
/// coarsest one that both divides the duration exactly and fits -- so a
/// five-second deadline is sent as `5S` rather than `5000000u`, which is the
/// same instant expressed the way a human reading the upstream's logs would
/// write it.
///
/// When no unit divides exactly, the finest one that fits is used and the value
/// is rounded UP. Up rather than down because rounding a deadline down would
/// cancel a call the caller was still entitled to make; the excess is at most
/// one unit of the finest representable resolution.
fn grpc_timeout_header(deadline: Duration) -> HeaderValue {
    const MAX_VALUE: u128 = 99_999_999;
    let nanos = deadline.as_nanos();

    for (divisor, unit) in TIMEOUT_UNITS {
        let value = nanos / divisor;
        if nanos.is_multiple_of(divisor) && value <= MAX_VALUE && value > 0 {
            return timeout_value(value, unit);
        }
    }
    for (divisor, unit) in TIMEOUT_UNITS.into_iter().rev() {
        let value = nanos.div_ceil(divisor);
        if value <= MAX_VALUE {
            return timeout_value(value, unit);
        }
    }

    // Unreachable for any duration a validated route can produce: the ceiling
    // is capped at seven days, which is 168 hours.
    HeaderValue::from_static("99999999H")
}

fn timeout_value(value: u128, unit: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("{value}{unit}"))
        .unwrap_or(HeaderValue::from_static("99999999H"))
}

/// Builds a gRPC trailers-only response.
///
/// A trailers-only response is HTTP 200 whose HEADERS frame carries the status
/// and ends the stream: it is how gRPC says "this call produced no messages and
/// here is why". Deliberately NOT an HTTP error status -- #257 requires that a
/// call refused before the upstream produce a protocol-correct answer rather
/// than a transport-level one a client would have to guess at.
///
/// The body is `Body::empty()` so hyper sets END_STREAM on the HEADERS frame,
/// which is what makes it trailers-only rather than a zero-length message.
fn trailers_only_response(
    status: GrpcStatus,
    reason: &'static str,
    request_id: &Option<HeaderValue>,
) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, GRPC_CONTENT_TYPE);
    headers.insert(GRPC_STATUS, status.header_value());
    headers.insert(GRPC_MESSAGE, bounded_message(reason));
    if let Some(request_id) = request_id {
        headers.insert(forward::request_id_header(), request_id.clone());
    }
    response.extensions_mut().insert(GrpcShapedResponse);
    response
}

/// Turns a bounded reason literal into a `grpc-message`.
///
/// Every caller passes a `&'static str` from this crate, all of which are
/// lowercase ASCII and therefore need no percent-encoding. The fallback exists
/// so a future literal with an unexpected byte degrades to a constant instead of
/// panicking inside a response path.
fn bounded_message(reason: &'static str) -> HeaderValue {
    HeaderValue::from_str(reason).unwrap_or(HeaderValue::from_static("internal"))
}

/// The outermost layer on the gRPC listener's router.
///
/// The gRPC listener runs the identical middleware stack as the HTTP data
/// listener -- the same `apply_middleware` call with the same value -- which is
/// what makes "a gRPC call is subject to exactly the decisions an HTTP request
/// is" a fact about the wiring rather than a claim. The cost is that those
/// middlewares answer in HTTP: a 401 with a JSON body, not a gRPC status.
///
/// This layer converts anything that is not already gRPC-shaped into a
/// trailers-only response, and drops the original body. Dropping it is
/// deliberate: a gRPC client would read those JSON bytes as a length-prefixed
/// message and mis-frame the stream, and the status it needs is in the headers
/// either way.
pub(crate) async fn shape_response(
    request: Request<Body>,
    next: axum::middleware::Next,
) -> Response {
    let response = next.run(request).await;
    if response.extensions().get::<GrpcShapedResponse>().is_some() {
        return response;
    }

    let status = grpc_status_for_http_status(response.status());
    let request_id = response.headers().get(forward::REQUEST_ID_HEADER).cloned();
    let mut shaped = trailers_only_response(status, status.as_str(), &request_id);
    // Preserve the decision extension so the observation layer above still sees
    // what the inner stack decided.
    if let Some(outcome) = response
        .extensions()
        .get::<middleware::decision::UpstreamOutcome>()
        .cloned()
    {
        shaped.extensions_mut().insert(outcome);
    }

    shaped
}

// ---------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------

/// Byte and message counters shared by both directions of one call.
#[derive(Default)]
struct CallBytesCounters {
    request_bytes: AtomicU64,
    request_messages: AtomicU64,
    response_bytes: AtomicU64,
    response_messages: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default)]
struct CallBytes {
    request_bytes: u64,
    request_messages: u64,
    response_bytes: u64,
    response_messages: u64,
}

impl CallBytesCounters {
    fn snapshot(&self) -> CallBytes {
        CallBytes {
            request_bytes: self.request_bytes.load(Ordering::Relaxed),
            request_messages: self.request_messages.load(Ordering::Relaxed),
            response_bytes: self.response_bytes.load(Ordering::Relaxed),
            response_messages: self.response_messages.load(Ordering::Relaxed),
        }
    }
}

/// A terminal status decided by one half of the call, readable by the other.
///
/// The request half runs inside hyper's own body machinery: when it trips a
/// bound it can only fail the body, which reaches the upstream as a stream
/// reset and comes back to the response half as an opaque transport error. Then
/// the client would be told "the connection broke" for what was actually "your
/// message was too large". Recording the real reason here lets the response
/// half report it.
#[derive(Default)]
struct CallFault(Mutex<Option<(GrpcStatus, &'static str)>>);

impl CallFault {
    fn record(&self, status: GrpcStatus, reason: &'static str) {
        let mut slot = match self.0.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        // First fault wins: it is the one that caused everything after it.
        if slot.is_none() {
            *slot = Some((status, reason));
        }
    }

    fn take(&self) -> Option<(GrpcStatus, &'static str)> {
        match self.0.lock() {
            Ok(mut slot) => slot.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        }
    }
}

/// The client's request body, bounded and counted on its way upstream.
///
/// Message bytes are counted and forwarded, never inspected: the only thing
/// read out of a chunk is the five-byte length-prefix envelope.
struct UpstreamRequestBody {
    inner: Body,
    framer: MessageFramer,
    max_message_bytes: usize,
    max_bytes: Option<u64>,
    sent: u64,
    counters: Arc<CallBytesCounters>,
    fault: Arc<CallFault>,
}

impl HttpBody for UpstreamRequestBody {
    type Data = Bytes;
    type Error = egress::EgressError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        loop {
            let polled = Pin::new(&mut self.inner).poll_frame(context);
            return match polled {
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => {
                    if self.framer.finish().is_err() {
                        self.fault
                            .record(GrpcStatus::Internal, "request_framing_truncated");
                        return Poll::Ready(Some(Err(egress::EgressError::Grpc(
                            egress::GrpcFailure::Protocol,
                        ))));
                    }
                    Poll::Ready(None)
                }
                Poll::Ready(Some(Err(_))) => {
                    // The client's own body failed. Its text is hyper's and is
                    // never recorded or forwarded.
                    self.fault
                        .record(GrpcStatus::Cancelled, "request_body_read_failed");
                    Poll::Ready(Some(Err(egress::EgressError::RequestBodyReadFailed)))
                }
                Poll::Ready(Some(Ok(frame))) => {
                    let Ok(data) = frame.into_data() else {
                        // A gRPC request carries no trailers. Forwarding
                        // unvalidated ones would be a metadata-injection channel
                        // that bypasses every header rule above, so they are
                        // dropped and the stream continues.
                        continue;
                    };
                    let length = u64::try_from(data.len()).unwrap_or(u64::MAX);
                    self.sent = self.sent.saturating_add(length);
                    if self.max_bytes.is_some_and(|maximum| self.sent > maximum) {
                        self.fault
                            .record(GrpcStatus::ResourceExhausted, "request_bytes");
                        return Poll::Ready(Some(Err(egress::EgressError::RequestBodyTooLarge {
                            size: usize::try_from(self.sent).unwrap_or(usize::MAX),
                            max: usize::try_from(self.max_bytes.unwrap_or(u64::MAX))
                                .unwrap_or(usize::MAX),
                        })));
                    }
                    let max_message_bytes = self.max_message_bytes;
                    match self.framer.observe(&data, max_message_bytes) {
                        Ok(completed) => {
                            self.counters
                                .request_messages
                                .fetch_add(completed, Ordering::Relaxed);
                        }
                        Err(FramingError::MessageTooLarge) => {
                            self.fault
                                .record(GrpcStatus::ResourceExhausted, "request_message_bytes");
                            return Poll::Ready(Some(Err(
                                egress::EgressError::RequestBodyTooLarge {
                                    size: max_message_bytes.saturating_add(1),
                                    max: max_message_bytes,
                                },
                            )));
                        }
                        Err(FramingError::Truncated) => {
                            self.fault
                                .record(GrpcStatus::Internal, "request_framing_truncated");
                            return Poll::Ready(Some(Err(egress::EgressError::Grpc(
                                egress::GrpcFailure::Protocol,
                            ))));
                        }
                    }
                    self.counters
                        .request_bytes
                        .fetch_add(length, Ordering::Relaxed);
                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
            };
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        // Deliberately unknown. The inner hint describes the CLIENT's body, and
        // this body drops trailers, so promising hyper an exact length that the
        // forwarded frames might not add up to would be worse than saying
        // nothing.
        SizeHint::default()
    }
}

/// The upstream's response body, bounded, deadline-aware, and terminated with a
/// gRPC status under every exit path.
struct ClientResponseBody {
    inner: Option<egress::GrpcResponseBody>,
    framer: MessageFramer,
    max_message_bytes: usize,
    max_bytes: Option<u64>,
    received: u64,
    counters: Arc<CallBytesCounters>,
    fault: Arc<CallFault>,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    idle: Option<(Duration, Pin<Box<tokio::time::Sleep>>)>,
    shutdown: Pin<Box<dyn Future<Output = ()> + Send>>,
    max_metadata_entries: usize,
    finished: bool,
    guard: Option<CallGuard>,
}

impl ClientResponseBody {
    /// Ends the call with gateway-generated trailers.
    ///
    /// Dropping `inner` here is what propagates cancellation upstream: releasing
    /// the h2 response body sends RST_STREAM, so a deadline, an idle timeout, a
    /// bound, or a forced shutdown all stop the upstream from producing more.
    fn terminate(&mut self, status: GrpcStatus, reason: &'static str) -> Frame<Bytes> {
        // A fault recorded by the request half is the cause of anything the
        // response half observed afterwards, so it wins.
        let (status, reason) = self.fault.take().unwrap_or((status, reason));
        self.inner = None;
        self.finished = true;
        if let Some(guard) = self.guard.as_ref() {
            guard.set_outcome(
                if status == GrpcStatus::Ok {
                    "completed"
                } else {
                    "failed"
                },
                reason,
                status,
            );
        }

        let mut trailers = HeaderMap::new();
        trailers.insert(GRPC_STATUS, status.header_value());
        trailers.insert(GRPC_MESSAGE, bounded_message(reason));

        Frame::trailers(trailers)
    }

    /// Sanitises the upstream's trailers before they reach the client.
    ///
    /// The upstream's `grpc-status` and `grpc-message` are preserved verbatim --
    /// that is the entire point of proxying gRPC rather than terminating it --
    /// but hop-by-hop names are stripped on the way out exactly as they are on
    /// the way in, and the entry count is bounded. An upstream missing
    /// `grpc-status` is a protocol violation and is replaced rather than
    /// forwarded, because a client that sees no status has no way to tell a
    /// success from a truncation.
    fn sanitize_trailers(&mut self, trailers: HeaderMap) -> Frame<Bytes> {
        if let Some((status, reason)) = self.fault.take() {
            return self.terminate(status, reason);
        }
        if trailers.iter().count() > self.max_metadata_entries {
            return self.terminate(GrpcStatus::ResourceExhausted, "response_metadata_entries");
        }
        if self.framer.finish().is_err() {
            return self.terminate(GrpcStatus::Internal, "response_framing_truncated");
        }

        let mut sanitized = HeaderMap::with_capacity(trailers.len());
        for (name, value) in &trailers {
            if is_forbidden_metadata(name) {
                continue;
            }
            sanitized.append(name.clone(), value.clone());
        }
        let Some(status) = sanitized.get(GRPC_STATUS) else {
            return self.terminate(GrpcStatus::Internal, "upstream_missing_grpc_status");
        };
        let status_label = upstream_status_label(status);

        self.inner = None;
        self.finished = true;
        if let Some(guard) = self.guard.as_ref() {
            guard.set_upstream_outcome(status_label);
        }

        Frame::trailers(sanitized)
    }
}

/// Names that must never be relayed from an upstream, in headers or trailers.
///
/// The hop-by-hop set plus the framing headers. A trailer section is still a
/// header block, so the same rule applies to both directions of the response:
/// an upstream that puts `transfer-encoding` or `connection` in either is
/// confused or probing, and `host` or `content-length` relayed onward would
/// describe the upstream's connection rather than the client's.
fn is_forbidden_metadata(name: &HeaderName) -> bool {
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

/// Sanitises the upstream's response headers -- gRPC's server initial metadata
/// -- before they reach the client.
///
/// Forwarding this is not optional transparency. `grpc-encoding` tells the
/// client how to decode the messages that follow, and everything else in there
/// is what the two ends are actually saying to each other; a proxy that dropped
/// it would break compression outright and silence application metadata in a
/// way no client can work around.
///
/// So it is relayed, under the same three rules the request direction follows:
/// the forbidden names are removed, the entry count is bounded, and
/// `content-type` is the gateway's canonical constant rather than the
/// upstream's bytes. `grpc-status` and `grpc-message` are removed here because
/// on a response that HAS a body they are response TRAILERS -- an upstream
/// putting them in the headers of a streaming response is describing an outcome
/// it cannot know yet, and relaying that would let a client read a status
/// before the messages it applies to. The trailers-only case, where they belong
/// in the headers, is handled separately by the caller.
fn sanitized_response_headers(
    upstream: &HeaderMap,
    content_type: HeaderValue,
    max_metadata_entries: usize,
) -> Result<HeaderMap, Denial> {
    if upstream.iter().count() > max_metadata_entries {
        return Err(Denial::failed(
            GrpcStatus::ResourceExhausted,
            "response_metadata_entries",
        ));
    }

    let mut headers = HeaderMap::with_capacity(upstream.len());
    for (name, value) in upstream {
        if is_forbidden_metadata(name) || name == CONTENT_TYPE {
            continue;
        }
        headers.append(name.clone(), value.clone());
    }
    headers.remove(GRPC_STATUS);
    headers.remove(GRPC_MESSAGE);
    headers.insert(CONTENT_TYPE, content_type);
    // Announce which trailers will follow, so an intermediary that honours
    // `Trailer` does not drop the status.
    headers.insert(
        header::TRAILER,
        HeaderValue::from_static("grpc-status, grpc-message"),
    );

    Ok(headers)
}

/// Relays an upstream Trailers-Only answer.
///
/// A gRPC server that has an outcome and no messages answers with the status in
/// the HEADERS frame and ends the stream there. That is a legitimate and common
/// shape -- it is how a server says `NOT_FOUND` -- so it is forwarded as what it
/// is, with the upstream's own `grpc-status` and `grpc-message` preserved.
/// Treating it as a streaming response instead would have the gateway wait for
/// trailers that are never coming and then report `INTERNAL` over the top of a
/// perfectly well-formed answer.
fn upstream_trailers_only_response(
    upstream: &HeaderMap,
    content_type: HeaderValue,
    max_metadata_entries: usize,
) -> Result<Response, Denial> {
    if upstream.iter().count() > max_metadata_entries {
        return Err(Denial::failed(
            GrpcStatus::ResourceExhausted,
            "response_metadata_entries",
        ));
    }

    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    for (name, value) in upstream {
        if is_forbidden_metadata(name) || name == CONTENT_TYPE {
            continue;
        }
        headers.append(name.clone(), value.clone());
    }
    headers.insert(CONTENT_TYPE, content_type);
    response.extensions_mut().insert(GrpcShapedResponse);

    Ok(response)
}

/// A bounded label for an upstream `grpc-status` value.
///
/// The header value is upstream-controlled, so it is never used as a metric
/// label directly. Recognised codes map to their canonical name and everything
/// else collapses to one bucket, which keeps cardinality at a constant.
fn upstream_status_label(value: &HeaderValue) -> &'static str {
    match value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
    {
        Some(0) => "ok",
        Some(1) => "cancelled",
        Some(2) => "unknown",
        Some(3) => "invalid_argument",
        Some(4) => "deadline_exceeded",
        Some(5) => "not_found",
        Some(6) => "already_exists",
        Some(7) => "permission_denied",
        Some(8) => "resource_exhausted",
        Some(9) => "failed_precondition",
        Some(10) => "aborted",
        Some(11) => "out_of_range",
        Some(12) => "unimplemented",
        Some(13) => "internal",
        Some(14) => "unavailable",
        Some(15) => "data_loss",
        Some(16) => "unauthenticated",
        _ => "other",
    }
}

impl HttpBody for ClientResponseBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    #[allow(clippy::too_many_lines)] // One state machine; splitting it hides the exits.
    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.finished {
            return Poll::Ready(None);
        }

        // Forced shutdown, the overall deadline, and the idle timeout are all
        // checked BEFORE the inner body, so a stalled upstream cannot starve
        // them by never becoming ready.
        if self.shutdown.as_mut().poll(context).is_ready() {
            let frame = self.terminate(GrpcStatus::Unavailable, "shutdown");
            return Poll::Ready(Some(Ok(frame)));
        }
        if let Some(deadline) = self.deadline.as_mut() {
            if deadline.as_mut().poll(context).is_ready() {
                let frame = self.terminate(GrpcStatus::DeadlineExceeded, "deadline_exceeded");
                return Poll::Ready(Some(Ok(frame)));
            }
        }
        if let Some((_, idle)) = self.idle.as_mut() {
            if idle.as_mut().poll(context).is_ready() {
                let frame = self.terminate(GrpcStatus::Unavailable, "idle_timeout");
                return Poll::Ready(Some(Ok(frame)));
            }
        }

        loop {
            let Some(inner) = self.inner.as_mut() else {
                self.finished = true;
                return Poll::Ready(None);
            };
            return match Pin::new(inner).poll_frame(context) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => {
                    // A gRPC response always ends with trailers. Ending without
                    // them is a protocol violation, and forwarding the silence
                    // would let a truncated stream read as a successful one.
                    let frame = self.terminate(GrpcStatus::Internal, "upstream_missing_trailers");
                    Poll::Ready(Some(Ok(frame)))
                }
                Poll::Ready(Some(Err(error))) => {
                    // A body error is a transport failure. The caller's own
                    // deadline is checked above and reported as
                    // `DEADLINE_EXCEEDED` there; nothing the transport reports
                    // may borrow that status.
                    let reason = error.safe_category();
                    let frame = self.terminate(GrpcStatus::Unavailable, reason);
                    Poll::Ready(Some(Ok(frame)))
                }
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some((idle, sleep)) = self.idle.as_mut() {
                        let deadline = tokio::time::Instant::now() + *idle;
                        sleep.as_mut().reset(deadline);
                    }
                    let data = match frame.into_data() {
                        Ok(data) => data,
                        Err(frame) => {
                            return match frame.into_trailers() {
                                Ok(trailers) => {
                                    let frame = self.sanitize_trailers(trailers);
                                    Poll::Ready(Some(Ok(frame)))
                                }
                                // Neither data nor trailers: a frame kind this
                                // build does not know. Skipping it is the only
                                // safe reading; it carries no gRPC meaning.
                                Err(_) => continue,
                            };
                        }
                    };
                    // hyper emits a trailing ZERO-LENGTH DATA frame to carry
                    // END_STREAM. It is not a body chunk, and forwarding it
                    // would end the client's stream before the trailers.
                    if data.is_empty() {
                        continue;
                    }
                    let length = u64::try_from(data.len()).unwrap_or(u64::MAX);
                    self.received = self.received.saturating_add(length);
                    if self
                        .max_bytes
                        .is_some_and(|maximum| self.received > maximum)
                    {
                        let frame = self.terminate(GrpcStatus::ResourceExhausted, "response_bytes");
                        return Poll::Ready(Some(Ok(frame)));
                    }
                    let max_message_bytes = self.max_message_bytes;
                    match self.framer.observe(&data, max_message_bytes) {
                        Ok(completed) => {
                            self.counters
                                .response_messages
                                .fetch_add(completed, Ordering::Relaxed);
                        }
                        Err(FramingError::MessageTooLarge) => {
                            let frame = self
                                .terminate(GrpcStatus::ResourceExhausted, "response_message_bytes");
                            return Poll::Ready(Some(Ok(frame)));
                        }
                        Err(FramingError::Truncated) => {
                            let frame =
                                self.terminate(GrpcStatus::Internal, "response_framing_truncated");
                            return Poll::Ready(Some(Ok(frame)));
                        }
                    }
                    self.counters
                        .response_bytes
                        .fetch_add(length, Ordering::Relaxed);
                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
            };
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished
    }
}

// ---------------------------------------------------------------------------
// Reservations and telemetry
// ---------------------------------------------------------------------------

/// Owns every reservation one established call holds.
///
/// Dropping it releases the admission permit, the per-endpoint call slot, the
/// shutdown tracker token, and the active-calls gauge together, and emits the
/// call's terminal telemetry. A stream that ends normally and a client that
/// disappears mid-stream therefore take the same code path -- the second one
/// simply has no recorded outcome, which is exactly what "the client cancelled"
/// looks like.
struct CallGuard {
    audit: audit::AuditLog,
    request_id: String,
    source_ip: String,
    pool_id: Arc<str>,
    endpoint_id: Arc<str>,
    method: String,
    deadline_ms: Option<u64>,
    client_deadline: bool,
    started: Instant,
    counters: Arc<CallBytesCounters>,
    outcome: Mutex<Option<(&'static str, &'static str, &'static str)>>,
    _admission: admission::PoolAdmissionPermit,
    _endpoint_slot: OwnedSemaphorePermit,
    _registration: tokio_util::task::task_tracker::TaskTrackerToken,
}

impl CallGuard {
    fn set_outcome(&self, result: &'static str, reason: &'static str, status: GrpcStatus) {
        self.store((result, reason, status.as_str()));
    }

    fn set_upstream_outcome(&self, status_label: &'static str) {
        self.store(("allowed", "upstream_status", status_label));
    }

    fn store(&self, outcome: (&'static str, &'static str, &'static str)) {
        let mut slot = match self.outcome.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        if slot.is_none() {
            *slot = Some(outcome);
        }
    }
}

impl Drop for CallGuard {
    fn drop(&mut self) {
        ::metrics::gauge!(
            metric_names::PROXY_GRPC_ACTIVE_CALLS,
            "pool_id" => Arc::clone(&self.pool_id),
            "endpoint_id" => Arc::clone(&self.endpoint_id)
        )
        .decrement(1.0);

        let (result, reason, status) = match self.outcome.lock() {
            Ok(slot) => *slot,
            Err(poisoned) => *poisoned.into_inner(),
        }
        // No recorded outcome means the body was dropped before it terminated,
        // which is the client going away mid-call.
        .unwrap_or(("failed", "client_cancelled", GrpcStatus::Cancelled.as_str()));

        let trace = CallTrace {
            pool_id: Some(Arc::clone(&self.pool_id)),
            endpoint_id: Some(Arc::clone(&self.endpoint_id)),
            method: Some(self.method.clone()),
            deadline_ms: self.deadline_ms,
            client_deadline: self.client_deadline,
        };
        record_call_outcome_with_status_label(
            &self.audit,
            &trace,
            &self.request_id,
            &self.source_ip,
            result,
            reason,
            status,
            self.counters.snapshot(),
            self.started.elapsed(),
        );
    }
}

#[allow(clippy::too_many_arguments)] // One argument per independently recorded fact.
fn record_call_outcome(
    audit_log: &audit::AuditLog,
    trace: &CallTrace,
    request_id: &str,
    source_ip: &str,
    result: &'static str,
    reason: &'static str,
    status: GrpcStatus,
    bytes: CallBytes,
    duration: Duration,
) {
    record_call_outcome_with_status_label(
        audit_log,
        trace,
        request_id,
        source_ip,
        result,
        reason,
        status.as_str(),
        bytes,
        duration,
    );
}

/// Emits one call's metrics and audit event.
///
/// Every metric label here is a constant or a configured identifier: `pool_id`
/// and `endpoint_id` come from configuration, and `result`, `reason` and
/// `status` are `&'static str` literals from this crate. The METHOD identity is
/// deliberately absent from the labels and present only in the audit payload,
/// because its cardinality is chosen by the caller -- and it appears there only
/// when it passed the grammar.
#[allow(clippy::too_many_arguments)] // One argument per independently recorded fact.
fn record_call_outcome_with_status_label(
    audit_log: &audit::AuditLog,
    trace: &CallTrace,
    request_id: &str,
    source_ip: &str,
    result: &'static str,
    reason: &'static str,
    status: &'static str,
    bytes: CallBytes,
    duration: Duration,
) {
    let pool_id = trace
        .pool_id
        .clone()
        .unwrap_or_else(|| Arc::from("unmatched"));
    ::metrics::counter!(
        metric_names::PROXY_GRPC_CALLS_TOTAL,
        "pool_id" => Arc::clone(&pool_id),
        "result" => result,
        "reason" => reason,
        "status" => status
    )
    .increment(1);
    if let Some(endpoint_id) = trace.endpoint_id.clone() {
        let labels = [
            ("pool_id", pool_id.to_string()),
            ("endpoint_id", endpoint_id.to_string()),
            ("status", status.to_owned()),
        ];
        ::metrics::histogram!(metric_names::PROXY_GRPC_CALL_DURATION_SECONDS, &labels)
            .record(duration.as_secs_f64());
        for (direction, messages, byte_count) in [
            (
                "client_to_upstream",
                bytes.request_messages,
                bytes.request_bytes,
            ),
            (
                "upstream_to_client",
                bytes.response_messages,
                bytes.response_bytes,
            ),
        ] {
            let labels = [
                ("pool_id", pool_id.to_string()),
                ("endpoint_id", endpoint_id.to_string()),
                ("direction", direction.to_owned()),
            ];
            ::metrics::counter!(metric_names::PROXY_GRPC_MESSAGES_TOTAL, &labels)
                .increment(messages);
            ::metrics::counter!(metric_names::PROXY_GRPC_BYTES_TOTAL, &labels)
                .increment(byte_count);
        }
    }

    audit_log.emit(audit::AuditEvent::new(
        audit::event::UPSTREAM_GRPC_CALL,
        request_id.to_owned(),
        source_ip.to_owned(),
        None::<audit::Actor>,
        json!({
            "pool_id": trace.pool_id,
            "endpoint_id": trace.endpoint_id,
            "method": trace.method,
            "result": result,
            "reason": reason,
            "grpc_status": status,
            "client_deadline": trace.client_deadline,
            "deadline_ms": trace.deadline_ms,
            "messages_client_to_upstream": bytes.request_messages,
            "messages_upstream_to_client": bytes.response_messages,
            "bytes_client_to_upstream": bytes.request_bytes,
            "bytes_upstream_to_client": bytes.response_bytes,
            "duration_ms": crate::duration_millis(duration),
        }),
    ));
}

/// The gRPC answer for a gateway with no proxy configured at all.
///
/// A 404 would leave a gRPC client guessing; `UNIMPLEMENTED` is the canonical
/// code for "this server does not serve that method".
pub(crate) fn unimplemented_response() -> Response {
    trailers_only_response(GrpcStatus::Unimplemented, "no_route", &None)
}

/// The gRPC answer for a request path this listener must never proxy.
///
/// The HTTP data listener answers the same two cases -- an unsafe raw path, and
/// a path inside the gateway's own reserved namespace -- with `404 Not Found`.
/// `UNIMPLEMENTED` is that answer in gRPC: this server does not serve that
/// method, and it is not going to ask anyone else whether they do.
///
/// `reason` is a `&'static str` from the caller, exactly as every other bounded
/// reason in this module is; nothing derived from the request is recorded.
pub(crate) fn not_proxyable_response(reason: &'static str) -> Response {
    trailers_only_response(GrpcStatus::Unimplemented, reason, &None)
}

impl ProxyState {
    pub(crate) async fn handle_grpc_call(
        &self,
        request: Request<Body>,
        source_ip: &str,
    ) -> Response {
        handle_call(self, request, source_ip).await
    }
}

/// Re-exported so `lifecycle` can bind and serve the listener without naming
/// the h2 server builder itself.
pub(crate) use listen::{GrpcListener, GrpcListenerLimits};
