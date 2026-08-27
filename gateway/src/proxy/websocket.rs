//! WebSocket proxying for routes that explicitly opt in.
//!
//! The gateway terminates both sides and re-originates the upgrade rather than
//! tunnelling bytes. Terminating is the only way to enforce a frame and message
//! bound, a subprotocol policy, and a close-code contract; a tunnel would make
//! the gateway a general-purpose relay whose payload it never inspects and
//! whose limits it cannot apply.
//!
//! The handshake is ordered so that every rejection reachable before the egress
//! step happens with zero DNS lookups, zero connections, and zero upstream
//! bytes. Nothing between the client's request and the upstream request crosses
//! the boundary unexamined: the upstream handshake is built from validated
//! state, and the 101 returned to the client contains only gateway-generated
//! headers.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{
        ws::{
            CloseFrame as AxumCloseFrame, Message as AxumMessage, Utf8Bytes as AxumUtf8Bytes,
            WebSocket, WebSocketUpgrade,
        },
        FromRequestParts,
    },
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use http::{
    header, request::Parts, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Version,
};
use serde_json::json;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_tungstenite::{
    tungstenite::{
        self,
        handshake::{client::generate_key, derive_accept_key},
        protocol::{
            frame::coding::CloseCode as TungsteniteCloseCode, CloseFrame as TungsteniteCloseFrame,
            Role, WebSocketConfig,
        },
        Message as TungsteniteMessage, Utf8Bytes as TungsteniteUtf8Bytes,
    },
    WebSocketStream,
};
use tokio_util::sync::CancellationToken;

use super::{admission, forward, MatchedUpstream, ProxyState};
use crate::{audit, config, egress::EgressUpgradedStream, middleware};

/// RFC 6455 caps a control frame payload at 125 bytes, and a close frame spends
/// two of them on the status code.
const MAX_CLOSE_REASON_BYTES: usize = 123;
/// A bound on handshake parsing work. A client offering more subprotocols than
/// a route could ever allow is not making a good-faith offer.
const MAX_OFFERED_SUBPROTOCOLS: usize = 64;
/// How long a terminating connection may spend on its closing handshake before
/// the socket is simply dropped.
const CLOSE_GRACE: Duration = Duration::from_secs(5);
/// Per-direction read buffer. Eagerly allocated per connection and per side, so
/// it is deliberately far below tungstenite's 128 KiB default: a route may hold
/// thousands of idle sockets, and a large frame is read in several passes
/// rather than into one buffer.
const READ_BUFFER_BYTES: usize = 16 * 1024;
/// Largest RFC 6455 frame header: two prefix bytes, an eight-byte extended
/// length, and a four-byte mask.
const MAX_FRAME_HEADER_BYTES: usize = 14;

const CLOSE_NORMAL: u16 = 1000;
const CLOSE_GOING_AWAY: u16 = 1001;
const CLOSE_PROTOCOL_ERROR: u16 = 1002;
const CLOSE_TOO_LARGE: u16 = 1009;
const CLOSE_INTERNAL_ERROR: u16 = 1011;

const SEC_WEBSOCKET_PREFIX: &str = "sec-websocket-";

/// Per-route WebSocket runtime: the validated policy with its durations already
/// converted, plus the capacity this route may spend on upgraded connections.
///
/// Admission is deliberately a **separate** [`admission::PoolAdmission`] rather
/// than the route's HTTP one. An upgraded connection can hold its slot for an
/// hour; sharing `max_in_flight` with ordinary requests would let a handful of
/// sockets starve the route's entire HTTP traffic.
pub(super) struct RouteWebSocketRuntime {
    admission: admission::PoolAdmission,
    endpoint_slots: HashMap<Arc<str>, Arc<Semaphore>>,
    handshake_timeout: Duration,
    idle_timeout: Option<Duration>,
    max_duration: Option<Duration>,
    max_frame_bytes: usize,
    max_message_bytes: usize,
    max_write_buffer_bytes: usize,
    allowed_origins: Vec<String>,
    require_origin: bool,
    allowed_subprotocols: Vec<String>,
}

impl RouteWebSocketRuntime {
    pub(super) fn new(
        route_id: &str,
        websocket: &config::UpstreamWebSocketConfig,
        endpoint_ids: impl Iterator<Item = Arc<str>>,
    ) -> Self {
        // A distinguishable pool label keeps the WebSocket admission gauges and
        // rejection counters from being read as the route's HTTP admission.
        let admission_pool_id: Arc<str> = Arc::from(format!("{route_id}#ws"));
        let per_endpoint = websocket
            .max_connections_per_endpoint
            .unwrap_or(websocket.max_connections);

        Self {
            admission: admission::PoolAdmission::new(
                admission_pool_id,
                websocket.max_connections,
                websocket.queue_depth,
                Duration::from_millis(websocket.queue_timeout_ms),
            ),
            endpoint_slots: endpoint_ids
                .map(|id| (id, Arc::new(Semaphore::new(per_endpoint))))
                .collect(),
            handshake_timeout: Duration::from_millis(websocket.handshake_timeout_ms),
            idle_timeout: (websocket.idle_timeout_ms != 0)
                .then(|| Duration::from_millis(websocket.idle_timeout_ms)),
            max_duration: (websocket.max_duration_ms != 0)
                .then(|| Duration::from_millis(websocket.max_duration_ms)),
            max_frame_bytes: websocket.max_frame_bytes,
            max_message_bytes: websocket.max_message_bytes,
            max_write_buffer_bytes: websocket.max_write_buffer_bytes,
            allowed_origins: websocket.allowed_origins.clone(),
            require_origin: websocket.require_origin,
            allowed_subprotocols: websocket.allowed_subprotocols.clone(),
        }
    }

    /// Takes an endpoint slot without ever queueing.
    ///
    /// Endpoint capacity is probed, not waited on: the caller reselects around a
    /// full endpoint, and waiting here would hold the route-level admission slot
    /// while doing it.
    fn try_acquire_endpoint_slot(&self, endpoint_id: &Arc<str>) -> Option<OwnedSemaphorePermit> {
        Arc::clone(self.endpoint_slots.get(endpoint_id)?)
            .try_acquire_owned()
            .ok()
    }

    /// The frame, message, and write-buffer bounds, applied identically to both
    /// sides of the bridge.
    ///
    /// `write_buffer_size` is zero so a forwarded message is written eagerly
    /// instead of waiting for a buffer to fill, which a proxy has no reason to
    /// do. The write-buffer ceiling is the configured budget *plus* one legal
    /// message, because tungstenite refuses to buffer a frame larger than the
    /// ceiling even when the buffer is empty: a route that permits a
    /// four-megabyte message and a smaller write buffer would otherwise be
    /// unable to forward any message it explicitly allows.
    fn socket_config(&self) -> WebSocketConfig {
        WebSocketConfig::default()
            .read_buffer_size(READ_BUFFER_BYTES.min(self.max_frame_bytes))
            .write_buffer_size(0)
            .max_write_buffer_size(
                self.max_write_buffer_bytes
                    .saturating_add(self.max_message_bytes)
                    .saturating_add(MAX_FRAME_HEADER_BYTES),
            )
            .max_message_size(Some(self.max_message_bytes))
            .max_frame_size(Some(self.max_frame_bytes))
    }
}

/// Whether a request on a WebSocket-enabled route is shaped like an upgrade.
///
/// Deliberately lenient: anything that is not upgrade-shaped continues down the
/// ordinary HTTP path completely unchanged, and anything that is gets the full
/// bounded validation below rather than being forwarded as a plain request.
pub(super) fn is_websocket_upgrade(parts: &Parts) -> bool {
    parts.method == Method::GET
        && header_nominates_token(&parts.headers, header::CONNECTION, "upgrade")
        && header_nominates_token(&parts.headers, header::UPGRADE, "websocket")
}

/// A refused handshake, carrying only a bounded category.
#[derive(Debug)]
struct Denial {
    status: StatusCode,
    error: &'static str,
    reason: &'static str,
    /// `denied` is a policy decision about the client; `failed` is the upstream
    /// or the gateway not completing the handshake.
    result: &'static str,
    upgrade_required: bool,
}

impl Denial {
    fn denied(status: StatusCode, error: &'static str, reason: &'static str) -> Self {
        Self {
            status,
            error,
            reason,
            result: "denied",
            upgrade_required: false,
        }
    }

    fn failed(status: StatusCode, error: &'static str, reason: &'static str) -> Self {
        Self {
            status,
            error,
            reason,
            result: "failed",
            upgrade_required: false,
        }
    }
}

/// Bounded facts about one handshake, all of them safe to record.
#[derive(Default)]
struct HandshakeTrace {
    endpoint_id: Option<Arc<str>>,
    /// Config-bounded, so recording it cannot leak caller-controlled text.
    subprotocol: Option<String>,
    origin_present: bool,
    origin_allowed: bool,
}

pub(super) async fn handle_upgrade(
    proxy: &ProxyState,
    parts: Parts,
    upstream: &MatchedUpstream,
    runtime: &Arc<RouteWebSocketRuntime>,
    source_ip: &str,
) -> Response {
    let started = Instant::now();
    let request_id = parts.headers.get(forward::REQUEST_ID_HEADER).cloned();
    let request_id_text = request_id
        .as_ref()
        .and_then(|value| value.to_str().ok())
        .unwrap_or("unknown")
        .to_owned();
    let pool_id = Arc::clone(&upstream.pool.id);
    let mut trace = HandshakeTrace::default();

    let outcome = attempt_upgrade(
        proxy,
        parts,
        upstream,
        runtime,
        source_ip,
        &mut trace,
        request_id.clone(),
    )
    .await;

    let (result, reason) = match &outcome {
        Ok(_) => ("allowed", "ok"),
        Err(denial) => (denial.result, denial.reason),
    };
    ::metrics::counter!(
        crate::metrics::PROXY_WEBSOCKET_HANDSHAKES_TOTAL,
        "pool_id" => Arc::clone(&pool_id),
        "result" => result,
        "reason" => reason
    )
    .increment(1);
    proxy.audit.emit(audit::AuditEvent::new(
        audit::event::UPSTREAM_WEBSOCKET_HANDSHAKE,
        request_id_text,
        source_ip.to_owned(),
        None::<audit::Actor>,
        json!({
            "pool_id": pool_id,
            "endpoint_id": trace.endpoint_id,
            "result": result,
            "reason": reason,
            "subprotocol": trace.subprotocol,
            "origin_present": trace.origin_present,
            "origin_allowed": trace.origin_allowed,
            "duration_ms": crate::duration_millis(started.elapsed()),
        }),
    ));

    match outcome {
        Ok(response) => response,
        Err(denial) => denial_response(
            &denial,
            &pool_id,
            trace.endpoint_id.as_deref(),
            request_id,
            started.elapsed(),
        ),
    }
}

#[allow(clippy::too_many_lines)]
async fn attempt_upgrade(
    proxy: &ProxyState,
    mut parts: Parts,
    upstream: &MatchedUpstream,
    runtime: &Arc<RouteWebSocketRuntime>,
    source_ip: &str,
    trace: &mut HandshakeTrace,
    request_id: Option<HeaderValue>,
) -> Result<Response, Denial> {
    // 1. Local protocol validation. Nothing here can reach the network.
    validate_local_protocol(&parts)?;

    // 2. Origin policy, fail closed.
    let origin = evaluate_origin(&parts.headers, runtime, trace)?;

    // 3. Subprotocol policy, fail closed.
    let offered_subprotocol = negotiate_subprotocol(&parts.headers, runtime)?;
    trace.subprotocol = offered_subprotocol.clone();

    // Extracting the upgrade is local: it only takes the pending upgrade out of
    // the request's own extensions. Doing it before any egress means a request
    // this server could never upgrade never opens an upstream connection.
    let client_upgrade = WebSocketUpgrade::from_request_parts(&mut parts, &())
        .await
        .map_err(|_| {
            Denial::failed(StatusCode::BAD_REQUEST, "invalid_upgrade", "not_upgradable")
        })?;

    // 4. Lifecycle gate, mirroring the ordinary forwarding path.
    let Some(registration) = proxy.lifecycle.try_register_response_stream() else {
        return Err(shutdown_denial());
    };
    if proxy.lifecycle.draining() {
        return Err(shutdown_denial());
    }

    // 5. WebSocket admission, raced against background cancellation.
    let shutdown = proxy.lifecycle.background_cancellation();
    let admission_result = tokio::select! {
        biased;
        () = shutdown.cancelled_owned() => return Err(shutdown_denial()),
        result = runtime.admission.acquire() => result,
    };
    let admission_permit = admission_result.map_err(|error| {
        Denial::denied(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
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

    // 6. Endpoint selection with a per-endpoint slot. Probing for capacity here
    //    is pre-egress, so a full endpoint costs no upstream bytes and is not a
    //    retry of anything.
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
        crate::metrics::PROXY_ENDPOINT_SELECTIONS_TOTAL,
        "pool_id" => Arc::clone(&upstream.pool.id),
        "endpoint_id" => Arc::clone(&endpoint.id)
    )
    .increment(1);

    // 7. Build the upstream handshake from validated state only.
    let gateway_key = generate_key();
    let headers = upstream_handshake_headers(
        &parts,
        source_ip,
        upstream,
        &gateway_key,
        offered_subprotocol.as_deref(),
        origin.as_deref(),
    )?;
    let target_url = forward::proxy_target_url(&endpoint.upstream_origin, &parts.uri);

    // 8. Egress, inside the handshake budget. Exactly one attempt: an upgrade is
    //    never replayable once the upstream has begun answering it.
    let forced_shutdown = proxy.lifecycle.response_stream_cancellation();
    let egress_client = Arc::clone(&endpoint.egress_client);
    let handshake = async {
        let destination = egress_client.checked_destination(&target_url).await?;
        egress_client
            .upgrade_request_at_checked_destination(&destination, &target_url, headers)
            .await
    };
    let response = tokio::select! {
        biased;
        () = forced_shutdown.cancelled() => return Err(shutdown_denial()),
        response = tokio::time::timeout(runtime.handshake_timeout, handshake) => response,
    };
    let response = match response {
        Err(_) => {
            forward::record_circuit_failure(&mut circuit_permit, "handshake_timeout");
            if let Some(config) = endpoint.health_config.as_deref() {
                endpoint.health.record_passive_timeout(config).await;
            }
            return Err(Denial::failed(
                StatusCode::GATEWAY_TIMEOUT,
                "gateway_timeout",
                "handshake_timeout",
            ));
        }
        Ok(Err(error)) => {
            forward::record_circuit_failure(&mut circuit_permit, error.safe_category());
            if let Some(config) = endpoint.health_config.as_deref() {
                endpoint
                    .health
                    .record_passive_proxy_error(&error, config)
                    .await;
            }
            let timed_out = error.is_timeout();
            return Err(Denial::failed(
                if timed_out {
                    StatusCode::GATEWAY_TIMEOUT
                } else {
                    StatusCode::BAD_GATEWAY
                },
                if timed_out {
                    "gateway_timeout"
                } else {
                    "bad_gateway"
                },
                error.safe_category(),
            ));
        }
        Ok(Ok(response)) => response,
    };

    // 9. Validate the upstream answer fail closed. Its headers and body are
    //    dropped either way; none of them is ever forwarded.
    if response.status != StatusCode::SWITCHING_PROTOCOLS {
        forward::record_circuit_failure(&mut circuit_permit, "upstream_rejected");
        if let Some(config) = endpoint.health_config.as_deref() {
            endpoint
                .health
                .record_passive_status(response.status.as_u16(), config)
                .await;
        }
        return Err(Denial::failed(
            StatusCode::BAD_GATEWAY,
            "bad_gateway",
            "upstream_rejected",
        ));
    }
    let negotiated =
        match validate_upstream_handshake(&response.headers, &gateway_key, &offered_subprotocol) {
            Ok(negotiated) => negotiated,
            Err(reason) => {
                forward::record_circuit_failure(&mut circuit_permit, "upstream_handshake_invalid");
                if let Some(config) = endpoint.health_config.as_deref() {
                    endpoint
                        .health
                        .record_passive_failure("upstream_handshake_invalid", config)
                        .await;
                }
                return Err(Denial::failed(
                    StatusCode::BAD_GATEWAY,
                    "bad_gateway",
                    reason,
                ));
            }
        };
    trace.subprotocol.clone_from(&negotiated);

    let upgraded =
        match tokio::time::timeout(runtime.handshake_timeout, response.into_upgraded()).await {
            Ok(Ok(upgraded)) => upgraded,
            Ok(Err(_)) | Err(_) => {
                forward::record_circuit_failure(&mut circuit_permit, "upgrade_failed");
                if let Some(config) = endpoint.health_config.as_deref() {
                    endpoint
                        .health
                        .record_passive_failure("upgrade_failed", config)
                        .await;
                }
                return Err(Denial::failed(
                    StatusCode::BAD_GATEWAY,
                    "bad_gateway",
                    "upgrade_failed",
                ));
            }
        };

    // 10. Commit to the client. The 101 is built by axum from the request's own
    //     key; no upstream header reaches it.
    if let Some(config) = endpoint.health_config.as_deref() {
        endpoint
            .health
            .record_passive_status(StatusCode::SWITCHING_PROTOCOLS.as_u16(), config)
            .await;
    }
    forward::record_circuit_success(&mut circuit_permit);

    let socket_config = runtime.socket_config();
    let upstream_socket =
        WebSocketStream::from_raw_socket(upgraded, Role::Client, Some(socket_config)).await;

    let mut client_upgrade = client_upgrade
        .read_buffer_size(socket_config.read_buffer_size)
        .write_buffer_size(socket_config.write_buffer_size)
        .max_write_buffer_size(socket_config.max_write_buffer_size)
        .max_message_size(runtime.max_message_bytes)
        .max_frame_size(runtime.max_frame_bytes);
    if let Some(protocol) = negotiated.as_deref() {
        let value = HeaderValue::from_str(protocol)
            .expect("a validated subprotocol token is a valid header value");
        client_upgrade.set_selected_protocol(value);
    }

    // 11. One guard owns every reservation, so both a running bridge and a
    //     client upgrade that never completes release identically.
    let guard = ConnectionGuard::new(
        Arc::clone(&upstream.pool.id),
        Arc::clone(&endpoint.id),
        admission_permit,
        endpoint_slot,
        registration,
    );
    let context = BridgeContext {
        audit: proxy.audit.clone(),
        request_id: request_id
            .as_ref()
            .and_then(|value| value.to_str().ok())
            .unwrap_or("unknown")
            .to_owned(),
        source_ip: source_ip.to_owned(),
        pool_id: Arc::clone(&upstream.pool.id),
        endpoint_id: Arc::clone(&endpoint.id),
        subprotocol: negotiated,
        idle_timeout: runtime.idle_timeout,
        max_duration: runtime.max_duration,
        forced_shutdown,
    };
    let failed_upgrade_context = context.clone();
    let mut response = client_upgrade
        .on_failed_upgrade(move |_error| {
            // The error carries hyper's own text; only the category is recorded.
            failed_upgrade_context.finish(
                Termination::gateway("client_upgrade_failed", CLOSE_INTERNAL_ERROR),
                BridgeCounters::default(),
                Duration::ZERO,
            );
        })
        .on_upgrade(move |client| bridge(client, upstream_socket, context, guard));

    response
        .extensions_mut()
        .insert(middleware::decision::UpstreamOutcome {
            latency_ms: 0,
            status: Some(StatusCode::SWITCHING_PROTOCOLS.as_u16()),
            pool_id: Some(upstream.pool.id.to_string()),
            endpoint_id: Some(endpoint.id.to_string()),
            attempts: Vec::new(),
            retry_exhausted: false,
            stream_terminal_pending: true,
        });
    if let Some(request_id) = request_id {
        response
            .headers_mut()
            .insert(forward::request_id_header(), request_id);
    }

    Ok(response)
}

fn shutdown_denial() -> Denial {
    Denial::denied(
        StatusCode::SERVICE_UNAVAILABLE,
        "service_unavailable",
        "shutdown",
    )
}

fn capacity_denial(saw_full_endpoint: bool) -> Denial {
    Denial::denied(
        StatusCode::SERVICE_UNAVAILABLE,
        "service_unavailable",
        if saw_full_endpoint {
            "endpoint_capacity"
        } else {
            "no_healthy_endpoint"
        },
    )
}

fn denial_response(
    denial: &Denial,
    pool_id: &Arc<str>,
    endpoint_id: Option<&str>,
    request_id: Option<HeaderValue>,
    latency: Duration,
) -> Response {
    let mut response = (denial.status, Json(json!({ "error": denial.error }))).into_response();
    if denial.upgrade_required {
        response.headers_mut().insert(
            header::SEC_WEBSOCKET_VERSION,
            HeaderValue::from_static("13"),
        );
    }
    response
        .extensions_mut()
        .insert(middleware::decision::UpstreamOutcome {
            latency_ms: crate::duration_millis(latency),
            status: None,
            pool_id: Some(pool_id.to_string()),
            endpoint_id: endpoint_id.map(str::to_owned),
            attempts: Vec::new(),
            retry_exhausted: false,
            stream_terminal_pending: false,
        });
    if let Some(request_id) = request_id {
        response
            .headers_mut()
            .insert(forward::request_id_header(), request_id);
    }
    tracing::info!(
        pool_id = pool_id.as_ref(),
        error_category = denial.reason,
        "websocket upgrade refused"
    );

    response
}

/// Validates the parts of the handshake that need no policy and no network.
///
/// Done by hand rather than by leaning on the extractor so that each refusal
/// carries its own bounded category, and so that a request the extractor would
/// have accepted loosely -- `Upgrade: websocket, h2c`, a duplicated version
/// header -- is refused rather than half-understood.
fn validate_local_protocol(parts: &Parts) -> Result<(), Denial> {
    // RFC 8441 extended CONNECT over HTTP/2 is explicitly out of scope.
    if parts.version != Version::HTTP_11 {
        return Err(Denial::denied(
            StatusCode::BAD_REQUEST,
            "invalid_upgrade",
            "http_version",
        ));
    }
    let connection = single_header(&parts.headers, header::CONNECTION)
        .map_err(|()| malformed_upgrade())?
        .ok_or_else(malformed_upgrade)?;
    if !value_nominates_token(connection, "upgrade") {
        return Err(malformed_upgrade());
    }
    let upgrade = single_header(&parts.headers, header::UPGRADE)
        .map_err(|()| malformed_upgrade())?
        .ok_or_else(malformed_upgrade)?;
    if !upgrade.as_bytes().eq_ignore_ascii_case(b"websocket") {
        return Err(malformed_upgrade());
    }

    let version = single_header(&parts.headers, header::SEC_WEBSOCKET_VERSION)
        .map_err(|()| unsupported_version())?
        .ok_or_else(unsupported_version)?;
    if version.as_bytes() != b"13" {
        return Err(unsupported_version());
    }

    let key = single_header(&parts.headers, header::SEC_WEBSOCKET_KEY)
        .map_err(|()| malformed_key())?
        .ok_or_else(malformed_key)?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(key.as_bytes())
        .map_err(|_| malformed_key())?;
    if decoded.len() != 16 {
        return Err(malformed_key());
    }

    Ok(())
}

fn malformed_upgrade() -> Denial {
    Denial::denied(
        StatusCode::BAD_REQUEST,
        "invalid_upgrade",
        "malformed_upgrade",
    )
}

fn malformed_key() -> Denial {
    Denial::denied(StatusCode::BAD_REQUEST, "invalid_upgrade", "malformed_key")
}

fn unsupported_version() -> Denial {
    Denial {
        status: StatusCode::UPGRADE_REQUIRED,
        error: "upgrade_required",
        reason: "unsupported_version",
        result: "denied",
        upgrade_required: true,
    }
}

/// Applies the route's origin allowlist to the presented `Origin`.
///
/// Returns the normalized serialization to forward upstream. Forwarding the
/// normalized form rather than the caller's bytes means the value crossing the
/// boundary is one the operator wrote, not one an attacker chose: it matched an
/// allowlist entry exactly, so it *is* that entry.
fn evaluate_origin(
    headers: &HeaderMap,
    runtime: &RouteWebSocketRuntime,
    trace: &mut HandshakeTrace,
) -> Result<Option<String>, Denial> {
    let origin = match single_header(headers, header::ORIGIN) {
        Ok(origin) => origin,
        Err(()) => {
            trace.origin_present = true;
            return Err(origin_denial("origin_malformed"));
        }
    };
    let Some(origin) = origin else {
        if runtime.require_origin {
            return Err(origin_denial("origin_missing"));
        }
        return Ok(None);
    };
    trace.origin_present = true;

    let Ok(origin) = origin.to_str() else {
        return Err(origin_denial("origin_malformed"));
    };
    let Some(normalized) = config::normalized_websocket_origin(origin) else {
        return Err(origin_denial("origin_malformed"));
    };
    // An empty allowlist denies every request that carries an Origin: a browser
    // upgrade is allowed explicitly or not at all.
    if !runtime.allowed_origins.contains(&normalized) {
        return Err(origin_denial("origin_denied"));
    }
    trace.origin_allowed = true;

    Ok(Some(normalized))
}

fn origin_denial(reason: &'static str) -> Denial {
    Denial::denied(StatusCode::FORBIDDEN, "forbidden", reason)
}

/// Intersects the client's offer with the route allowlist, preserving the
/// client's preference order.
///
/// A client that offers nothing negotiates nothing. A client that offers
/// something the route does not allow is refused rather than silently upgraded
/// without a subprotocol, because the two are not interchangeable to an
/// application that keyed its behavior on one.
fn negotiate_subprotocol(
    headers: &HeaderMap,
    runtime: &RouteWebSocketRuntime,
) -> Result<Option<String>, Denial> {
    let mut offered = Vec::new();
    for value in headers.get_all(header::SEC_WEBSOCKET_PROTOCOL) {
        let Ok(value) = value.to_str() else {
            return Err(subprotocol_denial());
        };
        for token in value.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if offered.len() >= MAX_OFFERED_SUBPROTOCOLS {
                return Err(subprotocol_denial());
            }
            offered.push(token);
        }
    }
    if offered.is_empty() {
        return Ok(None);
    }

    offered
        .into_iter()
        .find(|token| {
            runtime
                .allowed_subprotocols
                .iter()
                .any(|allowed| allowed == token)
        })
        .map(|token| Some(token.to_owned()))
        .ok_or_else(subprotocol_denial)
}

fn subprotocol_denial() -> Denial {
    Denial::denied(StatusCode::FORBIDDEN, "forbidden", "subprotocol_denied")
}

/// Builds the upstream handshake request headers.
///
/// Starts from the ordinary attempt headers, which already remove hop-by-hop
/// and Connection-nominated headers, `Host`, `Content-Length`, `Authorization`,
/// `Cookie`, the gateway request ID, and every spoofable forwarding header, and
/// then apply the route's own add/strip policy. On top of that every inbound
/// `sec-websocket-*` and `origin` is removed, so nothing the client sent about
/// the handshake survives: the key is freshly generated, the subprotocol is the
/// negotiated one, and the origin is the normalized allowlist entry.
fn upstream_handshake_headers(
    parts: &Parts,
    source_ip: &str,
    upstream: &MatchedUpstream,
    gateway_key: &str,
    subprotocol: Option<&str>,
    origin: Option<&str>,
) -> Result<HeaderMap, Denial> {
    let mut headers = forward::attempt_headers(
        &parts.headers,
        source_ip,
        &upstream.request_header_policy,
        None,
    );
    let handshake_headers = headers
        .keys()
        .filter(|name| name.as_str().starts_with(SEC_WEBSOCKET_PREFIX) || *name == header::ORIGIN)
        .cloned()
        .collect::<Vec<HeaderName>>();
    for name in handshake_headers {
        headers.remove(name);
    }

    headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
    headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
    headers.insert(
        header::SEC_WEBSOCKET_VERSION,
        HeaderValue::from_static("13"),
    );
    headers.insert(
        header::SEC_WEBSOCKET_KEY,
        HeaderValue::from_str(gateway_key)
            .expect("a generated WebSocket key is a valid header value"),
    );
    if let Some(subprotocol) = subprotocol {
        headers.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_str(subprotocol)
                .expect("a validated subprotocol token is a valid header value"),
        );
    }
    if let Some(origin) = origin {
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_str(origin).map_err(|_| origin_denial("origin_malformed"))?,
        );
    }
    // Compression is a non-goal, so no extension is ever offered and none may be
    // accepted.
    headers.remove(header::SEC_WEBSOCKET_EXTENSIONS);

    Ok(headers)
}

/// Checks that the upstream's 101 is the answer to the request the gateway
/// actually sent.
fn validate_upstream_handshake(
    headers: &HeaderMap,
    gateway_key: &str,
    offered: &Option<String>,
) -> Result<Option<String>, &'static str> {
    let upgrade = single_header(headers, header::UPGRADE)
        .map_err(|()| "upstream_handshake_invalid")?
        .ok_or("upstream_handshake_invalid")?;
    if !upgrade.as_bytes().eq_ignore_ascii_case(b"websocket") {
        return Err("upstream_handshake_invalid");
    }
    let connection = single_header(headers, header::CONNECTION)
        .map_err(|()| "upstream_handshake_invalid")?
        .ok_or("upstream_handshake_invalid")?;
    if !value_nominates_token(connection, "upgrade") {
        return Err("upstream_handshake_invalid");
    }
    let accept = single_header(headers, header::SEC_WEBSOCKET_ACCEPT)
        .map_err(|()| "upstream_handshake_invalid")?
        .ok_or("upstream_handshake_invalid")?;
    if accept.as_bytes() != derive_accept_key(gateway_key.as_bytes()).as_bytes() {
        return Err("upstream_accept_mismatch");
    }
    if headers.contains_key(header::SEC_WEBSOCKET_EXTENSIONS) {
        return Err("upstream_extension_offered");
    }

    let selected = single_header(headers, header::SEC_WEBSOCKET_PROTOCOL)
        .map_err(|()| "upstream_subprotocol_invalid")?;
    match selected {
        None => Ok(None),
        Some(selected) => {
            let Ok(selected) = selected.to_str() else {
                return Err("upstream_subprotocol_invalid");
            };
            let selected = selected.trim();
            // The upstream may only echo the one subprotocol the gateway sent,
            // which is by construction one the client offered and policy allows.
            match offered.as_deref() {
                Some(offered) if offered == selected => Ok(Some(selected.to_owned())),
                _ => Err("upstream_subprotocol_invalid"),
            }
        }
    }
}

/// Reads a header that must appear at most once.
///
/// `Err(())` means it appeared more than once, which for any header in this
/// handshake is a request the gateway refuses to interpret.
fn single_header(headers: &HeaderMap, name: HeaderName) -> Result<Option<&HeaderValue>, ()> {
    let mut values = headers.get_all(&name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(());
    }
    Ok(first)
}

fn header_nominates_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
    headers
        .get_all(&name)
        .iter()
        .any(|value| value_nominates_token(value, token))
}

fn value_nominates_token(value: &HeaderValue, token: &str) -> bool {
    value.to_str().is_ok_and(|value| {
        value
            .split(',')
            .any(|candidate| candidate.trim().eq_ignore_ascii_case(token))
    })
}

/// Owns every reservation an established connection holds.
///
/// Dropping it releases the admission permit, the endpoint slot, the shutdown
/// tracker token, and the active gauge together, so a bridge that ends and a
/// client upgrade that never completes are the same code path.
struct ConnectionGuard {
    pool_id: Arc<str>,
    endpoint_id: Arc<str>,
    _admission: admission::PoolAdmissionPermit,
    _endpoint_slot: OwnedSemaphorePermit,
    _registration: tokio_util::task::task_tracker::TaskTrackerToken,
}

impl ConnectionGuard {
    fn new(
        pool_id: Arc<str>,
        endpoint_id: Arc<str>,
        admission: admission::PoolAdmissionPermit,
        endpoint_slot: OwnedSemaphorePermit,
        registration: tokio_util::task::task_tracker::TaskTrackerToken,
    ) -> Self {
        ::metrics::gauge!(
            crate::metrics::PROXY_WEBSOCKET_ACTIVE,
            "pool_id" => Arc::clone(&pool_id),
            "endpoint_id" => Arc::clone(&endpoint_id)
        )
        .increment(1.0);
        Self {
            pool_id,
            endpoint_id,
            _admission: admission,
            _endpoint_slot: endpoint_slot,
            _registration: registration,
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        ::metrics::gauge!(
            crate::metrics::PROXY_WEBSOCKET_ACTIVE,
            "pool_id" => Arc::clone(&self.pool_id),
            "endpoint_id" => Arc::clone(&self.endpoint_id)
        )
        .decrement(1.0);
    }
}

#[derive(Clone)]
struct BridgeContext {
    audit: audit::AuditLog,
    request_id: String,
    source_ip: String,
    pool_id: Arc<str>,
    endpoint_id: Arc<str>,
    subprotocol: Option<String>,
    idle_timeout: Option<Duration>,
    max_duration: Option<Duration>,
    forced_shutdown: CancellationToken,
}

impl BridgeContext {
    fn finish(&self, termination: Termination, counters: BridgeCounters, duration: Duration) {
        let labels = [
            ("pool_id", self.pool_id.to_string()),
            ("endpoint_id", self.endpoint_id.to_string()),
            ("outcome", termination.outcome.to_owned()),
        ];
        ::metrics::counter!(crate::metrics::PROXY_WEBSOCKET_TERMINATIONS_TOTAL, &labels)
            .increment(1);
        ::metrics::histogram!(crate::metrics::PROXY_WEBSOCKET_DURATION_SECONDS, &labels)
            .record(duration.as_secs_f64());
        for (direction, frames, bytes) in [
            (
                "client_to_upstream",
                counters.client_frames,
                counters.client_bytes,
            ),
            (
                "upstream_to_client",
                counters.upstream_frames,
                counters.upstream_bytes,
            ),
        ] {
            let labels = [
                ("pool_id", self.pool_id.to_string()),
                ("endpoint_id", self.endpoint_id.to_string()),
                ("direction", direction.to_owned()),
            ];
            ::metrics::counter!(crate::metrics::PROXY_WEBSOCKET_FRAMES_TOTAL, &labels)
                .increment(frames);
            ::metrics::counter!(crate::metrics::PROXY_WEBSOCKET_BYTES_TOTAL, &labels)
                .increment(bytes);
        }

        // The close reason is peer-supplied text and is never recorded; the code
        // is a bounded integer and is.
        self.audit.emit(audit::AuditEvent::new(
            audit::event::UPSTREAM_WEBSOCKET_CLOSED,
            self.request_id.clone(),
            self.source_ip.clone(),
            None::<audit::Actor>,
            json!({
                "pool_id": self.pool_id,
                "endpoint_id": self.endpoint_id,
                "outcome": termination.outcome,
                "close_code": termination.close_code,
                "subprotocol": self.subprotocol,
                "frames_client_to_upstream": counters.client_frames,
                "frames_upstream_to_client": counters.upstream_frames,
                "bytes_client_to_upstream": counters.client_bytes,
                "bytes_upstream_to_client": counters.upstream_bytes,
                "duration_ms": crate::duration_millis(duration),
            }),
        ));
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct BridgeCounters {
    client_frames: u64,
    client_bytes: u64,
    upstream_frames: u64,
    upstream_bytes: u64,
}

impl BridgeCounters {
    fn observe_client(&mut self, payload: usize) {
        self.client_frames = self.client_frames.saturating_add(1);
        self.client_bytes = self
            .client_bytes
            .saturating_add(u64::try_from(payload).unwrap_or(u64::MAX));
    }

    fn observe_upstream(&mut self, payload: usize) {
        self.upstream_frames = self.upstream_frames.saturating_add(1);
        self.upstream_bytes = self
            .upstream_bytes
            .saturating_add(u64::try_from(payload).unwrap_or(u64::MAX));
    }
}

/// How a bridge ended.
///
/// `propagate` carries a close frame the gateway itself must send to both
/// peers; a close that arrived from one peer has already been forwarded to the
/// other, so it propagates nothing further.
struct Termination {
    outcome: &'static str,
    close_code: Option<u16>,
    propagate: Option<u16>,
}

impl Termination {
    fn gateway(outcome: &'static str, code: u16) -> Self {
        Self {
            outcome,
            close_code: Some(code),
            propagate: Some(code),
        }
    }

    fn forwarded(outcome: &'static str, code: Option<u16>) -> Self {
        Self {
            outcome,
            close_code: code,
            propagate: None,
        }
    }
}

async fn bridge(
    mut client: WebSocket,
    mut upstream: WebSocketStream<EgressUpgradedStream>,
    context: BridgeContext,
    guard: ConnectionGuard,
) {
    let started = Instant::now();
    let mut counters = BridgeCounters::default();
    let termination = run_bridge(&mut client, &mut upstream, &context, &mut counters).await;

    if let Some(code) = termination.propagate {
        let _ = tokio::time::timeout(
            CLOSE_GRACE,
            client.send(AxumMessage::Close(Some(AxumCloseFrame {
                code,
                reason: AxumUtf8Bytes::from(""),
            }))),
        )
        .await;
        let _ = tokio::time::timeout(
            CLOSE_GRACE,
            upstream.send(TungsteniteMessage::Close(Some(TungsteniteCloseFrame {
                code: TungsteniteCloseCode::from(code),
                reason: TungsteniteUtf8Bytes::from(""),
            }))),
        )
        .await;
    }
    let _ = tokio::time::timeout(CLOSE_GRACE, SinkExt::close(&mut client)).await;
    let _ = tokio::time::timeout(CLOSE_GRACE, SinkExt::close(&mut upstream)).await;

    context.finish(termination, counters, started.elapsed());
    drop(guard);
}

enum Incoming {
    Client(Option<Result<AxumMessage, axum::Error>>),
    Upstream(Option<Result<TungsteniteMessage, tungstenite::Error>>),
}

async fn run_bridge(
    client: &mut WebSocket,
    upstream: &mut WebSocketStream<EgressUpgradedStream>,
    context: &BridgeContext,
    counters: &mut BridgeCounters,
) -> Termination {
    let duration_deadline = context
        .max_duration
        .map(|duration| tokio::time::Instant::now() + duration);
    let mut idle_deadline = context
        .idle_timeout
        .map(|duration| tokio::time::Instant::now() + duration);

    loop {
        let incoming = tokio::select! {
            biased;
            () = context.forced_shutdown.cancelled() => {
                return Termination::gateway("shutdown", CLOSE_GOING_AWAY);
            }
            () = forward::sleep_until_optional(duration_deadline) => {
                return Termination::gateway("duration_limit", CLOSE_NORMAL);
            }
            () = forward::sleep_until_optional(idle_deadline) => {
                return Termination::gateway("idle_timeout", CLOSE_NORMAL);
            }
            message = client.next() => Incoming::Client(message),
            message = upstream.next() => Incoming::Upstream(message),
        };

        // Any frame in either direction is liveness, control frames included.
        idle_deadline = context
            .idle_timeout
            .map(|duration| tokio::time::Instant::now() + duration);

        match incoming {
            Incoming::Client(None) => return Termination::forwarded("client_close", None),
            Incoming::Client(Some(Err(error))) => return client_termination(error),
            Incoming::Client(Some(Ok(message))) => {
                counters.observe_client(message_payload_len(&message));
                let close_code = match &message {
                    AxumMessage::Close(frame) => Some(frame.as_ref().map(|frame| frame.code)),
                    _ => None,
                };
                // Awaiting the send before reading again is the backpressure: at
                // most one message per direction is ever in flight.
                if let Err(termination) = send_to_upstream(
                    upstream,
                    to_tungstenite(message),
                    context,
                    duration_deadline,
                )
                .await
                {
                    return termination;
                }
                if let Some(code) = close_code {
                    return Termination::forwarded("client_close", code);
                }
            }
            Incoming::Upstream(None) => return Termination::forwarded("upstream_close", None),
            Incoming::Upstream(Some(Err(error))) => {
                let (outcome, code) = classify_tungstenite_error(&error, Side::Upstream);
                return Termination::gateway(outcome, code);
            }
            Incoming::Upstream(Some(Ok(message))) => {
                let Some(message) = from_tungstenite(message) else {
                    continue;
                };
                counters.observe_upstream(message_payload_len(&message));
                let close_code = match &message {
                    AxumMessage::Close(frame) => Some(frame.as_ref().map(|frame| frame.code)),
                    _ => None,
                };
                if let Err(termination) =
                    send_to_client(client, message, context, duration_deadline).await
                {
                    return termination;
                }
                if let Some(code) = close_code {
                    return Termination::forwarded("upstream_close", code);
                }
            }
        }
    }
}

async fn send_to_upstream(
    upstream: &mut WebSocketStream<EgressUpgradedStream>,
    message: TungsteniteMessage,
    context: &BridgeContext,
    duration_deadline: Option<tokio::time::Instant>,
) -> Result<(), Termination> {
    let result = tokio::select! {
        biased;
        () = context.forced_shutdown.cancelled() => {
            return Err(Termination::gateway("shutdown", CLOSE_GOING_AWAY));
        }
        () = forward::sleep_until_optional(duration_deadline) => {
            return Err(Termination::gateway("duration_limit", CLOSE_NORMAL));
        }
        result = upstream.send(message) => result,
    };
    result.map_err(|error| {
        let (outcome, code) = classify_tungstenite_error(&error, Side::Upstream);
        Termination::gateway(outcome, code)
    })
}

async fn send_to_client(
    client: &mut WebSocket,
    message: AxumMessage,
    context: &BridgeContext,
    duration_deadline: Option<tokio::time::Instant>,
) -> Result<(), Termination> {
    let result = tokio::select! {
        biased;
        () = context.forced_shutdown.cancelled() => {
            return Err(Termination::gateway("shutdown", CLOSE_GOING_AWAY));
        }
        () = forward::sleep_until_optional(duration_deadline) => {
            return Err(Termination::gateway("duration_limit", CLOSE_NORMAL));
        }
        result = client.send(message) => result,
    };
    result.map_err(client_termination)
}

fn client_termination(error: axum::Error) -> Termination {
    match error.into_inner().downcast::<tungstenite::Error>() {
        Ok(error) => {
            let (outcome, code) = classify_tungstenite_error(&error, Side::Client);
            Termination::gateway(outcome, code)
        }
        Err(_) => Termination::gateway("client_error", CLOSE_INTERNAL_ERROR),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Side {
    Client,
    Upstream,
}

/// Maps a transport failure to a bounded outcome and the close code the peers
/// are told.
fn classify_tungstenite_error(error: &tungstenite::Error, side: Side) -> (&'static str, u16) {
    match error {
        tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => (
            match side {
                Side::Client => "client_close",
                Side::Upstream => "upstream_close",
            },
            CLOSE_NORMAL,
        ),
        tungstenite::Error::Capacity(_) | tungstenite::Error::WriteBufferFull(_) => (
            match side {
                Side::Client => "client_capacity",
                Side::Upstream => "upstream_capacity",
            },
            CLOSE_TOO_LARGE,
        ),
        tungstenite::Error::Protocol(_)
        | tungstenite::Error::Utf8(_)
        | tungstenite::Error::AttackAttempt => (
            match side {
                Side::Client => "client_protocol",
                Side::Upstream => "upstream_protocol",
            },
            CLOSE_PROTOCOL_ERROR,
        ),
        _ => (
            match side {
                Side::Client => "client_error",
                Side::Upstream => "upstream_error",
            },
            CLOSE_INTERNAL_ERROR,
        ),
    }
}

fn message_payload_len(message: &AxumMessage) -> usize {
    match message {
        AxumMessage::Text(text) => text.as_str().len(),
        AxumMessage::Binary(data) | AxumMessage::Ping(data) | AxumMessage::Pong(data) => data.len(),
        AxumMessage::Close(Some(frame)) => frame.reason.as_str().len(),
        AxumMessage::Close(None) => 0,
    }
}

fn to_tungstenite(message: AxumMessage) -> TungsteniteMessage {
    match message {
        AxumMessage::Text(text) => {
            TungsteniteMessage::Text(TungsteniteUtf8Bytes::from(text.as_str()))
        }
        AxumMessage::Binary(data) => TungsteniteMessage::Binary(data),
        AxumMessage::Ping(data) => TungsteniteMessage::Ping(data),
        AxumMessage::Pong(data) => TungsteniteMessage::Pong(data),
        AxumMessage::Close(frame) => {
            TungsteniteMessage::Close(frame.map(|frame| TungsteniteCloseFrame {
                code: TungsteniteCloseCode::from(frame.code),
                reason: TungsteniteUtf8Bytes::from(truncate_close_reason(frame.reason.as_str())),
            }))
        }
    }
}

fn from_tungstenite(message: TungsteniteMessage) -> Option<AxumMessage> {
    match message {
        TungsteniteMessage::Text(text) => {
            Some(AxumMessage::Text(AxumUtf8Bytes::from(text.as_str())))
        }
        TungsteniteMessage::Binary(data) => Some(AxumMessage::Binary(data)),
        TungsteniteMessage::Ping(data) => Some(AxumMessage::Ping(data)),
        TungsteniteMessage::Pong(data) => Some(AxumMessage::Pong(data)),
        TungsteniteMessage::Close(frame) => {
            Some(AxumMessage::Close(frame.map(|frame| AxumCloseFrame {
                code: frame.code.into(),
                reason: AxumUtf8Bytes::from(truncate_close_reason(frame.reason.as_str())),
            })))
        }
        // Raw frames are never produced by a read; tungstenite's own maintainers
        // recommend ignoring them.
        TungsteniteMessage::Frame(_) => None,
    }
}

/// Trims a close reason to the protocol's control-frame budget on a character
/// boundary. The text itself is forwarded but never logged.
fn truncate_close_reason(reason: &str) -> &str {
    if reason.len() <= MAX_CLOSE_REASON_BYTES {
        return reason;
    }
    let mut end = MAX_CLOSE_REASON_BYTES;
    while end > 0 && !reason.is_char_boundary(end) {
        end -= 1;
    }
    &reason[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::RouteRequestHeaderPolicy;

    const VALID_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

    fn websocket_settings() -> config::UpstreamWebSocketConfig {
        config::UpstreamWebSocketConfig {
            max_connections: config::DEFAULT_WEBSOCKET_MAX_CONNECTIONS,
            max_connections_per_endpoint: None,
            queue_depth: config::DEFAULT_WEBSOCKET_QUEUE_DEPTH,
            queue_timeout_ms: config::DEFAULT_WEBSOCKET_QUEUE_TIMEOUT_MS,
            handshake_timeout_ms: config::DEFAULT_WEBSOCKET_HANDSHAKE_TIMEOUT_MS,
            idle_timeout_ms: config::DEFAULT_WEBSOCKET_IDLE_TIMEOUT_MS,
            max_duration_ms: config::DEFAULT_WEBSOCKET_MAX_DURATION_MS,
            max_frame_bytes: config::DEFAULT_WEBSOCKET_MAX_FRAME_BYTES,
            max_message_bytes: config::DEFAULT_WEBSOCKET_MAX_MESSAGE_BYTES,
            max_write_buffer_bytes: config::DEFAULT_WEBSOCKET_MAX_WRITE_BUFFER_BYTES,
            allowed_origins: Vec::new(),
            require_origin: false,
            allowed_subprotocols: Vec::new(),
        }
    }

    fn runtime(
        configure: impl FnOnce(&mut config::UpstreamWebSocketConfig),
    ) -> RouteWebSocketRuntime {
        let mut settings = websocket_settings();
        configure(&mut settings);
        RouteWebSocketRuntime::new(
            "payments",
            &settings,
            [Arc::<str>::from("a"), Arc::<str>::from("b")].into_iter(),
        )
    }

    fn handshake_parts(extra: &[(&str, &str)]) -> Parts {
        let mut builder = http::Request::builder()
            .method(Method::GET)
            .uri("/socket/room")
            .version(Version::HTTP_11)
            .header(header::HOST, "gateway.example")
            .header(header::CONNECTION, "Upgrade")
            .header(header::UPGRADE, "websocket")
            .header(header::SEC_WEBSOCKET_VERSION, "13")
            .header(header::SEC_WEBSOCKET_KEY, VALID_KEY);
        for (name, value) in extra {
            builder = builder.header(*name, *value);
        }
        builder
            .body(())
            .expect("test handshake request should build")
            .into_parts()
            .0
    }

    fn headers_of(parts: &Parts) -> &HeaderMap {
        &parts.headers
    }

    #[test]
    fn upgrade_shape_detection_ignores_case_and_surrounding_tokens() {
        assert!(is_websocket_upgrade(&handshake_parts(&[])));
        assert!(is_websocket_upgrade(&{
            let mut parts = handshake_parts(&[]);
            parts.headers.insert(
                header::CONNECTION,
                HeaderValue::from_static("keep-alive, UPGRADE"),
            );
            parts
                .headers
                .insert(header::UPGRADE, HeaderValue::from_static("WebSocket"));
            parts
        }));

        let mut ordinary = handshake_parts(&[]);
        ordinary.headers.remove(header::UPGRADE);
        assert!(
            !is_websocket_upgrade(&ordinary),
            "a request without an Upgrade header stays on the ordinary HTTP path"
        );

        let mut posted = handshake_parts(&[]);
        posted.method = Method::POST;
        assert!(!is_websocket_upgrade(&posted));
    }

    #[test]
    fn local_validation_accepts_a_conforming_handshake() {
        validate_local_protocol(&handshake_parts(&[]))
            .expect("a conforming handshake should validate");
    }

    #[test]
    fn local_validation_refuses_every_malformed_shape_with_its_own_category() {
        let mut wrong_version = handshake_parts(&[]);
        wrong_version
            .headers
            .insert(header::SEC_WEBSOCKET_VERSION, HeaderValue::from_static("8"));
        let denial = validate_local_protocol(&wrong_version).expect_err("version 8 is refused");
        assert_eq!(denial.reason, "unsupported_version");
        assert_eq!(denial.status, StatusCode::UPGRADE_REQUIRED);
        assert!(
            denial.upgrade_required,
            "the refusal must advertise the version the gateway speaks"
        );

        let mut duplicate_version = handshake_parts(&[]);
        duplicate_version.headers.append(
            header::SEC_WEBSOCKET_VERSION,
            HeaderValue::from_static("13"),
        );
        assert_eq!(
            validate_local_protocol(&duplicate_version)
                .expect_err("a duplicated version header is ambiguous")
                .reason,
            "unsupported_version"
        );

        for key in [
            "",
            "not base64",
            "c2hvcnQ=",
            "dG9vLWxvbmctZm9yLWEta2V5LXZhbHVl",
        ] {
            let mut parts = handshake_parts(&[]);
            parts.headers.insert(
                header::SEC_WEBSOCKET_KEY,
                HeaderValue::from_str(key).expect("test key should be a header value"),
            );
            assert_eq!(
                validate_local_protocol(&parts).unwrap_err().reason,
                "malformed_key",
                "key {key:?} does not decode to sixteen bytes"
            );
        }

        let mut missing_key = handshake_parts(&[]);
        missing_key.headers.remove(header::SEC_WEBSOCKET_KEY);
        assert_eq!(
            validate_local_protocol(&missing_key).unwrap_err().reason,
            "malformed_key"
        );

        let mut extra_upgrade_token = handshake_parts(&[]);
        extra_upgrade_token
            .headers
            .insert(header::UPGRADE, HeaderValue::from_static("websocket, h2c"));
        assert_eq!(
            validate_local_protocol(&extra_upgrade_token)
                .unwrap_err()
                .reason,
            "malformed_upgrade"
        );

        let mut no_nomination = handshake_parts(&[]);
        no_nomination
            .headers
            .insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        assert_eq!(
            validate_local_protocol(&no_nomination).unwrap_err().reason,
            "malformed_upgrade"
        );

        let mut http2 = handshake_parts(&[]);
        http2.version = Version::HTTP_2;
        assert_eq!(
            validate_local_protocol(&http2).unwrap_err().reason,
            "http_version",
            "RFC 8441 extended CONNECT is out of scope and is refused, not guessed at"
        );
    }

    #[test]
    fn origin_policy_matches_only_the_exact_normalized_serialization() {
        let runtime = runtime(|websocket| {
            websocket.allowed_origins = vec!["https://app.example".to_owned()];
        });

        for allowed in [
            "https://app.example",
            "https://APP.Example",
            "https://app.example:443",
        ] {
            let parts = handshake_parts(&[("origin", allowed)]);
            let mut trace = HandshakeTrace::default();
            assert_eq!(
                evaluate_origin(headers_of(&parts), &runtime, &mut trace)
                    .unwrap_or_else(|_| panic!("origin {allowed} should be allowed")),
                Some("https://app.example".to_owned()),
                "the forwarded origin is always the normalized allowlist entry"
            );
            assert!(trace.origin_allowed);
        }

        for denied in [
            "https://evil.example",
            "http://app.example",
            "https://app.example:8443",
            "https://app.example.evil",
        ] {
            let parts = handshake_parts(&[("origin", denied)]);
            let mut trace = HandshakeTrace::default();
            assert_eq!(
                evaluate_origin(headers_of(&parts), &runtime, &mut trace)
                    .expect_err("origin should be denied")
                    .reason,
                "origin_denied",
                "origin {denied} must not match"
            );
            assert!(!trace.origin_allowed);
        }

        let mut parts = handshake_parts(&[("origin", "https://app.example")]);
        parts.headers.append(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        assert_eq!(
            evaluate_origin(headers_of(&parts), &runtime, &mut HandshakeTrace::default())
                .expect_err("two origins are ambiguous")
                .reason,
            "origin_malformed"
        );

        let parts = handshake_parts(&[("origin", "://not-an-origin")]);
        assert_eq!(
            evaluate_origin(headers_of(&parts), &runtime, &mut HandshakeTrace::default())
                .expect_err("an unparseable origin is refused")
                .reason,
            "origin_malformed"
        );
    }

    #[test]
    fn an_empty_origin_allowlist_allows_nothing_that_carries_an_origin() {
        let runtime = runtime(|_| {});
        let parts = handshake_parts(&[("origin", "https://app.example")]);
        assert_eq!(
            evaluate_origin(headers_of(&parts), &runtime, &mut HandshakeTrace::default())
                .expect_err("an empty allowlist denies by construction")
                .reason,
            "origin_denied"
        );

        let parts = handshake_parts(&[]);
        assert_eq!(
            evaluate_origin(headers_of(&parts), &runtime, &mut HandshakeTrace::default())
                .expect("an absent origin is allowed unless require_origin"),
            None
        );
    }

    #[test]
    fn require_origin_refuses_a_handshake_without_one() {
        let runtime = runtime(|websocket| {
            websocket.require_origin = true;
            websocket.allowed_origins = vec!["https://app.example".to_owned()];
        });
        let parts = handshake_parts(&[]);
        assert_eq!(
            evaluate_origin(headers_of(&parts), &runtime, &mut HandshakeTrace::default())
                .expect_err("require_origin refuses an origin-less handshake")
                .reason,
            "origin_missing"
        );
    }

    #[test]
    fn subprotocol_negotiation_follows_client_preference_and_fails_closed() {
        let runtime = runtime(|websocket| {
            websocket.allowed_subprotocols = vec!["chat.v1".to_owned(), "chat.v2".to_owned()];
        });

        let parts = handshake_parts(&[("sec-websocket-protocol", "unknown, chat.v2, chat.v1")]);
        assert_eq!(
            negotiate_subprotocol(headers_of(&parts), &runtime).expect("an allowed offer matches"),
            Some("chat.v2".to_owned()),
            "the client's order decides, not the configuration's"
        );

        let mut parts = handshake_parts(&[("sec-websocket-protocol", "unknown")]);
        parts.headers.append(
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static("chat.v1"),
        );
        assert_eq!(
            negotiate_subprotocol(headers_of(&parts), &runtime)
                .expect("a split offer is still one list"),
            Some("chat.v1".to_owned())
        );

        let parts = handshake_parts(&[("sec-websocket-protocol", "mqtt, chat.v9")]);
        assert_eq!(
            negotiate_subprotocol(headers_of(&parts), &runtime)
                .expect_err("an empty intersection is refused")
                .reason,
            "subprotocol_denied"
        );

        let parts = handshake_parts(&[]);
        assert_eq!(
            negotiate_subprotocol(headers_of(&parts), &runtime)
                .expect("a client that offers nothing negotiates nothing"),
            None
        );

        let offered = (0..=MAX_OFFERED_SUBPROTOCOLS)
            .map(|index| format!("chat.v{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        let parts = handshake_parts(&[("sec-websocket-protocol", offered.as_str())]);
        assert_eq!(
            negotiate_subprotocol(headers_of(&parts), &runtime)
                .expect_err("an unbounded offer is refused rather than scanned")
                .reason,
            "subprotocol_denied"
        );
    }

    #[test]
    fn an_empty_subprotocol_allowlist_denies_any_offer() {
        let runtime = runtime(|_| {});
        let parts = handshake_parts(&[("sec-websocket-protocol", "chat.v1")]);
        assert_eq!(
            negotiate_subprotocol(headers_of(&parts), &runtime)
                .expect_err("an empty allowlist allows no subprotocol")
                .reason,
            "subprotocol_denied"
        );
    }

    #[test]
    fn the_upstream_handshake_is_built_only_from_validated_state() {
        let parts = handshake_parts(&[
            ("authorization", "Bearer caller-token"),
            ("cookie", "session=caller"),
            ("x-forwarded-for", "203.0.113.9"),
            ("x-real-ip", "203.0.113.9"),
            ("x-forwarded-host", "evil.example"),
            ("x-request-id", "caller-supplied"),
            ("sec-websocket-extensions", "permessage-deflate"),
            ("origin", "https://app.example"),
            ("x-user-header", "kept"),
        ]);
        let upstream = MatchedUpstream {
            connection_id: None,
            request_header_policy: RouteRequestHeaderPolicy::default(),
            pool: test_pool(),
            request_body_mode: super::super::RequestBodyMode::Buffered,
            sse: None,
            websocket: None,
        };

        let headers = upstream_handshake_headers(
            &parts,
            "198.51.100.7",
            &upstream,
            "Z2F0ZXdheS1nZW5lcmF0ZWQta2V5",
            Some("chat.v1"),
            Some("https://app.example"),
        )
        .expect("the upstream handshake should build");

        assert!(headers.get(header::AUTHORIZATION).is_none());
        assert!(headers.get(header::COOKIE).is_none());
        assert!(headers.get(header::HOST).is_none());
        assert!(headers.get("x-forwarded-host").is_none());
        assert!(headers.get("x-request-id").is_none());
        assert_eq!(
            headers.get("x-forwarded-for").map(HeaderValue::as_bytes),
            Some(b"198.51.100.7".as_slice()),
            "the forwarding header is the gateway's observation, not the caller's claim"
        );
        assert_eq!(
            headers.get("x-user-header").map(HeaderValue::as_bytes),
            Some(b"kept".as_slice()),
            "an ordinary header the route did not strip still crosses"
        );
        assert_eq!(
            headers
                .get(header::SEC_WEBSOCKET_KEY)
                .map(HeaderValue::as_bytes),
            Some(b"Z2F0ZXdheS1nZW5lcmF0ZWQta2V5".as_slice()),
            "the upstream key is the gateway's, never the caller's"
        );
        assert_ne!(
            headers
                .get(header::SEC_WEBSOCKET_KEY)
                .map(HeaderValue::as_bytes),
            Some(VALID_KEY.as_bytes()),
        );
        assert_eq!(
            headers
                .get(header::SEC_WEBSOCKET_VERSION)
                .map(HeaderValue::as_bytes),
            Some(b"13".as_slice())
        );
        assert_eq!(
            headers
                .get(header::SEC_WEBSOCKET_PROTOCOL)
                .map(HeaderValue::as_bytes),
            Some(b"chat.v1".as_slice())
        );
        assert_eq!(
            headers.get(header::ORIGIN).map(HeaderValue::as_bytes),
            Some(b"https://app.example".as_slice())
        );
        assert!(
            headers.get(header::SEC_WEBSOCKET_EXTENSIONS).is_none(),
            "no extension is ever offered, so none can be negotiated"
        );
        assert!(value_nominates_token(
            headers
                .get(header::CONNECTION)
                .expect("the upstream request nominates the upgrade"),
            "upgrade"
        ));
        assert_eq!(
            headers.get(header::UPGRADE).map(HeaderValue::as_bytes),
            Some(b"websocket".as_slice())
        );
    }

    #[test]
    fn an_upgrade_without_a_negotiated_subprotocol_or_origin_sends_neither() {
        let parts = handshake_parts(&[("origin", "https://app.example")]);
        let upstream = MatchedUpstream {
            connection_id: None,
            request_header_policy: RouteRequestHeaderPolicy::default(),
            pool: test_pool(),
            request_body_mode: super::super::RequestBodyMode::Buffered,
            sse: None,
            websocket: None,
        };

        let headers = upstream_handshake_headers(
            &parts,
            "198.51.100.7",
            &upstream,
            "Z2F0ZXdheS1nZW5lcmF0ZWQta2V5",
            None,
            None,
        )
        .expect("the upstream handshake should build");

        assert!(headers.get(header::SEC_WEBSOCKET_PROTOCOL).is_none());
        assert!(
            headers.get(header::ORIGIN).is_none(),
            "an origin that did not pass policy is not relayed"
        );
    }

    #[test]
    fn the_upstream_answer_is_accepted_only_when_it_answers_this_request() {
        const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = derive_accept_key(KEY.as_bytes());
        let base = |accept: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
            headers.insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
            headers.insert(
                header::SEC_WEBSOCKET_ACCEPT,
                HeaderValue::from_str(accept).expect("accept key should be a header value"),
            );
            headers
        };

        assert_eq!(
            validate_upstream_handshake(&base(&accept), KEY, &None)
                .expect("a conforming answer is accepted"),
            None
        );

        assert_eq!(
            validate_upstream_handshake(&base("bm90LXRoZS1yaWdodC1rZXk="), KEY, &None)
                .expect_err("a wrong accept key is refused"),
            "upstream_accept_mismatch"
        );

        let mut missing_accept = base(&accept);
        missing_accept.remove(header::SEC_WEBSOCKET_ACCEPT);
        assert_eq!(
            validate_upstream_handshake(&missing_accept, KEY, &None).expect_err("no accept key"),
            "upstream_handshake_invalid"
        );

        let mut wrong_upgrade = base(&accept);
        wrong_upgrade.insert(header::UPGRADE, HeaderValue::from_static("h2c"));
        assert_eq!(
            validate_upstream_handshake(&wrong_upgrade, KEY, &None).expect_err("wrong upgrade"),
            "upstream_handshake_invalid"
        );

        let mut no_nomination = base(&accept);
        no_nomination.insert(header::CONNECTION, HeaderValue::from_static("close"));
        assert_eq!(
            validate_upstream_handshake(&no_nomination, KEY, &None).expect_err("no nomination"),
            "upstream_handshake_invalid"
        );

        let mut with_extension = base(&accept);
        with_extension.insert(
            header::SEC_WEBSOCKET_EXTENSIONS,
            HeaderValue::from_static("permessage-deflate"),
        );
        assert_eq!(
            validate_upstream_handshake(&with_extension, KEY, &None)
                .expect_err("an extension the gateway never offered is refused"),
            "upstream_extension_offered"
        );

        let mut unoffered_subprotocol = base(&accept);
        unoffered_subprotocol.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static("chat.v9"),
        );
        assert_eq!(
            validate_upstream_handshake(&unoffered_subprotocol, KEY, &None)
                .expect_err("a subprotocol the client never offered is refused"),
            "upstream_subprotocol_invalid"
        );
        assert_eq!(
            validate_upstream_handshake(&unoffered_subprotocol, KEY, &Some("chat.v1".to_owned()))
                .expect_err("the upstream may only echo what the gateway offered"),
            "upstream_subprotocol_invalid"
        );

        let mut echoed = base(&accept);
        echoed.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static("chat.v1"),
        );
        assert_eq!(
            validate_upstream_handshake(&echoed, KEY, &Some("chat.v1".to_owned()))
                .expect("an echoed offer is accepted"),
            Some("chat.v1".to_owned())
        );

        let mut duplicated = base(&accept);
        duplicated.append(
            header::SEC_WEBSOCKET_ACCEPT,
            HeaderValue::from_str(&accept).expect("accept key should be a header value"),
        );
        assert_eq!(
            validate_upstream_handshake(&duplicated, KEY, &None)
                .expect_err("a duplicated accept header is ambiguous"),
            "upstream_handshake_invalid"
        );
    }

    #[test]
    fn socket_bounds_can_always_carry_one_legal_message() {
        let runtime = runtime(|websocket| {
            websocket.max_frame_bytes = 1024 * 1024;
            websocket.max_message_bytes = 4 * 1024 * 1024;
            websocket.max_write_buffer_bytes = 256 * 1024;
        });
        let config = runtime.socket_config();

        assert_eq!(config.max_frame_size, Some(1024 * 1024));
        assert_eq!(config.max_message_size, Some(4 * 1024 * 1024));
        assert_eq!(config.write_buffer_size, 0);
        assert!(
            config.max_write_buffer_size > config.write_buffer_size,
            "tungstenite panics on a ceiling at or below the buffer target"
        );
        assert!(
            config.max_write_buffer_size >= 4 * 1024 * 1024 + MAX_FRAME_HEADER_BYTES,
            "a message the route permits must always be writable"
        );
        assert!(config.read_buffer_size <= READ_BUFFER_BYTES);
    }

    #[test]
    fn endpoint_slots_are_probed_never_queued() {
        let runtime = runtime(|websocket| {
            websocket.max_connections = 8;
            websocket.max_connections_per_endpoint = Some(1);
        });
        let first = Arc::<str>::from("a");
        let held = runtime
            .try_acquire_endpoint_slot(&first)
            .expect("the first connection takes the only slot");
        assert!(
            runtime.try_acquire_endpoint_slot(&first).is_none(),
            "a full endpoint refuses rather than waiting"
        );
        assert!(
            runtime
                .try_acquire_endpoint_slot(&Arc::<str>::from("b"))
                .is_some(),
            "another endpoint still has capacity"
        );
        drop(held);
        assert!(
            runtime.try_acquire_endpoint_slot(&first).is_some(),
            "a released slot is reusable"
        );
        assert!(
            runtime
                .try_acquire_endpoint_slot(&Arc::<str>::from("unknown"))
                .is_none(),
            "an endpoint the route does not own has no capacity at all"
        );
    }

    #[test]
    fn a_close_reason_is_trimmed_to_the_control_frame_budget_on_a_character_boundary() {
        assert_eq!(truncate_close_reason("short"), "short");

        let long = "x".repeat(MAX_CLOSE_REASON_BYTES + 10);
        assert_eq!(truncate_close_reason(&long).len(), MAX_CLOSE_REASON_BYTES);

        // A three-byte character straddling the limit is dropped whole rather
        // than split into invalid UTF-8.
        let multibyte = format!("{}\u{20ac}\u{20ac}", "y".repeat(MAX_CLOSE_REASON_BYTES - 1));
        let truncated = truncate_close_reason(&multibyte);
        assert!(truncated.len() <= MAX_CLOSE_REASON_BYTES);
        assert_eq!(truncated, "y".repeat(MAX_CLOSE_REASON_BYTES - 1));
        assert!(std::str::from_utf8(truncated.as_bytes()).is_ok());
    }

    #[test]
    fn transport_failures_map_to_bounded_outcomes_and_close_codes() {
        use tungstenite::error::{CapacityError, ProtocolError};

        for (error, client_outcome, upstream_outcome, code) in [
            (
                tungstenite::Error::Capacity(CapacityError::MessageTooLong {
                    size: 2,
                    max_size: 1,
                }),
                "client_capacity",
                "upstream_capacity",
                CLOSE_TOO_LARGE,
            ),
            (
                tungstenite::Error::Protocol(ProtocolError::ResetWithoutClosingHandshake),
                "client_protocol",
                "upstream_protocol",
                CLOSE_PROTOCOL_ERROR,
            ),
            (
                tungstenite::Error::ConnectionClosed,
                "client_close",
                "upstream_close",
                CLOSE_NORMAL,
            ),
            (
                tungstenite::Error::Io(std::io::Error::other("broken")),
                "client_error",
                "upstream_error",
                CLOSE_INTERNAL_ERROR,
            ),
        ] {
            assert_eq!(
                classify_tungstenite_error(&error, Side::Client),
                (client_outcome, code)
            );
            assert_eq!(
                classify_tungstenite_error(&error, Side::Upstream),
                (upstream_outcome, code)
            );
        }
    }

    #[test]
    fn messages_round_trip_between_the_two_socket_libraries_without_loss() {
        for message in [
            AxumMessage::Text(AxumUtf8Bytes::from("hello")),
            AxumMessage::Binary(bytes::Bytes::from_static(&[0, 1, 2, 255])),
            AxumMessage::Ping(bytes::Bytes::from_static(b"ping")),
            AxumMessage::Pong(bytes::Bytes::from_static(b"pong")),
            AxumMessage::Close(Some(AxumCloseFrame {
                code: 4001,
                reason: AxumUtf8Bytes::from("bye"),
            })),
            AxumMessage::Close(None),
        ] {
            let round_tripped = from_tungstenite(to_tungstenite(message.clone()))
                .expect("a data or control message always converts back");
            assert_eq!(round_tripped, message);
        }
    }

    fn test_pool() -> Arc<super::super::UpstreamPool> {
        Arc::new(super::super::UpstreamPool::new(
            "payments".to_owned(),
            vec![super::super::ProxyEndpoint {
                id: Arc::from("a"),
                upstream_origin: "http://127.0.0.1:1".to_owned(),
                weight: 1,
                egress_client: Arc::new(
                    crate::egress::EgressClient::new(crate::egress::EgressConfig::default())
                        .expect("test egress client should build"),
                ),
                health: super::super::health::UpstreamHealthState::new("payments", "a", None),
                health_config: None,
                circuit: None,
            }],
            &config::UpstreamPoolLimitsConfig::default(),
            None,
        ))
    }
}
