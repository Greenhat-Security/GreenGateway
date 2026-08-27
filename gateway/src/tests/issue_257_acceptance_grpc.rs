//! Acceptance coverage for the gRPC data plane (#257).
//!
//! These tests drive the REAL listener over a real socket, because the
//! properties they check cannot be observed any other way:
//!
//! * that `axum::serve` still refuses an HTTP/2 preface on the data listener is
//!   a fact about hyper-util's resolved features, and a router-level harness
//!   never sees a preface at all;
//! * that a denied call reaches no upstream is a fact about the middleware
//!   stack the listener's router was built with, not about `handle_call`;
//! * that no HTTP/2 server exists when `GRPC_LISTEN_ADDR` is unset is a fact
//!   about `grpc_app` returning `None`.
//!
//! `scripts/check-egress-only.sh` states plainly that it cannot express any of
//! the three. This file is where they are actually enforced.

use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode};
use hyper::body::{Body as HttpBody, Frame, Incoming};
use tokio::{net::TcpListener, sync::mpsc};

use crate::{
    egress::DnsResolver,
    proxy::grpc::{listen::test_support, GrpcListener},
};

use super::*;

// ---------------------------------------------------------------------------
// Test bodies
// ---------------------------------------------------------------------------

struct TestBody {
    receiver: mpsc::Receiver<Frame<Bytes>>,
}

impl TestBody {
    fn from_frames(frames: Vec<Frame<Bytes>>) -> Self {
        let (sender, receiver) = mpsc::channel(frames.len().max(1));
        for frame in frames {
            sender.try_send(frame).expect("test body should accept");
        }
        Self { receiver }
    }

    fn message(payload: &[u8]) -> Self {
        Self::from_frames(vec![Frame::data(framed(payload))])
    }

    fn empty() -> Self {
        Self::from_frames(Vec::new())
    }
}

impl HttpBody for TestBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.receiver.poll_recv(context).map(|frame| frame.map(Ok))
    }
}

fn framed(payload: &[u8]) -> Bytes {
    let mut encoded = vec![0_u8];
    encoded.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("test payload length fits")
            .to_be_bytes(),
    );
    encoded.extend_from_slice(payload);

    Bytes::from(encoded)
}

// ---------------------------------------------------------------------------
// Upstream
// ---------------------------------------------------------------------------

/// A gRPC upstream that answers `OK` and counts the calls it received.
async fn spawn_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("acceptance upstream should bind");
    let address = listener
        .local_addr()
        .expect("acceptance upstream address should be available");
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&calls);
    let service = hyper::service::service_fn(move |request: hyper::Request<Incoming>| {
        let counter = Arc::clone(&counter);
        async move {
            let (_, mut body) = request.into_parts();
            while let Some(frame) =
                std::future::poll_fn(|context| Pin::new(&mut body).poll_frame(context)).await
            {
                if frame.is_err() {
                    break;
                }
            }
            counter.fetch_add(1, Ordering::SeqCst);
            let mut trailers = HeaderMap::new();
            trailers.insert("grpc-status", HeaderValue::from_static("0"));
            trailers.insert("grpc-message", HeaderValue::from_static("acceptance-ok"));
            Ok::<_, Infallible>(
                hyper::Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .body(TestBody::from_frames(vec![
                        Frame::data(framed(b"pong")),
                        Frame::trailers(trailers),
                    ]))
                    .expect("acceptance upstream response should build"),
            )
        }
    });
    test_support::spawn_upstream(listener, service);

    (address, calls)
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

struct CountingResolver {
    answers: HashMap<String, Vec<IpAddr>>,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl DnsResolver for CountingResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.answers.get(host) {
            Some(addresses) => Ok(addresses
                .iter()
                .map(|address| SocketAddr::new(*address, port))
                .collect()),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "unexpected gRPC acceptance host",
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

fn default_grpc_settings() -> config::UpstreamGrpcConfig {
    config::UpstreamGrpcConfig {
        max_concurrent_calls: config::DEFAULT_GRPC_MAX_CONCURRENT_CALLS,
        max_concurrent_calls_per_endpoint: None,
        queue_depth: config::DEFAULT_GRPC_QUEUE_DEPTH,
        queue_timeout_ms: config::DEFAULT_GRPC_QUEUE_TIMEOUT_MS,
        connect_timeout_ms: 2_000,
        idle_timeout_ms: 0,
        max_duration_ms: 10_000,
        max_message_bytes: config::DEFAULT_GRPC_MAX_MESSAGE_BYTES,
        max_request_bytes: config::DEFAULT_GRPC_MAX_STREAM_BYTES,
        max_response_bytes: config::DEFAULT_GRPC_MAX_STREAM_BYTES,
        max_metadata_entries: config::DEFAULT_GRPC_MAX_METADATA_ENTRIES,
    }
}

fn grpc_config(upstream: SocketAddr, grpc_listener: bool) -> config::Config {
    let route = config::UpstreamRouteConfig {
        id: Some("grpc-route".to_owned()),
        connection_id: None,
        path_prefix: Some("/".to_owned()),
        host: None,
        upstream_url: String::new(),
        upstreams: vec![config::UpstreamEndpointConfig {
            id: "primary".to_owned(),
            url: format!("http://upstream.test:{}", upstream.port()),
            weight: 1,
            tls_ca_bundle_path: None,
            client_identity_pem_path: None,
        }],
        load_balancing: config::UpstreamLoadBalancingConfig::default(),
        request_body: config::UpstreamRequestBodyConfig::default(),
        sse: None,
        websocket: None,
        grpc: Some(default_grpc_settings()),
        limits: config::UpstreamPoolLimitsConfig::default(),
        health_check: None,
        retry: None,
        circuit_breaker: None,
        timeout_ms: None,
        response_idle_timeout_ms: None,
        connect_timeout_ms: None,
        add_request_headers: HashMap::new(),
        strip_request_headers: Vec::new(),
        tls_ca_bundle_path: None,
        openapi_spec_path: None,
    };

    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.csrf_enabled = false;
    config.upstream_routes = vec![route];
    config.egress_allowed_hosts = vec!["upstream.test".to_owned()];
    config.egress_deny_private_ips = false;
    if grpc_listener {
        // Port zero: the listener binds an ephemeral port and reports it back,
        // so nothing here races another test for a fixed one.
        config.grpc_listen_addr = Some(
            "127.0.0.1:0"
                .parse()
                .expect("test gRPC listen address should parse"),
        );
    }

    config
}

struct Harness {
    data_addr: SocketAddr,
    grpc_addr: Option<SocketAddr>,
    dns_calls: Arc<AtomicUsize>,
    audit: audit::sink::tests::CaptureSink,
    shutdown: tokio_util::sync::CancellationToken,
}

impl Harness {
    fn grpc_addr(&self) -> SocketAddr {
        self.grpc_addr
            .expect("this harness was built with a gRPC listener")
    }

    fn dns_calls(&self) -> usize {
        self.dns_calls.load(Ordering::SeqCst)
    }

    async fn wait_for_grpc_audit(&self) -> audit::AuditEvent {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(event) = self
                    .audit
                    .events()
                    .into_iter()
                    .find(|event| event.event_type == audit::event::UPSTREAM_GRPC_CALL)
                {
                    return event;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("a gRPC call audit event should be emitted")
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

async fn spawn_gateway(config: config::Config, upstream: SocketAddr) -> Harness {
    let dns_calls = Arc::new(AtomicUsize::new(0));
    let resolver = Arc::new(CountingResolver {
        answers: HashMap::from([("upstream.test".to_owned(), vec![upstream.ip()])]),
        calls: Arc::clone(&dns_calls),
    });
    let lifecycle = GatewayLifecycle::new();
    let sink = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(sink.clone()));
    // A local recorder handle, deliberately NOT installed globally: the
    // WebSocket acceptance suite owns the process recorder, and installing a
    // second one would panic whichever suite ran second.
    let metrics = PrometheusBuilder::new().build_recorder().handle();
    let apps = gateway_app_with_process_started_at_and_overrides(
        config,
        metrics,
        audit_log,
        test_audit_event_sender(),
        Instant::now(),
        GatewayAppBuildOverrides {
            lifecycle: Some(lifecycle.clone()),
            egress_resolver: Some(resolver as Arc<dyn DnsResolver>),
            disable_proxy_health_checks: true,
            ..GatewayAppBuildOverrides::default()
        },
    )
    .expect("gRPC acceptance app should build");

    let data_router = match apps.http {
        GatewayApp::Unified(router) => router,
        GatewayApp::Split { .. } => panic!("gRPC acceptance app should be unified"),
    };
    lifecycle.mark_ready();
    let shutdown = tokio_util::sync::CancellationToken::new();

    // The data listener is served exactly as production serves it, through
    // `axum::serve`. That is the whole point of the preface test below: it must
    // be the same builder, not a stand-in.
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("data listener should bind");
    let data_addr = listener
        .local_addr()
        .expect("data address should be available");
    let data_shutdown = shutdown.clone();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            data_router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(data_shutdown.cancelled_owned())
        .await;
    });

    let grpc_addr = match apps.grpc {
        Some(grpc) => {
            let listener = GrpcListener::bind(grpc.address, grpc.router, grpc.limits)
                .await
                .expect("gRPC listener should bind");
            let address = listener
                .local_addr()
                .expect("gRPC address should be available");
            let grpc_shutdown = shutdown.clone();
            tokio::spawn(async move {
                let _ = listener.serve(grpc_shutdown).await;
            });
            Some(address)
        }
        None => None,
    };

    Harness {
        data_addr,
        grpc_addr,
        dns_calls,
        audit: sink,
        shutdown,
    }
}

// ---------------------------------------------------------------------------
// Calling
// ---------------------------------------------------------------------------

struct CallResult {
    http_status: StatusCode,
    headers: HeaderMap,
    messages: Vec<Vec<u8>>,
    trailers: Option<HeaderMap>,
}

impl CallResult {
    fn grpc_status(&self) -> String {
        self.trailers
            .as_ref()
            .and_then(|trailers| trailers.get("grpc-status"))
            .or_else(|| self.headers.get("grpc-status"))
            .and_then(|value| value.to_str().ok())
            .unwrap_or("<absent>")
            .to_owned()
    }

    fn grpc_message(&self) -> String {
        self.trailers
            .as_ref()
            .and_then(|trailers| trailers.get("grpc-message"))
            .or_else(|| self.headers.get("grpc-message"))
            .and_then(|value| value.to_str().ok())
            .unwrap_or("<absent>")
            .to_owned()
    }
}

/// Makes one gRPC call over h2c prior knowledge.
///
/// Returns `Err` when the connection itself could not be established, which is
/// exactly what a listener that refuses an HTTP/2 preface produces.
async fn grpc_call(
    address: SocketAddr,
    path: &str,
    body: TestBody,
    configure: impl FnOnce(&mut HeaderMap),
) -> Result<CallResult, String> {
    let mut sender = crate::egress::grpc_test_client::connect::<TestBody>(address)
        .await
        .map_err(|error| format!("connect: {error}"))?;
    sender
        .ready()
        .await
        .map_err(|error| format!("ready: {error}"))?;

    let mut request = hyper::Request::builder()
        .method("POST")
        .uri(format!("http://{address}{path}"))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(body)
        .map_err(|error| format!("build: {error}"))?;
    configure(request.headers_mut());

    let response = sender
        .send_request(request)
        .await
        .map_err(|error| format!("send: {error}"))?;
    let (parts, mut response_body) = response.into_parts();
    let mut data = Vec::new();
    let mut trailers = None;
    while let Some(frame) =
        std::future::poll_fn(|context| Pin::new(&mut response_body).poll_frame(context)).await
    {
        let frame = frame.map_err(|error| format!("body: {error}"))?;
        match frame.into_data() {
            Ok(chunk) => {
                if !chunk.is_empty() {
                    data.push(chunk);
                }
            }
            Err(frame) => {
                if let Ok(map) = frame.into_trailers() {
                    trailers = Some(map);
                }
            }
        }
    }

    let mut joined = Vec::new();
    for chunk in &data {
        joined.extend_from_slice(chunk);
    }
    let mut messages = Vec::new();
    let mut offset = 0;
    while offset + 5 <= joined.len() {
        let length = u32::from_be_bytes([
            joined[offset + 1],
            joined[offset + 2],
            joined[offset + 3],
            joined[offset + 4],
        ]) as usize;
        offset += 5;
        let end = (offset + length).min(joined.len());
        messages.push(joined[offset..end].to_vec());
        offset = end;
    }

    Ok(CallResult {
        http_status: parts.status,
        headers: parts.headers,
        messages,
        trailers,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The load-bearing pair.
///
/// The same client code, the same preface, two listeners: served on the gRPC
/// listener and refused on the data listener. Asserting only the refusal would
/// pass against a broken client; asserting only the success would say nothing
/// about the data listener. Together they show that HTTP/2 is confined to the
/// listener that was configured for it.
#[tokio::test]
async fn an_http2_preface_is_served_on_the_grpc_listener_and_refused_on_the_data_listener() {
    let (upstream, calls) = spawn_upstream().await;
    let harness = spawn_gateway(grpc_config(upstream, true), upstream).await;

    let served = grpc_call(
        harness.grpc_addr(),
        "/acceptance.Service/Ping",
        TestBody::message(b"ping"),
        |_| {},
    )
    .await
    .expect("the gRPC listener must serve an HTTP/2 prior-knowledge connection");
    assert_eq!(served.http_status, StatusCode::OK);
    assert_eq!(served.grpc_status(), "0");
    assert_eq!(served.grpc_message(), "acceptance-ok");
    assert_eq!(served.messages, vec![b"pong".to_vec()]);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let refused = grpc_call(
        harness.data_addr,
        "/acceptance.Service/Ping",
        TestBody::message(b"ping"),
        |_| {},
    )
    .await;
    let error = refused
        .err()
        .expect("the data listener must refuse an HTTP/2 preface, not serve it");
    assert!(
        error.starts_with("connect:") || error.starts_with("ready:") || error.starts_with("send:"),
        "the data listener answered an HTTP/2 preface with something other than a refusal: \
         {error}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "the refused preface reached the upstream"
    );
}

/// A client that is not speaking HTTP/2 is refused by the listener itself.
///
/// The listener reads the HTTP/2 connection preface before it builds a service,
/// so a non-HTTP/2 client is dropped before a router, a request, or a request
/// extension exists. Stated plainly about what this does and does not pin: it
/// pins that such a client is refused rather than served, and that nothing
/// reaches the upstream. It does NOT discriminate the preface READ from hyper's
/// own handshake failure, because both close the connection without writing.
/// The read exists for the budget on it, which is what stops a silent socket
/// from holding a connection slot; that budget is ten seconds of wall clock and
/// is deliberately not spent in this suite.
#[tokio::test]
async fn a_client_that_is_not_speaking_http2_is_refused_by_the_listener() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let (upstream, calls) = spawn_upstream().await;
    let harness = spawn_gateway(grpc_config(upstream, true), upstream).await;

    let mut stream = tokio::net::TcpStream::connect(harness.grpc_addr())
        .await
        .expect("the listener should accept the connection");
    stream
        .write_all(
            b"POST /acceptance.Service/Ping HTTP/1.1\r\nhost: gateway\r\ncontent-length: 0\r\n\r\n",
        )
        .await
        .expect("the probe should be written");

    let mut answer = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut answer))
        .await
        .expect("the listener must close a non-HTTP/2 connection, not hold it open");
    assert_eq!(
        read.unwrap_or(0),
        0,
        "the listener answered a non-HTTP/2 client with {} byte(s): {:?}",
        answer.len(),
        String::from_utf8_lossy(&answer)
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a non-HTTP/2 client reached the upstream"
    );
    assert_eq!(harness.dns_calls(), 0);
}

/// With `GRPC_LISTEN_ADDR` unset, no HTTP/2 server is constructed at all.
///
/// Checked at the source -- `grpc_app` returns `None` -- rather than by probing
/// a port, because "nothing was listening on the port I guessed" is not
/// evidence that nothing was built.
#[tokio::test]
async fn no_grpc_listener_is_built_when_grpc_listen_addr_is_unset() {
    let (upstream, _calls) = spawn_upstream().await;
    let harness = spawn_gateway(grpc_config(upstream, false), upstream).await;

    assert!(
        harness.grpc_addr.is_none(),
        "an HTTP/2 listener was built with GRPC_LISTEN_ADDR unset"
    );
}

/// The gRPC router carries no admin surface and no gateway-owned probe routes.
///
/// Its only route is the proxy fallback, so a path the gateway serves on the
/// data listener is answered on the gRPC listener the way any other unmatched
/// method path is: refused, never served.
#[tokio::test]
async fn the_grpc_listener_serves_no_admin_or_probe_routes() {
    let (upstream, calls) = spawn_upstream().await;
    let harness = spawn_gateway(grpc_config(upstream, true), upstream).await;

    for path in ["/health", "/metrics", "/readyz", "/v1/admin/status"] {
        let result = grpc_call(harness.grpc_addr(), path, TestBody::empty(), |_| {})
            .await
            .expect("the gRPC listener should answer rather than drop the connection");
        assert_eq!(
            result.http_status,
            StatusCode::OK,
            "{path}: a gRPC answer is always HTTP 200"
        );
        assert_eq!(
            result.grpc_status(),
            "3",
            "{path} must be refused as INVALID_ARGUMENT by the method grammar, not served; \
             grpc-message was {}",
            result.grpc_message()
        );
        assert!(
            result.messages.is_empty(),
            "{path} produced a message body on the gRPC listener"
        );
    }

    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a gateway-owned path was forwarded upstream from the gRPC listener"
    );
    assert_eq!(harness.dns_calls(), 0);
}

/// A call the authentication layer refuses costs no DNS lookup and no upstream
/// call, and comes back as a gRPC status rather than an HTTP error.
///
/// The successful call at the end is the control: without it, a test asserting
/// only "the denial was UNAUTHENTICATED and nothing reached the upstream" would
/// also pass against a gateway that refused every call.
#[tokio::test]
async fn an_unauthenticated_call_is_refused_as_a_grpc_status_before_any_egress() {
    let (upstream, calls) = spawn_upstream().await;
    let mut config = grpc_config(upstream, true);
    config.auth_enabled = true;
    config.auth_mode = config::AuthMode::Required;
    // One exempt service, so the control call below runs through the SAME
    // listener, the same router and the same middleware stack as the denial.
    // A control that needed a second harness would only show that some other
    // configuration works.
    config.auth_exempt_paths = vec!["/exempt.Service".to_owned()];
    let harness = spawn_gateway(config, upstream).await;

    let denied = grpc_call(
        harness.grpc_addr(),
        "/acceptance.Service/Ping",
        TestBody::message(b"ping"),
        |_| {},
    )
    .await
    .expect("a denied call must still be answered, not dropped");

    assert_eq!(
        denied.http_status,
        StatusCode::OK,
        "a policy denial must be a gRPC status, not an HTTP error status"
    );
    assert_eq!(
        denied.grpc_status(),
        "16",
        "an unauthenticated call must map to UNAUTHENTICATED; grpc-message was {}",
        denied.grpc_message()
    );
    assert!(
        denied.messages.is_empty(),
        "a denied call must never carry a message envelope"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "an unauthenticated call reached the upstream"
    );
    assert_eq!(
        harness.dns_calls(),
        0,
        "an unauthenticated call resolved the endpoint's name"
    );

    // The control: the same call with a credential does reach the upstream, so
    // the assertions above are about the denial rather than about a gateway
    // that refuses everything.
    let allowed = grpc_call(
        harness.grpc_addr(),
        "/exempt.Service/Ping",
        TestBody::message(b"ping"),
        |_| {},
    )
    .await
    .expect("a call on an exempt path should be served");
    assert_eq!(allowed.grpc_status(), "0");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(harness.dns_calls() >= 1);
}

/// A call the direct policy refuses costs no DNS lookup and no upstream call.
///
/// Separate from the authentication case because it is a different middleware
/// answering a different HTTP status, and the mapping from HTTP to gRPC is the
/// thing being checked as much as the denial is.
#[tokio::test]
async fn an_rbac_denial_is_refused_as_permission_denied_before_any_egress() {
    let (upstream, calls) = spawn_upstream().await;
    let policy = TempPolicyFile::new(
        &serde_json::json!({
            "schema_version": "0.1.0",
            "id": "grpc-deny-all",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {},
            "routes": []
        })
        .to_string(),
    );
    let mut config = grpc_config(upstream, true);
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    let harness = spawn_gateway(config, upstream).await;

    let denied = grpc_call(
        harness.grpc_addr(),
        "/acceptance.Service/Ping",
        TestBody::message(b"ping"),
        |_| {},
    )
    .await
    .expect("a policy-denied call must still be answered, not dropped");

    assert_eq!(
        denied.http_status,
        StatusCode::OK,
        "a policy denial must be a gRPC status, not an HTTP error status"
    );
    assert_eq!(
        denied.grpc_status(),
        "7",
        "a deny-all policy must map to PERMISSION_DENIED; grpc-message was {}",
        denied.grpc_message()
    );
    assert!(denied.messages.is_empty());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a policy-denied call reached the upstream"
    );
    assert_eq!(
        harness.dns_calls(),
        0,
        "a policy-denied call resolved the endpoint's name"
    );
}

/// The listener's `max_header_list_size` is the configured value.
///
/// Asserted by exceeding it: an HTTP/2 server that never set the bound would
/// run on hyper's own 16 KiB default and accept this request, which the paired
/// under-limit call proves is otherwise servable.
#[tokio::test]
async fn the_configured_metadata_byte_ceiling_is_enforced_by_the_listener() {
    let (upstream, calls) = spawn_upstream().await;
    let mut config = grpc_config(upstream, true);
    config.grpc_max_metadata_bytes = 2_048;
    let harness = spawn_gateway(config, upstream).await;

    let under_limit = grpc_call(
        harness.grpc_addr(),
        "/acceptance.Service/Ping",
        TestBody::message(b"ping"),
        |headers| {
            headers.insert(
                "x-metadata",
                HeaderValue::from_str(&"a".repeat(512)).expect("test header value"),
            );
        },
    )
    .await
    .expect("metadata under the ceiling should be served");
    assert_eq!(under_limit.grpc_status(), "0");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let over_limit = grpc_call(
        harness.grpc_addr(),
        "/acceptance.Service/Ping",
        TestBody::message(b"ping"),
        |headers| {
            headers.insert(
                "x-metadata",
                HeaderValue::from_str(&"a".repeat(8_192)).expect("test header value"),
            );
        },
    )
    .await;
    match over_limit {
        Err(error) => assert!(
            error.starts_with("send:") || error.starts_with("body:"),
            "unexpected failure for oversized metadata: {error}"
        ),
        Ok(result) => assert_ne!(
            result.grpc_status(),
            "0",
            "metadata over the configured ceiling was served; the listener is running on \
             hyper's default rather than the configured max_header_list_size"
        ),
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "an over-sized metadata block reached the upstream"
    );
}

/// The end-to-end audit trail for a served call.
#[tokio::test]
async fn a_served_call_is_audited_with_bounded_facts_only() {
    let (upstream, _calls) = spawn_upstream().await;
    let harness = spawn_gateway(grpc_config(upstream, true), upstream).await;

    let served = grpc_call(
        harness.grpc_addr(),
        "/acceptance.Service/Ping",
        TestBody::message(b"acceptance-protobuf-canary"),
        |_| {},
    )
    .await
    .expect("the call should be served");
    assert_eq!(served.grpc_status(), "0");

    let event = harness.wait_for_grpc_audit().await;
    assert_eq!(event.payload["pool_id"], "grpc-route");
    assert_eq!(event.payload["method"], "/acceptance.Service/Ping");
    assert_eq!(event.payload["result"], "allowed");
    assert_eq!(event.payload["grpc_status"], "ok");

    let serialized = serde_json::to_string(&event).expect("audit event should serialize");
    assert!(
        !serialized.contains("acceptance-protobuf-canary"),
        "protobuf bytes reached the audit log: {serialized}"
    );
    assert!(
        !serialized.contains("acceptance-ok"),
        "the upstream's grpc-message reached the audit log: {serialized}"
    );
}

/// Keeps the unused-import lint honest: `HashSet` is used by `test_config`'s
/// surrounding module rather than by this file.
#[allow(dead_code)]
fn _unused(_: HashSet<u8>) {}
