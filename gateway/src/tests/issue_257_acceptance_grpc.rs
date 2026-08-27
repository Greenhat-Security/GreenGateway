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
    /// Held by a body that must never end. `from_frames` drops its sender, so
    /// the channel closes and the body reports end-of-stream once the frames
    /// run out; keeping the sender alive is what turns the same channel into an
    /// upstream that sent some messages and then went quiet forever.
    _open: Option<mpsc::Sender<Frame<Bytes>>>,
}

impl TestBody {
    fn from_frames(frames: Vec<Frame<Bytes>>) -> Self {
        let (sender, receiver) = mpsc::channel(frames.len().max(1));
        for frame in frames {
            sender.try_send(frame).expect("test body should accept");
        }
        Self {
            receiver,
            _open: None,
        }
    }

    /// The given frames, and then silence: no trailers and no end of stream.
    fn never_ending(frames: Vec<Frame<Bytes>>) -> Self {
        let (sender, receiver) = mpsc::channel(frames.len().max(1));
        for frame in frames {
            sender.try_send(frame).expect("test body should accept");
        }
        Self {
            receiver,
            _open: Some(sender),
        }
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

    // Two refusals, deliberately told apart rather than lumped together. The
    // gateway's own reserved namespace is refused BEFORE the method grammar
    // runs, because a path that survives the grammar is a path the proxy would
    // otherwise forward -- `/admin/Ping` is a well-formed method path. Anything
    // outside that namespace is still refused by the grammar, which is what
    // keeps the grammar covered here rather than shadowed by the new check.
    let refusals = [
        ("/health", "12", "gateway_owned_path"),
        ("/metrics", "12", "gateway_owned_path"),
        ("/readyz", "12", "gateway_owned_path"),
        ("/v1/admin/status", "12", "gateway_owned_path"),
        ("/admin/Ping", "12", "gateway_owned_path"),
        ("/notamethod", "3", "method_path_shape"),
        ("/a//b", "12", "unsafe_path"),
    ];
    for (path, status, reason) in refusals {
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
            status,
            "{path} must be refused, not served; grpc-message was {}",
            result.grpc_message()
        );
        assert_eq!(
            result.grpc_message(),
            reason,
            "{path} was refused by the wrong check"
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
    let store = TempDb::new("grpc-unauthenticated-control");
    let mut config = grpc_config(upstream, true);
    config.auth_enabled = true;
    config.auth_mode = config::AuthMode::Required;
    // A real credential, so the control call below runs through the SAME
    // listener, the same router and the same middleware stack as the denial. A
    // control that needed a second harness would only show that some other
    // configuration works.
    //
    // This was an `AUTH_EXEMPT_PATHS` entry until the #333 review. The exempt
    // lists no longer apply on the gRPC listener -- see `grpc_app` for why --
    // so an exempt path is no longer a way to get a call served, and a control
    // built on one would have been testing the hole rather than the fix.
    let token = service_token_credential(&mut config, &store);
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
        "/acceptance.Service/Ping",
        TestBody::message(b"ping"),
        |headers| {
            headers.insert(
                "authorization",
                HeaderValue::from_str(&format!("Bearer {token}"))
                    .expect("bearer value should build"),
            );
        },
    )
    .await
    .expect("a call with a credential should be served");
    assert_eq!(
        allowed.grpc_status(),
        "0",
        "the control call was refused: {}",
        allowed.grpc_message()
    );
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

// ---------------------------------------------------------------------------
// Deadlines that cover the wait for response HEADERS (#333 review)
// ---------------------------------------------------------------------------

/// A gRPC upstream that counts ACCEPTED CONNECTIONS as well as served calls,
/// and stalls before answering calls to one nominated service.
///
/// Accepts are counted rather than only calls because "the gateway never
/// proxied this" has to be observed where the gateway would first touch the
/// network. A call counter is incremented by the upstream's own handler, so a
/// gateway that connected and sent HEADERS the handler had not answered yet
/// still reads as zero calls while having very much reached the upstream.
struct ProbeUpstream {
    address: SocketAddr,
    accepts: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
}

impl ProbeUpstream {
    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

/// Calls whose SERVICE NAME starts with this are answered only after the
/// stall.
const STALLING_SERVICE_PREFIX: &str = "/stall.";
/// Calls whose service name contains this get HEADERS and whatever messages
/// they were given, and then nothing ever again -- no further messages, no
/// trailers, no end of stream.
///
/// A substring rather than a prefix so that the two behaviours compose: a
/// service named `stall.quiet_Service` stalls AND never ends, which is the only
/// way to spend part of a deadline before HEADERS and the rest after them.
const QUIET_SERVICE_MARKER: &str = "quiet";

/// Spawns an upstream that stalls `stall` before sending HEADERS for
/// `STALLING_SERVICE_PREFIX` and answers everything else immediately.
///
/// The stall is placed before the response is produced AND before the request
/// body is drained, because that is the ordinary shape of a slow unary handler:
/// grpc-go and tonic send response HEADERS when the handler returns, so every
/// slow unary upstream leaves the caller waiting on HEADERS with the stream
/// already open.
async fn spawn_probe_upstream(stall: Duration) -> ProbeUpstream {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("probe upstream should bind");
    let address = listener
        .local_addr()
        .expect("probe upstream address should be available");
    let accepts = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let accept_counter = Arc::clone(&accepts);
    let call_counter = Arc::clone(&calls);

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            accept_counter.fetch_add(1, Ordering::SeqCst);
            let call_counter = Arc::clone(&call_counter);
            tokio::spawn(async move {
                let service =
                    hyper::service::service_fn(move |request: hyper::Request<Incoming>| {
                        let call_counter = Arc::clone(&call_counter);
                        let path = request.uri().path();
                        let stalls = path.starts_with(STALLING_SERVICE_PREFIX);
                        let quiet = path.contains(QUIET_SERVICE_MARKER);
                        async move {
                            if stalls {
                                tokio::time::sleep(stall).await;
                            }
                            let (_, mut body) = request.into_parts();
                            while let Some(frame) = std::future::poll_fn(|context| {
                                Pin::new(&mut body).poll_frame(context)
                            })
                            .await
                            {
                                if frame.is_err() {
                                    break;
                                }
                            }
                            call_counter.fetch_add(1, Ordering::SeqCst);
                            let mut trailers = HeaderMap::new();
                            trailers.insert("grpc-status", HeaderValue::from_static("0"));
                            trailers.insert("grpc-message", HeaderValue::from_static("probe-ok"));
                            let response_body = if quiet {
                                TestBody::never_ending(vec![Frame::data(framed(b"pong"))])
                            } else {
                                TestBody::from_frames(vec![
                                    Frame::data(framed(b"pong")),
                                    Frame::trailers(trailers),
                                ])
                            };
                            Ok::<_, Infallible>(
                                hyper::Response::builder()
                                    .status(200)
                                    .header("content-type", "application/grpc")
                                    .body(response_body)
                                    .expect("probe upstream response should build"),
                            )
                        }
                    });
                test_support::serve_one(stream, service).await;
            });
        }
    });

    ProbeUpstream {
        address,
        accepts,
        calls,
    }
}

/// A TCP peer that accepts and then never sends its HTTP/2 connection preface.
///
/// The accepted streams are held rather than dropped: dropping would close the
/// socket and the gateway would see a connection error, which is not the case
/// under test. What is under test is silence.
async fn spawn_silent_peer() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("silent peer should bind");
    let address = listener
        .local_addr()
        .expect("silent peer address should be available");
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepts);

    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            held.push(stream);
        }
    });

    (address, accepts)
}

/// Replaces the route's gRPC policy wholesale.
fn with_grpc_settings(config: &mut config::Config, settings: config::UpstreamGrpcConfig) {
    config
        .upstream_routes
        .first_mut()
        .expect("the gRPC acceptance config has exactly one route")
        .grpc = Some(settings);
}

/// The client's `grpc-timeout` bounds the wait for the upstream's HEADERS.
///
/// The measurement is the assertion. A test that only checked "a slow call
/// eventually fails" would pass against a gateway with no timer at all, because
/// the call does eventually finish -- with `grpc-status: 0`, ten seconds after a
/// half-second deadline. So this asserts the status the deadline produces AND
/// that the answer arrived well before the upstream's own handler could have
/// produced one.
#[tokio::test]
async fn a_client_deadline_bounds_the_wait_for_response_headers() {
    let upstream = spawn_probe_upstream(Duration::from_secs(5)).await;
    let mut config = grpc_config(upstream.address, true);
    with_grpc_settings(
        &mut config,
        config::UpstreamGrpcConfig {
            // Deliberately far above both the client's deadline and the
            // upstream's stall: the bound under test is the CLIENT's.
            max_duration_ms: 30_000,
            ..default_grpc_settings()
        },
    );
    let harness = spawn_gateway(config, upstream.address).await;

    let started = Instant::now();
    let result = grpc_call(
        harness.grpc_addr(),
        "/stall.Service/Slow",
        TestBody::message(b"ping"),
        |headers| {
            headers.insert("grpc-timeout", HeaderValue::from_static("500m"));
        },
    )
    .await
    .expect("a call whose deadline elapses must still be answered");
    let elapsed = started.elapsed();

    assert_eq!(
        result.grpc_status(),
        "4",
        "a 500ms deadline against a 5s upstream must be DEADLINE_EXCEEDED after {}ms; \
         grpc-message was {}",
        elapsed.as_millis(),
        result.grpc_message()
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "the deadline did not bound the wait for HEADERS: the call took {}ms against a 500ms \
         deadline and a 5s upstream handler",
        elapsed.as_millis()
    );
    assert!(
        elapsed >= Duration::from_millis(400),
        "the call failed in {}ms, before its own 500ms deadline: this test would pass against a \
         gateway that refused the call for some other reason",
        elapsed.as_millis()
    );
    assert!(
        result.messages.is_empty(),
        "an expired call must never carry a message envelope"
    );
}

/// An expired deadline releases the route's call slot before HEADERS arrive.
///
/// The route admits exactly one call and queues none, so the second call is the
/// instrument: if the first call's reservations are still held it comes back
/// `RESOURCE_EXHAUSTED`/`queue_full`, and if they were released it is served.
/// One idle stream taking the route's entire gRPC capacity is the exhaustion
/// this pins -- at the default `max_concurrent_calls` of 256 it takes three
/// connections' worth of streams to close a route to every other caller.
#[tokio::test]
async fn an_expired_deadline_releases_the_call_slot_before_headers_arrive() {
    let upstream = spawn_probe_upstream(Duration::from_secs(30)).await;
    let mut config = grpc_config(upstream.address, true);
    with_grpc_settings(
        &mut config,
        config::UpstreamGrpcConfig {
            max_concurrent_calls: 1,
            queue_depth: 0,
            queue_timeout_ms: 10,
            max_duration_ms: 300,
            idle_timeout_ms: 200,
            ..default_grpc_settings()
        },
    );
    let harness = spawn_gateway(config, upstream.address).await;
    let grpc_addr = harness.grpc_addr();

    let stalled = tokio::spawn(async move {
        let started = Instant::now();
        let result = grpc_call(
            grpc_addr,
            "/stall.Service/Hang",
            TestBody::message(b"ping"),
            |_| {},
        )
        .await;
        (result, started.elapsed())
    });

    // Comfortably past the route's 300ms ceiling and nowhere near the 30s the
    // upstream will take.
    tokio::time::sleep(Duration::from_millis(900)).await;

    let started = Instant::now();
    let second = grpc_call(
        grpc_addr,
        "/acceptance.Service/Ping",
        TestBody::message(b"ping"),
        |_| {},
    )
    .await
    .expect("the second call must be answered");
    let second_elapsed = started.elapsed();

    assert_eq!(
        second.grpc_status(),
        "0",
        "a second call was refused after {}ms while the first call sat waiting for HEADERS it was \
         no longer entitled to wait for; grpc-message was {}",
        second_elapsed.as_millis(),
        second.grpc_message()
    );

    let (first, first_elapsed) = stalled.await.expect("the stalled call task should finish");
    let first = first.expect("the stalled call must be answered, not dropped");
    assert_eq!(
        first.grpc_status(),
        "4",
        "the route ceiling must end the call as DEADLINE_EXCEEDED after {}ms; grpc-message was {}",
        first_elapsed.as_millis(),
        first.grpc_message()
    );
    assert!(
        first_elapsed < Duration::from_secs(3),
        "the route's 300ms ceiling did not bound the wait for HEADERS: the call took {}ms",
        first_elapsed.as_millis()
    );
}

/// `connect_timeout_ms` bounds establishing a USABLE HTTP/2 connection.
///
/// Against a peer that accepts TCP and then says nothing, hyper's `handshake()`
/// resolves as soon as the gateway's own preface is written and `ready()`
/// resolves because a peer that has sent no SETTINGS has not constrained the
/// stream count yet. So both complete against a peer that has not proved it
/// speaks HTTP/2 at all, and the connect budget is spent on nothing.
///
/// The route's total-duration ceiling is set far above the connect budget so
/// that the deadline cannot be what ends the call: the elapsed time and the
/// reason together say which timer fired.
#[tokio::test]
async fn the_connect_budget_bounds_the_http2_handshake_not_only_the_tcp_connect() {
    let (silent, accepts) = spawn_silent_peer().await;
    let mut config = grpc_config(silent, true);
    with_grpc_settings(
        &mut config,
        config::UpstreamGrpcConfig {
            connect_timeout_ms: 1_000,
            max_duration_ms: 30_000,
            ..default_grpc_settings()
        },
    );
    let harness = spawn_gateway(config, silent).await;

    let started = Instant::now();
    let result = grpc_call(
        harness.grpc_addr(),
        "/acceptance.Service/Ping",
        TestBody::message(b"ping"),
        |_| {},
    )
    .await
    .expect("a call to an unusable peer must still be answered");
    let elapsed = started.elapsed();

    assert!(
        accepts.load(Ordering::SeqCst) >= 1,
        "the silent peer never accepted, so this test proved nothing"
    );
    assert_eq!(
        result.grpc_message(),
        "grpc_connect_timeout",
        "a peer that never sent SETTINGS must exhaust the connect budget, not some later timer; \
         the call took {}ms and reported grpc-status {}",
        elapsed.as_millis(),
        result.grpc_status()
    );
    assert_eq!(
        result.grpc_status(),
        "14",
        "the connect budget elapsing is UNAVAILABLE, never the caller's DEADLINE_EXCEEDED"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the connect budget did not bound the handshake: 1000ms was configured and the call took \
         {}ms",
        elapsed.as_millis()
    );
    assert!(
        elapsed >= Duration::from_millis(800),
        "the call failed in {}ms, before its own 1000ms connect budget could elapse",
        elapsed.as_millis()
    );
}

// ---------------------------------------------------------------------------
// Auth/RBAC exemptions on the gRPC listener (#333 review)
// ---------------------------------------------------------------------------

/// Creates a service token and points `config` at the store holding it.
fn service_token_credential(config: &mut config::Config, store: &TempDb) -> String {
    let token_store =
        auth::tokens::SqliteTokenStore::open(&store.path).expect("token store should open");
    let created = token_store
        .create(auth::tokens::CreateTokenRequest {
            scopes: vec!["grpc-client".to_owned()],
            created_by: "grpc-acceptance".to_owned(),
            expires_at: None,
        })
        .expect("service token should create");
    config.service_token_sqlite_path = Some(store.path.to_string_lossy().into_owned());

    created.plaintext_token
}

/// A gateway-owned exempt entry must not grant an unauthenticated upstream call
/// on the gRPC listener.
///
/// `default_admin_exempt_paths` pushes `ADMIN_PREFIX` into both
/// `AUTH_EXEMPT_PATHS` and `RBAC_EXEMPT_PATHS`, exempt entries are
/// segment-boundary prefixes, and `admin` and `Ping` are both valid protobuf
/// identifiers -- so `/admin/Ping` passes the method grammar, matches the
/// `/admin` exemption, and on the HTTP listener would then be refused by
/// `is_gateway_owned_path` before the proxy. This listener has no such refusal
/// unless it is written here.
///
/// Asserted by counting ACCEPTS. A status code says what the gateway told the
/// client; only the accept count says whether it opened a connection to
/// somebody else's server first.
#[tokio::test]
async fn a_gateway_owned_exempt_path_is_never_proxied_from_the_grpc_listener() {
    let upstream = spawn_probe_upstream(Duration::ZERO).await;
    let store = TempDb::new("grpc-exempt-upstream");
    let mut config = grpc_config(upstream.address, true);
    config.auth_enabled = true;
    config.auth_mode = config::AuthMode::Required;
    // The production defaults, restated here so this test fails if they change
    // out from under it rather than silently stopping to cover the case.
    assert!(
        config.auth_exempt_paths.iter().any(|path| path == "/admin"),
        "this test needs the default ADMIN_PREFIX exemption to be present"
    );
    assert!(
        config.rbac_exempt_paths.iter().any(|path| path == "/admin"),
        "this test needs the default ADMIN_PREFIX exemption to be present"
    );
    let token = service_token_credential(&mut config, &store);
    let harness = spawn_gateway(config, upstream.address).await;

    let exempt = grpc_call(
        harness.grpc_addr(),
        "/admin/Ping",
        TestBody::message(b"ping"),
        |_| {},
    )
    .await
    .expect("the gRPC listener must answer rather than drop the connection");

    assert_eq!(
        upstream.accepts(),
        0,
        "an unauthenticated call on the default /admin exemption opened a connection to the \
         upstream from the gRPC listener; grpc-status was {} ({})",
        exempt.grpc_status(),
        exempt.grpc_message()
    );
    assert_eq!(upstream.calls(), 0);
    assert_eq!(harness.dns_calls(), 0);
    assert_ne!(
        exempt.grpc_status(),
        "0",
        "an unauthenticated call on an exempt path was served"
    );

    // The control, through the same listener, router and middleware stack: a
    // real credential on a real method path does reach the upstream. Without it
    // this test would also pass against a gateway that refused everything.
    let allowed = grpc_call(
        harness.grpc_addr(),
        "/acceptance.Service/Ping",
        TestBody::message(b"ping"),
        |headers| {
            headers.insert(
                "authorization",
                HeaderValue::from_str(&format!("Bearer {token}"))
                    .expect("bearer value should build"),
            );
        },
    )
    .await
    .expect("an authenticated call should be served");
    assert_eq!(
        allowed.grpc_status(),
        "0",
        "the control call was refused: {}",
        allowed.grpc_message()
    );
    assert_eq!(upstream.accepts(), 1);
    assert_eq!(upstream.calls(), 1);
}

/// An operator-added exempt entry must not become an unauthenticated gRPC
/// service either.
///
/// This is the half `is_gateway_owned_path` cannot cover. `/public` is not
/// gateway-owned, so it is exempt by the operator's deliberate choice -- a
/// choice made about HTTP paths on the data listener. Read as a gRPC method
/// path, the same entry exempts the whole service named `public`, on a
/// different listener, with no second decision anywhere. The exempt lists
/// therefore do not apply on the gRPC listener at all: nothing gateway-owned is
/// served there, so an exemption there can only ever grant an unauthenticated
/// upstream call.
#[tokio::test]
async fn an_operator_exempt_prefix_is_not_an_unauthenticated_grpc_service() {
    let upstream = spawn_probe_upstream(Duration::ZERO).await;
    let store = TempDb::new("grpc-exempt-operator");
    let mut config = grpc_config(upstream.address, true);
    config.auth_enabled = true;
    config.auth_mode = config::AuthMode::Required;
    config.auth_exempt_paths.push("/public".to_owned());
    config.rbac_exempt_paths.push("/public".to_owned());
    let token = service_token_credential(&mut config, &store);
    let harness = spawn_gateway(config, upstream.address).await;

    let exempt = grpc_call(
        harness.grpc_addr(),
        "/public/Ping",
        TestBody::message(b"ping"),
        |_| {},
    )
    .await
    .expect("the gRPC listener must answer rather than drop the connection");

    assert_eq!(
        upstream.accepts(),
        0,
        "an HTTP path exemption became an unauthenticated gRPC service; grpc-status was {} ({})",
        exempt.grpc_status(),
        exempt.grpc_message()
    );
    assert_eq!(
        exempt.grpc_status(),
        "16",
        "an unauthenticated call must be UNAUTHENTICATED; grpc-message was {}",
        exempt.grpc_message()
    );

    // The control: the same path, with a credential, is served.
    let allowed = grpc_call(
        harness.grpc_addr(),
        "/public/Ping",
        TestBody::message(b"ping"),
        |headers| {
            headers.insert(
                "authorization",
                HeaderValue::from_str(&format!("Bearer {token}"))
                    .expect("bearer value should build"),
            );
        },
    )
    .await
    .expect("an authenticated call should be served");
    assert_eq!(
        allowed.grpc_status(),
        "0",
        "the control call was refused: {}",
        allowed.grpc_message()
    );
    assert_eq!(upstream.accepts(), 1);
}

/// The deadline also bounds the wait for an admission slot.
///
/// The queue timeout bounds how long the QUEUE will hold a call. It is not the
/// same question as how long the CALLER is still entitled to wait, and a call
/// admitted after its own deadline has passed is a slot spent on nobody. The
/// route here queues for five seconds and the client asks for three hundred
/// milliseconds, so the two answers are three seconds apart and the elapsed
/// time says which one was given.
#[tokio::test]
async fn a_client_deadline_bounds_the_wait_for_an_admission_slot() {
    let upstream = spawn_probe_upstream(Duration::from_secs(30)).await;
    let mut config = grpc_config(upstream.address, true);
    with_grpc_settings(
        &mut config,
        config::UpstreamGrpcConfig {
            max_concurrent_calls: 1,
            queue_depth: 4,
            queue_timeout_ms: 5_000,
            // High enough that the ROUTE ceiling cannot be what ends either
            // call: the bound under test is the queued caller's own.
            max_duration_ms: 60_000,
            idle_timeout_ms: 0,
            ..default_grpc_settings()
        },
    );
    let harness = spawn_gateway(config, upstream.address).await;
    let grpc_addr = harness.grpc_addr();

    // Takes the route's only slot and holds it: the upstream will not answer
    // for thirty seconds and this call is entitled to wait sixty.
    let holder = tokio::spawn(async move {
        grpc_call(
            grpc_addr,
            "/stall.Service/Hold",
            TestBody::message(b"ping"),
            |_| {},
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let started = Instant::now();
    let queued = grpc_call(
        grpc_addr,
        "/acceptance.Service/Ping",
        TestBody::message(b"ping"),
        |headers| {
            headers.insert("grpc-timeout", HeaderValue::from_static("300m"));
        },
    )
    .await
    .expect("a queued call whose deadline elapses must still be answered");
    let elapsed = started.elapsed();

    assert_eq!(
        queued.grpc_status(),
        "4",
        "a queued call whose own deadline elapsed must be DEADLINE_EXCEEDED, not the queue's \
         answer; it took {}ms and reported {}",
        elapsed.as_millis(),
        queued.grpc_message()
    );
    assert_eq!(
        queued.grpc_message(),
        "deadline_exceeded",
        "the queued call was refused by the wrong check after {}ms",
        elapsed.as_millis()
    );
    assert!(
        elapsed < Duration::from_millis(2_000),
        "the deadline did not bound the queue wait: 300ms was asked for, the queue timeout is \
         5000ms, and the call took {}ms",
        elapsed.as_millis()
    );
    assert!(
        elapsed >= Duration::from_millis(200),
        "the call was refused in {}ms, before its own 300ms deadline",
        elapsed.as_millis()
    );

    holder.abort();
}

/// The headers wait and the streaming phase share ONE budget.
///
/// The upstream answers after 500ms with HEADERS and one message and then goes
/// quiet forever, and the client asks for 1200ms. One budget ends the call
/// 1200ms after it started. A budget re-armed when the response body is built
/// would end it 500ms later than that, which is what a deadline that each phase
/// gets a fresh copy of looks like from outside.
#[tokio::test]
async fn the_headers_wait_and_the_streaming_phase_share_one_deadline() {
    let upstream = spawn_probe_upstream(Duration::from_millis(500)).await;
    let mut config = grpc_config(upstream.address, true);
    with_grpc_settings(
        &mut config,
        config::UpstreamGrpcConfig {
            max_duration_ms: 60_000,
            idle_timeout_ms: 0,
            ..default_grpc_settings()
        },
    );
    let harness = spawn_gateway(config, upstream.address).await;

    // `stall.` makes the handler wait 500ms before HEADERS; `quiet` makes the
    // response body never end. Both, so the budget is genuinely split across
    // the two phases: 500ms of the 1200ms is spent before HEADERS arrive, and
    // a re-armed timer would therefore expire 500ms late.
    let started = Instant::now();
    let result = grpc_call(
        harness.grpc_addr(),
        "/stall.quiet_Service/Trickle",
        TestBody::message(b"ping"),
        |headers| {
            headers.insert("grpc-timeout", HeaderValue::from_static("1200m"));
        },
    )
    .await
    .expect("a call whose deadline elapses mid-stream must still be answered");
    let elapsed = started.elapsed();

    assert_eq!(
        result.grpc_status(),
        "4",
        "a stream that never ends must be ended by the deadline after {}ms; grpc-message was {}",
        elapsed.as_millis(),
        result.grpc_message()
    );
    assert_eq!(
        result.messages,
        vec![b"pong".to_vec()],
        "the message the upstream did send must still reach the client"
    );
    assert!(
        elapsed < Duration::from_millis(1_500),
        "the streaming phase was given a fresh budget: one 1200ms deadline was armed, 500ms of it \
         was spent waiting for HEADERS, and the call took {}ms",
        elapsed.as_millis()
    );
    assert!(
        elapsed >= Duration::from_millis(1_100),
        "the call ended after {}ms, before its own 1200ms deadline",
        elapsed.as_millis()
    );
}

/// A peer that sends SETTINGS late and then admits no streams at all.
///
/// `delay` passes before the SETTINGS frame is written, and the frame sets
/// `SETTINGS_MAX_CONCURRENT_STREAMS` to zero, so `SendRequest::ready()` has
/// nothing to become ready for. Written by hand rather than with an h2 server
/// because no server implementation will advertise zero.
async fn spawn_saturated_peer(delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("saturated peer should bind");
    let address = listener
        .local_addr()
        .expect("saturated peer address should be available");

    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::time::sleep(delay).await;
            // length(3)=6 type(1)=SETTINGS flags(1)=0 stream(4)=0, then one
            // setting: identifier 0x0003 (MAX_CONCURRENT_STREAMS), value 0.
            let settings: [u8; 15] = [0, 0, 6, 0x04, 0x00, 0, 0, 0, 0, 0x00, 0x03, 0, 0, 0, 0];
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, &settings).await;
            let _ = tokio::io::AsyncWriteExt::flush(&mut stream).await;
            held.push(stream);
        }
    });

    address
}

/// A saturated upstream is bounded by the CALL DEADLINE, not by the connect
/// budget.
///
/// This corrects a claim, and the correction is the reason the test exists.
/// `hyper::client::conn::http2::SendRequest::poll_ready` (hyper 1.10.1,
/// `src/client/conn/http2.rs:96-103`) discards its `Context` and answers
/// `Ready(Ok(()))` whenever the connection is not closed. It never consults
/// `SETTINGS_MAX_CONCURRENT_STREAMS`, so `ready()` cannot wait for stream
/// capacity and `connect_timeout_ms` cannot bound acquiring it. What actually
/// happens against an upstream admitting no streams is that the request is
/// accepted, queued inside h2, and its response future stays pending -- the
/// same shape as any other upstream that has not sent HEADERS.
///
/// So the bound is the deadline, and the connect budget is set far above it
/// here to prove which one fired. Before the deadline covered the pre-HEADERS
/// window this call was unbounded, ending only when the 30s keep-alive and its
/// 10s grace closed the connection.
#[tokio::test]
async fn a_saturated_upstream_is_bounded_by_the_call_deadline() {
    let saturated = spawn_saturated_peer(Duration::ZERO).await;
    let mut config = grpc_config(saturated, true);
    with_grpc_settings(
        &mut config,
        config::UpstreamGrpcConfig {
            connect_timeout_ms: 20_000,
            max_duration_ms: 1_000,
            idle_timeout_ms: 0,
            ..default_grpc_settings()
        },
    );
    let harness = spawn_gateway(config, saturated).await;

    let started = Instant::now();
    let result = grpc_call(
        harness.grpc_addr(),
        "/acceptance.Service/Ping",
        TestBody::message(b"ping"),
        |_| {},
    )
    .await
    .expect("a call to a saturated peer must still be answered");
    let elapsed = started.elapsed();

    assert_eq!(
        result.grpc_status(),
        "4",
        "an upstream admitting no streams must be ended by the route's own ceiling after {}ms; \
         grpc-message was {}",
        elapsed.as_millis(),
        result.grpc_message()
    );
    assert_eq!(result.grpc_message(), "deadline_exceeded");
    assert!(
        elapsed < Duration::from_millis(3_000),
        "a saturated upstream was not bounded: the route ceiling is 1000ms and the call took {}ms",
        elapsed.as_millis()
    );
    assert!(
        elapsed >= Duration::from_millis(900),
        "the call ended after {}ms, before the route's own 1000ms ceiling",
        elapsed.as_millis()
    );
}

/// The RBAC exempt list does not apply on the gRPC listener either.
///
/// Separate from the authentication case because the two lists are consulted by
/// different middlewares and cleared independently, so one test cannot cover
/// both: a credential is supplied here precisely so that authentication passes
/// and the only remaining question is whether policy was consulted.
#[tokio::test]
async fn an_exempt_prefix_does_not_skip_policy_on_the_grpc_listener() {
    let upstream = spawn_probe_upstream(Duration::ZERO).await;
    let store = TempDb::new("grpc-exempt-rbac");
    let policy = TempPolicyFile::new(
        &serde_json::json!({
            "schema_version": "0.1.0",
            "id": "grpc-exempt-rbac",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {
                "grpc-client": { "permissions": ["grpc:call"] }
            },
            "routes": [
                {
                    "methods": ["POST"],
                    "path_prefix": "/acceptance.Service",
                    "permission": "grpc:call"
                }
            ]
        })
        .to_string(),
    );
    let mut config = grpc_config(upstream.address, true);
    config.auth_enabled = true;
    config.auth_mode = config::AuthMode::Required;
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.rbac_exempt_paths.push("/public".to_owned());
    let token = service_token_credential(&mut config, &store);
    let harness = spawn_gateway(config, upstream.address).await;

    let authenticate = |headers: &mut HeaderMap| {
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).expect("bearer value should build"),
        );
    };

    let exempt = grpc_call(
        harness.grpc_addr(),
        "/public/Ping",
        TestBody::message(b"ping"),
        authenticate,
    )
    .await
    .expect("the gRPC listener must answer rather than drop the connection");

    assert_eq!(
        upstream.accepts(),
        0,
        "an RBAC exemption proxied an unauthorized call from the gRPC listener; grpc-status was \
         {} ({})",
        exempt.grpc_status(),
        exempt.grpc_message()
    );
    assert_eq!(
        exempt.grpc_status(),
        "7",
        "a call the policy denies must be PERMISSION_DENIED; grpc-message was {}",
        exempt.grpc_message()
    );

    // The control: the same credential on a path the policy allows is served,
    // so the denial above is about the exemption rather than about a policy
    // that denies everything.
    let allowed = grpc_call(
        harness.grpc_addr(),
        "/acceptance.Service/Ping",
        TestBody::message(b"ping"),
        authenticate,
    )
    .await
    .expect("an authorized call should be served");
    assert_eq!(
        allowed.grpc_status(),
        "0",
        "the control call was refused: {}",
        allowed.grpc_message()
    );
    assert_eq!(upstream.accepts(), 1);
}

// Keeps the unused-import lint honest: `HashSet` is used by `test_config`'s
/// surrounding module rather than by this file.
#[allow(dead_code)]
fn _unused(_: HashSet<u8>) {}
