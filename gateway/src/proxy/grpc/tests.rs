//! Transport tests for the gRPC proxy.
//!
//! These drive `ProxyState::handle_grpc_call` directly against a real HTTP/2
//! upstream. The listener, the middleware stack, and the h2-preface refusal on
//! the other listeners are covered end to end in
//! `gateway/src/tests/issue_257_acceptance_grpc.rs`.
//!
//! Two habits this repository has been bitten by, avoided deliberately here:
//! every assertion names the value it expects rather than asserting that
//! nothing errored, and every bound is tested at the limit AND at the limit
//! plus one, so a test cannot pass against an implementation that enforces
//! nothing.

use std::{
    collections::HashSet,
    convert::Infallible,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use axum::body::Body;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Request, StatusCode, Version};
use hyper::body::{Body as HttpBody, Frame, Incoming};
use tokio::{net::TcpListener, sync::mpsc};

use super::{listen::test_support, protocol::GrpcStatus};
use crate::{
    audit::{self, sink::tests::CaptureSink},
    config, egress, lifecycle,
    proxy::{
        health, ProxyEndpoint, ProxyRoute, ProxyRoutes, ProxyState, RouteRequestHeaderPolicy,
        UpstreamPool,
    },
};

// ---------------------------------------------------------------------------
// Bodies
// ---------------------------------------------------------------------------

/// A body a test drives frame by frame.
///
/// Channel-backed rather than a pre-built vector so a streaming test can prove
/// that frames cross the gateway as they are produced, not after the sender
/// finished.
struct TestBody {
    receiver: mpsc::Receiver<Frame<Bytes>>,
    /// Whether the body reports itself finished BEFORE it is polled.
    ///
    /// hyper reads this to decide whether to put `END_STREAM` on the HEADERS
    /// frame, which is the only thing that distinguishes a gRPC Trailers-Only
    /// answer from a response that happens to carry no messages.
    ended: bool,
}

impl TestBody {
    fn channel(capacity: usize) -> (mpsc::Sender<Frame<Bytes>>, Self) {
        let (sender, receiver) = mpsc::channel(capacity);
        (
            sender,
            Self {
                receiver,
                ended: false,
            },
        )
    }

    /// A body that is over before it starts, so hyper ends the stream on the
    /// HEADERS frame.
    fn trailers_only() -> Self {
        let (_, mut body) = Self::channel(1);
        body.ended = true;
        body
    }

    fn from_frames(frames: Vec<Frame<Bytes>>) -> Self {
        let (sender, body) = Self::channel(frames.len().max(1));
        for frame in frames {
            sender.try_send(frame).expect("test body should accept");
        }
        body
    }

    fn messages(messages: &[&[u8]]) -> Self {
        Self::from_frames(vec![Frame::data(framed(messages))])
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

    fn is_end_stream(&self) -> bool {
        self.ended
    }
}

/// Encodes messages into the gRPC length-prefixed framing.
fn framed(messages: &[&[u8]]) -> Bytes {
    let mut encoded = Vec::new();
    for message in messages {
        encoded.push(0);
        encoded.extend_from_slice(
            &u32::try_from(message.len())
                .expect("test message length fits")
                .to_be_bytes(),
        );
        encoded.extend_from_slice(message);
    }

    Bytes::from(encoded)
}

/// Decodes gRPC framing back into messages, so assertions are about messages
/// rather than about where chunk boundaries happened to fall.
fn unframe(chunks: &[Bytes]) -> Vec<Vec<u8>> {
    let mut joined = Vec::new();
    for chunk in chunks {
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

    messages
}

// ---------------------------------------------------------------------------
// Upstream
// ---------------------------------------------------------------------------

/// What one upstream request looked like when it arrived.
#[derive(Clone, Debug, Default)]
struct UpstreamObservation {
    authority: Option<String>,
    path: Option<String>,
    headers: HeaderMap,
    chunks: Vec<Bytes>,
}

#[derive(Clone, Default)]
struct UpstreamLog(Arc<std::sync::Mutex<Vec<UpstreamObservation>>>);

impl UpstreamLog {
    fn record(&self, observation: UpstreamObservation) {
        self.0
            .lock()
            .expect("upstream log should not be poisoned")
            .push(observation);
    }

    fn last(&self) -> UpstreamObservation {
        self.0
            .lock()
            .expect("upstream log should not be poisoned")
            .last()
            .cloned()
            .expect("the upstream should have observed a request")
    }

    fn len(&self) -> usize {
        self.0
            .lock()
            .expect("upstream log should not be poisoned")
            .len()
    }

    fn all(&self) -> Vec<UpstreamObservation> {
        self.0
            .lock()
            .expect("upstream log should not be poisoned")
            .clone()
    }
}

async fn drain_request(request: hyper::Request<Incoming>, log: &UpstreamLog) -> Vec<Bytes> {
    let (parts, mut body) = request.into_parts();
    let mut chunks = Vec::new();
    while let Some(frame) =
        std::future::poll_fn(|context| Pin::new(&mut body).poll_frame(context)).await
    {
        let Ok(frame) = frame else { break };
        if let Ok(data) = frame.into_data() {
            if !data.is_empty() {
                chunks.push(data);
            }
        }
    }
    log.record(UpstreamObservation {
        authority: parts.uri.authority().map(ToString::to_string),
        path: Some(parts.uri.path().to_owned()),
        headers: parts.headers.clone(),
        chunks: chunks.clone(),
    });

    chunks
}

fn grpc_trailers(status: &str, message: &str) -> HeaderMap {
    let mut trailers = HeaderMap::new();
    trailers.insert(
        "grpc-status",
        HeaderValue::from_str(status).expect("test status"),
    );
    trailers.insert(
        "grpc-message",
        HeaderValue::from_str(message).expect("test message"),
    );
    trailers
}

fn grpc_response(frames: Vec<Frame<Bytes>>) -> hyper::Response<TestBody> {
    hyper::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(TestBody::from_frames(frames))
        .expect("test upstream response should build")
}

/// Stands up an HTTP/2 upstream whose behaviour is the supplied closure.
async fn spawn_upstream<F, Fut>(handler: F) -> SocketAddr
where
    F: Fn(hyper::Request<Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = hyper::Response<TestBody>> + Send + 'static,
{
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("test upstream should bind");
    let address = listener
        .local_addr()
        .expect("test upstream address should be available");
    let service = hyper::service::service_fn(move |request| {
        let handler = handler.clone();
        async move { Ok::<_, Infallible>(handler(request).await) }
    });
    test_support::spawn_upstream(listener, service);

    address
}

/// An upstream that echoes every request message back and ends with `OK`.
async fn spawn_echo_upstream() -> (SocketAddr, UpstreamLog) {
    let log = UpstreamLog::default();
    let handler_log = log.clone();
    let address = spawn_upstream(move |request| {
        let log = handler_log.clone();
        async move {
            let chunks = drain_request(request, &log).await;
            let mut frames: Vec<Frame<Bytes>> = chunks.into_iter().map(Frame::data).collect();
            frames.push(Frame::trailers(grpc_trailers("0", "echoed")));
            grpc_response(frames)
        }
    })
    .await;

    (address, log)
}

// ---------------------------------------------------------------------------
// Proxy construction
// ---------------------------------------------------------------------------

fn default_grpc_settings() -> config::UpstreamGrpcConfig {
    config::UpstreamGrpcConfig {
        max_concurrent_calls: config::DEFAULT_GRPC_MAX_CONCURRENT_CALLS,
        max_concurrent_calls_per_endpoint: None,
        queue_depth: config::DEFAULT_GRPC_QUEUE_DEPTH,
        queue_timeout_ms: config::DEFAULT_GRPC_QUEUE_TIMEOUT_MS,
        connect_timeout_ms: 2_000,
        idle_timeout_ms: config::DEFAULT_GRPC_IDLE_TIMEOUT_MS,
        max_duration_ms: config::DEFAULT_GRPC_MAX_DURATION_MS,
        max_message_bytes: config::DEFAULT_GRPC_MAX_MESSAGE_BYTES,
        max_request_bytes: config::DEFAULT_GRPC_MAX_STREAM_BYTES,
        max_response_bytes: config::DEFAULT_GRPC_MAX_STREAM_BYTES,
        max_metadata_entries: config::DEFAULT_GRPC_MAX_METADATA_ENTRIES,
    }
}

/// A DNS resolver that counts every lookup it is asked for.
///
/// The zero-bytes invariant is asserted by counting resolutions and accepts,
/// not by reading a status code: a denial that returned the right status while
/// still resolving the endpoint would satisfy a status assertion and violate
/// the actual requirement.
#[derive(Default)]
struct CountingResolver {
    lookups: AtomicUsize,
}

#[async_trait::async_trait]
impl egress::DnsResolver for CountingResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        let address: std::net::IpAddr = host
            .parse()
            .map_err(|_| std::io::Error::other("test resolver only accepts literal addresses"))?;
        Ok(vec![SocketAddr::new(address, port)])
    }
}

struct Harness {
    proxy: ProxyState,
    sink: CaptureSink,
    lifecycle: lifecycle::GatewayLifecycle,
    resolver: Arc<CountingResolver>,
}

impl Harness {
    fn lookups(&self) -> usize {
        self.resolver.lookups.load(Ordering::SeqCst)
    }
}

fn harness(
    upstream: SocketAddr,
    configure: impl FnOnce(&mut config::UpstreamGrpcConfig),
) -> Harness {
    harness_with_added_headers(upstream, &[], configure)
}

fn harness_with_added_headers(
    upstream: SocketAddr,
    added_headers: &[(&str, &str)],
    configure: impl FnOnce(&mut config::UpstreamGrpcConfig),
) -> Harness {
    let mut settings = default_grpc_settings();
    configure(&mut settings);
    let header_policy = RouteRequestHeaderPolicy {
        add_request_headers: added_headers
            .iter()
            .map(|(name, value)| {
                (
                    http::HeaderName::from_bytes(name.as_bytes()).expect("test header name"),
                    HeaderValue::from_str(value).expect("test header value"),
                )
            })
            .collect(),
        strip_request_headers: Vec::new(),
    };

    let sink = CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(sink.clone()));
    let resolver = Arc::new(CountingResolver::default());
    let egress_config = egress::EgressConfig {
        allowed_hosts: HashSet::from(["127.0.0.1".to_owned()]),
        timeout: Duration::from_secs(5),
        connect_timeout: Duration::from_secs(2),
        response_idle_timeout: Duration::from_secs(5),
        deny_private_ips: false,
        ..egress::EgressConfig::default()
    };
    let egress_client = Arc::new(
        egress::EgressClient::new_with_resolver(
            egress_config,
            Arc::clone(&resolver) as Arc<dyn egress::DnsResolver>,
        )
        .expect("test egress client should build"),
    );
    let endpoint_id: Arc<str> = Arc::from("primary");
    let endpoints = vec![ProxyEndpoint {
        id: Arc::clone(&endpoint_id),
        upstream_origin: format!("http://{upstream}"),
        weight: 1,
        egress_client,
        health: health::UpstreamHealthState::new("grpc", Arc::clone(&endpoint_id), None),
        health_config: None,
        circuit: None,
    }];
    let pool = Arc::new(UpstreamPool::new(
        "grpc".to_owned(),
        endpoints,
        &config::UpstreamPoolLimitsConfig::default(),
        None,
    ));
    let runtime = Arc::new(super::RouteGrpcRuntime::new(
        "grpc",
        &settings,
        pool.endpoints
            .iter()
            .map(|endpoint| Arc::clone(&endpoint.id)),
    ));
    let gateway_lifecycle = lifecycle::GatewayLifecycle::new();

    Harness {
        proxy: ProxyState {
            routes: ProxyRoutes::RoutingTable {
                routes: vec![ProxyRoute {
                    route_id: "grpc".to_owned(),
                    path_prefix: Some("/".to_owned()),
                    host: None,
                    authorization_origin: "pool:grpc".to_owned(),
                    connection_id: None,
                    request_header_policy: header_policy,
                    pool,
                    request_body_mode: crate::proxy::RequestBodyMode::Buffered,
                    sse: None,
                    websocket: None,
                    grpc: Some(runtime),
                }],
            },
            connection_http: None,
            upstream_health: Vec::new(),
            max_request_body_bytes: 1024 * 1024,
            health_runtime: health::UpstreamHealthRuntime::default(),
            lifecycle: gateway_lifecycle.clone(),
            audit: audit_log,
            request_selection_count: None,
            request_body_mode_override: None,
        },
        sink,
        lifecycle: gateway_lifecycle,
        resolver,
    }
}

// ---------------------------------------------------------------------------
// Requests and responses
// ---------------------------------------------------------------------------

fn grpc_request(path: &str, body: TestBody) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Body::new(body))
        .expect("test gRPC request should build");
    *request.version_mut() = Version::HTTP_2;
    request
}

#[derive(Debug)]
struct Collected {
    http_status: StatusCode,
    headers: HeaderMap,
    data: Vec<Bytes>,
    trailers: Option<HeaderMap>,
}

impl Collected {
    /// The `grpc-status`, wherever the protocol puts it: trailers for a call
    /// that produced a response, and headers for a trailers-only answer.
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

    fn messages(&self) -> Vec<Vec<u8>> {
        unframe(&self.data)
    }

    fn assert_status(&self, expected: GrpcStatus, message: &str) {
        assert_eq!(
            self.http_status,
            StatusCode::OK,
            "a gRPC answer is always HTTP 200; the status lives in grpc-status"
        );
        assert_eq!(
            self.grpc_status(),
            expected
                .header_value()
                .to_str()
                .expect("status header is ascii"),
            "expected {expected:?}, got grpc-status={} grpc-message={}",
            self.grpc_status(),
            self.grpc_message()
        );
        assert_eq!(self.grpc_message(), message);
    }
}

async fn collect(response: axum::response::Response) -> Collected {
    let (parts, mut body) = response.into_parts();
    let mut data = Vec::new();
    let mut trailers = None;
    while let Some(frame) =
        std::future::poll_fn(|context| Pin::new(&mut body).poll_frame(context)).await
    {
        let frame = frame.expect("the gateway response body must never error");
        match frame.into_data() {
            Ok(chunk) => data.push(chunk),
            Err(frame) => {
                if let Ok(map) = frame.into_trailers() {
                    trailers = Some(map);
                }
            }
        }
    }

    Collected {
        http_status: parts.status,
        headers: parts.headers,
        data,
        trailers,
    }
}

async fn call(harness: &Harness, request: Request<Body>) -> Collected {
    let response = harness.proxy.handle_grpc_call(request, "203.0.113.7").await;
    collect(response).await
}

// ---------------------------------------------------------------------------
// Call shapes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_unary_call_round_trips_its_message_and_preserves_the_upstream_status() {
    let (upstream, log) = spawn_echo_upstream().await;
    let harness = harness(upstream, |_| {});

    let response = call(
        &harness,
        grpc_request(
            "/helloworld.Greeter/SayHello",
            TestBody::messages(&[b"hello"]),
        ),
    )
    .await;

    assert_eq!(response.messages(), vec![b"hello".to_vec()]);
    // The upstream's own status and message survive verbatim: that is the
    // difference between proxying gRPC and terminating it.
    assert_eq!(response.grpc_status(), "0");
    assert_eq!(response.grpc_message(), "echoed");
    assert_eq!(
        log.last().path.as_deref(),
        Some("/helloworld.Greeter/SayHello")
    );
}

#[tokio::test]
async fn a_client_streaming_call_forwards_every_message_it_is_given() {
    let (upstream, log) = spawn_echo_upstream().await;
    let harness = harness(upstream, |_| {});

    let (sender, body) = TestBody::channel(4);
    let request = grpc_request("/stream.Service/Collect", body);
    let response = harness.proxy.handle_grpc_call(request, "203.0.113.7");
    tokio::pin!(response);

    // The call future and the sender are driven together: `handle_grpc_call`
    // does not resolve until the upstream answers with headers, and a
    // client-streaming upstream answers only after it has drained the request.
    let feeder = async move {
        for message in [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()] {
            sender
                .send(Frame::data(framed(&[message])))
                .await
                .expect("test client should send");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        drop(sender);
    };
    let (response, ()) = tokio::join!(response, feeder);
    let response = collect(response).await;
    assert_eq!(
        response.messages(),
        vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
    );
    assert_eq!(
        unframe(&log.last().chunks),
        vec![b"one".to_vec(), b"two".to_vec(), b"three".to_vec()]
    );
}

/// A server-streaming call must deliver each message as the upstream produces
/// it. Asserting only the final contents would pass against an implementation
/// that buffered the whole response, which is exactly the failure mode a
/// streaming proxy must not have.
#[tokio::test]
async fn a_server_streaming_call_delivers_each_message_before_the_next_is_produced() {
    let address = spawn_upstream(move |request| async move {
        let (_, body) = request.into_parts();
        drop(body);
        let (sender, response_body) = TestBody::channel(4);
        tokio::spawn(async move {
            for message in [b"first".as_slice(), b"second".as_slice()] {
                let _ = sender.send(Frame::data(framed(&[message]))).await;
                tokio::time::sleep(Duration::from_millis(80)).await;
            }
            let _ = sender
                .send(Frame::trailers(grpc_trailers("0", "streamed")))
                .await;
        });
        hyper::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(response_body)
            .expect("streaming upstream response should build")
    })
    .await;
    let harness = harness(address, |_| {});

    let response = harness
        .proxy
        .handle_grpc_call(
            grpc_request("/stream.Service/Watch", TestBody::empty()),
            "203.0.113.7",
        )
        .await;
    let (_, mut body) = response.into_parts();

    let started = std::time::Instant::now();
    let first = std::future::poll_fn(|context| Pin::new(&mut body).poll_frame(context))
        .await
        .expect("a first frame should arrive")
        .expect("frame should decode")
        .into_data()
        .expect("the first frame should be data");
    let first_at = started.elapsed();
    assert_eq!(unframe(&[first]), vec![b"first".to_vec()]);
    assert!(
        first_at < Duration::from_millis(80),
        "the first message arrived after {first_at:?}, which is at or past the upstream's \
         delay before producing the second -- the response was buffered, not streamed"
    );
}

#[tokio::test]
async fn a_bidirectional_call_interleaves_both_directions() {
    let address = spawn_upstream(move |request| async move {
        let (_, mut request_body) = request.into_parts();
        let (sender, response_body) = TestBody::channel(8);
        tokio::spawn(async move {
            while let Some(frame) =
                std::future::poll_fn(|context| Pin::new(&mut request_body).poll_frame(context))
                    .await
            {
                let Ok(frame) = frame else { break };
                if let Ok(data) = frame.into_data() {
                    if data.is_empty() {
                        continue;
                    }
                    // Answer each request message immediately, before the next
                    // one arrives.
                    let _ = sender.send(Frame::data(data)).await;
                }
            }
            let _ = sender
                .send(Frame::trailers(grpc_trailers("0", "duplex")))
                .await;
        });
        hyper::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(response_body)
            .expect("duplex upstream response should build")
    })
    .await;
    let harness = harness(address, |_| {});

    let (sender, body) = TestBody::channel(4);
    let response = harness
        .proxy
        .handle_grpc_call(grpc_request("/duplex.Service/Chat", body), "203.0.113.7")
        .await;
    let (_, mut response_body) = response.into_parts();

    for message in [b"ping-1".as_slice(), b"ping-2".as_slice()] {
        sender
            .send(Frame::data(framed(&[message])))
            .await
            .expect("test client should send");
        let frame =
            std::future::poll_fn(|context| Pin::new(&mut response_body).poll_frame(context))
                .await
                .expect("a reply should arrive before the next request message is sent")
                .expect("frame should decode")
                .into_data()
                .expect("reply should be data");
        assert_eq!(unframe(&[frame]), vec![message.to_vec()]);
    }
    drop(sender);
}

// ---------------------------------------------------------------------------
// The zero-bytes invariant
// ---------------------------------------------------------------------------

/// GUARD: every pre-upstream refusal.
///
/// Asserted by counting DNS lookups and TCP accepts rather than by reading a
/// status, because a denial that answered correctly while still resolving and
/// connecting to the endpoint would pass a status assertion and violate the
/// requirement. Zero accepts implies zero upstream bytes: there is no
/// connection to write them on.
#[tokio::test]
async fn every_pre_upstream_refusal_costs_zero_dns_lookups_and_zero_upstream_connections() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("counting listener should bind");
    let address = listener
        .local_addr()
        .expect("counting listener address should be available");
    let accepts = Arc::new(AtomicUsize::new(0));
    let accept_counter = Arc::clone(&accepts);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            accept_counter.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });

    let harness = harness(address, |settings| settings.max_metadata_entries = 8);

    let mut refusals: Vec<(&str, Request<Body>, GrpcStatus, &str)> = Vec::new();

    refusals.push((
        "a method path that is not two protobuf identifiers",
        grpc_request("/not-a-service/Method", TestBody::empty()),
        GrpcStatus::InvalidArgument,
        "service_name_grammar",
    ));
    refusals.push((
        "a method path with a query string",
        grpc_request("/pkg.Service/Method?x=1", TestBody::empty()),
        GrpcStatus::InvalidArgument,
        "method_path_query",
    ));

    let mut wrong_content_type = grpc_request("/pkg.Service/Method", TestBody::empty());
    wrong_content_type
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    refusals.push((
        "a non-gRPC content type",
        wrong_content_type,
        GrpcStatus::Internal,
        "content_type_not_grpc",
    ));

    let mut missing_te = grpc_request("/pkg.Service/Method", TestBody::empty());
    missing_te.headers_mut().remove("te");
    refusals.push((
        "a request that did not ask for trailers",
        missing_te,
        GrpcStatus::InvalidArgument,
        "te_trailers_missing",
    ));

    let mut wrong_method = grpc_request("/pkg.Service/Method", TestBody::empty());
    *wrong_method.method_mut() = http::Method::GET;
    refusals.push((
        "a method other than POST",
        wrong_method,
        GrpcStatus::Internal,
        "method_not_post",
    ));

    let mut bad_deadline = grpc_request("/pkg.Service/Method", TestBody::empty());
    bad_deadline
        .headers_mut()
        .insert("grpc-timeout", HeaderValue::from_static("10x"));
    refusals.push((
        "an unparseable grpc-timeout",
        bad_deadline,
        GrpcStatus::InvalidArgument,
        "grpc_timeout_unit",
    ));

    let mut too_much_metadata = grpc_request("/pkg.Service/Method", TestBody::empty());
    for index in 0..16 {
        too_much_metadata.headers_mut().insert(
            http::HeaderName::from_bytes(format!("x-meta-{index}").as_bytes())
                .expect("test header name"),
            HeaderValue::from_static("v"),
        );
    }
    refusals.push((
        "more metadata entries than the route permits",
        too_much_metadata,
        GrpcStatus::ResourceExhausted,
        "request_metadata_entries",
    ));

    for (description, request, status, reason) in refusals {
        let response = call(&harness, request).await;
        response.assert_status(status, reason);
        assert!(
            response.data.is_empty(),
            "{description}: a refusal must be trailers-only, but it carried {} data frame(s)",
            response.data.len()
        );
    }

    // Draining is checked separately because it changes gateway state.
    harness.lifecycle.begin_draining();
    let response = call(
        &harness,
        grpc_request("/pkg.Service/Method", TestBody::empty()),
    )
    .await;
    response.assert_status(GrpcStatus::Unavailable, "shutdown");

    assert_eq!(
        harness.lookups(),
        0,
        "a refused call resolved the endpoint's name; the refusal happened after \
         endpoint selection rather than before it"
    );
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        0,
        "a refused call opened a connection to the upstream"
    );
}

/// The admission bound denies without reaching the upstream, measured as a
/// delta so a legitimately established call does not mask the assertion.
#[tokio::test]
async fn admission_saturation_denies_without_a_new_upstream_connection() {
    let address = spawn_upstream(move |request| async move {
        let (_, body) = request.into_parts();
        drop(body);
        let (sender, response_body) = TestBody::channel(2);
        // Hold the stream open so the first call keeps its admission slot.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let _ = sender
                .send(Frame::trailers(grpc_trailers("0", "late")))
                .await;
        });
        hyper::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(response_body)
            .expect("slow upstream response should build")
    })
    .await;
    let harness = harness(address, |settings| {
        settings.max_concurrent_calls = 1;
        settings.queue_depth = 0;
    });

    let held = harness
        .proxy
        .handle_grpc_call(
            grpc_request("/pkg.Service/Slow", TestBody::empty()),
            "203.0.113.7",
        )
        .await;
    assert_eq!(held.status(), StatusCode::OK);
    let lookups_after_first = harness.lookups();
    assert_eq!(
        lookups_after_first, 1,
        "the accepted call should have resolved the endpoint exactly once"
    );

    let refused = call(
        &harness,
        grpc_request("/pkg.Service/Slow", TestBody::empty()),
    )
    .await;
    refused.assert_status(GrpcStatus::ResourceExhausted, "queue_full");
    assert_eq!(
        harness.lookups(),
        lookups_after_first,
        "the refused call resolved the endpoint; admission must complete before egress"
    );

    drop(held);
}

// ---------------------------------------------------------------------------
// Header and authority ownership
// ---------------------------------------------------------------------------

/// Route policy can ADD metadata, so the entry count is rechecked after it
/// runs.
///
/// Checking only the inbound count would let a route configuration push the
/// upstream over a limit the operator believed was enforced -- and the operator
/// would have no way to see it, because the request they sent was under the
/// limit.
#[tokio::test]
async fn metadata_added_by_route_policy_is_counted_against_the_limit() {
    let added: Vec<(String, String)> = (0..10)
        .map(|index| (format!("x-route-{index}"), "injected".to_owned()))
        .collect();
    let added: Vec<(&str, &str)> = added
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();

    // The control first: the same ten added headers, under a limit that fits
    // them, are forwarded.
    let (upstream, log) = spawn_echo_upstream().await;
    let permissive = harness_with_added_headers(upstream, &added, |settings| {
        settings.max_metadata_entries = 32;
    });
    let response = call(
        &permissive,
        grpc_request("/pkg.Service/Method", TestBody::messages(&[b"x"])),
    )
    .await;
    assert_eq!(response.grpc_status(), "0");
    assert_eq!(
        log.last()
            .headers
            .get("x-route-0")
            .and_then(|value| value.to_str().ok()),
        Some("injected")
    );

    // The same request, the same added headers, a limit the request alone is
    // under and the policy output is over.
    let strict = harness_with_added_headers(upstream, &added, |settings| {
        settings.max_metadata_entries = 8;
    });
    let calls_before = log.len();
    let response = call(
        &strict,
        grpc_request("/pkg.Service/Method", TestBody::messages(&[b"x"])),
    )
    .await;
    response.assert_status(GrpcStatus::ResourceExhausted, "request_metadata_entries");
    assert_eq!(
        log.len(),
        calls_before,
        "a call refused on its metadata count reached the upstream"
    );
}

#[tokio::test]
async fn client_credentials_and_forwarding_metadata_never_cross_the_boundary() {
    let (upstream, log) = spawn_echo_upstream().await;
    let harness = harness(upstream, |_| {});

    let mut request = grpc_request("/pkg.Service/Method", TestBody::messages(&[b"x"]));
    let headers = request.headers_mut();
    headers.insert(
        "authorization",
        HeaderValue::from_static("Bearer gateway-credential"),
    );
    headers.insert("cookie", HeaderValue::from_static("session=gateway"));
    headers.insert("host", HeaderValue::from_static("attacker.example"));
    headers.insert("x-forwarded-for", HeaderValue::from_static("10.0.0.1"));
    headers.insert("x-real-ip", HeaderValue::from_static("10.0.0.1"));
    headers.insert("cf-connecting-ip", HeaderValue::from_static("10.0.0.1"));
    headers.insert("x-request-id", HeaderValue::from_static("client-chosen"));
    headers.insert("grpc-status", HeaderValue::from_static("0"));
    headers.insert("grpc-message", HeaderValue::from_static("spoofed"));
    headers.insert("custom-metadata", HeaderValue::from_static("preserved"));

    let response = call(&harness, request).await;
    assert_eq!(response.grpc_status(), "0");

    let observed = log.last();
    for forbidden in [
        "authorization",
        "cookie",
        "cf-connecting-ip",
        "x-request-id",
        "grpc-status",
        "grpc-message",
    ] {
        assert!(
            !observed.headers.contains_key(forbidden),
            "{forbidden} reached the upstream; it must not be forwarded blindly"
        );
    }
    // The forwarding headers are REPLACED with the gateway's own view of the
    // caller, not merely dropped -- forwarding the client's claim would let a
    // caller choose the IP the upstream sees.
    assert_eq!(
        observed
            .headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok()),
        Some("203.0.113.7")
    );
    assert_eq!(
        observed
            .headers
            .get("x-real-ip")
            .and_then(|value| value.to_str().ok()),
        Some("203.0.113.7")
    );
    // Ordinary application metadata is transparent, which is the whole point.
    assert_eq!(
        observed
            .headers
            .get("custom-metadata")
            .and_then(|value| value.to_str().ok()),
        Some("preserved")
    );
    assert_eq!(
        observed
            .headers
            .get("te")
            .and_then(|value| value.to_str().ok()),
        Some("trailers")
    );
}

#[tokio::test]
async fn the_gateway_owns_the_upstream_authority() {
    let (upstream, log) = spawn_echo_upstream().await;
    let harness = harness(upstream, |_| {});

    let mut request = grpc_request("/pkg.Service/Method", TestBody::messages(&[b"x"]));
    request
        .headers_mut()
        .insert("host", HeaderValue::from_static("attacker.example"));

    let response = call(&harness, request).await;
    assert_eq!(response.grpc_status(), "0");

    let observed = log.last();
    assert_eq!(
        observed.authority.as_deref(),
        Some(upstream.to_string().as_str()),
        "the upstream :authority must be derived from the validated endpoint, not from a \
         header the caller chose"
    );
    assert!(
        !observed.headers.contains_key("host"),
        "an HTTP/2 request carries :authority, and a stray Host header would give the \
         upstream two different answers about who it is"
    );
}

// ---------------------------------------------------------------------------
// Deadlines
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_client_deadline_is_capped_by_the_route_ceiling_and_restated_by_the_gateway() {
    let (upstream, log) = spawn_echo_upstream().await;
    let harness = harness(upstream, |settings| settings.max_duration_ms = 5_000);

    let mut request = grpc_request("/pkg.Service/Method", TestBody::messages(&[b"x"]));
    request
        .headers_mut()
        .insert("grpc-timeout", HeaderValue::from_static("2H"));
    let response = call(&harness, request).await;
    assert_eq!(response.grpc_status(), "0");
    assert_eq!(
        log.last()
            .headers
            .get("grpc-timeout")
            .and_then(|value| value.to_str().ok()),
        Some("5S"),
        "a two-hour client deadline must be capped to the route's five-second ceiling, and \
         the value forwarded must be the gateway's own"
    );

    // A deadline under the ceiling is honoured rather than raised.
    let mut request = grpc_request("/pkg.Service/Method", TestBody::messages(&[b"x"]));
    request
        .headers_mut()
        .insert("grpc-timeout", HeaderValue::from_static("250m"));
    let response = call(&harness, request).await;
    assert_eq!(response.grpc_status(), "0");
    assert_eq!(
        log.last()
            .headers
            .get("grpc-timeout")
            .and_then(|value| value.to_str().ok()),
        Some("250m")
    );

    // With no client deadline the route ceiling still applies.
    let response = call(
        &harness,
        grpc_request("/pkg.Service/Method", TestBody::messages(&[b"x"])),
    )
    .await;
    assert_eq!(response.grpc_status(), "0");
    assert_eq!(
        log.last()
            .headers
            .get("grpc-timeout")
            .and_then(|value| value.to_str().ok()),
        Some("5S")
    );
}

/// The unit-selection rule, checked directly rather than only through a call.
#[test]
fn grpc_timeout_values_use_the_coarsest_exact_unit_and_round_up_otherwise() {
    for (duration, expected) in [
        (Duration::from_secs(5), "5S"),
        (Duration::from_millis(250), "250m"),
        (Duration::from_micros(1_500), "1500u"),
        (Duration::from_nanos(99), "99n"),
        (Duration::from_secs(3_600), "1H"),
        (Duration::from_secs(120), "2M"),
        // Seven days, the configured ceiling: only hours fit in eight digits.
        (Duration::from_secs(604_800), "168H"),
    ] {
        assert_eq!(
            super::grpc_timeout_header(duration)
                .to_str()
                .expect("timeout header is ascii"),
            expected,
            "{duration:?}"
        );
    }

    // No unit divides 1_500_000_001 nanoseconds exactly, so the finest unit
    // that fits is used and the value rounds UP -- never down, which would
    // shorten a deadline the caller was entitled to.
    let rounded = super::grpc_timeout_header(Duration::from_nanos(1_500_000_001));
    assert_eq!(
        rounded.to_str().expect("timeout header is ascii"),
        "1500001u"
    );
}

#[tokio::test]
async fn a_call_that_outruns_its_deadline_ends_with_deadline_exceeded() {
    let address = spawn_upstream(move |request| async move {
        let (_, body) = request.into_parts();
        drop(body);
        let (sender, response_body) = TestBody::channel(2);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let _ = sender
                .send(Frame::trailers(grpc_trailers("0", "never")))
                .await;
        });
        hyper::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(response_body)
            .expect("slow upstream response should build")
    })
    .await;
    let harness = harness(address, |settings| {
        settings.max_duration_ms = 300;
        settings.idle_timeout_ms = 0;
    });

    // Bounded so that removing the deadline check fails this test rather than
    // hanging it: a guard whose absence produces a hang is a guard whose
    // absence nobody sees.
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        call(
            &harness,
            grpc_request("/pkg.Service/Slow", TestBody::empty()),
        ),
    )
    .await
    .expect("the call deadline must end the stream, not leave it running");
    response.assert_status(GrpcStatus::DeadlineExceeded, "deadline_exceeded");
    assert!(
        response.data.is_empty(),
        "the upstream produced no messages, so none may be invented"
    );
}

#[tokio::test]
async fn a_stalled_stream_ends_on_the_idle_timeout_rather_than_hanging() {
    let address = spawn_upstream(move |request| async move {
        let (_, body) = request.into_parts();
        drop(body);
        let (sender, response_body) = TestBody::channel(2);
        tokio::spawn(async move {
            let _ = sender.send(Frame::data(framed(&[b"first"]))).await;
            // Then stall, without closing.
            tokio::time::sleep(Duration::from_secs(30)).await;
            let _ = sender
                .send(Frame::trailers(grpc_trailers("0", "never")))
                .await;
        });
        hyper::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(response_body)
            .expect("stalling upstream response should build")
    })
    .await;
    let harness = harness(address, |settings| {
        settings.idle_timeout_ms = 1_000;
        settings.max_duration_ms = 0;
    });

    let response = tokio::time::timeout(
        Duration::from_secs(5),
        call(
            &harness,
            grpc_request("/pkg.Service/Stall", TestBody::empty()),
        ),
    )
    .await
    .expect("the idle timeout must end the stream, not leave it stalled");
    response.assert_status(GrpcStatus::Unavailable, "idle_timeout");
    assert_eq!(
        response.messages(),
        vec![b"first".to_vec()],
        "the messages that did arrive before the stall must still reach the client"
    );
}

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_request_message_at_the_limit_is_forwarded_and_one_byte_over_is_refused() {
    let (upstream, log) = spawn_echo_upstream().await;
    let harness = harness(upstream, |settings| settings.max_message_bytes = 64);

    let at_limit = vec![b'a'; 64];
    let response = call(
        &harness,
        grpc_request("/pkg.Service/Method", TestBody::messages(&[&at_limit])),
    )
    .await;
    assert_eq!(response.grpc_status(), "0");
    assert_eq!(response.messages(), vec![at_limit.clone()]);

    let over_limit = vec![b'a'; 65];
    let response = call(
        &harness,
        grpc_request("/pkg.Service/Method", TestBody::messages(&[&over_limit])),
    )
    .await;
    response.assert_status(GrpcStatus::ResourceExhausted, "request_message_bytes");
    // The claim is about the BYTES, not about whether the upstream handler ran:
    // the refusal happens on the envelope header, so the upstream may observe a
    // stream that carried nothing, but it must never observe the message.
    let oversize: Vec<usize> = log
        .all()
        .iter()
        .flat_map(|observation| unframe(&observation.chunks))
        .map(|message| message.len())
        .filter(|length| *length > 64)
        .collect();
    assert!(
        oversize.is_empty(),
        "message(s) over the 64-byte limit reached the upstream: {oversize:?}"
    );
}

#[tokio::test]
async fn a_response_message_over_the_limit_terminates_the_stream_with_resource_exhausted() {
    let address = spawn_upstream(move |request| async move {
        let (_, body) = request.into_parts();
        drop(body);
        grpc_response(vec![
            Frame::data(framed(&[&[b'z'; 200]])),
            Frame::trailers(grpc_trailers("0", "big")),
        ])
    })
    .await;
    let harness = harness(address, |settings| settings.max_message_bytes = 64);

    let response = call(
        &harness,
        grpc_request("/pkg.Service/Method", TestBody::empty()),
    )
    .await;
    response.assert_status(GrpcStatus::ResourceExhausted, "response_message_bytes");
    assert!(
        !response.grpc_message().contains("big"),
        "the upstream's own trailers must not be forwarded once the gateway has refused the \
         stream, or a client would see a success message on a failed call"
    );
}

#[tokio::test]
async fn a_response_that_exceeds_the_per_direction_budget_is_cut_off() {
    let address = spawn_upstream(move |request| async move {
        let (_, body) = request.into_parts();
        drop(body);
        let (sender, response_body) = TestBody::channel(8);
        tokio::spawn(async move {
            for _ in 0..8 {
                let _ = sender.send(Frame::data(framed(&[&[b'z'; 64]]))).await;
            }
            let _ = sender
                .send(Frame::trailers(grpc_trailers("0", "done")))
                .await;
        });
        hyper::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(response_body)
            .expect("bulk upstream response should build")
    })
    .await;
    let harness = harness(address, |settings| {
        settings.max_message_bytes = 64;
        settings.max_response_bytes = 200;
    });

    let response = call(
        &harness,
        grpc_request("/pkg.Service/Bulk", TestBody::empty()),
    )
    .await;
    response.assert_status(GrpcStatus::ResourceExhausted, "response_bytes");
    let forwarded: usize = response.data.iter().map(bytes::Bytes::len).sum();
    assert!(
        forwarded <= 276,
        "the gateway forwarded {forwarded} bytes against a 200-byte budget; the cut-off must \
         happen at the frame that crosses the limit, not after the stream finishes"
    );
}

// ---------------------------------------------------------------------------
// Upstream misbehaviour
// ---------------------------------------------------------------------------

/// The upstream's server initial metadata reaches the client, sanitised.
///
/// Dropping it is the failure this test exists for: `grpc-encoding` tells the
/// client how to decode the messages that follow, so a proxy that swallowed it
/// would break compression outright, and application metadata is what the two
/// ends are saying to each other. Both halves are asserted -- what survives and
/// what does not -- because a test that only checked the removals would pass
/// against a gateway that forwarded nothing at all.
#[tokio::test]
async fn upstream_response_metadata_reaches_the_client_sanitized() {
    let address = spawn_upstream(move |request| async move {
        let (_, body) = request.into_parts();
        drop(body);
        let mut response = hyper::Response::builder()
            .status(200)
            // A content type the gateway serves, spelled the way a caller
            // might: the canonical constant must reach the client instead.
            .header("content-type", "APPLICATION/GRPC+PROTO")
            .header("grpc-encoding", "identity")
            .header("x-server-meta", "kept")
            // `host` and `trailer` stand in for the whole forbidden set. The
            // connection-specific names and a wrong `content-length` cannot be
            // tested from here at all: h2 marks them malformed on send
            // (`h2-0.4.15/src/frame/headers.rs:915-928`) and hyper validates
            // `content-length` against the DATA it actually writes, so an
            // upstream physically cannot emit them.
            .header("host", "upstream.internal")
            .header("trailer", "x-not-really")
            .body(TestBody::from_frames(vec![
                Frame::data(framed(&[b"payload"])),
                Frame::trailers(grpc_trailers("0", "fine")),
            ]))
            .expect("metadata upstream response should build");
        // `grpc-status` in the HEADERS of a response that HAS a body describes
        // an outcome the upstream cannot know yet.
        response
            .headers_mut()
            .insert("grpc-status", HeaderValue::from_static("0"));
        response
    })
    .await;
    let harness = harness(address, |_| {});

    let response = call(
        &harness,
        grpc_request("/pkg.Service/Method", TestBody::empty()),
    )
    .await;

    assert_eq!(response.grpc_status(), "0");
    assert_eq!(response.messages(), vec![b"payload".to_vec()]);
    assert_eq!(
        response
            .headers
            .get("grpc-encoding")
            .and_then(|value| value.to_str().ok()),
        Some("identity"),
        "grpc-encoding must reach the client, or a compressed response is undecodable"
    );
    assert_eq!(
        response
            .headers
            .get("x-server-meta")
            .and_then(|value| value.to_str().ok()),
        Some("kept"),
        "application metadata is transparent"
    );
    assert_eq!(
        response
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/grpc+proto"),
        "the canonical spelling must be forwarded, not the upstream's bytes"
    );
    assert!(
        !response.headers.contains_key("host"),
        "host was relayed from the upstream's response headers"
    );
    // `Trailer` is not relayed either -- it is REPLACED with the gateway's own
    // announcement, because the trailers a client will actually see are the
    // ones the gateway forwards or generates, not whatever the upstream
    // claimed.
    assert_eq!(
        response
            .headers
            .get(http::header::TRAILER)
            .and_then(|value| value.to_str().ok()),
        Some("grpc-status, grpc-message")
    );
    // The status belongs in the trailers on a response that carries messages,
    // and the trailers are where this call's status actually came from.
    assert!(
        response
            .trailers
            .as_ref()
            .is_some_and(|trailers| trailers.contains_key("grpc-status")),
        "the terminal status must arrive in the trailers"
    );
    assert!(
        !response.headers.contains_key("grpc-status"),
        "a premature grpc-status in the response headers must not be relayed"
    );
}

/// An upstream Trailers-Only answer is relayed as one.
///
/// A gRPC server with an outcome and no messages answers with the status in the
/// HEADERS frame and ends the stream. Treating that as a streaming response
/// would have the gateway wait for trailers that are never coming and then
/// report `INTERNAL` over the top of a perfectly well-formed answer.
#[tokio::test]
async fn an_upstream_trailers_only_answer_is_forwarded_as_trailers_only() {
    let address = spawn_upstream(move |request| async move {
        let (_, body) = request.into_parts();
        drop(body);
        let mut response = hyper::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .header("x-server-meta", "kept")
            .body(TestBody::trailers_only())
            .expect("trailers-only upstream response should build");
        let headers = response.headers_mut();
        headers.insert("grpc-status", HeaderValue::from_static("5"));
        headers.insert("grpc-message", HeaderValue::from_static("no such record"));
        response
    })
    .await;
    let harness = harness(address, |_| {});

    let response = call(
        &harness,
        grpc_request("/pkg.Service/Lookup", TestBody::empty()),
    )
    .await;

    assert_eq!(response.http_status, StatusCode::OK);
    assert_eq!(
        response.grpc_status(),
        "5",
        "the upstream's own NOT_FOUND must be preserved verbatim"
    );
    assert_eq!(response.grpc_message(), "no such record");
    assert!(
        response.trailers.is_none(),
        "a Trailers-Only answer carries its status in the headers and has no trailer section"
    );
    assert!(response.data.is_empty());
    assert_eq!(
        response
            .headers
            .get("x-server-meta")
            .and_then(|value| value.to_str().ok()),
        Some("kept")
    );
}

#[tokio::test]
async fn an_upstream_that_answers_with_a_non_200_never_looks_like_an_application_answer() {
    let address = spawn_upstream(move |request| async move {
        let (_, body) = request.into_parts();
        drop(body);
        hyper::Response::builder()
            .status(503)
            .body(TestBody::empty())
            .expect("failing upstream response should build")
    })
    .await;
    let harness = harness(address, |_| {});

    let response = call(
        &harness,
        grpc_request("/pkg.Service/Method", TestBody::empty()),
    )
    .await;
    response.assert_status(GrpcStatus::Unavailable, "upstream_status");
    assert!(response.data.is_empty());
}

#[tokio::test]
async fn an_upstream_that_ends_without_trailers_becomes_internal_rather_than_success() {
    let address = spawn_upstream(move |request| async move {
        let (_, body) = request.into_parts();
        drop(body);
        // Data, then end of stream, and no trailers at all.
        grpc_response(vec![Frame::data(framed(&[b"orphan"]))])
    })
    .await;
    let harness = harness(address, |_| {});

    let response = call(
        &harness,
        grpc_request("/pkg.Service/Method", TestBody::empty()),
    )
    .await;
    response.assert_status(GrpcStatus::Internal, "upstream_missing_trailers");
    assert_eq!(
        response.messages(),
        vec![b"orphan".to_vec()],
        "the messages that did arrive are still forwarded; only the missing status is invented"
    );
}

#[tokio::test]
async fn an_upstream_whose_trailers_omit_grpc_status_is_refused() {
    let address = spawn_upstream(move |request| async move {
        let (_, body) = request.into_parts();
        drop(body);
        let mut trailers = HeaderMap::new();
        trailers.insert("x-something-else", HeaderValue::from_static("1"));
        grpc_response(vec![
            Frame::data(framed(&[b"payload"])),
            Frame::trailers(trailers),
        ])
    })
    .await;
    let harness = harness(address, |_| {});

    let response = call(
        &harness,
        grpc_request("/pkg.Service/Method", TestBody::empty()),
    )
    .await;
    response.assert_status(GrpcStatus::Internal, "upstream_missing_grpc_status");
}

#[tokio::test]
async fn hop_by_hop_names_are_stripped_from_upstream_trailers() {
    let address = spawn_upstream(move |request| async move {
        let (_, body) = request.into_parts();
        drop(body);
        let mut trailers = grpc_trailers("0", "fine");
        // `connection` and `transfer-encoding` cannot even be tested here: the
        // h2 crate marks them malformed on send
        // (`h2-0.4.15/src/frame/headers.rs:915-928`), so an upstream physically
        // cannot put them in a trailer section. The names below are ones h2
        // does permit and this gateway still refuses to relay.
        trailers.insert("host", HeaderValue::from_static("upstream.internal"));
        trailers.insert("content-length", HeaderValue::from_static("0"));
        trailers.insert("trailer", HeaderValue::from_static("grpc-status"));
        trailers.insert("x-app-trailer", HeaderValue::from_static("kept"));
        grpc_response(vec![Frame::trailers(trailers)])
    })
    .await;
    let harness = harness(address, |_| {});

    let response = call(
        &harness,
        grpc_request("/pkg.Service/Method", TestBody::empty()),
    )
    .await;
    let trailers = response
        .trailers
        .as_ref()
        .expect("the call succeeded, so it must carry trailers");
    assert_eq!(response.grpc_status(), "0");
    assert!(!trailers.contains_key("host"));
    assert!(!trailers.contains_key("content-length"));
    assert!(!trailers.contains_key("trailer"));
    assert_eq!(
        trailers
            .get("x-app-trailer")
            .and_then(|value| value.to_str().ok()),
        Some("kept"),
        "application trailers are transparent; only hop-by-hop names are removed"
    );
}

#[tokio::test]
async fn an_unreachable_endpoint_becomes_unavailable_and_not_a_successful_envelope() {
    // A port nothing is listening on. The connect fails inside the egress
    // transport, which is the one failure mode that happens after every policy
    // check has passed.
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("probe listener should bind");
    let address = listener
        .local_addr()
        .expect("probe address should be available");
    drop(listener);

    let harness = harness(address, |settings| settings.connect_timeout_ms = 500);
    let response = call(
        &harness,
        grpc_request("/pkg.Service/Method", TestBody::empty()),
    )
    .await;

    assert_eq!(response.http_status, StatusCode::OK);
    assert_eq!(
        response.grpc_status(),
        "14",
        "an endpoint that could not be reached is UNAVAILABLE, not a success and not          DEADLINE_EXCEEDED; grpc-message was {}",
        response.grpc_message()
    );
    // Whether the operating system refuses the connect or lets it hang until
    // the gateway's own budget elapses is a platform detail; both are the
    // gateway failing to reach the endpoint, and both must be UNAVAILABLE.
    assert!(
        ["grpc_connect", "grpc_connect_timeout"].contains(&response.grpc_message().as_str()),
        "unexpected failure category: {}",
        response.grpc_message()
    );
    assert!(response.data.is_empty());
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unpolled_responses_release_resources_on_deadline_and_shutdown() {
    let address = spawn_upstream(move |request| async move {
        drop(request);
        let (sender, response_body) = TestBody::channel(1);
        tokio::spawn(async move {
            sender.closed().await;
        });
        hyper::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(response_body)
            .unwrap()
    })
    .await;
    for force_shutdown in [false, true] {
        let harness = harness(address, |settings| {
            settings.idle_timeout_ms = 0;
            settings.max_duration_ms = if force_shutdown { 0 } else { 100 };
        });
        let response = harness
            .proxy
            .handle_grpc_call(
                grpc_request("/pkg.Service/Watch", TestBody::empty()),
                "203.0.113.7",
            )
            .await;
        if force_shutdown {
            harness.lifecycle.force_shutdown_response_streams().await;
        }
        let event = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(event) = harness
                    .sink
                    .events()
                    .into_iter()
                    .find(|event| event.event_type == audit::event::UPSTREAM_GRPC_CALL)
                {
                    break event;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cleanup must run without downstream polling");
        let reason = if force_shutdown {
            "shutdown"
        } else {
            "deadline_exceeded"
        };
        assert_eq!(event.payload["reason"], reason);
        let collected = collect(response).await;
        collected.assert_status(
            if force_shutdown {
                GrpcStatus::Unavailable
            } else {
                GrpcStatus::DeadlineExceeded
            },
            reason,
        );
    }
}

#[tokio::test]
async fn forced_shutdown_terminates_an_in_flight_stream_with_a_status() {
    let address = spawn_upstream(move |request| async move {
        let (_, body) = request.into_parts();
        drop(body);
        let (sender, response_body) = TestBody::channel(2);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let _ = sender
                .send(Frame::trailers(grpc_trailers("0", "never")))
                .await;
        });
        hyper::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(response_body)
            .expect("slow upstream response should build")
    })
    .await;
    let harness = harness(address, |settings| {
        settings.idle_timeout_ms = 0;
        settings.max_duration_ms = 0;
    });

    let response = harness
        .proxy
        .handle_grpc_call(
            grpc_request("/pkg.Service/Slow", TestBody::empty()),
            "203.0.113.7",
        )
        .await;
    let collector = tokio::spawn(collect(response));

    tokio::time::sleep(Duration::from_millis(50)).await;
    harness.lifecycle.force_shutdown_response_streams().await;

    let collected = tokio::time::timeout(Duration::from_secs(5), collector)
        .await
        .expect("a forced shutdown must terminate the stream, not leave it hanging")
        .expect("collector task should finish");
    collected.assert_status(GrpcStatus::Unavailable, "shutdown");
}

/// A client that goes away mid-stream releases everything and is recorded as
/// having cancelled.
///
/// Dropping the response body is what a disconnected client looks like from
/// inside the gateway. It releases the h2 response body, which sends
/// RST_STREAM upstream, and it drops the guard, which releases the admission
/// permit, the endpoint slot, and the shutdown registration together. The
/// audit event is how that is observed without reaching into private state.
#[tokio::test]
async fn a_client_that_goes_away_mid_stream_is_recorded_as_cancelled() {
    let address = spawn_upstream(move |request| async move {
        let (_, body) = request.into_parts();
        drop(body);
        let (sender, response_body) = TestBody::channel(4);
        tokio::spawn(async move {
            let _ = sender.send(Frame::data(framed(&[b"first"]))).await;
            tokio::time::sleep(Duration::from_secs(30)).await;
            let _ = sender
                .send(Frame::trailers(grpc_trailers("0", "never")))
                .await;
        });
        hyper::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(response_body)
            .expect("slow upstream response should build")
    })
    .await;
    let harness = harness(address, |settings| {
        settings.idle_timeout_ms = 0;
        settings.max_duration_ms = 0;
    });

    let mut request = grpc_request("/pkg.Service/Watch", TestBody::empty());
    request
        .headers_mut()
        .insert("x-request-id", HeaderValue::from_static("grpc-cancel-1"));
    let response = harness.proxy.handle_grpc_call(request, "203.0.113.7").await;
    let (_, mut body) = response.into_parts();

    // Take the first message, then walk away.
    let first = std::future::poll_fn(|context| Pin::new(&mut body).poll_frame(context))
        .await
        .expect("a first frame should arrive")
        .expect("frame should decode");
    assert!(first.is_data());
    drop(body);

    let event = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(event) = harness.sink.events().into_iter().find(|event| {
                event.event_type == audit::event::UPSTREAM_GRPC_CALL
                    && event.request_id == "grpc-cancel-1"
            }) {
                return event;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a cancelled call must still be audited, and promptly");

    assert_eq!(event.payload["reason"], "client_cancelled");
    assert_eq!(event.payload["grpc_status"], "cancelled");
    assert_eq!(
        event.payload["messages_upstream_to_client"], 1,
        "the one message that did reach the client should be counted"
    );
}

/// A call that fails at the transport is attempted exactly once.
///
/// #257 disables retry, and a streaming call is not replayable in any case.
/// Counting connection attempts is the only way to see the difference: a retry
/// would produce the same status.
#[tokio::test]
async fn a_failing_call_is_never_retried() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("refusing listener should bind");
    let address = listener
        .local_addr()
        .expect("refusing listener address should be available");
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepts);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            // Accept and close immediately: the HTTP/2 handshake fails, which
            // is a failure AFTER a connection was made, so a retry would be
            // visible as a second accept.
            drop(stream);
        }
    });

    let harness = harness(address, |settings| settings.connect_timeout_ms = 500);
    let response = call(
        &harness,
        grpc_request("/pkg.Service/Method", TestBody::empty()),
    )
    .await;

    assert_eq!(
        response.grpc_status(),
        "14",
        "grpc-message was {}",
        response.grpc_message()
    );
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        1,
        "a failing call was attempted more than once; retries must stay disabled"
    );
    assert_eq!(
        harness.lookups(),
        1,
        "a failing call resolved the endpoint more than once"
    );
}

// ---------------------------------------------------------------------------
// Telemetry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_audit_event_records_bounded_facts_and_no_payload() {
    let (upstream, _log) = spawn_echo_upstream().await;
    let harness = harness(upstream, |_| {});

    let mut request = grpc_request(
        "/helloworld.Greeter/SayHello",
        TestBody::messages(&[b"secret-protobuf-bytes"]),
    );
    request
        .headers_mut()
        .insert("x-request-id", HeaderValue::from_static("grpc-audit-1"));
    let response = call(&harness, request).await;
    assert_eq!(response.grpc_status(), "0");

    let event = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(event) = harness.sink.events().into_iter().find(|event| {
                event.event_type == audit::event::UPSTREAM_GRPC_CALL
                    && event.request_id == "grpc-audit-1"
            }) {
                return event;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a gRPC call audit event should be emitted");

    assert_eq!(event.payload["pool_id"], "grpc");
    assert_eq!(event.payload["endpoint_id"], "primary");
    assert_eq!(event.payload["method"], "/helloworld.Greeter/SayHello");
    assert_eq!(event.payload["result"], "allowed");
    assert_eq!(event.payload["grpc_status"], "ok");
    assert_eq!(event.payload["messages_client_to_upstream"], 1);
    assert_eq!(event.payload["messages_upstream_to_client"], 1);

    let serialized = serde_json::to_string(&event).expect("audit event should serialize");
    assert!(
        !serialized.contains("secret-protobuf-bytes"),
        "protobuf message bytes reached the audit log: {serialized}"
    );
    assert!(
        !serialized.contains("echoed"),
        "the upstream's grpc-message reached the audit log: {serialized}"
    );
}

/// A refused call must not record the caller's raw path.
///
/// The method identity is an audit field only after it has passed the grammar;
/// before that it is unbounded caller-controlled bytes.
#[tokio::test]
async fn a_call_refused_on_its_method_path_records_no_method_identity() {
    let (upstream, _log) = spawn_echo_upstream().await;
    let harness = harness(upstream, |_| {});

    let mut request = grpc_request("/not-a-service/Method", TestBody::empty());
    request
        .headers_mut()
        .insert("x-request-id", HeaderValue::from_static("grpc-audit-2"));
    let response = call(&harness, request).await;
    response.assert_status(GrpcStatus::InvalidArgument, "service_name_grammar");

    let event = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(event) = harness.sink.events().into_iter().find(|event| {
                event.event_type == audit::event::UPSTREAM_GRPC_CALL
                    && event.request_id == "grpc-audit-2"
            }) {
                return event;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a refused gRPC call should still be audited");

    assert!(
        event.payload["method"].is_null(),
        "a path that failed the grammar must not be recorded: {}",
        event.payload
    );
    assert_eq!(event.payload["reason"], "service_name_grammar");
    let serialized = serde_json::to_string(&event).expect("audit event should serialize");
    assert!(
        !serialized.contains("not-a-service"),
        "the raw refused path reached the audit log: {serialized}"
    );
}
