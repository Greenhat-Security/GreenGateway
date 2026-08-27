//! Acceptance coverage for the WebSocket proxy data plane (#256).
//!
//! Every test here drives the real gateway over a real TCP listener, because
//! `tower::oneshot` cannot carry a hyper upgrade: the request never gains the
//! pending-upgrade extension, so a handshake that "passes" in a oneshot harness
//! proves nothing about the transport.

use std::{
    collections::{HashMap, HashSet},
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use futures_util::{future::BoxFuture, SinkExt, StreamExt};
use http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode};
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_tungstenite::{
    client_async,
    tungstenite::{
        self,
        client::IntoClientRequest,
        handshake::derive_accept_key,
        protocol::{
            frame::{
                coding::{Data as OpData, OpCode},
                Frame,
            },
            CloseFrame, Role, WebSocketConfig,
        },
        Message, Utf8Bytes,
    },
    WebSocketStream,
};

use crate::egress::DnsResolver;

use super::*;

// ---------------------------------------------------------------------------
// Upstream test server
// ---------------------------------------------------------------------------

/// How the upstream answers the gateway's handshake.
#[derive(Clone, Debug)]
struct UpstreamPlan {
    status_line: String,
    accept: AcceptKey,
    upgrade: Option<String>,
    connection: Option<String>,
    subprotocol: Option<String>,
    extensions: Option<String>,
    trailing_headers: Vec<(String, String)>,
    body: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcceptKey {
    Derived,
    Wrong,
    Omitted,
}

impl Default for UpstreamPlan {
    fn default() -> Self {
        Self {
            status_line: "HTTP/1.1 101 Switching Protocols".to_owned(),
            accept: AcceptKey::Derived,
            upgrade: Some("websocket".to_owned()),
            connection: Some("Upgrade".to_owned()),
            subprotocol: None,
            extensions: None,
            trailing_headers: Vec::new(),
            body: None,
        }
    }
}

impl UpstreamPlan {
    fn echoing_subprotocol() -> Self {
        Self {
            subprotocol: Some(String::new()),
            ..Self::default()
        }
    }

    fn switches_protocols(&self) -> bool {
        self.status_line.contains("101")
    }
}

type UpstreamHandler =
    Arc<dyn Fn(WebSocketStream<TcpStream>) -> BoxFuture<'static, ()> + Send + Sync>;

struct WsUpstream {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<HeaderMap>>>,
    connections: Arc<AtomicUsize>,
    shutdown: tokio_util::sync::CancellationToken,
    handle: JoinHandle<()>,
}

impl WsUpstream {
    fn request(&self, index: usize) -> HeaderMap {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(index)
            .cloned()
            .unwrap_or_else(|| panic!("upstream should have recorded request {index}"))
    }

    fn connection_count(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    async fn finish(self) {
        self.shutdown.cancel();
        let _ = self.handle.await;
    }
}

/// An upstream that speaks the handshake by hand.
///
/// Hand-writing the 101 is what makes the fail-closed upstream checks testable
/// at all: a conforming library can never produce a wrong `Sec-WebSocket-Accept`,
/// an unrequested extension, or a subprotocol the gateway did not offer.
async fn spawn_ws_upstream(plan: UpstreamPlan, handler: UpstreamHandler) -> WsUpstream {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("websocket test upstream should bind");
    let addr = listener
        .local_addr()
        .expect("websocket test upstream address should be available");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(AtomicUsize::new(0));
    let shutdown = tokio_util::sync::CancellationToken::new();

    let task_requests = Arc::clone(&requests);
    let task_connections = Arc::clone(&connections);
    let task_shutdown = shutdown.clone();
    let handle = tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                () = task_shutdown.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            let Ok((mut stream, _)) = accepted else { break };
            task_connections.fetch_add(1, Ordering::SeqCst);
            let Some(headers) = read_http_request(&mut stream).await else {
                continue;
            };
            let key = headers
                .get(header::SEC_WEBSOCKET_KEY)
                .map(|value| value.as_bytes().to_vec())
                .unwrap_or_default();
            let response = render_handshake_response_for(&plan, &headers, &key);
            task_requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(headers);

            if stream.write_all(&response).await.is_err() {
                continue;
            }
            if !plan.switches_protocols() {
                let _ = stream.shutdown().await;
                continue;
            }
            let socket = WebSocketStream::from_raw_socket(
                stream,
                Role::Server,
                Some(
                    WebSocketConfig::default()
                        .max_message_size(Some(64 * 1024 * 1024))
                        .max_frame_size(Some(64 * 1024 * 1024)),
                ),
            )
            .await;
            let running = handler(socket);
            tokio::select! {
                () = task_shutdown.cancelled() => break,
                () = running => {}
            }
        }
    });

    WsUpstream {
        addr,
        requests,
        connections,
        shutdown,
        handle,
    }
}

fn render_handshake_response(plan: &UpstreamPlan, key: &[u8]) -> Vec<u8> {
    let mut response = format!("{}\r\n", plan.status_line);
    if let Some(upgrade) = plan.upgrade.as_deref() {
        response.push_str(&format!("Upgrade: {upgrade}\r\n"));
    }
    if let Some(connection) = plan.connection.as_deref() {
        response.push_str(&format!("Connection: {connection}\r\n"));
    }
    match plan.accept {
        AcceptKey::Derived => {
            response.push_str(&format!(
                "Sec-WebSocket-Accept: {}\r\n",
                derive_accept_key(key)
            ));
        }
        AcceptKey::Wrong => {
            response.push_str("Sec-WebSocket-Accept: bm90LXRoZS1yaWdodC1rZXk=\r\n");
        }
        AcceptKey::Omitted => {}
    }
    if let Some(subprotocol) = plan.subprotocol.as_deref() {
        // An empty string means "echo whatever the gateway offered", which is
        // what a conforming upstream does.
        response.push_str(&format!("Sec-WebSocket-Protocol: {subprotocol}\r\n"));
    }
    if let Some(extensions) = plan.extensions.as_deref() {
        response.push_str(&format!("Sec-WebSocket-Extensions: {extensions}\r\n"));
    }
    for (name, value) in &plan.trailing_headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = plan.body.as_deref() {
        response.push_str(&format!("Content-Length: {}\r\n", body.len()));
        response.push_str("\r\n");
        response.push_str(body);
    } else {
        response.push_str("\r\n");
    }

    response.into_bytes()
}

/// Renders the plan, substituting the subprotocol the gateway actually offered
/// when the plan asked to echo it.
fn render_handshake_response_for(plan: &UpstreamPlan, headers: &HeaderMap, key: &[u8]) -> Vec<u8> {
    let mut plan = plan.clone();
    if plan.subprotocol.as_deref() == Some("") {
        plan.subprotocol = headers
            .get(header::SEC_WEBSOCKET_PROTOCOL)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
    }
    render_handshake_response(&plan, key)
}

async fn read_http_request(stream: &mut TcpStream) -> Option<HeaderMap> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        assert!(
            buffer.len() <= 64 * 1024,
            "test upstream request headers should stay bounded"
        );
    }
    let end = buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("request head should terminate");
    let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
    let mut headers = HeaderMap::new();
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let Ok(name) = HeaderName::from_bytes(name.trim().as_bytes()) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_str(value.trim()) else {
            continue;
        };
        headers.append(name, value);
    }

    Some(headers)
}

fn echo_handler() -> UpstreamHandler {
    Arc::new(|mut socket: WebSocketStream<TcpStream>| {
        Box::pin(async move {
            while let Some(Ok(message)) = socket.next().await {
                match message {
                    Message::Close(frame) => {
                        let _ = socket.send(Message::Close(frame)).await;
                        break;
                    }
                    Message::Ping(_) | Message::Pong(_) => {}
                    other => {
                        if socket.send(other).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }) as BoxFuture<'static, ()>
    })
}

/// Holds the socket open and never sends anything, so an idle or duration
/// deadline is the only thing that can end the connection.
fn silent_handler() -> UpstreamHandler {
    Arc::new(|mut socket: WebSocketStream<TcpStream>| {
        Box::pin(async move { while let Some(Ok(_)) = socket.next().await {} })
            as BoxFuture<'static, ()>
    })
}

/// Sends one message split across several frames, which the gateway must
/// reassemble before it applies the assembled-message bound and forwards it.
fn fragmenting_handler(fragments: Vec<&'static str>) -> UpstreamHandler {
    Arc::new(move |mut socket: WebSocketStream<TcpStream>| {
        let fragments = fragments.clone();
        Box::pin(async move {
            let last = fragments.len() - 1;
            for (index, fragment) in fragments.iter().enumerate() {
                let opcode = if index == 0 {
                    OpCode::Data(OpData::Text)
                } else {
                    OpCode::Data(OpData::Continue)
                };
                let frame = Frame::message(fragment.as_bytes().to_vec(), opcode, index == last);
                if socket.send(Message::Frame(frame)).await.is_err() {
                    return;
                }
            }
            while let Some(Ok(_)) = socket.next().await {}
        }) as BoxFuture<'static, ()>
    })
}

fn sending_handler(messages: Vec<Message>) -> UpstreamHandler {
    Arc::new(move |mut socket: WebSocketStream<TcpStream>| {
        let messages = messages.clone();
        Box::pin(async move {
            for message in messages {
                if socket.send(message).await.is_err() {
                    return;
                }
            }
            while let Some(Ok(_)) = socket.next().await {}
        }) as BoxFuture<'static, ()>
    })
}

// ---------------------------------------------------------------------------
// Gateway harness
// ---------------------------------------------------------------------------

struct CountingResolver {
    answers: HashMap<String, Vec<IpAddr>>,
    calls: Arc<AtomicUsize>,
}

impl CountingResolver {
    fn new(answers: HashMap<String, Vec<IpAddr>>) -> (Arc<Self>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(Self {
                answers,
                calls: Arc::clone(&calls),
            }),
            calls,
        )
    }
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
                "unexpected websocket acceptance host",
            )),
        }
    }
}

/// A listener that fails the test if anything ever connects to it.
struct SentinelUpstream {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    shutdown: tokio_util::sync::CancellationToken,
}

impl SentinelUpstream {
    async fn spawn() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("sentinel upstream should bind");
        let addr = listener
            .local_addr()
            .expect("sentinel upstream address should be available");
        let connections = Arc::new(AtomicUsize::new(0));
        let shutdown = tokio_util::sync::CancellationToken::new();
        let task_connections = Arc::clone(&connections);
        let task_shutdown = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = task_shutdown.cancelled() => break,
                    accepted = listener.accept() => {
                        if accepted.is_ok() {
                            task_connections.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            }
        });

        Self {
            addr,
            connections,
            shutdown,
        }
    }

    fn assert_untouched(&self) {
        assert_eq!(
            self.connections.load(Ordering::SeqCst),
            0,
            "a refused upgrade must never open an upstream connection"
        );
    }
}

impl Drop for SentinelUpstream {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

fn websocket_config(
    upstream_host: &str,
    upstream_addr: SocketAddr,
    configure: impl FnOnce(&mut config::UpstreamWebSocketConfig),
) -> config::Config {
    let mut websocket = default_websocket_settings();
    configure(&mut websocket);

    let route = config::UpstreamRouteConfig {
        id: Some("ws-route".to_owned()),
        connection_id: None,
        path_prefix: Some("/socket".to_owned()),
        host: None,
        upstream_url: String::new(),
        upstreams: vec![config::UpstreamEndpointConfig {
            id: "primary".to_owned(),
            url: format!("http://{upstream_host}:{}", upstream_addr.port()),
            weight: 1,
            tls_ca_bundle_path: None,
            client_identity_pem_path: None,
        }],
        load_balancing: config::UpstreamLoadBalancingConfig::default(),
        request_body: config::UpstreamRequestBodyConfig::default(),
        sse: None,
        websocket: Some(websocket),
        grpc: None,
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
    config.egress_allowed_hosts = vec![upstream_host.to_owned()];
    config.egress_deny_private_ips = false;

    config
}

fn default_websocket_settings() -> config::UpstreamWebSocketConfig {
    config::UpstreamWebSocketConfig {
        max_connections: config::DEFAULT_WEBSOCKET_MAX_CONNECTIONS,
        max_connections_per_endpoint: None,
        queue_depth: config::DEFAULT_WEBSOCKET_QUEUE_DEPTH,
        queue_timeout_ms: config::DEFAULT_WEBSOCKET_QUEUE_TIMEOUT_MS,
        handshake_timeout_ms: 2_000,
        idle_timeout_ms: 0,
        max_duration_ms: 0,
        max_frame_bytes: config::MIN_WEBSOCKET_MAX_FRAME_BYTES,
        max_message_bytes: config::MIN_WEBSOCKET_MAX_FRAME_BYTES,
        max_write_buffer_bytes: config::DEFAULT_WEBSOCKET_MAX_WRITE_BUFFER_BYTES,
        allowed_origins: Vec::new(),
        require_origin: false,
        allowed_subprotocols: Vec::new(),
    }
}

struct GatewayHarness {
    addr: SocketAddr,
    audit: audit::sink::tests::CaptureSink,
    lifecycle: GatewayLifecycle,
    dns_calls: Arc<AtomicUsize>,
    metrics: PrometheusHandle,
    shutdown: tokio_util::sync::CancellationToken,
    handle: JoinHandle<()>,
}

impl GatewayHarness {
    async fn finish(self) {
        self.shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.handle).await;
    }

    fn events(&self, event_type: &str) -> Vec<audit::AuditEvent> {
        self.audit
            .events()
            .into_iter()
            .filter(|event| event.event_type == event_type)
            .collect()
    }

    async fn wait_for_event(&self, event_type: &str) -> audit::AuditEvent {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(event) = self.events(event_type).into_iter().next() {
                    return event;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("audit event {event_type} should be emitted"))
    }

    /// Audit dispatch is asynchronous, so a count is only meaningful once it
    /// has had a bounded chance to settle.
    async fn wait_for_events(&self, event_type: &str, count: usize) -> Vec<audit::AuditEvent> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let events = self.events(event_type);
                if events.len() >= count {
                    return events;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "expected {count} {event_type} events, saw {}",
                self.events(event_type).len()
            )
        })
    }

    async fn wait_for_denied_handshake(&self) -> audit::AuditEvent {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(event) = self
                    .events(audit::event::UPSTREAM_WEBSOCKET_HANDSHAKE)
                    .into_iter()
                    .find(|event| event.payload["result"] == "denied")
                {
                    return event;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .expect("a refused handshake should be audited")
    }

    fn dns_calls(&self) -> usize {
        self.dns_calls.load(Ordering::SeqCst)
    }
}

/// The process-wide Prometheus registry these tests assert against.
///
/// `metrics` macros write to the globally installed recorder, so a handle built
/// per test would render an empty registry and quietly turn every metric
/// assertion into a tautology.
fn shared_metrics() -> PrometheusHandle {
    static HANDLE: std::sync::OnceLock<PrometheusHandle> = std::sync::OnceLock::new();
    HANDLE
        .get_or_init(|| {
            let recorder = PrometheusBuilder::new().build_recorder();
            let handle = recorder.handle();
            ::metrics::set_global_recorder(recorder)
                .expect("the websocket acceptance suite owns the process metrics recorder");
            handle
        })
        .clone()
}

async fn spawn_gateway(
    config: config::Config,
    dns: HashMap<String, Vec<IpAddr>>,
) -> GatewayHarness {
    let (resolver, dns_calls) = CountingResolver::new(dns);
    let lifecycle = GatewayLifecycle::new();
    let sink = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(sink.clone()));
    let metrics = shared_metrics();
    let app = gateway_app_with_process_started_at_and_overrides(
        config,
        metrics.clone(),
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
    .expect("websocket acceptance app should build");
    let router = match app.http {
        GatewayApp::Unified(router) => router,
        GatewayApp::Split { .. } => panic!("websocket acceptance app should be unified"),
    };
    lifecycle.mark_ready();

    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("gateway listener should bind");
    let addr = listener
        .local_addr()
        .expect("gateway address should be available");
    let shutdown = tokio_util::sync::CancellationToken::new();
    let serve_shutdown = shutdown.clone();
    let handle = tokio::spawn(async move {
        // Connect info is what makes the canonical client IP real, and the
        // canonical client IP is what replaces a spoofed forwarding header.
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(serve_shutdown.cancelled_owned())
        .await;
    });

    GatewayHarness {
        addr,
        audit: sink,
        lifecycle,
        dns_calls,
        metrics,
        shutdown,
        handle,
    }
}

// ---------------------------------------------------------------------------
// Client helpers
// ---------------------------------------------------------------------------

type ClientSocket = WebSocketStream<TcpStream>;

async fn connect_client(
    addr: SocketAddr,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> Result<(ClientSocket, http::Response<Option<Vec<u8>>>), tungstenite::Error> {
    let mut request = format!("ws://127.0.0.1:{}{path}", addr.port())
        .into_client_request()
        .expect("client request should build");
    for (name, value) in extra_headers {
        request.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).expect("test header name should parse"),
            HeaderValue::from_str(value).expect("test header value should parse"),
        );
    }
    let stream = TcpStream::connect(addr)
        .await
        .expect("client should reach the gateway");

    client_async(request, stream).await
}

fn refusal(error: tungstenite::Error) -> http::Response<Option<Vec<u8>>> {
    match error {
        tungstenite::Error::Http(response) => *response,
        other => panic!("expected an HTTP refusal, got {other}"),
    }
}

/// Sends a hand-written upgrade request so that shapes a conforming client
/// cannot produce -- a duplicated version header, a 16-byte key that is not
/// base64, `Upgrade: websocket, h2c` -- are reachable.
async fn raw_upgrade(addr: SocketAddr, request_lines: &[&str]) -> (StatusCode, HeaderMap) {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("raw client should reach the gateway");
    let mut request = String::new();
    for line in request_lines {
        request.push_str(line);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("raw request should write");

    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .expect("gateway should answer a raw upgrade")
            .expect("gateway response should read");
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    let end = buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("gateway response head should terminate");
    let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .and_then(|code| StatusCode::from_u16(code).ok())
        .expect("gateway status line should parse");
    let mut headers = HeaderMap::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.trim().as_bytes()),
            HeaderValue::from_str(value.trim()),
        ) {
            headers.append(name, value);
        }
    }

    (status, headers)
}

fn upgrade_request_lines(port: u16) -> Vec<String> {
    vec![
        "GET /socket HTTP/1.1".to_owned(),
        format!("Host: 127.0.0.1:{port}"),
        "Connection: Upgrade".to_owned(),
        "Upgrade: websocket".to_owned(),
        "Sec-WebSocket-Version: 13".to_owned(),
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==".to_owned(),
    ]
}

async fn next_message(socket: &mut ClientSocket) -> Message {
    tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("a message should arrive before the test times out")
        .expect("the socket should not have ended")
        .expect("the message should not be an error")
}

const UPSTREAM_HOST: &str = "ws-upstream.example.test";

fn upstream_dns() -> HashMap<String, Vec<IpAddr>> {
    HashMap::from([(
        UPSTREAM_HOST.to_owned(),
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    )])
}

fn header_text(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn as_lines(lines: &[String]) -> Vec<&str> {
    lines.iter().map(String::as_str).collect()
}

// ---------------------------------------------------------------------------
// Authorized handshake and bidirectional forwarding
// ---------------------------------------------------------------------------

#[tokio::test]
async fn authorized_upgrade_forwards_text_and_binary_and_rebuilds_the_handshake() {
    let upstream = spawn_ws_upstream(UpstreamPlan::echoing_subprotocol(), echo_handler()).await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |websocket| {
        websocket.allowed_subprotocols = vec!["chat.v1".to_owned()];
        websocket.allowed_origins = vec!["https://app.example".to_owned()];
    });
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let (mut socket, response) = connect_client(
        gateway.addr,
        "/socket/room?tenant=acme",
        &[
            ("origin", "https://APP.example:443"),
            ("sec-websocket-protocol", "unknown.v9, chat.v1"),
            ("authorization", "Bearer spoofed-token"),
            ("cookie", "session=spoofed"),
            ("x-forwarded-for", "203.0.113.9"),
            ("x-real-ip", "203.0.113.9"),
            ("sec-websocket-extensions", "permessage-deflate"),
        ],
    )
    .await
    .expect("the authorized upgrade should succeed");

    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(
        header_text(response.headers(), "sec-websocket-protocol").as_deref(),
        Some("chat.v1"),
        "the gateway must tell the client which subprotocol it negotiated"
    );

    socket
        .send(Message::text("hello upstream"))
        .await
        .expect("client should send text");
    assert_eq!(
        next_message(&mut socket)
            .await
            .into_text()
            .expect("echo should be text")
            .as_str(),
        "hello upstream"
    );
    socket
        .send(Message::binary(vec![0_u8, 1, 2, 250]))
        .await
        .expect("client should send binary");
    assert_eq!(
        next_message(&mut socket).await.into_data().to_vec(),
        vec![0_u8, 1, 2, 250]
    );

    let sent = upstream.request(0);
    assert_eq!(
        header_text(&sent, "host"),
        Some(format!("{UPSTREAM_HOST}:{}", upstream.addr.port())),
        "the upstream must see its own authority, never the client's Host"
    );
    assert_eq!(
        header_text(&sent, "sec-websocket-version").as_deref(),
        Some("13")
    );
    assert_eq!(
        header_text(&sent, "sec-websocket-protocol").as_deref(),
        Some("chat.v1"),
        "only the negotiated subprotocol is offered upstream"
    );
    assert_eq!(
        header_text(&sent, "origin").as_deref(),
        Some("https://app.example"),
        "the forwarded origin is the normalized allowlist entry"
    );
    assert_eq!(
        header_text(&sent, "x-forwarded-for").as_deref(),
        Some("127.0.0.1"),
        "the gateway replaces a spoofed forwarding header with the observed peer"
    );
    assert_eq!(
        header_text(&sent, "x-real-ip").as_deref(),
        Some("127.0.0.1")
    );
    assert!(
        sent.get("authorization").is_none(),
        "a caller credential must never reach the upstream"
    );
    assert!(
        sent.get("cookie").is_none(),
        "a caller cookie must never reach the upstream"
    );
    assert!(
        sent.get("sec-websocket-extensions").is_none(),
        "compression is a non-goal, so no extension is ever offered"
    );
    assert!(
        sent.get("sec-websocket-key").is_some(),
        "the gateway originates its own handshake key"
    );

    drop(socket);
    upstream.finish().await;
    gateway.finish().await;
}

#[tokio::test]
async fn client_websocket_key_and_connection_nominated_headers_never_cross_the_boundary() {
    let upstream = spawn_ws_upstream(UpstreamPlan::default(), echo_handler()).await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |_| {});
    let gateway = spawn_gateway(config, upstream_dns()).await;

    const CLIENT_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
    let mut lines = upgrade_request_lines(gateway.addr.port());
    lines[2] = "Connection: Upgrade, X-Secret-Header".to_owned();
    lines.push("X-Secret-Header: leaked".to_owned());
    lines.push("Sec-WebSocket-Extensions: permessage-deflate".to_owned());
    let (status, response_headers) = raw_upgrade(gateway.addr, &as_lines(&lines)).await;

    assert_eq!(status, StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(
        header_text(&response_headers, "sec-websocket-accept").as_deref(),
        Some(derive_accept_key(CLIENT_KEY.as_bytes()).as_str()),
        "the client's 101 is signed with the client's own key"
    );

    let sent = upstream.request(0);
    let upstream_key = header_text(&sent, "sec-websocket-key")
        .expect("the gateway must send its own handshake key");
    assert_ne!(
        upstream_key, CLIENT_KEY,
        "the gateway must never replay the client's Sec-WebSocket-Key upstream"
    );
    assert!(
        sent.get("x-secret-header").is_none(),
        "a Connection-nominated header must not survive the boundary"
    );
    assert!(sent.get("sec-websocket-extensions").is_none());

    upstream.finish().await;
    gateway.finish().await;
}

// ---------------------------------------------------------------------------
// Denials that must never reach the network
// ---------------------------------------------------------------------------

#[tokio::test]
async fn authentication_denial_causes_no_dns_and_no_upstream_connection() {
    let sentinel = SentinelUpstream::spawn().await;
    let mut config = websocket_config(UPSTREAM_HOST, sentinel.addr, |_| {});
    config.auth_enabled = true;
    config.auth_mode = config::AuthMode::Required;
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let error = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect_err("an unauthenticated upgrade must be refused");
    let response = refusal(error);

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        gateway.dns_calls(),
        0,
        "a denied upgrade must resolve nothing"
    );
    sentinel.assert_untouched();
    assert!(
        gateway
            .events(audit::event::UPSTREAM_WEBSOCKET_HANDSHAKE)
            .is_empty(),
        "a request refused before route dispatch never becomes a websocket handshake"
    );

    gateway.finish().await;
}

#[tokio::test]
async fn rbac_denial_causes_no_dns_and_no_upstream_connection() {
    let sentinel = SentinelUpstream::spawn().await;
    let policy = TempPolicyFile::new(
        &json!({
            "schema_version": "0.1.0",
            "id": "websocket-deny-all",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {},
            "routes": []
        })
        .to_string(),
    );
    let mut config = websocket_config(UPSTREAM_HOST, sentinel.addr, |_| {});
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let error = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect_err("a policy-denied upgrade must be refused");
    let response = refusal(error);

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(gateway.dns_calls(), 0);
    sentinel.assert_untouched();

    gateway.finish().await;
}

#[tokio::test]
async fn malformed_upgrade_requests_are_refused_before_any_egress() {
    let sentinel = SentinelUpstream::spawn().await;
    let config = websocket_config(UPSTREAM_HOST, sentinel.addr, |_| {});
    let gateway = spawn_gateway(config, upstream_dns()).await;
    let port = gateway.addr.port();

    // Wrong protocol version: the answer must advertise the one version the
    // gateway speaks, so a client can correct itself.
    let mut lines = upgrade_request_lines(port);
    lines[4] = "Sec-WebSocket-Version: 8".to_owned();
    let (status, headers) = raw_upgrade(gateway.addr, &as_lines(&lines)).await;
    assert_eq!(status, StatusCode::UPGRADE_REQUIRED);
    assert_eq!(
        header_text(&headers, "sec-websocket-version").as_deref(),
        Some("13")
    );

    // A duplicated version header is ambiguous, and ambiguity is refused.
    let mut lines = upgrade_request_lines(port);
    lines.push("Sec-WebSocket-Version: 13".to_owned());
    let (status, _) = raw_upgrade(gateway.addr, &as_lines(&lines)).await;
    assert_eq!(status, StatusCode::UPGRADE_REQUIRED);

    // A key that is not sixteen base64 bytes.
    for key in ["not-base64!!", "c2hvcnQ=", ""] {
        let mut lines = upgrade_request_lines(port);
        lines[5] = format!("Sec-WebSocket-Key: {key}");
        let (status, _) = raw_upgrade(gateway.addr, &as_lines(&lines)).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a key that does not decode to sixteen bytes is refused: {key:?}"
        );
    }

    // An Upgrade token list the gateway will not interpret loosely.
    let mut lines = upgrade_request_lines(port);
    lines[3] = "Upgrade: websocket, h2c".to_owned();
    let (status, _) = raw_upgrade(gateway.addr, &as_lines(&lines)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    assert_eq!(
        gateway.dns_calls(),
        0,
        "no malformed upgrade may resolve a name"
    );
    sentinel.assert_untouched();

    let denials = gateway
        .wait_for_events(audit::event::UPSTREAM_WEBSOCKET_HANDSHAKE, 6)
        .await;
    assert_eq!(denials.len(), 6);
    for event in &denials {
        assert_eq!(event.payload["result"], "denied");
        assert!(event.payload["endpoint_id"].is_null());
    }

    gateway.finish().await;
}

#[tokio::test]
async fn origin_policy_allows_denies_and_fails_closed() {
    let sentinel = SentinelUpstream::spawn().await;
    let config = websocket_config(UPSTREAM_HOST, sentinel.addr, |websocket| {
        websocket.allowed_origins = vec!["https://app.example".to_owned()];
    });
    let gateway = spawn_gateway(config, upstream_dns()).await;

    for origin in [
        "https://evil.example",
        "https://app.example.evil",
        "http://app.example",
        "https://app.example:8443",
        "not-an-origin",
    ] {
        let error = connect_client(gateway.addr, "/socket/room", &[("origin", origin)])
            .await
            .expect_err("a non-matching origin must be refused");
        assert_eq!(
            refusal(error).status(),
            StatusCode::FORBIDDEN,
            "origin {origin} must not be accepted"
        );
    }

    // Two Origin headers are refused rather than resolved to whichever the
    // gateway happened to read first.
    let mut lines = upgrade_request_lines(gateway.addr.port());
    lines.push("Origin: https://app.example".to_owned());
    lines.push("Origin: https://evil.example".to_owned());
    let (status, _) = raw_upgrade(gateway.addr, &as_lines(&lines)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    assert_eq!(gateway.dns_calls(), 0);
    sentinel.assert_untouched();

    for event in gateway.events(audit::event::UPSTREAM_WEBSOCKET_HANDSHAKE) {
        let payload = event.payload.to_string();
        assert!(
            !payload.contains("evil.example"),
            "an attacker-chosen origin must never be recorded: {payload}"
        );
    }

    gateway.finish().await;
}

#[tokio::test]
async fn an_empty_origin_allowlist_denies_every_origin_bearing_upgrade() {
    let sentinel = SentinelUpstream::spawn().await;
    let config = websocket_config(UPSTREAM_HOST, sentinel.addr, |_| {});
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let error = connect_client(
        gateway.addr,
        "/socket/room",
        &[("origin", "https://app.example")],
    )
    .await
    .expect_err("an empty allowlist allows no origin");
    assert_eq!(refusal(error).status(), StatusCode::FORBIDDEN);
    assert_eq!(gateway.dns_calls(), 0);
    sentinel.assert_untouched();

    gateway.finish().await;
}

#[tokio::test]
async fn require_origin_refuses_an_upgrade_that_carries_none() {
    let sentinel = SentinelUpstream::spawn().await;
    let config = websocket_config(UPSTREAM_HOST, sentinel.addr, |websocket| {
        websocket.require_origin = true;
        websocket.allowed_origins = vec!["https://app.example".to_owned()];
    });
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let error = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect_err("require_origin must refuse an origin-less upgrade");
    assert_eq!(refusal(error).status(), StatusCode::FORBIDDEN);
    assert_eq!(gateway.dns_calls(), 0);
    sentinel.assert_untouched();

    gateway.finish().await;
}

#[tokio::test]
async fn subprotocol_policy_intersects_in_client_preference_order() {
    let upstream = spawn_ws_upstream(UpstreamPlan::echoing_subprotocol(), echo_handler()).await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |websocket| {
        websocket.allowed_subprotocols = vec!["chat.v1".to_owned(), "chat.v2".to_owned()];
    });
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let (socket, response) = connect_client(
        gateway.addr,
        "/socket/room",
        &[("sec-websocket-protocol", "chat.v2, chat.v1")],
    )
    .await
    .expect("an allowed subprotocol should negotiate");
    assert_eq!(
        header_text(response.headers(), "sec-websocket-protocol").as_deref(),
        Some("chat.v2"),
        "the client's first acceptable preference wins, not the config order"
    );
    assert_eq!(
        header_text(&upstream.request(0), "sec-websocket-protocol").as_deref(),
        Some("chat.v2")
    );

    drop(socket);
    upstream.finish().await;
    gateway.finish().await;
}

#[tokio::test]
async fn subprotocol_mismatch_is_denied_before_any_egress() {
    let sentinel = SentinelUpstream::spawn().await;
    let config = websocket_config(UPSTREAM_HOST, sentinel.addr, |websocket| {
        websocket.allowed_subprotocols = vec!["chat.v1".to_owned()];
    });
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let error = connect_client(
        gateway.addr,
        "/socket/room",
        &[("sec-websocket-protocol", "chat.v9, mqtt")],
    )
    .await
    .expect_err("an unallowed subprotocol must be refused");
    assert_eq!(refusal(error).status(), StatusCode::FORBIDDEN);
    assert_eq!(gateway.dns_calls(), 0);
    sentinel.assert_untouched();

    gateway.finish().await;
}

#[tokio::test]
async fn an_empty_subprotocol_allowlist_denies_any_offer_but_allows_none() {
    let upstream = spawn_ws_upstream(UpstreamPlan::default(), echo_handler()).await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |_| {});
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let error = connect_client(
        gateway.addr,
        "/socket/room",
        &[("sec-websocket-protocol", "chat.v1")],
    )
    .await
    .expect_err("an empty allowlist allows no subprotocol");
    assert_eq!(refusal(error).status(), StatusCode::FORBIDDEN);

    let (socket, response) = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect("a client that offers nothing negotiates nothing");
    assert!(response.headers().get("sec-websocket-protocol").is_none());
    assert!(upstream.request(0).get("sec-websocket-protocol").is_none());

    drop(socket);
    upstream.finish().await;
    gateway.finish().await;
}

// ---------------------------------------------------------------------------
// Fail-closed validation of the upstream's answer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_upstream_handshake_the_gateway_did_not_ask_for_fails_closed() {
    for (label, plan, reason) in [
        (
            "wrong accept key",
            UpstreamPlan {
                accept: AcceptKey::Wrong,
                ..UpstreamPlan::default()
            },
            "upstream_accept_mismatch",
        ),
        (
            "missing accept key",
            UpstreamPlan {
                accept: AcceptKey::Omitted,
                ..UpstreamPlan::default()
            },
            "upstream_handshake_invalid",
        ),
        (
            "unrequested extension",
            UpstreamPlan {
                extensions: Some("permessage-deflate".to_owned()),
                ..UpstreamPlan::default()
            },
            "upstream_extension_offered",
        ),
        (
            "unoffered subprotocol",
            UpstreamPlan {
                subprotocol: Some("chat.v9".to_owned()),
                ..UpstreamPlan::default()
            },
            "upstream_subprotocol_invalid",
        ),
        (
            "no upgrade header",
            UpstreamPlan {
                upgrade: None,
                ..UpstreamPlan::default()
            },
            "upstream_handshake_invalid",
        ),
    ] {
        let upstream = spawn_ws_upstream(plan, echo_handler()).await;
        let config = websocket_config(UPSTREAM_HOST, upstream.addr, |_| {});
        let gateway = spawn_gateway(config, upstream_dns()).await;

        let error = connect_client(gateway.addr, "/socket/room", &[])
            .await
            .err()
            .unwrap_or_else(|| panic!("{label} must not produce a usable socket"));
        assert_eq!(
            refusal(error).status(),
            StatusCode::BAD_GATEWAY,
            "{label} must fail the handshake"
        );

        let event = gateway
            .wait_for_event(audit::event::UPSTREAM_WEBSOCKET_HANDSHAKE)
            .await;
        assert_eq!(event.payload["result"], "failed", "{label}");
        assert_eq!(event.payload["reason"], reason, "{label}");

        upstream.finish().await;
        gateway.finish().await;
    }
}

#[tokio::test]
async fn a_non_101_upstream_answer_never_forwards_its_body() {
    let upstream = spawn_ws_upstream(
        UpstreamPlan {
            status_line: "HTTP/1.1 403 Forbidden".to_owned(),
            accept: AcceptKey::Omitted,
            upgrade: None,
            connection: None,
            body: Some("upstream body that must never be forwarded".to_owned()),
            trailing_headers: vec![("X-Upstream-Secret".to_owned(), "leaked".to_owned())],
            ..UpstreamPlan::default()
        },
        echo_handler(),
    )
    .await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |_| {});
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let error = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect_err("a refused upstream upgrade must refuse the client");
    let response = refusal(error);

    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "the upstream's own status must not be replayed to the client"
    );
    assert!(
        response.headers().get("x-upstream-secret").is_none(),
        "no upstream header may reach the client"
    );
    let body = String::from_utf8_lossy(response.body().as_deref().unwrap_or(&[])).into_owned();
    assert!(
        !body.contains("must never be forwarded"),
        "the upstream body must never reach the client: {body}"
    );

    upstream.finish().await;
    gateway.finish().await;
}

#[tokio::test]
async fn an_upstream_that_never_answers_hits_the_handshake_timeout() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("stalling upstream should bind");
    let addr = listener
        .local_addr()
        .expect("stalling upstream address should be available");
    let stall = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    let config = websocket_config(UPSTREAM_HOST, addr, |websocket| {
        websocket.handshake_timeout_ms = config::MIN_WEBSOCKET_HANDSHAKE_TIMEOUT_MS;
    });
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let error = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect_err("a stalled upstream handshake must time out");
    assert_eq!(refusal(error).status(), StatusCode::GATEWAY_TIMEOUT);

    let event = gateway
        .wait_for_event(audit::event::UPSTREAM_WEBSOCKET_HANDSHAKE)
        .await;
    assert_eq!(event.payload["result"], "failed");
    assert_eq!(event.payload["reason"], "handshake_timeout");

    stall.abort();
    gateway.finish().await;
}

// ---------------------------------------------------------------------------
// Frames, fragmentation, and bounds
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_fragmented_upstream_message_is_reassembled_before_it_reaches_the_client() {
    let upstream = spawn_ws_upstream(
        UpstreamPlan::default(),
        fragmenting_handler(vec!["frag-one:", "frag-two:", "frag-three"]),
    )
    .await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |_| {});
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let (mut socket, _) = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect("the upgrade should succeed");
    assert_eq!(
        next_message(&mut socket)
            .await
            .into_text()
            .expect("the reassembled message should be text")
            .as_str(),
        "frag-one:frag-two:frag-three",
        "a message split across frames must arrive whole"
    );

    drop(socket);
    upstream.finish().await;
    gateway.finish().await;
}

#[tokio::test]
async fn control_frames_traverse_the_bridge_in_both_directions() {
    let upstream = spawn_ws_upstream(
        UpstreamPlan::default(),
        sending_handler(vec![Message::Ping(bytes::Bytes::from_static(
            b"upstream-ping",
        ))]),
    )
    .await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |_| {});
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let (mut socket, _) = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect("the upgrade should succeed");

    let mut saw_ping = false;
    for _ in 0..4 {
        if let Message::Ping(payload) = next_message(&mut socket).await {
            assert_eq!(payload.as_ref(), b"upstream-ping");
            saw_ping = true;
            break;
        }
    }
    assert!(saw_ping, "an upstream ping must reach the client");

    drop(socket);
    upstream.finish().await;
    gateway.finish().await;
}

#[tokio::test]
async fn an_oversized_client_message_closes_with_the_capacity_code() {
    let upstream = spawn_ws_upstream(UpstreamPlan::default(), echo_handler()).await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |websocket| {
        websocket.max_frame_bytes = config::MIN_WEBSOCKET_MAX_FRAME_BYTES;
        websocket.max_message_bytes = config::MIN_WEBSOCKET_MAX_FRAME_BYTES;
    });
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let (mut socket, _) = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect("the upgrade should succeed");
    socket
        .send(Message::binary(vec![
            7_u8;
            config::MIN_WEBSOCKET_MAX_FRAME_BYTES
                * 4
        ]))
        .await
        .expect("an oversized send is accepted locally and refused by the gateway");

    let closed = gateway
        .wait_for_event(audit::event::UPSTREAM_WEBSOCKET_CLOSED)
        .await;
    assert_eq!(closed.payload["outcome"], "client_capacity");
    assert_eq!(closed.payload["close_code"], 1009);
    assert_eq!(
        closed.payload["frames_client_to_upstream"], 0,
        "a message the gateway refused is never counted as forwarded"
    );

    drop(socket);
    upstream.finish().await;
    gateway.finish().await;
}

#[tokio::test]
async fn an_oversized_upstream_message_closes_with_the_capacity_code() {
    let upstream = spawn_ws_upstream(
        UpstreamPlan::default(),
        sending_handler(vec![Message::binary(vec![
            9_u8;
            config::MIN_WEBSOCKET_MAX_FRAME_BYTES
                * 4
        ])]),
    )
    .await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |websocket| {
        websocket.max_frame_bytes = config::MIN_WEBSOCKET_MAX_FRAME_BYTES;
        websocket.max_message_bytes = config::MIN_WEBSOCKET_MAX_FRAME_BYTES;
    });
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let (socket, _) = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect("the upgrade should succeed");

    let closed = gateway
        .wait_for_event(audit::event::UPSTREAM_WEBSOCKET_CLOSED)
        .await;
    assert_eq!(closed.payload["outcome"], "upstream_capacity");
    assert_eq!(closed.payload["close_code"], 1009);

    drop(socket);
    upstream.finish().await;
    gateway.finish().await;
}

// ---------------------------------------------------------------------------
// Close propagation and lifecycle
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_client_close_code_reaches_the_upstream() {
    let upstream = spawn_ws_upstream(UpstreamPlan::default(), echo_handler()).await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |_| {});
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let (mut socket, _) = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect("the upgrade should succeed");
    socket
        .send(Message::Close(Some(CloseFrame {
            code: 4001.into(),
            reason: Utf8Bytes::from("client is done"),
        })))
        .await
        .expect("the client should be able to close");

    let closed = gateway
        .wait_for_event(audit::event::UPSTREAM_WEBSOCKET_CLOSED)
        .await;
    assert_eq!(closed.payload["outcome"], "client_close");
    assert_eq!(closed.payload["close_code"], 4001);
    assert!(
        !closed.payload.to_string().contains("client is done"),
        "a close reason is peer-supplied text and must never be recorded"
    );

    upstream.finish().await;
    gateway.finish().await;
}

#[tokio::test]
async fn an_upstream_close_code_reaches_the_client() {
    let upstream = spawn_ws_upstream(
        UpstreamPlan::default(),
        sending_handler(vec![Message::Close(Some(CloseFrame {
            code: 4002.into(),
            reason: Utf8Bytes::from("upstream is done"),
        }))]),
    )
    .await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |_| {});
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let (mut socket, _) = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect("the upgrade should succeed");
    let message = next_message(&mut socket).await;
    let Message::Close(Some(frame)) = message else {
        panic!("the client should receive the upstream close frame, got {message:?}");
    };
    assert_eq!(u16::from(frame.code), 4002);
    assert_eq!(frame.reason.as_str(), "upstream is done");

    upstream.finish().await;
    gateway.finish().await;
}

#[tokio::test]
async fn an_idle_connection_is_closed_with_the_normal_code() {
    let upstream = spawn_ws_upstream(UpstreamPlan::default(), silent_handler()).await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |websocket| {
        websocket.idle_timeout_ms = config::MIN_WEBSOCKET_IDLE_TIMEOUT_MS;
    });
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let (mut socket, _) = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect("the upgrade should succeed");
    let message = next_message(&mut socket).await;
    let Message::Close(Some(frame)) = message else {
        panic!("an idle connection should be closed by the gateway, got {message:?}");
    };
    assert_eq!(u16::from(frame.code), 1000);

    let closed = gateway
        .wait_for_event(audit::event::UPSTREAM_WEBSOCKET_CLOSED)
        .await;
    assert_eq!(closed.payload["outcome"], "idle_timeout");

    upstream.finish().await;
    gateway.finish().await;
}

#[tokio::test]
async fn traffic_keeps_resetting_the_idle_deadline() {
    let upstream = spawn_ws_upstream(UpstreamPlan::default(), echo_handler()).await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |websocket| {
        websocket.idle_timeout_ms = config::MIN_WEBSOCKET_IDLE_TIMEOUT_MS;
    });
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let (mut socket, _) = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect("the upgrade should succeed");
    // Three round trips, each shorter than the idle budget but together longer.
    for round in 0..3 {
        tokio::time::sleep(Duration::from_millis(400)).await;
        socket
            .send(Message::text(format!("round-{round}")))
            .await
            .expect("client should send");
        assert_eq!(
            next_message(&mut socket)
                .await
                .into_text()
                .expect("echo should be text")
                .as_str(),
            format!("round-{round}")
        );
    }
    assert!(
        gateway
            .events(audit::event::UPSTREAM_WEBSOCKET_CLOSED)
            .is_empty(),
        "a connection carrying traffic must not hit its idle deadline"
    );

    drop(socket);
    upstream.finish().await;
    gateway.finish().await;
}

#[tokio::test]
async fn the_duration_limit_closes_an_otherwise_healthy_connection() {
    let upstream = spawn_ws_upstream(UpstreamPlan::default(), silent_handler()).await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |websocket| {
        websocket.max_duration_ms = 300;
    });
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let (mut socket, _) = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect("the upgrade should succeed");
    let message = next_message(&mut socket).await;
    let Message::Close(Some(frame)) = message else {
        panic!("the duration limit should close the connection, got {message:?}");
    };
    assert_eq!(u16::from(frame.code), 1000);

    let closed = gateway
        .wait_for_event(audit::event::UPSTREAM_WEBSOCKET_CLOSED)
        .await;
    assert_eq!(closed.payload["outcome"], "duration_limit");

    upstream.finish().await;
    gateway.finish().await;
}

#[tokio::test]
async fn an_established_connection_survives_drain_and_dies_at_forced_shutdown() {
    let upstream = spawn_ws_upstream(UpstreamPlan::default(), echo_handler()).await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |_| {});
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let (mut socket, _) = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect("the upgrade should succeed");

    gateway.lifecycle.begin_draining();
    socket
        .send(Message::text("still alive"))
        .await
        .expect("a draining gateway must not sever an established connection");
    assert_eq!(
        next_message(&mut socket)
            .await
            .into_text()
            .expect("echo should be text")
            .as_str(),
        "still alive"
    );

    // Forced shutdown waits on the tracker token every upgraded connection
    // holds, so a bridge that ignored the cancellation would hang here rather
    // than fail: bound it so the guard's absence is a failure, not a stall.
    tokio::time::timeout(
        Duration::from_secs(10),
        gateway.lifecycle.force_shutdown_response_streams(),
    )
    .await
    .expect("forced shutdown must finish once every bridge has released");
    let message = next_message(&mut socket).await;
    let Message::Close(Some(frame)) = message else {
        panic!("forced shutdown should close the connection, got {message:?}");
    };
    assert_eq!(
        u16::from(frame.code),
        1001,
        "forced shutdown is a going-away, not a normal close"
    );

    let closed = gateway
        .wait_for_event(audit::event::UPSTREAM_WEBSOCKET_CLOSED)
        .await;
    assert_eq!(closed.payload["outcome"], "shutdown");

    upstream.finish().await;
    gateway.finish().await;
}

#[tokio::test]
async fn a_draining_gateway_refuses_a_new_upgrade_without_touching_the_upstream() {
    let upstream = spawn_ws_upstream(UpstreamPlan::default(), echo_handler()).await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |_| {});
    let gateway = spawn_gateway(config, upstream_dns()).await;

    gateway.lifecycle.begin_draining();
    let error = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect_err("a draining gateway must refuse a new upgrade");
    assert_eq!(refusal(error).status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(gateway.dns_calls(), 0);
    assert_eq!(
        upstream.connection_count(),
        0,
        "a refused upgrade must never open an upstream connection"
    );

    let event = gateway
        .wait_for_event(audit::event::UPSTREAM_WEBSOCKET_HANDSHAKE)
        .await;
    assert_eq!(event.payload["reason"], "shutdown");

    upstream.finish().await;
    gateway.finish().await;
}

// ---------------------------------------------------------------------------
// Capacity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn websocket_admission_saturates_without_starving_ordinary_requests() {
    let upstream = spawn_ws_upstream(UpstreamPlan::default(), silent_handler()).await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |websocket| {
        websocket.max_connections = 1;
        websocket.queue_depth = 0;
    });
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let (held, _) = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect("the first upgrade should be admitted");

    let error = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect_err("a saturated route must refuse the second upgrade");
    assert_eq!(refusal(error).status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        upstream.connection_count(),
        1,
        "the refused upgrade must not have opened a second upstream connection"
    );

    let denied = gateway.wait_for_denied_handshake().await;
    assert_eq!(denied.payload["reason"], "queue_full");

    // Releasing the socket returns the slot, which proves the permit is not
    // leaked by the bridge.
    drop(held);
    let admitted = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok((socket, _)) = connect_client(gateway.addr, "/socket/room", &[]).await {
                return socket;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("a closed connection must return its admission slot");

    drop(admitted);
    upstream.finish().await;
    gateway.finish().await;
}

#[tokio::test]
async fn a_full_endpoint_refuses_rather_than_overbooking() {
    let upstream = spawn_ws_upstream(UpstreamPlan::default(), silent_handler()).await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |websocket| {
        websocket.max_connections = 4;
        websocket.max_connections_per_endpoint = Some(1);
    });
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let (held, _) = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect("the first upgrade should be admitted");
    let error = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect_err("the only endpoint is full, so the route has no capacity");
    assert_eq!(refusal(error).status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(upstream.connection_count(), 1);

    let denied = gateway.wait_for_denied_handshake().await;
    assert_eq!(denied.payload["reason"], "endpoint_capacity");

    drop(held);
    upstream.finish().await;
    gateway.finish().await;
}

// ---------------------------------------------------------------------------
// Observability
// ---------------------------------------------------------------------------

#[tokio::test]
async fn audit_and_metrics_carry_only_bounded_categories() {
    let upstream = spawn_ws_upstream(UpstreamPlan::echoing_subprotocol(), echo_handler()).await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |websocket| {
        websocket.allowed_subprotocols = vec!["chat.v1".to_owned()];
        websocket.allowed_origins = vec!["https://app.example".to_owned()];
    });
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let (mut socket, _) = connect_client(
        gateway.addr,
        "/socket/room?token=super-secret-query-value",
        &[
            ("origin", "https://app.example"),
            ("sec-websocket-protocol", "chat.v1"),
        ],
    )
    .await
    .expect("the upgrade should succeed");
    socket
        .send(Message::text("payload-that-must-never-be-recorded"))
        .await
        .expect("client should send");
    assert_eq!(
        next_message(&mut socket)
            .await
            .into_text()
            .expect("echo should be text")
            .as_str(),
        "payload-that-must-never-be-recorded"
    );
    socket
        .send(Message::Close(None))
        .await
        .expect("client should close");

    let handshake = gateway
        .wait_for_event(audit::event::UPSTREAM_WEBSOCKET_HANDSHAKE)
        .await;
    let handshake_keys = payload_keys(&handshake.payload);
    assert_eq!(
        handshake_keys,
        vec![
            "duration_ms",
            "endpoint_id",
            "origin_allowed",
            "origin_present",
            "pool_id",
            "reason",
            "result",
            "subprotocol",
        ],
        "the handshake audit payload is a closed set of bounded fields"
    );
    assert_eq!(handshake.payload["result"], "allowed");
    assert_eq!(handshake.payload["subprotocol"], "chat.v1");
    assert_eq!(handshake.payload["origin_allowed"], true);

    let closed = gateway
        .wait_for_event(audit::event::UPSTREAM_WEBSOCKET_CLOSED)
        .await;
    let closed_keys = payload_keys(&closed.payload);
    assert_eq!(
        closed_keys,
        vec![
            "bytes_client_to_upstream",
            "bytes_upstream_to_client",
            "close_code",
            "duration_ms",
            "endpoint_id",
            "frames_client_to_upstream",
            "frames_upstream_to_client",
            "outcome",
            "pool_id",
            "subprotocol",
        ],
        "the close audit payload is a closed set of bounded fields"
    );
    assert_eq!(closed.payload["outcome"], "client_close");
    assert_eq!(closed.payload["bytes_client_to_upstream"], 35);
    assert_eq!(closed.payload["bytes_upstream_to_client"], 35);

    for event in gateway.audit.events() {
        let rendered = event.payload.to_string();
        assert!(
            !rendered.contains("payload-that-must-never-be-recorded"),
            "no websocket payload may appear in audit: {rendered}"
        );
        assert!(
            !rendered.contains("super-secret-query-value"),
            "no raw URL may appear in audit: {rendered}"
        );
        assert!(
            !rendered.contains("app.example"),
            "the presented origin is attacker-controlled and is never recorded: {rendered}"
        );
    }

    let rendered = gateway.metrics.render();
    let websocket_lines = rendered
        .lines()
        .filter(|line| line.starts_with("proxy_websocket_"))
        .collect::<Vec<_>>();
    assert!(
        !websocket_lines.is_empty(),
        "websocket metrics should be recorded:\n{rendered}"
    );
    for line in &websocket_lines {
        let labels = metric_label_names(line);
        assert!(
            labels.iter().all(|label| matches!(
                label.as_str(),
                "pool_id"
                        | "endpoint_id"
                        | "result"
                        | "reason"
                        | "direction"
                        | "outcome"
                        // Added by the Prometheus exporter itself, not by the
                        // gateway.
                        | "quantile"
                        | "le"
            )),
            "websocket metric labels must stay low cardinality: {line}"
        );
        assert!(
            !line.contains("request_id"),
            "a request ID must never be a metric label: {line}"
        );
        assert!(
            !line.contains("app.example") && !line.contains("super-secret-query-value"),
            "no caller-controlled value may become a metric label: {line}"
        );
    }
    assert!(
        websocket_lines
            .iter()
            .any(|line| line.contains("proxy_websocket_handshakes_total")
                && line.contains("result=\"allowed\"")),
        "an allowed handshake should be counted:\n{rendered}"
    );

    upstream.finish().await;
    gateway.finish().await;
}

fn payload_keys(payload: &Value) -> Vec<String> {
    let mut keys = payload
        .as_object()
        .expect("an audit payload should be an object")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    keys.sort();
    keys
}

fn metric_label_names(line: &str) -> HashSet<String> {
    let Some(start) = line.find('{') else {
        return HashSet::new();
    };
    let Some(end) = line.find('}') else {
        return HashSet::new();
    };
    line[start + 1..end]
        .split(',')
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, _)| name.trim().to_owned())
        .collect()
}

// ---------------------------------------------------------------------------
// Transport security
// ---------------------------------------------------------------------------

const TLS_UPSTREAM_HOST: &str = "tls-ws-upstream.example.test";

struct TlsWsUpstream {
    addr: SocketAddr,
    ca_pem: String,
    connections: Arc<AtomicUsize>,
    shutdown: tokio_util::sync::CancellationToken,
    handle: JoinHandle<()>,
}

impl TlsWsUpstream {
    async fn finish(self) {
        self.shutdown.cancel();
        let _ = self.handle.await;
    }
}

/// A TLS WebSocket upstream whose certificate is issued by a throwaway CA.
///
/// `certificate_name` is what the certificate is issued *for*, which is what
/// makes the wrong-hostname case reachable: the gateway still connects to
/// 127.0.0.1, but SNI and verification use the configured authority.
async fn spawn_tls_ws_upstream(certificate_name: &str) -> TlsWsUpstream {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params.distinguished_name = rcgen::DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "GreenGateway WebSocket Test CA");
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

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(server.der().as_ref().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        )
        .expect("test TLS server config should build");
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("tls websocket upstream should bind");
    let addr = listener
        .local_addr()
        .expect("tls websocket upstream address should be available");
    let connections = Arc::new(AtomicUsize::new(0));
    let shutdown = tokio_util::sync::CancellationToken::new();
    let task_connections = Arc::clone(&connections);
    let task_shutdown = shutdown.clone();
    let handle = tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                () = task_shutdown.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            let Ok((stream, _)) = accepted else { break };
            let Ok(mut stream) = acceptor.accept(stream).await else {
                continue;
            };
            task_connections.fetch_add(1, Ordering::SeqCst);

            let mut buffer = Vec::new();
            let mut chunk = [0_u8; 1024];
            let key = loop {
                let Ok(read) = stream.read(&mut chunk).await else {
                    break None;
                };
                if read == 0 {
                    break None;
                }
                buffer.extend_from_slice(&chunk[..read]);
                if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buffer).into_owned();
                    break head
                        .split("\r\n")
                        .find_map(|line| {
                            line.split_once(':').filter(|(name, _)| {
                                name.trim().eq_ignore_ascii_case("sec-websocket-key")
                            })
                        })
                        .map(|(_, value)| value.trim().to_owned());
                }
            };
            let Some(key) = key else { continue };
            let response = render_handshake_response(&UpstreamPlan::default(), key.as_bytes());
            if stream.write_all(&response).await.is_err() {
                continue;
            }
            let mut socket = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
            while let Some(Ok(message)) = socket.next().await {
                match message {
                    Message::Ping(_) | Message::Pong(_) => {}
                    Message::Close(frame) => {
                        let _ = socket.send(Message::Close(frame)).await;
                        break;
                    }
                    other => {
                        if socket.send(other).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });

    TlsWsUpstream {
        addr,
        ca_pem: ca.pem(),
        connections,
        shutdown,
        handle,
    }
}

struct TempCaBundle {
    path: PathBuf,
}

impl TempCaBundle {
    fn new(pem: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "greengateway-websocket-ca-{}.pem",
            uuid::Uuid::new_v4()
        ));
        fs::write(&path, pem).expect("test CA bundle should be written");
        Self { path }
    }
}

impl Drop for TempCaBundle {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn tls_websocket_config(
    upstream: &TlsWsUpstream,
    certificate_name: &str,
    ca_bundle: Option<&TempCaBundle>,
) -> config::Config {
    let mut config = websocket_config(certificate_name, upstream.addr, |_| {});
    let route = &mut config.upstream_routes[0];
    route.upstreams[0].url = format!("https://{certificate_name}:{}", upstream.addr.port());
    route.upstreams[0].tls_ca_bundle_path = ca_bundle.map(|bundle| bundle.path.clone());
    config.egress_allowed_hosts = vec![certificate_name.to_owned()];

    config
}

fn tls_dns(certificate_name: &str) -> HashMap<String, Vec<IpAddr>> {
    HashMap::from([(
        certificate_name.to_owned(),
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    )])
}

#[tokio::test]
async fn a_tls_upgrade_verifies_the_certificate_against_a_route_local_ca() {
    let upstream = spawn_tls_ws_upstream(TLS_UPSTREAM_HOST).await;
    let bundle = TempCaBundle::new(&upstream.ca_pem);
    let config = tls_websocket_config(&upstream, TLS_UPSTREAM_HOST, Some(&bundle));
    let gateway = spawn_gateway(config, tls_dns(TLS_UPSTREAM_HOST)).await;

    let (mut socket, response) = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect("a certificate signed by the route's own CA should be trusted");
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);

    socket
        .send(Message::text("over tls"))
        .await
        .expect("client should send");
    assert_eq!(
        next_message(&mut socket)
            .await
            .into_text()
            .expect("echo should be text")
            .as_str(),
        "over tls"
    );
    assert_eq!(
        gateway.dns_calls(),
        1,
        "the upgrade resolves the destination exactly once and then pins it"
    );
    assert_eq!(
        upstream.connections.load(Ordering::SeqCst),
        1,
        "exactly one verified TLS connection carries the upgrade"
    );

    drop(socket);
    upstream.finish().await;
    gateway.finish().await;
}

#[tokio::test]
async fn an_untrusted_certificate_authority_refuses_the_upgrade() {
    let upstream = spawn_tls_ws_upstream(TLS_UPSTREAM_HOST).await;
    // No route-local CA: the certificate chains to a CA nothing trusts.
    let config = tls_websocket_config(&upstream, TLS_UPSTREAM_HOST, None);
    let gateway = spawn_gateway(config, tls_dns(TLS_UPSTREAM_HOST)).await;

    let error = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect_err("an untrusted CA must refuse the upgrade");
    assert_eq!(refusal(error).status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        upstream.connections.load(Ordering::SeqCst),
        0,
        "the TLS handshake must fail before the upstream sees a session"
    );

    let event = gateway
        .wait_for_event(audit::event::UPSTREAM_WEBSOCKET_HANDSHAKE)
        .await;
    assert_eq!(event.payload["result"], "failed");

    upstream.finish().await;
    gateway.finish().await;
}

#[tokio::test]
async fn a_certificate_issued_for_another_hostname_refuses_the_upgrade() {
    let upstream = spawn_tls_ws_upstream("other-host.example.test").await;
    let bundle = TempCaBundle::new(&upstream.ca_pem);
    // The CA is trusted, but the certificate does not name the authority the
    // gateway asked for, so verification must still fail.
    let config = tls_websocket_config(&upstream, TLS_UPSTREAM_HOST, Some(&bundle));
    let gateway = spawn_gateway(config, tls_dns(TLS_UPSTREAM_HOST)).await;

    let error = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect_err("a certificate for a different hostname must refuse the upgrade");
    assert_eq!(refusal(error).status(), StatusCode::BAD_GATEWAY);

    upstream.finish().await;
    gateway.finish().await;
}

#[tokio::test]
async fn an_upgrade_to_a_blocked_egress_destination_never_connects() {
    let upstream = spawn_ws_upstream(UpstreamPlan::default(), echo_handler()).await;
    let mut config = websocket_config(UPSTREAM_HOST, upstream.addr, |_| {});
    // The route still names the upstream, but the address it resolves to is one
    // egress policy refuses to reach.
    config.egress_deny_private_ips = true;
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let error = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect_err("a blocked egress destination must refuse the upgrade");
    assert_eq!(refusal(error).status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        upstream.connection_count(),
        0,
        "a blocked egress destination must never be connected to"
    );

    let event = gateway
        .wait_for_event(audit::event::UPSTREAM_WEBSOCKET_HANDSHAKE)
        .await;
    assert_eq!(event.payload["result"], "failed");
    assert_eq!(event.payload["reason"], "non_global_ip_blocked");

    upstream.finish().await;
    gateway.finish().await;
}

// ---------------------------------------------------------------------------
// Cancellation and backpressure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_abrupt_client_disconnect_ends_the_bridge_and_releases_capacity() {
    let upstream = spawn_ws_upstream(UpstreamPlan::default(), silent_handler()).await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |websocket| {
        websocket.max_connections = 1;
        websocket.queue_depth = 0;
    });
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let (socket, _) = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect("the upgrade should succeed");
    // No closing handshake: the transport simply disappears, which is what a
    // browser tab closing looks like.
    drop(socket);

    let closed = gateway
        .wait_for_event(audit::event::UPSTREAM_WEBSOCKET_CLOSED)
        .await;
    let outcome = closed.payload["outcome"]
        .as_str()
        .expect("the outcome should be a bounded string")
        .to_owned();
    assert!(
        outcome.starts_with("client_"),
        "an abrupt client disconnect is attributed to the client, got {outcome}"
    );

    let readmitted = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok((socket, _)) = connect_client(gateway.addr, "/socket/room", &[]).await {
                return socket;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("an abandoned connection must release its admission slot");

    drop(readmitted);
    upstream.finish().await;
    gateway.finish().await;
}

#[tokio::test]
async fn an_abrupt_upstream_disconnect_closes_the_client() {
    // The handler returns immediately, dropping the upstream socket without a
    // closing handshake.
    let upstream = spawn_ws_upstream(
        UpstreamPlan::default(),
        Arc::new(|_socket: WebSocketStream<TcpStream>| {
            Box::pin(async move {}) as BoxFuture<'static, ()>
        }),
    )
    .await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |_| {});
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let (mut socket, _) = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect("the upgrade should succeed");

    let ended = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(message) = socket.next().await {
            match message {
                Ok(Message::Close(_)) | Err(_) => return true,
                Ok(_) => {}
            }
        }
        true
    })
    .await
    .expect("the client must not be left hanging on a dead upstream");
    assert!(ended);

    let closed = gateway
        .wait_for_event(audit::event::UPSTREAM_WEBSOCKET_CLOSED)
        .await;
    let outcome = closed.payload["outcome"]
        .as_str()
        .expect("the outcome should be a bounded string")
        .to_owned();
    assert!(
        outcome.starts_with("upstream_"),
        "an abrupt upstream disconnect is attributed to the upstream, got {outcome}"
    );

    upstream.finish().await;
    gateway.finish().await;
}

#[tokio::test]
async fn a_slow_consumer_gets_backpressure_rather_than_dropped_or_buffered_messages() {
    const MESSAGES: usize = 24;
    const PAYLOAD: usize = 900;

    let upstream = spawn_ws_upstream(
        UpstreamPlan::default(),
        sending_handler(
            (0..MESSAGES)
                .map(|index| {
                    let mut payload = vec![b'a' + u8::try_from(index % 26).unwrap_or(0); PAYLOAD];
                    payload[0] = b'0' + u8::try_from(index % 10).unwrap_or(0);
                    Message::binary(payload)
                })
                .collect(),
        ),
    )
    .await;
    let config = websocket_config(UPSTREAM_HOST, upstream.addr, |websocket| {
        // A write budget far smaller than the traffic, so anything that
        // buffered instead of pushing back would overflow it.
        websocket.max_write_buffer_bytes = 1;
        websocket.max_frame_bytes = config::MIN_WEBSOCKET_MAX_FRAME_BYTES;
        websocket.max_message_bytes = config::MIN_WEBSOCKET_MAX_FRAME_BYTES;
    });
    let gateway = spawn_gateway(config, upstream_dns()).await;

    let (mut socket, _) = connect_client(gateway.addr, "/socket/room", &[])
        .await
        .expect("the upgrade should succeed");

    for index in 0..MESSAGES {
        // Read deliberately slowly. The gateway awaits each send before it
        // reads again, so the delay propagates to the upstream rather than
        // accumulating in the gateway.
        tokio::time::sleep(Duration::from_millis(5)).await;
        let payload = next_message(&mut socket).await.into_data();
        assert_eq!(
            payload.len(),
            PAYLOAD,
            "message {index} should arrive whole"
        );
        assert_eq!(
            payload[0],
            b'0' + u8::try_from(index % 10).unwrap_or(0),
            "messages must arrive in order without loss"
        );
    }

    assert!(
        gateway
            .events(audit::event::UPSTREAM_WEBSOCKET_CLOSED)
            .is_empty(),
        "a slow consumer is backpressure, not a capacity failure"
    );

    drop(socket);
    upstream.finish().await;
    gateway.finish().await;
}
