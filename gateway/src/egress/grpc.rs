//! The HTTP/2 client half of the gRPC transport.
//!
//! This lives inside the egress boundary for the same reason every other
//! outbound transport does: it is the only place a destination is turned into a
//! socket, and `scripts/check-egress-only.sh` binds the boundary by file path.
//! It is also the only file in the tree permitted to name
//! `hyper::client::conn::http2`, which the same script enforces.
//!
//! # Why this is not reqwest
//!
//! `reqwest/http2` would enable `hyper-util/http2`, and `axum::serve` builds on
//! that same `hyper-util`, so turning it on would make every listener -- the
//! admin listener included -- start accepting h2c prior-knowledge connections
//! with nothing in the diff to notice. Depending on `hyper` directly with
//! `http2` does not: feature edges are one-way. The guard script asserts both
//! halves by feature name.
//!
//! # What this transport inherits, and what it does not
//!
//! It inherits every egress control, because it reaches the network only
//! through [`EgressClient::revalidated_destination`] -- the same authority,
//! policy-port, private-IP and configuration-generation revalidation the pinned
//! reqwest clients go through, factored out so the two paths cannot drift.
//! Address pinning is not a `.resolve()` hint here but the literal thing that
//! happens: the TCP connect target is `CheckedEgressDestination::pinned_addr`,
//! and no name is resolved at connect time at all.
//!
//! What it does not inherit is reqwest's total-request timeout, because a
//! bidirectional stream has no such thing. The caller bounds the call instead.

use std::{
    collections::HashMap,
    fmt,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, LazyLock, Mutex, MutexGuard},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::Bytes;
use hyper::body::Body;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use reqwest::{header::HeaderMap, StatusCode, Url};
use tokio::net::TcpStream;
use tokio_rustls::{rustls::pki_types::ServerName, TlsConnector};

use super::{
    client_cache::ProtocolProfile, tls, CheckedEgressDestination, EgressClient, EgressError,
    TransportPartition,
};
use crate::metrics::{
    GRPC_UPSTREAM_CONNECTIONS_TOTAL, GRPC_UPSTREAM_CONNECTION_SLOTS, LOCK_POISON_RECOVERIES_TOTAL,
};

/// How long an unused upstream connection slot is kept before it is dropped.
///
/// Matches the pinned reqwest client cache's idle lifetime: an h2 connection is
/// a pooled transport like any other, and having the two expire on different
/// schedules would only make a deployment harder to reason about.
const CONNECTION_IDLE_TTL: Duration = Duration::from_secs(5 * 60);
/// Hard ceiling on distinct pooled upstream connections.
///
/// One slot per (destination, TLS material, transport partition). A gateway
/// with more live gRPC destinations than this evicts the least recently used
/// slot rather than growing without bound; the evicted connection closes once
/// its in-flight streams finish.
const MAX_CONNECTION_SLOTS: usize = 128;
/// Client-side h2 frame ceiling.
///
/// Deliberately the RFC 9113 minimum. A proxy gains nothing from larger frames
/// -- it forwards whatever the peer sends -- and a small frame size keeps the
/// per-connection read buffer small when many streams are multiplexed.
const CLIENT_MAX_FRAME_BYTES: u32 = 16_384;
/// Per-stream flow-control window offered to the upstream.
const CLIENT_STREAM_WINDOW_BYTES: u32 = 1024 * 1024;
/// Connection-level flow-control window offered to the upstream.
///
/// Larger than the stream window so several concurrently draining streams do
/// not contend for one connection's credit.
const CLIENT_CONNECTION_WINDOW_BYTES: u32 = 4 * 1024 * 1024;
/// Bound on resets the client will track for streams it cancelled.
const CLIENT_MAX_CONCURRENT_RESET_STREAMS: usize = 64;
/// Ceiling on the decoded size of one upstream response's metadata.
///
/// hyper's own client default is the same 16 KiB, so this changes nothing
/// today. It is stated anyway for the reason the inbound listener states its
/// bounds: a limit the gateway inherited is a limit that can move under it on a
/// dependency bump, and the response direction has to be bounded in bytes
/// somewhere -- the per-route `max_metadata_entries` bounds the COUNT, and a
/// count does not constrain a size.
///
/// Not operator-configurable, unlike the inbound `GRPC_MAX_METADATA_BYTES`,
/// because one pooled connection is shared by every route that reaches this
/// endpoint and a per-route value could not be applied to it.
const CLIENT_MAX_METADATA_BYTES: u32 = 16 * 1024;
const CONNECTION_LOCK_COMPONENT: &str = "egress_grpc_connection_pool";

/// The one shared upstream connection pool.
///
/// Process-global for the same reason the pinned reqwest client cache is: an
/// `EgressClient` is cloned and re-derived per route and per endpoint, so a
/// per-client pool would open a connection per clone. Isolation is preserved by
/// the key rather than by the container -- a different CA bundle, a different
/// client identity, or a different opaque transport partition is a different
/// key and therefore a different connection.
static PROCESS_CONNECTION_POOL: LazyLock<Arc<GrpcConnectionPool>> =
    LazyLock::new(|| Arc::new(GrpcConnectionPool::new()));

/// A bounded gRPC transport failure category.
///
/// Every failure this module reports is one of these. That is the point:
/// hyper's own error text can name the destination, the negotiated protocol, or
/// bytes the upstream sent, and none of that may reach a log line, a metric
/// label, an audit field, or a client. Mapping at the boundary makes leaking it
/// impossible rather than merely discouraged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GrpcFailure {
    /// The TCP connection to the pinned address could not be established.
    Connect,
    /// The TLS handshake failed.
    Tls,
    /// TLS completed but the peer did not select `h2`.
    AlpnNotH2,
    /// The HTTP/2 connection preface or settings exchange failed.
    Handshake,
    /// The connection went away before or during the call.
    ConnectionClosed,
    /// The upstream reset the stream.
    StreamReset,
    /// The upstream sent something this transport refuses to interpret.
    Protocol,
    /// The connect-and-acquire-capacity budget elapsed.
    ///
    /// Deliberately NOT the same thing as the caller's deadline: this is the
    /// gateway's own bound on establishing a usable connection, and a call with
    /// a generous deadline can still trip it. The proxy maps it to
    /// `UNAVAILABLE` rather than `DEADLINE_EXCEEDED` for exactly that reason.
    ConnectTimeout,
}

impl GrpcFailure {
    pub(crate) fn category(self) -> &'static str {
        match self {
            Self::Connect => "grpc_connect",
            Self::Tls => "grpc_tls",
            Self::AlpnNotH2 => "grpc_alpn_not_h2",
            Self::Handshake => "grpc_handshake",
            Self::ConnectionClosed => "grpc_connection_closed",
            Self::StreamReset => "grpc_stream_reset",
            Self::Protocol => "grpc_protocol",
            Self::ConnectTimeout => "grpc_connect_timeout",
        }
    }
}

impl fmt::Display for GrpcFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.category())
    }
}

/// Classifies a hyper error without reading its text.
///
/// Every arm is a predicate hyper exposes, so this cannot accidentally start
/// forwarding a message. An unclassified error becomes [`GrpcFailure::Protocol`]
/// rather than anything more specific.
fn classify(error: &hyper::Error) -> GrpcFailure {
    // hyper reports a keep-alive timeout as `is_timeout`, which means the
    // connection is gone rather than that a deadline the caller set has passed.
    // It is folded into `ConnectionClosed` so no transport failure can be
    // mistaken for the caller's own deadline.
    if error.is_timeout() || error.is_closed() || error.is_incomplete_message() {
        GrpcFailure::ConnectionClosed
    } else if error.is_canceled() || error.is_body_write_aborted() {
        GrpcFailure::StreamReset
    } else {
        GrpcFailure::Protocol
    }
}

fn transport_error(failure: GrpcFailure) -> EgressError {
    EgressError::Grpc(failure)
}

/// The request body handed to the upstream.
///
/// Boxed so the caller can supply any bounded body without this module
/// depending on the proxy's types, and so the error type is pinned to
/// [`EgressError`] at the boundary rather than being generic.
pub(crate) struct GrpcRequestBody {
    inner: Pin<Box<dyn Body<Data = Bytes, Error = EgressError> + Send>>,
}

impl GrpcRequestBody {
    pub(crate) fn new<B>(body: B) -> Self
    where
        B: Body<Data = Bytes, Error = EgressError> + Send + 'static,
    {
        Self {
            inner: Box::pin(body),
        }
    }
}

impl Body for GrpcRequestBody {
    type Data = Bytes;
    type Error = EgressError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, EgressError>>> {
        self.inner.as_mut().poll_frame(context)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// The upstream response body, with hyper's error type mapped away at the
/// boundary.
pub(crate) struct GrpcResponseBody {
    inner: hyper::body::Incoming,
}

impl Body for GrpcResponseBody {
    type Data = Bytes;
    type Error = EgressError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, EgressError>>> {
        match Pin::new(&mut self.inner).poll_frame(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(error))) => {
                Poll::Ready(Some(Err(transport_error(classify(&error)))))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

/// The upstream's answer to one call.
pub(crate) struct GrpcResponse {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) body: GrpcResponseBody,
}

impl fmt::Debug for GrpcResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GrpcResponse")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

/// Everything that must match for two calls to share one upstream connection.
///
/// Every field is a thing that changes who the peer is or what credentials are
/// presented to it. Two calls whose keys differ get different connections, so
/// custom-CA isolation and per-endpoint mTLS isolation are properties of the
/// key rather than of a check somewhere.
#[derive(Clone, Eq, Hash, PartialEq)]
struct ConnectionKey {
    scheme: String,
    host: String,
    port: u16,
    pinned_addr: SocketAddr,
    egress_generation: [u8; 32],
    tls_root_set_fingerprint: [u8; 32],
    client_identity_fingerprint: Option<[u8; 32]>,
    transport_partition: Option<TransportPartition>,
}

impl fmt::Debug for ConnectionKey {
    /// Renders the shape and never the fingerprints, on the same rule
    /// `PinnedClientCacheKey` follows.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionKey")
            .field("scheme", &self.scheme)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("pinned_addr", &self.pinned_addr)
            .field(
                "client_identity_configured",
                &self.client_identity_fingerprint.is_some(),
            )
            .field("transport_partitioned", &self.transport_partition.is_some())
            .finish()
    }
}

type SharedSlot = Arc<tokio::sync::Mutex<ConnectionSlot>>;

#[derive(Default)]
struct ConnectionSlot {
    sender: Option<hyper::client::conn::http2::SendRequest<GrpcRequestBody>>,
}

struct PoolEntry {
    slot: SharedSlot,
    last_used: Duration,
}

/// The pool itself.
///
/// The outer map is behind a `std::sync::Mutex` held only long enough to look
/// up or insert a slot handle; the connect itself happens under the slot's own
/// async mutex. That way concurrent calls to the SAME endpoint coalesce onto
/// one handshake while calls to DIFFERENT endpoints never wait on each other --
/// which is the whole reason a multiplexed transport is worth pooling.
struct GrpcConnectionPool {
    entries: Mutex<HashMap<ConnectionKey, PoolEntry>>,
    started_at: Instant,
}

impl GrpcConnectionPool {
    fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            started_at: Instant::now(),
        }
    }

    fn slot(&self, key: ConnectionKey) -> SharedSlot {
        let now = self.started_at.elapsed();
        let mut entries = self.lock();
        entries.retain(|_, entry| now.saturating_sub(entry.last_used) < CONNECTION_IDLE_TTL);

        if let Some(entry) = entries.get_mut(&key) {
            entry.last_used = now;
            return Arc::clone(&entry.slot);
        }

        if entries.len() >= MAX_CONNECTION_SLOTS {
            if let Some(eviction_key) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
            {
                entries.remove(&eviction_key);
            }
        }

        let slot: SharedSlot = Arc::new(tokio::sync::Mutex::new(ConnectionSlot::default()));
        entries.insert(
            key,
            PoolEntry {
                slot: Arc::clone(&slot),
                last_used: now,
            },
        );
        ::metrics::gauge!(GRPC_UPSTREAM_CONNECTION_SLOTS).set(entries.len() as f64);

        slot
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<ConnectionKey, PoolEntry>> {
        match self.entries.lock() {
            Ok(entries) => entries,
            Err(poisoned) => {
                ::metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => CONNECTION_LOCK_COMPONENT,
                    "lock" => "pool"
                )
                .increment(1);
                tracing::error!("gRPC upstream connection pool lock poisoned; recovering");
                poisoned.into_inner()
            }
        }
    }
}

impl EgressClient {
    /// Sends one gRPC call to an already validated destination.
    ///
    /// The destination is revalidated here through exactly the helper the
    /// pinned reqwest clients use, so this transport cannot be handed a
    /// destination the ordinary path would reject.
    ///
    /// `connect_timeout` is ONE budget covering establishing a usable HTTP/2
    /// connection -- TCP, TLS, and the peer's own connection preface -- rather
    /// than one budget per step. It does NOT bound the call: a bidirectional
    /// stream has no total duration the transport could know, and
    /// `send_request` below resolves only when the upstream sends response
    /// HEADERS. Nothing in this file bounds that wait, so the caller must arm
    /// its deadline before calling here.
    pub(crate) async fn grpc_call_at_checked_destination(
        &self,
        destination: &CheckedEgressDestination,
        url: &str,
        headers: HeaderMap,
        body: GrpcRequestBody,
        connect_timeout: Duration,
    ) -> Result<GrpcResponse, EgressError> {
        // One deadline, computed once, shared by connecting and by acquiring
        // stream capacity. Two separate `timeout(connect_timeout, ..)` calls
        // would let a single call spend the operator's budget twice, which is
        // not what "budget for establishing a connection and acquiring stream
        // capacity" says.
        let connect_deadline = tokio::time::Instant::now() + connect_timeout;
        let (parsed, host, port) = self.revalidated_destination(destination, url)?;

        let key = ConnectionKey {
            scheme: parsed.scheme().to_owned(),
            host: host.clone(),
            port,
            pinned_addr: destination.pinned_addr,
            egress_generation: self.config_generation,
            tls_root_set_fingerprint: self.config.tls_root_set_fingerprint,
            client_identity_fingerprint: self.config.client_identity_fingerprint,
            transport_partition: self.config.transport_partition,
        };
        let slot = PROCESS_CONNECTION_POOL.slot(key);

        // A pooled sender is reused only while it reports itself open;
        // otherwise a connection is established. That is not a request retry --
        // no bytes of this call have reached the upstream either way, and a
        // pooled h2 connection the peer closed while it sat idle is the
        // ordinary case a proxy must survive.
        //
        // What is deliberately NOT done: reconnecting when a sender that passed
        // the liveness check then fails `ready()`. That would also be safe, for
        // the same reason, but #257 disables retry and the honest cost of not
        // doing it is one bounded `UNAVAILABLE` in a narrow race, not a
        // correctness problem. The dead sender is replaced on the next call,
        // because `is_closed()` will report it by then.
        let mut reused_connection = false;
        let sender = {
            let mut slot = slot.lock().await;
            match slot.sender.as_ref() {
                Some(sender) if !sender.is_closed() => {
                    reused_connection = true;
                    sender.clone()
                }
                _ => {
                    let sender = tokio::time::timeout_at(
                        connect_deadline,
                        self.connect_grpc(&parsed, &host, destination.pinned_addr),
                    )
                    .await
                    .map_err(|_| transport_error(GrpcFailure::ConnectTimeout))??;
                    slot.sender = Some(sender.clone());
                    sender
                }
            }
        };

        ::metrics::counter!(
            GRPC_UPSTREAM_CONNECTIONS_TOTAL,
            "result" => if reused_connection { "reused" } else { "established" }
        )
        .increment(1);

        let mut sender = sender;
        // What `ready()` actually does here, stated plainly because it is less
        // than its name suggests: `SendRequest::poll_ready` (hyper 1.10.1,
        // `src/client/conn/http2.rs:96-103`) discards its `Context` and returns
        // `Ready(Ok(()))` unless the connection is closed. It does NOT consult
        // the upstream's `SETTINGS_MAX_CONCURRENT_STREAMS`, so this is a
        // liveness check on a pooled connection and nothing else.
        //
        // The consequence is worth naming: a saturated upstream is NOT bounded
        // by the connect budget. hyper accepts the request, h2 queues it, and
        // the response future stays pending -- the same shape as any other
        // upstream that has not sent HEADERS, and bounded by the same thing,
        // the caller's deadline in `proxy::grpc`.
        //
        // The timeout stays because it costs nothing and a future hyper that
        // makes `poll_ready` genuinely pend must not reintroduce an unbounded
        // wait here. It has no test, for the honest reason that hyper cannot
        // currently trip it.
        tokio::time::timeout_at(connect_deadline, sender.ready())
            .await
            .map_err(|_| transport_error(GrpcFailure::ConnectTimeout))?
            .map_err(|error| transport_error(classify(&error)))?;

        // The gateway owns `:authority` and `:path`. Both come from the
        // validated destination and the validated URL, never from a header the
        // client sent -- `Host` was stripped before this point and hyper
        // derives `:authority` from this URI alone.
        let mut request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(parsed.as_str())
            .body(body)
            .map_err(|_| transport_error(GrpcFailure::Protocol))?;
        *request.headers_mut() = headers;

        let response = sender
            .send_request(request)
            .await
            .map_err(|error| transport_error(classify(&error)))?;
        let (parts, body) = response.into_parts();

        Ok(GrpcResponse {
            status: parts.status,
            headers: parts.headers,
            body: GrpcResponseBody { inner: body },
        })
    }

    /// Opens one HTTP/2 connection to the pinned address.
    ///
    /// Note what is absent: any name resolution. The connect target is the
    /// socket address the egress check already validated, so DNS rebinding has
    /// no window here at all -- there is no second lookup to rebind.
    async fn connect_grpc(
        &self,
        url: &Url,
        host: &str,
        pinned_addr: SocketAddr,
    ) -> Result<hyper::client::conn::http2::SendRequest<GrpcRequestBody>, EgressError> {
        let tcp = TcpStream::connect(pinned_addr)
            .await
            .map_err(|_| transport_error(GrpcFailure::Connect))?;
        // Nagle batching and gRPC's small-frame streaming are a bad pairing: a
        // half-full frame would wait for an ack that the next message is waiting
        // to trigger.
        let _ = tcp.set_nodelay(true);

        match url.scheme() {
            "https" => {
                let tls_config = tls::client_config(
                    &self.config.tls_root_certificates,
                    self.config.client_identity.as_ref(),
                    ProtocolProfile::Grpc,
                )?;
                let server_name = ServerName::try_from(host.to_owned())
                    .map_err(|_| transport_error(GrpcFailure::Tls))?;
                let stream = TlsConnector::from(Arc::new(tls_config))
                    .connect(server_name, tcp)
                    .await
                    .map_err(|_| transport_error(GrpcFailure::Tls))?;
                // Fail closed on ALPN. A server that completed the handshake
                // without selecting h2 is about to be spoken HTTP/2 at, and
                // whatever it does with those bytes is not something this
                // gateway should discover in production.
                if stream.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
                    return Err(transport_error(GrpcFailure::AlpnNotH2));
                }
                self.handshake_grpc(stream).await
            }
            // h2c prior knowledge. The deployment contract for plaintext gRPC
            // is a terminator in front of the gateway, documented in
            // docs/deployment/grpc.md.
            _ => self.handshake_grpc(tcp).await,
        }
    }

    /// Completes the HTTP/2 handshake in both directions.
    ///
    /// `hyper`'s `handshake()` resolves once the GATEWAY's connection preface
    /// and SETTINGS have been written. It does not wait for the peer's, and
    /// neither does `SendRequest::ready()` -- a peer that has stated no
    /// SETTINGS_MAX_CONCURRENT_STREAMS has not constrained anything, so
    /// `ready()` has nothing to wait for. A peer that accepts TCP and then says
    /// nothing therefore passes both, and `connect_timeout_ms` is spent before
    /// the peer has proved it speaks HTTP/2 at all; the call then hangs on
    /// response HEADERS until some unrelated timer -- the 30s keep-alive plus
    /// its 10s grace -- notices.
    ///
    /// So the peer's own connection preface is waited for here, inside the
    /// caller's connect budget. RFC 9113 section 3.4 requires the server's
    /// first frame to be a SETTINGS frame, which makes "the peer sent a
    /// complete SETTINGS frame" the earliest checkable proof that there is an
    /// HTTP/2 implementation on the other end.
    async fn handshake_grpc<T>(
        &self,
        io: T,
    ) -> Result<hyper::client::conn::http2::SendRequest<GrpcRequestBody>, EgressError>
    where
        T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (io, peer_preface) = PrefaceObserver::wrap(io);
        let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
        let (sender, connection) = builder
            .timer(TokioTimer::new())
            .initial_stream_window_size(CLIENT_STREAM_WINDOW_BYTES)
            .initial_connection_window_size(CLIENT_CONNECTION_WINDOW_BYTES)
            .max_frame_size(CLIENT_MAX_FRAME_BYTES)
            .max_header_list_size(CLIENT_MAX_METADATA_BYTES)
            .max_concurrent_reset_streams(CLIENT_MAX_CONCURRENT_RESET_STREAMS)
            .keep_alive_interval(Some(Duration::from_secs(30)))
            .keep_alive_timeout(Duration::from_secs(10))
            .handshake(TokioIo::new(io))
            .await
            .map_err(|_| transport_error(GrpcFailure::Handshake))?;

        // The connection driver is deliberately untracked by the shutdown task
        // tracker. It outlives every individual call by design, and a drain
        // that waited for an idle pooled connection would never finish. It ends
        // when the last sender is dropped and the last stream completes, which
        // forced shutdown produces by cancelling the call tasks.
        //
        // It is also what reads, so it has to be running before the peer's
        // preface can arrive.
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(
                    error_category = classify(&error).category(),
                    "gRPC upstream connection ended"
                );
            }
        });

        // A closed channel means the observer was dropped without seeing a
        // SETTINGS frame -- the connection ended, or the peer's first frame was
        // something else. Either way there is no usable HTTP/2 connection here.
        // A caller whose budget elapses first drops this future instead, and
        // `sender` goes with it, so a connection that never proved itself is
        // never pooled.
        peer_preface
            .await
            .map_err(|_| transport_error(GrpcFailure::Handshake))?;

        Ok(sender)
    }
}

/// Watches a connection's inbound bytes for the peer's HTTP/2 connection
/// preface, and reports when a complete SETTINGS frame has been read.
///
/// It sits under `TokioIo` rather than over it so it can work in terms of
/// `tokio::io::ReadBuf`, whose `filled()` makes the bytes just read readable
/// without a copy and without `unsafe`. Once the frame is complete the wrapper
/// stops inspecting and is a pass-through for the life of the connection.
struct PrefaceObserver<T> {
    inner: T,
    /// `None` once the peer's preface has been seen, or once it has been
    /// judged impossible.
    scan: Option<PrefaceScan>,
    /// Dropped without sending if the connection ends first, which is what
    /// turns "the peer never proved itself" into a failure the caller can see.
    signal: Option<tokio::sync::oneshot::Sender<()>>,
}

/// Progress through the peer's first frame header and payload.
struct PrefaceScan {
    header: [u8; FRAME_HEADER_BYTES],
    header_filled: usize,
    payload_remaining: usize,
}

/// An HTTP/2 frame header is nine bytes: length(3) type(1) flags(1) id(4).
const FRAME_HEADER_BYTES: usize = 9;
/// The `SETTINGS` frame type.
const SETTINGS_FRAME_TYPE: u8 = 0x4;

impl<T> PrefaceObserver<T> {
    fn wrap(inner: T) -> (Self, tokio::sync::oneshot::Receiver<()>) {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let observer = Self {
            inner,
            scan: Some(PrefaceScan {
                header: [0; FRAME_HEADER_BYTES],
                header_filled: 0,
                payload_remaining: 0,
            }),
            signal: Some(sender),
        };

        (observer, receiver)
    }

    /// Feeds freshly read bytes to the scan.
    ///
    /// Deliberately tolerant of fragmentation: the peer's SETTINGS frame can
    /// arrive across any number of reads, and a scan that assumed one read per
    /// frame would report a healthy peer as a failure under a small MTU.
    fn observe(&mut self, mut bytes: &[u8]) {
        let Some(scan) = self.scan.as_mut() else {
            return;
        };

        while !bytes.is_empty() {
            if scan.header_filled < FRAME_HEADER_BYTES {
                let wanted = FRAME_HEADER_BYTES - scan.header_filled;
                let taken = wanted.min(bytes.len());
                scan.header[scan.header_filled..scan.header_filled + taken]
                    .copy_from_slice(&bytes[..taken]);
                scan.header_filled += taken;
                bytes = &bytes[taken..];
                if scan.header_filled < FRAME_HEADER_BYTES {
                    return;
                }
                if scan.header[3] != SETTINGS_FRAME_TYPE {
                    // Not an HTTP/2 server preface. Dropping the sender fails
                    // the caller rather than waiting out its budget on a peer
                    // that has already answered the question.
                    self.scan = None;
                    self.signal = None;
                    return;
                }
                scan.payload_remaining = usize::from(scan.header[0]) << 16
                    | usize::from(scan.header[1]) << 8
                    | usize::from(scan.header[2]);
            }

            let taken = scan.payload_remaining.min(bytes.len());
            scan.payload_remaining -= taken;
            bytes = &bytes[taken..];
            if scan.payload_remaining == 0 {
                self.scan = None;
                if let Some(signal) = self.signal.take() {
                    let _ = signal.send(());
                }
                return;
            }
        }
    }
}

impl<T> tokio::io::AsyncRead for PrefaceObserver<T>
where
    T: tokio::io::AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let observing = self.scan.is_some();
        let before = buffer.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(context, buffer);
        if observing && matches!(polled, Poll::Ready(Ok(()))) {
            let read = buffer.filled()[before..].to_vec();
            if !read.is_empty() {
                self.observe(&read);
            }
        }

        polled
    }
}

impl<T> tokio::io::AsyncWrite for PrefaceObserver<T>
where
    T: tokio::io::AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(context, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[cfg(test)]
pub(crate) mod test_client {
    //! An HTTP/2 client for tests.
    //!
    //! It lives in this file, rather than beside the tests that use it, because
    //! `scripts/check-egress-only.sh` permits `hyper::client::conn::http2` in
    //! exactly one file. A test exemption would be a hole in that guard rather
    //! than a convenience: "the h2 client is built in one reviewed place" is
    //! only worth asserting if it is true of the whole tree.

    use std::net::SocketAddr;

    use bytes::Bytes;
    use hyper::body::Body;
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
    use tokio::net::TcpStream;

    /// Opens an h2c prior-knowledge connection and returns a request sender.
    ///
    /// Deliberately plaintext: it is the deployment shape #257 settled on, and
    /// it is what the gRPC listener serves.
    pub(crate) async fn connect<B>(
        address: SocketAddr,
    ) -> std::io::Result<hyper::client::conn::http2::SendRequest<B>>
    where
        B: Body<Data = Bytes> + Unpin + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let tcp = TcpStream::connect(address).await?;
        let _ = tcp.set_nodelay(true);
        let (sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .handshake(TokioIo::new(tcp))
            .await
            .map_err(std::io::Error::other)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });

        Ok(sender)
    }
}
