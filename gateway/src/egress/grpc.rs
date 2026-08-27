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
    /// destination the ordinary path would reject. `connect_timeout` bounds
    /// establishing a connection and acquiring stream capacity on an existing
    /// one; it does not bound the call, because a bidirectional stream has no
    /// total duration the transport could know. The caller owns that.
    pub(crate) async fn grpc_call_at_checked_destination(
        &self,
        destination: &CheckedEgressDestination,
        url: &str,
        headers: HeaderMap,
        body: GrpcRequestBody,
        connect_timeout: Duration,
    ) -> Result<GrpcResponse, EgressError> {
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
                    let sender = tokio::time::timeout(
                        connect_timeout,
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
        // `ready()` is where the upstream's SETTINGS_MAX_CONCURRENT_STREAMS is
        // respected: it does not resolve until the connection can carry another
        // stream. Bounding it with the connect budget means a saturated upstream
        // surfaces as a bounded failure instead of an unbounded wait.
        tokio::time::timeout(connect_timeout, sender.ready())
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
                self.handshake_grpc(TokioIo::new(stream)).await
            }
            // h2c prior knowledge. The deployment contract for plaintext gRPC
            // is a terminator in front of the gateway, documented in
            // docs/deployment/grpc.md.
            _ => self.handshake_grpc(TokioIo::new(tcp)).await,
        }
    }

    async fn handshake_grpc<T>(
        &self,
        io: T,
    ) -> Result<hyper::client::conn::http2::SendRequest<GrpcRequestBody>, EgressError>
    where
        T: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    {
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
            .handshake(io)
            .await
            .map_err(|_| transport_error(GrpcFailure::Handshake))?;

        // The connection driver is deliberately untracked by the shutdown task
        // tracker. It outlives every individual call by design, and a drain
        // that waited for an idle pooled connection would never finish. It ends
        // when the last sender is dropped and the last stream completes, which
        // forced shutdown produces by cancelling the call tasks.
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(
                    error_category = classify(&error).category(),
                    "gRPC upstream connection ended"
                );
            }
        });

        Ok(sender)
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
