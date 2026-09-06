//! The gRPC listener: the one place in this tree that builds an HTTP/2 server.
//!
//! `scripts/check-egress-only.sh` enforces that, by path, and enforces that the
//! builder below names every bound issue #257 requires. Both halves matter: an
//! h2 server constructed anywhere else would be one nobody reviewed, and an h2
//! server built without these calls runs on hyper's defaults.
//!
//! # Why a third listener rather than a mode on the data listener
//!
//! `axum::serve` builds its connection handler internally
//! (`axum-0.8.9/src/serve/mod.rs:391`) and exposes no hook to reach it: no
//! `serve_with_builder`, and `Serve`'s entire public surface is
//! `with_graceful_shutdown` and `local_addr`. So under `axum::serve` the HTTP/2
//! settings below -- `max_concurrent_streams`, `max_header_list_size`,
//! `max_pending_accept_reset_streams`, `max_frame_size`, the flow-control
//! windows -- are simply unreachable, and the server would run on hyper's
//! defaults (200 concurrent streams, no pending-accept-reset bound). #257's
//! "Required bounds" section would be unimplementable.
//!
//! Two more reasons, either of which would be sufficient on its own:
//!
//! * Enabling `axum/http2` resolves `hyper-util` WITH `http2`, and
//!   `hyper-util`'s `auto::Builder` sniffs the HTTP/2 connection preface. Every
//!   listener would then serve h2c -- including the admin listener, which with
//!   `ADMIN_LISTEN_ADDR` unset (the default) is the SAME SOCKET as the data
//!   listener.
//! * axum turns on RFC 8441 extended CONNECT unconditionally under http2
//!   (`serve/mod.rs:393-394`), where hyper's own default is off. This builder
//!   deliberately does not call `enable_connect_protocol()`.
//!
//! The cost of not using `axum::serve` is that graceful shutdown, the accept
//! loop, and `ConnectInfo` have to be provided here. They are, below, and the
//! data and admin listeners are not touched at all -- which is the point of
//! choosing a third listener over converting an existing one.

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use axum::{body::Body, extract::ConnectInfo, Router};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt as _;

use crate::metrics::{GRPC_LISTENER_CONNECTIONS_ACTIVE, GRPC_LISTENER_CONNECTIONS_TOTAL};

/// Ceiling on simultaneously accepted gRPC connections.
///
/// There is no inbound accept-concurrency limit anywhere else in this gateway,
/// so this is not a smaller version of an existing bound -- it is the only one.
/// It matters more here than it would for HTTP/1.1 because each accepted socket
/// multiplies: one connection carries up to `max_concurrent_streams` in-flight
/// calls, so the real inbound ceiling is the product of the two.
const MAX_CONNECTIONS: usize = 512;
/// The HTTP/2 connection preface (RFC 9113 section 3.4).
///
/// This listener serves h2c by PRIOR KNOWLEDGE and nothing else, so the preface
/// is not a hint about what the peer might speak -- it is the whole of the
/// admission decision at this layer.
const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// Longest a connection may take to send that preface.
///
/// Without this, a socket that connects and never speaks holds a connection
/// slot indefinitely -- the h2 equivalent of a slowloris, and cheaper to mount
/// because one socket is one slot. It bounds the READ ONLY: once the preface has
/// arrived there is no timer on the connection at all, which is what a
/// multiplexed transport carrying hour-long streams requires. An earlier draft
/// of this file put the budget on the connection instead and would have sent
/// GOAWAY to every healthy connection after ten seconds.
const PREFACE_TIMEOUT: Duration = Duration::from_secs(10);
/// h2 frame ceiling. The RFC 9113 minimum, for the reason the client side gives:
/// a proxy gains nothing from larger frames and pays for them per connection.
const MAX_FRAME_BYTES: u32 = 16_384;
/// Per-stream flow-control window.
const STREAM_WINDOW_BYTES: u32 = 1024 * 1024;
/// Connection-level flow-control window.
const CONNECTION_WINDOW_BYTES: u32 = 4 * 1024 * 1024;
/// Bound on streams a peer may open and immediately reset before the server
/// stops accepting new ones.
///
/// hyper's default for this is `None` -- unbounded -- which is the CVE-2023-44487
/// ("HTTP/2 Rapid Reset") shape. Setting it is one of the reasons this listener
/// cannot go through `axum::serve`.
const MAX_PENDING_ACCEPT_RESET_STREAMS: usize = 32;
/// How often the server pings an otherwise idle connection.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// How long a keep-alive ping may go unanswered before the connection is closed.
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// Backoff after an accept error that belongs to the listener rather than to
/// one connection. Mirrors `axum-0.8.9/src/serve/mod.rs:180-192`.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_secs(1);

/// The HTTP/2 settings this listener states explicitly.
///
/// Two are operator-configurable because deployments genuinely differ on them;
/// the rest are constants above, each with the reason it is not a knob.
#[derive(Clone, Copy, Debug)]
pub(crate) struct GrpcListenerLimits {
    pub(crate) max_concurrent_streams: u32,
    pub(crate) max_metadata_bytes: u32,
}

/// A bound gRPC listener, before it starts serving.
///
/// Binding is separated from serving so a bind failure aborts startup before
/// the gateway reports itself ready, exactly as the data and admin listeners do.
pub(crate) struct GrpcListener {
    listener: TcpListener,
    router: Router,
    limits: GrpcListenerLimits,
}

impl GrpcListener {
    pub(crate) async fn bind(
        address: SocketAddr,
        router: Router,
        limits: GrpcListenerLimits,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(address).await?;
        Ok(Self {
            listener,
            router,
            limits,
        })
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accepts connections until `shutdown` is cancelled.
    ///
    /// Returns `Ok(())` only on cancellation. A listener that stops for any
    /// other reason returns `Err`, so a caller joining this with the HTTP
    /// listeners sees the failure rather than waiting forever on a socket that
    /// is no longer accepting.
    pub(crate) async fn serve(self, shutdown: CancellationToken) -> io::Result<()> {
        let Self {
            listener,
            router,
            limits,
        } = self;
        let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let mut tracker = tokio::task::JoinSet::new();

        loop {
            while tracker.try_join_next().is_some() {}
            // A connection slot is taken BEFORE the accept, so a saturated
            // gateway stops taking sockets off the queue instead of accepting
            // them and then dropping them -- which would look to a client like
            // a successful connect followed by a silent close.
            let permit = tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                permit = Arc::clone(&connections).acquire_owned() => match permit {
                    Ok(permit) => permit,
                    // Unreachable: nothing closes this semaphore. Returning an
                    // error rather than breaking keeps the contract above true
                    // -- `Ok(())` means cancellation and nothing else -- so a
                    // caller joining this with the HTTP listeners cannot mistake
                    // a dead listener for a clean drain.
                    Err(_) => {
                        return Err(io::Error::other(
                            "gRPC listener connection semaphore closed",
                        ))
                    }
                },
            };

            let accepted = tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            let (stream, peer) = match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    // The peer went away between the SYN and the accept. That
                    // says nothing about the listener and must not cost a
                    // backoff. Same set `axum::serve` and `inbound_tls` treat as
                    // retry-immediately.
                    if is_connection_error(&error) {
                        continue;
                    }
                    tracing::error!(
                        error_category = "accept_failed",
                        "gRPC listener accept failed; backing off"
                    );
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    continue;
                }
            };

            let router = router.clone();
            let shutdown = shutdown.clone();
            tracker.spawn(serve_connection(
                stream, peer, router, limits, shutdown, permit,
            ));
        }

        // Stop taking new connections, then wait for the ones in flight. The
        // per-connection tasks are already watching the same token and will have
        // begun their own graceful shutdown.
        // Dropping this listener future at the process deadline aborts every
        // remaining connection; JoinSet owns the tasks instead of detaching them.
        while tracker.join_next().await.is_some() {}

        Ok(())
    }
}

async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    router: Router,
    limits: GrpcListenerLimits,
    shutdown: CancellationToken,
    permit: OwnedSemaphorePermit,
) {
    let _permit = permit;
    let _active = ActiveConnection::new();
    let started = Instant::now();
    // gRPC streams small messages; Nagle would hold a half-full frame waiting
    // for an ack that the next message is waiting to trigger.
    let _ = stream.set_nodelay(true);

    // Read the preface here rather than letting hyper discover it, for two
    // reasons. It bounds how long a silent socket may hold a connection slot,
    // which nothing else does. And it makes the refusal of a non-HTTP/2 client
    // this listener's own decision, taken before a router, a service, or a
    // request extension exists.
    let Some(stream) = read_h2_preface(stream).await else {
        ::metrics::counter!(GRPC_LISTENER_CONNECTIONS_TOTAL, "outcome" => "preface_rejected")
            .increment(1);
        return;
    };

    // `ConnectInfo<SocketAddr>` is how `crate::client_ip` learns the peer
    // address, and it is read out of the request's own extensions
    // (`axum-0.8.9/src/extract/connect_info.rs:153-168`). Inserting it here is
    // the whole of what `axum::serve`'s connect-info wiring achieves -- and it
    // needs no `Connected` impl, which is a strictly better position than the
    // `tap_io` workaround the TLS listener needs.
    let service = TowerToHyperService::new(router.map_request(
        move |mut request: hyper::Request<Incoming>| {
            request.extensions_mut().insert(ConnectInfo(peer));
            request.map(Body::new)
        },
    ));

    let connection = build_h2_server(limits).serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);

    // No timer on the connection. Call duration, idle time, and deadlines are
    // bounded per call by the route's gRPC policy, which is where a multiplexed
    // transport has to bound them: a connection carrying a legitimate hour-long
    // stream must not be cut because the connection itself is old.
    let outcome = tokio::select! {
        result = connection.as_mut() => {
            if result.is_ok() { "closed" } else { "error" }
        }
        () = shutdown.cancelled() => {
            // `hyper_util::server::graceful::GracefulShutdown` cannot be used:
            // its `GracefulConnection` impl for an http2 connection is
            // `#[cfg(feature = "http2")]` on hyper-util
            // (`hyper-util-0.1.20/src/server/graceful.rs:180-195`) and the trait
            // is sealed. hyper's own `graceful_shutdown` is public and does the
            // same thing: send GOAWAY, let open streams finish.
            connection.as_mut().graceful_shutdown();
            match connection.await {
                Ok(()) => "drained",
                Err(_) => "error",
            }
        }
    };

    ::metrics::counter!(GRPC_LISTENER_CONNECTIONS_TOTAL, "outcome" => outcome).increment(1);
    tracing::debug!(
        outcome,
        duration_ms = crate::duration_millis(started.elapsed()),
        "gRPC connection ended"
    );
}

/// Builds the HTTP/2 server with every bound stated explicitly.
///
/// `scripts/check-egress-only.sh` greps this function for the four setter names
/// #257 lists as required. Do not remove one to "use the default": hyper's
/// defaults are 200 concurrent streams, an UNBOUNDED pending-accept-reset
/// allowance, and a 16 KiB header list -- and the whole reason this listener
/// exists rather than reusing `axum::serve` is that these are reachable here.
fn build_h2_server(
    limits: GrpcListenerLimits,
) -> hyper::server::conn::http2::Builder<TokioExecutor> {
    let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    builder
        .timer(TokioTimer::new())
        .max_concurrent_streams(limits.max_concurrent_streams)
        .max_header_list_size(limits.max_metadata_bytes)
        .max_pending_accept_reset_streams(MAX_PENDING_ACCEPT_RESET_STREAMS)
        .max_frame_size(MAX_FRAME_BYTES)
        .initial_stream_window_size(STREAM_WINDOW_BYTES)
        .initial_connection_window_size(CONNECTION_WINDOW_BYTES)
        .keep_alive_interval(Some(KEEP_ALIVE_INTERVAL))
        .keep_alive_timeout(KEEP_ALIVE_TIMEOUT);
    // Deliberately NOT `enable_connect_protocol()`. RFC 8441 extended CONNECT is
    // an explicit non-goal of #257, and axum turns it on unconditionally --
    // which is one of the reasons this listener does not go through
    // `axum::serve`. `middleware::validate` refuses CONNECT independently; this
    // is the layer that stops the protocol being advertised at all.
    builder
}

/// Reads and verifies the HTTP/2 connection preface within [`PREFACE_TIMEOUT`].
///
/// Returns the stream with the preface put back in front of it, so hyper reads
/// the connection exactly as it would have if nothing had looked first.
async fn read_h2_preface(mut stream: TcpStream) -> Option<Prefaced<TcpStream>> {
    let mut preface = [0_u8; H2_PREFACE.len()];
    let read = tokio::time::timeout(PREFACE_TIMEOUT, stream.read_exact(&mut preface)).await;
    if !matches!(read, Ok(Ok(count)) if count == preface.len()) {
        return None;
    }
    if &preface != H2_PREFACE {
        return None;
    }

    Some(Prefaced {
        prefix: preface,
        offset: 0,
        inner: stream,
    })
}

/// A stream whose first bytes have already been consumed and must be replayed.
///
/// Deliberately a fixed-size prefix rather than a general buffered reader: the
/// only thing this listener ever reads ahead is the preface, and a general
/// buffer would invite reading further.
struct Prefaced<S> {
    prefix: [u8; H2_PREFACE.len()],
    offset: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefaced<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() {
            let offset = self.offset;
            let take = (self.prefix.len() - offset).min(buffer.remaining());
            if take == 0 {
                return Poll::Ready(Ok(()));
            }
            let prefix = self.prefix;
            buffer.put_slice(&prefix[offset..offset + take]);
            self.offset += take;
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefaced<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(context, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

struct ActiveConnection;

impl ActiveConnection {
    fn new() -> Self {
        ::metrics::gauge!(GRPC_LISTENER_CONNECTIONS_ACTIVE).increment(1.0);
        Self
    }
}

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        ::metrics::gauge!(GRPC_LISTENER_CONNECTIONS_ACTIVE).decrement(1.0);
    }
}

/// Whether an `accept` error belongs to the connection rather than the listener.
///
/// The same set `axum::serve` and `crate::inbound_tls` treat as
/// retry-immediately.
fn is_connection_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}

#[cfg(test)]
pub(crate) mod test_support {
    //! An HTTP/2 server for tests, standing in for a gRPC upstream.
    //!
    //! In this file for the same reason the test h2 client is in
    //! `egress::grpc`: the guard script permits `hyper::server::conn::http2` in
    //! exactly one file, and exempting tests would make the guard describe
    //! something weaker than it claims.

    use std::error::Error;

    use bytes::Bytes;
    use hyper::body::Incoming;
    use tokio::net::TcpListener;

    use super::{TokioExecutor, TokioIo};

    /// Serves `service` on one already-established stream.
    ///
    /// Split out from [`spawn_upstream`] so a TLS test can do its own accept
    /// and handshake and still reach the one permitted h2 server builder.
    pub(crate) async fn serve_one<I, S, B>(io: I, service: S)
    where
        I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        S: hyper::service::Service<hyper::Request<Incoming>, Response = hyper::Response<B>>
            + Send
            + 'static,
        S::Error: Into<Box<dyn Error + Send + Sync>>,
        S::Future: Send,
        B: hyper::body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .timer(hyper_util::rt::TokioTimer::new())
            .serve_connection(TokioIo::new(io), service)
            .await;
    }

    /// Serves `service` on every connection `listener` accepts, forever.
    ///
    /// No bounds are configured: this is a stand-in for someone else's gRPC
    /// server, and giving it the gateway's own limits would make tests pass for
    /// the wrong reason.
    pub(crate) fn spawn_upstream<S, B>(listener: TcpListener, service: S)
    where
        S: hyper::service::Service<hyper::Request<Incoming>, Response = hyper::Response<B>>
            + Clone
            + Send
            + 'static,
        S::Error: Into<Box<dyn Error + Send + Sync>>,
        S::Future: Send,
        B: hyper::body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let service = service.clone();
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .timer(hyper_util::rt::TokioTimer::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
    }
}
