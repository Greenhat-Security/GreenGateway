use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, Request},
    middleware::Next,
    response::Response,
    Extension, Router,
};
use serde_json::json;
use time::OffsetDateTime;
use tokio_util::{
    sync::CancellationToken,
    task::{task_tracker::TaskTrackerToken, TaskTracker},
};

#[cfg(test)]
use crate::inbound_tls::ConnectionScheme;
use crate::{
    audit,
    auth::VerifiedClientIdentity,
    config,
    inbound_tls::{BoundListener, InboundConnectInfo, InboundTlsBindings},
};

const STARTING: u8 = 0;
const READY: u8 = 1;
const DRAINING: u8 = 2;

pub(crate) type BackgroundShutdown = Pin<Box<dyn Future<Output = ()> + Send>>;

#[derive(Clone)]
pub(crate) struct GatewayLifecycle {
    inner: Arc<GatewayLifecycleInner>,
}

struct GatewayLifecycleInner {
    phase: AtomicU8,
    background_cancellation: CancellationToken,
    background_tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    response_stream_cancellation: CancellationToken,
    response_stream_tasks: TaskTracker,
    response_stream_registration_open: Mutex<bool>,
}

impl Default for GatewayLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayLifecycle {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(GatewayLifecycleInner {
                phase: AtomicU8::new(STARTING),
                background_cancellation: CancellationToken::new(),
                background_tasks: Mutex::new(Vec::new()),
                response_stream_cancellation: CancellationToken::new(),
                response_stream_tasks: TaskTracker::new(),
                response_stream_registration_open: Mutex::new(true),
            }),
        }
    }

    pub(crate) fn mark_ready(&self) {
        let _ =
            self.inner
                .phase
                .compare_exchange(STARTING, READY, Ordering::AcqRel, Ordering::Acquire);
    }

    pub(crate) fn begin_draining(&self) -> bool {
        let was_draining = self.inner.phase.swap(DRAINING, Ordering::AcqRel) == DRAINING;
        self.inner.background_cancellation.cancel();
        self.close_response_stream_registration();
        !was_draining
    }

    pub(crate) fn startup_complete(&self) -> bool {
        self.inner.phase.load(Ordering::Acquire) != STARTING
    }

    pub(crate) fn accepting_work(&self) -> bool {
        self.inner.phase.load(Ordering::Acquire) == READY
    }

    pub(crate) fn draining(&self) -> bool {
        self.inner.phase.load(Ordering::Acquire) == DRAINING
    }

    pub(crate) fn phase_name(&self) -> &'static str {
        match self.inner.phase.load(Ordering::Acquire) {
            STARTING => "starting",
            READY => "ready",
            DRAINING => "draining",
            _ => "unknown",
        }
    }

    pub(crate) fn background_cancellation(&self) -> CancellationToken {
        self.inner.background_cancellation.clone()
    }

    pub(crate) fn register_background_task(&self, handle: tokio::task::JoinHandle<()>) {
        self.inner
            .background_tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(handle);
    }

    pub(crate) fn response_stream_cancellation(&self) -> CancellationToken {
        self.inner.response_stream_cancellation.clone()
    }

    pub(crate) fn try_register_response_stream(&self) -> Option<TaskTrackerToken> {
        let registration_open = self
            .inner
            .response_stream_registration_open
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        registration_open.then(|| self.inner.response_stream_tasks.token())
    }

    pub(crate) async fn force_shutdown_response_streams(&self) {
        self.close_response_stream_registration();
        self.inner.response_stream_cancellation.cancel();
        self.inner.response_stream_tasks.wait().await;
    }

    pub(crate) async fn shutdown_background_tasks(&self) {
        self.inner.background_cancellation.cancel();
        self.close_response_stream_registration();
        let handles = {
            let mut handles = self
                .inner
                .background_tasks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            handles.drain(..).collect::<Vec<_>>()
        };
        for handle in handles {
            if let Err(error) = handle.await {
                if !error.is_cancelled() {
                    tracing::error!(%error, "background task failed during shutdown");
                }
            }
        }
        self.inner.response_stream_tasks.wait().await;
    }

    fn close_response_stream_registration(&self) {
        let mut registration_open = self
            .inner
            .response_stream_registration_open
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *registration_open = false;
        self.inner.response_stream_tasks.close();
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ShutdownConfig {
    drain_delay: Duration,
    shutdown_timeout: Duration,
    audit_drain_timeout: Duration,
}

impl ShutdownConfig {
    pub(crate) fn from_config(config: &config::Config) -> Self {
        Self {
            drain_delay: Duration::from_millis(config.shutdown_drain_delay_ms),
            shutdown_timeout: Duration::from_millis(config.shutdown_timeout_ms),
            audit_drain_timeout: Duration::from_millis(config.audit_drain_timeout_ms),
        }
    }

    #[cfg(test)]
    fn immediate() -> Self {
        Self {
            drain_delay: Duration::ZERO,
            shutdown_timeout: Duration::from_secs(1),
            audit_drain_timeout: Duration::from_secs(1),
        }
    }
}

#[async_trait::async_trait]
trait ShutdownSignals: Send {
    async fn recv(&mut self);
}

struct SystemShutdownSignals {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(windows)]
    ctrl_c: tokio::signal::windows::CtrlC,
}

impl SystemShutdownSignals {
    fn new() -> std::io::Result<Self> {
        Ok(Self {
            #[cfg(unix)]
            interrupt: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
            #[cfg(unix)]
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
            #[cfg(windows)]
            ctrl_c: tokio::signal::windows::ctrl_c()?,
        })
    }
}

#[async_trait::async_trait]
impl ShutdownSignals for SystemShutdownSignals {
    async fn recv(&mut self) {
        #[cfg(unix)]
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
        }
        #[cfg(windows)]
        let _ = self.ctrl_c.recv().await;
        #[cfg(not(any(unix, windows)))]
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[async_trait::async_trait]
pub(crate) trait Clock: Send + Sync {
    fn now_utc(&self) -> OffsetDateTime;

    async fn sleep(&self, duration: Duration);
}

#[derive(Debug, Default)]
pub(crate) struct SystemClock;

#[async_trait::async_trait]
impl Clock for SystemClock {
    fn now_utc(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }

    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

pub(crate) enum GatewayApp {
    Unified(Router),
    Split { data: Router, admin: Router },
}

/// The opt-in gRPC listener's router and settings.
///
/// Kept beside `GatewayApp` rather than inside it because the gRPC listener is
/// orthogonal to the unified/split choice: it is a third socket either way, and
/// folding it into the enum would have made every existing arm carry an option
/// that has nothing to do with the distinction the enum draws.
pub(crate) struct GrpcApp {
    pub(crate) address: SocketAddr,
    pub(crate) router: Router,
    pub(crate) limits: crate::proxy::grpc::GrpcListenerLimits,
}

pub(crate) struct GatewayApps {
    pub(crate) http: GatewayApp,
    pub(crate) grpc: Option<GrpcApp>,
}

#[allow(clippy::too_many_arguments)] // One parameter per independently configured concern.
pub(crate) async fn serve_gateway(
    app: GatewayApp,
    grpc: Option<GrpcApp>,
    listen_addr: SocketAddr,
    admin_listen_addr: Option<SocketAddr>,
    inbound_tls: InboundTlsBindings,
    audit_log: audit::AuditLog,
    lifecycle: GatewayLifecycle,
    shutdown_config: ShutdownConfig,
    background_shutdown: BackgroundShutdown,
) -> std::io::Result<()> {
    let mut signals = SystemShutdownSignals::new()?;
    serve_gateway_with_signals(
        app,
        grpc,
        listen_addr,
        admin_listen_addr,
        inbound_tls,
        audit_log,
        lifecycle,
        shutdown_config,
        background_shutdown,
        &mut signals,
    )
    .await
}

#[allow(clippy::too_many_arguments)] // Signal injection keeps shutdown tests deterministic.
async fn serve_gateway_with_signals(
    app: GatewayApp,
    grpc: Option<GrpcApp>,
    listen_addr: SocketAddr,
    admin_listen_addr: Option<SocketAddr>,
    inbound_tls: InboundTlsBindings,
    audit_log: audit::AuditLog,
    lifecycle: GatewayLifecycle,
    shutdown_config: ShutdownConfig,
    background_shutdown: BackgroundShutdown,
    signals: &mut dyn ShutdownSignals,
) -> std::io::Result<()> {
    // Bound before `mark_ready`, and before any listener starts serving, so a
    // gRPC bind failure aborts startup exactly as a data or admin bind failure
    // does rather than leaving the gateway reporting itself healthy with one
    // listener missing.
    let grpc_listener = match grpc {
        Some(grpc) => Some(
            crate::proxy::grpc::GrpcListener::bind(grpc.address, grpc.router, grpc.limits).await?,
        ),
        None => None,
    };
    let grpc_bound_addr = match grpc_listener.as_ref() {
        Some(listener) => Some(listener.local_addr()?),
        None => None,
    };

    match app {
        GatewayApp::Unified(app) => {
            let listener = tokio::net::TcpListener::bind(listen_addr).await?;
            let listener = inbound_tls.bind_data(listener)?;
            let bound_addr = listener.local_addr()?;
            let scheme = listener.scheme();
            let app = app.layer(Extension(scheme));

            audit_log.emit(audit::AuditEvent::new(
                "gateway.startup",
                "startup",
                "internal",
                None::<audit::Actor>,
                json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "listen_addr": bound_addr.to_string(),
                    "listen_scheme": scheme.as_str(),
                    "grpc_listen_addr": grpc_bound_addr.map(|address| address.to_string()),
                    "tls_min_version": inbound_tls.min_version().map(|version| version.as_str()),
                }),
            ));

            if let Err(error) = emit_control_event(
                &audit_log,
                gateway_event(audit::event::GATEWAY_READY, json!({})),
            ) {
                let _ = drain_audit(&audit_log, shutdown_config.audit_drain_timeout).await;
                return Err(error);
            }
            lifecycle.mark_ready();
            tracing::info!(listen_addr = %bound_addr, scheme = scheme.as_str(), "gateway listening");
            let cancellation = CancellationToken::new();
            let server = serve_with_grpc(
                serve_router_with_shutdown(listener, app, cancellation.clone()),
                grpc_listener,
                cancellation.clone(),
            );
            tokio::pin!(server);
            tokio::select! {
                result = &mut server => {
                    return unexpected_listener_termination(
                        result,
                        &audit_log,
                        &lifecycle,
                        shutdown_config,
                        background_shutdown,
                        cancellation,
                    ).await;
                }
                () = signals.recv() => {}
            }
            coordinated_shutdown(
                &audit_log,
                &lifecycle,
                shutdown_config,
                background_shutdown,
                cancellation,
                server,
                signals,
            )
            .await?;
        }
        GatewayApp::Split { data, admin } => {
            let admin_listen_addr = admin_listen_addr
                .expect("split gateway app should only be built when ADMIN_LISTEN_ADDR is set");
            let data_listener = tokio::net::TcpListener::bind(listen_addr).await?;
            let data_listener = inbound_tls.bind_data(data_listener)?;
            let data_bound_addr = data_listener.local_addr()?;
            let data_scheme = data_listener.scheme();
            let admin_listener = tokio::net::TcpListener::bind(admin_listen_addr).await?;
            let admin_listener = inbound_tls.bind_admin(admin_listener)?;
            let admin_bound_addr = admin_listener.local_addr()?;
            let admin_scheme = admin_listener.scheme();
            let data = data.layer(Extension(data_scheme));
            let admin = admin.layer(Extension(admin_scheme));

            audit_log.emit(audit::AuditEvent::new(
                "gateway.startup",
                "startup",
                "internal",
                None::<audit::Actor>,
                json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "listen_addr": data_bound_addr.to_string(),
                    "listen_scheme": data_scheme.as_str(),
                    "admin_listen_addr": admin_bound_addr.to_string(),
                    "admin_listen_scheme": admin_scheme.as_str(),
                    "grpc_listen_addr": grpc_bound_addr.map(|address| address.to_string()),
                    "tls_min_version": inbound_tls.min_version().map(|version| version.as_str()),
                }),
            ));

            if let Err(error) = emit_control_event(
                &audit_log,
                gateway_event(audit::event::GATEWAY_READY, json!({})),
            ) {
                let _ = drain_audit(&audit_log, shutdown_config.audit_drain_timeout).await;
                return Err(error);
            }
            lifecycle.mark_ready();
            tracing::info!(listen_addr = %data_bound_addr, scheme = data_scheme.as_str(), "gateway data listener listening");
            tracing::info!(admin_listen_addr = %admin_bound_addr, scheme = admin_scheme.as_str(), "gateway admin listener listening");
            let cancellation = CancellationToken::new();
            let data_server = serve_with_grpc(
                serve_router_with_shutdown(data_listener, data, cancellation.clone()),
                grpc_listener,
                cancellation.clone(),
            );
            let admin_server =
                serve_router_with_shutdown(admin_listener, admin, cancellation.clone());
            tokio::pin!(data_server);
            tokio::pin!(admin_server);
            tokio::select! {
                result = &mut data_server => {
                    return unexpected_split_listener_termination(
                        result,
                        admin_server,
                        &audit_log,
                        &lifecycle,
                        shutdown_config,
                        background_shutdown,
                        cancellation,
                    ).await;
                }
                result = &mut admin_server => {
                    return unexpected_split_listener_termination(
                        result,
                        data_server,
                        &audit_log,
                        &lifecycle,
                        shutdown_config,
                        background_shutdown,
                        cancellation,
                    ).await;
                }
                () = signals.recv() => {}
            }
            coordinated_shutdown(
                &audit_log,
                &lifecycle,
                shutdown_config,
                background_shutdown,
                cancellation,
                async move {
                    tokio::try_join!(data_server, admin_server)?;
                    Ok(())
                },
                signals,
            )
            .await?;
        }
    }

    Ok(())
}

/// Runs an HTTP listener alongside the optional gRPC listener as one future.
///
/// With no gRPC listener the second half resolves only when the shutdown token
/// fires, so it never terminates the pair early -- and it still resolves during
/// shutdown, so the drain does not hang waiting for a listener that was never
/// bound.
async fn serve_with_grpc<Http>(
    http: Http,
    grpc: Option<crate::proxy::grpc::GrpcListener>,
    shutdown: CancellationToken,
) -> std::io::Result<()>
where
    Http: Future<Output = std::io::Result<()>>,
{
    let grpc = async move {
        match grpc {
            Some(listener) => listener.serve(shutdown).await,
            None => {
                shutdown.cancelled().await;
                Ok(())
            }
        }
    };
    tokio::try_join!(http, grpc)?;

    Ok(())
}

async fn coordinated_shutdown<Servers>(
    audit_log: &audit::AuditLog,
    lifecycle: &GatewayLifecycle,
    config: ShutdownConfig,
    background_shutdown: BackgroundShutdown,
    cancellation: CancellationToken,
    servers: Servers,
    signals: &mut dyn ShutdownSignals,
) -> std::io::Result<()>
where
    Servers: Future<Output = std::io::Result<()>>,
{
    let started = Instant::now();
    lifecycle.begin_draining();
    let mut audit_control_error = emit_control_event(
        audit_log,
        gateway_event(audit::event::GATEWAY_SHUTDOWN_STARTED, json!({})),
    )
    .err();

    let mut forced_reason = None;
    if !config.drain_delay.is_zero() {
        tokio::select! {
            () = tokio::time::sleep(config.drain_delay) => {}
            () = signals.recv() => forced_reason = Some("second_signal"),
        }
    }
    cancellation.cancel();

    if forced_reason.is_none() {
        let shutdown = async {
            let background_shutdown = async {
                background_shutdown.await;
                Ok::<(), std::io::Error>(())
            };
            tokio::try_join!(servers, background_shutdown)?;
            Ok::<(), std::io::Error>(())
        };
        tokio::select! {
            result = tokio::time::timeout(config.shutdown_timeout, shutdown) => {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        lifecycle.force_shutdown_response_streams().await;
                        if let Err(audit_error) =
                            emit_terminal_shutdown(audit_log, started, Some("listener_error"))
                        {
                            tracing::error!(%audit_error, "failed to admit terminal shutdown audit event");
                        }
                        if let Err(audit_error) =
                            drain_audit(audit_log, config.audit_drain_timeout).await
                        {
                            tracing::error!(%audit_error, "failed to drain audit after listener error");
                        }
                        return Err(error);
                    }
                    Err(_) => forced_reason = Some("deadline"),
                }
            }
            () = signals.recv() => forced_reason = Some("second_signal"),
        }
    }

    if forced_reason.is_some() {
        lifecycle.force_shutdown_response_streams().await;
    }
    if let Err(error) = emit_terminal_shutdown(audit_log, started, forced_reason) {
        if audit_control_error.is_none() {
            audit_control_error = Some(error);
        }
    }
    let drain_result = drain_audit(audit_log, config.audit_drain_timeout).await;
    if let Some(error) = audit_control_error {
        if let Err(drain_error) = drain_result {
            tracing::error!(%drain_error, "audit drain also failed after control-event admission failure");
        }
        return Err(error);
    }
    drain_result
}

async fn unexpected_listener_termination(
    result: std::io::Result<()>,
    audit_log: &audit::AuditLog,
    lifecycle: &GatewayLifecycle,
    config: ShutdownConfig,
    background_shutdown: BackgroundShutdown,
    cancellation: CancellationToken,
) -> std::io::Result<()> {
    lifecycle.begin_draining();
    cancellation.cancel();
    let _ = tokio::time::timeout(config.shutdown_timeout, background_shutdown).await;
    lifecycle.force_shutdown_response_streams().await;
    let terminal_result =
        emit_terminal_shutdown(audit_log, Instant::now(), Some("listener_terminated"));
    let drain_result = drain_audit(audit_log, config.audit_drain_timeout).await;
    terminal_result?;
    drain_result?;
    match result {
        Err(error) => Err(error),
        Ok(()) => Err(std::io::Error::other(
            "gateway listener terminated unexpectedly",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
async fn unexpected_split_listener_termination<Peer>(
    result: std::io::Result<()>,
    peer: Peer,
    audit_log: &audit::AuditLog,
    lifecycle: &GatewayLifecycle,
    config: ShutdownConfig,
    background_shutdown: BackgroundShutdown,
    cancellation: CancellationToken,
) -> std::io::Result<()>
where
    Peer: Future<Output = std::io::Result<()>>,
{
    lifecycle.begin_draining();
    cancellation.cancel();
    let peer_shutdown = async {
        let (peer_result, ()) = tokio::join!(peer, background_shutdown);
        peer_result
    };
    if tokio::time::timeout(config.shutdown_timeout, peer_shutdown)
        .await
        .is_err()
    {
        tracing::error!("peer listener exceeded shutdown deadline after split listener failure");
    }
    lifecycle.force_shutdown_response_streams().await;
    let terminal_result =
        emit_terminal_shutdown(audit_log, Instant::now(), Some("listener_terminated"));
    let drain_result = drain_audit(audit_log, config.audit_drain_timeout).await;
    terminal_result?;
    drain_result?;
    match result {
        Err(error) => Err(error),
        Ok(()) => Err(std::io::Error::other(
            "gateway listener terminated unexpectedly",
        )),
    }
}

fn emit_terminal_shutdown(
    audit_log: &audit::AuditLog,
    started: Instant,
    forced_reason: Option<&'static str>,
) -> std::io::Result<()> {
    let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    if let Some(reason) = forced_reason {
        emit_control_event(
            audit_log,
            gateway_event(
                audit::event::GATEWAY_SHUTDOWN_FORCED,
                json!({
                    "duration_ms": duration_ms,
                    "reason": reason,
                }),
            ),
        )
    } else {
        emit_control_event(
            audit_log,
            gateway_event(
                audit::event::GATEWAY_SHUTDOWN_COMPLETED,
                json!({
                    "duration_ms": duration_ms,
                }),
            ),
        )
    }
}

fn emit_control_event(
    audit_log: &audit::AuditLog,
    event: audit::AuditEvent,
) -> std::io::Result<()> {
    audit_log.emit_control(event).map_err(|error| {
        std::io::Error::other(format!("failed to admit lifecycle audit event: {error}"))
    })
}

async fn drain_audit(audit_log: &audit::AuditLog, timeout: Duration) -> std::io::Result<()> {
    audit_log
        .close_and_drain(timeout)
        .await
        .map_err(|error| std::io::Error::other(format!("failed to drain audit events: {error}")))
}

fn gateway_event(event_type: &'static str, payload: serde_json::Value) -> audit::AuditEvent {
    audit::AuditEvent::new(
        event_type,
        "lifecycle",
        "internal",
        None::<audit::Actor>,
        payload,
    )
}

/// Serves `app` on `listener` until `shutdown` is cancelled.
///
/// The two arms are deliberately the same `axum::serve` call: the router, the
/// `ConnectInfo<SocketAddr>` extractor `crate::client_ip` depends on, and
/// graceful shutdown are identical whether or not the listener terminates TLS.
/// TLS is a `Listener` implementation here, not a second serving path.
///
/// Both arms also go through [`spread_inbound_connect_info`], which is what
/// keeps `ConnectInfo<SocketAddr>` meaning what it has always meant while a
/// second, richer connect-info type carries the client-certificate identity.
/// Applying it here rather than at each router's construction site is the point:
/// every listener this gateway serves passes through this function, so no route
/// can be reached with a stale identity extension or without a peer address.
pub(crate) async fn serve_router_with_shutdown(
    listener: BoundListener,
    app: Router,
    shutdown: CancellationToken,
) -> std::io::Result<()> {
    let app = app.layer(axum::middleware::from_fn(spread_inbound_connect_info));
    let service = app.into_make_service_with_connect_info::<InboundConnectInfo>();
    match listener {
        BoundListener::Plain(listener) => {
            axum::serve(listener, service)
                .with_graceful_shutdown(shutdown.cancelled_owned())
                .await
        }
        BoundListener::Tls(listener) => {
            axum::serve(listener, service)
                .with_graceful_shutdown(shutdown.cancelled_owned())
                .await
        }
    }
}

/// Splits the listener's connect info into the extensions the rest of the
/// gateway reads.
///
/// Runs outermost, before authentication, RBAC, rate limiting, or header
/// hardening, because all four read one or both of the extensions it writes.
///
/// The identity extension is **removed before it is written**, on every
/// request, including requests that carry no certificate. Nothing today can put
/// one there -- extensions are not parsed from the wire, and
/// `VerifiedClientIdentity` has no public constructor -- so this is not
/// defusing a live path. It is making the invariant local: whatever else a
/// future layer or handler does, the identity a request reaches auth with is
/// the one this connection's handshake produced, and a connection that produced
/// none reaches auth with none.
async fn spread_inbound_connect_info(mut request: Request, next: Next) -> Response {
    request.extensions_mut().remove::<VerifiedClientIdentity>();

    if let Some(ConnectInfo(info)) = request
        .extensions_mut()
        .remove::<ConnectInfo<InboundConnectInfo>>()
    {
        request.extensions_mut().insert(ConnectInfo(info.peer_addr));
        if let Some(identity) = info.client_identity {
            request.extensions_mut().insert(identity);
        }
    }

    next.run(request).await
}

#[cfg(test)]
pub(crate) async fn serve_router(
    listener: tokio::net::TcpListener,
    app: Router,
) -> std::io::Result<()> {
    serve_router_with_shutdown(
        BoundListener::Plain(listener),
        app.layer(Extension(ConnectionScheme::Http)),
        CancellationToken::new(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::Duration,
    };

    use axum::{extract::ConnectInfo, routing::get};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::{mpsc, Notify},
    };

    use super::*;
    use crate::audit::{self, sink::tests::CaptureSink};

    #[tokio::test]
    async fn bind_failure_does_not_emit_startup_event() {
        let occupied = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener should bind");
        let occupied_addr = occupied
            .local_addr()
            .expect("occupied address should be available");
        let capture = CaptureSink::new();
        let audit_log = audit::AuditLog::new(Arc::new(capture.clone()));

        let error = serve_gateway(
            GatewayApp::Unified(Router::new()),
            None,
            occupied_addr,
            None,
            InboundTlsBindings::plaintext(),
            audit_log,
            GatewayLifecycle::new(),
            ShutdownConfig::immediate(),
            test_background_shutdown(),
        )
        .await
        .expect_err("binding an occupied address should fail");

        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        assert!(
            capture.events().is_empty(),
            "startup must be emitted only after every required listener binds"
        );
    }

    #[tokio::test]
    async fn split_second_bind_failure_leaves_no_listener_or_startup_event() {
        let occupied_admin = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("admin reservation should bind");
        let admin_addr = occupied_admin
            .local_addr()
            .expect("admin reservation address should be available");
        let data_reservation = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("data reservation should bind");
        let data_addr = data_reservation
            .local_addr()
            .expect("data reservation address should be available");
        drop(data_reservation);
        let capture = CaptureSink::new();

        let error = serve_gateway(
            GatewayApp::Split {
                data: Router::new(),
                admin: Router::new(),
            },
            None,
            data_addr,
            Some(admin_addr),
            InboundTlsBindings::plaintext(),
            audit::AuditLog::new(Arc::new(capture.clone())),
            GatewayLifecycle::new(),
            ShutdownConfig::immediate(),
            test_background_shutdown(),
        )
        .await
        .expect_err("occupied admin address should fail the split bind");

        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        assert!(capture.events().is_empty());
        let rebound = tokio::net::TcpListener::bind(data_addr)
            .await
            .expect("failed split startup must release the data listener");
        drop(rebound);
    }

    #[tokio::test]
    async fn split_listener_failure_gracefully_drains_in_flight_peer_request() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("peer listener should bind");
        let peer_addr = listener.local_addr().expect("peer address");
        let handler_started = Arc::new(Notify::new());
        let release_handler = Arc::new(Notify::new());
        let app = Router::new().route(
            "/",
            get({
                let handler_started = Arc::clone(&handler_started);
                let release_handler = Arc::clone(&release_handler);
                move || {
                    let handler_started = Arc::clone(&handler_started);
                    let release_handler = Arc::clone(&release_handler);
                    async move {
                        handler_started.notify_one();
                        release_handler.notified().await;
                        "peer-drained"
                    }
                }
            }),
        );
        let cancellation = CancellationToken::new();
        let peer_server = tokio::spawn(serve_router_with_shutdown(
            BoundListener::Plain(listener),
            app.layer(Extension(ConnectionScheme::Http)),
            cancellation.clone(),
        ));
        let response_task = tokio::spawn(async move {
            let mut stream = tokio::net::TcpStream::connect(peer_addr)
                .await
                .expect("peer request should connect");
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await
                .expect("peer request should write");
            let mut response = Vec::new();
            stream
                .read_to_end(&mut response)
                .await
                .expect("peer response should read");
            response
        });
        handler_started.notified().await;
        let release_after_cancel = tokio::spawn({
            let cancellation = cancellation.clone();
            async move {
                cancellation.cancelled().await;
                release_handler.notify_one();
            }
        });
        let capture = CaptureSink::new();
        let audit_log = audit::AuditLog::new(Arc::new(capture));

        let error = unexpected_split_listener_termination(
            Err(std::io::Error::other("data listener failed")),
            async move {
                peer_server
                    .await
                    .map_err(|error| std::io::Error::other(error.to_string()))?
            },
            &audit_log,
            &GatewayLifecycle::new(),
            ShutdownConfig::immediate(),
            test_background_shutdown(),
            cancellation,
        )
        .await
        .expect_err("the original listener failure should remain fatal");
        let response = response_task.await.expect("peer request task should join");
        release_after_cancel
            .await
            .expect("release task should observe cancellation");

        assert_eq!(error.to_string(), "data listener failed");
        assert!(
            String::from_utf8_lossy(&response).contains("peer-drained"),
            "in-flight peer response must complete before split shutdown returns"
        );
    }

    #[tokio::test]
    async fn unified_startup_reports_actual_address_and_preserves_connect_info() {
        let capture = CaptureSink::new();
        let server = tokio::spawn(serve_gateway(
            GatewayApp::Unified(peer_router()),
            None,
            "127.0.0.1:0".parse().expect("listen address should parse"),
            None,
            InboundTlsBindings::plaintext(),
            audit::AuditLog::new(Arc::new(capture.clone())),
            GatewayLifecycle::new(),
            ShutdownConfig::immediate(),
            test_background_shutdown(),
        ));

        let event = wait_for_startup_event(&capture).await;
        let listen_addr = event.payload["listen_addr"]
            .as_str()
            .expect("startup event should contain listen_addr")
            .parse::<SocketAddr>()
            .expect("startup listen_addr should parse");
        let peer = request_peer(listen_addr).await;

        assert_eq!(
            peer.ip(),
            "127.0.0.1"
                .parse::<std::net::IpAddr>()
                .expect("IP should parse")
        );
        assert_ne!(peer.port(), 0);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn split_startup_reports_both_actual_addresses() {
        let capture = CaptureSink::new();
        let server = tokio::spawn(serve_gateway(
            GatewayApp::Split {
                data: peer_router(),
                admin: peer_router(),
            },
            None,
            "127.0.0.1:0".parse().expect("data address should parse"),
            Some("127.0.0.1:0".parse().expect("admin address should parse")),
            InboundTlsBindings::plaintext(),
            audit::AuditLog::new(Arc::new(capture.clone())),
            GatewayLifecycle::new(),
            ShutdownConfig::immediate(),
            test_background_shutdown(),
        ));

        let event = wait_for_startup_event(&capture).await;
        let data_addr = event.payload["listen_addr"]
            .as_str()
            .expect("startup event should contain listen_addr")
            .parse::<SocketAddr>()
            .expect("data address should parse");
        let admin_addr = event.payload["admin_listen_addr"]
            .as_str()
            .expect("startup event should contain admin_listen_addr")
            .parse::<SocketAddr>()
            .expect("admin address should parse");

        assert_ne!(data_addr, admin_addr);
        request_peer(data_addr).await;
        request_peer(admin_addr).await;
        server.abort();
        let _ = server.await;
    }

    struct ChannelSignals {
        receiver: mpsc::UnboundedReceiver<()>,
    }

    #[async_trait::async_trait]
    impl ShutdownSignals for ChannelSignals {
        async fn recv(&mut self) {
            let _ = self.receiver.recv().await;
        }
    }

    #[tokio::test]
    async fn first_signal_drains_servers_background_tasks_and_audit_in_order() {
        let capture = CaptureSink::new();
        let audit_log = audit::AuditLog::new(Arc::new(capture.clone()));
        let lifecycle = GatewayLifecycle::new();
        let observed_lifecycle = lifecycle.clone();
        let background_finished = Arc::new(AtomicBool::new(false));
        let finished = Arc::clone(&background_finished);
        let background_cancellation = lifecycle.background_cancellation();
        lifecycle.register_background_task(tokio::spawn(async move {
            background_cancellation.cancelled().await;
            finished.store(true, Ordering::SeqCst);
        }));
        let background_lifecycle = lifecycle.clone();
        let (signal_tx, signal_rx) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let mut signals = ChannelSignals {
                receiver: signal_rx,
            };
            serve_gateway_with_signals(
                GatewayApp::Unified(peer_router()),
                None,
                "127.0.0.1:0".parse().expect("listen address should parse"),
                None,
                InboundTlsBindings::plaintext(),
                audit_log,
                lifecycle,
                ShutdownConfig::immediate(),
                Box::pin(async move {
                    background_lifecycle.shutdown_background_tasks().await;
                }),
                &mut signals,
            )
            .await
        });

        wait_for_startup_event(&capture).await;
        signal_tx
            .send(())
            .expect("first signal should be delivered");
        server
            .await
            .expect("server task should join")
            .expect("graceful shutdown should succeed");

        assert!(observed_lifecycle.draining());
        assert!(background_finished.load(Ordering::SeqCst));
        assert_eq!(
            capture
                .events()
                .into_iter()
                .filter(|event| event.event_type.starts_with("gateway."))
                .map(|event| event.event_type)
                .collect::<Vec<_>>(),
            vec![
                "gateway.startup",
                audit::event::GATEWAY_READY,
                audit::event::GATEWAY_SHUTDOWN_STARTED,
                audit::event::GATEWAY_SHUTDOWN_COMPLETED,
            ]
        );
    }

    #[tokio::test]
    async fn durable_audit_flush_failure_makes_shutdown_fail() {
        struct FailingFlushSink;

        impl audit::AuditSink for FailingFlushSink {
            fn emit(&self, _event: &audit::AuditEvent) {}

            fn flush(&self) -> Result<(), String> {
                Err("injected lifecycle flush failure".to_owned())
            }
        }

        let audit_log = audit::AuditLog::new(Arc::new(FailingFlushSink));
        let lifecycle = GatewayLifecycle::new();
        let observed_lifecycle = lifecycle.clone();
        let (signal_tx, signal_rx) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let mut signals = ChannelSignals {
                receiver: signal_rx,
            };
            serve_gateway_with_signals(
                GatewayApp::Unified(Router::new()),
                None,
                "127.0.0.1:0".parse().expect("listen address should parse"),
                None,
                InboundTlsBindings::plaintext(),
                audit_log,
                lifecycle,
                ShutdownConfig::immediate(),
                test_background_shutdown(),
                &mut signals,
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !observed_lifecycle.accepting_work() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("gateway should become ready");

        signal_tx
            .send(())
            .expect("shutdown signal should be delivered");
        let error = server
            .await
            .expect("server task should join")
            .expect_err("durable flush failure must make shutdown fail");

        assert!(error
            .to_string()
            .contains("injected lifecycle flush failure"));
    }

    #[tokio::test]
    async fn second_signal_forces_shutdown_during_drain_delay() {
        let capture = CaptureSink::new();
        let audit_log = audit::AuditLog::new(Arc::new(capture.clone()));
        let (signal_tx, signal_rx) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let mut signals = ChannelSignals {
                receiver: signal_rx,
            };
            serve_gateway_with_signals(
                GatewayApp::Unified(Router::new()),
                None,
                "127.0.0.1:0".parse().expect("listen address should parse"),
                None,
                InboundTlsBindings::plaintext(),
                audit_log,
                GatewayLifecycle::new(),
                ShutdownConfig {
                    drain_delay: Duration::from_secs(5),
                    shutdown_timeout: Duration::from_secs(5),
                    audit_drain_timeout: Duration::from_secs(1),
                },
                test_background_shutdown(),
                &mut signals,
            )
            .await
        });

        wait_for_startup_event(&capture).await;
        signal_tx
            .send(())
            .expect("first signal should be delivered");
        signal_tx
            .send(())
            .expect("second signal should be delivered");
        server
            .await
            .expect("server task should join")
            .expect("forced shutdown should still complete cleanup");

        let forced = capture
            .events()
            .into_iter()
            .find(|event| event.event_type == audit::event::GATEWAY_SHUTDOWN_FORCED)
            .expect("forced shutdown event should be emitted");
        assert_eq!(forced.payload["reason"], "second_signal");
    }

    #[tokio::test]
    async fn shutdown_deadline_forces_stuck_background_work() {
        let capture = CaptureSink::new();
        let audit_log = audit::AuditLog::new(Arc::new(capture.clone()));
        let (signal_tx, signal_rx) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let mut signals = ChannelSignals {
                receiver: signal_rx,
            };
            serve_gateway_with_signals(
                GatewayApp::Unified(Router::new()),
                None,
                "127.0.0.1:0".parse().expect("listen address should parse"),
                None,
                InboundTlsBindings::plaintext(),
                audit_log,
                GatewayLifecycle::new(),
                ShutdownConfig {
                    drain_delay: Duration::ZERO,
                    shutdown_timeout: Duration::from_millis(25),
                    audit_drain_timeout: Duration::from_secs(1),
                },
                test_background_shutdown(),
                &mut signals,
            )
            .await
        });

        wait_for_startup_event(&capture).await;
        signal_tx.send(()).expect("signal should be delivered");
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("shutdown deadline should bound stuck work")
            .expect("server task should join")
            .expect("forced shutdown should finish");

        let forced = capture
            .events()
            .into_iter()
            .find(|event| event.event_type == audit::event::GATEWAY_SHUTDOWN_FORCED)
            .expect("forced shutdown event should be emitted");
        assert_eq!(forced.payload["reason"], "deadline");
    }

    fn peer_router() -> Router {
        async fn peer(ConnectInfo(peer): ConnectInfo<SocketAddr>) -> String {
            peer.to_string()
        }

        Router::new().route("/", get(peer))
    }

    fn test_background_shutdown() -> BackgroundShutdown {
        Box::pin(std::future::pending())
    }

    async fn wait_for_startup_event(capture: &CaptureSink) -> audit::AuditEvent {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(event) = capture
                    .events()
                    .into_iter()
                    .find(|event| event.event_type == "gateway.startup")
                {
                    return event;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("startup event should be emitted")
    }

    async fn request_peer(addr: SocketAddr) -> SocketAddr {
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut stream = tokio::net::TcpStream::connect(addr)
                .await
                .expect("test client should connect");
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
                .await
                .expect("test request should write");
            let mut response = Vec::new();
            stream
                .read_to_end(&mut response)
                .await
                .expect("test response should read");
            let response = String::from_utf8(response).expect("response should be UTF-8");
            assert!(response.starts_with("HTTP/1.1 200"));
            response
                .split("\r\n\r\n")
                .nth(1)
                .expect("response should contain a body")
                .trim()
                .parse()
                .expect("ConnectInfo response should be a socket address")
        })
        .await
        .expect("test HTTP request should complete")
    }
}
