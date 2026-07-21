use std::{future::Future, net::SocketAddr, time::Duration};

use axum::Router;
use serde_json::json;
use time::OffsetDateTime;

use crate::audit;

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

pub(crate) async fn serve_gateway(
    app: GatewayApp,
    listen_addr: SocketAddr,
    admin_listen_addr: Option<SocketAddr>,
    audit_log: audit::AuditLog,
) -> std::io::Result<()> {
    match app {
        GatewayApp::Unified(app) => {
            let listener = tokio::net::TcpListener::bind(listen_addr).await?;
            let bound_addr = listener.local_addr()?;

            audit_log.emit(audit::AuditEvent::new(
                "gateway.startup",
                "startup",
                "internal",
                None::<audit::Actor>,
                json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "listen_addr": bound_addr.to_string(),
                }),
            ));

            tracing::info!(listen_addr = %bound_addr, "gateway listening");
            serve_router(listener, app).await?;
        }
        GatewayApp::Split { data, admin } => {
            let admin_listen_addr = admin_listen_addr
                .expect("split gateway app should only be built when ADMIN_LISTEN_ADDR is set");
            let data_listener = tokio::net::TcpListener::bind(listen_addr).await?;
            let data_bound_addr = data_listener.local_addr()?;
            let admin_listener = tokio::net::TcpListener::bind(admin_listen_addr).await?;
            let admin_bound_addr = admin_listener.local_addr()?;

            audit_log.emit(audit::AuditEvent::new(
                "gateway.startup",
                "startup",
                "internal",
                None::<audit::Actor>,
                json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "listen_addr": data_bound_addr.to_string(),
                    "admin_listen_addr": admin_bound_addr.to_string(),
                }),
            ));

            tracing::info!(listen_addr = %data_bound_addr, "gateway data listener listening");
            tracing::info!(admin_listen_addr = %admin_bound_addr, "gateway admin listener listening");
            serve_split(
                serve_router(data_listener, data),
                serve_router(admin_listener, admin),
            )
            .await?;
        }
    }

    Ok(())
}

async fn serve_split<DataServer, AdminServer>(
    data_server: DataServer,
    admin_server: AdminServer,
) -> std::io::Result<()>
where
    DataServer: Future<Output = std::io::Result<()>>,
    AdminServer: Future<Output = std::io::Result<()>>,
{
    tokio::try_join!(data_server, admin_server)?;
    Ok(())
}

pub(crate) async fn serve_router(
    listener: tokio::net::TcpListener,
    app: Router,
) -> std::io::Result<()> {
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
            occupied_addr,
            None,
            audit_log,
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
            data_addr,
            Some(admin_addr),
            audit::AuditLog::new(Arc::new(capture.clone())),
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
    async fn split_server_failure_cancels_peer_future() {
        struct DropSignal(Arc<AtomicBool>);

        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let peer_dropped = Arc::new(AtomicBool::new(false));
        let peer_guard = DropSignal(Arc::clone(&peer_dropped));
        let data_server = async { Err(std::io::Error::other("data server failed")) };
        let admin_server = async move {
            let _peer_guard = peer_guard;
            std::future::pending::<std::io::Result<()>>().await
        };

        let error = serve_split(data_server, admin_server)
            .await
            .expect_err("the first server failure should terminate split serving");

        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert!(
            peer_dropped.load(Ordering::SeqCst),
            "the still-running peer server future must be cancelled"
        );
    }

    #[tokio::test]
    async fn unified_startup_reports_actual_address_and_preserves_connect_info() {
        let capture = CaptureSink::new();
        let server = tokio::spawn(serve_gateway(
            GatewayApp::Unified(peer_router()),
            "127.0.0.1:0".parse().expect("listen address should parse"),
            None,
            audit::AuditLog::new(Arc::new(capture.clone())),
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
            "127.0.0.1:0".parse().expect("data address should parse"),
            Some("127.0.0.1:0".parse().expect("admin address should parse")),
            audit::AuditLog::new(Arc::new(capture.clone())),
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

    fn peer_router() -> Router {
        async fn peer(ConnectInfo(peer): ConnectInfo<SocketAddr>) -> String {
            peer.to_string()
        }

        Router::new().route("/", get(peer))
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
