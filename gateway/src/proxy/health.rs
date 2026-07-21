use std::{collections::HashSet, sync::Arc, time::Duration};

use http::Method;
use serde::Serialize;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::ProxyRoutes;
use crate::{egress, lifecycle::Clock};

const UPSTREAM_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum UpstreamHealthResponse {
    Single {
        configured: bool,
        reachable: Option<bool>,
        last_checked: Option<String>,
    },
    Routes {
        configured: bool,
        upstreams: Vec<UpstreamOriginHealthResponse>,
    },
}

#[derive(Serialize)]
pub(crate) struct UpstreamOriginHealthResponse {
    origin: String,
    reachable: Option<bool>,
    last_checked: Option<String>,
}

#[derive(Clone)]
pub(super) struct UpstreamHealthTarget {
    origin: String,
    egress_client: Arc<egress::EgressClient>,
    health: UpstreamHealthState,
}

#[derive(Clone)]
struct UpstreamHealthState {
    snapshot: Arc<tokio::sync::RwLock<UpstreamHealthSnapshot>>,
}

#[derive(Clone, Debug, Default)]
struct UpstreamHealthSnapshot {
    reachable: Option<bool>,
    last_checked: Option<OffsetDateTime>,
}

impl UpstreamHealthState {
    fn new() -> Self {
        Self {
            snapshot: Arc::new(tokio::sync::RwLock::new(UpstreamHealthSnapshot::default())),
        }
    }

    async fn response(&self) -> (Option<bool>, Option<String>) {
        let snapshot = self.snapshot.read().await.clone();

        (
            snapshot.reachable,
            snapshot.last_checked.map(rfc3339_timestamp),
        )
    }

    async fn update(&self, reachable: bool, checked_at: OffsetDateTime) {
        *self.snapshot.write().await = UpstreamHealthSnapshot {
            reachable: Some(reachable),
            last_checked: Some(checked_at),
        };
    }
}

pub(super) fn upstream_health_targets(
    upstream_origins: impl IntoIterator<Item = (String, Arc<egress::EgressClient>)>,
) -> Vec<UpstreamHealthTarget> {
    let mut seen = HashSet::new();
    let mut targets = Vec::new();

    for (origin, egress_client) in upstream_origins {
        if seen.insert(origin.clone()) {
            targets.push(UpstreamHealthTarget {
                origin,
                egress_client,
                health: UpstreamHealthState::new(),
            });
        }
    }

    targets
}

pub(super) async fn upstream_health_response(
    routes: &ProxyRoutes,
    upstream_health: &[UpstreamHealthTarget],
) -> UpstreamHealthResponse {
    match routes {
        ProxyRoutes::Legacy { .. } => {
            let target = upstream_health
                .first()
                .expect("legacy proxy state should have one upstream health target");
            let (reachable, last_checked) = target.health.response().await;

            UpstreamHealthResponse::Single {
                configured: true,
                reachable,
                last_checked,
            }
        }
        ProxyRoutes::RoutingTable { .. } => {
            let mut upstreams = Vec::with_capacity(upstream_health.len());
            for target in upstream_health {
                let (reachable, last_checked) = target.health.response().await;
                upstreams.push(UpstreamOriginHealthResponse {
                    origin: target.origin.clone(),
                    reachable,
                    last_checked,
                });
            }

            UpstreamHealthResponse::Routes {
                configured: true,
                upstreams,
            }
        }
    }
}

pub(super) fn spawn_upstream_health_checks(
    upstream_health: &[UpstreamHealthTarget],
    clock: Arc<dyn Clock>,
) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        tracing::warn!(
            "upstream reachability checks were not started because no Tokio runtime is active"
        );
        return;
    };

    for target in upstream_health {
        let health = target.health.clone();
        let egress_client = Arc::clone(&target.egress_client);
        let upstream_url = target.origin.clone();
        let clock = Arc::clone(&clock);

        handle.spawn(run_upstream_health_check_loop(
            health,
            egress_client,
            upstream_url,
            clock,
        ));
    }
}

async fn run_upstream_health_check_loop(
    health: UpstreamHealthState,
    egress_client: Arc<egress::EgressClient>,
    upstream_url: String,
    clock: Arc<dyn Clock>,
) {
    let mut first_check = true;
    let mut last_reachable = None;

    loop {
        let reachable = refresh_upstream_health(
            &health,
            &egress_client,
            &upstream_url,
            first_check,
            clock.as_ref(),
        )
        .await;

        if last_reachable == Some(false) && reachable {
            tracing::info!("upstream reachability restored");
        }

        last_reachable = Some(reachable);
        first_check = false;
        clock.sleep(UPSTREAM_HEALTH_CHECK_INTERVAL).await;
    }
}

async fn refresh_upstream_health(
    health: &UpstreamHealthState,
    egress_client: &egress::EgressClient,
    upstream_url: &str,
    first_check: bool,
    clock: &dyn Clock,
) -> bool {
    match check_upstream_reachable(egress_client, upstream_url).await {
        Ok(()) => {
            health.update(true, clock.now_utc()).await;
            true
        }
        Err(err) => {
            health.update(false, clock.now_utc()).await;
            if first_check {
                tracing::warn!(
                    error_category = err.safe_category(),
                    "startup upstream reachability check failed; continuing startup"
                );
            } else {
                tracing::warn!(
                    error_category = err.safe_category(),
                    "upstream reachability check failed"
                );
            }
            false
        }
    }
}

async fn check_upstream_reachable(
    egress_client: &egress::EgressClient,
    upstream_url: &str,
) -> Result<(), egress::EgressError> {
    egress_client
        .request(Method::HEAD, upstream_url)
        .await
        .map(|_| ())
}

fn rfc3339_timestamp(timestamp: OffsetDateTime) -> String {
    match timestamp.format(&Rfc3339) {
        Ok(value) => value,
        Err(_) => {
            tracing::warn!(
                error_category = "timestamp_format_failed",
                "failed to format upstream health timestamp"
            );
            timestamp.unix_timestamp().to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        io,
        net::SocketAddr,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use async_trait::async_trait;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::{mpsc, Semaphore},
    };
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

    struct StaticResolver {
        address: SocketAddr,
    }

    #[async_trait]
    impl egress::DnsResolver for StaticResolver {
        async fn resolve(
            &self,
            _host: &str,
            _port: u16,
        ) -> Result<Vec<SocketAddr>, std::io::Error> {
            Ok(vec![self.address])
        }
    }

    struct FakeClock {
        now: OffsetDateTime,
        sleeps: mpsc::UnboundedSender<Duration>,
        release: Arc<Semaphore>,
    }

    #[async_trait]
    impl Clock for FakeClock {
        fn now_utc(&self) -> OffsetDateTime {
            self.now
        }

        async fn sleep(&self, duration: Duration) {
            self.sleeps
                .send(duration)
                .expect("fake-clock receiver should remain open");
            self.release
                .acquire()
                .await
                .expect("fake-clock semaphore should remain open")
                .forget();
        }
    }

    #[tokio::test]
    async fn health_loop_checks_immediately_then_sleeps_thirty_seconds() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("health test server should bind");
        let address = listener
            .local_addr()
            .expect("health test address should be available");
        let (probes_tx, mut probes_rx) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let probes_tx = probes_tx.clone();
                tokio::spawn(async move {
                    let mut request = vec![0_u8; 1024];
                    let _ = stream.read(&mut request).await;
                    let _ = probes_tx.send(());
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                });
            }
        });
        let host = "health-clock.example.test";
        let client = Arc::new(
            egress::EgressClient::new_with_resolver(
                egress::EgressConfig {
                    allowed_hosts: HashSet::from([host.to_owned()]),
                    deny_private_ips: false,
                    ..egress::EgressConfig::default()
                },
                Arc::new(StaticResolver { address }),
            )
            .expect("health egress client should build"),
        );
        let health = UpstreamHealthState::new();
        let checked_at = OffsetDateTime::from_unix_timestamp(1_700_000_000)
            .expect("fake timestamp should be valid");
        let (sleeps_tx, mut sleeps_rx) = mpsc::unbounded_channel();
        let release = Arc::new(Semaphore::new(0));
        let clock: Arc<dyn Clock> = Arc::new(FakeClock {
            now: checked_at,
            sleeps: sleeps_tx,
            release: Arc::clone(&release),
        });
        let runner = tokio::spawn(run_upstream_health_check_loop(
            health.clone(),
            client,
            format!("http://{host}:{}/", address.port()),
            clock,
        ));

        tokio::time::timeout(Duration::from_secs(2), probes_rx.recv())
            .await
            .expect("first health check should be immediate")
            .expect("probe channel should stay open");
        assert_eq!(sleeps_rx.recv().await, Some(UPSTREAM_HEALTH_CHECK_INTERVAL));
        assert_eq!(
            health.response().await,
            (Some(true), Some(rfc3339_timestamp(checked_at)))
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), probes_rx.recv())
                .await
                .is_err(),
            "a second probe must wait for the requested sleep"
        );

        release.add_permits(1);
        tokio::time::timeout(Duration::from_secs(2), probes_rx.recv())
            .await
            .expect("releasing sleep should allow the second health check")
            .expect("probe channel should stay open");

        runner.abort();
        server.abort();
        let _ = runner.await;
        let _ = server.await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn health_and_egress_failure_logs_do_not_expose_destination_details() {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(logs.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let client = egress::EgressClient::new(egress::EgressConfig::default())
            .expect("egress client should build");
        let (sleeps_tx, _sleeps_rx) = mpsc::unbounded_channel();
        let clock = FakeClock {
            now: OffsetDateTime::UNIX_EPOCH,
            sleeps: sleeps_tx,
            release: Arc::new(Semaphore::new(0)),
        };

        let reachable = refresh_upstream_health(
            &UpstreamHealthState::new(),
            &client,
            "https://secret-upstream.example/private?token=secret-query",
            true,
            &clock,
        )
        .await;
        drop(_guard);

        assert!(!reachable);
        let output = logs.contents();
        assert!(output.contains("host_not_allowed"));
        for secret in ["secret-upstream", "private", "secret-query", "https://"] {
            assert!(
                !output.contains(secret),
                "captured health/egress log leaked {secret}: {output}"
            );
        }
    }

    #[derive(Clone, Default)]
    struct CapturedLogs {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl CapturedLogs {
        fn contents(&self) -> String {
            String::from_utf8(
                self.buffer
                    .lock()
                    .expect("captured logs should not be poisoned")
                    .clone(),
            )
            .expect("captured logs should be UTF-8")
        }
    }

    impl<'a> MakeWriter<'a> for CapturedLogs {
        type Writer = CapturedLogWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedLogWriter {
                buffer: Arc::clone(&self.buffer),
            }
        }
    }

    struct CapturedLogWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl io::Write for CapturedLogWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.buffer
                .lock()
                .map_err(|_| io::Error::other("captured logs lock poisoned"))?
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
