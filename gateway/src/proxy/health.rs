use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};

use http::Method;
use serde::Serialize;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::ProxyRoutes;
use crate::{
    audit, config, egress,
    lifecycle::{Clock, GatewayLifecycle},
};

const UPSTREAM_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);
const HEALTH_UNKNOWN: u8 = 0;
const HEALTHY: u8 = 1;
const UNHEALTHY: u8 = 2;

#[derive(Serialize)]
pub(crate) struct UpstreamHealthResponse {
    configured: bool,
    reachable: Option<bool>,
}

#[derive(Serialize)]
pub(crate) struct UpstreamHealthAdminResponse {
    pub(crate) ready: bool,
    pub(crate) pools: Vec<UpstreamPoolHealthAdminResponse>,
}

#[derive(Serialize)]
pub(crate) struct UpstreamPoolHealthAdminResponse {
    pool_id: String,
    required_for_readiness: bool,
    minimum_healthy: usize,
    eligible_endpoints: usize,
    total_endpoints: usize,
    ready: bool,
    endpoints: Vec<UpstreamEndpointHealthAdminResponse>,
}

#[derive(Serialize)]
pub(crate) struct UpstreamEndpointHealthAdminResponse {
    endpoint_id: String,
    state: &'static str,
    last_checked: Option<String>,
    last_failure_category: Option<String>,
    consecutive_successes: u32,
    consecutive_failures: u32,
}

#[derive(Clone)]
pub(super) struct UpstreamHealthTarget {
    pool_id: String,
    endpoint_id: String,
    origin: String,
    egress_client: Arc<egress::EgressClient>,
    health: UpstreamHealthState,
    config: Option<config::UpstreamHealthCheckConfig>,
}

#[derive(Clone)]
pub(super) struct UpstreamHealthState {
    eligibility: Arc<AtomicU8>,
    snapshot: Arc<tokio::sync::RwLock<UpstreamHealthSnapshot>>,
    identity: Arc<UpstreamHealthIdentity>,
    audit: Option<audit::AuditLog>,
}

#[derive(Clone, Debug, Default)]
struct UpstreamHealthSnapshot {
    last_checked: Option<OffsetDateTime>,
    last_failure_category: Option<String>,
    consecutive_successes: u32,
    consecutive_failures: u32,
}

#[derive(Debug)]
struct UpstreamHealthIdentity {
    pool_id: Arc<str>,
    endpoint_id: Arc<str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HealthTransition {
    Healthy,
    Unhealthy,
}

impl UpstreamHealthState {
    pub(super) fn new(
        pool_id: impl Into<Arc<str>>,
        endpoint_id: impl Into<Arc<str>>,
        audit: Option<audit::AuditLog>,
    ) -> Self {
        Self {
            eligibility: Arc::new(AtomicU8::new(HEALTH_UNKNOWN)),
            snapshot: Arc::new(tokio::sync::RwLock::new(UpstreamHealthSnapshot::default())),
            identity: Arc::new(UpstreamHealthIdentity {
                pool_id: pool_id.into(),
                endpoint_id: endpoint_id.into(),
            }),
            audit,
        }
    }

    pub(super) fn eligible(&self) -> bool {
        self.eligibility.load(Ordering::Acquire) == HEALTHY
    }

    fn state_name(&self) -> &'static str {
        health_state_name(self.eligibility.load(Ordering::Acquire))
    }

    async fn update(
        &self,
        succeeded: bool,
        observed_at: OffsetDateTime,
        active_check: bool,
        config: &config::UpstreamHealthCheckConfig,
        source: &'static str,
        failure_category: Option<&'static str>,
    ) -> Option<HealthTransition> {
        let healthy_threshold = config.healthy_threshold;
        let unhealthy_threshold = config.unhealthy_threshold;
        let mut snapshot = self.snapshot.write().await;
        if active_check {
            snapshot.last_checked = Some(observed_at);
        }
        let previous = self.eligibility.load(Ordering::Acquire);
        let transition = if succeeded {
            snapshot.consecutive_failures = 0;
            snapshot.consecutive_successes = snapshot.consecutive_successes.saturating_add(1);
            if snapshot.consecutive_successes >= healthy_threshold {
                snapshot.last_failure_category = None;
                (previous != HEALTHY).then_some(HealthTransition::Healthy)
            } else {
                None
            }
        } else {
            snapshot.last_failure_category = failure_category.map(str::to_owned);
            snapshot.consecutive_successes = 0;
            snapshot.consecutive_failures = snapshot.consecutive_failures.saturating_add(1);
            if snapshot.consecutive_failures >= unhealthy_threshold {
                (previous != UNHEALTHY).then_some(HealthTransition::Unhealthy)
            } else {
                None
            }
        };
        if let Some(transition) = transition {
            let next = match transition {
                HealthTransition::Healthy => HEALTHY,
                HealthTransition::Unhealthy => UNHEALTHY,
            };
            self.eligibility.store(next, Ordering::Release);
            drop(snapshot);
            self.emit_transition(transition, source, failure_category);
        }
        transition
    }

    pub(super) async fn record_passive_status(
        &self,
        status: u16,
        config: &config::UpstreamHealthCheckConfig,
    ) {
        let failed = config.passive_failure_statuses.contains(&status);
        let _ = self
            .update(
                !failed,
                OffsetDateTime::now_utc(),
                false,
                config,
                "passive",
                failed.then_some("upstream_status"),
            )
            .await;
    }

    pub(super) async fn record_passive_error(
        &self,
        error: &egress::EgressError,
        config: &config::UpstreamHealthCheckConfig,
    ) {
        if !error.is_passive_health_failure() {
            return;
        }
        let _ = self
            .update(
                false,
                OffsetDateTime::now_utc(),
                false,
                config,
                "passive",
                Some(error.safe_category()),
            )
            .await;
    }

    pub(super) async fn record_passive_proxy_error(
        &self,
        error: &egress::EgressError,
        config: &config::UpstreamHealthCheckConfig,
    ) {
        if error.is_timeout() {
            self.record_passive_timeout(config).await;
        } else {
            self.record_passive_error(error, config).await;
        }
    }

    pub(super) async fn record_passive_timeout(&self, config: &config::UpstreamHealthCheckConfig) {
        let _ = self
            .update(
                false,
                OffsetDateTime::now_utc(),
                false,
                config,
                "passive",
                Some("request_timeout"),
            )
            .await;
    }

    #[cfg(test)]
    pub(super) async fn last_failure_category(&self) -> Option<String> {
        self.snapshot.read().await.last_failure_category.clone()
    }

    #[cfg(test)]
    pub(super) fn mark_healthy_for_test(&self) {
        self.eligibility.store(HEALTHY, Ordering::Release);
    }

    fn emit_transition(
        &self,
        transition: HealthTransition,
        source: &'static str,
        failure_category: Option<&'static str>,
    ) {
        let state = match transition {
            HealthTransition::Healthy => "healthy",
            HealthTransition::Unhealthy => "unhealthy",
        };
        ::metrics::counter!(
            crate::metrics::UPSTREAM_HEALTH_TRANSITIONS_TOTAL,
            "pool_id" => Arc::clone(&self.identity.pool_id),
            "endpoint_id" => Arc::clone(&self.identity.endpoint_id),
            "state" => state,
            "source" => source,
        )
        .increment(1);
        match transition {
            HealthTransition::Healthy => tracing::info!(
                pool_id = self.identity.pool_id.as_ref(),
                endpoint_id = self.identity.endpoint_id.as_ref(),
                source,
                "upstream endpoint became healthy"
            ),
            HealthTransition::Unhealthy => tracing::warn!(
                pool_id = self.identity.pool_id.as_ref(),
                endpoint_id = self.identity.endpoint_id.as_ref(),
                source,
                error_category = failure_category.unwrap_or("unknown"),
                "upstream endpoint became unhealthy"
            ),
        }
        if let Some(audit) = self.audit.as_ref() {
            audit.emit(audit::AuditEvent::new(
                "upstream.health_state_changed",
                "health",
                "internal",
                None::<audit::Actor>,
                serde_json::json!({
                    "pool_id": self.identity.pool_id.as_ref(),
                    "endpoint_id": self.identity.endpoint_id.as_ref(),
                    "state": state,
                    "source": source,
                    "reason": failure_category.unwrap_or("none"),
                }),
            ));
        }
    }
}

pub(super) fn upstream_health_targets(
    upstream_origins: impl IntoIterator<
        Item = (
            String,
            String,
            String,
            Arc<egress::EgressClient>,
            UpstreamHealthState,
            Option<config::UpstreamHealthCheckConfig>,
        ),
    >,
) -> Vec<UpstreamHealthTarget> {
    let mut targets = Vec::new();

    for (pool_id, endpoint_id, origin, egress_client, health, config) in upstream_origins {
        targets.push(UpstreamHealthTarget {
            health,
            pool_id,
            endpoint_id,
            origin,
            egress_client,
            config,
        });
    }

    targets
}

pub(super) async fn upstream_health_response(
    routes: &ProxyRoutes,
    upstream_health: &[UpstreamHealthTarget],
) -> UpstreamHealthResponse {
    let _ = routes;
    let states = upstream_health
        .iter()
        .map(|target| target.health.eligibility.load(Ordering::Acquire))
        .collect::<Vec<_>>();
    let reachable = if states.iter().all(|state| *state == HEALTHY) {
        Some(true)
    } else if states.contains(&UNHEALTHY) {
        Some(false)
    } else {
        None
    };
    UpstreamHealthResponse {
        configured: true,
        reachable,
    }
}

pub(super) async fn upstream_health_admin_response(
    upstream_health: &[UpstreamHealthTarget],
) -> UpstreamHealthAdminResponse {
    let mut pools = BTreeMap::<String, UpstreamPoolHealthAdminResponse>::new();
    for target in upstream_health {
        let snapshot = target.health.snapshot.read().await.clone();
        let config = target.config.as_ref();
        let pool = pools.entry(target.pool_id.clone()).or_insert_with(|| {
            UpstreamPoolHealthAdminResponse {
                pool_id: target.pool_id.clone(),
                required_for_readiness: config.is_some_and(|config| config.required_for_readiness),
                minimum_healthy: config.map_or(0, |config| config.minimum_healthy),
                eligible_endpoints: 0,
                total_endpoints: 0,
                ready: true,
                endpoints: Vec::new(),
            }
        });
        pool.total_endpoints = pool.total_endpoints.saturating_add(1);
        if target.health.eligible() {
            pool.eligible_endpoints = pool.eligible_endpoints.saturating_add(1);
        }
        pool.endpoints.push(UpstreamEndpointHealthAdminResponse {
            endpoint_id: target.endpoint_id.clone(),
            state: target.health.state_name(),
            last_checked: snapshot.last_checked.map(rfc3339_timestamp),
            last_failure_category: snapshot.last_failure_category,
            consecutive_successes: snapshot.consecutive_successes,
            consecutive_failures: snapshot.consecutive_failures,
        });
    }
    let mut pools = pools.into_values().collect::<Vec<_>>();
    for pool in &mut pools {
        pool.ready =
            !pool.required_for_readiness || pool.eligible_endpoints >= pool.minimum_healthy;
    }
    UpstreamHealthAdminResponse {
        ready: pools.iter().all(|pool| pool.ready),
        pools,
    }
}

pub(super) fn required_pools_ready(upstream_health: &[UpstreamHealthTarget]) -> bool {
    let mut pools = BTreeMap::<&str, (usize, usize)>::new();
    for target in upstream_health {
        let Some(config) = target
            .config
            .as_ref()
            .filter(|config| config.required_for_readiness)
        else {
            continue;
        };
        let pool = pools
            .entry(target.pool_id.as_str())
            .or_insert((config.minimum_healthy, 0));
        if target.health.eligible() {
            pool.1 = pool.1.saturating_add(1);
        }
    }
    pools
        .into_values()
        .all(|(minimum_healthy, eligible)| eligible >= minimum_healthy)
}

#[derive(Clone, Default)]
pub(super) struct UpstreamHealthRuntime {
    inner: Arc<UpstreamHealthRuntimeInner>,
}

#[derive(Default)]
struct UpstreamHealthRuntimeInner {
    cancellation: CancellationToken,
}

impl Drop for UpstreamHealthRuntimeInner {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl UpstreamHealthRuntime {
    pub(super) fn spawn(
        &self,
        upstream_health: &[UpstreamHealthTarget],
        clock: Arc<dyn Clock>,
        lifecycle: &GatewayLifecycle,
    ) {
        let handles = spawn_upstream_health_checks(
            upstream_health,
            clock,
            self.inner.cancellation.clone(),
            lifecycle.background_cancellation(),
        );
        for handle in handles {
            lifecycle.register_background_task(handle);
        }
    }
}

fn spawn_upstream_health_checks(
    upstream_health: &[UpstreamHealthTarget],
    clock: Arc<dyn Clock>,
    cancellation: CancellationToken,
    lifecycle_cancellation: CancellationToken,
) -> Vec<JoinHandle<()>> {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        tracing::warn!(
            "upstream reachability checks were not started because no Tokio runtime is active"
        );
        return Vec::new();
    };

    let mut handles = Vec::with_capacity(upstream_health.len());
    for target in upstream_health {
        let health = target.health.clone();
        let egress_client = Arc::clone(&target.egress_client);
        let upstream_url = target.origin.clone();
        let config = target.config.clone();
        let clock = Arc::clone(&clock);
        let cancellation = cancellation.clone();
        let lifecycle_cancellation = lifecycle_cancellation.clone();

        handles.push(handle.spawn(run_upstream_health_check_loop(
            health,
            egress_client,
            upstream_url,
            config,
            clock,
            cancellation,
            lifecycle_cancellation,
        )));
    }
    handles
}

async fn run_upstream_health_check_loop(
    health: UpstreamHealthState,
    egress_client: Arc<egress::EgressClient>,
    upstream_url: String,
    config: Option<config::UpstreamHealthCheckConfig>,
    clock: Arc<dyn Clock>,
    cancellation: CancellationToken,
    lifecycle_cancellation: CancellationToken,
) {
    loop {
        let refresh = refresh_upstream_health(
            &health,
            &egress_client,
            &upstream_url,
            config.as_ref(),
            clock.as_ref(),
        );
        tokio::select! {
            () = refresh => {}
            () = cancellation.cancelled() => return,
            () = lifecycle_cancellation.cancelled() => return,
        }
        let interval = config
            .as_ref()
            .map_or(UPSTREAM_HEALTH_CHECK_INTERVAL, |config| {
                jittered_interval(config.interval_ms, config.jitter_ms, random_u64())
            });
        tokio::select! {
            () = clock.sleep(interval) => {}
            () = cancellation.cancelled() => return,
            () = lifecycle_cancellation.cancelled() => return,
        }
    }
}

async fn refresh_upstream_health(
    health: &UpstreamHealthState,
    egress_client: &egress::EgressClient,
    upstream_url: &str,
    config: Option<&config::UpstreamHealthCheckConfig>,
    clock: &dyn Clock,
) {
    let check = check_upstream_reachable(egress_client, upstream_url, config);
    let result = if let Some(config) = config {
        tokio::time::timeout(Duration::from_millis(config.timeout_ms), check)
            .await
            .unwrap_or(Err(egress::EgressError::ResponseIdleTimeout {
                timeout: Duration::from_millis(config.timeout_ms),
            }))
    } else {
        check.await
    };
    match result {
        Ok(()) => {
            if let Some(config) = config {
                let _ = health
                    .update(true, clock.now_utc(), true, config, "active", None)
                    .await;
            } else {
                let compatibility = compatibility_health_config();
                let _ = health
                    .update(true, clock.now_utc(), true, &compatibility, "active", None)
                    .await;
            }
        }
        Err(err) => {
            if let Some(config) = config {
                let _ = health
                    .update(
                        false,
                        clock.now_utc(),
                        true,
                        config,
                        "active",
                        Some(err.safe_category()),
                    )
                    .await;
            } else {
                let compatibility = compatibility_health_config();
                let _ = health
                    .update(
                        false,
                        clock.now_utc(),
                        true,
                        &compatibility,
                        "active",
                        Some(err.safe_category()),
                    )
                    .await;
            }
        }
    }
}

fn compatibility_health_config() -> config::UpstreamHealthCheckConfig {
    config::UpstreamHealthCheckConfig {
        method: "HEAD".to_owned(),
        path: "/".to_owned(),
        interval_ms: UPSTREAM_HEALTH_CHECK_INTERVAL.as_millis() as u64,
        jitter_ms: 0,
        timeout_ms: 1_000,
        healthy_threshold: 1,
        unhealthy_threshold: 1,
        expected_statuses: (100..=599).collect(),
        passive_failure_statuses: Vec::new(),
        required_for_readiness: false,
        minimum_healthy: 1,
    }
}

fn random_u64() -> u64 {
    let mut bytes = [0_u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return 0;
    }
    u64::from_le_bytes(bytes)
}

fn jittered_interval(interval_ms: u64, jitter_ms: u64, sample: u64) -> Duration {
    if jitter_ms == 0 {
        return Duration::from_millis(interval_ms);
    }
    let span = jitter_ms.saturating_mul(2).saturating_add(1);
    let offset = sample % span;
    Duration::from_millis(interval_ms - jitter_ms + offset)
}

async fn check_upstream_reachable(
    egress_client: &egress::EgressClient,
    upstream_url: &str,
    config: Option<&config::UpstreamHealthCheckConfig>,
) -> Result<(), egress::EgressError> {
    let method = config
        .and_then(|config| config.method.parse().ok())
        .unwrap_or(Method::HEAD);
    let url = config.map_or_else(
        || upstream_url.to_owned(),
        |config| format!("{upstream_url}{}", config.path),
    );
    egress_client
        .request(method, &url)
        .await
        .and_then(|response| {
            if config
                .is_none_or(|config| config.expected_statuses.contains(&response.status.as_u16()))
            {
                Ok(())
            } else {
                Err(egress::EgressError::UnexpectedStatus(
                    response.status.as_u16(),
                ))
            }
        })
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

fn health_state_name(state: u8) -> &'static str {
    match state {
        HEALTHY => "healthy",
        UNHEALTHY => "unhealthy",
        _ => "unknown",
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
    use crate::audit::{sink::tests::CaptureSink, AuditSink};

    fn test_health_config() -> config::UpstreamHealthCheckConfig {
        config::UpstreamHealthCheckConfig {
            method: "GET".to_owned(),
            path: "/ready".to_owned(),
            interval_ms: 100,
            jitter_ms: 0,
            timeout_ms: 50,
            healthy_threshold: 2,
            unhealthy_threshold: 2,
            expected_statuses: vec![200],
            passive_failure_statuses: vec![500, 502, 503, 504],
            required_for_readiness: true,
            minimum_healthy: 1,
        }
    }

    #[tokio::test]
    async fn configured_health_uses_thresholds_for_exclusion_and_recovery() {
        let health = UpstreamHealthState::new("payments", "primary", None);
        let config = test_health_config();
        let now = OffsetDateTime::UNIX_EPOCH;

        assert!(!health.eligible());
        health
            .update(true, now, true, &config, "active", None)
            .await;
        assert!(!health.eligible());
        health
            .update(true, now, true, &config, "active", None)
            .await;
        assert!(health.eligible());
        health
            .update(false, now, true, &config, "active", Some("http_connect"))
            .await;
        assert!(health.eligible());
        health
            .update(false, now, true, &config, "active", Some("http_connect"))
            .await;
        assert!(!health.eligible());
        health
            .update(true, now, true, &config, "active", None)
            .await;
        health
            .update(true, now, true, &config, "active", None)
            .await;
        assert!(health.eligible());
    }

    #[test]
    fn configured_jitter_stays_within_centered_bounds() {
        assert_eq!(
            jittered_interval(1_000, 0, u64::MAX),
            Duration::from_millis(1_000)
        );
        assert_eq!(jittered_interval(1_000, 100, 0), Duration::from_millis(900));
        assert_eq!(
            jittered_interval(1_000, 100, 200),
            Duration::from_millis(1_100)
        );
        for sample in [1, 7, 99, 1_000, u64::MAX] {
            let interval = jittered_interval(1_000, 100, sample);
            assert!((Duration::from_millis(900)..=Duration::from_millis(1_100)).contains(&interval));
        }
    }

    #[tokio::test]
    async fn passive_statuses_apply_thresholds_and_ignore_client_4xx() {
        let health = UpstreamHealthState::new("payments", "primary", None);
        let mut config = test_health_config();
        config.healthy_threshold = 1;
        health
            .update(
                true,
                OffsetDateTime::UNIX_EPOCH,
                true,
                &config,
                "active",
                None,
            )
            .await;
        assert!(health.eligible());

        health.record_passive_status(503, &config).await;
        assert!(health.eligible());
        health.record_passive_status(404, &config).await;
        assert!(health.eligible());
        health.record_passive_status(503, &config).await;
        health.record_passive_status(503, &config).await;
        assert!(!health.eligible());
        assert_eq!(
            health
                .snapshot
                .read()
                .await
                .last_failure_category
                .as_deref(),
            Some("upstream_status")
        );
    }

    #[tokio::test]
    async fn audit_is_emitted_once_per_transition_with_bounded_identity() {
        let capture = CaptureSink::new();
        let audit = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let health = UpstreamHealthState::new("payments", "primary", Some(audit));
        let config = test_health_config();

        health
            .update(
                true,
                OffsetDateTime::UNIX_EPOCH,
                true,
                &config,
                "active",
                None,
            )
            .await;
        health
            .update(
                true,
                OffsetDateTime::UNIX_EPOCH,
                true,
                &config,
                "active",
                None,
            )
            .await;
        health
            .update(
                true,
                OffsetDateTime::UNIX_EPOCH,
                true,
                &config,
                "active",
                None,
            )
            .await;
        health
            .update(
                false,
                OffsetDateTime::UNIX_EPOCH,
                true,
                &config,
                "active",
                Some("http_connect"),
            )
            .await;
        health
            .update(
                false,
                OffsetDateTime::UNIX_EPOCH,
                true,
                &config,
                "active",
                Some("http_connect"),
            )
            .await;

        let events = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let events = capture.events();
                if events.len() == 2 {
                    break events;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("transition audit events should be emitted");
        assert_eq!(
            events
                .iter()
                .map(|event| event.event_type.as_str())
                .collect::<Vec<_>>(),
            vec![
                "upstream.health_state_changed",
                "upstream.health_state_changed"
            ]
        );
        assert_eq!(events[0].payload["state"], "healthy");
        assert_eq!(events[1].payload["state"], "unhealthy");
        assert_eq!(events[1].payload["pool_id"], "payments");
        assert_eq!(events[1].payload["endpoint_id"], "primary");
        assert_eq!(events[1].payload["reason"], "http_connect");
        let serialized = serde_json::to_string(&events).expect("events should serialize");
        assert!(!serialized.contains("://"));
    }

    #[tokio::test]
    async fn readiness_uses_cached_required_pool_capacity_without_topology() {
        let client = Arc::new(
            egress::EgressClient::new(egress::EgressConfig::default())
                .expect("test client should build"),
        );
        let mut config = test_health_config();
        config.healthy_threshold = 1;
        config.minimum_healthy = 2;
        let first = UpstreamHealthState::new("payments", "first", None);
        let second = UpstreamHealthState::new("payments", "second", None);
        let targets = upstream_health_targets([
            (
                "payments".to_owned(),
                "first".to_owned(),
                "https://first.internal".to_owned(),
                Arc::clone(&client),
                first.clone(),
                Some(config.clone()),
            ),
            (
                "payments".to_owned(),
                "second".to_owned(),
                "https://second.internal".to_owned(),
                client,
                second.clone(),
                Some(config.clone()),
            ),
        ]);

        first
            .update(
                true,
                OffsetDateTime::UNIX_EPOCH,
                true,
                &config,
                "active",
                None,
            )
            .await;
        let status = upstream_health_admin_response(&targets).await;
        assert!(!status.ready);
        assert!(!required_pools_ready(&targets));
        assert_eq!(status.pools[0].eligible_endpoints, 1);
        assert_eq!(status.pools[0].minimum_healthy, 2);

        second
            .update(
                true,
                OffsetDateTime::UNIX_EPOCH,
                true,
                &config,
                "active",
                None,
            )
            .await;
        let status = upstream_health_admin_response(&targets).await;
        assert!(status.ready);
        assert!(required_pools_ready(&targets));
        assert_eq!(status.pools[0].eligible_endpoints, 2);
        let serialized = serde_json::to_string(&status).expect("status should serialize");
        assert!(!serialized.contains("first.internal"));
        assert!(!serialized.contains("second.internal"));
    }

    #[test]
    fn readiness_ignores_non_required_pools() {
        let client = Arc::new(
            egress::EgressClient::new(egress::EgressConfig::default())
                .expect("test client should build"),
        );
        let mut config = test_health_config();
        config.required_for_readiness = false;
        config.minimum_healthy = 2;
        let targets = upstream_health_targets([(
            "analytics".to_owned(),
            "optional".to_owned(),
            "https://analytics.internal".to_owned(),
            client,
            UpstreamHealthState::new("analytics", "optional", None),
            Some(config),
        )]);

        assert!(required_pools_ready(&targets));
    }

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
        let health = UpstreamHealthState::new("legacy", "primary", None);
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
            None,
            clock,
            CancellationToken::new(),
            CancellationToken::new(),
        ));

        tokio::time::timeout(Duration::from_secs(2), probes_rx.recv())
            .await
            .expect("first health check should be immediate")
            .expect("probe channel should stay open");
        assert_eq!(sleeps_rx.recv().await, Some(UPSTREAM_HEALTH_CHECK_INTERVAL));
        assert_eq!(health.state_name(), "healthy");
        assert_eq!(health.snapshot.read().await.last_checked, Some(checked_at));
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

    #[tokio::test]
    async fn cancellation_interrupts_an_in_flight_health_probe() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("health test server should bind");
        let address = listener.local_addr().expect("test address");
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("probe should connect");
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await;
            let _ = accepted_tx.send(());
            std::future::pending::<()>().await;
        });
        let host = "health-cancel.example.test";
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
        let mut config = test_health_config();
        config.interval_ms = 10_000;
        config.timeout_ms = 5_000;
        let (sleeps_tx, _sleeps_rx) = mpsc::unbounded_channel();
        let clock: Arc<dyn Clock> = Arc::new(FakeClock {
            now: OffsetDateTime::UNIX_EPOCH,
            sleeps: sleeps_tx,
            release: Arc::new(Semaphore::new(0)),
        });
        let cancellation = CancellationToken::new();
        let runner = tokio::spawn(run_upstream_health_check_loop(
            UpstreamHealthState::new("payments", "primary", None),
            client,
            format!("http://{host}:{}", address.port()),
            Some(config),
            clock,
            cancellation.clone(),
            CancellationToken::new(),
        ));

        tokio::time::timeout(Duration::from_secs(2), accepted_rx)
            .await
            .expect("probe should start")
            .expect("probe acceptance should be signaled");
        cancellation.cancel();
        tokio::time::timeout(Duration::from_millis(250), runner)
            .await
            .expect("cancellation should stop the in-flight probe")
            .expect("health loop should exit cleanly");
        server.abort();
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
        let _guard = crate::tracing_test_guard(subscriber);
        let client = egress::EgressClient::new(egress::EgressConfig::default())
            .expect("egress client should build");
        let (sleeps_tx, _sleeps_rx) = mpsc::unbounded_channel();
        let clock = FakeClock {
            now: OffsetDateTime::UNIX_EPOCH,
            sleeps: sleeps_tx,
            release: Arc::new(Semaphore::new(0)),
        };

        let health = UpstreamHealthState::new("legacy", "primary", None);
        refresh_upstream_health(
            &health,
            &client,
            "https://secret-upstream.example/private?token=secret-query",
            None,
            &clock,
        )
        .await;
        drop(_guard);

        assert_eq!(health.state_name(), "unhealthy");
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
