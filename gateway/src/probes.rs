//! probes boundary extracted from the application composition root.
use super::*;

const SQLITE_READINESS_INTERVAL: Duration = Duration::from_secs(15);
const SQLITE_READINESS_MAX_AGE: Duration = Duration::from_secs(45);
const SQLITE_READINESS_BUSY_TIMEOUT: Duration = Duration::from_millis(500);

/// Background-only committed writes to security stores. HTTP probes only read
/// this cache, so probe frequency cannot create SQLite writes or grow its WAL.
pub(super) struct StandaloneStorageReadiness {
    result: Mutex<(bool, Instant)>,
}

impl StandaloneStorageReadiness {
    pub(super) fn start(
        config: &config::Config,
        lifecycle: &GatewayLifecycle,
    ) -> Option<Arc<Self>> {
        if config.state_backend != config::StateBackend::Sqlite {
            return None;
        }
        let mut paths: Vec<(&'static str, PathBuf)> = [
            ("service_tokens", config.service_token_sqlite_path.as_ref()),
            ("connections", config.connections_sqlite_path.as_ref()),
        ]
        .into_iter()
        .filter_map(|(kind, path)| path.map(|path| (kind, PathBuf::from(path))))
        .collect();
        if let Some(path) = policy_history_sqlite_path(config) {
            paths.push(("policy_history", path));
        }
        if paths.is_empty() {
            return None;
        }
        let state = Arc::new(Self {
            result: Mutex::new((Self::check_paths(&paths), Instant::now())),
        });
        let background = Arc::clone(&state);
        let cancellation = lifecycle.background_cancellation();
        lifecycle.register_background_task(tokio::spawn(async move {
            let mut interval = tokio::time::interval_at(
                tokio::time::Instant::now() + SQLITE_READINESS_INTERVAL,
                SQLITE_READINESS_INTERVAL,
            );
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => break,
                    _ = interval.tick() => background.check(paths.clone()).await,
                }
            }
        }));
        Some(state)
    }

    async fn check(&self, paths: Vec<(&'static str, PathBuf)>) {
        let healthy = tokio::task::spawn_blocking(move || Self::check_paths(&paths))
            .await
            .unwrap_or(false);
        let mut result = self
            .result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *result = (healthy, Instant::now());
    }

    fn check_paths(paths: &[(&'static str, PathBuf)]) -> bool {
        let mut healthy = true;
        for (kind, path) in paths {
            let result = check_sqlite_storage(path);
            ::metrics::counter!(
                metrics::SQLITE_STORAGE_CHECKS_TOTAL,
                "store" => *kind,
                "outcome" => if result.is_ok() { "success" } else { "failure" },
            )
            .increment(1);
            if let Err(error) = result {
                healthy = false;
                tracing::warn!(store = kind, error = %error, "SQLite security storage is unavailable");
            }
        }
        healthy
    }

    pub(super) fn blocked_reason(&self) -> Option<&'static str> {
        let result = self
            .result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (!result.0 || result.1.elapsed() > SQLITE_READINESS_MAX_AGE)
            .then_some("storage_unavailable")
    }

    fn publish_gauges(&self) {
        let result = self
            .result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ::metrics::gauge!(metrics::SQLITE_STORAGE_HEALTHY).set(
            if result.0 && result.1.elapsed() <= SQLITE_READINESS_MAX_AGE {
                1.0
            } else {
                0.0
            },
        );
        ::metrics::gauge!(metrics::SQLITE_STORAGE_CHECK_AGE_SECONDS)
            .set(result.1.elapsed().as_secs_f64());
    }
}

fn check_sqlite_storage(path: &FsPath) -> rusqlite::Result<()> {
    // Never CREATE a missing store: an empty replacement is not recovery.
    let mut connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    connection.busy_timeout(SQLITE_READINESS_BUSY_TIMEOUT)?;
    commit_storage_canary(&mut connection)
}

fn commit_storage_canary(connection: &mut rusqlite::Connection) -> rusqlite::Result<()> {
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS gateway_storage_canary (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            value INTEGER NOT NULL CHECK(value IN (0, 1))
         );
         INSERT INTO gateway_storage_canary(singleton, value) VALUES(1, 0)
         ON CONFLICT(singleton) DO UPDATE SET value = 1 - value;",
    )?;
    let expected: i64 = transaction.query_row(
        "SELECT value FROM gateway_storage_canary WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    transaction.commit()?;
    let committed: i64 = connection.query_row(
        "SELECT value FROM gateway_storage_canary WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    if committed != expected {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

pub(super) async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    record_request("/health");
    let upstream = match state.proxy.as_ref() {
        Some(proxy) => Some(proxy.upstream_health_response().await),
        None => None,
    };

    Json(HealthResponse {
        status: "ok",
        upstream,
    })
}

pub(super) async fn livez() -> impl IntoResponse {
    record_request("/livez");
    operational_response((
        StatusCode::OK,
        Json(ProbeResponse {
            status: "alive",
            reason: None,
        }),
    ))
}

pub(super) async fn startupz(State(state): State<AppState>) -> Response {
    record_request("/startupz");
    let response = if state.lifecycle.startup_complete() {
        (
            StatusCode::OK,
            Json(ProbeResponse {
                status: "started",
                reason: None,
            }),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ProbeResponse {
                status: "not_started",
                reason: Some("starting"),
            }),
        )
            .into_response()
    };
    operational_response(response)
}

/// Why this replica refuses readiness, or `None` when it does not.
///
/// The one definition of the reason chain, in the failure matrix's order.
/// `/readyz` is its caller of record; the cluster status API calls it too,
/// which is what makes that view's `state` and `reason` incapable of
/// disagreeing with the probe an orchestrator is acting on.
pub(super) async fn readiness_blocked_reason(
    lifecycle: &GatewayLifecycle,
    cluster_readiness: Option<&Arc<ha::ClusterReadiness>>,
    readiness_probe: Option<&Arc<ha_status::ReadinessProbe>>,
    standalone_storage_readiness: Option<&Arc<StandaloneStorageReadiness>>,
    proxy: Option<&ProxyState>,
) -> Option<&'static str> {
    if !lifecycle.accepting_work() {
        return Some(if lifecycle.draining() {
            "draining"
        } else {
            "starting"
        });
    }
    // Cluster mode: a replica whose static configuration disagrees
    // with a live member's is not ready however healthy it is locally
    // (HA state model invariant 14). The membership heartbeat
    // re-evaluates the gate and opens it once the members agree.
    if let Some(reason) = cluster_readiness.and_then(|readiness| readiness.blocked_reason()) {
        return Some(reason);
    }
    // Cluster mode's authority-backed reasons (issue #241, PR 14):
    // storage, schema, this replica's membership lease, and its
    // security watermark, in the failure matrix's order. The one
    // authority round trip is cached for READINESS_PROBE_CACHE_MS,
    // so a probe storm costs one check per window. Standalone mode
    // holds no probe and skips this arm entirely.
    if let Some(probe) = readiness_probe {
        if let Some(reason) = probe.blocked_reason().await {
            return Some(reason);
        }
    }
    if let Some(reason) = standalone_storage_readiness.and_then(|probe| probe.blocked_reason()) {
        return Some(reason);
    }
    if proxy.is_some_and(|proxy| !proxy.required_pools_ready()) {
        return Some("required_upstream_unavailable");
    }
    None
}

pub(super) async fn readyz(State(state): State<AppState>) -> Response {
    record_request("/readyz");
    let reason = readiness_blocked_reason(
        &state.lifecycle,
        state.cluster_readiness.as_ref(),
        state.readiness_probe.as_ref(),
        state.standalone_storage_readiness.as_ref(),
        state.proxy.as_ref(),
    )
    .await;
    let response = match reason {
        Some(reason) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ProbeResponse {
                status: "not_ready",
                reason: Some(reason),
            }),
        )
            .into_response(),
        None => (
            StatusCode::OK,
            Json(ProbeResponse {
                status: "ready",
                reason: None,
            }),
        )
            .into_response(),
    };
    operational_response(response)
}

pub(super) async fn version(State(state): State<AppState>) -> Json<VersionResponse> {
    record_request("/version");
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION"),
        admin_login_configured: state.admin_login_configured,
        admin_session: state.admin_session,
    })
}

pub(super) async fn metrics_endpoint(State(state): State<AppState>) -> impl IntoResponse {
    record_request("/metrics");
    publish_scrape_gauges(&state);
    operational_response((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.metrics_handle.render(),
    ))
}

fn operational_response(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    response
        .extensions_mut()
        .insert(middleware::observation::BuiltinOperationalEndpoint);
    response
}

/// Sample the process state that has no periodic owner, just before
/// rendering (issue #241, PR 14).
///
/// Two kinds of value need this. The audit writer's queue is drained by a
/// blocking thread, so a gauge published from the writer would only ever
/// record the moments it was awake -- the moments a backlog is shrinking.
/// The database pool's `Pool::status()` is a snapshot with no history, so
/// there is no event at which to publish it. Both are cheap reads of
/// atomics and a mutex, taken once per scrape; observing at scrape is
/// exactly the semantics a Prometheus gauge has anyway.
///
/// Everything else is published where it changes, by the task that owns
/// it, so a value that stops changing keeps its last true reading rather
/// than silently tracking whether anyone is scraping.
pub(super) fn publish_scrape_gauges(state: &AppState) {
    state.audit_log.publish_queue_gauges();
    // The lifecycle phase is republished here too: it is set on every
    // transition, but a process that boots and never becomes ready makes
    // no transition at all, and "never became ready" is the condition
    // most worth alerting on.
    state.lifecycle.publish_phase_gauges();
    if let Some(probe) = state.standalone_storage_readiness.as_ref() {
        probe.publish_gauges();
    }
    #[cfg(feature = "postgres")]
    if let Some(pool) = state.database_pool.as_ref() {
        storage::postgres::publish_pool_gauges(pool);
    }
}

pub(super) async fn oauth_protected_resource_metadata_endpoint(
    State(state): State<AppState>,
) -> Response {
    let Some(metadata) = state.protected_resource_metadata.as_ref() else {
        return not_found(
            "OAuth protected-resource metadata requires GATEWAY_PUBLIC_URL to be configured",
        );
    };

    Json(metadata.document()).into_response()
}

pub(super) async fn proxy_fallback(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    record_request(PROXY_FALLBACK_ROUTE);

    let path = request.uri().path();
    if path_match::is_unsafe_request_path(path) || state.routes.is_gateway_owned_path(path) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let Some(proxy) = state.proxy.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let source_ip = client_ip::canonical_client_ip(
        request.headers(),
        request.extensions(),
        &state.client_ip_policy,
    );

    let mut response = proxy.forward_request(request, &source_ip).await;
    // Proxy bodies are data, not trusted code on the gateway/admin origin.
    // A second enforced policy intersects with the upstream's policy.
    response.headers_mut().append(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("sandbox; frame-ancestors 'none'"),
    );
    response
}

pub(super) fn payload_too_large(max_body_size: usize) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(json!({
            "error": "payload too large",
            "max_body_size": max_body_size,
        })),
    )
        .into_response()
}

pub(super) fn record_request(route: &'static str) {
    ::metrics::counter!(REQUEST_COUNTER, "route" => route).increment(1);
}

pub(super) fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod storage_readiness_tests {
    use super::*;

    struct TestDatabase(PathBuf);

    impl TestDatabase {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "gateway-storage-check-{}.sqlite",
                uuid::Uuid::new_v4()
            ));
            rusqlite::Connection::open(&path).expect("create test database");
            Self(path)
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let _ = fs::remove_file(format!("{}{suffix}", self.0.display()));
            }
        }
    }

    #[tokio::test]
    async fn lock_failure_recovers_without_http_probes_writing() {
        let db = TestDatabase::new();
        let state = StandaloneStorageReadiness {
            result: Mutex::new((false, Instant::now())),
        };
        state.check(vec![("service_tokens", db.0.clone())]).await;
        assert_eq!(state.blocked_reason(), None);
        let connection = rusqlite::Connection::open(&db.0).expect("open test database");
        let before: i64 = connection
            .query_row("SELECT value FROM gateway_storage_canary", [], |row| {
                row.get(0)
            })
            .unwrap();
        connection.execute_batch("BEGIN IMMEDIATE").unwrap();
        for _ in 0..1000 {
            assert_eq!(state.blocked_reason(), None);
            state.publish_gauges();
        }
        let after: i64 = connection
            .query_row("SELECT value FROM gateway_storage_canary", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            before, after,
            "HTTP probe reads must not perform canary writes"
        );
        state.check(vec![("service_tokens", db.0.clone())]).await;
        assert_eq!(state.blocked_reason(), Some("storage_unavailable"));
        connection.execute_batch("ROLLBACK").unwrap();
        state.check(vec![("service_tokens", db.0.clone())]).await;
        assert_eq!(state.blocked_reason(), None);
    }

    #[test]
    fn read_only_and_full_databases_fail_real_committed_write_check() {
        let mut readonly = rusqlite::Connection::open_in_memory().unwrap();
        readonly.execute_batch("PRAGMA query_only = ON").unwrap();
        assert!(commit_storage_canary(&mut readonly).is_err());
        let mut full = rusqlite::Connection::open_in_memory().unwrap();
        full.execute_batch("PRAGMA max_page_count = 1").unwrap();
        let error = commit_storage_canary(&mut full).unwrap_err();
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DiskFull)
        );
    }

    #[tokio::test]
    async fn stale_check_and_missing_store_refuse_readiness() {
        let state = StandaloneStorageReadiness {
            result: Mutex::new((
                true,
                Instant::now() - SQLITE_READINESS_MAX_AGE - Duration::from_secs(1),
            )),
        };
        assert_eq!(state.blocked_reason(), Some("storage_unavailable"));
        let db = TestDatabase::new();
        fs::remove_file(&db.0).unwrap();
        state.check(vec![("service_tokens", db.0.clone())]).await;
        assert_eq!(state.blocked_reason(), Some("storage_unavailable"));
        assert!(
            !db.0.exists(),
            "a missing security store must never be recreated by the probe"
        );
    }
}

#[cfg(test)]
pub(super) async fn audit_extension_probe_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if req.extensions().get::<audit::AuditLog>().is_none() {
        return http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    next.run(req).await
}

#[cfg(test)]
pub(super) async fn principal_probe(
    principal: Option<Extension<auth::Principal>>,
) -> axum::response::Response {
    match principal {
        Some(Extension(principal)) => Json(json!({
            "user_id": principal.user_id,
            "roles": principal.roles,
            "auth_method": test_auth_method_label(&principal.auth_method),
        }))
        .into_response(),
        None => http::StatusCode::NO_CONTENT.into_response(),
    }
}

#[cfg(test)]
pub(super) fn test_auth_method_label(auth_method: &auth::AuthMethod) -> &'static str {
    match auth_method {
        auth::AuthMethod::Cookie => "session_cookie",
        auth::AuthMethod::Bearer => "bearer_token",
        auth::AuthMethod::ServiceToken => "service_token",
        auth::AuthMethod::ClientCertificate => "client_certificate",
    }
}
