//! probes boundary extracted from the application composition root.
use super::*;

/// One-shot container probe. Never follows redirects, uses a proxy, initializes
/// gateway state, or accepts an arbitrary destination. HTTPS uses normal trust
/// validation; there is intentionally no insecure certificate bypass.
pub(super) async fn check_local_health(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let url = reqwest::Url::parse(url)?;
    let loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    };
    if !loopback
        || !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "/livez" | "/readyz" | "/startupz")
    {
        return Err("probe URL must name a loopback IP and /livez, /readyz or /startupz".into());
    }
    let response = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(2))
        .build()?
        .get(url)
        .send()
        .await?;
    if response.status() != StatusCode::OK {
        return Err(format!("probe returned HTTP {}", response.status()).into());
    }
    Ok(())
}

#[cfg(test)]
mod healthcheck_tests {
    use super::*;

    #[tokio::test]
    async fn only_successful_probe_status_passes() {
        for status in [
            StatusCode::OK,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::FOUND,
            StatusCode::NO_CONTENT,
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let app = Router::new()
                .route(
                    "/readyz",
                    get(move || async move { (status, [(header::LOCATION, "/livez")]) }),
                )
                .route("/livez", get(|| async { StatusCode::OK }));
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let result = check_local_health(&format!("http://{address}/readyz")).await;
            server.abort();
            assert_eq!(result.is_ok(), status == StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn rejects_non_probe_destinations() {
        for url in [
            "http://example.invalid/readyz",
            "http://localhost/readyz",
            "http://192.0.2.1/readyz",
            "http://127.0.0.1/admin",
            "http://user:password@127.0.0.1/readyz",
            "http://127.0.0.1/readyz?x=1",
            "http://127.0.0.1/readyz#fragment",
            "ftp://127.0.0.1/readyz",
        ] {
            assert!(check_local_health(url).await.is_err(), "{url}");
        }
    }

    #[tokio::test]
    async fn fails_when_listener_is_unavailable_or_stalls() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/livez", listener.local_addr().unwrap());
        // An open listener that never responds must not hang the Docker probe.
        let started = Instant::now();
        assert!(check_local_health(&url).await.is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(listener);
        assert!(check_local_health(&url).await.is_err());
    }
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
    (
        StatusCode::OK,
        Json(ProbeResponse {
            status: "alive",
            reason: None,
        }),
    )
}

pub(super) async fn startupz(State(state): State<AppState>) -> Response {
    record_request("/startupz");
    if state.lifecycle.startup_complete() {
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
    }
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
        state.proxy.as_ref(),
    )
    .await;
    match reason {
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
    }
}

pub(super) async fn version(State(state): State<AppState>) -> Json<VersionResponse> {
    record_request("/version");
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION"),
        admin_login_configured: state.admin_login_configured,
    })
}

pub(super) async fn metrics_endpoint(State(state): State<AppState>) -> impl IntoResponse {
    record_request("/metrics");
    publish_scrape_gauges(&state);
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.metrics_handle.render(),
    )
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
