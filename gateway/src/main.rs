use std::{
    collections::HashSet,
    convert::Infallible,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{Path, Query, State},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{any, get},
    Extension, Json, Router,
};
use futures_util::{stream, Stream, StreamExt};
use http::{header, HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tower_http::{
    cors::CorsLayer,
    request_id::{MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    trace::TraceLayer,
};
use url::Url;

mod audit;
mod auth;
mod client_ip;
mod config;
mod egress;
mod metrics;
mod middleware;
mod path_match;
mod rbac;

const REQUEST_COUNTER: &str = "gateway_http_requests";
const REQUEST_ID_HEADER: &str = "x-request-id";
const ADMIN_UI_ROUTE: &str = "/admin";
const ADMIN_UI_INDEX: &str = "index.html";
const ADMIN_UI_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
const DEFAULT_ADMIN_API_PREFIX: &str = "/v1/admin";
const AUDIT_ADMIN_ROUTE: &str = "/v1/admin/audit";
const AUDIT_EVENTS_STREAM_ROUTE: &str = "/v1/admin/events/stream";
const STATUS_ADMIN_ROUTE: &str = "/v1/admin/status";
const AUDIT_ADMIN_ROLE: &str = "admin";
const PROXY_FALLBACK_ROUTE: &str = "proxy_fallback";
const GATEWAY_OWNED_EXACT_PATHS: &[&str] = &["/health", "/version", "/metrics"];
const DEFAULT_AUDIT_QUERY_LIMIT: usize = 50;
const MAX_AUDIT_QUERY_LIMIT: usize = 500;
const UPSTREAM_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);

#[derive(rust_embed::RustEmbed)]
#[folder = "../admin-ui/dist/"]
struct AdminUiAssets;

#[derive(Clone)]
struct AppState {
    metrics_handle: PrometheusHandle,
    proxy: Option<ProxyState>,
    routes: GatewayRoutes,
}

#[derive(Clone)]
struct ProxyState {
    routes: ProxyRoutes,
    upstream_health: Vec<UpstreamHealthTarget>,
    egress_client: Arc<egress::EgressClient>,
    max_request_body_bytes: usize,
}

#[derive(Clone)]
enum ProxyRoutes {
    Legacy { upstream_origin: String },
    RoutingTable { routes: Vec<ProxyRoute> },
}

#[derive(Clone, Debug)]
struct ProxyRoute {
    path_prefix: Option<String>,
    host: Option<String>,
    upstream_origin: String,
}

#[derive(Clone)]
struct UpstreamHealthTarget {
    origin: String,
    health: UpstreamHealthState,
}

#[derive(Clone, Debug)]
struct GatewayRoutes {
    admin: AdminRoutes,
    exact_owned_paths: Vec<String>,
    prefix_owned_paths: Vec<String>,
}

#[derive(Clone, Debug)]
struct AdminRoutes {
    ui_prefix: String,
    ui_slash_route: String,
    ui_asset_route: String,
    api_prefix: String,
    audit_route: String,
    events_stream_route: String,
    status_route: String,
}

impl GatewayRoutes {
    fn from_config(config: &config::Config) -> Self {
        let admin = AdminRoutes::from_prefix(&config.admin_prefix);
        let exact_owned_paths = GATEWAY_OWNED_EXACT_PATHS
            .iter()
            .map(|path| (*path).to_owned())
            .collect();
        let mut prefix_owned_paths = vec![admin.ui_prefix.clone(), admin.api_prefix.clone()];
        prefix_owned_paths.sort();
        prefix_owned_paths.dedup();
        // Add the future /mcp control-plane prefix here when the Phase 6 route
        // lands; do not reserve it with a fabricated route before then.

        Self {
            admin,
            exact_owned_paths,
            prefix_owned_paths,
        }
    }

    fn is_gateway_owned_path(&self, path: &str) -> bool {
        self.exact_owned_paths.iter().any(|owned| path == owned)
            || self
                .prefix_owned_paths
                .iter()
                .any(|owned| path_match::path_prefix_matches(path, owned))
    }
}

impl AdminRoutes {
    fn from_prefix(admin_prefix: &str) -> Self {
        let api_prefix = format!("/v1{admin_prefix}");
        debug_assert!(
            admin_prefix != config::DEFAULT_ADMIN_PREFIX || api_prefix == DEFAULT_ADMIN_API_PREFIX
        );

        Self {
            ui_prefix: admin_prefix.to_owned(),
            ui_slash_route: format!("{admin_prefix}/"),
            ui_asset_route: format!("{admin_prefix}/{{*path}}"),
            audit_route: format!("{api_prefix}/audit"),
            events_stream_route: format!("{api_prefix}/events/stream"),
            status_route: format!("{api_prefix}/status"),
            api_prefix,
        }
    }
}

#[derive(Clone)]
struct AuditAdminState {
    query_store: Option<Arc<audit::query::AuditQueryStore>>,
    event_sender: audit::AuditEventSender,
}

#[derive(Clone)]
struct StatusAdminState {
    config: config::Config,
    rbac: RbacStatus,
    egress_allowed_hosts_count: usize,
    process_started_at: Instant,
}

#[derive(Clone, Copy, Debug)]
struct MakeRequestUuid;

impl MakeRequestId for MakeRequestUuid {
    fn make_request_id<B>(&mut self, _request: &Request<B>) -> Option<RequestId> {
        let id = uuid::Uuid::new_v4().to_string();
        id.parse().ok().map(RequestId::new)
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream: Option<UpstreamHealthResponse>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum UpstreamHealthResponse {
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
struct UpstreamOriginHealthResponse {
    origin: String,
    reachable: Option<bool>,
    last_checked: Option<String>,
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

#[derive(Serialize)]
struct VersionResponse {
    version: &'static str,
}

#[derive(Clone, Serialize)]
struct RbacStatus {
    policy_loaded: bool,
    policy_id: Option<String>,
}

#[derive(Serialize)]
struct AuditSinksStatus {
    stdout: bool,
    file: bool,
    sqlite: bool,
    broadcast: bool,
}

#[derive(Serialize)]
struct RateLimitStatus {
    requests_per_second: f64,
    burst: u32,
}

#[derive(Serialize)]
struct RateLimitsStatus {
    read: RateLimitStatus,
    write: RateLimitStatus,
}

#[derive(Serialize)]
struct EgressStatus {
    allowed_hosts_count: usize,
    deny_private_ips: bool,
}

#[derive(Serialize)]
struct StatusResponse {
    version: &'static str,
    uptime_seconds: u64,
    listen_addr: String,
    auth_enabled: bool,
    rbac: RbacStatus,
    audit_sinks: AuditSinksStatus,
    rate_limits: RateLimitsStatus,
    cors_allow_origins: Vec<String>,
    trust_proxy_headers: bool,
    csrf_enabled: bool,
    egress: EgressStatus,
}

#[derive(Deserialize)]
struct AuditQueryParams {
    from: Option<String>,
    to: Option<String>,
    event_type: Option<String>,
    actor: Option<String>,
    path: Option<String>,
    status: Option<String>,
    limit: Option<String>,
    before_id: Option<String>,
}

#[derive(Clone, Deserialize)]
struct AuditEventStreamParams {
    event_type: Option<String>,
    path: Option<String>,
}

#[derive(Serialize)]
struct AuditQueryResponse {
    events: Vec<audit::AuditEvent>,
    next_cursor: Option<i64>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

enum GatewayApp {
    Unified(Router),
    Split { data: Router, admin: Router },
}

#[derive(Clone)]
struct MiddlewareStack {
    config: config::Config,
    audit_log: audit::AuditLog,
    csrf_config: middleware::csrf::CsrfConfig,
    rate_limit_state: middleware::rate_limit::RateLimitState,
    observation_state: middleware::observation::ObservationState,
    rbac_state: Option<middleware::rbac::RbacState>,
    auth_state: Option<middleware::auth::AuthState>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let process_started_at = Instant::now();

    tracing_subscriber::fmt()
        .with_target(false)
        .compact()
        .init();

    let config = match config::Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let metrics_handle = install_metrics_recorder()?;
    let listen_addr = config.listen_addr;
    let admin_listen_addr = config.admin_listen_addr;
    let (audit_log, audit_event_sender) = audit::AuditLog::from_config(&config)?;
    let app = gateway_app_with_process_started_at(
        config,
        metrics_handle,
        audit_log.clone(),
        audit_event_sender,
        process_started_at,
    )?;

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
            tokio::try_join!(
                serve_router(data_listener, data),
                serve_router(admin_listener, admin)
            )?;
        }
    }

    Ok(())
}

async fn serve_router(listener: tokio::net::TcpListener, app: Router) -> std::io::Result<()> {
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

#[cfg(test)]
fn app(
    config: config::Config,
    metrics_handle: PrometheusHandle,
    audit_log: audit::AuditLog,
    audit_event_sender: audit::AuditEventSender,
) -> Result<Router, Box<dyn std::error::Error>> {
    app_with_process_started_at(
        config,
        metrics_handle,
        audit_log,
        audit_event_sender,
        Instant::now(),
    )
}

#[cfg(test)]
fn app_with_process_started_at(
    config: config::Config,
    metrics_handle: PrometheusHandle,
    audit_log: audit::AuditLog,
    audit_event_sender: audit::AuditEventSender,
    process_started_at: Instant,
) -> Result<Router, Box<dyn std::error::Error>> {
    match gateway_app_with_process_started_at(
        config,
        metrics_handle,
        audit_log,
        audit_event_sender,
        process_started_at,
    )? {
        GatewayApp::Unified(router) => Ok(router),
        GatewayApp::Split { .. } => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "app_with_process_started_at requires ADMIN_LISTEN_ADDR to be unset",
        )
        .into()),
    }
}

fn gateway_app_with_process_started_at(
    config: config::Config,
    metrics_handle: PrometheusHandle,
    audit_log: audit::AuditLog,
    audit_event_sender: audit::AuditEventSender,
    process_started_at: Instant,
) -> Result<GatewayApp, Box<dyn std::error::Error>> {
    let split_admin_listener = config.admin_listen_addr.is_some();
    let csrf_config = middleware::csrf::CsrfConfig::from_config(&config);
    let rate_limit_state = middleware::rate_limit::RateLimitState::from_config(&config);
    let observation_state =
        middleware::observation::ObservationState::from_config(&config, audit_log.clone());
    let audit_query_store = config
        .audit_sqlite_path
        .as_deref()
        .map(audit::query::AuditQueryStore::open)
        .transpose()?
        .map(Arc::new);
    let loaded_policy = rbac::Policy::from_config(&config)?;
    let egress_config = match loaded_policy.as_ref() {
        Some(policy) => {
            egress::EgressConfig::from_config_and_policy(&config, Some(&policy.egress))?
        }
        None => egress::EgressConfig::from_config(&config),
    };
    let egress_allowed_hosts_count = egress_config.allowed_host_rule_count();
    let proxy_egress_config = {
        let mut proxy_egress_config = egress_config.clone();
        proxy_egress_config.apply_upstream_timeout_overrides(&config);
        proxy_egress_config
    };
    let egress_client = Arc::new(egress::EgressClient::new(egress_config)?);
    let proxy_egress_client = Arc::new(egress::EgressClient::new(proxy_egress_config)?);
    let proxy_state = ProxyState::from_config(&config, proxy_egress_client);
    if let Some(proxy) = proxy_state.as_ref() {
        proxy.spawn_upstream_health_checks();
    }
    let routes = GatewayRoutes::from_config(&config);
    let validator = auth::JwtValidator::from_config(&config, egress_client)?
        .map(|validator| Arc::new(validator) as Arc<dyn auth::SessionValidator>);
    let rbac_status = RbacStatus {
        policy_loaded: loaded_policy.is_some(),
        policy_id: loaded_policy.as_ref().and_then(|policy| policy.id.clone()),
    };
    let rbac_state = match loaded_policy {
        Some(policy) => {
            tracing::info!(
                policy_id = policy.id.as_deref().unwrap_or("unnamed"),
                route_rules = policy.routes.len(),
                "RBAC enabled: policy file loaded"
            );
            Some(middleware::rbac::RbacState::from_policy(
                policy,
                &config,
                audit_log.clone(),
            ))
        }
        None => {
            tracing::warn!("RBAC disabled: no policy file configured");
            None
        }
    };
    if let (Some(policy_file), Some(rbac_state)) =
        (config.policy_file.as_ref(), rbac_state.as_ref())
    {
        middleware::rbac::spawn_policy_reload_tasks(policy_file.clone(), rbac_state.clone())?;
    }
    let status_state = StatusAdminState {
        config: config.clone(),
        rbac: rbac_status,
        egress_allowed_hosts_count,
        process_started_at,
    };

    if config.auth_enabled && validator.is_none() {
        tracing::warn!(
            "authentication is enabled but no session validator is configured; non-exempt requests will be rejected"
        );
    }

    let auth_state = if config.auth_enabled {
        Some(middleware::auth::AuthState::from_config(
            &config,
            validator,
            audit_log.clone(),
        ))
    } else {
        None
    };
    let middleware_stack = MiddlewareStack {
        config: config.clone(),
        audit_log: audit_log.clone(),
        csrf_config,
        rate_limit_state,
        observation_state,
        rbac_state,
        auth_state,
    };
    let app_state = AppState {
        metrics_handle,
        proxy: proxy_state,
        routes: routes.clone(),
    };
    let audit_admin_state = AuditAdminState {
        query_store: audit_query_store,
        event_sender: audit_event_sender,
    };

    if split_admin_listener {
        Ok(GatewayApp::Split {
            data: apply_middleware(data_router(app_state.clone()), &middleware_stack),
            admin: apply_middleware(
                admin_router(&routes, app_state, audit_admin_state, status_state),
                &middleware_stack,
            ),
        })
    } else {
        Ok(GatewayApp::Unified(apply_middleware(
            unified_router(&routes, app_state, audit_admin_state, status_state),
            &middleware_stack,
        )))
    }
}

fn unified_router(
    routes: &GatewayRoutes,
    app_state: AppState,
    audit_admin_state: AuditAdminState,
    status_state: StatusAdminState,
) -> Router {
    let router = Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/metrics", get(metrics_endpoint))
        .route(routes.admin.ui_prefix.as_str(), get(admin_ui_index))
        .route(routes.admin.ui_slash_route.as_str(), get(admin_ui_index))
        .route(routes.admin.ui_asset_route.as_str(), get(admin_ui_asset));

    let router = with_proxy_fallback_if_configured(router, &app_state).with_state(app_state);
    let router = add_admin_api_routes(router, routes, audit_admin_state, status_state);

    #[cfg(test)]
    let router = router.route(
        "/__test/principal",
        get(principal_probe).options(principal_probe),
    );

    router
}

fn data_router(app_state: AppState) -> Router {
    let router = Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/metrics", get(metrics_endpoint));

    with_proxy_fallback_if_configured(router, &app_state).with_state(app_state)
}

fn admin_router(
    routes: &GatewayRoutes,
    app_state: AppState,
    audit_admin_state: AuditAdminState,
    status_state: StatusAdminState,
) -> Router {
    let router = Router::new()
        .route(routes.admin.ui_prefix.as_str(), get(admin_ui_index))
        .route(routes.admin.ui_slash_route.as_str(), get(admin_ui_index))
        .route(routes.admin.ui_asset_route.as_str(), get(admin_ui_asset))
        .with_state(app_state);

    add_admin_api_routes(router, routes, audit_admin_state, status_state)
}

fn with_proxy_fallback_if_configured(
    router: Router<AppState>,
    app_state: &AppState,
) -> Router<AppState> {
    if app_state.proxy.is_some() {
        router.fallback(any(proxy_fallback))
    } else {
        router
    }
}

fn add_admin_api_routes(
    router: Router,
    routes: &GatewayRoutes,
    audit_admin_state: AuditAdminState,
    status_state: StatusAdminState,
) -> Router {
    router
        .merge(
            Router::new()
                .route(routes.admin.audit_route.as_str(), get(audit_query_endpoint))
                .route(
                    routes.admin.events_stream_route.as_str(),
                    get(audit_events_stream_endpoint),
                )
                .with_state(audit_admin_state),
        )
        .merge(
            Router::new()
                .route(routes.admin.status_route.as_str(), get(status_endpoint))
                .with_state(status_state),
        )
}

fn apply_middleware(router: Router, stack: &MiddlewareStack) -> Router {
    let request_id_header = request_id_header();

    // Later axum layers run earlier at runtime. Attach RBAC before auth, then
    // auth before CSRF, so requests flow through CSRF, auth, RBAC, then the
    // route handler.
    let router = if let Some(rbac_state) = stack.rbac_state.clone() {
        router.layer(axum::middleware::from_fn_with_state(
            rbac_state,
            middleware::rbac::rbac_middleware,
        ))
    } else {
        router
    };

    let router = if let Some(auth_state) = stack.auth_state.clone() {
        router.layer(axum::middleware::from_fn_with_state(
            auth_state,
            middleware::auth::auth_middleware,
        ))
    } else {
        router
    };

    let router = router
        .layer(axum::middleware::from_fn_with_state(
            stack.csrf_config.clone(),
            middleware::csrf::csrf_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            stack.config.clone(),
            middleware::validate::validate_request,
        ))
        .layer(axum::middleware::from_fn_with_state(
            stack.rate_limit_state.clone(),
            middleware::rate_limit::rate_limit_request,
        ))
        .layer(axum::middleware::from_fn_with_state(
            stack.observation_state.clone(),
            middleware::observation::observation_middleware,
        ))
        .layer(axum::middleware::from_fn(
            middleware::headers::header_hardening_middleware,
        ))
        .layer(cors_layer(&stack.config))
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(TraceLayer::new_for_http())
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid));

    #[cfg(test)]
    let router = router.layer(axum::middleware::from_fn(audit_extension_probe_middleware));

    router.layer(Extension(stack.audit_log.clone()))
}

fn install_metrics_recorder() -> Result<PrometheusHandle, metrics_exporter_prometheus::BuildError> {
    let handle = PrometheusBuilder::new()
        .with_recommended_naming(true)
        .install_recorder()?;

    ::metrics::describe_counter!(REQUEST_COUNTER, "HTTP requests served by GreenGateway");
    ::metrics::describe_counter!(
        audit::AUDIT_EVENTS_DROPPED_TOTAL,
        "Audit events dropped by the bounded asynchronous audit channel"
    );
    ::metrics::describe_counter!(
        audit::AUDIT_SQLITE_FLUSH_ERRORS_TOTAL,
        "SQLite audit sink flush or retention prune errors"
    );
    ::metrics::describe_counter!(
        metrics::LOCK_POISON_RECOVERIES_TOTAL,
        "Lock poison recoveries by component and lock"
    );

    Ok(handle)
}

fn cors_layer(config: &config::Config) -> CorsLayer {
    let allowed_origins: Vec<HeaderValue> = config
        .cors_allow_origins
        .iter()
        .map(|origin| {
            origin
                .parse::<HeaderValue>()
                .expect("validated CORS origin should be a valid HTTP header value")
        })
        .collect();
    let allowed_headers = vec![
        header::CONTENT_TYPE,
        header::AUTHORIZATION,
        header::COOKIE,
        header::ACCEPT,
        config
            .csrf_header_name
            .parse::<HeaderName>()
            .expect("validated CSRF header name should be a valid HTTP header name"),
        request_id_header(),
    ];

    CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(allowed_headers)
        .allow_credentials(true)
}

fn request_id_header() -> HeaderName {
    HeaderName::from_static(REQUEST_ID_HEADER)
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
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

    async fn update(&self, reachable: bool) {
        *self.snapshot.write().await = UpstreamHealthSnapshot {
            reachable: Some(reachable),
            last_checked: Some(OffsetDateTime::now_utc()),
        };
    }
}

async fn refresh_upstream_health(
    health: &UpstreamHealthState,
    egress_client: &egress::EgressClient,
    upstream_url: &str,
    first_check: bool,
) -> bool {
    match check_upstream_reachable(egress_client, upstream_url).await {
        Ok(()) => {
            health.update(true).await;
            true
        }
        Err(err) => {
            health.update(false).await;
            if first_check {
                tracing::warn!(
                    upstream_url,
                    error = %err,
                    "startup upstream reachability check failed; continuing startup"
                );
            } else {
                tracing::warn!(
                    upstream_url,
                    error = %err,
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
        Err(err) => {
            tracing::warn!(error = %err, "failed to format upstream health timestamp");
            timestamp.unix_timestamp().to_string()
        }
    }
}

async fn version() -> Json<VersionResponse> {
    record_request("/version");
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn metrics_endpoint(State(state): State<AppState>) -> impl IntoResponse {
    record_request("/metrics");
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.metrics_handle.render(),
    )
}

impl ProxyState {
    fn from_config(
        config: &config::Config,
        egress_client: Arc<egress::EgressClient>,
    ) -> Option<Self> {
        if let Some(upstream_url) = config.upstream_url.as_deref() {
            let upstream_origin = upstream_origin_from_url(upstream_url, "UPSTREAM_URL");

            return Some(Self {
                routes: ProxyRoutes::Legacy {
                    upstream_origin: upstream_origin.clone(),
                },
                upstream_health: upstream_health_targets([upstream_origin]),
                egress_client,
                max_request_body_bytes: config.egress_max_request_body_bytes,
            });
        }

        if config.upstream_routes.is_empty() {
            return None;
        }

        let routes: Vec<_> = config
            .upstream_routes
            .iter()
            .enumerate()
            .map(|(index, route)| ProxyRoute {
                path_prefix: route.path_prefix.clone(),
                host: route.host.as_ref().map(|host| host.to_ascii_lowercase()),
                upstream_origin: upstream_origin_from_url(
                    &route.upstream_url,
                    &format!("UPSTREAM_ROUTES[{index}].upstream_url"),
                ),
            })
            .collect();
        let upstream_health =
            upstream_health_targets(routes.iter().map(|route| route.upstream_origin.clone()));

        Some(Self {
            routes: ProxyRoutes::RoutingTable { routes },
            upstream_health,
            egress_client,
            max_request_body_bytes: config.egress_max_request_body_bytes,
        })
    }

    fn upstream_origin_for_request(&self, path: &str, headers: &HeaderMap) -> Option<&str> {
        match &self.routes {
            ProxyRoutes::Legacy { upstream_origin } => Some(upstream_origin),
            ProxyRoutes::RoutingTable { routes } => {
                let request_host = request_host_without_port(headers);
                let request_host = request_host.as_deref();
                let mut best = None::<(&ProxyRoute, usize, bool)>;

                for route in routes {
                    if !route.matches(path, request_host) {
                        continue;
                    }

                    let prefix_len = route.path_prefix.as_deref().map_or(0, str::len);
                    let host_specific = route.host.is_some();
                    let should_replace = match best {
                        Some((_, best_prefix_len, best_host_specific)) => {
                            prefix_len > best_prefix_len
                                || (prefix_len == best_prefix_len
                                    && host_specific
                                    && !best_host_specific)
                        }
                        None => true,
                    };

                    if should_replace {
                        best = Some((route, prefix_len, host_specific));
                    }
                }

                best.map(|(route, _, _)| route.upstream_origin.as_str())
            }
        }
    }

    async fn upstream_health_response(&self) -> UpstreamHealthResponse {
        match &self.routes {
            ProxyRoutes::Legacy { .. } => {
                let target = self
                    .upstream_health
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
                let mut upstreams = Vec::with_capacity(self.upstream_health.len());
                for target in &self.upstream_health {
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

    fn spawn_upstream_health_checks(&self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(
                "upstream reachability checks were not started because no Tokio runtime is active"
            );
            return;
        };

        for target in &self.upstream_health {
            let health = target.health.clone();
            let egress_client = Arc::clone(&self.egress_client);
            let upstream_url = target.origin.clone();

            handle.spawn(async move {
                let mut first_check = true;
                let mut last_reachable = None;

                loop {
                    let reachable =
                        refresh_upstream_health(&health, &egress_client, &upstream_url, first_check)
                            .await;

                    if last_reachable == Some(false) && reachable {
                        tracing::info!(upstream_url = %upstream_url, "upstream reachability restored");
                    }

                    last_reachable = Some(reachable);
                    first_check = false;
                    tokio::time::sleep(UPSTREAM_HEALTH_CHECK_INTERVAL).await;
                }
            });
        }
    }
}

impl ProxyRoute {
    fn matches(&self, path: &str, request_host: Option<&str>) -> bool {
        let host_matches = self
            .host
            .as_deref()
            .is_none_or(|host| request_host == Some(host));
        let path_matches = self
            .path_prefix
            .as_deref()
            .is_none_or(|path_prefix| path_match::path_prefix_matches(path, path_prefix));

        host_matches && path_matches
    }
}

fn upstream_origin_from_url(upstream_url: &str, source: &str) -> String {
    Url::parse(upstream_url)
        .unwrap_or_else(|err| {
            panic!("validated {source} should parse when building proxy state: {err}")
        })
        .origin()
        .ascii_serialization()
}

fn upstream_health_targets(
    upstream_origins: impl IntoIterator<Item = String>,
) -> Vec<UpstreamHealthTarget> {
    let mut seen = HashSet::new();
    let mut targets = Vec::new();

    for origin in upstream_origins {
        if seen.insert(origin.clone()) {
            targets.push(UpstreamHealthTarget {
                origin,
                health: UpstreamHealthState::new(),
            });
        }
    }

    targets
}

fn request_host_without_port(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::HOST)?.to_str().ok()?.trim();
    if value.is_empty() {
        return None;
    }

    let host = if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']')?;
        &rest[..end]
    } else {
        value.split_once(':').map_or(value, |(host, _)| host)
    };

    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

async fn proxy_fallback(State(state): State<AppState>, request: Request<Body>) -> Response {
    record_request(PROXY_FALLBACK_ROUTE);

    if state.routes.is_gateway_owned_path(request.uri().path()) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let Some(proxy) = state.proxy.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let Some(upstream_origin) =
        proxy.upstream_origin_for_request(request.uri().path(), request.headers())
    else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let upstream_origin = upstream_origin.to_owned();
    let (parts, body) = request.into_parts();
    let target_url = proxy_target_url(&upstream_origin, &parts.uri);
    let mut headers = strip_hop_by_hop_headers(&parts.headers);
    if let Some(request_id) = parts.headers.get(REQUEST_ID_HEADER) {
        headers.insert(request_id_header(), request_id.clone());
    }
    let request_id = parts.headers.get(REQUEST_ID_HEADER).cloned();
    let body = match axum::body::to_bytes(body, proxy.max_request_body_bytes).await {
        Ok(body) if body.is_empty() => None,
        Ok(body) => Some(body.to_vec()),
        Err(err) => {
            tracing::warn!(
                error = %err,
                max = proxy.max_request_body_bytes,
                "failed to read proxied request body"
            );
            return payload_too_large(proxy.max_request_body_bytes);
        }
    };

    let upstream_started = Instant::now();
    let upstream = match proxy
        .egress_client
        .stream_request_with_headers(parts.method, &target_url, headers, body)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            let latency_ms = duration_millis(upstream_started.elapsed());
            tracing::warn!(error = %err, "proxied upstream request failed");
            let mut response = proxy_error_response(&err);
            response
                .extensions_mut()
                .insert(middleware::decision::UpstreamOutcome {
                    latency_ms,
                    status: None,
                });
            if let Some(request_id) = request_id {
                response
                    .headers_mut()
                    .insert(request_id_header(), request_id);
            }
            return response;
        }
    };
    let upstream_latency_ms = duration_millis(upstream_started.elapsed());
    let upstream_status = upstream.status;
    let upstream_headers = strip_hop_by_hop_headers(&upstream.headers);
    let mut upstream_body = upstream.body;
    let first_chunk = match upstream_body.next().await {
        Some(Ok(chunk)) => Some(chunk),
        Some(Err(err)) => {
            let latency_ms = duration_millis(upstream_started.elapsed());
            tracing::warn!(error = %err, "proxied upstream response body failed");
            let mut response = proxy_error_response(&err);
            response
                .extensions_mut()
                .insert(middleware::decision::UpstreamOutcome {
                    latency_ms,
                    status: None,
                });
            if let Some(request_id) = request_id {
                response
                    .headers_mut()
                    .insert(request_id_header(), request_id);
            }
            return response;
        }
        None => None,
    };
    let response_body = match first_chunk {
        Some(chunk) => Body::from_stream(
            stream::once(async move { Ok::<_, egress::EgressError>(chunk) }).chain(upstream_body),
        ),
        None => Body::empty(),
    };
    let mut response = Response::new(response_body);
    *response.status_mut() = upstream_status;
    *response.headers_mut() = upstream_headers;
    response
        .extensions_mut()
        .insert(middleware::decision::UpstreamOutcome {
            latency_ms: upstream_latency_ms,
            status: Some(upstream_status.as_u16()),
        });
    if let Some(request_id) = request_id {
        response
            .headers_mut()
            .insert(request_id_header(), request_id);
    }

    response
}

fn proxy_target_url(upstream_origin: &str, uri: &http::Uri) -> String {
    let path_and_query = uri.path_and_query().map_or("/", |value| value.as_str());
    format!("{upstream_origin}{path_and_query}")
}

fn strip_hop_by_hop_headers(headers: &HeaderMap) -> HeaderMap {
    let connection_named_headers = connection_named_headers(headers);
    let mut forwarded = HeaderMap::new();

    for (name, value) in headers {
        if is_hop_by_hop_header(name) || connection_named_headers.contains(name) {
            continue;
        }
        forwarded.append(name.clone(), value.clone());
    }

    forwarded
}

fn connection_named_headers(headers: &HeaderMap) -> HashSet<HeaderName> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
        .collect()
}

fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
    )
}

fn proxy_error_response(error: &egress::EgressError) -> Response {
    let (status, code) = if error.is_timeout() {
        (StatusCode::GATEWAY_TIMEOUT, "gateway_timeout")
    } else {
        (StatusCode::BAD_GATEWAY, "bad_gateway")
    };

    (
        status,
        Json(ErrorResponse {
            error: code.to_owned(),
        }),
    )
        .into_response()
}

fn payload_too_large(max_body_size: usize) -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(json!({
            "error": "payload too large",
            "max_body_size": max_body_size,
        })),
    )
        .into_response()
}

async fn status_endpoint(
    State(state): State<StatusAdminState>,
    principal: Option<Extension<auth::Principal>>,
) -> Response {
    record_request(STATUS_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };

    if !principal.roles.iter().any(|role| role == AUDIT_ADMIN_ROLE) {
        return forbidden();
    }

    Json(StatusResponse::from_state(&state)).into_response()
}

async fn admin_ui_index(State(state): State<AppState>) -> Response {
    record_request(ADMIN_UI_ROUTE);
    admin_ui_index_response(&state.routes.admin)
}

async fn admin_ui_asset(State(state): State<AppState>, Path(path): Path<String>) -> Response {
    record_request(ADMIN_UI_ROUTE);

    let asset_path = path.trim_start_matches('/');
    if !asset_path.is_empty() {
        if let Some(asset) = AdminUiAssets::get(asset_path) {
            return embedded_asset_response(asset_path, asset);
        }
    }

    admin_ui_index_response(&state.routes.admin)
}

fn admin_ui_index_response(routes: &AdminRoutes) -> Response {
    match AdminUiAssets::get(ADMIN_UI_INDEX) {
        Some(asset) => admin_ui_html_response(routes, asset),
        None => internal_server_error("admin UI index not embedded"),
    }
}

fn admin_ui_html_response(routes: &AdminRoutes, asset: rust_embed::EmbeddedFile) -> Response {
    let html = match std::str::from_utf8(asset.data.as_ref()) {
        Ok(html) => rewrite_admin_ui_index(html, routes),
        Err(err) => {
            tracing::error!(error = %err, "embedded admin UI index is not UTF-8");
            return internal_server_error("admin UI index is not valid UTF-8");
        }
    };

    (
        [
            (header::CONTENT_TYPE, content_type_for_path(ADMIN_UI_INDEX)),
            (
                HeaderName::from_static("content-security-policy"),
                HeaderValue::from_static(ADMIN_UI_CONTENT_SECURITY_POLICY),
            ),
        ],
        html,
    )
        .into_response()
}

fn rewrite_admin_ui_index(html: &str, routes: &AdminRoutes) -> String {
    let admin_base_with_slash = format!("{}/", routes.ui_prefix);
    let html = html.replace("/admin/", &admin_base_with_slash);
    let config_meta = format!(
        r#"    <meta name="greengateway-admin-base" content="{}" />
    <meta name="greengateway-admin-api-base" content="{}" />
"#,
        html_attribute_value(&routes.ui_prefix),
        html_attribute_value(&routes.api_prefix),
    );

    html.replacen("  </head>", &format!("{config_meta}  </head>"), 1)
}

fn html_attribute_value(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn embedded_asset_response(path: &str, asset: rust_embed::EmbeddedFile) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type_for_path(path)),
            (
                HeaderName::from_static("content-security-policy"),
                HeaderValue::from_static(ADMIN_UI_CONTENT_SECURITY_POLICY),
            ),
        ],
        asset.data.into_owned(),
    )
        .into_response()
}

fn content_type_for_path(path: &str) -> HeaderValue {
    HeaderValue::from_str(mime_guess::from_path(path).first_or_octet_stream().as_ref())
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"))
}

impl StatusResponse {
    fn from_state(state: &StatusAdminState) -> Self {
        let config = &state.config;

        Self {
            version: env!("CARGO_PKG_VERSION"),
            uptime_seconds: state.process_started_at.elapsed().as_secs(),
            listen_addr: config.listen_addr.to_string(),
            auth_enabled: config.auth_enabled,
            rbac: state.rbac.clone(),
            audit_sinks: AuditSinksStatus {
                stdout: true,
                file: config.audit_log_file.is_some(),
                sqlite: config.audit_sqlite_path.is_some(),
                broadcast: true,
            },
            rate_limits: RateLimitsStatus {
                read: RateLimitStatus {
                    requests_per_second: config.rate_limit_read_rps,
                    burst: config.rate_limit_read_burst,
                },
                write: RateLimitStatus {
                    requests_per_second: config.rate_limit_write_rps,
                    burst: config.rate_limit_write_burst,
                },
            },
            cors_allow_origins: config.cors_allow_origins.clone(),
            trust_proxy_headers: config.trust_proxy_headers,
            csrf_enabled: config.csrf_enabled,
            egress: EgressStatus {
                allowed_hosts_count: state.egress_allowed_hosts_count,
                deny_private_ips: config.egress_deny_private_ips,
            },
        }
    }
}

async fn audit_query_endpoint(
    State(state): State<AuditAdminState>,
    principal: Option<Extension<auth::Principal>>,
    Query(params): Query<AuditQueryParams>,
) -> Response {
    record_request(AUDIT_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };

    if !principal.roles.iter().any(|role| role == AUDIT_ADMIN_ROLE) {
        return forbidden();
    }

    let Some(query_store) = state.query_store.as_ref() else {
        return service_unavailable("audit query store not configured");
    };

    let filters = match params.into_filters() {
        Ok(filters) => filters,
        Err(parameter) => return bad_request(&format!("invalid query parameter: {parameter}")),
    };

    match query_store.query(&filters) {
        Ok(page) => (
            StatusCode::OK,
            Json(AuditQueryResponse {
                events: page.events,
                next_cursor: page.next_cursor,
            }),
        )
            .into_response(),
        Err(err) => {
            tracing::error!(error = %err, "failed to query audit events");
            internal_server_error("audit query failed")
        }
    }
}

async fn audit_events_stream_endpoint(
    State(state): State<AuditAdminState>,
    principal: Option<Extension<auth::Principal>>,
    Query(params): Query<AuditEventStreamParams>,
) -> Response {
    record_request(AUDIT_EVENTS_STREAM_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };

    if !principal.roles.iter().any(|role| role == AUDIT_ADMIN_ROLE) {
        return forbidden();
    }

    Sse::new(audit_event_sse_stream(
        state.event_sender.subscribe(),
        params,
    ))
    .keep_alive(KeepAlive::default())
    .into_response()
}

fn audit_event_sse_stream(
    receiver: tokio::sync::broadcast::Receiver<audit::AuditEvent>,
    params: AuditEventStreamParams,
) -> impl Stream<Item = Result<Event, Infallible>> + Send + 'static {
    stream::unfold((receiver, params), |(mut receiver, params)| async move {
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    if !params.matches(&event) {
                        continue;
                    }

                    let event_type = event.event_type.clone();
                    let data = match serde_json::to_string(&event) {
                        Ok(data) => data,
                        Err(err) => {
                            tracing::error!(
                                error = %err,
                                "failed to serialize audit event for SSE stream"
                            );
                            continue;
                        }
                    };

                    return Some((
                        Ok(Event::default().event(event_type).data(data)),
                        (receiver, params),
                    ));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::debug!(
                        skipped,
                        "audit event stream receiver lagged; skipping missed events"
                    );
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
}

impl AuditQueryParams {
    fn into_filters(self) -> Result<audit::query::AuditQueryFilters, &'static str> {
        let from = validate_rfc3339("from", self.from)?;
        let to = validate_rfc3339("to", self.to)?;
        let status = parse_optional_i64("status", self.status)?;
        let limit = parse_limit(self.limit)?;
        let before_id = parse_before_id(self.before_id)?;

        Ok(audit::query::AuditQueryFilters {
            from,
            to,
            event_type: self.event_type,
            actor: self.actor,
            path: self.path,
            status,
            limit,
            before_id,
        })
    }
}

impl AuditEventStreamParams {
    fn matches(&self, event: &audit::AuditEvent) -> bool {
        if let Some(event_type) = self.event_type.as_deref() {
            if event.event_type != event_type {
                return false;
            }
        }

        if let Some(path) = self.path.as_deref() {
            if event.payload.get("path").and_then(|path| path.as_str()) != Some(path) {
                return false;
            }
        }

        true
    }
}

fn validate_rfc3339(
    parameter: &'static str,
    value: Option<String>,
) -> Result<Option<String>, &'static str> {
    if let Some(value) = value.as_deref() {
        OffsetDateTime::parse(value, &Rfc3339).map_err(|_| parameter)?;
    }

    Ok(value)
}

fn parse_optional_i64(
    parameter: &'static str,
    value: Option<String>,
) -> Result<Option<i64>, &'static str> {
    value
        .map(|value| value.parse::<i64>().map_err(|_| parameter))
        .transpose()
}

fn parse_limit(value: Option<String>) -> Result<usize, &'static str> {
    let Some(value) = value else {
        return Ok(DEFAULT_AUDIT_QUERY_LIMIT);
    };
    let limit = value.parse::<usize>().map_err(|_| "limit")?;
    if limit == 0 {
        return Err("limit");
    }

    Ok(limit.min(MAX_AUDIT_QUERY_LIMIT))
}

fn parse_before_id(value: Option<String>) -> Result<Option<i64>, &'static str> {
    let Some(value) = value else {
        return Ok(None);
    };
    let before_id = value.parse::<i64>().map_err(|_| "before_id")?;
    if before_id < 0 {
        return Err("before_id");
    }

    Ok(Some(before_id))
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        Json(ErrorResponse {
            error: "unauthorized".to_owned(),
        }),
    )
        .into_response()
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorResponse {
            error: "forbidden".to_owned(),
        }),
    )
        .into_response()
}

fn bad_request(error: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: error.to_owned(),
        }),
    )
        .into_response()
}

fn service_unavailable(error: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorResponse {
            error: error.to_owned(),
        }),
    )
        .into_response()
}

fn internal_server_error(error: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: error.to_owned(),
        }),
    )
        .into_response()
}

fn record_request(route: &'static str) {
    ::metrics::counter!(REQUEST_COUNTER, "route" => route).increment(1);
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
async fn audit_extension_probe_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if req.extensions().get::<audit::AuditLog>().is_none() {
        return http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    next.run(req).await
}

#[cfg(test)]
async fn principal_probe(
    principal: Option<Extension<auth::Principal>>,
) -> axum::response::Response {
    match principal {
        Some(Extension(principal)) => Json(json!({ "user_id": principal.user_id })).into_response(),
        None => http::StatusCode::NO_CONTENT.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::StatusCode};
    use futures_util::StreamExt;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use rusqlite::{params, Connection};
    use serde_json::Value;
    use std::{
        collections::HashSet,
        fs,
        path::PathBuf,
        sync::Arc,
        time::{Duration, Instant},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;

    fn test_config(cors_allow_origins: Vec<&str>) -> config::Config {
        config::Config {
            listen_addr: "127.0.0.1:0"
                .parse()
                .expect("test listen address should parse"),
            admin_listen_addr: None,
            admin_prefix: config::DEFAULT_ADMIN_PREFIX.to_owned(),
            audit_log_file: None,
            audit_sqlite_path: None,
            audit_sqlite_retention_days: None,
            policy_file: None,
            cors_allow_origins: cors_allow_origins.into_iter().map(str::to_owned).collect(),
            max_body_size: 1_048_576,
            rate_limit_read_rps: 50.0,
            rate_limit_read_burst: 100,
            rate_limit_write_rps: 10.0,
            rate_limit_write_burst: 20,
            trust_proxy_headers: false,
            rbac_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
                "/admin".to_owned(),
            ],
            session_cookie_name: String::new(),
            validation_allowed_content_types: vec!["application/json".to_owned()],
            auth_enabled: true,
            auth_mode: config::AuthMode::Required,
            auth_cookie_name: "session".to_owned(),
            auth_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
                "/admin".to_owned(),
            ],
            jwt_jwks_url: None,
            jwt_issuer: None,
            jwt_audience: None,
            jwt_jwks_timeout_ms: 2000,
            jwt_require_jti: false,
            roles_claim: "roles".to_owned(),
            csrf_enabled: true,
            csrf_cookie_name: "csrf_token".to_owned(),
            csrf_header_name: "x-csrf-token".to_owned(),
            csrf_cookie_domain: None,
            csrf_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
            upstream_url: None,
            upstream_routes: Vec::new(),
            upstream_timeout_ms: None,
            upstream_response_idle_timeout_ms: None,
            upstream_connect_timeout_ms: None,
            egress_allowed_hosts: Vec::new(),
            egress_timeout_ms: 30_000,
            egress_response_idle_timeout_ms: 30_000,
            egress_connect_timeout_ms: 10_000,
            egress_max_response_bytes: 5_242_880,
            egress_max_request_body_bytes: 1_048_576,
            egress_deny_private_ips: true,
        }
    }

    #[derive(Clone)]
    struct NoopSink;

    impl audit::AuditSink for NoopSink {
        fn emit(&self, _event: &audit::AuditEvent) {}
    }

    fn test_audit_log() -> audit::AuditLog {
        audit::AuditLog::new(Arc::new(NoopSink))
    }

    fn test_audit_event_sender() -> audit::AuditEventSender {
        let (sender, _) = tokio::sync::broadcast::channel(16);
        sender
    }

    fn test_audit_log_with_broadcast() -> (audit::AuditLog, audit::AuditEventSender) {
        let (sender, _) = tokio::sync::broadcast::channel(16);
        let audit_log =
            audit::AuditLog::new(Arc::new(audit::sink::BroadcastSink::new(sender.clone()))
                as Arc<dyn audit::AuditSink>);

        (audit_log, sender)
    }

    fn audit_log_with_sqlite_and_broadcast(
        sqlite_path: &PathBuf,
    ) -> (audit::AuditLog, audit::AuditEventSender) {
        let (sender, _) = tokio::sync::broadcast::channel(16);
        let sqlite_sink = Arc::new(
            audit::sqlite_sink::SqliteSink::new(audit::sqlite_sink::SqliteSinkConfig {
                path: sqlite_path.clone(),
                retention_days: None,
            })
            .expect("SQLite sink should create audit schema"),
        ) as Arc<dyn audit::AuditSink>;
        let broadcast_sink =
            Arc::new(audit::sink::BroadcastSink::new(sender.clone())) as Arc<dyn audit::AuditSink>;
        let audit_log = audit::AuditLog::new(Arc::new(audit::sink::CompositeSink::new(vec![
            sqlite_sink,
            broadcast_sink,
        ])) as Arc<dyn audit::AuditSink>);

        (audit_log, sender)
    }

    #[derive(Debug)]
    struct CapturedRequest {
        method: Method,
        path_and_query: String,
        headers: HeaderMap,
        body: Vec<u8>,
    }

    async fn spawn_capture_upstream() -> (
        std::net::SocketAddr,
        tokio::sync::mpsc::Receiver<CapturedRequest>,
    ) {
        let (sender, receiver) = tokio::sync::mpsc::channel(16);
        let router = Router::new()
            .fallback(any(capture_upstream))
            .with_state(sender);
        let addr = spawn_router(router).await;

        (addr, receiver)
    }

    async fn spawn_router(router: Router) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test upstream should bind");
        let addr = listener
            .local_addr()
            .expect("test upstream address should be available");
        tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("test upstream should serve");
        });

        addr
    }

    fn gateway_app_for_test(config: config::Config) -> GatewayApp {
        let recorder = PrometheusBuilder::new().build_recorder();
        gateway_app_with_process_started_at(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
            Instant::now(),
        )
        .expect("gateway app should build")
    }

    fn split_gateway_routers(config: config::Config) -> (Router, Router) {
        match gateway_app_for_test(config) {
            GatewayApp::Split { data, admin } => (data, admin),
            GatewayApp::Unified(_) => panic!("gateway app should build split routers"),
        }
    }

    async fn spawn_gateway_router(
        router: Router,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test gateway should bind");
        let addr = listener
            .local_addr()
            .expect("test gateway address should be available");
        let server = tokio::spawn(async move {
            serve_router(listener, router)
                .await
                .expect("test gateway should serve");
        });

        (addr, server)
    }

    async fn spawn_split_gateway(
        config: config::Config,
    ) -> (
        std::net::SocketAddr,
        std::net::SocketAddr,
        tokio::task::JoinHandle<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let (data, admin) = split_gateway_routers(config);
        let (data_addr, data_server) = spawn_gateway_router(data).await;
        let (admin_addr, admin_server) = spawn_gateway_router(admin).await;

        (data_addr, admin_addr, data_server, admin_server)
    }

    fn split_config() -> config::Config {
        let mut config = test_config(Vec::new());
        config.admin_listen_addr = Some(
            "127.0.0.1:0"
                .parse()
                .expect("test admin listen address should parse"),
        );
        config
    }

    #[derive(Debug)]
    struct TestHttpResponse {
        status: StatusCode,
        headers: HeaderMap,
        body: String,
    }

    impl TestHttpResponse {
        fn status(&self) -> StatusCode {
            self.status
        }

        fn headers(&self) -> &HeaderMap {
            &self.headers
        }
    }

    async fn test_http_request(
        addr: std::net::SocketAddr,
        method: &str,
        path: &str,
        bearer: Option<&str>,
    ) -> TestHttpResponse {
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut stream = tokio::net::TcpStream::connect(addr)
                .await
                .unwrap_or_else(|err| panic!("test HTTP client should connect to {addr}: {err}"));
            let mut request =
                format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
            if let Some(token) = bearer {
                request.push_str("Authorization: Bearer ");
                request.push_str(token);
                request.push_str("\r\n");
            }
            request.push_str("\r\n");

            stream
                .write_all(request.as_bytes())
                .await
                .unwrap_or_else(|err| panic!("test HTTP client should write request: {err}"));
            stream
                .flush()
                .await
                .unwrap_or_else(|err| panic!("test HTTP client should flush request: {err}"));

            let mut raw_response = Vec::new();
            stream
                .read_to_end(&mut raw_response)
                .await
                .unwrap_or_else(|err| panic!("test HTTP client should read response: {err}"));

            parse_test_http_response(&raw_response)
        })
        .await
        .unwrap_or_else(|_| panic!("test HTTP request timed out: {method} {path}"))
    }

    fn parse_test_http_response(raw_response: &[u8]) -> TestHttpResponse {
        let header_end = raw_response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("test HTTP response should contain headers");
        let raw_headers = std::str::from_utf8(&raw_response[..header_end])
            .expect("test HTTP response headers should be UTF-8");
        let raw_body = &raw_response[header_end + 4..];

        let mut lines = raw_headers.split("\r\n");
        let status_line = lines
            .next()
            .expect("test HTTP response should include a status line");
        let mut status_parts = status_line.splitn(3, ' ');
        let version = status_parts
            .next()
            .expect("test HTTP response should include a version");
        assert!(
            version.starts_with("HTTP/"),
            "test HTTP response should use HTTP, got {version}"
        );
        let status = status_parts
            .next()
            .expect("test HTTP response should include a status code")
            .parse::<u16>()
            .expect("test HTTP response status should be numeric");
        let status =
            StatusCode::from_u16(status).expect("test HTTP response status should be valid");

        let mut headers = HeaderMap::new();
        for line in lines {
            let (name, value) = line
                .split_once(':')
                .unwrap_or_else(|| panic!("test HTTP response header should contain ':': {line}"));
            let name = HeaderName::from_bytes(name.trim().as_bytes())
                .expect("test HTTP response header name should be valid");
            let value = HeaderValue::from_str(value.trim())
                .expect("test HTTP response header value should be valid");
            headers.append(name, value);
        }

        let body = if response_is_chunked(&headers) {
            decode_chunked_body(raw_body)
        } else if let Some(content_length) = headers
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .map(|value| {
                value
                    .parse::<usize>()
                    .expect("test HTTP response Content-Length should be numeric")
            })
        {
            assert!(
                raw_body.len() >= content_length,
                "test HTTP response body should contain Content-Length bytes"
            );
            raw_body[..content_length].to_vec()
        } else {
            raw_body.to_vec()
        };

        TestHttpResponse {
            status,
            headers,
            body: String::from_utf8(body).expect("test HTTP response body should be UTF-8"),
        }
    }

    fn response_is_chunked(headers: &HeaderMap) -> bool {
        headers
            .get(header::TRANSFER_ENCODING)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
            })
    }

    fn decode_chunked_body(mut encoded: &[u8]) -> Vec<u8> {
        let mut decoded = Vec::new();

        loop {
            let line_end = encoded
                .windows(2)
                .position(|window| window == b"\r\n")
                .expect("test HTTP chunk should include a size line");
            let size_line = std::str::from_utf8(&encoded[..line_end])
                .expect("test HTTP chunk size should be UTF-8");
            let size_text = size_line
                .split_once(';')
                .map_or(size_line, |(size, _extension)| size)
                .trim();
            let size = usize::from_str_radix(size_text, 16)
                .expect("test HTTP chunk size should be hexadecimal");
            encoded = &encoded[line_end + 2..];

            if size == 0 {
                break;
            }

            assert!(
                encoded.len() >= size + 2,
                "test HTTP chunk should contain declared bytes and trailing CRLF"
            );
            decoded.extend_from_slice(&encoded[..size]);
            assert_eq!(
                &encoded[size..size + 2],
                b"\r\n",
                "test HTTP chunk should end with CRLF"
            );
            encoded = &encoded[size + 2..];
        }

        decoded
    }

    async fn capture_upstream(
        State(sender): State<tokio::sync::mpsc::Sender<CapturedRequest>>,
        request: Request<Body>,
    ) -> Response {
        let (parts, body) = request.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .expect("upstream should read request body");
        let method = parts.method.clone();
        let path_and_query = parts
            .uri
            .path_and_query()
            .map_or("/", |value| value.as_str())
            .to_owned();
        let _ = sender
            .send(CapturedRequest {
                method: method.clone(),
                path_and_query: path_and_query.clone(),
                headers: parts.headers,
                body: body.to_vec(),
            })
            .await;

        let mut response = (
            StatusCode::CREATED,
            format!("upstream {method} {path_and_query}"),
        )
            .into_response();
        response
            .headers_mut()
            .insert("x-upstream-end-to-end", HeaderValue::from_static("kept"));
        response.headers_mut().insert(
            header::CONNECTION,
            HeaderValue::from_static("x-upstream-hop"),
        );
        response
            .headers_mut()
            .insert("x-upstream-hop", HeaderValue::from_static("strip"));
        response
            .headers_mut()
            .insert("keep-alive", HeaderValue::from_static("timeout=5"));
        response.headers_mut().insert(
            "proxy-authenticate",
            HeaderValue::from_static("Basic realm=\"upstream\""),
        );
        response
    }

    async fn assert_upstream_receives_no_request(
        captured: &mut tokio::sync::mpsc::Receiver<CapturedRequest>,
        context: &str,
    ) {
        let started = Instant::now();
        let timeout = Duration::from_millis(100);

        while started.elapsed() < timeout {
            let remaining = timeout.saturating_sub(started.elapsed());
            match tokio::time::timeout(remaining, captured.recv()).await {
                Ok(Some(request)) if is_upstream_health_probe(&request) => continue,
                Ok(Some(request)) => panic!(
                    "{context}: unexpected upstream request {} {}",
                    request.method, request.path_and_query
                ),
                Ok(None) | Err(_) => return,
            }
        }
    }

    async fn next_proxied_request(
        captured: &mut tokio::sync::mpsc::Receiver<CapturedRequest>,
        context: &str,
    ) -> CapturedRequest {
        let started = Instant::now();

        loop {
            let request = tokio::time::timeout(Duration::from_secs(1), captured.recv())
                .await
                .unwrap_or_else(|_| panic!("{context}: upstream did not receive request"))
                .unwrap_or_else(|| panic!("{context}: upstream capture channel closed"));

            if !is_upstream_health_probe(&request) {
                return request;
            }

            assert!(
                started.elapsed() < Duration::from_secs(1),
                "{context}: only upstream health probes were captured"
            );
        }
    }

    fn is_upstream_health_probe(request: &CapturedRequest) -> bool {
        request.method == Method::HEAD && request.path_and_query == "/" && request.body.is_empty()
    }

    async fn delayed_stream_upstream() -> Response {
        let chunks = futures_util::stream::unfold(0, |index| async move {
            match index {
                0 => Some((Ok::<_, Infallible>(bytes::Bytes::from_static(b"first")), 1)),
                1 => {
                    tokio::time::sleep(Duration::from_millis(700)).await;
                    Some((Ok::<_, Infallible>(bytes::Bytes::from_static(b"second")), 2))
                }
                _ => None,
            }
        });

        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/octet-stream")],
            Body::from_stream(chunks),
        )
            .into_response()
    }

    fn proxy_config(upstream_addr: std::net::SocketAddr) -> config::Config {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.csrf_enabled = false;
        config.validation_allowed_content_types = vec![
            "application/json".to_owned(),
            "application/octet-stream".to_owned(),
            "text/plain".to_owned(),
        ];
        config.upstream_url = Some(format!(
            "http://127.0.0.1:{}/ignored-base",
            upstream_addr.port()
        ));
        config.egress_allowed_hosts = vec!["127.0.0.1".to_owned()];
        config.egress_deny_private_ips = false;
        config
    }

    fn routing_proxy_config(routes: Vec<config::UpstreamRouteConfig>) -> config::Config {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.csrf_enabled = false;
        config.validation_allowed_content_types = vec![
            "application/json".to_owned(),
            "application/octet-stream".to_owned(),
            "text/plain".to_owned(),
        ];
        config.upstream_routes = routes;
        config.egress_deny_private_ips = false;
        config
    }

    fn path_route(
        path_prefix: &str,
        upstream_addr: std::net::SocketAddr,
    ) -> config::UpstreamRouteConfig {
        route(Some(path_prefix), None, upstream_addr)
    }

    fn host_path_route(
        host: &str,
        path_prefix: &str,
        upstream_addr: std::net::SocketAddr,
    ) -> config::UpstreamRouteConfig {
        route(Some(path_prefix), Some(host), upstream_addr)
    }

    fn route(
        path_prefix: Option<&str>,
        host: Option<&str>,
        upstream_addr: std::net::SocketAddr,
    ) -> config::UpstreamRouteConfig {
        config::UpstreamRouteConfig {
            path_prefix: path_prefix.map(str::to_owned),
            host: host.map(str::to_owned),
            upstream_url: format!("http://127.0.0.1:{}/ignored-base", upstream_addr.port()),
        }
    }

    fn proxy_router(config: config::Config, audit_log: audit::AuditLog) -> Router {
        let recorder = PrometheusBuilder::new().build_recorder();
        app(
            config,
            recorder.handle(),
            audit_log,
            test_audit_event_sender(),
        )
        .expect("app should build")
    }

    async fn preflight_response_to_path(
        config: config::Config,
        path: &str,
        origin: &str,
    ) -> axum::response::Response {
        let recorder = PrometheusBuilder::new().build_recorder();

        app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build")
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri(path)
                .header(header::ORIGIN, origin)
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete")
    }

    async fn preflight_response(config: config::Config, origin: &str) -> axum::response::Response {
        preflight_response_to_path(config, "/health", origin).await
    }

    async fn health_response(router: Router) -> axum::response::Response {
        router
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("health request should complete")
    }

    async fn wait_for_upstream_health(router: Router, reachable: bool) -> Value {
        let started = Instant::now();

        loop {
            let response = health_response(router.clone()).await;
            assert_eq!(response.status(), StatusCode::OK);
            let body = json_body(response).await;

            if body["upstream"]["reachable"] == json!(reachable)
                && body["upstream"]["last_checked"].as_str().is_some()
            {
                return body;
            }

            assert!(
                started.elapsed() < Duration::from_secs(2),
                "upstream health did not become {reachable} before timeout: {body}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn wait_for_routing_upstream_health(
        router: Router,
        upstream_count: usize,
        reachable: bool,
    ) -> Value {
        let started = Instant::now();

        loop {
            let response = health_response(router.clone()).await;
            assert_eq!(response.status(), StatusCode::OK);
            let body = json_body(response).await;
            let upstreams = body["upstream"]["upstreams"].as_array();

            if upstreams.is_some_and(|upstreams| {
                upstreams.len() == upstream_count
                    && upstreams.iter().all(|upstream| {
                        upstream["reachable"] == json!(reachable)
                            && upstream["last_checked"].as_str().is_some()
                    })
            }) {
                return body;
            }

            assert!(
                started.elapsed() < Duration::from_secs(2),
                "routing upstream health did not report {upstream_count} upstreams as {reachable} before timeout: {body}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn health_probe_count(
        captured: &mut tokio::sync::mpsc::Receiver<CapturedRequest>,
    ) -> usize {
        let started = Instant::now();
        let timeout = Duration::from_millis(100);
        let mut count = 0;

        while started.elapsed() < timeout {
            let remaining = timeout.saturating_sub(started.elapsed());
            match tokio::time::timeout(remaining, captured.recv()).await {
                Ok(Some(request)) if is_upstream_health_probe(&request) => count += 1,
                Ok(Some(request)) => panic!(
                    "unexpected non-health upstream request while counting probes: {} {}",
                    request.method, request.path_and_query
                ),
                Ok(None) | Err(_) => return count,
            }
        }

        count
    }

    #[tokio::test]
    async fn health_without_upstream_returns_original_body() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let response = app(
            test_config(Vec::new()),
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build")
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key(REQUEST_ID_HEADER));
        assert_eq!(body_string(response).await, r#"{"status":"ok"}"#);
    }

    #[tokio::test]
    async fn startup_upstream_health_check_reports_reachable_without_blocking_startup() {
        let upstream_addr =
            spawn_router(Router::new().route("/", get(|| async { StatusCode::NO_CONTENT }))).await;
        let config = proxy_config(upstream_addr);
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = tokio::time::timeout(Duration::from_millis(100), async move {
            app(
                config,
                recorder.handle(),
                test_audit_log(),
                test_audit_event_sender(),
            )
        })
        .await
        .expect("app startup should not wait for upstream health")
        .expect("app should build");

        let body = wait_for_upstream_health(router, true).await;
        assert_eq!(body["status"], json!("ok"));
        assert_eq!(body["upstream"]["configured"], json!(true));
        assert_eq!(body["upstream"]["reachable"], json!(true));
    }

    #[tokio::test]
    async fn startup_upstream_health_check_reports_unreachable_without_blocking_startup() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener should bind");
        let upstream_addr = listener
            .local_addr()
            .expect("listener local address should be available");
        drop(listener);
        let mut config = proxy_config(upstream_addr);
        config.upstream_timeout_ms = Some(100);
        config.upstream_connect_timeout_ms = Some(100);
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = tokio::time::timeout(Duration::from_millis(100), async move {
            app(
                config,
                recorder.handle(),
                test_audit_log(),
                test_audit_event_sender(),
            )
        })
        .await
        .expect("app startup should not wait for upstream health")
        .expect("app should build");

        let body = wait_for_upstream_health(router, false).await;
        assert_eq!(body["status"], json!("ok"));
        assert_eq!(body["upstream"]["configured"], json!(true));
        assert_eq!(body["upstream"]["reachable"], json!(false));
    }

    #[tokio::test]
    async fn routing_table_health_reports_distinct_upstreams_without_duplicate_probes() {
        let (first_addr, mut first_captured) = spawn_capture_upstream().await;
        let (second_addr, mut second_captured) = spawn_capture_upstream().await;
        let router = proxy_router(
            routing_proxy_config(vec![
                path_route("/api", first_addr),
                path_route("/api/v2", first_addr),
                path_route("/assets", second_addr),
            ]),
            test_audit_log(),
        );

        let body = wait_for_routing_upstream_health(router, 2, true).await;
        let upstreams = body["upstream"]["upstreams"]
            .as_array()
            .expect("routing health should include upstream list");
        assert_eq!(body["status"], json!("ok"));
        assert_eq!(body["upstream"]["configured"], json!(true));
        assert_eq!(
            upstreams[0]["origin"],
            json!(format!("http://127.0.0.1:{}", first_addr.port()))
        );
        assert_eq!(
            upstreams[1]["origin"],
            json!(format!("http://127.0.0.1:{}", second_addr.port()))
        );

        assert_eq!(
            health_probe_count(&mut first_captured).await,
            1,
            "duplicate route entries pointing at one origin should share one health loop"
        );
        assert_eq!(health_probe_count(&mut second_captured).await, 1);
    }

    #[test]
    fn admin_routes_keep_default_api_prefix_and_remap_custom_api_under_v1() {
        let default_routes = AdminRoutes::from_prefix(config::DEFAULT_ADMIN_PREFIX);
        assert_eq!(default_routes.api_prefix, DEFAULT_ADMIN_API_PREFIX);
        assert_eq!(default_routes.audit_route, AUDIT_ADMIN_ROUTE);
        assert_eq!(
            default_routes.events_stream_route,
            AUDIT_EVENTS_STREAM_ROUTE
        );
        assert_eq!(default_routes.status_route, STATUS_ADMIN_ROUTE);

        let custom_routes = AdminRoutes::from_prefix("/ops");
        assert_eq!(custom_routes.ui_prefix, "/ops");
        assert_eq!(custom_routes.api_prefix, "/v1/ops");
        assert_eq!(custom_routes.audit_route, "/v1/ops/audit");
        assert_eq!(custom_routes.events_stream_route, "/v1/ops/events/stream");
        assert_eq!(custom_routes.status_route, "/v1/ops/status");
    }

    #[tokio::test]
    async fn default_admin_listener_unset_builds_single_router_with_data_and_admin_routes() {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;

        let router = match gateway_app_for_test(config) {
            GatewayApp::Unified(router) => router,
            GatewayApp::Split { .. } => panic!("ADMIN_LISTEN_ADDR unset should build one router"),
        };

        let health_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("health request should complete");
        assert_eq!(health_response.status(), StatusCode::OK);

        let admin_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("admin UI request should complete");
        assert_eq!(admin_response.status(), StatusCode::OK);
        assert!(body_string(admin_response)
            .await
            .contains(r#"<div id="root"></div>"#));

        let status_response = router
            .oneshot(audit_query_request(
                STATUS_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
            ))
            .await
            .expect("admin status request should complete");
        assert_eq!(status_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn split_listeners_expose_admin_and_data_surfaces_separately() {
        let jwks_addr = spawn_test_jwks_server().await;
        let (upstream_addr, mut captured) = spawn_capture_upstream().await;
        let mut config = split_config();
        config.upstream_url = Some(format!(
            "http://127.0.0.1:{}/ignored-base",
            upstream_addr.port()
        ));
        config.egress_allowed_hosts = vec!["127.0.0.1".to_owned()];
        config.egress_deny_private_ips = false;
        config.jwt_jwks_url = Some(format!("http://127.0.0.1:{}/jwks.json", jwks_addr.port()));
        let token = signed_admin_token();
        let (data_addr, admin_addr, data_server, admin_server) = spawn_split_gateway(config).await;

        let data_admin_response = test_http_request(data_addr, "GET", "/admin", None).await;
        assert_eq!(data_admin_response.status(), StatusCode::NOT_FOUND);

        let data_admin_api_response =
            test_http_request(data_addr, "GET", STATUS_ADMIN_ROUTE, Some(&token)).await;
        assert_eq!(data_admin_api_response.status(), StatusCode::NOT_FOUND);
        assert_upstream_receives_no_request(
            &mut captured,
            "split data listener should reserve admin UI and API paths from proxy fallback",
        )
        .await;

        let admin_ui_response = test_http_request(admin_addr, "GET", "/admin", None).await;
        assert_eq!(admin_ui_response.status(), StatusCode::OK);
        assert!(admin_ui_response.body.contains(r#"<div id="root"></div>"#));

        let admin_status_response =
            test_http_request(admin_addr, "GET", STATUS_ADMIN_ROUTE, Some(&token)).await;
        assert_eq!(admin_status_response.status(), StatusCode::OK);
        let admin_status: Value = serde_json::from_str(&admin_status_response.body)
            .expect("admin status body should be JSON");
        assert_eq!(admin_status["version"], json!(env!("CARGO_PKG_VERSION")));

        for path in ["/health", "/version", "/metrics"] {
            let data_response = test_http_request(data_addr, "GET", path, None).await;
            assert_eq!(data_response.status(), StatusCode::OK, "{path}");

            let admin_response = test_http_request(admin_addr, "GET", path, None).await;
            assert_eq!(admin_response.status(), StatusCode::NOT_FOUND, "{path}");
        }

        let proxied_response =
            test_http_request(data_addr, "GET", "/proxied?x=1", Some(&token)).await;
        assert_eq!(proxied_response.status(), StatusCode::CREATED);
        assert_eq!(proxied_response.body, "upstream GET /proxied?x=1");
        let proxied_request =
            next_proxied_request(&mut captured, "data listener should proxy unmatched paths").await;
        assert_eq!(proxied_request.method, Method::GET);
        assert_eq!(proxied_request.path_and_query, "/proxied?x=1");

        let admin_proxy_response =
            test_http_request(admin_addr, "GET", "/proxied?x=1", Some(&token)).await;
        assert_eq!(admin_proxy_response.status(), StatusCode::NOT_FOUND);
        assert_upstream_receives_no_request(
            &mut captured,
            "split admin listener should not register proxy fallback",
        )
        .await;

        data_server.abort();
        admin_server.abort();
    }

    #[tokio::test]
    async fn split_listeners_handle_concurrent_requests() {
        let (data_addr, admin_addr, data_server, admin_server) =
            spawn_split_gateway(split_config()).await;

        let (data_response, admin_response) = tokio::join!(
            test_http_request(data_addr, "GET", "/health", None),
            test_http_request(admin_addr, "GET", "/admin", None),
        );

        assert_eq!(data_response.status(), StatusCode::OK);
        assert_eq!(admin_response.status(), StatusCode::OK);

        data_server.abort();
        admin_server.abort();
    }

    #[tokio::test]
    async fn split_admin_listener_enforces_auth_and_rbac_on_admin_api() {
        let jwks_addr = spawn_test_jwks_server().await;
        let policy = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "default_action": "deny",
                "enforcement_mode": "enforce",
                "roles": {
                    "admin": { "permissions": ["admin:read"] }
                }
            }"#,
        );
        let mut config = split_config();
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config.jwt_jwks_url = Some(format!("http://127.0.0.1:{}/jwks.json", jwks_addr.port()));
        config.egress_deny_private_ips = false;
        let token = signed_admin_token();
        let (_data_addr, admin_addr, data_server, admin_server) = spawn_split_gateway(config).await;

        let unauthenticated = test_http_request(admin_addr, "GET", STATUS_ADMIN_ROUTE, None).await;
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            unauthenticated
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer")
        );
        assert_eq!(unauthenticated.body, r#"{"error":"unauthorized"}"#);

        let rbac_denied =
            test_http_request(admin_addr, "GET", STATUS_ADMIN_ROUTE, Some(&token)).await;
        assert_eq!(rbac_denied.status(), StatusCode::FORBIDDEN);
        assert_eq!(rbac_denied.body, r#"{"error":"forbidden"}"#);

        data_server.abort();
        admin_server.abort();
    }

    #[tokio::test]
    async fn startup_returns_actionable_error_for_invalid_policy_file() {
        let policy = TempPolicyFile::new(r#"{ "schema_version": "#);
        let mut config = test_config(Vec::new());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        let recorder = PrometheusBuilder::new().build_recorder();

        let error = match app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        ) {
            Ok(_) => panic!("app startup should reject invalid policy file"),
            Err(error) => error,
        };
        let message = error.to_string();

        assert!(
            message.contains("failed to parse policy file"),
            "unexpected startup error: {message}"
        );
        assert!(
            message.contains(&policy.path.to_string_lossy().into_owned()),
            "startup error should name the policy file: {message}"
        );
        assert!(
            !message.contains("panicked"),
            "startup error should not be a panic: {message}"
        );
    }

    #[tokio::test]
    async fn admin_ui_shell_is_served_without_principal() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let response = app(
            test_config(Vec::new()),
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build")
        .oneshot(
            Request::builder()
                .uri("/admin")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_content_type_starts_with(response.headers(), "text/html");
        assert_eq!(
            response.headers()["content-security-policy"],
            ADMIN_UI_CONTENT_SECURITY_POLICY
        );
        let body = body_string(response).await;
        assert!(body.contains(r#"<div id="root"></div>"#));
    }

    #[tokio::test]
    async fn admin_ui_real_embedded_javascript_asset_is_served() {
        let asset_path = AdminUiAssets::iter()
            .find(|path| path.starts_with("assets/") && path.ends_with(".js"))
            .expect("Vite build should embed a JavaScript asset")
            .to_string();
        let uri = format!("/admin/{asset_path}");

        let recorder = PrometheusBuilder::new().build_recorder();
        let response = app(
            test_config(Vec::new()),
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build")
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .expect("content type should be present");
        assert!(
            content_type.starts_with("text/javascript")
                || content_type.starts_with("application/javascript"),
            "unexpected JavaScript content type: {content_type}"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should read");
        assert!(!body.is_empty());
    }

    #[tokio::test]
    async fn admin_ui_client_routes_fall_back_to_index() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let response = app(
            test_config(Vec::new()),
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build")
        .oneshot(
            Request::builder()
                .uri("/admin/logs")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_content_type_starts_with(response.headers(), "text/html");
        let body = body_string(response).await;
        assert!(body.contains(r#"<div id="root"></div>"#));
    }

    #[tokio::test]
    async fn admin_ui_traversal_attempts_fall_back_to_index_only() {
        for uri in [
            "/admin/../../../etc/passwd",
            "/admin/%2e%2e/%2e%2e/etc/passwd",
        ] {
            let recorder = PrometheusBuilder::new().build_recorder();
            let response = app(
                test_config(Vec::new()),
                recorder.handle(),
                test_audit_log(),
                test_audit_event_sender(),
            )
            .expect("app should build")
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

            assert_eq!(response.status(), StatusCode::OK);
            assert_content_type_starts_with(response.headers(), "text/html");
            let body = body_string(response).await;
            assert!(body.contains(r#"<div id="root"></div>"#));
            assert!(!body.contains("root:x:0:0"));
        }
    }

    #[tokio::test]
    async fn audit_log_extension_is_available_to_middleware() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let response = app(
            test_config(Vec::new()),
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build")
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_disabled_skips_non_exempt_route_without_principal() {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let recorder = PrometheusBuilder::new().build_recorder();

        let response = app(
            config,
            recorder.handle(),
            audit_log,
            test_audit_event_sender(),
        )
        .expect("app should build")
        .oneshot(
            Request::builder()
                .uri("/__test/principal")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eventually(Duration::from_secs(1), || !capture.events().is_empty());
        let events = capture.events();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == "http.request_observed")
                .count(),
            1
        );
        assert!(!events
            .iter()
            .any(|event| event.event_type.starts_with("auth.")));
    }

    #[tokio::test]
    async fn observe_auth_forwards_anonymous_request_to_rbac_enforcement() {
        let policy = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "default_action": "deny",
                "enforcement_mode": "enforce",
                "roles": {},
                "routes": [
                    {
                        "path_prefix": "/__test",
                        "permission": "test:read"
                    }
                ]
            }"#,
        );
        let mut config = test_config(Vec::new());
        config.auth_mode = config::AuthMode::Observe;
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            audit_log,
            test_audit_event_sender(),
        )
        .expect("app should build");
        let request_id = "request-observe-auth-rbac-deny";

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/__test/principal")
                    .header(REQUEST_ID_HEADER, request_id)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(body_string(response).await, r#"{"error":"forbidden"}"#);
        assert_eventually(Duration::from_secs(1), || {
            let events = capture.events();
            events
                .iter()
                .any(|event| event.event_type == "auth.failure")
                && events
                    .iter()
                    .any(|event| event.event_type == "authz.denied")
                && events
                    .iter()
                    .any(|event| event.event_type == "http.request_observed")
        });

        let events = capture.events();
        let auth_failure = events
            .iter()
            .find(|event| event.event_type == "auth.failure")
            .expect("auth failure should be captured");
        assert_eq!(auth_failure.request_id, request_id);
        assert_eq!(auth_failure.payload["path"], json!("/__test/principal"));
        assert_eq!(auth_failure.payload["reason"], json!("missing_credential"));

        let authz_denied = events
            .iter()
            .find(|event| event.event_type == "authz.denied")
            .expect("authz denied should be captured");
        assert_eq!(authz_denied.request_id, request_id);
        assert_eq!(authz_denied.payload["path"], json!("/__test/principal"));
        assert_eq!(authz_denied.payload["path_prefix"], json!("/__test"));
        assert_eq!(authz_denied.payload["permission"], json!("test:read"));
        assert_eq!(authz_denied.payload["reason"], json!("missing_principal"));

        let observed = events
            .iter()
            .find(|event| event.event_type == "http.request_observed")
            .expect("observation event should be captured");
        assert_eq!(observed.request_id, request_id);
        assert_eq!(observed.payload["status"], json!(403));
        assert_eq!(
            observed.payload["auth_outcome"],
            json!("anonymous_or_failed")
        );
        assert_eq!(observed.payload["auth_reason"], json!("missing_credential"));
        assert_eq!(observed.payload["policy_decision"], json!("denied"));
        assert_eq!(
            observed.payload["policy_reason"],
            json!("missing_principal")
        );
    }

    #[tokio::test]
    async fn proxy_forwards_methods_path_query_headers_and_bodies() {
        let (upstream_addr, mut captured) = spawn_capture_upstream().await;
        let router = proxy_router(proxy_config(upstream_addr), test_audit_log());

        for method in [Method::GET, Method::POST, Method::PUT, Method::DELETE] {
            let body = if matches!(method, Method::POST | Method::PUT) {
                format!("body for {method}").into_bytes()
            } else {
                Vec::new()
            };
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method.clone())
                        .uri("/api/items/42/?x=1&name=two%20words")
                        .header(header::AUTHORIZATION, "Bearer upstream-token")
                        .header(header::COOKIE, "session=abc")
                        .header(header::CONTENT_TYPE, "application/octet-stream")
                        .header(header::CONNECTION, "keep-alive, x-hop-by-connection")
                        .header("keep-alive", "timeout=5")
                        .header("proxy-authorization", "Basic stripped")
                        .header("te", "trailers")
                        .header("upgrade", "websocket")
                        .header(header::CONTENT_LENGTH, "0")
                        .header("x-hop-by-connection", "strip me")
                        .header("x-end-to-end", "keep me")
                        .body(Body::from(body.clone()))
                        .expect("request should build"),
                )
                .await
                .expect("proxy request should complete");

            assert_eq!(response.status(), StatusCode::CREATED);
            assert_eq!(
                response.headers().get("x-upstream-end-to-end"),
                Some(&HeaderValue::from_static("kept"))
            );
            for stripped in [
                header::CONNECTION.as_str(),
                "keep-alive",
                "proxy-authenticate",
                "transfer-encoding",
                "content-length",
                "x-upstream-hop",
            ] {
                assert!(
                    !response.headers().contains_key(stripped),
                    "proxied response should strip {stripped}"
                );
            }
            let response_request_id = response
                .headers()
                .get(REQUEST_ID_HEADER)
                .cloned()
                .expect("response should contain gateway request id");
            let response_body = body_string(response).await;
            assert_eq!(
                response_body,
                format!("upstream {method} /api/items/42/?x=1&name=two%20words")
            );

            let upstream =
                next_proxied_request(&mut captured, "upstream should receive proxied request")
                    .await;
            assert_eq!(upstream.method, method);
            assert_eq!(
                upstream.path_and_query,
                "/api/items/42/?x=1&name=two%20words"
            );
            assert_eq!(upstream.body, body);
            assert_eq!(
                upstream.headers.get(header::AUTHORIZATION),
                Some(&HeaderValue::from_static("Bearer upstream-token"))
            );
            assert_eq!(
                upstream.headers.get(header::COOKIE),
                Some(&HeaderValue::from_static("session=abc"))
            );
            assert_eq!(
                upstream.headers.get("x-end-to-end"),
                Some(&HeaderValue::from_static("keep me"))
            );
            if !body.is_empty() {
                assert_ne!(
                    upstream.headers.get(header::CONTENT_LENGTH),
                    Some(&HeaderValue::from_static("0")),
                    "upstream request should not forward the stale client content-length"
                );
            }
            assert_eq!(
                upstream.headers.get(REQUEST_ID_HEADER),
                Some(&response_request_id)
            );
            for stripped in [
                header::CONNECTION.as_str(),
                "keep-alive",
                "proxy-authorization",
                "te",
                "upgrade",
                "x-hop-by-connection",
            ] {
                assert!(
                    !upstream.headers.contains_key(stripped),
                    "upstream request should strip {stripped}"
                );
            }
        }
    }

    #[tokio::test]
    async fn routing_table_selects_two_upstreams_by_path_prefix() {
        let (api_addr, mut api_captured) = spawn_capture_upstream().await;
        let (assets_addr, mut assets_captured) = spawn_capture_upstream().await;
        let config = routing_proxy_config(vec![
            path_route("/api", api_addr),
            path_route("/assets", assets_addr),
        ]);
        assert!(config.egress_allowed_hosts.is_empty());
        let router = proxy_router(config, test_audit_log());

        let api_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/items?kind=primary")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("API proxy request should complete");
        assert_eq!(api_response.status(), StatusCode::CREATED);
        assert_eq!(
            body_string(api_response).await,
            "upstream GET /api/items?kind=primary"
        );

        let assets_response = router
            .oneshot(
                Request::builder()
                    .uri("/assets/logo.svg")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("assets proxy request should complete");
        assert_eq!(assets_response.status(), StatusCode::CREATED);
        assert_eq!(
            body_string(assets_response).await,
            "upstream GET /assets/logo.svg"
        );

        let api_request =
            next_proxied_request(&mut api_captured, "API upstream should receive request").await;
        assert_eq!(api_request.path_and_query, "/api/items?kind=primary");
        let assets_request = next_proxied_request(
            &mut assets_captured,
            "assets upstream should receive request",
        )
        .await;
        assert_eq!(assets_request.path_and_query, "/assets/logo.svg");
    }

    #[tokio::test]
    async fn routing_table_uses_longest_matching_path_prefix() {
        let (short_addr, mut short_captured) = spawn_capture_upstream().await;
        let (long_addr, mut long_captured) = spawn_capture_upstream().await;
        let router = proxy_router(
            routing_proxy_config(vec![
                path_route("/api", short_addr),
                path_route("/api/internal", long_addr),
            ]),
            test_audit_log(),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/internal/jobs/42")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("proxy request should complete");

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            body_string(response).await,
            "upstream GET /api/internal/jobs/42"
        );
        let long_request = next_proxied_request(
            &mut long_captured,
            "longest-prefix upstream should receive request",
        )
        .await;
        assert_eq!(long_request.path_and_query, "/api/internal/jobs/42");
        assert_upstream_receives_no_request(
            &mut short_captured,
            "shorter prefix should lose to longer prefix",
        )
        .await;
    }

    #[tokio::test]
    async fn routing_table_host_and_path_match_and_host_specific_tie_wins() {
        let (path_only_addr, mut path_only_captured) = spawn_capture_upstream().await;
        let (host_path_addr, mut host_path_captured) = spawn_capture_upstream().await;
        let router = proxy_router(
            routing_proxy_config(vec![
                path_route("/api", path_only_addr),
                host_path_route("api.example.test", "/api", host_path_addr),
            ]),
            test_audit_log(),
        );

        let host_specific_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/items")
                    .header(header::HOST, "api.example.test:9443")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("host-specific proxy request should complete");
        assert_eq!(host_specific_response.status(), StatusCode::CREATED);
        assert_eq!(
            body_string(host_specific_response).await,
            "upstream GET /api/items"
        );
        let host_specific_request = next_proxied_request(
            &mut host_path_captured,
            "host-specific upstream should receive request",
        )
        .await;
        assert_eq!(host_specific_request.path_and_query, "/api/items");

        let path_only_response = router
            .oneshot(
                Request::builder()
                    .uri("/api/items")
                    .header(header::HOST, "other.example.test")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("path-only proxy request should complete");
        assert_eq!(path_only_response.status(), StatusCode::CREATED);
        assert_eq!(
            body_string(path_only_response).await,
            "upstream GET /api/items"
        );
        let path_only_request = next_proxied_request(
            &mut path_only_captured,
            "path-only upstream should receive fallback request",
        )
        .await;
        assert_eq!(path_only_request.path_and_query, "/api/items");
    }

    #[test]
    fn routing_table_equal_specificity_uses_declaration_order() {
        let proxy = ProxyState {
            routes: ProxyRoutes::RoutingTable {
                routes: vec![
                    ProxyRoute {
                        path_prefix: Some("/api".to_owned()),
                        host: None,
                        upstream_origin: "https://first.example.test".to_owned(),
                    },
                    ProxyRoute {
                        path_prefix: Some("/api".to_owned()),
                        host: None,
                        upstream_origin: "https://second.example.test".to_owned(),
                    },
                ],
            },
            upstream_health: Vec::new(),
            egress_client: Arc::new(
                egress::EgressClient::new(egress::EgressConfig::default())
                    .expect("egress client should build"),
            ),
            max_request_body_bytes: 1_048_576,
        };

        assert_eq!(
            proxy.upstream_origin_for_request("/api/items", &HeaderMap::new()),
            Some("https://first.example.test")
        );
    }

    #[tokio::test]
    async fn routing_table_unmatched_paths_return_404() {
        let (upstream_addr, mut captured) = spawn_capture_upstream().await;
        let router = proxy_router(
            routing_proxy_config(vec![path_route("/api", upstream_addr)]),
            test_audit_log(),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/other")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_upstream_receives_no_request(&mut captured, "unmatched route should not proxy")
            .await;
    }

    #[tokio::test]
    async fn routing_table_reserved_gateway_paths_never_reach_matching_upstream() {
        let (upstream_addr, mut captured) = spawn_capture_upstream().await;
        let router = proxy_router(
            routing_proxy_config(vec![path_route("/admin", upstream_addr)]),
            test_audit_log(),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/not-found")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("reserved path request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_upstream_receives_no_request(
            &mut captured,
            "route table must not override gateway-owned paths",
        )
        .await;
    }

    #[tokio::test]
    async fn legacy_upstream_url_only_behavior_still_proxies_unmatched_paths() {
        let (upstream_addr, mut captured) = spawn_capture_upstream().await;
        let config = proxy_config(upstream_addr);
        assert!(config.upstream_routes.is_empty());
        let router = proxy_router(config, test_audit_log());

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/legacy?ok=true")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("legacy proxy request should complete");

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(body_string(response).await, "upstream GET /legacy?ok=true");
        let upstream =
            next_proxied_request(&mut captured, "legacy upstream should receive request").await;
        assert_eq!(upstream.path_and_query, "/legacy?ok=true");
    }

    #[tokio::test]
    async fn proxy_auto_seeds_configured_upstream_host_into_egress_allowlist() {
        let (upstream_addr, mut captured) = spawn_capture_upstream().await;
        let mut config = proxy_config(upstream_addr);
        config.egress_allowed_hosts.clear();
        let router = proxy_router(config, test_audit_log());

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/auto-seeded?ok=true")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("proxy request should complete");

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            body_string(response).await,
            "upstream GET /auto-seeded?ok=true"
        );
        let upstream =
            next_proxied_request(&mut captured, "upstream should receive proxied request").await;
        assert_eq!(upstream.path_and_query, "/auto-seeded?ok=true");
    }

    #[tokio::test]
    async fn proxy_auto_seeded_private_upstream_still_requires_private_ip_opt_out() {
        let (upstream_addr, mut captured) = spawn_capture_upstream().await;
        let mut config = proxy_config(upstream_addr);
        config.egress_allowed_hosts.clear();
        config.egress_deny_private_ips = true;
        let egress_config = egress::EgressConfig::from_config(&config);
        assert!(egress_config.allowed_hosts.contains("127.0.0.1"));
        assert!(egress_config.deny_private_ips);
        let router = proxy_router(config, test_audit_log());

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/private-blocked")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("proxy request should complete");

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(body_string(response).await, r#"{"error":"bad_gateway"}"#);
        assert_upstream_receives_no_request(
            &mut captured,
            "auto-seeded private upstream should still be blocked before proxying",
        )
        .await;
    }

    #[tokio::test]
    async fn proxy_streams_upstream_response_without_buffering() {
        let upstream_addr =
            spawn_router(Router::new().route("/stream", get(delayed_stream_upstream))).await;
        let router = proxy_router(proxy_config(upstream_addr), test_audit_log());

        let response = tokio::time::timeout(
            Duration::from_millis(500),
            router.oneshot(
                Request::builder()
                    .uri("/stream")
                    .body(Body::empty())
                    .expect("request should build"),
            ),
        )
        .await
        .expect("proxy should return response headers before full body is sent")
        .expect("proxy request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body().into_data_stream();
        let first = tokio::time::timeout(Duration::from_millis(200), body.next())
            .await
            .expect("first proxied chunk should arrive")
            .expect("body should yield first chunk")
            .expect("first chunk should be ok");
        assert_eq!(&first[..], b"first");

        assert!(
            tokio::time::timeout(Duration::from_millis(100), body.next())
                .await
                .is_err(),
            "second chunk should not be buffered before upstream sends it"
        );

        let second = tokio::time::timeout(Duration::from_secs(1), body.next())
            .await
            .expect("second proxied chunk should arrive")
            .expect("body should yield second chunk")
            .expect("second chunk should be ok");
        assert_eq!(&second[..], b"second");
    }

    #[tokio::test]
    async fn proxy_returns_502_for_reset_upstream_without_leaking_details() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener should bind");
        let upstream_addr = listener
            .local_addr()
            .expect("listener address should be available");
        let server = tokio::spawn(async move {
            loop {
                let (stream, _) = listener
                    .accept()
                    .await
                    .expect("test server should accept a connection");
                drop(stream);
            }
        });
        let mut config = proxy_config(upstream_addr);
        config.egress_timeout_ms = 1000;
        config.egress_connect_timeout_ms = 100;
        let router = proxy_router(config, test_audit_log());

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/unmatched")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("proxy request should complete");

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(body_string(response).await, r#"{"error":"bad_gateway"}"#);
        server.abort();
    }

    #[tokio::test]
    async fn proxy_uses_upstream_timeout_override_for_timed_out_upstream() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener should bind");
        let upstream_addr = listener
            .local_addr()
            .expect("listener address should be available");
        let server = tokio::spawn(async move {
            loop {
                let (stream, _) = listener
                    .accept()
                    .await
                    .expect("test server should accept a connection");
                tokio::spawn(async move {
                    let _stream = stream;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                });
            }
        });
        let mut config = proxy_config(upstream_addr);
        config.egress_timeout_ms = 5_000;
        config.egress_connect_timeout_ms = 5_000;
        config.upstream_timeout_ms = Some(100);
        config.upstream_connect_timeout_ms = Some(100);
        let router = proxy_router(config, test_audit_log());

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/slow")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("proxy request should complete");

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(
            body_string(response).await,
            r#"{"error":"gateway_timeout"}"#
        );
        server.abort();
    }

    #[tokio::test]
    async fn proxy_returns_504_when_streaming_upstream_body_idles_before_first_chunk() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener should bind");
        let upstream_addr = listener
            .local_addr()
            .expect("listener address should be available");
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .expect("test server should accept a connection");
                tokio::spawn(async move {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .expect("test server should write response headers");
                    tokio::time::sleep(Duration::from_secs(10)).await;
                });
            }
        });
        let mut config = proxy_config(upstream_addr);
        config.egress_timeout_ms = 5_000;
        config.egress_response_idle_timeout_ms = 5_000;
        config.egress_connect_timeout_ms = 100;
        config.upstream_response_idle_timeout_ms = Some(100);
        let router = proxy_router(config, test_audit_log());

        let response = tokio::time::timeout(
            Duration::from_secs(1),
            router.oneshot(
                Request::builder()
                    .uri("/slow-body")
                    .body(Body::empty())
                    .expect("request should build"),
            ),
        )
        .await
        .expect("proxy should return idle timeout response")
        .expect("proxy request should complete");

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(
            body_string(response).await,
            r#"{"error":"gateway_timeout"}"#
        );
        server.abort();
    }

    #[tokio::test]
    async fn existing_routes_win_over_proxy_fallback() {
        let (upstream_addr, mut captured) = spawn_capture_upstream().await;
        let router = proxy_router(proxy_config(upstream_addr), test_audit_log());

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("health request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["status"], json!("ok"));
        assert_eq!(body["upstream"]["configured"], json!(true));
        assert_upstream_receives_no_request(&mut captured, "health route should not be proxied")
            .await;
    }

    #[tokio::test]
    async fn reserved_gateway_paths_never_reach_proxy_upstream() {
        let (upstream_addr, mut captured) = spawn_capture_upstream().await;
        let config = proxy_config(upstream_addr);
        let routes = GatewayRoutes::from_config(&config);
        let router = proxy_router(config, test_audit_log());

        let admin_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(routes.admin.ui_prefix.as_str())
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("admin UI request should complete");

        assert_eq!(admin_response.status(), StatusCode::OK);
        assert!(body_string(admin_response)
            .await
            .contains(r#"<div id="root"></div>"#));

        let audit_response = router
            .oneshot(audit_query_request(&routes.admin.audit_route, None))
            .await
            .expect("audit request should complete");

        assert_eq!(audit_response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_string(audit_response).await,
            r#"{"error":"unauthorized"}"#
        );
        assert_upstream_receives_no_request(
            &mut captured,
            "reserved admin UI and audit API paths should not be proxied",
        )
        .await;
    }

    #[tokio::test]
    async fn custom_admin_prefix_moves_admin_surface_and_frees_default_admin_path() {
        let (upstream_addr, mut captured) = spawn_capture_upstream().await;
        let mut config = proxy_config(upstream_addr);
        config.admin_prefix = "/ops".to_owned();
        config.auth_exempt_paths = vec![
            "/health".to_owned(),
            "/version".to_owned(),
            "/metrics".to_owned(),
            "/ops".to_owned(),
        ];
        config.rbac_exempt_paths = config.auth_exempt_paths.clone();
        let routes = GatewayRoutes::from_config(&config);
        let router = proxy_router(config, test_audit_log());

        let admin_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/ops")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("custom admin UI request should complete");

        assert_eq!(admin_response.status(), StatusCode::OK);
        let admin_body = body_string(admin_response).await;
        assert!(admin_body.contains(r#"<div id="root"></div>"#));
        assert!(admin_body.contains(r#"greengateway-admin-base" content="/ops""#));
        assert!(admin_body.contains(r#"greengateway-admin-api-base" content="/v1/ops""#));
        assert!(admin_body.contains(r#"/ops/assets/"#));

        let status_response = router
            .clone()
            .oneshot(audit_query_request(
                &routes.admin.status_route,
                Some(test_principal(&["admin"])),
            ))
            .await
            .expect("custom admin status request should complete");

        assert_eq!(status_response.status(), StatusCode::OK);
        let status_body = json_body(status_response).await;
        assert_eq!(status_body["version"], json!(env!("CARGO_PKG_VERSION")));

        let old_admin_response = router
            .oneshot(
                Request::builder()
                    .uri("/admin")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("old admin path request should complete");

        assert_eq!(old_admin_response.status(), StatusCode::CREATED);
        assert_eq!(body_string(old_admin_response).await, "upstream GET /admin");
        let upstream = next_proxied_request(
            &mut captured,
            "old admin path should fall through to upstream",
        )
        .await;
        assert_eq!(upstream.method, Method::GET);
        assert_eq!(upstream.path_and_query, "/admin");
        assert_upstream_receives_no_request(
            &mut captured,
            "custom admin UI and API paths should not be proxied",
        )
        .await;
    }

    #[tokio::test]
    async fn custom_admin_prefix_api_requires_and_accepts_real_bearer_auth() {
        let jwks_addr = spawn_test_jwks_server().await;
        let db = TempDb::new("custom-admin-real-auth");
        create_audit_schema(&db.path);
        let mut config = test_config(Vec::new());
        config.admin_prefix = "/ops".to_owned();
        config.auth_exempt_paths = vec![
            "/health".to_owned(),
            "/version".to_owned(),
            "/metrics".to_owned(),
            "/ops".to_owned(),
        ];
        config.rbac_exempt_paths = config.auth_exempt_paths.clone();
        config.audit_sqlite_path = Some(db.path.to_string_lossy().into_owned());
        config.jwt_jwks_url = Some(format!("http://127.0.0.1:{}/jwks.json", jwks_addr.port()));
        config.egress_deny_private_ips = false;
        let routes = GatewayRoutes::from_config(&config);
        assert_eq!(routes.admin.api_prefix, "/v1/ops");
        assert_eq!(routes.admin.audit_route, "/v1/ops/audit");

        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");

        let ui_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/ops")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("custom admin UI request should complete");
        assert_eq!(ui_response.status(), StatusCode::OK);

        let missing_token_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(routes.admin.audit_route.as_str())
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("unauthenticated custom audit request should complete");
        assert_eq!(missing_token_response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_string(missing_token_response).await,
            r#"{"error":"unauthorized"}"#
        );

        let token = signed_admin_token();
        let authenticated_response = router
            .oneshot(
                Request::builder()
                    .uri(routes.admin.audit_route.as_str())
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("authenticated custom audit request should complete");
        assert_eq!(authenticated_response.status(), StatusCode::OK);
        assert_eq!(json_body(authenticated_response).await["events"], json!([]));
    }

    #[tokio::test]
    async fn custom_admin_prefix_is_reserved_from_proxy_collisions() {
        let (upstream_addr, mut captured) = spawn_capture_upstream().await;
        let mut config = proxy_config(upstream_addr);
        config.admin_prefix = "/ops".to_owned();
        config.auth_exempt_paths = vec![
            "/health".to_owned(),
            "/version".to_owned(),
            "/metrics".to_owned(),
            "/ops".to_owned(),
        ];
        config.rbac_exempt_paths = config.auth_exempt_paths.clone();
        let routes = GatewayRoutes::from_config(&config);
        let router = proxy_router(config, test_audit_log());
        assert_eq!(routes.admin.api_prefix, "/v1/ops");
        assert!(routes.is_gateway_owned_path("/ops/assets/app.js"));
        assert!(routes.is_gateway_owned_path("/v1/ops/audit"));
        assert!(!routes.is_gateway_owned_path("/ops-api/audit"));

        let admin_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(routes.admin.ui_prefix.as_str())
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("custom admin UI request should complete");

        assert_eq!(admin_response.status(), StatusCode::OK);

        let audit_response = router
            .oneshot(audit_query_request(&routes.admin.audit_route, None))
            .await
            .expect("custom audit request should complete");

        assert_eq!(audit_response.status(), StatusCode::UNAUTHORIZED);
        assert_upstream_receives_no_request(
            &mut captured,
            "custom admin prefix collision should not reach upstream",
        )
        .await;
    }

    #[tokio::test]
    async fn fixed_probe_routes_win_over_proxy_with_custom_admin_prefix() {
        let (upstream_addr, mut captured) = spawn_capture_upstream().await;
        let mut config = proxy_config(upstream_addr);
        config.admin_prefix = "/ops".to_owned();
        let router = proxy_router(config, test_audit_log());

        for (uri, expected_status) in [
            ("/health", StatusCode::OK),
            ("/version", StatusCode::OK),
            ("/metrics", StatusCode::OK),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(uri)
                        .body(Body::empty())
                        .expect("request should build"),
                )
                .await
                .expect("probe route request should complete");

            assert_eq!(response.status(), expected_status, "{uri}");
        }
        assert_upstream_receives_no_request(
            &mut captured,
            "fixed probe routes should not be proxied with custom admin prefix",
        )
        .await;
    }

    #[tokio::test]
    async fn unmatched_paths_still_404_when_upstream_url_is_unset() {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.csrf_enabled = false;
        let router = proxy_router(config, test_audit_log());

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/unmatched")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn proxy_observation_event_includes_upstream_latency_and_status() {
        let (upstream_addr, _) = spawn_capture_upstream().await;
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let router = proxy_router(proxy_config(upstream_addr), audit_log);

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/observed")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("proxy request should complete");

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eventually(Duration::from_secs(1), || {
            capture
                .events()
                .iter()
                .any(|event| event.event_type == "http.request_observed")
        });
        let observed = capture
            .events()
            .into_iter()
            .find(|event| event.event_type == "http.request_observed")
            .expect("observation event should be captured");
        assert_eq!(observed.payload["path"], json!("/observed"));
        assert_eq!(observed.payload["status"], json!(201));
        assert_eq!(observed.payload["upstream_status"], json!(201));
        assert!(observed.payload["upstream_latency_ms"].as_u64().is_some());
    }

    #[tokio::test]
    async fn audit_query_without_principal_returns_unauthorized() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let response = app(
            audit_query_config(None),
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build")
        .oneshot(audit_query_request(AUDIT_ADMIN_ROUTE, None))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_string(response).await, r#"{"error":"unauthorized"}"#);
    }

    #[tokio::test]
    async fn audit_query_non_admin_principal_returns_forbidden_without_store_leak() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let response = app(
            audit_query_config(None),
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build")
        .oneshot(audit_query_request(
            AUDIT_ADMIN_ROUTE,
            Some(test_principal(&["reader"])),
        ))
        .await
        .expect("request should complete");

        let body = body_string(response).await;
        assert_eq!(body, r#"{"error":"forbidden"}"#);
        assert!(!body.contains("audit query store"));
    }

    #[tokio::test]
    async fn audit_events_stream_without_principal_returns_unauthorized() {
        let (router, _) = audit_events_router();

        let response = router
            .oneshot(audit_query_request(AUDIT_EVENTS_STREAM_ROUTE, None))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_string(response).await, r#"{"error":"unauthorized"}"#);
    }

    #[tokio::test]
    async fn audit_events_stream_non_admin_principal_returns_forbidden() {
        let (router, _) = audit_events_router();

        let response = router
            .oneshot(audit_query_request(
                AUDIT_EVENTS_STREAM_ROUTE,
                Some(test_principal(&["reader"])),
            ))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(body_string(response).await, r#"{"error":"forbidden"}"#);
    }

    #[tokio::test]
    async fn status_without_principal_returns_unauthorized() {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        let router = status_router(config, Instant::now());

        let response = router
            .oneshot(audit_query_request(STATUS_ADMIN_ROUTE, None))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_string(response).await, r#"{"error":"unauthorized"}"#);
    }

    #[tokio::test]
    async fn status_non_admin_principal_returns_forbidden() {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        let router = status_router(config, Instant::now());

        let response = router
            .oneshot(audit_query_request(
                STATUS_ADMIN_ROUTE,
                Some(test_principal(&["reader"])),
            ))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(body_string(response).await, r#"{"error":"forbidden"}"#);
    }

    #[tokio::test]
    async fn status_admin_response_reflects_running_config_values() {
        let sqlite_db = TempDb::new("status-sqlite");
        let policy = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "id": "status-policy",
                "default_action": "allow",
                "roles": {
                    "admin": { "permissions": ["*"] }
                }
            }"#,
        );
        let mut rich_config = test_config(vec!["https://example.test", "https://ops.example.test"]);
        rich_config.listen_addr = "127.0.0.1:18181"
            .parse()
            .expect("listen address should parse");
        rich_config.audit_log_file = Some("audit-a.jsonl".to_owned());
        rich_config.audit_sqlite_path = Some(sqlite_db.path.to_string_lossy().into_owned());
        rich_config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        rich_config.rate_limit_read_rps = 17.5;
        rich_config.rate_limit_read_burst = 31;
        rich_config.rate_limit_write_rps = 4.25;
        rich_config.rate_limit_write_burst = 9;
        rich_config.trust_proxy_headers = true;
        rich_config.auth_enabled = true;
        rich_config
            .auth_exempt_paths
            .push(STATUS_ADMIN_ROUTE.to_owned());
        rich_config.csrf_enabled = false;
        rich_config.egress_allowed_hosts = vec![
            "api.example.test".to_owned(),
            "tiles.example.test".to_owned(),
        ];
        rich_config.egress_deny_private_ips = false;

        let rich = status_json(
            status_router(rich_config, Instant::now() - Duration::from_secs(42)),
            Some(test_principal(&["admin"])),
        )
        .await;

        assert_eq!(rich["version"], env!("CARGO_PKG_VERSION"));
        assert!(rich["uptime_seconds"].as_u64().unwrap_or_default() >= 42);
        assert_eq!(rich["listen_addr"], "127.0.0.1:18181");
        assert_eq!(rich["auth_enabled"], true);
        assert_eq!(rich["rbac"]["policy_loaded"], true);
        assert_eq!(rich["rbac"]["policy_id"], "status-policy");
        assert_eq!(rich["audit_sinks"]["stdout"], true);
        assert_eq!(rich["audit_sinks"]["file"], true);
        assert_eq!(rich["audit_sinks"]["sqlite"], true);
        assert_eq!(rich["audit_sinks"]["broadcast"], true);
        assert_eq!(
            rich["rate_limits"]["read"]["requests_per_second"].as_f64(),
            Some(17.5)
        );
        assert_eq!(rich["rate_limits"]["read"]["burst"], 31);
        assert_eq!(
            rich["rate_limits"]["write"]["requests_per_second"].as_f64(),
            Some(4.25)
        );
        assert_eq!(rich["rate_limits"]["write"]["burst"], 9);
        assert_eq!(
            rich["cors_allow_origins"],
            json!(["https://example.test", "https://ops.example.test"])
        );
        assert_eq!(rich["trust_proxy_headers"], true);
        assert_eq!(rich["csrf_enabled"], false);
        assert_eq!(rich["egress"]["allowed_hosts_count"], 2);
        assert_eq!(rich["egress"]["deny_private_ips"], false);

        let mut minimal_config = test_config(Vec::new());
        minimal_config.listen_addr = "127.0.0.1:18182"
            .parse()
            .expect("listen address should parse");
        minimal_config.auth_enabled = false;
        minimal_config.rate_limit_read_rps = 61.25;
        minimal_config.rate_limit_read_burst = 77;
        minimal_config.rate_limit_write_rps = 8.5;
        minimal_config.rate_limit_write_burst = 12;

        let minimal = status_json(
            status_router(minimal_config, Instant::now() - Duration::from_secs(5)),
            Some(test_principal(&["admin"])),
        )
        .await;

        assert_eq!(minimal["listen_addr"], "127.0.0.1:18182");
        assert_eq!(minimal["auth_enabled"], false);
        assert_eq!(minimal["rbac"]["policy_loaded"], false);
        assert!(minimal["rbac"]["policy_id"].is_null());
        assert_eq!(minimal["audit_sinks"]["file"], false);
        assert_eq!(minimal["audit_sinks"]["sqlite"], false);
        assert_eq!(
            minimal["rate_limits"]["read"]["requests_per_second"].as_f64(),
            Some(61.25)
        );
        assert_eq!(minimal["rate_limits"]["read"]["burst"], 77);
        assert_eq!(
            minimal["rate_limits"]["write"]["requests_per_second"].as_f64(),
            Some(8.5)
        );
        assert_eq!(minimal["rate_limits"]["write"]["burst"], 12);
        assert_eq!(minimal["cors_allow_origins"], json!([]));
        assert_eq!(minimal["egress"]["allowed_hosts_count"], 0);
        assert_eq!(minimal["egress"]["deny_private_ips"], true);
    }

    #[tokio::test]
    async fn status_reports_effective_egress_allowlist_count() {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.auth_exempt_paths.push(STATUS_ADMIN_ROUTE.to_owned());
        config.egress_allowed_hosts = vec!["api.example.test".to_owned()];
        config.upstream_url = Some("https://upstream.example.test/base".to_owned());
        let router = status_router(config, Instant::now());

        let status = status_json(router, Some(test_principal(&["admin"]))).await;

        assert_eq!(status["egress"]["allowed_hosts_count"], 2);
    }

    #[tokio::test]
    async fn status_uptime_increases_between_requests() {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        let router = status_router(config, Instant::now() - Duration::from_secs(30));

        let first = status_json(router.clone(), Some(test_principal(&["admin"]))).await;
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let second = status_json(router, Some(test_principal(&["admin"]))).await;

        let first_uptime = first["uptime_seconds"]
            .as_u64()
            .expect("uptime should be an integer");
        let second_uptime = second["uptime_seconds"]
            .as_u64()
            .expect("uptime should be an integer");

        assert!(first_uptime >= 30);
        assert!(
            second_uptime > first_uptime,
            "expected uptime to increase, got {first_uptime} then {second_uptime}"
        );
    }

    #[tokio::test]
    async fn audit_events_stream_admin_principal_receives_emitted_event() {
        let (router, audit_log) = audit_events_router();
        let response = router
            .oneshot(audit_query_request(
                AUDIT_EVENTS_STREAM_ROUTE,
                Some(test_principal(&["admin"])),
            ))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let event = test_stream_event("audit.sse.direct", "/direct");
        audit_log.emit(event.clone());

        let body = read_sse_until(response.into_body(), |body| {
            contains_event_id(body, &event.event_id)
        })
        .await;

        assert!(body.contains("event: audit.sse.direct"));
        assert!(body.contains(&format!(r#""path":"/direct""#)));
    }

    #[tokio::test]
    async fn audit_events_stream_filters_by_event_type_and_path() {
        let (router, audit_log) = audit_events_router();
        let response = router
            .oneshot(audit_query_request(
                &format!("{AUDIT_EVENTS_STREAM_ROUTE}?event_type=audit.sse.match&path=/match"),
                Some(test_principal(&["admin"])),
            ))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let wrong_type = test_stream_event("audit.sse.skip", "/match");
        let wrong_path = test_stream_event("audit.sse.match", "/skip");
        let matching = test_stream_event("audit.sse.match", "/match");
        audit_log.emit(wrong_type.clone());
        audit_log.emit(wrong_path.clone());
        audit_log.emit(matching.clone());

        let body = read_sse_until(response.into_body(), |body| {
            contains_event_id(body, &matching.event_id)
        })
        .await;

        assert!(contains_event_id(&body, &matching.event_id));
        assert!(!contains_event_id(&body, &wrong_type.event_id));
        assert!(!contains_event_id(&body, &wrong_path.event_id));
    }

    #[tokio::test]
    async fn audit_events_stream_delivers_request_event_within_latency_budget() {
        let (router, _) = audit_events_router();
        let response = router
            .clone()
            .oneshot(audit_query_request(
                &format!(
                    "{AUDIT_EVENTS_STREAM_ROUTE}?event_type=http.request_observed&path=/health"
                ),
                Some(test_principal(&["admin"])),
            ))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let started = Instant::now();
        let health_response = router
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("health request should complete");
        assert_eq!(health_response.status(), StatusCode::OK);

        let body = read_sse_until(response.into_body(), |body| {
            body.contains(r#""event_type":"http.request_observed""#)
                && body.contains(r#""path":"/health""#)
        })
        .await;

        assert!(body.contains(r#""status":200"#));
        // The issue target is roughly 100ms; this keeps CI stable while still
        // proving the audit writer and in-process broadcast do not add seconds
        // of delay.
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "streamed audit event arrived after {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn shadow_would_deny_events_are_queryable_and_streamable() {
        let db = TempDb::new("shadow-would-deny");
        let policy = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "default_action": "allow",
                "enforcement_mode": "shadow",
                "roles": {},
                "routes": [
                    {
                        "path_prefix": "/__test",
                        "permission": "test:read"
                    }
                ]
            }"#,
        );
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.audit_sqlite_path = Some(db.path.to_string_lossy().into_owned());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config.rbac_exempt_paths.push("/v1/admin".to_owned());
        let recorder = PrometheusBuilder::new().build_recorder();
        let (audit_log, audit_event_sender) = audit_log_with_sqlite_and_broadcast(&db.path);
        let router = app(config, recorder.handle(), audit_log, audit_event_sender)
            .expect("app should build");
        let request_id = "request-shadow-would-deny";
        let stream_response = router
            .clone()
            .oneshot(audit_query_request(
                &format!(
                    "{AUDIT_EVENTS_STREAM_ROUTE}?event_type=authz.would_deny&path=/__test/principal"
                ),
                Some(test_principal(&["admin"])),
            ))
            .await
            .expect("stream request should complete");
        assert_eq!(stream_response.status(), StatusCode::OK);

        let shadow_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/__test/principal")
                    .header(REQUEST_ID_HEADER, request_id)
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("shadow request should complete");
        assert_eq!(shadow_response.status(), StatusCode::NO_CONTENT);

        let stream_body = read_sse_until(stream_response.into_body(), |body| {
            body.contains(r#""event_type":"authz.would_deny""#)
                && body.contains(&format!(r#""request_id":"{request_id}""#))
        })
        .await;
        assert!(stream_body.contains("event: authz.would_deny"));
        assert!(stream_body.contains(r#""path":"/__test/principal""#));
        assert!(stream_body.contains(r#""path_prefix":"/__test""#));
        assert!(stream_body.contains(r#""permission":"test:read""#));
        assert!(stream_body.contains(r#""reason":"missing_principal""#));

        let body = wait_for_audit_query_event(
            router,
            "/v1/admin/audit?event_type=authz.would_deny",
            request_id,
        )
        .await;
        let event = body["events"]
            .as_array()
            .expect("events should be an array")
            .iter()
            .find(|event| event["request_id"] == json!(request_id))
            .expect("queried would-deny event should be present");
        assert_eq!(event["event_type"], json!("authz.would_deny"));
        assert_eq!(event["payload"]["path"], json!("/__test/principal"));
        assert_eq!(event["payload"]["path_prefix"], json!("/__test"));
        assert_eq!(event["payload"]["permission"], json!("test:read"));
        assert_eq!(event["payload"]["reason"], json!("missing_principal"));
    }

    #[test]
    fn stalled_sse_consumer_does_not_slow_audit_emit_burst() {
        const BURST_EVENTS: usize = 20_000;

        let event = test_stream_event("audit.sse.backpressure", "/burst");
        let baseline_log = test_audit_log();
        let baseline = emit_burst(&baseline_log, &event, BURST_EVENTS);

        let (audit_log, sender) = test_audit_log_with_broadcast();
        let _stalled_consumer = sender.subscribe();
        let stalled = emit_burst(&audit_log, &event, BURST_EVENTS);

        let allowed = baseline.mul_f64(20.0).max(Duration::from_millis(200));
        assert!(
            stalled < allowed,
            "stalled subscriber burst took {stalled:?}, baseline was {baseline:?}, allowed {allowed:?}"
        );
        assert!(
            stalled < Duration::from_secs(1),
            "stalled subscriber burst took {stalled:?}"
        );
    }

    #[tokio::test]
    async fn audit_query_admin_principal_filters_events() {
        let db = TempDb::new("audit-query-filters");
        create_audit_schema(&db.path);
        seed_filter_events(&db.path);
        let router = audit_query_router(Some(&db.path));

        assert_eq!(
            audit_event_ids(router.clone(), "/v1/admin/audit?event_type=audit.policy").await,
            vec!["fractionally-newer-event".to_owned()]
        );
        assert_eq!(
            audit_event_ids(router.clone(), "/v1/admin/audit?actor=bob").await,
            vec!["fractionally-newer-event".to_owned()]
        );
        assert_eq!(
            audit_event_ids(router.clone(), "/v1/admin/audit?path=/admin").await,
            vec!["fractionally-newer-event".to_owned()]
        );
        assert_eq!(
            audit_event_ids(router.clone(), "/v1/admin/audit?status=403").await,
            vec!["fractionally-newer-event".to_owned()]
        );
        assert_eq!(
            audit_event_ids(
                router,
                "/v1/admin/audit?from=2024-06-01T12:00:00Z&to=2024-06-01T12:00:00.5Z",
            )
            .await,
            vec![
                "fractionally-newer-event".to_owned(),
                "cutoff-event".to_owned()
            ]
        );
    }

    #[tokio::test]
    async fn audit_query_paginates_with_keyset_cursor_without_gaps() {
        let db = TempDb::new("audit-query-pagination");
        create_audit_schema(&db.path);
        for index in 0..25 {
            insert_audit_event(
                &db.path,
                SeedAuditEvent {
                    event_id: &format!("page-event-{index:02}"),
                    event_type: "audit.page",
                    timestamp: "2024-06-01T12:00:00Z",
                    actor_user_id: "admin-user",
                    path: "/page",
                    status: 200,
                },
            );
        }
        let router = audit_query_router(Some(&db.path));
        let mut next_cursor = None;
        let mut returned = Vec::new();
        let mut seen = HashSet::new();

        loop {
            let uri = match next_cursor {
                Some(cursor) => format!("/v1/admin/audit?limit=10&before_id={cursor}"),
                None => "/v1/admin/audit?limit=10".to_owned(),
            };
            let response = router
                .clone()
                .oneshot(audit_query_request(&uri, Some(test_principal(&["admin"]))))
                .await
                .expect("request should complete");
            assert_eq!(response.status(), StatusCode::OK);

            let body = json_body(response).await;
            let ids = event_ids_from_body(&body);
            for id in ids {
                assert!(seen.insert(id.clone()), "duplicate event id {id}");
                returned.push(id);
            }

            next_cursor = body["next_cursor"].as_i64();
            if next_cursor.is_none() {
                break;
            }
        }

        let expected = (0..25)
            .rev()
            .map(|index| format!("page-event-{index:02}"))
            .collect::<Vec<_>>();
        assert_eq!(returned, expected);
    }

    #[tokio::test]
    async fn audit_query_admin_principal_without_store_returns_service_unavailable() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let response = app(
            audit_query_config(None),
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build")
        .oneshot(audit_query_request(
            AUDIT_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
        ))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body_string(response).await,
            r#"{"error":"audit query store not configured"}"#
        );
    }

    #[tokio::test]
    async fn audit_query_malformed_params_return_bad_request() {
        let db = TempDb::new("audit-query-malformed");
        create_audit_schema(&db.path);
        let router = audit_query_router(Some(&db.path));

        for (uri, parameter) in [
            ("/v1/admin/audit?status=not-a-number", "status"),
            ("/v1/admin/audit?from=not-a-date", "from"),
            ("/v1/admin/audit?before_id=-1", "before_id"),
            ("/v1/admin/audit?before_id=not-a-number", "before_id"),
            ("/v1/admin/audit?limit=0", "limit"),
        ] {
            let response = router
                .clone()
                .oneshot(audit_query_request(uri, Some(test_principal(&["admin"]))))
                .await
                .expect("request should complete");

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                body_string(response).await,
                format!(r#"{{"error":"invalid query parameter: {parameter}"}}"#)
            );
        }
    }

    #[tokio::test]
    async fn auth_runs_before_rbac_for_non_exempt_routes() {
        let policy = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "default_action": "deny",
                "roles": {}
            }"#,
        );
        let mut config = test_config(Vec::new());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        let recorder = PrometheusBuilder::new().build_recorder();

        let response = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build")
        .oneshot(
            Request::builder()
                .uri("/__test/principal")
                .header(header::AUTHORIZATION, "Bearer token-123")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn cors_allows_allowlisted_origin() {
        let response = preflight_response(
            test_config(vec!["http://localhost:3000"]),
            "http://localhost:3000",
        )
        .await;

        assert_eq!(
            response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&HeaderValue::from_static("http://localhost:3000"))
        );
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS),
            Some(&HeaderValue::from_static("true"))
        );
    }

    #[tokio::test]
    async fn cors_preflight_to_non_exempt_path_succeeds_without_credential() {
        let response = preflight_response_to_path(
            test_config(vec!["http://localhost:3000"]),
            "/__test/principal",
            "http://localhost:3000",
        )
        .await;

        assert!(response.status().is_success());
        assert_eq!(
            response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&HeaderValue::from_static("http://localhost:3000"))
        );
        assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
    }

    #[tokio::test]
    async fn bare_options_without_origin_stops_at_cors_layer_before_handler() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let response = app(
            test_config(vec!["http://localhost:3000"]),
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build")
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/__test/principal")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

        // tower-http 0.6.8's CorsLayer handles bare OPTIONS requests before
        // auth. If this reached the unauthenticated test handler, it would
        // return 204; if CorsLayer passed it through to auth, auth would fail
        // closed with 401 as proven by the auth middleware unit test.
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
        assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
    }

    #[tokio::test]
    async fn cors_rejects_non_allowlisted_origin() {
        let response = preflight_response(
            test_config(vec!["http://localhost:3000"]),
            "http://localhost:4000",
        )
        .await;

        assert!(!response
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    #[tokio::test]
    async fn default_cors_origin_list_allows_no_cross_origin_requests() {
        let response = preflight_response(test_config(Vec::new()), "http://localhost:3000").await;

        assert!(!response
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    }

    #[tokio::test]
    async fn outer_layers_wrap_validation_rejections() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let response = app(
            test_config(Vec::new()),
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build")
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/health")
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("hello"))
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert!(response.headers().contains_key(REQUEST_ID_HEADER));
    }

    #[tokio::test]
    async fn validation_runs_before_csrf() {
        let config = test_config(Vec::new());
        assert!(config.csrf_enabled);

        let recorder = PrometheusBuilder::new().build_recorder();
        let response = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build")
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/does-not-exist")
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("hello"))
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

        // This proves ordering because CSRF is enabled and the path is not exempt.
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn rate_limit_runs_before_validation() {
        let mut config = test_config(Vec::new());
        config.max_body_size = 1;
        config.rate_limit_read_rps = 0.0;
        config.rate_limit_read_burst = 1;

        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/health")
                    .header(header::CONTENT_LENGTH, "2")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    fn audit_query_config(sqlite_path: Option<&PathBuf>) -> config::Config {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.audit_sqlite_path = sqlite_path.map(|path| path.to_string_lossy().into_owned());
        config
    }

    fn audit_query_router(sqlite_path: Option<&PathBuf>) -> Router {
        let recorder = PrometheusBuilder::new().build_recorder();
        app(
            audit_query_config(sqlite_path),
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build")
    }

    fn audit_events_router() -> (Router, audit::AuditLog) {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        let recorder = PrometheusBuilder::new().build_recorder();
        let (audit_log, audit_event_sender) = test_audit_log_with_broadcast();
        let router = app(
            config,
            recorder.handle(),
            audit_log.clone(),
            audit_event_sender,
        )
        .expect("app should build");

        (router, audit_log)
    }

    fn status_router(config: config::Config, process_started_at: Instant) -> Router {
        let recorder = PrometheusBuilder::new().build_recorder();
        app_with_process_started_at(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
            process_started_at,
        )
        .expect("app should build")
    }

    fn audit_query_request(uri: &str, principal: Option<auth::Principal>) -> Request<Body> {
        let mut request = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request should build");
        if let Some(principal) = principal {
            request.extensions_mut().insert(principal);
        }

        request
    }

    async fn status_json(router: Router, principal: Option<auth::Principal>) -> Value {
        let response = router
            .oneshot(audit_query_request(STATUS_ADMIN_ROUTE, principal))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        json_body(response).await
    }

    async fn read_sse_until(body: Body, predicate: impl Fn(&str) -> bool) -> String {
        let mut stream = body.into_data_stream();

        tokio::time::timeout(Duration::from_secs(2), async move {
            let mut body = String::new();

            while body.len() < 65_536 {
                let Some(chunk) = stream.next().await else {
                    panic!("SSE stream ended before expected event arrived");
                };
                let chunk = chunk.expect("SSE chunk should read");
                body.push_str(std::str::from_utf8(&chunk).expect("SSE chunk should be UTF-8"));

                if predicate(&body) {
                    return body;
                }
            }

            panic!("SSE stream exceeded bounded read without expected event");
        })
        .await
        .expect("SSE event should arrive before timeout")
    }

    fn contains_event_id(body: &str, event_id: &str) -> bool {
        body.contains(&format!(r#""event_id":"{event_id}""#))
    }

    fn emit_burst(
        audit_log: &audit::AuditLog,
        event: &audit::AuditEvent,
        count: usize,
    ) -> Duration {
        let started = Instant::now();

        for _ in 0..count {
            audit_log.emit(event.clone());
        }

        started.elapsed()
    }

    fn test_stream_event(event_type: &str, path: &str) -> audit::AuditEvent {
        audit::AuditEvent::new(
            event_type,
            "request-sse",
            "203.0.113.10",
            None,
            json!({
                "path": path,
                "status": 200
            }),
        )
    }

    async fn audit_event_ids(router: Router, uri: &str) -> Vec<String> {
        let response = router
            .oneshot(audit_query_request(uri, Some(test_principal(&["admin"]))))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        event_ids_from_body(&json_body(response).await)
    }

    async fn wait_for_audit_query_event(router: Router, uri: &str, request_id: &str) -> Value {
        let started = Instant::now();

        loop {
            let response = router
                .clone()
                .oneshot(audit_query_request(uri, Some(test_principal(&["admin"]))))
                .await
                .expect("audit query request should complete");
            assert_eq!(response.status(), StatusCode::OK);
            let body = json_body(response).await;
            let found = body["events"]
                .as_array()
                .expect("events should be an array")
                .iter()
                .any(|event| event["request_id"] == json!(request_id));
            if found {
                return body;
            }

            assert!(
                started.elapsed() < Duration::from_secs(2),
                "audit query did not return event with request_id {request_id}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    fn event_ids_from_body(body: &Value) -> Vec<String> {
        body["events"]
            .as_array()
            .expect("events should be an array")
            .iter()
            .map(|event| {
                event["event_id"]
                    .as_str()
                    .expect("event_id should be a string")
                    .to_owned()
            })
            .collect()
    }

    async fn json_body(response: axum::response::Response) -> Value {
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body should read"),
        )
        .expect("body should be JSON")
    }

    async fn body_string(response: axum::response::Response) -> String {
        String::from_utf8(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body should read")
                .to_vec(),
        )
        .expect("body should be UTF-8")
    }

    fn assert_content_type_starts_with(headers: &http::HeaderMap, expected: &str) {
        let content_type = headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .expect("content type should be present");

        assert!(
            content_type.starts_with(expected),
            "expected content type to start with {expected}, got {content_type}"
        );
    }

    fn test_principal(roles: &[&str]) -> auth::Principal {
        auth::Principal {
            user_id: "user-123".to_owned(),
            email: Some("user@example.com".to_owned()),
            org_id: Some("org-456".to_owned()),
            roles: roles.iter().map(|role| (*role).to_owned()).collect(),
            session_id: "session-789".to_owned(),
            auth_method: auth::AuthMethod::Bearer,
        }
    }

    const TEST_JWT_KID: &str = "test-kid";
    const TEST_JWT_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCnhXdj9xmwS1xg
0FSkz/Czegzbs7x52/LjNeVoaKsKFiiZh2X6TfeNv9FBHlqaP4crN3ONOutajg2o
jVy2LqOlmX0oWOsu7s9x1SZoy18N5jtOw/knSsYDc4y6ir/0H/WNRf+qMZXo/ZGU
eDU0C2fONU0XXaGWD3ypaQeqClnSInMIIjpJ0gATyGPJVNuVgmdeYdkNBdmlOKrX
dsRg7UjAmt9WXgCm6w1MRAIeZJ6cTNhQ5cx0JBVZRxeNRcVDpXx+IW6QC+HWTcbr
GxGpNzC1AaY9q67VyV/nLypaLF2m4SyKrYbkf5azoyH7zkpvpb6mgJPjdYlhO5M8
dVHvbB81AgMBAAECggEAByEJ7KomYLdETiZvg7gJsUmfZHYorjLrCjpP8fqKVNqO
jcISV+2bfF/OYuwMxQWxFei9NSRtwaPL9wFVEbe4ZSK8DcyC7bNiBqEgilMlT20d
1wNGBiMLfDgdpA6ljpkRlRqGf9KuY4Tu/heDhBx8JW1lQ3pLlxw/nOIIXnckTWny
I5qOpk5XZ/QzJNC2ze0F2VsQ5RAGNdDG9vKHm5qeYHzgM1z9SOUMXsfPYOiXvdZP
BPa59BdP7cmXDVCuh12ZhpVnDErYtA9iPXqmoAah14JP4xKju5QIvavsQt9S8gB5
cxhAu4LmT9p1iOsKaDsG44gxUzmHS0bcuoIgFzDh4QKBgQDp3q9If/ZfZuu3+NPr
F/o36JvUY5SPnbYf1p5hSyBkVhTzKyGiYq7W0Lxs/RcOhw8YlfNfzqRNnhjmZhlE
FXpUCSXVSAtdC3MpCx2XimZltJ+TdIzajeWmh2Wx6SpJJek10UL2n6ht2BBALWyz
Dt2s709dVlxfYwHnZWBe4xxJTQKBgQC3X4prVHXcIKTyNyMS8cC/iMgbOu+Q58CF
VnBuRWsL96vzrHUgUcoYNTPbMOjm98Wzrk2roW+fnDMp0Y8ZusceKOVraihDifN2
yQ2H053ctC8YEvZeOE6JlDq+llAGnRv+113pmfZ51qNeVFcwdR5ujhAunnW7UC28
+IGqI3H5iQKBgQDik2iUP8zsbqTuLrb5K9iyM7xND1DNtsjMnbwBnKw8KR3Q3LeQ
QDUNT1tN6AFfhL++XQBVkLijrgiHpuDRklFaeyZZNJw1v7MJT4iS2XYNEOoNDLyt
vQ2BwelnbPMXvQ/soNlUYCfoi4xq8Nc/vqZLNepZDiMeEqi0iwXLyBIOfQKBgQCv
wF1to2TXF16gXCI8vQKNUO7h0mncS5Mk+QUHW3dO4BGpmegkkt+Mtik+czE2ddHB
9lSxJChVJSOQeC6cbXz8thu1COkQWn7Doc1bGoLaDsR4YWxKP9NeX3iyRGTtAdXc
OdTj2VH30rV/6nwqkIYbVgPCetPCNQWxccjtJc3OaQKBgHGijhVSMmlnGeAIiPmq
0hj0A9bv7QQz5M2TS+yuhQjHDJWa4Asic+AkgfOu5belhSDd13QCou1r8CcUc9uv
mu96vvRxLhwFLatFo4mL0WnOwBvMrR+5YwboH7Er4PBhmVJ2UKiQn8bNX3qdhVTp
O2gecI9QwDJNpm29J9wJB2F8
-----END PRIVATE KEY-----"#;
    const TEST_JWT_PUBLIC_KEY_N: &str = "p4V3Y_cZsEtcYNBUpM_ws3oM27O8edvy4zXlaGirChYomYdl-k33jb_RQR5amj-HKzdzjTrrWo4NqI1cti6jpZl9KFjrLu7PcdUmaMtfDeY7TsP5J0rGA3OMuoq_9B_1jUX_qjGV6P2RlHg1NAtnzjVNF12hlg98qWkHqgpZ0iJzCCI6SdIAE8hjyVTblYJnXmHZDQXZpTiq13bEYO1IwJrfVl4ApusNTEQCHmSenEzYUOXMdCQVWUcXjUXFQ6V8fiFukAvh1k3G6xsRqTcwtQGmPauu1clf5y8qWixdpuEsiq2G5H-Ws6Mh-85Kb6W-poCT43WJYTuTPHVR72wfNQ";
    const TEST_JWT_PUBLIC_KEY_E: &str = "AQAB";

    async fn spawn_test_jwks_server() -> std::net::SocketAddr {
        let jwks = json!({
            "keys": [{
                "kty": "RSA",
                "kid": TEST_JWT_KID,
                "use": "sig",
                "alg": "RS256",
                "n": TEST_JWT_PUBLIC_KEY_N,
                "e": TEST_JWT_PUBLIC_KEY_E
            }]
        });

        spawn_router(Router::new().route(
            "/jwks.json",
            get(move || {
                let jwks = jwks.clone();
                async move { Json(jwks) }
            }),
        ))
        .await
    }

    fn signed_admin_token() -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(TEST_JWT_KID.to_owned());
        let claims = json!({
            "sub": "user-123",
            "email": "User@Example.COM",
            "exp": OffsetDateTime::now_utc().unix_timestamp() + 3600,
            "jti": "session-123",
            "roles": ["admin"]
        });

        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(TEST_JWT_PRIVATE_KEY.as_bytes())
                .expect("test RSA private key should parse"),
        )
        .expect("test token should sign")
    }

    fn create_audit_schema(path: &PathBuf) {
        drop(
            audit::sqlite_sink::SqliteSink::new(audit::sqlite_sink::SqliteSinkConfig {
                path: path.clone(),
                retention_days: None,
            })
            .expect("SQLite sink should create audit schema"),
        );
    }

    fn seed_filter_events(path: &PathBuf) {
        insert_audit_event(
            path,
            SeedAuditEvent {
                event_id: "older-event",
                event_type: "audit.auth",
                timestamp: "2024-06-01T11:59:59.5Z",
                actor_user_id: "alice",
                path: "/login",
                status: 200,
            },
        );
        insert_audit_event(
            path,
            SeedAuditEvent {
                event_id: "cutoff-event",
                event_type: "audit.auth",
                timestamp: "2024-06-01T12:00:00Z",
                actor_user_id: "alice",
                path: "/login",
                status: 200,
            },
        );
        insert_audit_event(
            path,
            SeedAuditEvent {
                event_id: "fractionally-newer-event",
                event_type: "audit.policy",
                timestamp: "2024-06-01T12:00:00.5Z",
                actor_user_id: "bob",
                path: "/admin",
                status: 403,
            },
        );
        insert_audit_event(
            path,
            SeedAuditEvent {
                event_id: "later-event",
                event_type: "audit.egress",
                timestamp: "2024-06-01T12:00:01Z",
                actor_user_id: "carol",
                path: "/upstream",
                status: 502,
            },
        );
    }

    struct SeedAuditEvent<'a> {
        event_id: &'a str,
        event_type: &'a str,
        timestamp: &'a str,
        actor_user_id: &'a str,
        path: &'a str,
        status: i64,
    }

    fn insert_audit_event(path: &PathBuf, event: SeedAuditEvent<'_>) {
        let connection = Connection::open(path).expect("test database should open");
        let actor_json = json!({
            "user_id": event.actor_user_id,
            "roles": ["admin"],
            "auth_mode": "bearer_token"
        })
        .to_string();
        let payload_json = json!({
            "path": event.path,
            "status": event.status
        })
        .to_string();

        connection
            .execute(
                r#"
                INSERT INTO audit_events (
                    event_id,
                    event_type,
                    timestamp,
                    schema_version,
                    request_id,
                    source_ip,
                    actor_user_id,
                    actor_json,
                    payload_path,
                    payload_status,
                    payload_json
                ) VALUES (?1, ?2, ?3, '0.1.0', 'request-test', '203.0.113.10', ?4, ?5, ?6, ?7, ?8)
                "#,
                params![
                    event.event_id,
                    event.event_type,
                    event.timestamp,
                    event.actor_user_id,
                    actor_json,
                    event.path,
                    event.status,
                    payload_json
                ],
            )
            .expect("event should insert");
    }

    struct TempDb {
        path: PathBuf,
    }

    impl TempDb {
        fn new(test_name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-main-{test_name}-{}.sqlite",
                uuid::Uuid::new_v4()
            ));

            Self { path }
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let path = PathBuf::from(format!("{}{}", self.path.display(), suffix));
                let _ = fs::remove_file(path);
            }
        }
    }

    struct TempPolicyFile {
        path: PathBuf,
    }

    impl TempPolicyFile {
        fn new(contents: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-app-policy-test-{}.json",
                uuid::Uuid::new_v4()
            ));
            fs::write(&path, contents)
                .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));

            Self { path }
        }
    }

    impl Drop for TempPolicyFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    fn assert_eventually(timeout: Duration, condition: impl Fn() -> bool) {
        let started = Instant::now();

        while started.elapsed() < timeout {
            if condition() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(
            condition(),
            "condition did not become true within {timeout:?}"
        );
    }
}
