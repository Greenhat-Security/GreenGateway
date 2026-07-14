use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    convert::Infallible,
    fs,
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{Path, Query, Request as AxumRequest, State},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{any, get, patch, post, put},
    Extension, Json, Router,
};
use bytes::Bytes;
use futures_util::{stream, Stream, StreamExt};
use http::{header, HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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
mod discovery;
mod egress;
mod mcp;
mod metrics;
mod middleware;
mod path_match;
mod rbac;
mod tools;
mod upstream_route;

const REQUEST_COUNTER: &str = "gateway_http_requests";
const REQUEST_ID_HEADER: &str = "x-request-id";
const ADMIN_UI_ROUTE: &str = "/admin";
const ADMIN_UI_INDEX: &str = "index.html";
const ADMIN_UI_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
const DEFAULT_ADMIN_API_PREFIX: &str = "/v1/admin";
const AUDIT_ADMIN_ROUTE: &str = "/v1/admin/audit";
const AUDIT_EVENTS_STREAM_ROUTE: &str = "/v1/admin/events/stream";
const ADMIN_AUTH_LOGIN_ROUTE: &str = "/v1/admin/auth/login";
const ADMIN_AUTH_CALLBACK_ROUTE: &str = "/v1/admin/auth/callback";
const STATUS_ADMIN_ROUTE: &str = "/v1/admin/status";
const POLICY_ADMIN_ROUTE: &str = "/v1/admin/policy";
const POLICY_HISTORY_ADMIN_ROUTE: &str = "/v1/admin/policy/history";
const POLICY_HISTORY_WARNING_HEADER: &str = "x-greengateway-policy-history-warning";
const POLICY_HISTORY_APPEND_FAILED_WARNING: &str = "policy_history_append_failed";
#[cfg(test)]
const POLICY_ROLLBACK_ADMIN_ROUTE_PREFIX: &str = "/v1/admin/policy/rollback";
const POLICY_ROLLBACK_ADMIN_ROUTE: &str = "/v1/admin/policy/rollback/{version}";
const POLICY_RULE_PREVIEW_ADMIN_ROUTE: &str = "/v1/admin/policy/rules/preview";
const POLICY_RULE_HITS_ADMIN_ROUTE: &str = "/v1/admin/policy/rules/hits";
const POLICY_RULE_SHADOW_REVIEW_ADMIN_ROUTE: &str = "/v1/admin/policy/rules/shadow-review";
const POLICY_VALIDATE_ADMIN_ROUTE: &str = "/v1/admin/policy/validate";
const POLICY_RULES_ADMIN_ROUTE: &str = "/v1/admin/policy/rules";
const POLICY_RULE_ADMIN_ROUTE: &str = "/v1/admin/policy/rules/{id}";
const POLICY_RULES_ORDER_ADMIN_ROUTE: &str = "/v1/admin/policy/rules/order";
const TOKENS_ADMIN_ROUTE: &str = "/v1/admin/tokens";
const TOKEN_ADMIN_ROUTE: &str = "/v1/admin/tokens/{id}";
const TOKEN_ROTATE_ADMIN_ROUTE: &str = "/v1/admin/tokens/{id}/rotate";
const TOOLS_OPENAPI_PREVIEW_ADMIN_ROUTE: &str = "/v1/admin/tools/openapi/preview";
const TOOLS_OPENAPI_REGISTER_ADMIN_ROUTE: &str = "/v1/admin/tools/openapi/register";
const OPENAPI_TOOLS_UNSUPPORTED_AUTH_REQUIREMENTS_ERROR: &str = "cannot register selected OpenAPI tools: upstream API-key header injection is not yet supported; see issue #36's known limitation";
const SCHEMA_COVERAGE_ADMIN_ROUTE: &str = "/v1/admin/schema/coverage";
const SIGNALS_ADMIN_ROUTE: &str = "/v1/admin/signals";
const SIGNAL_ACKNOWLEDGE_ADMIN_ROUTE: &str = "/v1/admin/signals/{id}/acknowledge";
const SIGNAL_DISMISS_ADMIN_ROUTE: &str = "/v1/admin/signals/{id}/dismiss";
const SUGGESTIONS_ADMIN_ROUTE: &str = "/v1/admin/suggestions";
const SUGGESTIONS_GENERATE_ADMIN_ROUTE: &str = "/v1/admin/suggestions/generate";
const SUGGESTION_ACCEPT_ADMIN_ROUTE: &str = "/v1/admin/suggestions/{id}/accept";
const SUGGESTION_DISMISS_ADMIN_ROUTE: &str = "/v1/admin/suggestions/{id}/dismiss";
const SCHEMA_INFERRED_ADMIN_ROUTE: &str = "/v1/admin/schema/inferred";
const TRAFFIC_ENDPOINTS_ADMIN_ROUTE: &str = "/v1/admin/traffic/endpoints";
const TRAFFIC_ENDPOINT_DETAIL_ADMIN_ROUTE: &str = "/v1/admin/traffic/endpoint";
const TRAFFIC_ENDPOINT_REVIEW_ADMIN_ROUTE: &str = "/v1/admin/traffic/endpoints/review";
const PRINCIPALS_ADMIN_ROUTE: &str = "/v1/admin/principals";
const PRINCIPAL_ADMIN_ROUTE: &str = "/v1/admin/principal";
const ADMIN_AUDIT_READ_PERMISSION: &str = "admin:audit:read";
const ADMIN_AUDIT_STREAM_PERMISSION: &str = "admin:audit:stream";
const ADMIN_STATUS_READ_PERMISSION: &str = "admin:status:read";
const ADMIN_POLICY_READ_PERMISSION: &str = "admin:policy:read";
const ADMIN_POLICY_WRITE_PERMISSION: &str = "admin:policy:write";
const ADMIN_TOKENS_READ_PERMISSION: &str = "admin:tokens:read";
const ADMIN_TOKENS_WRITE_PERMISSION: &str = "admin:tokens:write";
const ADMIN_TOOLS_READ_PERMISSION: &str = "admin:tools:read";
const ADMIN_TOOLS_WRITE_PERMISSION: &str = "admin:tools:write";
const ADMIN_SCHEMA_READ_PERMISSION: &str = "admin:schema:read";
const ADMIN_SIGNALS_READ_PERMISSION: &str = "admin:signals:read";
const ADMIN_SIGNALS_WRITE_PERMISSION: &str = "admin:signals:write";
const ADMIN_SUGGESTIONS_READ_PERMISSION: &str = "admin:suggestions:read";
const ADMIN_SUGGESTIONS_WRITE_PERMISSION: &str = "admin:suggestions:write";
const ADMIN_TRAFFIC_READ_PERMISSION: &str = "admin:traffic:read";
const ADMIN_TRAFFIC_WRITE_PERMISSION: &str = "admin:traffic:write";
const ADMIN_PRINCIPALS_READ_PERMISSION: &str = "admin:principals:read";
#[cfg(test)]
const ADMIN_MCP_USE_PERMISSION: &str = "admin:mcp:use";
#[cfg(test)]
const MCP_ROUTE: &str = auth::protected_resource::MCP_RESOURCE_PATH;
const PROXY_FALLBACK_ROUTE: &str = "proxy_fallback";
const GATEWAY_OWNED_EXACT_PATHS: &[&str] = &["/health", "/version", "/metrics"];
const DEFAULT_AUDIT_QUERY_LIMIT: usize = 50;
const MAX_AUDIT_QUERY_LIMIT: usize = 500;
const DEFAULT_TRAFFIC_RECENT_EVENTS_LIMIT: usize = 20;
const DEFAULT_PRINCIPAL_DETAIL_AUDIT_EVENT_LIMIT: usize = 500;
const DEFAULT_PRINCIPAL_ANOMALY_HISTORY_LIMIT: usize = 20;
const DEFAULT_RULE_PREVIEW_SAMPLE_LIMIT: usize = 20;
const MAX_RULE_PREVIEW_SAMPLE_LIMIT: usize = 100;
const UPSTREAM_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);

#[derive(rust_embed::RustEmbed)]
#[folder = "../admin-ui/dist/"]
struct AdminUiAssets;

#[derive(Clone)]
struct AppState {
    metrics_handle: PrometheusHandle,
    proxy: Option<ProxyState>,
    routes: GatewayRoutes,
    admin_login_configured: bool,
    mcp: mcp::McpState,
    protected_resource_metadata: Option<auth::protected_resource::ProtectedResourceMetadataConfig>,
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

#[derive(Clone)]
struct ProxyRoute {
    path_prefix: Option<String>,
    host: Option<String>,
    upstream_origin: String,
    request_header_policy: RouteRequestHeaderPolicy,
    egress_client: Arc<egress::EgressClient>,
}

#[derive(Clone, Debug, Default)]
struct RouteRequestHeaderPolicy {
    add_request_headers: Vec<(HeaderName, HeaderValue)>,
    strip_request_headers: Vec<HeaderName>,
}

#[derive(Clone)]
struct MatchedUpstream {
    upstream_origin: String,
    request_header_policy: RouteRequestHeaderPolicy,
    egress_client: Arc<egress::EgressClient>,
}

#[derive(Clone)]
struct UpstreamHealthTarget {
    origin: String,
    egress_client: Arc<egress::EgressClient>,
    health: UpstreamHealthState,
}

#[derive(Clone, Debug)]
struct GatewayRoutes {
    admin: AdminRoutes,
    exact_owned_paths: Vec<String>,
    prefix_owned_paths: Vec<String>,
    mcp_route_paths: Vec<String>,
}

#[derive(Clone, Debug)]
struct AdminRoutes {
    ui_prefix: String,
    ui_slash_route: String,
    ui_asset_route: String,
    api_prefix: String,
    audit_route: String,
    events_stream_route: String,
    auth_login_route: String,
    auth_callback_route: String,
    status_route: String,
    policy_route: String,
    policy_history_route: String,
    policy_rollback_route: String,
    policy_rule_preview_route: String,
    policy_rule_hits_route: String,
    policy_rule_shadow_review_route: String,
    policy_validate_route: String,
    policy_rules_route: String,
    policy_rule_route: String,
    policy_rules_order_route: String,
    tokens_route: String,
    token_route: String,
    token_rotate_route: String,
    tools_openapi_preview_route: String,
    tools_openapi_register_route: String,
    schema_coverage_route: String,
    signals_route: String,
    signal_acknowledge_route: String,
    signal_dismiss_route: String,
    suggestions_route: String,
    suggestions_generate_route: String,
    suggestion_accept_route: String,
    suggestion_dismiss_route: String,
    schema_inferred_route: String,
    traffic_endpoints_route: String,
    traffic_endpoint_detail_route: String,
    traffic_endpoint_review_route: String,
    principals_route: String,
    principal_detail_route: String,
}

impl GatewayRoutes {
    fn from_config(config: &config::Config) -> Self {
        let admin = AdminRoutes::from_prefix(&config.admin_prefix);
        let exact_owned_paths = GATEWAY_OWNED_EXACT_PATHS
            .iter()
            .map(|path| (*path).to_owned())
            .collect();
        let mcp_route_paths = auth::protected_resource::mcp_route_paths(config);
        let mut prefix_owned_paths = vec![admin.ui_prefix.clone(), admin.api_prefix.clone()];
        prefix_owned_paths.extend(mcp_route_paths.iter().cloned());
        prefix_owned_paths.sort();
        prefix_owned_paths.dedup();

        Self {
            admin,
            exact_owned_paths,
            prefix_owned_paths,
            mcp_route_paths,
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
            auth_login_route: format!("{api_prefix}/auth/login"),
            auth_callback_route: format!("{api_prefix}/auth/callback"),
            status_route: format!("{api_prefix}/status"),
            policy_route: format!("{api_prefix}/policy"),
            policy_history_route: format!("{api_prefix}/policy/history"),
            policy_rollback_route: format!("{api_prefix}/policy/rollback/{{version}}"),
            policy_rule_preview_route: format!("{api_prefix}/policy/rules/preview"),
            policy_rule_hits_route: format!("{api_prefix}/policy/rules/hits"),
            policy_rule_shadow_review_route: format!("{api_prefix}/policy/rules/shadow-review"),
            policy_validate_route: format!("{api_prefix}/policy/validate"),
            policy_rules_route: format!("{api_prefix}/policy/rules"),
            policy_rule_route: format!("{api_prefix}/policy/rules/{{id}}"),
            policy_rules_order_route: format!("{api_prefix}/policy/rules/order"),
            tokens_route: format!("{api_prefix}/tokens"),
            token_route: format!("{api_prefix}/tokens/{{id}}"),
            token_rotate_route: format!("{api_prefix}/tokens/{{id}}/rotate"),
            tools_openapi_preview_route: format!("{api_prefix}/tools/openapi/preview"),
            tools_openapi_register_route: format!("{api_prefix}/tools/openapi/register"),
            schema_coverage_route: format!("{api_prefix}/schema/coverage"),
            signals_route: format!("{api_prefix}/signals"),
            signal_acknowledge_route: format!("{api_prefix}/signals/{{id}}/acknowledge"),
            signal_dismiss_route: format!("{api_prefix}/signals/{{id}}/dismiss"),
            suggestions_route: format!("{api_prefix}/suggestions"),
            suggestions_generate_route: format!("{api_prefix}/suggestions/generate"),
            suggestion_accept_route: format!("{api_prefix}/suggestions/{{id}}/accept"),
            suggestion_dismiss_route: format!("{api_prefix}/suggestions/{{id}}/dismiss"),
            schema_inferred_route: format!("{api_prefix}/schema/inferred"),
            traffic_endpoints_route: format!("{api_prefix}/traffic/endpoints"),
            traffic_endpoint_detail_route: format!("{api_prefix}/traffic/endpoint"),
            traffic_endpoint_review_route: format!("{api_prefix}/traffic/endpoints/review"),
            principals_route: format!("{api_prefix}/principals"),
            principal_detail_route: format!("{api_prefix}/principal"),
            api_prefix,
        }
    }
}

#[derive(Clone)]
struct AuditAdminState {
    query_store: Option<Arc<audit::query::AuditQueryStore>>,
    event_sender: audit::AuditEventSender,
    rbac_state: Option<middleware::rbac::RbacState>,
}

#[derive(Clone)]
struct StatusAdminState {
    config: config::Config,
    rbac: RbacStatus,
    rbac_state: Option<middleware::rbac::RbacState>,
    egress_allowed_hosts_count: usize,
    process_started_at: Instant,
}

#[derive(Clone)]
struct PolicyAdminState {
    policy_file: Option<PathBuf>,
    rbac_state: Option<middleware::rbac::RbacState>,
    history_store: Option<Arc<rbac::PolicyHistoryStore>>,
    query_store: Option<Arc<audit::query::AuditQueryStore>>,
    audit: audit::AuditLog,
    trust_proxy_headers: bool,
    max_body_size: usize,
}

#[derive(Clone)]
struct TokenAdminState {
    store: Option<Arc<dyn auth::TokenStore>>,
    validator: Option<Arc<auth::ServiceTokenValidator>>,
    rbac_state: Option<middleware::rbac::RbacState>,
    audit: audit::AuditLog,
    trust_proxy_headers: bool,
    max_body_size: usize,
}

#[derive(Clone)]
struct ToolAdminState {
    tools_file: Option<PathBuf>,
    registry: tools::definitions::ToolRegistry,
    mcp_proxy_definitions_provider: Option<tools::definitions::McpProxyDefinitionsProvider>,
    rbac_state: Option<middleware::rbac::RbacState>,
    audit: audit::AuditLog,
    trust_proxy_headers: bool,
    max_body_size: usize,
    write_lock: Arc<Mutex<()>>,
}

#[derive(Clone)]
struct AdminAuthState {
    login: auth::OidcLoginState,
    admin_prefix: String,
}

#[derive(Clone)]
struct SchemaAdminState {
    coverage: discovery::openapi::SchemaCoverage,
    query_store: Option<Arc<discovery::query::DiscoveryQueryStore>>,
    rbac_state: Option<middleware::rbac::RbacState>,
    payload_capture_enabled: bool,
}

#[derive(Clone)]
struct SignalsAdminState {
    discovery_store: Option<Arc<discovery::query::DiscoveryQueryStore>>,
    rbac_state: Option<middleware::rbac::RbacState>,
    audit: audit::AuditLog,
    trust_proxy_headers: bool,
}

#[derive(Clone)]
struct SuggestionsAdminState {
    suggestion_engine: Option<Arc<discovery::suggestions::RuleSuggestionEngine>>,
    policy: PolicyAdminState,
}

#[derive(Clone)]
struct TrafficAdminState {
    discovery_store: Option<Arc<discovery::query::DiscoveryQueryStore>>,
    audit_query_store: Option<Arc<audit::query::AuditQueryStore>>,
    rbac_state: Option<middleware::rbac::RbacState>,
    audit: audit::AuditLog,
    trust_proxy_headers: bool,
    max_body_size: usize,
}

#[derive(Clone)]
struct PrincipalAdminState {
    directory: auth::PrincipalDirectory,
    audit_query_store: Option<Arc<audit::query::AuditQueryStore>>,
    discovery_store: Option<Arc<discovery::query::DiscoveryQueryStore>>,
    rbac_state: Option<middleware::rbac::RbacState>,
}

#[derive(Clone)]
struct AdminApiStates {
    audit: AuditAdminState,
    auth: Option<AdminAuthState>,
    status: StatusAdminState,
    policy: PolicyAdminState,
    tokens: TokenAdminState,
    tools: ToolAdminState,
    schema: SchemaAdminState,
    signals: SignalsAdminState,
    suggestions: SuggestionsAdminState,
    traffic: TrafficAdminState,
    principals: PrincipalAdminState,
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
    admin_login_configured: bool,
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

#[derive(Deserialize)]
struct AdminAuthCallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct TrafficEndpointListParams {
    method: Option<String>,
    endpoint_template: Option<String>,
    endpoint_template_prefix: Option<String>,
    first_seen_after: Option<String>,
    first_seen_before: Option<String>,
    last_seen_after: Option<String>,
    last_seen_before: Option<String>,
    min_call_count: Option<String>,
    new_since_hours: Option<String>,
    is_new: Option<String>,
    reviewed: Option<String>,
    covered_by_rule: Option<String>,
    sort: Option<String>,
    limit: Option<String>,
    cursor: Option<String>,
}

#[derive(Deserialize)]
struct PrincipalListParams {
    issuer: Option<String>,
    auth_method: Option<String>,
    principal_type: Option<String>,
    last_seen_after: Option<String>,
    last_seen_before: Option<String>,
    limit: Option<String>,
    cursor: Option<String>,
}

#[derive(Deserialize)]
struct SignalListParams {
    state: Option<String>,
    signal_type: Option<String>,
    target_kind: Option<String>,
    target_key: Option<String>,
    limit: Option<String>,
    cursor: Option<String>,
}

#[derive(Deserialize)]
struct RuleSuggestionListParams {
    state: Option<String>,
    suggestion_type: Option<String>,
    limit: Option<String>,
    cursor: Option<String>,
}

#[derive(Deserialize)]
struct PolicyHistoryParams {
    limit: Option<String>,
    cursor: Option<String>,
    include_policy: Option<String>,
}

#[derive(Deserialize)]
struct TokenListParams {
    limit: Option<String>,
    cursor: Option<String>,
}

#[derive(Deserialize)]
struct TrafficEndpointDetailParams {
    method: Option<String>,
    endpoint_template: Option<String>,
    principal_limit: Option<String>,
    principal_cursor: Option<String>,
    from: Option<String>,
    to: Option<String>,
    new_since_hours: Option<String>,
    bucket: Option<String>,
    events_limit: Option<String>,
    events_before_id: Option<String>,
}

#[derive(Deserialize)]
struct PrincipalDetailParams {
    subject: Option<String>,
    issuer: Option<String>,
    auth_method: Option<String>,
}

#[derive(Deserialize)]
struct InferredSchemaParams {
    method: Option<String>,
    endpoint_template: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrafficEndpointReviewRequest {
    method: String,
    endpoint_template: String,
    reviewed: bool,
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
struct TrafficEndpointDetailResponse {
    endpoint: discovery::query::EndpointAggregateDetail,
    principals: discovery::query::PrincipalPage,
    audit: TrafficEndpointAuditEnrichment,
}

#[derive(Serialize)]
struct PrincipalListResponse {
    principals: Vec<auth::principal_directory::PrincipalDirectoryRecord>,
    next_cursor: Option<String>,
    anonymous_request_count: u64,
}

#[derive(Serialize)]
struct PrincipalDetailResponse {
    principal: auth::principal_directory::PrincipalDirectoryRecord,
    endpoints_touched: Vec<PrincipalEndpointTouch>,
    rules_hit: Vec<String>,
    anomaly_history: Vec<discovery::signals::Signal>,
    tools_called: Vec<Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct PrincipalEndpointTouch {
    method: String,
    path: String,
    request_count: u64,
    last_seen: String,
}

#[derive(Serialize)]
struct TrafficEndpointAuditEnrichment {
    available: bool,
    match_strategy: &'static str,
    match_limitations: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    omitted_reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    time_series_truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    time_series: Option<Vec<audit::query::EndpointTimeSeriesPoint>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recent_events: Option<Vec<audit::query::EndpointRecentEvent>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recent_events_next_cursor: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recent_events_scan_truncated: Option<bool>,
}

struct InferredSchemaQuery {
    method: String,
    endpoint_template: String,
}

#[derive(Serialize)]
struct PolicyValidationResponse {
    valid: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<String>,
}

#[derive(Deserialize)]
struct PolicyRulePreviewRequest {
    rule: rbac::Rule,
    from: Option<String>,
    to: Option<String>,
    sample_limit: Option<usize>,
}

#[derive(Serialize)]
struct PolicyRulePreviewResponse {
    match_count: u64,
    scanned_event_count: u64,
    sample_strategy: &'static str,
    samples: Vec<PolicyRulePreviewSample>,
}

#[derive(Serialize)]
struct PolicyRulePreviewSample {
    event_id: String,
    timestamp: String,
    request_id: String,
    source_ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent: Option<String>,
    method: String,
    path: String,
    actor: Option<audit::Actor>,
    status: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    matched_rule_id: Option<String>,
}

#[derive(Serialize)]
struct PolicyRuleHitsResponse {
    rules: Vec<PolicyRuleHitCount>,
}

#[derive(Serialize)]
struct PolicyRuleHitCount {
    rule_id: String,
    hits: u64,
}

#[derive(Serialize)]
struct PolicyRuleShadowReviewResponse {
    rules: Vec<PolicyRuleShadowReviewSummary>,
    scanned_event_count: u64,
    scan_truncated: bool,
}

#[derive(Serialize)]
struct PolicyRuleShadowReviewSummary {
    rule_id: String,
    rule: rbac::Rule,
    would_deny_count: u64,
    affected_principals: Vec<audit::query::ShadowRuleAffectedPrincipal>,
    samples: Vec<audit::query::ShadowRuleWouldDenySample>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateTokenAdminRequest {
    scopes: Vec<String>,
    expires_at: Option<String>,
}

#[derive(Serialize)]
struct CreatedTokenAdminResponse {
    plaintext_token: String,
    plaintext_token_notice: &'static str,
    token: auth::tokens::TokenRecord,
}

#[derive(Serialize)]
struct OpenApiToolsPreviewResponse {
    tools: Vec<tools::definitions::ToolDefinition>,
    operation_id_fallbacks: Vec<OpenApiToolNameFallbackResponse>,
    skipped_operations: Vec<OpenApiSkippedOperationResponse>,
    api_key_header_auth_requirements: Vec<OpenApiApiKeyHeaderAuthRequirementResponse>,
}

#[derive(Serialize)]
struct OpenApiToolNameFallbackResponse {
    method: String,
    path_template: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    original_operation_id: Option<String>,
    generated_name: String,
    reason: &'static str,
}

#[derive(Serialize)]
struct OpenApiSkippedOperationResponse {
    method: String,
    path_template: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    original_operation_id: Option<String>,
    reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    property_name: Option<String>,
}

#[derive(Serialize)]
struct OpenApiApiKeyHeaderAuthRequirementResponse {
    tool_name: String,
    method: String,
    path_template: String,
    scheme_name: String,
    header_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenApiToolsRegisterRequest {
    spec: String,
    selected_tool_names: Vec<String>,
}

#[derive(Serialize)]
struct OpenApiToolsRegisterResponse {
    registered_tool_names: Vec<String>,
    tool_count: usize,
}

#[derive(Serialize)]
struct ToolNameConflictResponse {
    error: &'static str,
    conflicts: Vec<String>,
}

#[derive(Serialize)]
struct UnsupportedOpenApiToolAuthRequirementsResponse {
    error: &'static str,
    unsupported_tool_names: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ToolsFileAdminDocument {
    schema_version: String,
    #[serde(default)]
    tools: Vec<tools::definitions::ToolDefinition>,
}

#[derive(Serialize)]
struct RuleDeletedResponse {
    deleted_rule_id: String,
}

#[derive(Serialize)]
struct RulesReorderedResponse {
    order: Vec<String>,
}

#[derive(Serialize)]
struct RuleSuggestionAcceptResponse {
    suggestion: discovery::suggestions::RuleSuggestion,
    rule: rbac::Rule,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RulePatch {
    enabled: Option<bool>,
    methods: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_rule_path_patch")]
    path: Option<RulePathPatch>,
    #[serde(default, deserialize_with = "deserialize_rule_tool_name_patch")]
    tool_name: Option<RuleToolNamePatch>,
    principal: Option<rbac::PrincipalMatcher>,
    action: Option<rbac::RuleAction>,
}

enum RuleToolNamePatch {
    Set(String),
    Clear,
}

enum RulePathPatch {
    Set(String),
    Clear,
}

fn deserialize_rule_path_patch<'de, D>(deserializer: D) -> Result<Option<RulePathPatch>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|value| {
        Some(match value {
            Some(value) => RulePathPatch::Set(value),
            None => RulePathPatch::Clear,
        })
    })
}

fn deserialize_rule_tool_name_patch<'de, D>(
    deserializer: D,
) -> Result<Option<RuleToolNamePatch>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|value| {
        Some(match value {
            Some(value) => RuleToolNamePatch::Set(value),
            None => RuleToolNamePatch::Clear,
        })
    })
}

type ResponseResult<T> = Result<T, Box<Response>>;

struct PolicyMutationCommitResult {
    after_policy: rbac::Policy,
    new_etag: String,
    history_append_failed: bool,
}

struct PolicyRuleCreateResult {
    rule: rbac::Rule,
    new_etag: String,
    history_append_failed: bool,
}

struct PolicyMutationCommitContext<'a> {
    state: &'a PolicyAdminState,
    rbac_state: &'a middleware::rbac::RbacState,
    policy_file: &'a std::path::Path,
    parts: &'a http::request::Parts,
    principal: &'a auth::Principal,
}

enum PolicyAdminAuthzError {
    NotConfigured,
    Forbidden,
}

enum TokenAdminAuthzError {
    StoreNotConfigured,
    RbacNotConfigured,
    Forbidden,
}

enum ToolAdminAuthzError {
    RbacNotConfigured,
    ToolsFileNotConfigured,
    Forbidden,
}

enum TrafficAdminAuthzError {
    NotConfigured,
    Forbidden,
}

enum PrincipalAdminAuthzError {
    NotConfigured,
    Forbidden,
}

enum SignalsAdminAuthzError {
    NotConfigured,
    Forbidden,
}

enum SuggestionsAdminAuthzError {
    NotConfigured,
    Forbidden,
}

enum AdminReadAuthzError {
    NotConfigured,
    Forbidden,
}

enum IfMatchError {
    Missing,
    InvalidHeader,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct SchemaNotConfiguredResponse {
    error: String,
    spec_configured: bool,
}

#[derive(Serialize)]
struct DiscoveryNotConfiguredResponse {
    error: String,
    discovery_configured: bool,
}

#[derive(Serialize)]
struct PayloadCaptureNotConfiguredResponse {
    error: String,
    payload_capture_configured: bool,
}

#[derive(Serialize)]
struct InferredSchemaNoSamplesResponse {
    error: String,
    schema_inferred: bool,
}

enum GatewayApp {
    Unified(Router),
    Split { data: Router, admin: Router },
}

#[derive(Default)]
struct DiscoveredOidcConfig {
    jwks_urls: HashMap<String, String>,
    admin_login: Option<DiscoveredAdminLoginEndpoints>,
}

#[derive(Clone)]
struct DiscoveredAdminLoginEndpoints {
    provider_name: String,
    issuer: String,
    jwks_url: String,
    authorization_endpoint: String,
    token_endpoint: String,
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
    let audit_query_store = config
        .audit_sqlite_path
        .as_deref()
        .map(audit::query::AuditQueryStore::open)
        .transpose()?
        .map(Arc::new);
    let schema_coverage = discovery::openapi::SchemaCoverage::from_config(&config)?;
    let discovery_query_store = config
        .discovery_sqlite_path
        .as_deref()
        .map(discovery::query::DiscoveryQueryStore::open)
        .transpose()?
        .map(Arc::new);
    let rule_suggestion_engine = config
        .discovery_sqlite_path
        .as_deref()
        .map(|path| {
            discovery::suggestions::RuleSuggestionEngine::open(
                path,
                config.audit_sqlite_path.as_deref(),
                config.rule_suggestion_config(),
            )
        })
        .transpose()?
        .map(Arc::new);
    let policy_history_store = policy_history_sqlite_path(&config)
        .map(rbac::PolicyHistoryStore::open)
        .transpose()?
        .map(Arc::new);
    let observation_state =
        middleware::observation::ObservationState::from_config(&config, audit_log.clone())
            .with_conformance(
                middleware::observation::SchemaConformanceState::from_config(
                    &config,
                    schema_coverage.clone(),
                    discovery_query_store.clone(),
                ),
            );
    let loaded_policy = rbac::Policy::from_config(&config)?;
    let tool_runtime_config = match loaded_policy.as_ref() {
        Some(policy) => {
            tools::runtime::ToolRuntimeConfig::from_env_defaults(&config).with_policy_tools(policy)
        }
        None => tools::runtime::ToolRuntimeConfig::from_env_defaults(&config),
    };
    let rate_limit_state = middleware::rate_limit::RateLimitState::from_config_and_policy(
        &config,
        loaded_policy.as_ref(),
    );
    let mut egress_config = match loaded_policy.as_ref() {
        Some(policy) => {
            egress::EgressConfig::from_config_and_policy(&config, Some(&policy.egress))?
        }
        None => egress::EgressConfig::from_config(&config),
    };
    let discovery_egress_client = Arc::new(egress::EgressClient::new(egress_config.clone())?);
    let discovered_oidc = discover_oidc_from_config(&config, discovery_egress_client)?;
    auto_seed_discovered_oidc_hosts(&mut egress_config, &discovered_oidc);
    let egress_allowed_hosts_count = egress_config.allowed_host_rule_count();
    let proxy_egress_config = {
        let mut proxy_egress_config = egress_config.clone();
        proxy_egress_config.apply_upstream_timeout_overrides(&config);
        proxy_egress_config
    };
    let egress_client = Arc::new(egress::EgressClient::new(egress_config)?);
    let proxy_egress_client = Arc::new(egress::EgressClient::new(proxy_egress_config.clone())?);
    let proxy_state = ProxyState::from_config(&config, &proxy_egress_config, proxy_egress_client)?;
    if let Some(proxy) = proxy_state.as_ref() {
        proxy.spawn_upstream_health_checks();
    }
    let routes = GatewayRoutes::from_config(&config);
    let service_token_store = config
        .service_token_sqlite_path
        .as_deref()
        .map(auth::SqliteTokenStore::open)
        .transpose()?
        .map(|store| Arc::new(store) as Arc<dyn auth::TokenStore>);
    let service_token_validator = service_token_store.as_ref().map(|store| {
        Arc::new(auth::ServiceTokenValidator::new(
            Arc::clone(store),
            Duration::from_millis(config.service_token_cache_ttl_ms),
        ))
    });
    let validator = auth_validator_from_config(
        &config,
        Arc::clone(&egress_client),
        service_token_validator.clone(),
        &discovered_oidc.jwks_urls,
    )?;
    let admin_auth_state =
        admin_auth_state_from_config(&config, &discovered_oidc, Arc::clone(&egress_client))?;
    let principal_directory = auth::PrincipalDirectory::from_config(&config)?;
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
            Some(
                middleware::rbac::RbacState::from_policy(policy, &config, audit_log.clone())
                    .with_rate_limit_state(rate_limit_state.clone()),
            )
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
    let tool_registry =
        tools::definitions::ToolRegistry::from_config_with_audit(&config, audit_log.clone())?;
    let mcp_upstream_definitions =
        tools::mcp_upstream::discover_upstream_tools_blocking(&config, Arc::clone(&egress_client))?;
    tool_registry.merge_definitions(mcp_upstream_definitions)?;
    let mcp_proxy_definitions_provider =
        mcp_proxy_definitions_provider(&config, Arc::clone(&egress_client));
    if let Some(tools_file) = config.tools_file.as_ref() {
        tools::definitions::spawn_tool_registry_reload_tasks_with_mcp_proxy_definitions_provider(
            tools_file.clone(),
            tool_registry.clone(),
            mcp_proxy_definitions_provider.clone(),
        )?;
    }
    let tool_runtime = tools::runtime::ToolRuntime::new_with_rbac_state(
        tool_runtime_config,
        audit_log.clone(),
        rbac_state.clone(),
    );
    let mcp_executor = mcp::mcp_executor_from_config(
        &config,
        tool_registry.clone(),
        tool_runtime,
        Arc::clone(&egress_client),
        audit_log.clone(),
    )?;
    let mcp_state = mcp::McpState::new(
        tool_registry.clone(),
        mcp_executor,
        config.trust_proxy_headers,
    );
    let protected_resource_metadata =
        auth::protected_resource::ProtectedResourceMetadataConfig::from_config(&config);
    let status_state = StatusAdminState {
        config: config.clone(),
        rbac: rbac_status,
        rbac_state: rbac_state.clone(),
        egress_allowed_hosts_count,
        process_started_at,
    };
    let policy_admin_state = PolicyAdminState {
        policy_file: config.policy_file.as_ref().map(PathBuf::from),
        rbac_state: rbac_state.clone(),
        history_store: policy_history_store,
        query_store: audit_query_store.clone(),
        audit: audit_log.clone(),
        trust_proxy_headers: config.trust_proxy_headers,
        max_body_size: config.max_body_size,
    };
    let token_admin_state = TokenAdminState {
        store: service_token_store,
        validator: service_token_validator,
        rbac_state: rbac_state.clone(),
        audit: audit_log.clone(),
        trust_proxy_headers: config.trust_proxy_headers,
        max_body_size: config.max_body_size,
    };
    let tool_admin_state = ToolAdminState {
        tools_file: config.tools_file.as_ref().map(PathBuf::from),
        registry: tool_registry,
        mcp_proxy_definitions_provider,
        rbac_state: rbac_state.clone(),
        audit: audit_log.clone(),
        trust_proxy_headers: config.trust_proxy_headers,
        max_body_size: config.max_body_size,
        write_lock: Arc::new(Mutex::new(())),
    };
    let schema_admin_state = SchemaAdminState {
        coverage: schema_coverage,
        query_store: discovery_query_store.clone(),
        rbac_state: rbac_state.clone(),
        payload_capture_enabled: config.payload_capture_enabled,
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
            principal_directory.clone(),
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
        rbac_state: rbac_state.clone(),
        auth_state,
    };
    let app_state = AppState {
        metrics_handle,
        proxy: proxy_state,
        routes: routes.clone(),
        admin_login_configured: admin_auth_state.is_some(),
        mcp: mcp_state,
        protected_resource_metadata,
    };
    let audit_admin_state = AuditAdminState {
        query_store: audit_query_store,
        event_sender: audit_event_sender,
        rbac_state: rbac_state.clone(),
    };
    let signals_admin_state = SignalsAdminState {
        discovery_store: discovery_query_store.clone(),
        rbac_state: rbac_state.clone(),
        audit: audit_log.clone(),
        trust_proxy_headers: config.trust_proxy_headers,
    };
    let suggestions_admin_state = SuggestionsAdminState {
        suggestion_engine: rule_suggestion_engine,
        policy: policy_admin_state.clone(),
    };
    let principal_admin_state = PrincipalAdminState {
        directory: principal_directory,
        audit_query_store: audit_admin_state.query_store.clone(),
        discovery_store: discovery_query_store.clone(),
        rbac_state: rbac_state.clone(),
    };
    let traffic_admin_state = TrafficAdminState {
        discovery_store: discovery_query_store,
        audit_query_store: audit_admin_state.query_store.clone(),
        rbac_state,
        audit: audit_log,
        trust_proxy_headers: config.trust_proxy_headers,
        max_body_size: config.max_body_size,
    };
    let admin_api_states = AdminApiStates {
        audit: audit_admin_state,
        auth: admin_auth_state,
        status: status_state,
        policy: policy_admin_state,
        tokens: token_admin_state,
        tools: tool_admin_state,
        schema: schema_admin_state,
        signals: signals_admin_state,
        suggestions: suggestions_admin_state,
        traffic: traffic_admin_state,
        principals: principal_admin_state,
    };

    if split_admin_listener {
        Ok(GatewayApp::Split {
            data: apply_middleware(data_router(app_state.clone()), &middleware_stack),
            admin: apply_middleware(
                admin_router(&routes, app_state, admin_api_states),
                &middleware_stack,
            ),
        })
    } else {
        Ok(GatewayApp::Unified(apply_middleware(
            unified_router(&routes, app_state, admin_api_states),
            &middleware_stack,
        )))
    }
}

fn auth_validator_from_config(
    config: &config::Config,
    egress_client: Arc<egress::EgressClient>,
    service_token_validator: Option<Arc<auth::ServiceTokenValidator>>,
    discovered_oidc_jwks_urls: &HashMap<String, String>,
) -> Result<Option<Arc<dyn auth::SessionValidator>>, auth::AuthError> {
    if config.auth_providers.is_empty() && service_token_validator.is_none() {
        return Ok(None);
    }

    let mut validators = Vec::with_capacity(
        config.auth_providers.len() + usize::from(service_token_validator.is_some()),
    );
    if let Some(service_token_validator) = service_token_validator {
        validators.push(service_token_validator as Arc<dyn auth::SessionValidator>);
    }
    for provider in &config.auth_providers {
        match provider.provider_type {
            config::AuthProviderType::Jwt => {
                let jwks_url = match provider.jwks_url.clone() {
                    Some(jwks_url) => jwks_url,
                    None => {
                        let issuer = provider.issuer.as_deref().ok_or_else(|| {
                            auth::AuthError::Upstream(format!(
                                "JWT auth provider '{}' is missing jwks_url and issuer",
                                provider.name
                            ))
                        })?;
                        discovered_oidc_jwks_urls
                            .get(&provider.name)
                            .cloned()
                            .ok_or_else(|| {
                                auth::AuthError::Upstream(format!(
                                    "JWT auth provider '{}' is missing discovered jwks_uri for issuer '{issuer}'",
                                    provider.name
                                ))
                            })?
                    }
                };
                let jwt_config = auth::JwtAuthConfig::from_provider_config(provider, jwks_url);
                validators.push(Arc::new(auth::JwtValidator::new(
                    jwt_config,
                    Arc::clone(&egress_client),
                )?) as Arc<dyn auth::SessionValidator>);
            }
            config::AuthProviderType::CookieSession => {
                let cookie_config = auth::CookieSessionAuthConfig::from_provider_config(provider)?;
                validators.push(Arc::new(auth::CookieSessionValidator::new(
                    cookie_config,
                    Arc::clone(&egress_client),
                )?) as Arc<dyn auth::SessionValidator>);
            }
        }
    }

    Ok(Some(
        Arc::new(auth::ChainValidator::new(validators)) as Arc<dyn auth::SessionValidator>
    ))
}

fn admin_auth_state_from_config(
    config: &config::Config,
    discovered_oidc: &DiscoveredOidcConfig,
    egress_client: Arc<egress::EgressClient>,
) -> Result<Option<AdminAuthState>, auth::AuthError> {
    let Some(admin_login_provider) = config.admin_login_provider.as_deref() else {
        return Ok(None);
    };
    let provider = config
        .auth_providers
        .iter()
        .find(|provider| provider.name == admin_login_provider)
        .ok_or_else(|| {
            auth::AuthError::Upstream(format!(
                "ADMIN_LOGIN_PROVIDER references unknown auth provider '{admin_login_provider}'"
            ))
        })?;
    let endpoints = discovered_oidc
        .admin_login
        .as_ref()
        .filter(|endpoints| endpoints.provider_name == provider.name)
        .ok_or_else(|| {
            auth::AuthError::Upstream(format!(
                "ADMIN_LOGIN_PROVIDER '{}' is missing discovered OIDC login endpoints",
                provider.name
            ))
        })?;

    let login_config = auth::OidcLoginConfig {
        client_id: required_admin_login_provider_field(provider, "client_id", &provider.client_id)?,
        client_secret: required_admin_login_provider_field(
            provider,
            "client_secret",
            &provider.client_secret,
        )?,
        redirect_uri: required_admin_login_provider_field(
            provider,
            "redirect_uri",
            &provider.redirect_uri,
        )?,
        issuer: endpoints.issuer.clone(),
        jwks_url: endpoints.jwks_url.clone(),
        authorization_endpoint: endpoints.authorization_endpoint.clone(),
        token_endpoint: endpoints.token_endpoint.clone(),
        http_timeout: Duration::from_millis(provider.jwks_timeout_ms),
    };

    Ok(Some(AdminAuthState {
        login: auth::OidcLoginState::new(login_config, egress_client)?,
        admin_prefix: config.admin_prefix.clone(),
    }))
}

fn required_admin_login_provider_field(
    provider: &config::AuthProviderConfig,
    field_name: &str,
    value: &Option<String>,
) -> Result<String, auth::AuthError> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            auth::AuthError::Upstream(format!(
                "admin login provider '{}' is missing {field_name}",
                provider.name
            ))
        })
}

fn mcp_proxy_definitions_provider(
    config: &config::Config,
    egress_client: Arc<egress::EgressClient>,
) -> Option<tools::definitions::McpProxyDefinitionsProvider> {
    let config = config.clone();
    Some(Arc::new(
        move || match tools::mcp_upstream::discover_upstream_tools_strict_blocking(
            &config,
            Arc::clone(&egress_client),
        ) {
            Ok(definitions) => Some(definitions),
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "MCP upstream rediscovery failed during tool registry reload; preserving existing MCP proxy tools"
                );
                None
            }
        },
    ))
}

fn discover_oidc_from_config(
    config: &config::Config,
    egress_client: Arc<egress::EgressClient>,
) -> Result<DiscoveredOidcConfig, auth::AuthError> {
    let mut discovered = DiscoveredOidcConfig::default();

    for provider in &config.auth_providers {
        if provider.provider_type != config::AuthProviderType::Jwt {
            continue;
        }
        let is_admin_login_provider = config
            .admin_login_provider
            .as_deref()
            .is_some_and(|name| name == provider.name);
        if provider.jwks_url.is_some() && !is_admin_login_provider {
            continue;
        }

        let issuer = provider.issuer.as_deref().ok_or_else(|| {
            auth::AuthError::Upstream(format!(
                "JWT auth provider '{}' is missing jwks_url and issuer",
                provider.name
            ))
        })?;
        if !is_admin_login_provider {
            let jwks_url = auth::oidc::discover_jwks_uri_blocking(
                issuer,
                Duration::from_millis(provider.jwks_timeout_ms),
                Arc::clone(&egress_client),
            )?;
            discovered.jwks_urls.insert(provider.name.clone(), jwks_url);
            continue;
        }

        let document = auth::oidc::discover_document_blocking(
            issuer,
            Duration::from_millis(provider.jwks_timeout_ms),
            Arc::clone(&egress_client),
        )?;
        let issuer = document
            .issuer()
            .and_then(auth::oidc::normalize_issuer)
            .ok_or_else(|| {
                auth::AuthError::Upstream("OIDC discovery response missing issuer".to_owned())
            })?;

        let jwks_url = match provider.jwks_url.clone() {
            Some(jwks_url) => jwks_url,
            None => {
                let jwks_url = document.jwks_uri().ok_or_else(|| {
                    auth::AuthError::Upstream("OIDC discovery response missing jwks_uri".to_owned())
                })?;
                discovered
                    .jwks_urls
                    .insert(provider.name.clone(), jwks_url.clone());
                jwks_url
            }
        };

        let authorization_endpoint = document.authorization_endpoint().ok_or_else(|| {
            auth::AuthError::Upstream(
                "OIDC discovery response missing authorization_endpoint".to_owned(),
            )
        })?;
        let token_endpoint = document.token_endpoint().ok_or_else(|| {
            auth::AuthError::Upstream("OIDC discovery response missing token_endpoint".to_owned())
        })?;
        discovered.admin_login = Some(DiscoveredAdminLoginEndpoints {
            provider_name: provider.name.clone(),
            issuer,
            jwks_url,
            authorization_endpoint,
            token_endpoint,
        });
    }

    if let Some(admin_login_provider) = config.admin_login_provider.as_deref() {
        if discovered.admin_login.is_none() {
            return Err(auth::AuthError::Upstream(format!(
                "ADMIN_LOGIN_PROVIDER '{admin_login_provider}' could not be resolved through OIDC discovery"
            )));
        }
    }

    Ok(discovered)
}

#[cfg(test)]
fn discover_oidc_jwks_urls_from_config(
    config: &config::Config,
    egress_client: Arc<egress::EgressClient>,
) -> Result<HashMap<String, String>, auth::AuthError> {
    discover_oidc_from_config(config, egress_client).map(|discovered| discovered.jwks_urls)
}

fn auto_seed_discovered_oidc_hosts(
    egress_config: &mut egress::EgressConfig,
    discovered_oidc: &DiscoveredOidcConfig,
) {
    let mut auto_seeded_hosts = discovered_oidc
        .jwks_urls
        .values()
        .filter_map(|jwks_url| egress_config.auto_seed_endpoint_host(jwks_url))
        .collect::<Vec<_>>();
    if let Some(admin_login) = &discovered_oidc.admin_login {
        if let Some(host) = egress_config.auto_seed_endpoint_host(&admin_login.token_endpoint) {
            auto_seeded_hosts.push(host);
        }
    }

    if !auto_seeded_hosts.is_empty() {
        tracing::debug!(
            hosts = ?auto_seeded_hosts,
            "auto-seeded egress allowlist from discovered OIDC endpoints"
        );
    }
}

fn policy_history_sqlite_path(config: &config::Config) -> Option<PathBuf> {
    config
        .policy_history_sqlite_path
        .as_ref()
        .map(PathBuf::from)
        .or_else(|| {
            config
                .policy_file
                .as_deref()
                .map(default_policy_history_sqlite_path)
        })
}

fn default_policy_history_sqlite_path(policy_file: &str) -> PathBuf {
    PathBuf::from(format!("{policy_file}.history.sqlite"))
}

fn unified_router(
    routes: &GatewayRoutes,
    app_state: AppState,
    admin_api_states: AdminApiStates,
) -> Router {
    let router = Router::new()
        .route("/health", get(health))
        .route("/version", get(version))
        .route("/metrics", get(metrics_endpoint))
        .route(
            auth::protected_resource::WELL_KNOWN_PATH,
            get(oauth_protected_resource_metadata_endpoint),
        )
        .route(
            auth::protected_resource::WELL_KNOWN_SUFFIX_ROUTE,
            get(oauth_protected_resource_metadata_endpoint),
        )
        .route(routes.admin.ui_prefix.as_str(), get(admin_ui_index))
        .route(routes.admin.ui_slash_route.as_str(), get(admin_ui_index))
        .route(routes.admin.ui_asset_route.as_str(), get(admin_ui_asset));
    let router = add_mcp_routes(router, routes);

    let router = with_proxy_fallback_if_configured(router, &app_state).with_state(app_state);
    let router = add_admin_api_routes(router, routes, admin_api_states);

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
        .route("/metrics", get(metrics_endpoint))
        .route(
            auth::protected_resource::WELL_KNOWN_PATH,
            get(oauth_protected_resource_metadata_endpoint),
        )
        .route(
            auth::protected_resource::WELL_KNOWN_SUFFIX_ROUTE,
            get(oauth_protected_resource_metadata_endpoint),
        );
    let router = add_mcp_routes(router, &app_state.routes);

    with_proxy_fallback_if_configured(router, &app_state).with_state(app_state)
}

fn add_mcp_routes(mut router: Router<AppState>, routes: &GatewayRoutes) -> Router<AppState> {
    for route_path in &routes.mcp_route_paths {
        router = router.route(route_path.as_str(), any(mcp::mcp_endpoint));
    }
    router
}

fn admin_router(
    routes: &GatewayRoutes,
    app_state: AppState,
    admin_api_states: AdminApiStates,
) -> Router {
    let router = Router::new()
        .route(routes.admin.ui_prefix.as_str(), get(admin_ui_index))
        .route(routes.admin.ui_slash_route.as_str(), get(admin_ui_index))
        .route(routes.admin.ui_asset_route.as_str(), get(admin_ui_asset))
        .with_state(app_state);

    add_admin_api_routes(router, routes, admin_api_states)
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
    admin_api_states: AdminApiStates,
) -> Router {
    router
        .merge(
            Router::new()
                .route(routes.admin.audit_route.as_str(), get(audit_query_endpoint))
                .route(
                    routes.admin.events_stream_route.as_str(),
                    get(audit_events_stream_endpoint),
                )
                .with_state(admin_api_states.audit),
        )
        .merge(
            Router::new()
                .route(routes.admin.status_route.as_str(), get(status_endpoint))
                .with_state(admin_api_states.status),
        )
        .merge(admin_auth_router(routes, admin_api_states.auth))
        .merge(
            Router::new()
                .route(
                    routes.admin.schema_coverage_route.as_str(),
                    get(schema_coverage_endpoint),
                )
                .route(
                    routes.admin.schema_inferred_route.as_str(),
                    get(schema_inferred_endpoint),
                )
                .with_state(admin_api_states.schema),
        )
        .merge(
            Router::new()
                .route(
                    routes.admin.signals_route.as_str(),
                    get(signals_list_endpoint),
                )
                .route(
                    routes.admin.signal_acknowledge_route.as_str(),
                    post(signal_acknowledge_endpoint),
                )
                .route(
                    routes.admin.signal_dismiss_route.as_str(),
                    post(signal_dismiss_endpoint),
                )
                .with_state(admin_api_states.signals),
        )
        .merge(
            Router::new()
                .route(
                    routes.admin.suggestions_route.as_str(),
                    get(rule_suggestions_list_endpoint),
                )
                .route(
                    routes.admin.suggestions_generate_route.as_str(),
                    post(rule_suggestions_generate_endpoint),
                )
                .route(
                    routes.admin.suggestion_accept_route.as_str(),
                    post(rule_suggestion_accept_endpoint),
                )
                .route(
                    routes.admin.suggestion_dismiss_route.as_str(),
                    post(rule_suggestion_dismiss_endpoint),
                )
                .with_state(admin_api_states.suggestions),
        )
        .merge(
            Router::new()
                .route(
                    routes.admin.policy_route.as_str(),
                    get(policy_get_endpoint).put(policy_put_endpoint),
                )
                .route(
                    routes.admin.policy_history_route.as_str(),
                    get(policy_history_endpoint),
                )
                .route(
                    routes.admin.policy_rollback_route.as_str(),
                    post(policy_rollback_endpoint),
                )
                .route(
                    routes.admin.policy_rule_preview_route.as_str(),
                    post(policy_rule_preview_endpoint),
                )
                .route(
                    routes.admin.policy_rule_hits_route.as_str(),
                    get(policy_rule_hits_endpoint),
                )
                .route(
                    routes.admin.policy_rule_shadow_review_route.as_str(),
                    get(policy_rule_shadow_review_endpoint),
                )
                .route(
                    routes.admin.policy_validate_route.as_str(),
                    post(policy_validate_endpoint),
                )
                .route(
                    routes.admin.policy_rules_route.as_str(),
                    post(policy_rule_post_endpoint),
                )
                .route(
                    routes.admin.policy_rule_route.as_str(),
                    patch(policy_rule_patch_endpoint).delete(policy_rule_delete_endpoint),
                )
                .route(
                    routes.admin.policy_rules_order_route.as_str(),
                    put(policy_rules_order_put_endpoint),
                )
                .with_state(admin_api_states.policy),
        )
        .merge(
            Router::new()
                .route(
                    routes.admin.tokens_route.as_str(),
                    get(token_list_endpoint).post(token_create_endpoint),
                )
                .route(
                    routes.admin.token_route.as_str(),
                    get(token_get_endpoint).delete(token_revoke_endpoint),
                )
                .route(
                    routes.admin.token_rotate_route.as_str(),
                    post(token_rotate_endpoint),
                )
                .with_state(admin_api_states.tokens),
        )
        .merge(
            Router::new()
                .route(
                    routes.admin.tools_openapi_preview_route.as_str(),
                    post(tools_openapi_preview_endpoint),
                )
                .route(
                    routes.admin.tools_openapi_register_route.as_str(),
                    post(tools_openapi_register_endpoint),
                )
                .with_state(admin_api_states.tools),
        )
        .merge(
            Router::new()
                .route(
                    routes.admin.principals_route.as_str(),
                    get(principal_list_endpoint),
                )
                .route(
                    routes.admin.principal_detail_route.as_str(),
                    get(principal_detail_endpoint),
                )
                .with_state(admin_api_states.principals),
        )
        .merge(
            Router::new()
                .route(
                    routes.admin.traffic_endpoints_route.as_str(),
                    get(traffic_endpoint_list_endpoint),
                )
                .route(
                    routes.admin.traffic_endpoint_detail_route.as_str(),
                    get(traffic_endpoint_detail_endpoint),
                )
                .route(
                    routes.admin.traffic_endpoint_review_route.as_str(),
                    post(traffic_endpoint_review_endpoint),
                )
                .with_state(admin_api_states.traffic),
        )
}

fn admin_auth_router(routes: &GatewayRoutes, state: Option<AdminAuthState>) -> Router {
    let Some(state) = state else {
        return Router::new();
    };

    Router::new()
        .route(
            routes.admin.auth_login_route.as_str(),
            get(admin_auth_login_endpoint),
        )
        .route(
            routes.admin.auth_callback_route.as_str(),
            get(admin_auth_callback_endpoint),
        )
        .with_state(state)
}

fn apply_middleware(router: Router, stack: &MiddlewareStack) -> Router {
    let request_id_header = request_id_header();

    // Later axum layers run earlier at runtime. Attach RBAC before auth, then
    // auth before CSRF, so requests flow through CSRF, auth, RBAC, then the
    // route handler. The coarse global rate limiter remains outside auth for
    // early IP/session DoS protection; policy overrides run inside auth so
    // principal-aware buckets are based on real authenticated principals.
    let router = if let Some(rbac_state) = stack.rbac_state.clone() {
        router.layer(axum::middleware::from_fn_with_state(
            rbac_state,
            middleware::rbac::rbac_middleware,
        ))
    } else {
        router
    };

    let router = router.layer(axum::middleware::from_fn_with_state(
        stack.rate_limit_state.clone(),
        middleware::rate_limit::policy_rate_limit_request,
    ));

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
        auth::principal_directory::PRINCIPAL_DIRECTORY_EVENTS_DROPPED_TOTAL,
        "Principal directory observations dropped by the bounded asynchronous channel"
    );
    ::metrics::describe_counter!(
        auth::principal_directory::PRINCIPAL_DIRECTORY_SQLITE_FLUSH_ERRORS_TOTAL,
        "SQLite principal directory flush errors"
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

async fn version(State(state): State<AppState>) -> Json<VersionResponse> {
    record_request("/version");
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION"),
        admin_login_configured: state.admin_login_configured,
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

async fn oauth_protected_resource_metadata_endpoint(State(state): State<AppState>) -> Response {
    let Some(metadata) = state.protected_resource_metadata.as_ref() else {
        return not_found(
            "OAuth protected-resource metadata requires GATEWAY_PUBLIC_URL to be configured",
        );
    };

    Json(metadata.document()).into_response()
}

impl ProxyState {
    fn from_config(
        config: &config::Config,
        default_egress_config: &egress::EgressConfig,
        egress_client: Arc<egress::EgressClient>,
    ) -> Result<Option<Self>, egress::EgressError> {
        if let Some(upstream_url) = config.upstream_url.as_deref() {
            let upstream_origin = upstream_origin_from_url(upstream_url, "UPSTREAM_URL");

            return Ok(Some(Self {
                routes: ProxyRoutes::Legacy {
                    upstream_origin: upstream_origin.clone(),
                },
                upstream_health: upstream_health_targets([(
                    upstream_origin,
                    Arc::clone(&egress_client),
                )]),
                egress_client,
                max_request_body_bytes: config.egress_max_request_body_bytes,
            }));
        }

        if config.upstream_routes.is_empty() {
            return Ok(None);
        }

        let mut route_clients = HashMap::new();
        let routes: Vec<_> = config
            .upstream_routes
            .iter()
            .enumerate()
            .map(|(index, route)| {
                let egress_client = route_egress_client(
                    route,
                    default_egress_config,
                    &egress_client,
                    &mut route_clients,
                )?;

                Ok(ProxyRoute {
                    path_prefix: route.path_prefix.clone(),
                    host: route.host.as_ref().map(|host| host.to_ascii_lowercase()),
                    upstream_origin: upstream_origin_from_url(
                        &route.upstream_url,
                        &format!("UPSTREAM_ROUTES[{index}].upstream_url"),
                    ),
                    request_header_policy: route_request_header_policy(route),
                    egress_client,
                })
            })
            .collect::<Result<_, egress::EgressError>>()?;
        let upstream_health = upstream_health_targets(routes.iter().map(|route| {
            (
                route.upstream_origin.clone(),
                Arc::clone(&route.egress_client),
            )
        }));

        Ok(Some(Self {
            routes: ProxyRoutes::RoutingTable { routes },
            upstream_health,
            egress_client,
            max_request_body_bytes: config.egress_max_request_body_bytes,
        }))
    }

    #[cfg(test)]
    fn upstream_origin_for_request(&self, path: &str, headers: &HeaderMap) -> Option<&str> {
        match &self.routes {
            ProxyRoutes::Legacy { upstream_origin } => Some(upstream_origin),
            ProxyRoutes::RoutingTable { routes } => {
                routing_route_for_request(routes, path, headers)
                    .map(|route| route.upstream_origin.as_str())
            }
        }
    }

    fn upstream_for_request(&self, path: &str, headers: &HeaderMap) -> Option<MatchedUpstream> {
        match &self.routes {
            ProxyRoutes::Legacy { upstream_origin } => Some(MatchedUpstream {
                upstream_origin: upstream_origin.clone(),
                request_header_policy: RouteRequestHeaderPolicy::default(),
                egress_client: Arc::clone(&self.egress_client),
            }),
            ProxyRoutes::RoutingTable { routes } => {
                routing_route_for_request(routes, path, headers).map(|route| MatchedUpstream {
                    upstream_origin: route.upstream_origin.clone(),
                    request_header_policy: route.request_header_policy.clone(),
                    egress_client: Arc::clone(&route.egress_client),
                })
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
            let egress_client = Arc::clone(&target.egress_client);
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

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RouteEgressClientKey {
    timeout_ms: Option<u64>,
    response_idle_timeout_ms: Option<u64>,
    connect_timeout_ms: Option<u64>,
    tls_ca_bundle_path: Option<PathBuf>,
}

impl RouteEgressClientKey {
    fn from_route(route: &config::UpstreamRouteConfig) -> Self {
        Self {
            timeout_ms: route.timeout_ms,
            response_idle_timeout_ms: route.response_idle_timeout_ms,
            connect_timeout_ms: route.connect_timeout_ms,
            tls_ca_bundle_path: route.tls_ca_bundle_path.clone(),
        }
    }

    fn is_default(&self) -> bool {
        self.timeout_ms.is_none()
            && self.response_idle_timeout_ms.is_none()
            && self.connect_timeout_ms.is_none()
            && self.tls_ca_bundle_path.is_none()
    }

    fn apply_to_config(
        &self,
        config: &mut egress::EgressConfig,
    ) -> Result<(), egress::EgressError> {
        config.apply_timeout_overrides(
            self.timeout_ms,
            self.response_idle_timeout_ms,
            self.connect_timeout_ms,
        );
        if let Some(path) = &self.tls_ca_bundle_path {
            config.apply_tls_ca_bundle_path(path.clone())?;
        }

        Ok(())
    }
}

fn route_egress_client(
    route: &config::UpstreamRouteConfig,
    default_config: &egress::EgressConfig,
    default_client: &Arc<egress::EgressClient>,
    route_clients: &mut HashMap<RouteEgressClientKey, Arc<egress::EgressClient>>,
) -> Result<Arc<egress::EgressClient>, egress::EgressError> {
    let key = RouteEgressClientKey::from_route(route);
    if key.is_default() {
        return Ok(Arc::clone(default_client));
    }
    if let Some(client) = route_clients.get(&key) {
        return Ok(Arc::clone(client));
    }

    let mut config = default_config.clone();
    key.apply_to_config(&mut config)?;
    let client = Arc::new(egress::EgressClient::new(config)?);
    route_clients.insert(key, Arc::clone(&client));

    Ok(client)
}

fn route_request_header_policy(route: &config::UpstreamRouteConfig) -> RouteRequestHeaderPolicy {
    let mut add_request_headers = route
        .add_request_headers
        .iter()
        .map(|(name, value)| {
            (
                HeaderName::from_bytes(name.as_bytes())
                    .expect("validated route add header name should parse"),
                HeaderValue::from_str(value)
                    .expect("validated route add header value should parse"),
            )
        })
        .collect::<Vec<_>>();
    add_request_headers.sort_by(|(left, _), (right, _)| left.as_str().cmp(right.as_str()));

    let mut strip_request_headers = route
        .strip_request_headers
        .iter()
        .map(|name| {
            HeaderName::from_bytes(name.as_bytes())
                .expect("validated route strip header name should parse")
        })
        .collect::<Vec<_>>();
    strip_request_headers.sort_by(|left, right| left.as_str().cmp(right.as_str()));

    RouteRequestHeaderPolicy {
        add_request_headers,
        strip_request_headers,
    }
}

fn routing_route_for_request<'a>(
    routes: &'a [ProxyRoute],
    path: &str,
    headers: &HeaderMap,
) -> Option<&'a ProxyRoute> {
    let request_host = upstream_route::request_host_without_port(headers);
    upstream_route::matching_route(routes, path, request_host.as_deref())
}

impl upstream_route::RouteMatch for ProxyRoute {
    fn path_prefix(&self) -> Option<&str> {
        self.path_prefix.as_deref()
    }

    fn host(&self) -> Option<&str> {
        self.host.as_deref()
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

async fn proxy_fallback(State(state): State<AppState>, request: Request<Body>) -> Response {
    record_request(PROXY_FALLBACK_ROUTE);

    if state.routes.is_gateway_owned_path(request.uri().path()) {
        return StatusCode::NOT_FOUND.into_response();
    }

    let Some(proxy) = state.proxy.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let Some(upstream) = proxy.upstream_for_request(request.uri().path(), request.headers()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let (parts, body) = request.into_parts();
    let target_url = proxy_target_url(&upstream.upstream_origin, &parts.uri);
    let mut headers = strip_hop_by_hop_headers(&parts.headers);
    if let Some(request_id) = parts.headers.get(REQUEST_ID_HEADER) {
        headers.insert(request_id_header(), request_id.clone());
    }
    apply_route_request_header_policy(&mut headers, &upstream.request_header_policy);
    let request_id = parts.headers.get(REQUEST_ID_HEADER).cloned();
    let payload_capture = parts
        .extensions
        .get::<middleware::observation::PayloadCaptureHandle>()
        .cloned();
    let body = match axum::body::to_bytes(body, proxy.max_request_body_bytes).await {
        Ok(body) if body.is_empty() => None,
        Ok(body) => {
            if let Some(payload_capture) = payload_capture.as_ref() {
                payload_capture.capture_json_body(&parts.headers, &body);
            }
            Some(body.to_vec())
        }
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
    let upstream = match upstream
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

fn apply_route_request_header_policy(headers: &mut HeaderMap, policy: &RouteRequestHeaderPolicy) {
    for name in &policy.strip_request_headers {
        if name.as_str() == REQUEST_ID_HEADER {
            continue;
        }
        headers.remove(name);
    }

    for (name, value) in &policy.add_request_headers {
        if is_hop_by_hop_header(name) || name.as_str() == REQUEST_ID_HEADER {
            continue;
        }
        headers.insert(name.clone(), value.clone());
    }
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

async fn admin_auth_login_endpoint(State(state): State<AdminAuthState>) -> Response {
    record_request(ADMIN_AUTH_LOGIN_ROUTE);

    match state.login.begin_login() {
        Ok(start) => found_redirect(start.authorization_url),
        Err(err) => {
            tracing::warn!(error = %err, "failed to start admin OIDC login");
            found_redirect(admin_auth_error_url(
                &state.admin_prefix,
                "login_start_failed",
            ))
        }
    }
}

async fn admin_auth_callback_endpoint(
    State(state): State<AdminAuthState>,
    Query(params): Query<AdminAuthCallbackParams>,
) -> Response {
    record_request(ADMIN_AUTH_CALLBACK_ROUTE);

    if params.error.is_some() {
        return found_redirect(admin_auth_error_url(&state.admin_prefix, "provider_error"));
    }

    let Some(code) = params
        .code
        .as_deref()
        .map(str::trim)
        .filter(|code| !code.is_empty())
    else {
        return found_redirect(admin_auth_error_url(&state.admin_prefix, "missing_code"));
    };
    let Some(oauth_state) = params
        .state
        .as_deref()
        .map(str::trim)
        .filter(|state| !state.is_empty())
    else {
        return found_redirect(admin_auth_error_url(&state.admin_prefix, "invalid_state"));
    };

    match state.login.exchange_code(code, oauth_state).await {
        Ok(exchange) => found_redirect(admin_auth_complete_url(
            &state.admin_prefix,
            &exchange.access_token,
        )),
        Err(err) if err.is_invalid_state() => {
            tracing::warn!("admin OIDC callback rejected unknown or expired state");
            found_redirect(admin_auth_error_url(&state.admin_prefix, "invalid_state"))
        }
        Err(err) => {
            tracing::warn!(error = %err, "admin OIDC token exchange failed");
            found_redirect(admin_auth_error_url(
                &state.admin_prefix,
                "token_exchange_failed",
            ))
        }
    }
}

fn found_redirect(location: String) -> Response {
    match HeaderValue::from_str(&location) {
        Ok(location) => (StatusCode::FOUND, [(header::LOCATION, location)]).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "failed to build redirect Location header");
            internal_server_error("redirect location was invalid")
        }
    }
}

fn admin_auth_complete_url(admin_prefix: &str, token: &str) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("token", token);
    format!(
        "{}/#/auth/complete?{}",
        admin_prefix.trim_end_matches('/'),
        serializer.finish()
    )
}

fn admin_auth_error_url(admin_prefix: &str, error: &str) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("error", error);
    format!(
        "{}/#/auth/error?{}",
        admin_prefix.trim_end_matches('/'),
        serializer.finish()
    )
}

async fn status_endpoint(
    State(state): State<StatusAdminState>,
    principal: Option<Extension<auth::Principal>>,
) -> Response {
    record_request(STATUS_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };

    if let Err(error) = authorized_status_state(&state, &principal, ADMIN_STATUS_READ_PERMISSION) {
        return status_admin_authz_error_response(error);
    }

    Json(StatusResponse::from_state(&state)).into_response()
}

async fn policy_get_endpoint(
    State(state): State<PolicyAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_ADMIN_ROUTE);

    let Some(principal) = request.extensions().get::<auth::Principal>() else {
        return unauthorized();
    };
    let rbac_state = match authorized_policy_state(&state, principal, ADMIN_POLICY_READ_PERMISSION)
    {
        Ok(rbac_state) => rbac_state,
        Err(error) => return policy_admin_authz_error_response(error),
    };

    let policy = rbac_state.current_policy();
    let etag = match policy_etag(&policy) {
        Ok(etag) => etag,
        Err(err) => {
            tracing::error!(error = %err, "failed to compute policy ETag");
            return internal_server_error("policy ETag computation failed");
        }
    };

    (
        StatusCode::OK,
        [(header::ETAG, etag_header_value(&etag))],
        Json(policy),
    )
        .into_response()
}

async fn policy_put_endpoint(
    State(state): State<PolicyAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let rbac_state =
        match authorized_policy_state(&state, &principal, ADMIN_POLICY_WRITE_PERMISSION) {
            Ok(rbac_state) => rbac_state,
            Err(error) => return policy_admin_authz_error_response(error),
        };
    let Some(policy_file) = state.policy_file.as_deref() else {
        return policy_not_configured();
    };

    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let candidate = match parse_policy_body(&body) {
        Ok(policy) => policy,
        Err(errors) => return policy_validation_failed(errors),
    };

    let _policy_write_guard = match rbac_state.policy_write_guard() {
        Ok(guard) => guard,
        Err(err) => {
            tracing::error!(error = %err, "failed to acquire policy write lock");
            return internal_server_error("policy write lock failed");
        }
    };

    let before_policy = rbac_state.current_policy();
    let current_etag = match policy_etag(&before_policy) {
        Ok(etag) => etag,
        Err(err) => {
            tracing::error!(error = %err, "failed to compute current policy ETag");
            return internal_server_error("policy ETag computation failed");
        }
    };

    match if_match_matches(&parts.headers, &current_etag) {
        Ok(true) => {}
        Ok(false) => return precondition_failed("If-Match does not match the current policy ETag"),
        Err(error) => return if_match_error_response(error),
    }

    if let Err(err) = candidate.persist_to_file(policy_file) {
        tracing::error!(policy_file = %policy_file.display(), error = %err, "failed to persist policy");
        return internal_server_error("policy persist failed");
    }

    if let Err(err) = middleware::rbac::reload_policy_from_file(rbac_state, policy_file) {
        tracing::error!(policy_file = %policy_file.display(), error = %err, "failed to reload persisted policy");
        return internal_server_error("policy reload failed");
    }

    let after_policy = rbac_state.current_policy();
    let diff_summary = json!({
        "action": "policy_replaced",
    });
    let history_append_failed =
        append_policy_version_after_commit(&state, &principal, &after_policy, &diff_summary);
    emit_policy_rule_changed(
        &state,
        &parts,
        &principal,
        &before_policy,
        &after_policy,
        diff_summary,
    );

    let new_etag = match policy_etag(&after_policy) {
        Ok(etag) => etag,
        Err(err) => {
            tracing::error!(error = %err, "failed to compute updated policy ETag");
            return internal_server_error("policy ETag computation failed");
        }
    };

    let response = (
        StatusCode::OK,
        [(header::ETAG, etag_header_value(&new_etag))],
        Json(after_policy),
    )
        .into_response();
    with_policy_history_append_warning(response, history_append_failed)
}

async fn policy_history_endpoint(
    State(state): State<PolicyAdminState>,
    principal: Option<Extension<auth::Principal>>,
    Query(params): Query<PolicyHistoryParams>,
) -> Response {
    record_request(POLICY_HISTORY_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    if let Err(error) = authorized_policy_state(&state, &principal, ADMIN_POLICY_READ_PERMISSION) {
        return policy_admin_authz_error_response(error);
    }
    let Some(history_store) = state.history_store.as_ref() else {
        return policy_history_not_configured();
    };
    let filters = match params.into_filters() {
        Ok(filters) => filters,
        Err(parameter) => return bad_request(&format!("invalid query parameter: {parameter}")),
    };

    match history_store.list_versions(&filters) {
        Ok(page) => (StatusCode::OK, Json(page)).into_response(),
        Err(rbac::policy_history::PolicyHistoryError::InvalidCursor { parameter }) => {
            bad_request(&format!("invalid query parameter: {parameter}"))
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to query policy history");
            internal_server_error("policy history query failed")
        }
    }
}

async fn policy_rollback_endpoint(
    State(state): State<PolicyAdminState>,
    Path(version): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_ROLLBACK_ADMIN_ROUTE);

    let target_version = match parse_policy_history_version(&version) {
        Ok(version) => version,
        Err(parameter) => return bad_request(&format!("invalid path parameter: {parameter}")),
    };
    let (parts, _body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let rbac_state =
        match authorized_policy_state(&state, &principal, ADMIN_POLICY_WRITE_PERMISSION) {
            Ok(rbac_state) => rbac_state,
            Err(error) => return policy_admin_authz_error_response(error),
        };
    let Some(policy_file) = state.policy_file.as_deref() else {
        return policy_not_configured();
    };
    let Some(history_store) = state.history_store.as_ref() else {
        return policy_history_not_configured();
    };

    let target = match history_store.get_version(target_version) {
        Ok(Some(version)) => version,
        Ok(None) => return not_found("policy version was not found"),
        Err(err) => {
            tracing::error!(error = %err, version = target_version, "failed to load policy history version");
            return internal_server_error("policy history query failed");
        }
    };
    let Some(target_policy) = target.policy else {
        tracing::error!(
            version = target_version,
            "policy history detail omitted target snapshot"
        );
        return internal_server_error("policy history query failed");
    };

    let _policy_write_guard = match rbac_state.policy_write_guard() {
        Ok(guard) => guard,
        Err(err) => {
            tracing::error!(error = %err, "failed to acquire policy write lock");
            return internal_server_error("policy write lock failed");
        }
    };

    let before_policy = rbac_state.current_policy();
    match require_matching_if_match(&parts.headers, &before_policy) {
        Ok(_) => {}
        Err(response) => return *response,
    }

    let diff_summary = json!({
        "action": "policy_rolled_back",
        "target_version": target.version,
    });
    let commit = match persist_policy_mutation(
        PolicyMutationCommitContext {
            state: &state,
            rbac_state,
            policy_file,
            parts: &parts,
            principal: &principal,
        },
        &before_policy,
        &target_policy,
        diff_summary,
    ) {
        Ok(result) => result,
        Err(response) => return *response,
    };

    let response = (
        StatusCode::OK,
        [(header::ETAG, etag_header_value(&commit.new_etag))],
        Json(commit.after_policy),
    )
        .into_response();
    with_policy_history_append_warning(response, commit.history_append_failed)
}

async fn policy_validate_endpoint(
    State(state): State<PolicyAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_VALIDATE_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>() else {
        return unauthorized();
    };
    if let Err(error) = authorized_policy_state(&state, principal, ADMIN_POLICY_READ_PERMISSION) {
        return policy_admin_authz_error_response(error);
    }

    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return response,
    };

    match parse_policy_body(&body) {
        Ok(_) => Json(PolicyValidationResponse {
            valid: true,
            errors: Vec::new(),
        })
        .into_response(),
        Err(errors) => policy_validation_failed(errors),
    }
}

async fn policy_rule_post_endpoint(
    State(state): State<PolicyAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_RULES_ADMIN_ROUTE);

    let (parts, body, principal, rbac_state, policy_file) =
        match split_authorized_policy_mutation_request(&state, request) {
            Ok(context) => context,
            Err(response) => return *response,
        };

    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let rule = match parse_rule_body(&body) {
        Ok(rule) => rule,
        Err(errors) => return policy_validation_failed(errors),
    };

    let created =
        match create_policy_rule(&state, &parts, &principal, rbac_state, policy_file, rule) {
            Ok(result) => result,
            Err(response) => return *response,
        };

    let response = (
        StatusCode::CREATED,
        [(header::ETAG, etag_header_value(&created.new_etag))],
        Json(created.rule),
    )
        .into_response();
    with_policy_history_append_warning(response, created.history_append_failed)
}

async fn policy_rule_patch_endpoint(
    State(state): State<PolicyAdminState>,
    Path(rule_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_RULE_ADMIN_ROUTE);

    let (parts, body, principal, rbac_state, policy_file) =
        match split_authorized_policy_mutation_request(&state, request) {
            Ok(context) => context,
            Err(response) => return *response,
        };

    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let patch = match parse_rule_patch_body(&body) {
        Ok(patch) => patch,
        Err(errors) => return policy_validation_failed(errors),
    };
    if patch.is_empty() {
        return bad_request(
            "rule patch must include at least one of enabled, methods, path, tool_name, principal, action",
        );
    }

    let _policy_write_guard = match rbac_state.policy_write_guard() {
        Ok(guard) => guard,
        Err(err) => {
            tracing::error!(error = %err, "failed to acquire policy write lock");
            return internal_server_error("policy write lock failed");
        }
    };

    let before_policy = rbac_state.current_policy();
    match require_matching_if_match(&parts.headers, &before_policy) {
        Ok(_) => {}
        Err(response) => return *response,
    }

    let rule_index = match rule_index_by_id(&before_policy, &rule_id) {
        Ok(rule_index) => rule_index,
        Err(error) => return rule_lookup_error_response(&rule_id, error),
    };

    let mut candidate = before_policy.clone();
    let before_rule = candidate.rules[rule_index].clone();
    apply_rule_patch(&mut candidate.rules[rule_index], patch);
    let changed_fields = changed_rule_fields(&before_rule, &candidate.rules[rule_index]);

    let candidate = match validate_policy_candidate(&candidate) {
        Ok(candidate) => candidate,
        Err(response) => return *response,
    };
    let updated_rule = candidate.rules[rule_index].clone();

    let diff_summary = json!({
        "action": "rule_updated",
        "rule_id": rule_id,
        "changed_fields": changed_fields,
    });
    let commit = match persist_policy_mutation(
        PolicyMutationCommitContext {
            state: &state,
            rbac_state,
            policy_file,
            parts: &parts,
            principal: &principal,
        },
        &before_policy,
        &candidate,
        diff_summary,
    ) {
        Ok(result) => result,
        Err(response) => return *response,
    };

    let updated_rule = commit
        .after_policy
        .rules
        .get(rule_index)
        .cloned()
        .unwrap_or(updated_rule);

    let response = (
        StatusCode::OK,
        [(header::ETAG, etag_header_value(&commit.new_etag))],
        Json(updated_rule),
    )
        .into_response();
    with_policy_history_append_warning(response, commit.history_append_failed)
}

async fn policy_rule_delete_endpoint(
    State(state): State<PolicyAdminState>,
    Path(rule_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_RULE_ADMIN_ROUTE);

    let (parts, _body, principal, rbac_state, policy_file) =
        match split_authorized_policy_mutation_request(&state, request) {
            Ok(context) => context,
            Err(response) => return *response,
        };

    let _policy_write_guard = match rbac_state.policy_write_guard() {
        Ok(guard) => guard,
        Err(err) => {
            tracing::error!(error = %err, "failed to acquire policy write lock");
            return internal_server_error("policy write lock failed");
        }
    };

    let before_policy = rbac_state.current_policy();
    match require_matching_if_match(&parts.headers, &before_policy) {
        Ok(_) => {}
        Err(response) => return *response,
    }

    let rule_index = match rule_index_by_id(&before_policy, &rule_id) {
        Ok(rule_index) => rule_index,
        Err(error) => return rule_lookup_error_response(&rule_id, error),
    };

    let mut candidate = before_policy.clone();
    candidate.rules.remove(rule_index);
    let candidate = match validate_policy_candidate(&candidate) {
        Ok(candidate) => candidate,
        Err(response) => return *response,
    };

    let diff_summary = json!({
        "action": "rule_deleted",
        "rule_id": rule_id,
        "position": rule_index,
    });
    let commit = match persist_policy_mutation(
        PolicyMutationCommitContext {
            state: &state,
            rbac_state,
            policy_file,
            parts: &parts,
            principal: &principal,
        },
        &before_policy,
        &candidate,
        diff_summary,
    ) {
        Ok(result) => result,
        Err(response) => return *response,
    };

    let response = (
        StatusCode::OK,
        [(header::ETAG, etag_header_value(&commit.new_etag))],
        Json(RuleDeletedResponse {
            deleted_rule_id: rule_id,
        }),
    )
        .into_response();
    with_policy_history_append_warning(response, commit.history_append_failed)
}

async fn policy_rules_order_put_endpoint(
    State(state): State<PolicyAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_RULES_ORDER_ADMIN_ROUTE);

    let (parts, body, principal, rbac_state, policy_file) =
        match split_authorized_policy_mutation_request(&state, request) {
            Ok(context) => context,
            Err(response) => return *response,
        };

    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let requested_order = match parse_rule_order_body(&body) {
        Ok(order) => order,
        Err(errors) => return policy_validation_failed(errors),
    };

    let _policy_write_guard = match rbac_state.policy_write_guard() {
        Ok(guard) => guard,
        Err(err) => {
            tracing::error!(error = %err, "failed to acquire policy write lock");
            return internal_server_error("policy write lock failed");
        }
    };

    let before_policy = rbac_state.current_policy();
    match require_matching_if_match(&parts.headers, &before_policy) {
        Ok(_) => {}
        Err(response) => return *response,
    }

    let current_order = policy_rule_ids(&before_policy);
    if let Err(errors) = validate_rule_order(&current_order, &requested_order) {
        return policy_validation_failed(errors);
    }

    let mut candidate = before_policy.clone();
    candidate.rules = reordered_rules(&before_policy, &requested_order);
    let candidate = match validate_policy_candidate(&candidate) {
        Ok(candidate) => candidate,
        Err(response) => return *response,
    };

    let diff_summary = json!({
        "action": "rules_reordered",
        "new_order": requested_order,
    });
    let commit = match persist_policy_mutation(
        PolicyMutationCommitContext {
            state: &state,
            rbac_state,
            policy_file,
            parts: &parts,
            principal: &principal,
        },
        &before_policy,
        &candidate,
        diff_summary,
    ) {
        Ok(result) => result,
        Err(response) => return *response,
    };
    let order = policy_rule_ids(&commit.after_policy);

    let response = (
        StatusCode::OK,
        [(header::ETAG, etag_header_value(&commit.new_etag))],
        Json(RulesReorderedResponse { order }),
    )
        .into_response();
    with_policy_history_append_warning(response, commit.history_append_failed)
}

async fn token_create_endpoint(
    State(state): State<TokenAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(TOKENS_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let store = match authorized_token_store(&state, &principal, ADMIN_TOKENS_WRITE_PERMISSION) {
        Ok(store) => store,
        Err(error) => return token_admin_authz_error_response(error),
    };
    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let requested = match parse_create_token_body(&body) {
        Ok(requested) => requested,
        Err(response) => return *response,
    };

    let created = match store.create(auth::tokens::CreateTokenRequest {
        scopes: requested.scopes,
        created_by: principal.user_id.clone(),
        expires_at: requested.expires_at,
    }) {
        Ok(created) => created,
        Err(error) => return token_store_error_response(error),
    };

    emit_service_token_changed(&state, &parts, &principal, "token_created", &created.record);

    (
        StatusCode::CREATED,
        Json(CreatedTokenAdminResponse::from_created(created)),
    )
        .into_response()
}

async fn token_list_endpoint(
    State(state): State<TokenAdminState>,
    Query(params): Query<TokenListParams>,
    request: AxumRequest,
) -> Response {
    record_request(TOKENS_ADMIN_ROUTE);

    let Some(principal) = request.extensions().get::<auth::Principal>() else {
        return unauthorized();
    };
    let store = match authorized_token_store(&state, principal, ADMIN_TOKENS_READ_PERMISSION) {
        Ok(store) => store,
        Err(error) => return token_admin_authz_error_response(error),
    };
    let filters = match params.into_filters() {
        Ok(filters) => filters,
        Err(parameter) => return bad_request(&format!("invalid query parameter: {parameter}")),
    };

    match store.list(&filters) {
        Ok(page) => (StatusCode::OK, Json(page)).into_response(),
        Err(error) => token_store_error_response(error),
    }
}

async fn token_get_endpoint(
    State(state): State<TokenAdminState>,
    Path(token_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(TOKEN_ADMIN_ROUTE);

    let Some(principal) = request.extensions().get::<auth::Principal>() else {
        return unauthorized();
    };
    let store = match authorized_token_store(&state, principal, ADMIN_TOKENS_READ_PERMISSION) {
        Ok(store) => store,
        Err(error) => return token_admin_authz_error_response(error),
    };

    match store.get_by_id(&token_id) {
        Ok(Some(record)) => (StatusCode::OK, Json(record)).into_response(),
        Ok(None) => not_found("service token was not found"),
        Err(error) => token_store_error_response(error),
    }
}

async fn token_revoke_endpoint(
    State(state): State<TokenAdminState>,
    Path(token_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(TOKEN_ADMIN_ROUTE);

    let (parts, _body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let store = match authorized_token_store(&state, &principal, ADMIN_TOKENS_WRITE_PERMISSION) {
        Ok(store) => store,
        Err(error) => return token_admin_authz_error_response(error),
    };

    match store.revoke(&token_id) {
        Ok(Some(record)) => {
            if let Some(validator) = state.validator.as_ref() {
                validator.invalidate_token_id(&token_id);
            }
            emit_service_token_changed(&state, &parts, &principal, "token_revoked", &record);
            (StatusCode::OK, Json(record)).into_response()
        }
        Ok(None) => not_found("service token was not found"),
        Err(error) => token_store_error_response(error),
    }
}

async fn token_rotate_endpoint(
    State(state): State<TokenAdminState>,
    Path(token_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(TOKEN_ROTATE_ADMIN_ROUTE);

    let (parts, _body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let store = match authorized_token_store(&state, &principal, ADMIN_TOKENS_WRITE_PERMISSION) {
        Ok(store) => store,
        Err(error) => return token_admin_authz_error_response(error),
    };

    match store.rotate(&token_id) {
        Ok(Some(created)) => {
            if let Some(validator) = state.validator.as_ref() {
                validator.invalidate_token_id(&token_id);
            }
            emit_service_token_changed(
                &state,
                &parts,
                &principal,
                "token_rotated",
                &created.record,
            );
            (
                StatusCode::OK,
                Json(CreatedTokenAdminResponse::from_created(created)),
            )
                .into_response()
        }
        Ok(None) => not_found("service token was not found"),
        Err(auth::tokens::TokenStoreError::RevokedToken { .. }) => {
            conflict("cannot rotate revoked service token")
        }
        Err(error) => token_store_error_response(error),
    }
}

async fn tools_openapi_preview_endpoint(
    State(state): State<ToolAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(TOOLS_OPENAPI_PREVIEW_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>() else {
        return unauthorized();
    };
    let tools_file = match authorized_tools_file(&state, principal, ADMIN_TOOLS_READ_PERMISSION) {
        Ok(tools_file) => tools_file,
        Err(error) => return tool_admin_authz_error_response(error),
    };
    let tools_file_value = match read_valid_tools_file_value(tools_file) {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(tools_file = %tools_file.display(), error = %error, "failed to read current tools file for OpenAPI preview");
            return internal_server_error("tools file read failed");
        }
    };
    let current_etag = match tools_file_etag(&tools_file_value) {
        Ok(etag) => etag,
        Err(err) => {
            tracing::error!(error = %err, "failed to compute tools file ETag");
            return internal_server_error("tools file ETag computation failed");
        }
    };

    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let spec = match std::str::from_utf8(&body) {
        Ok(spec) => spec,
        Err(err) => return bad_request(&format!("invalid OpenAPI spec UTF-8: {err}")),
    };
    let generation =
        match tools::openapi::generate_tools_from_openapi_str("admin-openapi-preview", spec) {
            Ok(generation) => generation,
            Err(err) => return bad_request(&format!("invalid OpenAPI spec: {err}")),
        };

    (
        StatusCode::OK,
        [(header::ETAG, etag_header_value(&current_etag))],
        Json(openapi_tools_preview_response(generation)),
    )
        .into_response()
}

async fn tools_openapi_register_endpoint(
    State(state): State<ToolAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(TOOLS_OPENAPI_REGISTER_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let tools_file = match authorized_tools_file(&state, &principal, ADMIN_TOOLS_WRITE_PERMISSION) {
        Ok(tools_file) => tools_file,
        Err(error) => return tool_admin_authz_error_response(error),
    };

    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let requested = match parse_openapi_tools_register_body(&body) {
        Ok(requested) => requested,
        Err(response) => return *response,
    };
    if requested.selected_tool_names.is_empty() {
        return bad_request("selected_tool_names must include at least one tool name");
    }

    let generation = match tools::openapi::generate_tools_from_openapi_str(
        "admin-openapi-register",
        &requested.spec,
    ) {
        Ok(generation) => generation,
        Err(err) => return bad_request(&format!("invalid OpenAPI spec: {err}")),
    };
    let selected = match selected_generated_tools(&generation, &requested) {
        Ok(selected) => selected,
        Err(response) => return *response,
    };

    let _tools_write_guard = match state.write_lock.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let (current_value, mut current_document) = match read_tools_file_document(tools_file) {
        Ok(document) => document,
        Err(error) => {
            tracing::error!(tools_file = %tools_file.display(), error = %error, "failed to read current tools file for OpenAPI registration");
            return internal_server_error("tools file read failed");
        }
    };
    let current_etag = match tools_file_etag(&current_value) {
        Ok(etag) => etag,
        Err(err) => {
            tracing::error!(error = %err, "failed to compute current tools file ETag");
            return internal_server_error("tools file ETag computation failed");
        }
    };
    match if_match_matches(&parts.headers, &current_etag) {
        Ok(true) => {}
        Ok(false) => {
            return precondition_failed("If-Match does not match the current tools ETag");
        }
        Err(error) => return if_match_error_response(error),
    }

    let conflicts = conflicting_tool_names(&current_document.tools, &selected);
    if !conflicts.is_empty() {
        return (
            StatusCode::CONFLICT,
            Json(ToolNameConflictResponse {
                error: "tool name collision",
                conflicts,
            }),
        )
            .into_response();
    }

    let registered_tool_names = selected
        .iter()
        .map(|tool| tool.name.clone())
        .collect::<Vec<_>>();
    current_document.tools.extend(selected);
    let candidate_value = match serde_json::to_value(&current_document) {
        Ok(value) => value,
        Err(err) => {
            tracing::error!(error = %err, "failed to serialize merged tools file");
            return internal_server_error("tools file merge failed");
        }
    };
    if let Err(err) = tools::definitions::ToolRegistry::from_json_value(candidate_value.clone()) {
        tracing::error!(tools_file = %tools_file.display(), error = %err, "merged OpenAPI tools file failed validation");
        return internal_server_error("tools file validation failed");
    }
    let candidate_contents = match serde_json::to_string_pretty(&candidate_value) {
        Ok(contents) => contents,
        Err(err) => {
            tracing::error!(error = %err, "failed to render merged tools file");
            return internal_server_error("tools file merge failed");
        }
    };
    if let Err(err) = fs::write(tools_file, candidate_contents) {
        tracing::error!(tools_file = %tools_file.display(), error = %err, "failed to persist merged tools file");
        return internal_server_error("tools file persist failed");
    }
    if let Err(err) =
        tools::definitions::reload_tool_registry_from_file_with_mcp_proxy_definitions_provider(
            &state.registry,
            tools_file,
            state.mcp_proxy_definitions_provider.as_ref(),
        )
    {
        tracing::error!(tools_file = %tools_file.display(), error = %err, "failed to reload persisted tools file");
        return internal_server_error("tools registry reload failed");
    }

    emit_tool_registry_changed(
        &state,
        &parts,
        &principal,
        tools_file,
        &registered_tool_names,
        current_document.tools.len(),
    );
    let new_etag = match tools_file_etag(&candidate_value) {
        Ok(etag) => etag,
        Err(err) => {
            tracing::error!(error = %err, "failed to compute updated tools file ETag");
            return internal_server_error("tools file ETag computation failed");
        }
    };

    (
        StatusCode::CREATED,
        [(header::ETAG, etag_header_value(&new_etag))],
        Json(OpenApiToolsRegisterResponse {
            registered_tool_names,
            tool_count: current_document.tools.len(),
        }),
    )
        .into_response()
}

async fn policy_rule_preview_endpoint(
    State(state): State<PolicyAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_RULE_PREVIEW_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>() else {
        return unauthorized();
    };
    if let Err(error) = authorized_policy_state(&state, principal, ADMIN_POLICY_READ_PERMISSION) {
        return policy_admin_authz_error_response(error);
    }
    let Some(query_store) = state.query_store.as_ref() else {
        return service_unavailable(
            "policy rule preview requires AUDIT_SQLITE_PATH to be configured",
        );
    };

    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let preview_request = match parse_rule_preview_body(&body) {
        Ok(request) => request,
        Err(errors) => return policy_validation_failed(errors),
    };

    match preview_rule(query_store, preview_request) {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "failed to preview policy rule");
            internal_server_error("policy rule preview failed")
        }
    }
}

async fn policy_rule_hits_endpoint(
    State(state): State<PolicyAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_RULE_HITS_ADMIN_ROUTE);

    let Some(principal) = request.extensions().get::<auth::Principal>() else {
        return unauthorized();
    };
    let rbac_state = match authorized_policy_state(&state, principal, ADMIN_POLICY_READ_PERMISSION)
    {
        Ok(rbac_state) => rbac_state,
        Err(error) => return policy_admin_authz_error_response(error),
    };
    let policy = rbac_state.current_policy();
    let counts = match state.query_store.as_ref() {
        Some(query_store) => match query_store.rule_hit_counts() {
            Ok(counts) => counts,
            Err(err) => {
                tracing::error!(error = %err, "failed to query policy rule hit counts");
                return internal_server_error("policy rule hit count query failed");
            }
        },
        None => HashMap::new(),
    };

    Json(PolicyRuleHitsResponse {
        rules: policy
            .rules
            .iter()
            .enumerate()
            .map(|(rule_index, rule)| {
                let rule_id = rule.id.clone().unwrap_or_else(|| rule_index.to_string());
                let hits = counts.get(&rule_id).copied().unwrap_or(0);
                PolicyRuleHitCount { rule_id, hits }
            })
            .collect(),
    })
    .into_response()
}

async fn policy_rule_shadow_review_endpoint(
    State(state): State<PolicyAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_RULE_SHADOW_REVIEW_ADMIN_ROUTE);

    let Some(principal) = request.extensions().get::<auth::Principal>() else {
        return unauthorized();
    };
    let rbac_state = match authorized_policy_state(&state, principal, ADMIN_POLICY_READ_PERMISSION)
    {
        Ok(rbac_state) => rbac_state,
        Err(error) => return policy_admin_authz_error_response(error),
    };
    let policy = rbac_state.current_policy();
    let shadow_rules = policy
        .rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule.enabled && rule.action == rbac::RuleAction::Shadow)
        .map(|(rule_index, rule)| {
            (
                rule.id.clone().unwrap_or_else(|| rule_index.to_string()),
                rule.clone(),
            )
        })
        .collect::<Vec<_>>();
    let rule_ids = shadow_rules
        .iter()
        .map(|(rule_id, _)| rule_id.clone())
        .collect::<Vec<_>>();

    let review = match state.query_store.as_ref() {
        Some(query_store) => match query_store.shadow_rule_would_deny_summaries(&rule_ids) {
            Ok(review) => review,
            Err(err) => {
                tracing::error!(error = %err, "failed to query shadow rule review summaries");
                return internal_server_error("shadow rule review query failed");
            }
        },
        None => audit::query::ShadowRuleWouldDenySummarySet::default(),
    };

    Json(PolicyRuleShadowReviewResponse {
        scanned_event_count: review.scanned_event_count,
        scan_truncated: review.scan_truncated,
        rules: shadow_rules
            .into_iter()
            .map(|(rule_id, rule)| {
                let summary = review.summaries.get(&rule_id);
                PolicyRuleShadowReviewSummary {
                    rule_id,
                    rule,
                    would_deny_count: summary.map(|summary| summary.would_deny_count).unwrap_or(0),
                    affected_principals: summary
                        .map(|summary| summary.affected_principals.clone())
                        .unwrap_or_default(),
                    samples: summary
                        .map(|summary| summary.samples.clone())
                        .unwrap_or_default(),
                }
            })
            .collect(),
    })
    .into_response()
}

async fn schema_coverage_endpoint(
    State(state): State<SchemaAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(SCHEMA_COVERAGE_ADMIN_ROUTE);

    let Some(principal) = request.extensions().get::<auth::Principal>() else {
        return unauthorized();
    };
    if !authorized_schema_reader(&state, principal) {
        return forbidden();
    }
    if !state.coverage.spec_configured() {
        return schema_not_configured();
    }
    let Some(query_store) = state.query_store.as_ref() else {
        return schema_discovery_not_configured();
    };

    let observed = match query_store.observed_endpoints() {
        Ok(observed) => observed,
        Err(err) => {
            tracing::error!(error = %err, "failed to query schema coverage discovery inventory");
            return internal_server_error("schema coverage discovery query failed");
        }
    };

    Json(state.coverage.compare(&observed)).into_response()
}

async fn schema_inferred_endpoint(
    State(state): State<SchemaAdminState>,
    principal: Option<Extension<auth::Principal>>,
    Query(params): Query<InferredSchemaParams>,
) -> Response {
    record_request(SCHEMA_INFERRED_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    if !authorized_schema_reader(&state, &principal) {
        return forbidden();
    }
    if !state.payload_capture_enabled {
        return payload_capture_not_configured();
    }
    let Some(query_store) = state.query_store.as_ref() else {
        return schema_inference_discovery_not_configured();
    };
    let query = match params.into_query() {
        Ok(query) => query,
        Err(parameter) => return bad_request(&format!("invalid query parameter: {parameter}")),
    };

    match query_store.inferred_request_schema(&query.method, &query.endpoint_template) {
        Ok(Some(schema)) => (StatusCode::OK, Json(schema)).into_response(),
        Ok(None) => inferred_schema_no_samples(),
        Err(err) => {
            tracing::error!(error = %err, "failed to query inferred request schema");
            internal_server_error("inferred schema query failed")
        }
    }
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

    if let Err(error) = authorized_audit_state(&state, &principal, ADMIN_AUDIT_READ_PERMISSION) {
        return audit_admin_authz_error_response(error);
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

async fn signals_list_endpoint(
    State(state): State<SignalsAdminState>,
    principal: Option<Extension<auth::Principal>>,
    Query(params): Query<SignalListParams>,
) -> Response {
    record_request(SIGNALS_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    if let Err(error) = authorized_signals_state(&state, &principal, ADMIN_SIGNALS_READ_PERMISSION)
    {
        return signals_admin_authz_error_response(error);
    }

    let Some(discovery_store) = state.discovery_store.as_ref() else {
        return signals_discovery_not_configured();
    };
    let filters = match params.into_filters() {
        Ok(filters) => filters,
        Err(parameter) => return bad_request(&format!("invalid query parameter: {parameter}")),
    };

    match discovery_store.list_signals(&filters) {
        Ok(page) => (StatusCode::OK, Json(page)).into_response(),
        Err(discovery::query::DiscoveryQueryError::InvalidCursor { parameter }) => {
            bad_request(&format!("invalid query parameter: {parameter}"))
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to query discovery signals");
            internal_server_error("signals query failed")
        }
    }
}

async fn signal_acknowledge_endpoint(
    State(state): State<SignalsAdminState>,
    Path(id): Path<String>,
    request: AxumRequest,
) -> Response {
    signal_transition_endpoint(
        state,
        request,
        id,
        discovery::signals::SignalLifecycleState::Acknowledged,
        SIGNAL_ACKNOWLEDGE_ADMIN_ROUTE,
    )
    .await
}

async fn signal_dismiss_endpoint(
    State(state): State<SignalsAdminState>,
    Path(id): Path<String>,
    request: AxumRequest,
) -> Response {
    signal_transition_endpoint(
        state,
        request,
        id,
        discovery::signals::SignalLifecycleState::Dismissed,
        SIGNAL_DISMISS_ADMIN_ROUTE,
    )
    .await
}

async fn signal_transition_endpoint(
    state: SignalsAdminState,
    request: AxumRequest,
    id: String,
    lifecycle_state: discovery::signals::SignalLifecycleState,
    route: &'static str,
) -> Response {
    record_request(route);

    let (parts, _body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    if let Err(error) = authorized_signals_state(&state, &principal, ADMIN_SIGNALS_WRITE_PERMISSION)
    {
        return signals_admin_authz_error_response(error);
    }

    let id = id.trim();
    if id.is_empty() {
        return bad_request("invalid signal id");
    }

    let Some(discovery_store) = state.discovery_store.as_ref() else {
        return signals_discovery_not_configured();
    };
    let signal =
        match discovery_store.transition_signal(id, lifecycle_state, Some(&principal.user_id)) {
            Ok(Some(signal)) => signal,
            Ok(None) => return not_found("signal was not found"),
            Err(err) => {
                tracing::error!(error = %err, "failed to transition discovery signal");
                return internal_server_error("signal transition failed");
            }
        };
    emit_signal_lifecycle_changed(&state, &parts, &principal, &signal);

    (StatusCode::OK, Json(signal)).into_response()
}

async fn rule_suggestions_list_endpoint(
    State(state): State<SuggestionsAdminState>,
    principal: Option<Extension<auth::Principal>>,
    Query(params): Query<RuleSuggestionListParams>,
) -> Response {
    record_request(SUGGESTIONS_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    if let Err(error) =
        authorized_suggestions_state(&state, &principal, ADMIN_SUGGESTIONS_READ_PERMISSION)
    {
        return suggestions_admin_authz_error_response(error);
    }

    let Some(suggestion_engine) = state.suggestion_engine.as_ref() else {
        return suggestions_discovery_not_configured();
    };
    let filters = match params.into_filters() {
        Ok(filters) => filters,
        Err(parameter) => return bad_request(&format!("invalid query parameter: {parameter}")),
    };

    match suggestion_engine.list_suggestion_page(&filters) {
        Ok(page) => (StatusCode::OK, Json(page)).into_response(),
        Err(discovery::suggestions::RuleSuggestionError::InvalidCursor { parameter }) => {
            bad_request(&format!("invalid query parameter: {parameter}"))
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to query rule suggestions");
            internal_server_error("suggestions query failed")
        }
    }
}

async fn rule_suggestions_generate_endpoint(
    State(state): State<SuggestionsAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(SUGGESTIONS_GENERATE_ADMIN_ROUTE);

    let (parts, _body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let rbac_state = match authorized_suggestions_state(
        &state,
        &principal,
        ADMIN_SUGGESTIONS_WRITE_PERMISSION,
    ) {
        Ok(rbac_state) => rbac_state,
        Err(error) => return suggestions_admin_authz_error_response(error),
    };

    let Some(suggestion_engine) = state.suggestion_engine.as_ref() else {
        return suggestions_discovery_not_configured();
    };
    let policy = rbac_state.current_policy();

    match suggestion_engine.generate(&policy) {
        Ok(run) => (StatusCode::OK, Json(run)).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "failed to generate rule suggestions");
            internal_server_error("suggestion generation failed")
        }
    }
}

async fn rule_suggestion_accept_endpoint(
    State(state): State<SuggestionsAdminState>,
    Path(id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(SUGGESTION_ACCEPT_ADMIN_ROUTE);

    let (parts, _body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    if let Err(error) =
        authorized_suggestions_state(&state, &principal, ADMIN_SUGGESTIONS_WRITE_PERMISSION)
    {
        return suggestions_admin_authz_error_response(error);
    }
    let rbac_state =
        match authorized_policy_state(&state.policy, &principal, ADMIN_POLICY_WRITE_PERMISSION) {
            Ok(rbac_state) => rbac_state,
            Err(error) => return policy_admin_authz_error_response(error),
        };
    let Some(policy_file) = state.policy.policy_file.as_deref() else {
        return policy_not_configured();
    };

    let id = id.trim();
    if id.is_empty() {
        return bad_request("invalid suggestion id");
    }
    let Some(suggestion_engine) = state.suggestion_engine.as_ref() else {
        return suggestions_discovery_not_configured();
    };
    let suggestion = match suggestion_engine.get_suggestion(id) {
        Ok(Some(suggestion)) => suggestion,
        Ok(None) => return not_found("suggestion was not found"),
        Err(err) => {
            tracing::error!(error = %err, "failed to load rule suggestion");
            return internal_server_error("suggestion query failed");
        }
    };
    if suggestion.state != discovery::suggestions::RuleSuggestionLifecycleState::Open {
        return conflict("suggestion is not open");
    }

    let created = match create_policy_rule(
        &state.policy,
        &parts,
        &principal,
        rbac_state,
        policy_file,
        suggestion.proposed_rule.clone(),
    ) {
        Ok(result) => result,
        Err(response) => return *response,
    };

    let suggestion = match suggestion_engine.transition_suggestion(
        id,
        discovery::suggestions::RuleSuggestionLifecycleState::Accepted,
        Some(&principal.user_id),
    ) {
        Ok(Some(suggestion)) => suggestion,
        Ok(None) => return not_found("suggestion was not found"),
        Err(err) => {
            tracing::error!(error = %err, "failed to accept rule suggestion");
            return internal_server_error("suggestion transition failed");
        }
    };
    emit_suggestion_lifecycle_changed(&state, &parts, &principal, &suggestion);

    let response = (
        StatusCode::CREATED,
        [(header::ETAG, etag_header_value(&created.new_etag))],
        Json(RuleSuggestionAcceptResponse {
            suggestion,
            rule: created.rule,
        }),
    )
        .into_response();
    with_policy_history_append_warning(response, created.history_append_failed)
}

async fn rule_suggestion_dismiss_endpoint(
    State(state): State<SuggestionsAdminState>,
    Path(id): Path<String>,
    request: AxumRequest,
) -> Response {
    rule_suggestion_transition_endpoint(
        state,
        request,
        id,
        discovery::suggestions::RuleSuggestionLifecycleState::Dismissed,
        SUGGESTION_DISMISS_ADMIN_ROUTE,
    )
    .await
}

async fn rule_suggestion_transition_endpoint(
    state: SuggestionsAdminState,
    request: AxumRequest,
    id: String,
    lifecycle_state: discovery::suggestions::RuleSuggestionLifecycleState,
    route: &'static str,
) -> Response {
    record_request(route);

    let (parts, _body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    if let Err(error) =
        authorized_suggestions_state(&state, &principal, ADMIN_SUGGESTIONS_WRITE_PERMISSION)
    {
        return suggestions_admin_authz_error_response(error);
    }

    let id = id.trim();
    if id.is_empty() {
        return bad_request("invalid suggestion id");
    }

    let Some(suggestion_engine) = state.suggestion_engine.as_ref() else {
        return suggestions_discovery_not_configured();
    };
    match suggestion_engine.get_suggestion(id) {
        Ok(Some(suggestion)) => {
            if suggestion.state != discovery::suggestions::RuleSuggestionLifecycleState::Open {
                return conflict("suggestion is not open");
            }
        }
        Ok(None) => return not_found("suggestion was not found"),
        Err(err) => {
            tracing::error!(error = %err, "failed to load rule suggestion");
            return internal_server_error("suggestion query failed");
        }
    }
    let suggestion = match suggestion_engine.transition_suggestion(
        id,
        lifecycle_state,
        Some(&principal.user_id),
    ) {
        Ok(Some(suggestion)) => suggestion,
        Ok(None) => return not_found("suggestion was not found"),
        Err(err) => {
            tracing::error!(error = %err, "failed to transition rule suggestion");
            return internal_server_error("suggestion transition failed");
        }
    };
    emit_suggestion_lifecycle_changed(&state, &parts, &principal, &suggestion);

    (StatusCode::OK, Json(suggestion)).into_response()
}

async fn principal_list_endpoint(
    State(state): State<PrincipalAdminState>,
    principal: Option<Extension<auth::Principal>>,
    Query(params): Query<PrincipalListParams>,
) -> Response {
    record_request(PRINCIPALS_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    if let Err(error) =
        authorized_principal_state(&state, &principal, ADMIN_PRINCIPALS_READ_PERMISSION)
    {
        return principal_admin_authz_error_response(error);
    }

    if !state.directory.is_enabled() {
        return principal_directory_not_configured();
    }
    let query = match params.into_query() {
        Ok(query) => query,
        Err(parameter) => return bad_request(&format!("invalid query parameter: {parameter}")),
    };

    let directory = state.directory.clone();
    let filters = query.filters.clone();
    let page = match tokio::task::spawn_blocking(move || directory.list(&filters)).await {
        Ok(Ok(page)) => page,
        Ok(Err(auth::principal_directory::PrincipalDirectoryQueryError::InvalidCursor {
            parameter,
        })) => return bad_request(&format!("invalid query parameter: {parameter}")),
        Ok(Err(err)) => {
            tracing::error!(error = %err, "failed to query principal directory");
            return internal_server_error("principal directory query failed");
        }
        Err(err) => {
            tracing::error!(error = %err, "principal directory query task failed");
            return internal_server_error("principal directory query failed");
        }
    };
    let anonymous_request_count = match state.audit_query_store.as_ref() {
        Some(audit_query_store) => match audit_query_store.anonymous_request_count(
            query.filters.last_seen_after.as_deref(),
            query.filters.last_seen_before.as_deref(),
        ) {
            Ok(count) => count,
            Err(err) => {
                tracing::error!(error = %err, "failed to query anonymous request count");
                return internal_server_error("anonymous request count query failed");
            }
        },
        None => 0,
    };

    (
        StatusCode::OK,
        Json(PrincipalListResponse {
            principals: page.principals,
            next_cursor: page.next_cursor,
            anonymous_request_count,
        }),
    )
        .into_response()
}

async fn principal_detail_endpoint(
    State(state): State<PrincipalAdminState>,
    principal: Option<Extension<auth::Principal>>,
    Query(params): Query<PrincipalDetailParams>,
) -> Response {
    record_request(PRINCIPAL_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    if let Err(error) =
        authorized_principal_state(&state, &principal, ADMIN_PRINCIPALS_READ_PERMISSION)
    {
        return principal_admin_authz_error_response(error);
    }

    if !state.directory.is_enabled() {
        return principal_directory_not_configured();
    }
    let query = match params.into_query() {
        Ok(query) => query,
        Err(parameter) => return bad_request(&format!("invalid query parameter: {parameter}")),
    };

    let directory = state.directory.clone();
    let key = query.key.clone();
    let principal_record = match tokio::task::spawn_blocking(move || directory.get(&key)).await {
        Ok(Ok(Some(principal))) => principal,
        Ok(Ok(None)) => return not_found("principal was not found"),
        Ok(Err(err)) => {
            tracing::error!(error = %err, "failed to query principal detail");
            return internal_server_error("principal detail query failed");
        }
        Err(err) => {
            tracing::error!(error = %err, "principal detail query task failed");
            return internal_server_error("principal detail query failed");
        }
    };
    let (endpoints_touched, rules_hit) = match state.audit_query_store.as_ref() {
        Some(audit_query_store) => {
            match principal_audit_summary(audit_query_store, principal_record.subject.as_str()) {
                Ok(summary) => summary,
                Err(err) => {
                    tracing::error!(error = %err, "failed to query principal audit summary");
                    return internal_server_error("principal audit summary query failed");
                }
            }
        }
        None => (Vec::new(), Vec::new()),
    };
    let anomaly_history = match state.discovery_store.as_ref() {
        Some(discovery_store) => match discovery_store.list_principal_endpoint_signals(
            principal_record.subject.as_str(),
            DEFAULT_PRINCIPAL_ANOMALY_HISTORY_LIMIT,
        ) {
            Ok(signals) => signals,
            Err(err) => {
                tracing::error!(error = %err, "failed to query principal anomaly history");
                return internal_server_error("principal anomaly history query failed");
            }
        },
        None => Vec::new(),
    };

    (
        StatusCode::OK,
        Json(PrincipalDetailResponse {
            principal: principal_record,
            endpoints_touched,
            rules_hit,
            anomaly_history,
            tools_called: Vec::new(),
        }),
    )
        .into_response()
}

async fn traffic_endpoint_list_endpoint(
    State(state): State<TrafficAdminState>,
    principal: Option<Extension<auth::Principal>>,
    Query(params): Query<TrafficEndpointListParams>,
) -> Response {
    record_request(TRAFFIC_ENDPOINTS_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    let rbac_state =
        match authorized_traffic_state(&state, &principal, ADMIN_TRAFFIC_READ_PERMISSION) {
            Ok(rbac_state) => rbac_state,
            Err(error) => return traffic_admin_authz_error_response(error),
        };
    let include_open_signals =
        rbac_state.principal_has_permission(&principal, ADMIN_SIGNALS_READ_PERMISSION);

    let Some(discovery_store) = state.discovery_store.as_ref() else {
        return discovery_not_configured();
    };
    let query = match params.into_query() {
        Ok(query) => query,
        Err(parameter) => return bad_request(&format!("invalid query parameter: {parameter}")),
    };

    match list_traffic_endpoint_page(
        discovery_store,
        &query,
        Some(rbac_state),
        include_open_signals,
    ) {
        Ok(page) => (StatusCode::OK, Json(page)).into_response(),
        Err(discovery::query::DiscoveryQueryError::InvalidCursor { parameter }) => {
            bad_request(&format!("invalid query parameter: {parameter}"))
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to query traffic endpoint inventory");
            internal_server_error("traffic endpoint inventory query failed")
        }
    }
}

async fn traffic_endpoint_detail_endpoint(
    State(state): State<TrafficAdminState>,
    principal: Option<Extension<auth::Principal>>,
    Query(params): Query<TrafficEndpointDetailParams>,
) -> Response {
    record_request(TRAFFIC_ENDPOINT_DETAIL_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    let rbac_state =
        match authorized_traffic_state(&state, &principal, ADMIN_TRAFFIC_READ_PERMISSION) {
            Ok(rbac_state) => rbac_state,
            Err(error) => return traffic_admin_authz_error_response(error),
        };
    let include_open_signals =
        rbac_state.principal_has_permission(&principal, ADMIN_SIGNALS_READ_PERMISSION);

    let Some(discovery_store) = state.discovery_store.as_ref() else {
        return discovery_not_configured();
    };
    let params = match params.into_query() {
        Ok(params) => params,
        Err(parameter) => return bad_request(&format!("invalid query parameter: {parameter}")),
    };

    let mut endpoint = match discovery_store.get_endpoint_with_open_signal_summaries(
        &params.method,
        &params.endpoint_template,
        params.new_since_hours,
        include_open_signals,
    ) {
        Ok(Some(endpoint)) => endpoint,
        Ok(None) => return not_found("traffic endpoint was not found"),
        Err(err) => {
            tracing::error!(error = %err, "failed to query traffic endpoint detail");
            return internal_server_error("traffic endpoint detail query failed");
        }
    };
    endpoint.covered_by_rule = endpoint_covered_by_active_direct_rule(
        Some(rbac_state),
        &params.method,
        &params.endpoint_template,
    );
    let principals = match discovery_store.list_principals(
        &params.method,
        &params.endpoint_template,
        &discovery::query::PrincipalPageFilters {
            limit: params.principal_limit,
            cursor: params.principal_cursor.clone(),
        },
    ) {
        Ok(page) => page,
        Err(discovery::query::DiscoveryQueryError::InvalidCursor { parameter }) => {
            return bad_request(&format!("invalid query parameter: {parameter}"));
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to query traffic endpoint principals");
            return internal_server_error("traffic endpoint principal query failed");
        }
    };

    let audit = match state.audit_query_store.as_ref() {
        Some(audit_query_store) => {
            let filters = audit::query::EndpointAuditFilters {
                method: params.method.clone(),
                endpoint_template: params.endpoint_template.clone(),
                from: params
                    .from
                    .clone()
                    .or_else(|| Some(endpoint.first_seen.clone())),
                to: params
                    .to
                    .clone()
                    .or_else(|| Some(endpoint.last_seen.clone())),
                bucket: params.bucket,
                recent_limit: params.events_limit,
                recent_before_id: params.events_before_id,
            };
            match audit_query_store.query_endpoint_activity(&filters) {
                Ok(activity) => TrafficEndpointAuditEnrichment {
                    available: true,
                    match_strategy: audit::query::ENDPOINT_AUDIT_MATCH_STRATEGY,
                    match_limitations: audit::query::ENDPOINT_AUDIT_MATCH_LIMITATIONS,
                    omitted_reason: None,
                    time_series_truncated: Some(activity.time_series_truncated),
                    time_series: Some(activity.time_series),
                    recent_events: Some(activity.recent_events),
                    recent_events_next_cursor: activity.recent_events_next_cursor,
                    recent_events_scan_truncated: Some(activity.recent_events_scan_truncated),
                },
                Err(err) => {
                    tracing::error!(error = %err, "failed to query traffic endpoint audit enrichment");
                    return internal_server_error("traffic endpoint audit enrichment query failed");
                }
            }
        }
        None => TrafficEndpointAuditEnrichment {
            available: false,
            match_strategy: audit::query::ENDPOINT_AUDIT_MATCH_STRATEGY,
            match_limitations: audit::query::ENDPOINT_AUDIT_MATCH_LIMITATIONS,
            omitted_reason: Some("AUDIT_SQLITE_PATH not configured"),
            time_series_truncated: None,
            time_series: None,
            recent_events: None,
            recent_events_next_cursor: None,
            recent_events_scan_truncated: None,
        },
    };

    (
        StatusCode::OK,
        Json(TrafficEndpointDetailResponse {
            endpoint,
            principals,
            audit,
        }),
    )
        .into_response()
}

async fn traffic_endpoint_review_endpoint(
    State(state): State<TrafficAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(TRAFFIC_ENDPOINT_REVIEW_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    if let Err(error) = authorized_traffic_state(&state, &principal, ADMIN_TRAFFIC_WRITE_PERMISSION)
    {
        return traffic_admin_authz_error_response(error);
    }

    let Some(discovery_store) = state.discovery_store.as_ref() else {
        return discovery_not_configured();
    };
    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request = match serde_json::from_slice::<TrafficEndpointReviewRequest>(&body) {
        Ok(request) => request,
        Err(err) => {
            tracing::warn!(error = %err, "traffic endpoint review request body was invalid");
            return bad_request("invalid traffic endpoint review request body");
        }
    };
    let method = request.method.trim();
    if method.is_empty() {
        return bad_request("invalid traffic endpoint review request body: method");
    }
    let endpoint_template = request.endpoint_template.trim();
    if endpoint_template.is_empty() {
        return bad_request("invalid traffic endpoint review request body: endpoint_template");
    }

    let review = match discovery_store.set_endpoint_review(
        method,
        endpoint_template,
        request.reviewed,
        Some(&principal.user_id),
    ) {
        Ok(Some(review)) => review,
        Ok(None) => return not_found("traffic endpoint was not found"),
        Err(err) => {
            tracing::error!(error = %err, "failed to update traffic endpoint review state");
            return internal_server_error("traffic endpoint review update failed");
        }
    };
    emit_traffic_endpoint_review_changed(
        &state,
        &parts,
        &principal,
        method,
        endpoint_template,
        &review,
    );

    (StatusCode::OK, Json(review)).into_response()
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

    if let Err(error) = authorized_audit_state(&state, &principal, ADMIN_AUDIT_STREAM_PERMISSION) {
        return audit_admin_authz_error_response(error);
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
            method: None,
            path: self.path,
            status,
            matched_rule_id: None,
            limit,
            before_id,
        })
    }
}

impl SignalListParams {
    fn into_filters(self) -> Result<discovery::signals::SignalListFilters, &'static str> {
        let state = self
            .state
            .as_deref()
            .map(discovery::signals::SignalLifecycleState::parse)
            .transpose()?;
        let limit = parse_limit(self.limit)?;

        Ok(discovery::signals::SignalListFilters {
            state,
            signal_type: empty_string_as_none(self.signal_type),
            target_kind: empty_string_as_none(self.target_kind),
            target_key: empty_string_as_none(self.target_key),
            limit,
            cursor: self.cursor,
        })
    }
}

impl RuleSuggestionListParams {
    fn into_filters(
        self,
    ) -> Result<discovery::suggestions::RuleSuggestionListFilters, &'static str> {
        let state = self
            .state
            .as_deref()
            .map(discovery::suggestions::RuleSuggestionLifecycleState::parse)
            .transpose()?;
        let limit = parse_limit(self.limit)?;

        Ok(discovery::suggestions::RuleSuggestionListFilters {
            state,
            suggestion_type: empty_string_as_none(self.suggestion_type),
            limit,
            cursor: self.cursor,
        })
    }
}

impl PolicyHistoryParams {
    fn into_filters(self) -> Result<rbac::PolicyHistoryListFilters, &'static str> {
        let limit = parse_limit(self.limit)?;
        let include_policy =
            parse_optional_bool("include_policy", self.include_policy)?.unwrap_or(false);

        Ok(rbac::PolicyHistoryListFilters {
            limit,
            cursor: self.cursor,
            include_policy,
        })
    }
}

impl TokenListParams {
    fn into_filters(self) -> Result<auth::tokens::TokenListFilters, &'static str> {
        Ok(auth::tokens::TokenListFilters {
            limit: parse_limit(self.limit)?,
            cursor: self.cursor,
        })
    }
}

impl CreatedTokenAdminResponse {
    fn from_created(created: auth::tokens::CreatedToken) -> Self {
        Self {
            plaintext_token: created.plaintext_token,
            plaintext_token_notice: "Save this token now; the plaintext will not be shown again.",
            token: created.record,
        }
    }
}

struct TrafficEndpointDetailQuery {
    method: String,
    endpoint_template: String,
    new_since_hours: u64,
    principal_limit: usize,
    principal_cursor: Option<String>,
    from: Option<String>,
    to: Option<String>,
    bucket: audit::query::EndpointAuditBucket,
    events_limit: usize,
    events_before_id: Option<i64>,
}

struct TrafficEndpointListQuery {
    filters: discovery::query::EndpointListFilters,
    covered_by_rule: Option<bool>,
}

struct PrincipalListQuery {
    filters: auth::principal_directory::PrincipalDirectoryListFilters,
}

struct PrincipalDetailQuery {
    key: auth::principal_directory::PrincipalDirectoryKey,
}

impl TrafficEndpointListParams {
    fn into_query(self) -> Result<TrafficEndpointListQuery, &'static str> {
        let first_seen_after = validate_rfc3339("first_seen_after", self.first_seen_after)?;
        let first_seen_before = validate_rfc3339("first_seen_before", self.first_seen_before)?;
        let last_seen_after = validate_rfc3339("last_seen_after", self.last_seen_after)?;
        let last_seen_before = validate_rfc3339("last_seen_before", self.last_seen_before)?;
        let min_call_count =
            parse_optional_non_negative_i64("min_call_count", self.min_call_count)?;
        let new_since_hours = parse_new_since_hours(self.new_since_hours)?;
        let is_new = parse_optional_bool("is_new", self.is_new)?;
        let reviewed = parse_optional_bool("reviewed", self.reviewed)?;
        let covered_by_rule = parse_optional_bool("covered_by_rule", self.covered_by_rule)?;
        let sort = self
            .sort
            .as_deref()
            .map(discovery::query::EndpointSort::parse)
            .transpose()?
            .unwrap_or(discovery::query::EndpointSort::LastSeen);
        let limit = parse_limit(self.limit)?;

        Ok(TrafficEndpointListQuery {
            filters: discovery::query::EndpointListFilters {
                method: empty_string_as_none(self.method),
                endpoint_template_contains: empty_string_as_none(self.endpoint_template),
                endpoint_template_prefix: empty_string_as_none(self.endpoint_template_prefix),
                first_seen_after,
                first_seen_before,
                last_seen_after,
                last_seen_before,
                min_call_count,
                new_since_hours,
                is_new,
                reviewed,
                sort,
                limit,
                cursor: self.cursor,
            },
            covered_by_rule,
        })
    }
}

impl PrincipalListParams {
    fn into_query(self) -> Result<PrincipalListQuery, &'static str> {
        let last_seen_after = validate_rfc3339("last_seen_after", self.last_seen_after)?;
        let last_seen_before = validate_rfc3339("last_seen_before", self.last_seen_before)?;
        let principal_type = parse_principal_type(self.principal_type)?;
        let limit = parse_limit(self.limit)?;

        Ok(PrincipalListQuery {
            filters: auth::principal_directory::PrincipalDirectoryListFilters {
                issuer: self.issuer,
                auth_method: empty_string_as_none(self.auth_method),
                principal_type,
                last_seen_after,
                last_seen_before,
                limit,
                cursor: self.cursor,
            },
        })
    }
}

impl TrafficEndpointDetailParams {
    fn into_query(self) -> Result<TrafficEndpointDetailQuery, &'static str> {
        let method = required_non_empty("method", self.method)?;
        let endpoint_template = required_non_empty("endpoint_template", self.endpoint_template)?;
        let principal_limit =
            parse_limit_with_default(self.principal_limit, DEFAULT_AUDIT_QUERY_LIMIT)?;
        let from = validate_rfc3339("from", self.from)?;
        let to = validate_rfc3339("to", self.to)?;
        let new_since_hours = parse_new_since_hours(self.new_since_hours)?;
        let bucket = parse_endpoint_audit_bucket(self.bucket)?;
        let events_limit =
            parse_limit_with_default(self.events_limit, DEFAULT_TRAFFIC_RECENT_EVENTS_LIMIT)?;
        let events_before_id = parse_before_id(self.events_before_id)?;

        Ok(TrafficEndpointDetailQuery {
            method,
            endpoint_template,
            new_since_hours,
            principal_limit,
            principal_cursor: self.principal_cursor,
            from,
            to,
            bucket,
            events_limit,
            events_before_id,
        })
    }
}

impl PrincipalDetailParams {
    fn into_query(self) -> Result<PrincipalDetailQuery, &'static str> {
        let subject = required_non_empty("subject", self.subject)?;
        let issuer = self.issuer.ok_or("issuer")?;
        let auth_method = required_non_empty("auth_method", self.auth_method)?;

        Ok(PrincipalDetailQuery {
            key: auth::principal_directory::PrincipalDirectoryKey {
                subject,
                issuer,
                auth_method,
            },
        })
    }
}

impl InferredSchemaParams {
    fn into_query(self) -> Result<InferredSchemaQuery, &'static str> {
        Ok(InferredSchemaQuery {
            method: required_non_empty("method", self.method)?,
            endpoint_template: required_non_empty("endpoint_template", self.endpoint_template)?,
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

fn parse_optional_non_negative_i64(
    parameter: &'static str,
    value: Option<String>,
) -> Result<Option<i64>, &'static str> {
    let Some(value) = parse_optional_i64(parameter, value)? else {
        return Ok(None);
    };
    if value < 0 {
        return Err(parameter);
    }

    Ok(Some(value))
}

fn parse_optional_non_negative_u64(
    parameter: &'static str,
    value: Option<String>,
) -> Result<Option<u64>, &'static str> {
    value
        .map(|value| {
            let parsed = value.parse::<u64>().map_err(|_| parameter)?;
            Ok(parsed)
        })
        .transpose()
}

fn parse_new_since_hours(value: Option<String>) -> Result<u64, &'static str> {
    let hours = parse_optional_non_negative_u64("new_since_hours", value)?
        .unwrap_or(discovery::query::DEFAULT_NEW_SINCE_HOURS);
    if hours > discovery::query::MAX_NEW_SINCE_HOURS {
        return Err("new_since_hours");
    }
    Ok(hours)
}

fn parse_optional_bool(
    parameter: &'static str,
    value: Option<String>,
) -> Result<Option<bool>, &'static str> {
    value
        .map(|value| match value.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(parameter),
        })
        .transpose()
}

fn parse_principal_type(
    value: Option<String>,
) -> Result<Option<auth::principal_directory::PrincipalTypeFilter>, &'static str> {
    value
        .map(|value| match value.as_str() {
            "human" => Ok(auth::principal_directory::PrincipalTypeFilter::Human),
            "service" => Ok(auth::principal_directory::PrincipalTypeFilter::Service),
            _ => Err("principal_type"),
        })
        .transpose()
}

fn parse_policy_history_version(value: &str) -> Result<i64, &'static str> {
    match value.parse::<i64>() {
        Ok(version) if version > 0 => Ok(version),
        _ => Err("version"),
    }
}

fn parse_limit(value: Option<String>) -> Result<usize, &'static str> {
    parse_limit_with_default(value, DEFAULT_AUDIT_QUERY_LIMIT)
}

fn parse_limit_with_default(
    value: Option<String>,
    default_limit: usize,
) -> Result<usize, &'static str> {
    let Some(value) = value else {
        return Ok(default_limit);
    };
    let limit = value.parse::<usize>().map_err(|_| "limit")?;
    if limit == 0 {
        return Err("limit");
    }

    Ok(limit.min(MAX_AUDIT_QUERY_LIMIT))
}

fn required_non_empty(
    parameter: &'static str,
    value: Option<String>,
) -> Result<String, &'static str> {
    let Some(value) = value else {
        return Err(parameter);
    };
    let value = value.trim();
    if value.is_empty() {
        return Err(parameter);
    }

    Ok(value.to_owned())
}

fn empty_string_as_none(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_owned())
        }
    })
}

fn parse_endpoint_audit_bucket(
    value: Option<String>,
) -> Result<audit::query::EndpointAuditBucket, &'static str> {
    match value.as_deref().unwrap_or("hour") {
        "hour" => Ok(audit::query::EndpointAuditBucket::Hour),
        "day" => Ok(audit::query::EndpointAuditBucket::Day),
        _ => Err("bucket"),
    }
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

fn authorized_policy_state<'a>(
    state: &'a PolicyAdminState,
    principal: &auth::Principal,
    permission: &str,
) -> Result<&'a middleware::rbac::RbacState, PolicyAdminAuthzError> {
    let Some(rbac_state) = state.rbac_state.as_ref() else {
        return Err(PolicyAdminAuthzError::NotConfigured);
    };

    if !rbac_state.principal_has_permission(principal, permission) {
        return Err(PolicyAdminAuthzError::Forbidden);
    }

    Ok(rbac_state)
}

fn authorized_audit_state<'a>(
    state: &'a AuditAdminState,
    principal: &auth::Principal,
    permission: &str,
) -> Result<&'a middleware::rbac::RbacState, AdminReadAuthzError> {
    authorized_admin_rbac_state(state.rbac_state.as_ref(), principal, permission)
}

fn authorized_status_state<'a>(
    state: &'a StatusAdminState,
    principal: &auth::Principal,
    permission: &str,
) -> Result<&'a middleware::rbac::RbacState, AdminReadAuthzError> {
    authorized_admin_rbac_state(state.rbac_state.as_ref(), principal, permission)
}

fn authorized_admin_rbac_state<'a>(
    rbac_state: Option<&'a middleware::rbac::RbacState>,
    principal: &auth::Principal,
    permission: &str,
) -> Result<&'a middleware::rbac::RbacState, AdminReadAuthzError> {
    let Some(rbac_state) = rbac_state else {
        return Err(AdminReadAuthzError::NotConfigured);
    };

    if !rbac_state.principal_has_permission(principal, permission) {
        return Err(AdminReadAuthzError::Forbidden);
    }

    Ok(rbac_state)
}

fn authorized_token_store<'a>(
    state: &'a TokenAdminState,
    principal: &auth::Principal,
    permission: &str,
) -> Result<&'a Arc<dyn auth::TokenStore>, TokenAdminAuthzError> {
    let Some(rbac_state) = state.rbac_state.as_ref() else {
        return Err(TokenAdminAuthzError::RbacNotConfigured);
    };

    if !rbac_state.principal_has_permission(principal, permission) {
        return Err(TokenAdminAuthzError::Forbidden);
    }

    state
        .store
        .as_ref()
        .ok_or(TokenAdminAuthzError::StoreNotConfigured)
}

fn authorized_tools_file<'a>(
    state: &'a ToolAdminState,
    principal: &auth::Principal,
    permission: &str,
) -> Result<&'a FsPath, ToolAdminAuthzError> {
    let Some(rbac_state) = state.rbac_state.as_ref() else {
        return Err(ToolAdminAuthzError::RbacNotConfigured);
    };

    if !rbac_state.principal_has_permission(principal, permission) {
        return Err(ToolAdminAuthzError::Forbidden);
    }

    state
        .tools_file
        .as_deref()
        .ok_or(ToolAdminAuthzError::ToolsFileNotConfigured)
}

fn authorized_schema_reader(state: &SchemaAdminState, principal: &auth::Principal) -> bool {
    state.rbac_state.as_ref().is_some_and(|rbac_state| {
        rbac_state.principal_has_permission(principal, ADMIN_SCHEMA_READ_PERMISSION)
    })
}

fn authorized_traffic_state<'a>(
    state: &'a TrafficAdminState,
    principal: &auth::Principal,
    permission: &str,
) -> Result<&'a middleware::rbac::RbacState, TrafficAdminAuthzError> {
    let Some(rbac_state) = state.rbac_state.as_ref() else {
        return Err(TrafficAdminAuthzError::NotConfigured);
    };

    if !rbac_state.principal_has_permission(principal, permission) {
        return Err(TrafficAdminAuthzError::Forbidden);
    }

    Ok(rbac_state)
}

fn authorized_principal_state<'a>(
    state: &'a PrincipalAdminState,
    principal: &auth::Principal,
    permission: &str,
) -> Result<&'a middleware::rbac::RbacState, PrincipalAdminAuthzError> {
    let Some(rbac_state) = state.rbac_state.as_ref() else {
        return Err(PrincipalAdminAuthzError::NotConfigured);
    };

    if !rbac_state.principal_has_permission(principal, permission) {
        return Err(PrincipalAdminAuthzError::Forbidden);
    }

    Ok(rbac_state)
}

fn authorized_signals_state<'a>(
    state: &'a SignalsAdminState,
    principal: &auth::Principal,
    permission: &str,
) -> Result<&'a middleware::rbac::RbacState, SignalsAdminAuthzError> {
    let Some(rbac_state) = state.rbac_state.as_ref() else {
        return Err(SignalsAdminAuthzError::NotConfigured);
    };

    if !rbac_state.principal_has_permission(principal, permission) {
        return Err(SignalsAdminAuthzError::Forbidden);
    }

    Ok(rbac_state)
}

fn authorized_suggestions_state<'a>(
    state: &'a SuggestionsAdminState,
    principal: &auth::Principal,
    permission: &str,
) -> Result<&'a middleware::rbac::RbacState, SuggestionsAdminAuthzError> {
    let Some(rbac_state) = state.policy.rbac_state.as_ref() else {
        return Err(SuggestionsAdminAuthzError::NotConfigured);
    };

    if !rbac_state.principal_has_permission(principal, permission) {
        return Err(SuggestionsAdminAuthzError::Forbidden);
    }

    Ok(rbac_state)
}

fn policy_admin_authz_error_response(error: PolicyAdminAuthzError) -> Response {
    match error {
        PolicyAdminAuthzError::NotConfigured => policy_not_configured(),
        PolicyAdminAuthzError::Forbidden => forbidden(),
    }
}

fn audit_admin_authz_error_response(error: AdminReadAuthzError) -> Response {
    match error {
        AdminReadAuthzError::NotConfigured => audit_rbac_not_configured(),
        AdminReadAuthzError::Forbidden => forbidden(),
    }
}

fn status_admin_authz_error_response(error: AdminReadAuthzError) -> Response {
    match error {
        AdminReadAuthzError::NotConfigured => status_rbac_not_configured(),
        AdminReadAuthzError::Forbidden => forbidden(),
    }
}

fn token_admin_authz_error_response(error: TokenAdminAuthzError) -> Response {
    match error {
        TokenAdminAuthzError::StoreNotConfigured => token_store_not_configured(),
        TokenAdminAuthzError::RbacNotConfigured => token_rbac_not_configured(),
        TokenAdminAuthzError::Forbidden => forbidden(),
    }
}

fn tool_admin_authz_error_response(error: ToolAdminAuthzError) -> Response {
    match error {
        ToolAdminAuthzError::RbacNotConfigured => tools_rbac_not_configured(),
        ToolAdminAuthzError::ToolsFileNotConfigured => tools_file_not_configured(),
        ToolAdminAuthzError::Forbidden => forbidden(),
    }
}

fn traffic_admin_authz_error_response(error: TrafficAdminAuthzError) -> Response {
    match error {
        TrafficAdminAuthzError::NotConfigured => traffic_rbac_not_configured(),
        TrafficAdminAuthzError::Forbidden => forbidden(),
    }
}

fn principal_admin_authz_error_response(error: PrincipalAdminAuthzError) -> Response {
    match error {
        PrincipalAdminAuthzError::NotConfigured => principal_rbac_not_configured(),
        PrincipalAdminAuthzError::Forbidden => forbidden(),
    }
}

fn signals_admin_authz_error_response(error: SignalsAdminAuthzError) -> Response {
    match error {
        SignalsAdminAuthzError::NotConfigured => signals_rbac_not_configured(),
        SignalsAdminAuthzError::Forbidden => forbidden(),
    }
}

fn suggestions_admin_authz_error_response(error: SuggestionsAdminAuthzError) -> Response {
    match error {
        SuggestionsAdminAuthzError::NotConfigured => suggestions_rbac_not_configured(),
        SuggestionsAdminAuthzError::Forbidden => forbidden(),
    }
}

async fn read_request_body(body: Body, max_body_size: usize) -> Result<Bytes, Response> {
    axum::body::to_bytes(body, max_body_size)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "policy request body could not be read");
            payload_too_large(max_body_size)
        })
}

fn split_authorized_policy_mutation_request(
    state: &PolicyAdminState,
    request: AxumRequest,
) -> ResponseResult<(
    http::request::Parts,
    Body,
    auth::Principal,
    &middleware::rbac::RbacState,
    &std::path::Path,
)> {
    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return Err(Box::new(unauthorized()));
    };
    let rbac_state = match authorized_policy_state(state, &principal, ADMIN_POLICY_WRITE_PERMISSION)
    {
        Ok(rbac_state) => rbac_state,
        Err(error) => return Err(Box::new(policy_admin_authz_error_response(error))),
    };
    let Some(policy_file) = state.policy_file.as_deref() else {
        return Err(Box::new(policy_not_configured()));
    };

    Ok((parts, body, principal, rbac_state, policy_file))
}

fn parse_create_token_body(body: &Bytes) -> ResponseResult<CreateTokenAdminRequest> {
    serde_json::from_slice::<CreateTokenAdminRequest>(body)
        .map_err(|err| Box::new(bad_request(&format!("invalid token create JSON: {err}"))))
}

fn parse_openapi_tools_register_body(body: &Bytes) -> ResponseResult<OpenApiToolsRegisterRequest> {
    serde_json::from_slice::<OpenApiToolsRegisterRequest>(body).map_err(|err| {
        Box::new(bad_request(&format!(
            "invalid OpenAPI tools register JSON: {err}"
        )))
    })
}

fn parse_policy_body(body: &Bytes) -> Result<rbac::Policy, Vec<String>> {
    let value = serde_json::from_slice::<Value>(body)
        .map_err(|err| vec![format!("invalid JSON: {err}")])?;

    rbac::Policy::validate_json_value(value).map_err(|err| vec![policy_error_message(&err)])
}

fn parse_rule_body(body: &Bytes) -> Result<rbac::Rule, Vec<String>> {
    serde_json::from_slice::<rbac::Rule>(body)
        .map_err(|err| vec![format!("invalid rule JSON: {err}")])
}

fn parse_rule_patch_body(body: &Bytes) -> Result<RulePatch, Vec<String>> {
    serde_json::from_slice::<RulePatch>(body)
        .map_err(|err| vec![format!("invalid rule patch JSON: {err}")])
}

fn parse_rule_order_body(body: &Bytes) -> Result<Vec<String>, Vec<String>> {
    serde_json::from_slice::<Vec<String>>(body)
        .map_err(|err| vec![format!("invalid rule order JSON: {err}")])
}

fn parse_rule_preview_body(body: &Bytes) -> Result<PolicyRulePreviewRequest, Vec<String>> {
    let request = serde_json::from_slice::<PolicyRulePreviewRequest>(body)
        .map_err(|err| vec![format!("invalid JSON: {err}")])?;
    validate_rule_preview_request(&request)?;
    Ok(request)
}

fn validate_rule_preview_request(request: &PolicyRulePreviewRequest) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    if let Err(parameter) = validate_rfc3339("from", request.from.clone()) {
        errors.push(format!("invalid {parameter}: expected RFC 3339 timestamp"));
    }
    if let Err(parameter) = validate_rfc3339("to", request.to.clone()) {
        errors.push(format!("invalid {parameter}: expected RFC 3339 timestamp"));
    }
    let has_path = !request.rule.path.is_empty();
    let has_tool_name = request.rule.tool_name.is_some();
    if has_path == has_tool_name {
        errors.push("rule must set exactly one of path or tool_name".to_owned());
    }
    if has_tool_name {
        errors.push("rule preview currently supports HTTP path rules only".to_owned());
    }
    if has_path && !request.rule.path.starts_with('/') {
        errors.push(format!(
            "rule.path must start with '/', got '{}'",
            request.rule.path
        ));
    }
    for auth_method in &request.rule.principal.auth_methods {
        if !rbac::rule::valid_auth_method_name(auth_method) {
            errors.push(format!(
                "rule.principal.auth_methods contains unknown auth method '{auth_method}', expected 'bearer_token' or 'session_cookie'"
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn preview_rule(
    query_store: &audit::query::AuditQueryStore,
    request: PolicyRulePreviewRequest,
) -> Result<PolicyRulePreviewResponse, audit::query::AuditQueryError> {
    let matcher = rbac::RuleMatcher::new(std::slice::from_ref(&request.rule));
    let sample_limit = request
        .sample_limit
        .unwrap_or(DEFAULT_RULE_PREVIEW_SAMPLE_LIMIT)
        .min(MAX_RULE_PREVIEW_SAMPLE_LIMIT);
    let mut match_count = 0_u64;
    let mut scanned_event_count = 0_u64;
    let mut samples = Vec::with_capacity(sample_limit);

    query_store.scan_request_observations(
        &audit::query::RequestObservationFilters {
            from: request.from,
            to: request.to,
            methods: request.rule.methods.clone(),
            path_exact: exact_preview_path_filter(&request.rule.path),
            path_prefix: prefix_preview_path_filter(&request.rule.path),
            before_id: None,
        },
        |observation| {
            scanned_event_count = scanned_event_count.saturating_add(1);
            let principal = observation
                .actor
                .as_ref()
                .and_then(principal_from_audit_actor);

            if matcher
                .evaluate(&observation.method, &observation.path, principal.as_ref())
                .is_some()
            {
                match_count = match_count.saturating_add(1);
                if samples.len() < sample_limit {
                    samples.push(preview_sample(observation));
                }
            }

            true
        },
    )?;

    Ok(PolicyRulePreviewResponse {
        match_count,
        scanned_event_count,
        sample_strategy: "newest_matches",
        samples,
    })
}

fn exact_preview_path_filter(pattern: &str) -> Option<String> {
    preview_path_filter(pattern).exact
}

fn prefix_preview_path_filter(pattern: &str) -> Option<String> {
    preview_path_filter(pattern).prefix
}

struct PreviewPathFilter {
    exact: Option<String>,
    prefix: Option<String>,
}

fn preview_path_filter(pattern: &str) -> PreviewPathFilter {
    let Some(tail) = pattern.strip_prefix('/') else {
        return PreviewPathFilter {
            exact: None,
            prefix: None,
        };
    };
    if tail.is_empty() {
        return PreviewPathFilter {
            exact: Some("/".to_owned()),
            prefix: None,
        };
    }

    let mut literal_segments = Vec::new();
    let mut first_dynamic_segment = None;
    for segment in tail.split('/') {
        if segment == "*" || segment == "**" || segment.contains('{') || segment.contains('}') {
            first_dynamic_segment = Some(segment);
            break;
        }
        literal_segments.push(segment);
    }

    let Some(first_dynamic_segment) = first_dynamic_segment else {
        return PreviewPathFilter {
            exact: Some(pattern.to_owned()),
            prefix: None,
        };
    };
    if literal_segments.is_empty() {
        return PreviewPathFilter {
            exact: None,
            prefix: None,
        };
    }

    let literal_prefix = format!("/{}", literal_segments.join("/"));
    let prefix = if first_dynamic_segment == "**" {
        literal_prefix
    } else {
        format!("{literal_prefix}/")
    };

    PreviewPathFilter {
        exact: None,
        prefix: Some(prefix),
    }
}

fn principal_from_audit_actor(actor: &audit::Actor) -> Option<auth::Principal> {
    let auth_method = match actor.auth_mode.as_str() {
        rbac::rule::AUTH_METHOD_BEARER_TOKEN => auth::AuthMethod::Bearer,
        rbac::rule::AUTH_METHOD_SESSION_COOKIE => auth::AuthMethod::Cookie,
        _ => return None,
    };

    Some(auth::Principal {
        user_id: actor.user_id.clone(),
        issuer: None,
        email: actor.email.clone(),
        org_id: None,
        roles: actor.roles.clone().unwrap_or_default(),
        session_id: "audit-history".to_owned(),
        auth_method,
    })
}

fn preview_sample(observation: audit::query::RequestObservation) -> PolicyRulePreviewSample {
    let policy_decision = serde_json::from_str::<Value>(&observation.payload_json)
        .ok()
        .and_then(|payload| {
            payload
                .get("policy_decision")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });

    PolicyRulePreviewSample {
        event_id: observation.event_id,
        timestamp: observation.timestamp,
        request_id: observation.request_id,
        source_ip: observation.source_ip,
        user_agent: observation.user_agent,
        method: observation.method,
        path: observation.path,
        actor: observation.actor,
        status: observation.status,
        policy_decision,
        matched_rule_id: observation.matched_rule_id,
    }
}

fn enrich_endpoint_summaries_with_rule_coverage(
    endpoints: &mut [discovery::query::EndpointSummary],
    rbac_state: Option<&middleware::rbac::RbacState>,
) {
    let Some(rbac_state) = rbac_state else {
        return;
    };
    let policy = rbac_state.current_policy();

    for endpoint in endpoints {
        endpoint.covered_by_rule = endpoint_covered_by_policy_direct_rules(
            &policy,
            &endpoint.method,
            &endpoint.endpoint_template,
        );
    }
}

fn list_traffic_endpoint_page(
    discovery_store: &discovery::query::DiscoveryQueryStore,
    query: &TrafficEndpointListQuery,
    rbac_state: Option<&middleware::rbac::RbacState>,
    include_open_signals: bool,
) -> Result<discovery::query::EndpointListPage, discovery::query::DiscoveryQueryError> {
    let Some(covered_by_rule) = query.covered_by_rule else {
        let mut page = discovery_store
            .list_endpoints_with_open_signal_summaries(&query.filters, include_open_signals)?;
        enrich_endpoint_summaries_with_rule_coverage(&mut page.endpoints, rbac_state);
        return Ok(page);
    };

    let requested_limit = query.filters.limit;
    let mut scan_filters = query.filters.clone();
    scan_filters.limit = 1;
    let mut cursor = scan_filters.cursor.clone();
    let mut endpoints = Vec::with_capacity(requested_limit);
    let mut next_cursor = None;

    loop {
        scan_filters.cursor = cursor;
        let mut page = discovery_store
            .list_endpoints_with_open_signal_summaries(&scan_filters, include_open_signals)?;
        enrich_endpoint_summaries_with_rule_coverage(&mut page.endpoints, rbac_state);

        if let Some(endpoint) = page.endpoints.into_iter().next() {
            if endpoint.covered_by_rule == covered_by_rule {
                endpoints.push(endpoint);
                if endpoints.len() == requested_limit {
                    next_cursor = page.next_cursor;
                    break;
                }
            }
        }

        let Some(cursor_after_page) = page.next_cursor else {
            break;
        };
        cursor = Some(cursor_after_page);
    }

    Ok(discovery::query::EndpointListPage {
        endpoints,
        next_cursor,
    })
}

fn principal_audit_summary(
    audit_query_store: &audit::query::AuditQueryStore,
    subject: &str,
) -> Result<(Vec<PrincipalEndpointTouch>, Vec<String>), audit::query::AuditQueryError> {
    // Audit events currently store only actor_user_id, not issuer/auth_method,
    // so this convenience view can include same-subject events from another
    // principal-directory identity key.
    let page = audit_query_store.query(&audit::query::AuditQueryFilters {
        from: None,
        to: None,
        event_type: Some("http.request_observed".to_owned()),
        actor: Some(subject.to_owned()),
        method: None,
        path: None,
        status: None,
        matched_rule_id: None,
        limit: DEFAULT_PRINCIPAL_DETAIL_AUDIT_EVENT_LIMIT,
        before_id: None,
    })?;
    let mut endpoints = BTreeMap::<(String, String), (u64, String)>::new();
    let mut rules = BTreeSet::<String>::new();

    for event in page.events {
        let method = event
            .payload
            .get("method")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let path = event
            .payload
            .get("path")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let (Some(method), Some(path)) = (method, path) {
            let entry = endpoints
                .entry((method, path))
                .or_insert_with(|| (0, event.timestamp.clone()));
            entry.0 = entry.0.saturating_add(1);
            if rfc3339_after(&event.timestamp, &entry.1) {
                entry.1 = event.timestamp.clone();
            }
        }

        if let Some(rule_id) = event
            .payload
            .get("matched_rule_id")
            .and_then(Value::as_str)
            .filter(|rule_id| !rule_id.is_empty())
        {
            rules.insert(rule_id.to_owned());
        }
    }

    let mut endpoints = endpoints
        .into_iter()
        .map(
            |((method, path), (request_count, last_seen))| PrincipalEndpointTouch {
                method,
                path,
                request_count,
                last_seen,
            },
        )
        .collect::<Vec<_>>();
    endpoints.sort_by(|left, right| {
        right
            .last_seen
            .cmp(&left.last_seen)
            .then_with(|| left.method.cmp(&right.method))
            .then_with(|| left.path.cmp(&right.path))
    });

    Ok((endpoints, rules.into_iter().collect()))
}

fn rfc3339_after(left: &str, right: &str) -> bool {
    match (
        OffsetDateTime::parse(left, &Rfc3339),
        OffsetDateTime::parse(right, &Rfc3339),
    ) {
        (Ok(left), Ok(right)) => left > right,
        _ => left > right,
    }
}

fn endpoint_covered_by_active_direct_rule(
    rbac_state: Option<&middleware::rbac::RbacState>,
    method: &str,
    endpoint_template: &str,
) -> bool {
    let Some(rbac_state) = rbac_state else {
        return false;
    };
    let policy = rbac_state.current_policy();

    endpoint_covered_by_policy_direct_rules(&policy, method, endpoint_template)
}

fn endpoint_covered_by_policy_direct_rules(
    policy: &rbac::Policy,
    method: &str,
    endpoint_template: &str,
) -> bool {
    if policy.rules.is_empty() {
        return false;
    }

    let path = representative_path_from_endpoint_template(endpoint_template);
    let matcher = rbac::RuleMatcher::new(&policy.rules);
    if matcher.evaluate(method, &path, None).is_some() {
        return true;
    }

    policy.rules.iter().any(|rule| {
        let Some(principal) = representative_principal_for_rule(rule) else {
            return false;
        };
        matcher.evaluate(method, &path, Some(&principal)).is_some()
    })
}

fn representative_path_from_endpoint_template(endpoint_template: &str) -> String {
    let Some(tail) = endpoint_template.strip_prefix('/') else {
        return endpoint_template.to_owned();
    };
    if tail.is_empty() {
        return "/".to_owned();
    }

    let segments = tail
        .split('/')
        .map(representative_path_segment)
        .collect::<Vec<_>>();
    format!("/{}", segments.join("/"))
}

fn representative_path_segment(segment: &str) -> String {
    let Some(capture) = segment
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
    else {
        return segment.to_owned();
    };

    if capture.eq_ignore_ascii_case("id") {
        "123".to_owned()
    } else {
        "sample".to_owned()
    }
}

fn representative_principal_for_rule(rule: &rbac::Rule) -> Option<auth::Principal> {
    if rule.principal.is_unconstrained() {
        return None;
    }

    let auth_method = if rule
        .principal
        .auth_methods
        .iter()
        .any(|method| method == rbac::rule::AUTH_METHOD_SESSION_COOKIE)
    {
        auth::AuthMethod::Cookie
    } else {
        auth::AuthMethod::Bearer
    };

    Some(auth::Principal {
        user_id: rule
            .principal
            .principal_ids
            .first()
            .cloned()
            .unwrap_or_else(|| "traffic-coverage-principal".to_owned()),
        issuer: None,
        email: None,
        org_id: None,
        roles: rule.principal.roles.clone(),
        session_id: "traffic-coverage".to_owned(),
        auth_method,
    })
}

fn policy_error_message(error: &rbac::policy::PolicyError) -> String {
    match error {
        rbac::policy::PolicyError::Invalid(message) => message.clone(),
        _ => error.to_string(),
    }
}

fn openapi_tools_preview_response(
    generation: tools::openapi::OpenApiToolGeneration,
) -> OpenApiToolsPreviewResponse {
    OpenApiToolsPreviewResponse {
        tools: generation.definitions,
        operation_id_fallbacks: generation
            .operation_id_fallbacks
            .into_iter()
            .map(openapi_tool_name_fallback_response)
            .collect(),
        skipped_operations: generation
            .skipped_operations
            .into_iter()
            .map(openapi_skipped_operation_response)
            .collect(),
        api_key_header_auth_requirements: generation
            .api_key_header_auth_requirements
            .into_iter()
            .map(|requirement| OpenApiApiKeyHeaderAuthRequirementResponse {
                tool_name: requirement.tool_name,
                method: requirement.method,
                path_template: requirement.path_template,
                scheme_name: requirement.scheme_name,
                header_name: requirement.header_name,
            })
            .collect(),
    }
}

fn openapi_tool_name_fallback_response(
    fallback: tools::openapi::OpenApiToolNameFallback,
) -> OpenApiToolNameFallbackResponse {
    OpenApiToolNameFallbackResponse {
        method: fallback.method,
        path_template: fallback.path_template,
        original_operation_id: fallback.original_operation_id,
        generated_name: fallback.generated_name,
        reason: match fallback.reason {
            tools::openapi::OpenApiToolNameFallbackReason::MissingOperationId => {
                "missing_operation_id"
            }
            tools::openapi::OpenApiToolNameFallbackReason::InvalidOperationId => {
                "invalid_operation_id"
            }
            tools::openapi::OpenApiToolNameFallbackReason::DuplicateToolName => {
                "duplicate_tool_name"
            }
        },
    }
}

fn openapi_skipped_operation_response(
    skipped: tools::openapi::OpenApiSkippedOperation,
) -> OpenApiSkippedOperationResponse {
    match skipped.reason {
        tools::openapi::OpenApiSkippedOperationReason::BodyPropertyParameterNameCollision {
            property_name,
        } => OpenApiSkippedOperationResponse {
            method: skipped.method,
            path_template: skipped.path_template,
            original_operation_id: skipped.original_operation_id,
            reason: "body_property_parameter_name_collision",
            property_name: Some(property_name),
        },
    }
}

fn selected_generated_tools(
    generation: &tools::openapi::OpenApiToolGeneration,
    request: &OpenApiToolsRegisterRequest,
) -> ResponseResult<Vec<tools::definitions::ToolDefinition>> {
    let duplicates = duplicate_strings(&request.selected_tool_names);
    if !duplicates.is_empty() {
        return Err(Box::new(bad_request(&format!(
            "selected_tool_names contains duplicate names: {}",
            duplicates.join(", ")
        ))));
    }

    let generated_names = generation
        .definitions
        .iter()
        .map(|definition| definition.name.as_str())
        .collect::<BTreeSet<_>>();
    let selected_names = request
        .selected_tool_names
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let unknown = selected_names
        .iter()
        .filter(|name| !generated_names.contains(**name))
        .copied()
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        return Err(Box::new(bad_request(&format!(
            "selected tool names were not generated: {}",
            unknown.join(", ")
        ))));
    }

    let unsupported_tool_names = generation
        .api_key_header_auth_requirements
        .iter()
        .filter(|requirement| selected_names.contains(requirement.tool_name.as_str()))
        .map(|requirement| requirement.tool_name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if !unsupported_tool_names.is_empty() {
        return Err(Box::new(
            unsupported_openapi_tool_auth_requirements_response(unsupported_tool_names),
        ));
    }

    Ok(generation
        .definitions
        .iter()
        .filter(|definition| selected_names.contains(definition.name.as_str()))
        .cloned()
        .collect())
}

fn unsupported_openapi_tool_auth_requirements_response(
    unsupported_tool_names: Vec<String>,
) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(UnsupportedOpenApiToolAuthRequirementsResponse {
            error: OPENAPI_TOOLS_UNSUPPORTED_AUTH_REQUIREMENTS_ERROR,
            unsupported_tool_names,
        }),
    )
        .into_response()
}

fn duplicate_strings(values: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();

    for value in values {
        if !seen.insert(value.as_str()) {
            duplicates.insert(value.clone());
        }
    }

    duplicates.into_iter().collect()
}

fn conflicting_tool_names(
    existing: &[tools::definitions::ToolDefinition],
    selected: &[tools::definitions::ToolDefinition],
) -> Vec<String> {
    let existing_names = existing
        .iter()
        .map(|definition| definition.name.as_str())
        .collect::<BTreeSet<_>>();

    selected
        .iter()
        .filter(|definition| existing_names.contains(definition.name.as_str()))
        .map(|definition| definition.name.clone())
        .collect()
}

impl RulePatch {
    fn is_empty(&self) -> bool {
        self.methods.is_none()
            && self.enabled.is_none()
            && self.path.is_none()
            && self.tool_name.is_none()
            && self.principal.is_none()
            && self.action.is_none()
    }
}

fn apply_rule_patch(rule: &mut rbac::Rule, patch: RulePatch) {
    if let Some(enabled) = patch.enabled {
        rule.enabled = enabled;
    }
    if let Some(methods) = patch.methods {
        rule.methods = methods;
    }
    if let Some(path) = patch.path {
        rule.path = match path {
            RulePathPatch::Set(value) => value,
            RulePathPatch::Clear => String::new(),
        };
    }
    if let Some(tool_name) = patch.tool_name {
        rule.tool_name = match tool_name {
            RuleToolNamePatch::Set(value) => Some(value),
            RuleToolNamePatch::Clear => None,
        };
    }
    if let Some(principal) = patch.principal {
        rule.principal = principal;
    }
    if let Some(action) = patch.action {
        rule.action = action;
    }
}

fn changed_rule_fields(before: &rbac::Rule, after: &rbac::Rule) -> Vec<&'static str> {
    let mut fields = Vec::new();

    if before.methods != after.methods {
        fields.push("methods");
    }
    if before.enabled != after.enabled {
        fields.push("enabled");
    }
    if before.path != after.path {
        fields.push("path");
    }
    if before.tool_name != after.tool_name {
        fields.push("tool_name");
    }
    if before.principal != after.principal {
        fields.push("principal");
    }
    if before.action != after.action {
        fields.push("action");
    }

    fields
}

fn validate_policy_candidate(candidate: &rbac::Policy) -> ResponseResult<rbac::Policy> {
    let value = match serde_json::to_value(candidate) {
        Ok(value) => value,
        Err(err) => {
            tracing::error!(error = %err, "failed to serialize candidate policy for validation");
            return Err(Box::new(internal_server_error("policy validation failed")));
        }
    };

    rbac::Policy::validate_json_value(value)
        .map_err(|err| Box::new(policy_validation_failed(vec![policy_error_message(&err)])))
}

fn require_matching_if_match(
    headers: &HeaderMap,
    before_policy: &rbac::Policy,
) -> ResponseResult<String> {
    let current_etag = match policy_etag(before_policy) {
        Ok(etag) => etag,
        Err(err) => {
            tracing::error!(error = %err, "failed to compute current policy ETag");
            return Err(Box::new(internal_server_error(
                "policy ETag computation failed",
            )));
        }
    };

    match if_match_matches(headers, &current_etag) {
        Ok(true) => Ok(current_etag),
        Ok(false) => Err(Box::new(precondition_failed(
            "If-Match does not match the current policy ETag",
        ))),
        Err(error) => Err(Box::new(if_match_error_response(error))),
    }
}

fn create_policy_rule(
    state: &PolicyAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    rbac_state: &middleware::rbac::RbacState,
    policy_file: &std::path::Path,
    mut rule: rbac::Rule,
) -> ResponseResult<PolicyRuleCreateResult> {
    let _policy_write_guard = match rbac_state.policy_write_guard() {
        Ok(guard) => guard,
        Err(err) => {
            tracing::error!(error = %err, "failed to acquire policy write lock");
            return Err(Box::new(internal_server_error("policy write lock failed")));
        }
    };

    let before_policy = rbac_state.current_policy();
    let current_etag = require_matching_if_match(&parts.headers, &before_policy)?;

    if let Some(rule_id) = rule.id.as_deref() {
        if policy_rule_ids(&before_policy)
            .iter()
            .any(|existing_id| existing_id == rule_id)
        {
            return Err(Box::new(bad_request(&format!(
                "rule id '{rule_id}' already exists"
            ))));
        }
    } else {
        rule.id = Some(generate_unique_rule_id(&before_policy));
    }

    let rule_id = rule
        .id
        .clone()
        .unwrap_or_else(|| before_policy.rules.len().to_string());
    let position = before_policy.rules.len();
    let mut candidate = before_policy.clone();
    candidate.rules.push(rule);
    let candidate = validate_policy_candidate(&candidate)?;
    let created_rule = candidate.rules[position].clone();

    let diff_summary = json!({
        "action": "rule_created",
        "rule_id": rule_id,
        "position": position,
    });
    let commit = persist_policy_mutation(
        PolicyMutationCommitContext {
            state,
            rbac_state,
            policy_file,
            parts,
            principal,
        },
        &before_policy,
        &candidate,
        diff_summary,
    )?;

    debug_assert_ne!(current_etag, commit.new_etag);
    let created_rule = commit
        .after_policy
        .rules
        .get(position)
        .cloned()
        .unwrap_or(created_rule);

    Ok(PolicyRuleCreateResult {
        rule: created_rule,
        new_etag: commit.new_etag,
        history_append_failed: commit.history_append_failed,
    })
}

fn persist_policy_mutation(
    context: PolicyMutationCommitContext<'_>,
    before_policy: &rbac::Policy,
    candidate: &rbac::Policy,
    diff_summary: Value,
) -> ResponseResult<PolicyMutationCommitResult> {
    if let Err(err) = candidate.persist_to_file(context.policy_file) {
        tracing::error!(policy_file = %context.policy_file.display(), error = %err, "failed to persist policy");
        return Err(Box::new(internal_server_error("policy persist failed")));
    }

    if let Err(err) =
        middleware::rbac::reload_policy_from_file(context.rbac_state, context.policy_file)
    {
        tracing::error!(policy_file = %context.policy_file.display(), error = %err, "failed to reload persisted policy");
        return Err(Box::new(internal_server_error("policy reload failed")));
    }

    let after_policy = context.rbac_state.current_policy();
    let history_append_failed = append_policy_version_after_commit(
        context.state,
        context.principal,
        &after_policy,
        &diff_summary,
    );
    emit_policy_rule_changed(
        context.state,
        context.parts,
        context.principal,
        before_policy,
        &after_policy,
        diff_summary,
    );

    let new_etag = match policy_etag(&after_policy) {
        Ok(etag) => etag,
        Err(err) => {
            tracing::error!(error = %err, "failed to compute updated policy ETag");
            return Err(Box::new(internal_server_error(
                "policy ETag computation failed",
            )));
        }
    };

    Ok(PolicyMutationCommitResult {
        after_policy,
        new_etag,
        history_append_failed,
    })
}

fn append_policy_version_after_commit(
    state: &PolicyAdminState,
    principal: &auth::Principal,
    policy: &rbac::Policy,
    diff_summary: &Value,
) -> bool {
    match append_policy_version(state, principal, policy, diff_summary) {
        Ok(()) => false,
        Err(err) => {
            tracing::error!(
                error = %err,
                "failed to append policy history version after policy mutation committed; returning mutation success with warning"
            );
            true
        }
    }
}

fn append_policy_version(
    state: &PolicyAdminState,
    principal: &auth::Principal,
    policy: &rbac::Policy,
    diff_summary: &Value,
) -> Result<(), String> {
    let Some(history_store) = state.history_store.as_ref() else {
        return Err("policy history store is not configured".to_owned());
    };

    history_store
        .append_version(&principal.user_id, diff_summary, policy)
        .map(|_| ())
        .map_err(|err| err.to_string())
}

fn effective_rule_id(rule: &rbac::Rule, rule_index: usize) -> String {
    rule.id.clone().unwrap_or_else(|| rule_index.to_string())
}

fn policy_rule_ids(policy: &rbac::Policy) -> Vec<String> {
    policy
        .rules
        .iter()
        .enumerate()
        .map(|(rule_index, rule)| effective_rule_id(rule, rule_index))
        .collect()
}

fn generate_unique_rule_id(policy: &rbac::Policy) -> String {
    let existing_ids = policy_rule_ids(policy).into_iter().collect::<HashSet<_>>();

    loop {
        let rule_id = format!("rule-{}", uuid::Uuid::new_v4());
        if !existing_ids.contains(&rule_id) {
            return rule_id;
        }
    }
}

enum RuleLookupError {
    NotFound,
    Ambiguous,
}

fn rule_index_by_id(policy: &rbac::Policy, rule_id: &str) -> Result<usize, RuleLookupError> {
    let mut matched_index = None;

    for (rule_index, rule) in policy.rules.iter().enumerate() {
        if effective_rule_id(rule, rule_index) == rule_id {
            if matched_index.is_some() {
                return Err(RuleLookupError::Ambiguous);
            }
            matched_index = Some(rule_index);
        }
    }

    matched_index.ok_or(RuleLookupError::NotFound)
}

fn rule_lookup_error_response(rule_id: &str, error: RuleLookupError) -> Response {
    match error {
        RuleLookupError::NotFound => not_found(&format!("rule id '{rule_id}' was not found")),
        RuleLookupError::Ambiguous => bad_request(&format!(
            "rule id '{rule_id}' is ambiguous in the current policy"
        )),
    }
}

fn validate_rule_order(
    current_order: &[String],
    requested_order: &[String],
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    let current_ids = current_order.iter().cloned().collect::<HashSet<_>>();
    if current_ids.len() != current_order.len() {
        errors.push(
            "current policy contains duplicate rule ids; cannot reorder rules safely".to_owned(),
        );
    }

    if requested_order.len() != current_order.len() {
        errors.push(format!(
            "rule order length mismatch: expected {}, got {}",
            current_order.len(),
            requested_order.len()
        ));
    }

    let mut seen = HashSet::new();
    let mut duplicate_ids = Vec::new();
    for rule_id in requested_order {
        if !seen.insert(rule_id) && !duplicate_ids.iter().any(|id| id == rule_id) {
            duplicate_ids.push(rule_id.clone());
        }
    }
    if !duplicate_ids.is_empty() {
        errors.push(format!(
            "rule order contains duplicate ids: {}",
            duplicate_ids.join(", ")
        ));
    }

    let requested_ids = requested_order.iter().cloned().collect::<HashSet<_>>();
    let missing_ids = current_order
        .iter()
        .filter(|rule_id| !requested_ids.contains(*rule_id))
        .cloned()
        .collect::<Vec<_>>();
    if !missing_ids.is_empty() {
        errors.push(format!(
            "rule order is missing ids: {}",
            missing_ids.join(", ")
        ));
    }

    let unknown_ids = requested_order
        .iter()
        .filter(|rule_id| !current_ids.contains(*rule_id))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown_ids.is_empty() {
        errors.push(format!(
            "rule order contains unknown ids: {}",
            unknown_ids.join(", ")
        ));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn reordered_rules(policy: &rbac::Policy, requested_order: &[String]) -> Vec<rbac::Rule> {
    requested_order
        .iter()
        .filter_map(|requested_id| {
            policy
                .rules
                .iter()
                .enumerate()
                .find(|(rule_index, rule)| effective_rule_id(rule, *rule_index) == *requested_id)
                .map(|(_, rule)| rule.clone())
        })
        .collect()
}

fn policy_etag(policy: &rbac::Policy) -> Result<String, serde_json::Error> {
    let mut value = serde_json::to_value(policy)?;
    sort_json_value(&mut value);
    let bytes = serde_json::to_vec(&value)?;
    let digest = Sha256::digest(&bytes);

    Ok(format!("\"sha256:{}\"", hex::encode(digest)))
}

fn tools_file_etag(value: &Value) -> Result<String, serde_json::Error> {
    let mut value = value.clone();
    sort_json_value(&mut value);
    let bytes = serde_json::to_vec(&value)?;
    let digest = Sha256::digest(&bytes);

    Ok(format!("\"sha256:{}\"", hex::encode(digest)))
}

fn read_valid_tools_file_value(path: &FsPath) -> Result<Value, String> {
    let (value, _) = read_tools_file_document(path)?;
    Ok(value)
}

fn read_tools_file_document(path: &FsPath) -> Result<(Value, ToolsFileAdminDocument), String> {
    let contents = fs::read_to_string(path)
        .map_err(|err| format!("failed to read tools file {}: {err}", path.display()))?;
    let value = serde_json::from_str::<Value>(&contents).map_err(|err| {
        format!(
            "failed to parse tools file {} as JSON: {err}",
            path.display()
        )
    })?;

    tools::definitions::ToolRegistry::from_json_value(value.clone())
        .map_err(|err| err.to_string())?;
    let document = serde_json::from_value::<ToolsFileAdminDocument>(value.clone())
        .map_err(|err| format!("failed to decode tools file {}: {err}", path.display()))?;

    Ok((value, document))
}

fn sort_json_value(value: &mut Value) {
    match value {
        Value::Array(values) => {
            for value in values {
                sort_json_value(value);
            }
        }
        Value::Object(map) => {
            let mut entries = std::mem::take(map).into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            for (_, value) in &mut entries {
                sort_json_value(value);
            }
            map.extend(entries);
        }
        _ => {}
    }
}

fn etag_header_value(etag: &str) -> HeaderValue {
    HeaderValue::from_str(etag).expect("policy ETag should be a valid HTTP header value")
}

fn with_policy_history_append_warning(
    mut response: Response,
    history_append_failed: bool,
) -> Response {
    if history_append_failed {
        response.headers_mut().insert(
            HeaderName::from_static(POLICY_HISTORY_WARNING_HEADER),
            HeaderValue::from_static(POLICY_HISTORY_APPEND_FAILED_WARNING),
        );
    }

    response
}

fn if_match_matches(headers: &HeaderMap, current_etag: &str) -> Result<bool, IfMatchError> {
    let mut saw_if_match = false;

    for value in headers.get_all(header::IF_MATCH) {
        saw_if_match = true;
        let value = value.to_str().map_err(|_| IfMatchError::InvalidHeader)?;
        if value
            .split(',')
            .map(str::trim)
            .any(|candidate| candidate == current_etag)
        {
            return Ok(true);
        }
    }

    if saw_if_match {
        Ok(false)
    } else {
        Err(IfMatchError::Missing)
    }
}

fn if_match_error_response(error: IfMatchError) -> Response {
    match error {
        IfMatchError::Missing => precondition_required("If-Match header is required"),
        IfMatchError::InvalidHeader => bad_request("If-Match header must be valid ASCII"),
    }
}

fn policy_validation_failed(errors: Vec<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(PolicyValidationResponse {
            valid: false,
            errors,
        }),
    )
        .into_response()
}

fn emit_policy_rule_changed(
    state: &PolicyAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    before: &rbac::Policy,
    after: &rbac::Policy,
    diff_summary: Value,
) {
    let mut payload = policy_change_payload(before, after);
    if let Some(payload) = payload.as_object_mut() {
        payload.insert("diff_summary".to_owned(), diff_summary);
    }

    emit_policy_changed_payload(state, parts, principal, payload);
}

fn emit_policy_changed_payload(
    state: &PolicyAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    payload: Value,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip = client_ip::canonical_client_ip(
        &parts.headers,
        &parts.extensions,
        state.trust_proxy_headers,
    );
    let actor = Some(auth::actor_from_principal(principal));

    state.audit.emit(audit::AuditEvent::new(
        audit::event::POLICY_CHANGED,
        request_id,
        source_ip,
        actor,
        payload,
    ));
}

fn emit_service_token_changed(
    state: &TokenAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    action: &'static str,
    record: &auth::tokens::TokenRecord,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip = client_ip::canonical_client_ip(
        &parts.headers,
        &parts.extensions,
        state.trust_proxy_headers,
    );
    let actor = Some(auth::actor_from_principal(principal));
    let mut payload = json!({
        "action": action,
        "token_id": &record.id,
        "token_prefix": &record.token_prefix,
        "scopes": &record.scopes,
        "created_by": &record.created_by,
    });
    if let Some(expires_at) = record.expires_at.as_deref() {
        payload["expires_at"] = json!(expires_at);
    }
    if let Some(revoked_at) = record.revoked_at.as_deref() {
        payload["revoked_at"] = json!(revoked_at);
    }

    state.audit.emit(audit::AuditEvent::new(
        audit::event::SERVICE_TOKEN_CHANGED,
        request_id,
        source_ip,
        actor,
        payload,
    ));
}

fn emit_tool_registry_changed(
    state: &ToolAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    tools_file: &FsPath,
    registered_tool_names: &[String],
    tool_count: usize,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip = client_ip::canonical_client_ip(
        &parts.headers,
        &parts.extensions,
        state.trust_proxy_headers,
    );
    let actor = Some(auth::actor_from_principal(principal));
    let payload = json!({
        "action": "openapi_tools_registered",
        "tools_file": tools_file.display().to_string(),
        "registered_tool_names": registered_tool_names,
        "registered_tool_count": registered_tool_names.len(),
        "tool_count": tool_count,
    });

    state.audit.emit(audit::AuditEvent::new(
        audit::event::TOOL_REGISTRY_CHANGED,
        request_id,
        source_ip,
        actor,
        payload,
    ));
}

fn emit_traffic_endpoint_review_changed(
    state: &TrafficAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    method: &str,
    endpoint_template: &str,
    review: &discovery::query::EndpointReviewState,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip = client_ip::canonical_client_ip(
        &parts.headers,
        &parts.extensions,
        state.trust_proxy_headers,
    );
    let actor = Some(auth::actor_from_principal(principal));
    let payload = json!({
        "method": method,
        "endpoint_template": endpoint_template,
        "reviewed": review.reviewed,
        "reviewed_at": review.reviewed_at,
        "reviewed_by": review.reviewed_by,
    });

    state.audit.emit(audit::AuditEvent::new(
        audit::event::TRAFFIC_ENDPOINT_REVIEW_CHANGED,
        request_id,
        source_ip,
        actor,
        payload,
    ));
}

fn emit_signal_lifecycle_changed(
    state: &SignalsAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    signal: &discovery::signals::Signal,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip = client_ip::canonical_client_ip(
        &parts.headers,
        &parts.extensions,
        state.trust_proxy_headers,
    );
    let actor = Some(auth::actor_from_principal(principal));
    let payload = json!({
        "id": &signal.id,
        "signal_type": &signal.signal_type,
        "target": &signal.target,
        "state": signal.state.as_str(),
        "transitioned_at": &signal.transitioned_at,
        "transitioned_by": &signal.transitioned_by,
    });

    state.audit.emit(audit::AuditEvent::new(
        audit::event::SIGNAL_LIFECYCLE_CHANGED,
        request_id,
        source_ip,
        actor,
        payload,
    ));
}

fn emit_suggestion_lifecycle_changed(
    state: &SuggestionsAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    suggestion: &discovery::suggestions::RuleSuggestion,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip = client_ip::canonical_client_ip(
        &parts.headers,
        &parts.extensions,
        state.policy.trust_proxy_headers,
    );
    let actor = Some(auth::actor_from_principal(principal));
    let payload = json!({
        "id": &suggestion.id,
        "suggestion_type": &suggestion.suggestion_type,
        "method": &suggestion.method,
        "path_pattern": &suggestion.path_pattern,
        "proposed_rule": &suggestion.proposed_rule,
        "state": suggestion.state.as_str(),
        "transitioned_at": &suggestion.transitioned_at,
        "transitioned_by": &suggestion.transitioned_by,
        "source_signal_id": &suggestion.source_signal_id,
    });

    state.policy.audit.emit(audit::AuditEvent::new(
        audit::event::SUGGESTION_LIFECYCLE_CHANGED,
        request_id,
        source_ip,
        actor,
        payload,
    ));
}

fn policy_change_payload(before: &rbac::Policy, after: &rbac::Policy) -> Value {
    json!({
        "before": policy_audit_summary(before),
        "after": policy_audit_summary(after),
        "changed_sections": changed_policy_sections(before, after),
    })
}

fn policy_audit_summary(policy: &rbac::Policy) -> Value {
    json!({
        "id": policy.id,
        "roles": policy.roles.len(),
        "routes": policy.routes.len(),
        "rules": policy.rules.len(),
        "egress_hosts": policy.egress.hosts.len(),
        "egress_cidrs": policy.egress.cidrs.len(),
        "egress_ports": policy.egress.ports.len(),
        "tools": policy.tools.len(),
    })
}

fn changed_policy_sections(before: &rbac::Policy, after: &rbac::Policy) -> Vec<&'static str> {
    let mut sections = Vec::new();

    if before.schema_version != after.schema_version {
        sections.push("schema_version");
    }
    if before.id != after.id {
        sections.push("id");
    }
    if before.default_action != after.default_action {
        sections.push("default_action");
    }
    if before.enforcement_mode != after.enforcement_mode {
        sections.push("enforcement_mode");
    }
    if before.roles != after.roles {
        sections.push("roles");
    }
    if before.routes != after.routes {
        sections.push("routes");
    }
    if before.rules != after.rules {
        sections.push("rules");
    }
    if before.egress != after.egress {
        sections.push("egress");
    }
    if before.tools != after.tools {
        sections.push("tools");
    }

    sections
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

fn not_found(error: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: error.to_owned(),
        }),
    )
        .into_response()
}

fn policy_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "policy API requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

fn policy_history_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error:
                "policy history requires POLICY_FILE or POLICY_HISTORY_SQLITE_PATH to be configured"
                    .to_owned(),
        }),
    )
        .into_response()
}

fn token_rbac_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "token API requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

fn audit_rbac_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "audit API requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

fn status_rbac_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "status API requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

fn token_store_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "token API requires SERVICE_TOKEN_SQLITE_PATH to be configured".to_owned(),
        }),
    )
        .into_response()
}

fn tools_rbac_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "tools API requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

fn tools_file_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "tools API requires TOOLS_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

fn schema_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(SchemaNotConfiguredResponse {
            error: "schema coverage requires OPENAPI_SPEC_PATH or UPSTREAM_ROUTES[].openapi_spec_path to be configured".to_owned(),
            spec_configured: false,
        }),
    )
        .into_response()
}

fn traffic_rbac_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "traffic endpoint inventory requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

fn principal_rbac_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "principal directory requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

fn signals_rbac_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "signals API requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

fn suggestions_rbac_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "suggestions API requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

fn schema_discovery_not_configured() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(DiscoveryNotConfiguredResponse {
            error: "schema coverage requires DISCOVERY_SQLITE_PATH to be configured".to_owned(),
            discovery_configured: false,
        }),
    )
        .into_response()
}

fn schema_inference_discovery_not_configured() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(DiscoveryNotConfiguredResponse {
            error: "inferred schema requires DISCOVERY_SQLITE_PATH to be configured".to_owned(),
            discovery_configured: false,
        }),
    )
        .into_response()
}

fn payload_capture_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(PayloadCaptureNotConfiguredResponse {
            error: "inferred schema requires PAYLOAD_CAPTURE_ENABLED=true".to_owned(),
            payload_capture_configured: false,
        }),
    )
        .into_response()
}

fn inferred_schema_no_samples() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(InferredSchemaNoSamplesResponse {
            error:
                "inferred schema has no captured payload samples for method and endpoint_template"
                    .to_owned(),
            schema_inferred: false,
        }),
    )
        .into_response()
}

fn discovery_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "traffic endpoint inventory requires DISCOVERY_SQLITE_PATH to be configured"
                .to_owned(),
        }),
    )
        .into_response()
}

fn principal_directory_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "principal directory requires PRINCIPAL_SQLITE_PATH to be configured".to_owned(),
        }),
    )
        .into_response()
}

fn signals_discovery_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "signals API requires DISCOVERY_SQLITE_PATH to be configured".to_owned(),
        }),
    )
        .into_response()
}

fn suggestions_discovery_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "suggestions API requires DISCOVERY_SQLITE_PATH to be configured".to_owned(),
        }),
    )
        .into_response()
}

fn precondition_required(error: &str) -> Response {
    (
        StatusCode::PRECONDITION_REQUIRED,
        Json(ErrorResponse {
            error: error.to_owned(),
        }),
    )
        .into_response()
}

fn precondition_failed(error: &str) -> Response {
    (
        StatusCode::PRECONDITION_FAILED,
        Json(ErrorResponse {
            error: error.to_owned(),
        }),
    )
        .into_response()
}

fn conflict(error: &str) -> Response {
    (
        StatusCode::CONFLICT,
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

fn token_store_error_response(error: auth::tokens::TokenStoreError) -> Response {
    match error {
        auth::tokens::TokenStoreError::InvalidCursor { parameter } => {
            bad_request(&format!("invalid query parameter: {parameter}"))
        }
        auth::tokens::TokenStoreError::TimeParse { context, .. } => {
            bad_request(&format!("invalid service-token {context} timestamp"))
        }
        auth::tokens::TokenStoreError::RevokedToken { .. } => {
            conflict("cannot rotate revoked service token")
        }
        error => {
            tracing::error!(error = %error, "service-token store operation failed");
            internal_server_error("service-token store operation failed")
        }
    }
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
fn test_auth_method_label(auth_method: &auth::AuthMethod) -> &'static str {
    match auth_method {
        auth::AuthMethod::Cookie => "session_cookie",
        auth::AuthMethod::Bearer => "bearer_token",
        auth::AuthMethod::ServiceToken => "service_token",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::TokenStore;
    use axum::{body::Body, http::StatusCode};
    use futures_util::StreamExt;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use rmcp::{
        model::{
            CallToolRequestParams as RmcpCallToolRequestParams,
            CallToolResult as RmcpCallToolResult, ErrorData as RmcpErrorData, Implementation,
            JsonObject as RmcpJsonObject, ListToolsResult as RmcpListToolsResult,
            PaginatedRequestParams as RmcpPaginatedRequestParams,
            ServerCapabilities as RmcpServerCapabilities, ServerInfo as RmcpServerInfo,
            Tool as RmcpTool,
        },
        service::{RequestContext as RmcpRequestContext, RoleServer as RmcpRoleServer},
        transport::{
            streamable_http_client::StreamableHttpClientTransportConfig,
            streamable_http_server::{
                session::never::NeverSessionManager as RmcpNeverSessionManager,
                StreamableHttpServerConfig as RmcpStreamableHttpServerConfig,
                StreamableHttpService as RmcpStreamableHttpService,
            },
            StreamableHttpClientTransport,
        },
        ServerHandler as RmcpServerHandler, ServiceExt as RmcpServiceExt,
    };
    use rusqlite::{params, Connection};
    use serde_json::Value;
    use std::{
        collections::{HashMap, HashSet},
        fs,
        io::{Read, Write},
        net::{IpAddr, Ipv4Addr},
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Mutex,
        },
        time::{Duration, Instant},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::{
        rustls::{
            pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
            ServerConfig,
        },
        TlsAcceptor,
    };
    use tower::ServiceExt;

    fn test_config(cors_allow_origins: Vec<&str>) -> config::Config {
        config::Config {
            listen_addr: "127.0.0.1:0"
                .parse()
                .expect("test listen address should parse"),
            admin_listen_addr: None,
            admin_prefix: config::DEFAULT_ADMIN_PREFIX.to_owned(),
            admin_login_provider: None,
            gateway_public_url: None,
            audit_log_file: None,
            audit_sqlite_path: None,
            audit_sqlite_retention_days: None,
            discovery_sqlite_path: None,
            principal_sqlite_path: None,
            payload_capture_enabled: false,
            payload_capture_sample_rate: config::DEFAULT_PAYLOAD_CAPTURE_SAMPLE_RATE,
            schema_mismatch_signal_threshold:
                discovery::signals::DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
            error_rate_spike_signal_threshold:
                discovery::signals::DEFAULT_ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
            principal_new_to_endpoint_signal_threshold:
                discovery::signals::DEFAULT_PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
            volume_outlier_signal_threshold:
                discovery::signals::DEFAULT_VOLUME_OUTLIER_SIGNAL_THRESHOLD,
            rule_suggestion_baseline_window_hours:
                discovery::suggestions::DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
            openapi_spec_path: None,
            policy_file: None,
            tools_file: None,
            policy_history_sqlite_path: None,
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
            auth_providers: Vec::new(),
            jwt_jwks_url: None,
            jwt_issuer: None,
            jwt_audience: None,
            jwt_jwks_timeout_ms: 2000,
            jwt_require_jti: false,
            roles_claim: "roles".to_owned(),
            service_token_sqlite_path: None,
            service_token_cache_ttl_ms: config::DEFAULT_SERVICE_TOKEN_CACHE_TTL_MS,
            tool_runtime_queue_depth: config::DEFAULT_TOOL_RUNTIME_QUEUE_DEPTH,
            tool_runtime_global_concurrency: config::DEFAULT_TOOL_RUNTIME_GLOBAL_CONCURRENCY,
            tool_runtime_queue_timeout_ms: config::DEFAULT_TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
            tool_runtime_default_timeout_ms: config::DEFAULT_TOOL_RUNTIME_DEFAULT_TIMEOUT_MS,
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
            mcp_upstream_servers: Vec::new(),
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

    struct TlsCaptureUpstream {
        addr: std::net::SocketAddr,
        ca_pem: String,
        captured: tokio::sync::mpsc::Receiver<CapturedRequest>,
    }

    async fn spawn_tls_capture_upstream() -> TlsCaptureUpstream {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let (ca_pem, server_cert_der, server_key_der) = test_ca_signed_server_certificate();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(server_cert_der)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key_der)),
            )
            .expect("test TLS server config should build");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test TLS upstream should bind");
        let addr = listener
            .local_addr()
            .expect("test TLS upstream address should be available");
        let (sender, captured) = tokio::sync::mpsc::channel(16);

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let sender = sender.clone();
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    capture_tls_http_request(&mut stream, sender).await;
                });
            }
        });

        TlsCaptureUpstream {
            addr,
            ca_pem,
            captured,
        }
    }

    fn test_ca_signed_server_certificate() -> (String, Vec<u8>, Vec<u8>) {
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.distinguished_name = rcgen::DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "GreenGateway Test CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().expect("test CA key should generate");
        let ca = ca_params
            .self_signed(&ca_key)
            .expect("test CA certificate should build");

        let mut server_params = rcgen::CertificateParams::default();
        server_params.distinguished_name = rcgen::DistinguishedName::new();
        server_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "127.0.0.1");
        server_params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let server_key = rcgen::KeyPair::generate().expect("test server key should generate");
        let server = server_params
            .signed_by(&server_key, &ca, &ca_key)
            .expect("test server certificate should build");

        (
            ca.pem(),
            server.der().as_ref().to_vec(),
            server_key.serialize_der(),
        )
    }

    async fn capture_tls_http_request(
        stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        sender: tokio::sync::mpsc::Sender<CapturedRequest>,
    ) {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        let header_end = loop {
            let read = stream
                .read(&mut chunk)
                .await
                .expect("test TLS upstream should read request");
            if read == 0 {
                return;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(index) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break index;
            }
            assert!(
                buffer.len() <= 16 * 1024,
                "test TLS upstream request headers should stay bounded"
            );
        };
        let raw_headers = std::str::from_utf8(&buffer[..header_end])
            .expect("test TLS request headers should be UTF-8");
        let mut lines = raw_headers.split("\r\n");
        let request_line = lines
            .next()
            .expect("test TLS request should include request line");
        let mut request_parts = request_line.split_whitespace();
        let method = request_parts
            .next()
            .and_then(|method| Method::from_bytes(method.as_bytes()).ok())
            .expect("test TLS request method should parse");
        let path_and_query = request_parts
            .next()
            .expect("test TLS request should include path")
            .to_owned();
        let mut headers = HeaderMap::new();
        for line in lines {
            let (name, value) = line
                .split_once(':')
                .unwrap_or_else(|| panic!("test TLS request header should contain ':': {line}"));
            let name = HeaderName::from_bytes(name.trim().as_bytes())
                .expect("test TLS request header name should parse");
            let value = HeaderValue::from_str(value.trim())
                .expect("test TLS request header value should parse");
            headers.append(name, value);
        }
        let _ = sender
            .send(CapturedRequest {
                method,
                path_and_query,
                headers,
                body: Vec::new(),
            })
            .await;

        stream
            .write_all(
                b"HTTP/1.1 201 Created\r\nContent-Length: 12\r\nConnection: close\r\n\r\ntls upstream",
            )
            .await
            .expect("test TLS upstream should write response");
        stream
            .shutdown()
            .await
            .expect("test TLS upstream should close response");
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

    struct MockOidcDiscoveryEndpoint {
        issuer: String,
        authorization_endpoint: String,
        handle: std::thread::JoinHandle<usize>,
    }

    impl MockOidcDiscoveryEndpoint {
        fn finish(self) {
            assert_eq!(
                self.handle
                    .join()
                    .expect("mock OIDC discovery endpoint should finish"),
                1
            );
        }
    }

    #[derive(Clone)]
    struct MockOidcTokenState {
        access_token: Arc<Mutex<Option<String>>>,
        id_token: Arc<Mutex<Option<String>>>,
        requests: Arc<Mutex<Vec<CapturedTokenRequest>>>,
    }

    #[derive(Clone)]
    struct MockOidcTokenEndpoint {
        url: String,
        access_token: Arc<Mutex<Option<String>>>,
        id_token: Arc<Mutex<Option<String>>>,
        requests: Arc<Mutex<Vec<CapturedTokenRequest>>>,
        handle: Arc<tokio::task::JoinHandle<()>>,
    }

    #[derive(Clone, Debug)]
    struct CapturedTokenRequest {
        method: Method,
        headers: HeaderMap,
        body: String,
    }

    impl MockOidcTokenEndpoint {
        fn set_access_token(&self, token: String) {
            *self
                .access_token
                .lock()
                .expect("mock token state should lock") = Some(token);
        }

        fn set_id_token(&self, token: String) {
            *self.id_token.lock().expect("mock token state should lock") = Some(token);
        }

        fn requests(&self) -> Vec<CapturedTokenRequest> {
            self.requests
                .lock()
                .expect("mock token requests should lock")
                .clone()
        }

        fn abort(self) {
            self.handle.abort();
        }
    }

    fn spawn_mock_oidc_discovery_endpoint(
        token_endpoint: Option<String>,
    ) -> MockOidcDiscoveryEndpoint {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
            .expect("mock OIDC discovery endpoint should bind");
        let addr = listener
            .local_addr()
            .expect("mock OIDC discovery endpoint address should be available");
        let issuer = format!("http://127.0.0.1:{}", addr.port());
        let authorization_endpoint = format!("{issuer}/authorize");
        let token_endpoint = token_endpoint.unwrap_or_else(|| format!("{issuer}/token"));
        let discovery = json!({
            "issuer": issuer.clone(),
            "jwks_uri": format!("{issuer}/jwks.json"),
            "authorization_endpoint": authorization_endpoint.clone(),
            "token_endpoint": token_endpoint
        });
        let handle = spawn_blocking_json_server(
            listener,
            vec![(
                "/.well-known/openid-configuration".to_owned(),
                discovery.to_string(),
            )],
            1,
        );

        MockOidcDiscoveryEndpoint {
            issuer,
            authorization_endpoint,
            handle,
        }
    }

    async fn spawn_mock_oidc_token_endpoint(
        host: Ipv4Addr,
        access_token: Option<String>,
    ) -> MockOidcTokenEndpoint {
        let listener = tokio::net::TcpListener::bind((host, 0))
            .await
            .expect("mock OIDC token endpoint should bind");
        let addr = listener
            .local_addr()
            .expect("mock OIDC token endpoint address should be available");
        let url = format!("http://{}:{}/token", host, addr.port());
        let access_token = Arc::new(Mutex::new(access_token));
        let id_token = Arc::new(Mutex::new(None));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let state = MockOidcTokenState {
            access_token: Arc::clone(&access_token),
            id_token: Arc::clone(&id_token),
            requests: Arc::clone(&requests),
        };
        let router = Router::new()
            .route("/token", post(mock_oidc_token))
            .with_state(state);
        let handle = Arc::new(tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("mock OIDC token endpoint should serve");
        }));

        MockOidcTokenEndpoint {
            url,
            access_token,
            id_token,
            requests,
            handle,
        }
    }

    async fn mock_oidc_token(
        State(state): State<MockOidcTokenState>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        let body = String::from_utf8(body.to_vec()).expect("token request body should be UTF-8");
        state
            .requests
            .lock()
            .expect("mock token requests should lock")
            .push(CapturedTokenRequest {
                method: Method::POST,
                headers,
                body,
            });
        let access_token = state
            .access_token
            .lock()
            .expect("mock token state should lock")
            .clone()
            .expect("mock access token should be set before token exchange");
        let id_token = state
            .id_token
            .lock()
            .expect("mock token state should lock")
            .clone();

        let mut response = json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600
        });
        if let Some(id_token) = id_token {
            response["id_token"] = json!(id_token);
        }

        Json(response).into_response()
    }

    fn admin_oidc_login_router(issuer: &str) -> Router {
        admin_oidc_login_router_from_config(admin_oidc_login_config(issuer))
    }

    fn admin_oidc_login_router_from_config(mut config: config::Config) -> Router {
        config.egress_deny_private_ips = false;
        let recorder = PrometheusBuilder::new().build_recorder();
        app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("admin OIDC login app should build")
    }

    fn admin_oidc_login_config(issuer: &str) -> config::Config {
        let mut config = test_config(Vec::new());
        config.admin_login_provider = Some("oidc".to_owned());
        for path in [ADMIN_AUTH_LOGIN_ROUTE, ADMIN_AUTH_CALLBACK_ROUTE] {
            config.auth_exempt_paths.push(path.to_owned());
            config.rbac_exempt_paths.push(path.to_owned());
        }
        config.auth_providers = vec![config::AuthProviderConfig {
            name: "oidc".to_owned(),
            provider_type: config::AuthProviderType::Jwt,
            jwks_url: None,
            issuer: Some(issuer.to_owned()),
            audience: None,
            jwks_timeout_ms: 2000,
            require_jti: false,
            roles_claim: "roles".to_owned(),
            roles_claim_delimiter: None,
            org_claim: None,
            introspection_url: None,
            introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
            cache_ttl_ms: config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
            user_id_claim: None,
            email_claim: None,
            client_id: Some("admin-ui".to_owned()),
            client_secret: Some("secret-value".to_owned()),
            redirect_uri: Some("http://gateway.example.test/v1/admin/auth/callback".to_owned()),
        }];

        config
    }

    async fn admin_oidc_id_token_callback_response(
        id_token_for_nonce: impl FnOnce(&str, &str) -> String,
    ) -> (Response, String) {
        let jwks_addr = spawn_test_jwks_server().await;
        let jwks_url = format!("http://127.0.0.1:{}/jwks.json", jwks_addr.port());
        let token_endpoint =
            spawn_mock_oidc_token_endpoint(Ipv4Addr::new(127, 0, 0, 2), None).await;
        let oidc = spawn_mock_oidc_discovery_endpoint(Some(token_endpoint.url.clone()));
        let access_token = signed_token_with_issuer("admin-operator", &["admin"], &oidc.issuer);
        token_endpoint.set_access_token(access_token.clone());

        let mut config = admin_oidc_login_config(&oidc.issuer);
        config.auth_providers[0].jwks_url = Some(jwks_url);
        let router = admin_oidc_login_router_from_config(config);

        let login_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/auth/login")
                    .body(Body::empty())
                    .expect("login request should build"),
            )
            .await
            .expect("login request should complete");
        let login_location = response_location(&login_response);
        let authorization_url =
            Url::parse(&login_location).expect("authorization redirect should be absolute");
        let authorization_query = url_query_pairs(&authorization_url);
        let state = authorization_query
            .get("state")
            .expect("authorization redirect should include state");
        let nonce = authorization_query
            .get("nonce")
            .expect("authorization redirect should include nonce");
        token_endpoint.set_id_token(id_token_for_nonce(nonce, &oidc.issuer));

        let callback_response = router
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/admin/auth/callback?code=admin-code&state={}",
                        query_encode(state)
                    ))
                    .body(Body::empty())
                    .expect("callback request should build"),
            )
            .await
            .expect("callback request should complete");

        oidc.finish();
        token_endpoint.abort();

        (callback_response, access_token)
    }

    fn response_location(response: &Response) -> String {
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .expect("response should include Location")
            .to_owned()
    }

    fn url_query_pairs(url: &Url) -> HashMap<String, String> {
        url.query_pairs().into_owned().collect()
    }

    fn form_pairs(body: &str) -> HashMap<String, String> {
        url::form_urlencoded::parse(body.as_bytes())
            .into_owned()
            .collect()
    }

    fn fragment_query_pairs(
        location: &str,
        expected_path: &str,
    ) -> Option<HashMap<String, String>> {
        let url = Url::parse(&format!("http://gateway.test{location}"))
            .expect("relative redirect location should parse against test origin");
        let fragment = url.fragment()?;
        let (path, query) = fragment.split_once('?')?;
        if path != expected_path {
            return None;
        }

        Some(form_pairs(query))
    }

    fn pkce_challenge_for_verifier(verifier: &str) -> String {
        base64url_no_padding(&Sha256::digest(verifier.as_bytes()))
    }

    fn base64url_no_padding(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut output = String::with_capacity((bytes.len() * 4).div_ceil(3));
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0];
            let b1 = chunk.get(1).copied().unwrap_or(0);
            let b2 = chunk.get(2).copied().unwrap_or(0);
            output.push(ALPHABET[(b0 >> 2) as usize] as char);
            output.push(ALPHABET[(((b0 & 0b0000_0011) << 4) | (b1 >> 4)) as usize] as char);
            if chunk.len() > 1 {
                output.push(ALPHABET[(((b1 & 0b0000_1111) << 2) | (b2 >> 6)) as usize] as char);
            }
            if chunk.len() > 2 {
                output.push(ALPHABET[(b2 & 0b0011_1111) as usize] as char);
            }
        }

        output
    }

    fn is_pkce_unreserved(value: &str) -> bool {
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
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

    async fn delayed_upstream(State(delay): State<Duration>) -> Response {
        tokio::time::sleep(delay).await;
        (StatusCode::CREATED, "slow upstream").into_response()
    }

    async fn spawn_delayed_upstream(delay: Duration) -> std::net::SocketAddr {
        spawn_router(
            Router::new()
                .fallback(any(delayed_upstream))
                .with_state(delay),
        )
        .await
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

    fn https_path_route(
        path_prefix: &str,
        upstream_addr: std::net::SocketAddr,
    ) -> config::UpstreamRouteConfig {
        let mut route = path_route(path_prefix, upstream_addr);
        route.upstream_url = format!("https://127.0.0.1:{}/ignored-base", upstream_addr.port());
        route
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
            timeout_ms: None,
            response_idle_timeout_ms: None,
            connect_timeout_ms: None,
            add_request_headers: HashMap::new(),
            strip_request_headers: Vec::new(),
            tls_ca_bundle_path: None,
            openapi_spec_path: None,
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
        assert_eq!(default_routes.policy_route, POLICY_ADMIN_ROUTE);
        assert_eq!(
            default_routes.policy_history_route,
            POLICY_HISTORY_ADMIN_ROUTE
        );
        assert_eq!(
            default_routes.policy_rollback_route,
            POLICY_ROLLBACK_ADMIN_ROUTE
        );
        assert_eq!(
            default_routes.policy_rule_preview_route,
            POLICY_RULE_PREVIEW_ADMIN_ROUTE
        );
        assert_eq!(
            default_routes.policy_rule_hits_route,
            POLICY_RULE_HITS_ADMIN_ROUTE
        );
        assert_eq!(
            default_routes.policy_rule_shadow_review_route,
            POLICY_RULE_SHADOW_REVIEW_ADMIN_ROUTE
        );
        assert_eq!(
            default_routes.policy_validate_route,
            POLICY_VALIDATE_ADMIN_ROUTE
        );
        assert_eq!(default_routes.policy_rules_route, POLICY_RULES_ADMIN_ROUTE);
        assert_eq!(default_routes.policy_rule_route, POLICY_RULE_ADMIN_ROUTE);
        assert_eq!(
            default_routes.policy_rules_order_route,
            POLICY_RULES_ORDER_ADMIN_ROUTE
        );
        assert_eq!(default_routes.tokens_route, TOKENS_ADMIN_ROUTE);
        assert_eq!(default_routes.token_route, TOKEN_ADMIN_ROUTE);
        assert_eq!(default_routes.token_rotate_route, TOKEN_ROTATE_ADMIN_ROUTE);
        assert_eq!(
            default_routes.tools_openapi_preview_route,
            TOOLS_OPENAPI_PREVIEW_ADMIN_ROUTE
        );
        assert_eq!(
            default_routes.tools_openapi_register_route,
            TOOLS_OPENAPI_REGISTER_ADMIN_ROUTE
        );
        assert_eq!(
            default_routes.schema_coverage_route,
            SCHEMA_COVERAGE_ADMIN_ROUTE
        );
        assert_eq!(
            default_routes.schema_inferred_route,
            SCHEMA_INFERRED_ADMIN_ROUTE
        );
        assert_eq!(default_routes.suggestions_route, SUGGESTIONS_ADMIN_ROUTE);
        assert_eq!(
            default_routes.suggestions_generate_route,
            SUGGESTIONS_GENERATE_ADMIN_ROUTE
        );
        assert_eq!(
            default_routes.suggestion_accept_route,
            SUGGESTION_ACCEPT_ADMIN_ROUTE
        );
        assert_eq!(
            default_routes.suggestion_dismiss_route,
            SUGGESTION_DISMISS_ADMIN_ROUTE
        );
        assert_eq!(
            default_routes.traffic_endpoints_route,
            TRAFFIC_ENDPOINTS_ADMIN_ROUTE
        );
        assert_eq!(
            default_routes.traffic_endpoint_detail_route,
            TRAFFIC_ENDPOINT_DETAIL_ADMIN_ROUTE
        );
        assert_eq!(
            default_routes.traffic_endpoint_review_route,
            TRAFFIC_ENDPOINT_REVIEW_ADMIN_ROUTE
        );
        assert_eq!(default_routes.principals_route, PRINCIPALS_ADMIN_ROUTE);
        assert_eq!(default_routes.principal_detail_route, PRINCIPAL_ADMIN_ROUTE);

        let custom_routes = AdminRoutes::from_prefix("/ops");
        assert_eq!(custom_routes.ui_prefix, "/ops");
        assert_eq!(custom_routes.api_prefix, "/v1/ops");
        assert_eq!(custom_routes.audit_route, "/v1/ops/audit");
        assert_eq!(custom_routes.events_stream_route, "/v1/ops/events/stream");
        assert_eq!(custom_routes.status_route, "/v1/ops/status");
        assert_eq!(custom_routes.policy_route, "/v1/ops/policy");
        assert_eq!(custom_routes.policy_history_route, "/v1/ops/policy/history");
        assert_eq!(
            custom_routes.policy_rollback_route,
            "/v1/ops/policy/rollback/{version}"
        );
        assert_eq!(
            custom_routes.policy_rule_preview_route,
            "/v1/ops/policy/rules/preview"
        );
        assert_eq!(
            custom_routes.policy_rule_hits_route,
            "/v1/ops/policy/rules/hits"
        );
        assert_eq!(
            custom_routes.policy_rule_shadow_review_route,
            "/v1/ops/policy/rules/shadow-review"
        );
        assert_eq!(
            custom_routes.policy_validate_route,
            "/v1/ops/policy/validate"
        );
        assert_eq!(custom_routes.policy_rules_route, "/v1/ops/policy/rules");
        assert_eq!(custom_routes.policy_rule_route, "/v1/ops/policy/rules/{id}");
        assert_eq!(
            custom_routes.policy_rules_order_route,
            "/v1/ops/policy/rules/order"
        );
        assert_eq!(custom_routes.tokens_route, "/v1/ops/tokens");
        assert_eq!(custom_routes.token_route, "/v1/ops/tokens/{id}");
        assert_eq!(
            custom_routes.token_rotate_route,
            "/v1/ops/tokens/{id}/rotate"
        );
        assert_eq!(
            custom_routes.tools_openapi_preview_route,
            "/v1/ops/tools/openapi/preview"
        );
        assert_eq!(
            custom_routes.tools_openapi_register_route,
            "/v1/ops/tools/openapi/register"
        );
        assert_eq!(
            custom_routes.schema_coverage_route,
            "/v1/ops/schema/coverage"
        );
        assert_eq!(
            custom_routes.schema_inferred_route,
            "/v1/ops/schema/inferred"
        );
        assert_eq!(custom_routes.suggestions_route, "/v1/ops/suggestions");
        assert_eq!(
            custom_routes.suggestions_generate_route,
            "/v1/ops/suggestions/generate"
        );
        assert_eq!(
            custom_routes.suggestion_accept_route,
            "/v1/ops/suggestions/{id}/accept"
        );
        assert_eq!(
            custom_routes.suggestion_dismiss_route,
            "/v1/ops/suggestions/{id}/dismiss"
        );
        assert_eq!(
            custom_routes.traffic_endpoints_route,
            "/v1/ops/traffic/endpoints"
        );
        assert_eq!(
            custom_routes.traffic_endpoint_detail_route,
            "/v1/ops/traffic/endpoint"
        );
        assert_eq!(
            custom_routes.traffic_endpoint_review_route,
            "/v1/ops/traffic/endpoints/review"
        );
        assert_eq!(custom_routes.principals_route, "/v1/ops/principals");
        assert_eq!(custom_routes.principal_detail_route, "/v1/ops/principal");
    }

    #[tokio::test]
    async fn default_admin_listener_unset_builds_single_router_with_data_and_admin_routes() {
        let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        let config = status_config_with_policy(config, &policy);

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
        let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
        config = status_config_with_policy(config, &policy);
        configure_test_jwt_provider(&mut config, jwks_addr);
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
        configure_test_jwt_provider(&mut config, jwks_addr);
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
    async fn proxy_path_ending_in_openapi_preview_does_not_get_preview_content_type_exception() {
        let (upstream_addr, mut captured) = spawn_capture_upstream().await;
        let mut config = proxy_config(upstream_addr);
        config.validation_allowed_content_types = vec!["application/json".to_owned()];
        let router = proxy_router(config, test_audit_log());

        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/some/other/prefix/tools/openapi/preview")
                    .header(header::CONTENT_TYPE, "application/yaml")
                    .body(Body::from("openapi: 3.0.3"))
                    .expect("proxy request should build"),
            )
            .await
            .expect("proxy request should complete");

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_upstream_receives_no_request(
            &mut captured,
            "content-type validation should reject suffix-confused proxy path",
        )
        .await;
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
    async fn routing_table_applies_distinct_timeout_per_upstream_route() {
        let short_addr = spawn_delayed_upstream(Duration::from_millis(250)).await;
        let long_addr = spawn_delayed_upstream(Duration::from_millis(250)).await;
        let mut short_route = path_route("/short", short_addr);
        short_route.timeout_ms = Some(75);
        let mut long_route = path_route("/long", long_addr);
        long_route.timeout_ms = Some(1_000);
        let router = proxy_router(
            routing_proxy_config(vec![short_route, long_route]),
            test_audit_log(),
        );

        let short_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/short/slow")
                    .body(Body::empty())
                    .expect("short-timeout request should build"),
            )
            .await
            .expect("short-timeout proxy request should complete");
        assert_eq!(short_response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(
            body_string(short_response).await,
            r#"{"error":"gateway_timeout"}"#
        );

        let long_response = router
            .oneshot(
                Request::builder()
                    .uri("/long/slow")
                    .body(Body::empty())
                    .expect("long-timeout request should build"),
            )
            .await
            .expect("long-timeout proxy request should complete");
        assert_eq!(long_response.status(), StatusCode::CREATED);
        assert_eq!(body_string(long_response).await, "slow upstream");
    }

    #[tokio::test]
    async fn routing_table_adds_configured_request_headers_per_route() {
        let (upstream_addr, mut captured) = spawn_capture_upstream().await;
        let mut route = path_route("/api", upstream_addr);
        route.add_request_headers =
            HashMap::from([("x-route-added".to_owned(), "route-added-value".to_owned())]);
        let router = proxy_router(routing_proxy_config(vec![route]), test_audit_log());

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/headers")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("proxy request should complete");

        assert_eq!(response.status(), StatusCode::CREATED);
        let upstream =
            next_proxied_request(&mut captured, "upstream should receive proxied request").await;
        assert_eq!(
            upstream.headers.get("x-route-added"),
            Some(&HeaderValue::from_static("route-added-value"))
        );
    }

    #[tokio::test]
    async fn routing_table_strips_configured_request_headers_without_breaking_request_id() {
        let (upstream_addr, mut captured) = spawn_capture_upstream().await;
        let mut route = path_route("/api", upstream_addr);
        route.strip_request_headers = vec!["x-client-secret".to_owned()];
        let router = proxy_router(routing_proxy_config(vec![route]), test_audit_log());
        let request_id = HeaderValue::from_static("route-strip-request-id");

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/headers")
                    .header(REQUEST_ID_HEADER, request_id.clone())
                    .header("x-client-secret", "remove-me")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("proxy request should complete");

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers().get(REQUEST_ID_HEADER), Some(&request_id));
        let upstream =
            next_proxied_request(&mut captured, "upstream should receive proxied request").await;
        assert!(!upstream.headers.contains_key("x-client-secret"));
        assert_eq!(upstream.headers.get(REQUEST_ID_HEADER), Some(&request_id));
    }

    #[tokio::test]
    async fn routing_table_tls_ca_bundle_is_applied_only_to_configured_route() {
        let mut trusted_upstream = spawn_tls_capture_upstream().await;
        let mut untrusted_upstream = spawn_tls_capture_upstream().await;
        let ca_bundle_path =
            std::env::temp_dir().join(format!("greengateway-test-ca-{}.pem", uuid::Uuid::new_v4()));
        fs::write(&ca_bundle_path, trusted_upstream.ca_pem.as_bytes())
            .expect("test CA bundle should be written");

        let mut trusted_route = https_path_route("/trusted", trusted_upstream.addr);
        trusted_route.tls_ca_bundle_path = Some(ca_bundle_path.clone());
        trusted_route.timeout_ms = Some(1_000);
        let mut untrusted_route = https_path_route("/untrusted", untrusted_upstream.addr);
        untrusted_route.timeout_ms = Some(1_000);
        let router = proxy_router(
            routing_proxy_config(vec![trusted_route, untrusted_route]),
            test_audit_log(),
        );

        let trusted_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/trusted/tls")
                    .body(Body::empty())
                    .expect("trusted TLS request should build"),
            )
            .await
            .expect("trusted TLS proxy request should complete");
        assert_eq!(trusted_response.status(), StatusCode::CREATED);
        assert_eq!(body_string(trusted_response).await, "tls upstream");
        let trusted_request = next_proxied_request(
            &mut trusted_upstream.captured,
            "trusted TLS upstream should receive request",
        )
        .await;
        assert_eq!(trusted_request.path_and_query, "/trusted/tls");

        let untrusted_response = router
            .oneshot(
                Request::builder()
                    .uri("/untrusted/tls")
                    .body(Body::empty())
                    .expect("untrusted TLS request should build"),
            )
            .await
            .expect("untrusted TLS proxy request should complete");
        assert_eq!(untrusted_response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            body_string(untrusted_response).await,
            r#"{"error":"bad_gateway"}"#
        );
        assert_upstream_receives_no_request(
            &mut untrusted_upstream.captured,
            "untrusted TLS route should fail during handshake before HTTP request",
        )
        .await;

        let _ = fs::remove_file(ca_bundle_path);
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
        let egress_client = Arc::new(
            egress::EgressClient::new(egress::EgressConfig::default())
                .expect("egress client should build"),
        );
        let proxy = ProxyState {
            routes: ProxyRoutes::RoutingTable {
                routes: vec![
                    ProxyRoute {
                        path_prefix: Some("/api".to_owned()),
                        host: None,
                        upstream_origin: "https://first.example.test".to_owned(),
                        request_header_policy: RouteRequestHeaderPolicy::default(),
                        egress_client: Arc::clone(&egress_client),
                    },
                    ProxyRoute {
                        path_prefix: Some("/api".to_owned()),
                        host: None,
                        upstream_origin: "https://second.example.test".to_owned(),
                        request_header_policy: RouteRequestHeaderPolicy::default(),
                        egress_client: Arc::clone(&egress_client),
                    },
                ],
            },
            upstream_health: Vec::new(),
            egress_client,
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
        let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
        config.admin_prefix = "/ops".to_owned();
        config.auth_exempt_paths = vec![
            "/health".to_owned(),
            "/version".to_owned(),
            "/metrics".to_owned(),
            "/ops".to_owned(),
        ];
        config.rbac_exempt_paths = config.auth_exempt_paths.clone();
        config = status_config_with_policy(config, &policy);
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
        let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
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
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        configure_test_jwt_provider(&mut config, jwks_addr);
        config.egress_deny_private_ips = false;
        let routes = GatewayRoutes::from_config(&config);
        config
            .rbac_exempt_paths
            .push(routes.admin.audit_route.clone());
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
    async fn real_service_token_authenticates_through_full_stack() {
        let token_db = TempDb::new("service-token-full-stack");
        let token_store =
            auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
        let created = token_store
            .create(auth::tokens::CreateTokenRequest {
                scopes: vec!["probe-reader".to_owned()],
                created_by: "bootstrap-admin".to_owned(),
                expires_at: None,
            })
            .expect("service token should create");
        let policy = TempPolicyFile::new(&service_token_policy_document());
        let mut config = test_config(Vec::new());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
        config.service_token_cache_ttl_ms = 20;
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");

        let response = authenticated_principal_probe(&router, &created.plaintext_token).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(
            body["user_id"],
            json!(format!("service-token:{}", created.record.id))
        );
        assert_eq!(body["auth_method"], json!("service_token"));
        assert_eq!(body["roles"], json!(["probe-reader"]));
    }

    #[tokio::test]
    async fn mcp_initialize_handshake_succeeds() {
        let harness = mcp_test_harness(&["admin"], test_audit_log()).await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            1,
            "initialize",
            Some(mcp_initialize_params()),
            "mcp-init-request",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["jsonrpc"], json!("2.0"));
        assert_eq!(body["id"], json!(1));
        assert_eq!(body["result"]["serverInfo"]["name"], json!("greengateway"));
        assert_eq!(body["result"]["capabilities"]["tools"], json!({}));
    }

    #[tokio::test]
    async fn mcp_path_prefixed_public_url_serves_advertised_resource_route() {
        let harness = mcp_test_harness_with_public_url(
            &["admin"],
            test_audit_log(),
            "https://gateway.example.test/base",
        )
        .await;

        let response = harness
            .router
            .clone()
            .oneshot(mcp_request_to(
                "/base/mcp",
                Some(&harness.admin_token),
                1,
                "initialize",
                Some(mcp_initialize_params()),
                "mcp-prefixed-init-request",
            ))
            .await
            .expect("prefixed MCP request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["jsonrpc"], json!("2.0"));
        assert_eq!(body["id"], json!(1));
        assert_eq!(body["result"]["serverInfo"]["name"], json!("greengateway"));
    }

    #[tokio::test]
    async fn oauth_protected_resource_metadata_returns_mcp_resource_document() {
        let mut config = test_config(Vec::new());
        config.gateway_public_url = Some("https://gateway.example.test/base/".to_owned());
        config.auth_providers = vec![config::AuthProviderConfig {
            name: "oidc".to_owned(),
            provider_type: config::AuthProviderType::Jwt,
            jwks_url: Some("https://auth.example.test/.well-known/jwks.json".to_owned()),
            issuer: Some("https://auth.example.test/".to_owned()),
            audience: None,
            jwks_timeout_ms: config.jwt_jwks_timeout_ms,
            require_jti: false,
            roles_claim: "roles".to_owned(),
            roles_claim_delimiter: None,
            org_claim: None,
            introspection_url: None,
            introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
            cache_ttl_ms: config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
            user_id_claim: None,
            email_claim: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
        }];
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");

        let response = router
            .oneshot(
                Request::builder()
                    .uri(auth::protected_resource::WELL_KNOWN_PATH)
                    .body(Body::empty())
                    .expect("metadata request should build"),
            )
            .await
            .expect("metadata request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(
            body,
            json!({
                "resource": "https://gateway.example.test/base/mcp",
                "authorization_servers": ["https://auth.example.test"],
                "scopes_supported": ["mcp:tools"],
                "bearer_methods_supported": ["header"]
            })
        );
    }

    #[tokio::test]
    async fn oauth_protected_resource_metadata_serves_rfc9728_path_for_mcp_resource_path() {
        let mut config = test_config(Vec::new());
        config.gateway_public_url = Some("https://gateway.example.test/base".to_owned());
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/.well-known/oauth-protected-resource/base/mcp")
                    .body(Body::empty())
                    .expect("metadata request should build"),
            )
            .await
            .expect("metadata request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(
            body["resource"],
            json!("https://gateway.example.test/base/mcp")
        );
    }

    #[tokio::test]
    async fn oauth_protected_resource_metadata_returns_clear_not_configured_error() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            test_config(Vec::new()),
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");

        let response = router
            .oneshot(
                Request::builder()
                    .uri(auth::protected_resource::WELL_KNOWN_PATH)
                    .body(Body::empty())
                    .expect("metadata request should build"),
            )
            .await
            .expect("metadata request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_string(response).await,
            r#"{"error":"OAuth protected-resource metadata requires GATEWAY_PUBLIC_URL to be configured"}"#
        );
    }

    #[tokio::test]
    async fn mcp_unauthorized_challenge_includes_resource_metadata_for_prefixed_route() {
        let mut config = test_config(Vec::new());
        config.gateway_public_url = Some("https://gateway.example.test/base".to_owned());
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/base/mcp")
                    .body(Body::empty())
                    .expect("prefixed MCP request should build"),
            )
            .await
            .expect("prefixed MCP request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE),
            Some(&HeaderValue::from_static(
                "Bearer realm=\"mcp\", resource_metadata=\"https://gateway.example.test/.well-known/oauth-protected-resource/base/mcp\""
            ))
        );
    }

    #[tokio::test]
    async fn mcp_unauthorized_challenge_includes_resource_metadata_only_for_mcp() {
        let mut config = test_config(Vec::new());
        config.gateway_public_url = Some("https://gateway.example.test".to_owned());
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");

        let mcp_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(auth::protected_resource::MCP_RESOURCE_PATH)
                    .body(Body::empty())
                    .expect("MCP request should build"),
            )
            .await
            .expect("MCP request should complete");

        assert_eq!(mcp_response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            mcp_response.headers().get(header::WWW_AUTHENTICATE),
            Some(&HeaderValue::from_static(
                "Bearer realm=\"mcp\", resource_metadata=\"https://gateway.example.test/.well-known/oauth-protected-resource/mcp\""
            ))
        );

        let non_mcp_response = router
            .oneshot(
                Request::builder()
                    .uri("/__test/principal")
                    .body(Body::empty())
                    .expect("non-MCP request should build"),
            )
            .await
            .expect("non-MCP request should complete");

        assert_eq!(non_mcp_response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            non_mcp_response.headers().get(header::WWW_AUTHENTICATE),
            Some(&HeaderValue::from_static("Bearer"))
        );
    }

    #[tokio::test]
    async fn mcp_unauthorized_challenge_inserts_metadata_path_before_mcp_resource_path() {
        let mut config = test_config(Vec::new());
        config.gateway_public_url = Some("https://gateway.example.test/base".to_owned());
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");

        let response = router
            .oneshot(
                Request::builder()
                    // Bare /mcp remains a compatibility route even when the
                    // public resource URL is advertised under /base/mcp.
                    .uri(auth::protected_resource::MCP_RESOURCE_PATH)
                    .body(Body::empty())
                    .expect("MCP request should build"),
            )
            .await
            .expect("MCP request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE),
            Some(&HeaderValue::from_static(
                "Bearer realm=\"mcp\", resource_metadata=\"https://gateway.example.test/.well-known/oauth-protected-resource/base/mcp\""
            ))
        );
    }

    #[tokio::test]
    async fn mcp_jwt_requires_resource_audience_when_public_url_is_configured() {
        let jwks_addr = spawn_test_jwks_server().await;
        let mut config = test_config(Vec::new());
        config.gateway_public_url = Some("https://gateway.example.test".to_owned());
        configure_test_jwt_provider(&mut config, jwks_addr);
        config.egress_deny_private_ips = false;
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");

        let missing_audience = signed_token("mcp-missing-audience", &["member"]);
        let (missing_status, _) = mcp_rpc(
            &router,
            Some(&missing_audience),
            91,
            "initialize",
            Some(mcp_initialize_params()),
            "mcp-missing-audience",
        )
        .await;
        assert_eq!(missing_status, StatusCode::UNAUTHORIZED);

        let wrong_audience = signed_token_with_claims(json!({
            "sub": "mcp-wrong-audience",
            "email": "mcp-wrong-audience@example.test",
            "exp": OffsetDateTime::now_utc().unix_timestamp() + 3600,
            "jti": "mcp-wrong-audience-session",
            "roles": ["member"],
            "aud": "https://other-api.example.test"
        }));
        let (wrong_status, _) = mcp_rpc(
            &router,
            Some(&wrong_audience),
            92,
            "initialize",
            Some(mcp_initialize_params()),
            "mcp-wrong-audience",
        )
        .await;
        assert_eq!(wrong_status, StatusCode::UNAUTHORIZED);

        let matching_audience = signed_token_with_claims(json!({
            "sub": "mcp-matching-audience",
            "email": "mcp-matching-audience@example.test",
            "exp": OffsetDateTime::now_utc().unix_timestamp() + 3600,
            "jti": "mcp-matching-audience-session",
            "roles": ["member"],
            "aud": ["https://other-api.example.test", "https://gateway.example.test/mcp"]
        }));
        let (matching_status, body) = mcp_rpc(
            &router,
            Some(&matching_audience),
            93,
            "initialize",
            Some(mcp_initialize_params()),
            "mcp-matching-audience",
        )
        .await;

        assert_eq!(matching_status, StatusCode::OK);
        assert_eq!(body["result"]["serverInfo"]["name"], json!("greengateway"));
    }

    #[tokio::test]
    async fn mcp_service_token_requires_mcp_scope_when_public_url_is_configured() {
        let token_db = TempDb::new("mcp-resource-service-token");
        let token_store =
            auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
        let token_without_mcp_scope = create_service_token(&token_store, &["admin"]);
        let token_with_mcp_scope = create_service_token(&token_store, &["admin", "mcp:tools"]);
        let mut config = test_config(Vec::new());
        config.gateway_public_url = Some("https://gateway.example.test".to_owned());
        config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
        config.service_token_cache_ttl_ms = 20;
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");

        let (missing_scope_status, missing_scope_body) = mcp_rpc(
            &router,
            Some(&token_without_mcp_scope),
            94,
            "initialize",
            Some(mcp_initialize_params()),
            "mcp-service-token-missing-scope",
        )
        .await;
        assert_eq!(missing_scope_status, StatusCode::UNAUTHORIZED);
        assert_eq!(missing_scope_body, json!({ "error": "unauthorized" }));

        let non_mcp_response =
            authenticated_principal_probe(&router, &token_without_mcp_scope).await;
        assert_eq!(non_mcp_response.status(), StatusCode::OK);
        let non_mcp_body = json_body(non_mcp_response).await;
        assert_eq!(non_mcp_body["auth_method"], json!("service_token"));
        assert_eq!(non_mcp_body["roles"], json!(["admin"]));

        let (matching_scope_status, matching_scope_body) = mcp_rpc(
            &router,
            Some(&token_with_mcp_scope),
            95,
            "initialize",
            Some(mcp_initialize_params()),
            "mcp-service-token-matching-scope",
        )
        .await;

        assert_eq!(matching_scope_status, StatusCode::OK);
        assert_eq!(
            matching_scope_body["result"]["serverInfo"]["name"],
            json!("greengateway")
        );
    }

    #[tokio::test]
    async fn mcp_cookie_session_is_rejected_when_public_url_is_configured() {
        let (introspection_url, introspection_server) =
            spawn_blocking_cookie_session_server(Ipv4Addr::LOCALHOST, 1);
        let mut config = test_config(Vec::new());
        config.gateway_public_url = Some("https://gateway.example.test".to_owned());
        configure_test_cookie_session_provider(&mut config, introspection_url);
        config.egress_deny_private_ips = false;
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");

        let mcp_response = router
            .clone()
            .oneshot(mcp_cookie_request(
                "session=session-secret-123",
                96,
                "initialize",
                Some(mcp_initialize_params()),
                "mcp-cookie-session",
            ))
            .await
            .expect("MCP cookie request should complete");

        assert_eq!(mcp_response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            json_body(mcp_response).await,
            json!({ "error": "unauthorized" })
        );

        let non_mcp_response = router
            .oneshot(
                Request::builder()
                    .uri("/__test/principal")
                    .header(header::COOKIE, "session=session-secret-123")
                    .body(Body::empty())
                    .expect("non-MCP cookie request should build"),
            )
            .await
            .expect("non-MCP cookie request should complete");

        assert_eq!(non_mcp_response.status(), StatusCode::OK);
        let non_mcp_body = json_body(non_mcp_response).await;
        assert_eq!(non_mcp_body["user_id"], json!("cookie-user"));
        assert_eq!(non_mcp_body["auth_method"], json!("session_cookie"));
        assert_eq!(
            introspection_server
                .join()
                .expect("cookie-session introspection server should finish"),
            1
        );
    }

    #[tokio::test]
    async fn mcp_tools_list_returns_registry_tools_and_schemas() {
        let harness = mcp_test_harness(&["admin"], test_audit_log()).await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            2,
            "tools/list",
            None,
            "mcp-list-request",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let tools = body["result"]["tools"]
            .as_array()
            .expect("tools/list result should include tools array");
        let echo = tools
            .iter()
            .find(|tool| tool["name"] == json!("echo"))
            .expect("echo tool should be listed");
        let widget = tools
            .iter()
            .find(|tool| tool["name"] == json!("get_widget"))
            .expect("get_widget tool should be listed");

        assert_eq!(
            echo["description"],
            json!("Echoes a message through a generic upstream endpoint.")
        );
        assert_eq!(echo["inputSchema"]["required"], json!(["message"]));
        assert_eq!(
            echo["inputSchema"]["properties"]["message"]["type"],
            json!("string")
        );
        assert_eq!(widget["inputSchema"]["required"], json!(["widget_id"]));
        assert_eq!(
            widget["inputSchema"]["properties"]["include_details"]["type"],
            json!("boolean")
        );
    }

    #[tokio::test]
    async fn mcp_tools_list_filters_tools_by_allowed_roles() {
        let harness = mcp_test_harness(&[], test_audit_log()).await;

        let (reader_status, reader_body) = mcp_rpc(
            &harness.router,
            Some(&harness.reader_token),
            11,
            "tools/list",
            None,
            "mcp-list-reader",
        )
        .await;
        assert_eq!(reader_status, StatusCode::OK);
        let reader_tools = reader_body["result"]["tools"]
            .as_array()
            .expect("tools/list result should include tools array");
        assert!(
            reader_tools
                .iter()
                .any(|tool| tool["name"] == json!("echo")),
            "unrestricted tool should be listed"
        );
        assert!(
            !reader_tools
                .iter()
                .any(|tool| tool["name"] == json!("get_widget")),
            "admin-only tool should not be listed to reader"
        );

        let (admin_status, admin_body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            12,
            "tools/list",
            None,
            "mcp-list-admin",
        )
        .await;
        assert_eq!(admin_status, StatusCode::OK);
        let admin_tools = admin_body["result"]["tools"]
            .as_array()
            .expect("tools/list result should include tools array");
        assert!(
            admin_tools
                .iter()
                .any(|tool| tool["name"] == json!("get_widget")),
            "matching role should see role-restricted tool"
        );
    }

    #[tokio::test]
    async fn mcp_tools_list_follows_live_tool_enabled_and_membership_policy() {
        let harness = mcp_test_harness(&["admin"], test_audit_log()).await;

        let (before_status, before_body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            53,
            "tools/list",
            None,
            "mcp-list-before-tool-membership-reload",
        )
        .await;
        assert_eq!(before_status, StatusCode::OK);
        let before_tools = before_body["result"]["tools"]
            .as_array()
            .expect("tools/list result should include tools array");
        assert!(before_tools
            .iter()
            .any(|tool| tool["name"] == json!("echo")));
        assert!(before_tools
            .iter()
            .any(|tool| tool["name"] == json!("get_widget")));

        let current_policy = rbac::Policy::from_file(&harness._policy.path)
            .expect("current MCP policy should parse");
        let etag = policy_etag(&current_policy).expect("current MCP policy ETag should compute");
        let mut policy =
            serde_json::to_value(&current_policy).expect("current MCP policy should serialize");
        policy["tools"]["echo"]["enabled"] = json!(false);
        policy["tools"]
            .as_object_mut()
            .expect("tools policy should be an object")
            .remove("get_widget");

        let put_response = harness
            .router
            .clone()
            .oneshot(authenticated_json_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                &harness.admin_token,
                Some(policy.to_string()),
                Some(&etag),
            ))
            .await
            .expect("policy PUT should complete");
        assert_eq!(put_response.status(), StatusCode::OK);

        let (after_status, after_body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            54,
            "tools/list",
            None,
            "mcp-list-after-tool-membership-reload",
        )
        .await;
        assert_eq!(after_status, StatusCode::OK);
        let after_tools = after_body["result"]["tools"]
            .as_array()
            .expect("tools/list result should include tools array");
        assert!(
            !after_tools.iter().any(|tool| tool["name"] == json!("echo")),
            "disabled echo tool should not be listed after policy reload: {after_body}"
        );
        assert!(
            !after_tools
                .iter()
                .any(|tool| tool["name"] == json!("get_widget")),
            "removed get_widget tool should not be listed after policy reload: {after_body}"
        );
    }

    #[tokio::test]
    async fn mcp_route_rejects_missing_authentication_and_missing_permission() {
        let harness = mcp_test_harness(&["admin"], test_audit_log()).await;

        let (missing_status, missing_body) = mcp_rpc(
            &harness.router,
            None,
            3,
            "tools/list",
            None,
            "mcp-missing-auth",
        )
        .await;
        assert_eq!(missing_status, StatusCode::UNAUTHORIZED);
        assert_eq!(missing_body, json!({ "error": "unauthorized" }));

        let (forbidden_status, forbidden_body) = mcp_rpc(
            &harness.router,
            Some(&harness.blocked_token),
            4,
            "tools/list",
            None,
            "mcp-forbidden",
        )
        .await;
        assert_eq!(forbidden_status, StatusCode::FORBIDDEN);
        assert_eq!(forbidden_body, json!({ "error": "forbidden" }));
    }

    #[tokio::test]
    async fn mcp_tools_call_echo_succeeds() {
        let harness = mcp_test_harness(&["admin"], test_audit_log()).await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            5,
            "tools/call",
            Some(json!({
                "name": "echo",
                "arguments": {
                    "message": "hello from mcp"
                }
            })),
            "mcp-call-success",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["error"], Value::Null);
        assert_eq!(body["result"]["isError"], json!(false));
        assert_eq!(body["result"]["structuredContent"]["status"], json!(200));
        assert_eq!(
            body["result"]["structuredContent"]["body"],
            json!({ "message": "hello from mcp" })
        );
    }

    #[tokio::test]
    async fn mcp_tool_name_rules_follow_policy_admin_reload() {
        let harness = mcp_test_harness(&["admin"], test_audit_log()).await;

        let (before_status, before_body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            51,
            "tools/call",
            Some(json!({
                "name": "echo",
                "arguments": {
                    "message": "before reload"
                }
            })),
            "mcp-call-before-tool-rule-reload",
        )
        .await;

        assert_eq!(before_status, StatusCode::OK);
        assert_eq!(before_body["error"], Value::Null);
        assert_eq!(before_body["result"]["isError"], json!(false));

        let current_policy = rbac::Policy::from_file(&harness._policy.path)
            .expect("current MCP policy should parse");
        let etag = policy_etag(&current_policy).expect("current MCP policy ETag should compute");
        let mut policy =
            serde_json::to_value(&current_policy).expect("current MCP policy should serialize");
        policy["rules"] = json!([
            {
                "id": "deny-echo-after-reload",
                "tool_name": "echo",
                "principal": {
                    "roles": ["admin"]
                },
                "action": "deny"
            }
        ]);

        let put_response = harness
            .router
            .clone()
            .oneshot(authenticated_json_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                &harness.admin_token,
                Some(policy.to_string()),
                Some(&etag),
            ))
            .await
            .expect("policy PUT should complete");
        assert_eq!(put_response.status(), StatusCode::OK);

        let (after_status, after_body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            52,
            "tools/call",
            Some(json!({
                "name": "echo",
                "arguments": {
                    "message": "after reload"
                }
            })),
            "mcp-call-after-tool-rule-reload",
        )
        .await;

        assert_eq!(after_status, StatusCode::OK);
        assert_eq!(after_body["error"]["code"], json!(-32001));
        assert_eq!(after_body["error"]["data"]["tool_name"], json!("echo"));
        assert_eq!(after_body["error"]["data"]["reason"], json!("matched_rule"));
    }

    #[tokio::test]
    async fn mcp_tools_call_get_widget_succeeds() {
        let harness = mcp_test_harness(&["admin"], test_audit_log()).await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            10,
            "tools/call",
            Some(json!({
                "name": "get_widget",
                "arguments": {
                    "widget_id": "widget-123",
                    "include_details": true
                }
            })),
            "mcp-call-widget-success",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["error"], Value::Null);
        assert_eq!(body["result"]["isError"], json!(false));
        assert_eq!(body["result"]["structuredContent"]["status"], json!(200));
        assert_eq!(
            body["result"]["structuredContent"]["body"],
            json!({
                "widget_id": "widget-123",
                "include_details": true
            })
        );
    }

    #[tokio::test]
    async fn mcp_tools_call_errors_are_mapped_to_json_rpc_errors() {
        let harness = mcp_test_harness(&["admin"], test_audit_log()).await;

        let (unknown_status, unknown_body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            6,
            "tools/call",
            Some(json!({
                "name": "missing_tool",
                "arguments": {}
            })),
            "mcp-call-unknown",
        )
        .await;
        assert_eq!(unknown_status, StatusCode::OK);
        assert_eq!(unknown_body["error"]["code"], json!(-32601));
        assert_eq!(
            unknown_body["error"]["message"],
            json!("tool 'missing_tool' is not defined")
        );
        assert_eq!(
            unknown_body["error"]["data"]["tool_name"],
            json!("missing_tool")
        );

        let (schema_status, schema_body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            7,
            "tools/call",
            Some(json!({
                "name": "echo",
                "arguments": {}
            })),
            "mcp-call-schema",
        )
        .await;
        assert_eq!(schema_status, StatusCode::OK);
        assert_eq!(schema_body["error"]["code"], json!(-32602));
        assert_eq!(schema_body["error"]["data"]["tool_name"], json!("echo"));
        assert!(schema_body["error"]["message"]
            .as_str()
            .expect("invalid params error should include a message")
            .contains("failed input schema validation"));

        let (role_status, role_body) = mcp_rpc(
            &harness.router,
            Some(&harness.reader_token),
            8,
            "tools/call",
            Some(json!({
                "name": "echo",
                "arguments": {
                    "message": "reader should be denied by tool policy"
                }
            })),
            "mcp-call-role-denied",
        )
        .await;
        assert_eq!(role_status, StatusCode::OK);
        assert_eq!(role_body["error"]["code"], json!(-32001));
        assert_eq!(
            role_body["error"]["message"],
            json!("tool invocation is denied by role policy")
        );
        assert_eq!(role_body["error"]["data"]["tool_name"], json!("echo"));
        assert_eq!(role_body["error"]["data"]["reason"], json!("role_denied"));
    }

    #[tokio::test]
    async fn mcp_tools_call_transport_failure_uses_sanitized_error_reason() {
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
        let harness = mcp_test_harness_with_upstream_url(
            &["admin"],
            test_audit_log(),
            format!("http://{upstream_addr}"),
            mcp_tools_document(),
            vec!["127.0.0.1".to_owned()],
        )
        .await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            13,
            "tools/call",
            Some(json!({
                "name": "echo",
                "arguments": {
                    "message": "trigger reset"
                }
            })),
            "mcp-call-reset-upstream",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["error"]["code"], json!(-32603));
        assert_eq!(body["error"]["message"], json!("tool invocation failed"));
        assert_eq!(body["error"]["data"]["tool_name"], json!("echo"));
        assert_eq!(body["error"]["data"]["reason"], json!("http_error"));
        let body_string = body.to_string();
        assert!(!body_string.contains("127.0.0.1"));
        assert!(!body_string.contains(&upstream_addr.port().to_string()));
        assert!(!body_string.contains("connection"));
        assert!(!body_string.contains("reqwest"));
        assert!(!body_string.contains("error sending request"));
        server.abort();
    }

    #[tokio::test]
    async fn mcp_tools_call_sanitizes_non_success_upstream_error_body() {
        let upstream_addr = spawn_fixed_echo_upstream(
            StatusCode::BAD_REQUEST,
            "application/json",
            json!({
                "message": "validation failed against api.internal.example.test",
                "errors": [
                    {
                        "detail": "bad value used secret=gg_test_fake_secret_400"
                    }
                ],
                "debug": "stack trace from api.internal.example.test with gg_test_fake_secret_400"
            })
            .to_string(),
        )
        .await;
        let harness = mcp_test_harness_with_upstream_url(
            &["admin"],
            test_audit_log(),
            format!("http://{upstream_addr}"),
            mcp_tools_document(),
            vec!["127.0.0.1".to_owned()],
        )
        .await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            14,
            "tools/call",
            Some(json!({
                "name": "echo",
                "arguments": {
                    "message": "bad input"
                }
            })),
            "mcp-call-upstream-400",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["error"], Value::Null);
        assert_eq!(body["result"]["isError"], json!(true));
        assert_eq!(body["result"]["structuredContent"]["status"], json!(400));
        assert_eq!(
            body["result"]["structuredContent"]["body"]["message"],
            json!("validation failed against [redacted]")
        );
        assert_eq!(
            body["result"]["structuredContent"]["body"]["errors"][0]["detail"],
            json!("bad value used [redacted]")
        );
        let body_string = body.to_string();
        assert!(!body_string.contains("api.internal.example.test"));
        assert!(!body_string.contains("gg_test_fake_secret_400"));
        assert!(!body_string.contains("stack trace"));
        assert!(!mcp_content_text(&body).contains("api.internal.example.test"));
        assert!(!mcp_content_text(&body).contains("gg_test_fake_secret_400"));
    }

    #[tokio::test]
    async fn mcp_tools_call_plain_http_marker_header_is_not_trusted() {
        let upstream_addr = spawn_fixed_echo_upstream_with_headers(
            StatusCode::INTERNAL_SERVER_ERROR,
            "application/json",
            json!({
                "content": [{
                    "type": "text",
                    "text": "spoofed success from api.internal.example.test with secret=gg_test_fake_secret_spoof"
                }],
                "structuredContent": {
                    "summary": "spoofed success",
                    "leak": "api.internal.example.test"
                },
                "isError": false,
                "message": "upstream failed at api.internal.example.test with secret=gg_test_fake_secret_spoof"
            })
            .to_string(),
            vec![(crate::tools::mcp_upstream::MCP_CALL_TOOL_RESULT_HEADER, "call-tool-result")],
        )
        .await;
        let harness = mcp_test_harness_with_upstream_url(
            &["admin"],
            test_audit_log(),
            format!("http://{upstream_addr}"),
            mcp_tools_document(),
            vec!["127.0.0.1".to_owned()],
        )
        .await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            16,
            "tools/call",
            Some(json!({
                "name": "echo",
                "arguments": {
                    "message": "trigger spoofed marker"
                }
            })),
            "mcp-call-spoofed-marker",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["error"], Value::Null);
        assert_eq!(body["result"]["isError"], json!(true));
        assert_eq!(body["result"]["structuredContent"]["status"], json!(500));
        assert_eq!(
            body["result"]["structuredContent"]["body"]["message"],
            json!("upstream failed at [redacted] with [redacted]")
        );
        let body_string = body.to_string();
        assert!(!body_string.contains("spoofed success"));
        assert!(!body_string.contains("api.internal.example.test"));
        assert!(!body_string.contains("gg_test_fake_secret_spoof"));
    }

    #[tokio::test]
    async fn mcp_tools_call_success_body_is_forwarded_faithfully() {
        let upstream_body = json!({
            "message": "ok",
            "diagnostic": "api.internal.example.test",
            "marker": "gg_test_fake_secret_success"
        });
        let upstream_addr = spawn_fixed_echo_upstream(
            StatusCode::OK,
            "application/json",
            upstream_body.to_string(),
        )
        .await;
        let harness = mcp_test_harness_with_upstream_url(
            &["admin"],
            test_audit_log(),
            format!("http://{upstream_addr}"),
            mcp_tools_document(),
            vec!["127.0.0.1".to_owned()],
        )
        .await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            15,
            "tools/call",
            Some(json!({
                "name": "echo",
                "arguments": {
                    "message": "successful output"
                }
            })),
            "mcp-call-success-passthrough",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["error"], Value::Null);
        assert_eq!(body["result"]["isError"], json!(false));
        assert_eq!(body["result"]["structuredContent"]["status"], json!(200));
        assert_eq!(body["result"]["structuredContent"]["body"], upstream_body);
        assert!(mcp_content_text(&body).contains("api.internal.example.test"));
        assert!(mcp_content_text(&body).contains("gg_test_fake_secret_success"));
    }

    #[tokio::test]
    async fn mcp_tools_call_emits_http_observation_event() {
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let harness = mcp_test_harness(&["admin"], audit_log).await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            9,
            "tools/call",
            Some(json!({
                "name": "echo",
                "arguments": {
                    "message": "observe me"
                }
            })),
            "mcp-observed-request",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["result"]["isError"], json!(false));

        assert_eventually(Duration::from_secs(1), || {
            capture.events().iter().any(|event| {
                event.event_type == "http.request_observed"
                    && event.request_id == "mcp-observed-request"
                    && event.payload["path"] == json!(MCP_ROUTE)
                    && event.payload["method"] == json!("POST")
                    && event.payload["status"] == json!(200)
            })
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mcp_real_client_connects_lists_calls_and_records_observability() {
        let upstream_addr = spawn_echo_json_upstream().await;
        let harness = mcp_inventory_test_harness(McpInventoryHarnessConfig {
            upstream_url: Some(format!("http://{upstream_addr}")),
            tools_document: mcp_tools_document(),
            mcp_upstream_servers: Vec::new(),
            egress_allowed_hosts: vec!["127.0.0.1".to_owned()],
        })
        .await;
        let (gateway_addr, gateway_server) = spawn_gateway_router(harness.router.clone()).await;
        let request_id = "mcp-sdk-conformance";
        let custom_headers = HashMap::from([
            (
                HeaderName::from_static(REQUEST_ID_HEADER),
                HeaderValue::from_static(request_id),
            ),
            (
                header::COOKIE,
                HeaderValue::from_static("csrf_token=mcp-test-csrf"),
            ),
            (
                HeaderName::from_static("x-csrf-token"),
                HeaderValue::from_static("mcp-test-csrf"),
            ),
        ]);
        let transport = StreamableHttpClientTransport::from_config(
            StreamableHttpClientTransportConfig::with_uri(format!(
                "http://{gateway_addr}{MCP_ROUTE}"
            ))
            .auth_header(harness.admin_token.clone())
            .custom_headers(custom_headers),
        );
        let client = ().serve(transport).await.expect("rmcp client should initialize");

        let tools = client
            .list_all_tools()
            .await
            .expect("rmcp client should list tools");
        assert!(
            tools.iter().any(|tool| tool.name == "echo"),
            "rmcp tools/list should include echo: {tools:?}"
        );

        let arguments: RmcpJsonObject =
            serde_json::from_value(json!({ "message": "hello from real rmcp client" }))
                .expect("tool arguments should be a JSON object");
        let result = client
            .call_tool(RmcpCallToolRequestParams::new("echo").with_arguments(arguments))
            .await
            .expect("rmcp client should call echo");
        assert_eq!(result.is_error, Some(false));
        assert_eq!(
            result.structured_content,
            Some(json!({
                "status": 200,
                "body": {
                    "message": "hello from real rmcp client"
                }
            }))
        );

        assert_eventually(Duration::from_secs(2), || {
            let events = harness.capture.events();
            let has_start = events.iter().any(|event| {
                event.event_type == audit::event::TOOL_INVOKE_START
                    && event.request_id == request_id
                    && event.payload["tool_name"] == json!("echo")
            });
            let has_success = events.iter().any(|event| {
                event.event_type == audit::event::TOOL_INVOKE_SUCCESS
                    && event.request_id == request_id
                    && event.payload["tool_name"] == json!("echo")
            });
            let has_tool_observation = events.iter().any(|event| {
                event.event_type == "http.request_observed"
                    && event.request_id == request_id
                    && event.payload["method"] == json!("MCP")
                    && event.payload["path"] == json!("/mcp/tools/echo")
                    && event.payload["status"] == json!(200)
            });

            has_start && has_success && has_tool_observation
        });

        let row =
            wait_for_mcp_tool_inventory_row(&harness.router, &harness.admin_token, "echo", |row| {
                row["call_count"] == json!(1) && status_count(row, 200) == Some(1)
            })
            .await;
        assert_eq!(row["method"], json!("MCP"));
        assert_eq!(row["endpoint_template"], json!("/mcp/tools/echo"));
        assert_eq!(row["call_count"], json!(1));
        assert_eq!(row["schema_mismatch_count"], json!(0));
        assert_eq!(row["distinct_principal_count"], json!(1));
        assert_eq!(status_count(&row, 200), Some(1));

        client
            .cancel()
            .await
            .expect("rmcp client should cancel cleanly");
        gateway_server.abort();
    }

    #[tokio::test]
    async fn successful_mcp_tool_call_appears_as_per_tool_traffic_inventory_row() {
        let upstream_addr = spawn_echo_json_upstream().await;
        let harness = mcp_inventory_test_harness(McpInventoryHarnessConfig {
            upstream_url: Some(format!("http://{upstream_addr}")),
            tools_document: mcp_tools_document(),
            mcp_upstream_servers: Vec::new(),
            egress_allowed_hosts: vec!["127.0.0.1".to_owned()],
        })
        .await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            30,
            "tools/call",
            Some(json!({
                "name": "echo",
                "arguments": {
                    "message": "inventory success"
                }
            })),
            "mcp-inventory-success",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["result"]["isError"], json!(false));

        let row =
            wait_for_mcp_tool_inventory_row(&harness.router, &harness.admin_token, "echo", |row| {
                row["call_count"] == json!(1) && status_count(row, 200) == Some(1)
            })
            .await;
        assert_eq!(row["method"], json!("MCP"));
        assert_eq!(row["endpoint_template"], json!("/mcp/tools/echo"));
        assert_eq!(row["call_count"], json!(1));
        assert_eq!(row["schema_mismatch_count"], json!(0));
        assert_eq!(row["distinct_principal_count"], json!(1));
        assert_eq!(status_count(&row, 200), Some(1));
        let open_signal_types = row["open_signals"]["signal_types"]
            .as_array()
            .expect("tool inventory row should include open signal types");
        assert!(
            open_signal_types
                .iter()
                .any(|signal_type| signal_type == "new_endpoint_seen"),
            "successful tool call should open a new_endpoint_seen signal: {row}"
        );
        assert!(row["latency"]["p50_ms"].as_u64().is_some());
        assert!(row["latency"]["p95_ms"].as_u64().is_some());
        assert!(row["latency"]["p99_ms"].as_u64().is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn proxied_mcp_tool_call_appears_as_per_tool_traffic_inventory_row() {
        let upstream = spawn_test_mcp_upstream("remote_echo").await;
        let harness = mcp_inventory_test_harness(McpInventoryHarnessConfig {
            upstream_url: None,
            tools_document: empty_tools_document(),
            mcp_upstream_servers: vec![config::McpUpstreamServerConfig {
                name: "alpha".to_owned(),
                url: upstream.url.clone(),
                timeout_ms: Some(2_000),
                response_idle_timeout_ms: Some(2_000),
                connect_timeout_ms: Some(2_000),
            }],
            egress_allowed_hosts: vec!["127.0.0.1".to_owned()],
        })
        .await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            31,
            "tools/call",
            Some(json!({
                "name": "alpha:remote_echo",
                "arguments": {
                    "message": "inventory proxied"
                }
            })),
            "mcp-inventory-proxied",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["result"]["isError"], json!(false));

        let row = wait_for_mcp_tool_inventory_row(
            &harness.router,
            &harness.admin_token,
            "alpha:remote_echo",
            |row| row["call_count"] == json!(1) && status_count(row, 200) == Some(1),
        )
        .await;
        assert_eq!(row["method"], json!("MCP"));
        assert_eq!(
            row["endpoint_template"],
            json!("/mcp/tools/alpha:remote_echo")
        );
        assert_eq!(row["call_count"], json!(1));
        assert_eq!(row["schema_mismatch_count"], json!(0));
        assert_eq!(status_count(&row, 200), Some(1));
    }

    #[tokio::test]
    async fn non_schema_mismatch_mcp_tool_failure_appears_as_error_inventory_row() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener should bind");
        let upstream_addr = listener
            .local_addr()
            .expect("listener address should be available");
        drop(listener);
        let harness = mcp_inventory_test_harness(McpInventoryHarnessConfig {
            upstream_url: Some(format!("http://{upstream_addr}")),
            tools_document: mcp_tools_document(),
            mcp_upstream_servers: Vec::new(),
            egress_allowed_hosts: vec!["127.0.0.1".to_owned()],
        })
        .await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            32,
            "tools/call",
            Some(json!({
                "name": "echo",
                "arguments": {
                    "message": "inventory failure"
                }
            })),
            "mcp-inventory-failure",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["error"]["code"], json!(-32603));

        let row =
            wait_for_mcp_tool_inventory_row(&harness.router, &harness.admin_token, "echo", |row| {
                row["call_count"] == json!(1) && status_count(row, 502) == Some(1)
            })
            .await;
        assert_eq!(row["method"], json!("MCP"));
        assert_eq!(row["endpoint_template"], json!("/mcp/tools/echo"));
        assert_eq!(row["call_count"], json!(1));
        assert_eq!(row["schema_mismatch_count"], json!(0));
        assert_eq!(status_count(&row, 502), Some(1));
    }

    #[tokio::test]
    async fn unknown_mcp_tool_call_appears_as_inventory_row() {
        let harness = mcp_inventory_test_harness(McpInventoryHarnessConfig {
            upstream_url: Some("http://127.0.0.1:1".to_owned()),
            tools_document: mcp_tools_document(),
            mcp_upstream_servers: Vec::new(),
            egress_allowed_hosts: vec!["127.0.0.1".to_owned()],
        })
        .await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            36,
            "tools/call",
            Some(json!({
                "name": "missing_tool",
                "arguments": {}
            })),
            "mcp-inventory-unknown-tool",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["error"]["code"], json!(-32601));
        assert_eq!(body["error"]["data"]["tool_name"], json!("missing_tool"));

        let row = wait_for_mcp_tool_inventory_row(
            &harness.router,
            &harness.admin_token,
            "missing_tool",
            |row| row["call_count"] == json!(1) && status_count(row, 404) == Some(1),
        )
        .await;
        assert_eq!(row["method"], json!("MCP"));
        assert_eq!(row["endpoint_template"], json!("/mcp/tools/missing_tool"));
        assert_eq!(row["call_count"], json!(1));
        assert_eq!(row["schema_mismatch_count"], json!(0));
        assert_eq!(row["distinct_principal_count"], json!(1));
        assert_eq!(status_count(&row, 404), Some(1));
    }

    #[tokio::test]
    async fn task_style_mcp_tool_call_is_rejected_by_gateway_and_records_inventory() {
        let harness = mcp_inventory_test_harness(McpInventoryHarnessConfig {
            upstream_url: Some("http://127.0.0.1:1".to_owned()),
            tools_document: mcp_tools_document(),
            mcp_upstream_servers: Vec::new(),
            egress_allowed_hosts: vec!["127.0.0.1".to_owned()],
        })
        .await;

        let request_id = "mcp-inventory-task-unsupported";
        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            37,
            "tools/call",
            Some(json!({
                "name": "echo",
                "arguments": {
                    "message": "task style"
                },
                "task": {}
            })),
            request_id,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["error"]["code"], json!(-32602));
        assert_eq!(
            body["error"]["message"],
            json!("task-based tool invocation is not supported by GreenGateway")
        );
        assert_eq!(body["error"]["data"]["tool_name"], json!("echo"));
        assert_eq!(body["error"]["data"]["reason"], json!("task_unsupported"));

        assert_eventually(Duration::from_secs(1), || {
            let events = harness.capture.events();
            let failure_seen = events.iter().any(|event| {
                event.event_type == audit::event::TOOL_INVOKE_FAILURE
                    && event.request_id == request_id
                    && event.payload["tool_name"] == json!("echo")
            });
            let observation_seen = events.iter().any(|event| {
                event.event_type == "http.request_observed"
                    && event.request_id == request_id
                    && event.payload["method"] == json!("MCP")
                    && event.payload["tool_name"] == json!("echo")
                    && event.payload["status"] == json!(400)
                    && event.payload["reason"] == json!("task_unsupported")
            });
            failure_seen && observation_seen
        });

        let row =
            wait_for_mcp_tool_inventory_row(&harness.router, &harness.admin_token, "echo", |row| {
                row["call_count"] == json!(1) && status_count(row, 400) == Some(1)
            })
            .await;
        assert_eq!(row["method"], json!("MCP"));
        assert_eq!(row["endpoint_template"], json!("/mcp/tools/echo"));
        assert_eq!(row["call_count"], json!(1));
        assert_eq!(row["schema_mismatch_count"], json!(0));
        assert_eq!(status_count(&row, 400), Some(1));
    }

    #[tokio::test]
    async fn task_style_unknown_mcp_tool_call_uses_unknown_tool_inventory_path() {
        let harness = mcp_inventory_test_harness(McpInventoryHarnessConfig {
            upstream_url: Some("http://127.0.0.1:1".to_owned()),
            tools_document: mcp_tools_document(),
            mcp_upstream_servers: Vec::new(),
            egress_allowed_hosts: vec!["127.0.0.1".to_owned()],
        })
        .await;

        let request_id = "mcp-inventory-task-unknown-tool";
        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            38,
            "tools/call",
            Some(json!({
                "name": "missing_tool",
                "arguments": {},
                "task": {}
            })),
            request_id,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["error"]["code"], json!(-32601));
        assert_eq!(
            body["error"]["message"],
            json!("tool 'missing_tool' is not defined")
        );
        assert_eq!(body["error"]["data"]["tool_name"], json!("missing_tool"));

        assert_eventually(Duration::from_secs(1), || {
            harness.capture.events().iter().any(|event| {
                event.event_type == "http.request_observed"
                    && event.request_id == request_id
                    && event.payload["method"] == json!("MCP")
                    && event.payload["tool_name"] == json!("missing_tool")
                    && event.payload["status"] == json!(404)
                    && event.payload["reason"] == json!("unknown_tool")
            })
        });

        let row = wait_for_mcp_tool_inventory_row(
            &harness.router,
            &harness.admin_token,
            "missing_tool",
            |row| row["call_count"] == json!(1) && status_count(row, 404) == Some(1),
        )
        .await;
        assert_eq!(row["method"], json!("MCP"));
        assert_eq!(row["endpoint_template"], json!("/mcp/tools/missing_tool"));
        assert_eq!(row["call_count"], json!(1));
        assert_eq!(row["schema_mismatch_count"], json!(0));
        assert_eq!(status_count(&row, 404), Some(1));
    }

    #[tokio::test]
    async fn repeated_mcp_tool_calls_accumulate_into_one_inventory_row() {
        let upstream_addr = spawn_echo_json_upstream().await;
        let harness = mcp_inventory_test_harness(McpInventoryHarnessConfig {
            upstream_url: Some(format!("http://{upstream_addr}")),
            tools_document: mcp_tools_document(),
            mcp_upstream_servers: Vec::new(),
            egress_allowed_hosts: vec!["127.0.0.1".to_owned()],
        })
        .await;

        for index in 0..3 {
            let (status, body) = mcp_rpc(
                &harness.router,
                Some(&harness.admin_token),
                33 + index,
                "tools/call",
                Some(json!({
                    "name": "echo",
                    "arguments": {
                        "message": format!("inventory repeat {index}")
                    }
                })),
                &format!("mcp-inventory-repeat-{index}"),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["result"]["isError"], json!(false));
        }

        let row =
            wait_for_mcp_tool_inventory_row(&harness.router, &harness.admin_token, "echo", |row| {
                row["call_count"] == json!(3) && status_count(row, 200) == Some(3)
            })
            .await;
        assert_eq!(row["endpoint_template"], json!("/mcp/tools/echo"));
        assert_eq!(row["call_count"], json!(3));
        assert_eq!(status_count(&row, 200), Some(3));
        assert_eq!(
            inventory_rows_for_tool(&harness.router, &harness.admin_token, "echo")
                .await
                .len(),
            1
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mcp_upstream_tools_are_discovered_and_namespaced_in_tools_list() {
        let upstream = spawn_test_mcp_upstream("remote_echo").await;
        let harness =
            mcp_upstream_test_harness("alpha", upstream.url.clone(), &["admin", "reader"]).await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            20,
            "tools/list",
            None,
            "mcp-upstream-list",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let tools = body["result"]["tools"]
            .as_array()
            .expect("tools/list result should include tools array");
        let remote = tools
            .iter()
            .find(|tool| tool["name"] == json!("alpha:remote_echo"))
            .expect("upstream tool should be listed under its namespace");
        assert_eq!(remote["description"], json!("Remote test tool"));
        assert_eq!(remote["inputSchema"]["required"], json!(["message"]));
        assert_eq!(
            remote["inputSchema"]["properties"]["message"]["type"],
            json!("string")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mcp_upstream_tools_call_forwards_to_remote_tool_and_returns_result() {
        let upstream = spawn_test_mcp_upstream("remote_echo").await;
        let calls = Arc::clone(&upstream.calls);
        let harness =
            mcp_upstream_test_harness("alpha", upstream.url.clone(), &["admin", "reader"]).await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            21,
            "tools/call",
            Some(json!({
                "name": "alpha:remote_echo",
                "arguments": {
                    "message": "proxied hello"
                }
            })),
            "mcp-upstream-call",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["error"], Value::Null);
        assert_eq!(body["result"]["isError"], json!(false));
        assert_eq!(
            body["result"]["structuredContent"],
            json!({
                "remote_tool": "remote_echo",
                "arguments": {
                    "message": "proxied hello"
                }
            })
        );
        assert_eq!(
            calls
                .lock()
                .expect("upstream calls lock should not poison")
                .as_slice(),
            &[json!({
                "name": "remote_echo",
                "arguments": {
                    "message": "proxied hello"
                }
            })]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mcp_upstream_tool_call_rejects_response_larger_than_egress_limit() {
        const RESPONSE_LIMIT: usize = 512;

        let upstream = spawn_raw_mcp_upstream(RawMcpOversizeTarget::ToolCall, RESPONSE_LIMIT).await;
        let harness = mcp_upstream_test_harness_with_response_limit(
            "alpha",
            upstream.url.clone(),
            &["admin", "reader"],
            RESPONSE_LIMIT,
        )
        .await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            31,
            "tools/call",
            Some(json!({
                "name": "alpha:remote_echo",
                "arguments": {
                    "message": "oversized upstream response"
                }
            })),
            "mcp-upstream-call-too-large",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["error"]["code"], json!(-32603));
        assert_eq!(body["error"]["message"], json!("tool invocation failed"));
        assert_eq!(
            body["error"]["data"]["tool_name"],
            json!("alpha:remote_echo")
        );
        assert_eq!(body["error"]["data"]["reason"], json!("response_too_large"));
        assert!(
            !upstream.oversized_body_started.load(Ordering::SeqCst),
            "Content-Length precheck should reject before the oversized call body is sent"
        );

        upstream.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mcp_upstream_tool_call_rejects_request_larger_than_egress_limit_before_send() {
        const REQUEST_LIMIT: usize = 1024;

        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let upstream = spawn_raw_mcp_upstream(RawMcpOversizeTarget::None, 0).await;
        let tool_call_request_count = Arc::clone(&upstream.tool_call_request_count);
        let harness = mcp_upstream_test_harness_with_audit_and_limits(
            "alpha",
            upstream.url.clone(),
            &["admin", "reader"],
            audit_log,
            None,
            Some(REQUEST_LIMIT),
        )
        .await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            34,
            "tools/call",
            Some(json!({
                "name": "alpha:remote_echo",
                "arguments": {
                    "message": "x".repeat(REQUEST_LIMIT)
                }
            })),
            "mcp-upstream-call-request-too-large",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["error"]["code"], json!(-32603));
        assert_eq!(body["error"]["message"], json!("tool invocation failed"));
        assert_eq!(
            body["error"]["data"]["tool_name"],
            json!("alpha:remote_echo")
        );
        assert_eq!(
            body["error"]["data"]["reason"],
            json!("request_body_too_large")
        );
        assert_eq!(
            tool_call_request_count.load(Ordering::SeqCst),
            0,
            "oversized MCP tools/call request must not reach the upstream"
        );
        assert_eventually(Duration::from_secs(1), || {
            capture.events().iter().any(|event| {
                event.event_type == audit::event::TOOL_UPSTREAM_REQUEST
                    && event.request_id == "mcp-upstream-call-request-too-large"
                    && event.payload["tool_name"] == json!("alpha:remote_echo")
                    && event.payload["method"] == json!("MCP")
                    && event.payload["outcome"] == json!("failure")
                    && event.payload["reason"] == json!("request_body_too_large")
            })
        });

        upstream.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mcp_upstream_tools_list_discovery_rejects_response_larger_than_egress_limit() {
        const RESPONSE_LIMIT: usize = 512;

        let upstream =
            spawn_raw_mcp_upstream(RawMcpOversizeTarget::ToolsList, RESPONSE_LIMIT).await;
        let harness = mcp_upstream_test_harness_with_response_limit(
            "alpha",
            upstream.url.clone(),
            &["admin", "reader"],
            RESPONSE_LIMIT,
        )
        .await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            32,
            "tools/list",
            None,
            "mcp-upstream-list-too-large",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let tools = body["result"]["tools"]
            .as_array()
            .expect("tools/list result should include tools array");
        assert!(
            tools
                .iter()
                .all(|tool| tool["name"] != json!("alpha:remote_echo")),
            "oversized discovery response must not import upstream tools"
        );

        upstream.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mcp_upstream_tools_list_discovery_rejects_excessive_pagination() {
        let upstream = spawn_raw_mcp_upstream(RawMcpOversizeTarget::TooManyToolsListPages, 0).await;
        let list_request_count = Arc::clone(&upstream.tools_list_request_count);
        let harness =
            mcp_upstream_test_harness("alpha", upstream.url.clone(), &["admin", "reader"]).await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            36,
            "tools/list",
            None,
            "mcp-upstream-list-too-many-pages",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let tools = body["result"]["tools"]
            .as_array()
            .expect("tools/list result should include tools array");
        assert!(
            tools
                .iter()
                .all(|tool| tool["name"] != json!("alpha:remote_echo")),
            "excessive paginated discovery must fail closed and import no upstream tools"
        );
        assert!(
            list_request_count.load(Ordering::SeqCst) < RAW_MCP_EXCESSIVE_TOOLS_LIST_PAGES,
            "discovery should stop at its aggregate pagination cap"
        );

        upstream.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mcp_upstream_tools_list_discovery_accepts_small_pagination() {
        let upstream = spawn_raw_mcp_upstream(RawMcpOversizeTarget::TwoPageToolsList, 0).await;
        let harness =
            mcp_upstream_test_harness("alpha", upstream.url.clone(), &["admin", "reader"]).await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            37,
            "tools/list",
            None,
            "mcp-upstream-list-small-pages",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        let tools = body["result"]["tools"]
            .as_array()
            .expect("tools/list result should include tools array");
        assert!(
            tools
                .iter()
                .any(|tool| tool["name"] == json!("alpha:remote_echo")),
            "small paginated discovery should import the upstream tool"
        );

        upstream.shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mcp_upstream_tool_call_under_egress_limit_still_returns_result() {
        let upstream = spawn_test_mcp_upstream("remote_echo").await;
        let harness = mcp_upstream_test_harness_with_response_limit(
            "alpha",
            upstream.url.clone(),
            &["admin", "reader"],
            16 * 1024,
        )
        .await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            33,
            "tools/call",
            Some(json!({
                "name": "alpha:remote_echo",
                "arguments": {
                    "message": "small proxied hello"
                }
            })),
            "mcp-upstream-call-under-limit",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["error"], Value::Null);
        assert_eq!(body["result"]["isError"], json!(false));
        assert_eq!(
            body["result"]["structuredContent"],
            json!({
                "remote_tool": "remote_echo",
                "arguments": {
                    "message": "small proxied hello"
                }
            })
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mcp_upstream_tool_call_under_request_egress_limit_still_returns_result() {
        let upstream = spawn_test_mcp_upstream("remote_echo").await;
        let calls = Arc::clone(&upstream.calls);
        let harness = mcp_upstream_test_harness_with_request_limit(
            "alpha",
            upstream.url.clone(),
            &["admin", "reader"],
            16 * 1024,
        )
        .await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            35,
            "tools/call",
            Some(json!({
                "name": "alpha:remote_echo",
                "arguments": {
                    "message": "small proxied hello"
                }
            })),
            "mcp-upstream-call-under-request-limit",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["error"], Value::Null);
        assert_eq!(body["result"]["isError"], json!(false));
        assert_eq!(
            body["result"]["structuredContent"],
            json!({
                "remote_tool": "remote_echo",
                "arguments": {
                    "message": "small proxied hello"
                }
            })
        );
        assert_eq!(
            calls
                .lock()
                .expect("upstream calls lock should not poison")
                .len(),
            1,
            "under-limit MCP tools/call request should reach upstream"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mcp_upstream_tool_call_emits_mcp_upstream_audit_event() {
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let upstream = spawn_test_mcp_upstream("remote_echo").await;
        let harness = mcp_upstream_test_harness_with_audit(
            "alpha",
            upstream.url.clone(),
            &["admin"],
            audit_log,
        )
        .await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            25,
            "tools/call",
            Some(json!({
                "name": "alpha:remote_echo",
                "arguments": {
                    "message": "audit me"
                }
            })),
            "mcp-upstream-audit",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["result"]["isError"], json!(false));
        assert_eventually(Duration::from_secs(1), || {
            capture.events().iter().any(|event| {
                event.event_type == audit::event::TOOL_UPSTREAM_REQUEST
                    && event.request_id == "mcp-upstream-audit"
                    && event.payload["tool_name"] == json!("alpha:remote_echo")
                    && event.payload["method"] == json!("MCP")
                    && event.payload["upstream_type"] == json!("mcp")
                    && event.payload["mcp_server_name"] == json!("alpha")
                    && event.payload["mcp_tool_name"] == json!("remote_echo")
                    && event.payload["outcome"] == json!("success")
            })
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mcp_upstream_tool_role_policy_is_enforced_before_forwarding() {
        let upstream = spawn_test_mcp_upstream("remote_echo").await;
        let calls = Arc::clone(&upstream.calls);
        let harness = mcp_upstream_test_harness("alpha", upstream.url.clone(), &["admin"]).await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.reader_token),
            22,
            "tools/call",
            Some(json!({
                "name": "alpha:remote_echo",
                "arguments": {
                    "message": "reader should not forward"
                }
            })),
            "mcp-upstream-role-denied",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["error"]["code"], json!(-32001));
        assert_eq!(
            body["error"]["message"],
            json!("tool invocation is denied by role policy")
        );
        assert_eq!(
            body["error"]["data"]["tool_name"],
            json!("alpha:remote_echo")
        );
        assert_eq!(body["error"]["data"]["reason"], json!("role_denied"));
        assert!(
            calls
                .lock()
                .expect("upstream calls lock should not poison")
                .is_empty(),
            "role-denied proxy call must not reach upstream"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mcp_upstream_tool_schema_validation_applies_before_forwarding() {
        let upstream = spawn_test_mcp_upstream("remote_echo").await;
        let calls = Arc::clone(&upstream.calls);
        let harness =
            mcp_upstream_test_harness("alpha", upstream.url.clone(), &["admin", "reader"]).await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            23,
            "tools/call",
            Some(json!({
                "name": "alpha:remote_echo",
                "arguments": {
                    "message": "valid field",
                    "unexpected": true
                }
            })),
            "mcp-upstream-schema-denied",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["error"]["code"], json!(-32602));
        assert_eq!(
            body["error"]["data"]["tool_name"],
            json!("alpha:remote_echo")
        );
        assert!(body["error"]["message"]
            .as_str()
            .expect("invalid params error should include a message")
            .contains("failed input schema validation"));
        assert!(
            calls
                .lock()
                .expect("upstream calls lock should not poison")
                .is_empty(),
            "schema-invalid proxy call must not reach upstream"
        );
    }

    #[tokio::test]
    async fn mcp_upstream_url_rejected_by_egress_allowlist_fails_startup() {
        let mut config = test_config(Vec::new());
        config.mcp_upstream_servers = vec![config::McpUpstreamServerConfig {
            name: "alpha".to_owned(),
            url: "http://blocked.example.test/mcp".to_owned(),
            timeout_ms: Some(500),
            response_idle_timeout_ms: Some(500),
            connect_timeout_ms: Some(500),
        }];
        config.egress_allowed_hosts = Vec::new();
        config.egress_deny_private_ips = false;

        let recorder = PrometheusBuilder::new().build_recorder();
        let error = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect_err("non-allowlisted MCP upstream should fail startup");
        let message = error.to_string();
        assert!(
            message.contains("MCP upstream server 'alpha' URL is rejected by egress policy"),
            "unexpected error: {message}"
        );
        assert!(
            message.contains("egress host is not allowed: blocked.example.test"),
            "unexpected error: {message}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mcp_upstream_namespaced_name_collision_fails_startup() {
        let first = spawn_test_mcp_upstream("beta:echo").await;
        let second = spawn_test_mcp_upstream("echo").await;
        let mut config = test_config(Vec::new());
        config.mcp_upstream_servers = vec![
            config::McpUpstreamServerConfig {
                name: "alpha".to_owned(),
                url: first.url,
                timeout_ms: Some(1000),
                response_idle_timeout_ms: Some(1000),
                connect_timeout_ms: Some(1000),
            },
            config::McpUpstreamServerConfig {
                name: "alpha:beta".to_owned(),
                url: second.url,
                timeout_ms: Some(1000),
                response_idle_timeout_ms: Some(1000),
                connect_timeout_ms: Some(1000),
            },
        ];
        config.egress_allowed_hosts = vec!["127.0.0.1".to_owned()];
        config.egress_deny_private_ips = false;

        let recorder = PrometheusBuilder::new().build_recorder();
        let error = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect_err("namespaced MCP upstream tool collision should fail startup");
        let message = error.to_string();
        assert!(
            message.contains("duplicate tool name 'alpha:beta:echo'"),
            "unexpected error: {message}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mcp_upstream_unreachable_call_uses_sanitized_error() {
        let upstream = spawn_test_mcp_upstream("remote_echo").await;
        let port = upstream.addr.port();
        let url = upstream.url.clone();
        let harness = mcp_upstream_test_harness("alpha", url, &["admin"]).await;
        upstream.shutdown().await;

        let (status, body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            24,
            "tools/call",
            Some(json!({
                "name": "alpha:remote_echo",
                "arguments": {
                    "message": "after shutdown"
                }
            })),
            "mcp-upstream-unreachable",
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["error"]["code"], json!(-32603));
        assert_eq!(body["error"]["message"], json!("tool invocation failed"));
        assert_eq!(
            body["error"]["data"]["tool_name"],
            json!("alpha:remote_echo")
        );
        assert_eq!(body["error"]["data"]["reason"], json!("connect_failed"));
        let body_string = body.to_string();
        assert!(!body_string.contains("127.0.0.1"));
        assert!(!body_string.contains(&port.to_string()));
        assert!(!body_string.contains("connection"));
        assert!(!body_string.contains("reqwest"));
    }

    #[tokio::test]
    async fn authenticated_request_persists_principal_directory_row() {
        let jwks_addr = spawn_test_jwks_server().await;
        let principal_db = TempDb::new("principal-directory-full-stack");
        let mut config = test_config(Vec::new());
        config.principal_sqlite_path = Some(principal_db.path.to_string_lossy().into_owned());
        configure_test_jwt_provider(&mut config, jwks_addr);
        config.egress_deny_private_ips = false;
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");
        let token = signed_token("directory-user", &["member"]);

        let response = authenticated_principal_probe(&router, &token).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eventually(Duration::from_secs(1), || {
            principal_directory_row_count(&principal_db.path) == 1
        });
        let row = principal_directory_row(&principal_db.path, "directory-user", "", "bearer");
        assert_eq!(row.email.as_deref(), Some("directory-user@example.test"));
        assert_eq!(row.request_count, 1);
    }

    #[tokio::test]
    async fn unset_principal_sqlite_path_leaves_directory_disabled() {
        let jwks_addr = spawn_test_jwks_server().await;
        let unused_db = TempDb::new("principal-directory-disabled");
        let mut config = test_config(Vec::new());
        configure_test_jwt_provider(&mut config, jwks_addr);
        config.egress_deny_private_ips = false;
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");
        let token = signed_token("directory-disabled-user", &["member"]);

        let response = authenticated_principal_probe(&router, &token).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            !unused_db.path.exists(),
            "unset PRINCIPAL_SQLITE_PATH should not create an unrelated SQLite file"
        );
    }

    #[tokio::test]
    async fn principal_directory_list_filters_paginates_and_counts_anonymous_requests() {
        let principal_db = TempDb::new("principal-directory-list");
        let audit_db = TempDb::new("principal-directory-list-audit");
        create_principal_schema(&principal_db.path);
        create_audit_schema(&audit_db.path);
        seed_principal_directory_rows(&principal_db.path);
        insert_anonymous_observation_event(
            &audit_db.path,
            "anonymous-in-window",
            "2026-01-03T12:00:00Z",
            "/anonymous",
        );
        insert_anonymous_observation_event(
            &audit_db.path,
            "anonymous-outside-window",
            "2025-12-31T23:59:59Z",
            "/anonymous",
        );
        let (router, _policy) =
            principal_admin_router(Some(&principal_db.path), Some(&audit_db.path), None);

        let issuer = query_encode("https://issuer-a.example.test/");
        let first_page = principal_json(
            &router,
            &format!("/v1/admin/principals?issuer={issuer}&limit=2"),
            Some(test_principal(&["principal-reader"])),
        )
        .await;
        assert_eq!(
            principal_subjects(&first_page),
            vec!["alpha".to_owned(), "bravo".to_owned()]
        );
        let cursor = first_page["next_cursor"]
            .as_str()
            .expect("first principal page should include a cursor");
        let second_page = principal_json(
            &router,
            &format!("/v1/admin/principals?issuer={issuer}&limit=2&cursor={cursor}"),
            Some(test_principal(&["principal-reader"])),
        )
        .await;
        assert_eq!(principal_subjects(&second_page), vec!["delta".to_owned()]);
        assert!(second_page["next_cursor"].is_null());

        let service_tokens = principal_json(
            &router,
            "/v1/admin/principals?auth_method=service_token",
            Some(test_principal(&["principal-reader"])),
        )
        .await;
        assert_eq!(
            principal_subjects(&service_tokens),
            vec!["bravo".to_owned()]
        );

        let humans = principal_json(
            &router,
            "/v1/admin/principals?principal_type=human",
            Some(test_principal(&["principal-reader"])),
        )
        .await;
        assert_eq!(
            principal_subjects(&humans),
            vec!["alpha".to_owned(), "charlie".to_owned(), "delta".to_owned()]
        );

        let combined = principal_json(
            &router,
            &format!(
                "/v1/admin/principals?issuer={issuer}&auth_method=bearer&principal_type=human&last_seen_after=2026-01-01T12:00:00Z&last_seen_before=2026-01-04T12:00:00Z"
            ),
            Some(test_principal(&["principal-reader"])),
        )
        .await;
        assert_eq!(principal_subjects(&combined), vec!["alpha".to_owned()]);
        assert_eq!(combined["anonymous_request_count"], json!(1));
    }

    #[tokio::test]
    async fn principal_directory_admin_requires_principals_read_permission() {
        let principal_db = TempDb::new("principal-directory-authz");
        create_principal_schema(&principal_db.path);
        insert_principal_directory_row(
            &principal_db.path,
            PrincipalDirectorySeed {
                subject: "alpha",
                issuer: "",
                auth_method: "bearer",
                email: None,
                org_id: None,
                first_seen: "2026-01-01T00:00:00Z",
                last_seen: "2026-01-01T00:00:00Z",
                request_count: 1,
            },
        );
        let (router, _policy) = principal_admin_router(Some(&principal_db.path), None, None);

        for uri in [
            "/v1/admin/principals",
            "/v1/admin/principal?subject=alpha&issuer=&auth_method=bearer",
        ] {
            let unauthenticated = router
                .clone()
                .oneshot(principal_admin_request(uri, None))
                .await
                .expect("principal admin request should complete");
            assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

            let forbidden_response = router
                .clone()
                .oneshot(principal_admin_request(
                    uri,
                    Some(test_principal(&["reader"])),
                ))
                .await
                .expect("principal admin request should complete");
            assert_eq!(forbidden_response.status(), StatusCode::FORBIDDEN);
            assert_eq!(
                body_string(forbidden_response).await,
                r#"{"error":"forbidden"}"#
            );
        }
    }

    #[tokio::test]
    async fn principal_directory_admin_reports_not_configured() {
        let (router, _policy) = principal_admin_router(None, None, None);

        for uri in [
            "/v1/admin/principals",
            "/v1/admin/principal?subject=missing&issuer=&auth_method=bearer",
        ] {
            let response = router
                .clone()
                .oneshot(principal_admin_request(
                    uri,
                    Some(test_principal(&["principal-reader"])),
                ))
                .await
                .expect("principal admin request should complete");

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                body_string(response).await,
                r#"{"error":"principal directory requires PRINCIPAL_SQLITE_PATH to be configured"}"#
            );
        }
    }

    #[tokio::test]
    async fn principal_directory_detail_returns_404_for_missing_composite_key() {
        let principal_db = TempDb::new("principal-directory-detail-missing");
        create_principal_schema(&principal_db.path);
        let (router, _policy) = principal_admin_router(Some(&principal_db.path), None, None);

        let response = router
            .oneshot(principal_admin_request(
                "/v1/admin/principal?subject=missing&issuer=&auth_method=bearer",
                Some(test_principal(&["principal-reader"])),
            ))
            .await
            .expect("principal detail request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_string(response).await,
            r#"{"error":"principal was not found"}"#
        );
    }

    #[tokio::test]
    async fn principal_directory_detail_enriches_authenticated_request_from_audit() {
        let jwks_addr = spawn_test_jwks_server().await;
        let principal_db = TempDb::new("principal-directory-detail-full-stack");
        let audit_db = TempDb::new("principal-directory-detail-audit");
        let policy = TempPolicyFile::new(&principal_full_stack_policy_document_string());
        let mut config = test_config(Vec::new());
        config.principal_sqlite_path = Some(principal_db.path.to_string_lossy().into_owned());
        config.audit_sqlite_path = Some(audit_db.path.to_string_lossy().into_owned());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config
            .rbac_exempt_paths
            .push("/v1/admin/principals".to_owned());
        config
            .rbac_exempt_paths
            .push("/v1/admin/principal".to_owned());
        configure_test_jwt_provider(&mut config, jwks_addr);
        config.egress_deny_private_ips = false;
        let recorder = PrometheusBuilder::new().build_recorder();
        let (audit_log, audit_event_sender) = audit_log_with_sqlite_and_broadcast(&audit_db.path);
        let router = app(config, recorder.handle(), audit_log, audit_event_sender)
            .expect("app should build");
        let user_token = signed_token("directory-detail-user", &["member"]);
        let admin_token = signed_token("directory-admin", &["principal-reader"]);

        let response = authenticated_principal_probe(&router, &user_token).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eventually(Duration::from_secs(1), || {
            principal_directory_row_count(&principal_db.path) == 1
        });

        let detail_uri =
            "/v1/admin/principal?subject=directory-detail-user&issuer=&auth_method=bearer";
        let body = wait_for_principal_detail_json(&router, detail_uri, &admin_token, |body| {
            principal_detail_endpoint_paths(body)
                .contains(&("GET".to_owned(), "/__test/principal".to_owned()))
                && principal_detail_rule_ids(body).contains(&"allow-probe".to_owned())
        })
        .await;

        assert_eq!(body["principal"]["subject"], json!("directory-detail-user"));
        assert_eq!(body["principal"]["auth_method"], json!("bearer"));
        assert_eq!(body["tools_called"], json!([]));
    }

    #[tokio::test]
    async fn principal_directory_detail_filters_principal_endpoint_signal_history_exactly() {
        let principal_db = TempDb::new("principal-directory-signals");
        let discovery_db = TempDb::new("principal-directory-signals-discovery");
        create_principal_schema(&principal_db.path);
        create_discovery_schema(&discovery_db.path);
        for subject in ["bob", "alice bob", "charlie"] {
            insert_principal_directory_row(
                &principal_db.path,
                PrincipalDirectorySeed {
                    subject,
                    issuer: "",
                    auth_method: "bearer",
                    email: None,
                    org_id: None,
                    first_seen: "2026-01-01T00:00:00Z",
                    last_seen: "2026-01-01T00:00:00Z",
                    request_count: 1,
                },
            );
        }
        insert_principal_endpoint_signal(
            &discovery_db.path,
            "sig-bob",
            "POST",
            "/principal-pairs/{id}",
            "bob",
            "2026-01-02T00:00:00Z",
        );
        insert_principal_endpoint_signal(
            &discovery_db.path,
            "sig-alice-bob",
            "POST",
            "/principal-pairs/{id}",
            "alice bob",
            "2026-01-03T00:00:00Z",
        );
        let (router, _policy) =
            principal_admin_router(Some(&principal_db.path), None, Some(&discovery_db.path));

        let bob = principal_json(
            &router,
            "/v1/admin/principal?subject=bob&issuer=&auth_method=bearer",
            Some(test_principal(&["principal-reader"])),
        )
        .await;
        assert_eq!(
            principal_detail_signal_ids(&bob),
            vec!["sig-bob".to_owned()]
        );

        let charlie = principal_json(
            &router,
            "/v1/admin/principal?subject=charlie&issuer=&auth_method=bearer",
            Some(test_principal(&["principal-reader"])),
        )
        .await;
        assert!(principal_detail_signal_ids(&charlie).is_empty());
    }

    #[tokio::test]
    async fn principal_directory_list_counts_failed_auth_without_creating_principal_row() {
        let jwks_addr = spawn_test_jwks_server().await;
        let principal_db = TempDb::new("principal-directory-anonymous");
        let audit_db = TempDb::new("principal-directory-anonymous-audit");
        let mut config = test_config(Vec::new());
        config.principal_sqlite_path = Some(principal_db.path.to_string_lossy().into_owned());
        config.audit_sqlite_path = Some(audit_db.path.to_string_lossy().into_owned());
        configure_test_jwt_provider(&mut config, jwks_addr);
        config.egress_deny_private_ips = false;
        let recorder = PrometheusBuilder::new().build_recorder();
        let (audit_log, audit_event_sender) = audit_log_with_sqlite_and_broadcast(&audit_db.path);
        let router = app(config, recorder.handle(), audit_log, audit_event_sender)
            .expect("app should build");
        let window_start = (OffsetDateTime::now_utc() - time::Duration::seconds(10))
            .format(&Rfc3339)
            .expect("window start should format");

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/__test/principal")
                    .body(Body::empty())
                    .expect("anonymous request should build"),
            )
            .await
            .expect("anonymous request should complete");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eventually(Duration::from_secs(1), || {
            anonymous_observation_count(&audit_db.path) == 1
        });
        assert_eq!(principal_directory_row_count(&principal_db.path), 0);

        let window_end = (OffsetDateTime::now_utc() + time::Duration::seconds(10))
            .format(&Rfc3339)
            .expect("window end should format");
        let (query_router, _policy) =
            principal_admin_router(Some(&principal_db.path), Some(&audit_db.path), None);
        let body = principal_json(
            &query_router,
            &format!(
                "/v1/admin/principals?last_seen_after={window_start}&last_seen_before={window_end}"
            ),
            Some(test_principal(&["principal-reader"])),
        )
        .await;

        assert_eq!(body["principals"], json!([]));
        assert_eq!(body["anonymous_request_count"], json!(1));
    }

    #[tokio::test]
    async fn real_cookie_session_authenticates_through_full_stack() {
        let (introspection_url, introspection_server) =
            spawn_blocking_cookie_session_server(Ipv4Addr::LOCALHOST, 1);
        let mut config = test_config(Vec::new());
        configure_test_cookie_session_provider(&mut config, introspection_url);
        config.egress_deny_private_ips = false;
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/__test/principal")
                    .header(header::COOKIE, "session=session-secret-123")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["user_id"], json!("cookie-user"));
        assert_eq!(body["auth_method"], json!("session_cookie"));
        assert_eq!(body["roles"], json!(["admin", "member"]));
        assert_eq!(
            introspection_server
                .join()
                .expect("cookie-session introspection server should finish"),
            1
        );
    }

    #[tokio::test]
    async fn cookie_session_introspection_host_is_auto_seeded_for_cross_host_egress() {
        let (introspection_url, introspection_server) =
            spawn_blocking_cookie_session_server(Ipv4Addr::new(127, 0, 0, 2), 1);
        let mut config = test_config(Vec::new());
        configure_test_cookie_session_provider(&mut config, introspection_url);
        config.egress_deny_private_ips = false;
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/__test/principal")
                    .header(header::COOKIE, "session=session-secret-123")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await["user_id"], json!("cookie-user"));
        assert_eq!(
            introspection_server
                .join()
                .expect("cookie-session introspection server should finish"),
            1
        );
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
        let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
        let recorder = PrometheusBuilder::new().build_recorder();
        let response = app(
            audit_query_config_with_policy(None, &policy),
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
        let (router, _, _policy) = audit_events_router();

        let response = router
            .oneshot(audit_query_request(AUDIT_EVENTS_STREAM_ROUTE, None))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(body_string(response).await, r#"{"error":"unauthorized"}"#);
    }

    #[tokio::test]
    async fn audit_events_stream_non_admin_principal_returns_forbidden() {
        let (router, _, _policy) = audit_events_router();

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
        let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        let config = status_config_with_policy(config, &policy);
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
    async fn audit_and_status_principals_without_policy_return_not_configured() {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        let router = status_router(config, Instant::now());

        for (uri, expected_body) in [
            (
                AUDIT_ADMIN_ROUTE,
                r#"{"error":"audit API requires POLICY_FILE to be configured"}"#,
            ),
            (
                AUDIT_EVENTS_STREAM_ROUTE,
                r#"{"error":"audit API requires POLICY_FILE to be configured"}"#,
            ),
            (
                STATUS_ADMIN_ROUTE,
                r#"{"error":"status API requires POLICY_FILE to be configured"}"#,
            ),
        ] {
            let response = router
                .clone()
                .oneshot(audit_query_request(uri, Some(test_principal(&["admin"]))))
                .await
                .expect("request should complete");

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_eq!(body_string(response).await, expected_body);
        }
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

        let minimal_policy = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "id": "status-minimal-policy",
                "default_action": "deny",
                "roles": {
                    "status-reader": { "permissions": ["admin:status:read"] }
                }
            }"#,
        );
        let mut minimal_config = test_config(Vec::new());
        minimal_config.listen_addr = "127.0.0.1:18182"
            .parse()
            .expect("listen address should parse");
        minimal_config.auth_enabled = false;
        minimal_config.rate_limit_read_rps = 61.25;
        minimal_config.rate_limit_read_burst = 77;
        minimal_config.rate_limit_write_rps = 8.5;
        minimal_config.rate_limit_write_burst = 12;
        let minimal_config = status_config_with_policy(minimal_config, &minimal_policy);

        let minimal = status_json(
            status_router(minimal_config, Instant::now() - Duration::from_secs(5)),
            Some(test_principal(&["status-reader"])),
        )
        .await;

        assert_eq!(minimal["listen_addr"], "127.0.0.1:18182");
        assert_eq!(minimal["auth_enabled"], false);
        assert_eq!(minimal["rbac"]["policy_loaded"], true);
        assert_eq!(minimal["rbac"]["policy_id"], "status-minimal-policy");
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
        let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.auth_exempt_paths.push(STATUS_ADMIN_ROUTE.to_owned());
        config.egress_allowed_hosts = vec!["api.example.test".to_owned()];
        config.upstream_url = Some("https://upstream.example.test/base".to_owned());
        let config = status_config_with_policy(config, &policy);
        let router = status_router(config, Instant::now());

        let status = status_json(router, Some(test_principal(&["status-reader"]))).await;

        assert_eq!(status["egress"]["allowed_hosts_count"], 2);
    }

    #[tokio::test]
    async fn policy_get_returns_current_policy_with_stable_etag_and_requires_read_permission() {
        let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
        let router = policy_admin_router(Some(&policy), test_audit_log());

        let response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("policy GET should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let etag = policy_etag_header(&response);
        assert!(etag.starts_with("\"sha256:"));
        assert!(etag.ends_with('"'));
        let body = json_body(response).await;
        assert_eq!(body["id"], json!("initial-policy"));

        let second_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("second policy GET should complete");
        assert_eq!(second_response.status(), StatusCode::OK);
        assert_eq!(policy_etag_header(&second_response), etag);

        let read_only_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["policy-reader"])),
                None,
                None,
            ))
            .await
            .expect("read-only policy GET should complete");
        assert_eq!(read_only_response.status(), StatusCode::OK);

        let forbidden_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["reader"])),
                None,
                None,
            ))
            .await
            .expect("forbidden policy GET should complete");
        assert_eq!(forbidden_response.status(), StatusCode::FORBIDDEN);

        let unauthenticated_response = router
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                None,
                None,
                None,
            ))
            .await
            .expect("unauthenticated policy GET should complete");
        assert_eq!(unauthenticated_response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn policy_put_with_valid_if_match_updates_live_policy_and_emits_audit_event() {
        let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let router = policy_admin_router(Some(&policy), audit_log);

        let before_new_reader = router
            .clone()
            .oneshot(audit_query_request(
                "/__test/principal",
                Some(test_principal(&["new-reader"])),
            ))
            .await
            .expect("pre-update test request should complete");
        assert_eq!(before_new_reader.status(), StatusCode::FORBIDDEN);

        let get_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("policy GET should complete");
        let current_etag = policy_etag_header(&get_response);

        let candidate = policy_document_string("updated-policy", "test:new");
        let put_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                Some(candidate),
                Some(&current_etag),
            ))
            .await
            .expect("policy PUT should complete");
        assert_eq!(put_response.status(), StatusCode::OK);
        let new_etag = policy_etag_header(&put_response);
        assert_ne!(new_etag, current_etag);
        let put_body = json_body(put_response).await;
        assert_eq!(put_body["id"], json!("updated-policy"));

        let after_new_reader = router
            .clone()
            .oneshot(audit_query_request(
                "/__test/principal",
                Some(test_principal(&["new-reader"])),
            ))
            .await
            .expect("post-update new-reader request should complete");
        assert_eq!(after_new_reader.status(), StatusCode::OK);

        let after_old_reader = router
            .oneshot(audit_query_request(
                "/__test/principal",
                Some(test_principal(&["old-reader"])),
            ))
            .await
            .expect("post-update old-reader request should complete");
        assert_eq!(after_old_reader.status(), StatusCode::FORBIDDEN);

        assert_eventually(Duration::from_secs(1), || {
            capture
                .events()
                .iter()
                .any(|event| event.event_type == audit::event::POLICY_CHANGED)
        });
        let events = capture.events();
        let event = events
            .iter()
            .find(|event| event.event_type == audit::event::POLICY_CHANGED)
            .expect("policy.changed event should be captured");
        let actor = event.actor.as_ref().expect("actor should be set");
        assert_eq!(actor.user_id, "user-123");
        assert_eq!(actor.roles, Some(vec!["admin".to_owned()]));
        assert_eq!(event.payload["before"]["id"], json!("initial-policy"));
        assert_eq!(event.payload["after"]["id"], json!("updated-policy"));
        assert_eq!(event.payload["before"]["routes"], json!(6));
        assert_eq!(event.payload["after"]["routes"], json!(6));
        assert_eq!(event.payload["changed_sections"], json!(["id", "routes"]));
    }

    #[tokio::test]
    async fn policy_history_records_every_policy_mutation_path_once() {
        let initial_policy = policy_document_with_rules_string(
            "initial-policy",
            json!([
                direct_rule_json(Some("managed-rule"), &["GET"], "/managed", "allow"),
                direct_rule_json(Some("second-rule"), &["POST"], "/second", "deny")
            ]),
        );
        let policy = TempPolicyFile::new(&initial_policy);
        let history_db = TempDb::new("policy-history-all-mutations");
        let router = policy_admin_router_with_history(Some(&policy), &history_db);

        assert!(policy_history_entries(&router, None).await.is_empty());

        let (etag, _) = current_policy(&router).await;
        let put_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                Some(policy_document_with_rules_string(
                    "whole-policy",
                    json!([
                        direct_rule_json(Some("managed-rule"), &["GET"], "/managed", "allow"),
                        direct_rule_json(Some("second-rule"), &["POST"], "/second", "deny")
                    ]),
                )),
                Some(&etag),
            ))
            .await
            .expect("policy PUT should complete");
        assert_eq!(put_response.status(), StatusCode::OK);
        assert_history_versions(&router, &["policy_replaced"]).await;

        let create_etag = policy_etag_header(&put_response);
        let create_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::POST,
                POLICY_RULES_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                Some(
                    json!({ "id": "created-rule", "path": "/created", "action": "allow" })
                        .to_string(),
                ),
                Some(&create_etag),
            ))
            .await
            .expect("rule POST should complete");
        assert_eq!(create_response.status(), StatusCode::CREATED);
        assert_history_versions(&router, &["rule_created", "policy_replaced"]).await;

        let patch_etag = policy_etag_header(&create_response);
        let patch_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::PATCH,
                &format!("{POLICY_RULES_ADMIN_ROUTE}/created-rule"),
                Some(test_principal(&["admin"])),
                Some(json!({ "action": "deny" }).to_string()),
                Some(&patch_etag),
            ))
            .await
            .expect("rule PATCH should complete");
        assert_eq!(patch_response.status(), StatusCode::OK);
        assert_history_versions(
            &router,
            &["rule_updated", "rule_created", "policy_replaced"],
        )
        .await;

        let delete_etag = policy_etag_header(&patch_response);
        let delete_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::DELETE,
                &format!("{POLICY_RULES_ADMIN_ROUTE}/created-rule"),
                Some(test_principal(&["admin"])),
                None,
                Some(&delete_etag),
            ))
            .await
            .expect("rule DELETE should complete");
        assert_eq!(delete_response.status(), StatusCode::OK);
        assert_history_versions(
            &router,
            &[
                "rule_deleted",
                "rule_updated",
                "rule_created",
                "policy_replaced",
            ],
        )
        .await;

        let reorder_etag = policy_etag_header(&delete_response);
        let reorder_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::PUT,
                POLICY_RULES_ORDER_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                Some(json!(["second-rule", "managed-rule"]).to_string()),
                Some(&reorder_etag),
            ))
            .await
            .expect("rule order PUT should complete");
        assert_eq!(reorder_response.status(), StatusCode::OK);

        let entries = policy_history_page(
            &router,
            POLICY_HISTORY_ADMIN_ROUTE,
            Some(test_principal(&["admin"])),
        )
        .await["versions"]
            .as_array()
            .expect("versions should be an array")
            .clone();
        assert_eq!(
            entries.len(),
            5,
            "every successful mutation should append exactly one version"
        );
        assert_eq!(
            history_actions(&entries),
            vec![
                "rules_reordered",
                "rule_deleted",
                "rule_updated",
                "rule_created",
                "policy_replaced",
            ]
        );
        for (expected_version, entry) in (1..=5).rev().zip(entries.iter()) {
            assert_eq!(entry["version"], json!(expected_version));
            assert_eq!(entry["actor"], json!("user-123"));
            assert_rfc3339_timestamp(
                entry["created_at"]
                    .as_str()
                    .expect("timestamp should exist"),
            );
            assert!(
                entry.get("policy").is_none(),
                "list entries should omit policy snapshots"
            );
        }
    }

    #[tokio::test]
    async fn policy_put_succeeds_with_warning_when_history_append_fails_after_commit() {
        let initial_policy = policy_document_string("initial-policy", "test:old");
        let policy = TempPolicyFile::new(&initial_policy);
        let history_db = TempDb::new("policy-history-append-failure");
        let router = policy_admin_router_with_history(Some(&policy), &history_db);

        let connection =
            rusqlite::Connection::open(&history_db.path).expect("history db should open");
        connection
            .execute_batch("DROP TABLE policy_versions;")
            .expect("history table should be droppable");
        drop(connection);

        let (current_etag, _) = current_policy(&router).await;
        let candidate = policy_document_string("updated-policy", "test:new");
        let expected_policy = serde_json::to_value(
            rbac::Policy::validate_json_value(
                serde_json::from_str::<Value>(&candidate).expect("candidate policy should be JSON"),
            )
            .expect("candidate policy should validate"),
        )
        .expect("validated candidate policy should serialize");
        let response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                Some(candidate),
                Some(&current_etag),
            ))
            .await
            .expect("policy PUT should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-greengateway-policy-history-warning")
                .and_then(|value| value.to_str().ok()),
            Some("policy_history_append_failed")
        );
        let new_etag = policy_etag_header(&response);
        assert_ne!(new_etag, current_etag);
        assert_eq!(json_body(response).await, expected_policy);

        let (live_etag, live_policy) = current_policy(&router).await;
        assert_eq!(live_etag, new_etag);
        assert_eq!(live_policy, expected_policy);
    }

    #[tokio::test]
    async fn policy_rule_create_succeeds_with_warning_when_history_append_fails_after_commit() {
        let initial_policy = policy_document_string("initial-policy", "test:old");
        let policy = TempPolicyFile::new(&initial_policy);
        let history_db = TempDb::new("policy-history-rule-append-failure");
        let router = policy_admin_router_with_history(Some(&policy), &history_db);

        let connection =
            rusqlite::Connection::open(&history_db.path).expect("history db should open");
        connection
            .execute_batch("DROP TABLE policy_versions;")
            .expect("history table should be droppable");
        drop(connection);

        let (current_etag, _) = current_policy(&router).await;
        let response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::POST,
                POLICY_RULES_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                Some(
                    json!({ "id": "created-rule", "path": "/created", "action": "allow" })
                        .to_string(),
                ),
                Some(&current_etag),
            ))
            .await
            .expect("rule POST should complete");

        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response
                .headers()
                .get("x-greengateway-policy-history-warning")
                .and_then(|value| value.to_str().ok()),
            Some("policy_history_append_failed")
        );
        let new_etag = policy_etag_header(&response);
        assert_ne!(new_etag, current_etag);
        let created_rule = json_body(response).await;
        assert_eq!(created_rule["id"], json!("created-rule"));
        assert_eq!(created_rule["path"], json!("/created"));
        assert_eq!(created_rule["action"], json!("allow"));

        let (live_etag, live_policy) = current_policy(&router).await;
        assert_eq!(live_etag, new_etag);
        assert_eq!(live_policy["rules"][0]["id"], json!("created-rule"));
        assert_eq!(live_policy["rules"][0]["path"], json!("/created"));
        assert_eq!(live_policy["rules"][0]["action"], json!("allow"));
    }

    #[tokio::test]
    async fn policy_history_list_paginates_and_requires_read_permission() {
        let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
        let history_db = TempDb::new("policy-history-list");
        let router = policy_admin_router_with_history(Some(&policy), &history_db);

        for id in ["first-policy", "second-policy"] {
            let (etag, _) = current_policy(&router).await;
            let response = router
                .clone()
                .oneshot(policy_admin_request(
                    Method::PUT,
                    POLICY_ADMIN_ROUTE,
                    Some(test_principal(&["admin"])),
                    Some(policy_document_string(id, "test:new")),
                    Some(&etag),
                ))
                .await
                .expect("policy PUT should complete");
            assert_eq!(response.status(), StatusCode::OK);
        }

        let first_page = policy_history_page(
            &router,
            "/v1/admin/policy/history?limit=1",
            Some(test_principal(&["policy-reader"])),
        )
        .await;
        assert_eq!(
            first_page["versions"]
                .as_array()
                .expect("versions array")
                .len(),
            1
        );
        assert_eq!(first_page["versions"][0]["version"], json!(2));
        let cursor = first_page["next_cursor"]
            .as_str()
            .expect("first page should include a cursor");

        let second_page = policy_history_page(
            &router,
            &format!("/v1/admin/policy/history?limit=1&cursor={cursor}"),
            Some(test_principal(&["policy-reader"])),
        )
        .await;
        assert_eq!(
            second_page["versions"]
                .as_array()
                .expect("versions array")
                .len(),
            1
        );
        assert_eq!(second_page["versions"][0]["version"], json!(1));
        assert!(second_page["next_cursor"].is_null());

        let forbidden = router
            .clone()
            .oneshot(policy_admin_request(
                Method::GET,
                "/v1/admin/policy/history",
                Some(test_principal(&["reader"])),
                None,
                None,
            ))
            .await
            .expect("forbidden history request should complete");
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let unauthenticated = router
            .oneshot(policy_admin_request(
                Method::GET,
                "/v1/admin/policy/history",
                None,
                None,
                None,
            ))
            .await
            .expect("unauthenticated history request should complete");
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn policy_rollback_restores_snapshot_appends_history_and_requires_write_permission() {
        let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
        let history_db = TempDb::new("policy-history-rollback");
        let router = policy_admin_router_with_history(Some(&policy), &history_db);

        let (first_etag, _) = current_policy(&router).await;
        let first_update = router
            .clone()
            .oneshot(policy_admin_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                Some(policy_document_string("target-policy", "test:new")),
                Some(&first_etag),
            ))
            .await
            .expect("first policy PUT should complete");
        assert_eq!(first_update.status(), StatusCode::OK);

        let (second_etag, _) = current_policy(&router).await;
        let second_update = router
            .clone()
            .oneshot(policy_admin_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                Some(policy_document_string("later-policy", "test:old")),
                Some(&second_etag),
            ))
            .await
            .expect("second policy PUT should complete");
        assert_eq!(second_update.status(), StatusCode::OK);

        let entries_before_rollback = policy_history_entries(&router, None).await;
        assert_eq!(entries_before_rollback.len(), 2);
        assert_eq!(entries_before_rollback[1]["version"], json!(1));
        let target_snapshot = entries_before_rollback[1]["policy"].clone();
        assert_eq!(target_snapshot["id"], json!("target-policy"));

        let (rollback_etag, _) = current_policy(&router).await;
        let forbidden = router
            .clone()
            .oneshot(policy_admin_request(
                Method::POST,
                "/v1/admin/policy/rollback/1",
                Some(test_principal(&["policy-reader"])),
                None,
                Some(&rollback_etag),
            ))
            .await
            .expect("read-only rollback request should complete");
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let unknown = router
            .clone()
            .oneshot(policy_admin_request(
                Method::POST,
                "/v1/admin/policy/rollback/404",
                Some(test_principal(&["admin"])),
                None,
                Some(&rollback_etag),
            ))
            .await
            .expect("unknown rollback request should complete");
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

        let missing_if_match = router
            .clone()
            .oneshot(policy_admin_request(
                Method::POST,
                "/v1/admin/policy/rollback/1",
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("missing If-Match rollback request should complete");
        assert_eq!(missing_if_match.status(), StatusCode::PRECONDITION_REQUIRED);

        let rollback = router
            .clone()
            .oneshot(policy_admin_request(
                Method::POST,
                "/v1/admin/policy/rollback/1",
                Some(test_principal(&["admin"])),
                None,
                Some(&rollback_etag),
            ))
            .await
            .expect("rollback request should complete");
        assert_eq!(rollback.status(), StatusCode::OK);
        let rolled_back = json_body(rollback).await;
        assert_eq!(rolled_back, target_snapshot);

        let (_, live_policy) = current_policy(&router).await;
        assert_eq!(live_policy, target_snapshot);

        let entries_after_rollback = policy_history_entries(&router, None).await;
        assert_eq!(
            entries_after_rollback.len(),
            entries_before_rollback.len() + 1,
            "rollback should append history without deleting prior versions"
        );
        assert_eq!(
            history_actions(&entries_after_rollback),
            vec!["policy_rolled_back", "policy_replaced", "policy_replaced"]
        );
        assert_eq!(entries_after_rollback[0]["version"], json!(3));
        assert_eq!(
            entries_after_rollback[0]["diff_summary"]["target_version"],
            json!(1)
        );
        assert_eq!(entries_after_rollback[0]["policy"], target_snapshot);
        assert_eq!(entries_after_rollback[1], entries_before_rollback[0]);
        assert_eq!(entries_after_rollback[2], entries_before_rollback[1]);
    }

    #[tokio::test]
    async fn policy_put_with_stale_if_match_returns_precondition_failed_without_changes() {
        let initial_policy = policy_document_string("initial-policy", "test:old");
        let policy = TempPolicyFile::new(&initial_policy);
        let router = policy_admin_router(Some(&policy), test_audit_log());
        let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");

        let get_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("policy GET should complete");
        let current_etag = policy_etag_header(&get_response);

        let response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                Some(policy_document_string("updated-policy", "test:new")),
                Some("\"sha256:stale\""),
            ))
            .await
            .expect("stale policy PUT should complete");

        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
        assert_eq!(
            fs::read_to_string(&policy.path).expect("policy file should read"),
            before_contents
        );

        let after_get = router
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("policy GET after stale PUT should complete");
        assert_eq!(after_get.status(), StatusCode::OK);
        assert_eq!(policy_etag_header(&after_get), current_etag);
        assert_eq!(json_body(after_get).await["id"], json!("initial-policy"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_policy_puts_with_same_if_match_allow_only_one_update() {
        let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
        let router = policy_admin_router(Some(&policy), test_audit_log());

        let get_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("policy GET should complete");
        let current_etag = policy_etag_header(&get_response);

        let first_policy = policy_document("concurrent-policy-a", "test:new");
        let second_policy = policy_document("concurrent-policy-b", "test:new");
        let first_candidate =
            serde_json::to_string_pretty(&first_policy).expect("test policy should serialize");
        let second_candidate =
            serde_json::to_string_pretty(&second_policy).expect("test policy should serialize");
        let body_barrier = Arc::new(tokio::sync::Barrier::new(3));

        let first_task = tokio::spawn({
            let router = router.clone();
            let current_etag = current_etag.clone();
            let body_barrier = Arc::clone(&body_barrier);

            async move {
                router
                    .oneshot(synchronized_policy_put_request(
                        first_candidate,
                        &current_etag,
                        body_barrier,
                    ))
                    .await
                    .expect("first policy PUT should complete")
            }
        });
        let second_task = tokio::spawn({
            let router = router.clone();
            let current_etag = current_etag.clone();
            let body_barrier = Arc::clone(&body_barrier);

            async move {
                router
                    .oneshot(synchronized_policy_put_request(
                        second_candidate,
                        &current_etag,
                        body_barrier,
                    ))
                    .await
                    .expect("second policy PUT should complete")
            }
        });

        tokio::time::timeout(Duration::from_secs(2), body_barrier.wait())
            .await
            .expect("both policy PUT bodies should reach the release barrier");

        let (first_response, second_response) = tokio::join!(first_task, second_task);
        let first_response = first_response.expect("first policy PUT task should join");
        let second_response = second_response.expect("second policy PUT task should join");

        let first_status = first_response.status();
        let first_etag =
            (first_status == StatusCode::OK).then(|| policy_etag_header(&first_response));
        let first_body = if first_status == StatusCode::OK {
            Some(json_body(first_response).await)
        } else {
            assert_eq!(first_status, StatusCode::PRECONDITION_FAILED);
            assert_eq!(
                body_string(first_response).await,
                r#"{"error":"If-Match does not match the current policy ETag"}"#
            );
            None
        };

        let second_status = second_response.status();
        let second_etag =
            (second_status == StatusCode::OK).then(|| policy_etag_header(&second_response));
        let second_body = if second_status == StatusCode::OK {
            Some(json_body(second_response).await)
        } else {
            assert_eq!(second_status, StatusCode::PRECONDITION_FAILED);
            assert_eq!(
                body_string(second_response).await,
                r#"{"error":"If-Match does not match the current policy ETag"}"#
            );
            None
        };

        assert_eq!(
            [first_status, second_status]
                .iter()
                .filter(|status| **status == StatusCode::OK)
                .count(),
            1
        );
        assert_eq!(
            [first_status, second_status]
                .iter()
                .filter(|status| **status == StatusCode::PRECONDITION_FAILED)
                .count(),
            1
        );

        let (winning_id, winning_etag, winning_body, mut winning_policy) =
            if first_status == StatusCode::OK {
                (
                    "concurrent-policy-a",
                    first_etag.expect("successful PUT should include ETag"),
                    first_body.expect("successful PUT should include JSON body"),
                    first_policy,
                )
            } else {
                (
                    "concurrent-policy-b",
                    second_etag.expect("successful PUT should include ETag"),
                    second_body.expect("successful PUT should include JSON body"),
                    second_policy,
                )
            };

        assert_ne!(winning_etag, current_etag);
        assert_eq!(winning_body["id"], json!(winning_id));
        winning_policy["rules"] = json!([]);

        let persisted_policy: Value = serde_json::from_str(
            &fs::read_to_string(&policy.path).expect("policy file should read"),
        )
        .expect("persisted policy should be JSON");
        assert_eq!(persisted_policy, winning_policy);

        let live_response = router
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("policy GET after concurrent PUTs should complete");
        assert_eq!(live_response.status(), StatusCode::OK);
        assert_eq!(policy_etag_header(&live_response), winning_etag);
        assert_eq!(json_body(live_response).await, winning_policy);
    }

    #[tokio::test]
    async fn policy_put_with_invalid_policy_returns_errors_without_persisting_or_swapping() {
        let initial_policy = policy_document_string("initial-policy", "test:old");
        let policy = TempPolicyFile::new(&initial_policy);
        let router = policy_admin_router(Some(&policy), test_audit_log());
        let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");

        let get_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("policy GET should complete");
        let current_etag = policy_etag_header(&get_response);

        let response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                Some(r#"{ "schema_version": "1.0.0" }"#.to_owned()),
                Some(&current_etag),
            ))
            .await
            .expect("invalid policy PUT should complete");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = json_body(response).await;
        assert_eq!(body["valid"], json!(false));
        assert!(
            body["errors"][0]
                .as_str()
                .unwrap_or_default()
                .contains("schema_version must start with"),
            "unexpected validation body: {body}"
        );
        assert_eq!(
            fs::read_to_string(&policy.path).expect("policy file should read"),
            before_contents
        );

        let after_get = router
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("policy GET after invalid PUT should complete");
        assert_eq!(policy_etag_header(&after_get), current_etag);
        assert_eq!(json_body(after_get).await["id"], json!("initial-policy"));
    }

    #[tokio::test]
    async fn policy_put_missing_if_match_is_rejected_without_changes() {
        let initial_policy = policy_document_string("initial-policy", "test:old");
        let policy = TempPolicyFile::new(&initial_policy);
        let router = policy_admin_router(Some(&policy), test_audit_log());
        let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");

        let response = router
            .oneshot(policy_admin_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                Some(policy_document_string("updated-policy", "test:new")),
                None,
            ))
            .await
            .expect("missing If-Match policy PUT should complete");

        assert_eq!(response.status(), StatusCode::PRECONDITION_REQUIRED);
        assert_eq!(
            body_string(response).await,
            r#"{"error":"If-Match header is required"}"#
        );
        assert_eq!(
            fs::read_to_string(&policy.path).expect("policy file should read"),
            before_contents
        );
    }

    #[tokio::test]
    async fn policy_put_requires_write_permission() {
        let initial_policy = policy_document_string("initial-policy", "test:old");
        let policy = TempPolicyFile::new(&initial_policy);
        let router = policy_admin_router(Some(&policy), test_audit_log());
        let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");

        let get_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("policy GET should complete");
        let current_etag = policy_etag_header(&get_response);

        let response = router
            .oneshot(policy_admin_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["policy-reader"])),
                Some(policy_document_string("updated-policy", "test:new")),
                Some(&current_etag),
            ))
            .await
            .expect("read-only policy PUT should complete");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            fs::read_to_string(&policy.path).expect("policy file should read"),
            before_contents
        );
    }

    #[tokio::test]
    async fn policy_rule_create_without_id_generates_stable_id_that_survives_position_shift_and_emits_audit_event(
    ) {
        let initial_policy = policy_document_with_rules_string(
            "initial-policy",
            json!([direct_rule_json(Some("seed"), &["GET"], "/seed", "allow")]),
        );
        let policy = TempPolicyFile::new(&initial_policy);
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let router = policy_admin_router(Some(&policy), audit_log);
        let (current_etag, _) = current_policy(&router).await;

        let create_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::POST,
                POLICY_RULES_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                Some(
                    json!({
                        "methods": ["GET"],
                        "path": "/created/a",
                        "action": "allow"
                    })
                    .to_string(),
                ),
                Some(&current_etag),
            ))
            .await
            .expect("rule POST should complete");

        assert_eq!(create_response.status(), StatusCode::CREATED);
        let create_etag = policy_etag_header(&create_response);
        let created_rule = json_body(create_response).await;
        let created_rule_id = created_rule["id"]
            .as_str()
            .expect("created rule id should be present")
            .to_owned();
        assert!(created_rule_id.starts_with("rule-"));
        assert_ne!(created_rule_id, "1");
        assert_eq!(created_rule["path"], json!("/created/a"));

        let event = captured_policy_change(&capture, "rule_created");
        assert_policy_change_actor(&event);
        assert_eq!(
            event.payload["diff_summary"],
            json!({
                "action": "rule_created",
                "rule_id": created_rule_id,
                "position": 1
            })
        );

        let delete_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::DELETE,
                &format!("{POLICY_RULES_ADMIN_ROUTE}/seed"),
                Some(test_principal(&["admin"])),
                None,
                Some(&create_etag),
            ))
            .await
            .expect("seed DELETE should complete");
        assert_eq!(delete_response.status(), StatusCode::OK);
        let delete_etag = policy_etag_header(&delete_response);

        let patch_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::PATCH,
                &format!("{POLICY_RULES_ADMIN_ROUTE}/{created_rule_id}"),
                Some(test_principal(&["admin"])),
                Some(json!({ "action": "deny" }).to_string()),
                Some(&delete_etag),
            ))
            .await
            .expect("created rule PATCH should complete");

        assert_eq!(patch_response.status(), StatusCode::OK);
        let patched_rule = json_body(patch_response).await;
        assert_eq!(patched_rule["id"], json!(created_rule_id));
        assert_eq!(patched_rule["path"], json!("/created/a"));
        assert_eq!(patched_rule["action"], json!("deny"));

        let (_, live_policy) = current_policy(&router).await;
        assert_eq!(
            live_policy["rules"].as_array().unwrap_or(&Vec::new()).len(),
            1
        );
        assert_eq!(live_policy["rules"][0]["id"], json!(created_rule_id));
        assert_eq!(live_policy["rules"][0]["action"], json!("deny"));
    }

    #[tokio::test]
    async fn policy_rule_create_rejects_explicit_id_collision() {
        let initial_policy = policy_document_with_rules_string(
            "initial-policy",
            json!([direct_rule_json(
                Some("existing-rule"),
                &["GET"],
                "/existing",
                "allow"
            )]),
        );
        let policy = TempPolicyFile::new(&initial_policy);
        let router = policy_admin_router(Some(&policy), test_audit_log());
        let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");
        let (current_etag, _) = current_policy(&router).await;

        let response = router
            .oneshot(policy_admin_request(
                Method::POST,
                POLICY_RULES_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                Some(
                    json!({
                        "id": "existing-rule",
                        "methods": ["GET"],
                        "path": "/new",
                        "action": "deny"
                    })
                    .to_string(),
                ),
                Some(&current_etag),
            ))
            .await
            .expect("colliding rule POST should complete");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            body_string(response).await,
            r#"{"error":"rule id 'existing-rule' already exists"}"#
        );
        assert_eq!(
            fs::read_to_string(&policy.path).expect("policy file should read"),
            before_contents
        );
    }

    #[tokio::test]
    async fn policy_rule_patch_updates_one_field_preserves_others_and_emits_audit_event() {
        let initial_policy = policy_document_with_rules_string(
            "initial-policy",
            json!([{
                "id": "managed-rule",
                "methods": ["GET"],
                "path": "/patch",
                "principal": { "roles": ["admin"] },
                "action": "allow"
            }]),
        );
        let policy = TempPolicyFile::new(&initial_policy);
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let router = policy_admin_router(Some(&policy), audit_log);
        let (current_etag, _) = current_policy(&router).await;

        let response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::PATCH,
                &format!("{POLICY_RULES_ADMIN_ROUTE}/managed-rule"),
                Some(test_principal(&["admin"])),
                Some(json!({ "action": "deny" }).to_string()),
                Some(&current_etag),
            ))
            .await
            .expect("rule PATCH should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let new_etag = policy_etag_header(&response);
        assert_ne!(new_etag, current_etag);
        let patched_rule = json_body(response).await;
        assert_eq!(patched_rule["id"], json!("managed-rule"));
        assert_eq!(patched_rule["methods"], json!(["GET"]));
        assert_eq!(patched_rule["path"], json!("/patch"));
        assert_eq!(patched_rule["principal"]["roles"], json!(["admin"]));
        assert_eq!(patched_rule["action"], json!("deny"));

        let event = captured_policy_change(&capture, "rule_updated");
        assert_policy_change_actor(&event);
        assert_eq!(
            event.payload["diff_summary"],
            json!({
                "action": "rule_updated",
                "rule_id": "managed-rule",
                "changed_fields": ["action"]
            })
        );
    }

    #[tokio::test]
    async fn policy_rule_patch_can_replace_path_matcher_with_tool_name_matcher() {
        let initial_policy = policy_document_with_rules_string(
            "initial-policy",
            json!([{
                "id": "managed-rule",
                "methods": ["GET"],
                "path": "/patch",
                "principal": { "roles": ["admin"] },
                "action": "allow"
            }]),
        );
        let policy = TempPolicyFile::new(&initial_policy);
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let router = policy_admin_router(Some(&policy), audit_log);
        let (current_etag, _) = current_policy(&router).await;

        let response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::PATCH,
                &format!("{POLICY_RULES_ADMIN_ROUTE}/managed-rule"),
                Some(test_principal(&["admin"])),
                Some(
                    json!({
                        "methods": [],
                        "path": null,
                        "tool_name": "reports.export",
                        "action": "deny"
                    })
                    .to_string(),
                ),
                Some(&current_etag),
            ))
            .await
            .expect("rule PATCH should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let patched_rule = json_body(response).await;
        assert_eq!(patched_rule["id"], json!("managed-rule"));
        assert_eq!(patched_rule.get("path"), None);
        assert_eq!(patched_rule["tool_name"], json!("reports.export"));
        assert_eq!(patched_rule["methods"], json!([]));
        assert_eq!(patched_rule["action"], json!("deny"));

        let event = captured_policy_change(&capture, "rule_updated");
        assert_policy_change_actor(&event);
        assert_eq!(
            event.payload["diff_summary"],
            json!({
                "action": "rule_updated",
                "rule_id": "managed-rule",
                "changed_fields": ["methods", "path", "tool_name", "action"]
            })
        );
    }

    #[tokio::test]
    async fn policy_rule_patch_can_disable_rule_and_live_evaluation_skips_it() {
        let initial_policy = policy_document_with_rules_string(
            "initial-policy",
            json!([
                {
                    "id": "deny-probe",
                    "methods": ["GET"],
                    "path": "/__test/principal",
                    "action": "deny"
                },
                {
                    "id": "allow-probe",
                    "methods": ["GET"],
                    "path": "/__test/principal",
                    "action": "allow"
                }
            ]),
        );
        let policy = TempPolicyFile::new(&initial_policy);
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let router = policy_admin_router(Some(&policy), audit_log);

        let before_probe = router
            .clone()
            .oneshot(audit_query_request(
                "/__test/principal",
                Some(test_principal(&["admin"])),
            ))
            .await
            .expect("pre-disable probe should complete");
        assert_eq!(before_probe.status(), StatusCode::FORBIDDEN);

        let (current_etag, _) = current_policy(&router).await;
        let response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::PATCH,
                &format!("{POLICY_RULES_ADMIN_ROUTE}/deny-probe"),
                Some(test_principal(&["admin"])),
                Some(json!({ "enabled": false }).to_string()),
                Some(&current_etag),
            ))
            .await
            .expect("rule enabled PATCH should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let new_etag = policy_etag_header(&response);
        assert_ne!(new_etag, current_etag);
        let patched_rule = json_body(response).await;
        assert_eq!(patched_rule["id"], json!("deny-probe"));
        assert_eq!(patched_rule["enabled"], json!(false));
        assert_eq!(patched_rule["action"], json!("deny"));

        let after_probe = router
            .clone()
            .oneshot(audit_query_request(
                "/__test/principal",
                Some(test_principal(&["admin"])),
            ))
            .await
            .expect("post-disable probe should complete");
        assert_eq!(after_probe.status(), StatusCode::OK);
        assert_eq!(json_body(after_probe).await["user_id"], json!("user-123"));

        let (_, live_policy) = current_policy(&router).await;
        assert_eq!(live_policy["rules"][0]["enabled"], json!(false));

        let event = captured_policy_change(&capture, "rule_updated");
        assert_policy_change_actor(&event);
        assert_eq!(
            event.payload["diff_summary"],
            json!({
                "action": "rule_updated",
                "rule_id": "deny-probe",
                "changed_fields": ["enabled"]
            })
        );
    }

    #[tokio::test]
    async fn policy_rule_patch_and_delete_unknown_id_return_not_found() {
        let initial_policy = policy_document_with_rules_string(
            "initial-policy",
            json!([direct_rule_json(
                Some("managed-rule"),
                &["GET"],
                "/managed",
                "allow"
            )]),
        );
        let policy = TempPolicyFile::new(&initial_policy);
        let router = policy_admin_router(Some(&policy), test_audit_log());
        let (current_etag, _) = current_policy(&router).await;

        let patch_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::PATCH,
                &format!("{POLICY_RULES_ADMIN_ROUTE}/missing-rule"),
                Some(test_principal(&["admin"])),
                Some(json!({ "action": "deny" }).to_string()),
                Some(&current_etag),
            ))
            .await
            .expect("missing rule PATCH should complete");
        assert_eq!(patch_response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_string(patch_response).await,
            r#"{"error":"rule id 'missing-rule' was not found"}"#
        );

        let delete_response = router
            .oneshot(policy_admin_request(
                Method::DELETE,
                &format!("{POLICY_RULES_ADMIN_ROUTE}/missing-rule"),
                Some(test_principal(&["admin"])),
                None,
                Some(&current_etag),
            ))
            .await
            .expect("missing rule DELETE should complete");
        assert_eq!(delete_response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_string(delete_response).await,
            r#"{"error":"rule id 'missing-rule' was not found"}"#
        );
    }

    #[tokio::test]
    async fn policy_rule_delete_removes_rule_and_emits_audit_event() {
        let initial_policy = policy_document_with_rules_string(
            "initial-policy",
            json!([direct_rule_json(
                Some("managed-rule"),
                &["GET"],
                "/managed",
                "allow"
            )]),
        );
        let policy = TempPolicyFile::new(&initial_policy);
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let router = policy_admin_router(Some(&policy), audit_log);
        let (current_etag, _) = current_policy(&router).await;

        let response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::DELETE,
                &format!("{POLICY_RULES_ADMIN_ROUTE}/managed-rule"),
                Some(test_principal(&["admin"])),
                None,
                Some(&current_etag),
            ))
            .await
            .expect("rule DELETE should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_ne!(policy_etag_header(&response), current_etag);
        assert_eq!(
            json_body(response).await,
            json!({ "deleted_rule_id": "managed-rule" })
        );

        let (_, live_policy) = current_policy(&router).await;
        assert_eq!(live_policy["rules"], json!([]));

        let event = captured_policy_change(&capture, "rule_deleted");
        assert_policy_change_actor(&event);
        assert_eq!(
            event.payload["diff_summary"],
            json!({
                "action": "rule_deleted",
                "rule_id": "managed-rule",
                "position": 0
            })
        );
    }

    #[tokio::test]
    async fn policy_rules_reorder_valid_permutation_changes_first_match_order_and_emits_audit_event(
    ) {
        let initial_policy = policy_document_with_rules_string(
            "initial-policy",
            json!([
                direct_rule_json(Some("deny-probe"), &["GET"], "/__test/principal", "deny"),
                direct_rule_json(Some("allow-probe"), &["GET"], "/__test/principal", "allow")
            ]),
        );
        let policy = TempPolicyFile::new(&initial_policy);
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let router = policy_admin_router(Some(&policy), audit_log);

        let before_probe = router
            .clone()
            .oneshot(audit_query_request(
                "/__test/principal",
                Some(test_principal(&["admin"])),
            ))
            .await
            .expect("pre-reorder probe should complete");
        assert_eq!(before_probe.status(), StatusCode::FORBIDDEN);

        let (current_etag, _) = current_policy(&router).await;
        let response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::PUT,
                POLICY_RULES_ORDER_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                Some(json!(["allow-probe", "deny-probe"]).to_string()),
                Some(&current_etag),
            ))
            .await
            .expect("rule order PUT should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let new_etag = policy_etag_header(&response);
        assert_ne!(new_etag, current_etag);
        assert_eq!(
            json_body(response).await,
            json!({ "order": ["allow-probe", "deny-probe"] })
        );

        let after_probe = router
            .clone()
            .oneshot(audit_query_request(
                "/__test/principal",
                Some(test_principal(&["admin"])),
            ))
            .await
            .expect("post-reorder probe should complete");
        assert_eq!(after_probe.status(), StatusCode::OK);
        assert_eq!(json_body(after_probe).await["user_id"], json!("user-123"));

        let (_, live_policy) = current_policy(&router).await;
        assert_eq!(live_policy["rules"][0]["id"], json!("allow-probe"));
        assert_eq!(live_policy["rules"][1]["id"], json!("deny-probe"));

        let event = captured_policy_change(&capture, "rules_reordered");
        assert_policy_change_actor(&event);
        assert_eq!(
            event.payload["diff_summary"],
            json!({
                "action": "rules_reordered",
                "new_order": ["allow-probe", "deny-probe"]
            })
        );
    }

    #[tokio::test]
    async fn policy_rules_reorder_invalid_set_is_rejected_without_partial_reorder() {
        let initial_policy = policy_document_with_rules_string(
            "initial-policy",
            json!([
                direct_rule_json(Some("first-rule"), &["GET"], "/first", "allow"),
                direct_rule_json(Some("second-rule"), &["GET"], "/second", "deny")
            ]),
        );
        let policy = TempPolicyFile::new(&initial_policy);
        let router = policy_admin_router(Some(&policy), test_audit_log());
        let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");
        let (current_etag, _) = current_policy(&router).await;

        let response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::PUT,
                POLICY_RULES_ORDER_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                Some(json!(["second-rule", "second-rule", "unknown-rule"]).to_string()),
                Some(&current_etag),
            ))
            .await
            .expect("invalid rule order PUT should complete");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = json_body(response).await;
        let errors = body["errors"]
            .as_array()
            .expect("errors should be an array")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();
        assert!(errors.iter().any(|error| error.contains("length mismatch")));
        assert!(errors.iter().any(|error| error.contains("duplicate ids")));
        assert!(errors.iter().any(|error| error.contains("missing ids")));
        assert!(errors.iter().any(|error| error.contains("unknown ids")));
        assert_eq!(
            fs::read_to_string(&policy.path).expect("policy file should read"),
            before_contents
        );

        let (after_etag, live_policy) = current_policy(&router).await;
        assert_eq!(after_etag, current_etag);
        assert_eq!(live_policy["rules"][0]["id"], json!("first-rule"));
        assert_eq!(live_policy["rules"][1]["id"], json!("second-rule"));
    }

    #[tokio::test]
    async fn policy_rule_mutations_require_write_permission() {
        let initial_policy = policy_document_with_rules_string(
            "initial-policy",
            json!([direct_rule_json(
                Some("managed-rule"),
                &["GET"],
                "/managed",
                "allow"
            )]),
        );
        let policy = TempPolicyFile::new(&initial_policy);
        let router = policy_admin_router(Some(&policy), test_audit_log());
        let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");
        let (current_etag, _) = current_policy(&router).await;

        for (method, uri, body) in [
            (
                Method::POST,
                POLICY_RULES_ADMIN_ROUTE.to_owned(),
                Some(json!({ "path": "/new", "action": "allow" }).to_string()),
            ),
            (
                Method::PATCH,
                format!("{POLICY_RULES_ADMIN_ROUTE}/managed-rule"),
                Some(json!({ "action": "deny" }).to_string()),
            ),
            (
                Method::DELETE,
                format!("{POLICY_RULES_ADMIN_ROUTE}/managed-rule"),
                None,
            ),
            (
                Method::PUT,
                POLICY_RULES_ORDER_ADMIN_ROUTE.to_owned(),
                Some(json!(["managed-rule"]).to_string()),
            ),
        ] {
            let response = router
                .clone()
                .oneshot(policy_admin_request(
                    method,
                    &uri,
                    Some(test_principal(&["policy-reader"])),
                    body,
                    Some(&current_etag),
                ))
                .await
                .expect("write-forbidden policy rule request should complete");
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
        }

        assert_eq!(
            fs::read_to_string(&policy.path).expect("policy file should read"),
            before_contents
        );
    }

    #[tokio::test]
    async fn policy_rule_mutations_require_fresh_if_match() {
        let initial_policy = policy_document_with_rules_string(
            "initial-policy",
            json!([direct_rule_json(
                Some("managed-rule"),
                &["GET"],
                "/managed",
                "allow"
            )]),
        );
        let policy = TempPolicyFile::new(&initial_policy);
        let router = policy_admin_router(Some(&policy), test_audit_log());
        let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");
        let (current_etag, _) = current_policy(&router).await;

        for (method, uri, body) in [
            (
                Method::POST,
                POLICY_RULES_ADMIN_ROUTE.to_owned(),
                Some(json!({ "path": "/new", "action": "allow" }).to_string()),
            ),
            (
                Method::PATCH,
                format!("{POLICY_RULES_ADMIN_ROUTE}/managed-rule"),
                Some(json!({ "action": "deny" }).to_string()),
            ),
            (
                Method::DELETE,
                format!("{POLICY_RULES_ADMIN_ROUTE}/managed-rule"),
                None,
            ),
            (
                Method::PUT,
                POLICY_RULES_ORDER_ADMIN_ROUTE.to_owned(),
                Some(json!(["managed-rule"]).to_string()),
            ),
        ] {
            let missing_response = router
                .clone()
                .oneshot(policy_admin_request(
                    method.clone(),
                    &uri,
                    Some(test_principal(&["admin"])),
                    body.clone(),
                    None,
                ))
                .await
                .expect("missing If-Match policy rule request should complete");
            assert_eq!(
                missing_response.status(),
                StatusCode::PRECONDITION_REQUIRED,
                "{uri}"
            );
            assert_eq!(
                body_string(missing_response).await,
                r#"{"error":"If-Match header is required"}"#
            );

            let stale_response = router
                .clone()
                .oneshot(policy_admin_request(
                    method,
                    &uri,
                    Some(test_principal(&["admin"])),
                    body,
                    Some("\"sha256:stale\""),
                ))
                .await
                .expect("stale If-Match policy rule request should complete");
            assert_eq!(
                stale_response.status(),
                StatusCode::PRECONDITION_FAILED,
                "{uri}"
            );
            assert_eq!(
                body_string(stale_response).await,
                r#"{"error":"If-Match does not match the current policy ETag"}"#
            );
        }

        assert_eq!(
            fs::read_to_string(&policy.path).expect("policy file should read"),
            before_contents
        );
        let (after_etag, _) = current_policy(&router).await;
        assert_eq!(after_etag, current_etag);
    }

    #[tokio::test]
    async fn token_admin_create_list_get_require_permissions_and_never_list_secret_material() {
        let token_db = TempDb::new("token-admin-create-list");
        let policy = TempPolicyFile::new(&token_policy_document_string());
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let router = token_admin_router(&token_db, &policy, audit_log);

        let forbidden_create = router
            .clone()
            .oneshot(token_admin_request(
                Method::POST,
                TOKENS_ADMIN_ROUTE,
                Some(test_principal(&["tokens-reader"])),
                Some(json!({ "scopes": ["probe-reader"] }).to_string()),
            ))
            .await
            .expect("read-only token create request should complete");
        assert_eq!(forbidden_create.status(), StatusCode::FORBIDDEN);

        let create_response = router
            .clone()
            .oneshot(token_admin_request(
                Method::POST,
                TOKENS_ADMIN_ROUTE,
                Some(test_principal(&["tokens-writer"])),
                Some(
                    json!({
                        "scopes": ["probe-reader", "admin:tokens:read"],
                        "expires_at": "2099-01-01T00:00:00Z"
                    })
                    .to_string(),
                ),
            ))
            .await
            .expect("token create request should complete");
        assert_eq!(create_response.status(), StatusCode::CREATED);
        let create_body = json_body(create_response).await;
        let plaintext = create_body["plaintext_token"]
            .as_str()
            .expect("created response should include one-time plaintext token")
            .to_owned();
        assert!(plaintext.starts_with("ggw_"));
        assert!(create_body["plaintext_token_notice"]
            .as_str()
            .unwrap_or_default()
            .contains("will not be shown again"));
        let token_id = create_body["token"]["id"]
            .as_str()
            .expect("created response should include token id")
            .to_owned();
        assert_eq!(
            create_body["token"]["scopes"],
            json!(["probe-reader", "admin:tokens:read"])
        );
        let create_serialized = serde_json::to_string(&create_body).unwrap();
        assert!(!create_serialized.contains("token_hash"));

        let forbidden_list = router
            .clone()
            .oneshot(token_admin_request(
                Method::GET,
                TOKENS_ADMIN_ROUTE,
                Some(test_principal(&["tokens-writer"])),
                None,
            ))
            .await
            .expect("write-only token list request should complete");
        assert_eq!(forbidden_list.status(), StatusCode::FORBIDDEN);

        let list_response = router
            .clone()
            .oneshot(token_admin_request(
                Method::GET,
                TOKENS_ADMIN_ROUTE,
                Some(test_principal(&["tokens-reader"])),
                None,
            ))
            .await
            .expect("token list request should complete");
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_body = json_body(list_response).await;
        assert_eq!(list_body["tokens"][0]["id"], json!(token_id));
        let list_serialized = serde_json::to_string(&list_body).unwrap();
        assert!(!list_serialized.contains(&plaintext));
        assert!(!list_serialized.contains("plaintext_token"));
        assert!(!list_serialized.contains("token_hash"));

        let get_missing = router
            .clone()
            .oneshot(token_admin_request(
                Method::GET,
                &format!("{TOKENS_ADMIN_ROUTE}/missing"),
                Some(test_principal(&["tokens-reader"])),
                None,
            ))
            .await
            .expect("missing token get request should complete");
        assert_eq!(get_missing.status(), StatusCode::NOT_FOUND);

        let get_response = router
            .clone()
            .oneshot(token_admin_request(
                Method::GET,
                &format!("{TOKENS_ADMIN_ROUTE}/{token_id}"),
                Some(test_principal(&["tokens-reader"])),
                None,
            ))
            .await
            .expect("token get request should complete");
        assert_eq!(get_response.status(), StatusCode::OK);
        let get_body = json_body(get_response).await;
        assert_eq!(get_body["id"], json!(token_id));
        let get_serialized = serde_json::to_string(&get_body).unwrap();
        assert!(!get_serialized.contains(&plaintext));
        assert!(!get_serialized.contains("plaintext_token"));
        assert!(!get_serialized.contains("token_hash"));

        let event = captured_token_change(&capture, "token_created");
        assert_token_change_actor(&event);
        assert_eq!(event.payload["action"], json!("token_created"));
        assert_eq!(event.payload["token_id"], json!(token_id));
        assert_eq!(
            event.payload["scopes"],
            json!(["probe-reader", "admin:tokens:read"])
        );
        let audit_serialized = serde_json::to_string(&event).unwrap();
        assert!(!audit_serialized.contains(&plaintext));
        assert!(!audit_serialized.contains("token_hash"));
    }

    #[tokio::test]
    async fn token_admin_mutation_with_real_jwt_persists_audit_actor_identity() {
        let jwks_addr = spawn_test_jwks_server().await;
        let token_db = TempDb::new("token-admin-real-jwt-audit-token");
        let audit_db = TempDb::new("token-admin-real-jwt-audit-log");
        let policy = TempPolicyFile::new(&token_audit_full_stack_policy_document_string());
        let mut config = test_config(Vec::new());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
        config.audit_sqlite_path = Some(audit_db.path.to_string_lossy().into_owned());
        config.egress_deny_private_ips = false;
        configure_test_jwt_provider(&mut config, jwks_addr);
        let recorder = PrometheusBuilder::new().build_recorder();
        let (audit_log, audit_event_sender) =
            audit::AuditLog::from_config(&config).expect("audit log should build");
        let router = app(config, recorder.handle(), audit_log, audit_event_sender)
            .expect("app should build");
        let token = signed_token("sso-admin", &["admin"]);

        let create_response = router
            .clone()
            .oneshot(bearer_json_request(
                Method::POST,
                TOKENS_ADMIN_ROUTE,
                &token,
                json!({ "scopes": ["probe-reader"] }).to_string(),
            ))
            .await
            .expect("token create request should complete");
        assert_eq!(create_response.status(), StatusCode::CREATED);

        let event = wait_for_bearer_audit_event(
            &router,
            &format!(
                "{AUDIT_ADMIN_ROUTE}?event_type={}",
                audit::event::SERVICE_TOKEN_CHANGED
            ),
            &token,
            |event| event["payload"]["action"] == json!("token_created"),
        )
        .await;
        let actor = event["actor"]
            .as_object()
            .expect("service token audit event should include actor");

        assert_eq!(actor["user_id"], json!("sso-admin"));
        assert_eq!(actor["email"], json!("sso-admin@example.test"));
        assert_eq!(actor["roles"], json!(["admin"]));
        assert_eq!(actor["auth_mode"], json!("bearer_token"));
    }

    #[tokio::test]
    async fn openapi_tools_preview_returns_generated_tools_and_current_tools_etag() {
        let harness = tools_admin_harness(empty_tools_document(), test_audit_log()).await;

        let response = harness
            .router
            .clone()
            .oneshot(tools_openapi_preview_request(
                &harness.admin_token,
                widget_openapi_spec(),
            ))
            .await
            .expect("OpenAPI tools preview request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .expect("preview response should include current tools ETag")
            .to_owned();
        assert!(
            etag.starts_with("\"sha256:"),
            "tools ETag should be a quoted sha256 digest: {etag}"
        );
        let body = json_body(response).await;

        let tools = body["tools"]
            .as_array()
            .expect("preview response should include tools");
        assert_eq!(tools.len(), 2);
        let create_widget = tools
            .iter()
            .find(|tool| tool["name"] == json!("createWidget"))
            .expect("createWidget should be generated");
        assert_eq!(create_widget["upstream"]["method"], json!("POST"));
        assert_eq!(
            create_widget["upstream"]["path_template"],
            json!("/widgets")
        );
        let get_widget = tools
            .iter()
            .find(|tool| tool["name"] == json!("getWidget"))
            .expect("getWidget should be generated");
        assert_eq!(get_widget["upstream"]["method"], json!("GET"));
        assert_eq!(
            body["api_key_header_auth_requirements"],
            json!([
                {
                    "tool_name": "getWidget",
                    "method": "GET",
                    "path_template": "/widgets/{widgetId}",
                    "scheme_name": "ApiKeyAuth",
                    "header_name": "X-API-Key"
                }
            ])
        );
        assert_eq!(body["skipped_operations"], json!([]));
    }

    #[tokio::test]
    async fn openapi_tools_preview_accepts_spec_content_types() {
        for content_type in [
            "text/plain; charset=utf-8",
            "application/yaml",
            "application/x-yaml",
        ] {
            let harness = tools_admin_harness(empty_tools_document(), test_audit_log()).await;

            let response = harness
                .router
                .oneshot(tools_openapi_preview_request_with_content_type(
                    &harness.admin_token,
                    widget_openapi_spec(),
                    content_type,
                ))
                .await
                .expect("OpenAPI tools preview request should complete");

            assert_eq!(response.status(), StatusCode::OK, "{content_type}");
            let body = json_body(response).await;
            assert!(
                body["tools"]
                    .as_array()
                    .expect("preview response should include tools")
                    .iter()
                    .any(|tool| tool["name"] == json!("createWidget")),
                "preview response should include createWidget for {content_type}: {body}"
            );
        }
    }

    #[tokio::test]
    async fn openapi_tools_preview_rejects_invalid_spec_without_500() {
        let harness = tools_admin_harness(empty_tools_document(), test_audit_log()).await;

        let response = harness
            .router
            .oneshot(tools_openapi_preview_request(
                &harness.admin_token,
                "openapi: [",
            ))
            .await
            .expect("invalid OpenAPI tools preview request should complete");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = json_body(response).await;
        assert!(
            body["error"]
                .as_str()
                .expect("error response should include message")
                .contains("invalid OpenAPI spec"),
            "unexpected body: {body}"
        );
    }

    #[tokio::test]
    async fn openapi_tools_preview_requires_read_permission_and_tools_file() {
        let harness = tools_admin_harness(empty_tools_document(), test_audit_log()).await;

        let forbidden = harness
            .router
            .clone()
            .oneshot(tools_openapi_preview_request(
                &harness.blocked_token,
                widget_openapi_spec(),
            ))
            .await
            .expect("read-forbidden OpenAPI tools preview request should complete");
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let policy = TempPolicyFile::new(&tools_policy_document());
        let token_db = TempDb::new("tools-preview-no-tools-file-token");
        let token_store =
            auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
        let admin_token = create_service_token(&token_store, &["admin"]);
        let mut config = test_config(Vec::new());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build without TOOLS_FILE");

        let not_configured = router
            .oneshot(tools_openapi_preview_request(
                &admin_token,
                widget_openapi_spec(),
            ))
            .await
            .expect("tools-file-unconfigured OpenAPI tools preview request should complete");
        assert_eq!(not_configured.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_string(not_configured).await,
            r#"{"error":"tools API requires TOOLS_FILE to be configured"}"#
        );
    }

    #[tokio::test]
    async fn openapi_tools_register_persists_selection_reloads_registry_and_audits() {
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log = audit::AuditLog::new(Arc::new(capture.clone()));
        let harness = tools_admin_harness(empty_tools_document(), audit_log).await;
        let preview = harness
            .router
            .clone()
            .oneshot(tools_openapi_preview_request(
                &harness.admin_token,
                widget_openapi_spec(),
            ))
            .await
            .expect("OpenAPI tools preview request should complete");
        assert_eq!(preview.status(), StatusCode::OK);
        let etag = preview
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .expect("preview should include ETag")
            .to_owned();

        let register = harness
            .router
            .clone()
            .oneshot(tools_openapi_register_request(
                &harness.admin_token,
                json!({
                    "spec": widget_openapi_spec(),
                    "selected_tool_names": ["createWidget"]
                }),
                Some(&etag),
            ))
            .await
            .expect("OpenAPI tools register request should complete");

        assert_eq!(register.status(), StatusCode::CREATED);
        let register_body = json_body(register).await;
        assert_eq!(
            register_body["registered_tool_names"],
            json!(["createWidget"])
        );
        assert_eq!(register_body["tool_count"], json!(1));
        let persisted = fs::read_to_string(&harness.tools.path).expect("tools file should read");
        let persisted: Value =
            serde_json::from_str(&persisted).expect("tools file should remain JSON");
        assert_eq!(persisted["tools"][0]["name"], json!("createWidget"));

        let (list_status, list_body) = mcp_rpc(
            &harness.router,
            Some(&harness.admin_token),
            41,
            "tools/list",
            None,
            "mcp-list-after-openapi-register",
        )
        .await;
        assert_eq!(list_status, StatusCode::OK);
        let listed_tools = list_body["result"]["tools"]
            .as_array()
            .expect("tools/list response should include tools");
        assert!(
            listed_tools
                .iter()
                .any(|tool| tool["name"] == json!("createWidget")),
            "registered tool should be visible through live MCP tools/list: {list_body}"
        );

        let event = captured_tool_registry_change(&capture, "openapi_tools_registered");
        assert_eq!(
            event.payload["registered_tool_names"],
            json!(["createWidget"])
        );
        assert_eq!(event.payload["registered_tool_count"], json!(1));
        assert_eq!(event.payload["tool_count"], json!(1));
        let actor = event.actor.as_ref().expect("actor should be set");
        assert_eq!(actor.roles, Some(vec!["admin".to_owned()]));
    }

    #[tokio::test]
    async fn openapi_tools_register_rejects_name_collisions_without_partial_persist() {
        let harness = tools_admin_harness(
            json!({
                "schema_version": "0.1.0",
                "tools": [
                    {
                        "name": "createWidget",
                        "description": "Existing hand-authored widget creator.",
                        "input_json_schema": {
                            "type": "object",
                            "properties": {
                                "message": { "type": "string" }
                            },
                            "additionalProperties": false
                        },
                        "upstream": {
                            "method": "POST",
                            "path_template": "/manual/widgets",
                            "body": { "mode": "whole_args_json" }
                        }
                    }
                ]
            })
            .to_string(),
            test_audit_log(),
        )
        .await;
        let before_contents =
            fs::read_to_string(&harness.tools.path).expect("tools file should read");
        let preview = harness
            .router
            .clone()
            .oneshot(tools_openapi_preview_request(
                &harness.admin_token,
                widget_openapi_spec(),
            ))
            .await
            .expect("OpenAPI tools preview request should complete");
        let etag = preview
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .expect("preview should include ETag")
            .to_owned();

        let response = harness
            .router
            .oneshot(tools_openapi_register_request(
                &harness.admin_token,
                json!({
                    "spec": widget_openapi_spec(),
                    "selected_tool_names": ["createWidget"]
                }),
                Some(&etag),
            ))
            .await
            .expect("colliding OpenAPI tools register request should complete");

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = json_body(response).await;
        assert_eq!(body["error"], json!("tool name collision"));
        assert_eq!(body["conflicts"], json!(["createWidget"]));
        assert_eq!(
            fs::read_to_string(&harness.tools.path).expect("tools file should read"),
            before_contents,
            "colliding register must not partially persist selected tools"
        );
    }

    #[tokio::test]
    async fn openapi_tools_register_rejects_auth_required_tools_without_partial_persist() {
        let harness = tools_admin_harness(empty_tools_document(), test_audit_log()).await;
        let before_contents =
            fs::read_to_string(&harness.tools.path).expect("tools file should read");
        let preview = harness
            .router
            .clone()
            .oneshot(tools_openapi_preview_request(
                &harness.admin_token,
                widget_openapi_spec(),
            ))
            .await
            .expect("OpenAPI tools preview request should complete");
        let etag = preview
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .expect("preview should include ETag")
            .to_owned();

        let response = harness
            .router
            .oneshot(tools_openapi_register_request(
                &harness.admin_token,
                json!({
                    "spec": widget_openapi_spec(),
                    "selected_tool_names": ["createWidget", "getWidget"]
                }),
                Some(&etag),
            ))
            .await
            .expect("auth-required OpenAPI tools register request should complete");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = json_body(response).await;
        assert_eq!(
            body["error"],
            json!("cannot register selected OpenAPI tools: upstream API-key header injection is not yet supported; see issue #36's known limitation")
        );
        assert_eq!(body["unsupported_tool_names"], json!(["getWidget"]));
        assert_eq!(
            fs::read_to_string(&harness.tools.path).expect("tools file should read"),
            before_contents,
            "auth-required register must not partially persist selected tools"
        );
    }

    #[tokio::test]
    async fn openapi_tools_register_requires_write_permission() {
        let harness = tools_admin_harness(empty_tools_document(), test_audit_log()).await;
        let preview = harness
            .router
            .clone()
            .oneshot(tools_openapi_preview_request(
                &harness.admin_token,
                widget_openapi_spec(),
            ))
            .await
            .expect("OpenAPI tools preview request should complete");
        let etag = preview
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .expect("preview should include ETag")
            .to_owned();

        let forbidden = harness
            .router
            .oneshot(tools_openapi_register_request(
                &harness.reader_token,
                json!({
                    "spec": widget_openapi_spec(),
                    "selected_tool_names": ["createWidget"]
                }),
                Some(&etag),
            ))
            .await
            .expect("write-forbidden OpenAPI tools register request should complete");

        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn token_admin_revoke_is_idempotent_requires_write_and_audits() {
        let token_db = TempDb::new("token-admin-revoke");
        let policy = TempPolicyFile::new(&token_policy_document_string());
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let router = token_admin_router(&token_db, &policy, audit_log);
        let created = create_token_via_endpoint(&router, &["probe-reader"]).await;
        let token_id = created["token"]["id"]
            .as_str()
            .expect("created response should include token id")
            .to_owned();

        let forbidden_revoke = router
            .clone()
            .oneshot(token_admin_request(
                Method::DELETE,
                &format!("{TOKENS_ADMIN_ROUTE}/{token_id}"),
                Some(test_principal(&["tokens-reader"])),
                None,
            ))
            .await
            .expect("read-only token revoke request should complete");
        assert_eq!(forbidden_revoke.status(), StatusCode::FORBIDDEN);

        let first = router
            .clone()
            .oneshot(token_admin_request(
                Method::DELETE,
                &format!("{TOKENS_ADMIN_ROUTE}/{token_id}"),
                Some(test_principal(&["tokens-writer"])),
                None,
            ))
            .await
            .expect("token revoke request should complete");
        assert_eq!(first.status(), StatusCode::OK);
        let first_body = json_body(first).await;
        let first_revoked_at = first_body["revoked_at"]
            .as_str()
            .expect("revoked token should include revoked_at")
            .to_owned();

        let second = router
            .clone()
            .oneshot(token_admin_request(
                Method::DELETE,
                &format!("{TOKENS_ADMIN_ROUTE}/{token_id}"),
                Some(test_principal(&["tokens-writer"])),
                None,
            ))
            .await
            .expect("second token revoke request should complete");
        assert_eq!(second.status(), StatusCode::OK);
        assert_eq!(
            json_body(second).await["revoked_at"],
            json!(first_revoked_at)
        );

        let event = captured_token_change(&capture, "token_revoked");
        assert_token_change_actor(&event);
        assert_eq!(event.payload["action"], json!("token_revoked"));
        assert_eq!(event.payload["token_id"], json!(token_id));
    }

    #[tokio::test]
    async fn token_admin_rotate_returns_new_plaintext_and_invalidates_old_bearer() {
        let token_db = TempDb::new("token-admin-rotate");
        let token_store =
            auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
        let created = token_store
            .create(auth::tokens::CreateTokenRequest {
                scopes: vec!["token-admin".to_owned(), "probe-reader".to_owned()],
                created_by: "bootstrap-admin".to_owned(),
                expires_at: None,
            })
            .expect("service token should create");
        let policy = TempPolicyFile::new(&service_token_policy_document());
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let mut config = test_config(Vec::new());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
        config.service_token_cache_ttl_ms = 5_000;
        config.rbac_exempt_paths.push(TOKENS_ADMIN_ROUTE.to_owned());
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            audit_log,
            test_audit_event_sender(),
        )
        .expect("app should build");

        let before_rotate = authenticated_principal_probe(&router, &created.plaintext_token).await;
        assert_eq!(before_rotate.status(), StatusCode::OK);

        let rotate_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("{TOKENS_ADMIN_ROUTE}/{}/rotate", created.record.id))
                    .header(
                        header::AUTHORIZATION,
                        format!("Bearer {}", created.plaintext_token),
                    )
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::empty())
                    .expect("rotate request should build"),
            )
            .await
            .expect("token rotate request should complete");
        assert_eq!(rotate_response.status(), StatusCode::OK);
        let rotate_body = json_body(rotate_response).await;
        let new_plaintext = rotate_body["plaintext_token"]
            .as_str()
            .expect("rotate response should include new one-time plaintext")
            .to_owned();
        assert_ne!(new_plaintext, created.plaintext_token);
        assert!(rotate_body["plaintext_token_notice"]
            .as_str()
            .unwrap_or_default()
            .contains("will not be shown again"));

        let old_probe = authenticated_principal_probe(&router, &created.plaintext_token).await;
        assert_eq!(old_probe.status(), StatusCode::UNAUTHORIZED);
        let new_probe = authenticated_principal_probe(&router, &new_plaintext).await;
        assert_eq!(new_probe.status(), StatusCode::OK);

        let event = captured_token_change(&capture, "token_rotated");
        let actor = event.actor.as_ref().expect("rotate actor should be set");
        assert_eq!(
            actor.user_id,
            format!("service-token:{}", created.record.id)
        );
        assert_eq!(actor.auth_mode, "service_token");
        assert_eq!(event.payload["action"], json!("token_rotated"));
        assert_eq!(event.payload["token_id"], json!(created.record.id));
        let audit_serialized = serde_json::to_string(&event).unwrap();
        assert!(!audit_serialized.contains(&created.plaintext_token));
        assert!(!audit_serialized.contains(&new_plaintext));
        assert!(!audit_serialized.contains("token_hash"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_policy_rule_patch_and_policy_put_with_same_if_match_allow_only_one_update()
    {
        let initial_policy = policy_document_with_rules_string(
            "initial-policy",
            json!([direct_rule_json(
                Some("managed-rule"),
                &["GET"],
                "/managed",
                "allow"
            )]),
        );
        let policy = TempPolicyFile::new(&initial_policy);
        let router = policy_admin_router(Some(&policy), test_audit_log());
        let (current_etag, _) = current_policy(&router).await;

        let patch_body = json!({ "action": "deny" }).to_string();
        let whole_policy = policy_document("concurrent-put-policy", "test:old");
        let whole_policy_body =
            serde_json::to_string_pretty(&whole_policy).expect("test policy should serialize");
        let body_barrier = Arc::new(tokio::sync::Barrier::new(3));

        let patch_task = tokio::spawn({
            let router = router.clone();
            let current_etag = current_etag.clone();
            let body_barrier = Arc::clone(&body_barrier);

            async move {
                router
                    .oneshot(synchronized_policy_admin_request(
                        Method::PATCH,
                        &format!("{POLICY_RULES_ADMIN_ROUTE}/managed-rule"),
                        patch_body,
                        &current_etag,
                        body_barrier,
                    ))
                    .await
                    .expect("rule PATCH should complete")
            }
        });
        let put_task = tokio::spawn({
            let router = router.clone();
            let current_etag = current_etag.clone();
            let body_barrier = Arc::clone(&body_barrier);

            async move {
                router
                    .oneshot(synchronized_policy_put_request(
                        whole_policy_body,
                        &current_etag,
                        body_barrier,
                    ))
                    .await
                    .expect("policy PUT should complete")
            }
        });

        tokio::time::timeout(Duration::from_secs(2), body_barrier.wait())
            .await
            .expect("both policy mutation bodies should reach the release barrier");

        let (patch_response, put_response) = tokio::join!(patch_task, put_task);
        let patch_response = patch_response.expect("rule PATCH task should join");
        let put_response = put_response.expect("policy PUT task should join");

        let patch_status = patch_response.status();
        let patch_etag =
            (patch_status == StatusCode::OK).then(|| policy_etag_header(&patch_response));
        if patch_status == StatusCode::OK {
            assert_eq!(json_body(patch_response).await["action"], json!("deny"));
        } else {
            assert_eq!(patch_status, StatusCode::PRECONDITION_FAILED);
            assert_eq!(
                body_string(patch_response).await,
                r#"{"error":"If-Match does not match the current policy ETag"}"#
            );
        }

        let put_status = put_response.status();
        let put_etag = (put_status == StatusCode::OK).then(|| policy_etag_header(&put_response));
        if put_status == StatusCode::OK {
            assert_eq!(
                json_body(put_response).await["id"],
                json!("concurrent-put-policy")
            );
        } else {
            assert_eq!(put_status, StatusCode::PRECONDITION_FAILED);
            assert_eq!(
                body_string(put_response).await,
                r#"{"error":"If-Match does not match the current policy ETag"}"#
            );
        }

        assert_eq!(
            [patch_status, put_status]
                .iter()
                .filter(|status| **status == StatusCode::OK)
                .count(),
            1
        );
        assert_eq!(
            [patch_status, put_status]
                .iter()
                .filter(|status| **status == StatusCode::PRECONDITION_FAILED)
                .count(),
            1
        );

        let (live_etag, live_policy) = current_policy(&router).await;
        if patch_status == StatusCode::OK {
            assert_eq!(live_etag, patch_etag.expect("PATCH should include ETag"));
            assert_eq!(live_policy["id"], json!("initial-policy"));
            assert_eq!(live_policy["rules"][0]["id"], json!("managed-rule"));
            assert_eq!(live_policy["rules"][0]["action"], json!("deny"));
        } else {
            assert_eq!(live_etag, put_etag.expect("PUT should include ETag"));
            assert_eq!(live_policy["id"], json!("concurrent-put-policy"));
            assert_eq!(live_policy["rules"], json!([]));
        }
    }

    #[tokio::test]
    async fn policy_validate_accepts_valid_candidate_without_changing_live_policy_or_file() {
        let initial_policy = policy_document_string("initial-policy", "test:old");
        let policy = TempPolicyFile::new(&initial_policy);
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let router = policy_admin_router(Some(&policy), audit_log);
        let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");

        let get_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("policy GET should complete");
        let current_etag = policy_etag_header(&get_response);

        let response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::POST,
                POLICY_VALIDATE_ADMIN_ROUTE,
                Some(test_principal(&["policy-reader"])),
                Some(policy_document_string("validated-only", "test:new")),
                None,
            ))
            .await
            .expect("policy validate should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(json_body(response).await, json!({ "valid": true }));
        assert_eq!(
            fs::read_to_string(&policy.path).expect("policy file should read"),
            before_contents
        );
        assert!(!capture
            .events()
            .iter()
            .any(|event| event.event_type == audit::event::POLICY_CHANGED));

        let after_get = router
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("policy GET after validate should complete");
        assert_eq!(policy_etag_header(&after_get), current_etag);
        assert_eq!(json_body(after_get).await["id"], json!("initial-policy"));
    }

    #[tokio::test]
    async fn policy_validate_invalid_candidate_returns_errors_without_changes() {
        let initial_policy = policy_document_string("initial-policy", "test:old");
        let policy = TempPolicyFile::new(&initial_policy);
        let router = policy_admin_router(Some(&policy), test_audit_log());
        let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");

        let response = router
            .oneshot(policy_admin_request(
                Method::POST,
                POLICY_VALIDATE_ADMIN_ROUTE,
                Some(test_principal(&["policy-reader"])),
                Some(r#"{ "schema_version": "1.0.0" }"#.to_owned()),
                None,
            ))
            .await
            .expect("invalid policy validate should complete");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = json_body(response).await;
        assert_eq!(body["valid"], json!(false));
        assert!(
            body["errors"][0]
                .as_str()
                .unwrap_or_default()
                .contains("schema_version must start with"),
            "unexpected validation body: {body}"
        );
        assert_eq!(
            fs::read_to_string(&policy.path).expect("policy file should read"),
            before_contents
        );
    }

    #[tokio::test]
    async fn policy_rule_preview_returns_matches_samples_and_does_not_mutate_policy() {
        let db = TempDb::new("rule-preview");
        create_audit_schema(&db.path);
        seed_rule_preview_events(&db.path);
        let initial_policy = policy_document_string("initial-policy", "test:old");
        let policy = TempPolicyFile::new(&initial_policy);
        let before_contents = fs::read_to_string(&policy.path).expect("policy file should read");
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let router = policy_admin_router_with_sqlite(Some(&policy), audit_log, Some(&db.path));

        let get_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("policy GET should complete");
        let before_etag = policy_etag_header(&get_response);

        let preview_body = json!({
            "rule": {
                "methods": ["GET"],
                "path": "/api/items/{id}",
                "principal": {
                    "roles": ["reader"],
                    "auth_methods": ["bearer_token"]
                },
                "action": "deny"
            },
            "from": "2024-06-01T12:00:00Z",
            "to": "2024-06-01T12:00:05Z",
            "sample_limit": 2
        })
        .to_string();
        let response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::POST,
                POLICY_RULE_PREVIEW_ADMIN_ROUTE,
                Some(test_principal(&["policy-reader"])),
                Some(preview_body),
                None,
            ))
            .await
            .expect("policy rule preview should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["match_count"], json!(2));
        assert_eq!(body["scanned_event_count"], json!(3));
        assert_eq!(body["sample_strategy"], json!("newest_matches"));
        assert_eq!(body["samples"][0]["event_id"], json!("match-new"));
        assert_eq!(body["samples"][0]["method"], json!("GET"));
        assert_eq!(body["samples"][0]["path"], json!("/api/items/4"));
        assert_eq!(body["samples"][0]["actor"]["user_id"], json!("reader-1"));
        assert_eq!(body["samples"][0]["policy_decision"], json!("allowed"));
        assert_eq!(body["samples"][1]["event_id"], json!("match-old"));

        assert_eq!(
            fs::read_to_string(&policy.path).expect("policy file should read"),
            before_contents
        );
        assert!(!capture
            .events()
            .iter()
            .any(|event| event.event_type == audit::event::POLICY_CHANGED));

        let after_get = router
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("policy GET after preview should complete");
        assert_eq!(policy_etag_header(&after_get), before_etag);
        assert_eq!(json_body(after_get).await["id"], json!("initial-policy"));
    }

    #[tokio::test]
    async fn policy_rule_preview_zero_matches_returns_empty_samples() {
        let db = TempDb::new("rule-preview-zero");
        create_audit_schema(&db.path);
        seed_rule_preview_events(&db.path);
        let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
        let router =
            policy_admin_router_with_sqlite(Some(&policy), test_audit_log(), Some(&db.path));

        let response = router
            .oneshot(policy_admin_request(
                Method::POST,
                POLICY_RULE_PREVIEW_ADMIN_ROUTE,
                Some(test_principal(&["policy-reader"])),
                Some(
                    json!({
                        "rule": {
                            "methods": ["DELETE"],
                            "path": "/api/items/{id}",
                            "action": "deny"
                        },
                        "from": "2024-06-01T12:00:00Z",
                        "to": "2024-06-01T12:00:05Z"
                    })
                    .to_string(),
                ),
                None,
            ))
            .await
            .expect("policy rule preview should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["match_count"], json!(0));
        assert_eq!(body["samples"], json!([]));
    }

    #[tokio::test]
    async fn policy_rule_preview_requires_audit_sqlite_path() {
        let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
        let router = policy_admin_router(Some(&policy), test_audit_log());

        let response = router
            .oneshot(policy_admin_request(
                Method::POST,
                POLICY_RULE_PREVIEW_ADMIN_ROUTE,
                Some(test_principal(&["policy-reader"])),
                Some(
                    json!({
                        "rule": {
                            "methods": ["GET"],
                            "path": "/api/items/{id}",
                            "action": "deny"
                        }
                    })
                    .to_string(),
                ),
                None,
            ))
            .await
            .expect("policy rule preview should complete");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            json_body(response).await,
            json!({ "error": "policy rule preview requires AUDIT_SQLITE_PATH to be configured" })
        );
    }

    #[tokio::test]
    async fn policy_rule_preview_requires_policy_read_permission() {
        let db = TempDb::new("rule-preview-forbidden");
        create_audit_schema(&db.path);
        let policy = TempPolicyFile::new(&policy_document_string("initial-policy", "test:old"));
        let router =
            policy_admin_router_with_sqlite(Some(&policy), test_audit_log(), Some(&db.path));

        let response = router
            .oneshot(policy_admin_request(
                Method::POST,
                POLICY_RULE_PREVIEW_ADMIN_ROUTE,
                Some(test_principal(&["reader"])),
                Some(
                    json!({
                        "rule": {
                            "methods": ["GET"],
                            "path": "/api/items/{id}",
                            "action": "deny"
                        }
                    })
                    .to_string(),
                ),
                None,
            ))
            .await
            .expect("policy rule preview should complete");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn policy_rule_hits_count_real_rbac_observation_events() {
        let db = TempDb::new("rule-hits-real-middleware");
        let policy = TempPolicyFile::new(&direct_rule_policy_document());
        let mut config = policy_admin_config_with_sqlite(Some(&policy), Some(&db.path));
        config.rbac_exempt_paths.push(POLICY_ADMIN_ROUTE.to_owned());
        let recorder = PrometheusBuilder::new().build_recorder();
        let (audit_log, audit_event_sender) = audit_log_with_sqlite_and_broadcast(&db.path);
        let router = app(config, recorder.handle(), audit_log, audit_event_sender)
            .expect("app should build");

        for _ in 0..2 {
            let response = router
                .clone()
                .oneshot(audit_query_request(
                    "/__test/principal",
                    Some(test_principal(&["member"])),
                ))
                .await
                .expect("direct allow request should complete");
            assert_eq!(response.status(), StatusCode::OK);
        }
        let denied = router
            .clone()
            .oneshot(audit_query_request(
                "/__test/blocked",
                Some(test_principal(&["member"])),
            ))
            .await
            .expect("direct deny request should complete");
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);

        let body = wait_for_rule_hits(router, |body| {
            rule_hit(body, "allow-principal-probe") == Some(2)
                && rule_hit(body, "deny-blocked") == Some(1)
        })
        .await;

        assert_eq!(rule_hit(&body, "allow-principal-probe"), Some(2));
        assert_eq!(rule_hit(&body, "deny-blocked"), Some(1));
    }

    #[tokio::test]
    async fn policy_rule_hits_return_zero_counts_when_sqlite_is_unset() {
        let policy = TempPolicyFile::new(&direct_rule_policy_document());
        let router = policy_admin_router(Some(&policy), test_audit_log());

        let response = router
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_RULE_HITS_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("policy rule hits should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(rule_hit(&body, "allow-principal-probe"), Some(0));
        assert_eq!(rule_hit(&body, "deny-blocked"), Some(0));
    }

    #[tokio::test]
    async fn policy_rule_shadow_review_returns_enabled_shadow_rules_with_would_deny_summaries() {
        let db = TempDb::new("policy-shadow-review");
        create_audit_schema(&db.path);
        insert_authz_event(
            &db.path,
            SeedAuthzEvent {
                event_id: "shadow-reports-1",
                event_type: "authz.would_deny",
                timestamp: "2024-06-01T12:00:00Z",
                actor_user_id: Some("analyst-1"),
                roles: &["analyst"],
                method: "GET",
                request_path: "/reports/1",
                matched_rule_id: Some("shadow-reports"),
            },
        );
        insert_authz_event(
            &db.path,
            SeedAuthzEvent {
                event_id: "allow-reports-1",
                event_type: "authz.would_deny",
                timestamp: "2024-06-01T12:00:01Z",
                actor_user_id: Some("analyst-2"),
                roles: &["analyst"],
                method: "GET",
                request_path: "/allow/1",
                matched_rule_id: Some("allow-reports"),
            },
        );
        insert_authz_event(
            &db.path,
            SeedAuthzEvent {
                event_id: "disabled-shadow-1",
                event_type: "authz.would_deny",
                timestamp: "2024-06-01T12:00:02Z",
                actor_user_id: Some("analyst-3"),
                roles: &["analyst"],
                method: "GET",
                request_path: "/disabled/1",
                matched_rule_id: Some("shadow-disabled"),
            },
        );
        insert_authz_event(
            &db.path,
            SeedAuthzEvent {
                event_id: "shadow-reports-2",
                event_type: "authz.would_deny",
                timestamp: "2024-06-01T12:00:03Z",
                actor_user_id: Some("analyst-2"),
                roles: &["analyst", "manager"],
                method: "DELETE",
                request_path: "/reports/2",
                matched_rule_id: Some("shadow-reports"),
            },
        );
        let policy = TempPolicyFile::new(&shadow_review_policy_document());
        let router =
            policy_admin_router_with_sqlite(Some(&policy), test_audit_log(), Some(&db.path));

        let response = router
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_RULE_SHADOW_REVIEW_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("policy shadow review should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(
            shadow_review_rule_ids(&body),
            vec!["shadow-reports".to_owned(), "shadow-exports".to_owned()]
        );
        let reports = shadow_review_rule(&body, "shadow-reports")
            .expect("shadow reports rule should be present");
        assert_eq!(reports["rule"]["action"], json!("shadow"));
        assert_eq!(reports["would_deny_count"], json!(2));
        assert_eq!(
            reports["affected_principals"],
            json!([
                {
                    "user_id": "analyst-2",
                    "roles": ["analyst", "manager"]
                },
                {
                    "user_id": "analyst-1",
                    "roles": ["analyst"]
                }
            ])
        );
        assert_eq!(reports["samples"][0]["method"], json!("DELETE"));
        assert_eq!(reports["samples"][0]["path"], json!("/reports/2"));
        assert_eq!(
            reports["samples"][0]["actor"]["user_id"],
            json!("analyst-2")
        );

        let exports = shadow_review_rule(&body, "shadow-exports")
            .expect("shadow exports rule should be present");
        assert_eq!(exports["would_deny_count"], json!(0));
        assert_eq!(exports["affected_principals"], json!([]));
        assert_eq!(exports["samples"], json!([]));
    }

    #[tokio::test]
    async fn policy_rule_shadow_review_returns_zero_counts_when_sqlite_is_unset() {
        let policy = TempPolicyFile::new(&shadow_review_policy_document());
        let router = policy_admin_router(Some(&policy), test_audit_log());

        let response = router
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_RULE_SHADOW_REVIEW_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("policy shadow review should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(
            shadow_review_rule_ids(&body),
            vec!["shadow-reports".to_owned(), "shadow-exports".to_owned()]
        );
        assert_eq!(
            shadow_review_rule(&body, "shadow-reports")
                .and_then(|rule| rule["would_deny_count"].as_u64()),
            Some(0)
        );
        assert_eq!(
            shadow_review_rule(&body, "shadow-exports")
                .and_then(|rule| rule["would_deny_count"].as_u64()),
            Some(0)
        );
    }

    #[test]
    fn policy_rule_preview_moderate_scale_completes_under_two_seconds() {
        let db = TempDb::new("rule-preview-performance");
        create_audit_schema(&db.path);
        let event_count = 50_000;
        bulk_insert_preview_events(&db.path, event_count);
        let store = audit::query::AuditQueryStore::open(&db.path).expect("query store should open");
        let request = PolicyRulePreviewRequest {
            rule: rbac::Rule {
                id: None,
                enabled: true,
                methods: vec!["GET".to_owned()],
                path: "/load/{id}".to_owned(),
                tool_name: None,
                principal: rbac::PrincipalMatcher {
                    roles: vec!["reader".to_owned()],
                    auth_methods: vec!["bearer_token".to_owned()],
                    principal_ids: Vec::new(),
                },
                action: rbac::RuleAction::Deny,
            },
            from: Some("2026-01-01T00:00:00Z".to_owned()),
            to: Some("2026-01-02T00:00:00Z".to_owned()),
            sample_limit: Some(5),
        };

        let started = Instant::now();
        let response = preview_rule(&store, request).expect("preview should complete");
        let elapsed = started.elapsed();
        println!(
            "previewed {event_count} synthetic events in {elapsed:?}; scanned={}, matched={}",
            response.scanned_event_count, response.match_count
        );

        assert_eq!(response.match_count, 5_000);
        assert_eq!(response.samples.len(), 5);
        assert!(
            elapsed < Duration::from_secs(2),
            "50k-row preview took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn policy_admin_endpoints_return_not_found_when_policy_file_is_unset() {
        let router = policy_admin_router(None, test_audit_log());

        let get_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("policy GET without policy file should complete");
        assert_eq!(get_response.status(), StatusCode::NOT_FOUND);

        let put_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::PUT,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                Some(policy_document_string("updated-policy", "test:new")),
                Some("\"sha256:anything\""),
            ))
            .await
            .expect("policy PUT without policy file should complete");
        assert_eq!(put_response.status(), StatusCode::NOT_FOUND);

        let validate_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::POST,
                POLICY_VALIDATE_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                Some(policy_document_string("updated-policy", "test:new")),
                None,
            ))
            .await
            .expect("policy validate without policy file should complete");
        assert_eq!(validate_response.status(), StatusCode::NOT_FOUND);

        let preview_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::POST,
                POLICY_RULE_PREVIEW_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                Some(
                    json!({
                        "rule": {
                            "methods": ["GET"],
                            "path": "/api/items/{id}",
                            "action": "deny"
                        }
                    })
                    .to_string(),
                ),
                None,
            ))
            .await
            .expect("policy preview without policy file should complete");
        assert_eq!(preview_response.status(), StatusCode::NOT_FOUND);

        let hits_response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_RULE_HITS_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("policy hits without policy file should complete");
        assert_eq!(hits_response.status(), StatusCode::NOT_FOUND);

        let shadow_review_response = router
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_RULE_SHADOW_REVIEW_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("policy shadow review without policy file should complete");
        assert_eq!(shadow_review_response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn schema_coverage_reports_undocumented_endpoints_and_unused_operations() {
        let discovery_db = TempDb::new("schema-coverage");
        seed_discovery_endpoint(&discovery_db.path, "GET", "/users/{id}");
        seed_discovery_endpoint(&discovery_db.path, "POST", "/users");
        seed_discovery_endpoint(&discovery_db.path, "GET", "/internal/health");
        seed_discovery_endpoint(&discovery_db.path, "GET", "/reports/{id}/summary/details");
        let spec = TempSpecFile::new(
            "coverage",
            r#"
openapi: 3.0.3
info:
  title: Coverage API
  version: 1.0.0
paths:
  /users/{userId}:
    get:
      operationId: getUser
      summary: Fetch a user
    patch:
      operationId: updateUser
      summary: Update a user
  /users:
    post:
      operationId: createUser
  /reports/{reportId}/summary:
    get:
      operationId: reportSummary
"#,
        );
        let policy = TempPolicyFile::new(&schema_policy_document());
        let router = schema_coverage_router(Some(&spec), Some(&discovery_db), &policy);

        let response = router
            .oneshot(audit_query_request(
                SCHEMA_COVERAGE_ADMIN_ROUTE,
                Some(test_principal(&["schema-reader"])),
            ))
            .await
            .expect("schema coverage request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["spec_configured"], true);
        assert_eq!(body["discovery_configured"], true);
        assert_eq!(
            body["undocumented_endpoints"],
            json!([
                {
                    "method": "GET",
                    "endpoint_template": "/internal/health"
                },
                {
                    "method": "GET",
                    "endpoint_template": "/reports/{id}/summary/details"
                }
            ])
        );
        assert_eq!(
            body["unused_operations"],
            json!([
                {
                    "method": "GET",
                    "path_template": "/reports/{reportId}/summary",
                    "operation_id": "reportSummary",
                    "source": spec.path.to_string_lossy()
                },
                {
                    "method": "PATCH",
                    "path_template": "/users/{userId}",
                    "operation_id": "updateUser",
                    "summary": "Update a user",
                    "source": spec.path.to_string_lossy()
                }
            ])
        );
    }

    #[tokio::test]
    async fn schema_coverage_without_spec_returns_not_found() {
        let discovery_db = TempDb::new("schema-no-spec");
        seed_discovery_endpoint(&discovery_db.path, "GET", "/users/{id}");
        let policy = TempPolicyFile::new(&schema_policy_document());
        let router = schema_coverage_router(None, Some(&discovery_db), &policy);

        let response = router
            .oneshot(audit_query_request(
                SCHEMA_COVERAGE_ADMIN_ROUTE,
                Some(test_principal(&["schema-reader"])),
            ))
            .await
            .expect("schema coverage request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_string(response).await,
            r#"{"error":"schema coverage requires OPENAPI_SPEC_PATH or UPSTREAM_ROUTES[].openapi_spec_path to be configured","spec_configured":false}"#
        );
    }

    #[tokio::test]
    async fn schema_coverage_without_discovery_store_returns_service_unavailable() {
        let spec = TempSpecFile::new(
            "no-discovery",
            r#"
openapi: 3.0.3
info:
  title: Coverage API
  version: 1.0.0
paths:
  /users/{userId}:
    get:
      operationId: getUser
"#,
        );
        let policy = TempPolicyFile::new(&schema_policy_document());
        let router = schema_coverage_router(Some(&spec), None, &policy);

        let response = router
            .oneshot(audit_query_request(
                SCHEMA_COVERAGE_ADMIN_ROUTE,
                Some(test_principal(&["schema-reader"])),
            ))
            .await
            .expect("schema coverage request should complete");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body_string(response).await,
            r#"{"error":"schema coverage requires DISCOVERY_SQLITE_PATH to be configured","discovery_configured":false}"#
        );
    }

    #[tokio::test]
    async fn schema_coverage_requires_schema_read_permission() {
        let discovery_db = TempDb::new("schema-authz");
        seed_discovery_endpoint(&discovery_db.path, "GET", "/users/{id}");
        let spec = TempSpecFile::new(
            "authz",
            r#"
openapi: 3.0.3
info:
  title: Coverage API
  version: 1.0.0
paths:
  /users/{userId}:
    get:
      operationId: getUser
"#,
        );
        let policy = TempPolicyFile::new(&schema_policy_document());
        let router = schema_coverage_router(Some(&spec), Some(&discovery_db), &policy);

        let unauthenticated = router
            .clone()
            .oneshot(audit_query_request(SCHEMA_COVERAGE_ADMIN_ROUTE, None))
            .await
            .expect("unauthenticated request should complete");
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_string(unauthenticated).await,
            r#"{"error":"unauthorized"}"#
        );

        let forbidden_response = router
            .oneshot(audit_query_request(
                SCHEMA_COVERAGE_ADMIN_ROUTE,
                Some(test_principal(&["reader"])),
            ))
            .await
            .expect("forbidden request should complete");
        assert_eq!(forbidden_response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_string(forbidden_response).await,
            r#"{"error":"forbidden"}"#
        );
    }

    #[tokio::test]
    async fn schema_inference_returns_inferred_payload_shape_schema() {
        let discovery_db = TempDb::new("schema-inferred");
        seed_payload_shape_samples(
            &discovery_db.path,
            "POST",
            "/users/{id}",
            &[
                json!({
                    "query_params": [
                        { "name": "page", "redacted": false, "value_type": "number" },
                        { "name": "search", "redacted": false, "value_type": "string" }
                    ],
                    "json_body": {
                        "top_level_keys": [
                            { "name": "display_name", "redacted": false },
                            { "name_hash": "sha256:redacted-body-key", "redacted": true }
                        ]
                    }
                }),
                json!({
                    "query_params": [
                        { "name": "page", "redacted": false, "value_type": "number" }
                    ],
                    "json_body": {
                        "top_level_keys": [
                            { "name": "display_name", "redacted": false }
                        ]
                    }
                }),
            ],
        );
        let policy = TempPolicyFile::new(&schema_policy_document());
        let router = schema_inference_router(Some(&discovery_db), true, &policy);
        let template = query_encode("/users/{id}");

        let response = router
            .oneshot(audit_query_request(
                &format!("/v1/admin/schema/inferred?method=POST&endpoint_template={template}"),
                Some(test_principal(&["schema-reader"])),
            ))
            .await
            .expect("schema inference request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["method"], json!("POST"));
        assert_eq!(body["endpoint_template"], json!("/users/{id}"));
        assert_eq!(body["sample_count"], json!(2));
        assert_eq!(body["required_threshold"], json!(0.95));
        assert_eq!(
            body["query_params"],
            json!([
                {
                    "name": "page",
                    "redacted": false,
                    "present_count": 2,
                    "frequency": 1.0,
                    "required": true,
                    "value_types": [
                        { "value_type": "number", "count": 2 }
                    ]
                },
                {
                    "name": "search",
                    "redacted": false,
                    "present_count": 1,
                    "frequency": 0.5,
                    "required": false,
                    "value_types": [
                        { "value_type": "string", "count": 1 }
                    ]
                }
            ])
        );
        assert_eq!(
            body["json_body_keys"],
            json!([
                {
                    "name": "display_name",
                    "redacted": false,
                    "present_count": 2,
                    "frequency": 1.0,
                    "required": true
                },
                {
                    "name_hash": "sha256:redacted-body-key",
                    "redacted": true,
                    "present_count": 1,
                    "frequency": 0.5,
                    "required": false
                }
            ])
        );
    }

    #[tokio::test]
    async fn schema_inference_distinguishes_payload_capture_disabled_from_no_samples() {
        let discovery_db = TempDb::new("schema-inferred-empty");
        let policy = TempPolicyFile::new(&schema_policy_document());
        let configured_router = schema_inference_router(Some(&discovery_db), true, &policy);
        let template = query_encode("/users/{id}");

        let no_samples = configured_router
            .oneshot(audit_query_request(
                &format!("/v1/admin/schema/inferred?method=POST&endpoint_template={template}"),
                Some(test_principal(&["schema-reader"])),
            ))
            .await
            .expect("schema inference no-samples request should complete");

        assert_eq!(no_samples.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_string(no_samples).await,
            r#"{"error":"inferred schema has no captured payload samples for method and endpoint_template","schema_inferred":false}"#
        );

        let disabled_router = schema_inference_router(Some(&discovery_db), false, &policy);
        let disabled = disabled_router
            .oneshot(audit_query_request(
                &format!("/v1/admin/schema/inferred?method=POST&endpoint_template={template}"),
                Some(test_principal(&["schema-reader"])),
            ))
            .await
            .expect("schema inference disabled request should complete");

        assert_eq!(disabled.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            body_string(disabled).await,
            r#"{"error":"inferred schema requires PAYLOAD_CAPTURE_ENABLED=true","payload_capture_configured":false}"#
        );
    }

    #[tokio::test]
    async fn schema_inference_requires_schema_read_permission() {
        let discovery_db = TempDb::new("schema-inferred-authz");
        seed_payload_shape_samples(
            &discovery_db.path,
            "GET",
            "/users",
            &[json!({
                "query_params": [
                    { "name": "page", "redacted": false, "value_type": "number" }
                ]
            })],
        );
        let policy = TempPolicyFile::new(&schema_policy_document());
        let router = schema_inference_router(Some(&discovery_db), true, &policy);

        let unauthenticated = router
            .clone()
            .oneshot(audit_query_request(
                "/v1/admin/schema/inferred?method=GET&endpoint_template=%2Fusers",
                None,
            ))
            .await
            .expect("unauthenticated schema inference request should complete");
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            body_string(unauthenticated).await,
            r#"{"error":"unauthorized"}"#
        );

        let forbidden_response = router
            .oneshot(audit_query_request(
                "/v1/admin/schema/inferred?method=GET&endpoint_template=%2Fusers",
                Some(test_principal(&["reader"])),
            ))
            .await
            .expect("forbidden schema inference request should complete");
        assert_eq!(forbidden_response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            body_string(forbidden_response).await,
            r#"{"error":"forbidden"}"#
        );
    }

    #[test]
    fn missing_openapi_spec_file_returns_actionable_startup_error() {
        let mut config = test_config(Vec::new());
        config.openapi_spec_path = Some(
            std::env::temp_dir().join(format!("missing-openapi-{}.yaml", uuid::Uuid::new_v4())),
        );
        let recorder = PrometheusBuilder::new().build_recorder();

        let error = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect_err("app startup should reject missing OpenAPI spec file");
        let message = error.to_string();

        assert!(
            message.contains("OpenAPI schema configuration is invalid"),
            "unexpected startup error: {message}"
        );
        assert!(
            message.contains("OPENAPI_SPEC_PATH"),
            "startup error should name OPENAPI_SPEC_PATH: {message}"
        );
    }

    #[test]
    fn broken_openapi_spec_file_returns_actionable_startup_error() {
        let spec = TempSpecFile::new("broken", "openapi: 2.0\npaths: {}\n");
        let mut config = test_config(Vec::new());
        config.openapi_spec_path = Some(spec.path.clone());
        let recorder = PrometheusBuilder::new().build_recorder();

        let error = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect_err("app startup should reject broken OpenAPI spec file");
        let message = error.to_string();

        assert!(
            message.contains("OpenAPI schema configuration is invalid"),
            "unexpected startup error: {message}"
        );
        assert!(
            message.contains("OPENAPI_SPEC_PATH"),
            "startup error should name OPENAPI_SPEC_PATH: {message}"
        );
        assert!(
            message.contains("OpenAPI 3.x"),
            "startup error should explain the expected spec version: {message}"
        );
    }

    #[tokio::test]
    async fn status_uptime_increases_between_requests() {
        let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        let config = status_config_with_policy(config, &policy);
        let router = status_router(config, Instant::now() - Duration::from_secs(30));

        let first = status_json(router.clone(), Some(test_principal(&["status-reader"]))).await;
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let second = status_json(router, Some(test_principal(&["status-reader"]))).await;

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
        let (router, audit_log, _policy) = audit_events_router();
        let response = router
            .oneshot(audit_query_request(
                AUDIT_EVENTS_STREAM_ROUTE,
                Some(test_principal(&["audit-streamer"])),
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
        let (router, audit_log, _policy) = audit_events_router();
        let response = router
            .oneshot(audit_query_request(
                &format!("{AUDIT_EVENTS_STREAM_ROUTE}?event_type=audit.sse.match&path=/match"),
                Some(test_principal(&["audit-streamer"])),
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
        let (router, _, _policy) = audit_events_router();
        let response = router
            .clone()
            .oneshot(audit_query_request(
                &format!(
                    "{AUDIT_EVENTS_STREAM_ROUTE}?event_type=http.request_observed&path=/health"
                ),
                Some(test_principal(&["audit-streamer"])),
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
    async fn audit_events_stream_delivers_signal_opened_events_from_discovery() {
        let discovery_db = TempDb::new("signal-opened-stream");
        let (upstream_addr, _upstream_rx) = spawn_capture_upstream().await;
        let mut config = proxy_config(upstream_addr);
        config.auth_enabled = false;
        config.discovery_sqlite_path = Some(discovery_db.path.to_string_lossy().into_owned());
        let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config
            .rbac_exempt_paths
            .push(AUDIT_EVENTS_STREAM_ROUTE.to_owned());
        config
            .rbac_exempt_paths
            .push("/signal-stream-opened".to_owned());
        let recorder = PrometheusBuilder::new().build_recorder();
        let (audit_log, audit_event_sender) =
            audit::AuditLog::from_config(&config).expect("audit log should build");
        let router = app(config, recorder.handle(), audit_log, audit_event_sender)
            .expect("app should build");

        let stream_response = router
            .clone()
            .oneshot(audit_query_request(
                &format!("{AUDIT_EVENTS_STREAM_ROUTE}?event_type=signal.opened"),
                Some(test_principal(&["audit-streamer"])),
            ))
            .await
            .expect("stream request should complete");
        assert_eq!(stream_response.status(), StatusCode::OK);

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/signal-stream-opened")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("data request should complete");
        assert_eq!(response.status(), StatusCode::CREATED);

        let body = read_sse_until(stream_response.into_body(), |body| {
            body.contains(r#""event_type":"signal.opened""#)
                && body.contains(r#""signal_type":"new_endpoint_seen""#)
                && body.contains(r#""endpoint_template":"/signal-stream-opened""#)
        })
        .await;

        assert!(body.contains("event: signal.opened"));
        assert!(body.contains(r#""state":"open""#));
        assert!(body.contains(r#""target":"#));
        assert!(body.contains(r#""kind":"endpoint""#));
        assert!(body.contains(r#""explanation":"New endpoint observed: GET /signal-stream-opened"#));
    }

    #[tokio::test]
    async fn audit_events_stream_delivers_signal_lifecycle_transitions() {
        let discovery_db = TempDb::new("signal-transition-stream");
        create_signal_schema(&discovery_db.path);
        insert_signal(
            &discovery_db.path,
            SignalSeed {
                id: "sig-stream-ack",
                signal_type: "new_endpoint_seen",
                method: "GET",
                endpoint_template: "/stream/{id}",
                explanation:
                    "New endpoint observed: GET /stream/{id} was first seen at 2024-06-01T00:00:00Z.",
                evidence: json!({
                    "first_seen": "2024-06-01T00:00:00Z",
                    "initial_call_count": 1
                }),
                state: "open",
                created_at: "2024-06-01T00:00:00Z",
                transitioned_at: None,
                transitioned_by: None,
            },
        );
        let policy = TempPolicyFile::new(&signals_policy_document_string());
        let recorder = PrometheusBuilder::new().build_recorder();
        let (audit_log, audit_event_sender) = test_audit_log_with_broadcast();
        let mut config = signals_admin_config(Some(&discovery_db.path), &policy);
        config
            .rbac_exempt_paths
            .push(AUDIT_EVENTS_STREAM_ROUTE.to_owned());
        let router = app(config, recorder.handle(), audit_log, audit_event_sender)
            .expect("app should build");

        let stream_response = router
            .clone()
            .oneshot(audit_query_request(
                &format!("{AUDIT_EVENTS_STREAM_ROUTE}?event_type=signal.lifecycle_changed"),
                Some(test_principal(&["admin"])),
            ))
            .await
            .expect("stream request should complete");
        assert_eq!(stream_response.status(), StatusCode::OK);

        let transition_response = router
            .oneshot(signals_admin_json_request(
                Method::POST,
                "/v1/admin/signals/sig-stream-ack/acknowledge",
                Some(test_principal(&["signals-writer"])),
            ))
            .await
            .expect("signals transition request should complete");
        assert_eq!(transition_response.status(), StatusCode::OK);

        let body = read_sse_until(stream_response.into_body(), |body| {
            body.contains(r#""event_type":"signal.lifecycle_changed""#)
                && body.contains(r#""id":"sig-stream-ack""#)
        })
        .await;

        assert!(body.contains("event: signal.lifecycle_changed"));
        assert!(body.contains(r#""signal_type":"new_endpoint_seen""#));
        assert!(body.contains(r#""state":"acknowledged""#));
        assert!(body.contains(r#""transitioned_by":"user-123""#));
    }

    #[tokio::test]
    async fn shadow_would_deny_events_are_queryable_and_streamable() {
        let db = TempDb::new("shadow-would-deny");
        let policy = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "default_action": "allow",
                "enforcement_mode": "shadow",
                "roles": {
                    "admin": {
                        "permissions": [
                            "admin:audit:read",
                            "admin:audit:stream"
                        ]
                    }
                },
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
        let (router, _policy) = audit_query_router(Some(&db.path));

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
        let (router, _policy) = audit_query_router(Some(&db.path));
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
        let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
        let recorder = PrometheusBuilder::new().build_recorder();
        let response = app(
            audit_query_config_with_policy(None, &policy),
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
        let (router, _policy) = audit_query_router(Some(&db.path));

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
    async fn traffic_endpoint_list_filters_sorts_and_paginates() {
        let discovery_db = TempDb::new("traffic-list");
        create_discovery_schema(&discovery_db.path);
        seed_list_discovery_endpoints(&discovery_db.path);
        let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), None);

        let call_count_page = traffic_json(
            &router,
            "/v1/admin/traffic/endpoints?method=GET&sort=call_count&limit=2",
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
        assert_eq!(
            endpoint_templates(&call_count_page),
            vec!["/reports/{id}".to_owned(), "/users/{id}".to_owned()]
        );
        let next_cursor = call_count_page["next_cursor"]
            .as_str()
            .expect("list response should include next cursor");

        let second_page = traffic_json(
            &router,
            &format!("/v1/admin/traffic/endpoints?method=GET&sort=call_count&limit=2&cursor={next_cursor}"),
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
        assert_eq!(
            endpoint_templates(&second_page),
            vec!["/admin/status".to_owned()]
        );
        assert!(second_page["next_cursor"].is_null());

        let substring = traffic_json(
            &router,
            "/v1/admin/traffic/endpoints?endpoint_template=users&sort=last_seen",
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
        assert_eq!(
            endpoint_templates(&substring),
            vec!["/users/{id}".to_owned(), "/users".to_owned()]
        );

        let prefix = traffic_json(
            &router,
            "/v1/admin/traffic/endpoints?endpoint_template_prefix=/admin",
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
        assert_eq!(
            endpoint_templates(&prefix),
            vec!["/admin/status".to_owned()]
        );

        let last_seen_window = traffic_json(
            &router,
            "/v1/admin/traffic/endpoints?last_seen_after=2024-06-02T00:00:00Z&last_seen_before=2024-06-03T23:59:59Z",
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
        assert_eq!(
            endpoint_templates(&last_seen_window),
            vec!["/users/{id}".to_owned(), "/users".to_owned()]
        );

        let min_call_count = traffic_json(
            &router,
            "/v1/admin/traffic/endpoints?min_call_count=20&sort=call_count",
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
        assert_eq!(
            endpoint_templates(&min_call_count),
            vec!["/reports/{id}".to_owned(), "/users/{id}".to_owned()]
        );

        let first_seen = traffic_json(
            &router,
            "/v1/admin/traffic/endpoints?sort=first_seen",
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
        assert_eq!(
            first_seen["endpoints"][0]["endpoint_template"],
            json!("/admin/status")
        );
        assert_eq!(
            first_seen["endpoints"][0]["status_counts"][0]["status"],
            json!(204)
        );
        assert_eq!(first_seen["endpoints"][0]["latency"]["p95_ms"], json!(5));
    }

    #[tokio::test]
    async fn traffic_endpoint_inventory_surfaces_schema_mismatch_count() {
        let discovery_db = TempDb::new("traffic-schema-mismatch-count");
        create_discovery_schema(&discovery_db.path);
        insert_discovery_endpoint(
            &discovery_db.path,
            SeedEndpoint {
                method: "GET",
                endpoint_template: "/users/{id}",
                first_seen: "2024-06-01T00:00:00Z",
                last_seen: "2024-06-01T01:00:00Z",
                call_count: 3,
                latency_count: 3,
                latency_p50_ms: 10,
                latency_p95_ms: 20,
                latency_p99_ms: 30,
                distinct_principal_count: 1,
                status_counts: &[(200, 3)],
            },
        );
        set_schema_mismatch_count(&discovery_db.path, "GET", "/users/{id}", 2);
        let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), None);

        let list = traffic_json(
            &router,
            "/v1/admin/traffic/endpoints?method=GET",
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
        assert_eq!(list["endpoints"][0]["schema_mismatch_count"], json!(2));

        let template = query_encode("/users/{id}");
        let detail = traffic_json(
            &router,
            &format!("/v1/admin/traffic/endpoint?method=GET&endpoint_template={template}"),
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
        assert_eq!(detail["endpoint"]["schema_mismatch_count"], json!(2));
    }

    #[tokio::test]
    async fn traffic_endpoint_inventory_includes_open_signal_summary_without_signal_n_plus_one() {
        let discovery_db = TempDb::new("traffic-open-signals");
        create_discovery_schema(&discovery_db.path);
        for index in 0..25 {
            let endpoint_template = format!("/bulk/{index}");
            insert_discovery_endpoint(
                &discovery_db.path,
                SeedEndpoint {
                    method: "GET",
                    endpoint_template: &endpoint_template,
                    first_seen: "2024-06-01T00:00:00Z",
                    last_seen: "2024-06-01T01:00:00Z",
                    call_count: 1,
                    latency_count: 1,
                    latency_p50_ms: 10,
                    latency_p95_ms: 10,
                    latency_p99_ms: 10,
                    distinct_principal_count: 1,
                    status_counts: &[(200, 1)],
                },
            );
            let signal_id = format!("sig-bulk-{index}");
            insert_signal(
                &discovery_db.path,
                SignalSeed {
                    id: &signal_id,
                    signal_type: "new_endpoint_seen",
                    method: "GET",
                    endpoint_template: &endpoint_template,
                    explanation: "New endpoint observed during signal summary query-count test.",
                    evidence: json!({ "first_seen": "2024-06-01T00:00:00Z" }),
                    state: "open",
                    created_at: "2024-06-01T00:00:00Z",
                    transitioned_at: None,
                    transitioned_by: None,
                },
            );
        }
        insert_signal(
            &discovery_db.path,
            SignalSeed {
                id: "sig-bulk-extra-type",
                signal_type: "schema_mismatch",
                method: "GET",
                endpoint_template: "/bulk/0",
                explanation: "Schema mismatch for GET /bulk/0.",
                evidence: json!({ "reason": "body_shape_changed" }),
                state: "open",
                created_at: "2024-06-01T00:10:00Z",
                transitioned_at: None,
                transitioned_by: None,
            },
        );
        insert_signal(
            &discovery_db.path,
            SignalSeed {
                id: "sig-bulk-acknowledged",
                signal_type: "principal_new_to_endpoint",
                method: "GET",
                endpoint_template: "/bulk/1",
                explanation: "Acknowledged signal should not count as open.",
                evidence: json!({ "principal": "alice" }),
                state: "acknowledged",
                created_at: "2024-06-01T00:15:00Z",
                transitioned_at: Some("2024-06-01T00:16:00Z"),
                transitioned_by: Some("reviewer"),
            },
        );

        let store = discovery::query::DiscoveryQueryStore::open(&discovery_db.path)
            .expect("discovery query store should open");
        let page = store
            .list_endpoints(&discovery::query::EndpointListFilters {
                method: Some("GET".to_owned()),
                endpoint_template_contains: None,
                endpoint_template_prefix: None,
                first_seen_after: None,
                first_seen_before: None,
                last_seen_after: None,
                last_seen_before: None,
                min_call_count: None,
                new_since_hours: discovery::query::DEFAULT_NEW_SINCE_HOURS,
                is_new: None,
                reviewed: None,
                sort: discovery::query::EndpointSort::LastSeen,
                limit: 50,
                cursor: None,
            })
            .expect("endpoint page should load");
        assert_eq!(page.endpoints.len(), 25);
        assert_eq!(
            store.open_signal_summary_query_count_for_test(),
            1,
            "endpoint page should load all open-signal summaries with one set-based query"
        );
        let first = page
            .endpoints
            .iter()
            .find(|endpoint| endpoint.endpoint_template == "/bulk/0")
            .expect("/bulk/0 endpoint should be present");
        let first_open_signals = first
            .open_signals
            .as_ref()
            .expect("open signal summary should be loaded by default");
        assert_eq!(first_open_signals.count, 2);
        assert_eq!(
            first_open_signals.signal_types,
            vec!["new_endpoint_seen".to_owned(), "schema_mismatch".to_owned()]
        );
        assert!(page.endpoints.iter().all(|endpoint| {
            endpoint.endpoint_template == "/bulk/0"
                || endpoint
                    .open_signals
                    .as_ref()
                    .expect("open signal summary should be loaded by default")
                    .count
                    == 1
        }));

        let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), None);
        let list = traffic_json(
            &router,
            "/v1/admin/traffic/endpoints?method=GET&endpoint_template_prefix=/bulk&sort=last_seen&limit=50",
            Some(test_principal(&["traffic-and-signals-reader"])),
        )
        .await;
        let bulk_zero = list["endpoints"]
            .as_array()
            .expect("endpoints should be an array")
            .iter()
            .find(|endpoint| endpoint["endpoint_template"] == json!("/bulk/0"))
            .expect("/bulk/0 should be returned");
        assert_eq!(bulk_zero["open_signals"]["count"], json!(2));
        assert_eq!(
            bulk_zero["open_signals"]["signal_types"],
            json!(["new_endpoint_seen", "schema_mismatch"])
        );

        let detail = traffic_json(
            &router,
            "/v1/admin/traffic/endpoint?method=GET&endpoint_template=%2Fbulk%2F0",
            Some(test_principal(&["traffic-and-signals-reader"])),
        )
        .await;
        assert_eq!(detail["endpoint"]["open_signals"]["count"], json!(2));
        assert_eq!(
            detail["endpoint"]["open_signals"]["signal_types"],
            json!(["new_endpoint_seen", "schema_mismatch"])
        );
    }

    #[tokio::test]
    async fn traffic_endpoint_inventory_omits_open_signal_summary_without_signals_read() {
        let discovery_db = TempDb::new("traffic-open-signals-hidden");
        create_discovery_schema(&discovery_db.path);
        insert_discovery_endpoint(
            &discovery_db.path,
            SeedEndpoint {
                method: "GET",
                endpoint_template: "/hidden-signals",
                first_seen: "2024-06-01T00:00:00Z",
                last_seen: "2024-06-01T01:00:00Z",
                call_count: 1,
                latency_count: 1,
                latency_p50_ms: 10,
                latency_p95_ms: 10,
                latency_p99_ms: 10,
                distinct_principal_count: 1,
                status_counts: &[(200, 1)],
            },
        );
        insert_signal(
            &discovery_db.path,
            SignalSeed {
                id: "sig-hidden",
                signal_type: "security_anomaly",
                method: "GET",
                endpoint_template: "/hidden-signals",
                explanation: "Signal type should not leak to traffic-only readers.",
                evidence: json!({ "category": "authorization" }),
                state: "open",
                created_at: "2024-06-01T00:00:00Z",
                transitioned_at: None,
                transitioned_by: None,
            },
        );

        let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), None);
        let list = traffic_json(
            &router,
            "/v1/admin/traffic/endpoints?method=GET&endpoint_template_prefix=/hidden",
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
        assert!(
            list["endpoints"][0].get("open_signals").is_none(),
            "open_signals should be absent from list responses for traffic-only readers: {list}"
        );

        let detail = traffic_json(
            &router,
            "/v1/admin/traffic/endpoint?method=GET&endpoint_template=%2Fhidden-signals",
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
        assert!(
            detail["endpoint"].get("open_signals").is_none(),
            "open_signals should be absent from detail responses for traffic-only readers: {detail}"
        );
    }

    #[test]
    fn endpoint_queries_can_skip_open_signal_summary_lookup() {
        let discovery_db = TempDb::new("traffic-open-signals-query-skipped");
        create_discovery_schema(&discovery_db.path);
        insert_discovery_endpoint(
            &discovery_db.path,
            SeedEndpoint {
                method: "GET",
                endpoint_template: "/skip-signals",
                first_seen: "2024-06-01T00:00:00Z",
                last_seen: "2024-06-01T01:00:00Z",
                call_count: 1,
                latency_count: 1,
                latency_p50_ms: 10,
                latency_p95_ms: 10,
                latency_p99_ms: 10,
                distinct_principal_count: 1,
                status_counts: &[(200, 1)],
            },
        );
        insert_signal(
            &discovery_db.path,
            SignalSeed {
                id: "sig-skip",
                signal_type: "security_anomaly",
                method: "GET",
                endpoint_template: "/skip-signals",
                explanation: "Signal type should not be queried when hidden.",
                evidence: json!({ "category": "authorization" }),
                state: "open",
                created_at: "2024-06-01T00:00:00Z",
                transitioned_at: None,
                transitioned_by: None,
            },
        );

        let store = discovery::query::DiscoveryQueryStore::open(&discovery_db.path)
            .expect("discovery query store should open");
        let page = store
            .list_endpoints_with_open_signal_summaries(
                &discovery::query::EndpointListFilters {
                    method: Some("GET".to_owned()),
                    endpoint_template_contains: None,
                    endpoint_template_prefix: Some("/skip".to_owned()),
                    first_seen_after: None,
                    first_seen_before: None,
                    last_seen_after: None,
                    last_seen_before: None,
                    min_call_count: None,
                    new_since_hours: discovery::query::DEFAULT_NEW_SINCE_HOURS,
                    is_new: None,
                    reviewed: None,
                    sort: discovery::query::EndpointSort::LastSeen,
                    limit: 50,
                    cursor: None,
                },
                false,
            )
            .expect("endpoint page should load");
        assert_eq!(page.endpoints.len(), 1);
        assert!(page.endpoints[0].open_signals.is_none());
        assert_eq!(
            store.open_signal_summary_query_count_for_test(),
            0,
            "endpoint page should not run the open-signal summary query when summaries are hidden"
        );

        let detail = store
            .get_endpoint_with_open_signal_summaries("GET", "/skip-signals", 24, false)
            .expect("endpoint detail should load")
            .expect("endpoint should exist");
        assert!(detail.open_signals.is_none());
        assert_eq!(
            store.open_signal_summary_query_count_for_test(),
            0,
            "endpoint detail should not run the open-signal summary query when summaries are hidden"
        );
    }

    #[tokio::test]
    async fn spec_conformance_mismatch_is_visible_in_traffic_inventory() {
        let discovery_db = TempDb::new("traffic-spec-conformance");
        let spec = TempSpecFile::new(
            "traffic-conformance",
            r#"
openapi: 3.0.3
info:
  title: Traffic Conformance API
  version: 1.0.0
paths:
  /users/{userId}:
    get:
      parameters:
        - in: query
          name: page
          required: true
"#,
        );
        let policy = TempPolicyFile::new(&traffic_policy_document_string());
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.discovery_sqlite_path = Some(discovery_db.path.to_string_lossy().into_owned());
        config.openapi_spec_path = Some(spec.path.clone());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config
            .rbac_exempt_paths
            .push(TRAFFIC_ENDPOINTS_ADMIN_ROUTE.to_owned());
        config
            .rbac_exempt_paths
            .push(TRAFFIC_ENDPOINT_DETAIL_ADMIN_ROUTE.to_owned());
        let (audit_log, audit_event_sender) =
            audit::AuditLog::from_config(&config).expect("audit log should build");
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(config, recorder.handle(), audit_log, audit_event_sender)
            .expect("app should build");

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/users/123")
                    .header(REQUEST_ID_HEADER, "request-spec-conformance-missing")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let body =
            wait_for_traffic_json(&router, "/v1/admin/traffic/endpoints?method=GET", |body| {
                body["endpoints"].as_array().is_some_and(|endpoints| {
                    endpoints.iter().any(|endpoint| {
                        endpoint["endpoint_template"] == json!("/users/{id}")
                            && endpoint["schema_mismatch_count"] == json!(1)
                    })
                })
            })
            .await;
        let users_endpoint = body["endpoints"]
            .as_array()
            .expect("endpoints should be an array")
            .iter()
            .find(|endpoint| endpoint["endpoint_template"] == json!("/users/{id}"))
            .expect("users endpoint should be present");
        assert_eq!(users_endpoint["schema_mismatch_count"], json!(1));
    }

    #[tokio::test]
    async fn traffic_endpoint_lifecycle_flags_rule_coverage_and_hot_reload() {
        let discovery_db = TempDb::new("traffic-lifecycle-coverage");
        create_discovery_schema(&discovery_db.path);
        insert_discovery_endpoint(
            &discovery_db.path,
            SeedEndpoint {
                method: "GET",
                endpoint_template: "/covered/{id}",
                first_seen: "2024-06-01T00:00:00Z",
                last_seen: "2024-06-01T01:00:00Z",
                call_count: 3,
                latency_count: 3,
                latency_p50_ms: 10,
                latency_p95_ms: 20,
                latency_p99_ms: 30,
                distinct_principal_count: 1,
                status_counts: &[(200, 3)],
            },
        );
        insert_discovery_endpoint(
            &discovery_db.path,
            SeedEndpoint {
                method: "GET",
                endpoint_template: "/open/{id}",
                first_seen: "2024-06-01T00:00:00Z",
                last_seen: "2024-06-01T01:00:00Z",
                call_count: 2,
                latency_count: 2,
                latency_p50_ms: 10,
                latency_p95_ms: 20,
                latency_p99_ms: 30,
                distinct_principal_count: 1,
                status_counts: &[(200, 2)],
            },
        );
        let policy = TempPolicyFile::new(&traffic_policy_document_with_rules(json!([
            {
                "id": "cover-id-endpoint",
                "methods": ["GET"],
                "path": "/covered/{id}",
                "action": "allow"
            }
        ])));
        let router = traffic_admin_router_with_policy(Some(&discovery_db.path), None, &policy);

        let body = traffic_json(
            &router,
            "/v1/admin/traffic/endpoints?sort=first_seen",
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
        assert_eq!(
            endpoint_coverage(&body),
            HashMap::from([
                ("/covered/{id}".to_owned(), true),
                ("/open/{id}".to_owned(), false)
            ])
        );

        let uncovered = traffic_json(
            &router,
            "/v1/admin/traffic/endpoints?covered_by_rule=false&sort=first_seen",
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
        assert_eq!(
            endpoint_templates(&uncovered),
            vec!["/open/{id}".to_owned()]
        );

        let uncovered_limited = traffic_json(
            &router,
            "/v1/admin/traffic/endpoints?covered_by_rule=false&sort=first_seen&limit=1",
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
        assert_eq!(
            endpoint_templates(&uncovered_limited),
            vec!["/open/{id}".to_owned()]
        );

        policy.write(&traffic_policy_document_with_rules(json!([
            {
                "id": "cover-id-endpoint",
                "methods": ["GET"],
                "path": "/covered/{id}",
                "action": "allow"
            },
            {
                "id": "cover-open-endpoint",
                "methods": ["GET"],
                "path": "/open/{id}",
                "principal": {
                    "roles": ["traffic-reader"],
                    "auth_methods": ["bearer_token"]
                },
                "action": "shadow"
            }
        ])));

        let reloaded = wait_for_traffic_json(&router, "/v1/admin/traffic/endpoints", |body| {
            endpoint_coverage(body).get("/open/{id}") == Some(&true)
        })
        .await;
        assert_eq!(
            endpoint_coverage(&reloaded),
            HashMap::from([
                ("/covered/{id}".to_owned(), true),
                ("/open/{id}".to_owned(), true)
            ])
        );
    }

    #[tokio::test]
    async fn traffic_endpoint_new_flag_uses_configurable_window() {
        let discovery_db = TempDb::new("traffic-lifecycle-new");
        create_discovery_schema(&discovery_db.path);
        let recent = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("current timestamp should format");
        let old = (OffsetDateTime::now_utc() - time::Duration::hours(48))
            .format(&Rfc3339)
            .expect("old timestamp should format");
        insert_discovery_endpoint(
            &discovery_db.path,
            SeedEndpoint {
                method: "GET",
                endpoint_template: "/recent",
                first_seen: &recent,
                last_seen: &recent,
                call_count: 1,
                latency_count: 1,
                latency_p50_ms: 1,
                latency_p95_ms: 1,
                latency_p99_ms: 1,
                distinct_principal_count: 0,
                status_counts: &[(200, 1)],
            },
        );
        insert_discovery_endpoint(
            &discovery_db.path,
            SeedEndpoint {
                method: "GET",
                endpoint_template: "/old",
                first_seen: &old,
                last_seen: &old,
                call_count: 1,
                latency_count: 1,
                latency_p50_ms: 1,
                latency_p95_ms: 1,
                latency_p99_ms: 1,
                distinct_principal_count: 0,
                status_counts: &[(200, 1)],
            },
        );
        let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), None);

        let body = traffic_json(
            &router,
            "/v1/admin/traffic/endpoints?new_since_hours=24&sort=first_seen",
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
        assert_eq!(
            endpoint_new_flags(&body),
            HashMap::from([("/recent".to_owned(), true), ("/old".to_owned(), false)])
        );

        let only_new = traffic_json(
            &router,
            "/v1/admin/traffic/endpoints?is_new=true&new_since_hours=24",
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
        assert_eq!(endpoint_templates(&only_new), vec!["/recent".to_owned()]);
    }

    #[tokio::test]
    async fn traffic_endpoint_new_since_hours_rejects_out_of_range_values_instead_of_panicking() {
        let discovery_db = TempDb::new("traffic-lifecycle-new-since-bounds");
        create_discovery_schema(&discovery_db.path);
        let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), None);
        let principal = Some(test_principal(&["traffic-reader"]));
        let template = query_encode("/users/{id}");

        for uri in [
            "/v1/admin/traffic/endpoints?new_since_hours=1000000000".to_owned(),
            format!(
                "/v1/admin/traffic/endpoint?method=GET&endpoint_template={template}&new_since_hours=1000000000"
            ),
        ] {
            let response = router
                .clone()
                .oneshot(traffic_admin_request(&uri, principal.clone()))
                .await
                .expect("traffic request should complete");

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                body_string(response).await,
                r#"{"error":"invalid query parameter: new_since_hours"}"#
            );
        }
    }

    #[tokio::test]
    async fn traffic_endpoint_review_mark_clear_and_write_permission() {
        let discovery_db = TempDb::new("traffic-lifecycle-review");
        create_discovery_schema(&discovery_db.path);
        insert_discovery_endpoint(
            &discovery_db.path,
            SeedEndpoint {
                method: "GET",
                endpoint_template: "/reviewed/{id}",
                first_seen: "2024-06-01T00:00:00Z",
                last_seen: "2024-06-01T01:00:00Z",
                call_count: 1,
                latency_count: 1,
                latency_p50_ms: 10,
                latency_p95_ms: 10,
                latency_p99_ms: 10,
                distinct_principal_count: 0,
                status_counts: &[(200, 1)],
            },
        );
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log =
            audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
        let policy = TempPolicyFile::new(&traffic_policy_document_string());
        let router = traffic_admin_router_with_policy_and_audit(
            Some(&discovery_db.path),
            None,
            &policy,
            audit_log,
        );
        let body = json!({
            "method": "GET",
            "endpoint_template": "/reviewed/{id}",
            "reviewed": true
        })
        .to_string();

        let unauthenticated = router
            .clone()
            .oneshot(traffic_admin_json_request(
                Method::POST,
                TRAFFIC_ENDPOINT_REVIEW_ADMIN_ROUTE,
                None,
                Some(body.clone()),
            ))
            .await
            .expect("traffic review request should complete");
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let read_only = router
            .clone()
            .oneshot(traffic_admin_json_request(
                Method::POST,
                TRAFFIC_ENDPOINT_REVIEW_ADMIN_ROUTE,
                Some(test_principal(&["traffic-reader"])),
                Some(body.clone()),
            ))
            .await
            .expect("traffic review request should complete");
        assert_eq!(read_only.status(), StatusCode::FORBIDDEN);

        let marked = router
            .clone()
            .oneshot(traffic_admin_json_request(
                Method::POST,
                TRAFFIC_ENDPOINT_REVIEW_ADMIN_ROUTE,
                Some(test_principal(&["traffic-writer"])),
                Some(body),
            ))
            .await
            .expect("traffic review request should complete");
        assert_eq!(marked.status(), StatusCode::OK);
        let marked_body = json_body(marked).await;
        assert_eq!(marked_body["reviewed"], json!(true));
        assert!(marked_body["reviewed_at"].as_str().is_some());
        assert_eq!(marked_body["reviewed_by"], json!("user-123"));

        let template = query_encode("/reviewed/{id}");
        let detail = traffic_json(
            &router,
            &format!("/v1/admin/traffic/endpoint?method=GET&endpoint_template={template}"),
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
        assert_eq!(detail["endpoint"]["reviewed"], json!(true));
        assert_eq!(
            detail["endpoint"]["reviewed_at"],
            marked_body["reviewed_at"]
        );
        assert_eq!(detail["endpoint"]["reviewed_by"], json!("user-123"));

        let reviewed_list = traffic_json(
            &router,
            "/v1/admin/traffic/endpoints?reviewed=true",
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
        assert_eq!(
            endpoint_templates(&reviewed_list),
            vec!["/reviewed/{id}".to_owned()]
        );
        assert_eventually(Duration::from_secs(1), || {
            capture
                .events()
                .iter()
                .any(|event| event.event_type == audit::event::TRAFFIC_ENDPOINT_REVIEW_CHANGED)
        });

        let cleared = router
            .clone()
            .oneshot(traffic_admin_json_request(
                Method::POST,
                TRAFFIC_ENDPOINT_REVIEW_ADMIN_ROUTE,
                Some(test_principal(&["traffic-writer"])),
                Some(
                    json!({
                        "method": "GET",
                        "endpoint_template": "/reviewed/{id}",
                        "reviewed": false
                    })
                    .to_string(),
                ),
            ))
            .await
            .expect("traffic review clear request should complete");
        assert_eq!(cleared.status(), StatusCode::OK);
        let cleared_body = json_body(cleared).await;
        assert_eq!(cleared_body["reviewed"], json!(false));
        assert!(cleared_body["reviewed_at"].is_null());
        assert!(cleared_body["reviewed_by"].is_null());

        let unreviewed_list = traffic_json(
            &router,
            "/v1/admin/traffic/endpoints?reviewed=false",
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
        assert_eq!(
            endpoint_templates(&unreviewed_list),
            vec!["/reviewed/{id}".to_owned()]
        );
    }

    #[tokio::test]
    async fn signals_admin_list_filters_paginates_and_explains() {
        let discovery_db = TempDb::new("signals-list");
        create_signal_schema(&discovery_db.path);
        insert_signal(
            &discovery_db.path,
            SignalSeed {
                id: "sig-open-newer",
                signal_type: "new_endpoint_seen",
                method: "POST",
                endpoint_template: "/widgets",
                explanation:
                    "New endpoint observed: POST /widgets was first seen at 2024-06-03T00:00:00Z.",
                evidence: json!({
                    "first_seen": "2024-06-03T00:00:00Z",
                    "initial_call_count": 1,
                    "initial_principal": "alice"
                }),
                state: "open",
                created_at: "2024-06-03T00:00:00Z",
                transitioned_at: None,
                transitioned_by: None,
            },
        );
        insert_signal(
            &discovery_db.path,
            SignalSeed {
                id: "sig-acknowledged",
                signal_type: "new_endpoint_seen",
                method: "DELETE",
                endpoint_template: "/widgets/{id}",
                explanation: "New endpoint observed: DELETE /widgets/{id} was first seen at 2024-06-02T00:00:00Z.",
                evidence: json!({
                    "first_seen": "2024-06-02T00:00:00Z",
                    "initial_call_count": 1,
                    "initial_principal": "bob"
                }),
                state: "acknowledged",
                created_at: "2024-06-02T00:00:00Z",
                transitioned_at: Some("2024-06-02T01:00:00Z"),
                transitioned_by: Some("reviewer"),
            },
        );
        insert_signal(
            &discovery_db.path,
            SignalSeed {
                id: "sig-open-older",
                signal_type: "new_endpoint_seen",
                method: "GET",
                endpoint_template: "/widgets/{id}",
                explanation: "New endpoint observed: GET /widgets/{id} was first seen at 2024-06-01T00:00:00Z.",
                evidence: json!({
                    "first_seen": "2024-06-01T00:00:00Z",
                    "initial_call_count": 1,
                    "initial_principal": "carol"
                }),
                state: "open",
                created_at: "2024-06-01T00:00:00Z",
                transitioned_at: None,
                transitioned_by: None,
            },
        );
        let (router, _policy) = signals_admin_router(Some(&discovery_db.path));

        let first_page = signals_json(
            &router,
            "/v1/admin/signals?state=open&limit=1",
            Some(test_principal(&["signals-reader"])),
        )
        .await;
        assert_eq!(signal_ids(&first_page), vec!["sig-open-newer".to_owned()]);
        assert!(first_page["next_cursor"].as_str().is_some());
        assert_eq!(first_page["signals"][0]["state"], json!("open"));
        assert_eq!(
            first_page["signals"][0]["target"],
            json!({
                "kind": "endpoint",
                "identity": {
                    "method": "POST",
                    "endpoint_template": "/widgets"
                }
            })
        );
        assert!(
            first_page["signals"][0]["explanation"]
                .as_str()
                .expect("signal explanation should be a string")
                .contains("POST /widgets"),
            "signal explanation should describe what fired"
        );

        let cursor = first_page["next_cursor"]
            .as_str()
            .expect("first page should include next cursor");
        let second_page = signals_json(
            &router,
            &format!("/v1/admin/signals?state=open&limit=1&cursor={cursor}"),
            Some(test_principal(&["signals-reader"])),
        )
        .await;
        assert_eq!(signal_ids(&second_page), vec!["sig-open-older".to_owned()]);
        assert!(second_page["next_cursor"].is_null());

        let acknowledged = signals_json(
            &router,
            "/v1/admin/signals?state=acknowledged",
            Some(test_principal(&["signals-reader"])),
        )
        .await;
        assert_eq!(
            signal_ids(&acknowledged),
            vec!["sig-acknowledged".to_owned()]
        );

        let target_key = query_encode("GET /widgets/{id}");
        let target_filtered = signals_json(
            &router,
            &format!("/v1/admin/signals?target_kind=endpoint&target_key={target_key}"),
            Some(test_principal(&["signals-reader"])),
        )
        .await;
        assert_eq!(
            signal_ids(&target_filtered),
            vec!["sig-open-older".to_owned()]
        );

        let forbidden = router
            .clone()
            .oneshot(signals_admin_request(
                "/v1/admin/signals",
                Some(test_principal(&["reader"])),
            ))
            .await
            .expect("signals request should complete");
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let unauthenticated = router
            .clone()
            .oneshot(signals_admin_request("/v1/admin/signals", None))
            .await
            .expect("signals request should complete");
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn signals_admin_lifecycle_transitions_persist_and_require_write_permission() {
        let discovery_db = TempDb::new("signals-lifecycle");
        create_signal_schema(&discovery_db.path);
        insert_signal(
            &discovery_db.path,
            SignalSeed {
                id: "sig-ack",
                signal_type: "new_endpoint_seen",
                method: "GET",
                endpoint_template: "/ack/{id}",
                explanation:
                    "New endpoint observed: GET /ack/{id} was first seen at 2024-06-01T00:00:00Z.",
                evidence: json!({
                    "first_seen": "2024-06-01T00:00:00Z",
                    "initial_call_count": 1
                }),
                state: "open",
                created_at: "2024-06-01T00:00:00Z",
                transitioned_at: None,
                transitioned_by: None,
            },
        );
        insert_signal(
            &discovery_db.path,
            SignalSeed {
                id: "sig-dismiss",
                signal_type: "new_endpoint_seen",
                method: "GET",
                endpoint_template: "/dismiss/{id}",
                explanation: "New endpoint observed: GET /dismiss/{id} was first seen at 2024-06-01T01:00:00Z.",
                evidence: json!({
                    "first_seen": "2024-06-01T01:00:00Z",
                    "initial_call_count": 1
                }),
                state: "open",
                created_at: "2024-06-01T01:00:00Z",
                transitioned_at: None,
                transitioned_by: None,
            },
        );
        let (router, _policy) = signals_admin_router(Some(&discovery_db.path));

        let unauthenticated = router
            .clone()
            .oneshot(signals_admin_json_request(
                Method::POST,
                "/v1/admin/signals/sig-ack/acknowledge",
                None,
            ))
            .await
            .expect("signals transition request should complete");
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let read_only = router
            .clone()
            .oneshot(signals_admin_json_request(
                Method::POST,
                "/v1/admin/signals/sig-ack/acknowledge",
                Some(test_principal(&["signals-reader"])),
            ))
            .await
            .expect("signals transition request should complete");
        assert_eq!(read_only.status(), StatusCode::FORBIDDEN);

        let acknowledged = router
            .clone()
            .oneshot(signals_admin_json_request(
                Method::POST,
                "/v1/admin/signals/sig-ack/acknowledge",
                Some(test_principal(&["signals-writer"])),
            ))
            .await
            .expect("signals transition request should complete");
        assert_eq!(acknowledged.status(), StatusCode::OK);
        let acknowledged_body = json_body(acknowledged).await;
        assert_eq!(acknowledged_body["state"], json!("acknowledged"));
        assert_eq!(acknowledged_body["transitioned_by"], json!("user-123"));
        assert!(acknowledged_body["transitioned_at"].as_str().is_some());

        let dismissed = router
            .clone()
            .oneshot(signals_admin_json_request(
                Method::POST,
                "/v1/admin/signals/sig-dismiss/dismiss",
                Some(test_principal(&["signals-writer"])),
            ))
            .await
            .expect("signals transition request should complete");
        assert_eq!(dismissed.status(), StatusCode::OK);
        let dismissed_body = json_body(dismissed).await;
        assert_eq!(dismissed_body["state"], json!("dismissed"));
        assert_eq!(dismissed_body["transitioned_by"], json!("user-123"));
        assert!(dismissed_body["transitioned_at"].as_str().is_some());

        let acknowledged_page = signals_json(
            &router,
            "/v1/admin/signals?state=acknowledged",
            Some(test_principal(&["signals-reader"])),
        )
        .await;
        assert_eq!(signal_ids(&acknowledged_page), vec!["sig-ack".to_owned()]);
        assert_eq!(
            acknowledged_page["signals"][0]["transitioned_by"],
            json!("user-123")
        );

        let dismissed_page = signals_json(
            &router,
            "/v1/admin/signals?state=dismissed",
            Some(test_principal(&["signals-reader"])),
        )
        .await;
        assert_eq!(signal_ids(&dismissed_page), vec!["sig-dismiss".to_owned()]);
    }

    #[tokio::test]
    async fn suggestions_admin_list_filters_paginates_and_requires_read_permission() {
        let discovery_db = TempDb::new("suggestions-list");
        create_rule_suggestion_schema(&discovery_db.path);
        insert_rule_suggestion(
            &discovery_db.path,
            RuleSuggestionSeed {
                id: "sug-open-newer",
                suggestion_type: "baseline_allow",
                method: "POST",
                path_pattern: "/widgets",
                role: Some("writer"),
                action: "allow",
                rationale: "Observed writer calls to POST /widgets.",
                evidence: json!({ "observation_count": 3 }),
                state: "open",
                created_at: "2024-06-03T00:00:00Z",
                transitioned_at: None,
                transitioned_by: None,
                source_signal_id: None,
            },
        );
        insert_rule_suggestion(
            &discovery_db.path,
            RuleSuggestionSeed {
                id: "sug-dismissed",
                suggestion_type: "signal_shadow_error_rate_spike",
                method: "GET",
                path_pattern: "/widgets/{id}",
                role: None,
                action: "shadow",
                rationale: "Open error-rate signal targets GET /widgets/{id}.",
                evidence: json!({ "source_signal_id": "sig-error" }),
                state: "dismissed",
                created_at: "2024-06-02T00:00:00Z",
                transitioned_at: Some("2024-06-02T01:00:00Z"),
                transitioned_by: Some("reviewer"),
                source_signal_id: Some("sig-error"),
            },
        );
        insert_rule_suggestion(
            &discovery_db.path,
            RuleSuggestionSeed {
                id: "sug-open-older",
                suggestion_type: "baseline_allow",
                method: "GET",
                path_pattern: "/widgets/{id}",
                role: Some("reader"),
                action: "allow",
                rationale: "Observed reader calls to GET /widgets/{id}.",
                evidence: json!({ "observation_count": 5 }),
                state: "open",
                created_at: "2024-06-01T00:00:00Z",
                transitioned_at: None,
                transitioned_by: None,
                source_signal_id: None,
            },
        );
        let (router, _policy) = suggestions_admin_router(Some(&discovery_db.path), None);

        let first_page = suggestions_json(
            &router,
            "/v1/admin/suggestions?state=open&suggestion_type=baseline_allow&limit=1",
            Some(test_principal(&["suggestions-reader"])),
        )
        .await;
        assert_eq!(
            suggestion_ids(&first_page),
            vec!["sug-open-newer".to_owned()]
        );
        assert!(first_page["next_cursor"].as_str().is_some());
        assert_eq!(first_page["suggestions"][0]["state"], json!("open"));
        assert_eq!(
            first_page["suggestions"][0]["proposed_rule"],
            json!({
                "methods": ["POST"],
                "path": "/widgets",
                "principal": {
                    "roles": ["writer"],
                    "auth_methods": [],
                    "principal_ids": []
                },
                "action": "allow"
            })
        );
        assert_eq!(
            first_page["suggestions"][0]["rationale"],
            json!("Observed writer calls to POST /widgets.")
        );
        assert_eq!(
            first_page["suggestions"][0]["evidence"],
            json!({ "observation_count": 3 })
        );

        let cursor = first_page["next_cursor"]
            .as_str()
            .expect("first page should include next cursor");
        let second_page = suggestions_json(
            &router,
            &format!(
                "/v1/admin/suggestions?state=open&suggestion_type=baseline_allow&limit=1&cursor={cursor}"
            ),
            Some(test_principal(&["suggestions-reader"])),
        )
        .await;
        assert_eq!(
            suggestion_ids(&second_page),
            vec!["sug-open-older".to_owned()]
        );
        assert!(second_page["next_cursor"].is_null());

        let dismissed = suggestions_json(
            &router,
            "/v1/admin/suggestions?state=dismissed",
            Some(test_principal(&["suggestions-reader"])),
        )
        .await;
        assert_eq!(suggestion_ids(&dismissed), vec!["sug-dismissed".to_owned()]);

        let forbidden = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::GET,
                "/v1/admin/suggestions",
                Some(test_principal(&["reader"])),
                None,
                None,
            ))
            .await
            .expect("suggestions request should complete");
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        let unauthenticated = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::GET,
                "/v1/admin/suggestions",
                None,
                None,
                None,
            ))
            .await
            .expect("suggestions request should complete");
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn suggestions_admin_generate_is_explicit_and_list_does_not_refresh() {
        let discovery_db = TempDb::new("suggestions-generate-discovery");
        let audit_db = TempDb::new("suggestions-generate-audit");
        seed_suggestion_generation_observation(
            &discovery_db.path,
            &audit_db.path,
            "first",
            "GET",
            "/generated/{id}",
            "reader",
            "2024-06-01T12:00:00Z",
        );
        let (router, _policy) =
            suggestions_admin_router(Some(&discovery_db.path), Some(&audit_db.path));

        let initially_empty = suggestions_json(
            &router,
            "/v1/admin/suggestions",
            Some(test_principal(&["suggestions-reader"])),
        )
        .await;
        assert_eq!(suggestion_ids(&initially_empty), Vec::<String>::new());

        let generated = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::POST,
                "/v1/admin/suggestions/generate",
                Some(test_principal(&["suggestions-writer"])),
                None,
                None,
            ))
            .await
            .expect("suggestion generation request should complete");
        assert_eq!(generated.status(), StatusCode::OK);
        let generated_body = json_body(generated).await;
        assert_eq!(generated_body["inserted_count"], json!(1));

        seed_suggestion_generation_observation(
            &discovery_db.path,
            &audit_db.path,
            "second",
            "POST",
            "/generated/{id}",
            "writer",
            "2024-06-01T12:01:00Z",
        );
        let after_list_only = suggestions_json(
            &router,
            "/v1/admin/suggestions",
            Some(test_principal(&["suggestions-reader"])),
        )
        .await;
        assert_eq!(suggestion_ids(&after_list_only).len(), 1);

        let regenerated = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::POST,
                "/v1/admin/suggestions/generate",
                Some(test_principal(&["suggestions-writer"])),
                None,
                None,
            ))
            .await
            .expect("second generation request should complete");
        assert_eq!(regenerated.status(), StatusCode::OK);
        let regenerated_body = json_body(regenerated).await;
        assert_eq!(regenerated_body["inserted_count"], json!(1));

        let refreshed = suggestions_json(
            &router,
            "/v1/admin/suggestions?state=open",
            Some(test_principal(&["suggestions-reader"])),
        )
        .await;
        assert_eq!(suggestion_ids(&refreshed).len(), 2);
    }

    #[tokio::test]
    async fn suggestions_admin_accept_creates_real_rule_requires_both_permissions_and_audits() {
        let discovery_db = TempDb::new("suggestions-accept");
        create_rule_suggestion_schema(&discovery_db.path);
        insert_rule_suggestion(
            &discovery_db.path,
            RuleSuggestionSeed {
                id: "sug-accept",
                suggestion_type: "baseline_allow",
                method: "GET",
                path_pattern: "/accepted/{id}",
                role: Some("accepted-reader"),
                action: "allow",
                rationale: "Observed accepted-reader calls to GET /accepted/{id}.",
                evidence: json!({ "observation_count": 4 }),
                state: "open",
                created_at: "2024-06-01T00:00:00Z",
                transitioned_at: None,
                transitioned_by: None,
                source_signal_id: None,
            },
        );
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log = audit::AuditLog::new(Arc::new(capture.clone()));
        let policy = TempPolicyFile::new(&suggestions_policy_document_string());
        let router = suggestions_admin_router_with_policy(
            Some(&discovery_db.path),
            None,
            &policy,
            audit_log,
        );

        let current_etag = suggestions_policy_etag(&router).await;

        let suggestion_only = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::POST,
                "/v1/admin/suggestions/sug-accept/accept",
                Some(test_principal(&["suggestions-writer"])),
                None,
                Some(&current_etag),
            ))
            .await
            .expect("suggestion-only accept request should complete");
        assert_eq!(suggestion_only.status(), StatusCode::FORBIDDEN);

        let policy_only = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::POST,
                "/v1/admin/suggestions/sug-accept/accept",
                Some(test_principal(&["policy-writer"])),
                None,
                Some(&current_etag),
            ))
            .await
            .expect("policy-only accept request should complete");
        assert_eq!(policy_only.status(), StatusCode::FORBIDDEN);

        let accepted = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::POST,
                "/v1/admin/suggestions/sug-accept/accept",
                Some(test_principal(&["suggestions-policy-writer"])),
                None,
                Some(&current_etag),
            ))
            .await
            .expect("accept request should complete");
        assert_eq!(accepted.status(), StatusCode::CREATED);
        let accepted_etag = policy_etag_header(&accepted);
        let accepted_body = json_body(accepted).await;
        assert_eq!(accepted_body["suggestion"]["state"], json!("accepted"));
        assert_eq!(accepted_body["rule"]["path"], json!("/accepted/{id}"));
        assert_eq!(accepted_body["rule"]["action"], json!("allow"));
        assert_eq!(
            accepted_body["rule"]["principal"]["roles"],
            json!(["accepted-reader"])
        );
        assert!(accepted_body["rule"]["id"].as_str().is_some());

        let policy_response = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["policy-reader"])),
                None,
                None,
            ))
            .await
            .expect("policy GET should complete");
        assert_eq!(policy_response.status(), StatusCode::OK);
        assert_eq!(policy_etag_header(&policy_response), accepted_etag);
        let policy_body = json_body(policy_response).await;
        assert_eq!(policy_body["rules"].as_array().unwrap().len(), 1);
        assert_eq!(policy_body["rules"][0], accepted_body["rule"]);

        let accepted_page = suggestions_json(
            &router,
            "/v1/admin/suggestions?state=accepted",
            Some(test_principal(&["suggestions-reader"])),
        )
        .await;
        assert_eq!(
            suggestion_ids(&accepted_page),
            vec!["sug-accept".to_owned()]
        );
        assert_eq!(
            accepted_page["suggestions"][0]["transitioned_by"],
            json!("user-123")
        );

        assert_eventually(Duration::from_secs(1), || {
            let events = capture.events();
            events
                .iter()
                .any(|event| event.event_type == audit::event::POLICY_CHANGED)
                && events
                    .iter()
                    .any(|event| event.event_type == audit::event::SUGGESTION_LIFECYCLE_CHANGED)
        });
        let events = capture.events();
        let policy_event = events
            .iter()
            .find(|event| event.event_type == audit::event::POLICY_CHANGED)
            .expect("policy.changed should be emitted");
        assert_eq!(
            policy_event.payload["diff_summary"]["action"],
            json!("rule_created")
        );
        let suggestion_event = events
            .iter()
            .find(|event| event.event_type == audit::event::SUGGESTION_LIFECYCLE_CHANGED)
            .expect("suggestion lifecycle event should be emitted");
        assert_eq!(suggestion_event.payload["id"], json!("sug-accept"));
        assert_eq!(suggestion_event.payload["state"], json!("accepted"));
    }

    #[tokio::test]
    async fn suggestions_admin_accept_surfaces_policy_etag_conflict_without_transition() {
        let discovery_db = TempDb::new("suggestions-accept-conflict");
        create_rule_suggestion_schema(&discovery_db.path);
        insert_rule_suggestion(
            &discovery_db.path,
            RuleSuggestionSeed {
                id: "sug-stale",
                suggestion_type: "baseline_allow",
                method: "GET",
                path_pattern: "/stale/{id}",
                role: Some("stale-reader"),
                action: "allow",
                rationale: "Observed stale-reader calls to GET /stale/{id}.",
                evidence: json!({ "observation_count": 2 }),
                state: "open",
                created_at: "2024-06-01T00:00:00Z",
                transitioned_at: None,
                transitioned_by: None,
                source_signal_id: None,
            },
        );
        let policy = TempPolicyFile::new(&suggestions_policy_document_string());
        let router = suggestions_admin_router_with_policy(
            Some(&discovery_db.path),
            None,
            &policy,
            test_audit_log(),
        );
        let stale_etag = suggestions_policy_etag(&router).await;

        let manual_rule = json!({
            "methods": ["POST"],
            "path": "/manual",
            "action": "deny"
        })
        .to_string();
        let manual_response = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::POST,
                POLICY_RULES_ADMIN_ROUTE,
                Some(test_principal(&["policy-writer"])),
                Some(manual_rule),
                Some(&stale_etag),
            ))
            .await
            .expect("manual policy rule create should complete");
        assert_eq!(manual_response.status(), StatusCode::CREATED);

        let conflict = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::POST,
                "/v1/admin/suggestions/sug-stale/accept",
                Some(test_principal(&["suggestions-policy-writer"])),
                None,
                Some(&stale_etag),
            ))
            .await
            .expect("stale accept request should complete");
        assert_eq!(conflict.status(), StatusCode::PRECONDITION_FAILED);
        assert_eq!(
            body_string(conflict).await,
            r#"{"error":"If-Match does not match the current policy ETag"}"#
        );

        let open_page = suggestions_json(
            &router,
            "/v1/admin/suggestions?state=open",
            Some(test_principal(&["suggestions-reader"])),
        )
        .await;
        assert_eq!(suggestion_ids(&open_page), vec!["sug-stale".to_owned()]);
        assert!(open_page["suggestions"][0]["transitioned_at"].is_null());
    }

    #[tokio::test]
    async fn suggestions_admin_dismiss_transitions_requires_write_only_and_audits() {
        let discovery_db = TempDb::new("suggestions-dismiss");
        create_rule_suggestion_schema(&discovery_db.path);
        insert_rule_suggestion(
            &discovery_db.path,
            RuleSuggestionSeed {
                id: "sug-dismiss",
                suggestion_type: "signal_shadow_schema_mismatch",
                method: "PATCH",
                path_pattern: "/dismiss/{id}",
                role: None,
                action: "shadow",
                rationale: "Open schema mismatch signal targets PATCH /dismiss/{id}.",
                evidence: json!({ "source_signal_id": "sig-schema" }),
                state: "open",
                created_at: "2024-06-01T00:00:00Z",
                transitioned_at: None,
                transitioned_by: None,
                source_signal_id: Some("sig-schema"),
            },
        );
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log = audit::AuditLog::new(Arc::new(capture.clone()));
        let policy = TempPolicyFile::new(&suggestions_policy_document_string());
        let router = suggestions_admin_router_with_policy(
            Some(&discovery_db.path),
            None,
            &policy,
            audit_log,
        );

        let unauthenticated = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::POST,
                "/v1/admin/suggestions/sug-dismiss/dismiss",
                None,
                None,
                None,
            ))
            .await
            .expect("dismiss request should complete");
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let read_only = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::POST,
                "/v1/admin/suggestions/sug-dismiss/dismiss",
                Some(test_principal(&["suggestions-reader"])),
                None,
                None,
            ))
            .await
            .expect("dismiss request should complete");
        assert_eq!(read_only.status(), StatusCode::FORBIDDEN);

        let dismissed = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::POST,
                "/v1/admin/suggestions/sug-dismiss/dismiss",
                Some(test_principal(&["suggestions-writer"])),
                None,
                None,
            ))
            .await
            .expect("dismiss request should complete");
        assert_eq!(dismissed.status(), StatusCode::OK);
        let dismissed_body = json_body(dismissed).await;
        assert_eq!(dismissed_body["state"], json!("dismissed"));
        assert_eq!(dismissed_body["transitioned_by"], json!("user-123"));
        assert!(dismissed_body["transitioned_at"].as_str().is_some());

        let dismissed_page = suggestions_json(
            &router,
            "/v1/admin/suggestions?state=dismissed",
            Some(test_principal(&["suggestions-reader"])),
        )
        .await;
        assert_eq!(
            suggestion_ids(&dismissed_page),
            vec!["sug-dismiss".to_owned()]
        );

        assert_eventually(Duration::from_secs(1), || {
            capture
                .events()
                .iter()
                .any(|event| event.event_type == audit::event::SUGGESTION_LIFECYCLE_CHANGED)
        });
        let event = capture
            .events()
            .into_iter()
            .find(|event| event.event_type == audit::event::SUGGESTION_LIFECYCLE_CHANGED)
            .expect("suggestion lifecycle event should be emitted");
        assert_eq!(event.payload["id"], json!("sug-dismiss"));
        assert_eq!(event.payload["state"], json!("dismissed"));
    }

    #[tokio::test]
    async fn suggestions_admin_dismiss_rejects_non_open_suggestion_without_overwriting_state() {
        let discovery_db = TempDb::new("suggestions-dismiss-non-open");
        create_rule_suggestion_schema(&discovery_db.path);
        insert_rule_suggestion(
            &discovery_db.path,
            RuleSuggestionSeed {
                id: "sug-already-dismissed",
                suggestion_type: "signal_shadow_schema_mismatch",
                method: "PATCH",
                path_pattern: "/dismiss/{id}",
                role: None,
                action: "shadow",
                rationale: "Open schema mismatch signal targets PATCH /dismiss/{id}.",
                evidence: json!({ "source_signal_id": "sig-schema" }),
                state: "dismissed",
                created_at: "2024-06-01T00:00:00Z",
                transitioned_at: Some("2024-06-02T00:00:00Z"),
                transitioned_by: Some("original-dismisser"),
                source_signal_id: Some("sig-schema"),
            },
        );
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log = audit::AuditLog::new(Arc::new(capture.clone()));
        let policy = TempPolicyFile::new(&suggestions_policy_document_string());
        let router = suggestions_admin_router_with_policy(
            Some(&discovery_db.path),
            None,
            &policy,
            audit_log,
        );

        let response = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::POST,
                "/v1/admin/suggestions/sug-already-dismissed/dismiss",
                Some(test_principal(&["suggestions-writer"])),
                None,
                None,
            ))
            .await
            .expect("dismiss request should complete");
        assert_eq!(response.status(), StatusCode::CONFLICT);

        let page = suggestions_json(
            &router,
            "/v1/admin/suggestions?state=dismissed",
            Some(test_principal(&["suggestions-reader"])),
        )
        .await;
        let suggestion = page["suggestions"]
            .as_array()
            .expect("suggestions array should exist")
            .iter()
            .find(|suggestion| suggestion["id"] == json!("sug-already-dismissed"))
            .expect("suggestion should still exist");
        assert_eq!(
            suggestion["transitioned_by"],
            json!("original-dismisser"),
            "rejected dismiss must not overwrite the original transition metadata"
        );
        assert_eq!(suggestion["transitioned_at"], json!("2024-06-02T00:00:00Z"));

        assert!(
            capture
                .events()
                .iter()
                .all(|event| event.event_type != audit::event::SUGGESTION_LIFECYCLE_CHANGED),
            "a rejected dismiss must not emit a lifecycle-changed audit event"
        );
    }

    #[test]
    fn endpoint_rule_coverage_without_rbac_is_false() {
        assert!(!endpoint_covered_by_active_direct_rule(
            None,
            "GET",
            "/anything/{id}"
        ));
    }

    #[tokio::test]
    async fn traffic_endpoint_detail_paginates_principals() {
        let discovery_db = TempDb::new("traffic-principals");
        create_discovery_schema(&discovery_db.path);
        insert_discovery_endpoint(
            &discovery_db.path,
            SeedEndpoint {
                method: "GET",
                endpoint_template: "/users/{id}",
                first_seen: "2024-06-01T00:00:00Z",
                last_seen: "2024-06-03T00:00:00Z",
                call_count: 75,
                latency_count: 75,
                latency_p50_ms: 10,
                latency_p95_ms: 30,
                latency_p99_ms: 50,
                distinct_principal_count: 75,
                status_counts: &[(200, 75)],
            },
        );
        for index in 0..75 {
            insert_discovery_principal(
                &discovery_db.path,
                "GET",
                "/users/{id}",
                &format!("user-{index:03}"),
                "2024-06-01T00:00:00Z",
                &format!("2024-06-03T00:{:02}:00Z", index % 60),
            );
        }
        let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), None);
        let template = query_encode("/users/{id}");

        let first_page = traffic_json(
            &router,
            &format!("/v1/admin/traffic/endpoint?method=GET&endpoint_template={template}&principal_limit=10"),
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
        assert_eq!(first_page["endpoint"]["call_count"], json!(75));
        let first_principals = principal_ids(&first_page);
        assert_eq!(first_principals.len(), 10);
        assert_eq!(first_principals[0], "user-059");
        assert_eq!(first_principals[9], "user-050");
        assert!(first_page["principals"]["next_cursor"].as_str().is_some());
        assert_eq!(first_page["audit"]["available"], json!(false));
        assert!(first_page["audit"].get("time_series").is_none());
        assert!(first_page["audit"].get("recent_events").is_none());

        let cursor = first_page["principals"]["next_cursor"]
            .as_str()
            .expect("principal page should include next cursor");
        let second_page = traffic_json(
            &router,
            &format!("/v1/admin/traffic/endpoint?method=GET&endpoint_template={template}&principal_limit=10&principal_cursor={cursor}"),
            Some(test_principal(&["traffic-reader"])),
        )
        .await;
        let second_principals = principal_ids(&second_page);
        assert_eq!(second_principals[0], "user-049");
        assert_eq!(second_principals[9], "user-040");
    }

    #[tokio::test]
    async fn traffic_endpoint_detail_enriches_from_audit_for_stateless_id_templates() {
        let discovery_db = TempDb::new("traffic-detail-discovery");
        let audit_db = TempDb::new("traffic-detail-audit");
        emit_observed_events_to_discovery_and_audit(
            &discovery_db.path,
            &audit_db.path,
            &[
                observed_request_event(
                    "GET",
                    "/users/123",
                    200,
                    10,
                    Some("alice"),
                    "2024-06-01T00:05:00Z",
                ),
                observed_request_event(
                    "GET",
                    "/users/456",
                    404,
                    20,
                    Some("bob"),
                    "2024-06-01T00:40:00Z",
                ),
                observed_request_event(
                    "GET",
                    "/users/789",
                    200,
                    30,
                    Some("alice"),
                    "2024-06-01T01:10:00Z",
                ),
                observed_request_event(
                    "POST",
                    "/users/123",
                    201,
                    40,
                    Some("alice"),
                    "2024-06-01T01:20:00Z",
                ),
            ],
        );
        let (router, _policy) =
            traffic_admin_router(Some(&discovery_db.path), Some(&audit_db.path));
        let template = query_encode("/users/{id}");

        let body = traffic_json(
            &router,
            &format!("/v1/admin/traffic/endpoint?method=GET&endpoint_template={template}&from=2024-06-01T00:00:00Z&to=2024-06-01T02:00:00Z&bucket=hour&events_limit=2"),
            Some(test_principal(&["traffic-reader"])),
        )
        .await;

        assert_eq!(body["endpoint"]["call_count"], json!(3));
        assert_eq!(body["endpoint"]["status_counts"][0]["status"], json!(200));
        assert_eq!(body["endpoint"]["status_counts"][0]["count"], json!(2));
        assert_eq!(
            body["principals"]["principals"].as_array().unwrap().len(),
            2
        );
        assert_eq!(body["audit"]["available"], json!(true));
        assert_eq!(
            body["audit"]["match_strategy"],
            json!(audit::query::ENDPOINT_AUDIT_MATCH_STRATEGY)
        );
        assert_eq!(
            body["audit"]["time_series"],
            json!([
                { "bucket_start": "2024-06-01T00:00:00Z", "count": 2 },
                { "bucket_start": "2024-06-01T01:00:00Z", "count": 1 }
            ])
        );
        assert_eq!(body["audit"]["time_series_truncated"], json!(false));
        let recent_paths = body["audit"]["recent_events"]
            .as_array()
            .expect("recent events should be present")
            .iter()
            .map(|event| event["path"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            recent_paths,
            vec!["/users/789".to_owned(), "/users/456".to_owned()]
        );
        assert_eq!(body["audit"]["recent_events_scan_truncated"], json!(false));
        assert!(body["audit"]["recent_events_next_cursor"]
            .as_i64()
            .is_some());
    }

    #[tokio::test]
    async fn traffic_endpoint_detail_documents_learned_param_reverse_mapping_limit() {
        let discovery_db = TempDb::new("traffic-learned-discovery");
        let audit_db = TempDb::new("traffic-learned-audit");
        emit_observed_events_to_discovery_and_audit(
            &discovery_db.path,
            &audit_db.path,
            &["apple", "banana", "cherry", "date"]
                .into_iter()
                .enumerate()
                .map(|(index, slug)| {
                    observed_request_event(
                        "GET",
                        &format!("/catalog/{slug}"),
                        200,
                        10,
                        Some("alice"),
                        &format!("2024-06-01T00:0{index}:00Z"),
                    )
                })
                .collect::<Vec<_>>(),
        );
        let (router, _policy) =
            traffic_admin_router(Some(&discovery_db.path), Some(&audit_db.path));
        let template = query_encode("/catalog/{param}");

        let body = traffic_json(
            &router,
            &format!("/v1/admin/traffic/endpoint?method=GET&endpoint_template={template}&from=2024-06-01T00:00:00Z&to=2024-06-01T01:00:00Z"),
            Some(test_principal(&["traffic-reader"])),
        )
        .await;

        assert_eq!(body["endpoint"]["call_count"], json!(4));
        assert_eq!(body["audit"]["available"], json!(true));
        assert_eq!(body["audit"]["time_series"], json!([]));
        assert_eq!(body["audit"]["recent_events"], json!([]));
        assert!(body["audit"]["match_limitations"]
            .as_str()
            .expect("match limitation should be present")
            .contains("learned slug templates"));
    }

    #[tokio::test]
    async fn traffic_endpoint_inventory_requires_discovery_sqlite_path() {
        let (router, _policy) = traffic_admin_router(None, None);
        let principal = Some(test_principal(&["traffic-reader"]));

        for uri in [
            "/v1/admin/traffic/endpoints",
            "/v1/admin/traffic/endpoint?method=GET&endpoint_template=%2Fusers%2F%7Bid%7D",
        ] {
            let response = router
                .clone()
                .oneshot(traffic_admin_request(uri, principal.clone()))
                .await
                .expect("traffic request should complete");

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                body_string(response).await,
                r#"{"error":"traffic endpoint inventory requires DISCOVERY_SQLITE_PATH to be configured"}"#
            );
        }
    }

    #[tokio::test]
    async fn traffic_endpoint_detail_omits_audit_enrichment_when_audit_sqlite_path_is_unset() {
        let discovery_db = TempDb::new("traffic-no-audit");
        create_discovery_schema(&discovery_db.path);
        insert_discovery_endpoint(
            &discovery_db.path,
            SeedEndpoint {
                method: "GET",
                endpoint_template: "/users/{id}",
                first_seen: "2024-06-01T00:00:00Z",
                last_seen: "2024-06-01T01:00:00Z",
                call_count: 1,
                latency_count: 1,
                latency_p50_ms: 10,
                latency_p95_ms: 10,
                latency_p99_ms: 10,
                distinct_principal_count: 0,
                status_counts: &[(200, 1)],
            },
        );
        let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), None);
        let template = query_encode("/users/{id}");

        let body = traffic_json(
            &router,
            &format!("/v1/admin/traffic/endpoint?method=GET&endpoint_template={template}"),
            Some(test_principal(&["traffic-reader"])),
        )
        .await;

        assert_eq!(body["endpoint"]["call_count"], json!(1));
        assert_eq!(body["audit"]["available"], json!(false));
        assert_eq!(
            body["audit"]["omitted_reason"],
            json!("AUDIT_SQLITE_PATH not configured")
        );
        assert!(body["audit"].get("time_series").is_none());
        assert!(body["audit"].get("recent_events").is_none());
    }

    #[tokio::test]
    async fn traffic_endpoint_admin_reports_rbac_not_configured() {
        let discovery_db = TempDb::new("traffic-rbac-unconfigured");
        create_discovery_schema(&discovery_db.path);
        insert_discovery_endpoint(
            &discovery_db.path,
            SeedEndpoint {
                method: "GET",
                endpoint_template: "/users/{id}",
                first_seen: "2024-06-01T00:00:00Z",
                last_seen: "2024-06-01T01:00:00Z",
                call_count: 1,
                latency_count: 1,
                latency_p50_ms: 10,
                latency_p95_ms: 10,
                latency_p99_ms: 10,
                distinct_principal_count: 0,
                status_counts: &[(200, 1)],
            },
        );
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.discovery_sqlite_path = Some(discovery_db.path.to_string_lossy().into_owned());
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");
        let detail_uri =
            "/v1/admin/traffic/endpoint?method=GET&endpoint_template=%2Fusers%2F%7Bid%7D";

        for uri in ["/v1/admin/traffic/endpoints", detail_uri] {
            let response = router
                .clone()
                .oneshot(traffic_admin_request(
                    uri,
                    Some(test_principal(&["traffic-reader"])),
                ))
                .await
                .expect("traffic request should complete");

            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                body_string(response).await,
                r#"{"error":"traffic endpoint inventory requires POLICY_FILE to be configured"}"#
            );
        }
    }

    #[tokio::test]
    async fn traffic_endpoint_admin_requires_traffic_read_permission() {
        let discovery_db = TempDb::new("traffic-authz");
        create_discovery_schema(&discovery_db.path);
        insert_discovery_endpoint(
            &discovery_db.path,
            SeedEndpoint {
                method: "GET",
                endpoint_template: "/users/{id}",
                first_seen: "2024-06-01T00:00:00Z",
                last_seen: "2024-06-01T01:00:00Z",
                call_count: 1,
                latency_count: 1,
                latency_p50_ms: 10,
                latency_p95_ms: 10,
                latency_p99_ms: 10,
                distinct_principal_count: 0,
                status_counts: &[(200, 1)],
            },
        );
        let (router, _policy) = traffic_admin_router(Some(&discovery_db.path), None);
        let detail_uri =
            "/v1/admin/traffic/endpoint?method=GET&endpoint_template=%2Fusers%2F%7Bid%7D";

        for uri in ["/v1/admin/traffic/endpoints", detail_uri] {
            let unauthenticated = router
                .clone()
                .oneshot(traffic_admin_request(uri, None))
                .await
                .expect("traffic request should complete");
            assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

            let forbidden_response = router
                .clone()
                .oneshot(traffic_admin_request(
                    uri,
                    Some(test_principal(&["reader"])),
                ))
                .await
                .expect("traffic request should complete");
            assert_eq!(forbidden_response.status(), StatusCode::FORBIDDEN);
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
    async fn auth_validator_resolves_oidc_discovery_for_issuer_only_provider() {
        let (issuer, server) = spawn_oidc_jwks_server();
        let issuer_claim = issuer.clone();
        let mut config = test_config(Vec::new());
        config.auth_providers = vec![config::AuthProviderConfig {
            name: "oidc".to_owned(),
            provider_type: config::AuthProviderType::Jwt,
            jwks_url: None,
            issuer: Some(issuer),
            audience: None,
            jwks_timeout_ms: 2000,
            require_jti: false,
            roles_claim: "roles".to_owned(),
            roles_claim_delimiter: None,
            org_claim: None,
            introspection_url: None,
            introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
            cache_ttl_ms: config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
            user_id_claim: None,
            email_claim: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
        }];
        config.egress_deny_private_ips = false;
        let egress_client = Arc::new(
            egress::EgressClient::new(egress::EgressConfig::from_config(&config))
                .expect("egress client should build"),
        );
        let discovered_oidc_jwks_urls =
            discover_oidc_jwks_urls_from_config(&config, Arc::clone(&egress_client))
                .expect("issuer-only provider should discover JWKS URI");

        let validator =
            auth_validator_from_config(&config, egress_client, None, &discovered_oidc_jwks_urls)
                .expect("issuer-only provider should build")
                .expect("auth validator should be configured");
        let principal = validator
            .validate_session(&auth::SessionCredential::Bearer(signed_token_with_issuer(
                "oidc-user",
                &["member"],
                &issuer_claim,
            )))
            .await
            .expect("token should validate through discovered JWKS URI");

        assert_eq!(principal.user_id, "oidc-user");
        server
            .join()
            .expect("OIDC discovery test server should finish");
    }

    #[tokio::test]
    async fn auth_validator_accepts_slashless_oidc_issuer_when_config_has_trailing_slash() {
        let (issuer, document_issuer, server) =
            spawn_oidc_jwks_server_with_document_issuer(str::to_owned);
        let mut config = test_config(Vec::new());
        config.auth_providers = vec![oidc_jwt_provider(format!("{issuer}/"))];
        config.egress_deny_private_ips = false;
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build with slash-normalized OIDC issuer");

        let response = authenticated_principal_probe(
            &router,
            &signed_token_with_issuer("slashless-oidc-user", &["member"], &document_issuer),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await["user_id"],
            json!("slashless-oidc-user")
        );
        server
            .join()
            .expect("OIDC discovery and JWKS test server should finish");
    }

    #[tokio::test]
    async fn auth_validator_accepts_slash_retained_oidc_issuer_and_token() {
        let (_issuer, document_issuer, server) =
            spawn_oidc_jwks_server_with_document_issuer(|issuer| format!("{issuer}/"));
        let mut config = test_config(Vec::new());
        config.auth_providers = vec![oidc_jwt_provider(document_issuer.clone())];
        config.egress_deny_private_ips = false;
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build with slash-retained OIDC issuer");

        let response = authenticated_principal_probe(
            &router,
            &signed_token_with_issuer("slash-retained-oidc-user", &["member"], &document_issuer),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await["user_id"],
            json!("slash-retained-oidc-user")
        );
        server
            .join()
            .expect("OIDC discovery and JWKS test server should finish");
    }

    #[test]
    fn auth_validator_rejects_oidc_discovery_with_mismatched_issuer() {
        let (issuer, server) = spawn_oidc_discovery_server(
            json!({
                "issuer": "http://attacker.example.test",
                "jwks_uri": "http://127.0.0.1:1/jwks.json"
            }),
            1,
        );
        let mut config = test_config(Vec::new());
        config.auth_providers = vec![config::AuthProviderConfig {
            name: "oidc".to_owned(),
            provider_type: config::AuthProviderType::Jwt,
            jwks_url: None,
            issuer: Some(issuer),
            audience: None,
            jwks_timeout_ms: 2000,
            require_jti: false,
            roles_claim: "roles".to_owned(),
            roles_claim_delimiter: None,
            org_claim: None,
            introspection_url: None,
            introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
            cache_ttl_ms: config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
            user_id_claim: None,
            email_claim: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
        }];
        config.egress_deny_private_ips = false;
        let egress_client = Arc::new(
            egress::EgressClient::new(egress::EgressConfig::from_config(&config))
                .expect("egress client should build"),
        );

        let error = discover_oidc_jwks_urls_from_config(&config, egress_client)
            .expect_err("mismatched discovery issuer should fail provider construction");

        assert!(matches!(
            error,
            auth::AuthError::Upstream(message)
                if message.contains("OIDC discovery issuer mismatch")
        ));
        server
            .join()
            .expect("OIDC discovery test server should finish");
    }

    #[test]
    fn auth_validator_rejects_oidc_discovery_without_issuer() {
        let (issuer, server) = spawn_oidc_discovery_server(
            json!({
                "jwks_uri": "http://127.0.0.1:1/jwks.json"
            }),
            1,
        );
        let mut config = test_config(Vec::new());
        config.auth_providers = vec![config::AuthProviderConfig {
            name: "oidc".to_owned(),
            provider_type: config::AuthProviderType::Jwt,
            jwks_url: None,
            issuer: Some(issuer),
            audience: None,
            jwks_timeout_ms: 2000,
            require_jti: false,
            roles_claim: "roles".to_owned(),
            roles_claim_delimiter: None,
            org_claim: None,
            introspection_url: None,
            introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
            cache_ttl_ms: config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
            user_id_claim: None,
            email_claim: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
        }];
        config.egress_deny_private_ips = false;
        let egress_client = Arc::new(
            egress::EgressClient::new(egress::EgressConfig::from_config(&config))
                .expect("egress client should build"),
        );

        let error = discover_oidc_jwks_urls_from_config(&config, egress_client)
            .expect_err("discovery without issuer should fail provider construction");

        assert!(matches!(
            error,
            auth::AuthError::Upstream(message)
                if message.contains("OIDC discovery response missing issuer")
        ));
        server
            .join()
            .expect("OIDC discovery test server should finish");
    }

    #[tokio::test]
    async fn oidc_discovery_allowlists_jwks_uri_host_when_it_differs_from_issuer() {
        let (jwks_url, jwks_server) = spawn_blocking_jwks_server(Ipv4Addr::new(127, 0, 0, 2), 1);
        let (issuer, discovery_server) = spawn_blocking_oidc_discovery_server(jwks_url);
        let issuer_claim = issuer.clone();
        let mut config = test_config(Vec::new());
        config.auth_providers = vec![config::AuthProviderConfig {
            name: "oidc".to_owned(),
            provider_type: config::AuthProviderType::Jwt,
            jwks_url: None,
            issuer: Some(issuer),
            audience: None,
            jwks_timeout_ms: 2000,
            require_jti: false,
            roles_claim: "roles".to_owned(),
            roles_claim_delimiter: None,
            org_claim: None,
            introspection_url: None,
            introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
            cache_ttl_ms: config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
            user_id_claim: None,
            email_claim: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
        }];
        config.egress_deny_private_ips = false;
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build with issuer-only OIDC provider");

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/__test/principal")
                    .header(
                        header::AUTHORIZATION,
                        format!(
                            "Bearer {}",
                            signed_token_with_issuer("split-oidc-user", &["member"], &issuer_claim)
                        ),
                    )
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await["user_id"],
            json!("split-oidc-user")
        );
        assert_eq!(
            discovery_server
                .join()
                .expect("OIDC discovery server should finish"),
            1
        );
        assert_eq!(jwks_server.join().expect("JWKS server should finish"), 1);
    }

    #[tokio::test]
    async fn admin_oidc_login_redirects_exchanges_code_and_consumes_state_once() {
        let jwks_addr = spawn_test_jwks_server().await;
        let jwks_url = format!("http://127.0.0.1:{}/jwks.json", jwks_addr.port());
        let token_endpoint =
            spawn_mock_oidc_token_endpoint(Ipv4Addr::new(127, 0, 0, 2), None).await;
        let oidc = spawn_mock_oidc_discovery_endpoint(Some(token_endpoint.url.clone()));
        let access_token = signed_token_with_issuer("admin-operator", &["admin"], &oidc.issuer);
        token_endpoint.set_access_token(access_token.clone());
        let mut config = admin_oidc_login_config(&oidc.issuer);
        config.auth_providers[0].jwks_url = Some(jwks_url);
        let router = admin_oidc_login_router_from_config(config);

        let login_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/auth/login")
                    .body(Body::empty())
                    .expect("login request should build"),
            )
            .await
            .expect("login request should complete");

        assert_eq!(login_response.status(), StatusCode::FOUND);
        let login_location = response_location(&login_response);
        let authorization_url =
            Url::parse(&login_location).expect("authorization redirect should be absolute");
        assert_eq!(
            authorization_url.as_str().split('?').next(),
            Some(oidc.authorization_endpoint.as_str())
        );
        let authorization_query = url_query_pairs(&authorization_url);
        assert_eq!(
            authorization_query.get("response_type").map(String::as_str),
            Some("code")
        );
        assert_eq!(
            authorization_query.get("client_id").map(String::as_str),
            Some("admin-ui")
        );
        assert_eq!(
            authorization_query.get("redirect_uri").map(String::as_str),
            Some("http://gateway.example.test/v1/admin/auth/callback")
        );
        assert_eq!(
            authorization_query.get("scope").map(String::as_str),
            Some("openid email profile")
        );
        assert_eq!(
            authorization_query
                .get("code_challenge_method")
                .map(String::as_str),
            Some("S256")
        );
        let state = authorization_query
            .get("state")
            .expect("authorization redirect should include state");
        let nonce = authorization_query
            .get("nonce")
            .expect("authorization redirect should include nonce");
        assert!(!state.is_empty());
        assert!(!nonce.is_empty());
        token_endpoint.set_id_token(signed_admin_id_token(&oidc.issuer, "admin-ui", nonce));
        let challenge = authorization_query
            .get("code_challenge")
            .expect("authorization redirect should include PKCE challenge");
        assert_eq!(challenge.len(), 43);
        assert!(is_pkce_unreserved(challenge));

        let callback_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/admin/auth/callback?code=admin-code&state={}",
                        query_encode(state)
                    ))
                    .body(Body::empty())
                    .expect("callback request should build"),
            )
            .await
            .expect("callback request should complete");

        assert_eq!(callback_response.status(), StatusCode::FOUND);
        let callback_location = response_location(&callback_response);
        let completion = fragment_query_pairs(&callback_location, "/auth/complete")
            .expect("callback should redirect to auth completion fragment");
        assert_eq!(completion.get("token"), Some(&access_token));

        let token_requests = token_endpoint.requests();
        assert_eq!(token_requests.len(), 1);
        assert_eq!(token_requests[0].method, Method::POST);
        assert_eq!(
            token_requests[0].headers.get(header::CONTENT_TYPE),
            Some(&HeaderValue::from_static(
                "application/x-www-form-urlencoded"
            ))
        );
        let token_form = form_pairs(&token_requests[0].body);
        assert_eq!(
            token_form.get("grant_type").map(String::as_str),
            Some("authorization_code")
        );
        assert_eq!(
            token_form.get("code").map(String::as_str),
            Some("admin-code")
        );
        assert_eq!(
            token_form.get("redirect_uri").map(String::as_str),
            Some("http://gateway.example.test/v1/admin/auth/callback")
        );
        assert_eq!(
            token_form.get("client_id").map(String::as_str),
            Some("admin-ui")
        );
        assert_eq!(
            token_form.get("client_secret").map(String::as_str),
            Some("secret-value")
        );
        let verifier = token_form
            .get("code_verifier")
            .expect("token exchange should include the PKCE verifier");
        assert!((43..=128).contains(&verifier.len()));
        assert!(is_pkce_unreserved(verifier));
        assert_eq!(pkce_challenge_for_verifier(verifier), *challenge);

        let replay_response = router
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/admin/auth/callback?code=admin-code&state={}",
                        query_encode(state)
                    ))
                    .body(Body::empty())
                    .expect("replay callback request should build"),
            )
            .await
            .expect("replay callback should complete");

        assert_eq!(replay_response.status(), StatusCode::FOUND);
        assert!(
            fragment_query_pairs(&response_location(&replay_response), "/auth/error")
                .expect("replay should redirect to auth error fragment")
                .get("error")
                .is_some_and(|error| error == "invalid_state")
        );
        assert_eq!(token_endpoint.requests().len(), 1);

        oidc.finish();
        token_endpoint.abort();
    }

    #[tokio::test]
    async fn admin_oidc_login_rejects_token_response_without_id_token() {
        let token_endpoint =
            spawn_mock_oidc_token_endpoint(Ipv4Addr::new(127, 0, 0, 2), None).await;
        let oidc = spawn_mock_oidc_discovery_endpoint(Some(token_endpoint.url.clone()));
        token_endpoint.set_access_token(signed_token_with_issuer(
            "admin-operator",
            &["admin"],
            &oidc.issuer,
        ));
        let router = admin_oidc_login_router(&oidc.issuer);

        let login_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/auth/login")
                    .body(Body::empty())
                    .expect("login request should build"),
            )
            .await
            .expect("login request should complete");
        let login_location = response_location(&login_response);
        let authorization_url =
            Url::parse(&login_location).expect("authorization redirect should be absolute");
        let authorization_query = url_query_pairs(&authorization_url);
        let state = authorization_query
            .get("state")
            .expect("authorization redirect should include state");

        let callback_response = router
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v1/admin/auth/callback?code=admin-code&state={}",
                        query_encode(state)
                    ))
                    .body(Body::empty())
                    .expect("callback request should build"),
            )
            .await
            .expect("callback request should complete");

        assert_eq!(callback_response.status(), StatusCode::FOUND);
        assert!(
            fragment_query_pairs(&response_location(&callback_response), "/auth/error")
                .expect("missing id_token should redirect to auth error fragment")
                .get("error")
                .is_some_and(|error| error == "token_exchange_failed")
        );
        assert_eq!(token_endpoint.requests().len(), 1);

        oidc.finish();
        token_endpoint.abort();
    }

    #[tokio::test]
    async fn admin_oidc_login_accepts_valid_id_token_with_matching_nonce_audience_and_issuer() {
        let (callback_response, access_token) =
            admin_oidc_id_token_callback_response(|nonce, issuer| {
                signed_admin_id_token(issuer, "admin-ui", nonce)
            })
            .await;

        assert_eq!(callback_response.status(), StatusCode::FOUND);
        let callback_location = response_location(&callback_response);
        let completion = fragment_query_pairs(&callback_location, "/auth/complete")
            .expect("callback should redirect to auth completion fragment");
        assert_eq!(completion.get("token"), Some(&access_token));
    }

    #[tokio::test]
    async fn admin_oidc_login_rejects_id_token_with_mismatched_nonce() {
        let (callback_response, _) = admin_oidc_id_token_callback_response(|_, issuer| {
            signed_admin_id_token(issuer, "admin-ui", "other-nonce")
        })
        .await;

        assert_eq!(callback_response.status(), StatusCode::FOUND);
        assert!(
            fragment_query_pairs(&response_location(&callback_response), "/auth/error")
                .expect("invalid id_token should redirect to auth error fragment")
                .get("error")
                .is_some_and(|error| error == "token_exchange_failed")
        );
    }

    #[tokio::test]
    async fn admin_oidc_login_rejects_id_token_with_mismatched_audience() {
        let (callback_response, _) = admin_oidc_id_token_callback_response(|nonce, issuer| {
            signed_admin_id_token(issuer, "other-client", nonce)
        })
        .await;

        assert_eq!(callback_response.status(), StatusCode::FOUND);
        assert!(
            fragment_query_pairs(&response_location(&callback_response), "/auth/error")
                .expect("invalid id_token should redirect to auth error fragment")
                .get("error")
                .is_some_and(|error| error == "token_exchange_failed")
        );
    }

    #[tokio::test]
    async fn admin_oidc_login_rejects_id_token_with_mismatched_issuer() {
        let (callback_response, _) = admin_oidc_id_token_callback_response(|nonce, _| {
            signed_admin_id_token("http://other-issuer.example.test", "admin-ui", nonce)
        })
        .await;

        assert_eq!(callback_response.status(), StatusCode::FOUND);
        assert!(
            fragment_query_pairs(&response_location(&callback_response), "/auth/error")
                .expect("invalid id_token should redirect to auth error fragment")
                .get("error")
                .is_some_and(|error| error == "token_exchange_failed")
        );
    }

    #[tokio::test]
    async fn admin_oidc_login_rejects_id_token_with_invalid_signature() {
        let (callback_response, _) = admin_oidc_id_token_callback_response(|nonce, issuer| {
            corrupt_jwt_signature(&signed_admin_id_token(issuer, "admin-ui", nonce))
        })
        .await;

        assert_eq!(callback_response.status(), StatusCode::FOUND);
        assert!(
            fragment_query_pairs(&response_location(&callback_response), "/auth/error")
                .expect("invalid id_token should redirect to auth error fragment")
                .get("error")
                .is_some_and(|error| error == "token_exchange_failed")
        );
    }

    #[tokio::test]
    async fn admin_oidc_callback_with_unknown_state_does_not_exchange_token() {
        let token_endpoint = spawn_mock_oidc_token_endpoint(Ipv4Addr::LOCALHOST, None).await;
        let oidc = spawn_mock_oidc_discovery_endpoint(Some(token_endpoint.url.clone()));
        token_endpoint.set_access_token(signed_token_with_issuer(
            "admin-operator",
            &["admin"],
            &oidc.issuer,
        ));
        let router = admin_oidc_login_router(&oidc.issuer);

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/auth/callback?code=admin-code&state=unknown-state")
                    .body(Body::empty())
                    .expect("callback request should build"),
            )
            .await
            .expect("callback request should complete");

        assert_eq!(response.status(), StatusCode::FOUND);
        assert!(
            fragment_query_pairs(&response_location(&response), "/auth/error")
                .expect("unknown state should redirect to auth error fragment")
                .get("error")
                .is_some_and(|error| error == "invalid_state")
        );
        assert!(token_endpoint.requests().is_empty());

        oidc.finish();
        token_endpoint.abort();
    }

    #[test]
    fn admin_oidc_login_provider_rejects_discovery_with_mismatched_issuer() {
        let (issuer, server) = spawn_oidc_discovery_server(
            json!({
                "issuer": "http://attacker.example.test",
                "jwks_uri": "http://127.0.0.1:1/jwks.json",
                "authorization_endpoint": "http://127.0.0.1:1/authorize",
                "token_endpoint": "http://127.0.0.1:1/token"
            }),
            1,
        );
        let mut config = admin_oidc_login_config(&issuer);
        config.egress_deny_private_ips = false;
        let recorder = PrometheusBuilder::new().build_recorder();

        let error = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect_err("admin login discovery with mismatched issuer should fail startup");

        assert!(error.to_string().contains("OIDC discovery issuer mismatch"));
        server
            .join()
            .expect("OIDC discovery test server should finish");
    }

    #[test]
    fn admin_oidc_login_provider_rejects_discovery_without_issuer() {
        let (issuer, server) = spawn_oidc_discovery_server(
            json!({
                "jwks_uri": "http://127.0.0.1:1/jwks.json",
                "authorization_endpoint": "http://127.0.0.1:1/authorize",
                "token_endpoint": "http://127.0.0.1:1/token"
            }),
            1,
        );
        let mut config = admin_oidc_login_config(&issuer);
        config.egress_deny_private_ips = false;
        let recorder = PrometheusBuilder::new().build_recorder();

        let error = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect_err("admin login discovery without issuer should fail startup");

        assert!(error
            .to_string()
            .contains("OIDC discovery response missing issuer"));
        server
            .join()
            .expect("OIDC discovery test server should finish");
    }

    #[test]
    fn admin_oidc_login_provider_requires_discovered_authorize_and_token_endpoints() {
        let (issuer, server) = spawn_oidc_discovery_server_with(
            |issuer| {
                json!({
                    "issuer": issuer,
                    "jwks_uri": "http://127.0.0.1:1/jwks.json",
                    "authorization_endpoint": "http://127.0.0.1:1/authorize"
                })
            },
            1,
        );
        let mut config = admin_oidc_login_config(&issuer);
        config.egress_deny_private_ips = false;
        let recorder = PrometheusBuilder::new().build_recorder();

        let error = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect_err("admin login discovery without token endpoint should fail startup");

        assert!(error
            .to_string()
            .contains("OIDC discovery response missing token_endpoint"));
        server
            .join()
            .expect("OIDC discovery test server should finish");
    }

    #[tokio::test]
    async fn admin_oidc_login_routes_are_absent_when_provider_unset() {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build without admin login provider");

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/auth/login")
                    .body(Body::empty())
                    .expect("login request should build"),
            )
            .await
            .expect("login request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn oidc_discovery_jwks_uri_auto_seed_still_blocks_private_ip() {
        let (jwks_url, jwks_server) = spawn_blocking_jwks_server(Ipv4Addr::new(127, 0, 0, 2), 1);
        let (issuer, discovery_server) = spawn_blocking_oidc_discovery_server(jwks_url);
        let issuer_claim = issuer.clone();
        let policy = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "default_action": "allow",
                "roles": {},
                "routes": [],
                "egress": {
                    "cidrs": ["127.0.0.1/32"]
                }
            }"#,
        );
        let mut config = test_config(Vec::new());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config.auth_providers = vec![config::AuthProviderConfig {
            name: "oidc".to_owned(),
            provider_type: config::AuthProviderType::Jwt,
            jwks_url: None,
            issuer: Some(issuer),
            audience: None,
            jwks_timeout_ms: 2000,
            require_jti: false,
            roles_claim: "roles".to_owned(),
            roles_claim_delimiter: None,
            org_claim: None,
            introspection_url: None,
            introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
            cache_ttl_ms: config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
            user_id_claim: None,
            email_claim: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
        }];
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build after OIDC discovery");

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/__test/principal")
                    .header(
                        header::AUTHORIZATION,
                        format!(
                            "Bearer {}",
                            signed_token_with_issuer(
                                "blocked-jwks-user",
                                &["member"],
                                &issuer_claim
                            )
                        ),
                    )
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            discovery_server
                .join()
                .expect("OIDC discovery server should finish"),
            1
        );
        assert_eq!(jwks_server.join().expect("JWKS server should finish"), 0);
    }

    #[test]
    fn auth_validator_reports_construction_error_when_oidc_discovery_lacks_jwks_uri() {
        let (issuer, server) =
            spawn_oidc_discovery_server_with(|issuer| json!({"issuer": issuer}), 1);
        let mut config = test_config(Vec::new());
        config.auth_providers = vec![config::AuthProviderConfig {
            name: "oidc".to_owned(),
            provider_type: config::AuthProviderType::Jwt,
            jwks_url: None,
            issuer: Some(issuer),
            audience: None,
            jwks_timeout_ms: 2000,
            require_jti: false,
            roles_claim: "roles".to_owned(),
            roles_claim_delimiter: None,
            org_claim: None,
            introspection_url: None,
            introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
            cache_ttl_ms: config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
            user_id_claim: None,
            email_claim: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
        }];
        config.egress_deny_private_ips = false;
        let egress_client = Arc::new(
            egress::EgressClient::new(egress::EgressConfig::from_config(&config))
                .expect("egress client should build"),
        );

        let error = match discover_oidc_jwks_urls_from_config(&config, egress_client) {
            Ok(_) => panic!("missing jwks_uri should fail provider construction"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            auth::AuthError::Upstream(message)
                if message.contains("OIDC discovery response missing jwks_uri")
        ));
        server
            .join()
            .expect("OIDC discovery test server should finish");
    }

    #[tokio::test]
    async fn policy_rate_limit_uses_real_authenticated_principal_buckets_in_app_stack() {
        let jwks_addr = spawn_test_jwks_server().await;
        let policy = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "default_action": "deny",
                "enforcement_mode": "enforce",
                "roles": {
                    "member": { "permissions": ["test:read"] }
                },
                "routes": [
                    {
                        "path_prefix": "/__test",
                        "permission": "test:read"
                    }
                ],
                "rate_limits": [
                    {
                        "principal": {
                            "auth_methods": ["bearer_token"]
                        },
                        "methods": ["GET"],
                        "path": "/__test/principal",
                        "requests_per_second": 0.000001,
                        "burst": 1
                    }
                ]
            }"#,
        );
        let mut config = test_config(Vec::new());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        configure_test_jwt_provider(&mut config, jwks_addr);
        config.egress_deny_private_ips = false;
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");
        let user_a_token = signed_token("user-a", &["member"]);
        let user_b_token = signed_token("user-b", &["member"]);

        let first_user_a = authenticated_principal_probe(&router, &user_a_token).await;
        assert_eq!(first_user_a.status(), StatusCode::OK);
        assert_eq!(json_body(first_user_a).await["user_id"], json!("user-a"));

        let second_user_a = authenticated_principal_probe(&router, &user_a_token).await;
        assert_eq!(second_user_a.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            body_string(second_user_a).await,
            r#"{"error":"too many requests"}"#
        );

        let first_user_b = authenticated_principal_probe(&router, &user_b_token).await;
        assert_eq!(first_user_b.status(), StatusCode::OK);
        assert_eq!(json_body(first_user_b).await["user_id"], json!("user-b"));
    }

    #[tokio::test]
    async fn authenticated_requests_without_policy_override_use_global_rate_limit_in_app_stack() {
        let jwks_addr = spawn_test_jwks_server().await;
        let policy = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "default_action": "allow",
                "roles": {},
                "rate_limits": [
                    {
                        "methods": ["GET"],
                        "path": "/elsewhere",
                        "requests_per_second": 100.0,
                        "burst": 100
                    }
                ]
            }"#,
        );
        let mut config = test_config(Vec::new());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config.rate_limit_read_rps = 0.0;
        config.rate_limit_read_burst = 1;
        configure_test_jwt_provider(&mut config, jwks_addr);
        config.egress_deny_private_ips = false;
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");
        let token = signed_token("user-a", &["member"]);

        let first = authenticated_principal_probe(&router, &token).await;
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(json_body(first).await["user_id"], json!("user-a"));

        let second = authenticated_principal_probe(&router, &token).await;
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn unauthenticated_requests_still_use_pre_auth_global_rate_limit_in_app_stack() {
        let policy = TempPolicyFile::new(
            r#"{
                "schema_version": "0.1.0",
                "default_action": "allow",
                "roles": {},
                "rate_limits": [
                    {
                        "methods": ["GET"],
                        "path": "/__test/principal",
                        "requests_per_second": 100.0,
                        "burst": 100
                    }
                ]
            }"#,
        );
        let mut config = test_config(Vec::new());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
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

        let first = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/__test/principal")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");
        assert_eq!(first.status(), StatusCode::UNAUTHORIZED);

        let second = router
            .oneshot(
                Request::builder()
                    .uri("/__test/principal")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
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

    fn audit_query_config_with_policy(
        sqlite_path: Option<&PathBuf>,
        policy: &TempPolicyFile,
    ) -> config::Config {
        let mut config = audit_query_config(sqlite_path);
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config.rbac_exempt_paths.push(AUDIT_ADMIN_ROUTE.to_owned());
        config
            .rbac_exempt_paths
            .push(AUDIT_EVENTS_STREAM_ROUTE.to_owned());

        config
    }

    fn audit_query_router(sqlite_path: Option<&PathBuf>) -> (Router, TempPolicyFile) {
        let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            audit_query_config_with_policy(sqlite_path, &policy),
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");

        (router, policy)
    }

    fn principal_admin_config(
        principal_path: Option<&PathBuf>,
        audit_path: Option<&PathBuf>,
        discovery_path: Option<&PathBuf>,
        policy: &TempPolicyFile,
    ) -> config::Config {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.principal_sqlite_path =
            principal_path.map(|path| path.to_string_lossy().into_owned());
        config.audit_sqlite_path = audit_path.map(|path| path.to_string_lossy().into_owned());
        config.discovery_sqlite_path =
            discovery_path.map(|path| path.to_string_lossy().into_owned());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config
            .rbac_exempt_paths
            .push("/v1/admin/principals".to_owned());
        config
            .rbac_exempt_paths
            .push("/v1/admin/principal".to_owned());
        config
    }

    fn principal_admin_router(
        principal_path: Option<&PathBuf>,
        audit_path: Option<&PathBuf>,
        discovery_path: Option<&PathBuf>,
    ) -> (Router, TempPolicyFile) {
        let policy = TempPolicyFile::new(&principal_policy_document_string());
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            principal_admin_config(principal_path, audit_path, discovery_path, &policy),
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");

        (router, policy)
    }

    fn principal_admin_request(uri: &str, principal: Option<auth::Principal>) -> Request<Body> {
        let mut request = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request should build");
        if let Some(principal) = principal {
            request.extensions_mut().insert(principal);
        }

        request
    }

    fn principal_admin_bearer_request(uri: &str, token: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .expect("principal admin bearer request should build")
    }

    async fn principal_json(
        router: &Router,
        uri: &str,
        principal: Option<auth::Principal>,
    ) -> Value {
        let response = router
            .clone()
            .oneshot(principal_admin_request(uri, principal))
            .await
            .expect("principal admin request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        json_body(response).await
    }

    async fn wait_for_principal_detail_json(
        router: &Router,
        uri: &str,
        token: &str,
        predicate: impl Fn(&Value) -> bool,
    ) -> Value {
        let started = Instant::now();

        loop {
            let response = router
                .clone()
                .oneshot(principal_admin_bearer_request(uri, token))
                .await
                .expect("principal detail request should complete");
            let status = response.status();
            if status != StatusCode::OK {
                panic!(
                    "principal detail request returned {status}: {}",
                    body_string(response).await
                );
            }
            let body = json_body(response).await;
            if predicate(&body) {
                return body;
            }

            assert!(
                started.elapsed() < Duration::from_secs(2),
                "principal detail did not match condition within async flush window: {body}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    fn principal_policy_document_string() -> String {
        serde_json::to_string_pretty(&json!({
            "schema_version": "0.1.0",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {
                "principal-reader": {
                    "permissions": ["admin:principals:read"]
                },
                "reader": {
                    "permissions": []
                }
            },
            "rules": []
        }))
        .expect("principal policy should serialize")
    }

    fn principal_full_stack_policy_document_string() -> String {
        serde_json::to_string_pretty(&json!({
            "schema_version": "0.1.0",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {
                "principal-reader": {
                    "permissions": ["admin:principals:read"]
                },
                "member": {
                    "permissions": []
                }
            },
            "rules": [
                direct_rule_json(Some("allow-probe"), &["GET"], "/__test/principal", "allow")
            ]
        }))
        .expect("principal full-stack policy should serialize")
    }

    fn audit_admin_policy_document_string() -> String {
        json!({
            "schema_version": "0.1.0",
            "id": "audit-admin-policy",
            "default_action": "allow",
            "enforcement_mode": "enforce",
            "roles": {
                "admin": {
                    "permissions": [
                        ADMIN_AUDIT_READ_PERMISSION,
                        ADMIN_AUDIT_STREAM_PERMISSION,
                        ADMIN_STATUS_READ_PERMISSION
                    ]
                },
                "audit-reader": {
                    "permissions": [ADMIN_AUDIT_READ_PERMISSION]
                },
                "audit-streamer": {
                    "permissions": [ADMIN_AUDIT_STREAM_PERMISSION]
                },
                "status-reader": {
                    "permissions": [ADMIN_STATUS_READ_PERMISSION]
                },
                "reader": {
                    "permissions": []
                }
            },
            "routes": []
        })
        .to_string()
    }

    fn traffic_admin_config(
        discovery_path: Option<&PathBuf>,
        audit_path: Option<&PathBuf>,
        policy: &TempPolicyFile,
    ) -> config::Config {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.discovery_sqlite_path =
            discovery_path.map(|path| path.to_string_lossy().into_owned());
        config.audit_sqlite_path = audit_path.map(|path| path.to_string_lossy().into_owned());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config
            .rbac_exempt_paths
            .push(TRAFFIC_ENDPOINTS_ADMIN_ROUTE.to_owned());
        config
            .rbac_exempt_paths
            .push(TRAFFIC_ENDPOINT_DETAIL_ADMIN_ROUTE.to_owned());
        config
            .rbac_exempt_paths
            .push(TRAFFIC_ENDPOINT_REVIEW_ADMIN_ROUTE.to_owned());
        config
    }

    fn traffic_admin_router(
        discovery_path: Option<&PathBuf>,
        audit_path: Option<&PathBuf>,
    ) -> (Router, TempPolicyFile) {
        let policy = TempPolicyFile::new(&traffic_policy_document_string());
        let router = traffic_admin_router_with_policy(discovery_path, audit_path, &policy);

        (router, policy)
    }

    fn traffic_admin_router_with_policy(
        discovery_path: Option<&PathBuf>,
        audit_path: Option<&PathBuf>,
        policy: &TempPolicyFile,
    ) -> Router {
        traffic_admin_router_with_policy_and_audit(
            discovery_path,
            audit_path,
            policy,
            test_audit_log(),
        )
    }

    fn traffic_admin_router_with_policy_and_audit(
        discovery_path: Option<&PathBuf>,
        audit_path: Option<&PathBuf>,
        policy: &TempPolicyFile,
        audit_log: audit::AuditLog,
    ) -> Router {
        let recorder = PrometheusBuilder::new().build_recorder();
        app(
            traffic_admin_config(discovery_path, audit_path, policy),
            recorder.handle(),
            audit_log,
            test_audit_event_sender(),
        )
        .expect("app should build")
    }

    fn traffic_admin_request(uri: &str, principal: Option<auth::Principal>) -> Request<Body> {
        let mut request = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request should build");
        if let Some(principal) = principal {
            request.extensions_mut().insert(principal);
        }

        request
    }

    fn traffic_admin_json_request(
        method: Method,
        uri: &str,
        principal: Option<auth::Principal>,
        body: Option<String>,
    ) -> Request<Body> {
        let mut builder = Request::builder().method(method.clone()).uri(uri);
        if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
            builder = builder
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, "Bearer test-token");
        }

        let mut request = builder
            .body(Body::from(body.unwrap_or_default()))
            .expect("request should build");
        if let Some(principal) = principal {
            request.extensions_mut().insert(principal);
        }

        request
    }

    async fn traffic_json(router: &Router, uri: &str, principal: Option<auth::Principal>) -> Value {
        let response = router
            .clone()
            .oneshot(traffic_admin_request(uri, principal))
            .await
            .expect("traffic request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        json_body(response).await
    }

    async fn wait_for_traffic_json(
        router: &Router,
        uri: &str,
        condition: impl Fn(&Value) -> bool,
    ) -> Value {
        let started = Instant::now();

        loop {
            let body = traffic_json(router, uri, Some(test_principal(&["traffic-reader"]))).await;
            if condition(&body) {
                return body;
            }

            assert!(
                started.elapsed() < Duration::from_secs(2),
                "traffic response did not match condition within reload window: {body}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    fn traffic_policy_document_string() -> String {
        traffic_policy_document_with_rules(json!([]))
    }

    fn traffic_policy_document_with_rules(rules: Value) -> String {
        serde_json::to_string_pretty(&json!({
            "schema_version": "0.1.0",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {
                "traffic-reader": {
                    "permissions": [ADMIN_TRAFFIC_READ_PERMISSION]
                },
                "traffic-and-signals-reader": {
                    "permissions": [
                        ADMIN_TRAFFIC_READ_PERMISSION,
                        ADMIN_SIGNALS_READ_PERMISSION
                    ]
                },
                "traffic-writer": {
                    "permissions": [
                        ADMIN_TRAFFIC_READ_PERMISSION,
                        ADMIN_TRAFFIC_WRITE_PERMISSION
                    ]
                },
                "reader": {
                    "permissions": []
                }
            },
            "rules": rules
        }))
        .expect("traffic policy should serialize")
    }

    fn signals_admin_config(
        discovery_path: Option<&PathBuf>,
        policy: &TempPolicyFile,
    ) -> config::Config {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.discovery_sqlite_path =
            discovery_path.map(|path| path.to_string_lossy().into_owned());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config
            .rbac_exempt_paths
            .push("/v1/admin/signals".to_owned());
        config
    }

    fn signals_admin_router(discovery_path: Option<&PathBuf>) -> (Router, TempPolicyFile) {
        let policy = TempPolicyFile::new(&signals_policy_document_string());
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            signals_admin_config(discovery_path, &policy),
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build");

        (router, policy)
    }

    fn signals_admin_request(uri: &str, principal: Option<auth::Principal>) -> Request<Body> {
        let mut request = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request should build");
        if let Some(principal) = principal {
            request.extensions_mut().insert(principal);
        }

        request
    }

    fn signals_admin_json_request(
        method: Method,
        uri: &str,
        principal: Option<auth::Principal>,
    ) -> Request<Body> {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, "Bearer test-token")
            .body(Body::empty())
            .expect("request should build");
        if let Some(principal) = principal {
            request.extensions_mut().insert(principal);
        }

        request
    }

    async fn signals_json(router: &Router, uri: &str, principal: Option<auth::Principal>) -> Value {
        let response = router
            .clone()
            .oneshot(signals_admin_request(uri, principal))
            .await
            .expect("signals request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        json_body(response).await
    }

    fn signal_ids(body: &Value) -> Vec<String> {
        body["signals"]
            .as_array()
            .expect("signals should be an array")
            .iter()
            .map(|signal| {
                signal["id"]
                    .as_str()
                    .expect("signal id should be a string")
                    .to_owned()
            })
            .collect()
    }

    fn signals_policy_document_string() -> String {
        serde_json::to_string_pretty(&json!({
            "schema_version": "0.1.0",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {
                "admin": {
                    "permissions": [ADMIN_AUDIT_STREAM_PERMISSION]
                },
                "signals-reader": {
                    "permissions": ["admin:signals:read"]
                },
                "signals-writer": {
                    "permissions": [
                        "admin:signals:read",
                        "admin:signals:write"
                    ]
                },
                "reader": {
                    "permissions": []
                }
            },
            "rules": []
        }))
        .expect("signals policy should serialize")
    }

    fn suggestions_admin_config(
        discovery_path: Option<&PathBuf>,
        audit_path: Option<&PathBuf>,
        policy: &TempPolicyFile,
    ) -> config::Config {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.discovery_sqlite_path =
            discovery_path.map(|path| path.to_string_lossy().into_owned());
        config.audit_sqlite_path = audit_path.map(|path| path.to_string_lossy().into_owned());
        config.rule_suggestion_baseline_window_hours = 876_000;
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config
            .rbac_exempt_paths
            .push("/v1/admin/suggestions".to_owned());
        config.rbac_exempt_paths.push(POLICY_ADMIN_ROUTE.to_owned());
        config
    }

    fn suggestions_admin_router(
        discovery_path: Option<&PathBuf>,
        audit_path: Option<&PathBuf>,
    ) -> (Router, TempPolicyFile) {
        let policy = TempPolicyFile::new(&suggestions_policy_document_string());
        let router = suggestions_admin_router_with_policy(
            discovery_path,
            audit_path,
            &policy,
            test_audit_log(),
        );

        (router, policy)
    }

    fn suggestions_admin_router_with_policy(
        discovery_path: Option<&PathBuf>,
        audit_path: Option<&PathBuf>,
        policy: &TempPolicyFile,
        audit_log: audit::AuditLog,
    ) -> Router {
        let recorder = PrometheusBuilder::new().build_recorder();
        app(
            suggestions_admin_config(discovery_path, audit_path, policy),
            recorder.handle(),
            audit_log,
            test_audit_event_sender(),
        )
        .expect("app should build")
    }

    fn suggestions_admin_request(
        method: Method,
        uri: &str,
        principal: Option<auth::Principal>,
        body: Option<String>,
        if_match: Option<&str>,
    ) -> Request<Body> {
        let mut builder = Request::builder().method(method.clone()).uri(uri);
        if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
            builder = builder
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, "Bearer test-token");
        }
        if let Some(if_match) = if_match {
            builder = builder.header(header::IF_MATCH, if_match);
        }

        let mut request = builder
            .body(Body::from(body.unwrap_or_default()))
            .expect("request should build");
        if let Some(principal) = principal {
            request.extensions_mut().insert(principal);
        }

        request
    }

    async fn suggestions_json(
        router: &Router,
        uri: &str,
        principal: Option<auth::Principal>,
    ) -> Value {
        let response = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::GET,
                uri,
                principal,
                None,
                None,
            ))
            .await
            .expect("suggestions request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        json_body(response).await
    }

    fn suggestion_ids(body: &Value) -> Vec<String> {
        body["suggestions"]
            .as_array()
            .expect("suggestions should be an array")
            .iter()
            .map(|suggestion| {
                suggestion["id"]
                    .as_str()
                    .expect("suggestion id should be a string")
                    .to_owned()
            })
            .collect()
    }

    async fn suggestions_policy_etag(router: &Router) -> String {
        let response = router
            .clone()
            .oneshot(suggestions_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["policy-reader"])),
                None,
                None,
            ))
            .await
            .expect("policy GET should complete");
        assert_eq!(response.status(), StatusCode::OK);
        policy_etag_header(&response)
    }

    fn suggestions_policy_document_string() -> String {
        serde_json::to_string_pretty(&json!({
            "schema_version": "0.1.0",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {
                "suggestions-reader": {
                    "permissions": [ADMIN_SUGGESTIONS_READ_PERMISSION]
                },
                "suggestions-writer": {
                    "permissions": [
                        ADMIN_SUGGESTIONS_READ_PERMISSION,
                        ADMIN_SUGGESTIONS_WRITE_PERMISSION
                    ]
                },
                "policy-reader": {
                    "permissions": [ADMIN_POLICY_READ_PERMISSION]
                },
                "policy-writer": {
                    "permissions": [
                        ADMIN_POLICY_READ_PERMISSION,
                        ADMIN_POLICY_WRITE_PERMISSION
                    ]
                },
                "suggestions-policy-writer": {
                    "permissions": [
                        ADMIN_SUGGESTIONS_READ_PERMISSION,
                        ADMIN_SUGGESTIONS_WRITE_PERMISSION,
                        ADMIN_POLICY_READ_PERMISSION,
                        ADMIN_POLICY_WRITE_PERMISSION
                    ]
                },
                "reader": {
                    "permissions": []
                }
            },
            "rules": []
        }))
        .expect("suggestions policy should serialize")
    }

    fn audit_events_router() -> (Router, audit::AuditLog, TempPolicyFile) {
        let policy = TempPolicyFile::new(&audit_admin_policy_document_string());
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config
            .rbac_exempt_paths
            .push(AUDIT_EVENTS_STREAM_ROUTE.to_owned());
        let recorder = PrometheusBuilder::new().build_recorder();
        let (audit_log, audit_event_sender) = test_audit_log_with_broadcast();
        let router = app(
            config,
            recorder.handle(),
            audit_log.clone(),
            audit_event_sender,
        )
        .expect("app should build");

        (router, audit_log, policy)
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

    fn status_config_with_policy(
        mut config: config::Config,
        policy: &TempPolicyFile,
    ) -> config::Config {
        let status_route = GatewayRoutes::from_config(&config).admin.status_route;
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config.rbac_exempt_paths.push(status_route);
        config
    }

    fn schema_coverage_router(
        spec: Option<&TempSpecFile>,
        discovery_db: Option<&TempDb>,
        policy: &TempPolicyFile,
    ) -> Router {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config
            .rbac_exempt_paths
            .push(SCHEMA_COVERAGE_ADMIN_ROUTE.to_owned());
        config.openapi_spec_path = spec.map(|spec| spec.path.clone());
        config.discovery_sqlite_path =
            discovery_db.map(|db| db.path.to_string_lossy().into_owned());
        let recorder = PrometheusBuilder::new().build_recorder();

        app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build")
    }

    fn schema_inference_router(
        discovery_db: Option<&TempDb>,
        payload_capture_enabled: bool,
        policy: &TempPolicyFile,
    ) -> Router {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config
            .rbac_exempt_paths
            .push(SCHEMA_INFERRED_ADMIN_ROUTE.to_owned());
        config.discovery_sqlite_path =
            discovery_db.map(|db| db.path.to_string_lossy().into_owned());
        config.payload_capture_enabled = payload_capture_enabled;
        let recorder = PrometheusBuilder::new().build_recorder();

        app(
            config,
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
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

    fn policy_admin_config_with_sqlite(
        policy: Option<&TempPolicyFile>,
        sqlite_path: Option<&PathBuf>,
    ) -> config::Config {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.audit_sqlite_path = sqlite_path.map(|path| path.to_string_lossy().into_owned());
        if let Some(policy) = policy {
            config.policy_file = Some(policy.path.to_string_lossy().into_owned());
            config.rbac_exempt_paths.push(POLICY_ADMIN_ROUTE.to_owned());
        }

        config
    }

    fn policy_admin_config_with_history(
        policy: Option<&TempPolicyFile>,
        history_path: Option<&PathBuf>,
    ) -> config::Config {
        let mut config = policy_admin_config_with_sqlite(policy, None);
        config.policy_history_sqlite_path =
            history_path.map(|path| path.to_string_lossy().into_owned());
        config
            .rbac_exempt_paths
            .push(POLICY_HISTORY_ADMIN_ROUTE.to_owned());
        config
            .rbac_exempt_paths
            .push(POLICY_ROLLBACK_ADMIN_ROUTE_PREFIX.to_owned());

        config
    }

    fn policy_admin_router(policy: Option<&TempPolicyFile>, audit_log: audit::AuditLog) -> Router {
        policy_admin_router_with_sqlite(policy, audit_log, None)
    }

    fn policy_admin_router_with_sqlite(
        policy: Option<&TempPolicyFile>,
        audit_log: audit::AuditLog,
        sqlite_path: Option<&PathBuf>,
    ) -> Router {
        let recorder = PrometheusBuilder::new().build_recorder();
        app(
            policy_admin_config_with_sqlite(policy, sqlite_path),
            recorder.handle(),
            audit_log,
            test_audit_event_sender(),
        )
        .expect("app should build")
    }

    fn policy_admin_router_with_history(
        policy: Option<&TempPolicyFile>,
        history_db: &TempDb,
    ) -> Router {
        let recorder = PrometheusBuilder::new().build_recorder();
        app(
            policy_admin_config_with_history(policy, Some(&history_db.path)),
            recorder.handle(),
            test_audit_log(),
            test_audit_event_sender(),
        )
        .expect("app should build")
    }

    fn token_admin_router(
        token_db: &TempDb,
        policy: &TempPolicyFile,
        audit_log: audit::AuditLog,
    ) -> Router {
        let mut config = test_config(Vec::new());
        config.auth_enabled = false;
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
        config.rbac_exempt_paths.push(TOKENS_ADMIN_ROUTE.to_owned());
        let recorder = PrometheusBuilder::new().build_recorder();

        app(
            config,
            recorder.handle(),
            audit_log,
            test_audit_event_sender(),
        )
        .expect("app should build")
    }

    fn token_admin_request(
        method: Method,
        uri: &str,
        principal: Option<auth::Principal>,
        body: Option<String>,
    ) -> Request<Body> {
        let mut builder = Request::builder().method(method.clone()).uri(uri);
        if matches!(method, Method::POST) {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        if matches!(method, Method::POST | Method::DELETE) {
            builder = builder.header(header::AUTHORIZATION, "Bearer test-token");
        }

        let mut request = builder
            .body(Body::from(body.unwrap_or_default()))
            .expect("token admin request should build");
        if let Some(principal) = principal {
            request.extensions_mut().insert(principal);
        }

        request
    }

    fn bearer_json_request(method: Method, uri: &str, token: &str, body: String) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .expect("bearer JSON request should build")
    }

    fn bearer_get_request(uri: &str, token: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .expect("bearer GET request should build")
    }

    async fn create_token_via_endpoint(router: &Router, scopes: &[&str]) -> Value {
        let response = router
            .clone()
            .oneshot(token_admin_request(
                Method::POST,
                TOKENS_ADMIN_ROUTE,
                Some(test_principal(&["tokens-writer"])),
                Some(json!({ "scopes": scopes }).to_string()),
            ))
            .await
            .expect("token create request should complete");
        assert_eq!(response.status(), StatusCode::CREATED);
        json_body(response).await
    }

    fn policy_admin_request(
        method: Method,
        uri: &str,
        principal: Option<auth::Principal>,
        body: Option<String>,
        if_match: Option<&str>,
    ) -> Request<Body> {
        policy_admin_request_with_body(
            method,
            uri,
            principal,
            Body::from(body.unwrap_or_default()),
            if_match,
        )
    }

    fn synchronized_policy_put_request(
        body: String,
        if_match: &str,
        barrier: Arc<tokio::sync::Barrier>,
    ) -> Request<Body> {
        synchronized_policy_admin_request(Method::PUT, POLICY_ADMIN_ROUTE, body, if_match, barrier)
    }

    fn synchronized_policy_admin_request(
        method: Method,
        uri: &str,
        body: String,
        if_match: &str,
        barrier: Arc<tokio::sync::Barrier>,
    ) -> Request<Body> {
        let chunks = stream::once(async move {
            barrier.wait().await;
            Ok::<Bytes, Infallible>(Bytes::from(body))
        });

        policy_admin_request_with_body(
            method,
            uri,
            Some(test_principal(&["admin"])),
            Body::from_stream(chunks),
            Some(if_match),
        )
    }

    fn policy_admin_request_with_body(
        method: Method,
        uri: &str,
        principal: Option<auth::Principal>,
        body: Body,
        if_match: Option<&str>,
    ) -> Request<Body> {
        let mut builder = Request::builder().method(method.clone()).uri(uri);

        if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        if matches!(
            method,
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        ) {
            builder = builder.header(header::AUTHORIZATION, "Bearer test-token");
        }
        if let Some(if_match) = if_match {
            builder = builder.header(header::IF_MATCH, if_match);
        }

        let mut request = builder.body(body).expect("request should build");
        if let Some(principal) = principal {
            request.extensions_mut().insert(principal);
        }

        request
    }

    fn policy_etag_header(response: &Response) -> String {
        response
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .expect("policy response should include an ETag")
            .to_owned()
    }

    async fn current_policy(router: &Router) -> (String, Value) {
        let response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::GET,
                POLICY_ADMIN_ROUTE,
                Some(test_principal(&["admin"])),
                None,
                None,
            ))
            .await
            .expect("policy GET should complete");
        assert_eq!(response.status(), StatusCode::OK);
        let etag = policy_etag_header(&response);
        let body = json_body(response).await;

        (etag, body)
    }

    async fn policy_history_page(
        router: &Router,
        uri: &str,
        principal: Option<auth::Principal>,
    ) -> Value {
        let response = router
            .clone()
            .oneshot(policy_admin_request(
                Method::GET,
                uri,
                principal,
                None,
                None,
            ))
            .await
            .expect("policy history request should complete");
        assert_eq!(response.status(), StatusCode::OK);
        json_body(response).await
    }

    async fn policy_history_entries(router: &Router, limit: Option<usize>) -> Vec<Value> {
        let uri = limit
            .map(|limit| format!("{POLICY_HISTORY_ADMIN_ROUTE}?limit={limit}&include_policy=true"))
            .unwrap_or_else(|| format!("{POLICY_HISTORY_ADMIN_ROUTE}?include_policy=true"));
        policy_history_page(router, &uri, Some(test_principal(&["admin"]))).await["versions"]
            .as_array()
            .expect("versions should be an array")
            .clone()
    }

    async fn assert_history_versions(router: &Router, expected_actions: &[&str]) {
        let entries = policy_history_entries(router, None).await;
        assert_eq!(
            history_actions(&entries),
            expected_actions,
            "unexpected policy history actions"
        );
    }

    fn history_actions(entries: &[Value]) -> Vec<&str> {
        entries
            .iter()
            .map(|entry| {
                entry["diff_summary"]["action"]
                    .as_str()
                    .expect("history entry should include action")
            })
            .collect()
    }

    fn assert_rfc3339_timestamp(value: &str) {
        OffsetDateTime::parse(value, &Rfc3339)
            .unwrap_or_else(|err| panic!("timestamp should be RFC3339: {value}: {err}"));
    }

    fn policy_document_string(id: &str, test_permission: &str) -> String {
        serde_json::to_string_pretty(&policy_document(id, test_permission))
            .expect("test policy should serialize")
    }

    fn policy_document_with_rules_string(id: &str, rules: Value) -> String {
        serde_json::to_string_pretty(&policy_document_with_rules(id, rules))
            .expect("test policy should serialize")
    }

    fn policy_document_with_rules(id: &str, rules: Value) -> Value {
        let mut policy = policy_document(id, "test:old");
        policy["rules"] = rules;
        policy
    }

    fn direct_rule_json(id: Option<&str>, methods: &[&str], path: &str, action: &str) -> Value {
        let mut rule = json!({
            "methods": methods,
            "path": path,
            "action": action,
        });
        if let Some(id) = id {
            rule["id"] = json!(id);
        }

        rule
    }

    fn policy_document(id: &str, test_permission: &str) -> Value {
        json!({
            "schema_version": "0.1.0",
            "id": id,
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {
                "admin": {
                    "permissions": [
                        ADMIN_POLICY_READ_PERMISSION,
                        ADMIN_POLICY_WRITE_PERMISSION
                    ]
                },
                "policy-reader": {
                    "permissions": [ADMIN_POLICY_READ_PERMISSION]
                },
                "reader": {
                    "permissions": []
                },
                "old-reader": {
                    "permissions": ["test:old"]
                },
                "new-reader": {
                    "permissions": ["test:new"]
                }
            },
            "routes": [
                {
                    "methods": ["GET"],
                    "path_prefix": POLICY_ADMIN_ROUTE,
                    "permission": ADMIN_POLICY_READ_PERMISSION
                },
                {
                    "methods": ["PUT"],
                    "path_prefix": POLICY_ADMIN_ROUTE,
                    "permission": ADMIN_POLICY_WRITE_PERMISSION
                },
                {
                    "methods": ["GET"],
                    "path_prefix": POLICY_HISTORY_ADMIN_ROUTE,
                    "permission": ADMIN_POLICY_READ_PERMISSION
                },
                {
                    "methods": ["POST"],
                    "path_prefix": POLICY_ROLLBACK_ADMIN_ROUTE_PREFIX,
                    "permission": ADMIN_POLICY_WRITE_PERMISSION
                },
                {
                    "methods": ["POST"],
                    "path_prefix": POLICY_VALIDATE_ADMIN_ROUTE,
                    "permission": ADMIN_POLICY_READ_PERMISSION
                },
                {
                    "methods": ["GET"],
                    "path_prefix": "/__test",
                    "permission": test_permission
                }
            ]
        })
    }

    fn token_policy_document_string() -> String {
        json!({
            "schema_version": "0.1.0",
            "id": "token-admin-policy",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {
                "tokens-reader": {
                    "permissions": [ADMIN_TOKENS_READ_PERMISSION]
                },
                "tokens-writer": {
                    "permissions": [ADMIN_TOKENS_WRITE_PERMISSION]
                },
                "token-admin": {
                    "permissions": [
                        ADMIN_TOKENS_READ_PERMISSION,
                        ADMIN_TOKENS_WRITE_PERMISSION
                    ]
                },
                "probe-reader": {
                    "permissions": ["test:read"]
                }
            },
            "routes": []
        })
        .to_string()
    }

    fn token_audit_full_stack_policy_document_string() -> String {
        json!({
            "schema_version": "0.1.0",
            "id": "token-audit-full-stack-policy",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {
                "admin": {
                    "permissions": [
                        ADMIN_TOKENS_WRITE_PERMISSION,
                        ADMIN_AUDIT_READ_PERMISSION
                    ]
                }
            },
            "routes": [
                {
                    "methods": ["POST"],
                    "path_prefix": TOKENS_ADMIN_ROUTE,
                    "permission": ADMIN_TOKENS_WRITE_PERMISSION
                },
                {
                    "methods": ["GET"],
                    "path_prefix": AUDIT_ADMIN_ROUTE,
                    "permission": ADMIN_AUDIT_READ_PERMISSION
                }
            ]
        })
        .to_string()
    }

    fn service_token_policy_document() -> String {
        json!({
            "schema_version": "0.1.0",
            "id": "service-token-policy",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {
                "probe-reader": {
                    "permissions": ["test:read"]
                },
                "token-admin": {
                    "permissions": [
                        ADMIN_TOKENS_READ_PERMISSION,
                        ADMIN_TOKENS_WRITE_PERMISSION
                    ]
                }
            },
            "routes": [
                {
                    "methods": ["GET"],
                    "path_prefix": "/__test",
                    "permission": "test:read"
                },
                {
                    "methods": ["GET"],
                    "path_prefix": TOKENS_ADMIN_ROUTE,
                    "permission": ADMIN_TOKENS_READ_PERMISSION
                },
                {
                    "methods": ["POST", "DELETE"],
                    "path_prefix": TOKENS_ADMIN_ROUTE,
                    "permission": ADMIN_TOKENS_WRITE_PERMISSION
                }
            ]
        })
        .to_string()
    }

    struct ToolsAdminTestHarness {
        router: Router,
        admin_token: String,
        reader_token: String,
        blocked_token: String,
        tools: TempToolsFile,
        _policy: TempPolicyFile,
        _token_db: TempDb,
    }

    async fn tools_admin_harness(
        tools_document: String,
        audit_log: audit::AuditLog,
    ) -> ToolsAdminTestHarness {
        let token_db = TempDb::new("tools-admin-service-tokens");
        let token_store =
            auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
        let admin_token = create_service_token(&token_store, &["admin"]);
        let reader_token = create_service_token(&token_store, &["tools-reader"]);
        let blocked_token = create_service_token(&token_store, &["blocked"]);
        let policy = TempPolicyFile::new(&tools_policy_document());
        let tools = TempToolsFile::new(&tools_document);

        let mut config = test_config(Vec::new());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config.tools_file = Some(tools.path.to_string_lossy().into_owned());
        config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
        config.service_token_cache_ttl_ms = 20;
        config.upstream_url = Some("http://127.0.0.1:65535".to_owned());
        config.egress_allowed_hosts = vec!["127.0.0.1".to_owned()];
        config.egress_deny_private_ips = false;

        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            audit_log,
            test_audit_event_sender(),
        )
        .expect("tools admin test app should build");

        ToolsAdminTestHarness {
            router,
            admin_token,
            reader_token,
            blocked_token,
            tools,
            _policy: policy,
            _token_db: token_db,
        }
    }

    fn tools_openapi_preview_request(token: &str, spec: &str) -> Request<Body> {
        tools_openapi_preview_request_with_content_type(token, spec, "text/plain; charset=utf-8")
    }

    fn tools_openapi_preview_request_with_content_type(
        token: &str,
        spec: &str,
        content_type: &str,
    ) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(TOOLS_OPENAPI_PREVIEW_ADMIN_ROUTE)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(spec.to_owned()))
            .expect("OpenAPI tools preview request should build")
    }

    fn tools_openapi_register_request(
        token: &str,
        body: Value,
        if_match: Option<&str>,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(TOOLS_OPENAPI_REGISTER_ADMIN_ROUTE)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(if_match) = if_match {
            builder = builder.header(header::IF_MATCH, if_match);
        }

        builder
            .body(Body::from(body.to_string()))
            .expect("OpenAPI tools register request should build")
    }

    fn empty_tools_document() -> String {
        json!({
            "schema_version": "0.1.0",
            "tools": []
        })
        .to_string()
    }

    fn tools_policy_document() -> String {
        json!({
            "schema_version": "0.1.0",
            "id": "tools-admin-policy",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {
                "admin": {
                    "permissions": [
                        ADMIN_TOOLS_READ_PERMISSION,
                        ADMIN_TOOLS_WRITE_PERMISSION,
                        ADMIN_MCP_USE_PERMISSION
                    ]
                },
                "tools-reader": {
                    "permissions": [ADMIN_TOOLS_READ_PERMISSION]
                }
            },
            "routes": [
                {
                    "methods": ["POST"],
                    "path_prefix": TOOLS_OPENAPI_PREVIEW_ADMIN_ROUTE,
                    "permission": ADMIN_TOOLS_READ_PERMISSION
                },
                {
                    "methods": ["POST"],
                    "path_prefix": TOOLS_OPENAPI_REGISTER_ADMIN_ROUTE,
                    "permission": ADMIN_TOOLS_WRITE_PERMISSION
                },
                {
                    "methods": ["POST"],
                    "path_prefix": MCP_ROUTE,
                    "permission": ADMIN_MCP_USE_PERMISSION
                }
            ],
            "tools": {
                "createWidget": {
                    "allowed_roles": ["admin"],
                    "timeout_ms": 5000,
                    "max_concurrent": 2
                },
                "getWidget": {
                    "allowed_roles": ["admin"],
                    "timeout_ms": 5000,
                    "max_concurrent": 2
                }
            }
        })
        .to_string()
    }

    fn widget_openapi_spec() -> &'static str {
        r#"
openapi: 3.0.3
info:
  title: Widget API
  version: 1.0.0
components:
  securitySchemes:
    ApiKeyAuth:
      type: apiKey
      in: header
      name: X-API-Key
paths:
  /widgets:
    post:
      operationId: createWidget
      summary: Create a widget
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              properties:
                name:
                  type: string
  /widgets/{widgetId}:
    get:
      operationId: getWidget
      summary: Fetch a widget
      security:
        - ApiKeyAuth: []
      parameters:
        - in: path
          name: widgetId
          required: true
          schema:
            type: string
"#
    }

    struct McpTestHarness {
        router: Router,
        admin_token: String,
        reader_token: String,
        blocked_token: String,
        _policy: TempPolicyFile,
        _tools: TempToolsFile,
        _token_db: TempDb,
    }

    async fn mcp_test_harness(
        echo_allowed_roles: &[&str],
        audit_log: audit::AuditLog,
    ) -> McpTestHarness {
        let upstream_addr = spawn_echo_json_upstream().await;
        mcp_test_harness_with_upstream_url(
            echo_allowed_roles,
            audit_log,
            format!("http://{upstream_addr}"),
            mcp_tools_document(),
            vec!["127.0.0.1".to_owned()],
        )
        .await
    }

    async fn mcp_test_harness_with_public_url(
        echo_allowed_roles: &[&str],
        audit_log: audit::AuditLog,
        gateway_public_url: &str,
    ) -> McpTestHarness {
        let upstream_addr = spawn_echo_json_upstream().await;
        mcp_test_harness_from_parts(
            echo_allowed_roles,
            audit_log,
            format!("http://{upstream_addr}"),
            mcp_tools_document(),
            vec!["127.0.0.1".to_owned()],
            Some(gateway_public_url.to_owned()),
            &["admin", auth::protected_resource::MCP_SCOPE],
        )
        .await
    }

    async fn mcp_test_harness_with_upstream_url(
        echo_allowed_roles: &[&str],
        audit_log: audit::AuditLog,
        upstream_url: String,
        tools_document: String,
        egress_allowed_hosts: Vec<String>,
    ) -> McpTestHarness {
        mcp_test_harness_from_parts(
            echo_allowed_roles,
            audit_log,
            upstream_url,
            tools_document,
            egress_allowed_hosts,
            None,
            &["admin"],
        )
        .await
    }

    async fn mcp_test_harness_from_parts(
        echo_allowed_roles: &[&str],
        audit_log: audit::AuditLog,
        upstream_url: String,
        tools_document: String,
        egress_allowed_hosts: Vec<String>,
        gateway_public_url: Option<String>,
        admin_token_roles: &[&str],
    ) -> McpTestHarness {
        let token_db = TempDb::new("mcp-service-tokens");
        let token_store =
            auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
        let admin_token = create_service_token(&token_store, admin_token_roles);
        let reader_token = create_service_token(&token_store, &["reader"]);
        let blocked_token = create_service_token(&token_store, &["blocked"]);
        let policy = TempPolicyFile::new(&mcp_policy_document(echo_allowed_roles));
        let tools = TempToolsFile::new(&tools_document);

        let mut config = test_config(Vec::new());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config.tools_file = Some(tools.path.to_string_lossy().into_owned());
        config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
        config.service_token_cache_ttl_ms = 20;
        config.upstream_url = Some(upstream_url);
        config.egress_allowed_hosts = egress_allowed_hosts;
        config.egress_deny_private_ips = false;
        config.gateway_public_url = gateway_public_url;

        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            audit_log,
            test_audit_event_sender(),
        )
        .expect("MCP test app should build");

        McpTestHarness {
            router,
            admin_token,
            reader_token,
            blocked_token,
            _policy: policy,
            _tools: tools,
            _token_db: token_db,
        }
    }

    struct McpUpstreamTestHarness {
        router: Router,
        admin_token: String,
        reader_token: String,
        _blocked_token: String,
        _policy: TempPolicyFile,
        _token_db: TempDb,
    }

    struct McpInventoryHarnessConfig {
        upstream_url: Option<String>,
        tools_document: String,
        mcp_upstream_servers: Vec<config::McpUpstreamServerConfig>,
        egress_allowed_hosts: Vec<String>,
    }

    struct McpInventoryTestHarness {
        router: Router,
        admin_token: String,
        capture: audit::sink::tests::CaptureSink,
        _policy: TempPolicyFile,
        _tools: TempToolsFile,
        _token_db: TempDb,
        _discovery_db: TempDb,
    }

    async fn mcp_inventory_test_harness(
        harness_config: McpInventoryHarnessConfig,
    ) -> McpInventoryTestHarness {
        let token_db = TempDb::new("mcp-inventory-service-tokens");
        let discovery_db = TempDb::new("mcp-inventory-discovery");
        let token_store =
            auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
        let admin_token = create_service_token(&token_store, &["admin"]);
        let policy = TempPolicyFile::new(&mcp_inventory_policy_document());
        let tools = TempToolsFile::new(&harness_config.tools_document);

        let mut config = test_config(Vec::new());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config.tools_file = Some(tools.path.to_string_lossy().into_owned());
        config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
        config.service_token_cache_ttl_ms = 20;
        config.discovery_sqlite_path = Some(discovery_db.path.to_string_lossy().into_owned());
        config.upstream_url = harness_config.upstream_url;
        config.mcp_upstream_servers = harness_config.mcp_upstream_servers;
        config.egress_allowed_hosts = harness_config.egress_allowed_hosts;
        config.egress_deny_private_ips = false;

        let (sink, audit_event_sender) =
            audit::sink::build_sink_from_config(&config).expect("audit sink should build");
        let capture = audit::sink::tests::CaptureSink::new();
        let audit_log = audit::AuditLog::new(Arc::new(audit::sink::CompositeSink::new(vec![
            sink,
            Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>,
        ])) as Arc<dyn audit::AuditSink>);
        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(config, recorder.handle(), audit_log, audit_event_sender)
            .expect("MCP inventory test app should build");

        McpInventoryTestHarness {
            router,
            admin_token,
            capture,
            _policy: policy,
            _tools: tools,
            _token_db: token_db,
            _discovery_db: discovery_db,
        }
    }

    async fn mcp_upstream_test_harness(
        server_name: &str,
        upstream_url: String,
        allowed_roles: &[&str],
    ) -> McpUpstreamTestHarness {
        mcp_upstream_test_harness_with_audit(
            server_name,
            upstream_url,
            allowed_roles,
            test_audit_log(),
        )
        .await
    }

    async fn mcp_upstream_test_harness_with_response_limit(
        server_name: &str,
        upstream_url: String,
        allowed_roles: &[&str],
        max_response_bytes: usize,
    ) -> McpUpstreamTestHarness {
        mcp_upstream_test_harness_with_audit_and_response_limit(
            server_name,
            upstream_url,
            allowed_roles,
            test_audit_log(),
            Some(max_response_bytes),
        )
        .await
    }

    async fn mcp_upstream_test_harness_with_request_limit(
        server_name: &str,
        upstream_url: String,
        allowed_roles: &[&str],
        max_request_body_bytes: usize,
    ) -> McpUpstreamTestHarness {
        mcp_upstream_test_harness_with_audit_and_limits(
            server_name,
            upstream_url,
            allowed_roles,
            test_audit_log(),
            None,
            Some(max_request_body_bytes),
        )
        .await
    }

    async fn mcp_upstream_test_harness_with_audit(
        server_name: &str,
        upstream_url: String,
        allowed_roles: &[&str],
        audit_log: audit::AuditLog,
    ) -> McpUpstreamTestHarness {
        mcp_upstream_test_harness_with_audit_and_response_limit(
            server_name,
            upstream_url,
            allowed_roles,
            audit_log,
            None,
        )
        .await
    }

    async fn mcp_upstream_test_harness_with_audit_and_response_limit(
        server_name: &str,
        upstream_url: String,
        allowed_roles: &[&str],
        audit_log: audit::AuditLog,
        max_response_bytes: Option<usize>,
    ) -> McpUpstreamTestHarness {
        mcp_upstream_test_harness_with_audit_and_limits(
            server_name,
            upstream_url,
            allowed_roles,
            audit_log,
            max_response_bytes,
            None,
        )
        .await
    }

    async fn mcp_upstream_test_harness_with_audit_and_limits(
        server_name: &str,
        upstream_url: String,
        allowed_roles: &[&str],
        audit_log: audit::AuditLog,
        max_response_bytes: Option<usize>,
        max_request_body_bytes: Option<usize>,
    ) -> McpUpstreamTestHarness {
        let token_db = TempDb::new("mcp-upstream-service-tokens");
        let token_store =
            auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
        let admin_token = create_service_token(&token_store, &["admin"]);
        let reader_token = create_service_token(&token_store, &["reader"]);
        let blocked_token = create_service_token(&token_store, &["blocked"]);
        let tool_name = format!("{server_name}:remote_echo");
        let policy = TempPolicyFile::new(&mcp_upstream_policy_document(&tool_name, allowed_roles));

        let mut config = test_config(Vec::new());
        config.policy_file = Some(policy.path.to_string_lossy().into_owned());
        config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
        config.service_token_cache_ttl_ms = 20;
        config.mcp_upstream_servers = vec![config::McpUpstreamServerConfig {
            name: server_name.to_owned(),
            url: upstream_url,
            timeout_ms: Some(2_000),
            response_idle_timeout_ms: Some(2_000),
            connect_timeout_ms: Some(2_000),
        }];
        config.egress_allowed_hosts = vec!["127.0.0.1".to_owned()];
        config.egress_deny_private_ips = false;
        if let Some(max_response_bytes) = max_response_bytes {
            config.egress_max_response_bytes = max_response_bytes;
        }
        if let Some(max_request_body_bytes) = max_request_body_bytes {
            config.egress_max_request_body_bytes = max_request_body_bytes;
        }

        let recorder = PrometheusBuilder::new().build_recorder();
        let router = app(
            config,
            recorder.handle(),
            audit_log,
            test_audit_event_sender(),
        )
        .expect("MCP upstream test app should build");

        McpUpstreamTestHarness {
            router,
            admin_token,
            reader_token,
            _blocked_token: blocked_token,
            _policy: policy,
            _token_db: token_db,
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum RawMcpOversizeTarget {
        None,
        ToolsList,
        ToolCall,
        TooManyToolsListPages,
        TwoPageToolsList,
    }

    const RAW_MCP_EXCESSIVE_TOOLS_LIST_PAGES: usize = 40;

    struct RawMcpUpstream {
        url: String,
        oversized_body_started: Arc<AtomicBool>,
        tool_call_request_count: Arc<AtomicUsize>,
        tools_list_request_count: Arc<AtomicUsize>,
        shutdown: tokio_util::sync::CancellationToken,
        handle: tokio::task::JoinHandle<()>,
    }

    impl RawMcpUpstream {
        async fn shutdown(self) {
            self.shutdown.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(1), self.handle).await;
        }
    }

    async fn spawn_raw_mcp_upstream(
        oversize_target: RawMcpOversizeTarget,
        max_response_bytes: usize,
    ) -> RawMcpUpstream {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("raw MCP upstream should bind");
        let addr = listener
            .local_addr()
            .expect("raw MCP upstream address should be available");
        let shutdown = tokio_util::sync::CancellationToken::new();
        let shutdown_task = shutdown.clone();
        let oversized_body_started = Arc::new(AtomicBool::new(false));
        let oversized_body_started_task = Arc::clone(&oversized_body_started);
        let tool_call_request_count = Arc::new(AtomicUsize::new(0));
        let tool_call_request_count_task = Arc::clone(&tool_call_request_count);
        let tools_list_request_count = Arc::new(AtomicUsize::new(0));
        let tools_list_request_count_task = Arc::clone(&tools_list_request_count);

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_task.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((mut stream, _)) = accepted else {
                            break;
                        };
                        let shutdown_connection = shutdown_task.clone();
                        let oversized_body_started_connection =
                            Arc::clone(&oversized_body_started_task);
                        let tool_call_request_count_connection =
                            Arc::clone(&tool_call_request_count_task);
                        let tools_list_request_count_connection =
                            Arc::clone(&tools_list_request_count_task);
                        tokio::spawn(async move {
                            handle_raw_mcp_connection(
                                &mut stream,
                                oversize_target,
                                max_response_bytes,
                                oversized_body_started_connection,
                                tool_call_request_count_connection,
                                tools_list_request_count_connection,
                                shutdown_connection,
                            )
                            .await;
                        });
                    }
                }
            }
        });

        RawMcpUpstream {
            url: format!("http://{addr}/mcp"),
            oversized_body_started,
            tool_call_request_count,
            tools_list_request_count,
            shutdown,
            handle,
        }
    }

    async fn handle_raw_mcp_connection(
        stream: &mut tokio::net::TcpStream,
        oversize_target: RawMcpOversizeTarget,
        max_response_bytes: usize,
        oversized_body_started: Arc<AtomicBool>,
        tool_call_request_count: Arc<AtomicUsize>,
        tools_list_request_count: Arc<AtomicUsize>,
        shutdown: tokio_util::sync::CancellationToken,
    ) {
        let Some(request) = read_raw_mcp_http_request(stream).await else {
            return;
        };
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if method == "tools/call" {
            tool_call_request_count.fetch_add(1, Ordering::SeqCst);
        }
        if method == "tools/list" {
            tools_list_request_count.fetch_add(1, Ordering::SeqCst);
        }

        match method {
            "initialize" => {
                write_raw_mcp_json_response(stream, raw_mcp_initialize_response(&request)).await;
            }
            "notifications/initialized" => {
                write_raw_mcp_accepted_response(stream).await;
            }
            "tools/list" if oversize_target == RawMcpOversizeTarget::ToolsList => {
                write_raw_mcp_oversized_response(
                    stream,
                    raw_mcp_oversized_tools_list_response(&request, max_response_bytes),
                    true,
                    oversized_body_started,
                    shutdown,
                )
                .await;
            }
            "tools/list" if oversize_target == RawMcpOversizeTarget::TooManyToolsListPages => {
                write_raw_mcp_json_response(
                    stream,
                    raw_mcp_excessive_tools_list_page_response(&request),
                )
                .await;
            }
            "tools/list" if oversize_target == RawMcpOversizeTarget::TwoPageToolsList => {
                write_raw_mcp_json_response(stream, raw_mcp_two_page_tools_list_response(&request))
                    .await;
            }
            "tools/list" => {
                write_raw_mcp_json_response(stream, raw_mcp_tools_list_response(&request)).await;
            }
            "tools/call" if oversize_target == RawMcpOversizeTarget::ToolCall => {
                write_raw_mcp_oversized_response(
                    stream,
                    raw_mcp_oversized_call_response(&request, max_response_bytes),
                    false,
                    oversized_body_started,
                    shutdown,
                )
                .await;
            }
            "tools/call" => {
                write_raw_mcp_json_response(stream, raw_mcp_call_response(&request)).await;
            }
            _ => {
                write_raw_mcp_json_response(
                    stream,
                    json!({
                        "jsonrpc": "2.0",
                        "id": raw_mcp_request_id(&request),
                        "error": {
                            "code": -32601,
                            "message": "method not found"
                        }
                    }),
                )
                .await;
            }
        }
    }

    async fn read_raw_mcp_http_request(stream: &mut tokio::net::TcpStream) -> Option<Value> {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        let header_end = loop {
            let read = stream
                .read(&mut chunk)
                .await
                .expect("raw MCP upstream should read request");
            if read == 0 {
                return None;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(index) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break index;
            }
            assert!(
                buffer.len() <= 16 * 1024,
                "raw MCP request headers should stay bounded"
            );
        };
        let raw_headers = std::str::from_utf8(&buffer[..header_end])
            .expect("raw MCP request headers should be UTF-8");
        let content_length = raw_headers
            .split("\r\n")
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        let body_start = header_end + 4;
        while buffer.len() < body_start + content_length {
            let read = stream
                .read(&mut chunk)
                .await
                .expect("raw MCP upstream should read request body");
            if read == 0 {
                return None;
            }
            buffer.extend_from_slice(&chunk[..read]);
        }

        Some(
            serde_json::from_slice::<Value>(&buffer[body_start..body_start + content_length])
                .unwrap_or_else(|err| panic!("raw MCP request body should be JSON: {err}")),
        )
    }

    async fn write_raw_mcp_json_response(stream: &mut tokio::net::TcpStream, body: Value) {
        let body = body.to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("raw MCP upstream should write JSON response");
    }

    async fn write_raw_mcp_accepted_response(stream: &mut tokio::net::TcpStream) {
        stream
            .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .expect("raw MCP upstream should write accepted response");
    }

    async fn write_raw_mcp_oversized_response(
        stream: &mut tokio::net::TcpStream,
        body: Value,
        send_body: bool,
        oversized_body_started: Arc<AtomicBool>,
        shutdown: tokio_util::sync::CancellationToken,
    ) {
        let body = body.to_string();
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(headers.as_bytes())
            .await
            .expect("raw MCP upstream should write oversized response headers");

        if send_body {
            oversized_body_started.store(true, Ordering::SeqCst);
            stream
                .write_all(body.as_bytes())
                .await
                .expect("raw MCP upstream should write oversized response body");
            return;
        }

        tokio::select! {
            _ = shutdown.cancelled() => {}
            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
        }
    }

    fn raw_mcp_request_id(request: &Value) -> Value {
        request.get("id").cloned().unwrap_or(Value::Null)
    }

    fn raw_mcp_initialize_response(request: &Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": raw_mcp_request_id(request),
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "raw-greengateway-test-upstream",
                    "version": "0.0.0"
                }
            }
        })
    }

    fn raw_mcp_tools_list_response(request: &Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": raw_mcp_request_id(request),
            "result": {
                "tools": [raw_mcp_tool("Remote test tool")]
            }
        })
    }

    fn raw_mcp_excessive_tools_list_page_response(request: &Value) -> Value {
        let page = raw_mcp_request_page(request);
        let tool_name = if page == 0 {
            "remote_echo".to_owned()
        } else {
            format!("remote_echo_page_{page}")
        };
        let mut result = json!({
            "tools": [raw_mcp_named_tool(tool_name, "Remote paginated test tool")]
        });
        if page + 1 < RAW_MCP_EXCESSIVE_TOOLS_LIST_PAGES {
            result["nextCursor"] = json!((page + 1).to_string());
        }

        json!({
            "jsonrpc": "2.0",
            "id": raw_mcp_request_id(request),
            "result": result
        })
    }

    fn raw_mcp_two_page_tools_list_response(request: &Value) -> Value {
        let page = raw_mcp_request_page(request);
        let result = if page == 0 {
            json!({
                "tools": [],
                "nextCursor": "1"
            })
        } else {
            json!({
                "tools": [raw_mcp_tool("Remote paginated test tool")]
            })
        };

        json!({
            "jsonrpc": "2.0",
            "id": raw_mcp_request_id(request),
            "result": result
        })
    }

    fn raw_mcp_request_page(request: &Value) -> usize {
        request
            .get("params")
            .and_then(|params| params.get("cursor"))
            .and_then(Value::as_str)
            .and_then(|cursor| cursor.parse::<usize>().ok())
            .unwrap_or(0)
    }

    fn raw_mcp_oversized_tools_list_response(request: &Value, max_response_bytes: usize) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": raw_mcp_request_id(request),
            "result": {
                "tools": [raw_mcp_tool("x".repeat(max_response_bytes + 256))]
            }
        })
    }

    fn raw_mcp_tool(description: impl Into<String>) -> Value {
        raw_mcp_named_tool("remote_echo", description)
    }

    fn raw_mcp_named_tool(name: impl Into<String>, description: impl Into<String>) -> Value {
        json!({
            "name": name.into(),
            "description": description.into(),
            "inputSchema": remote_echo_input_schema()
        })
    }

    fn raw_mcp_call_response(request: &Value) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": raw_mcp_request_id(request),
            "result": {
                "content": [],
                "structuredContent": {
                    "remote_tool": "remote_echo",
                    "arguments": {}
                },
                "isError": false
            }
        })
    }

    fn raw_mcp_oversized_call_response(request: &Value, max_response_bytes: usize) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": raw_mcp_request_id(request),
            "result": {
                "content": [{
                    "type": "text",
                    "text": "x".repeat(max_response_bytes + 256)
                }],
                "isError": false
            }
        })
    }

    struct TestMcpUpstream {
        addr: std::net::SocketAddr,
        url: String,
        calls: Arc<Mutex<Vec<Value>>>,
        shutdown: tokio_util::sync::CancellationToken,
        handle: tokio::task::JoinHandle<()>,
    }

    impl TestMcpUpstream {
        async fn shutdown(self) {
            self.shutdown.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(1), self.handle).await;
        }
    }

    #[derive(Clone)]
    struct TestMcpUpstreamServer {
        tool_name: String,
        calls: Arc<Mutex<Vec<Value>>>,
    }

    impl RmcpServerHandler for TestMcpUpstreamServer {
        fn get_info(&self) -> RmcpServerInfo {
            RmcpServerInfo::new(RmcpServerCapabilities::builder().enable_tools().build())
                .with_server_info(
                    Implementation::new("greengateway-test-upstream", "0.0.0")
                        .with_title("GreenGateway Test Upstream"),
                )
        }

        async fn list_tools(
            &self,
            _request: Option<RmcpPaginatedRequestParams>,
            _context: RmcpRequestContext<RmcpRoleServer>,
        ) -> Result<RmcpListToolsResult, RmcpErrorData> {
            Ok(RmcpListToolsResult::with_all_items(vec![RmcpTool::new(
                self.tool_name.clone(),
                "Remote test tool",
                Arc::new(remote_echo_input_schema()),
            )]))
        }

        async fn call_tool(
            &self,
            request: RmcpCallToolRequestParams,
            _context: RmcpRequestContext<RmcpRoleServer>,
        ) -> Result<RmcpCallToolResult, RmcpErrorData> {
            let arguments = request.arguments.unwrap_or_default();
            let call = json!({
                "name": request.name.to_string(),
                "arguments": Value::Object(arguments.clone()),
            });
            self.calls
                .lock()
                .expect("upstream calls lock should not poison")
                .push(call);

            Ok(RmcpCallToolResult::structured(json!({
                "remote_tool": request.name.to_string(),
                "arguments": Value::Object(arguments),
            })))
        }
    }

    async fn spawn_test_mcp_upstream(tool_name: &str) -> TestMcpUpstream {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let handler = TestMcpUpstreamServer {
            tool_name: tool_name.to_owned(),
            calls: Arc::clone(&calls),
        };
        let config = RmcpStreamableHttpServerConfig::default()
            .with_stateful_mode(false)
            .with_json_response(true)
            .disable_allowed_hosts();
        let service = RmcpStreamableHttpService::new(
            move || Ok(handler.clone()),
            Arc::new(RmcpNeverSessionManager::default()),
            config,
        );
        let router = Router::new().nest_service("/mcp", service);
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test MCP upstream should bind");
        let addr = listener
            .local_addr()
            .expect("test MCP upstream address should be available");
        let shutdown = tokio_util::sync::CancellationToken::new();
        let shutdown_task = shutdown.clone();
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(shutdown_task.cancelled_owned())
                .await
                .expect("test MCP upstream should serve");
        });

        TestMcpUpstream {
            addr,
            url: format!("http://{addr}/mcp"),
            calls,
            shutdown,
            handle,
        }
    }

    fn remote_echo_input_schema() -> RmcpJsonObject {
        let Value::Object(schema) = json!({
            "type": "object",
            "required": ["message"],
            "properties": {
                "message": {
                    "type": "string"
                }
            }
        }) else {
            unreachable!("remote echo schema is always an object")
        };

        schema
    }

    fn create_service_token(store: &auth::SqliteTokenStore, roles: &[&str]) -> String {
        store
            .create(auth::tokens::CreateTokenRequest {
                scopes: roles.iter().map(|role| (*role).to_owned()).collect(),
                created_by: "mcp-test-bootstrap".to_owned(),
                expires_at: None,
            })
            .expect("service token should create")
            .plaintext_token
    }

    async fn spawn_echo_json_upstream() -> std::net::SocketAddr {
        async fn echo(body: Bytes) -> Response {
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response()
        }

        async fn get_widget(
            Path(widget_id): Path<String>,
            Query(params): Query<HashMap<String, String>>,
        ) -> Response {
            Json(json!({
                "widget_id": widget_id,
                "include_details": params
                    .get("include_details")
                    .is_some_and(|value| value == "true"),
            }))
            .into_response()
        }

        spawn_router(
            Router::new()
                .route("/v1/echo", post(echo))
                .route("/v1/widgets/{widget_id}", get(get_widget)),
        )
        .await
    }

    async fn spawn_fixed_echo_upstream(
        status: StatusCode,
        content_type: &'static str,
        body: String,
    ) -> std::net::SocketAddr {
        spawn_fixed_echo_upstream_with_headers(status, content_type, body, Vec::new()).await
    }

    async fn spawn_fixed_echo_upstream_with_headers(
        status: StatusCode,
        content_type: &'static str,
        body: String,
        headers: Vec<(&'static str, &'static str)>,
    ) -> std::net::SocketAddr {
        let body = Arc::new(body);
        let headers = Arc::new(headers);

        spawn_router(Router::new().route(
            "/v1/echo",
            post(move || {
                let body = Arc::clone(&body);
                let headers = Arc::clone(&headers);
                async move {
                    let mut builder = Response::builder()
                        .status(status)
                        .header(header::CONTENT_TYPE, content_type);
                    for (name, value) in headers.iter() {
                        builder = builder.header(*name, *value);
                    }

                    builder
                        .body(Body::from(body.as_ref().clone()))
                        .expect("fixed upstream response should build")
                }
            }),
        ))
        .await
    }

    async fn mcp_rpc(
        router: &Router,
        token: Option<&str>,
        id: u64,
        method: &str,
        params: Option<Value>,
        request_id: &str,
    ) -> (StatusCode, Value) {
        let response = router
            .clone()
            .oneshot(mcp_request(token, id, method, params, request_id))
            .await
            .expect("MCP request should complete");
        let status = response.status();
        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("MCP body should read");
        let body = serde_json::from_slice(&body_bytes).unwrap_or_else(|err| {
            panic!(
                "MCP body should be JSON, status={status}, body={:?}: {err}",
                String::from_utf8_lossy(&body_bytes)
            )
        });

        (status, body)
    }

    fn authenticated_json_request(
        method: Method,
        uri: &str,
        token: &str,
        body: Option<String>,
        if_match: Option<&str>,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, "csrf_token=mcp-test-csrf")
            .header("x-csrf-token", "mcp-test-csrf");

        if let Some(if_match) = if_match {
            builder = builder.header(header::IF_MATCH, if_match);
        }

        builder
            .body(Body::from(body.unwrap_or_default()))
            .expect("authenticated JSON request should build")
    }

    fn mcp_request(
        token: Option<&str>,
        id: u64,
        method: &str,
        params: Option<Value>,
        request_id: &str,
    ) -> Request<Body> {
        mcp_request_to(MCP_ROUTE, token, id, method, params, request_id)
    }

    fn mcp_request_to(
        uri: &str,
        token: Option<&str>,
        id: u64,
        method: &str,
        params: Option<Value>,
        request_id: &str,
    ) -> Request<Body> {
        let mut body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
        });

        if let Some(params) = params {
            body["params"] = params;
        }

        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::HOST, "localhost")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header(header::COOKIE, "csrf_token=mcp-test-csrf")
            .header("x-csrf-token", "mcp-test-csrf")
            .header("MCP-Protocol-Version", "2025-11-25")
            .header(REQUEST_ID_HEADER, request_id);

        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }

        builder
            .body(Body::from(body.to_string()))
            .expect("MCP request should build")
    }

    fn mcp_cookie_request(
        session_cookie: &str,
        id: u64,
        method: &str,
        params: Option<Value>,
        request_id: &str,
    ) -> Request<Body> {
        let mut request = mcp_request(None, id, method, params, request_id);
        request.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("{session_cookie}; csrf_token=mcp-test-csrf"))
                .expect("test cookie header should be valid"),
        );
        request
    }

    fn mcp_content_text(body: &Value) -> &str {
        body["result"]["content"][0]["text"]
            .as_str()
            .expect("MCP result should include text content")
    }

    async fn wait_for_mcp_tool_inventory_row(
        router: &Router,
        token: &str,
        tool_name: &str,
        condition: impl Fn(&Value) -> bool,
    ) -> Value {
        let started = Instant::now();

        loop {
            let rows = inventory_rows_for_tool(router, token, tool_name).await;
            if let Some(row) = rows.iter().find(|row| condition(row)) {
                return row.clone();
            }

            assert!(
                started.elapsed() < Duration::from_secs(2),
                "MCP tool inventory row did not match condition: {rows:?}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn inventory_rows_for_tool(router: &Router, token: &str, tool_name: &str) -> Vec<Value> {
        let endpoint_template = format!("/mcp/tools/{tool_name}");
        let uri = format!(
            "{TRAFFIC_ENDPOINTS_ADMIN_ROUTE}?method=MCP&endpoint_template_prefix={endpoint_template}"
        );
        let response = router
            .clone()
            .oneshot(bearer_get_request(&uri, token))
            .await;
        let response = response.expect("traffic inventory request should complete");
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;

        body["endpoints"]
            .as_array()
            .expect("traffic response should include endpoints")
            .iter()
            .filter(|row| row["endpoint_template"] == json!(endpoint_template))
            .cloned()
            .collect()
    }

    fn status_count(row: &Value, status: u16) -> Option<u64> {
        row["status_counts"]
            .as_array()?
            .iter()
            .find(|count| count["status"] == json!(status))
            .and_then(|count| count["count"].as_u64())
    }

    fn mcp_initialize_params() -> Value {
        json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {
                "name": "greengateway-test-client",
                "version": "0.0.0"
            }
        })
    }

    fn mcp_tools_document() -> String {
        json!({
            "schema_version": "0.1.0",
            "tools": [
                {
                    "name": "echo",
                    "description": "Echoes a message through a generic upstream endpoint.",
                    "input_json_schema": {
                        "type": "object",
                        "required": ["message"],
                        "properties": {
                            "message": {
                                "type": "string"
                            }
                        },
                        "additionalProperties": false
                    },
                    "upstream": {
                        "method": "POST",
                        "path_template": "/v1/echo",
                        "body": {
                            "mode": "whole_args_json"
                        }
                    }
                },
                {
                    "name": "get_widget",
                    "description": "Looks up an illustrative widget by identifier.",
                    "input_json_schema": {
                        "type": "object",
                        "required": ["widget_id"],
                        "properties": {
                            "widget_id": {
                                "type": "string"
                            },
                            "include_details": {
                                "type": "boolean",
                                "default": false
                            }
                        },
                        "additionalProperties": false
                    },
                    "upstream": {
                        "method": "GET",
                        "path_template": "/v1/widgets/{widget_id}",
                        "query_params": [
                            {
                                "arg_name": "include_details",
                                "query_name": "include_details",
                                "required": false
                            }
                        ]
                    }
                }
            ]
        })
        .to_string()
    }

    fn mcp_inventory_policy_document() -> String {
        json!({
            "schema_version": "0.1.0",
            "id": "mcp-inventory-test-policy",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {
                "admin": {
                    "permissions": [
                        ADMIN_MCP_USE_PERMISSION,
                        ADMIN_TRAFFIC_READ_PERMISSION,
                        ADMIN_SIGNALS_READ_PERMISSION
                    ]
                }
            },
            "routes": [
                {
                    "methods": ["POST"],
                    "path_prefix": MCP_ROUTE,
                    "permission": ADMIN_MCP_USE_PERMISSION
                },
                {
                    "methods": ["GET"],
                    "path_prefix": TRAFFIC_ENDPOINTS_ADMIN_ROUTE,
                    "permission": ADMIN_TRAFFIC_READ_PERMISSION
                }
            ],
            "tools": {
                "echo": {
                    "allowed_roles": ["admin"],
                    "timeout_ms": 5000,
                    "max_concurrent": 2
                },
                "get_widget": {
                    "allowed_roles": ["admin"],
                    "timeout_ms": 5000,
                    "max_concurrent": 2
                },
                "alpha:remote_echo": {
                    "allowed_roles": ["admin"],
                    "timeout_ms": 5000,
                    "max_concurrent": 2
                }
            }
        })
        .to_string()
    }

    fn mcp_policy_document(echo_allowed_roles: &[&str]) -> String {
        json!({
            "schema_version": "0.1.0",
            "id": "mcp-test-policy",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {
                "admin": {
                    "permissions": [
                        ADMIN_MCP_USE_PERMISSION,
                        ADMIN_POLICY_READ_PERMISSION,
                        ADMIN_POLICY_WRITE_PERMISSION
                    ]
                },
                "reader": {
                    "permissions": [ADMIN_MCP_USE_PERMISSION]
                },
                "blocked": {
                    "permissions": []
                }
            },
            "routes": [
                {
                    "methods": ["POST"],
                    "path_prefix": MCP_ROUTE,
                    "permission": ADMIN_MCP_USE_PERMISSION
                },
                {
                    "methods": ["PUT"],
                    "path_prefix": POLICY_ADMIN_ROUTE,
                    "permission": ADMIN_POLICY_WRITE_PERMISSION
                }
            ],
            "tools": {
                "echo": {
                    "allowed_roles": echo_allowed_roles,
                    "timeout_ms": 5000,
                    "max_concurrent": 2
                },
                "get_widget": {
                    "allowed_roles": ["admin"],
                    "timeout_ms": 5000,
                    "max_concurrent": 2
                }
            }
        })
        .to_string()
    }

    fn mcp_upstream_policy_document(tool_name: &str, allowed_roles: &[&str]) -> String {
        json!({
            "schema_version": "0.1.0",
            "id": "mcp-upstream-test-policy",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {
                "admin": {
                    "permissions": [ADMIN_MCP_USE_PERMISSION]
                },
                "reader": {
                    "permissions": [ADMIN_MCP_USE_PERMISSION]
                },
                "blocked": {
                    "permissions": []
                }
            },
            "routes": [
                {
                    "methods": ["POST"],
                    "path_prefix": MCP_ROUTE,
                    "permission": ADMIN_MCP_USE_PERMISSION
                }
            ],
            "tools": {
                tool_name: {
                    "allowed_roles": allowed_roles,
                    "timeout_ms": 5000,
                    "max_concurrent": 2
                }
            }
        })
        .to_string()
    }

    fn schema_policy_document() -> String {
        json!({
            "schema_version": "0.1.0",
            "id": "schema-policy",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {
                "schema-reader": {
                    "permissions": [ADMIN_SCHEMA_READ_PERMISSION]
                },
                "reader": {
                    "permissions": []
                }
            }
        })
        .to_string()
    }

    fn direct_rule_policy_document() -> String {
        json!({
            "schema_version": "0.1.0",
            "id": "direct-rule-policy",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {
                "admin": {
                    "permissions": [
                        ADMIN_POLICY_READ_PERMISSION,
                        ADMIN_POLICY_WRITE_PERMISSION
                    ]
                },
                "member": {
                    "permissions": []
                }
            },
            "routes": [],
            "rules": [
                {
                    "id": "allow-principal-probe",
                    "methods": ["GET"],
                    "path": "/__test/principal",
                    "principal": {
                        "roles": ["member"],
                        "auth_methods": ["bearer_token"]
                    },
                    "action": "allow"
                },
                {
                    "id": "deny-blocked",
                    "methods": ["GET"],
                    "path": "/__test/blocked",
                    "action": "deny"
                }
            ]
        })
        .to_string()
    }

    fn shadow_review_policy_document() -> String {
        json!({
            "schema_version": "0.1.0",
            "id": "shadow-review-policy",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": {
                "admin": {
                    "permissions": [
                        ADMIN_POLICY_READ_PERMISSION,
                        ADMIN_POLICY_WRITE_PERMISSION
                    ]
                },
                "policy-reader": {
                    "permissions": [ADMIN_POLICY_READ_PERMISSION]
                },
                "reader": {
                    "permissions": []
                }
            },
            "routes": [],
            "rules": [
                {
                    "id": "shadow-reports",
                    "methods": ["GET", "DELETE"],
                    "path": "/reports/**",
                    "principal": {
                        "roles": ["analyst"]
                    },
                    "action": "shadow"
                },
                {
                    "id": "allow-reports",
                    "methods": ["GET"],
                    "path": "/allow/**",
                    "action": "allow"
                },
                {
                    "id": "shadow-disabled",
                    "enabled": false,
                    "methods": ["GET"],
                    "path": "/disabled/**",
                    "action": "shadow"
                },
                {
                    "id": "shadow-exports",
                    "methods": ["POST"],
                    "path": "/exports/**",
                    "principal": {
                        "roles": ["manager"]
                    },
                    "action": "shadow"
                }
            ]
        })
        .to_string()
    }

    fn captured_policy_change(
        capture: &audit::sink::tests::CaptureSink,
        action: &str,
    ) -> audit::AuditEvent {
        assert_eventually(Duration::from_secs(1), || {
            capture.events().iter().any(|event| {
                event.event_type == audit::event::POLICY_CHANGED
                    && event.payload["diff_summary"]["action"] == json!(action)
            })
        });

        capture
            .events()
            .into_iter()
            .find(|event| {
                event.event_type == audit::event::POLICY_CHANGED
                    && event.payload["diff_summary"]["action"] == json!(action)
            })
            .expect("policy.changed event should be captured")
    }

    fn assert_policy_change_actor(event: &audit::AuditEvent) {
        let actor = event.actor.as_ref().expect("actor should be set");
        assert_eq!(actor.user_id, "user-123");
        assert_eq!(actor.roles, Some(vec!["admin".to_owned()]));
    }

    fn captured_token_change(
        capture: &audit::sink::tests::CaptureSink,
        action: &str,
    ) -> audit::AuditEvent {
        assert_eventually(Duration::from_secs(1), || {
            capture.events().iter().any(|event| {
                event.event_type == audit::event::SERVICE_TOKEN_CHANGED
                    && event.payload["action"] == json!(action)
            })
        });

        capture
            .events()
            .into_iter()
            .find(|event| {
                event.event_type == audit::event::SERVICE_TOKEN_CHANGED
                    && event.payload["action"] == json!(action)
            })
            .expect("service_token.changed event should be captured")
    }

    fn captured_tool_registry_change(
        capture: &audit::sink::tests::CaptureSink,
        action: &str,
    ) -> audit::AuditEvent {
        assert_eventually(Duration::from_secs(1), || {
            capture.events().iter().any(|event| {
                event.event_type == audit::event::TOOL_REGISTRY_CHANGED
                    && event.payload["action"] == json!(action)
            })
        });

        capture
            .events()
            .into_iter()
            .find(|event| {
                event.event_type == audit::event::TOOL_REGISTRY_CHANGED
                    && event.payload["action"] == json!(action)
            })
            .expect("tool_registry.changed event should be captured")
    }

    fn assert_token_change_actor(event: &audit::AuditEvent) {
        let actor = event.actor.as_ref().expect("actor should be set");
        assert_eq!(actor.user_id, "user-123");
        assert_eq!(actor.auth_mode, "bearer_token");
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
            .oneshot(audit_query_request(
                uri,
                Some(test_principal(&["audit-reader"])),
            ))
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

    async fn wait_for_bearer_audit_event(
        router: &Router,
        uri: &str,
        token: &str,
        predicate: impl Fn(&Value) -> bool,
    ) -> Value {
        let started = Instant::now();

        loop {
            let response = router
                .clone()
                .oneshot(bearer_get_request(uri, token))
                .await
                .expect("bearer audit query request should complete");
            let status = response.status();
            if status != StatusCode::OK {
                panic!(
                    "bearer audit query returned {status}: {}",
                    body_string(response).await
                );
            }
            let body = json_body(response).await;
            if let Some(event) = body["events"]
                .as_array()
                .expect("events should be an array")
                .iter()
                .find(|event| predicate(event))
            {
                return event.clone();
            }

            assert!(
                started.elapsed() < Duration::from_secs(2),
                "bearer audit query did not return matching event: {body}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn wait_for_rule_hits(router: Router, predicate: impl Fn(&Value) -> bool) -> Value {
        let started = Instant::now();

        loop {
            let response = router
                .clone()
                .oneshot(policy_admin_request(
                    Method::GET,
                    POLICY_RULE_HITS_ADMIN_ROUTE,
                    Some(test_principal(&["admin"])),
                    None,
                    None,
                ))
                .await
                .expect("rule hits request should complete");
            assert_eq!(response.status(), StatusCode::OK);
            let body = json_body(response).await;
            if predicate(&body) {
                return body;
            }

            assert!(
                started.elapsed() < Duration::from_secs(2),
                "rule hits did not reach expected counts"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    fn rule_hit(body: &Value, rule_id: &str) -> Option<u64> {
        body["rules"]
            .as_array()?
            .iter()
            .find(|rule| rule["rule_id"] == json!(rule_id))
            .and_then(|rule| rule["hits"].as_u64())
    }

    fn shadow_review_rule_ids(body: &Value) -> Vec<String> {
        body["rules"]
            .as_array()
            .expect("shadow review rules should be an array")
            .iter()
            .map(|rule| {
                rule["rule_id"]
                    .as_str()
                    .expect("shadow review rule id should be a string")
                    .to_owned()
            })
            .collect()
    }

    fn shadow_review_rule<'a>(body: &'a Value, rule_id: &str) -> Option<&'a Value> {
        body["rules"]
            .as_array()?
            .iter()
            .find(|rule| rule["rule_id"] == json!(rule_id))
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

    fn endpoint_templates(body: &Value) -> Vec<String> {
        body["endpoints"]
            .as_array()
            .expect("endpoints should be an array")
            .iter()
            .map(|endpoint| {
                endpoint["endpoint_template"]
                    .as_str()
                    .expect("endpoint_template should be a string")
                    .to_owned()
            })
            .collect()
    }

    fn endpoint_coverage(body: &Value) -> HashMap<String, bool> {
        body["endpoints"]
            .as_array()
            .expect("endpoints should be an array")
            .iter()
            .map(|endpoint| {
                (
                    endpoint["endpoint_template"]
                        .as_str()
                        .expect("endpoint_template should be a string")
                        .to_owned(),
                    endpoint["covered_by_rule"]
                        .as_bool()
                        .expect("covered_by_rule should be a boolean"),
                )
            })
            .collect()
    }

    fn endpoint_new_flags(body: &Value) -> HashMap<String, bool> {
        body["endpoints"]
            .as_array()
            .expect("endpoints should be an array")
            .iter()
            .map(|endpoint| {
                (
                    endpoint["endpoint_template"]
                        .as_str()
                        .expect("endpoint_template should be a string")
                        .to_owned(),
                    endpoint["is_new"]
                        .as_bool()
                        .expect("is_new should be a boolean"),
                )
            })
            .collect()
    }

    fn principal_ids(body: &Value) -> Vec<String> {
        body["principals"]["principals"]
            .as_array()
            .expect("principals should be an array")
            .iter()
            .map(|principal| {
                principal["user_id"]
                    .as_str()
                    .expect("user_id should be a string")
                    .to_owned()
            })
            .collect()
    }

    fn principal_subjects(body: &Value) -> Vec<String> {
        body["principals"]
            .as_array()
            .expect("principals should be an array")
            .iter()
            .map(|principal| {
                principal["subject"]
                    .as_str()
                    .expect("subject should be a string")
                    .to_owned()
            })
            .collect()
    }

    fn principal_detail_endpoint_paths(body: &Value) -> Vec<(String, String)> {
        body["endpoints_touched"]
            .as_array()
            .expect("endpoints_touched should be an array")
            .iter()
            .map(|endpoint| {
                (
                    endpoint["method"]
                        .as_str()
                        .expect("endpoint method should be a string")
                        .to_owned(),
                    endpoint["path"]
                        .as_str()
                        .expect("endpoint path should be a string")
                        .to_owned(),
                )
            })
            .collect()
    }

    fn principal_detail_rule_ids(body: &Value) -> Vec<String> {
        body["rules_hit"]
            .as_array()
            .expect("rules_hit should be an array")
            .iter()
            .map(|rule_id| {
                rule_id
                    .as_str()
                    .expect("rule id should be a string")
                    .to_owned()
            })
            .collect()
    }

    fn principal_detail_signal_ids(body: &Value) -> Vec<String> {
        body["anomaly_history"]
            .as_array()
            .expect("anomaly_history should be an array")
            .iter()
            .map(|signal| {
                signal["id"]
                    .as_str()
                    .expect("signal id should be a string")
                    .to_owned()
            })
            .collect()
    }

    fn query_encode(value: &str) -> String {
        value
            .bytes()
            .flat_map(|byte| match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    vec![char::from(byte)]
                }
                _ => format!("%{byte:02X}").chars().collect::<Vec<_>>(),
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

    async fn authenticated_principal_probe(
        router: &Router,
        token: &str,
    ) -> axum::response::Response {
        router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/__test/principal")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete")
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
            issuer: None,
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

    fn spawn_oidc_jwks_server() -> (String, std::thread::JoinHandle<()>) {
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
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
            .expect("OIDC discovery test server should bind");
        let issuer = format!(
            "http://127.0.0.1:{}",
            listener
                .local_addr()
                .expect("OIDC discovery test server address should be available")
                .port()
        );
        let discovery = json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/jwks.json")
        });
        spawn_oidc_server(listener, discovery, Some(jwks), 2)
    }

    fn spawn_oidc_jwks_server_with_document_issuer(
        document_issuer: impl FnOnce(&str) -> String,
    ) -> (String, String, std::thread::JoinHandle<()>) {
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
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
            .expect("OIDC discovery test server should bind");
        let issuer = format!(
            "http://127.0.0.1:{}",
            listener
                .local_addr()
                .expect("OIDC discovery test server address should be available")
                .port()
        );
        let document_issuer = document_issuer(&issuer);
        let discovery = json!({
            "issuer": document_issuer.clone(),
            "jwks_uri": format!("{issuer}/jwks.json")
        });
        let (issuer, server) = spawn_oidc_server(listener, discovery, Some(jwks), 2);

        (issuer, document_issuer, server)
    }

    fn spawn_oidc_discovery_server(
        discovery: Value,
        request_count: usize,
    ) -> (String, std::thread::JoinHandle<()>) {
        spawn_oidc_discovery_server_with(|_| discovery, request_count)
    }

    fn spawn_oidc_discovery_server_with(
        discovery: impl FnOnce(&str) -> Value,
        request_count: usize,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
            .expect("OIDC discovery test server should bind");
        let issuer = format!(
            "http://127.0.0.1:{}",
            listener
                .local_addr()
                .expect("OIDC discovery test server address should be available")
                .port()
        );
        let discovery = discovery(&issuer);
        spawn_oidc_server(listener, discovery, None, request_count)
    }

    fn spawn_blocking_jwks_server(
        host: Ipv4Addr,
        request_count: usize,
    ) -> (String, std::thread::JoinHandle<usize>) {
        let listener = std::net::TcpListener::bind((host, 0))
            .expect("JWKS split-host test server should bind");
        let jwks_url = format!(
            "http://{}:{}/jwks.json",
            host,
            listener
                .local_addr()
                .expect("JWKS split-host test server address should be available")
                .port()
        );
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
        let server = spawn_blocking_json_server(
            listener,
            vec![("/jwks.json".to_owned(), jwks.to_string())],
            request_count,
        );

        (jwks_url, server)
    }

    fn spawn_blocking_cookie_session_server(
        host: Ipv4Addr,
        request_count: usize,
    ) -> (String, std::thread::JoinHandle<usize>) {
        let listener = std::net::TcpListener::bind((host, 0))
            .expect("cookie-session introspection test server should bind");
        let introspection_url = format!(
            "http://{}:{}/introspect",
            host,
            listener
                .local_addr()
                .expect("cookie-session introspection test server address should be available")
                .port()
        );
        let body = json!({
            "account": {
                "id": "cookie-user",
                "email": "Cookie.User@Example.TEST",
                "tenant": { "id": "cookie-org" },
                "scope": "admin member"
            }
        });
        let server = spawn_blocking_json_server(
            listener,
            vec![("/introspect".to_owned(), body.to_string())],
            request_count,
        );

        (introspection_url, server)
    }

    fn spawn_blocking_oidc_discovery_server(
        jwks_url: String,
    ) -> (String, std::thread::JoinHandle<usize>) {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
            .expect("OIDC split-host discovery test server should bind");
        let issuer = format!(
            "http://127.0.0.1:{}",
            listener
                .local_addr()
                .expect("OIDC split-host discovery test server address should be available")
                .port()
        );
        let discovery = json!({
            "issuer": issuer,
            "jwks_uri": jwks_url
        });
        let server = spawn_blocking_json_server(
            listener,
            vec![(
                "/.well-known/openid-configuration".to_owned(),
                discovery.to_string(),
            )],
            1,
        );

        (issuer, server)
    }

    fn spawn_blocking_json_server(
        listener: std::net::TcpListener,
        routes: Vec<(String, String)>,
        request_count: usize,
    ) -> std::thread::JoinHandle<usize> {
        std::thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .expect("blocking JSON test server should set nonblocking mode");
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut handled = 0;
            while handled < request_count && Instant::now() < deadline {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                };
                stream
                    .set_nonblocking(false)
                    .expect("blocking JSON test stream should use blocking reads");
                let path = read_blocking_http_path(&mut stream);
                let matched = routes
                    .iter()
                    .find(|(route_path, _)| route_path == &path)
                    .map(|(_, body)| body.as_str());
                let (status, body) = match matched {
                    Some(body) => ("200 OK", body),
                    None => ("404 Not Found", "{}"),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("blocking JSON test response should write");
                handled += 1;
            }
            handled
        })
    }

    fn spawn_oidc_server(
        listener: std::net::TcpListener,
        discovery: Value,
        jwks: Option<Value>,
        request_count: usize,
    ) -> (String, std::thread::JoinHandle<()>) {
        let issuer = format!(
            "http://127.0.0.1:{}",
            listener
                .local_addr()
                .expect("OIDC discovery test server address should be available")
                .port()
        );
        let discovery = discovery.to_string();
        let jwks = jwks.map(|jwks| jwks.to_string());
        let server = std::thread::spawn(move || {
            listener
                .set_nonblocking(true)
                .expect("OIDC discovery test server should set nonblocking mode");
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut handled = 0;
            while handled < request_count && Instant::now() < deadline {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                };
                stream
                    .set_nonblocking(false)
                    .expect("OIDC discovery test stream should use blocking reads");
                let path = read_blocking_http_path(&mut stream);
                let (status, body) = match path.as_str() {
                    "/.well-known/openid-configuration" => ("200 OK", discovery.as_str()),
                    "/jwks.json" => ("200 OK", jwks.as_deref().unwrap_or("{}")),
                    _ => ("404 Not Found", "{}"),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .expect("OIDC discovery test response should write");
                handled += 1;
            }
        });

        (issuer, server)
    }

    fn read_blocking_http_path(stream: &mut std::net::TcpStream) -> String {
        let mut buffer = [0; 2048];
        let read = stream
            .read(&mut buffer)
            .expect("OIDC discovery test request should read");
        let request = String::from_utf8_lossy(&buffer[..read]);
        request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("/")
            .to_owned()
    }

    fn configure_test_jwt_provider(config: &mut config::Config, jwks_addr: std::net::SocketAddr) {
        let jwks_url = format!("http://127.0.0.1:{}/jwks.json", jwks_addr.port());
        config.jwt_jwks_url = Some(jwks_url.clone());
        config.auth_providers = vec![config::AuthProviderConfig {
            name: "legacy".to_owned(),
            provider_type: config::AuthProviderType::Jwt,
            jwks_url: Some(jwks_url),
            issuer: None,
            audience: None,
            jwks_timeout_ms: config.jwt_jwks_timeout_ms,
            require_jti: config.jwt_require_jti,
            roles_claim: config.roles_claim.clone(),
            roles_claim_delimiter: None,
            org_claim: None,
            introspection_url: None,
            introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
            cache_ttl_ms: config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
            user_id_claim: None,
            email_claim: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
        }];
    }

    fn oidc_jwt_provider(issuer: String) -> config::AuthProviderConfig {
        config::AuthProviderConfig {
            name: "oidc".to_owned(),
            provider_type: config::AuthProviderType::Jwt,
            jwks_url: None,
            issuer: Some(issuer),
            audience: None,
            jwks_timeout_ms: 2000,
            require_jti: false,
            roles_claim: "roles".to_owned(),
            roles_claim_delimiter: None,
            org_claim: None,
            introspection_url: None,
            introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
            cache_ttl_ms: config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
            user_id_claim: None,
            email_claim: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
        }
    }

    fn configure_test_cookie_session_provider(
        config: &mut config::Config,
        introspection_url: String,
    ) {
        config.auth_providers = vec![config::AuthProviderConfig {
            name: "app-session".to_owned(),
            provider_type: config::AuthProviderType::CookieSession,
            jwks_url: None,
            issuer: None,
            audience: None,
            jwks_timeout_ms: config.jwt_jwks_timeout_ms,
            require_jti: false,
            roles_claim: "account.scope".to_owned(),
            roles_claim_delimiter: Some(" ".to_owned()),
            org_claim: Some("account.tenant.id".to_owned()),
            introspection_url: Some(introspection_url),
            introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
            cache_ttl_ms: 20,
            user_id_claim: Some("account.id".to_owned()),
            email_claim: Some("account.email".to_owned()),
            client_id: None,
            client_secret: None,
            redirect_uri: None,
        }];
    }

    fn signed_admin_token() -> String {
        signed_token("user-123", &["admin"])
    }

    fn signed_token(user_id: &str, roles: &[&str]) -> String {
        signed_token_with_claims(json!({
            "sub": user_id,
            "email": format!("{user_id}@example.test"),
            "exp": OffsetDateTime::now_utc().unix_timestamp() + 3600,
            "jti": format!("{user_id}-session"),
            "roles": roles
        }))
    }

    fn signed_token_with_issuer(user_id: &str, roles: &[&str], issuer: &str) -> String {
        signed_token_with_claims(json!({
            "sub": user_id,
            "email": format!("{user_id}@example.test"),
            "exp": OffsetDateTime::now_utc().unix_timestamp() + 3600,
            "jti": format!("{user_id}-session"),
            "roles": roles,
            "iss": issuer
        }))
    }

    fn signed_admin_id_token(issuer: &str, audience: &str, nonce: &str) -> String {
        signed_token_with_claims(json!({
            "sub": "admin-operator",
            "email": "admin-operator@example.test",
            "exp": OffsetDateTime::now_utc().unix_timestamp() + 3600,
            "iss": issuer,
            "aud": audience,
            "nonce": nonce
        }))
    }

    fn corrupt_jwt_signature(token: &str) -> String {
        let mut parts = token.split('.').map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(parts.len(), 3);
        let replacement = if parts[2].ends_with('A') { 'B' } else { 'A' };
        parts[2].pop();
        parts[2].push(replacement);
        parts.join(".")
    }

    fn signed_token_with_claims(claims: Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(TEST_JWT_KID.to_owned());

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

    fn create_discovery_schema(path: &PathBuf) {
        drop(
            discovery::aggregator::EndpointAggregatorSink::new(
                discovery::aggregator::EndpointAggregatorSinkConfig {
                    path: path.clone(),
                    payload_capture_enabled: false,
                    signal_event_sender: None,
                    signal_detector_config: discovery::signals::SignalDetectorConfig::default(),
                },
            )
            .expect("discovery aggregator should create schema"),
        );
    }

    fn create_signal_schema(path: &PathBuf) {
        let connection = Connection::open(path).expect("test discovery database should open");
        connection
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS discovery_signals (
                    id TEXT PRIMARY KEY,
                    signal_type TEXT NOT NULL,
                    target_kind TEXT NOT NULL,
                    target_key TEXT NOT NULL,
                    target_identity_json TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    transitioned_at TEXT,
                    transitioned_by TEXT
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_discovery_signals_identity
                ON discovery_signals(signal_type, target_kind, target_key);

                CREATE INDEX IF NOT EXISTS idx_discovery_signals_state_created
                ON discovery_signals(state, created_at, id);
                "#,
            )
            .expect("signal schema should create");
    }

    fn create_rule_suggestion_schema(path: &PathBuf) {
        let connection = Connection::open(path).expect("test discovery database should open");
        discovery::suggestions::configure_connection(&connection)
            .expect("rule suggestion schema should create");
    }

    struct RuleSuggestionSeed<'a> {
        id: &'a str,
        suggestion_type: &'a str,
        method: &'a str,
        path_pattern: &'a str,
        role: Option<&'a str>,
        action: &'a str,
        rationale: &'a str,
        evidence: Value,
        state: &'a str,
        created_at: &'a str,
        transitioned_at: Option<&'a str>,
        transitioned_by: Option<&'a str>,
        source_signal_id: Option<&'a str>,
    }

    fn insert_rule_suggestion(path: &PathBuf, suggestion: RuleSuggestionSeed<'_>) {
        let connection = Connection::open(path).expect("test discovery database should open");
        let principal = match suggestion.role {
            Some(role) => json!({
                "roles": [role],
                "auth_methods": [],
                "principal_ids": []
            }),
            None => json!({
                "roles": [],
                "auth_methods": [],
                "principal_ids": []
            }),
        };
        let proposed_rule_json = json!({
            "methods": [suggestion.method],
            "path": suggestion.path_pattern,
            "principal": principal,
            "action": suggestion.action
        })
        .to_string();
        let principal_key = suggestion
            .role
            .map(|role| format!("role:{role}"))
            .unwrap_or_else(|| "principal:any".to_owned());
        let evidence_json = serde_json::to_string(&suggestion.evidence)
            .expect("suggestion evidence should serialize");

        connection
            .execute(
                r#"
                INSERT INTO discovery_rule_suggestions (
                    id,
                    suggestion_type,
                    method,
                    path_pattern,
                    principal_key,
                    proposed_rule_json,
                    rationale,
                    evidence_json,
                    state,
                    created_at,
                    updated_at,
                    transitioned_at,
                    transitioned_by,
                    source_signal_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, ?11, ?12, ?13)
                "#,
                params![
                    suggestion.id,
                    suggestion.suggestion_type,
                    suggestion.method,
                    suggestion.path_pattern,
                    principal_key,
                    proposed_rule_json,
                    suggestion.rationale,
                    evidence_json,
                    suggestion.state,
                    suggestion.created_at,
                    suggestion.transitioned_at,
                    suggestion.transitioned_by,
                    suggestion.source_signal_id,
                ],
            )
            .expect("rule suggestion should insert");
    }

    fn seed_suggestion_generation_observation(
        discovery_path: &PathBuf,
        audit_path: &PathBuf,
        event_id: &str,
        method: &str,
        endpoint_template: &str,
        role: &str,
        timestamp: &str,
    ) {
        create_discovery_schema(discovery_path);
        insert_discovery_endpoint(
            discovery_path,
            SeedEndpoint {
                method,
                endpoint_template,
                first_seen: timestamp,
                last_seen: timestamp,
                call_count: 1,
                latency_count: 1,
                latency_p50_ms: 10,
                latency_p95_ms: 10,
                latency_p99_ms: 10,
                distinct_principal_count: 1,
                status_counts: &[(200, 1)],
            },
        );
        create_audit_schema(audit_path);
        let connection = Connection::open(audit_path).expect("test audit database should open");
        let actor_json = json!({
            "user_id": format!("user-{event_id}"),
            "roles": [role],
            "auth_mode": "bearer_token"
        })
        .to_string();
        let payload_json = json!({
            "method": method,
            "path": concrete_path_for_template(endpoint_template),
            "status": 200,
            "policy_decision": "allowed"
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
                    payload_method,
                    payload_path,
                    payload_status,
                    payload_json
                ) VALUES (?1, 'http.request_observed', ?2, '0.1.0', ?3, '203.0.113.10', ?4, ?5, ?6, ?7, 200, ?8)
                "#,
                params![
                    event_id,
                    timestamp,
                    format!("request-{event_id}"),
                    format!("user-{event_id}"),
                    actor_json,
                    method,
                    concrete_path_for_template(endpoint_template),
                    payload_json,
                ],
            )
            .expect("audit observation should insert");
    }

    fn concrete_path_for_template(endpoint_template: &str) -> String {
        endpoint_template.replace("{id}", "123")
    }

    fn seed_list_discovery_endpoints(path: &PathBuf) {
        insert_discovery_endpoint(
            path,
            SeedEndpoint {
                method: "GET",
                endpoint_template: "/users/{id}",
                first_seen: "2024-06-01T00:00:00Z",
                last_seen: "2024-06-03T12:00:00Z",
                call_count: 25,
                latency_count: 25,
                latency_p50_ms: 12,
                latency_p95_ms: 40,
                latency_p99_ms: 60,
                distinct_principal_count: 2,
                status_counts: &[(200, 20), (404, 5)],
            },
        );
        insert_discovery_endpoint(
            path,
            SeedEndpoint {
                method: "POST",
                endpoint_template: "/users",
                first_seen: "2024-06-02T00:00:00Z",
                last_seen: "2024-06-02T12:00:00Z",
                call_count: 5,
                latency_count: 5,
                latency_p50_ms: 20,
                latency_p95_ms: 30,
                latency_p99_ms: 30,
                distinct_principal_count: 1,
                status_counts: &[(201, 5)],
            },
        );
        insert_discovery_endpoint(
            path,
            SeedEndpoint {
                method: "GET",
                endpoint_template: "/reports/{id}",
                first_seen: "2024-05-30T00:00:00Z",
                last_seen: "2024-05-31T12:00:00Z",
                call_count: 100,
                latency_count: 100,
                latency_p50_ms: 50,
                latency_p95_ms: 90,
                latency_p99_ms: 120,
                distinct_principal_count: 3,
                status_counts: &[(200, 80), (500, 20)],
            },
        );
        insert_discovery_endpoint(
            path,
            SeedEndpoint {
                method: "GET",
                endpoint_template: "/admin/status",
                first_seen: "2024-06-04T00:00:00Z",
                last_seen: "2024-06-04T12:00:00Z",
                call_count: 1,
                latency_count: 1,
                latency_p50_ms: 5,
                latency_p95_ms: 5,
                latency_p99_ms: 5,
                distinct_principal_count: 1,
                status_counts: &[(204, 1)],
            },
        );
    }

    struct SignalSeed<'a> {
        id: &'a str,
        signal_type: &'a str,
        method: &'a str,
        endpoint_template: &'a str,
        explanation: &'a str,
        evidence: Value,
        state: &'a str,
        created_at: &'a str,
        transitioned_at: Option<&'a str>,
        transitioned_by: Option<&'a str>,
    }

    fn insert_signal(path: &PathBuf, signal: SignalSeed<'_>) {
        let connection = Connection::open(path).expect("test discovery database should open");
        let target_identity_json = serde_json::to_string(&json!({
            "method": signal.method,
            "endpoint_template": signal.endpoint_template,
        }))
        .expect("target identity should serialize");
        let evidence_json =
            serde_json::to_string(&signal.evidence).expect("evidence should serialize");
        let target_key = format!("{} {}", signal.method, signal.endpoint_template);

        connection
            .execute(
                r#"
                INSERT INTO discovery_signals (
                    id,
                    signal_type,
                    target_kind,
                    target_key,
                    target_identity_json,
                    explanation,
                    evidence_json,
                    state,
                    created_at,
                    updated_at,
                    transitioned_at,
                    transitioned_by
                ) VALUES (?1, ?2, 'endpoint', ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9, ?10)
                "#,
                params![
                    signal.id,
                    signal.signal_type,
                    target_key,
                    target_identity_json,
                    signal.explanation,
                    evidence_json,
                    signal.state,
                    signal.created_at,
                    signal.transitioned_at,
                    signal.transitioned_by,
                ],
            )
            .expect("signal should insert");
    }

    struct SeedEndpoint<'a> {
        method: &'a str,
        endpoint_template: &'a str,
        first_seen: &'a str,
        last_seen: &'a str,
        call_count: i64,
        latency_count: i64,
        latency_p50_ms: i64,
        latency_p95_ms: i64,
        latency_p99_ms: i64,
        distinct_principal_count: i64,
        status_counts: &'a [(i64, i64)],
    }

    fn insert_discovery_endpoint(path: &PathBuf, endpoint: SeedEndpoint<'_>) {
        let connection = Connection::open(path).expect("test discovery database should open");
        let latency_samples_json = serde_json::to_string(&[
            endpoint.latency_p50_ms,
            endpoint.latency_p95_ms,
            endpoint.latency_p99_ms,
        ])
        .expect("latency samples should serialize");

        connection
            .execute(
                r#"
                INSERT INTO discovery_endpoint_aggregates (
                    method,
                    endpoint_template,
                    first_seen,
                    last_seen,
                    call_count,
                    latency_count,
                    latency_p50_ms,
                    latency_p95_ms,
                    latency_p99_ms,
                    latency_samples_json,
                    distinct_principal_count,
                    updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, '2024-06-05T00:00:00Z')
                "#,
                params![
                    endpoint.method,
                    endpoint.endpoint_template,
                    endpoint.first_seen,
                    endpoint.last_seen,
                    endpoint.call_count,
                    endpoint.latency_count,
                    endpoint.latency_p50_ms,
                    endpoint.latency_p95_ms,
                    endpoint.latency_p99_ms,
                    latency_samples_json,
                    endpoint.distinct_principal_count,
                ],
            )
            .expect("endpoint aggregate should insert");

        for (status, count) in endpoint.status_counts {
            connection
                .execute(
                    r#"
                    INSERT INTO discovery_endpoint_status_counts (
                        method, endpoint_template, status, count
                    ) VALUES (?1, ?2, ?3, ?4)
                    "#,
                    params![endpoint.method, endpoint.endpoint_template, status, count,],
                )
                .expect("endpoint status count should insert");
        }
    }

    fn set_schema_mismatch_count(
        path: &PathBuf,
        method: &str,
        endpoint_template: &str,
        count: i64,
    ) {
        let connection = Connection::open(path).expect("test discovery database should open");
        connection
            .execute(
                r#"
                UPDATE discovery_endpoint_aggregates
                SET schema_mismatch_count = ?3
                WHERE method = ?1 AND endpoint_template = ?2
                "#,
                params![method, endpoint_template, count],
            )
            .expect("schema mismatch count should update");
    }

    fn create_principal_schema(path: &PathBuf) {
        let connection = Connection::open(path).expect("test principal database should open");
        connection
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS principal_directory (
                    subject TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    auth_method TEXT NOT NULL,
                    email TEXT,
                    org_id TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    request_count INTEGER NOT NULL,
                    PRIMARY KEY (subject, issuer, auth_method)
                );
                "#,
            )
            .expect("principal directory schema should create");
    }

    fn seed_principal_directory_rows(path: &PathBuf) {
        for principal in [
            PrincipalDirectorySeed {
                subject: "alpha",
                issuer: "https://issuer-a.example.test/",
                auth_method: "bearer",
                email: Some("alpha@example.test"),
                org_id: Some("org-a"),
                first_seen: "2026-01-01T00:00:00Z",
                last_seen: "2026-01-04T00:00:00Z",
                request_count: 4,
            },
            PrincipalDirectorySeed {
                subject: "bravo",
                issuer: "https://issuer-a.example.test/",
                auth_method: "service_token",
                email: None,
                org_id: Some("org-a"),
                first_seen: "2026-01-01T00:00:00Z",
                last_seen: "2026-01-03T00:00:00Z",
                request_count: 3,
            },
            PrincipalDirectorySeed {
                subject: "charlie",
                issuer: "https://issuer-b.example.test/",
                auth_method: "cookie",
                email: Some("charlie@example.test"),
                org_id: Some("org-b"),
                first_seen: "2026-01-01T00:00:00Z",
                last_seen: "2026-01-02T00:00:00Z",
                request_count: 2,
            },
            PrincipalDirectorySeed {
                subject: "delta",
                issuer: "https://issuer-a.example.test/",
                auth_method: "bearer",
                email: None,
                org_id: None,
                first_seen: "2026-01-01T00:00:00Z",
                last_seen: "2026-01-01T00:00:00Z",
                request_count: 1,
            },
        ] {
            insert_principal_directory_row(path, principal);
        }
    }

    struct PrincipalDirectorySeed<'a> {
        subject: &'a str,
        issuer: &'a str,
        auth_method: &'a str,
        email: Option<&'a str>,
        org_id: Option<&'a str>,
        first_seen: &'a str,
        last_seen: &'a str,
        request_count: i64,
    }

    fn insert_principal_directory_row(path: &PathBuf, principal: PrincipalDirectorySeed<'_>) {
        let connection = Connection::open(path).expect("test principal database should open");
        connection
            .execute(
                r#"
                INSERT INTO principal_directory (
                    subject,
                    issuer,
                    auth_method,
                    email,
                    org_id,
                    first_seen,
                    last_seen,
                    request_count
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                "#,
                params![
                    principal.subject,
                    principal.issuer,
                    principal.auth_method,
                    principal.email,
                    principal.org_id,
                    principal.first_seen,
                    principal.last_seen,
                    principal.request_count,
                ],
            )
            .expect("principal directory row should insert");
    }

    fn insert_anonymous_observation_event(
        path: &PathBuf,
        event_id: &str,
        timestamp: &str,
        request_path: &str,
    ) {
        let connection = Connection::open(path).expect("test audit database should open");
        let payload_json = json!({
            "method": "GET",
            "path": request_path,
            "status": 401,
            "auth_outcome": "anonymous_or_failed"
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
                    payload_method,
                    payload_path,
                    payload_status,
                    payload_json
                ) VALUES (?1, 'http.request_observed', ?2, '0.1.0', ?3, '203.0.113.10', NULL, NULL, 'GET', ?4, 401, ?5)
                "#,
                params![
                    event_id,
                    timestamp,
                    format!("request-{event_id}"),
                    request_path,
                    payload_json,
                ],
            )
            .expect("anonymous observation should insert");
    }

    fn anonymous_observation_count(path: &PathBuf) -> i64 {
        let connection = Connection::open(path).expect("test audit database should open");
        connection
            .query_row(
                r#"
                SELECT COUNT(*)
                FROM audit_events
                WHERE event_type = 'http.request_observed'
                  AND actor_user_id IS NULL
                "#,
                [],
                |row| row.get(0),
            )
            .expect("anonymous observation count should query")
    }

    fn insert_principal_endpoint_signal(
        path: &PathBuf,
        id: &str,
        method: &str,
        endpoint_template: &str,
        principal: &str,
        created_at: &str,
    ) {
        let connection = Connection::open(path).expect("test discovery database should open");
        let target_identity_json = serde_json::to_string(&json!({
            "method": method,
            "endpoint_template": endpoint_template,
            "principal": principal,
        }))
        .expect("target identity should serialize");
        let evidence_json = serde_json::to_string(&json!({
            "observed_at": created_at,
            "principal": principal,
            "prior_distinct_principal_count": 1,
            "threshold": 1
        }))
        .expect("evidence should serialize");
        let target_key =
            discovery::signals::principal_endpoint_target_key(method, endpoint_template, principal);

        connection
            .execute(
                r#"
                INSERT INTO discovery_signals (
                    id,
                    signal_type,
                    target_kind,
                    target_key,
                    target_identity_json,
                    explanation,
                    evidence_json,
                    state,
                    created_at,
                    updated_at,
                    transitioned_at,
                    transitioned_by
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'open', ?8, ?8, NULL, NULL)
                "#,
                params![
                    id,
                    discovery::signals::PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_TYPE,
                    discovery::signals::PRINCIPAL_ENDPOINT_TARGET_KIND,
                    target_key,
                    target_identity_json,
                    format!("Principal new to endpoint: {principal}"),
                    evidence_json,
                    created_at,
                ],
            )
            .expect("principal endpoint signal should insert");
    }

    #[derive(Debug)]
    struct PrincipalDirectoryRow {
        email: Option<String>,
        request_count: i64,
    }

    fn principal_directory_row_count(path: &PathBuf) -> i64 {
        let connection = Connection::open(path).expect("test principal database should open");
        connection
            .query_row("SELECT COUNT(*) FROM principal_directory", [], |row| {
                row.get(0)
            })
            .expect("principal directory count should query")
    }

    fn principal_directory_row(
        path: &PathBuf,
        subject: &str,
        issuer: &str,
        auth_method: &str,
    ) -> PrincipalDirectoryRow {
        let connection = Connection::open(path).expect("test principal database should open");
        connection
            .query_row(
                r#"
                SELECT email, request_count
                FROM principal_directory
                WHERE subject = ?1 AND issuer = ?2 AND auth_method = ?3
                "#,
                params![subject, issuer, auth_method],
                |row| {
                    Ok(PrincipalDirectoryRow {
                        email: row.get(0)?,
                        request_count: row.get(1)?,
                    })
                },
            )
            .expect("principal directory row should query")
    }

    fn insert_discovery_principal(
        path: &PathBuf,
        method: &str,
        endpoint_template: &str,
        user_id: &str,
        first_seen: &str,
        last_seen: &str,
    ) {
        let connection = Connection::open(path).expect("test discovery database should open");
        connection
            .execute(
                r#"
                INSERT INTO discovery_endpoint_principals (
                    method, endpoint_template, user_id, first_seen, last_seen
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                params![method, endpoint_template, user_id, first_seen, last_seen],
            )
            .expect("endpoint principal should insert");
    }

    fn emit_observed_events_to_discovery_and_audit(
        discovery_path: &PathBuf,
        audit_path: &PathBuf,
        events: &[audit::AuditEvent],
    ) {
        let discovery_sink = discovery::aggregator::EndpointAggregatorSink::new(
            discovery::aggregator::EndpointAggregatorSinkConfig {
                path: discovery_path.clone(),
                payload_capture_enabled: false,
                signal_event_sender: None,
                signal_detector_config: discovery::signals::SignalDetectorConfig::default(),
            },
        )
        .expect("discovery aggregator should build");
        let audit_sink =
            audit::sqlite_sink::SqliteSink::new(audit::sqlite_sink::SqliteSinkConfig {
                path: audit_path.clone(),
                retention_days: None,
            })
            .expect("audit SQLite sink should build");

        for event in events {
            audit::AuditSink::emit(&discovery_sink, event);
            audit::AuditSink::emit(&audit_sink, event);
        }
        drop(discovery_sink);
        drop(audit_sink);
    }

    fn observed_request_event(
        method: &str,
        path: &str,
        status: u16,
        latency_ms: u64,
        user_id: Option<&str>,
        timestamp: &str,
    ) -> audit::AuditEvent {
        let actor = user_id.map(|user_id| audit::Actor {
            user_id: user_id.to_owned(),
            email: None,
            roles: Some(vec!["reader".to_owned()]),
            auth_mode: "bearer_token".to_owned(),
        });
        let mut event = audit::AuditEvent::new(
            "http.request_observed",
            "request-traffic-test",
            "203.0.113.10",
            actor,
            json!({
                "method": method,
                "path": path,
                "status": status,
                "latency_ms": latency_ms
            }),
        );
        event.timestamp = timestamp.to_owned();
        event
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

    fn seed_rule_preview_events(path: &PathBuf) {
        for event in [
            SeedObservationEvent {
                event_id: "outside-window",
                timestamp: "2024-06-01T11:59:59Z",
                actor_user_id: "reader-1",
                roles: &["reader"],
                method: "GET",
                request_path: "/api/items/0",
                status: 200,
                policy_decision: "allowed",
                matched_rule_id: Some("existing-rule"),
            },
            SeedObservationEvent {
                event_id: "match-old",
                timestamp: "2024-06-01T12:00:01Z",
                actor_user_id: "reader-1",
                roles: &["reader"],
                method: "GET",
                request_path: "/api/items/1",
                status: 200,
                policy_decision: "allowed",
                matched_rule_id: Some("existing-rule"),
            },
            SeedObservationEvent {
                event_id: "wrong-method",
                timestamp: "2024-06-01T12:00:02Z",
                actor_user_id: "reader-1",
                roles: &["reader"],
                method: "POST",
                request_path: "/api/items/2",
                status: 201,
                policy_decision: "allowed",
                matched_rule_id: None,
            },
            SeedObservationEvent {
                event_id: "wrong-role",
                timestamp: "2024-06-01T12:00:03Z",
                actor_user_id: "admin-1",
                roles: &["admin"],
                method: "GET",
                request_path: "/api/items/3",
                status: 200,
                policy_decision: "allowed",
                matched_rule_id: Some("existing-rule"),
            },
            SeedObservationEvent {
                event_id: "match-new",
                timestamp: "2024-06-01T12:00:04Z",
                actor_user_id: "reader-1",
                roles: &["reader"],
                method: "GET",
                request_path: "/api/items/4",
                status: 200,
                policy_decision: "allowed",
                matched_rule_id: Some("existing-rule"),
            },
            SeedObservationEvent {
                event_id: "wrong-path",
                timestamp: "2024-06-01T12:00:05Z",
                actor_user_id: "reader-1",
                roles: &["reader"],
                method: "GET",
                request_path: "/api/other",
                status: 404,
                policy_decision: "denied",
                matched_rule_id: Some("existing-rule"),
            },
        ] {
            insert_observation_event(path, event);
        }
    }

    struct SeedAuditEvent<'a> {
        event_id: &'a str,
        event_type: &'a str,
        timestamp: &'a str,
        actor_user_id: &'a str,
        path: &'a str,
        status: i64,
    }

    struct SeedObservationEvent<'a> {
        event_id: &'a str,
        timestamp: &'a str,
        actor_user_id: &'a str,
        roles: &'a [&'a str],
        method: &'a str,
        request_path: &'a str,
        status: i64,
        policy_decision: &'a str,
        matched_rule_id: Option<&'a str>,
    }

    struct SeedAuthzEvent<'a> {
        event_id: &'a str,
        event_type: &'a str,
        timestamp: &'a str,
        actor_user_id: Option<&'a str>,
        roles: &'a [&'a str],
        method: &'a str,
        request_path: &'a str,
        matched_rule_id: Option<&'a str>,
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

    fn insert_observation_event(path: &PathBuf, event: SeedObservationEvent<'_>) {
        let connection = Connection::open(path).expect("test database should open");
        let roles = event
            .roles
            .iter()
            .map(|role| json!(role))
            .collect::<Vec<_>>();
        let actor_json = json!({
            "user_id": event.actor_user_id,
            "roles": roles,
            "auth_mode": "bearer_token"
        })
        .to_string();
        let mut payload = json!({
            "method": event.method,
            "path": event.request_path,
            "status": event.status,
            "policy_decision": event.policy_decision,
            "policy_reason": "matched_rule"
        });
        if let Some(matched_rule_id) = event.matched_rule_id {
            payload["matched_rule_id"] = json!(matched_rule_id);
        }
        let payload_json = payload.to_string();

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
                    payload_method,
                    payload_path,
                    payload_status,
                    payload_matched_rule_id,
                    payload_json
                ) VALUES (?1, 'http.request_observed', ?2, '0.1.0', ?3, '203.0.113.10', ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                "#,
                params![
                    event.event_id,
                    event.timestamp,
                    format!("request-{}", event.event_id),
                    event.actor_user_id,
                    actor_json,
                    event.method,
                    event.request_path,
                    event.status,
                    event.matched_rule_id,
                    payload_json,
                ],
            )
            .expect("observation event should insert");
    }

    fn insert_authz_event(path: &PathBuf, event: SeedAuthzEvent<'_>) {
        let connection = Connection::open(path).expect("test database should open");
        let roles = event
            .roles
            .iter()
            .map(|role| json!(role))
            .collect::<Vec<_>>();
        let actor_json = event.actor_user_id.map(|user_id| {
            json!({
                "user_id": user_id,
                "roles": roles,
                "auth_mode": "bearer_token"
            })
            .to_string()
        });
        let mut payload = json!({
            "method": event.method,
            "path": event.request_path,
            "reason": "matched_rule"
        });
        if let Some(matched_rule_id) = event.matched_rule_id {
            payload["matched_rule_id"] = json!(matched_rule_id);
        }
        let payload_json = payload.to_string();

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
                    payload_method,
                    payload_path,
                    payload_status,
                    payload_matched_rule_id,
                    payload_json
                ) VALUES (?1, ?2, ?3, '0.1.0', ?4, '203.0.113.10', ?5, ?6, ?7, ?8, NULL, ?9, ?10)
                "#,
                params![
                    event.event_id,
                    event.event_type,
                    event.timestamp,
                    format!("request-{}", event.event_id),
                    event.actor_user_id,
                    actor_json,
                    event.method,
                    event.request_path,
                    event.matched_rule_id,
                    payload_json,
                ],
            )
            .expect("authz event should insert");
    }

    fn bulk_insert_preview_events(path: &PathBuf, event_count: usize) {
        let mut connection = Connection::open(path).expect("test database should open");
        connection
            .execute_batch(
                r#"
                PRAGMA synchronous=OFF;
                PRAGMA temp_store=MEMORY;
                "#,
            )
            .expect("bulk insert pragmas should apply");

        let chunk_size = 5_000;
        for chunk_start in (0..event_count).step_by(chunk_size) {
            let chunk_end = (chunk_start + chunk_size).min(event_count);
            let transaction = connection
                .transaction()
                .expect("bulk insert transaction should start");

            {
                let mut statement = transaction
                    .prepare_cached(
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
                            payload_method,
                            payload_path,
                            payload_status,
                            payload_matched_rule_id,
                            payload_json
                        ) VALUES (?1, 'http.request_observed', ?2, '0.1.0', ?3, '203.0.113.10', 'reader-1', ?4, ?5, ?6, 200, ?7, ?8)
                        "#,
                    )
                    .expect("bulk insert statement should prepare");

                for index in chunk_start..chunk_end {
                    let method = if index % 2 == 0 { "GET" } else { "POST" };
                    let request_path = if index % 10 == 0 {
                        format!("/load/{index}")
                    } else {
                        format!("/other/{index}")
                    };
                    let matched_rule_id = (index % 10 == 0).then_some("existing-load-rule");
                    let actor_json =
                        r#"{"user_id":"reader-1","roles":["reader"],"auth_mode":"bearer_token"}"#;
                    let payload_json = json!({
                        "method": method,
                        "path": &request_path,
                        "status": 200,
                        "policy_decision": "allowed",
                        "matched_rule_id": matched_rule_id
                    })
                    .to_string();

                    statement
                        .execute(params![
                            format!("preview-event-{index:05}"),
                            preview_timestamp(index),
                            format!("preview-request-{index:05}"),
                            actor_json,
                            method,
                            request_path,
                            matched_rule_id,
                            payload_json,
                        ])
                        .expect("bulk preview event should insert");
                }
            }

            transaction
                .commit()
                .expect("bulk insert transaction should commit");
        }
    }

    fn preview_timestamp(index: usize) -> String {
        let second = index % 60;
        let minute = (index / 60) % 60;
        let hour = (index / 3_600) % 24;

        format!("2026-01-01T{hour:02}:{minute:02}:{second:02}Z")
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

        fn write(&self, contents: &str) {
            fs::write(&self.path, contents)
                .unwrap_or_else(|err| panic!("failed to write {}: {err}", self.path.display()));
        }
    }

    impl Drop for TempPolicyFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
            let history_path = default_policy_history_sqlite_path(&self.path.to_string_lossy());
            for suffix in ["", "-wal", "-shm"] {
                let path = PathBuf::from(format!("{}{}", history_path.display(), suffix));
                let _ = fs::remove_file(path);
            }
        }
    }

    struct TempToolsFile {
        path: PathBuf,
    }

    impl TempToolsFile {
        fn new(contents: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-mcp-tools-test-{}.json",
                uuid::Uuid::new_v4()
            ));
            fs::write(&path, contents)
                .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));

            Self { path }
        }
    }

    impl Drop for TempToolsFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    struct TempSpecFile {
        path: PathBuf,
    }

    impl TempSpecFile {
        fn new(test_name: &str, contents: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-openapi-{test_name}-{}.yaml",
                uuid::Uuid::new_v4()
            ));
            fs::write(&path, contents)
                .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));

            Self { path }
        }
    }

    impl Drop for TempSpecFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    fn seed_discovery_endpoint(path: &PathBuf, method: &str, endpoint_template: &str) {
        let connection = Connection::open(path).expect("test database should open");
        connection
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS discovery_endpoint_aggregates (
                    method TEXT NOT NULL,
                    endpoint_template TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    call_count INTEGER NOT NULL,
                    latency_count INTEGER NOT NULL,
                    latency_p50_ms INTEGER NOT NULL,
                    latency_p95_ms INTEGER NOT NULL,
                    latency_p99_ms INTEGER NOT NULL,
                    latency_samples_json TEXT NOT NULL,
                    distinct_principal_count INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (method, endpoint_template)
                );
                "#,
            )
            .expect("discovery schema should create");
        connection
            .execute(
                r#"
                INSERT INTO discovery_endpoint_aggregates (
                    method,
                    endpoint_template,
                    first_seen,
                    last_seen,
                    call_count,
                    latency_count,
                    latency_p50_ms,
                    latency_p95_ms,
                    latency_p99_ms,
                    latency_samples_json,
                    distinct_principal_count,
                    updated_at
                ) VALUES (?1, ?2, '2024-06-01T12:00:00Z', '2024-06-01T12:00:00Z', 1, 1, 1, 1, 1, '[]', 0, '2024-06-01T12:00:00Z')
                "#,
                params![method, endpoint_template],
            )
            .expect("endpoint aggregate should insert");
    }

    fn seed_payload_shape_samples(
        path: &PathBuf,
        method: &str,
        endpoint_template: &str,
        shapes: &[Value],
    ) {
        let connection = Connection::open(path).expect("test database should open");
        connection
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS discovery_payload_shape_stats (
                    method TEXT NOT NULL,
                    endpoint_template TEXT NOT NULL,
                    shape_observation_count INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (method, endpoint_template)
                );

                CREATE TABLE IF NOT EXISTS discovery_payload_shape_samples (
                    method TEXT NOT NULL,
                    endpoint_template TEXT NOT NULL,
                    sample_slot INTEGER NOT NULL,
                    observed_at TEXT NOT NULL,
                    shape_hash TEXT NOT NULL,
                    shape_json TEXT NOT NULL,
                    PRIMARY KEY (method, endpoint_template, sample_slot)
                );
                "#,
            )
            .expect("payload shape schema should create");
        connection
            .execute(
                r#"
                INSERT INTO discovery_payload_shape_stats (
                    method,
                    endpoint_template,
                    shape_observation_count,
                    updated_at
                ) VALUES (?1, ?2, ?3, '2024-06-01T12:00:00Z')
                "#,
                params![
                    method,
                    endpoint_template,
                    i64::try_from(shapes.len()).expect("shape count should fit i64")
                ],
            )
            .expect("payload shape stats should insert");

        for (index, shape) in shapes.iter().enumerate() {
            connection
                .execute(
                    r#"
                    INSERT INTO discovery_payload_shape_samples (
                        method,
                        endpoint_template,
                        sample_slot,
                        observed_at,
                        shape_hash,
                        shape_json
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                    "#,
                    params![
                        method,
                        endpoint_template,
                        i64::try_from(index).expect("sample slot should fit i64"),
                        format!("2024-06-01T12:00:0{index}Z"),
                        format!("sha256:test-shape-{index}"),
                        shape.to_string(),
                    ],
                )
                .expect("payload shape sample should insert");
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
