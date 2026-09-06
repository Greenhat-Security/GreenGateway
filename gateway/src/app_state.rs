//! app state boundary extracted from the application composition root.
use super::*;

pub(super) const REQUEST_COUNTER: &str = "gateway_http_requests";
pub(super) const REQUEST_ID_HEADER: &str = "x-request-id";
#[cfg(test)]
pub(super) const X_FORWARDED_FOR_HEADER: HeaderName = HeaderName::from_static("x-forwarded-for");
#[cfg(test)]
pub(super) const X_REAL_IP_HEADER: HeaderName = HeaderName::from_static("x-real-ip");
pub(super) const ADMIN_UI_ROUTE: &str = "/admin";
pub(super) const ADMIN_UI_INDEX: &str = "index.html";
pub(super) const ADMIN_UI_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
pub(super) const DEFAULT_ADMIN_API_PREFIX: &str = "/v1/admin";
pub(super) const AUDIT_ADMIN_ROUTE: &str = "/v1/admin/audit";
pub(super) const AUDIT_EVENTS_STREAM_ROUTE: &str = "/v1/admin/events/stream";
pub(super) const ADMIN_AUTH_LOGIN_ROUTE: &str = "/v1/admin/auth/login";
pub(super) const ADMIN_AUTH_CALLBACK_ROUTE: &str = "/v1/admin/auth/callback";
pub(super) const ADMIN_CAPABILITIES_ROUTE: &str = "/v1/admin/capabilities";
pub(super) const STATUS_ADMIN_ROUTE: &str = "/v1/admin/status";
pub(super) const CLUSTER_ADMIN_ROUTE: &str = "/v1/admin/cluster";
pub(super) const CLUSTER_REPLICAS_ADMIN_ROUTE: &str = "/v1/admin/cluster/replicas";
pub(super) const POLICY_ADMIN_ROUTE: &str = "/v1/admin/policy";
pub(super) const POLICY_HISTORY_ADMIN_ROUTE: &str = "/v1/admin/policy/history";
pub(super) const POLICY_HISTORY_WARNING_HEADER: &str = "x-greengateway-policy-history-warning";
pub(super) const POLICY_HISTORY_APPEND_FAILED_WARNING: &str = "policy_history_append_failed";
#[cfg(test)]
pub(super) const POLICY_ROLLBACK_ADMIN_ROUTE_PREFIX: &str = "/v1/admin/policy/rollback";
pub(super) const POLICY_ROLLBACK_ADMIN_ROUTE: &str = "/v1/admin/policy/rollback/{version}";
pub(super) const POLICY_RULE_PREVIEW_ADMIN_ROUTE: &str = "/v1/admin/policy/rules/preview";
pub(super) const POLICY_RULE_HITS_ADMIN_ROUTE: &str = "/v1/admin/policy/rules/hits";
pub(super) const POLICY_RULE_SHADOW_REVIEW_ADMIN_ROUTE: &str =
    "/v1/admin/policy/rules/shadow-review";
pub(super) const POLICY_VALIDATE_ADMIN_ROUTE: &str = "/v1/admin/policy/validate";
pub(super) const POLICY_RULES_ADMIN_ROUTE: &str = "/v1/admin/policy/rules";
pub(super) const POLICY_RULE_ADMIN_ROUTE: &str = "/v1/admin/policy/rules/{id}";
pub(super) const POLICY_RULES_ORDER_ADMIN_ROUTE: &str = "/v1/admin/policy/rules/order";
pub(super) const TOKENS_ADMIN_ROUTE: &str = "/v1/admin/tokens";
pub(super) const TOKEN_ADMIN_ROUTE: &str = "/v1/admin/tokens/{id}";
pub(super) const TOKEN_ROTATE_ADMIN_ROUTE: &str = "/v1/admin/tokens/{id}/rotate";
pub(super) const CONNECTIONS_ADMIN_ROUTE: &str = "/v1/admin/connections";
pub(super) const CONNECTION_ADMIN_ROUTE: &str = "/v1/admin/connections/{id}";
pub(super) const CONNECTION_REFRESH_ADMIN_ROUTE: &str = "/v1/admin/connections/{id}/refresh";
pub(super) const CONNECTION_TEST_ADMIN_ROUTE: &str = "/v1/admin/connections/{id}/test";
pub(super) const CONNECTION_OPENAPI_PREVIEW_ADMIN_ROUTE: &str =
    "/v1/admin/connections/{id}/openapi/preview";
pub(super) const CONNECTION_OPENAPI_REGISTER_ADMIN_ROUTE: &str =
    "/v1/admin/connections/{id}/openapi/register";
pub(super) const CONNECTION_OPENAPI_OVERLAY_ADMIN_ROUTE: &str =
    "/v1/admin/connections/{id}/overlay";
pub(super) const CONNECTION_SECRETS_ADMIN_ROUTE: &str = "/v1/admin/connection-secrets";
pub(super) const CONNECTION_SECRET_ADMIN_ROUTE: &str = "/v1/admin/connection-secrets/{id}";
pub(super) const CONNECTION_COLLECTION_ETAG_HEADER: &str = "x-greengateway-connections-etag";
pub(super) const CONNECTION_SECRET_COLLECTION_ETAG_HEADER: &str =
    "x-greengateway-connection-secrets-etag";
/// The expected suggestion revision on the accept route (issue #241,
/// PR 12). Acceptance is a two-resource precondition: `If-Match` there
/// carries the policy ETag the rule is committed against, so the
/// suggestion's own `revision` -- the same `If-Match`-style value the
/// dismiss route reads -- travels in this header instead.
pub(super) const SUGGESTION_REVISION_HEADER: &str = "x-greengateway-suggestion-revision";
pub(super) const MANAGED_OPENAPI_JSON_ENVELOPE_OVERHEAD_BYTES: usize = 64 * 1024;
pub(super) const TOOLS_ADMIN_ROUTE: &str = "/v1/admin/tools";
pub(super) const TOOL_ADMIN_ROUTE: &str = "/v1/admin/tools/{id}";
pub(super) const TOOL_EXECUTE_ADMIN_ROUTE: &str = "/v1/admin/tools/{id}/execute";
pub(super) const TOOLS_OPENAPI_PREVIEW_ADMIN_ROUTE: &str = "/v1/admin/tools/openapi/preview";
pub(super) const TOOLS_OPENAPI_REGISTER_ADMIN_ROUTE: &str = "/v1/admin/tools/openapi/register";
pub(super) const OPENAPI_TOOLS_UNSUPPORTED_AUTH_REQUIREMENTS_ERROR: &str = "cannot register selected OpenAPI tools: upstream API-key header injection is not yet supported; see issue #36's known limitation";
pub(super) const SCHEMA_COVERAGE_ADMIN_ROUTE: &str = "/v1/admin/schema/coverage";
pub(super) const SIGNALS_ADMIN_ROUTE: &str = "/v1/admin/signals";
pub(super) const SIGNAL_ACKNOWLEDGE_ADMIN_ROUTE: &str = "/v1/admin/signals/{id}/acknowledge";
pub(super) const SIGNAL_DISMISS_ADMIN_ROUTE: &str = "/v1/admin/signals/{id}/dismiss";
pub(super) const SUGGESTIONS_ADMIN_ROUTE: &str = "/v1/admin/suggestions";
pub(super) const SUGGESTIONS_GENERATE_ADMIN_ROUTE: &str = "/v1/admin/suggestions/generate";
pub(super) const SUGGESTION_ACCEPT_ADMIN_ROUTE: &str = "/v1/admin/suggestions/{id}/accept";
pub(super) const SUGGESTION_DISMISS_ADMIN_ROUTE: &str = "/v1/admin/suggestions/{id}/dismiss";
pub(super) const SCHEMA_INFERRED_ADMIN_ROUTE: &str = "/v1/admin/schema/inferred";
pub(super) const TRAFFIC_ENDPOINTS_ADMIN_ROUTE: &str = "/v1/admin/traffic/endpoints";
pub(super) const TRAFFIC_ENDPOINT_DETAIL_ADMIN_ROUTE: &str = "/v1/admin/traffic/endpoint";
pub(super) const TRAFFIC_ENDPOINT_REVIEW_ADMIN_ROUTE: &str = "/v1/admin/traffic/endpoints/review";
pub(super) const PRINCIPALS_ADMIN_ROUTE: &str = "/v1/admin/principals";
pub(super) const PRINCIPAL_ADMIN_ROUTE: &str = "/v1/admin/principal";
pub(super) const ADMIN_AUDIT_READ_PERMISSION: &str = "admin:audit:read";
pub(super) const ADMIN_AUDIT_STREAM_PERMISSION: &str = "admin:audit:stream";
pub(super) const ADMIN_STATUS_READ_PERMISSION: &str = "admin:status:read";
pub(super) const ADMIN_CLUSTER_READ_PERMISSION: &str = connections::permissions::ADMIN_CLUSTER_READ;
pub(super) const ADMIN_POLICY_READ_PERMISSION: &str = "admin:policy:read";
pub(super) const ADMIN_POLICY_WRITE_PERMISSION: &str = "admin:policy:write";
pub(super) const ADMIN_TOKENS_READ_PERMISSION: &str = "admin:tokens:read";
pub(super) const ADMIN_TOKENS_WRITE_PERMISSION: &str = "admin:tokens:write";
pub(super) const ADMIN_CONNECTIONS_READ_PERMISSION: &str =
    connections::permissions::ADMIN_CONNECTIONS_READ;
pub(super) const ADMIN_CONNECTIONS_WRITE_PERMISSION: &str =
    connections::permissions::ADMIN_CONNECTIONS_WRITE;
pub(super) const ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION: &str =
    connections::permissions::ADMIN_CONNECTIONS_SECRETS_WRITE;
pub(super) const ADMIN_CONNECTIONS_TEST_PERMISSION: &str =
    connections::permissions::ADMIN_CONNECTIONS_TEST;
pub(super) const ADMIN_CONNECTIONS_REFRESH_PERMISSION: &str =
    connections::permissions::ADMIN_CONNECTIONS_REFRESH;
pub(super) const ADMIN_TOOLS_READ_PERMISSION: &str = connections::permissions::ADMIN_TOOLS_READ;
pub(super) const ADMIN_TOOLS_WRITE_PERMISSION: &str = connections::permissions::ADMIN_TOOLS_WRITE;
pub(super) const ADMIN_TOOLS_EXECUTE_PERMISSION: &str =
    connections::permissions::ADMIN_TOOLS_EXECUTE;
pub(super) const ADMIN_SCHEMA_READ_PERMISSION: &str = "admin:schema:read";
pub(super) const ADMIN_SIGNALS_READ_PERMISSION: &str = "admin:signals:read";
pub(super) const ADMIN_SIGNALS_WRITE_PERMISSION: &str = "admin:signals:write";
pub(super) const ADMIN_SUGGESTIONS_READ_PERMISSION: &str = "admin:suggestions:read";
pub(super) const ADMIN_SUGGESTIONS_WRITE_PERMISSION: &str = "admin:suggestions:write";
pub(super) const ADMIN_TRAFFIC_READ_PERMISSION: &str = "admin:traffic:read";
pub(super) const ADMIN_TRAFFIC_WRITE_PERMISSION: &str = "admin:traffic:write";
pub(super) const ADMIN_PRINCIPALS_READ_PERMISSION: &str = "admin:principals:read";
#[cfg(test)]
pub(super) const ADMIN_MCP_USE_PERMISSION: &str = "admin:mcp:use";
#[cfg(test)]
pub(super) const MCP_ROUTE: &str = auth::protected_resource::MCP_RESOURCE_PATH;
pub(super) const PROXY_FALLBACK_ROUTE: &str = "proxy_fallback";
pub(super) const GRPC_FALLBACK_ROUTE: &str = "grpc_fallback";
pub(super) const GATEWAY_OWNED_EXACT_PATHS: &[&str] = path_match::GATEWAY_EXACT_ROUTE_PATHS;
pub(super) const DEFAULT_AUDIT_QUERY_LIMIT: usize = 50;
pub(super) const MAX_AUDIT_QUERY_LIMIT: usize = 500;
pub(super) const DEFAULT_TRAFFIC_RECENT_EVENTS_LIMIT: usize = 20;
pub(super) const DEFAULT_PRINCIPAL_DETAIL_AUDIT_EVENT_LIMIT: usize = 500;
pub(super) const DEFAULT_PRINCIPAL_ANOMALY_HISTORY_LIMIT: usize = 20;
pub(super) const DEFAULT_RULE_PREVIEW_SAMPLE_LIMIT: usize = 20;
pub(super) const MAX_RULE_PREVIEW_SAMPLE_LIMIT: usize = 100;

#[derive(rust_embed::RustEmbed)]
#[folder = "../admin-ui/dist/"]
pub(super) struct AdminUiAssets;

#[derive(Clone)]
pub(super) struct AppState {
    pub(super) metrics_handle: PrometheusHandle,
    pub(super) proxy: Option<ProxyState>,
    pub(super) routes: GatewayRoutes,
    pub(super) client_ip_policy: client_ip::ClientIpPolicy,
    pub(super) admin_login_configured: bool,
    pub(super) csrf_cookie_name: String,
    pub(super) csrf_header_name: String,
    pub(super) max_body_size: usize,
    pub(super) mcp: mcp::McpState,
    pub(super) protected_resource_metadata:
        Option<auth::protected_resource::ProtectedResourceMetadataConfig>,
    pub(super) lifecycle: GatewayLifecycle,
    /// Cluster mode's fingerprint-agreement gate for `/readyz` (issue
    /// #241, PR 13); None in standalone mode, which is always agreed.
    pub(super) cluster_readiness: Option<Arc<ha::ClusterReadiness>>,
    /// Cluster mode's authority-backed readiness reasons for `/readyz`
    /// (issue #241, PR 14): storage, schema, this replica's membership
    /// lease, and its security watermark. None in standalone mode,
    /// which has no shared authority and so none of these states.
    pub(super) readiness_probe: Option<Arc<ha_status::ReadinessProbe>>,
    /// The audit writer, so a scrape can sample its queue (issue #241,
    /// PR 14). The queue has no periodic owner -- the writer is a
    /// blocking consumer -- so publishing from the writer would sample
    /// only the instants it is awake, which are exactly the instants a
    /// backlog is draining rather than accumulating.
    pub(super) audit_log: audit::AuditLog,
    /// Cluster mode's database pool, sampled at scrape for the same
    /// reason: `Pool::status()` describes the pool right now and keeps no
    /// history, so it has to be read when somebody asks.
    #[cfg(feature = "postgres")]
    pub(super) database_pool: Option<deadpool_postgres::Pool>,
    pub(super) _connections: connections::control_plane::ConnectionControlPlane,
}

#[derive(Clone)]
pub(super) struct ProxyDispatchState {
    pub(super) classifier: Option<ProxyClassifier>,
    pub(super) routes: GatewayRoutes,
}

#[derive(Clone, Debug)]
pub(super) struct GatewayRoutes {
    pub(super) admin: AdminRoutes,
    pub(super) exact_owned_paths: Vec<String>,
    pub(super) prefix_owned_paths: Vec<String>,
    pub(super) mcp_route_paths: Vec<String>,
}

#[derive(Clone, Debug)]
pub(super) struct AdminRoutes {
    pub(super) ui_prefix: String,
    pub(super) ui_slash_route: String,
    pub(super) ui_asset_route: String,
    pub(super) api_prefix: String,
    pub(super) audit_route: String,
    pub(super) events_stream_route: String,
    pub(super) auth_login_route: String,
    pub(super) auth_callback_route: String,
    pub(super) status_route: String,
    pub(super) cluster_route: String,
    pub(super) cluster_replicas_route: String,
    pub(super) policy_route: String,
    pub(super) policy_history_route: String,
    pub(super) policy_rollback_route: String,
    pub(super) policy_rule_preview_route: String,
    pub(super) policy_rule_hits_route: String,
    pub(super) policy_rule_shadow_review_route: String,
    pub(super) policy_validate_route: String,
    pub(super) policy_rules_route: String,
    pub(super) policy_rule_route: String,
    pub(super) policy_rules_order_route: String,
    pub(super) tokens_route: String,
    pub(super) token_route: String,
    pub(super) token_rotate_route: String,
    pub(super) connections_route: String,
    pub(super) connection_route: String,
    pub(super) connection_refresh_route: String,
    pub(super) connection_test_route: String,
    pub(super) connection_openapi_preview_route: String,
    pub(super) connection_openapi_register_route: String,
    pub(super) connection_openapi_overlay_route: String,
    pub(super) connection_secrets_route: String,
    pub(super) connection_secret_route: String,
    pub(super) tools_route: String,
    pub(super) tool_route: String,
    pub(super) tool_execute_route: String,
    pub(super) tools_openapi_preview_route: String,
    pub(super) tools_openapi_register_route: String,
    pub(super) schema_coverage_route: String,
    pub(super) signals_route: String,
    pub(super) signal_acknowledge_route: String,
    pub(super) signal_dismiss_route: String,
    pub(super) suggestions_route: String,
    pub(super) suggestions_generate_route: String,
    pub(super) suggestion_accept_route: String,
    pub(super) suggestion_dismiss_route: String,
    pub(super) schema_inferred_route: String,
    pub(super) traffic_endpoints_route: String,
    pub(super) traffic_endpoint_detail_route: String,
    pub(super) traffic_endpoint_review_route: String,
    pub(super) principals_route: String,
    pub(super) principal_detail_route: String,
}

impl GatewayRoutes {
    pub(super) fn from_config(config: &config::Config) -> Self {
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

    pub(super) fn is_gateway_owned_path(&self, path: &str) -> bool {
        auth::protected_resource::is_well_known_path(path)
            || self.exact_owned_paths.iter().any(|owned| path == owned)
            || self
                .prefix_owned_paths
                .iter()
                .any(|owned| path_match::path_prefix_matches(path, owned))
    }

    /// Returns exempt-list entries that do not fall under a gateway-owned
    /// path. These entries bypass auth/RBAC before reaching proxy fallback.
    pub(super) fn unowned_exempt_paths<'a>(&self, exempt_paths: &'a [String]) -> Vec<&'a str> {
        exempt_paths
            .iter()
            .filter(|path| !self.is_gateway_owned_path(path))
            .map(String::as_str)
            .collect()
    }
}

impl AdminRoutes {
    pub(super) fn from_prefix(admin_prefix: &str) -> Self {
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
            cluster_route: format!("{api_prefix}/cluster"),
            cluster_replicas_route: format!("{api_prefix}/cluster/replicas"),
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
            connections_route: format!("{api_prefix}/connections"),
            connection_route: format!("{api_prefix}/connections/{{id}}"),
            connection_refresh_route: format!("{api_prefix}/connections/{{id}}/refresh"),
            connection_test_route: format!("{api_prefix}/connections/{{id}}/test"),
            connection_openapi_preview_route: format!(
                "{api_prefix}/connections/{{id}}/openapi/preview"
            ),
            connection_openapi_register_route: format!(
                "{api_prefix}/connections/{{id}}/openapi/register"
            ),
            connection_openapi_overlay_route: format!("{api_prefix}/connections/{{id}}/overlay"),
            connection_secrets_route: format!("{api_prefix}/connection-secrets"),
            connection_secret_route: format!("{api_prefix}/connection-secrets/{{id}}"),
            tools_route: format!("{api_prefix}/tools"),
            tool_route: format!("{api_prefix}/tools/{{id}}"),
            tool_execute_route: format!("{api_prefix}/tools/{{id}}/execute"),
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
pub(super) struct AuditAdminState {
    pub(super) query_store: Option<Arc<dyn storage::AuditEventStore>>,
    pub(super) event_sender: audit::AuditEventSender,
    pub(super) rbac_state: Option<middleware::rbac::RbacState>,
    /// The durable PostgreSQL audit store, present only in cluster mode.
    /// Its stream cursor is what the SSE endpoint serves: committed events
    /// from every replica, replayable from a client's `Last-Event-ID`,
    /// with the broadcast channel demoted to a wake-up for latency.
    #[cfg(feature = "postgres")]
    pub(super) pg_audit: Option<Arc<storage::postgres_audit::PostgresAuditEventStore>>,
}

#[derive(Clone)]
pub(super) struct StatusAdminState {
    pub(super) config: config::Config,
    pub(super) rbac: RbacStatus,
    pub(super) rbac_state: Option<middleware::rbac::RbacState>,
    pub(super) egress_allowed_hosts_count: usize,
    pub(super) process_started_at: Instant,
    pub(super) proxy: Option<ProxyState>,
    pub(super) lifecycle: GatewayLifecycle,
}

/// The cluster status API's state (issue #241, PR 14).
///
/// Read-only by construction: it holds the readiness chain's own inputs,
/// one seam that reads the shared authority, and process-local counters.
/// There is nothing here a request could write through.
#[derive(Clone)]
pub(super) struct ClusterAdminState {
    pub(super) rbac_state: Option<middleware::rbac::RbacState>,
    /// The authority-backed readout. `None` in standalone mode, which has
    /// no authority: the endpoints then report this process alone.
    pub(super) source: Option<Arc<dyn cluster_status::ClusterStatusSource>>,
    /// The same four inputs `/readyz` consults, in the same order, so
    /// `state` and `reason` can never disagree with the probe.
    pub(super) lifecycle: GatewayLifecycle,
    pub(super) cluster_readiness: Option<Arc<ha::ClusterReadiness>>,
    pub(super) readiness_probe: Option<Arc<ha_status::ReadinessProbe>>,
    pub(super) proxy: Option<ProxyState>,
    /// The cluster security runtime, absent in standalone mode.
    pub(super) security: Option<Arc<dyn cluster_status::SecurityStatus>>,
    pub(super) audit: audit::AuditLog,
    /// This replica's identity: the roster row's in cluster mode, and a
    /// per-process one in standalone mode, where there is no roster.
    pub(super) identity: ha::InstanceIdentity,
    pub(super) fingerprint: String,
    pub(super) cluster_mode: bool,
    /// This process's hostname, resolved once at startup and only when
    /// `CLUSTER_STATUS_EXPOSE_HOSTNAMES=true`. `None` otherwise, which is
    /// the default: see `cluster_status`'s module docs.
    pub(super) hostname: Option<String>,
    pub(super) process_started_at: Instant,
}

#[derive(Clone)]
pub(super) struct PolicyAdminState {
    pub(super) policy_file: Option<PathBuf>,
    pub(super) rbac_state: Option<middleware::rbac::RbacState>,
    pub(super) history_store: Option<Arc<dyn storage::PolicyHistory>>,
    /// Cluster mode's authoritative control plane. Present exactly when
    /// `policy_file` is absent-but-cluster: mutations commit through its
    /// CAS transaction instead of the file, and history is its documents.
    #[cfg(feature = "postgres")]
    pub(super) control_plane: Option<Arc<dyn storage::PolicyControlPlane>>,
    pub(super) event_store: Option<Arc<dyn storage::AuditEventStore>>,
    pub(super) query_store: Option<Arc<storage::SqliteAuditEventStore>>,
    pub(super) audit: audit::AuditLog,
    pub(super) client_ip_policy: client_ip::ClientIpPolicy,
    pub(super) max_body_size: usize,
}

#[derive(Clone)]
pub(super) struct TokenAdminState {
    pub(super) store: Option<Arc<dyn storage::ServiceTokenStore>>,
    pub(super) validator: Option<Arc<auth::ServiceTokenValidator>>,
    pub(super) rbac_state: Option<middleware::rbac::RbacState>,
    pub(super) audit: audit::AuditLog,
    pub(super) client_ip_policy: client_ip::ClientIpPolicy,
    pub(super) max_body_size: usize,
}

#[derive(Clone)]
pub(super) struct ConnectionAdminState {
    pub(super) control_plane: connections::control_plane::ConnectionControlPlane,
    pub(super) inventory: tools::inventory::CapabilityInventory,
    pub(super) mcp_catalogs: connections::mcp::McpConnectionCatalogService,
    pub(super) openapi_catalogs: connections::openapi::OpenApiConnectionCatalogService,
    pub(super) tests: connections::test::ConnectionTestService,
    pub(super) rbac_state: Option<middleware::rbac::RbacState>,
    pub(super) audit: audit::AuditLog,
    pub(super) client_ip_policy: client_ip::ClientIpPolicy,
    pub(super) max_body_size: usize,
    // Serializes the HTTP precondition snapshot with its mutation. This is
    // intentionally distinct from the control plane's secret/activation lock.
    pub(super) secret_precondition_lock: Arc<Mutex<()>>,
}

#[derive(Clone)]
pub(super) struct ToolAdminState {
    pub(super) tools_file: Option<PathBuf>,
    pub(super) registry: tools::definitions::ToolRegistry,
    pub(super) inventory: tools::inventory::CapabilityInventory,
    pub(super) executor: tools::executor::ToolExecutor,
    pub(super) rbac_state: Option<middleware::rbac::RbacState>,
    pub(super) audit: audit::AuditLog,
    pub(super) client_ip_policy: client_ip::ClientIpPolicy,
    pub(super) max_body_size: usize,
    pub(super) write_lock: Arc<Mutex<()>>,
    /// Cluster mode's authoritative tools control plane. Present exactly
    /// when `tools_file` is absent-but-cluster: register commits through
    /// its CAS transaction instead of the file.
    #[cfg(feature = "postgres")]
    pub(super) tool_control_plane: Option<Arc<dyn storage::ToolControlPlane>>,
    /// The gate's tools adapter, so a register installs through the same
    /// revision-guarded step the reconciler uses and can never roll the
    /// live lane back to an older commit.
    #[cfg(feature = "postgres")]
    pub(super) tools_resource: Option<Arc<security_cluster::ToolsResource>>,
}

#[derive(Clone)]
pub(super) struct AdminAuthState {
    pub(super) login: auth::OidcLoginState,
    pub(super) audit: audit::AuditLog,
    pub(super) admin_prefix: String,
    pub(super) cookie_max_age: u64,
    pub(super) client_ip_policy: client_ip::ClientIpPolicy,
}

impl AdminAuthState {
    pub(super) fn record(
        &self,
        parts: &http::request::Parts,
        phase: &'static str,
        outcome: &'static str,
        reason: &'static str,
    ) {
        self.audit.emit(audit::AuditEvent::new(
            "admin_login.transaction",
            client_ip::request_id(&parts.headers, &parts.extensions),
            client_ip::canonical_client_ip(
                &parts.headers,
                &parts.extensions,
                &self.client_ip_policy,
            ),
            None,
            json!({"phase": phase, "outcome": outcome, "reason": reason}),
        ));
    }

    pub(super) fn cookie_name(&self) -> String {
        let prefix = if self.login.uses_secure_cookie() {
            "__Host-"
        } else {
            ""
        };
        let namespace = hex::encode(Sha256::digest(self.admin_prefix.as_bytes()));
        format!("{prefix}ggw-admin-login-{}", &namespace[..16])
    }

    pub(super) fn browser_binding(&self, headers: &HeaderMap) -> Option<String> {
        let name = self.cookie_name();
        let mut values = headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|header| header.to_str().ok())
            .flat_map(|header| header.split(';'))
            .filter_map(|cookie| cookie.trim().split_once('='))
            .filter(|(key, _)| *key == name)
            .map(|(_, value)| value);
        let value = values.next()?;
        // Ambiguous cookies fail closed, including duplicate identical values.
        if values.next().is_some() {
            return None;
        }
        Some(value.to_owned())
    }

    pub(super) fn set_browser_cookie(&self, response: &mut Response, value: &str, max_age: u64) {
        // Host-only and prefix-isolated; HTTPS uses __Host- to prevent cookie
        // injection from sibling subdomains. HTTP is for local development.
        let secure = if self.login.uses_secure_cookie() {
            "; Secure"
        } else {
            ""
        };
        let cookie = format!(
            "{}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}",
            self.cookie_name()
        );
        match HeaderValue::from_str(&cookie) {
            Ok(cookie) => {
                response.headers_mut().append(header::SET_COOKIE, cookie);
            }
            Err(_) => {
                *response = internal_server_error("login cookie could not be set");
            }
        }
    }
}

/// The discovery inventory the admin surfaces read: the SQLite file in
/// standalone mode, the PostgreSQL tables the projector writes in cluster
/// mode. The handlers are written once against the trait.
pub(super) type DiscoveryReadHandle = Arc<dyn discovery::query::DiscoveryReadStore>;

#[derive(Clone)]
pub(super) struct SchemaAdminState {
    pub(super) coverage: discovery::openapi::SchemaCoverage,
    pub(super) query_store: Option<DiscoveryReadHandle>,
    pub(super) rbac_state: Option<middleware::rbac::RbacState>,
    pub(super) payload_capture_enabled: bool,
}

#[derive(Clone)]
pub(super) struct SignalsAdminState {
    pub(super) discovery_store: Option<DiscoveryReadHandle>,
    pub(super) rbac_state: Option<middleware::rbac::RbacState>,
    pub(super) audit: audit::AuditLog,
    pub(super) client_ip_policy: client_ip::ClientIpPolicy,
}

/// The suggestion routes' state. `suggestion_engine` is the SQLite engine
/// in standalone mode and the PostgreSQL engine in cluster mode (issue
/// #241, PR 12), behind one async handle so the handlers are written once;
/// `None` when no discovery store is configured, which every route answers
/// as "not configured".
#[derive(Clone)]
pub(super) struct SuggestionsAdminState {
    pub(super) suggestion_engine: Option<discovery::suggestions::SuggestionEngineHandle>,
    pub(super) policy: PolicyAdminState,
    /// Serializes suggestion lifecycle writes within this process (issue
    /// #241, PR 12). Standalone acceptance is three steps -- read the
    /// suggestion, write the policy, transition -- and the policy write is
    /// long (file, history, audit). Without this lock a dismissal arriving
    /// mid-acceptance moves the row, the acceptance's conditional
    /// transition is then refused, and the deployment is left with the
    /// rule installed for a dismissed suggestion: the partial success the
    /// HA state model's rule 7 forbids. One process serves many concurrent
    /// requests, so "one process cannot race itself" is only true when
    /// something makes it true; this is that something. Cluster mode does
    /// not depend on it -- its authority is the acceptance transaction's
    /// `FOR UPDATE` lock, which also excludes the other replicas.
    pub(super) lifecycle_guard: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Clone)]
pub(super) struct TrafficAdminState {
    pub(super) discovery_store: Option<DiscoveryReadHandle>,
    pub(super) audit_query_store: Option<Arc<storage::SqliteAuditEventStore>>,
    pub(super) rbac_state: Option<middleware::rbac::RbacState>,
    pub(super) audit: audit::AuditLog,
    pub(super) client_ip_policy: client_ip::ClientIpPolicy,
    pub(super) max_body_size: usize,
}

#[derive(Clone)]
pub(super) struct PrincipalAdminState {
    pub(super) directory: auth::PrincipalDirectory,
    pub(super) audit_query_store: Option<Arc<storage::SqliteAuditEventStore>>,
    pub(super) discovery_store: Option<DiscoveryReadHandle>,
    pub(super) rbac_state: Option<middleware::rbac::RbacState>,
}

#[derive(Clone)]
pub(super) struct AdminApiStates {
    pub(super) audit: AuditAdminState,
    pub(super) auth: Option<AdminAuthState>,
    pub(super) status: StatusAdminState,
    pub(super) cluster: ClusterAdminState,
    pub(super) policy: PolicyAdminState,
    pub(super) tokens: TokenAdminState,
    pub(super) connections: ConnectionAdminState,
    pub(super) tools: ToolAdminState,
    pub(super) schema: SchemaAdminState,
    pub(super) signals: SignalsAdminState,
    pub(super) suggestions: SuggestionsAdminState,
    pub(super) traffic: TrafficAdminState,
    pub(super) principals: PrincipalAdminState,
    /// Cluster mode's revision gate, layered over every admin API route
    /// except the (pre-authorization) auth routes: an admin endpoint's
    /// permission check consults the compiled policy snapshot, so it is a
    /// protected request under the HA state model's strict rule and must
    /// never authorize against a stale revision.
    #[cfg(feature = "postgres")]
    pub(super) revision_gate: Option<Arc<dyn middleware::rbac::SecurityRevisionGate>>,
}
