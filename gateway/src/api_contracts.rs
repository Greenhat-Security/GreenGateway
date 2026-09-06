//! api contracts boundary extracted from the application composition root.
use super::*;

pub(super) fn warn_on_mcp_exempt_prefix_overlaps(routes: &GatewayRoutes, config: &config::Config) {
    for mcp_path in &routes.mcp_route_paths {
        for (exempt_list, exempt_paths) in [
            ("AUTH_EXEMPT_PATHS", &config.auth_exempt_paths),
            ("RBAC_EXEMPT_PATHS", &config.rbac_exempt_paths),
        ] {
            if let Some(exempt_prefix) = mcp_route_covering_exempt_prefix(mcp_path, exempt_paths) {
                tracing::warn!(
                    mcp_route = %mcp_path,
                    exempt_prefix = %exempt_prefix,
                    exempt_list,
                    "MCP route falls under an exempt prefix; authentication and authorization are \
                     still enforced on the MCP route, but the overlapping configuration is likely \
                     unintended"
                );
            }
        }
    }
}

pub(super) fn mcp_route_covering_exempt_prefix<'a>(
    mcp_path: &str,
    exempt_paths: &'a [String],
) -> Option<&'a str> {
    exempt_paths
        .iter()
        .find(|exempt_path| {
            exempt_path.as_str() != mcp_path
                && path_match::exempt_path_matches(mcp_path, exempt_path)
        })
        .map(String::as_str)
}

#[derive(Clone, Copy, Debug)]
pub(super) struct MakeRequestUuid;

impl MakeRequestId for MakeRequestUuid {
    fn make_request_id<B>(&mut self, _request: &Request<B>) -> Option<RequestId> {
        let id = uuid::Uuid::new_v4().to_string();
        id.parse().ok().map(RequestId::new)
    }
}

#[derive(Serialize)]
pub(super) struct HealthResponse {
    pub(super) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) upstream: Option<proxy::UpstreamHealthResponse>,
}

#[derive(Serialize)]
pub(super) struct ProbeResponse {
    pub(super) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
}

#[derive(Serialize)]
pub(super) struct VersionResponse {
    pub(super) version: &'static str,
    pub(super) admin_login_configured: bool,
}

#[derive(Clone, Serialize)]
pub(super) struct RbacStatus {
    pub(super) policy_loaded: bool,
    pub(super) policy_id: Option<String>,
}

#[derive(Serialize)]
pub(super) struct AuditSinksStatus {
    pub(super) stdout: bool,
    pub(super) file: bool,
    pub(super) sqlite: bool,
    pub(super) broadcast: bool,
}

#[derive(Serialize)]
pub(super) struct RateLimitStatus {
    pub(super) requests_per_second: f64,
    pub(super) burst: u32,
}

#[derive(Serialize)]
pub(super) struct RateLimitsStatus {
    pub(super) read: RateLimitStatus,
    pub(super) write: RateLimitStatus,
}

#[derive(Serialize)]
pub(super) struct EgressStatus {
    pub(super) allowed_hosts_count: usize,
    pub(super) nat64_prefixes_count: usize,
    pub(super) deny_private_ips: bool,
}

#[derive(Serialize)]
pub(super) struct StatusResponse {
    pub(super) version: &'static str,
    pub(super) uptime_seconds: u64,
    pub(super) listen_addr: String,
    pub(super) auth_enabled: bool,
    pub(super) rbac: RbacStatus,
    pub(super) audit_sinks: AuditSinksStatus,
    pub(super) rate_limits: RateLimitsStatus,
    pub(super) cors_allow_origins: Vec<String>,
    pub(super) trust_proxy_headers: bool,
    pub(super) csrf_enabled: bool,
    pub(super) egress: EgressStatus,
    pub(super) lifecycle: LifecycleStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) upstream: Option<proxy::UpstreamHealthAdminResponse>,
}

#[derive(Serialize)]
pub(super) struct LifecycleStatus {
    pub(super) phase: &'static str,
    pub(super) accepting_work: bool,
}

#[derive(Deserialize)]
pub(super) struct AuditQueryParams {
    pub(super) from: Option<String>,
    pub(super) to: Option<String>,
    pub(super) event_type: Option<String>,
    pub(super) actor: Option<String>,
    pub(super) path: Option<String>,
    pub(super) status: Option<String>,
    pub(super) limit: Option<String>,
    pub(super) before_id: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct AdminAuthCallbackParams {
    pub(super) code: Option<String>,
    pub(super) state: Option<String>,
    pub(super) error: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdminAuthCompletionParams {
    pub(super) code: String,
    pub(super) state: String,
}

#[derive(Deserialize)]
pub(super) struct TrafficEndpointListParams {
    pub(super) method: Option<String>,
    pub(super) endpoint_template: Option<String>,
    pub(super) endpoint_template_prefix: Option<String>,
    pub(super) first_seen_after: Option<String>,
    pub(super) first_seen_before: Option<String>,
    pub(super) last_seen_after: Option<String>,
    pub(super) last_seen_before: Option<String>,
    pub(super) min_call_count: Option<String>,
    pub(super) new_since_hours: Option<String>,
    pub(super) is_new: Option<String>,
    pub(super) reviewed: Option<String>,
    pub(super) covered_by_rule: Option<String>,
    pub(super) sort: Option<String>,
    pub(super) limit: Option<String>,
    pub(super) cursor: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct PrincipalListParams {
    pub(super) issuer: Option<String>,
    pub(super) auth_method: Option<String>,
    pub(super) principal_type: Option<String>,
    pub(super) last_seen_after: Option<String>,
    pub(super) last_seen_before: Option<String>,
    pub(super) limit: Option<String>,
    pub(super) cursor: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct SignalListParams {
    pub(super) state: Option<String>,
    pub(super) signal_type: Option<String>,
    pub(super) target_kind: Option<String>,
    pub(super) target_key: Option<String>,
    pub(super) limit: Option<String>,
    pub(super) cursor: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct RuleSuggestionListParams {
    pub(super) state: Option<String>,
    pub(super) suggestion_type: Option<String>,
    pub(super) limit: Option<String>,
    pub(super) cursor: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct PolicyHistoryParams {
    pub(super) limit: Option<String>,
    pub(super) cursor: Option<String>,
    pub(super) include_policy: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct TokenListParams {
    pub(super) limit: Option<String>,
    pub(super) cursor: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct TrafficEndpointDetailParams {
    pub(super) method: Option<String>,
    pub(super) endpoint_template: Option<String>,
    pub(super) principal_limit: Option<String>,
    pub(super) principal_cursor: Option<String>,
    pub(super) from: Option<String>,
    pub(super) to: Option<String>,
    pub(super) new_since_hours: Option<String>,
    pub(super) bucket: Option<String>,
    pub(super) events_limit: Option<String>,
    pub(super) events_before_id: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct PrincipalDetailParams {
    pub(super) subject: Option<String>,
    pub(super) issuer: Option<String>,
    pub(super) auth_method: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct InferredSchemaParams {
    pub(super) method: Option<String>,
    pub(super) endpoint_template: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TrafficEndpointReviewRequest {
    pub(super) method: String,
    pub(super) endpoint_template: String,
    pub(super) reviewed: bool,
}

#[derive(Clone, Deserialize)]
pub(super) struct AuditEventStreamParams {
    pub(super) event_type: Option<String>,
    pub(super) path: Option<String>,
}

#[derive(Serialize)]
pub(super) struct AuditQueryResponse {
    pub(super) events: Vec<audit::AuditEvent>,
    pub(super) next_cursor: Option<i64>,
}

#[derive(Serialize)]
pub(super) struct TrafficEndpointDetailResponse {
    pub(super) endpoint: discovery::query::EndpointAggregateDetail,
    pub(super) principals: discovery::query::PrincipalPage,
    pub(super) audit: TrafficEndpointAuditEnrichment,
}

#[derive(Serialize)]
pub(super) struct PrincipalListResponse {
    pub(super) principals: Vec<auth::principal_directory::PrincipalDirectoryRecord>,
    pub(super) next_cursor: Option<String>,
    pub(super) anonymous_request_count: u64,
}

#[derive(Serialize)]
pub(super) struct PrincipalDetailResponse {
    pub(super) principal: auth::principal_directory::PrincipalDirectoryRecord,
    pub(super) endpoints_touched: Vec<PrincipalEndpointTouch>,
    pub(super) rules_hit: Vec<String>,
    pub(super) anomaly_history: Vec<discovery::signals::Signal>,
    pub(super) tools_called: Vec<Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(super) struct PrincipalEndpointTouch {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) request_count: u64,
    pub(super) last_seen: String,
}

#[derive(Serialize)]
pub(super) struct TrafficEndpointAuditEnrichment {
    pub(super) available: bool,
    pub(super) match_strategy: &'static str,
    pub(super) match_limitations: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) omitted_reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) time_series_truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) time_series: Option<Vec<audit::query::EndpointTimeSeriesPoint>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) recent_events: Option<Vec<audit::query::EndpointRecentEvent>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) recent_events_next_cursor: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) recent_events_scan_truncated: Option<bool>,
}

pub(super) struct InferredSchemaQuery {
    pub(super) method: String,
    pub(super) endpoint_template: String,
}

#[derive(Serialize)]
pub(super) struct PolicyValidationResponse {
    pub(super) valid: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) errors: Vec<String>,
}

#[derive(Deserialize)]
pub(super) struct PolicyRulePreviewRequest {
    pub(super) rule: rbac::Rule,
    pub(super) from: Option<String>,
    pub(super) to: Option<String>,
    pub(super) sample_limit: Option<usize>,
}

#[derive(Serialize)]
pub(super) struct PolicyRulePreviewResponse {
    pub(super) match_count: u64,
    pub(super) scanned_event_count: u64,
    pub(super) sample_strategy: &'static str,
    pub(super) samples: Vec<PolicyRulePreviewSample>,
}

#[derive(Serialize)]
pub(super) struct PolicyRulePreviewSample {
    pub(super) event_id: String,
    pub(super) timestamp: String,
    pub(super) request_id: String,
    pub(super) source_ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) user_agent: Option<String>,
    pub(super) method: String,
    pub(super) path: String,
    pub(super) actor: Option<audit::Actor>,
    pub(super) status: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) policy_decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) matched_rule_id: Option<String>,
}

#[derive(Serialize)]
pub(super) struct PolicyRuleHitsResponse {
    pub(super) rules: Vec<PolicyRuleHitCount>,
}

#[derive(Serialize)]
pub(super) struct PolicyRuleHitCount {
    pub(super) rule_id: String,
    pub(super) hits: u64,
}

#[derive(Serialize)]
pub(super) struct PolicyRuleShadowReviewResponse {
    pub(super) rules: Vec<PolicyRuleShadowReviewSummary>,
    pub(super) scanned_event_count: u64,
    pub(super) scan_truncated: bool,
}

#[derive(Serialize)]
pub(super) struct PolicyRuleShadowReviewSummary {
    pub(super) rule_id: String,
    pub(super) rule: rbac::Rule,
    pub(super) would_deny_count: u64,
    pub(super) affected_principals: Vec<audit::query::ShadowRuleAffectedPrincipal>,
    pub(super) samples: Vec<audit::query::ShadowRuleWouldDenySample>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CreateTokenAdminRequest {
    pub(super) scopes: Vec<String>,
    pub(super) expires_at: Option<String>,
}

#[derive(Serialize)]
pub(super) struct CreatedTokenAdminResponse {
    pub(super) plaintext_token: String,
    pub(super) plaintext_token_notice: &'static str,
    pub(super) token: auth::tokens::TokenRecord,
}

#[derive(Serialize)]
pub(super) struct OpenApiToolsPreviewResponse {
    pub(super) tools: Vec<tools::definitions::ToolDefinition>,
    pub(super) operation_id_fallbacks: Vec<OpenApiToolNameFallbackResponse>,
    pub(super) skipped_operations: Vec<OpenApiSkippedOperationResponse>,
    pub(super) api_key_header_auth_requirements: Vec<OpenApiApiKeyHeaderAuthRequirementResponse>,
}

#[derive(Serialize)]
pub(super) struct OpenApiToolNameFallbackResponse {
    pub(super) method: String,
    pub(super) path_template: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) original_operation_id: Option<String>,
    pub(super) generated_name: String,
    pub(super) reason: &'static str,
}

#[derive(Serialize)]
pub(super) struct OpenApiSkippedOperationResponse {
    pub(super) method: String,
    pub(super) path_template: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) original_operation_id: Option<String>,
    pub(super) reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) property_name: Option<String>,
}

#[derive(Serialize)]
pub(super) struct OpenApiApiKeyHeaderAuthRequirementResponse {
    pub(super) tool_name: String,
    pub(super) method: String,
    pub(super) path_template: String,
    pub(super) scheme_name: String,
    pub(super) header_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OpenApiToolsRegisterRequest {
    pub(super) spec: String,
    pub(super) selected_tool_names: Vec<String>,
}

#[derive(Serialize)]
pub(super) struct OpenApiToolsRegisterResponse {
    pub(super) registered_tool_names: Vec<String>,
    pub(super) tool_count: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManagedOpenApiPreviewRequest {
    pub(super) spec: String,
    #[serde(default)]
    pub(super) overlay: Option<Value>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OpenApiOverlayPutParams {
    #[serde(default)]
    pub(super) allow_unresolved_enum_sources: bool,
}

#[derive(Serialize)]
pub(super) struct ManagedOpenApiPreviewResponse {
    pub(super) connection_id: connections::model::ConnectionId,
    pub(super) connection_etag: String,
    pub(super) spec_digest: String,
    pub(super) spec_revision: u64,
    pub(super) catalog_revision: u64,
    pub(super) tools: Vec<tools::definitions::ToolDefinition>,
    pub(super) security_confirmations: Vec<ManagedOpenApiSecuritySelectionResponse>,
    pub(super) incompatibilities: Vec<ManagedOpenApiIncompatibilityResponse>,
    pub(super) operation_id_fallbacks: Vec<OpenApiToolNameFallbackResponse>,
    pub(super) skipped_operations: Vec<OpenApiSkippedOperationResponse>,
    pub(super) overlay: ManagedOpenApiOverlayReportResponse,
}

#[derive(Serialize)]
pub(super) struct ManagedOpenApiOverlayReportResponse {
    pub(super) applied: bool,
    pub(super) problems: Vec<tools::overlay::OverlayProblem>,
    pub(super) warnings: Vec<tools::overlay::OverlayWarning>,
    pub(super) sources: Vec<connections::store::StoredOpenApiSourceReport>,
    pub(super) tools: Vec<tools::overlay::OverlayToolReport>,
    pub(super) composites: Vec<tools::overlay::OverlayCompositeReport>,
}

#[derive(Serialize)]
pub(super) struct ConnectionOpenApiOverlayGetResponse {
    pub(super) connection_id: connections::model::ConnectionId,
    pub(super) etag: String,
    pub(super) overlay_revision: u64,
    pub(super) applied_catalog_revision: u64,
    pub(super) document: Option<Value>,
    pub(super) sources: Vec<connections::store::StoredOpenApiSourceReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) updated_at: Option<String>,
}

#[derive(Serialize)]
pub(super) struct ConnectionOpenApiOverlayMutationResponse {
    pub(super) connection_id: connections::model::ConnectionId,
    pub(super) overlay_revision: u64,
    pub(super) catalog_revision: u64,
    pub(super) warnings: Vec<tools::overlay::OverlayWarning>,
    pub(super) sources: Vec<connections::store::StoredOpenApiSourceReport>,
    pub(super) tools: Vec<tools::overlay::OverlayToolReport>,
    pub(super) composites: Vec<tools::overlay::OverlayCompositeReport>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManagedOpenApiRegisterRequest {
    pub(super) spec: String,
    pub(super) spec_digest: String,
    pub(super) expected_spec_revision: u64,
    pub(super) expected_catalog_revision: u64,
    pub(super) selected_tool_names: Vec<String>,
    pub(super) security_confirmations: Vec<ManagedOpenApiSecuritySelectionRequest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManagedOpenApiSecuritySelectionRequest {
    pub(super) tool_name: String,
    pub(super) selected_scheme_names: Vec<String>,
}

#[derive(Serialize)]
pub(super) struct ManagedOpenApiSecuritySelectionResponse {
    pub(super) tool_name: String,
    pub(super) selected_scheme_names: Vec<String>,
}

#[derive(Serialize)]
pub(super) struct ManagedOpenApiIncompatibilityResponse {
    pub(super) tool_name: String,
    pub(super) reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) path_template: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) detail: Option<String>,
}

#[derive(Serialize)]
#[serde(untagged)]
pub(super) enum ConnectionCatalogRefreshResponse {
    Mcp(connections::mcp::McpCatalogRefreshResult),
    OpenApi(connections::openapi::OpenApiCatalogPublishResult),
}

impl ConnectionCatalogRefreshResponse {
    pub(super) fn audit_summary(&self) -> ConnectionRefreshAuditSummary {
        match self {
            Self::Mcp(result) => ConnectionRefreshAuditSummary {
                catalog_revision: result.catalog_revision,
                total_count: result.total_count,
                added_count: result.added_count,
                changed_count: result.changed_count,
                removed_count: result.removed_count,
            },
            Self::OpenApi(result) => ConnectionRefreshAuditSummary {
                catalog_revision: result.catalog_revision,
                total_count: result.total_count,
                added_count: result.added_count,
                changed_count: result.changed_count,
                removed_count: result.removed_count,
            },
        }
    }
}

pub(super) struct ConnectionRefreshAuditSummary {
    pub(super) catalog_revision: u64,
    pub(super) total_count: usize,
    pub(super) added_count: usize,
    pub(super) changed_count: usize,
    pub(super) removed_count: usize,
}

#[derive(Clone, Copy)]
pub(super) struct ConnectionRefreshFailure {
    pub(super) reason: &'static str,
    pub(super) upstream_method: Option<&'static str>,
    pub(super) upstream_error_code: Option<i32>,
}

impl ConnectionRefreshFailure {
    pub(super) const fn plain(reason: &'static str) -> Self {
        Self {
            reason,
            upstream_method: None,
            upstream_error_code: None,
        }
    }

    pub(super) const fn mcp(error: connections::mcp::McpCatalogRefreshError) -> Self {
        Self {
            reason: error.safe_reason(),
            upstream_method: error.upstream_method(),
            upstream_error_code: error.upstream_error_code(),
        }
    }
}

#[derive(Serialize)]
pub(super) struct ToolNameConflictResponse {
    pub(super) error: &'static str,
    pub(super) conflicts: Vec<String>,
}

#[derive(Serialize)]
pub(super) struct UnsupportedOpenApiToolAuthRequirementsResponse {
    pub(super) error: &'static str,
    pub(super) unsupported_tool_names: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ToolsFileAdminDocument {
    pub(super) schema_version: String,
    #[serde(default)]
    pub(super) tools: Vec<tools::definitions::ToolDefinition>,
}

#[derive(Serialize)]
pub(super) struct RuleDeletedResponse {
    pub(super) deleted_rule_id: String,
}

#[derive(Serialize)]
pub(super) struct RulesReorderedResponse {
    pub(super) order: Vec<String>,
}

#[derive(Serialize)]
pub(super) struct RuleSuggestionAcceptResponse {
    pub(super) suggestion: discovery::suggestions::RuleSuggestion,
    pub(super) rule: rbac::Rule,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RulePatch {
    pub(super) enabled: Option<bool>,
    pub(super) methods: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_rule_path_patch")]
    pub(super) path: Option<RulePathPatch>,
    #[serde(default, deserialize_with = "deserialize_rule_tool_name_patch")]
    pub(super) tool_name: Option<RuleToolNamePatch>,
    pub(super) principal: Option<rbac::PrincipalMatcher>,
    pub(super) action: Option<rbac::RuleAction>,
}

pub(super) enum RuleToolNamePatch {
    Set(String),
    Clear,
}

pub(super) enum RulePathPatch {
    Set(String),
    Clear,
}

pub(super) fn deserialize_rule_path_patch<'de, D>(
    deserializer: D,
) -> Result<Option<RulePathPatch>, D::Error>
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

pub(super) fn deserialize_rule_tool_name_patch<'de, D>(
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

/// Serializes tests that install a `tracing` subscriber, and keeps the
/// process-wide callsite-interest cache consistent across them.
///
/// `tracing` caches per-callsite interest globally. With only thread-local
/// defaults in play a rebuild stamps the *calling* thread's subscriber onto that
/// shared cache, so without serialization two tests overwrite each other's
/// filters.
///
/// Do NOT add a rebuild when a guard is released: with the subscriber already
/// uninstalled it evaluates against `NoSubscriber`, stamping every callsite
/// `never` and the global max level `OFF` for the rest of the process. Leaking
/// one test's filter is the lesser evil, and the next guard's entry rebuild
/// repairs it. See [`TracingTestGuard::drop`].
///
/// Every test that installs a subscriber must serialize on this lock and rebuild
/// the interest cache while its subscriber is live -- a single non-participant is
/// enough to defeat it for all of them. Use [`tracing_test_guard`] for the
/// `set_default` form; the closure form must take this lock itself and rebuild
/// *inside* the closure (see `discovery::suggestions`).
#[cfg(test)]
pub(crate) static TRACING_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) struct TracingTestGuard {
    pub(super) dispatch: Option<tracing::subscriber::DefaultGuard>,
    pub(super) _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for TracingTestGuard {
    fn drop(&mut self) {
        // Deliberately does NOT rebuild on the way out. With the subscriber
        // already uninstalled a rebuild would evaluate every callsite against
        // `NoSubscriber` and stamp the shared cache as "never" -- globally
        // disabling tracing until something rebuilt it again. Each guard
        // rebuilds on entry instead, which is what actually matters, and every
        // test that asserts on log output goes through this guard.
        drop(self.dispatch.take());
    }
}

/// Installs `subscriber` as the thread-local default for the rest of the scope,
/// serialized against every other subscriber-installing test.
#[cfg(test)]
pub(crate) fn tracing_test_guard<S>(subscriber: S) -> TracingTestGuard
where
    S: tracing::Subscriber + Send + Sync + 'static,
{
    let lock = TRACING_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dispatch = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    TracingTestGuard {
        dispatch: Some(dispatch),
        _lock: lock,
    }
}

pub(super) type ResponseResult<T> = Result<T, Box<Response>>;

pub(super) struct PolicyMutationCommitResult {
    pub(super) after_policy: rbac::Policy,
    pub(super) new_etag: String,
    pub(super) history_append_failed: bool,
}

pub(super) struct PolicyRuleCreateResult {
    pub(super) rule: rbac::Rule,
    pub(super) new_etag: String,
    pub(super) history_append_failed: bool,
}

pub(super) struct PolicyMutationCommitContext<'a, 'guard> {
    pub(super) state: &'a PolicyAdminState,
    pub(super) rbac_state: &'a middleware::rbac::RbacState,
    pub(super) policy_write_guard: &'a middleware::rbac::PolicyWriteGuard<'guard>,
    pub(super) parts: &'a http::request::Parts,
    pub(super) principal: &'a auth::Principal,
}

pub(super) enum PolicyAdminAuthzError {
    NotConfigured,
    Forbidden(String),
}

pub(super) enum TokenAdminAuthzError {
    StoreNotConfigured,
    RbacNotConfigured,
    Forbidden(String),
}

pub(super) enum ConnectionAdminAuthzError {
    RbacNotConfigured,
    Forbidden(String),
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct TokenScopeAuthzError {
    pub(super) disallowed: Vec<String>,
}

pub(super) enum ToolAdminAuthzError {
    RbacNotConfigured,
    ToolsFileNotConfigured,
    Forbidden(String),
}

pub(super) enum TrafficAdminAuthzError {
    NotConfigured,
    Forbidden(String),
}

pub(super) enum PrincipalAdminAuthzError {
    NotConfigured,
    Forbidden(String),
}

pub(super) enum SignalsAdminAuthzError {
    NotConfigured,
    Forbidden(String),
}

pub(super) enum SuggestionsAdminAuthzError {
    NotConfigured,
    Forbidden(String),
}

pub(super) enum AdminReadAuthzError {
    NotConfigured,
    Forbidden(String),
}

pub(super) enum IfMatchError {
    Missing,
    InvalidHeader,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ToolPlaygroundIfMatchError {
    Missing,
    Invalid,
}

#[derive(Serialize)]
pub(super) struct ErrorResponse {
    pub(super) error: String,
}

#[derive(Serialize)]
pub(super) struct ConnectionValidationProblem {
    pub(super) field: &'static str,
    pub(super) code: &'static str,
}

#[derive(Serialize)]
pub(super) struct ConnectionValidationResponse {
    pub(super) error: &'static str,
    pub(super) problems: Vec<ConnectionValidationProblem>,
}

#[derive(Serialize)]
pub(super) struct ConnectionDeletedResponse {
    pub(super) deleted_connection_id: connections::model::ConnectionId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConnectionSecretCreateRequest {
    pub(super) label: String,
    pub(super) purpose: connections::secret::SecretPurpose,
    #[serde(deserialize_with = "deserialize_secret_value")]
    pub(super) value: Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ConnectionSecretRotateRequest {
    pub(super) purpose: connections::secret::SecretPurpose,
    #[serde(deserialize_with = "deserialize_secret_value")]
    pub(super) value: Zeroizing<String>,
}

pub(super) fn deserialize_secret_value<'de, D>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
}

#[derive(Serialize)]
pub(super) struct ConnectionSecretDeletedResponse {
    pub(super) deleted_secret_id: String,
}

#[derive(Serialize)]
pub(super) struct SchemaNotConfiguredResponse {
    pub(super) error: String,
    pub(super) spec_configured: bool,
}

#[derive(Serialize)]
pub(super) struct DiscoveryNotConfiguredResponse {
    pub(super) error: String,
    pub(super) discovery_configured: bool,
}

#[derive(Serialize)]
pub(super) struct PayloadCaptureNotConfiguredResponse {
    pub(super) error: String,
    pub(super) payload_capture_configured: bool,
}

#[derive(Serialize)]
pub(super) struct InferredSchemaNoSamplesResponse {
    pub(super) error: String,
    pub(super) schema_inferred: bool,
}

#[derive(Default)]
pub(super) struct DiscoveredOidcConfig {
    pub(super) jwks_urls: HashMap<String, String>,
    pub(super) admin_login: Option<DiscoveredAdminLoginEndpoints>,
}

#[derive(Clone)]
pub(super) struct DiscoveredAdminLoginEndpoints {
    pub(super) provider_name: String,
    pub(super) issuer: String,
    pub(super) jwks_url: String,
    pub(super) authorization_endpoint: String,
    pub(super) token_endpoint: String,
}

#[derive(Clone)]
pub(super) struct MiddlewareStack {
    pub(super) config: config::Config,
    pub(super) audit_log: audit::AuditLog,
    pub(super) csrf_config: middleware::csrf::CsrfConfig,
    pub(super) rate_limit_state: middleware::rate_limit::RateLimitState,
    pub(super) observation_state: middleware::observation::ObservationState,
    pub(super) rbac_state: Option<middleware::rbac::RbacState>,
    pub(super) auth_state: Option<middleware::auth::AuthState>,
    pub(super) proxy_dispatch_state: ProxyDispatchState,
}

#[derive(Clone)]
pub(super) struct ManagedAdminCacheControlState {
    pub(super) connections_route: String,
    pub(super) connection_secrets_route: String,
    pub(super) tools_route: String,
}

#[derive(Default)]
pub(super) struct GatewayAppBuildOverrides {
    pub(super) lifecycle: Option<GatewayLifecycle>,
    /// This replica's cluster identity, so the status API names the same
    /// instance the roster row does. `None` in standalone mode, where the
    /// builder generates a per-process identity for its self-report --
    /// there is no roster for it to have to agree with.
    pub(super) ha_identity: Option<ha::InstanceIdentity>,
    /// The durable PostgreSQL audit store for cluster history, preview and SSE;
    /// None in standalone mode and in tests that exercise the broadcast
    /// path.
    #[cfg(feature = "postgres")]
    pub(super) pg_audit: Option<Arc<storage::postgres_audit::PostgresAuditEventStore>>,
    /// The cluster-mode policy control plane seed: the store plus the
    /// authoritative active document `run()` loaded and validated enough
    /// to hand to the app builder. None in standalone mode.
    #[cfg(feature = "postgres")]
    pub(super) pg_policy: Option<ClusterPolicySeed>,
    /// The cluster-mode tools control plane seed: the store plus the
    /// authoritative local lane `run()` seeded and loaded. None in
    /// standalone mode.
    #[cfg(feature = "postgres")]
    pub(super) pg_tools: Option<ClusterToolsSeed>,
    /// The cluster-mode Connection control plane seed: the store, the
    /// records the runtime snapshot starts from, and the catalogs the
    /// (synchronous) catalog services read at boot. None in standalone
    /// mode, where the control plane opens `CONNECTIONS_SQLITE_PATH`
    /// itself.
    #[cfg(feature = "postgres")]
    pub(super) pg_connections: Option<ClusterConnectionsSeed>,
    /// The cluster-mode service-token store and the revision it was read
    /// at. None in standalone mode, where SERVICE_TOKEN_SQLITE_PATH is the
    /// store.
    #[cfg(feature = "postgres")]
    pub(super) pg_service_tokens: Option<ClusterServiceTokenSeed>,
    /// The cluster-mode pending-login store: the pool, the deployment ID
    /// the digests and associated data bind, and the loaded login keyring.
    /// None in standalone mode, or when no admin login provider is set.
    #[cfg(feature = "postgres")]
    pub(super) pg_pending_logins: Option<ClusterPendingLoginSeed>,
    /// The cluster-mode rate-limit and execution-lease stores' seed: the
    /// pool, the deployment ID, the loaded rate-limit keyring, and the
    /// replica's instance identity. None in standalone mode.
    #[cfg(feature = "postgres")]
    pub(super) pg_limits: Option<ClusterLimitsSeed>,
    /// The cluster-mode discovery seed: the pool, the identity the
    /// projector leads under, and the durable audit store it projects.
    /// None in standalone mode, where the SQLite aggregator sink and
    /// query store are discovery.
    #[cfg(feature = "postgres")]
    pub(super) pg_discovery: Option<ClusterDiscoverySeed>,
    /// The cluster-mode membership runtime (issue #241, PR 13): its boot
    /// row is written and its first fingerprint check run before the app
    /// is built; the builder starts its heartbeat task and wires its
    /// readiness gate into `/readyz`. None in standalone mode.
    #[cfg(feature = "postgres")]
    pub(super) pg_membership: Option<Arc<cluster_membership::ClusterMembership>>,
    /// Test seam: a readiness gate for `/readyz` without a membership
    /// store behind it, so the `config_fingerprint_mismatch` answer is
    /// testable without PostgreSQL.
    #[cfg(test)]
    pub(super) cluster_readiness: Option<Arc<ha::ClusterReadiness>>,
    /// Test seam: the PR 14 readiness probe with a scripted authority
    /// behind it, so every failure-matrix reason is reachable from a
    /// handler test without PostgreSQL.
    #[cfg(test)]
    pub(super) readiness_probe: Option<Arc<ha_status::ReadinessProbe>>,
    /// Test seam: a scripted readout for the PR 14 cluster status API, so
    /// the cluster shape of both routes -- a roster, a job ledger, a
    /// projector -- is reachable from a handler test without PostgreSQL.
    /// Supplying one also puts the state in cluster mode, exactly as
    /// having a real authority to read does.
    #[cfg(test)]
    pub(super) cluster_status_source: Option<Arc<dyn cluster_status::ClusterStatusSource>>,
    #[cfg(test)]
    pub(super) egress_resolver: Option<Arc<dyn egress::DnsResolver>>,
    /// Test seam: the pending-login backend the admin login flow uses,
    /// so a handler test can stand in an unavailable store.
    #[cfg(test)]
    pub(super) pending_login_backend: Option<Arc<dyn auth::oidc_login::PendingLoginBackend>>,
    #[cfg(test)]
    pub(super) request_selection_count: Option<Arc<std::sync::atomic::AtomicUsize>>,
    #[cfg(test)]
    pub(super) disable_proxy_health_checks: bool,
    #[cfg(test)]
    pub(super) stream_proxy_request_bodies: bool,
}

/// What `run()` proves about the policy authority before the app is built:
/// the store to serve from, and the active document the first snapshot
/// compiles from.
#[cfg(feature = "postgres")]
pub(super) struct ClusterPolicySeed {
    pub(super) store: Arc<storage::PostgresPolicyStore>,
    pub(super) active: storage::ActivePolicy,
}

/// The tools control plane's equivalent: the store, and the authoritative
/// local lane the registry installs at boot.
#[cfg(feature = "postgres")]
pub(super) struct ClusterToolsSeed {
    pub(super) store: Arc<storage::PostgresToolStore>,
    pub(super) active: storage::ActiveToolDocument,
}

/// Why cluster mode refused to start on the tools control plane. Fail
/// closed, like the policy plane's startup errors.
#[cfg(feature = "postgres")]
#[derive(Debug)]
pub(super) enum ClusterToolsStartupError {
    /// Seeding (or loading) the empty document failed.
    Seeding(storage::PolicyCommitError),
    /// The authority could not be read at startup.
    Store(storage::RepositoryError),
    /// Unreachable after a successful seed; defensive fail closed.
    NotSeeded,
    /// The active document failed validation: this binary refuses to
    /// activate a tools document it cannot fully parse and enforce.
    InvalidDocument(String),
}

#[cfg(feature = "postgres")]
impl std::fmt::Display for ClusterToolsStartupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Seeding(error) => write!(
                formatter,
                "the cluster-mode tools control plane could not seed its initial \
                 document: {error}"
            ),
            Self::Store(error) => write!(
                formatter,
                "the cluster-mode tools control plane could not be read at startup: {error}"
            ),
            Self::NotSeeded => write!(
                formatter,
                "the cluster-mode tools control plane has no active document after \
                 seeding; this is an internal validation gap -- please report it"
            ),
            Self::InvalidDocument(reason) => write!(
                formatter,
                "the active tools document failed validation and will not be served: {reason}"
            ),
        }
    }
}

#[cfg(feature = "postgres")]
impl std::error::Error for ClusterToolsStartupError {}

/// Why cluster mode refused to start on the policy control plane. Every
/// variant is fail-closed: an uninitialized deployment, an unreadable
/// authority, or a document this binary cannot serve all mean "do not
/// serve", never "serve something local instead".
#[cfg(feature = "postgres")]
#[derive(Debug)]
pub(super) enum ClusterPolicyStartupError {
    /// The deployment has no active policy. Initialization is an explicit
    /// workflow (the standalone-to-cluster import of #241 PR 15, or a
    /// seeding tool); a gateway that started anyway would either serve
    /// protected traffic with no authorization policy or fall back to
    /// local state the mode forbids.
    Uninitialized,
    /// The authority could not be read at startup.
    Store(storage::RepositoryError),
    /// The active document failed validation: this binary refuses to
    /// activate a document it cannot fully parse and enforce.
    InvalidDocument(String),
}

#[cfg(feature = "postgres")]
impl std::fmt::Display for ClusterPolicyStartupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uninitialized => formatter.write_str(
                "STATE_BACKEND=postgres requires an initialized deployment: the \
                 policy control plane has no active policy document. Initialize the \
                 deployment (the standalone import workflow lands in a later #241 \
                 PR) or unset STATE_BACKEND to run standalone",
            ),
            Self::Store(error) => write!(
                formatter,
                "the cluster-mode policy control plane could not be read at startup: {error}"
            ),
            Self::InvalidDocument(reason) => write!(
                formatter,
                "the active policy document failed validation and will not be served: {reason}"
            ),
        }
    }
}

#[cfg(feature = "postgres")]
impl std::error::Error for ClusterPolicyStartupError {}

/// What `run()` proves about the Connection authority before the app is
/// built: the store to serve from, the records the first runtime snapshot
/// is published from, the catalogs the synchronous catalog services need,
/// and the revision the reconciler starts its watermark at.
#[cfg(feature = "postgres")]
pub(super) struct ClusterConnectionsSeed {
    pub(super) store: Arc<connections::pg_store::PostgresConnectionStore>,
    pub(super) records: Vec<connections::store::StoredConnection>,
    pub(super) boot: Arc<connections::managed_store::ClusterConnectionsBoot>,
    pub(super) revision: i64,
}

/// The cluster-mode service-token authority and the security revision
/// its state was last changed at, read by `run()` for the gate's boot
/// watermark.
#[cfg(feature = "postgres")]
pub(super) struct ClusterServiceTokenSeed {
    pub(super) store: Arc<storage::PostgresServiceTokenStore>,
    pub(super) revision: i64,
    /// For the per-provider JWT revocation stores, which are built inside
    /// the validator chain where only the seed reaches.
    pub(super) pool: deadpool_postgres::Pool,
    pub(super) deployment_id: String,
}

#[cfg(feature = "postgres")]
#[derive(Debug)]
pub(super) struct ClusterServiceTokenStartupError(pub(super) storage::RepositoryError);

#[cfg(feature = "postgres")]
impl std::fmt::Display for ClusterServiceTokenStartupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "the cluster-mode service-token store could not be read at startup: {}",
            self.0
        )
    }
}

#[cfg(feature = "postgres")]
impl std::error::Error for ClusterServiceTokenStartupError {}

/// What `run()` loads for the pending-login store before the app is
/// built: the keyring must be read from disk with the same care the
/// connections keyring gets, and that is startup work.
#[cfg(feature = "postgres")]
pub(super) struct ClusterPendingLoginSeed {
    pub(super) pool: deadpool_postgres::Pool,
    pub(super) deployment_id: String,
    pub(super) keyring: connections::local_secret::LocalSecretKeyring,
}

/// What `run()` loads for cluster-mode rate limiting and execution
/// leases (issue #241, PR 10): the pool, the deployment ID, the loaded
/// rate-limit keyring, and this replica's instance identity (the lease
/// holder).
#[cfg(feature = "postgres")]
pub(super) struct ClusterLimitsSeed {
    pub(super) pool: deadpool_postgres::Pool,
    pub(super) deployment_id: String,
    pub(super) keyring: connections::local_secret::LocalSecretKeyring,
    pub(super) instance_id: uuid::Uuid,
}

/// What `run()` loads for cluster-mode discovery (issue #241, PR 11): the
/// pool the read store and the projector's write store ride, the
/// deployment ID and instance identity the projector's leadership lease is
/// scoped to and held by, and the durable audit store the projector reads
/// observations from.
#[cfg(feature = "postgres")]
pub(super) struct ClusterDiscoverySeed {
    pub(super) pool: deadpool_postgres::Pool,
    pub(super) deployment_id: String,
    pub(super) instance_id: uuid::Uuid,
    pub(super) audit: Arc<storage::postgres_audit::PostgresAuditEventStore>,
}

/// Why a cluster-mode boot could not register itself in the membership
/// roster (issue #241, PR 13). The database was proven reachable a moment
/// earlier, so a row that cannot be written is a fail-closed startup
/// error, not a warning. A fingerprint disagreement is *not* an error:
/// the replica boots unready and waits for agreement.
#[cfg(feature = "postgres")]
#[derive(Debug)]
pub(super) struct ClusterMembershipStartupError(pub(super) storage::RepositoryError);

#[cfg(feature = "postgres")]
impl std::fmt::Display for ClusterMembershipStartupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "the cluster-mode membership row could not be written at startup: {}",
            self.0
        )
    }
}

#[cfg(feature = "postgres")]
impl std::error::Error for ClusterMembershipStartupError {}

/// Why a cluster-mode boot refused to serve Connections.
#[cfg(feature = "postgres")]
#[derive(Debug)]
pub(super) enum ClusterConnectionsStartupError {
    Store(connections::store::ConnectionStoreError),
    Corrupt(connections::store::ConnectionStoreError),
}

#[cfg(feature = "postgres")]
impl std::fmt::Display for ClusterConnectionsStartupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(
                formatter,
                "the cluster-mode Connection control plane could not be read at startup: {error}"
            ),
            Self::Corrupt(error) => write!(
                formatter,
                "the Connection tables failed their integrity preflight and will not be served: \
                 {error}"
            ),
        }
    }
}

#[cfg(feature = "postgres")]
impl std::error::Error for ClusterConnectionsStartupError {}

pub(super) fn egress_client_for_build(
    config: egress::EgressConfig,
    _build_overrides: &GatewayAppBuildOverrides,
) -> Result<egress::EgressClient, egress::EgressError> {
    #[cfg(test)]
    if let Some(resolver) = _build_overrides.egress_resolver.as_ref() {
        return egress::EgressClient::new_with_resolver(config, Arc::clone(resolver));
    }

    egress::EgressClient::new(config)
}

/// Builds one revocation store per JWT provider, keyed by the issuer the
/// validator stamps on its principals. Cluster mode supplies the
/// PostgreSQL-backed one; standalone mode has none and keeps the no-op
/// store.
pub(super) type JwtRevocationStoreFactory<'a> =
    &'a (dyn Fn(&str) -> Arc<dyn auth::RevocationStore> + Send + Sync);

impl ClusterAdminState {
    /// Gather everything the two endpoints report: what this process
    /// knows about itself, and one read of the shared authority.
    ///
    /// The two are gathered together because the assembly compares them --
    /// the projector's leader is judged against the roster, the ledger's
    /// extent against this binary's manifest range -- and a view built
    /// from two reads taken minutes apart would invent disagreements that
    /// never existed.
    pub(super) async fn read_facts(
        &self,
    ) -> (cluster_status::LocalFacts, cluster_status::ClusterReadout) {
        let blocked_reason = readiness_blocked_reason(
            &self.lifecycle,
            self.cluster_readiness.as_ref(),
            self.readiness_probe.as_ref(),
            self.proxy.as_ref(),
        )
        .await;
        let mut readout = match self.source.as_ref() {
            Some(source) => source.read().await,
            None => cluster_status::ClusterReadout::default(),
        };
        // The ledger's extent comes from the readiness probe's cached
        // observation, so this endpoint reports the number `/readyz`
        // judged `schema_incompatible` on rather than a second, possibly
        // different, read.
        readout.schema_ledger_version = match self.readiness_probe.as_ref() {
            Some(probe) => probe.observed_schema_version().await,
            None => None,
        };
        let local = cluster_status::LocalFacts {
            cluster_mode: self.cluster_mode,
            instance_id: self.identity.instance_id(),
            boot_id: self.identity.boot_id(),
            binary_version: env!("CARGO_PKG_VERSION").to_owned(),
            fingerprint: self.fingerprint.clone(),
            schema_versions: schema_version_range_for_status(),
            document_versions: document_version_range_for_status(),
            boot_age_secs: self.process_started_at.elapsed().as_secs(),
            hostname: self.hostname.clone(),
            instance_ready: self.lifecycle.accepting_work() && blocked_reason.is_none(),
            draining: self.lifecycle.draining(),
            blocked_reason,
            compiled_security_revision: self
                .security
                .as_ref()
                .map_or(0, |security| security.compiled()),
            observed_security_revision: self
                .security
                .as_ref()
                .map_or(0, |security| security.observed()),
            reconcile_last_pass_age: self
                .security
                .as_ref()
                .and_then(|security| security.last_reconcile_pass_age()),
            reconcile_failures_total: self
                .security
                .as_ref()
                .map_or(0, |security| security.reconcile_failures_total()),
            audit: cluster_status::AuditQueueFacts {
                queue_depth: self.audit.queue_depth(),
                queue_capacity: self.audit.queue_capacity(),
                oldest_age_secs: self.audit.oldest_queued_age().as_secs_f64(),
                dropped_total: self.audit.dropped_total(),
            },
        };
        (local, readout)
    }
}

/// The merged candidate shared by both register authorities: the selected
/// tools appended to the current document, plus everything the persist and
/// response paths need.
#[derive(Debug)]
pub(super) struct MergedToolsCandidate {
    pub(super) registered_tool_names: Vec<String>,
    pub(super) previous_local_tools: Vec<tools::definitions::ToolDefinition>,
    pub(super) candidate_value: Value,
    pub(super) candidate_contents: String,
    pub(super) candidate_local_tools: Vec<tools::definitions::ToolDefinition>,
    pub(super) tool_count: usize,
}

/// Which authority owns the tools document for this deployment: the
/// standalone TOOLS_FILE, or (cluster mode) the PostgreSQL control plane.
pub(super) enum ToolsAuthority<'a> {
    File(&'a FsPath),
    #[cfg(feature = "postgres")]
    Postgres(&'a Arc<dyn storage::ToolControlPlane>),
}

impl ToolsAuthority<'_> {
    pub(super) fn audit_source_label(&self) -> String {
        match self {
            Self::File(path) => path.display().to_string(),
            #[cfg(feature = "postgres")]
            Self::Postgres(_) => "postgres-authority".to_owned(),
        }
    }
}

impl StatusResponse {
    pub(super) async fn from_state(state: &StatusAdminState) -> Self {
        let config = &state.config;
        let upstream = match state.proxy.as_ref() {
            Some(proxy) => Some(proxy.upstream_health_admin_response().await),
            None => None,
        };

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
                nat64_prefixes_count: config.egress_nat64_prefixes.len(),
                deny_private_ips: config.egress_deny_private_ips,
            },
            lifecycle: LifecycleStatus {
                phase: state.lifecycle.phase_name(),
                accepting_work: state.lifecycle.accepting_work(),
            },
            upstream,
        }
    }
}

/// What the accept handler has already established when it hands the
/// request to the cluster path: the state it answers from, the request
/// itself, who is accepting, and the RBAC state both permissions were
/// checked against.
#[cfg(feature = "postgres")]
pub(super) struct SuggestionAcceptContext<'a> {
    pub(super) state: &'a SuggestionsAdminState,
    pub(super) parts: &'a http::request::Parts,
    pub(super) principal: &'a auth::Principal,
    pub(super) rbac_state: &'a middleware::rbac::RbacState,
}

/// How many stream rows one durable poll fetches: large enough that a
/// replay catches up in few round trips, small enough that a slow client
/// buffers only a bounded slice.
#[cfg(feature = "postgres")]
pub(super) const DURABLE_STREAM_BATCH: usize = 64;

/// How long the durable stream sleeps between polls when the broadcast
/// wake-up is idle. Cross-replica events arrive without any local
/// notification, so polling -- not the broadcast channel -- is what makes
/// the stream correct; the wake-up only sharpens local-event latency.
#[cfg(feature = "postgres")]
pub(super) const DURABLE_STREAM_IDLE_POLL: std::time::Duration =
    std::time::Duration::from_millis(500);

// The `outcome` vocabulary of
// `greengateway_audit_stream_connections_total` (issue #241, PR 14): how a
// durable audit-stream connection attempt ended, one compile-time constant
// each. The `Last-Event-ID` value itself is caller-controlled and is never
// a label -- a client could otherwise mint a time series per reconnect by
// varying its header.
/// A live tail from the committed head: no `Last-Event-ID`.
#[cfg(feature = "postgres")]
pub(super) const AUDIT_STREAM_OUTCOME_LIVE: &str = "live";
/// A gapless replay resuming after the client's cursor.
#[cfg(feature = "postgres")]
pub(super) const AUDIT_STREAM_OUTCOME_REPLAY: &str = "replay";
/// The header was present but not a stream position.
#[cfg(feature = "postgres")]
pub(super) const AUDIT_STREAM_OUTCOME_CURSOR_INVALID: &str = "cursor_invalid";
/// The cursor predates the retained window; events the client never saw
/// have been pruned, so the replay it asked for cannot be gapless.
#[cfg(feature = "postgres")]
pub(super) const AUDIT_STREAM_OUTCOME_CURSOR_EXPIRED: &str = "cursor_expired";
/// The store could not be consulted; the stream fails closed rather than
/// falling back to the broadcast-only tail.
#[cfg(feature = "postgres")]
pub(super) const AUDIT_STREAM_OUTCOME_UNAVAILABLE: &str = "unavailable";

/// The whole vocabulary of the `outcome` label. Read by the registry
/// label audit; the five call sites pass their own constant.
#[cfg(feature = "postgres")]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const AUDIT_STREAM_OUTCOMES: [&str; 5] = [
    AUDIT_STREAM_OUTCOME_LIVE,
    AUDIT_STREAM_OUTCOME_REPLAY,
    AUDIT_STREAM_OUTCOME_CURSOR_INVALID,
    AUDIT_STREAM_OUTCOME_CURSOR_EXPIRED,
    AUDIT_STREAM_OUTCOME_UNAVAILABLE,
];

#[cfg(feature = "postgres")]
pub(super) enum DurableStreamStartError {
    /// The Last-Event-ID header was present but not an integer position.
    BadCursor,
    /// The client's cursor predates the retained window: events it has
    /// not seen were deleted, and replay can no longer be gapless.
    ExpiredCursor { cursor: i64, first_available: i64 },
    /// The store could not be consulted. An authority that cannot be
    /// consulted is a fail-closed condition, never a silent fallback to
    /// the broadcast-only stream (which would silently hide other
    /// replicas' committed events).
    Unavailable,
}

impl AuditQueryParams {
    pub(super) fn into_filters(self) -> Result<audit::query::AuditQueryFilters, &'static str> {
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
            actor_issuer: None,
            actor_auth_mode: None,
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
    pub(super) fn into_filters(
        self,
    ) -> Result<discovery::signals::SignalListFilters, &'static str> {
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
    pub(super) fn into_filters(
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
    pub(super) fn into_filters(self) -> Result<rbac::PolicyHistoryListFilters, &'static str> {
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
    pub(super) fn into_filters(self) -> Result<auth::tokens::TokenListFilters, &'static str> {
        Ok(auth::tokens::TokenListFilters {
            limit: parse_limit(self.limit)?,
            cursor: self.cursor,
        })
    }
}

impl CreatedTokenAdminResponse {
    pub(super) fn from_created(created: auth::tokens::CreatedToken) -> Self {
        Self {
            plaintext_token: created.plaintext_token,
            plaintext_token_notice: "Save this token now; the plaintext will not be shown again.",
            token: created.record,
        }
    }
}

pub(super) struct TrafficEndpointDetailQuery {
    pub(super) method: String,
    pub(super) endpoint_template: String,
    pub(super) new_since_hours: u64,
    pub(super) principal_limit: usize,
    pub(super) principal_cursor: Option<String>,
    pub(super) from: Option<String>,
    pub(super) to: Option<String>,
    pub(super) bucket: audit::query::EndpointAuditBucket,
    pub(super) events_limit: usize,
    pub(super) events_before_id: Option<i64>,
}

pub(super) struct TrafficEndpointListQuery {
    pub(super) filters: discovery::query::EndpointListFilters,
    pub(super) covered_by_rule: Option<bool>,
}

pub(super) struct PrincipalListQuery {
    pub(super) filters: auth::principal_directory::PrincipalDirectoryListFilters,
}

pub(super) struct PrincipalDetailQuery {
    pub(super) key: auth::principal_directory::PrincipalDirectoryKey,
}

impl TrafficEndpointListParams {
    pub(super) fn into_query(self) -> Result<TrafficEndpointListQuery, &'static str> {
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
    pub(super) fn into_query(self) -> Result<PrincipalListQuery, &'static str> {
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
    pub(super) fn into_query(self) -> Result<TrafficEndpointDetailQuery, &'static str> {
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
    pub(super) fn into_query(self) -> Result<PrincipalDetailQuery, &'static str> {
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
    pub(super) fn into_query(self) -> Result<InferredSchemaQuery, &'static str> {
        Ok(InferredSchemaQuery {
            method: required_non_empty("method", self.method)?,
            endpoint_template: required_non_empty("endpoint_template", self.endpoint_template)?,
        })
    }
}

impl AuditEventStreamParams {
    pub(super) fn matches(&self, event: &audit::AuditEvent) -> bool {
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

pub(super) enum TimedBodyReadError {
    DeadlineExceeded,
    Rejected(Box<Response>),
}

pub(super) struct ConnectionCollectionRuntimeData {
    pub(super) statuses:
        BTreeMap<connections::model::ConnectionId, connections::status::SafeConnectionStatus>,
    pub(super) status_revisions: BTreeMap<connections::model::ConnectionId, u64>,
    pub(super) dependency_counts: BTreeMap<connections::model::ConnectionId, usize>,
    pub(super) capability_counts: BTreeMap<connections::model::ConnectionId, usize>,
    pub(super) activity_times:
        BTreeMap<connections::model::ConnectionId, connections::store::ConnectionActivityTimes>,
}

pub(super) struct PreviewPathFilter {
    pub(super) exact: Option<String>,
    pub(super) prefix: Option<String>,
}

impl RulePatch {
    pub(super) fn is_empty(&self) -> bool {
        self.methods.is_none()
            && self.enabled.is_none()
            && self.path.is_none()
            && self.tool_name.is_none()
            && self.principal.is_none()
            && self.action.is_none()
    }
}

/// A rule-creating policy mutation, built and validated against the
/// current authoritative document but not yet written: the candidate a
/// commit installs, the ETag that commit must present, and where the new
/// rule sits in it.
///
/// Preparation and commit are separate steps because suggestion
/// acceptance in cluster mode (issue #241, PR 12) commits this candidate
/// INSIDE the suggestion's transaction rather than through
/// [`persist_policy_mutation`]. Both paths must build and validate the
/// candidate identically, so they share this.
pub(super) struct PreparedPolicyRuleCreate {
    pub(super) before_policy: rbac::Policy,
    /// What the commit must present as its compare-and-swap value.
    pub(super) current_etag: String,
    pub(super) candidate: rbac::Policy,
    pub(super) diff_summary: Value,
    /// Index of the created rule in the candidate's rule list.
    pub(super) position: usize,
    /// The created rule as the candidate holds it: the answer when a
    /// committed document somehow does not carry that position.
    pub(super) created_rule: rbac::Rule,
}

pub(super) enum RuleLookupError {
    NotFound,
    Ambiguous,
}
