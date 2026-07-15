use std::{sync::Arc, time::Instant};

use axum::{
    body::Body,
    extract::{Request as AxumRequest, State},
    response::{IntoResponse, Response},
};
use http::{header, request::Parts};
use rmcp::{
    model::{
        CallToolRequestParams, CallToolResult, CreateTaskResult, ErrorCode, ErrorData,
        Implementation, JsonObject, ListToolsResult, PaginatedRequestParams, ServerCapabilities,
        ServerInfo, Tool,
    },
    service::{RequestContext, RoleServer},
    transport::streamable_http_server::{
        session::never::NeverSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    },
    ServerHandler,
};
use serde_json::{json, Map, Value};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use crate::{
    auth, client_ip,
    egress::EgressResponse,
    tools::{
        definitions::{ToolDefinition, ToolRegistry},
        executor::{ToolExecutionResult, ToolExecutor, ToolExecutorError},
        runtime::{ToolInvocationContext, ToolRuntimeError},
    },
};

const TOOL_POLICY_DENIED_CODE: ErrorCode = ErrorCode(-32001);
const TOOL_RUNTIME_UNAVAILABLE_CODE: ErrorCode = ErrorCode(-32000);
const TOOL_TASK_UNSUPPORTED_REASON: &str = "task_unsupported";
const JSON_MIME: &str = "application/json";

type McpHttpService = StreamableHttpService<McpServer, NeverSessionManager>;

#[derive(Clone)]
pub(crate) struct McpState {
    service: McpHttpService,
}

impl McpState {
    pub(crate) fn new(
        registry: ToolRegistry,
        executor: Option<ToolExecutor>,
        client_ip_policy: client_ip::ClientIpPolicy,
    ) -> Self {
        let server = McpServer {
            registry,
            executor,
            client_ip_policy,
        };
        let config = StreamableHttpServerConfig::default()
            .with_stateful_mode(false)
            .with_json_response(true)
            .disable_allowed_hosts();

        Self {
            service: StreamableHttpService::new(
                move || Ok(server.clone()),
                Arc::new(NeverSessionManager::default()),
                config,
            ),
        }
    }
}

pub(crate) async fn mcp_endpoint(
    State(app): State<crate::AppState>,
    request: AxumRequest<Body>,
) -> Response {
    let (parts, body) = request.into_parts();
    let body = match crate::read_request_body(body, app.max_body_size).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request = AxumRequest::from_parts(parts, Body::from(body));

    match app.mcp.service.oneshot(request).await {
        Ok(response) => response.map(Body::new).into_response(),
        Err(error) => match error {},
    }
}

#[derive(Clone)]
struct McpServer {
    registry: ToolRegistry,
    executor: Option<ToolExecutor>,
    client_ip_policy: client_ip::ClientIpPolicy,
}

impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(
            Implementation::new("greengateway", env!("CARGO_PKG_VERSION"))
                .with_title("GreenGateway"),
        )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let invocation_context = invocation_context_from_request(&context, &self.client_ip_policy);
        let tools = self
            .registry
            .list()
            .into_iter()
            .filter(|definition| {
                self.executor.as_ref().is_none_or(|executor| {
                    executor.can_list_tool(&definition.name, &invocation_context)
                })
            })
            .map(|definition| mcp_tool_from_definition(definition.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let tool_name = request.name.to_string();
        let lookup_started = Instant::now();
        let invocation_context = invocation_context_from_request(&context, &self.client_ip_policy);

        if self.registry.get(&tool_name).is_none() {
            if let Some(executor) = self.executor.as_ref() {
                executor.record_unknown_tool_call(
                    &invocation_context,
                    &tool_name,
                    lookup_started.elapsed(),
                );
            }
            return Err(unknown_tool_error(&tool_name));
        }

        let Some(executor) = self.executor.as_ref() else {
            return Err(ErrorData::internal_error(
                "tool executor is not configured",
                Some(json!({ "tool_name": tool_name })),
            ));
        };

        let arguments = Value::Object(request.arguments.unwrap_or_default());

        match executor
            .execute(
                &tool_name,
                arguments,
                invocation_context,
                CancellationToken::new(),
            )
            .await
        {
            Ok(ToolExecutionResult::Http(response)) => {
                Ok(call_tool_result_from_egress_response(response))
            }
            Ok(ToolExecutionResult::McpCallToolResult(result)) => Ok(result),
            Err(error) => Err(runtime_error_to_mcp_error(error)),
        }
    }

    async fn enqueue_task(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CreateTaskResult, ErrorData> {
        let tool_name = request.name.to_string();
        let lookup_started = Instant::now();
        let invocation_context = invocation_context_from_request(&context, &self.client_ip_policy);

        if self.registry.get(&tool_name).is_none() {
            if let Some(executor) = self.executor.as_ref() {
                executor.record_unknown_tool_call(
                    &invocation_context,
                    &tool_name,
                    lookup_started.elapsed(),
                );
            }
            return Err(unknown_tool_error(&tool_name));
        }

        let Some(executor) = self.executor.as_ref() else {
            return Err(ErrorData::internal_error(
                "tool executor is not configured",
                Some(json!({ "tool_name": tool_name })),
            ));
        };

        match executor
            .reject_task_tool_call(invocation_context, &tool_name)
            .await
        {
            Ok(()) => Err(task_unsupported_error(tool_name)),
            Err(ToolRuntimeError::WorkFailed {
                tool_name,
                reason: Some(reason),
                ..
            }) if reason == TOOL_TASK_UNSUPPORTED_REASON => Err(task_unsupported_error(tool_name)),
            Err(error) => Err(runtime_error_to_mcp_error(error)),
        }
    }

    fn get_tool(&self, _name: &str) -> Option<Tool> {
        // rmcp uses this hook only for taskSupport prevalidation. GreenGateway
        // intentionally owns SEP-1319 task rejection so rejected task calls feed
        // the same audit/inventory path as ordinary tool calls.
        None
    }
}

fn mcp_tool_from_definition(definition: &ToolDefinition) -> Result<Tool, ErrorData> {
    let Some(input_schema) = json_object_from_value(&definition.input_schema) else {
        return Err(ErrorData::internal_error(
            "tool input schema must be a JSON object",
            Some(json!({ "tool_name": definition.name })),
        ));
    };

    Ok(Tool::new(
        definition.name.clone(),
        definition.description.clone(),
        Arc::new(input_schema),
    ))
}

fn json_object_from_value(value: &Value) -> Option<JsonObject> {
    match value {
        Value::Object(map) => Some(map.clone()),
        _ => None,
    }
}

fn invocation_context_from_request(
    context: &RequestContext<RoleServer>,
    client_ip_policy: &client_ip::ClientIpPolicy,
) -> ToolInvocationContext {
    let Some(parts) = context.extensions.get::<Parts>() else {
        return ToolInvocationContext::default();
    };

    ToolInvocationContext {
        request_id: client_ip::request_id(&parts.headers, &parts.extensions),
        source_ip: client_ip::canonical_client_ip(
            &parts.headers,
            &parts.extensions,
            client_ip_policy,
        ),
        actor: parts
            .extensions
            .get::<auth::Principal>()
            .map(auth::actor_from_principal),
    }
}

fn call_tool_result_from_egress_response(response: EgressResponse) -> CallToolResult {
    let body = if response.status.is_success() {
        response_body_value(&response)
    } else {
        sanitized_error_body_value(&response)
    };
    let result = json!({
        "status": response.status.as_u16(),
        "body": body,
    });

    if response.status.is_success() {
        CallToolResult::structured(result)
    } else {
        CallToolResult::structured_error(result)
    }
}

fn response_body_value(response: &EgressResponse) -> Value {
    if response_is_json(response) {
        if let Ok(value) = serde_json::from_slice(&response.body) {
            return value;
        }
    }

    Value::String(String::from_utf8_lossy(&response.body).into_owned())
}

fn response_is_json(response: &EgressResponse) -> bool {
    response
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            let media_type = value.split(';').next().map(str::trim).unwrap_or_default();
            media_type.eq_ignore_ascii_case(JSON_MIME)
                || media_type.to_ascii_lowercase().ends_with("+json")
        })
}

const MAX_ERROR_TEXT_CHARS: usize = 512;
const MAX_ERROR_ARRAY_ITEMS: usize = 8;
const MAX_ERROR_OBJECT_FIELDS: usize = 16;
const MAX_ERROR_NESTING_DEPTH: usize = 4;
const REDACTED: &str = "[redacted]";

fn sanitized_error_body_value(response: &EgressResponse) -> Value {
    if response_is_json(response) {
        if let Ok(body) = serde_json::from_slice::<Value>(&response.body) {
            match body {
                Value::Object(body) => {
                    let mut sanitized = Map::new();
                    for key in [
                        "type",
                        "title",
                        "code",
                        "error",
                        "error_code",
                        "message",
                        "detail",
                        "details",
                        "errors",
                    ] {
                        if let Some(value) = body.get(key) {
                            sanitized
                                .insert(key.to_owned(), sanitize_error_json_value(key, value, 0));
                        }
                    }

                    return if sanitized.is_empty() {
                        generic_upstream_error_body()
                    } else {
                        Value::Object(sanitized)
                    };
                }
                Value::String(value) => {
                    return Value::String(sanitize_error_text(&value, MAX_ERROR_TEXT_CHARS));
                }
                _ => return generic_upstream_error_body(),
            }
        }
    }

    Value::String(sanitize_error_text(
        &String::from_utf8_lossy(&response.body),
        MAX_ERROR_TEXT_CHARS,
    ))
}

fn generic_upstream_error_body() -> Value {
    json!({ "summary": "upstream returned an error response" })
}

fn sanitize_error_json_value(key: &str, value: &Value, depth: usize) -> Value {
    if sensitive_json_key(key) {
        return Value::String(REDACTED.to_owned());
    }

    if depth >= MAX_ERROR_NESTING_DEPTH {
        return Value::String("[omitted]".to_owned());
    }

    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => value.clone(),
        Value::String(value) => Value::String(sanitize_error_text(value, MAX_ERROR_TEXT_CHARS)),
        Value::Array(values) => Value::Array(
            values
                .iter()
                .take(MAX_ERROR_ARRAY_ITEMS)
                .map(|value| sanitize_error_json_value("", value, depth + 1))
                .collect(),
        ),
        Value::Object(values) => {
            let mut sanitized = Map::new();
            for (key, value) in values.iter().take(MAX_ERROR_OBJECT_FIELDS) {
                let sanitized_key = sanitize_error_text(key, 80);
                sanitized.insert(
                    sanitized_key,
                    sanitize_error_json_value(key, value, depth + 1),
                );
            }
            Value::Object(sanitized)
        }
    }
}

fn sanitize_error_text(value: &str, max_chars: usize) -> String {
    let (truncated, was_truncated) = truncate_chars(value, max_chars);
    let redacted = redact_sensitive_tokens(&truncated);

    if was_truncated {
        format!("{redacted}...[truncated]")
    } else {
        redacted
    }
}

fn truncate_chars(value: &str, max_chars: usize) -> (String, bool) {
    let mut chars = value.chars();
    let truncated = chars.by_ref().take(max_chars).collect::<String>();
    let was_truncated = chars.next().is_some();

    (truncated, was_truncated)
}

fn redact_sensitive_tokens(value: &str) -> String {
    let mut redacted = String::with_capacity(value.len());
    let mut token = String::new();

    for ch in value.chars() {
        if is_error_token_char(ch) {
            token.push(ch);
        } else {
            push_redacted_token(&mut redacted, &mut token);
            redacted.push(ch);
        }
    }
    push_redacted_token(&mut redacted, &mut token);

    redacted
}

fn push_redacted_token(redacted: &mut String, token: &mut String) {
    if token.is_empty() {
        return;
    }

    if sensitive_error_token(token) {
        redacted.push_str(REDACTED);
    } else {
        redacted.push_str(token);
    }
    token.clear();
}

fn is_error_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric()
        || matches!(
            ch,
            '.' | '-' | '_' | ':' | '/' | '?' | '&' | '=' | '%' | '+' | '@'
        )
}

fn sensitive_json_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("authorization")
        || key.contains("credential")
        || key.contains("password")
        || key.contains("secret")
        || key.contains("session")
        || key.contains("cookie")
        || key.contains("api_key")
        || key.contains("apikey")
        || key.ends_with("token")
        || key.contains("_token")
}

fn sensitive_error_token(token: &str) -> bool {
    let token = token
        .trim_matches(|ch: char| matches!(ch, '"' | '\'' | ',' | ';' | ')' | '(' | '[' | ']'))
        .to_ascii_lowercase();

    token.starts_with("http://")
        || token.starts_with("https://")
        || token.starts_with("sk_")
        || token.starts_with("pk_")
        || token.starts_with("ghp_")
        || token.starts_with("github_pat_")
        || token.starts_with("xoxb-")
        || token.starts_with("xoxp-")
        || token.contains("secret=")
        || token.contains("token=")
        || token.contains("password=")
        || token.contains("api_key=")
        || token.contains("apikey=")
        || token.contains(".internal")
        || token.contains("internal.")
        || token.ends_with(".local")
}

fn runtime_error_to_mcp_error(error: ToolRuntimeError) -> ErrorData {
    match error {
        ToolRuntimeError::UnknownTool { tool_name } => unknown_tool_error(&tool_name),
        ToolRuntimeError::Disabled { tool_name } => {
            policy_denied_error(tool_name, "tool is disabled by policy", "disabled", None)
        }
        ToolRuntimeError::RoleDenied {
            tool_name,
            allowed_roles,
        } => policy_denied_error(
            tool_name,
            "tool invocation is denied by role policy",
            "role_denied",
            Some(json!({ "allowed_roles": allowed_roles })),
        ),
        ToolRuntimeError::Rejected { tool_name, reason } => policy_denied_error(
            tool_name,
            "tool invocation was rejected by runtime policy",
            "rejected",
            Some(json!({ "reason": reason })),
        ),
        ToolRuntimeError::QueueTimeout { tool_name } => runtime_unavailable_error(
            tool_name,
            "tool invocation timed out while waiting for admission",
            "queue_timeout",
        ),
        ToolRuntimeError::Timeout { tool_name } => runtime_unavailable_error(
            tool_name,
            "tool invocation timed out during execution",
            "timeout",
        ),
        ToolRuntimeError::Cancelled { tool_name } => {
            runtime_unavailable_error(tool_name, "tool invocation was cancelled", "cancelled")
        }
        ToolRuntimeError::WorkFailed {
            tool_name,
            message,
            reason,
        } => {
            let executor_error = classify_executor_work_failure(reason.as_deref(), &message);
            match executor_error {
                ExecutorWorkFailure::InvalidParams => {
                    ErrorData::invalid_params(message, Some(json!({ "tool_name": tool_name })))
                }
                ExecutorWorkFailure::UnknownTool => unknown_tool_error(&tool_name),
                ExecutorWorkFailure::Internal { reason } => ErrorData::internal_error(
                    "tool invocation failed",
                    Some(json!({ "tool_name": tool_name, "reason": reason })),
                ),
            }
        }
    }
}

fn unknown_tool_error(tool_name: &str) -> ErrorData {
    ErrorData::new(
        ErrorCode::METHOD_NOT_FOUND,
        format!("tool '{tool_name}' is not defined"),
        Some(json!({ "tool_name": tool_name })),
    )
}

fn task_unsupported_error(tool_name: String) -> ErrorData {
    ErrorData::invalid_params(
        "task-based tool invocation is not supported by GreenGateway",
        Some(json!({
            "tool_name": tool_name,
            "reason": TOOL_TASK_UNSUPPORTED_REASON,
        })),
    )
}

fn policy_denied_error(
    tool_name: String,
    message: &'static str,
    reason: &'static str,
    extra_data: Option<Value>,
) -> ErrorData {
    let mut data = json!({
        "tool_name": tool_name,
        "reason": reason,
    });

    if let Some(Value::Object(extra)) = extra_data {
        let Value::Object(data_object) = &mut data else {
            unreachable!("data is always an object");
        };
        data_object.extend(extra);
    }

    ErrorData::new(TOOL_POLICY_DENIED_CODE, message, Some(data))
}

fn runtime_unavailable_error(
    tool_name: String,
    message: &'static str,
    reason: &'static str,
) -> ErrorData {
    ErrorData::new(
        TOOL_RUNTIME_UNAVAILABLE_CODE,
        message,
        Some(json!({
            "tool_name": tool_name,
            "reason": reason,
        })),
    )
}

enum ExecutorWorkFailure {
    UnknownTool,
    InvalidParams,
    Internal { reason: String },
}

fn classify_executor_work_failure(reason: Option<&str>, message: &str) -> ExecutorWorkFailure {
    match reason {
        Some("unknown_tool") => return ExecutorWorkFailure::UnknownTool,
        Some("invalid_params") => return ExecutorWorkFailure::InvalidParams,
        Some(reason) => {
            return ExecutorWorkFailure::Internal {
                reason: reason.to_owned(),
            };
        }
        None => {}
    }

    if message.contains("is not defined in the tool registry") {
        return ExecutorWorkFailure::UnknownTool;
    }

    if message.contains("input schema")
        || message.contains("missing required")
        || message.contains("must be a string, number, or boolean")
        || message.contains("must not be a dot segment")
    {
        return ExecutorWorkFailure::InvalidParams;
    }

    ExecutorWorkFailure::Internal {
        reason: "internal_error".to_owned(),
    }
}

pub(crate) fn mcp_executor_from_config(
    config: &crate::config::Config,
    registry: ToolRegistry,
    runtime: crate::tools::runtime::ToolRuntime,
    egress_client: Arc<crate::egress::EgressClient>,
    audit: crate::audit::AuditLog,
) -> Result<Option<ToolExecutor>, ToolExecutorError> {
    if registry.list().is_empty() {
        return Ok(None);
    }

    ToolExecutor::from_config(config, registry, runtime, egress_client, audit).map(Some)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::{
        audit::{self, AuditSink},
        config,
        discovery::{self, suggestions::DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS},
        egress,
        tools::runtime::ToolRuntime,
    };

    #[test]
    fn empty_registry_does_not_configure_mcp_executor() {
        let config = test_config();
        let registry = ToolRegistry::disabled();
        let runtime = ToolRuntime::new(Default::default(), test_audit_log());
        let egress_client = Arc::new(
            egress::EgressClient::new(egress::EgressConfig::from_config(&config))
                .expect("test egress client should build"),
        );

        let executor =
            mcp_executor_from_config(&config, registry, runtime, egress_client, test_audit_log())
                .expect("empty registry should be a valid no-executor configuration");

        assert!(
            executor.is_none(),
            "empty registry intentionally skips inventory persistence because no executor/audit path exists"
        );
    }

    #[tokio::test]
    async fn empty_registry_tool_call_returns_unknown_tool_without_executor() {
        let state = McpState::new(
            ToolRegistry::disabled(),
            None,
            client_ip::ClientIpPolicy::default(),
        );
        let request = AxumRequest::builder()
            .method(http::Method::POST)
            .uri("/mcp")
            .header(header::HOST, "localhost")
            .header(header::CONTENT_TYPE, JSON_MIME)
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2025-11-25")
            .body(Body::from(
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "missing_tool",
                        "arguments": {}
                    }
                })
                .to_string(),
            ))
            .expect("MCP request should build");

        let response = state
            .service
            .clone()
            .oneshot(request)
            .await
            .expect("MCP service should respond")
            .map(Body::new);
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("MCP error body should be readable");
        let body: Value = serde_json::from_slice(&body).unwrap_or_else(|err| {
            panic!(
                "MCP response body should be JSON, status={status}, body={:?}: {err}",
                String::from_utf8_lossy(&body)
            )
        });

        assert_eq!(body["error"]["code"], json!(ErrorCode::METHOD_NOT_FOUND.0));
        assert_eq!(
            body["error"]["message"],
            json!("tool 'missing_tool' is not defined")
        );
        assert_eq!(body["error"]["data"]["tool_name"], json!("missing_tool"));
    }

    #[derive(Clone)]
    struct NoopSink;

    impl AuditSink for NoopSink {
        fn emit(&self, _event: &audit::AuditEvent) {}
    }

    fn test_audit_log() -> audit::AuditLog {
        audit::AuditLog::new(Arc::new(NoopSink))
    }

    fn test_config() -> config::Config {
        config::Config {
            listen_addr: "127.0.0.1:0"
                .parse::<SocketAddr>()
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
            rule_suggestion_baseline_window_hours: DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
            openapi_spec_path: None,
            policy_file: None,
            tools_file: None,
            policy_history_sqlite_path: None,
            cors_allow_origins: Vec::new(),
            max_body_size: 1_048_576,
            rate_limit_read_rps: 50.0,
            rate_limit_read_burst: 100,
            rate_limit_write_rps: 10.0,
            rate_limit_write_burst: 20,
            trust_proxy_headers: false,
            trusted_proxy_cidrs: Vec::new(),
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
            egress_nat64_prefixes: Vec::new(),
            egress_deny_private_ips: true,
        }
    }
}
