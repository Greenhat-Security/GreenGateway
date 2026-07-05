use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Request as AxumRequest, State},
    response::{IntoResponse, Response},
};
use http::{header, request::Parts};
use rmcp::{
    model::{
        CallToolRequestParams, CallToolResult, ErrorCode, ErrorData, Implementation, JsonObject,
        ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo, Tool,
    },
    service::{RequestContext, RoleServer},
    transport::streamable_http_server::{
        session::never::NeverSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    },
    ServerHandler,
};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use crate::{
    auth, client_ip,
    egress::EgressResponse,
    tools::{
        definitions::{ToolDefinition, ToolRegistry},
        executor::{ToolExecutor, ToolExecutorError},
        runtime::{ToolInvocationContext, ToolRuntimeError},
    },
};

const TOOL_POLICY_DENIED_CODE: ErrorCode = ErrorCode(-32001);
const TOOL_RUNTIME_UNAVAILABLE_CODE: ErrorCode = ErrorCode(-32000);
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
        trust_proxy_headers: bool,
    ) -> Self {
        let server = McpServer {
            registry,
            executor,
            trust_proxy_headers,
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
    match app.mcp.service.oneshot(request).await {
        Ok(response) => response.map(Body::new).into_response(),
        Err(error) => match error {},
    }
}

#[derive(Clone)]
struct McpServer {
    registry: ToolRegistry,
    executor: Option<ToolExecutor>,
    trust_proxy_headers: bool,
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
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let tools = self
            .registry
            .list()
            .into_iter()
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

        if self.registry.get(&tool_name).is_none() {
            return Err(unknown_tool_error(&tool_name));
        }

        let Some(executor) = self.executor.as_ref() else {
            return Err(ErrorData::internal_error(
                "tool executor is not configured",
                Some(json!({ "tool_name": tool_name })),
            ));
        };

        let arguments = Value::Object(request.arguments.unwrap_or_default());
        let invocation_context =
            invocation_context_from_request(&context, self.trust_proxy_headers);

        match executor
            .execute(
                &tool_name,
                arguments,
                invocation_context,
                CancellationToken::new(),
            )
            .await
        {
            Ok(response) => Ok(call_tool_result_from_egress_response(response)),
            Err(error) => Err(runtime_error_to_mcp_error(error)),
        }
    }

    fn get_tool(&self, name: &str) -> Option<Tool> {
        self.registry
            .get(name)
            .and_then(|definition| mcp_tool_from_definition(definition.as_ref()).ok())
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
    trust_proxy_headers: bool,
) -> ToolInvocationContext {
    let Some(parts) = context.extensions.get::<Parts>() else {
        return ToolInvocationContext::default();
    };

    ToolInvocationContext {
        request_id: client_ip::request_id(&parts.headers, &parts.extensions),
        source_ip: client_ip::canonical_client_ip(
            &parts.headers,
            &parts.extensions,
            trust_proxy_headers,
        ),
        actor: parts
            .extensions
            .get::<auth::Principal>()
            .map(auth::actor_from_principal),
    }
}

fn call_tool_result_from_egress_response(response: EgressResponse) -> CallToolResult {
    let body = response_body_value(&response);
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
        })
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
        ToolRuntimeError::WorkFailed { tool_name, message } => {
            let executor_error = classify_executor_work_failure(&message);
            match executor_error {
                ExecutorWorkFailure::InvalidParams => {
                    ErrorData::invalid_params(message, Some(json!({ "tool_name": tool_name })))
                }
                ExecutorWorkFailure::UnknownTool => unknown_tool_error(&tool_name),
                ExecutorWorkFailure::Internal => ErrorData::internal_error(
                    "tool invocation failed",
                    Some(json!({ "tool_name": tool_name, "message": message })),
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
    Internal,
}

fn classify_executor_work_failure(message: &str) -> ExecutorWorkFailure {
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

    ExecutorWorkFailure::Internal
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
