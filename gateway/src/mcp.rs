use std::{borrow::Cow, fmt, future::Future, pin::Pin, sync::Arc, time::Instant};

use axum::{
    body::Body,
    extract::{Request as AxumRequest, State},
    response::{IntoResponse, Response},
};
use http::{header, request::Parts};
use rmcp::{
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ErrorCode, ErrorData,
        Implementation, JsonObject, ListToolsResult, PaginatedRequestParams, ProtocolVersion,
        ServerCapabilities, ServerConfig, Tool,
    },
    service::{RequestContext, RoleServer},
    transport::streamable_http_server::{
        session::never::NeverSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    },
    ServerHandler,
};
use serde::{
    de::{IgnoredAny, MapAccess, Visitor},
    Deserialize,
};
use serde_json::{json, Map, Value};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use crate::{
    auth, client_ip,
    connections::caller_assertion::AttestedCaller,
    egress::EgressResponse,
    tools::{
        definitions::{ToolDefinition, ToolRegistry},
        executor::{
            HttpToolExecutionResult, ToolConnectionRuntimes, ToolExecutionResult, ToolExecutor,
            ToolExecutorError,
        },
        runtime::{ToolInvocationContext, ToolInvocationSource, ToolRuntimeError},
    },
};

const TOOL_POLICY_DENIED_CODE: ErrorCode = ErrorCode(-32001);
const TOOL_RUNTIME_UNAVAILABLE_CODE: ErrorCode = ErrorCode(-32000);
const TOOL_TASK_UNSUPPORTED_REASON: &str = "task_unsupported";
const JSON_MIME: &str = "application/json";

/// The newest MCP revision `/mcp` serves. rmcp 3 also implements 2026-07-28,
/// whose per-request `_meta` lifecycle, SEP-2549 cache hints on the
/// per-caller `tools/list`, input-required results and HTTP status mapping
/// have not been reviewed for this gateway. `initialize` therefore still
/// agrees only on 2024-11-05 through 2025-11-25, and a request naming
/// 2026-07-28 in its `_meta` is refused as an unsupported version.
const MAX_SERVED_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::V_2025_11_25;

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
        max_body_size: usize,
    ) -> Self {
        let server = McpServer {
            registry,
            executor,
            client_ip_policy,
        };
        // `mcp_endpoint` reads the body under MAX_BODY_SIZE before rmcp sees
        // it. rmcp 3 added its own 4 MiB default, which would refuse bodies a
        // larger configured limit admits, so it gets the same limit.
        let config = StreamableHttpServerConfig::default()
            .with_legacy_session_mode(false)
            .with_json_response(true)
            .with_max_request_body_bytes(max_body_size)
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
    let (mut parts, body) = request.into_parts();
    let body = match crate::read_request_body(body, app.max_body_size).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    if is_task_augmented_tool_call(&body) {
        parts.extensions.insert(TaskAugmentedToolCall);
    }
    let request = AxumRequest::from_parts(parts, Body::from(body));

    match app.mcp.service.oneshot(request).await {
        Ok(response) => response.map(Body::new).into_response(),
        Err(error) => match error {},
    }
}

/// Marks a `tools/call` whose params carry a SEP-1319 `task` member.
///
/// MCP 2025-11-25 lets a client ask for a tool call to run as a task. rmcp 2
/// routed such a call to `ServerHandler::enqueue_task`, which GreenGateway
/// answers with an audited `task_unsupported` rejection. rmcp 3 replaced
/// SEP-1319 with the SEP-2663 tasks extension and no longer parses `task`, so
/// the same call would run synchronously and return an ordinary result to a
/// client that asked for a task. The endpoint classifies the body before rmcp
/// parses it and `call_tool` keeps refusing the call.
#[derive(Clone, Copy, Debug)]
struct TaskAugmentedToolCall;

/// Whether `body` is a `tools/call` request with a non-null `params.task`.
///
/// Any non-null value counts, including one rmcp 2 could not parse as task
/// metadata: such a call is refused, never run. Repeated members are all
/// read, because rmcp ignores the `task` member it no longer knows however
/// often it occurs: a call any copy of which asks for a task is refused. A
/// body this cannot read counts as well. rmcp rejects such a body before any
/// tool runs, and a call it did accept would still be refused, not run.
fn is_task_augmented_tool_call(body: &[u8]) -> bool {
    serde_json::from_slice::<TaskCallProbe>(body)
        .map_or(true, |probe| probe.names_tools_call && probe.carries_task)
}

/// The members of a JSON-RPC request `is_task_augmented_tool_call` reads,
/// collected without materializing the body.
#[derive(Default)]
struct TaskCallProbe {
    /// Some `method` member is `"tools/call"`.
    names_tools_call: bool,
    /// Some `params` member has a non-null `task`.
    carries_task: bool,
}

impl<'de> Deserialize<'de> for TaskCallProbe {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(TaskCallProbeVisitor)
    }
}

struct TaskCallProbeVisitor;

impl<'de> Visitor<'de> for TaskCallProbeVisitor {
    type Value = TaskCallProbe;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON-RPC request object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut probe = TaskCallProbe::default();
        while let Some(member) = map.next_key::<ProbeWord>()? {
            match member {
                ProbeWord::Method => {
                    probe.names_tools_call |=
                        map.next_value::<ProbeWord>()? == ProbeWord::ToolsCall;
                }
                ProbeWord::Params => {
                    let params = map.next_value::<Option<TaskParamsProbe>>()?;
                    probe.carries_task |= params.is_some_and(|params| params.carries_task);
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(probe)
    }
}

/// Whether some `task` member of a `params` object is non-null.
struct TaskParamsProbe {
    carries_task: bool,
}

impl<'de> Deserialize<'de> for TaskParamsProbe {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(TaskParamsProbeVisitor)
    }
}

struct TaskParamsProbeVisitor;

impl<'de> Visitor<'de> for TaskParamsProbeVisitor {
    type Value = TaskParamsProbe;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON-RPC params object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut carries_task = false;
        while let Some(member) = map.next_key::<ProbeWord>()? {
            if member == ProbeWord::Task {
                carries_task |= map.next_value::<Option<IgnoredAny>>()?.is_some();
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(TaskParamsProbe { carries_task })
    }
}

/// A member name or `method` value the probes look for, compared unescaped
/// as rmcp reads it. Other strings are not kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeWord {
    Method,
    Params,
    Task,
    ToolsCall,
    Other,
}

impl<'de> Deserialize<'de> for ProbeWord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(ProbeWordVisitor)
    }
}

struct ProbeWordVisitor;

impl Visitor<'_> for ProbeWordVisitor {
    type Value = ProbeWord;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(match value {
            "method" => ProbeWord::Method,
            "params" => ProbeWord::Params,
            "task" => ProbeWord::Task,
            "tools/call" => ProbeWord::ToolsCall,
            _ => ProbeWord::Other,
        })
    }
}

fn is_task_augmented_request(context: &RequestContext<RoleServer>) -> bool {
    context
        .extensions
        .get::<Parts>()
        .is_some_and(|parts| parts.extensions.get::<TaskAugmentedToolCall>().is_some())
}

#[derive(Clone)]
struct McpServer {
    registry: ToolRegistry,
    executor: Option<ToolExecutor>,
    client_ip_policy: client_ip::ClientIpPolicy,
}

impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerConfig {
        // The protocol version here is what `initialize` falls back to when a
        // client names one this server does not support.
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(MAX_SERVED_PROTOCOL_VERSION)
            .with_server_info(
                Implementation::new("greengateway", env!("CARGO_PKG_VERSION"))
                    .with_title("GreenGateway"),
            )
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(ProtocolVersion::known_up_to(&MAX_SERVED_PROTOCOL_VERSION))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        // Fail closed: without an executor there is no runtime to evaluate
        // `enabled`, allowed_roles/issuers/auth_methods or tool deny rules
        // against, so advertising the registry would publish tool names,
        // descriptions and input schemas the policy conceals.
        let Some(executor) = self.executor.as_ref() else {
            return Ok(ListToolsResult::with_all_items(Vec::new()));
        };
        let invocation_context = invocation_context_from_request(&context, &self.client_ip_policy);
        // rmcp serves this request from a task it spawned, which the snapshots
        // the revision gate pinned for the HTTP request do not reach. Re-enter
        // them so the registry and every visibility check read the admitted
        // revision rather than the live lanes. Without such pins (standalone
        // mode) the executor still judges the whole listing by one policy
        // snapshot and one registry read (#422).
        let request_extensions = context
            .extensions
            .get::<Parts>()
            .map(|parts| &parts.extensions);
        crate::middleware::rbac::with_request_pins(request_extensions, async {
            let tools = executor
                .list_visible_tools(&invocation_context)
                .await
                .iter()
                .map(|definition| {
                    let served = executor
                        .served_definition(definition.as_ref())
                        .map_err(|_| {
                            ErrorData::internal_error(
                                "tool input schema could not be prepared",
                                Some(json!({ "tool_name": definition.name })),
                            )
                        })?;
                    mcp_tool_from_definition(served.definition.as_ref())
                })
                .collect::<Result<Vec<_>, _>>()?;

            Ok::<_, ErrorData>(ListToolsResult::with_all_items(tools))
        })
        .await
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let lookup_started = Instant::now();
        let invocation_context = invocation_context_from_request(&context, &self.client_ip_policy);
        // As in `list_tools`: the lookup, the invocation and the rendered
        // request are judged by the revision the HTTP request was admitted
        // at, never by one a reconcile installed while it was in flight. A
        // rejected task call is still admitted, audited and observed under it.
        let request_extensions = context
            .extensions
            .get::<Parts>()
            .map(|parts| &parts.extensions);
        if is_task_augmented_request(&context) {
            let rejection = crate::middleware::rbac::with_request_pins(
                request_extensions,
                self.reject_task_call_work(request, lookup_started, invocation_context),
            )
            .await;
            return Err(rejection);
        }
        crate::middleware::rbac::with_request_pins(
            request_extensions,
            self.call_tool_work(request, lookup_started, invocation_context),
        )
        .await
        .map(CallToolResponse::Complete)
    }

    fn get_tool(&self, _name: &str) -> Option<Tool> {
        // rmcp uses this hook for SEP-2243 `Mcp-Param-*` header validation on
        // 2026-07-28 requests, which this server does not serve. GreenGateway
        // owns task rejection (`TaskAugmentedToolCall`) so rejected task calls
        // feed the same audit/inventory path as ordinary tool calls.
        None
    }
}

/// The work of `call_tool`, ordinary or rejected as a task, which it runs
/// under the request's pins. Each is built in a stack frame of its own and
/// boxed: the tool executor's future is large, and every layer that pins it
/// would otherwise hold, and in unoptimized builds copy across the stack, a
/// whole instance of it.
impl McpServer {
    fn call_tool_work(
        &self,
        request: CallToolRequestParams,
        lookup_started: Instant,
        invocation_context: ToolInvocationContext,
    ) -> Pin<Box<dyn Future<Output = Result<CallToolResult, ErrorData>> + Send + '_>> {
        Box::pin(async move {
            let tool_name = request.name.to_string();

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
            let composite_error_context =
                executor
                    .is_composite(&tool_name)
                    .then(|| CompositeRuntimeErrorContext {
                        request_id: invocation_context.request_id.clone(),
                    });

            match executor
                .execute(
                    &tool_name,
                    arguments,
                    invocation_context,
                    CancellationToken::new(),
                )
                .await
            {
                Ok(ToolExecutionResult::Http(result)) => {
                    Ok(call_tool_result_from_http_execution(result))
                }
                Ok(ToolExecutionResult::McpCallToolResult(result)) => Ok(result),
                Ok(ToolExecutionResult::Composite(result)) => {
                    Ok(CallToolResult::structured(json!({
                        "status": http::StatusCode::OK.as_u16(),
                        "body": result.body,
                    })))
                }
                Err(error) => Err(runtime_error_to_mcp_error(error, composite_error_context)),
            }
        })
    }

    fn reject_task_call_work(
        &self,
        request: CallToolRequestParams,
        lookup_started: Instant,
        invocation_context: ToolInvocationContext,
    ) -> Pin<Box<dyn Future<Output = ErrorData> + Send + '_>> {
        Box::pin(async move {
            let tool_name = request.name.to_string();

            if self.registry.get(&tool_name).is_none() {
                if let Some(executor) = self.executor.as_ref() {
                    executor.record_unknown_tool_call(
                        &invocation_context,
                        &tool_name,
                        lookup_started.elapsed(),
                    );
                }
                return unknown_tool_error(&tool_name);
            }

            let Some(executor) = self.executor.as_ref() else {
                return ErrorData::internal_error(
                    "tool executor is not configured",
                    Some(json!({ "tool_name": tool_name })),
                );
            };

            match executor
                .reject_task_tool_call(invocation_context, &tool_name)
                .await
            {
                Ok(()) => task_unsupported_error(tool_name),
                Err(ToolRuntimeError::WorkFailed {
                    tool_name,
                    reason: Some(reason),
                    ..
                }) if reason == TOOL_TASK_UNSUPPORTED_REASON => task_unsupported_error(tool_name),
                Err(error) => runtime_error_to_mcp_error(error, None),
            }
        })
    }
}

fn mcp_tool_from_definition(definition: &ToolDefinition) -> Result<Tool, ErrorData> {
    let Some(input_schema) = json_object_from_value(&definition.input_schema) else {
        return Err(ErrorData::internal_error(
            "tool input schema must be a JSON object",
            Some(json!({ "tool_name": definition.name })),
        ));
    };

    let mut tool = Tool::new(
        definition.name.clone(),
        definition.description.clone(),
        Arc::new(input_schema),
    );
    tool.title = definition.title.clone();
    tool.annotations = definition.annotations.clone().map(Into::into);
    Ok(tool)
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
        return ToolInvocationContext {
            source: ToolInvocationSource::Mcp,
            ..ToolInvocationContext::default()
        };
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
        caller: parts
            .extensions
            .get::<auth::Principal>()
            .and_then(AttestedCaller::from_principal)
            .map(Arc::new),
        source: ToolInvocationSource::Mcp,
        admitted_deadline: None,
    }
}

fn call_tool_result_from_http_execution(result: HttpToolExecutionResult) -> CallToolResult {
    let HttpToolExecutionResult { response, warnings } = result;
    let body = if response.status.is_success() {
        response_body_value(&response)
    } else {
        sanitized_error_body_value(&response)
    };
    let mut result = json!({
        "status": response.status.as_u16(),
        "body": body,
    });
    if !warnings.is_empty() {
        result["warnings"] = json!(warnings);
    }

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
                        "messages",
                        "statusCode",
                        "detail",
                        "details",
                        "errors",
                    ] {
                        if let Some(value) = body.get(key) {
                            let value = match (key, value) {
                                ("messages", Value::Array(values)) => Value::Array(
                                    values
                                        .iter()
                                        .take(MAX_ERROR_ARRAY_ITEMS)
                                        .filter_map(Value::as_str)
                                        .map(|value| {
                                            Value::String(sanitize_error_text(
                                                value,
                                                MAX_ERROR_TEXT_CHARS,
                                            ))
                                        })
                                        .collect(),
                                ),
                                ("statusCode", Value::Number(_)) => value.clone(),
                                ("messages" | "statusCode", _) => continue,
                                _ => sanitize_error_json_value(key, value, 0),
                            };
                            sanitized.insert(key.to_owned(), value);
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
    // An opaque credential has no recognizable prefix. Withhold diagnostics
    // naming authorization or common credential schemes instead of guessing
    // where an upstream's free-form credential value ends. Inspect before
    // truncating so the context cannot be separated from an earlier value.
    if value
        .split(|ch: char| !ch.is_ascii_alphabetic())
        .any(|word| {
            word.eq_ignore_ascii_case("authorization")
                || word.eq_ignore_ascii_case("bearer")
                || word.eq_ignore_ascii_case("basic")
        })
    {
        return REDACTED.to_owned();
    }
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

struct CompositeRuntimeErrorContext {
    request_id: String,
}

fn runtime_error_to_mcp_error(
    error: ToolRuntimeError,
    composite: Option<CompositeRuntimeErrorContext>,
) -> ErrorData {
    match error {
        ToolRuntimeError::UnknownTool { tool_name } => unknown_tool_error(&tool_name),
        ToolRuntimeError::Disabled { tool_name } => {
            policy_denied_error(tool_name, "tool is disabled by policy", "disabled", None)
        }
        // `allowed_roles` is deliberately not echoed back: `tools/list` hides
        // exactly the tools whose role policy the caller fails, so returning the
        // role names here would hand that caller the policy the filter conceals.
        // The rejection is still audited with the actor, tool and reason.
        ToolRuntimeError::RoleDenied { tool_name, .. } => policy_denied_error(
            tool_name,
            "tool invocation is denied by role policy",
            "role_denied",
            None,
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
            None,
        ),
        ToolRuntimeError::Timeout { tool_name } => runtime_unavailable_error(
            tool_name,
            "tool invocation timed out during execution",
            "timeout",
            composite.as_ref(),
        ),
        ToolRuntimeError::Cancelled { tool_name } => runtime_unavailable_error(
            tool_name,
            "tool invocation was cancelled",
            "cancelled",
            composite.as_ref(),
        ),
        ToolRuntimeError::AuthorityUnavailable { tool_name } => runtime_unavailable_error(
            tool_name,
            "tool invocation could not be admitted: the execution lease authority is unavailable",
            "authority_unavailable",
            None,
        ),
        ToolRuntimeError::LeaseLost { tool_name } => runtime_unavailable_error(
            tool_name,
            "tool invocation lost its execution lease",
            "lease_lost",
            composite.as_ref(),
        ),
        ToolRuntimeError::WorkFailed {
            tool_name,
            message,
            reason,
            details,
        } => {
            let details = details.map(|details| {
                if matches!(
                    reason.as_deref(),
                    Some("composite_failed" | "composite_failed_compensation_incomplete")
                ) {
                    crate::tools::playground::project_composite_failure_details(details)
                } else {
                    details
                }
            });
            let executor_error = classify_executor_work_failure(reason.as_deref(), &message);
            match executor_error {
                ExecutorWorkFailure::InvalidParams => {
                    ErrorData::invalid_params(message, Some(work_failure_data(tool_name, details)))
                }
                ExecutorWorkFailure::UnknownTool => unknown_tool_error(&tool_name),
                ExecutorWorkFailure::Internal { reason } => ErrorData::internal_error(
                    "tool invocation failed",
                    Some(work_failure_internal_data(tool_name, reason, details)),
                ),
            }
        }
    }
}

fn work_failure_data(tool_name: String, details: Option<Value>) -> Value {
    let mut data = Map::from_iter([("tool_name".to_owned(), Value::String(tool_name))]);
    match details {
        Some(Value::Object(details)) => {
            for (key, value) in details {
                if key != "tool_name" {
                    data.insert(key, value);
                }
            }
        }
        Some(details) => {
            data.insert("details".to_owned(), details);
        }
        None => {}
    }
    Value::Object(data)
}

fn work_failure_internal_data(tool_name: String, reason: String, details: Option<Value>) -> Value {
    let mut data = match work_failure_data(tool_name, details) {
        Value::Object(data) => data,
        _ => unreachable!("work failure data is always an object"),
    };
    data.insert("reason".to_owned(), Value::String(reason));
    Value::Object(data)
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
    composite: Option<&CompositeRuntimeErrorContext>,
) -> ErrorData {
    let mut data = json!({
        "tool_name": tool_name,
        "reason": reason,
    });
    if let Some(composite) = composite {
        data["request_id"] = json!(composite.request_id);
        data["composite"] = json!("pending_compensation");
    }
    ErrorData::new(TOOL_RUNTIME_UNAVAILABLE_CODE, message, Some(data))
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
    connection_runtimes: ToolConnectionRuntimes,
    audit: crate::audit::AuditLog,
) -> Result<Option<ToolExecutor>, ToolExecutorError> {
    // The executor is built once and cached in `McpState`, but the registry it
    // reads is an `ArcSwap` shared with the TOOLS_FILE watcher and the admin
    // tools API. An empty registry at startup therefore says nothing about what
    // `/mcp` will serve later, so the executor is always built: skipping it left
    // `list_tools` with no runtime to check visibility against and made every
    // `tools/call` fail until the process was restarted.
    ToolExecutor::from_config(
        config,
        registry,
        runtime,
        egress_client,
        connection_runtimes,
        audit,
    )
    .map(Some)
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Duration};

    use rmcp::model::{ClientJsonRpcMessage, ClientRequest};

    use super::*;
    use crate::{
        audit::{self, AuditSink},
        config,
        discovery::{self, suggestions::DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS},
        egress,
        tools::{
            definitions::{ToolSource, UpstreamMapping},
            runtime::{ToolRuntime, ToolRuntimeConfig, ToolRuntimeToolConfig},
        },
    };

    const VISIBLE_TOOL: &str = "public_probe";
    const RESTRICTED_TOOL: &str = "payroll_export";
    const COMPOSITE_ONLY_TOOL: &str = "composite_step";
    const PRIVILEGED_ROLE: &str = "payroll-admin";
    /// The default MAX_BODY_SIZE, which `mcp_endpoint` enforces before rmcp.
    const TEST_MAX_BODY_SIZE: usize = 1_048_576;

    #[test]
    fn composite_runtime_error_carries_request_id_and_pending_compensation_marker() {
        for error in [
            ToolRuntimeError::Timeout {
                tool_name: "workflow".to_owned(),
            },
            ToolRuntimeError::Cancelled {
                tool_name: "workflow".to_owned(),
            },
            ToolRuntimeError::LeaseLost {
                tool_name: "workflow".to_owned(),
            },
        ] {
            let error = runtime_error_to_mcp_error(
                error,
                Some(CompositeRuntimeErrorContext {
                    request_id: "request-composite-runtime".to_owned(),
                }),
            );
            let data = error.data.expect("runtime error should carry data");
            assert_eq!(data["request_id"], json!("request-composite-runtime"));
            assert_eq!(data["composite"], json!("pending_compensation"));
        }
    }

    #[test]
    fn composite_failure_is_internal_error_with_bounded_safe_orphans() {
        let credential_canary = "FAKE_mcp_composite_credential";
        let orphans = (0..crate::tools::playground::MAX_COMPOSITE_FAILURE_ORPHANS + 2)
            .map(|iteration| {
                json!({
                    "step": "attach",
                    "iteration": iteration,
                    "tool": "createOneNoteTarget",
                    "certainty": "confirmed",
                    "reason": "compensation_status:500",
                    "upstream_status": 500,
                    "wire_body": credential_canary
                })
            })
            .collect::<Vec<_>>();
        let error = runtime_error_to_mcp_error(
            ToolRuntimeError::WorkFailed {
                tool_name: "create_note_for_records".to_owned(),
                message: "composite execution failed".to_owned(),
                reason: Some("composite_failed_compensation_incomplete".to_owned()),
                details: Some(json!({
                    "tool_name": "create_note_for_records",
                    "request_id": "request-composite-failure",
                    "reason": "composite_failed_compensation_incomplete",
                    "failed_step": "attach",
                    "failed_iteration": 2,
                    "failure_reason": "upstream_status:400",
                    "compensation": "incomplete",
                    "orphans": orphans,
                    "upstream_body": credential_canary
                })),
            },
            None,
        );

        assert_eq!(error.code, ErrorCode(-32603));
        let data = error.data.expect("composite failure should carry data");
        assert_eq!(
            data["orphans"].as_array().map(Vec::len),
            Some(crate::tools::playground::MAX_COMPOSITE_FAILURE_ORPHANS)
        );
        assert_eq!(data["orphans_truncated"], json!(true));
        assert_eq!(data["request_id"], json!("request-composite-failure"));
        let encoded = data.to_string();
        assert!(!encoded.contains(credential_canary));
        assert!(!encoded.contains("wire_body"));
        assert!(!encoded.contains("upstream_body"));
    }

    #[test]
    fn empty_registry_still_configures_mcp_executor() {
        let config = test_config();
        let registry = ToolRegistry::disabled();
        let runtime = ToolRuntime::new(Default::default(), test_audit_log());
        let egress_client = Arc::new(
            egress::EgressClient::new(egress::EgressConfig::from_config(&config))
                .expect("test egress client should build"),
        );

        let executor = mcp_executor_from_config(
            &config,
            registry,
            runtime,
            egress_client,
            ToolConnectionRuntimes::default(),
            test_audit_log(),
        )
        .expect("empty registry should still be a valid executor configuration");

        assert!(
            executor.is_some(),
            "the registry can gain tools through hot reload, so the executor must exist even when startup sees none"
        );
    }

    #[test]
    fn http_error_messages_keep_string_and_array_limits_and_redaction() {
        let long_message = format!("{}discarded tail", "é".repeat(MAX_ERROR_TEXT_CHARS));
        let mut messages = vec![json!(long_message); MAX_ERROR_ARRAY_ITEMS + 1];
        messages[0] =
            json!("filter failed at https://api.example.test with secret=FAKE_error_token");
        messages[MAX_ERROR_ARRAY_ITEMS] = json!("discarded ninth message");
        let result = call_tool_result_from_http_execution(HttpToolExecutionResult {
            response: error_response(json!({
                "statusCode": 422,
                "error": "BadRequestException",
                "messages": messages,
                "debug": "discarded diagnostics"
            })),
            warnings: Vec::new(),
        });

        assert_eq!(result.is_error, Some(true));
        let content = result.structured_content.expect("structured error result");
        assert_eq!(content["status"], json!(400));
        assert_eq!(content["body"]["statusCode"], json!(422));
        assert_eq!(content["body"]["error"], json!("BadRequestException"));
        let messages = content["body"]["messages"]
            .as_array()
            .expect("messages array");
        assert_eq!(messages.len(), MAX_ERROR_ARRAY_ITEMS);
        assert_eq!(
            messages[0],
            json!("filter failed at [redacted] with [redacted]")
        );
        for message in &messages[1..] {
            assert_eq!(
                message,
                &json!(format!(
                    "{}...[truncated]",
                    "é".repeat(MAX_ERROR_TEXT_CHARS)
                ))
            );
        }
        let serialized = serde_json::to_string(&result.content).expect("text content serializes");
        for discarded in ["discarded", "api.example.test", "FAKE_error_token"] {
            assert!(!content.to_string().contains(discarded));
            assert!(!serialized.contains(discarded));
        }
    }

    #[test]
    fn http_error_authorization_diagnostics_are_withheld_in_both_result_forms() {
        let canary = uuid::Uuid::new_v4().simple().to_string();
        for diagnostic in [
            format!("Authorization: Bearer {canary}"),
            format!("proxy-AUTHORIZATION: Basic {canary}"),
            format!("rejected bEaReR\t{canary}"),
            format!("{canary}{} authorization diagnostic", "x".repeat(600)),
        ] {
            let result = call_tool_result_from_http_execution(HttpToolExecutionResult {
                response: error_response(json!({
                    "messages": [diagnostic, "filter must be an object"],
                    "message": diagnostic,
                    "statusCode": 400
                })),
                warnings: Vec::new(),
            });
            let body = &result.structured_content.as_ref().unwrap()["body"];
            assert_eq!(
                body["messages"],
                json!([REDACTED, "filter must be an object"])
            );
            assert_eq!(body["message"], json!(REDACTED));
            assert!(!body.to_string().contains(&canary));
            assert!(!serde_json::to_string(&result.content)
                .unwrap()
                .contains(&canary));
        }
    }

    #[test]
    fn http_error_messages_and_status_code_drop_unexpected_types() {
        let sanitized = sanitized_error_body_value(&error_response(json!({
            "messages": ["valid", {"message": "nested"}, ["nested"], null, true, 400, "also valid"],
            "statusCode": {"message": "nested status"}
        })));
        assert_eq!(sanitized, json!({"messages": ["valid", "also valid"]}));

        for malformed in [
            Value::Null,
            json!(true),
            json!("400"),
            json!([400]),
            json!({}),
        ] {
            let sanitized = sanitized_error_body_value(&error_response(json!({
                "messages": "not an array",
                "statusCode": malformed,
                "debug": "discarded diagnostics"
            })));
            assert_eq!(sanitized, generic_upstream_error_body());
        }
    }

    fn error_response(body: Value) -> EgressResponse {
        EgressResponse {
            status: http::StatusCode::BAD_REQUEST,
            headers: http::HeaderMap::from_iter([(
                header::CONTENT_TYPE,
                http::HeaderValue::from_static(JSON_MIME),
            )]),
            body: serde_json::to_vec(&body).expect("error body serializes"),
        }
    }

    #[test]
    fn http_transform_warnings_are_optional_in_mcp_structured_content() {
        let response = || EgressResponse {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::from_iter([(
                header::CONTENT_TYPE,
                http::HeaderValue::from_static(JSON_MIME),
            )]),
            body: br#"{"amount":24000}"#.to_vec(),
        };

        let plain = call_tool_result_from_http_execution(HttpToolExecutionResult {
            response: response(),
            warnings: Vec::new(),
        });
        assert_eq!(
            plain.structured_content,
            Some(json!({"status": 200, "body": {"amount": 24000}}))
        );

        let warned = call_tool_result_from_http_execution(HttpToolExecutionResult {
            response: response(),
            warnings: vec![crate::tools::transforms::TransformWarning {
                path: "/data/company/annualRecurringRevenue".to_owned(),
                reason: "wire value must match the canonical integer grammar".to_owned(),
            }],
        });
        assert_eq!(
            warned
                .structured_content
                .as_ref()
                .and_then(|content| content.get("warnings")),
            Some(&json!([{
                "path": "/data/company/annualRecurringRevenue",
                "reason": "wire value must match the canonical integer grammar",
            }]))
        );
    }

    #[test]
    fn transformed_http_body_and_warnings_have_mcp_playground_parity() {
        let response = || EgressResponse {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::from_iter([(
                header::CONTENT_TYPE,
                http::HeaderValue::from_static(JSON_MIME),
            )]),
            body: br#"{"amount":24000,"currency":"USD"}"#.to_vec(),
        };
        let warnings = || {
            vec![crate::tools::transforms::TransformWarning {
                path: "/data/company/annualRecurringRevenue".to_owned(),
                reason: "wire value must match the canonical integer grammar".to_owned(),
            }]
        };

        let mcp = call_tool_result_from_http_execution(HttpToolExecutionResult {
            response: response(),
            warnings: warnings(),
        })
        .structured_content
        .expect("MCP HTTP result should carry structured content");
        let playground = crate::tools::playground::project_tool_execution_result(
            ToolExecutionResult::Http(HttpToolExecutionResult {
                response: response(),
                warnings: warnings(),
            }),
        )
        .expect("playground should project the same executor result");

        assert_eq!(mcp["status"], playground["status"]);
        assert_eq!(mcp["body"], playground["body"]["value"]);
        assert_eq!(mcp["warnings"], playground["warnings"]);
    }

    #[test]
    fn transform_rejection_details_are_preserved_in_mcp_invalid_params() {
        let error = runtime_error_to_mcp_error(
            ToolRuntimeError::WorkFailed {
                tool_name: "createCompany".to_owned(),
                message: "tool 'createCompany' argument 'amount' could not be encoded".to_owned(),
                reason: Some("invalid_params".to_owned()),
                details: Some(json!({
                    "problems": [{
                        "path": "/amount",
                        "keyword": "codec",
                        "reason": "value has 7 fraction digits, codec allows 6",
                    }],
                })),
            },
            None,
        );

        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
        assert_eq!(
            error.data,
            Some(json!({
                "tool_name": "createCompany",
                "problems": [{
                    "path": "/amount",
                    "keyword": "codec",
                    "reason": "value has 7 fraction digits, codec allows 6",
                }],
            }))
        );
    }

    #[test]
    fn enum_validation_failure_preserves_exact_allowed_values_in_mcp_data() {
        let error = runtime_error_to_mcp_error(
            ToolRuntimeError::WorkFailed {
                tool_name: "set_status".to_owned(),
                message: "tool 'set_status' arguments failed input schema validation".to_owned(),
                reason: Some("invalid_params".to_owned()),
                details: Some(json!({
                    "problems": [{
                        "path": "/status",
                        "keyword": "enum",
                        "allowed": ["Active", "Paused"],
                        "message": "value is not one of the allowed values"
                    }]
                })),
            },
            None,
        );

        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
        assert_eq!(
            error
                .data
                .as_ref()
                .and_then(|data| data.pointer("/problems/0/path")),
            Some(&json!("/status"))
        );
        assert_eq!(
            error
                .data
                .as_ref()
                .and_then(|data| data.pointer("/problems/0/allowed")),
            Some(&json!(["Active", "Paused"]))
        );
    }

    #[tokio::test]
    async fn hot_reloaded_tools_are_still_filtered_by_visibility_policy() {
        let (state, registry) = mcp_state_from_empty_registry();
        registry
            .merge_definitions(vec![
                legacy_tool_definition(VISIBLE_TOOL),
                legacy_tool_definition(RESTRICTED_TOOL),
            ])
            .expect("hot-reloaded definitions should register");

        let body = mcp_json_rpc(&state, 1, "tools/list", None).await;
        let listed = listed_tool_names(&body);

        assert!(
            listed.iter().any(|name| name == VISIBLE_TOOL),
            "an unrestricted tool must stay listed, otherwise this test would also pass if the filter hid everything: {listed:?}"
        );
        assert!(
            !listed.iter().any(|name| name == RESTRICTED_TOOL),
            "a tool restricted to '{PRIVILEGED_ROLE}' must not be advertised to a caller without that role: {listed:?}"
        );
    }

    #[tokio::test]
    async fn transformed_tool_advertises_agent_schema_and_validates_it_over_mcp() {
        let (state, registry) = mcp_state_from_empty_registry();
        registry
            .merge_definitions(vec![transformed_visible_tool_definition()])
            .expect("transformed definition should register");

        let listed = mcp_json_rpc(&state, 20, "tools/list", None).await;
        let tool = listed["result"]["tools"]
            .as_array()
            .and_then(|tools| {
                tools
                    .iter()
                    .find(|tool| tool["name"] == json!(VISIBLE_TOOL))
            })
            .unwrap_or_else(|| panic!("transformed tool should be listed: {listed}"));
        assert_eq!(
            tool["inputSchema"]["properties"]["amount"]["type"],
            "number"
        );
        assert_eq!(
            tool["inputSchema"]["properties"]["currency"]["type"],
            "string"
        );
        assert!(tool["inputSchema"]["properties"]
            .get("annualRecurringRevenue")
            .is_none());

        let wire_shaped = mcp_json_rpc(
            &state,
            21,
            "tools/call",
            Some(json!({
                "name": VISIBLE_TOOL,
                "arguments": {
                    "annualRecurringRevenue": {
                        "amountMicros": "24000000000",
                        "currencyCode": "USD"
                    }
                }
            })),
        )
        .await;
        assert_eq!(
            wire_shaped["error"]["code"],
            json!(ErrorCode::INVALID_PARAMS.0),
            "wire-facing arguments must not bypass the agent schema: {wire_shaped}"
        );

        let inexact = mcp_json_rpc(
            &state,
            22,
            "tools/call",
            Some(json!({
                "name": VISIBLE_TOOL,
                "arguments": {"amount": 24000.1234567, "currency": "USD"}
            })),
        )
        .await;
        assert_eq!(inexact["error"]["code"], json!(ErrorCode::INVALID_PARAMS.0));
        assert_eq!(inexact["error"]["data"]["problems"][0]["path"], "/amount");
        assert_eq!(inexact["error"]["data"]["problems"][0]["keyword"], "codec");
    }

    #[tokio::test]
    async fn composite_only_tool_is_neither_listed_nor_callable_over_mcp() {
        let (state, registry) = mcp_state_from_empty_registry();
        registry
            .merge_definitions(vec![composite_only_tool_definition()])
            .expect("composite-only definition should register");

        let list_body = mcp_json_rpc(&state, 10, "tools/list", None).await;
        assert!(
            !listed_tool_names(&list_body)
                .iter()
                .any(|name| name == COMPOSITE_ONLY_TOOL),
            "tools/list must not disclose composite-only tool metadata: {list_body}"
        );

        let call_body = mcp_json_rpc(
            &state,
            11,
            "tools/call",
            Some(json!({ "name": COMPOSITE_ONLY_TOOL, "arguments": {} })),
        )
        .await;
        assert_eq!(
            call_body["error"]["code"],
            json!(ErrorCode::METHOD_NOT_FOUND.0),
            "a hidden tool must be indistinguishable from a missing tool: {call_body}"
        );
        assert_eq!(
            call_body["error"]["message"],
            json!(format!("tool '{COMPOSITE_ONLY_TOOL}' is not defined"))
        );
        assert_eq!(
            call_body["error"]["data"]["tool_name"],
            json!(COMPOSITE_ONLY_TOOL)
        );
    }

    #[tokio::test]
    async fn tools_list_advertises_nothing_without_an_executor() {
        let registry = ToolRegistry::disabled();
        registry
            .merge_definitions(vec![legacy_tool_definition(RESTRICTED_TOOL)])
            .expect("definitions should register");
        let state = McpState::new(
            registry,
            None,
            client_ip::ClientIpPolicy::default(),
            TEST_MAX_BODY_SIZE,
        );

        let body = mcp_json_rpc(&state, 2, "tools/list", None).await;

        assert_eq!(
            body["result"]["tools"],
            json!([]),
            "without an executor there is no runtime to evaluate visibility, so nothing may be advertised"
        );
    }

    #[tokio::test]
    async fn initialize_agrees_on_the_revisions_served_before_rmcp_3() {
        let (state, _registry) = mcp_state_from_empty_registry();
        // A client may name any revision with a handshake and gets it back.
        // 2026-07-28 has no handshake, and an unknown revision is not served,
        // so both get the newest served one, as rmcp 3's own clients expect.
        for (requested, agreed) in [
            ("2024-11-05", "2024-11-05"),
            ("2025-03-26", "2025-03-26"),
            ("2025-06-18", "2025-06-18"),
            ("2025-11-25", "2025-11-25"),
            ("2026-07-28", "2025-11-25"),
            ("2099-01-01", "2025-11-25"),
        ] {
            let (status, body) = mcp_json_rpc_status_and_body(
                &state,
                mcp_json_rpc_request_at(
                    1,
                    "initialize",
                    Some(json!({
                        "protocolVersion": requested,
                        "capabilities": {},
                        "clientInfo": { "name": "negotiation-test", "version": "0.0.0" }
                    })),
                    None,
                ),
            )
            .await;

            assert_eq!(status, http::StatusCode::OK, "{requested}: {body}");
            assert_eq!(
                body["result"]["protocolVersion"],
                json!(agreed),
                "{requested}: {body}"
            );
            assert_eq!(
                body["result"]["serverInfo"]["name"],
                json!("greengateway"),
                "{requested}: {body}"
            );
        }
    }

    #[tokio::test]
    async fn requests_naming_the_2026_07_28_revision_are_refused_without_serving_tools() {
        let (state, registry) = mcp_state_from_empty_registry();
        registry
            .merge_definitions(vec![legacy_tool_definition(VISIBLE_TOOL)])
            .expect("definitions should register");
        let modern_meta = json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        });

        // Self-contained 2026-07-28 requests, with the SEP-2243 method header
        // such clients send, are an unsupported revision.
        let modern_request = |id, method: &str, params: Option<Value>| {
            let mut request = mcp_json_rpc_request_at(id, method, params, Some("2026-07-28"));
            request.headers_mut().insert(
                "Mcp-Method",
                http::HeaderValue::from_str(method).expect("method header should encode"),
            );
            request
        };
        for method in ["tools/list", "server/discover"] {
            let (status, body) = mcp_json_rpc_status_and_body(
                &state,
                modern_request(3, method, Some(modern_meta.clone())),
            )
            .await;
            assert_eq!(status, http::StatusCode::BAD_REQUEST, "{method}: {body}");
            assert_eq!(body["error"]["code"], json!(-32022), "{method}: {body}");
            assert_eq!(
                body["error"]["data"]["supported"],
                json!(["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"]),
                "{method}: {body}"
            );
            assert!(body.get("result").is_none(), "{method}: {body}");
        }

        // rmcp 2 served a request whose only 2026-07-28 signal was the
        // header with 2025-11-25 semantics. rmcp 3 refuses it as malformed:
        // without the SEP-2243 headers, and without the `_meta` lifecycle.
        let (status, body) = mcp_json_rpc_status_and_body(
            &state,
            mcp_json_rpc_request_at(4, "tools/list", None, Some("2026-07-28")),
        )
        .await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], json!(-32020), "{body}");
        assert!(body.get("result").is_none(), "{body}");
        let (status, body) =
            mcp_json_rpc_status_and_body(&state, modern_request(4, "tools/list", None)).await;
        assert_eq!(status, http::StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"]["code"], json!(-32602), "{body}");
        assert!(body.get("result").is_none(), "{body}");

        // The same tool stays listed for the revisions that are served.
        let body = mcp_json_rpc(&state, 5, "tools/list", None).await;
        assert_eq!(listed_tool_names(&body), vec![VISIBLE_TOOL.to_owned()]);
        assert!(
            body["result"].get("ttlMs").is_none() && body["result"].get("cacheScope").is_none(),
            "2025-11-25 results carry no SEP-2549 cache hints: {body}"
        );
        assert!(
            body["result"].get("resultType").is_none(),
            "2025-11-25 results carry no resultType: {body}"
        );
    }

    #[tokio::test]
    async fn posted_json_rpc_responses_are_refused_and_notifications_accepted() {
        let (state, _registry) = mcp_state_from_empty_registry();
        let post = |payload: Value| {
            AxumRequest::builder()
                .method(http::Method::POST)
                .uri("/mcp")
                .header(header::HOST, "localhost")
                .header(header::CONTENT_TYPE, JSON_MIME)
                .header(header::ACCEPT, "application/json, text/event-stream")
                .header("MCP-Protocol-Version", "2025-11-25")
                .body(Body::from(payload.to_string()))
                .expect("MCP request should build")
        };

        // `/mcp` is stateless and sends the client no requests, so a JSON-RPC
        // response or error answers nothing. rmcp 3.6 refuses one with 400 and
        // an invalid-request error that names no id; rmcp 3.5 accepted it.
        for payload in [
            json!({"jsonrpc": "2.0", "id": 7, "result": {}}),
            json!({"jsonrpc": "2.0", "id": 7, "error": {"code": -32603, "message": "failed"}}),
        ] {
            let (status, body) = mcp_json_rpc_status_and_body(&state, post(payload.clone())).await;
            assert_eq!(status, http::StatusCode::BAD_REQUEST, "{payload}: {body}");
            assert_eq!(body["error"]["code"], json!(-32600), "{payload}: {body}");
            assert!(
                body.get("id").is_none_or(Value::is_null),
                "{payload}: {body}"
            );
            assert!(body.get("result").is_none(), "{payload}: {body}");
        }

        // A notification is still accepted without a body.
        let response = state
            .service
            .clone()
            .oneshot(post(
                json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            ))
            .await
            .expect("MCP service should respond");
        assert_eq!(response.status(), http::StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn json_rpc_messages_are_classified_by_their_members() {
        let (state, _registry) = mcp_state_from_empty_registry();
        let post = |payload: Value| {
            AxumRequest::builder()
                .method(http::Method::POST)
                .uri("/mcp")
                .header(header::HOST, "localhost")
                .header(header::CONTENT_TYPE, JSON_MIME)
                .header(header::ACCEPT, "application/json, text/event-stream")
                .header("MCP-Protocol-Version", "2025-11-25")
                .body(Body::from(payload.to_string()))
                .expect("MCP request should build")
        };

        // rmcp 3.6 classifies a message by its members before parsing it, so
        // a request that also carries `result` or `error`, or a message with
        // both, is no JSON-RPC message at all and is refused.
        for payload in [
            json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list", "result": {}}),
            json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list",
                   "error": {"code": -32603, "message": "failed"}}),
            json!({"jsonrpc": "2.0", "id": 7, "result": {},
                   "error": {"code": -32603, "message": "failed"}}),
        ] {
            let response = state
                .service
                .clone()
                .oneshot(post(payload.clone()))
                .await
                .expect("MCP service should respond")
                .map(Body::new);
            assert!(
                response.status().is_client_error(),
                "{payload}: {}",
                response.status()
            );
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("MCP response body should be readable");
            let body = serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null);
            assert!(body.get("result").is_none(), "{payload}: {body}");
        }

        // rmcp 3.6 reads an integral request id written in float form as that
        // integer, and the answer carries the integer.
        let (status, body) = mcp_json_rpc_status_and_body(
            &state,
            post(json!({"jsonrpc": "2.0", "id": 7.0, "method": "tools/list"})),
        )
        .await;
        assert_eq!(status, http::StatusCode::OK, "{body}");
        assert_eq!(body["id"], json!(7), "{body}");
        assert_eq!(body["result"]["tools"], json!([]), "{body}");
    }

    #[test]
    fn task_augmented_tool_calls_are_recognized_before_rmcp_parses_them() {
        for body in [
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "echo", "task": {}}}),
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "echo", "task": {"ttl": 60000}}}),
            // rmcp 2 could not parse this task metadata; it is still refused.
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "echo", "task": "later"}}),
        ] {
            assert!(
                is_task_augmented_tool_call(body.to_string().as_bytes()),
                "{body}"
            );
        }
        // Escaped names and values are read as rmcp reads them, and every
        // copy of a repeated member counts. rmcp ignores `task` however often
        // it occurs, so it would run these calls as ordinary ones.
        for body in [
            r#"{"jsonrpc":"2.0","id":1,"method":"tools\/call","params":{"name":"echo","task":{}}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","t\u0061sk":{}}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","task":{},"task":null}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","task":null,"task":{}}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","task":{},"task":{}}}"#,
        ] {
            assert!(is_task_augmented_tool_call(body.as_bytes()), "{body}");
            assert!(
                matches!(
                    serde_json::from_str::<ClientJsonRpcMessage>(body),
                    Ok(ClientJsonRpcMessage::Request(request))
                        if matches!(request.request, ClientRequest::CallToolRequest(_))
                ),
                "rmcp should route {body} as a tools/call"
            );
        }

        for body in [
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "echo", "arguments": {"task": {}}}}),
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "echo", "task": null}}),
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "echo", "_meta": {"task": {}}}}),
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list",
                   "params": {"task": {}}}),
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "task": {},
                   "params": {"name": "echo"}}),
        ] {
            assert!(
                !is_task_augmented_tool_call(body.to_string().as_bytes()),
                "{body}"
            );
        }

        // A body the probe cannot read counts as a task call. rmcp rejects
        // each of these before any tool runs.
        for body in [
            "not json".to_owned(),
            json!([{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": "echo"}}])
            .to_string(),
            json!({"jsonrpc": "2.0", "id": 1, "method": 7, "params": {"name": "echo"}}).to_string(),
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": ["echo"]})
                .to_string(),
        ] {
            assert!(is_task_augmented_tool_call(body.as_bytes()), "{body}");
            assert!(
                serde_json::from_str::<ClientJsonRpcMessage>(&body).is_err(),
                "rmcp should reject {body}"
            );
        }
    }

    #[tokio::test]
    async fn mcp_service_admits_bodies_up_to_the_configured_limit_above_the_rmcp_default() {
        // rmcp 3 refuses bodies over 4 MiB unless told otherwise; MAX_BODY_SIZE
        // may admit more, and `mcp_endpoint` has already enforced it.
        let configured_limit = 6 * 1024 * 1024;
        let state = McpState::new(
            ToolRegistry::disabled(),
            None,
            client_ip::ClientIpPolicy::default(),
            configured_limit,
        );
        let padding = "x".repeat(5 * 1024 * 1024);

        let (status, body) = mcp_json_rpc_status_and_body(
            &state,
            mcp_json_rpc_request(
                6,
                "tools/list",
                Some(json!({ "_meta": { "padding": padding } })),
            ),
        )
        .await;

        assert_eq!(status, http::StatusCode::OK);
        assert_eq!(body["result"]["tools"], json!([]));
    }

    #[tokio::test]
    async fn role_denied_tool_call_does_not_disclose_allowed_roles() {
        let (state, registry) = mcp_state_from_empty_registry();
        registry
            .merge_definitions(vec![legacy_tool_definition(RESTRICTED_TOOL)])
            .expect("definitions should register");

        let body = mcp_json_rpc(
            &state,
            3,
            "tools/call",
            Some(json!({ "name": RESTRICTED_TOOL, "arguments": {} })),
        )
        .await;

        // Pin the denial reason first: without it this test would also pass on an
        // earlier rejection that never reaches the role check.
        assert_eq!(
            body["error"]["code"],
            json!(TOOL_POLICY_DENIED_CODE.0),
            "{body}"
        );
        assert_eq!(
            body["error"]["data"]["reason"],
            json!("role_denied"),
            "{body}"
        );
        assert_eq!(
            body["error"]["data"]["tool_name"],
            json!(RESTRICTED_TOOL),
            "{body}"
        );
        assert_eq!(
            body["error"]["data"]["allowed_roles"],
            Value::Null,
            "a role-denied error must not echo the policy role names that tools/list conceals"
        );
    }

    #[tokio::test]
    async fn empty_registry_tool_call_returns_unknown_tool_without_executor() {
        let state = McpState::new(
            ToolRegistry::disabled(),
            None,
            client_ip::ClientIpPolicy::default(),
            TEST_MAX_BODY_SIZE,
        );

        let body = mcp_json_rpc(
            &state,
            1,
            "tools/call",
            Some(json!({ "name": "missing_tool", "arguments": {} })),
        )
        .await;

        assert_eq!(body["error"]["code"], json!(ErrorCode::METHOD_NOT_FOUND.0));
        assert_eq!(
            body["error"]["message"],
            json!("tool 'missing_tool' is not defined")
        );
        assert_eq!(body["error"]["data"]["tool_name"], json!("missing_tool"));
    }

    /// Standalone mode has no revision gate, so there are no request pins to
    /// re-enter: the executor pins the listing itself (#422). The hook below
    /// installs the next policy, through the file reload standalone serves,
    /// and the next local registry lane right after the first tool's
    /// visibility is decided, so the rest of the listing runs after both
    /// installs. The first snapshot shows only `alpha`: it denies `beta`, and
    /// its registry lists `gamma` as composite-only. The next shows only `beta`
    /// and `gamma`: it denies `alpha` and lists `gamma`. A listing that asked
    /// the live policy again would show `alpha` beside `beta`, and one that
    /// read the registry again would show `alpha` beside `gamma`, which no
    /// single snapshot shows together.
    #[tokio::test]
    async fn a_policy_installed_midway_through_a_standalone_listing_never_answers_part_of_it() {
        let policy_denying = |tool_name: &str| {
            json!({
                "schema_version": "0.1.0",
                "default_action": "allow",
                "tools": {
                    "alpha": { "timeout_ms": 5000, "max_concurrent": 2 },
                    "beta": { "timeout_ms": 5000, "max_concurrent": 2 },
                    "gamma": { "timeout_ms": 5000, "max_concurrent": 2 }
                },
                "rules": [{
                    "id": format!("deny-{tool_name}"),
                    "tool_name": tool_name,
                    "action": "deny"
                }]
            })
            .to_string()
        };
        let definitions = |gamma_visibility| {
            let mut gamma = legacy_tool_definition("gamma");
            gamma.visibility = gamma_visibility;
            vec![
                legacy_tool_definition("alpha"),
                legacy_tool_definition("beta"),
                gamma,
            ]
        };
        let file = TempPolicyFile::new(&policy_denying("beta"));
        let first_policy =
            crate::rbac::Policy::from_file(&file.path).expect("the first policy should parse");
        let audit = test_audit_log();
        let rbac_state = crate::middleware::rbac::RbacState::new(
            first_policy.clone(),
            Vec::new(),
            false,
            audit.clone(),
        );
        let runtime = ToolRuntime::new_with_rbac_state(
            ToolRuntimeConfig::from_policy(&first_policy)
                .expect("the first policy should configure the runtime"),
            audit.clone(),
            Some(rbac_state.clone()),
        );
        let registry = ToolRegistry::disabled();
        registry
            .merge_definitions(definitions(
                crate::tools::definitions::ToolVisibility::CompositeOnly,
            ))
            .expect("the first registry lane registers");

        let checked = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let installed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook: crate::tools::executor::ListingHook = {
            let checked = Arc::clone(&checked);
            let rbac_state = rbac_state.clone();
            let registry = registry.clone();
            let policy_path = file.path.clone();
            let next_policy = policy_denying("alpha");
            let next_definitions = definitions(crate::tools::definitions::ToolVisibility::Listed);
            Arc::new(
                move |tool_name: &str| -> crate::tools::executor::ListingHookFuture {
                    checked
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(tool_name.to_owned());
                    let install = (tool_name == "alpha"
                        && !installed.swap(true, std::sync::atomic::Ordering::SeqCst))
                    .then(|| {
                        (
                            rbac_state.clone(),
                            registry.clone(),
                            policy_path.clone(),
                            next_policy.clone(),
                            next_definitions.clone(),
                        )
                    });
                    Box::pin(async move {
                        let Some((
                            rbac_state,
                            registry,
                            policy_path,
                            next_policy,
                            next_definitions,
                        )) = install
                        else {
                            return;
                        };
                        std::fs::write(&policy_path, next_policy)
                            .expect("the next policy should be written");
                        crate::middleware::rbac::reload_policy_from_file(&rbac_state, &policy_path)
                            .await
                            .expect("the next policy installs midway through the listing");
                        registry
                            .install_local_definitions(next_definitions)
                            .expect("the next registry lane installs midway through the listing");
                    })
                },
            )
        };
        let egress_client = Arc::new(
            egress::EgressClient::new(egress::EgressConfig::default())
                .expect("test egress client should build"),
        );
        let executor = ToolExecutor::new(
            registry.clone(),
            runtime,
            egress_client,
            audit,
            "https://upstream.invalid",
        )
        .expect("MCP executor should build")
        .with_listing_hook_for_test(hook);
        let state = McpState::new(
            registry,
            Some(executor),
            client_ip::ClientIpPolicy::default(),
            TEST_MAX_BODY_SIZE,
        );

        let listed = mcp_json_rpc(&state, 50, "tools/list", None).await;
        assert_eq!(
            listed_tool_names(&listed),
            vec!["alpha".to_owned()],
            "the whole listing is judged by the snapshots it started with: {listed}"
        );
        assert_eq!(
            *checked
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            vec!["alpha".to_owned(), "beta".to_owned(), "gamma".to_owned()],
            "the installs landed after the first tool and before the rest were judged"
        );

        let next = mcp_json_rpc(&state, 51, "tools/list", None).await;
        assert_eq!(
            listed_tool_names(&next),
            vec!["beta".to_owned(), "gamma".to_owned()],
            "the installs really moved the live lanes, and judge the next listing: {next}"
        );
    }

    /// A policy file in the temp directory, removed when dropped.
    struct TempPolicyFile {
        path: std::path::PathBuf,
    }

    impl TempPolicyFile {
        fn new(contents: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-mcp-policy-test-{}.json",
                uuid::Uuid::new_v4()
            ));
            std::fs::write(&path, contents)
                .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
            Self { path }
        }
    }

    impl Drop for TempPolicyFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// rmcp serves `/mcp` from tasks it spawns, which the revision gate's
    /// task-local pins do not reach. Driven through `rbac_middleware`, a
    /// `tools/list` and a `tools/call` must still be judged by the bundle the
    /// gate admitted them under: the registry lookup, the invocation and the
    /// rendered HTTP rule. The gate below has a reconcile install the next
    /// revision on the live lanes right after each admission, so any of those
    /// reads falling back to the live lane would find no such tool, or a
    /// policy that denies both the tool and its rendered request.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn mcp_requests_are_judged_by_the_admitted_revision_not_one_installed_in_flight() {
        let admitted_policy = crate::rbac::Policy::validate_json_value(json!({
            "schema_version": "0.1.0",
            "default_action": "allow",
            "tools": {
                "pinned_probe": {
                    "timeout_ms": 5000,
                    "max_concurrent": 2
                }
            },
            "rules": [
                {
                    "id": "allow-probe-tool-admitted",
                    "tool_name": "pinned_probe",
                    "action": "allow"
                },
                {
                    "id": "allow-probe-http-admitted",
                    "methods": ["GET"],
                    "path": "/pinned_probe",
                    "action": "allow"
                }
            ]
        }))
        .expect("admitted policy should parse");
        let live_policy = crate::rbac::Policy::validate_json_value(json!({
            "schema_version": "0.1.0",
            "default_action": "allow",
            "tools": {
                "pinned_probe": {
                    "timeout_ms": 5000,
                    "max_concurrent": 2
                }
            },
            "rules": [
                {
                    "id": "deny-probe-tool-live",
                    "tool_name": "pinned_probe",
                    "action": "deny"
                },
                {
                    "id": "deny-probe-http-live",
                    "methods": ["GET"],
                    "path": "/pinned_probe",
                    "action": "deny"
                }
            ]
        }))
        .expect("live policy should parse");
        let capture = crate::audit::sink::tests::CaptureSink::new();
        let audit = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let rbac_state = crate::middleware::rbac::RbacState::new(
            admitted_policy.clone(),
            Vec::new(),
            false,
            audit.clone(),
        );
        rbac_state
            .install_revision_snapshot(admitted_policy.clone(), 1)
            .await
            .expect("the admitted revision installs");
        let registry = ToolRegistry::disabled();
        registry
            .merge_definitions(vec![legacy_tool_definition("pinned_probe")])
            .expect("the admitted tool registers");
        let admitted = Arc::new(crate::security_cluster::SecurityBundle {
            revision: 1,
            policy: rbac_state.policy_handle().load_full(),
            tools: registry.state_handle().load_full(),
            connections: Arc::new(
                crate::connections::control_plane::ConnectionRuntimeSnapshot::empty_for_test(),
            ),
        });
        let runtime = ToolRuntime::new_with_rbac_state(
            ToolRuntimeConfig::from_policy(&admitted_policy)
                .expect("admitted policy should configure the runtime"),
            audit.clone(),
            Some(rbac_state.clone()),
        );
        // No egress host is allowed, so a call admitted all the way through
        // fails at egress, after both policy decisions, without leaving the
        // process.
        let egress_client = Arc::new(
            egress::EgressClient::new(egress::EgressConfig::default())
                .expect("test egress client should build"),
        );
        let executor = ToolExecutor::new(
            registry.clone(),
            runtime,
            egress_client,
            audit.clone(),
            "https://upstream.invalid",
        )
        .expect("MCP executor should build");
        let state = McpState::new(
            registry.clone(),
            Some(executor),
            client_ip::ClientIpPolicy::default(),
            TEST_MAX_BODY_SIZE,
        );
        let gate = ReconcileAfterAdmissionGate {
            admitted,
            rbac_state: rbac_state.clone(),
            next_policy: live_policy,
            live_tools: registry.state_handle(),
            next_tools: ToolRegistry::disabled().state_handle().load_full(),
        };
        let router = axum::Router::new()
            .route("/mcp", axum::routing::post(serve_mcp))
            .with_state(state.clone())
            .layer(axum::middleware::from_fn_with_state(
                rbac_state.clone().with_revision_gate(Arc::new(gate)),
                crate::middleware::rbac::rbac_middleware,
            ))
            .layer(axum::middleware::from_fn(admit_mcp_caller));

        let listed = mcp_json_rpc_body(
            router
                .clone()
                .oneshot(mcp_json_rpc_request(40, "tools/list", None))
                .await
                .expect("the gated MCP route should respond"),
        )
        .await;
        assert_eq!(
            listed_tool_names(&listed),
            vec!["pinned_probe".to_owned()],
            "the admitted registry and policy list the tool: {listed}"
        );

        let called = mcp_json_rpc_body(
            router
                .clone()
                .oneshot(mcp_json_rpc_request(
                    41,
                    "tools/call",
                    Some(json!({ "name": "pinned_probe", "arguments": {} })),
                ))
                .await
                .expect("the gated MCP route should respond"),
        )
        .await;
        // Not unknown (the live registry), not rejected (the live tool rule)
        // and not denied (the live rendered-HTTP rule): the call got as far as
        // egress, which is only reachable past both policy decisions.
        assert_eq!(
            called["error"]["code"],
            json!(ErrorCode::INTERNAL_ERROR.0),
            "{called}"
        );
        assert_eq!(
            called["error"]["data"]["reason"],
            json!("host_not_allowed"),
            "{called}"
        );

        audit
            .close_and_drain(Duration::from_secs(5))
            .await
            .expect("audit should drain");
        let matched = capture
            .events()
            .iter()
            .filter_map(|event| {
                event.payload["matched_rule_id"]
                    .as_str()
                    .map(|rule_id| (event.event_type.clone(), rule_id.to_owned()))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            matched,
            vec![
                (
                    "authz.allowed".to_owned(),
                    "allow-probe-tool-admitted".to_owned()
                ),
                (
                    "authz.allowed".to_owned(),
                    "allow-probe-http-admitted".to_owned()
                ),
            ],
            "the invocation and the rendered request are audited under the admitted revision"
        );

        // The reconcile really did move the live lanes: read without the
        // pins, the policy is the next revision and the tool is gone.
        assert_eq!(rbac_state.snapshot_security_revision(), 2);
        let unpinned = mcp_json_rpc(&state, 42, "tools/list", None).await;
        assert!(
            listed_tool_names(&unpinned).is_empty(),
            "without the pins the live lanes are read: {unpinned}"
        );
    }

    /// Admits every request under `admitted`, then has a reconcile install
    /// the next revision on the live lanes before the request is served: the
    /// policy the tool runtime reads and the registry the executor reads.
    #[cfg(feature = "postgres")]
    struct ReconcileAfterAdmissionGate {
        admitted: Arc<crate::security_cluster::SecurityBundle>,
        rbac_state: crate::middleware::rbac::RbacState,
        next_policy: crate::rbac::Policy,
        live_tools: Arc<arc_swap::ArcSwap<crate::tools::definitions::ToolRegistryState>>,
        next_tools: Arc<crate::tools::definitions::ToolRegistryState>,
    }

    #[cfg(feature = "postgres")]
    #[async_trait::async_trait]
    impl crate::middleware::rbac::SecurityRevisionGate for ReconcileAfterAdmissionGate {
        async fn ensure_current_revision(
            &self,
        ) -> Result<i64, crate::middleware::rbac::SecurityRevisionCheckError> {
            Ok(self.admitted.revision)
        }

        async fn admit(
            &self,
        ) -> Result<
            crate::middleware::rbac::Admission,
            crate::middleware::rbac::SecurityRevisionCheckError,
        > {
            let admission = crate::middleware::rbac::Admission {
                revision: self.admitted.revision,
                bundle: Some(Arc::clone(&self.admitted)),
            };
            self.rbac_state
                .install_revision_snapshot(self.next_policy.clone(), self.admitted.revision + 1)
                .await
                .expect("the next revision installs");
            self.live_tools.store(Arc::clone(&self.next_tools));
            Ok(admission)
        }
    }

    /// `mcp_endpoint` without the body limit, over a bare `McpState`.
    #[cfg(feature = "postgres")]
    async fn serve_mcp(State(state): State<McpState>, request: AxumRequest<Body>) -> Response {
        match state.service.oneshot(request).await {
            Ok(response) => response.map(Body::new).into_response(),
            Err(error) => match error {},
        }
    }

    /// What production establishes before `rbac_middleware` runs: an
    /// authenticated caller and a completed routing classification.
    #[cfg(feature = "postgres")]
    async fn admit_mcp_caller(
        mut request: AxumRequest<Body>,
        next: axum::middleware::Next,
    ) -> Response {
        request.extensions_mut().insert(auth::Principal {
            user_id: "user-123".to_owned(),
            issuer: None,
            email: Some("user@example.test".to_owned()),
            org_id: None,
            roles: vec!["operator".to_owned()],
            session_id: "session-123".to_owned(),
            auth_method: auth::AuthMethod::Bearer,
        });
        request
            .extensions_mut()
            .insert(crate::upstream_route::ProxyRouteClassificationCompleted);
        next.run(request).await
    }

    /// Builds the MCP surface the way startup does when TOOLS_FILE is present but
    /// still empty, and hands back the shared registry so a test can hot-reload
    /// definitions into it afterwards.
    fn mcp_state_from_empty_registry() -> (McpState, ToolRegistry) {
        let config = test_config();
        let registry = ToolRegistry::disabled();
        let egress_client = Arc::new(
            egress::EgressClient::new(egress::EgressConfig::from_config(&config))
                .expect("test egress client should build"),
        );
        let executor = mcp_executor_from_config(
            &config,
            registry.clone(),
            tool_visibility_runtime(),
            egress_client,
            ToolConnectionRuntimes::default(),
            test_audit_log(),
        )
        .expect("MCP executor should build");

        let state = McpState::new(
            registry.clone(),
            executor,
            client_ip::ClientIpPolicy::default(),
            TEST_MAX_BODY_SIZE,
        );

        (state, registry)
    }

    fn tool_visibility_runtime() -> ToolRuntime {
        let tools = [
            (VISIBLE_TOOL.to_owned(), tool_policy(Vec::new())),
            (COMPOSITE_ONLY_TOOL.to_owned(), tool_policy(Vec::new())),
            (
                RESTRICTED_TOOL.to_owned(),
                tool_policy(vec![PRIVILEGED_ROLE.to_owned()]),
            ),
        ]
        .into_iter()
        .collect();

        ToolRuntime::new(
            ToolRuntimeConfig {
                tools,
                ..Default::default()
            },
            test_audit_log(),
        )
    }

    fn tool_policy(allowed_roles: Vec<String>) -> ToolRuntimeToolConfig {
        ToolRuntimeToolConfig {
            enabled: true,
            allowed_roles,
            issuers: Vec::new(),
            auth_methods: Vec::new(),
            timeout: Duration::from_secs(5),
            max_concurrent: 2,
        }
    }

    fn legacy_tool_definition(name: &str) -> ToolDefinition {
        ToolDefinition {
            name: name.to_owned(),
            title: None,
            description: format!("{name} fixture"),
            input_schema: json!({ "type": "object" }),
            target: None,
            source: ToolSource::default(),
            upstream: UpstreamMapping {
                method: "GET".to_owned(),
                path_template: format!("/{name}"),
                query_params: Vec::new(),
                body: None,
            },
            composite: None,
            enum_bindings: Vec::new(),
            visibility: crate::tools::definitions::ToolVisibility::Listed,
            transform: None,
            annotations: None,
        }
    }

    fn transformed_visible_tool_definition() -> ToolDefinition {
        serde_json::from_value(json!({
            "name": VISIBLE_TOOL,
            "description": "Creates a company with normalized currency.",
            "input_json_schema": {
                "type": "object",
                "required": ["amount", "currency"],
                "properties": {
                    "amount": { "type": "number" },
                    "currency": { "type": "string" }
                },
                "additionalProperties": false
            },
            "upstream": {
                "method": "POST",
                "path_template": "/companies",
                "body": { "mode": "body_args_json" }
            },
            "transform": {
                "parameters": [{
                    "wire_property": "annualRecurringRevenue",
                    "wire_required": true,
                    "agent": [
                        { "name": "amount", "schema": { "type": "number" } },
                        { "name": "currency", "schema": { "type": "string" } }
                    ],
                    "wire": [
                        {
                            "pointer": "/amountMicros",
                            "from": "amount",
                            "codec": [{
                                "kind": "decimal_scale",
                                "scale": 6,
                                "wire_encoding": "integer_string",
                                "max_integer_digits": 24
                            }]
                        },
                        { "pointer": "/currencyCode", "from": "currency" }
                    ],
                    "response": [
                        {
                            "agent_property": "amount",
                            "from": "/amountMicros",
                            "codec": [{
                                "kind": "decimal_scale",
                                "scale": 6,
                                "wire_encoding": "integer_string",
                                "max_integer_digits": 24
                            }]
                        },
                        { "agent_property": "currency", "from": "/currencyCode" }
                    ]
                }]
            }
        }))
        .expect("transformed MCP fixture definition should deserialize")
    }

    fn composite_only_tool_definition() -> ToolDefinition {
        let mut definition = legacy_tool_definition(COMPOSITE_ONLY_TOOL);
        definition.visibility = crate::tools::definitions::ToolVisibility::CompositeOnly;
        definition
    }

    fn listed_tool_names(body: &Value) -> Vec<String> {
        body["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("tools/list should return a tools array: {body}"))
            .iter()
            .map(|tool| tool["name"].as_str().unwrap_or_default().to_owned())
            .collect()
    }

    #[test]
    fn mcp_tool_preserves_optional_title_and_annotations_without_inventing_them() {
        let plain = mcp_tool_from_definition(&legacy_tool_definition("plain"))
            .expect("plain definition converts");
        let plain = serde_json::to_value(plain).expect("plain tool serializes");
        assert!(plain.get("title").is_none());
        assert!(plain.get("annotations").is_none());

        let mut annotated = legacy_tool_definition("annotated");
        annotated.title = Some("Search contacts".to_owned());
        annotated.annotations = Some(crate::tools::definitions::ToolAnnotations {
            title: Some("Contact lookup".to_owned()),
            read_only_hint: Some(true),
            destructive_hint: Some(false),
            idempotent_hint: Some(true),
            open_world_hint: Some(false),
        });
        let served = mcp_tool_from_definition(&annotated).expect("annotated definition converts");
        let served = serde_json::to_value(served).expect("annotated tool serializes");
        assert_eq!(served["title"], json!("Search contacts"));
        assert_eq!(
            served["annotations"],
            json!({
                "title": "Contact lookup",
                "readOnlyHint": true,
                "destructiveHint": false,
                "idempotentHint": true,
                "openWorldHint": false
            })
        );
    }

    async fn mcp_json_rpc(state: &McpState, id: u64, method: &str, params: Option<Value>) -> Value {
        let response = state
            .service
            .clone()
            .oneshot(mcp_json_rpc_request(id, method, params))
            .await
            .expect("MCP service should respond")
            .map(Body::new);
        mcp_json_rpc_body(response).await
    }

    fn mcp_json_rpc_request(id: u64, method: &str, params: Option<Value>) -> AxumRequest<Body> {
        mcp_json_rpc_request_at(id, method, params, Some("2025-11-25"))
    }

    /// A JSON-RPC POST carrying `protocol_version` in `MCP-Protocol-Version`,
    /// or no such header.
    fn mcp_json_rpc_request_at(
        id: u64,
        method: &str,
        params: Option<Value>,
        protocol_version: Option<&str>,
    ) -> AxumRequest<Body> {
        let mut payload = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
        });
        if let Some(params) = params {
            payload["params"] = params;
        }

        let mut request = AxumRequest::builder()
            .method(http::Method::POST)
            .uri("/mcp")
            .header(header::HOST, "localhost")
            .header(header::CONTENT_TYPE, JSON_MIME)
            .header(header::ACCEPT, "application/json, text/event-stream");
        if let Some(protocol_version) = protocol_version {
            request = request.header("MCP-Protocol-Version", protocol_version);
        }
        request
            .body(Body::from(payload.to_string()))
            .expect("MCP request should build")
    }

    async fn mcp_json_rpc_status_and_body(
        state: &McpState,
        request: AxumRequest<Body>,
    ) -> (http::StatusCode, Value) {
        let response = state
            .service
            .clone()
            .oneshot(request)
            .await
            .expect("MCP service should respond")
            .map(Body::new);
        let status = response.status();
        (status, mcp_json_rpc_body(response).await)
    }

    async fn mcp_json_rpc_body(response: Response) -> Value {
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("MCP response body should be readable");

        serde_json::from_slice(&body).unwrap_or_else(|err| {
            panic!(
                "MCP response body should be JSON, status={status}, body={:?}: {err}",
                String::from_utf8_lossy(&body)
            )
        })
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
            grpc_listen_addr: None,
            grpc_max_concurrent_streams: crate::config::DEFAULT_GRPC_MAX_CONCURRENT_STREAMS,
            grpc_max_metadata_bytes: crate::config::DEFAULT_GRPC_MAX_METADATA_BYTES,
            tls_cert_files: None,
            tls_key_files: None,
            admin_tls_cert_files: None,
            admin_tls_key_files: None,
            tls_min_version: config::DEFAULT_TLS_MIN_VERSION,
            tls_handshake_timeout_ms: config::DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS,
            tls_max_concurrent_handshakes: config::DEFAULT_TLS_MAX_CONCURRENT_HANDSHAKES,
            client_cert_auth: None,
            admin_client_cert_auth: None,
            admin_prefix: config::DEFAULT_ADMIN_PREFIX.to_owned(),
            admin_login_provider: None,
            admin_session: None,
            admin_login_pending_ttl_secs: config::DEFAULT_ADMIN_LOGIN_PENDING_TTL_SECS,
            admin_login_pending_max_entries: config::DEFAULT_ADMIN_LOGIN_PENDING_MAX_ENTRIES,
            admin_login_pending_max_per_ip: config::DEFAULT_ADMIN_LOGIN_PENDING_MAX_PER_IP,
            admin_login_keyring: Vec::new(),
            rate_limit_keyring: Vec::new(),
            gateway_public_url: None,
            audit_log_file: None,
            audit_sqlite_path: None,
            audit_sqlite_retention_days: None,
            audit_successful_probes_metrics_only: false,
            shutdown_drain_delay_ms: config::DEFAULT_SHUTDOWN_DRAIN_DELAY_MS,
            shutdown_timeout_ms: config::DEFAULT_SHUTDOWN_TIMEOUT_MS,
            audit_drain_timeout_ms: config::DEFAULT_AUDIT_DRAIN_TIMEOUT_MS,
            audit_durability: config::DEFAULT_AUDIT_DURABILITY,
            audit_durability_timeout_ms: config::DEFAULT_AUDIT_DURABILITY_TIMEOUT_MS,
            discovery_sqlite_path: None,
            discovery_endpoint_limit: config::DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
            discovery_projector_lease_ttl_ms: config::DEFAULT_DISCOVERY_PROJECTOR_LEASE_TTL_MS,
            discovery_projector_poll_ms: config::DEFAULT_DISCOVERY_PROJECTOR_POLL_MS,
            discovery_projector_batch: config::DEFAULT_DISCOVERY_PROJECTOR_BATCH,
            principal_sqlite_path: None,
            connections_sqlite_path: None,
            connection_local_secret_keyring: Vec::new(),
            connection_vault_provider:
                crate::connections::vault_secret::VaultProviderConfig::default(),
            connection_gcp_provider: crate::connections::gcp_secret::GcpProviderConfig::default(),
            connection_azure_provider:
                crate::connections::azure_secret::AzureProviderConfig::default(),
            connection_aws_provider: crate::connections::aws_secret::AwsProviderConfig::default(),
            connection_kubernetes_provider:
                crate::connections::kubernetes_secret::KubernetesProviderConfig::default(),
            connection_secret_aliases: Vec::new(),
            connection_secrets_root: None,
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
            max_request_path_bytes: crate::config::DEFAULT_MAX_REQUEST_PATH_BYTES,
            rate_limit_read_rps: 50.0,
            rate_limit_read_burst: 100,
            rate_limit_write_rps: 10.0,
            rate_limit_write_burst: 20,
            rate_limit_max_buckets: crate::config::DEFAULT_RATE_LIMIT_MAX_BUCKETS,
            rate_limit_bucket_ttl_ms: crate::config::DEFAULT_RATE_LIMIT_BUCKET_TTL_MS,
            trust_proxy_headers: false,
            trusted_proxy_cidrs: Vec::new(),
            rbac_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
                "/admin".to_owned(),
            ],
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
            jwt_jwks_max_key_age_secs: 300,
            jwt_require_jti: false,
            roles_claim: "roles".to_owned(),
            service_token_sqlite_path: None,
            service_token_cache_ttl_ms: config::DEFAULT_SERVICE_TOKEN_CACHE_TTL_MS,
            tool_runtime_queue_depth: config::DEFAULT_TOOL_RUNTIME_QUEUE_DEPTH,
            tool_runtime_global_concurrency: config::DEFAULT_TOOL_RUNTIME_GLOBAL_CONCURRENCY,
            tool_runtime_queue_timeout_ms: config::DEFAULT_TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
            tool_lease_ttl_ms: config::DEFAULT_TOOL_LEASE_TTL_MS,
            cluster_heartbeat_ms: config::DEFAULT_CLUSTER_HEARTBEAT_MS,
            cluster_member_stale_ms: config::DEFAULT_CLUSTER_MEMBER_STALE_MS,
            cluster_maintenance_interval_ms: config::DEFAULT_CLUSTER_MAINTENANCE_INTERVAL_MS,
            cluster_maintenance_lease_ttl_ms: config::DEFAULT_CLUSTER_MAINTENANCE_LEASE_TTL_MS,
            readiness_probe_cache_ms: config::DEFAULT_READINESS_PROBE_CACHE_MS,
            cluster_status_expose_hostnames: false,
            audit_postgres_retention_days: None,
            authority_events: Default::default(),
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
            state_backend: crate::config::StateBackend::Sqlite,
            deployment_id: None,
            database: crate::config::DatabaseSettings::default(),
        }
    }
}
