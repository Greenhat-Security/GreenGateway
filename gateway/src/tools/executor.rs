use std::{
    collections::HashMap,
    error::Error,
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{Duration, Instant},
};

use futures_util::StreamExt;
use http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use rmcp::model::CallToolResult;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{
    audit::{self, AuditEvent, AuditLog},
    config::{Config, McpUpstreamServerConfig},
    connections::{
        http::{ConnectionHttpError, ConnectionHttpRuntime, ConnectionHttpTarget},
        mcp::McpConnectionCatalogRuntime,
        openapi::OpenApiConnectionCatalogRuntime,
    },
    egress::{EgressClient, EgressError, EgressRequestBody, EgressResponse},
    tools::{
        definitions::{
            BodyMappingMode, McpProxyMapping, ToolDefinition, ToolRegistry, ToolSource, ToolTarget,
        },
        mcp_upstream::{self, McpUpstreamRuntimeConfig},
        runtime::{ToolInvocationContext, ToolRuntime, ToolRuntimeError, ToolWorkErrorDisposition},
    },
};

// Path arguments are substituted into exactly one path segment. Encoding `/`,
// `?`, and `#` prevents caller-controlled values from adding path, query, or
// fragment structure; encoding `\` avoids backslash-based path confusion. Dot
// segment collapse is handled by an explicit `.`/`..` rejection before URL
// parsing, because WHATWG URL parsing also treats encoded dot-only segments as
// dot segments.
const PATH_SEGMENT_ARGUMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'.')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b'\\');

const HTTP_REQUEST_OBSERVED: &str = "http.request_observed";
const MCP_TOOL_OBSERVATION_METHOD: &str = "MCP";
const TOOL_INPUT_VALIDATION_STATUS: u16 = 400;
const TOOL_INPUT_VALIDATION_REASON: &str = "input_validation";
const TOOL_EXECUTOR_CONFIGURATION_ERROR_STATUS: u16 = 520;
const TOOL_EXECUTOR_CONFIGURATION_ERROR_REASON: &str = "internal_configuration_error";
const TOOL_INVALID_PARAMS_REASON: &str = "invalid_params";
const TOOL_UNKNOWN_TOOL_REASON: &str = "unknown_tool";
const TOOL_DISABLED_REASON: &str = "disabled";
const TOOL_ROLE_NOT_ALLOWED_REASON: &str = "role_not_allowed";
const TOOL_MATCHED_RULE_REASON: &str = "matched_rule";
const TOOL_QUEUE_FULL_REASON: &str = "queue_full";
const TOOL_QUEUE_TIMEOUT_REASON: &str = "queue_timeout";
const TOOL_TIMEOUT_REASON: &str = "timeout";
const TOOL_CANCELLED_REASON: &str = "cancelled";
const TOOL_RUNTIME_CLOSED_REASON: &str = "runtime_closed";
const TOOL_RUNTIME_REJECTED_REASON: &str = "runtime_rejected";
const TOOL_PRECONDITION_FAILED_REASON: &str = "precondition_failed";
const TOOL_EXECUTION_STATE_UNAVAILABLE_REASON: &str = "execution_state_unavailable";
const TOOL_TASK_UNSUPPORTED_STATUS: u16 = 400;
const TOOL_TASK_UNSUPPORTED_REASON: &str = "task_unsupported";
const STRICT_SCHEMA_INJECTION_SKIP_KEYWORDS: &[&str] =
    &["$ref", "oneOf", "anyOf", "allOf", "patternProperties"];
// OpenAPI-generated schemas can come from externally supplied specs. Sixty-four
// child-schema edges is far deeper than realistic tool input shapes, while
// still bounding strict-default injection well below stack-overflow territory.
const MAX_STRICT_SCHEMA_INJECTION_DEPTH: usize = 64;
const MAX_VALIDATOR_CACHE_ENTRIES: usize = 4_096;

type ValidatorCache = HashMap<ValidatorCacheKey, Arc<jsonschema::Validator>>;

struct ToolExecutorBackends {
    upstream_url: Option<String>,
    connection_http: Option<ConnectionHttpRuntime>,
    mcp_catalog_runtime: Option<McpConnectionCatalogRuntime>,
    openapi_catalog_runtime: Option<OpenApiConnectionCatalogRuntime>,
    mcp_upstream_servers: HashMap<String, McpUpstreamServerConfig>,
    mcp_upstream_runtime_config: McpUpstreamRuntimeConfig,
}

#[derive(Clone, Default)]
pub(crate) struct ToolConnectionRuntimes {
    pub(crate) http: Option<ConnectionHttpRuntime>,
    pub(crate) mcp_catalog: Option<McpConnectionCatalogRuntime>,
    pub(crate) openapi_catalog: Option<OpenApiConnectionCatalogRuntime>,
}

#[allow(dead_code)] // Issue #33 will call this from the MCP endpoint.
#[derive(Clone)]
pub struct ToolExecutor {
    registry: ToolRegistry,
    runtime: ToolRuntime,
    egress_client: Arc<EgressClient>,
    audit: AuditLog,
    upstream_origin: Option<String>,
    connection_http: Option<ConnectionHttpRuntime>,
    mcp_catalog_runtime: Option<McpConnectionCatalogRuntime>,
    openapi_catalog_runtime: Option<OpenApiConnectionCatalogRuntime>,
    mcp_upstream_servers: Arc<HashMap<String, McpUpstreamServerConfig>>,
    mcp_upstream_runtime_config: Arc<McpUpstreamRuntimeConfig>,
    validator_cache: Arc<Mutex<ValidatorCache>>,
}

#[allow(dead_code)] // Issue #33 will expose executor errors to callers.
#[derive(Debug)]
pub enum ToolExecutorError {
    MissingUpstreamUrl,
    InvalidUpstreamUrl {
        message: String,
    },
    UnknownTool {
        tool_name: String,
    },
    SchemaCacheKey {
        tool_name: String,
        message: String,
    },
    SchemaCompile {
        tool_name: String,
        message: String,
    },
    InputValidation {
        tool_name: String,
        problems: Vec<String>,
    },
    InvalidMapping {
        tool_name: String,
        message: String,
    },
    MissingArgument {
        tool_name: String,
        arg_name: String,
        location: &'static str,
    },
    UnsupportedArgumentValue {
        tool_name: String,
        arg_name: String,
        location: &'static str,
        value_type: &'static str,
    },
    PathSegmentIsDotSegment {
        tool_name: String,
        arg_name: String,
    },
    InvalidMethod {
        tool_name: String,
        method: String,
        message: String,
    },
    BodySerialize {
        tool_name: String,
        message: String,
    },
    UrlBuild {
        tool_name: String,
        message: String,
    },
    Egress {
        tool_name: String,
        source: EgressError,
    },
    McpUpstream {
        tool_name: String,
        server_name: String,
        reason: &'static str,
    },
    HttpRuleDenied {
        tool_name: String,
    },
    PreconditionFailed {
        tool_name: String,
    },
    ExecutionStateUnavailable {
        tool_name: String,
    },
    Connection {
        tool_name: String,
        reason: &'static str,
    },
}

#[derive(Debug)]
pub enum ToolExecutionResult {
    Http(EgressResponse),
    McpCallToolResult(CallToolResult),
}

type ToolExecutionPreconditionChecker =
    dyn Fn(&ToolDefinition) -> Result<(), ToolExecutionPreconditionError> + Send + Sync + 'static;

#[derive(Clone)]
pub struct ToolExecutionPrecondition {
    checker: Arc<ToolExecutionPreconditionChecker>,
}

impl ToolExecutionPrecondition {
    pub fn new<F>(checker: F) -> Self
    where
        F: Fn(&ToolDefinition) -> Result<(), ToolExecutionPreconditionError>
            + Send
            + Sync
            + 'static,
    {
        Self {
            checker: Arc::new(checker),
        }
    }

    fn check(&self, definition: &ToolDefinition) -> Result<(), ToolExecutionPreconditionError> {
        (self.checker)(definition)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolExecutionPreconditionError {
    Failed,
    Unavailable,
}

impl fmt::Display for ToolExecutorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingUpstreamUrl => {
                write!(formatter, "tool executor requires UPSTREAM_URL to be set")
            }
            Self::InvalidUpstreamUrl { message } => {
                write!(formatter, "tool executor UPSTREAM_URL is invalid: {message}")
            }
            Self::UnknownTool { tool_name } => {
                write!(formatter, "tool '{tool_name}' is not defined in the tool registry")
            }
            Self::SchemaCacheKey { tool_name, message } => write!(
                formatter,
                "tool '{tool_name}' input schema could not be cached: {message}"
            ),
            Self::SchemaCompile { tool_name, message } => write!(
                formatter,
                "tool '{tool_name}' input schema could not be compiled: {message}"
            ),
            Self::InputValidation {
                tool_name,
                problems,
            } => write!(
                formatter,
                "tool '{tool_name}' arguments failed input schema validation: {}",
                problems.join("; ")
            ),
            Self::InvalidMapping { tool_name, message } => {
                write!(formatter, "tool '{tool_name}' upstream mapping is invalid: {message}")
            }
            Self::MissingArgument {
                tool_name,
                arg_name,
                location,
            } => write!(
                formatter,
                "tool '{tool_name}' is missing required {location} argument '{arg_name}'"
            ),
            Self::UnsupportedArgumentValue {
                tool_name,
                arg_name,
                location,
                value_type,
            } => write!(
                formatter,
                "tool '{tool_name}' {location} argument '{arg_name}' must be a string, number, or boolean, got {value_type}"
            ),
            Self::PathSegmentIsDotSegment {
                tool_name,
                arg_name,
            } => write!(
                formatter,
                "tool '{tool_name}' path argument '{arg_name}' must not be a dot segment ('.' or '..')"
            ),
            Self::InvalidMethod {
                tool_name,
                method,
                message,
            } => write!(
                formatter,
                "tool '{tool_name}' has invalid HTTP method '{method}': {message}"
            ),
            Self::BodySerialize { tool_name, message } => {
                write!(formatter, "tool '{tool_name}' request body could not serialize: {message}")
            }
            Self::UrlBuild { tool_name, message } => {
                write!(formatter, "tool '{tool_name}' upstream URL could not be built: {message}")
            }
            Self::Egress { tool_name, source } => {
                write!(formatter, "tool '{tool_name}' upstream request failed: {source}")
            }
            Self::McpUpstream {
                tool_name,
                server_name,
                reason,
            } => write!(
                formatter,
                "tool '{tool_name}' upstream MCP server '{server_name}' request failed: {reason}"
            ),
            Self::HttpRuleDenied { tool_name } => {
                write!(formatter, "tool '{tool_name}' HTTP operation is denied by policy")
            }
            Self::PreconditionFailed { tool_name } => {
                write!(
                    formatter,
                    "tool '{tool_name}' execution precondition no longer holds"
                )
            }
            Self::ExecutionStateUnavailable { tool_name } => {
                write!(
                    formatter,
                    "tool '{tool_name}' execution state is unavailable"
                )
            }
            Self::Connection { tool_name, reason } => {
                write!(
                    formatter,
                    "tool '{tool_name}' connection-bound request failed: {reason}"
                )
            }
        }
    }
}

impl Error for ToolExecutorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Egress { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct ToolUpstreamRequest {
    method: Method,
    path: String,
    path_and_query: String,
    url: String,
    headers: HeaderMap,
    body: Option<Vec<u8>>,
}

struct UpstreamAuditOutcome {
    outcome: &'static str,
    status: Option<u16>,
    latency_ms: u64,
    reason: Option<&'static str>,
}

struct ToolObservationOutcome {
    status: u16,
    latency_ms: u64,
    schema_mismatch: bool,
    reason: Option<&'static str>,
}

struct UnsupportedTaskInvocation;

impl fmt::Display for UnsupportedTaskInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("task-based tool invocation is not supported by GreenGateway")
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
struct ValidatorCacheKey {
    tool_name: String,
    schema_sha256: [u8; 32],
}

impl ToolExecutor {
    #[allow(dead_code)] // Issue #33 will construct this during app startup.
    pub fn from_config(
        config: &Config,
        registry: ToolRegistry,
        runtime: ToolRuntime,
        egress_client: Arc<EgressClient>,
        connection_runtimes: ToolConnectionRuntimes,
        audit: AuditLog,
    ) -> Result<Self, ToolExecutorError> {
        let upstream_url = if registry.has_legacy_http_tools() {
            Some(
                config
                    .upstream_url
                    .as_deref()
                    .ok_or(ToolExecutorError::MissingUpstreamUrl)?,
            )
        } else {
            config.upstream_url.as_deref()
        };
        let mcp_upstream_servers = config
            .mcp_upstream_servers
            .iter()
            .map(|server| (server.name.clone(), server.clone()))
            .collect();

        Self::new_inner(
            registry,
            runtime,
            egress_client,
            audit,
            ToolExecutorBackends {
                upstream_url: upstream_url.map(str::to_owned),
                connection_http: connection_runtimes.http,
                mcp_catalog_runtime: connection_runtimes.mcp_catalog,
                openapi_catalog_runtime: connection_runtimes.openapi_catalog,
                mcp_upstream_servers,
                mcp_upstream_runtime_config: McpUpstreamRuntimeConfig::from_config(config),
            },
        )
    }

    #[allow(dead_code)] // Tests and future app wiring construct the executor directly.
    pub fn new(
        registry: ToolRegistry,
        runtime: ToolRuntime,
        egress_client: Arc<EgressClient>,
        audit: AuditLog,
        upstream_url: &str,
    ) -> Result<Self, ToolExecutorError> {
        Self::new_inner(
            registry,
            runtime,
            egress_client,
            audit,
            ToolExecutorBackends {
                upstream_url: Some(upstream_url.to_owned()),
                connection_http: None,
                mcp_catalog_runtime: None,
                openapi_catalog_runtime: None,
                mcp_upstream_servers: HashMap::new(),
                mcp_upstream_runtime_config: McpUpstreamRuntimeConfig {
                    timeout: Duration::from_secs(30),
                    response_idle_timeout: Duration::from_secs(30),
                    connect_timeout: Duration::from_secs(10),
                    max_request_body_bytes: 1_048_576,
                    max_response_bytes: 5_242_880,
                },
            },
        )
    }

    fn new_inner(
        registry: ToolRegistry,
        runtime: ToolRuntime,
        egress_client: Arc<EgressClient>,
        audit: AuditLog,
        backends: ToolExecutorBackends,
    ) -> Result<Self, ToolExecutorError> {
        Ok(Self {
            registry,
            runtime,
            egress_client,
            audit,
            upstream_origin: backends
                .upstream_url
                .as_deref()
                .map(upstream_origin_from_url)
                .transpose()?,
            connection_http: backends.connection_http,
            mcp_catalog_runtime: backends.mcp_catalog_runtime,
            openapi_catalog_runtime: backends.openapi_catalog_runtime,
            mcp_upstream_servers: Arc::new(backends.mcp_upstream_servers),
            mcp_upstream_runtime_config: Arc::new(backends.mcp_upstream_runtime_config),
            validator_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    #[allow(dead_code)] // Issue #33 will call this from the MCP endpoint.
    pub async fn execute(
        &self,
        tool_name: &str,
        args: Value,
        context: ToolInvocationContext,
        cancel: CancellationToken,
    ) -> Result<ToolExecutionResult, ToolRuntimeError> {
        self.execute_with_optional_precondition(tool_name, args, context, cancel, None)
            .await
    }

    pub async fn execute_with_precondition(
        &self,
        tool_name: &str,
        args: Value,
        context: ToolInvocationContext,
        cancel: CancellationToken,
        precondition: ToolExecutionPrecondition,
    ) -> Result<ToolExecutionResult, ToolRuntimeError> {
        self.execute_with_optional_precondition(
            tool_name,
            args,
            context,
            cancel,
            Some(precondition),
        )
        .await
    }

    async fn execute_with_optional_precondition(
        &self,
        tool_name: &str,
        args: Value,
        context: ToolInvocationContext,
        cancel: CancellationToken,
        precondition: Option<ToolExecutionPrecondition>,
    ) -> Result<ToolExecutionResult, ToolRuntimeError> {
        let started = Instant::now();
        let runtime_tool_name = tool_name.to_owned();
        let work_tool_name = runtime_tool_name.clone();
        let observation_context = context.clone();
        let work_context = context.clone();
        let work_started = Arc::new(AtomicBool::new(false));
        let work_started_for_closure = Arc::clone(&work_started);
        let executor = self.clone();

        let result = self
            .runtime
            .execute_result_with_context_and_reason(
                &runtime_tool_name,
                context,
                cancel,
                move || async move {
                    work_started_for_closure.store(true, Ordering::SeqCst);
                    executor
                        .execute_inner(&work_tool_name, args, &work_context, precondition.as_ref())
                        .await
                },
                executor_work_error_disposition,
            )
            .await;

        if let Err(error) = &result {
            self.emit_runtime_admission_failure_observation(
                &observation_context,
                &runtime_tool_name,
                duration_millis(started.elapsed()),
                error,
                work_started.load(Ordering::SeqCst),
            );
        }

        result
    }

    pub(crate) fn can_list_tool(&self, tool_name: &str, context: &ToolInvocationContext) -> bool {
        self.runtime.tool_visible_to_context(tool_name, context)
    }

    pub(crate) fn record_unknown_tool_call(
        &self,
        context: &ToolInvocationContext,
        tool_name: &str,
        elapsed: Duration,
    ) {
        self.emit_unknown_tool_observation(context, tool_name, duration_millis(elapsed));
    }

    pub(crate) async fn reject_task_tool_call(
        &self,
        context: ToolInvocationContext,
        tool_name: &str,
    ) -> Result<(), ToolRuntimeError> {
        let started = Instant::now();
        let result: Result<(), ToolRuntimeError> = self
            .runtime
            .execute_result_with_context_and_reason(
                tool_name,
                context.clone(),
                CancellationToken::new(),
                || async { Err(UnsupportedTaskInvocation) },
                |_| {
                    ToolWorkErrorDisposition::Failure(Some(TOOL_TASK_UNSUPPORTED_REASON.to_owned()))
                },
            )
            .await;

        if let Err(error) = &result {
            if matches!(
                error,
                ToolRuntimeError::WorkFailed {
                    reason: Some(reason),
                    ..
                } if reason == TOOL_TASK_UNSUPPORTED_REASON
            ) {
                self.emit_named_tool_observation(
                    &context,
                    tool_name,
                    ToolObservationOutcome {
                        status: TOOL_TASK_UNSUPPORTED_STATUS,
                        latency_ms: duration_millis(started.elapsed()),
                        schema_mismatch: false,
                        reason: Some(TOOL_TASK_UNSUPPORTED_REASON),
                    },
                );
            } else {
                self.emit_runtime_admission_failure_observation(
                    &context,
                    tool_name,
                    duration_millis(started.elapsed()),
                    error,
                    false,
                );
            }
        }

        result
    }

    async fn execute_inner(
        &self,
        tool_name: &str,
        args: Value,
        context: &ToolInvocationContext,
        precondition: Option<&ToolExecutionPrecondition>,
    ) -> Result<ToolExecutionResult, ToolExecutorError> {
        let lookup_started = Instant::now();
        let tool = match self.registry.get(tool_name) {
            Some(tool) => tool,
            None => {
                self.emit_unknown_tool_observation(
                    context,
                    tool_name,
                    duration_millis(lookup_started.elapsed()),
                );
                return Err(ToolExecutorError::UnknownTool {
                    tool_name: tool_name.to_owned(),
                });
            }
        };
        let validation_started = Instant::now();
        let validator = match self.validator_for(&tool) {
            Ok(validator) => validator,
            Err(error) => {
                self.emit_executor_failure_observation(
                    context,
                    &tool,
                    duration_millis(validation_started.elapsed()),
                    &error,
                );
                return Err(error);
            }
        };
        if let Err(error) = validate_args(&tool, &validator, &args) {
            if matches!(error, ToolExecutorError::InputValidation { .. }) {
                self.emit_schema_mismatch_observation(
                    context,
                    &tool,
                    duration_millis(validation_started.elapsed()),
                );
            }
            return Err(error);
        }

        if let Some(mapping) = tool.upstream.mcp_proxy_mapping() {
            self.validate_openapi_target_binding(
                context,
                &tool,
                duration_millis(validation_started.elapsed()),
            )?;
            let captured_connection_target = self.capture_mcp_connection_target(&tool, &mapping);
            self.enforce_execution_precondition(context, &tool, precondition)?;
            if precondition.is_some()
                && captured_connection_target
                    .as_ref()
                    .and_then(|target| target.as_ref().ok())
                    .is_some_and(|target| !self.mcp_connection_target_is_current(target))
            {
                return Err(ToolExecutorError::PreconditionFailed {
                    tool_name: tool.name.clone(),
                });
            }
            return self
                .execute_mcp_proxy(context, &tool, mapping, args, captured_connection_target)
                .await;
        }

        let request_build_started = Instant::now();
        let request = match self.build_request(&tool, &args) {
            Ok(request) => request,
            Err(error) => {
                self.emit_executor_failure_observation(
                    context,
                    &tool,
                    duration_millis(request_build_started.elapsed()),
                    &error,
                );
                return Err(error);
            }
        };
        if !self.runtime.authorize_http_operation(
            &tool.name,
            request.method.as_str(),
            &request.path,
            context,
        ) {
            return Err(ToolExecutorError::HttpRuleDenied {
                tool_name: tool.name.clone(),
            });
        }
        self.validate_openapi_target_binding(
            context,
            &tool,
            duration_millis(request_build_started.elapsed()),
        )?;
        let started = Instant::now();
        let request_method = request.method.clone();
        // Capture an immutable Connection target before evaluating the final
        // execution precondition. The precondition may read the old revision
        // immediately before a concurrent update publishes a new one; the
        // post-check below detects that race, while successful execution keeps
        // using only this captured target instead of rebuilding it from mutable
        // control-plane state.
        let captured_connection_target = match (&tool.target, &tool.source) {
            (
                Some(ToolTarget::Http { connection_id, .. }),
                ToolSource::OpenApi {
                    connection_id: source_connection_id,
                    ..
                },
            ) if source_connection_id != connection_id => {
                let error = ToolExecutorError::Connection {
                    tool_name: tool.name.clone(),
                    reason: "catalog_stale",
                };
                self.emit_executor_failure_observation(
                    context,
                    &tool,
                    duration_millis(started.elapsed()),
                    &error,
                );
                return Err(error);
            }
            (Some(ToolTarget::Http { .. }), source)
                if !matches!(source, ToolSource::Manual | ToolSource::OpenApi { .. }) =>
            {
                let error = ToolExecutorError::Connection {
                    tool_name: tool.name.clone(),
                    reason: "target_source_unsupported",
                };
                self.emit_executor_failure_observation(
                    context,
                    &tool,
                    duration_millis(started.elapsed()),
                    &error,
                );
                return Err(error);
            }
            (Some(ToolTarget::Http { connection_id, .. }), _) => {
                let target = self
                    .connection_http
                    .as_ref()
                    .ok_or_else(|| ToolExecutorError::Connection {
                        tool_name: tool.name.clone(),
                        reason: "connection_runtime_unavailable",
                    })
                    .and_then(|runtime| {
                        runtime
                            .target(connection_id, &request.path_and_query)
                            .map_err(|error| connection_tool_error(&tool, error))
                    });
                Some(target)
            }
            (Some(ToolTarget::Mcp { .. }), _) => None,
            (None, _) => None,
        };
        self.enforce_execution_precondition(context, &tool, precondition)?;
        if precondition.is_some()
            && captured_connection_target
                .as_ref()
                .and_then(|target| target.as_ref().ok())
                .is_some_and(|target| {
                    !self
                        .connection_http
                        .as_ref()
                        .is_some_and(|runtime| runtime.target_is_current(target))
                })
        {
            return Err(ToolExecutorError::PreconditionFailed {
                tool_name: tool.name.clone(),
            });
        }

        let (result, connection_id) = match (&tool.target, captured_connection_target) {
            (Some(ToolTarget::Http { connection_id, .. }), target) => {
                let target = target.unwrap_or_else(|| {
                    Err(ToolExecutorError::Connection {
                        tool_name: tool.name.clone(),
                        reason: "connection_runtime_unavailable",
                    })
                });
                let result = match target {
                    Ok(target) => {
                        self.execute_connection_http(context, &tool, target, request)
                            .await
                    }
                    Err(error) => Err(error),
                };
                (result, Some(connection_id.as_str()))
            }
            (Some(ToolTarget::Mcp { .. }), _) => {
                let error = ToolExecutorError::Connection {
                    tool_name: tool.name.clone(),
                    reason: "target_kind_mismatch",
                };
                self.emit_executor_failure_observation(
                    context,
                    &tool,
                    duration_millis(started.elapsed()),
                    &error,
                );
                return Err(error);
            }
            (None, _) => {
                let result = self
                    .egress_client
                    .request_with_headers(
                        request.method.clone(),
                        &request.url,
                        request.headers,
                        request.body,
                    )
                    .await
                    .map_err(|source| ToolExecutorError::Egress {
                        tool_name: tool.name.clone(),
                        source,
                    });
                (result, None)
            }
        };
        let latency_ms = duration_millis(started.elapsed());

        match result {
            Ok(response) => {
                let status = response.status.as_u16();
                self.emit_upstream_audit(
                    context,
                    &tool,
                    &request_method,
                    connection_id,
                    UpstreamAuditOutcome {
                        outcome: "success",
                        status: Some(status),
                        latency_ms,
                        reason: None,
                    },
                );
                self.emit_tool_observation(
                    context,
                    &tool,
                    ToolObservationOutcome {
                        status,
                        latency_ms,
                        schema_mismatch: false,
                        reason: None,
                    },
                );
                Ok(ToolExecutionResult::Http(response))
            }
            Err(error) => {
                let outcome = executor_failure_observation_outcome(latency_ms, &error);
                self.emit_upstream_audit(
                    context,
                    &tool,
                    &request_method,
                    connection_id,
                    UpstreamAuditOutcome {
                        outcome: "failure",
                        status: None,
                        latency_ms,
                        reason: outcome.reason,
                    },
                );
                self.emit_tool_observation(context, &tool, outcome);
                Err(error)
            }
        }
    }

    fn enforce_execution_precondition(
        &self,
        context: &ToolInvocationContext,
        tool: &ToolDefinition,
        precondition: Option<&ToolExecutionPrecondition>,
    ) -> Result<(), ToolExecutorError> {
        let Some(precondition) = precondition else {
            return Ok(());
        };
        let started = Instant::now();

        match precondition.check(tool) {
            Ok(()) => Ok(()),
            Err(ToolExecutionPreconditionError::Failed) => {
                Err(ToolExecutorError::PreconditionFailed {
                    tool_name: tool.name.clone(),
                })
            }
            Err(ToolExecutionPreconditionError::Unavailable) => {
                let error = ToolExecutorError::ExecutionStateUnavailable {
                    tool_name: tool.name.clone(),
                };
                self.emit_executor_failure_observation(
                    context,
                    tool,
                    duration_millis(started.elapsed()),
                    &error,
                );
                Err(error)
            }
        }
    }

    fn validate_openapi_target_binding(
        &self,
        context: &ToolInvocationContext,
        tool: &ToolDefinition,
        latency_ms: u64,
    ) -> Result<(), ToolExecutorError> {
        let ToolSource::OpenApi {
            connection_id: source_connection_id,
            ..
        } = &tool.source
        else {
            return Ok(());
        };
        let binding_matches = matches!(
            &tool.target,
            Some(ToolTarget::Http { connection_id, .. })
                if connection_id == source_connection_id
        );
        if binding_matches {
            return Ok(());
        }

        let error = ToolExecutorError::Connection {
            tool_name: tool.name.clone(),
            reason: "catalog_stale",
        };
        self.emit_executor_failure_observation(context, tool, latency_ms, &error);
        Err(error)
    }

    fn capture_mcp_connection_target(
        &self,
        tool: &ToolDefinition,
        mapping: &McpProxyMapping,
    ) -> Option<Result<ConnectionHttpTarget, &'static str>> {
        let Some(ToolTarget::Mcp {
            connection_id,
            remote_tool_name,
        }) = &tool.target
        else {
            return None;
        };
        if connection_id != &mapping.server_name || remote_tool_name != &mapping.tool_name {
            return None;
        }
        let Some(runtime) = self.connection_http.as_ref() else {
            return Some(Err("connection_runtime_unavailable"));
        };
        let Some(expected_etag) = self
            .mcp_catalog_runtime
            .as_ref()
            .and_then(|catalog| catalog.expected_connection_etag(connection_id))
        else {
            return Some(Err("catalog_stale"));
        };
        Some(
            runtime
                .mcp_target(connection_id)
                .map_err(|error| error.safe_reason())
                .and_then(|target| {
                    if target.connection_etag() == expected_etag {
                        Ok(target)
                    } else {
                        Err("catalog_stale")
                    }
                }),
        )
    }

    fn mcp_connection_target_is_current(&self, target: &ConnectionHttpTarget) -> bool {
        self.connection_http
            .as_ref()
            .is_some_and(|runtime| runtime.target_is_current(target))
            && self
                .mcp_catalog_runtime
                .as_ref()
                .and_then(|catalog| {
                    catalog.expected_connection_etag(target.connection_id().as_str())
                })
                .is_some_and(|etag| etag == target.connection_etag())
    }

    async fn execute_connection_http(
        &self,
        context: &ToolInvocationContext,
        tool: &ToolDefinition,
        target: ConnectionHttpTarget,
        mut request: ToolUpstreamRequest,
    ) -> Result<EgressResponse, ToolExecutorError> {
        let runtime =
            self.connection_http
                .as_ref()
                .ok_or_else(|| ToolExecutorError::Connection {
                    tool_name: tool.name.clone(),
                    reason: "connection_runtime_unavailable",
                })?;
        if matches!(tool.source, ToolSource::OpenApi { .. })
            && !self
                .openapi_catalog_runtime
                .as_ref()
                .is_some_and(|catalog| {
                    catalog.definition_is_current(tool, target.connection_etag())
                })
        {
            return Err(ToolExecutorError::Connection {
                tool_name: tool.name.clone(),
                reason: "catalog_stale",
            });
        }
        if request.method == Method::TRACE && target.authentication_kind() != "none" {
            return Err(ToolExecutorError::Connection {
                tool_name: tool.name.clone(),
                reason: "unsafe_trace_method",
            });
        }
        if let Some(header_name) = target.credential_header_name() {
            request.headers.remove(header_name);
        }

        let destination = target
            .preflight_client()
            .checked_destination(target.url())
            .await
            .map_err(|source| connection_egress_tool_error(tool, &source))?;
        let prepared = runtime
            .prepare_transport(&target, &destination)
            .await
            .map_err(|error| {
                if error.is_secret_resolution_failure() {
                    self.emit_connection_secret_resolution_failed(
                        context,
                        tool,
                        &target,
                        error.safe_reason(),
                    );
                }
                connection_tool_error(tool, error)
            })?;
        let credential = runtime.resolve_credential(&target).await.map_err(|error| {
            if error.is_secret_resolution_failure() {
                self.emit_connection_secret_resolution_failed(
                    context,
                    tool,
                    &target,
                    error.safe_reason(),
                );
            }
            connection_tool_error(tool, error)
        })?;
        if let Some(credential) = credential.as_ref() {
            credential.inject(&mut request.headers).map_err(|error| {
                if error.is_secret_resolution_failure() {
                    self.emit_connection_secret_resolution_failed(
                        context,
                        tool,
                        &target,
                        error.safe_reason(),
                    );
                }
                connection_tool_error(tool, error)
            })?;
        }

        let response = prepared
            .client()
            .stream_request_with_body_at_checked_destination(
                prepared.destination(),
                request.method,
                target.url(),
                request.headers,
                request
                    .body
                    .map_or(EgressRequestBody::Empty, EgressRequestBody::Buffered),
            )
            .await
            .map_err(|source| connection_egress_tool_error(tool, &source))?;
        if connection_authentication_rejected(response.status, target.authentication_kind()) {
            if response.status == StatusCode::UNAUTHORIZED {
                if let Some(credential) = credential
                    .as_ref()
                    .filter(|credential| credential.is_oauth())
                {
                    credential.invalidate_after_unauthorized().await;
                }
            }
            return Err(connection_tool_error(
                tool,
                ConnectionHttpError::UpstreamAuthenticationRejected,
            ));
        }
        let mut body = Vec::new();
        let mut response_body = response.body;
        while let Some(chunk) = response_body.next().await {
            body.extend_from_slice(
                &chunk.map_err(|source| connection_egress_tool_error(tool, &source))?,
            );
        }
        Ok(EgressResponse {
            status: response.status,
            headers: response.headers,
            body,
        })
    }

    async fn execute_mcp_proxy(
        &self,
        context: &ToolInvocationContext,
        tool: &ToolDefinition,
        mapping: McpProxyMapping,
        args: Value,
        captured_connection_target: Option<Result<ConnectionHttpTarget, &'static str>>,
    ) -> Result<ToolExecutionResult, ToolExecutorError> {
        let started = Instant::now();
        let managed_connection_id = match &tool.target {
            Some(ToolTarget::Mcp {
                connection_id,
                remote_tool_name,
            }) if connection_id == &mapping.server_name
                && remote_tool_name == &mapping.tool_name =>
            {
                Some(connection_id.as_str())
            }
            _ => None,
        };
        let result = if let Some(connection_id) = managed_connection_id {
            let Some(connection_http) = self.connection_http.as_ref() else {
                return self.mcp_proxy_preflight_error(
                    context,
                    tool,
                    &mapping,
                    "connection_runtime_unavailable",
                );
            };
            let target = match captured_connection_target {
                Some(Ok(target)) => target,
                Some(Err(reason)) => {
                    return self.mcp_proxy_preflight_error(context, tool, &mapping, reason);
                }
                None => {
                    return self.mcp_proxy_preflight_error(
                        context,
                        tool,
                        &mapping,
                        "catalog_stale",
                    );
                }
            };
            debug_assert_eq!(target.connection_id().as_str(), connection_id);
            mcp_upstream::call_connection_tool_at_target(
                connection_http,
                target,
                &mapping.tool_name,
                args,
            )
            .await
        } else {
            let Some(server) = self.mcp_upstream_servers.get(&mapping.server_name) else {
                return self.mcp_proxy_preflight_error(
                    context,
                    tool,
                    &mapping,
                    "unknown_mcp_upstream_server",
                );
            };
            mcp_upstream::call_tool(
                server,
                &self.mcp_upstream_runtime_config,
                Arc::clone(&self.egress_client),
                &mapping.tool_name,
                args,
            )
            .await
        };
        let latency_ms = duration_millis(started.elapsed());

        match result {
            Ok(result) => {
                self.emit_mcp_upstream_audit(
                    context,
                    tool,
                    &mapping,
                    UpstreamAuditOutcome {
                        outcome: "success",
                        status: Some(http::StatusCode::OK.as_u16()),
                        latency_ms,
                        reason: None,
                    },
                );
                self.emit_tool_observation(
                    context,
                    tool,
                    ToolObservationOutcome {
                        status: StatusCode::OK.as_u16(),
                        latency_ms,
                        schema_mismatch: false,
                        reason: None,
                    },
                );
                Ok(ToolExecutionResult::McpCallToolResult(result))
            }
            Err(source) => {
                let reason = source.reason();
                let status = mcp_upstream_error_observation_status(&source);
                self.emit_mcp_upstream_audit(
                    context,
                    tool,
                    &mapping,
                    UpstreamAuditOutcome {
                        outcome: "failure",
                        status: None,
                        latency_ms,
                        reason: Some(reason),
                    },
                );
                self.emit_tool_observation(
                    context,
                    tool,
                    ToolObservationOutcome {
                        status,
                        latency_ms,
                        schema_mismatch: false,
                        reason: Some(reason),
                    },
                );
                Err(ToolExecutorError::McpUpstream {
                    tool_name: tool.name.clone(),
                    server_name: mapping.server_name,
                    reason,
                })
            }
        }
    }

    fn mcp_proxy_preflight_error(
        &self,
        context: &ToolInvocationContext,
        tool: &ToolDefinition,
        mapping: &McpProxyMapping,
        reason: &'static str,
    ) -> Result<ToolExecutionResult, ToolExecutorError> {
        self.emit_mcp_upstream_audit(
            context,
            tool,
            mapping,
            UpstreamAuditOutcome {
                outcome: "failure",
                status: None,
                latency_ms: 0,
                reason: Some(reason),
            },
        );
        self.emit_tool_observation(
            context,
            tool,
            ToolObservationOutcome {
                status: StatusCode::BAD_GATEWAY.as_u16(),
                latency_ms: 0,
                schema_mismatch: false,
                reason: Some(reason),
            },
        );
        Err(ToolExecutorError::McpUpstream {
            tool_name: tool.name.clone(),
            server_name: mapping.server_name.clone(),
            reason,
        })
    }

    fn validator_for(
        &self,
        tool: &ToolDefinition,
    ) -> Result<Arc<jsonschema::Validator>, ToolExecutorError> {
        let effective_schema = effective_input_schema(&tool.input_schema);
        let key = ValidatorCacheKey::new(tool, &effective_schema)?;

        if let Some(validator) = self.validator_cache_guard().get(&key).cloned() {
            return Ok(validator);
        }

        let validator = Arc::new(jsonschema::validator_for(&effective_schema).map_err(|err| {
            ToolExecutorError::SchemaCompile {
                tool_name: tool.name.clone(),
                message: err.to_string(),
            }
        })?);
        let mut cache = self.validator_cache_guard();
        Ok(insert_bounded_validator(
            &mut cache,
            key,
            validator,
            MAX_VALIDATOR_CACHE_ENTRIES,
        ))
    }

    fn validator_cache_guard(&self) -> MutexGuard<'_, ValidatorCache> {
        match self.validator_cache.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn build_request(
        &self,
        tool: &ToolDefinition,
        args: &Value,
    ) -> Result<ToolUpstreamRequest, ToolExecutorError> {
        let method = tool.upstream.method.parse::<Method>().map_err(|err| {
            ToolExecutorError::InvalidMethod {
                tool_name: tool.name.clone(),
                method: tool.upstream.method.clone(),
                message: err.to_string(),
            }
        })?;
        let path = render_path_template(tool, args)?;
        let connection_target = matches!(tool.target, Some(ToolTarget::Http { .. }));
        let upstream_origin = if connection_target {
            "http://connection.invalid"
        } else {
            self.upstream_origin
                .as_deref()
                .ok_or(ToolExecutorError::MissingUpstreamUrl)?
        };
        let mut url = Url::parse(&format!("{}{}", upstream_origin, path)).map_err(|err| {
            ToolExecutorError::UrlBuild {
                tool_name: tool.name.clone(),
                message: err.to_string(),
            }
        })?;

        if !tool.upstream.query_params.is_empty() {
            let mut query = url.query_pairs_mut();
            for mapping in &tool.upstream.query_params {
                if mapping.arg_name.trim().is_empty() {
                    return Err(ToolExecutorError::InvalidMapping {
                        tool_name: tool.name.clone(),
                        message: "query parameter mapping has an empty arg_name".to_owned(),
                    });
                }
                if mapping.query_name.trim().is_empty() {
                    return Err(ToolExecutorError::InvalidMapping {
                        tool_name: tool.name.clone(),
                        message: format!(
                            "query parameter mapping for '{}' has an empty query_name",
                            mapping.arg_name
                        ),
                    });
                }

                let Some(value) = optional_argument(args, &mapping.arg_name) else {
                    if mapping.required {
                        return Err(ToolExecutorError::MissingArgument {
                            tool_name: tool.name.clone(),
                            arg_name: mapping.arg_name.clone(),
                            location: "query",
                        });
                    }
                    continue;
                };
                let value = scalar_argument_to_string(tool, &mapping.arg_name, "query", value)?;
                query.append_pair(&mapping.query_name, &value);
            }
        }

        let mut headers = HeaderMap::new();
        let body = match &tool.upstream.body {
            Some(body) => match body.mode {
                BodyMappingMode::WholeArgsJson => {
                    headers.insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/json"),
                    );
                    Some(serde_json::to_vec(args).map_err(|err| {
                        ToolExecutorError::BodySerialize {
                            tool_name: tool.name.clone(),
                            message: err.to_string(),
                        }
                    })?)
                }
            },
            None => None,
        };

        Ok(ToolUpstreamRequest {
            method,
            path: url.path().to_owned(),
            path_and_query: url[::url::Position::BeforePath..].to_owned(),
            url: url.to_string(),
            headers,
            body,
        })
    }

    fn emit_upstream_audit(
        &self,
        context: &ToolInvocationContext,
        tool: &ToolDefinition,
        method: &Method,
        connection_id: Option<&str>,
        outcome: UpstreamAuditOutcome,
    ) {
        let mut payload = json!({
            "tool_name": tool.name,
            "method": method.as_str(),
            "path_template": tool.upstream.path_template,
            "outcome": outcome.outcome,
            "latency_ms": outcome.latency_ms,
            "invocation_source": context.source.as_str(),
        });

        if let Some(status) = outcome.status {
            payload["upstream_status"] = json!(status);
        }
        if let Some(reason) = outcome.reason {
            payload["reason"] = json!(reason);
        }
        if let Some(connection_id) = connection_id {
            payload["connection_id"] = json!(connection_id);
        }

        self.audit.emit(AuditEvent::new(
            audit::event::TOOL_UPSTREAM_REQUEST,
            &context.request_id,
            &context.source_ip,
            context.actor.clone(),
            payload,
        ));
    }

    fn emit_connection_secret_resolution_failed(
        &self,
        context: &ToolInvocationContext,
        tool: &ToolDefinition,
        target: &ConnectionHttpTarget,
        reason: &'static str,
    ) {
        self.audit.emit(AuditEvent::new(
            audit::event::CONNECTION_SECRET_RESOLUTION_FAILED,
            &context.request_id,
            &context.source_ip,
            context.actor.clone(),
            json!({
                "connection_id": target.connection_id(),
                "auth_type": target.authentication_kind(),
                "consumer_kind": match tool.source {
                    ToolSource::OpenApi { .. } => "openapi_tool",
                    _ => "manual_tool",
                },
                "consumer_id": tool.name,
                "outcome": "failure",
                "reason": reason,
                "invocation_source": context.source.as_str(),
            }),
        ));
    }

    fn emit_mcp_upstream_audit(
        &self,
        context: &ToolInvocationContext,
        tool: &ToolDefinition,
        mapping: &McpProxyMapping,
        outcome: UpstreamAuditOutcome,
    ) {
        let mut payload = json!({
            "tool_name": tool.name,
            "method": MCP_TOOL_OBSERVATION_METHOD,
            "upstream_type": "mcp",
            "mcp_tool_name": mapping.tool_name,
            "outcome": outcome.outcome,
            "latency_ms": outcome.latency_ms,
            "invocation_source": context.source.as_str(),
        });
        if matches!(&tool.target, Some(ToolTarget::Mcp { .. })) {
            payload["connection_id"] = json!(mapping.server_name);
        } else {
            payload["mcp_server_name"] = json!(mapping.server_name);
        }

        if let Some(status) = outcome.status {
            payload["upstream_status"] = json!(status);
        }
        if let Some(reason) = outcome.reason {
            payload["reason"] = json!(reason);
        }

        self.audit.emit(AuditEvent::new(
            audit::event::TOOL_UPSTREAM_REQUEST,
            &context.request_id,
            &context.source_ip,
            context.actor.clone(),
            payload,
        ));
    }

    fn emit_tool_observation(
        &self,
        context: &ToolInvocationContext,
        tool: &ToolDefinition,
        outcome: ToolObservationOutcome,
    ) {
        self.emit_named_tool_observation(context, &tool.name, outcome);
    }

    fn emit_unknown_tool_observation(
        &self,
        context: &ToolInvocationContext,
        tool_name: &str,
        latency_ms: u64,
    ) {
        self.emit_named_tool_observation(
            context,
            tool_name,
            ToolObservationOutcome {
                status: StatusCode::NOT_FOUND.as_u16(),
                latency_ms,
                schema_mismatch: false,
                reason: Some(TOOL_UNKNOWN_TOOL_REASON),
            },
        );
    }

    fn emit_named_tool_observation(
        &self,
        context: &ToolInvocationContext,
        tool_name: &str,
        outcome: ToolObservationOutcome,
    ) {
        let path = tool_observation_path(tool_name);
        let endpoint_template = path.clone();
        let mut payload = json!({
                "method": MCP_TOOL_OBSERVATION_METHOD,
                "path": path,
                "endpoint_template": endpoint_template,
                "status": outcome.status,
                "latency_ms": outcome.latency_ms,
                "tool_name": tool_name,
                "schema_mismatch": outcome.schema_mismatch,
                "routing_context_known": true,
                "invocation_source": context.source.as_str(),
        });

        if let Some(reason) = outcome.reason {
            payload["reason"] = json!(reason);
        }

        self.audit.emit(AuditEvent::new(
            HTTP_REQUEST_OBSERVED,
            &context.request_id,
            &context.source_ip,
            context.actor.clone(),
            payload,
        ));
    }

    fn emit_schema_mismatch_observation(
        &self,
        context: &ToolInvocationContext,
        tool: &ToolDefinition,
        latency_ms: u64,
    ) {
        self.emit_tool_observation(
            context,
            tool,
            ToolObservationOutcome {
                status: TOOL_INPUT_VALIDATION_STATUS,
                latency_ms,
                schema_mismatch: true,
                reason: Some(TOOL_INPUT_VALIDATION_REASON),
            },
        );
    }

    fn emit_executor_failure_observation(
        &self,
        context: &ToolInvocationContext,
        tool: &ToolDefinition,
        latency_ms: u64,
        error: &ToolExecutorError,
    ) {
        let outcome = executor_failure_observation_outcome(latency_ms, error);
        self.emit_tool_observation(context, tool, outcome);
    }

    fn emit_runtime_admission_failure_observation(
        &self,
        context: &ToolInvocationContext,
        tool_name: &str,
        latency_ms: u64,
        error: &ToolRuntimeError,
        work_started: bool,
    ) {
        if matches!(error, ToolRuntimeError::UnknownTool { .. }) {
            self.emit_unknown_tool_observation(context, tool_name, latency_ms);
            return;
        }

        let Some(outcome) =
            runtime_admission_failure_observation_outcome(latency_ms, error, work_started)
        else {
            return;
        };

        match self.registry.get(tool_name) {
            Some(tool) => self.emit_tool_observation(context, &tool, outcome),
            None => self.emit_named_tool_observation(context, tool_name, outcome),
        }
    }
}

fn insert_bounded_validator(
    cache: &mut ValidatorCache,
    key: ValidatorCacheKey,
    validator: Arc<jsonschema::Validator>,
    maximum: usize,
) -> Arc<jsonschema::Validator> {
    if let Some(existing) = cache.get(&key) {
        return Arc::clone(existing);
    }
    if maximum == 0 {
        return validator;
    }
    if cache.len() >= maximum {
        cache.clear();
    }
    cache.insert(key, Arc::clone(&validator));
    validator
}

impl ValidatorCacheKey {
    fn new(tool: &ToolDefinition, schema: &Value) -> Result<Self, ToolExecutorError> {
        let schema =
            serde_json::to_vec(schema).map_err(|err| ToolExecutorError::SchemaCacheKey {
                tool_name: tool.name.clone(),
                message: err.to_string(),
            })?;
        let digest = Sha256::digest(schema);
        let mut schema_sha256 = [0; 32];
        schema_sha256.copy_from_slice(&digest);

        Ok(Self {
            tool_name: tool.name.clone(),
            schema_sha256,
        })
    }
}

fn effective_input_schema(schema: &Value) -> Value {
    schema_with_strict_object_defaults(schema, true, 0)
}

fn schema_with_strict_object_defaults(schema: &Value, is_root: bool, depth: usize) -> Value {
    if depth > MAX_STRICT_SCHEMA_INJECTION_DEPTH {
        return schema.clone();
    }

    match schema {
        Value::Object(schema) if schema_has_strict_injection_skip_keyword(schema) => {
            // Sibling additionalProperties changes jsonschema 0.46.9 behavior for
            // composition, reference, and pattern-based schemas. Leave that schema
            // level and its branches unchanged rather than pretending strictness is
            // safely enforceable there.
            Value::Object(schema.clone())
        }
        Value::Object(schema) => {
            let mut schema = schema.clone();
            stricten_child_schemas(&mut schema, depth);
            if !schema.contains_key("additionalProperties")
                && (is_root || schema_type_includes_object(&schema))
            {
                schema.insert("additionalProperties".to_owned(), Value::Bool(false));
            }
            Value::Object(schema)
        }
        _ => schema.clone(),
    }
}

fn stricten_child_schemas(schema: &mut Map<String, Value>, depth: usize) {
    stricten_property_schemas(schema, depth);
    stricten_array_item_schemas(schema, depth);
}

fn stricten_property_schemas(schema: &mut Map<String, Value>, depth: usize) {
    if let Some(Value::Object(properties)) = schema.get_mut("properties") {
        for property_schema in properties.values_mut() {
            *property_schema =
                schema_with_strict_object_defaults(property_schema, false, depth + 1);
        }
    }
}

fn stricten_array_item_schemas(schema: &mut Map<String, Value>, depth: usize) {
    stricten_array_items_keyword(schema, "items", depth);
    stricten_tuple_item_schemas(schema, "prefixItems", depth);
}

fn stricten_array_items_keyword(schema: &mut Map<String, Value>, keyword: &str, depth: usize) {
    match schema.get_mut(keyword) {
        Some(items_schema @ Value::Object(_)) => {
            *items_schema = schema_with_strict_object_defaults(items_schema, false, depth + 1);
        }
        Some(Value::Array(item_schemas)) => {
            for item_schema in item_schemas {
                *item_schema = schema_with_strict_object_defaults(item_schema, false, depth + 1);
            }
        }
        _ => {}
    }
}

fn stricten_tuple_item_schemas(schema: &mut Map<String, Value>, keyword: &str, depth: usize) {
    if let Some(Value::Array(item_schemas)) = schema.get_mut(keyword) {
        for item_schema in item_schemas {
            *item_schema = schema_with_strict_object_defaults(item_schema, false, depth + 1);
        }
    }
}

fn schema_has_strict_injection_skip_keyword(schema: &Map<String, Value>) -> bool {
    STRICT_SCHEMA_INJECTION_SKIP_KEYWORDS
        .iter()
        .any(|keyword| schema.contains_key(*keyword))
}

fn schema_type_includes_object(schema: &Map<String, Value>) -> bool {
    match schema.get("type") {
        Some(Value::String(schema_type)) => schema_type == "object",
        Some(Value::Array(schema_types)) => schema_types
            .iter()
            .any(|schema_type| schema_type.as_str() == Some("object")),
        _ => false,
    }
}

fn validate_args(
    tool: &ToolDefinition,
    validator: &jsonschema::Validator,
    args: &Value,
) -> Result<(), ToolExecutorError> {
    let problems: Vec<_> = validator
        .iter_errors(args)
        .map(|error| format!("{}: {error}", error.instance_path()))
        .collect();

    if problems.is_empty() {
        Ok(())
    } else {
        Err(ToolExecutorError::InputValidation {
            tool_name: tool.name.clone(),
            problems,
        })
    }
}

fn render_path_template(tool: &ToolDefinition, args: &Value) -> Result<String, ToolExecutorError> {
    let template = tool.upstream.path_template.as_str();
    if !template.starts_with('/') {
        return Err(ToolExecutorError::InvalidMapping {
            tool_name: tool.name.clone(),
            message: "path_template must start with '/'".to_owned(),
        });
    }
    if template.contains('?') || template.contains('#') {
        return Err(ToolExecutorError::InvalidMapping {
            tool_name: tool.name.clone(),
            message: "path_template must not include query strings or fragments".to_owned(),
        });
    }

    let mut rendered = String::with_capacity(template.len());
    let mut rest = template;
    loop {
        if let Some(close) = rest.find('}') {
            match rest.find('{') {
                Some(open) if open < close => {}
                _ => {
                    return Err(ToolExecutorError::InvalidMapping {
                        tool_name: tool.name.clone(),
                        message: "path_template contains an unmatched '}'".to_owned(),
                    });
                }
            }
        }

        let Some(open) = rest.find('{') else {
            rendered.push_str(rest);
            break;
        };
        rendered.push_str(&rest[..open]);

        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            return Err(ToolExecutorError::InvalidMapping {
                tool_name: tool.name.clone(),
                message: "path_template contains an unmatched '{'".to_owned(),
            });
        };
        let arg_name = &after_open[..close];
        validate_placeholder_name(tool, arg_name)?;
        validate_placeholder_declared_in_schema(tool, arg_name)?;
        let value = required_argument(tool, args, arg_name, "path")?;
        let value = scalar_argument_to_string(tool, arg_name, "path", value)?;
        if is_dot_segment(&value) {
            return Err(ToolExecutorError::PathSegmentIsDotSegment {
                tool_name: tool.name.clone(),
                arg_name: arg_name.to_owned(),
            });
        }
        rendered.push_str(&encode_path_segment_argument(&value));

        rest = &after_open[close + 1..];
    }

    Ok(rendered)
}

fn validate_placeholder_name(
    tool: &ToolDefinition,
    arg_name: &str,
) -> Result<(), ToolExecutorError> {
    if arg_name.is_empty() {
        return Err(ToolExecutorError::InvalidMapping {
            tool_name: tool.name.clone(),
            message: "path_template contains an empty placeholder".to_owned(),
        });
    }
    if arg_name.contains('{') || arg_name.contains('}') {
        return Err(ToolExecutorError::InvalidMapping {
            tool_name: tool.name.clone(),
            message: format!("path_template placeholder '{arg_name}' contains a brace"),
        });
    }

    Ok(())
}

fn validate_placeholder_declared_in_schema(
    tool: &ToolDefinition,
    arg_name: &str,
) -> Result<(), ToolExecutorError> {
    let Some(schema) = tool.input_schema.as_object() else {
        return Ok(());
    };
    let Some(properties) = schema.get("properties") else {
        return Ok(());
    };
    let Some(properties) = properties.as_object() else {
        return Ok(());
    };

    if properties.contains_key(arg_name) {
        Ok(())
    } else {
        Err(ToolExecutorError::InvalidMapping {
            tool_name: tool.name.clone(),
            message: format!(
                "path_template placeholder '{arg_name}' is not declared in input_json_schema.properties"
            ),
        })
    }
}

fn required_argument<'a>(
    tool: &ToolDefinition,
    args: &'a Value,
    arg_name: &str,
    location: &'static str,
) -> Result<&'a Value, ToolExecutorError> {
    optional_argument(args, arg_name).ok_or_else(|| ToolExecutorError::MissingArgument {
        tool_name: tool.name.clone(),
        arg_name: arg_name.to_owned(),
        location,
    })
}

fn optional_argument<'a>(args: &'a Value, arg_name: &str) -> Option<&'a Value> {
    args.as_object()?.get(arg_name)
}

fn scalar_argument_to_string(
    tool: &ToolDefinition,
    arg_name: &str,
    location: &'static str,
    value: &Value,
) -> Result<String, ToolExecutorError> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => {
            Err(ToolExecutorError::UnsupportedArgumentValue {
                tool_name: tool.name.clone(),
                arg_name: arg_name.to_owned(),
                location,
                value_type: json_value_type(value),
            })
        }
    }
}

fn encode_path_segment_argument(value: &str) -> String {
    utf8_percent_encode(value, PATH_SEGMENT_ARGUMENT_ENCODE_SET).to_string()
}

fn is_dot_segment(value: &str) -> bool {
    matches!(value, "." | "..")
}

fn upstream_origin_from_url(upstream_url: &str) -> Result<String, ToolExecutorError> {
    let parsed = Url::parse(upstream_url).map_err(|err| ToolExecutorError::InvalidUpstreamUrl {
        message: err.to_string(),
    })?;

    if parsed.host_str().is_none() {
        return Err(ToolExecutorError::InvalidUpstreamUrl {
            message: "missing host".to_owned(),
        });
    }
    match parsed.scheme() {
        "http" | "https" => Ok(parsed.origin().ascii_serialization()),
        scheme => Err(ToolExecutorError::InvalidUpstreamUrl {
            message: format!("unsupported scheme '{scheme}'"),
        }),
    }
}

fn json_value_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn egress_error_reason(error: &EgressError) -> &'static str {
    match error {
        EgressError::HostNotAllowed(_) => "host_not_allowed",
        EgressError::PortNotAllowed(_) => "port_not_allowed",
        // Keep the original machine reason stable for audit and alert consumers.
        EgressError::NonGlobalIpBlocked(_) => "private_ip_blocked",
        EgressError::InvalidPolicy(_) => "invalid_egress_policy",
        EgressError::DnsResolutionFailed(_) => "dns_resolution_failed",
        EgressError::InvalidUrl(_) => "invalid_url",
        EgressError::SchemeNotAllowed(_) => "scheme_not_allowed",
        EgressError::RequestBodyTooLarge { .. } => "request_body_too_large",
        EgressError::RequestBodyReadFailed => "request_body_read_failed",
        EgressError::UnexpectedStatus(_) => "unexpected_status",
        EgressError::ResponseTooLarge { .. } => "response_too_large",
        EgressError::ResponseIdleTimeout { .. } => "response_idle_timeout",
        EgressError::InvalidTlsCaBundle { .. } => "invalid_tls_ca_bundle",
        EgressError::InvalidTlsClientIdentity => "invalid_tls_client_identity",
        EgressError::Http(err) if err.is_timeout() => "timeout",
        EgressError::Http(_) => "http_error",
    }
}

fn egress_error_observation_status(error: &EgressError) -> u16 {
    if error.is_timeout() {
        StatusCode::GATEWAY_TIMEOUT.as_u16()
    } else {
        StatusCode::BAD_GATEWAY.as_u16()
    }
}

fn mcp_upstream_error_observation_status(_error: &mcp_upstream::McpUpstreamCallError) -> u16 {
    StatusCode::BAD_GATEWAY.as_u16()
}

fn connection_tool_error(tool: &ToolDefinition, error: ConnectionHttpError) -> ToolExecutorError {
    ToolExecutorError::Connection {
        tool_name: tool.name.clone(),
        reason: error.safe_reason(),
    }
}

fn connection_authentication_rejected(status: StatusCode, authentication_kind: &str) -> bool {
    matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
        && authentication_kind != "none"
}

fn connection_egress_tool_error(tool: &ToolDefinition, error: &EgressError) -> ToolExecutorError {
    ToolExecutorError::Connection {
        tool_name: tool.name.clone(),
        reason: egress_error_reason(error),
    }
}

fn executor_failure_observation_outcome(
    latency_ms: u64,
    error: &ToolExecutorError,
) -> ToolObservationOutcome {
    match error {
        ToolExecutorError::InputValidation { .. }
        | ToolExecutorError::MissingArgument { .. }
        | ToolExecutorError::UnsupportedArgumentValue { .. }
        | ToolExecutorError::PathSegmentIsDotSegment { .. } => ToolObservationOutcome {
            status: TOOL_INPUT_VALIDATION_STATUS,
            latency_ms,
            schema_mismatch: true,
            reason: Some(TOOL_INPUT_VALIDATION_REASON),
        },
        ToolExecutorError::UnknownTool { .. } => ToolObservationOutcome {
            status: StatusCode::NOT_FOUND.as_u16(),
            latency_ms,
            schema_mismatch: false,
            reason: Some(TOOL_UNKNOWN_TOOL_REASON),
        },
        ToolExecutorError::Egress { source, .. } => ToolObservationOutcome {
            status: egress_error_observation_status(source),
            latency_ms,
            schema_mismatch: false,
            reason: Some(egress_error_reason(source)),
        },
        ToolExecutorError::McpUpstream { reason, .. } => ToolObservationOutcome {
            status: StatusCode::BAD_GATEWAY.as_u16(),
            latency_ms,
            schema_mismatch: false,
            reason: Some(reason),
        },
        ToolExecutorError::Connection { reason, .. } => ToolObservationOutcome {
            status: match *reason {
                "connection_disabled"
                | "credential_unavailable"
                | "transport_unavailable"
                | "connection_runtime_unavailable" => StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                "timeout" | "response_idle_timeout" => StatusCode::GATEWAY_TIMEOUT.as_u16(),
                _ => StatusCode::BAD_GATEWAY.as_u16(),
            },
            latency_ms,
            schema_mismatch: false,
            reason: Some(reason),
        },
        ToolExecutorError::HttpRuleDenied { .. } => ToolObservationOutcome {
            status: StatusCode::FORBIDDEN.as_u16(),
            latency_ms,
            schema_mismatch: false,
            reason: Some(TOOL_MATCHED_RULE_REASON),
        },
        ToolExecutorError::PreconditionFailed { .. } => ToolObservationOutcome {
            status: StatusCode::PRECONDITION_FAILED.as_u16(),
            latency_ms,
            schema_mismatch: false,
            reason: Some(TOOL_PRECONDITION_FAILED_REASON),
        },
        ToolExecutorError::ExecutionStateUnavailable { .. } => ToolObservationOutcome {
            status: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
            latency_ms,
            schema_mismatch: false,
            reason: Some(TOOL_EXECUTION_STATE_UNAVAILABLE_REASON),
        },
        ToolExecutorError::MissingUpstreamUrl
        | ToolExecutorError::InvalidUpstreamUrl { .. }
        | ToolExecutorError::SchemaCacheKey { .. }
        | ToolExecutorError::SchemaCompile { .. }
        | ToolExecutorError::InvalidMapping { .. }
        | ToolExecutorError::InvalidMethod { .. }
        | ToolExecutorError::BodySerialize { .. }
        | ToolExecutorError::UrlBuild { .. } => ToolObservationOutcome {
            status: TOOL_EXECUTOR_CONFIGURATION_ERROR_STATUS,
            latency_ms,
            schema_mismatch: false,
            reason: Some(TOOL_EXECUTOR_CONFIGURATION_ERROR_REASON),
        },
    }
}

fn runtime_admission_failure_observation_outcome(
    latency_ms: u64,
    error: &ToolRuntimeError,
    work_started: bool,
) -> Option<ToolObservationOutcome> {
    match error {
        ToolRuntimeError::Disabled { .. } => Some(ToolObservationOutcome {
            status: StatusCode::FORBIDDEN.as_u16(),
            latency_ms,
            schema_mismatch: false,
            reason: Some(TOOL_DISABLED_REASON),
        }),
        ToolRuntimeError::RoleDenied { .. } => Some(ToolObservationOutcome {
            status: StatusCode::FORBIDDEN.as_u16(),
            latency_ms,
            schema_mismatch: false,
            reason: Some(TOOL_ROLE_NOT_ALLOWED_REASON),
        }),
        ToolRuntimeError::Rejected { reason, .. } => {
            let (status, reason) = match reason.as_str() {
                TOOL_QUEUE_FULL_REASON => (
                    StatusCode::TOO_MANY_REQUESTS.as_u16(),
                    TOOL_QUEUE_FULL_REASON,
                ),
                TOOL_MATCHED_RULE_REASON => {
                    (StatusCode::FORBIDDEN.as_u16(), TOOL_MATCHED_RULE_REASON)
                }
                TOOL_PRECONDITION_FAILED_REASON => (
                    StatusCode::PRECONDITION_FAILED.as_u16(),
                    TOOL_PRECONDITION_FAILED_REASON,
                ),
                TOOL_RUNTIME_CLOSED_REASON => (
                    StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                    TOOL_RUNTIME_CLOSED_REASON,
                ),
                _ => (
                    StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                    TOOL_RUNTIME_REJECTED_REASON,
                ),
            };
            Some(ToolObservationOutcome {
                status,
                latency_ms,
                schema_mismatch: false,
                reason: Some(reason),
            })
        }
        ToolRuntimeError::QueueTimeout { .. } => Some(ToolObservationOutcome {
            status: StatusCode::TOO_MANY_REQUESTS.as_u16(),
            latency_ms,
            schema_mismatch: false,
            reason: Some(TOOL_QUEUE_TIMEOUT_REASON),
        }),
        ToolRuntimeError::Timeout { .. } if work_started => Some(ToolObservationOutcome {
            status: StatusCode::GATEWAY_TIMEOUT.as_u16(),
            latency_ms,
            schema_mismatch: false,
            reason: Some(TOOL_TIMEOUT_REASON),
        }),
        ToolRuntimeError::Cancelled { .. } => Some(ToolObservationOutcome {
            status: StatusCode::TOO_MANY_REQUESTS.as_u16(),
            latency_ms,
            schema_mismatch: false,
            reason: Some(TOOL_CANCELLED_REASON),
        }),
        ToolRuntimeError::UnknownTool { .. }
        | ToolRuntimeError::Timeout { .. }
        | ToolRuntimeError::WorkFailed { .. } => None,
    }
}

fn executor_work_error_disposition(error: &ToolExecutorError) -> ToolWorkErrorDisposition {
    match error {
        ToolExecutorError::HttpRuleDenied { .. } => {
            return ToolWorkErrorDisposition::Rejected(TOOL_MATCHED_RULE_REASON.to_owned());
        }
        ToolExecutorError::PreconditionFailed { .. } => {
            return ToolWorkErrorDisposition::Rejected(TOOL_PRECONDITION_FAILED_REASON.to_owned());
        }
        _ => {}
    }

    ToolWorkErrorDisposition::Failure(Some(
        match error {
            ToolExecutorError::UnknownTool { .. } => TOOL_UNKNOWN_TOOL_REASON,
            ToolExecutorError::InputValidation { .. }
            | ToolExecutorError::MissingArgument { .. }
            | ToolExecutorError::UnsupportedArgumentValue { .. }
            | ToolExecutorError::PathSegmentIsDotSegment { .. } => TOOL_INVALID_PARAMS_REASON,
            ToolExecutorError::Egress { source, .. } => egress_error_reason(source),
            ToolExecutorError::McpUpstream { reason, .. } => reason,
            ToolExecutorError::Connection { reason, .. } => reason,
            ToolExecutorError::ExecutionStateUnavailable { .. } => {
                TOOL_EXECUTION_STATE_UNAVAILABLE_REASON
            }
            ToolExecutorError::MissingUpstreamUrl
            | ToolExecutorError::InvalidUpstreamUrl { .. }
            | ToolExecutorError::SchemaCacheKey { .. }
            | ToolExecutorError::SchemaCompile { .. }
            | ToolExecutorError::InvalidMapping { .. }
            | ToolExecutorError::InvalidMethod { .. }
            | ToolExecutorError::BodySerialize { .. }
            | ToolExecutorError::UrlBuild { .. } => TOOL_EXECUTOR_CONFIGURATION_ERROR_REASON,
            ToolExecutorError::HttpRuleDenied { .. }
            | ToolExecutorError::PreconditionFailed { .. } => unreachable!("handled above"),
        }
        .to_owned(),
    ))
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn tool_observation_path(tool_name: &str) -> String {
    format!("/mcp/tools/{tool_name}")
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        fs,
        net::SocketAddr,
        net::{IpAddr, Ipv4Addr},
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Mutex, MutexGuard,
        },
        time::Duration,
    };

    use http::StatusCode;
    use rusqlite::{params, Connection};
    use serde_json::json;
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
        net::TcpListener,
        sync::Notify,
    };
    use tokio_rustls::{
        rustls::{
            pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
            ServerConfig,
        },
        TlsAcceptor,
    };

    use super::*;
    use crate::{
        audit::{
            sink::{tests::CaptureSink, AuditSink, CompositeSink},
            Actor, AuditLog,
        },
        connections::{
            control_plane::ConnectionControlPlane,
            http::ConnectionHttpRuntime,
            model::{
                ConnectionAuthentication, ConnectionEndpoint, ConnectionKind, ConnectionWrite,
                OAuthClientAuthMethod, TlsProfile,
            },
            secret::{OperatorSecretAliasConfig, OperatorSecretAliasSource, SecretRootConfig},
            store::{StoredOpenApiCatalog, StoredOpenApiCatalogEntry},
        },
        discovery::{
            aggregator::{EndpointAggregatorSink, EndpointAggregatorSinkConfig},
            signals::{DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD, SCHEMA_MISMATCH_SIGNAL_TYPE},
        },
        egress::EgressConfig,
        rbac::Policy,
        tools::runtime::{
            DefaultToolPolicy, ToolInvocationSource, ToolRuntimeConfig, ToolRuntimeToolConfig,
        },
    };

    const EXPECTED_STRICT_SCHEMA_INJECTION_MAX_DEPTH: usize = 64;
    const OVERSIZED_AUTH_BODY_CANARY: &str = "oversized-oauth-auth-body-canary";
    const OAUTH_CHALLENGE_CANARY: &str = "Bearer realm=\"oversized-challenge-canary\"";
    const FIRST_OAUTH_ACCESS_TOKEN: &str = "first-oauth-access-token";
    const REPLACEMENT_OAUTH_ACCESS_TOKEN: &str = "replacement-oauth-access-token";

    #[test]
    fn non_global_egress_reason_preserves_machine_contract() {
        let error = EgressError::NonGlobalIpBlocked(
            "10.0.0.1".parse().expect("test IP address should parse"),
        );

        assert_eq!(egress_error_reason(&error), "private_ip_blocked");
    }

    #[tokio::test]
    async fn valid_args_are_mapped_to_upstream_request_and_audited() {
        let (addr, server) = one_request_server(StatusCode::CREATED, br#"{"ok":true}"#).await;
        let (executor, capture) = executor_for_tools(
            addr,
            [echo_tool()],
            runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
        );

        let response = http_response(
            executor
                .execute(
                    "echo",
                    json!({ "message": "hello" }),
                    invocation_context(),
                    CancellationToken::new(),
                )
                .await
                .expect("valid tool invocation should succeed"),
        );

        assert_eq!(response.status, StatusCode::CREATED);
        assert_eq!(response.body, br#"{"ok":true}"#);

        let request = server.await.expect("server task should join");
        assert_eq!(request.method, "POST");
        assert_eq!(request.target, "/v1/echo");
        assert_eq!(request.header("content-type"), Some("application/json"));
        assert_eq!(request.body, br#"{"message":"hello"}"#);

        let events = audit_events(&capture, 4).await;
        assert_eq!(events[0].event_type, audit::event::TOOL_INVOKE_START);
        assert_eq!(events[1].event_type, audit::event::TOOL_UPSTREAM_REQUEST);
        assert_eq!(events[2].event_type, HTTP_REQUEST_OBSERVED);
        assert_eq!(events[3].event_type, audit::event::TOOL_INVOKE_SUCCESS);
        for event in &events {
            assert_eq!(event.payload["invocation_source"], json!("internal"));
        }
        assert_eq!(events[1].payload["tool_name"], json!("echo"));
        assert_eq!(events[1].payload["method"], json!("POST"));
        assert_eq!(events[1].payload["path_template"], json!("/v1/echo"));
        assert_eq!(events[1].payload["outcome"], json!("success"));
        assert_eq!(events[1].payload["upstream_status"], json!(201));
        assert!(
            events[1].payload["latency_ms"].as_u64().is_some(),
            "upstream audit event should include latency_ms"
        );
        assert_eq!(events[2].payload["tool_name"], json!("echo"));
        assert_eq!(events[2].payload["method"], json!("MCP"));
        assert_eq!(events[2].payload["path"], json!("/mcp/tools/echo"));
        assert_eq!(
            events[2].payload["endpoint_template"],
            json!("/mcp/tools/echo")
        );
        assert_eq!(events[2].payload["status"], json!(201));
        assert_eq!(events[2].payload["schema_mismatch"], json!(false));
        assert_eq!(events[2].payload["routing_context_known"], json!(true));
        assert!(
            events[2].payload["latency_ms"].as_u64().is_some(),
            "tool observation event should include latency_ms"
        );
        assert_eq!(executor.validator_cache_guard().len(), 1);
    }

    #[tokio::test]
    async fn failed_execution_precondition_rejects_before_egress() {
        let (addr, server) = one_request_server(StatusCode::OK, b"should-not-run").await;
        let (executor, capture) = executor_for_tools(
            addr,
            [echo_tool()],
            runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
        );
        let checks = Arc::new(AtomicUsize::new(0));
        let checks_for_precondition = Arc::clone(&checks);

        let error = executor
            .execute_with_precondition(
                "echo",
                json!({ "message": "hello" }),
                invocation_context(),
                CancellationToken::new(),
                ToolExecutionPrecondition::new(move |definition| {
                    assert_eq!(definition.name, "echo");
                    checks_for_precondition.fetch_add(1, Ordering::SeqCst);
                    Err(ToolExecutionPreconditionError::Failed)
                }),
            )
            .await
            .expect_err("failed execution precondition should reject the invocation");

        assert!(matches!(
            error,
            ToolRuntimeError::Rejected { ref reason, .. }
                if reason == TOOL_PRECONDITION_FAILED_REASON
        ));
        assert_eq!(checks.load(Ordering::SeqCst), 1);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), server)
                .await
                .is_err(),
            "failed precondition must stop execution before egress"
        );

        let events = audit_events(&capture, 3).await;
        assert!(events.iter().any(|event| {
            event.event_type == audit::event::TOOL_INVOKE_REJECTED
                && event.payload["reason"] == json!(TOOL_PRECONDITION_FAILED_REASON)
        }));
        assert!(events.iter().any(|event| {
            event.event_type == HTTP_REQUEST_OBSERVED
                && event.payload["status"] == json!(StatusCode::PRECONDITION_FAILED.as_u16())
                && event.payload["reason"] == json!(TOOL_PRECONDITION_FAILED_REASON)
        }));
    }

    #[tokio::test]
    async fn unavailable_execution_precondition_is_a_safe_work_failure() {
        let (executor, capture) = executor_for_tools(
            socket_addr(1),
            [echo_tool()],
            runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
        );

        let error = executor
            .execute_with_precondition(
                "echo",
                json!({ "message": "hello" }),
                invocation_context(),
                CancellationToken::new(),
                ToolExecutionPrecondition::new(|_| {
                    Err(ToolExecutionPreconditionError::Unavailable)
                }),
            )
            .await
            .expect_err("unavailable execution state should fail closed");

        assert!(matches!(
            error,
            ToolRuntimeError::WorkFailed {
                ref reason,
                ..
            } if reason.as_deref() == Some(TOOL_EXECUTION_STATE_UNAVAILABLE_REASON)
        ));
        let events = audit_events(&capture, 3).await;
        assert!(events.iter().any(|event| {
            event.event_type == HTTP_REQUEST_OBSERVED
                && event.payload["status"] == json!(StatusCode::SERVICE_UNAVAILABLE.as_u16())
                && event.payload["reason"] == json!(TOOL_EXECUTION_STATE_UNAVAILABLE_REASON)
        }));
    }

    #[tokio::test]
    async fn schema_validation_runs_before_execution_precondition() {
        let (executor, _capture) = executor_for_tools(
            socket_addr(1),
            [echo_tool()],
            runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
        );
        let checks = Arc::new(AtomicUsize::new(0));
        let checks_for_precondition = Arc::clone(&checks);

        let error = executor
            .execute_with_precondition(
                "echo",
                json!({ "unexpected": true }),
                invocation_context(),
                CancellationToken::new(),
                ToolExecutionPrecondition::new(move |_| {
                    checks_for_precondition.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }),
            )
            .await
            .expect_err("invalid input must fail before the execution precondition");

        assert!(matches!(
            error,
            ToolRuntimeError::WorkFailed {
                ref reason,
                ..
            } if reason.as_deref() == Some(TOOL_INVALID_PARAMS_REASON)
        ));
        assert_eq!(checks.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn execution_keeps_the_checked_definition_across_registry_reloads() {
        let (addr, server) = one_request_server(StatusCode::OK, b"ok").await;
        let (executor, _capture) = executor_for_tools(
            addr,
            [echo_tool()],
            runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
        );
        let registry = executor.registry.clone();
        let replacement_registry = registry.clone();
        let mut replacement = registry
            .get("echo")
            .expect("echo definition should exist")
            .as_ref()
            .clone();
        replacement.upstream.path_template = "/v2/echo".to_owned();

        let response = http_response(
            executor
                .execute_with_precondition(
                    "echo",
                    json!({ "message": "hello" }),
                    invocation_context(),
                    CancellationToken::new(),
                    ToolExecutionPrecondition::new(move |definition| {
                        assert_eq!(definition.upstream.path_template, "/v1/echo");
                        replacement_registry
                            .replace_local_definitions_with_persist(
                                vec![replacement.clone()],
                                || Ok::<(), ()>(()),
                            )
                            .expect("replacement definition should publish");
                        Ok(())
                    }),
                )
                .await
                .expect("checked invocation should retain its original definition"),
        );

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            server.await.expect("server task should join").target,
            "/v1/echo",
            "dispatch must use the same definition that passed the precondition"
        );
        assert_eq!(
            registry
                .get("echo")
                .expect("replacement definition should exist")
                .upstream
                .path_template,
            "/v2/echo"
        );
    }

    #[tokio::test]
    async fn mcp_precondition_runs_after_schema_and_before_upstream_lookup() {
        let registry = ToolRegistry::disabled();
        registry
            .merge_definitions(vec![ToolDefinition::mcp_proxy(
                "remote_echo".to_owned(),
                "Remote echo".to_owned(),
                json!({
                    "type": "object",
                    "required": ["message"],
                    "properties": {
                        "message": { "type": "string" }
                    },
                    "additionalProperties": false
                }),
                "missing_server".to_owned(),
                "echo".to_owned(),
            )])
            .expect("MCP proxy definition should publish");
        let audit = AuditLog::new(Arc::new(CaptureSink::new()) as Arc<dyn AuditSink>);
        let runtime = ToolRuntime::new(
            runtime_config([("remote_echo", enabled_tool(500, 1))], 2, 1, 100),
            audit.clone(),
        );
        let executor = executor_for_registry_with_runtime(registry, runtime, audit, None);
        let checks = Arc::new(AtomicUsize::new(0));
        let checks_for_invalid = Arc::clone(&checks);

        let invalid = executor
            .execute_with_precondition(
                "remote_echo",
                json!({ "unexpected": true }),
                invocation_context(),
                CancellationToken::new(),
                ToolExecutionPrecondition::new(move |_| {
                    checks_for_invalid.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }),
            )
            .await
            .expect_err("MCP schema failure should precede the precondition");
        assert!(matches!(
            invalid,
            ToolRuntimeError::WorkFailed {
                ref reason,
                ..
            } if reason.as_deref() == Some(TOOL_INVALID_PARAMS_REASON)
        ));
        assert_eq!(checks.load(Ordering::SeqCst), 0);

        let checks_for_valid = Arc::clone(&checks);
        let rejected = executor
            .execute_with_precondition(
                "remote_echo",
                json!({ "message": "hello" }),
                invocation_context(),
                CancellationToken::new(),
                ToolExecutionPrecondition::new(move |_| {
                    checks_for_valid.fetch_add(1, Ordering::SeqCst);
                    Err(ToolExecutionPreconditionError::Failed)
                }),
            )
            .await
            .expect_err("MCP precondition should precede missing upstream lookup");
        assert!(matches!(
            rejected,
            ToolRuntimeError::Rejected { ref reason, .. }
                if reason == TOOL_PRECONDITION_FAILED_REASON
        ));
        assert_eq!(checks.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn compiled_validator_cache_stays_bounded_across_schema_revisions() {
        let mut cache = ValidatorCache::new();
        let validator = || {
            Arc::new(
                jsonschema::validator_for(&json!({"type": "object"}))
                    .expect("test schema should compile"),
            )
        };
        for revision in 1_u8..=2 {
            insert_bounded_validator(
                &mut cache,
                ValidatorCacheKey {
                    tool_name: "managed-tool".to_owned(),
                    schema_sha256: [revision; 32],
                },
                validator(),
                2,
            );
        }
        assert_eq!(cache.len(), 2);

        let latest_key = ValidatorCacheKey {
            tool_name: "managed-tool".to_owned(),
            schema_sha256: [3; 32],
        };
        insert_bounded_validator(&mut cache, latest_key.clone(), validator(), 2);
        assert_eq!(cache.len(), 1);
        assert!(cache.contains_key(&latest_key));

        let uncached = validator();
        let returned = insert_bounded_validator(
            &mut cache,
            ValidatorCacheKey {
                tool_name: "uncached".to_owned(),
                schema_sha256: [4; 32],
            },
            Arc::clone(&uncached),
            0,
        );
        assert!(Arc::ptr_eq(&returned, &uncached));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn connection_only_registry_does_not_require_the_legacy_upstream_url() {
        let registry = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [connection_charge_tool("billing-api")]
        }))
        .expect("connection-bound registry should load");
        let config = Config::test_defaults();
        assert!(config.upstream_url.is_none());
        let audit = AuditLog::new(Arc::new(CaptureSink::new()) as Arc<dyn AuditSink>);
        let runtime = ToolRuntime::new(
            runtime_config([("get_charge", enabled_tool(500, 1))], 2, 1, 100),
            audit.clone(),
        );
        let egress = Arc::new(
            EgressClient::new(EgressConfig::default()).expect("egress client should build"),
        );

        ToolExecutor::from_config(
            &config,
            registry,
            runtime,
            egress,
            ToolConnectionRuntimes::default(),
            audit,
        )
        .expect("a connection-only registry must not require UPSTREAM_URL");
    }

    #[tokio::test]
    async fn connection_bound_manual_tool_injects_operator_api_key_after_destination_check() {
        let (addr, ca_pem, server) = one_request_tls_server().await;
        let connection =
            TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"operator-owned-key");
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let runtime = ToolRuntime::new(
            runtime_config([("get_charge", enabled_tool(2_000, 1))], 2, 1, 100),
            audit.clone(),
        );
        let executor = executor_for_connection_tool(
            connection_charge_tool(&connection.connection_id),
            &connection,
            runtime,
            audit,
        );

        let response = http_response(
            executor
                .execute(
                    "get_charge",
                    json!({ "charge_id": "ch_123" }),
                    invocation_context(),
                    CancellationToken::new(),
                )
                .await
                .expect("connection-bound tool invocation should succeed"),
        );
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, b"secure");
        let request = server.await.expect("TLS server task should join");
        assert_eq!(request.method, "GET");
        assert_eq!(request.target, "/v1/charges/ch_123");
        assert_eq!(request.header("x-api-key"), Some("operator-owned-key"));
        assert_eq!(request.header("authorization"), None);
        assert_eq!(request.header("cookie"), None);

        let events = audit_events(&capture, 4).await;
        let upstream = events
            .iter()
            .find(|event| event.event_type == audit::event::TOOL_UPSTREAM_REQUEST)
            .expect("tool upstream event should exist");
        assert_eq!(
            upstream.payload["connection_id"],
            json!(connection.connection_id)
        );
        assert!(
            !format!("{events:?}").contains("operator-owned-key"),
            "audit events must never contain resolved credential material"
        );
    }

    #[tokio::test]
    async fn managed_openapi_tool_without_current_catalog_fails_before_upstream_io() {
        let (addr, ca_pem, server) = one_request_tls_server().await;
        let connection =
            TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"must-not-be-read");
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let runtime = ToolRuntime::new(
            runtime_config([("get_charge", enabled_tool(500, 1))], 2, 1, 100),
            audit.clone(),
        );
        let mut definition = serde_json::from_value::<ToolDefinition>(connection_charge_tool(
            &connection.connection_id,
        ))
        .expect("connection tool definition should deserialize");
        definition.source = ToolSource::OpenApi {
            connection_id: connection.connection_id.clone(),
            operation_id: Some("getCharge".to_owned()),
            catalog_revision: Some(1),
        };
        let registry = ToolRegistry::disabled();
        registry
            .replace_openapi_connection_catalog(&connection.connection_id, vec![definition], || {
                Ok::<(), ()>(())
            })
            .expect("managed OpenAPI definition should publish for the test");
        let executor = ToolExecutor::new_inner(
            registry,
            runtime,
            Arc::clone(&connection.egress_client),
            audit,
            ToolExecutorBackends {
                upstream_url: None,
                connection_http: Some(connection.runtime.clone()),
                mcp_catalog_runtime: None,
                openapi_catalog_runtime: None,
                mcp_upstream_servers: HashMap::new(),
                mcp_upstream_runtime_config: McpUpstreamRuntimeConfig {
                    timeout: Duration::from_secs(30),
                    response_idle_timeout: Duration::from_secs(30),
                    connect_timeout: Duration::from_secs(10),
                    max_request_body_bytes: 1_048_576,
                    max_response_bytes: 5_242_880,
                },
            },
        )
        .expect("connection-bound executor should build");

        let error = executor
            .execute(
                "get_charge",
                json!({ "charge_id": "ch_stale" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("missing active catalog must fail closed");
        assert!(work_failed_message(error).contains("catalog_stale"));

        let events = audit_events(&capture, 4).await;
        let upstream = events
            .iter()
            .find(|event| event.event_type == audit::event::TOOL_UPSTREAM_REQUEST)
            .expect("catalog rejection should be audited as an upstream failure");
        assert_eq!(upstream.payload["reason"], json!("catalog_stale"));
        assert_eq!(
            upstream.payload["connection_id"],
            json!(connection.connection_id)
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), server)
                .await
                .is_err(),
            "catalog validation must reject before any upstream socket is opened"
        );
    }

    #[tokio::test]
    async fn held_old_openapi_definition_fails_before_secret_or_upstream_io() {
        let (addr, ca_pem, server) = one_request_tls_server().await;
        let connection =
            TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"must-not-be-read");
        let record = connection
            .control_plane
            .runtime_snapshot()
            .managed()
            .values()
            .find(|record| record.id.as_str() == connection.connection_id)
            .cloned()
            .expect("test connection should be present");

        let mut held_definition = serde_json::from_value::<ToolDefinition>(connection_charge_tool(
            &connection.connection_id,
        ))
        .expect("connection tool definition should deserialize");
        held_definition.source = ToolSource::OpenApi {
            connection_id: connection.connection_id.clone(),
            operation_id: Some("getCharge".to_owned()),
            catalog_revision: Some(1),
        };
        let mut current_definition = held_definition.clone();
        current_definition.description =
            "Current catalog definition with a changed fingerprint.".to_owned();
        current_definition.source = ToolSource::OpenApi {
            connection_id: connection.connection_id.clone(),
            operation_id: Some("getCharge".to_owned()),
            catalog_revision: Some(2),
        };
        let current_catalog = StoredOpenApiCatalog {
            connection_id: record.id.clone(),
            spec_revision: 2,
            catalog_revision: 2,
            observed_etag: record.etag(),
            spec_digest: "current-spec-digest".to_owned(),
            spec: r#"{"openapi":"3.0.0"}"#.to_owned(),
            refreshed_at: "2026-07-28T00:00:00Z".to_owned(),
            entries: vec![StoredOpenApiCatalogEntry {
                tool_name: current_definition.name.clone(),
                operation_id: Some("getCharge".to_owned()),
                selected_scheme_names: vec!["ApiKey".to_owned()],
                definition: serde_json::to_value(&current_definition)
                    .expect("current definition should serialize"),
            }],
        };
        let openapi_catalog_runtime =
            OpenApiConnectionCatalogRuntime::from_catalogs_for_test(&[current_catalog])
                .expect("current catalog runtime should build");

        let registry = ToolRegistry::disabled();
        registry
            .replace_openapi_connection_catalog(
                &connection.connection_id,
                vec![held_definition],
                || Ok::<(), ()>(()),
            )
            .expect("held OpenAPI definition should publish for the test");
        fs::remove_file(&connection.secret_path)
            .expect("provider file should disappear before invocation");
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let runtime = ToolRuntime::new(
            runtime_config([("get_charge", enabled_tool(500, 1))], 2, 1, 100),
            audit.clone(),
        );
        let executor = ToolExecutor::new_inner(
            registry,
            runtime,
            Arc::clone(&connection.egress_client),
            audit,
            ToolExecutorBackends {
                upstream_url: None,
                connection_http: Some(connection.runtime.clone()),
                mcp_catalog_runtime: None,
                openapi_catalog_runtime: Some(openapi_catalog_runtime),
                mcp_upstream_servers: HashMap::new(),
                mcp_upstream_runtime_config: McpUpstreamRuntimeConfig {
                    timeout: Duration::from_secs(30),
                    response_idle_timeout: Duration::from_secs(30),
                    connect_timeout: Duration::from_secs(10),
                    max_request_body_bytes: 1_048_576,
                    max_response_bytes: 5_242_880,
                },
            },
        )
        .expect("connection-bound executor should build");

        let error = executor
            .execute(
                "get_charge",
                json!({ "charge_id": "ch_old_generation" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("a held definition from an old catalog generation must fail closed");
        assert!(work_failed_message(error).contains("catalog_stale"));

        let events = audit_events(&capture, 4).await;
        let upstream = events
            .iter()
            .find(|event| event.event_type == audit::event::TOOL_UPSTREAM_REQUEST)
            .expect("old catalog rejection should be audited");
        assert_eq!(upstream.payload["reason"], json!("catalog_stale"));
        assert!(events.iter().all(|event| {
            event.event_type != audit::event::CONNECTION_SECRET_RESOLUTION_FAILED
        }));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), server)
                .await
                .is_err(),
            "catalog generation validation must reject before upstream I/O"
        );
    }

    #[tokio::test]
    async fn connection_tool_auth_rejection_is_sanitized_and_recorded_as_failure() {
        const CHALLENGE_CANARY: &str = "Bearer realm=\"challenge-canary\"";
        const BODY_CANARY: &[u8] = b"upstream-auth-body-canary";
        let (addr, ca_pem, server) = one_request_tls_server_response(
            StatusCode::UNAUTHORIZED,
            BODY_CANARY,
            Some(CHALLENGE_CANARY),
        )
        .await;
        let connection =
            TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"operator-owned-key");
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let runtime = ToolRuntime::new(
            runtime_config([("get_charge", enabled_tool(2_000, 1))], 2, 1, 100),
            audit.clone(),
        );
        let executor = executor_for_connection_tool(
            connection_charge_tool(&connection.connection_id),
            &connection,
            runtime,
            audit,
        );

        let error = executor
            .execute(
                "get_charge",
                json!({ "charge_id": "ch_auth_rejected" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("credentialed upstream 401 must fail closed");
        let message = work_failed_message(error);
        assert!(message.contains("auth_failed"));
        assert!(!message.contains(CHALLENGE_CANARY));
        assert!(!message
            .contains(std::str::from_utf8(BODY_CANARY).expect("body canary should be ASCII")));

        let request = server.await.expect("TLS server task should join once");
        assert_eq!(request.method, "GET");
        assert_eq!(request.target, "/v1/charges/ch_auth_rejected");
        let events = audit_events(&capture, 4).await;
        let rendered = serde_json::to_string(&events).expect("events should serialize");
        assert!(!rendered.contains(CHALLENGE_CANARY));
        assert!(!rendered
            .contains(std::str::from_utf8(BODY_CANARY).expect("body canary should be ASCII")));
        let upstream = events
            .iter()
            .find(|event| event.event_type == audit::event::TOOL_UPSTREAM_REQUEST)
            .expect("tool upstream failure should be audited");
        assert_eq!(upstream.payload["outcome"], json!("failure"));
        assert_eq!(upstream.payload["reason"], json!("auth_failed"));
        assert_eq!(upstream.payload["upstream_status"], Value::Null);
    }

    #[tokio::test]
    async fn oversized_oauth_rejection_invalidates_before_body_buffering() {
        let (addr, ca_pem, server) = oauth_rejection_then_success_tls_server().await;
        let connection = TemporaryStaticAuthRuntime::oauth_client_credentials(addr, &ca_pem);
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let runtime = ToolRuntime::new(
            runtime_config([("get_charge", enabled_tool(2_000, 1))], 2, 1, 100),
            audit.clone(),
        );
        let executor = executor_for_connection_tool(
            connection_charge_tool(&connection.connection_id),
            &connection,
            runtime,
            audit,
        );

        let error = executor
            .execute(
                "get_charge",
                json!({ "charge_id": "ch_oauth_rejected" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("oversized OAuth 401 must fail as an authentication rejection");
        let message = work_failed_message(error);
        assert!(message.contains("auth_failed"));
        assert!(!message.contains("response_too_large"));
        assert!(!message.contains(OAUTH_CHALLENGE_CANARY));
        assert!(!message.contains(OVERSIZED_AUTH_BODY_CANARY));

        let response = http_response(
            executor
                .execute(
                    "get_charge",
                    json!({ "charge_id": "ch_after_invalidation" }),
                    invocation_context(),
                    CancellationToken::new(),
                )
                .await
                .expect("the next call should mint a replacement token and succeed"),
        );
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, b"replacement accepted");

        let requests = server.await.expect("OAuth TLS server should join");
        let token_requests = requests
            .iter()
            .filter(|request| request.target == "/oauth/token")
            .count();
        assert_eq!(
            token_requests, 2,
            "the rejected cached token must be invalidated before the next invocation"
        );
        let api_requests = requests
            .iter()
            .filter(|request| request.target.starts_with("/v1/charges/"))
            .collect::<Vec<_>>();
        assert_eq!(api_requests.len(), 2);
        let first_authorization = format!("Bearer {FIRST_OAUTH_ACCESS_TOKEN}");
        let replacement_authorization = format!("Bearer {REPLACEMENT_OAUTH_ACCESS_TOKEN}");
        assert_eq!(
            api_requests[0].header("authorization"),
            Some(first_authorization.as_str())
        );
        assert_eq!(
            api_requests[1].header("authorization"),
            Some(replacement_authorization.as_str())
        );

        let events = audit_events(&capture, 8).await;
        let rendered = serde_json::to_string(&events).expect("events should serialize");
        assert!(!rendered.contains(OAUTH_CHALLENGE_CANARY));
        assert!(!rendered.contains(OVERSIZED_AUTH_BODY_CANARY));
        assert!(events.iter().any(|event| {
            event.event_type == audit::event::TOOL_UPSTREAM_REQUEST
                && event.payload["outcome"] == json!("failure")
                && event.payload["reason"] == json!("auth_failed")
        }));
    }

    #[tokio::test]
    async fn connection_tool_checks_egress_before_reading_the_secret_provider() {
        let (addr, ca_pem, server) = one_request_tls_server().await;
        let mut connection =
            TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"unread-secret");
        fs::remove_file(&connection.secret_path)
            .expect("provider file should disappear after Connection activation");
        let blocked_config = EgressConfig::default();
        let blocked_client = Arc::new(
            EgressClient::new(blocked_config.clone()).expect("blocked egress should build"),
        );
        connection.runtime = ConnectionHttpRuntime::new(
            connection.control_plane.clone(),
            blocked_config,
            Arc::clone(&blocked_client),
        );
        connection.egress_client = blocked_client;
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let runtime = ToolRuntime::new(
            runtime_config([("get_charge", enabled_tool(500, 1))], 2, 1, 100),
            audit.clone(),
        );
        let executor = executor_for_connection_tool(
            connection_charge_tool(&connection.connection_id),
            &connection,
            runtime,
            audit,
        );

        let error = executor
            .execute(
                "get_charge",
                json!({ "charge_id": "ch_egress_first" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("non-allowlisted Connection destination must fail closed");
        let message = work_failed_message(error);
        assert!(message.contains("host_not_allowed"));
        assert!(!message.contains("127.0.0.1"));
        let events = audit_events(&capture, 3).await;
        assert!(
            events.iter().all(|event| {
                event.event_type != audit::event::CONNECTION_SECRET_RESOLUTION_FAILED
            }),
            "the provider must not be touched after an egress denial"
        );
        assert!(
            !format!("{events:?}").contains("unread-secret"),
            "failure telemetry must not contain secret material"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), server)
                .await
                .is_err(),
            "egress denial must happen before the TLS upstream receives a request"
        );
    }

    #[tokio::test]
    async fn credentialed_connection_trace_fails_before_secret_or_upstream_io() {
        let (addr, ca_pem, server) = one_request_tls_server().await;
        let connection =
            TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"must-not-be-read");
        fs::remove_file(&connection.secret_path)
            .expect("provider file should disappear before invocation");
        let mut tool = connection_charge_tool(&connection.connection_id);
        tool["target"]["mapping"]["method"] = json!("TRACE");
        tool["upstream"]["method"] = json!("TRACE");
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let runtime = ToolRuntime::new(
            runtime_config([("get_charge", enabled_tool(500, 1))], 2, 1, 100),
            audit.clone(),
        );
        let executor = executor_for_connection_tool(tool, &connection, runtime, audit);

        let error = executor
            .execute(
                "get_charge",
                json!({ "charge_id": "ch_trace" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("credentialed Connection TRACE must fail closed");
        assert!(work_failed_message(error).contains("unsafe_trace_method"));

        let events = audit_events(&capture, 4).await;
        let upstream = events
            .iter()
            .find(|event| event.event_type == audit::event::TOOL_UPSTREAM_REQUEST)
            .expect("TRACE rejection should be audited");
        assert_eq!(upstream.payload["reason"], json!("unsafe_trace_method"));
        assert!(events.iter().all(|event| {
            event.event_type != audit::event::CONNECTION_SECRET_RESOLUTION_FAILED
        }));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), server)
                .await
                .is_err(),
            "TRACE rejection must happen before opening an upstream socket"
        );
    }

    #[tokio::test]
    async fn connection_tool_secret_failure_is_safe_and_audited_without_upstream_bytes() {
        const ARGUMENT_CANARY: &str = "admin-playground-argument-canary";
        let (addr, ca_pem, server) = one_request_tls_server().await;
        let connection =
            TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, b"never-log-this");
        fs::remove_file(&connection.secret_path)
            .expect("provider file should disappear after Connection activation");
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let runtime = ToolRuntime::new(
            runtime_config([("get_charge", enabled_tool(500, 1))], 2, 1, 100),
            audit.clone(),
        );
        let executor = executor_for_connection_tool(
            connection_charge_tool(&connection.connection_id),
            &connection,
            runtime,
            audit,
        );
        let mut context = invocation_context();
        context.source = ToolInvocationSource::AdminPlayground;

        let error = executor
            .execute(
                "get_charge",
                json!({ "charge_id": ARGUMENT_CANARY }),
                context,
                CancellationToken::new(),
            )
            .await
            .expect_err("missing provider material must fail closed");
        let message = work_failed_message(error);
        assert!(message.contains("credential_unavailable"));
        assert!(!message.contains("never-log-this"));
        assert!(!message.contains("api-key"));

        let events = audit_events(&capture, 4).await;
        let failure = events
            .iter()
            .find(|event| event.event_type == audit::event::CONNECTION_SECRET_RESOLUTION_FAILED)
            .expect("secret resolution failure should emit a dedicated audit event");
        assert_eq!(
            failure.payload["connection_id"],
            json!(connection.connection_id)
        );
        assert_eq!(failure.payload["consumer_kind"], json!("manual_tool"));
        assert_eq!(failure.payload["consumer_id"], json!("get_charge"));
        assert_eq!(failure.payload["auth_type"], json!("header_api_key"));
        assert_eq!(failure.payload["reason"], json!("credential_unavailable"));
        assert_eq!(
            failure.payload["invocation_source"],
            json!("admin_playground")
        );
        assert!(failure.payload.get("arguments").is_none());
        let rendered_events =
            serde_json::to_string(&events).expect("audit events should serialize");
        assert!(!rendered_events.contains("never-log-this"));
        assert!(!rendered_events.contains(ARGUMENT_CANARY));
        assert!(!rendered_events.contains(&format!("https://127.0.0.1:{}", addr.port())));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), server)
                .await
                .is_err(),
            "credential resolution failure must happen before upstream bytes"
        );
    }

    #[tokio::test]
    async fn connection_change_during_execution_precondition_fails_before_secret_or_upstream_io() {
        const ARGUMENT_CANARY: &str = "connection-race-argument-canary";
        const SECRET_CANARY: &str = "connection-race-secret-canary";

        let (addr, ca_pem, server) = one_request_tls_server().await;
        let connection =
            TemporaryStaticAuthRuntime::header_api_key(addr, &ca_pem, SECRET_CANARY.as_bytes());
        let record = connection
            .control_plane
            .runtime_snapshot()
            .managed()
            .values()
            .find(|record| record.id.as_str() == connection.connection_id)
            .cloned()
            .expect("test Connection should be present");
        let connection_id = record.id.clone();
        let expected_etag = record.etag();
        let mut edited = record.write.clone();
        edited.endpoint.base_path = "/edited".to_owned();

        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let runtime = ToolRuntime::new(
            runtime_config([("get_charge", enabled_tool(500, 1))], 2, 1, 100),
            audit.clone(),
        );
        let executor = executor_for_connection_tool(
            connection_charge_tool(&connection.connection_id),
            &connection,
            runtime,
            audit,
        );
        let control_plane = connection.control_plane.clone();
        let secret_path = connection.secret_path.clone();
        let mut context = invocation_context();
        context.source = ToolInvocationSource::AdminPlayground;

        let error = executor
            .execute_with_precondition(
                "get_charge",
                json!({ "charge_id": ARGUMENT_CANARY }),
                context,
                CancellationToken::new(),
                ToolExecutionPrecondition::new(move |_| {
                    let observed = control_plane
                        .runtime_snapshot()
                        .managed()
                        .get(&connection_id)
                        .cloned()
                        .expect("Connection should still exist before the racing edit");
                    assert_eq!(
                        observed.etag(),
                        expected_etag,
                        "the validator must first observe the expected old revision"
                    );
                    control_plane
                        .replace_managed(&connection_id, &expected_etag, edited.clone())
                        .expect("racing Connection edit should publish");
                    fs::remove_file(&secret_path)
                        .expect("secret canary should disappear after the validator read");
                    Ok(())
                }),
            )
            .await
            .expect_err("a Connection edit during validation must fail closed");

        assert!(matches!(
            error,
            ToolRuntimeError::Rejected { ref reason, .. }
                if reason == TOOL_PRECONDITION_FAILED_REASON
        ));
        let events = audit_events(&capture, 3).await;
        assert!(events.iter().any(|event| {
            event.event_type == audit::event::TOOL_INVOKE_REJECTED
                && event.payload["reason"] == json!(TOOL_PRECONDITION_FAILED_REASON)
                && event.payload["invocation_source"] == json!("admin_playground")
        }));
        assert!(events.iter().all(|event| {
            event.event_type != audit::event::CONNECTION_SECRET_RESOLUTION_FAILED
                && event.event_type != audit::event::TOOL_UPSTREAM_REQUEST
        }));
        let rendered_events =
            serde_json::to_string(&events).expect("race audit events should serialize");
        assert!(!rendered_events.contains(ARGUMENT_CANARY));
        assert!(!rendered_events.contains(SECRET_CANARY));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), server)
                .await
                .is_err(),
            "the edited target must not receive upstream bytes"
        );
    }

    #[tokio::test]
    async fn schema_validation_rejects_args_before_network() {
        let (addr, server) = one_request_server(StatusCode::OK, b"should-not-run").await;
        let (executor, _capture) = executor_for_tools(
            addr,
            [echo_tool()],
            runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
        );

        let error = executor
            .execute(
                "echo",
                json!({ "unexpected": "value" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("invalid args should fail");

        let message = work_failed_message(error);
        assert!(message.contains("arguments failed input schema validation"));
        assert!(message.contains("required"));

        assert!(
            tokio::time::timeout(Duration::from_millis(100), server)
                .await
                .is_err(),
            "schema rejection must not reach the upstream listener"
        );
    }

    #[tokio::test]
    async fn schema_validation_rejects_unexpected_args_by_default_before_network() {
        let (addr, server) = one_request_server(StatusCode::OK, b"should-not-run").await;
        let (executor, _capture) = executor_for_tools(
            addr,
            [echo_tool_without_additional_properties()],
            runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
        );

        let error = executor
            .execute(
                "echo",
                json!({
                    "message": "hello",
                    "unexpected": "value"
                }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("unexpected args should fail without an explicit schema opt-in");

        let message = work_failed_message(error);
        assert!(message.contains("arguments failed input schema validation"));
        assert!(
            message.contains("unexpected"),
            "validation message should identify the extra argument: {message}"
        );

        assert!(
            tokio::time::timeout(Duration::from_millis(100), server)
                .await
                .is_err(),
            "strict schema rejection must not reach the upstream listener"
        );
    }

    #[tokio::test]
    async fn schema_validation_skips_strict_injection_for_top_level_one_of_schema() {
        let (addr, server) = one_request_server(StatusCode::OK, b"ok").await;
        let (executor, _capture) = executor_for_tools(
            addr,
            [one_of_echo_tool_without_additional_properties()],
            runtime_config([("echo_one_of", enabled_tool(500, 1))], 2, 1, 100),
        );

        let response = http_response(
            executor
                .execute(
                    "echo_one_of",
                    json!({ "message": "hello" }),
                    invocation_context(),
                    CancellationToken::new(),
                )
                .await
                .expect("top-level oneOf schema should validate through its branch"),
        );

        assert_eq!(response.status, StatusCode::OK);
        let request = server.await.expect("server task should join");
        assert_eq!(request.target, "/v1/echo");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&request.body)
                .expect("request body should be JSON"),
            json!({ "message": "hello" })
        );
    }

    #[tokio::test]
    async fn schema_validation_rejects_unexpected_nested_object_args_by_default_before_network() {
        let (addr, server) = one_request_server(StatusCode::OK, b"should-not-run").await;
        let (executor, _capture) = executor_for_tools(
            addr,
            [nested_config_tool_without_nested_additional_properties()],
            runtime_config([("configure", enabled_tool(500, 1))], 2, 1, 100),
        );

        let error = executor
            .execute(
                "configure",
                json!({
                    "settings": {
                        "name": "primary",
                        "unexpected": "value"
                    }
                }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("unexpected nested object args should fail by default");

        let message = work_failed_message(error);
        assert!(message.contains("arguments failed input schema validation"));
        assert!(
            message.contains("unexpected"),
            "validation message should identify the nested extra argument: {message}"
        );

        assert!(
            tokio::time::timeout(Duration::from_millis(100), server)
                .await
                .is_err(),
            "nested strict schema rejection must not reach the upstream listener"
        );
    }

    #[tokio::test]
    async fn schema_validation_rejects_unexpected_deeply_nested_object_args_by_default() {
        let (addr, server) = one_request_server(StatusCode::OK, b"should-not-run").await;
        let (executor, _capture) = executor_for_tools(
            addr,
            [deeply_nested_config_tool_without_additional_properties()],
            runtime_config([("deep_configure", enabled_tool(500, 1))], 2, 1, 100),
        );

        let error = executor
            .execute(
                "deep_configure",
                json!({
                    "settings": {
                        "limits": {
                            "rate": 10,
                            "unexpected": true
                        }
                    }
                }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("unexpected deeply nested object args should fail by default");

        let message = work_failed_message(error);
        assert!(message.contains("arguments failed input schema validation"));
        assert!(
            message.contains("unexpected"),
            "validation message should identify the deeply nested extra argument: {message}"
        );

        assert!(
            tokio::time::timeout(Duration::from_millis(100), server)
                .await
                .is_err(),
            "deeply nested strict schema rejection must not reach the upstream listener"
        );
    }

    #[test]
    fn strict_schema_injection_depth_cap_leaves_deeper_branch_unmodified_without_crashing() {
        let nested_depth = EXPECTED_STRICT_SCHEMA_INJECTION_MAX_DEPTH + 2;
        let tool = tool_definition(
            deep_schema_tool(nested_object_schema(nested_depth)),
            "deep_schema",
        );
        let effective_schema = effective_input_schema(&tool.input_schema);
        let validator = jsonschema::validator_for(&effective_schema)
            .expect("capped strict schema injection should compile without crashing");
        let args = nested_object_args_with_extra_at_depth(nested_depth, nested_depth);
        let problems = validation_problem_messages(&validator, &args);

        assert!(
            problems.is_empty(),
            "extra fields beyond the strict injection depth cap should be left to the original schema: {problems:?}"
        );
    }

    #[test]
    fn strict_schema_injection_applies_at_every_level_below_depth_cap() {
        let nested_depth = EXPECTED_STRICT_SCHEMA_INJECTION_MAX_DEPTH - 1;
        let effective_schema = effective_input_schema(&nested_object_schema(nested_depth));
        let validator = jsonschema::validator_for(&effective_schema)
            .expect("below-cap strict schema should compile");

        for extra_depth in 0..=nested_depth {
            let args = nested_object_args_with_extra_at_depth(nested_depth, extra_depth);
            let problems = validation_problem_messages(&validator, &args);
            assert!(
                !problems.is_empty(),
                "extra field at object depth {extra_depth} should be rejected below the strict injection depth cap"
            );
        }
    }

    #[tokio::test]
    async fn schema_validation_rejects_unexpected_array_item_object_args_before_network() {
        let (addr, server) = one_request_server(StatusCode::OK, b"should-not-run").await;
        let (executor, _capture) = executor_for_tools(
            addr,
            [array_items_tool_without_item_additional_properties()],
            runtime_config([("bulk_configure", enabled_tool(500, 1))], 2, 1, 100),
        );

        let error = executor
            .execute(
                "bulk_configure",
                json!({
                    "items": [
                        {
                            "name": "primary",
                            "unexpected": "value"
                        }
                    ]
                }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("unexpected array item object args should fail by default");

        let message = work_failed_message(error);
        assert!(message.contains("arguments failed input schema validation"));
        assert!(
            message.contains("unexpected"),
            "validation message should identify the array item extra argument: {message}"
        );

        assert!(
            tokio::time::timeout(Duration::from_millis(100), server)
                .await
                .is_err(),
            "array item strict schema rejection must not reach the upstream listener"
        );
    }

    #[tokio::test]
    async fn schema_validation_rejects_unexpected_prefix_item_object_args_before_network() {
        let (addr, server) = one_request_server(StatusCode::OK, b"should-not-run").await;
        let (executor, _capture) = executor_for_tools(
            addr,
            [prefix_items_tool_without_item_additional_properties()],
            runtime_config([("tuple_configure", enabled_tool(500, 1))], 2, 1, 100),
        );

        let error = executor
            .execute(
                "tuple_configure",
                json!({
                    "items": [
                        {
                            "name": "primary",
                            "unexpected": "value"
                        }
                    ]
                }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("unexpected prefix item object args should fail by default");

        let message = work_failed_message(error);
        assert!(message.contains("arguments failed input schema validation"));
        assert!(
            message.contains("unexpected"),
            "validation message should identify the prefix item extra argument: {message}"
        );

        assert!(
            tokio::time::timeout(Duration::from_millis(100), server)
                .await
                .is_err(),
            "prefix item strict schema rejection must not reach the upstream listener"
        );
    }

    #[tokio::test]
    async fn schema_validation_rejects_unexpected_nested_array_item_object_args_before_network() {
        let (addr, server) = one_request_server(StatusCode::OK, b"should-not-run").await;
        let (executor, _capture) = executor_for_tools(
            addr,
            [nested_array_items_tool_without_item_additional_properties()],
            runtime_config([("group_configure", enabled_tool(500, 1))], 2, 1, 100),
        );

        let error = executor
            .execute(
                "group_configure",
                json!({
                    "groups": [
                        {
                            "members": [
                                {
                                    "name": "alice",
                                    "unexpected": "value"
                                }
                            ]
                        }
                    ]
                }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("unexpected nested array item object args should fail by default");

        let message = work_failed_message(error);
        assert!(message.contains("arguments failed input schema validation"));
        assert!(
            message.contains("unexpected"),
            "validation message should identify the nested array item extra argument: {message}"
        );

        assert!(
            tokio::time::timeout(Duration::from_millis(100), server)
                .await
                .is_err(),
            "nested array item strict schema rejection must not reach the upstream listener"
        );
    }

    #[tokio::test]
    async fn schema_validation_respects_explicit_additional_properties_true() {
        let (addr, server) = one_request_server(StatusCode::OK, b"ok").await;
        let (executor, _capture) = executor_for_tools(
            addr,
            [echo_tool_with_additional_properties(true)],
            runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
        );

        let response = http_response(
            executor
                .execute(
                    "echo",
                    json!({
                        "message": "hello",
                        "unexpected": "allowed"
                    }),
                    invocation_context(),
                    CancellationToken::new(),
                )
                .await
                .expect("explicit additionalProperties=true should allow extra args"),
        );

        assert_eq!(response.status, StatusCode::OK);
        let request = server.await.expect("server task should join");
        assert_eq!(request.target, "/v1/echo");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&request.body)
                .expect("request body should be JSON"),
            json!({
                "message": "hello",
                "unexpected": "allowed"
            })
        );
    }

    #[tokio::test]
    async fn schema_validation_failure_feeds_schema_mismatch_aggregate_and_signal() {
        let db = TempDiscoveryDb::new("tool-schema-mismatch-signal");
        let aggregator = EndpointAggregatorSink::new(EndpointAggregatorSinkConfig {
            path: db.path.clone(),
            payload_capture_enabled: false,
            endpoint_limit: crate::config::DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
            signal_event_sender: None,
            signal_detector_config: Default::default(),
        })
        .expect("discovery aggregator sink should build");
        let audit = AuditLog::new(Arc::new(aggregator) as Arc<dyn AuditSink>);
        let executor = executor_for_tools_with_audit(
            socket_addr(1),
            [echo_tool()],
            runtime_config([("echo", enabled_tool(500, 1))], 8, 1, 100),
            audit,
        );

        for _ in 0..DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD {
            let error = executor
                .execute(
                    "echo",
                    json!({ "unexpected": "value" }),
                    invocation_context(),
                    CancellationToken::new(),
                )
                .await
                .expect_err("schema validation should reject invalid args");
            let message = work_failed_message(error);
            assert!(message.contains("arguments failed input schema validation"));
        }

        wait_until(Duration::from_secs(2), || {
            discovery_aggregate_snapshot(&db.path, "MCP", "/mcp/tools/echo").is_some_and(
                |aggregate| {
                    aggregate.call_count
                        == i64::try_from(DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD)
                            .expect("default threshold should fit i64")
                        && aggregate.schema_mismatch_count
                            == i64::try_from(DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD)
                                .expect("default threshold should fit i64")
                },
            ) && discovery_signal_rows_by_type(&db.path, SCHEMA_MISMATCH_SIGNAL_TYPE).len() == 1
        })
        .await;

        let aggregate = discovery_aggregate_snapshot(&db.path, "MCP", "/mcp/tools/echo")
            .expect("tool schema mismatch aggregate should be present");
        assert_eq!(
            aggregate.call_count,
            i64::try_from(DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD)
                .expect("default threshold should fit i64")
        );
        assert_eq!(aggregate.call_count, aggregate.schema_mismatch_count);

        let rows = discovery_signal_rows_by_type(&db.path, SCHEMA_MISMATCH_SIGNAL_TYPE);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].target_kind, "endpoint");
        assert_eq!(rows[0].target_key, "MCP /mcp/tools/echo");
        let evidence: serde_json::Value =
            serde_json::from_str(&rows[0].evidence_json).expect("signal evidence should be JSON");
        assert_eq!(
            evidence["schema_mismatch_count"],
            json!(DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD)
        );
        assert_eq!(
            evidence["threshold"],
            json!(DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD)
        );
    }

    #[tokio::test]
    async fn missing_path_placeholder_arg_is_rejected() {
        let (executor, capture) = executor_for_tools(
            socket_addr(1),
            [widget_tool(false, false)],
            runtime_config([("get_widget", enabled_tool(500, 1))], 2, 1, 100),
        );

        let error = executor
            .execute(
                "get_widget",
                json!({}),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("missing path arg should fail");

        let message = work_failed_message(error);
        assert!(message.contains("arguments failed input schema validation"));
        assert!(
            message.contains("widget_id"),
            "schema validation error should name the missing path argument: {message}"
        );

        let events = audit_events(&capture, 3).await;
        assert_eq!(events[0].event_type, audit::event::TOOL_INVOKE_START);
        assert_eq!(events[1].event_type, HTTP_REQUEST_OBSERVED);
        assert_eq!(events[2].event_type, audit::event::TOOL_INVOKE_FAILURE);
        assert_eq!(events[1].payload["tool_name"], json!("get_widget"));
        assert_eq!(events[1].payload["method"], json!("MCP"));
        assert_eq!(events[1].payload["path"], json!("/mcp/tools/get_widget"));
        assert_eq!(
            events[1].payload["endpoint_template"],
            json!("/mcp/tools/get_widget")
        );
        assert_eq!(events[1].payload["status"], json!(400));
        assert_eq!(events[1].payload["schema_mismatch"], json!(true));
        assert_eq!(events[1].payload["reason"], json!("input_validation"));
        assert!(
            events[1].payload["latency_ms"].as_u64().is_some(),
            "tool observation event should include latency_ms"
        );
    }

    #[tokio::test]
    async fn missing_upstream_url_reports_configuration_error_observation() {
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let executor = executor_for_tools_with_optional_upstream(
            [echo_tool()],
            runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
            audit,
            None,
        );

        let error = executor
            .execute(
                "echo",
                json!({ "message": "hello" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("missing upstream URL should fail during request build");

        let message = work_failed_message(error);
        assert!(message.contains("requires UPSTREAM_URL to be set"));

        let events = audit_events(&capture, 3).await;
        assert_eq!(events[0].event_type, audit::event::TOOL_INVOKE_START);
        assert_eq!(events[1].event_type, HTTP_REQUEST_OBSERVED);
        assert_eq!(events[2].event_type, audit::event::TOOL_INVOKE_FAILURE);
        assert_eq!(events[1].payload["tool_name"], json!("echo"));
        assert_eq!(events[1].payload["method"], json!("MCP"));
        assert_eq!(events[1].payload["path"], json!("/mcp/tools/echo"));
        assert_eq!(
            events[1].payload["endpoint_template"],
            json!("/mcp/tools/echo")
        );
        assert_eq!(events[1].payload["status"], json!(520));
        assert_eq!(events[1].payload["schema_mismatch"], json!(false));
        assert_eq!(
            events[1].payload["reason"],
            json!("internal_configuration_error")
        );
        assert!(
            events[1].payload["latency_ms"].as_u64().is_some(),
            "tool observation event should include latency_ms"
        );
    }

    #[tokio::test]
    async fn unknown_tool_emits_raw_name_inventory_observation() {
        let db = TempDiscoveryDb::new("tool-unknown-tool-inventory");
        let aggregator = Arc::new(
            EndpointAggregatorSink::new(EndpointAggregatorSinkConfig {
                path: db.path.clone(),
                payload_capture_enabled: false,
                endpoint_limit: crate::config::DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
                signal_event_sender: None,
                signal_detector_config: Default::default(),
            })
            .expect("discovery aggregator sink should build"),
        ) as Arc<dyn AuditSink>;
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(CompositeSink::new(vec![
            Arc::new(capture.clone()) as Arc<dyn AuditSink>,
            aggregator,
        ])) as Arc<dyn AuditSink>);
        let executor = executor_for_tools_with_audit(
            socket_addr(1),
            [echo_tool()],
            runtime_config_without_tools(DefaultToolPolicy::Allow),
            audit,
        );

        let error = executor
            .execute(
                "missing_tool",
                json!({}),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("unknown registry tool should fail inside the executor");

        let message = work_failed_message(error);
        assert!(message.contains("tool 'missing_tool' is not defined"));

        let events = audit_events(&capture, 3).await;
        assert_eq!(events[0].event_type, audit::event::TOOL_INVOKE_START);
        assert_eq!(events[1].event_type, HTTP_REQUEST_OBSERVED);
        assert_eq!(events[2].event_type, audit::event::TOOL_INVOKE_FAILURE);
        assert_eq!(events[1].payload["tool_name"], json!("missing_tool"));
        assert_eq!(events[1].payload["method"], json!("MCP"));
        assert_eq!(events[1].payload["path"], json!("/mcp/tools/missing_tool"));
        assert_eq!(
            events[1].payload["endpoint_template"],
            json!("/mcp/tools/missing_tool")
        );
        assert_eq!(events[1].payload["status"], json!(404));
        assert_eq!(events[1].payload["schema_mismatch"], json!(false));
        assert_eq!(events[1].payload["reason"], json!("unknown_tool"));
        assert!(
            events[1].payload["latency_ms"].as_u64().is_some(),
            "tool observation event should include latency_ms"
        );

        wait_until(Duration::from_secs(2), || {
            discovery_aggregate_snapshot(&db.path, "MCP", "/mcp/tools/missing_tool").is_some_and(
                |aggregate| aggregate.call_count == 1 && aggregate.schema_mismatch_count == 0,
            )
        })
        .await;

        let aggregate = discovery_aggregate_snapshot(&db.path, "MCP", "/mcp/tools/missing_tool")
            .expect("unknown tool inventory aggregate should be present");
        assert_eq!(aggregate.call_count, 1);
        assert_eq!(aggregate.schema_mismatch_count, 0);
    }

    #[tokio::test]
    async fn disabled_live_policy_tool_feeds_inventory_observation() {
        let (audit, capture, db) = inventory_audit("tool-disabled-policy-inventory");
        let runtime = live_policy_runtime(
            json!({
                "schema_version": "0.1.0",
                "tools": {
                    "echo": {
                        "enabled": false,
                        "timeout_ms": 500,
                        "max_concurrent": 1
                    }
                }
            }),
            audit.clone(),
            runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
        );
        let executor =
            executor_for_tools_with_runtime(socket_addr(1), [echo_tool()], runtime, audit);

        let error = executor
            .execute(
                "echo",
                json!({ "message": "hello" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("live policy enabled=false should reject before execution");

        assert!(matches!(error, ToolRuntimeError::Disabled { .. }));
        assert_inventory_observation(&capture, &db.path, "echo", 403, "disabled").await;
    }

    #[tokio::test]
    async fn role_denied_live_policy_tool_feeds_inventory_observation() {
        let (audit, capture, db) = inventory_audit("tool-role-denied-policy-inventory");
        let runtime = live_policy_runtime(
            json!({
                "schema_version": "0.1.0",
                "tools": {
                    "echo": {
                        "allowed_roles": ["operator"],
                        "timeout_ms": 500,
                        "max_concurrent": 1
                    }
                }
            }),
            audit.clone(),
            runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
        );
        let executor =
            executor_for_tools_with_runtime(socket_addr(1), [echo_tool()], runtime, audit);

        let error = executor
            .execute(
                "echo",
                json!({ "message": "hello" }),
                invocation_context_with_roles(&["viewer"]),
                CancellationToken::new(),
            )
            .await
            .expect_err("viewer should not satisfy the live policy allowed_roles");

        assert!(matches!(error, ToolRuntimeError::RoleDenied { .. }));
        assert_inventory_observation(&capture, &db.path, "echo", 403, "role_not_allowed").await;
    }

    #[tokio::test]
    async fn direct_http_deny_rule_blocks_rendered_tool_path_before_egress() {
        let (addr, server) = one_request_server(StatusCode::OK, b"should-not-run").await;
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let runtime = live_policy_runtime(
            json!({
                "schema_version": "0.1.0",
                "tools": {
                    "get_widget": {
                        "timeout_ms": 500,
                        "max_concurrent": 1
                    }
                },
                "rules": [
                    {
                        "id": "deny-widget-http-path",
                        "methods": ["GET"],
                        "path": "/v1/widgets/{widget_id}",
                        "action": "deny"
                    }
                ]
            }),
            audit.clone(),
            runtime_config([("get_widget", enabled_tool(500, 1))], 2, 1, 100),
        );
        let executor =
            executor_for_tools_with_runtime(addr, [widget_tool(false, true)], runtime, audit);
        let precondition_checks = Arc::new(AtomicUsize::new(0));
        let precondition_checks_for_call = Arc::clone(&precondition_checks);

        let error = executor
            .execute_with_precondition(
                "get_widget",
                json!({ "widget_id": "private/record" }),
                invocation_context(),
                CancellationToken::new(),
                ToolExecutionPrecondition::new(move |_| {
                    precondition_checks_for_call.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }),
            )
            .await
            .expect_err("matching direct HTTP Deny rule should reject the tool invocation");

        assert!(matches!(
            error,
            ToolRuntimeError::Rejected { ref reason, .. } if reason == TOOL_MATCHED_RULE_REASON
        ));
        assert_eq!(
            precondition_checks.load(Ordering::SeqCst),
            0,
            "direct HTTP policy must reject before the execution precondition"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), server)
                .await
                .is_err(),
            "direct HTTP Deny rule must stop the rendered request before egress"
        );

        let events = audit_events(&capture, 4).await;
        let denied = events
            .iter()
            .find(|event| event.event_type == "authz.denied")
            .expect("direct HTTP Deny rule should emit authz.denied");
        assert_eq!(denied.payload["tool_name"], json!("get_widget"));
        assert_eq!(denied.payload["method"], json!("GET"));
        assert_eq!(
            denied.payload["path"],
            json!("/v1/widgets/private%2Frecord")
        );
        assert_eq!(
            denied.payload["matched_rule_id"],
            json!("deny-widget-http-path")
        );
        assert_eq!(denied.payload["invocation_source"], json!("internal"));
        assert!(events.iter().any(|event| {
            event.event_type == audit::event::TOOL_INVOKE_REJECTED
                && event.payload["reason"] == json!(TOOL_MATCHED_RULE_REASON)
        }));
        assert!(events.iter().any(|event| {
            event.event_type == HTTP_REQUEST_OBSERVED
                && event.payload["status"] == json!(StatusCode::FORBIDDEN.as_u16())
                && event.payload["reason"] == json!(TOOL_MATCHED_RULE_REASON)
        }));
    }

    #[tokio::test]
    async fn direct_http_deny_rule_runs_before_connection_lookup() {
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let runtime = live_policy_runtime(
            json!({
                "schema_version": "0.1.0",
                "tools": {
                    "get_charge": {
                        "timeout_ms": 500,
                        "max_concurrent": 1
                    }
                },
                "rules": [
                    {
                        "id": "deny-charge-http-path",
                        "methods": ["GET"],
                        "path": "/charges/{charge_id}",
                        "action": "deny"
                    }
                ]
            }),
            audit.clone(),
            runtime_config([("get_charge", enabled_tool(500, 1))], 2, 1, 100),
        );
        let registry = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [connection_charge_tool("missing-connection")]
        }))
        .expect("connection-bound tool should load");
        let executor = executor_for_registry_with_runtime(registry, runtime, audit, None);

        let error = executor
            .execute(
                "get_charge",
                json!({ "charge_id": "private" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("matching deny rule should reject before Connection lookup");
        assert!(matches!(
            error,
            ToolRuntimeError::Rejected { ref reason, .. } if reason == TOOL_MATCHED_RULE_REASON
        ));
        let events = audit_events(&capture, 3).await;
        assert!(events.iter().any(|event| {
            event.event_type == "authz.denied"
                && event.payload["matched_rule_id"] == json!("deny-charge-http-path")
        }));
        assert!(events.iter().all(|event| {
            event.event_type != audit::event::CONNECTION_SECRET_RESOLUTION_FAILED
        }));
    }

    #[tokio::test]
    async fn direct_http_shadow_rule_audits_rendered_tool_path_and_allows_egress() {
        let (addr, server) = one_request_server(StatusCode::OK, b"ok").await;
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let runtime = live_policy_runtime(
            json!({
                "schema_version": "0.1.0",
                "tools": {
                    "get_widget": {
                        "timeout_ms": 500,
                        "max_concurrent": 1
                    }
                },
                "rules": [
                    {
                        "id": "shadow-widget-http-path",
                        "methods": ["GET"],
                        "path": "/v1/widgets/{widget_id}",
                        "action": "shadow"
                    }
                ]
            }),
            audit.clone(),
            runtime_config([("get_widget", enabled_tool(500, 1))], 2, 1, 100),
        );
        let executor =
            executor_for_tools_with_runtime(addr, [widget_tool(false, true)], runtime, audit);

        let response = http_response(
            executor
                .execute(
                    "get_widget",
                    json!({ "widget_id": "public" }),
                    invocation_context(),
                    CancellationToken::new(),
                )
                .await
                .expect("Shadow rule should preserve tool execution"),
        );

        assert_eq!(response.status, StatusCode::OK);
        let request = server.await.expect("server task should join");
        assert_eq!(request.target, "/v1/widgets/public?");

        let events = audit_events(&capture, 5).await;
        let shadow = events
            .iter()
            .find(|event| event.event_type == "authz.would_deny")
            .expect("direct HTTP Shadow rule should emit authz.would_deny");
        assert_eq!(shadow.payload["tool_name"], json!("get_widget"));
        assert_eq!(shadow.payload["method"], json!("GET"));
        assert_eq!(shadow.payload["path"], json!("/v1/widgets/public"));
        assert_eq!(
            shadow.payload["matched_rule_id"],
            json!("shadow-widget-http-path")
        );
    }

    #[tokio::test]
    async fn live_policy_unknown_tool_feeds_inventory_observation() {
        let (audit, capture, db) = inventory_audit("tool-live-policy-unknown-inventory");
        let runtime = live_policy_runtime(
            json!({ "schema_version": "0.1.0" }),
            audit.clone(),
            runtime_config([("echo", enabled_tool(500, 1))], 2, 1, 100),
        );
        let executor =
            executor_for_tools_with_runtime(socket_addr(1), [echo_tool()], runtime, audit);

        let error = executor
            .execute(
                "echo",
                json!({ "message": "hello" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("registered tool absent from live policy tools map should reject");

        assert!(matches!(error, ToolRuntimeError::UnknownTool { .. }));
        assert_inventory_observation(&capture, &db.path, "echo", 404, "unknown_tool").await;
    }

    #[tokio::test]
    async fn queue_full_rejection_feeds_inventory_observation() {
        let server = gated_server().await;
        let (audit, capture, db) = inventory_audit("tool-queue-full-inventory");
        let executor = executor_for_tools_with_audit(
            server.addr,
            [widget_tool(false, true)],
            runtime_config([("get_widget", enabled_tool(1_000, 1))], 1, 1, 100),
            audit,
        );

        let first = tokio::spawn({
            let executor = executor.clone();
            async move {
                executor
                    .execute(
                        "get_widget",
                        json!({ "widget_id": "first" }),
                        invocation_context(),
                        CancellationToken::new(),
                    )
                    .await
            }
        });
        wait_until(Duration::from_secs(1), || server.request_count() == 1).await;

        let error = executor
            .execute(
                "get_widget",
                json!({ "widget_id": "second" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("full runtime queue should reject before execution");

        assert!(matches!(
            error,
            ToolRuntimeError::Rejected { ref reason, .. } if reason == "queue_full"
        ));
        assert_inventory_observation(&capture, &db.path, "get_widget", 429, "queue_full").await;

        server.release.release();
        first
            .await
            .expect("first invocation task should join")
            .expect("first invocation should complete after server release");
        server.stop.cancel();
        server.handle.abort();
    }

    #[tokio::test]
    async fn execution_timeout_after_work_started_feeds_inventory_observation() {
        let server = gated_server().await;
        let (audit, capture, db) = inventory_audit("tool-execution-timeout-inventory");
        let executor = executor_for_tools_with_audit(
            server.addr,
            [widget_tool(false, true)],
            runtime_config([("get_widget", enabled_tool(100, 1))], 2, 1, 100),
            audit,
        );

        let running = tokio::spawn({
            let executor = executor.clone();
            async move {
                executor
                    .execute(
                        "get_widget",
                        json!({ "widget_id": "timeout" }),
                        invocation_context(),
                        CancellationToken::new(),
                    )
                    .await
            }
        });
        wait_until(Duration::from_secs(1), || server.request_count() == 1).await;

        let error = running
            .await
            .expect("timed-out invocation task should join")
            .expect_err("runtime timeout should abort slow upstream work");

        assert!(matches!(error, ToolRuntimeError::Timeout { .. }));
        assert_inventory_observation(&capture, &db.path, "get_widget", 504, "timeout").await;

        server.stop.cancel();
        server.handle.abort();
    }

    #[tokio::test]
    async fn mid_execution_cancellation_feeds_inventory_observation() {
        let server = gated_server().await;
        let (audit, capture, db) = inventory_audit("tool-execution-cancelled-inventory");
        let executor = executor_for_tools_with_audit(
            server.addr,
            [widget_tool(false, true)],
            runtime_config([("get_widget", enabled_tool(1_000, 1))], 2, 1, 100),
            audit,
        );
        let cancel = CancellationToken::new();

        let running = tokio::spawn({
            let executor = executor.clone();
            let cancel = cancel.clone();
            async move {
                executor
                    .execute(
                        "get_widget",
                        json!({ "widget_id": "cancelled" }),
                        invocation_context(),
                        cancel,
                    )
                    .await
            }
        });
        wait_until(Duration::from_secs(1), || server.request_count() == 1).await;
        cancel.cancel();

        let error = running
            .await
            .expect("cancelled invocation task should join")
            .expect_err("mid-execution cancellation should abort upstream work");

        assert!(matches!(error, ToolRuntimeError::Cancelled { .. }));
        assert_inventory_observation(&capture, &db.path, "get_widget", 429, "cancelled").await;

        server.stop.cancel();
        server.handle.abort();
    }

    #[tokio::test]
    async fn missing_required_query_arg_is_rejected() {
        let (executor, _capture) = executor_for_tools(
            socket_addr(1),
            [widget_tool(true, false)],
            runtime_config([("get_widget", enabled_tool(500, 1))], 2, 1, 100),
        );

        let error = executor
            .execute(
                "get_widget",
                json!({ "widget_id": "abc" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("missing required query arg should fail");

        let message = work_failed_message(error);
        assert!(message.contains("arguments failed input schema validation"));
        assert!(
            message.contains("include_details"),
            "schema validation error should name the missing query argument: {message}"
        );
    }

    #[tokio::test]
    async fn dot_dot_path_placeholder_arg_is_rejected_before_network() {
        assert_dot_segment_rejected_before_network(
            widget_tool(false, true),
            "get_widget",
            json!({ "widget_id": ".." }),
            "widget_id",
        )
        .await;
    }

    #[tokio::test]
    async fn single_dot_path_placeholder_arg_is_rejected_before_network() {
        assert_dot_segment_rejected_before_network(
            widget_tool(false, true),
            "get_widget",
            json!({ "widget_id": "." }),
            "widget_id",
        )
        .await;
    }

    #[tokio::test]
    async fn non_dot_segment_path_placeholder_args_with_dots_are_accepted_and_encoded() {
        for (value, expected_target) in [
            ("v1.2.3", "/v1/widgets/v1%2E2%2E3?include_details=true"),
            ("file.txt", "/v1/widgets/file%2Etxt?include_details=true"),
            (".hidden", "/v1/widgets/%2Ehidden?include_details=true"),
        ] {
            let (addr, server) = one_request_server(StatusCode::OK, b"safe").await;
            let (executor, _capture) = executor_for_tools(
                addr,
                [widget_tool(false, true)],
                runtime_config([("get_widget", enabled_tool(500, 1))], 2, 1, 100),
            );

            let response = http_response(
                executor
                    .execute(
                        "get_widget",
                        json!({
                            "widget_id": value,
                            "include_details": true
                        }),
                        invocation_context(),
                        CancellationToken::new(),
                    )
                    .await
                    .expect("non-dot-segment value should make a valid request"),
            );

            assert_eq!(response.status, StatusCode::OK);
            let request = server.await.expect("server task should join");
            assert_eq!(request.target, expected_target);
        }
    }

    #[tokio::test]
    async fn tenant_subtree_dot_segment_placeholder_arg_is_rejected_before_network() {
        for (args, rejected_arg_name) in [
            (
                json!({
                    "tenant_id": "..",
                    "config_name": "default"
                }),
                "tenant_id",
            ),
            (
                json!({
                    "tenant_id": "tenant-a",
                    "config_name": "."
                }),
                "config_name",
            ),
        ] {
            assert_dot_segment_rejected_before_network(
                tenant_config_tool(),
                "get_tenant_config",
                args,
                rejected_arg_name,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn path_placeholder_args_are_segment_encoded_to_block_path_injection() {
        let (addr, server) = one_request_server(StatusCode::OK, b"safe").await;
        let (executor, _capture) = executor_for_tools(
            addr,
            [widget_tool(false, true)],
            runtime_config([("get_widget", enabled_tool(500, 1))], 2, 1, 100),
        );

        let malicious = "../../../etc/passwd?host=evil.example.com#frag";
        let response = http_response(
            executor
                .execute(
                    "get_widget",
                    json!({
                        "widget_id": malicious,
                        "include_details": true
                    }),
                    invocation_context(),
                    CancellationToken::new(),
                )
                .await
                .expect("encoded malicious value should still make a valid request"),
        );

        assert_eq!(response.status, StatusCode::OK);
        let request = server.await.expect("server task should join");
        assert_eq!(
            request.target,
            "/v1/widgets/%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd%3Fhost=evil%2Eexample%2Ecom%23frag?include_details=true"
        );
        assert!(
            !request.target.contains("../"),
            "raw traversal must not survive substitution: {}",
            request.target
        );
        assert!(
            !request.target.contains("?host=evil.example.com"),
            "argument value must not introduce a query string: {}",
            request.target
        );
        assert!(
            !request.target.contains("#frag"),
            "argument value must not introduce a fragment: {}",
            request.target
        );
    }

    #[tokio::test]
    async fn runtime_timeout_cancels_slow_upstream_call() {
        let (addr, server) = delayed_response_server(Duration::from_secs(5)).await;
        let (executor, _capture) = executor_for_tools(
            addr,
            [widget_tool(false, true)],
            runtime_config([("get_widget", enabled_tool(50, 1))], 2, 1, 100),
        );

        let error = executor
            .execute(
                "get_widget",
                json!({ "widget_id": "abc" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("runtime timeout should abort slow upstream work");

        assert!(matches!(error, ToolRuntimeError::Timeout { .. }));
        server.abort();
    }

    #[tokio::test]
    async fn runtime_queue_limits_apply_to_executor_invocations() {
        let server = gated_server().await;
        let (executor, _capture) = executor_for_tools(
            server.addr,
            [widget_tool(false, true)],
            runtime_config([("get_widget", enabled_tool(1_000, 1))], 2, 1, 50),
        );

        let first = tokio::spawn({
            let executor = executor.clone();
            async move {
                executor
                    .execute(
                        "get_widget",
                        json!({ "widget_id": "first" }),
                        invocation_context(),
                        CancellationToken::new(),
                    )
                    .await
            }
        });
        wait_until(Duration::from_secs(1), || server.request_count() == 1).await;

        let second = executor
            .execute(
                "get_widget",
                json!({ "widget_id": "second" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("second invocation should time out in the runtime queue");

        assert!(matches!(second, ToolRuntimeError::QueueTimeout { .. }));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            server.request_count(),
            1,
            "queue-limited invocation must not reach upstream"
        );

        server.release.release();
        first
            .await
            .expect("first invocation task should join")
            .expect("first invocation should complete after server release");
        server.stop.cancel();
        server.handle.abort();
    }

    #[tokio::test]
    async fn default_policy_deny_blocks_registry_tool_absent_from_policy_map() {
        let server = gated_server().await;
        let (executor, _capture) = executor_for_tools(
            server.addr,
            [echo_tool()],
            runtime_config_without_tools(DefaultToolPolicy::Deny),
        );
        let precondition_checks = Arc::new(AtomicUsize::new(0));
        let precondition_checks_for_call = Arc::clone(&precondition_checks);

        let error = executor
            .execute_with_precondition(
                "echo",
                json!({ "message": "hello" }),
                invocation_context(),
                CancellationToken::new(),
                ToolExecutionPrecondition::new(move |_| {
                    precondition_checks_for_call.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }),
            )
            .await
            .expect_err("default deny should reject registry tools absent from policy map");

        assert!(matches!(error, ToolRuntimeError::UnknownTool { .. }));
        assert_eq!(
            precondition_checks.load(Ordering::SeqCst),
            0,
            "normal tool policy must reject before the execution precondition"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            server.request_count(),
            0,
            "default-policy rejection must not reach upstream"
        );

        server.stop.cancel();
        server.handle.abort();
    }

    #[tokio::test]
    async fn default_policy_allow_permits_registry_tool_absent_from_policy_map() {
        let (addr, server) = one_request_server(StatusCode::OK, b"ok").await;
        let (executor, _capture) = executor_for_tools(
            addr,
            [echo_tool()],
            runtime_config_without_tools(DefaultToolPolicy::Allow),
        );

        let response = http_response(
            executor
                .execute(
                    "echo",
                    json!({ "message": "hello" }),
                    invocation_context(),
                    CancellationToken::new(),
                )
                .await
                .expect("default allow should admit a registered tool absent from policy map"),
        );

        assert_eq!(response.status, StatusCode::OK);
        let request = server.await.expect("server task should join");
        assert_eq!(request.target, "/v1/echo");
    }

    fn http_response(result: ToolExecutionResult) -> EgressResponse {
        match result {
            ToolExecutionResult::Http(response) => response,
            ToolExecutionResult::McpCallToolResult(_) => {
                panic!("expected HTTP tool execution result")
            }
        }
    }

    fn executor_for_tools<const N: usize>(
        addr: SocketAddr,
        tools: [Value; N],
        runtime_config: ToolRuntimeConfig,
    ) -> (ToolExecutor, CaptureSink) {
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let executor = executor_for_tools_with_audit(addr, tools, runtime_config, audit);

        (executor, capture)
    }

    fn executor_for_tools_with_audit<const N: usize>(
        addr: SocketAddr,
        tools: [Value; N],
        runtime_config: ToolRuntimeConfig,
        audit: AuditLog,
    ) -> ToolExecutor {
        executor_for_tools_with_optional_upstream(
            tools,
            runtime_config,
            audit,
            Some(format!("http://127.0.0.1:{}/ignored-base", addr.port())),
        )
    }

    fn executor_for_tools_with_optional_upstream<const N: usize>(
        tools: [Value; N],
        runtime_config: ToolRuntimeConfig,
        audit: AuditLog,
        upstream_url: Option<String>,
    ) -> ToolExecutor {
        let registry = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": Value::Array(tools.into_iter().collect())
        }))
        .expect("test tools should load");
        let runtime = ToolRuntime::new(runtime_config, audit.clone());
        executor_for_registry_with_runtime(registry, runtime, audit, upstream_url)
    }

    fn executor_for_tools_with_runtime<const N: usize>(
        addr: SocketAddr,
        tools: [Value; N],
        runtime: ToolRuntime,
        audit: AuditLog,
    ) -> ToolExecutor {
        let registry = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": Value::Array(tools.into_iter().collect())
        }))
        .expect("test tools should load");
        executor_for_registry_with_runtime(
            registry,
            runtime,
            audit,
            Some(format!("http://127.0.0.1:{}/ignored-base", addr.port())),
        )
    }

    fn executor_for_registry_with_runtime(
        registry: ToolRegistry,
        runtime: ToolRuntime,
        audit: AuditLog,
        upstream_url: Option<String>,
    ) -> ToolExecutor {
        let egress_client = Arc::new(
            EgressClient::new(EgressConfig {
                allowed_hosts: ["127.0.0.1".to_owned()].into_iter().collect(),
                deny_private_ips: false,
                ..EgressConfig::default()
            })
            .expect("test egress client should build"),
        );
        let executor = ToolExecutor::new_inner(
            registry,
            runtime,
            egress_client,
            audit,
            ToolExecutorBackends {
                upstream_url,
                connection_http: None,
                mcp_catalog_runtime: None,
                openapi_catalog_runtime: None,
                mcp_upstream_servers: HashMap::new(),
                mcp_upstream_runtime_config: McpUpstreamRuntimeConfig {
                    timeout: Duration::from_secs(30),
                    response_idle_timeout: Duration::from_secs(30),
                    connect_timeout: Duration::from_secs(10),
                    max_request_body_bytes: 1_048_576,
                    max_response_bytes: 5_242_880,
                },
            },
        )
        .expect("tool executor should build");

        executor
    }

    fn executor_for_connection_tool(
        tool: Value,
        connection: &TemporaryStaticAuthRuntime,
        runtime: ToolRuntime,
        audit: AuditLog,
    ) -> ToolExecutor {
        let registry = ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect("connection-bound tool should load");
        ToolExecutor::new_inner(
            registry,
            runtime,
            Arc::clone(&connection.egress_client),
            audit,
            ToolExecutorBackends {
                upstream_url: None,
                connection_http: Some(connection.runtime.clone()),
                mcp_catalog_runtime: None,
                openapi_catalog_runtime: None,
                mcp_upstream_servers: HashMap::new(),
                mcp_upstream_runtime_config: McpUpstreamRuntimeConfig {
                    timeout: Duration::from_secs(30),
                    response_idle_timeout: Duration::from_secs(30),
                    connect_timeout: Duration::from_secs(10),
                    max_request_body_bytes: 1_048_576,
                    max_response_bytes: 5_242_880,
                },
            },
        )
        .expect("connection-bound tool executor should build without UPSTREAM_URL")
    }

    fn live_policy_runtime(
        policy_document: Value,
        audit: AuditLog,
        runtime_config: ToolRuntimeConfig,
    ) -> ToolRuntime {
        let policy =
            Policy::validate_json_value(policy_document).expect("test live policy should validate");
        let rbac_state =
            crate::middleware::rbac::RbacState::new(policy, Vec::new(), false, audit.clone());
        ToolRuntime::new_with_rbac_state(runtime_config, audit, Some(rbac_state))
    }

    fn inventory_audit(test_name: &str) -> (AuditLog, CaptureSink, TempDiscoveryDb) {
        let db = TempDiscoveryDb::new(test_name);
        let aggregator = Arc::new(
            EndpointAggregatorSink::new(EndpointAggregatorSinkConfig {
                path: db.path.clone(),
                payload_capture_enabled: false,
                endpoint_limit: crate::config::DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
                signal_event_sender: None,
                signal_detector_config: Default::default(),
            })
            .expect("discovery aggregator sink should build"),
        ) as Arc<dyn AuditSink>;
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(CompositeSink::new(vec![
            Arc::new(capture.clone()) as Arc<dyn AuditSink>,
            aggregator,
        ])) as Arc<dyn AuditSink>);

        (audit, capture, db)
    }

    fn runtime_config<const N: usize>(
        tools: [(&str, ToolRuntimeToolConfig); N],
        max_queue: usize,
        max_concurrent_global: usize,
        queue_timeout_ms: u64,
    ) -> ToolRuntimeConfig {
        ToolRuntimeConfig {
            max_queue,
            queue_timeout: Duration::from_millis(queue_timeout_ms),
            max_concurrent_global,
            default_policy: DefaultToolPolicy::Deny,
            default_timeout: Duration::from_millis(500),
            rules: Vec::new(),
            tools: tools
                .into_iter()
                .map(|(name, config)| (name.to_owned(), config))
                .collect::<HashMap<_, _>>(),
        }
    }

    fn runtime_config_without_tools(default_policy: DefaultToolPolicy) -> ToolRuntimeConfig {
        ToolRuntimeConfig {
            max_queue: 2,
            queue_timeout: Duration::from_millis(100),
            max_concurrent_global: 1,
            default_policy,
            default_timeout: Duration::from_millis(500),
            rules: Vec::new(),
            tools: HashMap::new(),
        }
    }

    fn enabled_tool(timeout_ms: u64, max_concurrent: usize) -> ToolRuntimeToolConfig {
        ToolRuntimeToolConfig {
            enabled: true,
            allowed_roles: Vec::new(),
            issuers: Vec::new(),
            auth_methods: Vec::new(),
            timeout: Duration::from_millis(timeout_ms),
            max_concurrent,
        }
    }

    fn echo_tool() -> Value {
        json!({
            "name": "echo",
            "description": "Echoes a message through a generic upstream endpoint.",
            "input_json_schema": {
                "type": "object",
                "required": ["message"],
                "properties": {
                    "message": { "type": "string" }
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
        })
    }

    fn connection_charge_tool(connection_id: &str) -> Value {
        let mapping = json!({
            "method": "GET",
            "path_template": "/charges/{charge_id}"
        });
        json!({
            "name": "get_charge",
            "description": "Looks up a charge through an operator-managed Connection.",
            "input_json_schema": {
                "type": "object",
                "required": ["charge_id"],
                "properties": {
                    "charge_id": { "type": "string" }
                },
                "additionalProperties": false
            },
            "target": {
                "type": "http",
                "connection_id": connection_id,
                "mapping": mapping
            },
            "source": {
                "type": "manual"
            },
            "upstream": mapping
        })
    }

    fn echo_tool_without_additional_properties() -> Value {
        let mut tool = echo_tool();
        tool["input_json_schema"]
            .as_object_mut()
            .expect("input schema should be an object")
            .remove("additionalProperties");
        tool
    }

    fn echo_tool_with_additional_properties(additional_properties: bool) -> Value {
        let mut tool = echo_tool();
        tool["input_json_schema"]["additionalProperties"] = json!(additional_properties);
        tool
    }

    fn one_of_echo_tool_without_additional_properties() -> Value {
        json!({
            "name": "echo_one_of",
            "description": "Echoes a message through a oneOf input schema.",
            "input_json_schema": {
                "properties": {},
                "oneOf": [
                    {
                        "type": "object",
                        "required": ["message"],
                        "properties": {
                            "message": { "type": "string" }
                        },
                        "additionalProperties": false
                    }
                ]
            },
            "upstream": {
                "method": "POST",
                "path_template": "/v1/echo",
                "body": {
                    "mode": "whole_args_json"
                }
            }
        })
    }

    fn nested_config_tool_without_nested_additional_properties() -> Value {
        json!({
            "name": "configure",
            "description": "Configures nested settings.",
            "input_json_schema": {
                "type": "object",
                "required": ["settings"],
                "properties": {
                    "settings": {
                        "type": "object",
                        "required": ["name"],
                        "properties": {
                            "name": { "type": "string" }
                        }
                    }
                }
            },
            "upstream": {
                "method": "POST",
                "path_template": "/v1/configure",
                "body": {
                    "mode": "whole_args_json"
                }
            }
        })
    }

    fn deeply_nested_config_tool_without_additional_properties() -> Value {
        json!({
            "name": "deep_configure",
            "description": "Configures deeply nested settings.",
            "input_json_schema": {
                "type": "object",
                "required": ["settings"],
                "properties": {
                    "settings": {
                        "type": "object",
                        "required": ["limits"],
                        "properties": {
                            "limits": {
                                "type": "object",
                                "required": ["rate"],
                                "properties": {
                                    "rate": { "type": "integer" }
                                }
                            }
                        }
                    }
                }
            },
            "upstream": {
                "method": "POST",
                "path_template": "/v1/configure",
                "body": {
                    "mode": "whole_args_json"
                }
            }
        })
    }

    fn array_items_tool_without_item_additional_properties() -> Value {
        json!({
            "name": "bulk_configure",
            "description": "Configures a list of named items.",
            "input_json_schema": {
                "type": "object",
                "required": ["items"],
                "properties": {
                    "items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["name"],
                            "properties": {
                                "name": { "type": "string" }
                            }
                        }
                    }
                }
            },
            "upstream": {
                "method": "POST",
                "path_template": "/v1/bulk-configure",
                "body": {
                    "mode": "whole_args_json"
                }
            }
        })
    }

    fn prefix_items_tool_without_item_additional_properties() -> Value {
        json!({
            "name": "tuple_configure",
            "description": "Configures a tuple-style list of named items.",
            "input_json_schema": {
                "type": "object",
                "required": ["items"],
                "properties": {
                    "items": {
                        "type": "array",
                        "prefixItems": [
                            {
                                "type": "object",
                                "required": ["name"],
                                "properties": {
                                    "name": { "type": "string" }
                                }
                            }
                        ]
                    }
                }
            },
            "upstream": {
                "method": "POST",
                "path_template": "/v1/tuple-configure",
                "body": {
                    "mode": "whole_args_json"
                }
            }
        })
    }

    fn nested_array_items_tool_without_item_additional_properties() -> Value {
        json!({
            "name": "group_configure",
            "description": "Configures groups with nested member arrays.",
            "input_json_schema": {
                "type": "object",
                "required": ["groups"],
                "properties": {
                    "groups": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["members"],
                            "properties": {
                                "members": {
                                    "type": "array",
                                    "items": {
                                        "type": "object",
                                        "required": ["name"],
                                        "properties": {
                                            "name": { "type": "string" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "upstream": {
                "method": "POST",
                "path_template": "/v1/group-configure",
                "body": {
                    "mode": "whole_args_json"
                }
            }
        })
    }

    fn deep_schema_tool(input_schema: Value) -> Value {
        json!({
            "name": "deep_schema",
            "description": "Exercises strict schema depth handling.",
            "input_json_schema": input_schema,
            "upstream": {
                "method": "POST",
                "path_template": "/v1/deep-schema",
                "body": {
                    "mode": "whole_args_json"
                }
            }
        })
    }

    fn nested_object_schema(nested_depth: usize) -> Value {
        let mut schema = json!({
            "type": "object",
            "required": ["value"],
            "properties": {
                "value": { "type": "string" }
            }
        });

        for depth in (0..nested_depth).rev() {
            let property_name = format!("level_{depth}");
            schema = json!({
                "type": "object",
                "required": [property_name],
                "properties": {
                    property_name: schema
                }
            });
        }

        schema
    }

    fn nested_object_args_with_extra_at_depth(nested_depth: usize, extra_depth: usize) -> Value {
        assert!(extra_depth <= nested_depth);
        nested_object_args_at_depth(0, nested_depth, extra_depth)
    }

    fn nested_object_args_at_depth(
        current_depth: usize,
        nested_depth: usize,
        extra_depth: usize,
    ) -> Value {
        let mut object = Map::new();
        if current_depth == nested_depth {
            object.insert("value".to_owned(), json!("ok"));
        } else {
            object.insert(
                format!("level_{current_depth}"),
                nested_object_args_at_depth(current_depth + 1, nested_depth, extra_depth),
            );
        }

        if current_depth == extra_depth {
            object.insert("unexpected".to_owned(), json!("value"));
        }

        Value::Object(object)
    }

    fn validation_problem_messages(validator: &jsonschema::Validator, args: &Value) -> Vec<String> {
        validator
            .iter_errors(args)
            .map(|error| format!("{}: {error}", error.instance_path()))
            .collect()
    }

    fn widget_tool(query_required: bool, _widget_required: bool) -> Value {
        let required = if query_required {
            json!(["widget_id", "include_details"])
        } else {
            json!(["widget_id"])
        };

        json!({
            "name": "get_widget",
            "description": "Looks up an illustrative widget by identifier.",
            "input_json_schema": {
                "type": "object",
                "required": required,
                "properties": {
                    "widget_id": { "type": "string" },
                    "include_details": { "type": "boolean" }
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
                        "required": query_required
                    }
                ]
            }
        })
    }

    fn tenant_config_tool() -> Value {
        json!({
            "name": "get_tenant_config",
            "description": "Reads tenant-scoped configuration.",
            "input_json_schema": {
                "type": "object",
                "required": ["tenant_id", "config_name"],
                "properties": {
                    "tenant_id": { "type": "string" },
                    "config_name": { "type": "string" }
                },
                "additionalProperties": false
            },
            "upstream": {
                "method": "GET",
                "path_template": "/v1/tenants/{tenant_id}/config/{config_name}"
            }
        })
    }

    async fn one_request_server(
        status: StatusCode,
        body: &'static [u8],
    ) -> (SocketAddr, tokio::task::JoinHandle<CapturedRequest>) {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener local address should be available");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("test server should accept one request");
            let request = read_http_request(&mut stream).await;
            write_response(&mut stream, status, body).await;
            request
        });

        (addr, handle)
    }

    async fn one_request_tls_server(
    ) -> (SocketAddr, String, tokio::task::JoinHandle<CapturedRequest>) {
        one_request_tls_server_response(StatusCode::OK, b"secure", None).await
    }

    async fn one_request_tls_server_response(
        status: StatusCode,
        body: &'static [u8],
        www_authenticate: Option<&'static str>,
    ) -> (SocketAddr, String, tokio::task::JoinHandle<CapturedRequest>) {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.distinguished_name = rcgen::DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "GreenGateway Tool Test CA");
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
        let server_certificate = server_params
            .signed_by(&server_key, &ca, &ca_key)
            .expect("test server certificate should build");
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(
                    server_certificate.der().as_ref().to_vec(),
                )],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            )
            .expect("test TLS server config should build");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test TLS listener should bind");
        let addr = listener
            .local_addr()
            .expect("test TLS listener address should be available");
        let handle = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("test TLS server should accept one request");
            let mut stream = acceptor
                .accept(stream)
                .await
                .expect("test TLS handshake should succeed");
            let request = read_http_request(&mut stream).await;
            let reason = status.canonical_reason().unwrap_or("Response");
            let challenge = www_authenticate
                .map(|value| format!("WWW-Authenticate: {value}\r\n"))
                .unwrap_or_default();
            let response = format!(
                "HTTP/1.1 {} {reason}\r\n{challenge}Content-Length: {}\r\nConnection: close\r\n\r\n",
                status.as_u16(),
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("test TLS response headers should write");
            stream
                .write_all(body)
                .await
                .expect("test TLS response body should write");
            request
        });

        (addr, ca.pem(), handle)
    }

    async fn oauth_rejection_then_success_tls_server() -> (
        SocketAddr,
        String,
        tokio::task::JoinHandle<Vec<CapturedRequest>>,
    ) {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.distinguished_name = rcgen::DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "GreenGateway OAuth Tool Test CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().expect("OAuth test CA key should generate");
        let ca = ca_params
            .self_signed(&ca_key)
            .expect("OAuth test CA certificate should build");
        let mut server_params = rcgen::CertificateParams::default();
        server_params.distinguished_name = rcgen::DistinguishedName::new();
        server_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "127.0.0.1");
        server_params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let server_key = rcgen::KeyPair::generate().expect("OAuth test server key should generate");
        let server_certificate = server_params
            .signed_by(&server_key, &ca, &ca_key)
            .expect("OAuth test server certificate should build");
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(
                    server_certificate.der().as_ref().to_vec(),
                )],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            )
            .expect("OAuth test TLS server config should build");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("OAuth test TLS listener should bind");
        let addr = listener
            .local_addr()
            .expect("OAuth test TLS listener address should be available");
        let handle = tokio::spawn(async move {
            let mut requests = Vec::new();
            let mut token_request_count = 0usize;
            let mut api_request_count = 0usize;

            while api_request_count < 2 {
                let (stream, _) = listener
                    .accept()
                    .await
                    .expect("OAuth test server should accept a request");
                let mut stream = acceptor
                    .accept(stream)
                    .await
                    .expect("OAuth test TLS handshake should succeed");
                let request = read_http_request(&mut stream).await;

                let (status, content_type, challenge, body) = if request.target == "/oauth/token" {
                    token_request_count += 1;
                    let access_token = if token_request_count == 1 {
                        FIRST_OAUTH_ACCESS_TOKEN
                    } else {
                        REPLACEMENT_OAUTH_ACCESS_TOKEN
                    };
                    (
                        StatusCode::OK,
                        Some("application/json"),
                        None,
                        serde_json::to_vec(&json!({
                            "access_token": access_token,
                            "token_type": "Bearer",
                            "expires_in": 3600
                        }))
                        .expect("OAuth token response should serialize"),
                    )
                } else {
                    api_request_count += 1;
                    if api_request_count == 1 {
                        let mut body = OVERSIZED_AUTH_BODY_CANARY.as_bytes().to_vec();
                        body.resize(256, b'x');
                        (
                            StatusCode::UNAUTHORIZED,
                            Some("text/plain"),
                            Some(OAUTH_CHALLENGE_CANARY),
                            body,
                        )
                    } else {
                        (
                            StatusCode::OK,
                            Some("text/plain"),
                            None,
                            b"replacement accepted".to_vec(),
                        )
                    }
                };
                let reason = status.canonical_reason().unwrap_or("Response");
                let content_type = content_type
                    .map(|value| format!("Content-Type: {value}\r\n"))
                    .unwrap_or_default();
                let challenge = challenge
                    .map(|value| format!("WWW-Authenticate: {value}\r\n"))
                    .unwrap_or_default();
                let response = format!(
                    "HTTP/1.1 {} {reason}\r\n{content_type}{challenge}Content-Length: {}\r\nConnection: close\r\n\r\n",
                    status.as_u16(),
                    body.len()
                );
                if stream.write_all(response.as_bytes()).await.is_ok() {
                    let _ = stream.write_all(&body).await;
                }
                requests.push(request);
            }

            requests
        });

        (addr, ca.pem(), handle)
    }

    struct TemporaryStaticAuthRuntime {
        root: PathBuf,
        secret_path: PathBuf,
        connection_id: String,
        control_plane: ConnectionControlPlane,
        runtime: ConnectionHttpRuntime,
        egress_client: Arc<EgressClient>,
    }

    impl TemporaryStaticAuthRuntime {
        fn header_api_key(addr: SocketAddr, ca_pem: &str, secret: &[u8]) -> Self {
            let root = std::env::temp_dir().join(format!(
                "greengateway-tool-static-auth-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&root).expect("temporary Connection root should create");
            let secret_path = root.join("api-key");
            fs::write(&secret_path, secret).expect("temporary API key should write");
            let ca_path = root.join("test-ca.pem");
            fs::write(&ca_path, ca_pem).expect("test CA should write");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                    .expect("temporary Connection root permissions should set");
                fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))
                    .expect("temporary API-key permissions should set");
                fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o600))
                    .expect("temporary CA permissions should set");
            }

            let mut config = Config::test_defaults();
            config.connections_sqlite_path =
                Some(root.join("connections.sqlite").display().to_string());
            config.connection_secrets_root = Some(SecretRootConfig::new(root.clone()));
            config.connection_secret_aliases = vec![OperatorSecretAliasConfig {
                id: "billing-api-key".to_owned(),
                label: "Billing API key".to_owned(),
                source: OperatorSecretAliasSource::File {
                    key: "api-key".to_owned(),
                },
            }];
            let control_plane =
                ConnectionControlPlane::from_config(&config).expect("control plane should build");
            let initial = control_plane.runtime_snapshot();
            let created = control_plane
                .create_managed(
                    initial.collection_etag(),
                    ConnectionWrite {
                        display_name: "Billing API".to_owned(),
                        description: None,
                        enabled: true,
                        kind: ConnectionKind::HttpApi,
                        endpoint: ConnectionEndpoint {
                            base_url: format!("https://127.0.0.1:{}", addr.port()),
                            base_path: "/v1".to_owned(),
                        },
                        authentication: ConnectionAuthentication::HeaderApiKey {
                            header_name: "x-api-key".to_owned(),
                            secret_id: Some("billing-api-key".to_owned()),
                        },
                        tls: TlsProfile::default(),
                        timeouts: None,
                        discovery: None,
                        test_profile: None,
                    },
                )
                .expect("test Connection should create");
            let mut egress_config = EgressConfig {
                allowed_hosts: ["127.0.0.1".to_owned()].into_iter().collect(),
                deny_private_ips: false,
                ..EgressConfig::default()
            };
            egress_config
                .apply_tls_ca_bundle_path(ca_path)
                .expect("test CA should configure");
            let egress_client = Arc::new(
                EgressClient::new(egress_config.clone()).expect("test egress client should build"),
            );
            let runtime = ConnectionHttpRuntime::new(
                control_plane.clone(),
                egress_config,
                Arc::clone(&egress_client),
            );

            Self {
                root,
                secret_path,
                connection_id: created.id.to_string(),
                control_plane,
                runtime,
                egress_client,
            }
        }

        fn oauth_client_credentials(addr: SocketAddr, ca_pem: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "greengateway-tool-static-auth-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&root).expect("temporary OAuth Connection root should create");
            let secret_path = root.join("client-secret");
            fs::write(&secret_path, b"oauth-client-secret")
                .expect("temporary OAuth client secret should write");
            let ca_path = root.join("test-ca.pem");
            fs::write(&ca_path, ca_pem).expect("OAuth test CA should write");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                    .expect("temporary OAuth Connection root permissions should set");
                fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))
                    .expect("temporary OAuth client-secret permissions should set");
                fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o600))
                    .expect("temporary OAuth CA permissions should set");
            }

            let mut config = Config::test_defaults();
            config.connections_sqlite_path =
                Some(root.join("connections.sqlite").display().to_string());
            config.connection_secrets_root = Some(SecretRootConfig::new(root.clone()));
            config.connection_secret_aliases = vec![OperatorSecretAliasConfig {
                id: "billing-oauth-client-secret".to_owned(),
                label: "Billing OAuth client secret".to_owned(),
                source: OperatorSecretAliasSource::File {
                    key: "client-secret".to_owned(),
                },
            }];
            let control_plane =
                ConnectionControlPlane::from_config(&config).expect("control plane should build");
            let initial = control_plane.runtime_snapshot();
            let created = control_plane
                .create_managed(
                    initial.collection_etag(),
                    ConnectionWrite {
                        display_name: "Billing OAuth API".to_owned(),
                        description: None,
                        enabled: true,
                        kind: ConnectionKind::HttpApi,
                        endpoint: ConnectionEndpoint {
                            base_url: format!("https://127.0.0.1:{}", addr.port()),
                            base_path: "/v1".to_owned(),
                        },
                        authentication: ConnectionAuthentication::OAuth2ClientCredentials {
                            client_id: "billing-client".to_owned(),
                            client_secret_id: Some("billing-oauth-client-secret".to_owned()),
                            token_url: format!("https://127.0.0.1:{}/oauth/token", addr.port()),
                            scopes: Vec::new(),
                            audience: None,
                            resource: None,
                            client_auth_method: OAuthClientAuthMethod::ClientSecretBasic,
                        },
                        tls: TlsProfile::default(),
                        timeouts: None,
                        discovery: None,
                        test_profile: None,
                    },
                )
                .expect("OAuth test Connection should create");
            let mut egress_config = EgressConfig {
                allowed_hosts: ["127.0.0.1".to_owned()].into_iter().collect(),
                max_response_bytes: 128,
                deny_private_ips: false,
                ..EgressConfig::default()
            };
            egress_config
                .apply_tls_ca_bundle_path(ca_path)
                .expect("OAuth test CA should configure");
            let egress_client = Arc::new(
                EgressClient::new(egress_config.clone())
                    .expect("OAuth test egress client should build"),
            );
            let runtime = ConnectionHttpRuntime::new(
                control_plane.clone(),
                egress_config,
                Arc::clone(&egress_client),
            );

            Self {
                root,
                secret_path,
                connection_id: created.id.to_string(),
                control_plane,
                runtime,
                egress_client,
            }
        }
    }

    impl Drop for TemporaryStaticAuthRuntime {
        fn drop(&mut self) {
            if self
                .root
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("greengateway-tool-static-auth-"))
                && self.root.starts_with(std::env::temp_dir())
            {
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }

    async fn delayed_response_server(
        delay: Duration,
    ) -> (SocketAddr, tokio::task::JoinHandle<CapturedRequest>) {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener local address should be available");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("test server should accept one request");
            let request = read_http_request(&mut stream).await;
            tokio::time::sleep(delay).await;
            write_response(&mut stream, StatusCode::OK, b"late").await;
            request
        });

        (addr, handle)
    }

    async fn gated_server() -> GatedServer {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener local address should be available");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let release = ReleaseGate::new();
        let stop = CancellationToken::new();
        let handle = tokio::spawn({
            let requests = Arc::clone(&requests);
            let release = release.clone();
            let stop = stop.clone();
            async move {
                loop {
                    tokio::select! {
                        _ = stop.cancelled() => break,
                        accepted = listener.accept() => {
                        let (mut stream, _) = accepted.expect("test server accept should succeed");
                        let requests = Arc::clone(&requests);
                        let release = release.clone();
                        tokio::spawn(async move {
                            let request = read_http_request(&mut stream).await;
                            requests_guard(&requests).push(request);
                            release.wait().await;
                            write_response(&mut stream, StatusCode::OK, b"released").await;
                        });
                        }
                    }
                }
            }
        });

        GatedServer {
            addr,
            requests,
            release,
            stop,
            handle,
        }
    }

    async fn read_http_request<S>(stream: &mut S) -> CapturedRequest
    where
        S: AsyncRead + Unpin,
    {
        let mut bytes = Vec::new();
        let mut buffer = [0; 1024];

        loop {
            let count = stream
                .read(&mut buffer)
                .await
                .expect("test server should read request bytes");
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..count]);

            if let Some(header_end) = header_end(&bytes) {
                let content_length = content_length(&bytes[..header_end]);
                if bytes.len() >= header_end + 4 + content_length {
                    break;
                }
            }
        }

        let header_end = header_end(&bytes).expect("request should include complete headers");
        let head = String::from_utf8_lossy(&bytes[..header_end]);
        let mut lines = head.lines();
        let request_line = lines.next().expect("request should include request line");
        let mut request_parts = request_line.split_whitespace();
        let method = request_parts
            .next()
            .expect("request line should include method")
            .to_owned();
        let target = request_parts
            .next()
            .expect("request line should include target")
            .to_owned();
        let headers = lines
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                Some((name.trim().to_ascii_lowercase(), value.trim().to_owned()))
            })
            .collect::<HashMap<_, _>>();
        let body = bytes[header_end + 4..].to_vec();

        CapturedRequest {
            method,
            target,
            headers,
            body,
        }
    }

    async fn write_response<S>(stream: &mut S, status: StatusCode, body: &[u8])
    where
        S: AsyncWrite + Unpin,
    {
        let reason = status.canonical_reason().unwrap_or("OK");
        let response = format!(
            "HTTP/1.1 {} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            status.as_u16(),
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("test response headers should write");
        stream
            .write_all(body)
            .await
            .expect("test response body should write");
    }

    fn header_end(bytes: &[u8]) -> Option<usize> {
        bytes.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn content_length(header_bytes: &[u8]) -> usize {
        let head = String::from_utf8_lossy(header_bytes);
        head.lines()
            .filter_map(|line| line.split_once(':'))
            .find_map(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0)
    }

    async fn audit_events(capture: &CaptureSink, expected_count: usize) -> Vec<AuditEvent> {
        wait_until(Duration::from_secs(1), || capture.len() >= expected_count).await;
        capture.events()
    }

    async fn wait_until(timeout: Duration, condition: impl Fn() -> bool) {
        let started = Instant::now();

        while started.elapsed() < timeout {
            if condition() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert!(
            condition(),
            "condition did not become true within {timeout:?}"
        );
    }

    fn work_failed_message(error: ToolRuntimeError) -> String {
        match error {
            ToolRuntimeError::WorkFailed { message, .. } => message,
            other => panic!("expected work failure, got {other:?}"),
        }
    }

    fn invocation_context() -> ToolInvocationContext {
        ToolInvocationContext {
            request_id: "request-tool-test".to_owned(),
            source_ip: "203.0.113.10".to_owned(),
            actor: None,
            source: ToolInvocationSource::Internal,
        }
    }

    fn invocation_context_with_roles(roles: &[&str]) -> ToolInvocationContext {
        ToolInvocationContext {
            request_id: "request-tool-test".to_owned(),
            source_ip: "203.0.113.10".to_owned(),
            actor: Some(Actor {
                user_id: "user-123".to_owned(),
                issuer: None,
                email: None,
                roles: Some(roles.iter().map(|role| (*role).to_owned()).collect()),
                auth_mode: "bearer_token".to_owned(),
            }),
            source: ToolInvocationSource::Internal,
        }
    }

    fn socket_addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[derive(Debug)]
    struct DiscoveryAggregateSnapshot {
        call_count: i64,
        schema_mismatch_count: i64,
    }

    fn discovery_aggregate_snapshot(
        path: &Path,
        method: &str,
        endpoint_template: &str,
    ) -> Option<DiscoveryAggregateSnapshot> {
        let connection = Connection::open(path).expect("test database should open");
        connection
            .query_row(
                r#"
                SELECT call_count, schema_mismatch_count
                FROM discovery_endpoint_aggregates
                WHERE method = ?1 AND endpoint_template = ?2
                "#,
                params![method, endpoint_template],
                |row| {
                    Ok(DiscoveryAggregateSnapshot {
                        call_count: row.get(0)?,
                        schema_mismatch_count: row.get(1)?,
                    })
                },
            )
            .ok()
    }

    #[derive(Debug)]
    struct DiscoverySignalRow {
        target_kind: String,
        target_key: String,
        evidence_json: String,
    }

    fn discovery_signal_rows_by_type(path: &Path, signal_type: &str) -> Vec<DiscoverySignalRow> {
        let connection = Connection::open(path).expect("test database should open");
        let mut statement = connection
            .prepare(
                r#"
                SELECT target_kind, target_key, evidence_json
                FROM discovery_signals
                WHERE signal_type = ?1
                ORDER BY created_at, id
                "#,
            )
            .expect("signal query should prepare");

        statement
            .query_map(params![signal_type], |row| {
                Ok(DiscoverySignalRow {
                    target_kind: row.get(0)?,
                    target_key: row.get(1)?,
                    evidence_json: row.get(2)?,
                })
            })
            .expect("signal query should run")
            .collect::<Result<Vec<_>, _>>()
            .expect("signal rows should read")
    }

    async fn assert_inventory_observation(
        capture: &CaptureSink,
        db_path: &Path,
        tool_name: &str,
        status: u16,
        reason: &str,
    ) {
        wait_until(Duration::from_secs(1), || {
            capture.events().iter().any(|event| {
                event.event_type == HTTP_REQUEST_OBSERVED
                    && event.payload["tool_name"] == json!(tool_name)
                    && event.payload["status"] == json!(status)
                    && event.payload["reason"] == json!(reason)
            })
        })
        .await;

        let events = capture.events();
        let observation = events
            .iter()
            .find(|event| {
                event.event_type == HTTP_REQUEST_OBSERVED
                    && event.payload["tool_name"] == json!(tool_name)
            })
            .unwrap_or_else(|| panic!("expected inventory observation in {events:#?}"));
        assert_eq!(observation.payload["method"], json!("MCP"));
        assert_eq!(
            observation.payload["path"],
            json!(format!("/mcp/tools/{tool_name}"))
        );
        assert_eq!(
            observation.payload["endpoint_template"],
            json!(format!("/mcp/tools/{tool_name}"))
        );
        assert_eq!(observation.payload["status"], json!(status));
        assert_eq!(observation.payload["schema_mismatch"], json!(false));
        assert_eq!(observation.payload["routing_context_known"], json!(true));
        assert_eq!(observation.payload["reason"], json!(reason));
        assert!(
            observation.payload["latency_ms"].as_u64().is_some(),
            "tool observation event should include latency_ms"
        );

        wait_until(Duration::from_secs(2), || {
            discovery_aggregate_snapshot(db_path, "MCP", &format!("/mcp/tools/{tool_name}"))
                .is_some_and(|aggregate| {
                    aggregate.call_count == 1 && aggregate.schema_mismatch_count == 0
                })
        })
        .await;
        let aggregate =
            discovery_aggregate_snapshot(db_path, "MCP", &format!("/mcp/tools/{tool_name}"))
                .expect("inventory aggregate should be present");
        assert_eq!(aggregate.call_count, 1);
        assert_eq!(aggregate.schema_mismatch_count, 0);
    }

    struct TempDiscoveryDb {
        path: PathBuf,
    }

    impl TempDiscoveryDb {
        fn new(test_name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-tool-executor-{test_name}-{}.sqlite",
                uuid::Uuid::new_v4()
            ));

            Self { path }
        }
    }

    impl Drop for TempDiscoveryDb {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let path = PathBuf::from(format!("{}{}", self.path.display(), suffix));
                let _ = std::fs::remove_file(path);
            }
        }
    }

    fn requests_guard(
        requests: &Arc<Mutex<Vec<CapturedRequest>>>,
    ) -> MutexGuard<'_, Vec<CapturedRequest>> {
        match requests.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    async fn assert_dot_segment_rejected_before_network(
        tool: Value,
        tool_name: &str,
        args: Value,
        rejected_arg_name: &str,
    ) {
        let definition = tool_definition(tool.clone(), tool_name);
        let error = render_path_template(&definition, &args)
            .expect_err("dot-segment path arg should reject during path rendering");
        assert_path_segment_is_dot_segment(error, tool_name, rejected_arg_name);

        let server = gated_server().await;
        let (executor, _capture) = executor_for_tools(
            server.addr,
            [tool],
            runtime_config([(tool_name, enabled_tool(500, 1))], 2, 1, 100),
        );

        let error = executor
            .execute(
                tool_name,
                args,
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("dot-segment path arg should fail before upstream request");
        let message = work_failed_message(error);
        assert!(
            message.contains(&format!(
                "path argument '{rejected_arg_name}' must not be a dot segment"
            )),
            "unexpected error: {message}"
        );

        assert_no_upstream_requests(&server).await;
        server.stop.cancel();
        server.handle.abort();
    }

    fn tool_definition(tool: Value, tool_name: &str) -> Arc<ToolDefinition> {
        ToolRegistry::from_json_value(json!({
            "schema_version": "0.1.0",
            "tools": [tool]
        }))
        .expect("test tool should load")
        .get(tool_name)
        .expect("test tool should exist")
    }

    fn assert_path_segment_is_dot_segment(
        error: ToolExecutorError,
        expected_tool_name: &str,
        expected_arg_name: &str,
    ) {
        match error {
            ToolExecutorError::PathSegmentIsDotSegment {
                tool_name,
                arg_name,
            } => {
                assert_eq!(tool_name, expected_tool_name);
                assert_eq!(arg_name, expected_arg_name);
            }
            other => panic!("expected PathSegmentIsDotSegment, got {other:?}"),
        }
    }

    async fn assert_no_upstream_requests(server: &GatedServer) {
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            server.request_count(),
            0,
            "dot-segment rejection must not reach upstream"
        );
    }

    #[derive(Debug)]
    struct CapturedRequest {
        method: String,
        target: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    }

    impl CapturedRequest {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .get(&name.to_ascii_lowercase())
                .map(String::as_str)
        }
    }

    struct GatedServer {
        addr: SocketAddr,
        requests: Arc<Mutex<Vec<CapturedRequest>>>,
        release: ReleaseGate,
        stop: CancellationToken,
        handle: tokio::task::JoinHandle<()>,
    }

    impl GatedServer {
        fn request_count(&self) -> usize {
            requests_guard(&self.requests).len()
        }
    }

    #[derive(Clone)]
    struct ReleaseGate {
        released: Arc<AtomicBool>,
        notify: Arc<Notify>,
    }

    impl ReleaseGate {
        fn new() -> Self {
            Self {
                released: Arc::new(AtomicBool::new(false)),
                notify: Arc::new(Notify::new()),
            }
        }

        fn release(&self) {
            self.released.store(true, Ordering::SeqCst);
            self.notify.notify_waiters();
        }

        async fn wait(&self) {
            while !self.released.load(Ordering::SeqCst) {
                self.notify.notified().await;
            }
        }
    }
}
