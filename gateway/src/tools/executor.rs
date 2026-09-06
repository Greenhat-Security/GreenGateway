use std::{
    borrow::Cow,
    collections::HashMap,
    error::Error,
    fmt,
    future::Future,
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
use serde::Serialize;
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
        composite::{
            resolve_arguments, resolve_binding, resolve_for_each, status_is_ambiguous,
            status_is_success, BindingScope, CompositeBinding, CompositeCompensation,
            CompositeCompensationOutcome, CompositeCompensationState, CompositeCompensationSummary,
            CompositeCompletionAudit, CompositeMapping, CompositeOrphan, CompositeOrphanCertainty,
            CompositeOutputs, CompositeResult, CompositeStep, CompositeStepOutcome,
            CompositeStepOutput, CompositeStepSummary, PendingCompensation,
            MAX_COMPOSITE_ARGUMENTS, MAX_COMPOSITE_BODY_BYTES, MAX_COMPOSITE_ITERATIONS,
            MAX_COMPOSITE_JSON_DEPTH, MAX_COMPOSITE_RESULT_PROPERTIES, MAX_COMPOSITE_STEPS,
        },
        definitions::{
            BodyMappingMode, McpProxyMapping, ToolDefinition, ToolRegistry, ToolSource, ToolTarget,
        },
        enum_source::{EnumSourceRuntime, EnumSourceState},
        mcp_upstream::{self, McpUpstreamRuntimeConfig},
        overlay::{apply_enum_to_served_clone, mark_enum_unavailable_on_served_clone},
        runtime::{
            ToolInvocationContext, ToolInvocationSource, ToolRuntime, ToolRuntimeError,
            ToolWorkErrorDisposition,
        },
        transforms::{
            apply_request_transform, apply_response_transform, TransformError, TransformWarning,
            MAX_TRANSFORM_WARNINGS,
        },
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
/// Discovery keys endpoint aggregates and signals by `endpoint_template`, so a
/// template may only ever hold values the gateway itself controls. Tool names
/// that do not resolve in the registry are caller supplied and unbounded in
/// cardinality, so they all share this one template instead.
const UNKNOWN_TOOL_OBSERVATION_TEMPLATE: &str = "/mcp/tools/{tool}";
const TOOL_INPUT_VALIDATION_STATUS: u16 = 400;
const TOOL_INPUT_VALIDATION_REASON: &str = "input_validation";
const TOOL_ENUM_VALUE_REJECTED_REASON: &str = "enum_value_rejected";
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
const TOOL_AUTHORITY_UNAVAILABLE_REASON: &str = "authority_unavailable";
const TOOL_LEASE_LOST_REASON: &str = "lease_lost";
const TOOL_RUNTIME_CLOSED_REASON: &str = "runtime_closed";
const TOOL_RUNTIME_REJECTED_REASON: &str = "runtime_rejected";
const TOOL_PRECONDITION_FAILED_REASON: &str = "precondition_failed";
const TOOL_EXECUTION_STATE_UNAVAILABLE_REASON: &str = "execution_state_unavailable";
const TOOL_ENUM_SOURCE_UNAVAILABLE_REASON: &str = "enum_source_unavailable";
const TOOL_TASK_UNSUPPORTED_STATUS: u16 = 400;
const TOOL_TASK_UNSUPPORTED_REASON: &str = "task_unsupported";
const STRICT_SCHEMA_INJECTION_SKIP_KEYWORDS: &[&str] =
    &["$ref", "oneOf", "anyOf", "allOf", "patternProperties"];
// OpenAPI-generated schemas can come from externally supplied specs. Sixty-four
// child-schema edges is far deeper than realistic tool input shapes, while
// still bounding strict-default injection well below stack-overflow territory.
const MAX_STRICT_SCHEMA_INJECTION_DEPTH: usize = 64;
const MAX_VALIDATOR_CACHE_ENTRIES: usize = 4_096;
const MAX_AUDITED_TRANSFORM_WARNINGS: usize = MAX_TRANSFORM_WARNINGS;
const MAX_TRANSFORM_WARNING_PATH_CHARS: usize = 256;
const MAX_TRANSFORM_WARNING_REASON_CHARS: usize = 256;
const MAX_VALIDATION_PROBLEMS: usize = 16;
const MAX_VALIDATION_TEXT_CHARS: usize = 64;

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
    enum_source_runtime: Option<EnumSourceRuntime>,
    mcp_upstream_servers: Arc<HashMap<String, McpUpstreamServerConfig>>,
    mcp_upstream_runtime_config: Arc<McpUpstreamRuntimeConfig>,
    validator_cache: Arc<Mutex<ValidatorCache>>,
}

pub(crate) struct ServedToolDefinition<'a> {
    pub(crate) definition: Cow<'a, ToolDefinition>,
    enum_sources_available: bool,
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
        problems: Vec<ValidationProblem>,
    },
    TransformRejected {
        tool_name: String,
        parameter: String,
        path: String,
        reason: String,
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
    CompositeFailed {
        tool_name: String,
        request_id: String,
        failed_step: String,
        failed_iteration: Option<usize>,
        reason: Box<str>,
        compensation: CompositeCompensationState,
        orphans: Box<[CompositeOrphan]>,
    },
}

/// Bounded protocol-safe details for one input-schema validation failure.
///
/// `allowed` is populated only for the JSON Schema `enum` keyword. Dynamic
/// enum sources are restricted to strings and booleans by the overlay
/// compiler, so this preserves exact JSON equality without any coercion.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationProblem {
    pub path: String,
    pub keyword: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed: Option<Vec<Value>>,
    pub message: String,
}

#[derive(Debug)]
pub enum ToolExecutionResult {
    Http(HttpToolExecutionResult),
    McpCallToolResult(CallToolResult),
    Composite(CompositeResult),
}

impl ToolExecutionResult {
    fn application_failure_reason(&self) -> Option<&'static str> {
        match self {
            Self::McpCallToolResult(result) if result.is_error == Some(true) => {
                Some("mcp_tool_error")
            }
            Self::Http(result)
                if result.response.status.is_client_error()
                    || result.response.status.is_server_error() =>
            {
                Some("upstream_http_status")
            }
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct HttpToolExecutionResult {
    pub response: EgressResponse,
    pub warnings: Vec<TransformWarning>,
}

type ToolExecutionPreconditionChecker =
    dyn Fn(&ToolDefinition) -> Result<(), ToolExecutionPreconditionError> + Send + Sync + 'static;

/// The asynchronous form of a precondition check. It takes the definition
/// by value because the returned future outlives the call: a checker that
/// has to consult shared state (the capability inventory reads the
/// Connection store) cannot borrow across its own await.
type ToolExecutionPreconditionFuture = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(), ToolExecutionPreconditionError>> + Send>,
>;

type ToolExecutionAsyncPreconditionChecker =
    dyn Fn(ToolDefinition) -> ToolExecutionPreconditionFuture + Send + Sync + 'static;

#[derive(Clone)]
enum PreconditionChecker {
    /// A check that needs nothing but the definition in front of it.
    /// See [`ToolExecutionPrecondition::new`] for why this arm is retained
    /// with no production constructor today.
    #[cfg_attr(not(test), allow(dead_code))]
    Sync(Arc<ToolExecutionPreconditionChecker>),
    /// A check that has to read shared state. Awaited in place by the
    /// executor -- never blocked on from an executor thread.
    Async(Arc<ToolExecutionAsyncPreconditionChecker>),
}

#[derive(Clone)]
pub struct ToolExecutionPrecondition {
    checker: PreconditionChecker,
}

impl ToolExecutionPrecondition {
    /// A checker that decides from the definition in front of it and
    /// nothing else -- no shared state, so no future to await and no
    /// allocation per execution.
    ///
    /// No production caller needs this form today (the admin playground's
    /// precondition reads the capability inventory, which reads the
    /// Connection store, so it uses `new_async`), but the arm it
    /// constructs is a live branch of `check` that the executor's own
    /// tests exercise. Keeping the cheap form is deliberate: forcing every
    /// checker through a boxed future would tax callers that have nothing
    /// to await.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new<F>(checker: F) -> Self
    where
        F: Fn(&ToolDefinition) -> Result<(), ToolExecutionPreconditionError>
            + Send
            + Sync
            + 'static,
    {
        Self {
            checker: PreconditionChecker::Sync(Arc::new(checker)),
        }
    }

    pub fn new_async<F>(checker: F) -> Self
    where
        F: Fn(ToolDefinition) -> ToolExecutionPreconditionFuture + Send + Sync + 'static,
    {
        Self {
            checker: PreconditionChecker::Async(Arc::new(checker)),
        }
    }

    async fn check(
        &self,
        definition: &ToolDefinition,
    ) -> Result<(), ToolExecutionPreconditionError> {
        match &self.checker {
            PreconditionChecker::Sync(checker) => checker(definition),
            PreconditionChecker::Async(checker) => checker(definition.clone()).await,
        }
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
                problems
                    .iter()
                    .map(|problem| format!("{}: {}", problem.path, problem.message))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            Self::TransformRejected {
                tool_name,
                parameter,
                reason,
                ..
            } => write!(
                formatter,
                "tool '{tool_name}' argument '{parameter}' could not be encoded: {reason}"
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
            Self::CompositeFailed {
                tool_name,
                failed_step,
                failed_iteration,
                reason,
                compensation,
                ..
            } => {
                let iteration = failed_iteration
                    .map(|iteration| format!(" iteration {iteration}"))
                    .unwrap_or_default();
                write!(
                    formatter,
                    "composite tool '{tool_name}' failed at step '{failed_step}'{iteration}: {reason} (compensation {compensation:?})"
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

struct ClassifiedConnectionError {
    error: Box<ToolExecutorError>,
    request_sent: bool,
}

struct PreparedCompositeLeaf {
    tool: Arc<ToolDefinition>,
    target: ConnectionHttpTarget,
    request: ToolUpstreamRequest,
}

struct CompositeLeafPreparationError {
    reason: String,
    method: String,
    path_template: String,
}

enum CompositeLeafCallOutcome {
    Response {
        response: EgressResponse,
        latency_ms: u64,
    },
    Transport {
        reason: String,
        latency_ms: u64,
        request_sent: bool,
    },
    Timeout {
        latency_ms: u64,
        request_sent: bool,
    },
}

struct CompositeJournalEntry {
    step_id: String,
    iteration: Option<usize>,
    forward_tool: String,
    compensation: CompositeCompensation,
    response_json: Option<Value>,
    item: Option<(String, Value)>,
}

struct CompositeFailurePoint {
    step_id: String,
    iteration: Option<usize>,
    reason: String,
}

struct CompositeAuditGuard {
    audit: AuditLog,
    context: ToolInvocationContext,
    tool_name: String,
    connection_id: String,
    steps: Vec<CompositeStepSummary>,
    compensations: Vec<CompositeCompensationSummary>,
    pending_compensation: Vec<PendingCompensation>,
    failed_step: Option<String>,
    emitted: bool,
}

impl CompositeAuditGuard {
    fn new(
        audit: AuditLog,
        context: ToolInvocationContext,
        tool_name: &str,
        connection_id: &str,
    ) -> Self {
        Self {
            audit,
            context,
            tool_name: tool_name.to_owned(),
            connection_id: connection_id.to_owned(),
            steps: Vec::new(),
            compensations: Vec::new(),
            pending_compensation: Vec::new(),
            failed_step: None,
            emitted: false,
        }
    }

    fn begin_step(
        &mut self,
        index: usize,
        step: &CompositeStep,
        iteration: Option<usize>,
        method: &str,
        path_template: &str,
    ) -> usize {
        self.steps.push(CompositeStepSummary {
            index,
            id: step.id.clone(),
            iteration,
            tool: step.tool.clone(),
            method: method.to_owned(),
            path_template: path_template.to_owned(),
            // If the work future is dropped during I/O, this conservative
            // placeholder is the final, truthful classification.
            outcome: CompositeStepOutcome::Ambiguous,
            upstream_status: None,
            latency_ms: 0,
        });
        self.steps.len() - 1
    }

    fn record_preflight_failure(
        &mut self,
        index: usize,
        step: &CompositeStep,
        iteration: Option<usize>,
        method: &str,
        path_template: &str,
        latency_ms: u64,
    ) {
        self.steps.push(CompositeStepSummary {
            index,
            id: step.id.clone(),
            iteration,
            tool: step.tool.clone(),
            method: method.to_owned(),
            path_template: path_template.to_owned(),
            outcome: CompositeStepOutcome::Failed,
            upstream_status: None,
            latency_ms,
        });
    }

    fn complete_step(
        &mut self,
        summary_index: usize,
        outcome: CompositeStepOutcome,
        upstream_status: Option<u16>,
        latency_ms: u64,
    ) {
        if let Some(summary) = self.steps.get_mut(summary_index) {
            summary.outcome = outcome;
            summary.upstream_status = upstream_status;
            summary.latency_ms = latency_ms;
        }
    }

    fn add_pending(&mut self, entry: &CompositeJournalEntry) {
        self.pending_compensation.push(PendingCompensation {
            step: entry.step_id.clone(),
            iteration: entry.iteration,
            tool: entry.compensation.tool.clone(),
        });
    }

    fn clear_pending(&mut self, step: &str, iteration: Option<usize>, tool: &str) {
        if let Some(index) = self.pending_compensation.iter().position(|pending| {
            pending.step == step && pending.iteration == iteration && pending.tool == tool
        }) {
            self.pending_compensation.remove(index);
        }
    }

    fn finish(&mut self, outcome: &str, failed_step: Option<&str>) {
        self.failed_step = failed_step.map(str::to_owned);
        self.emit(outcome);
    }

    fn emit(&mut self, outcome: &str) {
        if self.emitted {
            return;
        }
        self.emitted = true;
        let payload = CompositeCompletionAudit {
            tool_name: self.tool_name.clone(),
            request_id: self.context.request_id.clone(),
            outcome: outcome.to_owned(),
            failed_step: self.failed_step.clone(),
            steps: self.steps.clone(),
            compensations: self.compensations.clone(),
            pending_compensation: self.pending_compensation.clone(),
            invocation_source: self.context.source.as_str().to_owned(),
            connection_id: self.connection_id.clone(),
        };
        let payload = serde_json::to_value(payload).unwrap_or_else(|_| {
            json!({
                "tool_name": self.tool_name,
                "request_id": self.context.request_id,
                "outcome": outcome,
                "invocation_source": self.context.source.as_str(),
                "connection_id": self.connection_id,
            })
        });
        self.audit.emit(AuditEvent::new(
            audit::event::TOOL_COMPOSITE_COMPLETED,
            &self.context.request_id,
            &self.context.source_ip,
            self.context.actor.clone(),
            payload,
        ));
    }
}

impl Drop for CompositeAuditGuard {
    fn drop(&mut self) {
        if !self.emitted {
            self.emit("abandoned");
        }
    }
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
            enum_source_runtime: None,
            mcp_upstream_servers: Arc::new(backends.mcp_upstream_servers),
            mcp_upstream_runtime_config: Arc::new(backends.mcp_upstream_runtime_config),
            validator_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub(crate) fn with_enum_source_runtime(
        mut self,
        enum_source_runtime: Option<EnumSourceRuntime>,
    ) -> Self {
        self.enum_source_runtime = enum_source_runtime;
        self
    }

    /// Return the immutable registry definition when it has no dynamic
    /// bindings, and otherwise an owned serve-time clone populated only from
    /// the in-memory enum cache. This path performs no durable or upstream I/O.
    pub(crate) fn served_definition<'a>(
        &self,
        definition: &'a ToolDefinition,
    ) -> Result<ServedToolDefinition<'a>, ToolExecutorError> {
        if definition.enum_bindings.is_empty() {
            return Ok(ServedToolDefinition {
                definition: Cow::Borrowed(definition),
                enum_sources_available: true,
            });
        }
        let connection_id = match &definition.source {
            ToolSource::OpenApi { connection_id, .. } => {
                crate::connections::model::ConnectionId::parse(connection_id.clone()).map_err(
                    |_| ToolExecutorError::SchemaCompile {
                        tool_name: definition.name.clone(),
                        message: "dynamic enum binding has an invalid Connection id".to_owned(),
                    },
                )?
            }
            _ => {
                return Err(ToolExecutorError::SchemaCompile {
                    tool_name: definition.name.clone(),
                    message: "dynamic enum binding is not attached to an OpenAPI tool".to_owned(),
                });
            }
        };
        let mut served = definition.clone();
        let mut enum_sources_available = true;
        for binding in &definition.enum_bindings {
            let snapshot = self.enum_source_runtime.as_ref().map(|runtime| {
                runtime.snapshot(&connection_id, &binding.source_id, &binding.source_digest)
            });
            match snapshot {
                Some(snapshot) if snapshot.state != EnumSourceState::Missing => {
                    apply_enum_to_served_clone(
                        &mut served,
                        binding,
                        &snapshot.values,
                        snapshot.labels.as_deref(),
                    )
                    .map_err(|message| ToolExecutorError::SchemaCompile {
                        tool_name: definition.name.clone(),
                        message,
                    })?;
                }
                _ => {
                    enum_sources_available = false;
                    mark_enum_unavailable_on_served_clone(&mut served, binding).map_err(
                        |message| ToolExecutorError::SchemaCompile {
                            tool_name: definition.name.clone(),
                            message,
                        },
                    )?;
                }
            }
        }
        Ok(ServedToolDefinition {
            definition: Cow::Owned(served),
            enum_sources_available,
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
        if context.source != ToolInvocationSource::AdminPlayground
            && self
                .registry
                .get(tool_name)
                .is_some_and(|tool| !tool.visibility.is_listed())
        {
            // Composite-only tools deliberately look absent at the public
            // executor boundary. This runs before runtime/RBAC admission so
            // callers cannot infer a hidden tool from a different error.
            self.emit_unknown_tool_observation(
                &context,
                tool_name,
                duration_millis(started.elapsed()),
            );
            return Err(ToolRuntimeError::UnknownTool {
                tool_name: tool_name.to_owned(),
            });
        }
        let runtime_tool_name = tool_name.to_owned();
        let work_tool_name = runtime_tool_name.clone();
        let observation_context = context.clone();
        let work_cancel = cancel.clone();
        let work_started = Arc::new(AtomicBool::new(false));
        let work_started_for_closure = Arc::clone(&work_started);
        let executor = self.clone();

        let result = self
            .runtime
            .execute_result_with_context_and_outcome(
                &runtime_tool_name,
                context,
                cancel,
                move |work_context| async move {
                    work_started_for_closure.store(true, Ordering::SeqCst);
                    executor
                        .execute_inner(
                            &work_tool_name,
                            args,
                            &work_context,
                            &work_cancel,
                            precondition.as_ref(),
                        )
                        .await
                },
                executor_work_error_disposition,
                ToolExecutionResult::application_failure_reason,
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
        self.registry
            .get(tool_name)
            .is_some_and(|tool| tool.visibility.is_listed())
            && self.runtime.tool_visible_to_context(tool_name, context)
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
        if context.source != ToolInvocationSource::AdminPlayground
            && self
                .registry
                .get(tool_name)
                .is_some_and(|tool| !tool.visibility.is_listed())
        {
            self.emit_unknown_tool_observation(
                &context,
                tool_name,
                duration_millis(started.elapsed()),
            );
            return Err(ToolRuntimeError::UnknownTool {
                tool_name: tool_name.to_owned(),
            });
        }
        let result: Result<(), ToolRuntimeError> = self
            .runtime
            .execute_result_with_context_and_reason(
                tool_name,
                context.clone(),
                CancellationToken::new(),
                |_| async { Err(UnsupportedTaskInvocation) },
                |_| ToolWorkErrorDisposition::Failure {
                    reason: Some(TOOL_TASK_UNSUPPORTED_REASON.to_owned()),
                    details: None,
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
        cancel: &CancellationToken,
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
        let served = match self.served_definition(tool.as_ref()) {
            Ok(served) => served,
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
        if !served.enum_sources_available {
            let error = ToolExecutorError::Connection {
                tool_name: tool.name.clone(),
                reason: TOOL_ENUM_SOURCE_UNAVAILABLE_REASON,
            };
            self.emit_executor_failure_observation(
                context,
                &tool,
                duration_millis(validation_started.elapsed()),
                &error,
            );
            return Err(error);
        }
        let validator = match self.validator_for(served.definition.as_ref()) {
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
        if let Err(error) = validate_args(served.definition.as_ref(), &validator, &args) {
            if let ToolExecutorError::InputValidation { problems, .. } = &error {
                self.emit_input_validation_observation(
                    context,
                    &tool,
                    duration_millis(validation_started.elapsed()),
                    problems,
                );
            }
            return Err(error);
        }

        if let Some(composite) = tool.composite.as_ref() {
            let connection_id = match (&tool.target, &tool.source) {
                (
                    Some(ToolTarget::Composite { connection_id }),
                    ToolSource::OpenApi {
                        connection_id: source_connection_id,
                        ..
                    },
                ) if connection_id == source_connection_id => connection_id,
                _ => {
                    return Err(ToolExecutorError::Connection {
                        tool_name: tool.name.clone(),
                        reason: "catalog_stale",
                    });
                }
            };
            self.enforce_execution_precondition(context, &tool, precondition)
                .await?;
            return self
                .execute_composite(&tool, composite, connection_id, &args, context, cancel)
                .await;
        }

        if matches!(tool.target, Some(ToolTarget::Composite { .. })) {
            return Err(ToolExecutorError::Connection {
                tool_name: tool.name.clone(),
                reason: "catalog_stale",
            });
        }

        if let Some(mapping) = tool.upstream.mcp_proxy_mapping() {
            self.validate_openapi_target_binding(
                context,
                &tool,
                duration_millis(validation_started.elapsed()),
            )?;
            let captured_connection_target = self.capture_mcp_connection_target(&tool, &mapping);
            self.enforce_execution_precondition(context, &tool, precondition)
                .await?;
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

        let wire_args = match apply_request_transform(tool.transform.as_ref(), &args) {
            Ok(args) => args,
            Err(error) => {
                let error = transform_executor_error(&tool, error);
                self.emit_executor_failure_observation(
                    context,
                    &tool,
                    duration_millis(validation_started.elapsed()),
                    &error,
                );
                return Err(error);
            }
        };

        let request_build_started = Instant::now();
        let request = match self.build_request(&tool, wire_args.as_ref()) {
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
            (Some(ToolTarget::Mcp { .. } | ToolTarget::Composite { .. }), _) => None,
            (None, _) => None,
        };
        self.enforce_execution_precondition(context, &tool, precondition)
            .await?;
        if precondition.is_some()
            && !self.runtime.authorize_http_operation(
                &tool.name,
                request.method.as_str(),
                &request.path,
                context,
            )
        {
            return Err(ToolExecutorError::HttpRuleDenied {
                tool_name: tool.name.clone(),
            });
        }
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
            (Some(ToolTarget::Mcp { .. } | ToolTarget::Composite { .. }), _) => {
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
            Ok(mut response) => {
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
                let warnings = self.apply_http_response_transform(context, &tool, &mut response);
                Ok(ToolExecutionResult::Http(HttpToolExecutionResult {
                    response,
                    warnings,
                }))
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

    fn apply_http_response_transform(
        &self,
        context: &ToolInvocationContext,
        tool: &ToolDefinition,
        response: &mut EgressResponse,
    ) -> Vec<TransformWarning> {
        let Some(transform) = tool.transform.as_ref() else {
            return Vec::new();
        };
        if !response.status.is_success() || !response_has_json_content_type(response) {
            return Vec::new();
        }

        let mut body = match serde_json::from_slice::<Value>(&response.body) {
            Ok(body) => body,
            Err(_) => {
                let (warnings, warnings_truncated) =
                    bounded_transform_warnings(vec![TransformWarning {
                        path: "/".to_owned(),
                        reason: "response_json_invalid".to_owned(),
                    }]);
                self.emit_transform_warnings(context, tool, &warnings, warnings_truncated);
                return warnings;
            }
        };
        let mut warnings = apply_response_transform(transform, &mut body);

        match serde_json::to_vec(&body) {
            Ok(body) => response.body = body,
            Err(_) => warnings.push(TransformWarning {
                path: "/".to_owned(),
                reason: "response_json_serialize_failed".to_owned(),
            }),
        }
        let (warnings, warnings_truncated) = bounded_transform_warnings(warnings);
        if !warnings.is_empty() {
            self.emit_transform_warnings(context, tool, &warnings, warnings_truncated);
        }
        warnings
    }

    fn emit_transform_warnings(
        &self,
        context: &ToolInvocationContext,
        tool: &ToolDefinition,
        warnings: &[TransformWarning],
        warnings_truncated: bool,
    ) {
        let audited = warnings
            .iter()
            .take(MAX_AUDITED_TRANSFORM_WARNINGS)
            .map(|warning| {
                json!({
                    "path": bounded_chars(&warning.path, MAX_TRANSFORM_WARNING_PATH_CHARS),
                    "reason": bounded_chars(&warning.reason, MAX_TRANSFORM_WARNING_REASON_CHARS),
                })
            })
            .collect::<Vec<_>>();
        self.audit.emit(AuditEvent::new(
            audit::event::TOOL_TRANSFORM_WARNING,
            &context.request_id,
            &context.source_ip,
            context.actor.clone(),
            json!({
                "tool_name": tool.name,
                "warning_count": warnings.len(),
                "warnings": audited,
                "warnings_truncated": warnings_truncated,
                "invocation_source": context.source.as_str(),
            }),
        ));
    }

    pub(crate) fn is_composite(&self, tool_name: &str) -> bool {
        self.registry
            .get(tool_name)
            .is_some_and(|tool| tool.composite.is_some())
    }

    async fn execute_composite(
        &self,
        tool: &ToolDefinition,
        mapping: &CompositeMapping,
        connection_id: &str,
        args: &Value,
        context: &ToolInvocationContext,
        cancel: &CancellationToken,
    ) -> Result<ToolExecutionResult, ToolExecutorError> {
        let mut audit = CompositeAuditGuard::new(
            self.audit.clone(),
            context.clone(),
            &tool.name,
            connection_id,
        );
        let input = args
            .as_object()
            .ok_or_else(|| ToolExecutorError::CompositeFailed {
                tool_name: tool.name.clone(),
                request_id: context.request_id.clone(),
                failed_step: tool.name.clone(),
                failed_iteration: None,
                reason: "invalid_params".into(),
                compensation: CompositeCompensationState::Complete,
                orphans: Vec::new().into_boxed_slice(),
            })?;
        let first_step = mapping
            .steps
            .first()
            .map(|step| step.id.clone())
            .unwrap_or_else(|| tool.name.clone());
        let definition_in_bounds = !mapping.steps.is_empty()
            && mapping.steps.len() <= MAX_COMPOSITE_STEPS
            && mapping
                .result
                .as_ref()
                .is_none_or(|result| result.len() <= MAX_COMPOSITE_RESULT_PROPERTIES)
            && mapping.limits.max_iterations <= MAX_COMPOSITE_ITERATIONS
            && input.len() <= MAX_COMPOSITE_ARGUMENTS
            && json_value_within_depth(args, MAX_COMPOSITE_JSON_DEPTH)
            && serde_json::to_vec(args)
                .is_ok_and(|encoded| encoded.len() <= MAX_COMPOSITE_BODY_BYTES);
        if !definition_in_bounds {
            audit.finish("failed", Some(&first_step));
            return Err(ToolExecutorError::CompositeFailed {
                tool_name: tool.name.clone(),
                request_id: context.request_id.clone(),
                failed_step: first_step,
                failed_iteration: None,
                reason: "composite_limit_exceeded".into(),
                compensation: CompositeCompensationState::Complete,
                orphans: Vec::new().into_boxed_slice(),
            });
        }

        // Input-backed fan-outs are known before the first request. Reject an
        // oversized call here so the limit can never leave partial upstream
        // state. Step-collect fan-outs are checked again when they resolve.
        let empty_outputs = CompositeOutputs::new();
        let preflight_scope = BindingScope {
            input,
            steps: &empty_outputs,
            item: None,
            self_body: None,
        };
        let mut known_iterations = 0usize;
        for step in &mapping.steps {
            let Some(for_each) = &step.for_each else {
                continue;
            };
            if !matches!(for_each.over, CompositeBinding::Input { .. }) {
                continue;
            }
            match resolve_for_each(&for_each.over, &preflight_scope) {
                Ok(items) => known_iterations = known_iterations.saturating_add(items.len()),
                Err(error) => {
                    audit.finish("failed", Some(&step.id));
                    return Err(ToolExecutorError::CompositeFailed {
                        tool_name: tool.name.clone(),
                        request_id: context.request_id.clone(),
                        failed_step: step.id.clone(),
                        failed_iteration: None,
                        reason: error.reason().into(),
                        compensation: CompositeCompensationState::Complete,
                        orphans: Vec::new().into_boxed_slice(),
                    });
                }
            }
        }
        if known_iterations > mapping.limits.max_iterations
            || known_iterations > MAX_COMPOSITE_ITERATIONS
        {
            audit.finish("failed", Some(&first_step));
            return Err(ToolExecutorError::InputValidation {
                tool_name: tool.name.clone(),
                problems: vec![ValidationProblem {
                    path: String::new(),
                    keyword: "max_iterations".to_owned(),
                    allowed: None,
                    message: format!(
                        "composite iteration count {known_iterations} exceeds the configured maximum {}",
                        mapping.limits.max_iterations.min(MAX_COMPOSITE_ITERATIONS)
                    ),
                }],
            });
        }

        let admitted_deadline = context
            .admitted_deadline
            .unwrap_or_else(tokio::time::Instant::now);
        let reserve = Duration::from_millis(mapping.limits.compensation_timeout_ms);
        let forward_deadline = admitted_deadline
            .checked_sub(reserve)
            .unwrap_or_else(tokio::time::Instant::now);
        let mut outputs = CompositeOutputs::new();
        let mut journal = Vec::<CompositeJournalEntry>::new();
        let mut uncompensatable_writes = Vec::<CompositeOrphan>::new();
        let mut failure = None::<CompositeFailurePoint>;
        let mut total_iterations = 0usize;

        'steps: for (step_index, step) in mapping.steps.iter().enumerate() {
            if cancel.is_cancelled() {
                return std::future::pending().await;
            }
            let scope = BindingScope {
                input,
                steps: &outputs,
                item: None,
                self_body: None,
            };
            let iterations = match &step.for_each {
                Some(for_each) => match resolve_for_each(&for_each.over, &scope) {
                    Ok(items) => items.into_iter().map(Some).collect::<Vec<_>>(),
                    Err(error) => {
                        audit.record_preflight_failure(step_index, step, None, "", "", 0);
                        failure = Some(CompositeFailurePoint {
                            step_id: step.id.clone(),
                            iteration: None,
                            reason: error.reason().to_owned(),
                        });
                        break 'steps;
                    }
                },
                None => vec![None],
            };
            if step.for_each.is_some() {
                total_iterations = total_iterations.saturating_add(iterations.len());
                if total_iterations > mapping.limits.max_iterations
                    || total_iterations > MAX_COMPOSITE_ITERATIONS
                {
                    audit.record_preflight_failure(step_index, step, None, "", "", 0);
                    failure = Some(CompositeFailurePoint {
                        step_id: step.id.clone(),
                        iteration: None,
                        reason: "iteration_limit_exceeded".to_owned(),
                    });
                    break 'steps;
                }
            }

            let mut step_outputs = Vec::with_capacity(iterations.len());
            for (iteration_index, item) in iterations.iter().enumerate() {
                if cancel.is_cancelled() {
                    return std::future::pending().await;
                }
                let iteration = step.for_each.as_ref().map(|_| iteration_index);
                if tokio::time::Instant::now() >= forward_deadline {
                    audit.record_preflight_failure(step_index, step, iteration, "", "", 0);
                    failure = Some(CompositeFailurePoint {
                        step_id: step.id.clone(),
                        iteration,
                        reason: "budget_exhausted".to_owned(),
                    });
                    break 'steps;
                }
                let scope = BindingScope {
                    input,
                    steps: &outputs,
                    item: step
                        .for_each
                        .as_ref()
                        .zip(item.as_ref())
                        .map(|(for_each, item)| (for_each.item_name.as_str(), item)),
                    self_body: None,
                };
                let resolved = match resolve_arguments(&step.arguments, &scope) {
                    Ok(resolved) => resolved,
                    Err(error) => {
                        audit.record_preflight_failure(step_index, step, iteration, "", "", 0);
                        failure = Some(CompositeFailurePoint {
                            step_id: step.id.clone(),
                            iteration,
                            reason: error.reason().to_owned(),
                        });
                        break 'steps;
                    }
                };
                let prepared = match self.prepare_composite_leaf(
                    &step.tool,
                    connection_id,
                    &resolved,
                    context,
                ) {
                    Ok(prepared) => prepared,
                    Err(error) => {
                        audit.record_preflight_failure(
                            step_index,
                            step,
                            iteration,
                            &error.method,
                            &error.path_template,
                            0,
                        );
                        failure = Some(CompositeFailurePoint {
                            step_id: step.id.clone(),
                            iteration,
                            reason: error.reason,
                        });
                        break 'steps;
                    }
                };
                let method = prepared.request.method.clone();
                let summary_index = audit.begin_step(
                    step_index,
                    step,
                    iteration,
                    method.as_str(),
                    &prepared.tool.upstream.path_template,
                );
                match self
                    .call_composite_leaf(context, prepared, forward_deadline)
                    .await
                {
                    CompositeLeafCallOutcome::Response {
                        response,
                        latency_ms,
                    } => {
                        let status = response.status.as_u16();
                        if status_is_success(step, status) {
                            if step.compensate.is_none()
                                && method != Method::GET
                                && method != Method::HEAD
                            {
                                uncompensatable_writes.push(CompositeOrphan {
                                    step: step.id.clone(),
                                    iteration,
                                    tool: step.tool.clone(),
                                    certainty: CompositeOrphanCertainty::Confirmed,
                                    reason: "no_compensation".to_owned(),
                                    upstream_status: Some(status),
                                });
                            }
                            match composite_step_output(&response) {
                                Ok(output) => {
                                    audit.complete_step(
                                        summary_index,
                                        CompositeStepOutcome::Succeeded,
                                        Some(status),
                                        latency_ms,
                                    );
                                    if let Some(compensation) = step.compensate.clone() {
                                        let entry = CompositeJournalEntry {
                                            step_id: step.id.clone(),
                                            iteration,
                                            forward_tool: step.tool.clone(),
                                            compensation,
                                            response_json: output.json_body.clone(),
                                            item: step.for_each.as_ref().zip(item.as_ref()).map(
                                                |(for_each, item)| {
                                                    (for_each.item_name.clone(), item.clone())
                                                },
                                            ),
                                        };
                                        audit.add_pending(&entry);
                                        journal.push(entry);
                                    }
                                    step_outputs.push(output);
                                }
                                Err(reason) => {
                                    audit.complete_step(
                                        summary_index,
                                        CompositeStepOutcome::Failed,
                                        Some(status),
                                        latency_ms,
                                    );
                                    if let Some(compensation) = step.compensate.clone() {
                                        let entry = CompositeJournalEntry {
                                            step_id: step.id.clone(),
                                            iteration,
                                            forward_tool: step.tool.clone(),
                                            compensation,
                                            response_json: None,
                                            item: step.for_each.as_ref().zip(item.as_ref()).map(
                                                |(for_each, item)| {
                                                    (for_each.item_name.clone(), item.clone())
                                                },
                                            ),
                                        };
                                        audit.add_pending(&entry);
                                        journal.push(entry);
                                    }
                                    failure = Some(CompositeFailurePoint {
                                        step_id: step.id.clone(),
                                        iteration,
                                        reason: reason.to_owned(),
                                    });
                                    break 'steps;
                                }
                            }
                        } else {
                            let ambiguous = status_is_ambiguous(step, &method, status);
                            audit.complete_step(
                                summary_index,
                                if ambiguous {
                                    CompositeStepOutcome::Ambiguous
                                } else {
                                    CompositeStepOutcome::Failed
                                },
                                Some(status),
                                latency_ms,
                            );
                            failure = Some(CompositeFailurePoint {
                                step_id: step.id.clone(),
                                iteration,
                                reason: if ambiguous {
                                    format!("ambiguous_status:{status}")
                                } else {
                                    format!("upstream_status:{status}")
                                },
                            });
                            break 'steps;
                        }
                    }
                    CompositeLeafCallOutcome::Transport {
                        reason,
                        latency_ms,
                        request_sent,
                    } => {
                        let ambiguous =
                            request_sent && method != Method::GET && method != Method::HEAD;
                        audit.complete_step(
                            summary_index,
                            if ambiguous {
                                CompositeStepOutcome::Ambiguous
                            } else {
                                CompositeStepOutcome::Failed
                            },
                            None,
                            latency_ms,
                        );
                        failure = Some(CompositeFailurePoint {
                            step_id: step.id.clone(),
                            iteration,
                            reason: if ambiguous {
                                "transport_ambiguous".to_owned()
                            } else {
                                reason
                            },
                        });
                        break 'steps;
                    }
                    CompositeLeafCallOutcome::Timeout {
                        latency_ms,
                        request_sent,
                    } => {
                        audit.complete_step(
                            summary_index,
                            if request_sent {
                                CompositeStepOutcome::Ambiguous
                            } else {
                                CompositeStepOutcome::Failed
                            },
                            None,
                            latency_ms,
                        );
                        failure = Some(CompositeFailurePoint {
                            step_id: step.id.clone(),
                            iteration,
                            reason: if request_sent {
                                "timeout_ambiguous".to_owned()
                            } else {
                                "budget_exhausted".to_owned()
                            },
                        });
                        break 'steps;
                    }
                }
            }
            outputs.insert(step.id.clone(), step_outputs);
        }

        if failure.is_none() {
            let scope = BindingScope {
                input,
                steps: &outputs,
                item: None,
                self_body: None,
            };
            let body = if let Some(result) = &mapping.result {
                let mut body = Map::new();
                for (name, binding) in result {
                    match resolve_binding(binding, &scope) {
                        Ok(value) => {
                            body.insert(name.clone(), value);
                        }
                        Err(error) => {
                            let failed_step =
                                mapping.steps.last().expect("bounds checked").id.clone();
                            failure = Some(CompositeFailurePoint {
                                step_id: failed_step,
                                iteration: None,
                                reason: error.reason().to_owned(),
                            });
                            break;
                        }
                    }
                }
                Value::Object(body)
            } else {
                outputs
                    .get(&mapping.steps.last().expect("bounds checked").id)
                    .and_then(|values| values.last())
                    .map(|output| output.result_body.clone())
                    .unwrap_or(Value::Null)
            };
            if failure.is_none() {
                audit.finish("success", None);
                return Ok(ToolExecutionResult::Composite(CompositeResult {
                    body,
                    steps_summary: audit.steps.clone(),
                }));
            }
        }

        let failure = failure.expect("failure established before compensation");
        audit.failed_step = Some(failure.step_id.clone());
        let mut orphans = uncompensatable_writes;
        if audit.steps.iter().any(|summary| {
            summary.id == failure.step_id
                && summary.iteration == failure.iteration
                && summary.outcome == CompositeStepOutcome::Ambiguous
        }) {
            let failed_tool = mapping
                .steps
                .iter()
                .find(|step| step.id == failure.step_id)
                .map(|step| step.tool.clone())
                .unwrap_or_else(|| failure.step_id.clone());
            let upstream_status = audit
                .steps
                .iter()
                .find(|summary| {
                    summary.id == failure.step_id && summary.iteration == failure.iteration
                })
                .and_then(|summary| summary.upstream_status);
            orphans.push(CompositeOrphan {
                step: failure.step_id.clone(),
                iteration: failure.iteration,
                tool: failed_tool,
                certainty: CompositeOrphanCertainty::Possible,
                reason: failure.reason.clone(),
                upstream_status,
            });
        }

        for entry in journal.iter().rev() {
            if cancel.is_cancelled() {
                return std::future::pending().await;
            }
            if tokio::time::Instant::now() >= admitted_deadline {
                audit.compensations.push(CompositeCompensationSummary {
                    for_step: entry.step_id.clone(),
                    iteration: entry.iteration,
                    tool: entry.compensation.tool.clone(),
                    outcome: CompositeCompensationOutcome::Skipped,
                    upstream_status: None,
                    reason: Some("budget_exhausted".to_owned()),
                });
                orphans.push(composite_confirmed_orphan(entry, "budget_exhausted", None));
                continue;
            }
            let scope = BindingScope {
                input,
                steps: &outputs,
                item: entry
                    .item
                    .as_ref()
                    .map(|(name, item)| (name.as_str(), item)),
                self_body: entry.response_json.as_ref(),
            };
            let resolved = match resolve_arguments(&entry.compensation.arguments, &scope) {
                Ok(resolved) => resolved,
                Err(_) => {
                    audit.compensations.push(CompositeCompensationSummary {
                        for_step: entry.step_id.clone(),
                        iteration: entry.iteration,
                        tool: entry.compensation.tool.clone(),
                        outcome: CompositeCompensationOutcome::Skipped,
                        upstream_status: None,
                        reason: Some("self_pointer_unresolved".to_owned()),
                    });
                    orphans.push(composite_confirmed_orphan(
                        entry,
                        "self_pointer_unresolved",
                        None,
                    ));
                    continue;
                }
            };
            let prepared = match self.prepare_composite_leaf(
                &entry.compensation.tool,
                connection_id,
                &resolved,
                context,
            ) {
                Ok(prepared) => prepared,
                Err(error) => {
                    let reason = composite_compensation_preflight_reason(&error.reason);
                    audit.compensations.push(CompositeCompensationSummary {
                        for_step: entry.step_id.clone(),
                        iteration: entry.iteration,
                        tool: entry.compensation.tool.clone(),
                        outcome: CompositeCompensationOutcome::Skipped,
                        upstream_status: None,
                        reason: Some(reason.to_owned()),
                    });
                    orphans.push(composite_confirmed_orphan(entry, reason, None));
                    continue;
                }
            };
            match self
                .call_composite_leaf(context, prepared, admitted_deadline)
                .await
            {
                CompositeLeafCallOutcome::Response {
                    response,
                    latency_ms: _,
                } if response.status.is_success() => {
                    audit.compensations.push(CompositeCompensationSummary {
                        for_step: entry.step_id.clone(),
                        iteration: entry.iteration,
                        tool: entry.compensation.tool.clone(),
                        outcome: CompositeCompensationOutcome::Succeeded,
                        upstream_status: Some(response.status.as_u16()),
                        reason: None,
                    });
                    audit.clear_pending(&entry.step_id, entry.iteration, &entry.compensation.tool);
                }
                CompositeLeafCallOutcome::Response { response, .. } => {
                    let status = response.status.as_u16();
                    let reason = format!("compensation_status:{status}");
                    audit.compensations.push(CompositeCompensationSummary {
                        for_step: entry.step_id.clone(),
                        iteration: entry.iteration,
                        tool: entry.compensation.tool.clone(),
                        outcome: CompositeCompensationOutcome::Failed,
                        upstream_status: Some(status),
                        reason: Some(reason.clone()),
                    });
                    orphans.push(composite_confirmed_orphan(entry, &reason, Some(status)));
                }
                CompositeLeafCallOutcome::Timeout { .. } => {
                    audit.compensations.push(CompositeCompensationSummary {
                        for_step: entry.step_id.clone(),
                        iteration: entry.iteration,
                        tool: entry.compensation.tool.clone(),
                        outcome: CompositeCompensationOutcome::Failed,
                        upstream_status: None,
                        reason: Some("compensation_timeout".to_owned()),
                    });
                    orphans.push(composite_confirmed_orphan(
                        entry,
                        "compensation_timeout",
                        None,
                    ));
                }
                CompositeLeafCallOutcome::Transport { .. } => {
                    audit.compensations.push(CompositeCompensationSummary {
                        for_step: entry.step_id.clone(),
                        iteration: entry.iteration,
                        tool: entry.compensation.tool.clone(),
                        outcome: CompositeCompensationOutcome::Failed,
                        upstream_status: None,
                        reason: Some("compensation_transport_error".to_owned()),
                    });
                    orphans.push(composite_confirmed_orphan(
                        entry,
                        "compensation_transport_error",
                        None,
                    ));
                }
            }
        }

        let compensation = if orphans.is_empty() && audit.pending_compensation.is_empty() {
            CompositeCompensationState::Complete
        } else {
            CompositeCompensationState::Incomplete
        };
        audit.finish(
            if compensation == CompositeCompensationState::Complete {
                "failed"
            } else {
                "failed_compensation_incomplete"
            },
            Some(&failure.step_id),
        );
        Err(ToolExecutorError::CompositeFailed {
            tool_name: tool.name.clone(),
            request_id: context.request_id.clone(),
            failed_step: failure.step_id,
            failed_iteration: failure.iteration,
            reason: failure.reason.into_boxed_str(),
            compensation,
            orphans: orphans.into_boxed_slice(),
        })
    }

    fn prepare_composite_leaf(
        &self,
        tool_name: &str,
        connection_id: &str,
        args: &Value,
        context: &ToolInvocationContext,
    ) -> Result<PreparedCompositeLeaf, CompositeLeafPreparationError> {
        let tool = self
            .registry
            .get(tool_name)
            .ok_or_else(|| CompositeLeafPreparationError {
                reason: "catalog_stale".to_owned(),
                method: String::new(),
                path_template: String::new(),
            })?;
        let method = tool.upstream.method.clone();
        let path_template = tool.upstream.path_template.clone();
        let fail = |reason: &str| CompositeLeafPreparationError {
            reason: reason.to_owned(),
            method: method.clone(),
            path_template: path_template.clone(),
        };
        if tool.composite.is_some()
            || !matches!(
                (&tool.source, &tool.target),
                (
                    ToolSource::OpenApi {
                        connection_id: source_connection_id,
                        ..
                    },
                    Some(ToolTarget::Http {
                        connection_id: target_connection_id,
                        ..
                    })
                ) if source_connection_id == connection_id
                    && target_connection_id == connection_id
            )
        {
            return Err(fail("catalog_stale"));
        }
        if !self.runtime.composite_leaf_enabled(tool_name) {
            return Err(fail("tool_disabled"));
        }
        if args
            .as_object()
            .is_none_or(|args| args.len() > MAX_COMPOSITE_ARGUMENTS)
            || !json_value_within_depth(args, MAX_COMPOSITE_JSON_DEPTH)
            || !serde_json::to_vec(args)
                .is_ok_and(|encoded| encoded.len() <= MAX_COMPOSITE_BODY_BYTES)
        {
            return Err(fail("composite_limit_exceeded"));
        }
        let served = self
            .served_definition(tool.as_ref())
            .map_err(|error| fail(executor_error_safe_reason(&error)))?;
        if !served.enum_sources_available {
            return Err(fail(TOOL_ENUM_SOURCE_UNAVAILABLE_REASON));
        }
        let served_definition = served.definition.as_ref();
        let validator = self
            .validator_for(served_definition)
            .map_err(|error| fail(executor_error_safe_reason(&error)))?;
        validate_args(served_definition, &validator, args)
            .map_err(|error| fail(executor_error_safe_reason(&error)))?;
        let wire_args = apply_request_transform(served_definition.transform.as_ref(), args)
            .map_err(|error| {
                let error = transform_executor_error(served_definition, error);
                fail(executor_error_safe_reason(&error))
            })?;
        let request = self
            .build_request(served_definition, wire_args.as_ref())
            .map_err(|error| fail(executor_error_safe_reason(&error)))?;
        if request
            .body
            .as_ref()
            .is_some_and(|body| body.len() > MAX_COMPOSITE_BODY_BYTES)
        {
            return Err(fail("request_body_too_large"));
        }
        if !self.runtime.authorize_http_operation(
            &tool.name,
            request.method.as_str(),
            &request.path,
            context,
        ) {
            return Err(fail("http_rule_denied"));
        }
        let runtime = self
            .connection_http
            .as_ref()
            .ok_or_else(|| fail("connection_runtime_unavailable"))?;
        let target = runtime
            .target(connection_id, &request.path_and_query)
            .map_err(|error| fail(error.safe_reason()))?;
        Ok(PreparedCompositeLeaf {
            tool,
            target,
            request,
        })
    }

    async fn call_composite_leaf(
        &self,
        context: &ToolInvocationContext,
        prepared: PreparedCompositeLeaf,
        deadline: tokio::time::Instant,
    ) -> CompositeLeafCallOutcome {
        let started = Instant::now();
        let method = prepared.request.method.clone();
        let connection_id = prepared.target.connection_id().to_string();
        let result = self
            .execute_connection_http_classified(
                context,
                &prepared.tool,
                prepared.target,
                prepared.request,
                Some(deadline),
            )
            .await;
        let latency_ms = duration_millis(started.elapsed());
        match result {
            Ok(mut response) => {
                let status = response.status.as_u16();
                self.emit_upstream_audit(
                    context,
                    &prepared.tool,
                    &method,
                    Some(&connection_id),
                    UpstreamAuditOutcome {
                        outcome: "success",
                        status: Some(status),
                        latency_ms,
                        reason: None,
                    },
                );
                self.emit_tool_observation(
                    context,
                    &prepared.tool,
                    ToolObservationOutcome {
                        status,
                        latency_ms,
                        schema_mismatch: false,
                        reason: None,
                    },
                );
                let _warnings =
                    self.apply_http_response_transform(context, &prepared.tool, &mut response);
                CompositeLeafCallOutcome::Response {
                    response,
                    latency_ms,
                }
            }
            Err(classified) => {
                let reason = executor_error_safe_reason(&classified.error);
                let outcome = executor_failure_observation_outcome(latency_ms, &classified.error);
                self.emit_upstream_audit(
                    context,
                    &prepared.tool,
                    &method,
                    Some(&connection_id),
                    UpstreamAuditOutcome {
                        outcome: "failure",
                        status: None,
                        latency_ms,
                        reason: Some(reason),
                    },
                );
                self.emit_tool_observation(context, &prepared.tool, outcome);
                if reason == "timeout" || reason == "response_idle_timeout" {
                    CompositeLeafCallOutcome::Timeout {
                        latency_ms,
                        request_sent: classified.request_sent,
                    }
                } else {
                    CompositeLeafCallOutcome::Transport {
                        reason: reason.to_owned(),
                        latency_ms,
                        request_sent: classified.request_sent,
                    }
                }
            }
        }
    }

    async fn enforce_execution_precondition(
        &self,
        context: &ToolInvocationContext,
        tool: &ToolDefinition,
        precondition: Option<&ToolExecutionPrecondition>,
    ) -> Result<(), ToolExecutorError> {
        let Some(precondition) = precondition else {
            return Ok(());
        };
        let started = Instant::now();

        match precondition.check(tool).await {
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
        request: ToolUpstreamRequest,
    ) -> Result<EgressResponse, ToolExecutorError> {
        self.execute_connection_http_classified(context, tool, target, request, None)
            .await
            .map_err(|classified| *classified.error)
    }

    async fn execute_connection_http_classified(
        &self,
        context: &ToolInvocationContext,
        tool: &ToolDefinition,
        target: ConnectionHttpTarget,
        mut request: ToolUpstreamRequest,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<EgressResponse, ClassifiedConnectionError> {
        let runtime = self
            .connection_http
            .as_ref()
            .ok_or_else(|| ClassifiedConnectionError {
                error: Box::new(ToolExecutorError::Connection {
                    tool_name: tool.name.clone(),
                    reason: "connection_runtime_unavailable",
                }),
                request_sent: false,
            })?;
        if matches!(tool.source, ToolSource::OpenApi { .. })
            && !self
                .openapi_catalog_runtime
                .as_ref()
                .is_some_and(|catalog| {
                    catalog.definition_is_current(tool, target.connection_etag())
                })
        {
            return Err(ClassifiedConnectionError {
                error: Box::new(ToolExecutorError::Connection {
                    tool_name: tool.name.clone(),
                    reason: "catalog_stale",
                }),
                request_sent: false,
            });
        }
        if request.method == Method::TRACE && target.is_credentialed() {
            return Err(ClassifiedConnectionError {
                error: Box::new(ToolExecutorError::Connection {
                    tool_name: tool.name.clone(),
                    reason: "unsafe_trace_method",
                }),
                request_sent: false,
            });
        }
        // Every header the Connection owns is stripped before injection, so
        // a caller cannot smuggle a value under a configured name.
        for header_name in target.credential_header_names() {
            request.headers.remove(header_name);
        }

        let destination = run_before_deadline(
            deadline,
            target.preflight_client().checked_destination(target.url()),
        )
        .await
        .map_err(|_| ClassifiedConnectionError {
            error: Box::new(ToolExecutorError::Connection {
                tool_name: tool.name.clone(),
                reason: "timeout",
            }),
            request_sent: false,
        })?
        .map_err(|source| ClassifiedConnectionError {
            error: Box::new(connection_egress_tool_error(tool, &source)),
            request_sent: false,
        })?;
        let prepared =
            run_before_deadline(deadline, runtime.prepare_transport(&target, &destination))
                .await
                .map_err(|_| ClassifiedConnectionError {
                    error: Box::new(ToolExecutorError::Connection {
                        tool_name: tool.name.clone(),
                        reason: "timeout",
                    }),
                    request_sent: false,
                })?
                .map_err(|error| {
                    if error.is_secret_resolution_failure() {
                        self.emit_connection_secret_resolution_failed(
                            context,
                            tool,
                            &target,
                            error.safe_reason(),
                        );
                    }
                    ClassifiedConnectionError {
                        error: Box::new(connection_tool_error(tool, error)),
                        request_sent: false,
                    }
                })?;
        let credential = run_before_deadline(deadline, runtime.resolve_credential(&target))
            .await
            .map_err(|_| ClassifiedConnectionError {
                error: Box::new(ToolExecutorError::Connection {
                    tool_name: tool.name.clone(),
                    reason: "timeout",
                }),
                request_sent: false,
            })?
            .map_err(|error| {
                if error.is_secret_resolution_failure() {
                    self.emit_connection_secret_resolution_failed(
                        context,
                        tool,
                        &target,
                        error.safe_reason(),
                    );
                }
                ClassifiedConnectionError {
                    error: Box::new(connection_tool_error(tool, error)),
                    request_sent: false,
                }
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
                ClassifiedConnectionError {
                    error: Box::new(connection_tool_error(tool, error)),
                    request_sent: false,
                }
            })?;
        }

        let response = run_before_deadline(
            deadline,
            prepared
                .client()
                .stream_request_with_body_at_checked_destination(
                    prepared.destination(),
                    request.method,
                    target.url(),
                    request.headers,
                    request
                        .body
                        .map_or(EgressRequestBody::Empty, EgressRequestBody::Buffered),
                ),
        )
        .await
        .map_err(|_| ClassifiedConnectionError {
            error: Box::new(ToolExecutorError::Connection {
                tool_name: tool.name.clone(),
                reason: "timeout",
            }),
            request_sent: true,
        })?
        .map_err(|source| ClassifiedConnectionError {
            error: Box::new(connection_egress_tool_error(tool, &source)),
            request_sent: true,
        })?;
        if connection_authentication_rejected(response.status, target.is_credentialed()) {
            if response.status == StatusCode::UNAUTHORIZED {
                if let Some(credential) = credential
                    .as_ref()
                    .filter(|credential| credential.is_oauth())
                {
                    credential.invalidate_after_unauthorized().await;
                }
            }
            return Err(ClassifiedConnectionError {
                error: Box::new(connection_tool_error(
                    tool,
                    ConnectionHttpError::UpstreamAuthenticationRejected,
                )),
                // The upstream gave a definite rejection; it did not perform
                // the requested operation.
                request_sent: false,
            });
        }
        let mut body = Vec::new();
        let mut response_body = response.body;
        loop {
            let next = run_before_deadline(deadline, response_body.next())
                .await
                .map_err(|_| ClassifiedConnectionError {
                    error: Box::new(ToolExecutorError::Connection {
                        tool_name: tool.name.clone(),
                        reason: "timeout",
                    }),
                    request_sent: true,
                })?;
            let Some(chunk) = next else {
                break;
            };
            body.extend_from_slice(&chunk.map_err(|source| ClassifiedConnectionError {
                error: Box::new(connection_egress_tool_error(tool, &source)),
                request_sent: true,
            })?);
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
                let failed = result.is_error == Some(true);
                self.emit_mcp_upstream_audit(
                    context,
                    tool,
                    &mapping,
                    UpstreamAuditOutcome {
                        outcome: if failed { "failure" } else { "success" },
                        status: Some(http::StatusCode::OK.as_u16()),
                        latency_ms,
                        reason: failed.then_some("mcp_tool_error"),
                    },
                );
                self.emit_tool_observation(
                    context,
                    tool,
                    ToolObservationOutcome {
                        // Observation status classifies the logical tool result;
                        // the upstream audit above retains transport HTTP 200.
                        status: if failed { 500 } else { 200 },
                        latency_ms,
                        schema_mismatch: false,
                        reason: failed.then_some("mcp_tool_error"),
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
                BodyMappingMode::BodyArgsJson => {
                    headers.insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/json"),
                    );
                    let body_args = body_arguments_without_path_and_query(tool, args);
                    Some(serde_json::to_vec(&body_args).map_err(|err| {
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
        // Fail closed: only a name the registry resolves earns its own
        // discovery endpoint template. The raw name is still reported in `path`
        // and `tool_name`, neither of which is an aggregate key.
        let endpoint_template = if self.registry.get(tool_name).is_some() {
            path.clone()
        } else {
            UNKNOWN_TOOL_OBSERVATION_TEMPLATE.to_owned()
        };
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

    fn emit_input_validation_observation(
        &self,
        context: &ToolInvocationContext,
        tool: &ToolDefinition,
        latency_ms: u64,
        problems: &[ValidationProblem],
    ) {
        let reason = if problems.iter().any(|problem| problem.keyword == "enum") {
            TOOL_ENUM_VALUE_REJECTED_REASON
        } else {
            TOOL_INPUT_VALIDATION_REASON
        };
        self.emit_tool_observation(
            context,
            tool,
            ToolObservationOutcome {
                status: TOOL_INPUT_VALIDATION_STATUS,
                latency_ms,
                schema_mismatch: true,
                reason: Some(reason),
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
        .take(MAX_VALIDATION_PROBLEMS)
        .map(|error| {
            let allowed = match error.kind() {
                jsonschema::error::ValidationErrorKind::Enum { options } => {
                    options.as_array().cloned()
                }
                _ => None,
            };
            ValidationProblem {
                path: bounded_validation_text(
                    &error.instance_path().to_string(),
                    MAX_VALIDATION_TEXT_CHARS,
                ),
                keyword: bounded_validation_text(error.kind().keyword(), MAX_VALIDATION_TEXT_CHARS),
                allowed,
                message: safe_validation_message(error.kind()),
            }
        })
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

fn safe_validation_message(kind: &jsonschema::error::ValidationErrorKind) -> String {
    use jsonschema::error::ValidationErrorKind;

    match kind {
        ValidationErrorKind::Enum { .. } => "value is not one of the allowed values".to_owned(),
        ValidationErrorKind::Required { property } => property.as_str().map_or_else(
            || "a required argument is missing".to_owned(),
            |property| {
                format!(
                    "required argument '{}' is missing",
                    bounded_validation_text(property, MAX_VALIDATION_TEXT_CHARS)
                )
            },
        ),
        ValidationErrorKind::AdditionalProperties { unexpected }
        | ValidationErrorKind::UnevaluatedProperties { unexpected } => {
            safe_unexpected_arguments(unexpected)
        }
        ValidationErrorKind::Type { .. } => "value has the wrong JSON type".to_owned(),
        ValidationErrorKind::MaxLength { limit } => {
            format!("string exceeds the maximum length of {limit}")
        }
        ValidationErrorKind::MinLength { limit } => {
            format!("string is shorter than the minimum length of {limit}")
        }
        ValidationErrorKind::MaxItems { limit } => {
            format!("array exceeds the maximum item count of {limit}")
        }
        ValidationErrorKind::MinItems { limit } => {
            format!("array has fewer than the minimum item count of {limit}")
        }
        ValidationErrorKind::MaxProperties { limit } => {
            format!("object exceeds the maximum property count of {limit}")
        }
        ValidationErrorKind::MinProperties { limit } => {
            format!("object has fewer than the minimum property count of {limit}")
        }
        ValidationErrorKind::AdditionalItems { limit } => {
            format!("array has items beyond the allowed limit of {limit}")
        }
        _ => format!(
            "value does not satisfy the '{}' constraint",
            bounded_validation_text(kind.keyword(), MAX_VALIDATION_TEXT_CHARS)
        ),
    }
}

fn safe_unexpected_arguments(unexpected: &[String]) -> String {
    if unexpected.is_empty() {
        return "unexpected argument is not allowed".to_owned();
    }
    let names = unexpected
        .iter()
        .take(3)
        .map(|name| {
            format!(
                "'{}'",
                bounded_validation_text(name, MAX_VALIDATION_TEXT_CHARS)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    if unexpected.len() > 3 {
        format!("unexpected arguments {names}, … are not allowed")
    } else if unexpected.len() == 1 {
        format!("unexpected argument {names} is not allowed")
    } else {
        format!("unexpected arguments {names} are not allowed")
    }
}

fn bounded_validation_text(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let mut bounded = chars
        .by_ref()
        .take(max_chars)
        .map(|character| {
            if character.is_control() {
                '\u{fffd}'
            } else {
                character
            }
        })
        .collect::<String>();
    if chars.next().is_some() {
        bounded.push('…');
    }
    bounded
}

/// The `body_args_json` body (issue #360): the validated argument object
/// with every path-template placeholder and every mapped query argument
/// removed. Runs after `render_path_template` has already validated the
/// template, so a malformed placeholder cannot reach here; an unmatched
/// brace simply contributes no exclusion.
fn body_arguments_without_path_and_query(tool: &ToolDefinition, args: &Value) -> Value {
    let Some(object) = args.as_object() else {
        return args.clone();
    };
    let mut excluded = std::collections::BTreeSet::new();
    let mut rest = tool.upstream.path_template.as_str();
    while let Some(open) = rest.find('{') {
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            break;
        };
        excluded.insert(after_open[..close].to_owned());
        rest = &after_open[close + 1..];
    }
    for mapping in &tool.upstream.query_params {
        excluded.insert(mapping.arg_name.clone());
    }
    Value::Object(
        object
            .iter()
            .filter(|(key, _)| !excluded.contains(key.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    )
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
        // Unreachable for tool invocation, which uses the pinned HTTP/1.1
        // transport. The category is already bounded, so forward it rather than
        // flattening several distinct transport failures into one label.
        EgressError::Grpc(failure) => failure.category(),
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

fn connection_authentication_rejected(status: StatusCode, credentialed: bool) -> bool {
    matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) && credentialed
}

fn connection_egress_tool_error(tool: &ToolDefinition, error: &EgressError) -> ToolExecutorError {
    ToolExecutorError::Connection {
        tool_name: tool.name.clone(),
        reason: egress_error_reason(error),
    }
}

fn transform_executor_error(tool: &ToolDefinition, error: TransformError) -> ToolExecutorError {
    ToolExecutorError::TransformRejected {
        tool_name: tool.name.clone(),
        parameter: bounded_chars(&error.parameter, 128),
        path: bounded_chars(&error.path, MAX_TRANSFORM_WARNING_PATH_CHARS),
        reason: bounded_chars(&error.reason, MAX_TRANSFORM_WARNING_REASON_CHARS),
    }
}

fn response_has_json_content_type(response: &EgressResponse) -> bool {
    response
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            let media_type = value.split(';').next().map(str::trim).unwrap_or_default();
            media_type.eq_ignore_ascii_case("application/json")
                || media_type
                    .split_once('/')
                    .is_some_and(|(_, subtype)| subtype.to_ascii_lowercase().ends_with("+json"))
        })
}

fn bounded_chars(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let mut bounded = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        bounded.push_str("...[truncated]");
    }
    bounded
}

fn bounded_transform_warnings(warnings: Vec<TransformWarning>) -> (Vec<TransformWarning>, bool) {
    let had_truncation_sentinel = warnings
        .last()
        .is_some_and(|warning| warning.reason == "warnings_truncated");
    let raw_warning_count = warnings
        .len()
        .saturating_sub(usize::from(had_truncation_sentinel));
    let was_truncated = had_truncation_sentinel || raw_warning_count > MAX_TRANSFORM_WARNINGS;
    let retained = if was_truncated {
        MAX_TRANSFORM_WARNINGS.saturating_sub(1)
    } else {
        MAX_TRANSFORM_WARNINGS
    };
    let mut bounded = warnings
        .into_iter()
        .take(raw_warning_count.min(retained))
        .map(|warning| TransformWarning {
            path: bounded_chars(&warning.path, MAX_TRANSFORM_WARNING_PATH_CHARS),
            reason: bounded_chars(&warning.reason, MAX_TRANSFORM_WARNING_REASON_CHARS),
        })
        .collect::<Vec<_>>();
    if was_truncated {
        bounded.push(TransformWarning {
            path: "/".to_owned(),
            reason: "warnings_truncated".to_owned(),
        });
    }
    (bounded, was_truncated)
}

fn executor_failure_observation_outcome(
    latency_ms: u64,
    error: &ToolExecutorError,
) -> ToolObservationOutcome {
    match error {
        ToolExecutorError::InputValidation { .. }
        | ToolExecutorError::TransformRejected { .. }
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
                | "enum_source_unavailable"
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
        ToolExecutorError::CompositeFailed { .. } => ToolObservationOutcome {
            status: StatusCode::BAD_GATEWAY.as_u16(),
            latency_ms,
            schema_mismatch: false,
            reason: Some("composite_failed"),
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
        ToolRuntimeError::AuthorityUnavailable { .. } => Some(ToolObservationOutcome {
            status: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
            latency_ms,
            schema_mismatch: false,
            reason: Some(TOOL_AUTHORITY_UNAVAILABLE_REASON),
        }),
        ToolRuntimeError::LeaseLost { .. } => Some(ToolObservationOutcome {
            status: StatusCode::SERVICE_UNAVAILABLE.as_u16(),
            latency_ms,
            schema_mismatch: false,
            reason: Some(TOOL_LEASE_LOST_REASON),
        }),
        ToolRuntimeError::UnknownTool { .. }
        | ToolRuntimeError::Timeout { .. }
        | ToolRuntimeError::WorkFailed { .. } => None,
    }
}

fn executor_work_error_disposition(error: &ToolExecutorError) -> ToolWorkErrorDisposition {
    if let ToolExecutorError::CompositeFailed {
        tool_name,
        request_id,
        failed_step,
        failed_iteration,
        reason,
        compensation,
        orphans,
    } = error
    {
        let failure_reason = if *compensation == CompositeCompensationState::Complete {
            "composite_failed"
        } else {
            "composite_failed_compensation_incomplete"
        };
        return ToolWorkErrorDisposition::Failure {
            reason: Some(failure_reason.to_owned()),
            details: Some(json!({
                "tool_name": tool_name,
                "request_id": request_id,
                "reason": failure_reason,
                "failed_step": failed_step,
                "failed_iteration": failed_iteration,
                "failure_reason": reason,
                "compensation": compensation,
                "orphans": orphans,
            })),
        };
    }
    match error {
        ToolExecutorError::TransformRejected { path, reason, .. } => {
            return ToolWorkErrorDisposition::Failure {
                reason: Some(TOOL_INVALID_PARAMS_REASON.to_owned()),
                details: Some(json!({
                    "problems": [{
                        "path": path,
                        "keyword": "codec",
                        "reason": reason,
                    }],
                })),
            };
        }
        ToolExecutorError::HttpRuleDenied { .. } => {
            return ToolWorkErrorDisposition::Rejected(TOOL_MATCHED_RULE_REASON.to_owned());
        }
        ToolExecutorError::PreconditionFailed { .. } => {
            return ToolWorkErrorDisposition::Rejected(TOOL_PRECONDITION_FAILED_REASON.to_owned());
        }
        _ => {}
    }

    let reason = match error {
        ToolExecutorError::UnknownTool { .. } => TOOL_UNKNOWN_TOOL_REASON,
        ToolExecutorError::InputValidation { .. }
        | ToolExecutorError::MissingArgument { .. }
        | ToolExecutorError::UnsupportedArgumentValue { .. }
        | ToolExecutorError::PathSegmentIsDotSegment { .. } => TOOL_INVALID_PARAMS_REASON,
        ToolExecutorError::Egress { source, .. } => egress_error_reason(source),
        ToolExecutorError::McpUpstream { reason, .. } => reason,
        ToolExecutorError::Connection { reason, .. } => reason,
        ToolExecutorError::CompositeFailed { .. } => unreachable!("handled above"),
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
        | ToolExecutorError::PreconditionFailed { .. }
        | ToolExecutorError::TransformRejected { .. } => {
            unreachable!("handled above")
        }
    };
    let details = match error {
        ToolExecutorError::InputValidation { problems, .. } => {
            Some(json!({ "problems": problems }))
        }
        _ => None,
    };
    ToolWorkErrorDisposition::Failure {
        reason: Some(reason.to_owned()),
        details,
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn executor_error_safe_reason(error: &ToolExecutorError) -> &'static str {
    match error {
        ToolExecutorError::UnknownTool { .. } => "unknown_tool",
        ToolExecutorError::InputValidation { .. }
        | ToolExecutorError::MissingArgument { .. }
        | ToolExecutorError::UnsupportedArgumentValue { .. }
        | ToolExecutorError::PathSegmentIsDotSegment { .. }
        | ToolExecutorError::TransformRejected { .. } => "invalid_params",
        ToolExecutorError::Egress { source, .. } => egress_error_reason(source),
        ToolExecutorError::McpUpstream { reason, .. }
        | ToolExecutorError::Connection { reason, .. } => reason,
        ToolExecutorError::HttpRuleDenied { .. } => "http_rule_denied",
        ToolExecutorError::PreconditionFailed { .. } => "precondition_failed",
        ToolExecutorError::ExecutionStateUnavailable { .. } => "execution_state_unavailable",
        ToolExecutorError::CompositeFailed { .. } => "composite_failed",
        ToolExecutorError::MissingUpstreamUrl
        | ToolExecutorError::InvalidUpstreamUrl { .. }
        | ToolExecutorError::SchemaCacheKey { .. }
        | ToolExecutorError::SchemaCompile { .. }
        | ToolExecutorError::InvalidMapping { .. }
        | ToolExecutorError::InvalidMethod { .. }
        | ToolExecutorError::BodySerialize { .. }
        | ToolExecutorError::UrlBuild { .. } => "internal_configuration_error",
    }
}

fn composite_step_output(response: &EgressResponse) -> Result<CompositeStepOutput, &'static str> {
    if response.body.len() > MAX_COMPOSITE_BODY_BYTES {
        return Err("response_too_large");
    }
    let json_body = serde_json::from_slice::<Value>(&response.body).ok();
    if json_body
        .as_ref()
        .is_some_and(|value| !json_value_within_depth(value, MAX_COMPOSITE_JSON_DEPTH))
    {
        return Err("response_too_deep");
    }
    let result_body = json_body.clone().unwrap_or_else(|| {
        String::from_utf8(response.body.clone())
            .map(Value::String)
            .unwrap_or(Value::Null)
    });
    Ok(CompositeStepOutput {
        json_body,
        result_body,
    })
}

fn json_value_within_depth(value: &Value, maximum: usize) -> bool {
    fn visit(value: &Value, depth: usize, maximum: usize) -> bool {
        if depth > maximum {
            return false;
        }
        match value {
            Value::Array(values) => values
                .iter()
                .all(|value| visit(value, depth.saturating_add(1), maximum)),
            Value::Object(values) => values
                .values()
                .all(|value| visit(value, depth.saturating_add(1), maximum)),
            _ => true,
        }
    }
    visit(value, 0, maximum)
}

fn composite_confirmed_orphan(
    entry: &CompositeJournalEntry,
    reason: &str,
    upstream_status: Option<u16>,
) -> CompositeOrphan {
    CompositeOrphan {
        step: entry.step_id.clone(),
        iteration: entry.iteration,
        tool: entry.forward_tool.clone(),
        certainty: CompositeOrphanCertainty::Confirmed,
        reason: reason.to_owned(),
        upstream_status,
    }
}

fn composite_compensation_preflight_reason(reason: &str) -> &'static str {
    match reason {
        "tool_disabled" => "tool_disabled",
        "http_rule_denied" => "http_rule_denied",
        "timeout" => "compensation_timeout",
        _ => "compensation_transport_error",
    }
}

async fn run_before_deadline<F, T>(deadline: Option<tokio::time::Instant>, work: F) -> Result<T, ()>
where
    F: Future<Output = T>,
{
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, work)
            .await
            .map_err(|_| ()),
        None => Ok(work.await),
    }
}

fn tool_observation_path(tool_name: &str) -> String {
    format!("/mcp/tools/{tool_name}")
}

#[cfg(test)]
#[path = "executor_tests.rs"]
mod tests;
