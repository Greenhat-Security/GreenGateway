use std::{
    collections::HashMap,
    error::Error,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use rmcp::model::CallToolResult;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{
    audit::{self, AuditEvent, AuditLog},
    config::{Config, McpUpstreamServerConfig},
    egress::{EgressClient, EgressError, EgressResponse},
    tools::{
        definitions::{BodyMappingMode, McpProxyMapping, ToolDefinition, ToolRegistry},
        mcp_upstream::{self, McpUpstreamRuntimeConfig},
        runtime::{ToolInvocationContext, ToolRuntime, ToolRuntimeError},
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

type ValidatorCache = HashMap<ValidatorCacheKey, Arc<jsonschema::Validator>>;

#[allow(dead_code)] // Issue #33 will call this from the MCP endpoint.
#[derive(Clone)]
pub struct ToolExecutor {
    registry: ToolRegistry,
    runtime: ToolRuntime,
    egress_client: Arc<EgressClient>,
    audit: AuditLog,
    upstream_origin: Option<String>,
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
}

#[derive(Debug)]
pub enum ToolExecutionResult {
    Http(EgressResponse),
    McpCallToolResult(CallToolResult),
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
        audit: AuditLog,
    ) -> Result<Self, ToolExecutorError> {
        let upstream_url = if registry.has_http_tools() {
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
            upstream_url,
            mcp_upstream_servers,
            McpUpstreamRuntimeConfig::from_config(config),
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
            Some(upstream_url),
            HashMap::new(),
            McpUpstreamRuntimeConfig {
                timeout: Duration::from_secs(30),
                response_idle_timeout: Duration::from_secs(30),
                connect_timeout: Duration::from_secs(10),
                max_request_body_bytes: 1_048_576,
                max_response_bytes: 5_242_880,
            },
        )
    }

    fn new_inner(
        registry: ToolRegistry,
        runtime: ToolRuntime,
        egress_client: Arc<EgressClient>,
        audit: AuditLog,
        upstream_url: Option<&str>,
        mcp_upstream_servers: HashMap<String, McpUpstreamServerConfig>,
        mcp_upstream_runtime_config: McpUpstreamRuntimeConfig,
    ) -> Result<Self, ToolExecutorError> {
        Ok(Self {
            registry,
            runtime,
            egress_client,
            audit,
            upstream_origin: upstream_url.map(upstream_origin_from_url).transpose()?,
            mcp_upstream_servers: Arc::new(mcp_upstream_servers),
            mcp_upstream_runtime_config: Arc::new(mcp_upstream_runtime_config),
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
        let runtime_tool_name = tool_name.to_owned();
        let work_tool_name = runtime_tool_name.clone();
        let work_context = context.clone();
        let executor = self.clone();

        self.runtime
            .execute_result_with_context_and_reason(
                &runtime_tool_name,
                context,
                cancel,
                move || async move {
                    executor
                        .execute_inner(&work_tool_name, args, &work_context)
                        .await
                },
                |error| Some(executor_work_failure_reason(error).to_owned()),
            )
            .await
    }

    pub(crate) fn can_list_tool(&self, tool_name: &str, context: &ToolInvocationContext) -> bool {
        self.runtime.tool_visible_to_context(tool_name, context)
    }

    async fn execute_inner(
        &self,
        tool_name: &str,
        args: Value,
        context: &ToolInvocationContext,
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
            return self.execute_mcp_proxy(context, &tool, mapping, args).await;
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
        let started = Instant::now();
        let result = self
            .egress_client
            .request_with_headers(
                request.method.clone(),
                &request.url,
                request.headers,
                request.body,
            )
            .await;
        let latency_ms = duration_millis(started.elapsed());

        match result {
            Ok(response) => {
                let status = response.status.as_u16();
                self.emit_upstream_audit(
                    context,
                    &tool,
                    &request.method,
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
            Err(source) => {
                let reason = egress_error_reason(&source);
                let status = egress_error_observation_status(&source);
                self.emit_upstream_audit(
                    context,
                    &tool,
                    &request.method,
                    UpstreamAuditOutcome {
                        outcome: "failure",
                        status: None,
                        latency_ms,
                        reason: Some(reason),
                    },
                );
                self.emit_tool_observation(
                    context,
                    &tool,
                    ToolObservationOutcome {
                        status,
                        latency_ms,
                        schema_mismatch: false,
                        reason: Some(reason),
                    },
                );
                Err(ToolExecutorError::Egress {
                    tool_name: tool.name.clone(),
                    source,
                })
            }
        }
    }

    async fn execute_mcp_proxy(
        &self,
        context: &ToolInvocationContext,
        tool: &ToolDefinition,
        mapping: McpProxyMapping,
        args: Value,
    ) -> Result<ToolExecutionResult, ToolExecutorError> {
        let Some(server) = self.mcp_upstream_servers.get(&mapping.server_name) else {
            self.emit_tool_observation(
                context,
                tool,
                ToolObservationOutcome {
                    status: StatusCode::BAD_GATEWAY.as_u16(),
                    latency_ms: 0,
                    schema_mismatch: false,
                    reason: Some("unknown_mcp_upstream_server"),
                },
            );
            return Err(ToolExecutorError::McpUpstream {
                tool_name: tool.name.clone(),
                server_name: mapping.server_name,
                reason: "unknown_mcp_upstream_server",
            });
        };

        let started = Instant::now();
        let result = mcp_upstream::call_tool(
            server,
            &self.mcp_upstream_runtime_config,
            Arc::clone(&self.egress_client),
            &mapping.tool_name,
            args,
        )
        .await;
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
        Ok(cache.entry(key).or_insert(validator).clone())
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
        let Some(upstream_origin) = self.upstream_origin.as_ref() else {
            return Err(ToolExecutorError::MissingUpstreamUrl);
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
        outcome: UpstreamAuditOutcome,
    ) {
        let mut payload = json!({
            "tool_name": tool.name,
            "method": method.as_str(),
            "path_template": tool.upstream.path_template,
            "outcome": outcome.outcome,
            "latency_ms": outcome.latency_ms,
        });

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
            "mcp_server_name": mapping.server_name,
            "mcp_tool_name": mapping.tool_name,
            "outcome": outcome.outcome,
            "latency_ms": outcome.latency_ms,
        });

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
    match schema {
        Value::Object(schema) if !schema.contains_key("additionalProperties") => {
            let mut schema = schema.clone();
            schema.insert("additionalProperties".to_owned(), Value::Bool(false));
            Value::Object(schema)
        }
        _ => schema.clone(),
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
        EgressError::PrivateIpBlocked(_) => "private_ip_blocked",
        EgressError::InvalidPolicy(_) => "invalid_egress_policy",
        EgressError::DnsResolutionFailed(_) => "dns_resolution_failed",
        EgressError::InvalidUrl(_) => "invalid_url",
        EgressError::SchemeNotAllowed(_) => "scheme_not_allowed",
        EgressError::RequestBodyTooLarge { .. } => "request_body_too_large",
        EgressError::ResponseTooLarge { .. } => "response_too_large",
        EgressError::ResponseIdleTimeout { .. } => "response_idle_timeout",
        EgressError::InvalidTlsCaBundle { .. } => "invalid_tls_ca_bundle",
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

fn executor_work_failure_reason(error: &ToolExecutorError) -> &'static str {
    match error {
        ToolExecutorError::UnknownTool { .. } => TOOL_UNKNOWN_TOOL_REASON,
        ToolExecutorError::InputValidation { .. }
        | ToolExecutorError::MissingArgument { .. }
        | ToolExecutorError::UnsupportedArgumentValue { .. }
        | ToolExecutorError::PathSegmentIsDotSegment { .. } => TOOL_INVALID_PARAMS_REASON,
        ToolExecutorError::Egress { source, .. } => egress_error_reason(source),
        ToolExecutorError::McpUpstream { reason, .. } => reason,
        ToolExecutorError::MissingUpstreamUrl
        | ToolExecutorError::InvalidUpstreamUrl { .. }
        | ToolExecutorError::SchemaCacheKey { .. }
        | ToolExecutorError::SchemaCompile { .. }
        | ToolExecutorError::InvalidMapping { .. }
        | ToolExecutorError::InvalidMethod { .. }
        | ToolExecutorError::BodySerialize { .. }
        | ToolExecutorError::UrlBuild { .. } => TOOL_EXECUTOR_CONFIGURATION_ERROR_REASON,
    }
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
        net::SocketAddr,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex, MutexGuard,
        },
        time::Duration,
    };

    use http::StatusCode;
    use rusqlite::{params, Connection};
    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::Notify,
    };

    use super::*;
    use crate::{
        audit::{
            sink::{tests::CaptureSink, AuditSink, CompositeSink},
            AuditLog,
        },
        discovery::{
            aggregator::{EndpointAggregatorSink, EndpointAggregatorSinkConfig},
            signals::{DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD, SCHEMA_MISMATCH_SIGNAL_TYPE},
        },
        egress::EgressConfig,
        tools::runtime::{DefaultToolPolicy, ToolRuntimeConfig, ToolRuntimeToolConfig},
    };

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
        assert!(
            events[2].payload["latency_ms"].as_u64().is_some(),
            "tool observation event should include latency_ms"
        );
        assert_eq!(executor.validator_cache_guard().len(), 1);
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
        assert!(message.contains("missing required path argument 'widget_id'"));

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
        assert!(message.contains("missing required query argument 'include_details'"));
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

        let error = executor
            .execute(
                "echo",
                json!({ "message": "hello" }),
                invocation_context(),
                CancellationToken::new(),
            )
            .await
            .expect_err("default deny should reject registry tools absent from policy map");

        assert!(matches!(error, ToolRuntimeError::UnknownTool { .. }));
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
            upstream_url.as_deref(),
            HashMap::new(),
            McpUpstreamRuntimeConfig {
                timeout: Duration::from_secs(30),
                response_idle_timeout: Duration::from_secs(30),
                connect_timeout: Duration::from_secs(10),
            },
        )
        .expect("tool executor should build");

        executor
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

    fn widget_tool(query_required: bool, widget_required: bool) -> Value {
        let required = if widget_required {
            json!(["widget_id"])
        } else {
            json!([])
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

    async fn read_http_request(stream: &mut TcpStream) -> CapturedRequest {
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

    async fn write_response(stream: &mut TcpStream, status: StatusCode, body: &[u8]) {
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
