use std::{
    error::Error,
    fmt,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use http::{
    header::{HeaderMap, HeaderValue, CONTENT_TYPE},
    StatusCode,
};
use rmcp::{
    model::{CallToolRequestParams, CallToolResult, JsonObject, Tool},
    transport::{
        streamable_http_client::StreamableHttpClientTransportConfig, StreamableHttpClientTransport,
    },
};
use serde_json::Value;

use crate::{
    config::{Config, McpUpstreamServerConfig},
    egress::{CheckedEgressDestination, EgressClient, EgressError, EgressResponse},
    tools::definitions::ToolDefinition,
};

pub const MCP_CALL_TOOL_RESULT_HEADER: &str = "x-greengateway-mcp-call-tool-result";
const MCP_CALL_TOOL_RESULT_HEADER_VALUE: &str = "call-tool-result";
const JSON_MIME: &str = "application/json";

#[derive(Debug)]
pub enum McpUpstreamDiscoveryError {
    RuntimeBuild {
        message: String,
    },
    ThreadPanicked,
    EgressRejected {
        server_name: String,
        source: EgressError,
    },
}

impl fmt::Display for McpUpstreamDiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeBuild { message } => {
                write!(
                    formatter,
                    "failed to create MCP upstream discovery runtime: {message}"
                )
            }
            Self::ThreadPanicked => write!(formatter, "MCP upstream discovery thread panicked"),
            Self::EgressRejected {
                server_name,
                source,
            } => write!(
                formatter,
                "MCP upstream server '{server_name}' URL is rejected by egress policy: {source}"
            ),
        }
    }
}

impl Error for McpUpstreamDiscoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::EgressRejected { source, .. } => Some(source),
            Self::RuntimeBuild { .. } | Self::ThreadPanicked => None,
        }
    }
}

#[derive(Debug)]
pub enum McpUpstreamCallError {
    EgressRejected,
    ClientBuild,
    Connect,
    Call,
    Serialize,
}

impl McpUpstreamCallError {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::EgressRejected => "egress_rejected",
            Self::ClientBuild => "client_build_failed",
            Self::Connect => "connect_failed",
            Self::Call => "call_failed",
            Self::Serialize => "result_serialize_failed",
        }
    }
}

impl fmt::Display for McpUpstreamCallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EgressRejected => {
                write!(
                    formatter,
                    "upstream MCP server URL is rejected by egress policy"
                )
            }
            Self::ClientBuild => write!(formatter, "upstream MCP client could not be built"),
            Self::Connect => write!(formatter, "upstream MCP server could not be reached"),
            Self::Call => write!(formatter, "upstream MCP tool call failed"),
            Self::Serialize => write!(formatter, "upstream MCP result could not be serialized"),
        }
    }
}

impl Error for McpUpstreamCallError {}

#[derive(Clone)]
pub struct McpUpstreamRuntimeConfig {
    pub timeout: Duration,
    pub response_idle_timeout: Duration,
    pub connect_timeout: Duration,
}

impl McpUpstreamRuntimeConfig {
    pub fn from_config(config: &Config) -> Self {
        Self {
            timeout: Duration::from_millis(config.egress_timeout_ms),
            response_idle_timeout: Duration::from_millis(config.egress_response_idle_timeout_ms),
            connect_timeout: Duration::from_millis(config.egress_connect_timeout_ms),
        }
    }
}

pub fn discover_upstream_tools_blocking(
    config: &Config,
    egress_client: Arc<EgressClient>,
) -> Result<Vec<ToolDefinition>, McpUpstreamDiscoveryError> {
    if config.mcp_upstream_servers.is_empty() {
        return Ok(Vec::new());
    }

    let config = config.clone();
    let handle = thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| McpUpstreamDiscoveryError::RuntimeBuild {
                message: err.to_string(),
            })?
            .block_on(discover_upstream_tools(&config, egress_client))
    });

    handle
        .join()
        .map_err(|_| McpUpstreamDiscoveryError::ThreadPanicked)?
}

async fn discover_upstream_tools(
    config: &Config,
    egress_client: Arc<EgressClient>,
) -> Result<Vec<ToolDefinition>, McpUpstreamDiscoveryError> {
    let runtime_config = McpUpstreamRuntimeConfig::from_config(config);
    let mut definitions = Vec::new();

    for server in &config.mcp_upstream_servers {
        let destination = egress_client
            .checked_destination(&server.url)
            .await
            .map_err(|source| McpUpstreamDiscoveryError::EgressRejected {
                server_name: server.name.clone(),
                source,
            })?;

        match list_tools(server, &runtime_config, &destination).await {
            Ok(tools) => {
                definitions.extend(tools.into_iter().map(|tool| proxy_definition(server, tool)));
            }
            Err(error) => {
                tracing::warn!(
                    server_name = %server.name,
                    reason = %error,
                    "MCP upstream discovery failed; no tools imported from this server"
                );
            }
        }
    }

    Ok(definitions)
}

pub async fn call_tool(
    server: &McpUpstreamServerConfig,
    runtime_config: &McpUpstreamRuntimeConfig,
    egress_client: Arc<EgressClient>,
    remote_tool_name: &str,
    args: Value,
) -> Result<EgressResponse, McpUpstreamCallError> {
    let destination = egress_client
        .checked_destination(&server.url)
        .await
        .map_err(|_| McpUpstreamCallError::EgressRejected)?;

    let arguments = match args {
        Value::Object(arguments) => arguments,
        _ => JsonObject::new(),
    };
    let request = CallToolRequestParams::new(remote_tool_name.to_owned()).with_arguments(arguments);
    let mut service = connect(server, runtime_config, &destination).await?;
    let result = service
        .call_tool(request)
        .await
        .map_err(|_| McpUpstreamCallError::Call)?;
    let _ = service.close_with_timeout(Duration::from_millis(250)).await;

    response_from_call_tool_result(result)
}

async fn list_tools(
    server: &McpUpstreamServerConfig,
    runtime_config: &McpUpstreamRuntimeConfig,
    destination: &CheckedEgressDestination,
) -> Result<Vec<Tool>, McpUpstreamCallError> {
    let mut service = connect(server, runtime_config, destination).await?;
    let tools = service
        .list_all_tools()
        .await
        .map_err(|_| McpUpstreamCallError::Call);
    let _ = service.close_with_timeout(Duration::from_millis(250)).await;
    tools
}

async fn connect(
    server: &McpUpstreamServerConfig,
    runtime_config: &McpUpstreamRuntimeConfig,
    destination: &CheckedEgressDestination,
) -> Result<rmcp::service::RunningService<rmcp::RoleClient, ()>, McpUpstreamCallError> {
    let client = rmcp_reqwest::Client::builder()
        .timeout(server_timeout(server, runtime_config))
        .read_timeout(server_response_idle_timeout(server, runtime_config))
        .connect_timeout(server_connect_timeout(server, runtime_config))
        .redirect(rmcp_reqwest::redirect::Policy::none())
        .resolve(&destination.host, destination.pinned_addr)
        .build()
        .map_err(|_| McpUpstreamCallError::ClientBuild)?;
    let transport = StreamableHttpClientTransport::with_client(
        client,
        StreamableHttpClientTransportConfig::with_uri(server.url.clone()),
    );

    let started = Instant::now();
    let result = rmcp::serve_client((), transport).await;
    tracing::debug!(
        server_name = %server.name,
        latency_ms = duration_millis(started.elapsed()),
        "MCP upstream client initialized"
    );
    result.map_err(|_| McpUpstreamCallError::Connect)
}

fn response_from_call_tool_result(
    result: CallToolResult,
) -> Result<EgressResponse, McpUpstreamCallError> {
    let body = serde_json::to_vec(&result).map_err(|_| McpUpstreamCallError::Serialize)?;
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(JSON_MIME));
    headers.insert(
        MCP_CALL_TOOL_RESULT_HEADER,
        HeaderValue::from_static(MCP_CALL_TOOL_RESULT_HEADER_VALUE),
    );

    Ok(EgressResponse {
        status: StatusCode::OK,
        headers,
        body,
    })
}

fn proxy_definition(server: &McpUpstreamServerConfig, tool: Tool) -> ToolDefinition {
    let remote_tool_name = tool.name.to_string();
    let description = tool
        .description
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| remote_tool_name.clone());

    ToolDefinition::mcp_proxy(
        format!("{}:{remote_tool_name}", server.name),
        description,
        Value::Object(tool.input_schema.as_ref().clone()),
        server.name.clone(),
        remote_tool_name,
    )
}

fn server_timeout(
    server: &McpUpstreamServerConfig,
    runtime_config: &McpUpstreamRuntimeConfig,
) -> Duration {
    server
        .timeout_ms
        .map(Duration::from_millis)
        .unwrap_or(runtime_config.timeout)
}

fn server_connect_timeout(
    server: &McpUpstreamServerConfig,
    runtime_config: &McpUpstreamRuntimeConfig,
) -> Duration {
    server
        .connect_timeout_ms
        .map(Duration::from_millis)
        .unwrap_or(runtime_config.connect_timeout)
}

fn server_response_idle_timeout(
    server: &McpUpstreamServerConfig,
    runtime_config: &McpUpstreamRuntimeConfig,
) -> Duration {
    server
        .response_idle_timeout_ms
        .map(Duration::from_millis)
        .unwrap_or(runtime_config.response_idle_timeout)
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
