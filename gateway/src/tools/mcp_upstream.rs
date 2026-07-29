use std::{
    borrow::Cow,
    collections::HashMap,
    error::Error,
    fmt,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures_util::{
    stream::{self, BoxStream},
    Stream, StreamExt,
};
use http::{
    header::{HeaderName, HeaderValue, ACCEPT, CONTENT_TYPE, WWW_AUTHENTICATE},
    StatusCode,
};
use rmcp::{
    model::{
        CallToolRequest, CallToolRequestParams, CallToolResult, ClientJsonRpcMessage,
        ClientRequest, JsonObject, Meta, NumberOrString, PaginatedRequestParams, ProgressToken,
        Resource as McpResource, ResourceTemplate as McpResourceTemplate, ServerJsonRpcMessage,
        Tool,
    },
    service::{ClientInitializeError, QuitReason, ServiceError},
    transport::{
        common::client_side_sse::NeverRetry,
        streamable_http_client::{
            AuthRequiredError, InsufficientScopeError, SseError, StreamableHttpClient,
            StreamableHttpClientTransportConfig, StreamableHttpError, StreamableHttpPostResponse,
        },
        DynamicTransportError, StreamableHttpClientTransport,
    },
};
use serde_json::Value;
use sse_stream::{Sse, SseStream};

use crate::{
    config::{Config, McpUpstreamServerConfig},
    connections::{
        http::{
            ConnectionHttpError, ConnectionHttpRuntime, ConnectionHttpTarget,
            ResolvedConnectionCredential,
        },
        model::MAX_CATALOG_ENTRIES,
        status::{ConnectionOperationalState, ConnectionStatusReason},
        store::{validate_mcp_resource_metadata, StoredMcpResource, StoredMcpResourceTemplate},
        test::{ConnectionTestReason, ConnectionTestStageName},
    },
    egress::{rmcp_http, CheckedEgressDestination, EgressClient, EgressError},
    tools::definitions::ToolDefinition,
};

#[cfg(test)]
pub const MCP_CALL_TOOL_RESULT_HEADER: &str = "x-greengateway-mcp-call-tool-result";
const EVENT_STREAM_MIME: &str = "text/event-stream";
const HEADER_LAST_EVENT_ID: &str = "Last-Event-Id";
const HEADER_SESSION_ID: &str = "Mcp-Session-Id";
const JSON_MIME: &str = "application/json";
const MAX_DISCOVERY_PAGES_PER_UPSTREAM: usize = 32;
const MAX_DISCOVERY_TOOLS_PER_UPSTREAM: usize = 1024;
const MAX_DISCOVERY_RESOURCES_PER_UPSTREAM: usize = 1024;
const MAX_DISCOVERY_RESOURCE_TEMPLATES_PER_UPSTREAM: usize = 1024;
const MAX_DISCOVERY_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const PROTOCOL_PROBE_CLEANUP_RESERVE: Duration = Duration::from_millis(500);
const REDACTED_MCP_UPSTREAM_VALUE: &str = "<redacted>";

#[derive(Clone, Debug, PartialEq)]
pub struct McpDiscoveredCatalog {
    pub tools: Vec<ToolDefinition>,
    pub resources: Vec<StoredMcpResource>,
    pub resource_templates: Vec<StoredMcpResourceTemplate>,
}

impl McpDiscoveredCatalog {
    pub fn total_count(&self) -> usize {
        self.tools
            .len()
            .saturating_add(self.resources.len())
            .saturating_add(self.resource_templates.len())
    }
}

#[derive(Debug)]
pub enum McpUpstreamDiscoveryError {
    RuntimeBuild {
        message: String,
    },
    ThreadPanicked,
    EgressRejected {
        server_name: String,
        reason: &'static str,
    },
    UpstreamListFailed {
        server_name: String,
        source: McpUpstreamCallError,
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
                reason,
            } => write!(
                formatter,
                "MCP upstream server '{server_name}' URL is rejected by egress policy ({reason})"
            ),
            Self::UpstreamListFailed {
                server_name,
                source,
            } => write!(
                formatter,
                "MCP upstream server '{server_name}' tools/list discovery failed: {source}"
            ),
        }
    }
}

impl Error for McpUpstreamDiscoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::UpstreamListFailed { source, .. } => Some(source),
            Self::RuntimeBuild { .. } | Self::ThreadPanicked | Self::EgressRejected { .. } => None,
        }
    }
}

#[derive(Debug)]
pub enum McpUpstreamCallError {
    EgressRejected,
    ClientBuild,
    Connect,
    Call,
    Connection { reason: &'static str },
    AuthenticationRejected,
    DiscoveryPageLimitExceeded { max: usize },
    DiscoveryToolLimitExceeded { max: usize },
    DiscoveryResourceLimitExceeded { max: usize },
    DiscoveryResourceTemplateLimitExceeded { max: usize },
    DiscoveryCapabilityLimitExceeded { max: usize },
    DiscoveryResponseLimitExceeded { max: usize },
    InvalidDiscoveryMetadata,
    RequestBodyTooLarge { size: usize, max: usize },
    ResponseTooLarge { max: usize },
}

impl McpUpstreamCallError {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::EgressRejected => "egress_rejected",
            Self::ClientBuild => "client_build_failed",
            Self::Connect => "connect_failed",
            Self::Call => "call_failed",
            Self::Connection { reason } => reason,
            Self::AuthenticationRejected => "auth_failed",
            Self::DiscoveryPageLimitExceeded { .. } => "discovery_page_limit_exceeded",
            Self::DiscoveryToolLimitExceeded { .. } => "discovery_tool_limit_exceeded",
            Self::DiscoveryResourceLimitExceeded { .. } => "discovery_resource_limit_exceeded",
            Self::DiscoveryResourceTemplateLimitExceeded { .. } => {
                "discovery_resource_template_limit_exceeded"
            }
            Self::DiscoveryCapabilityLimitExceeded { .. } => "discovery_capability_limit_exceeded",
            Self::DiscoveryResponseLimitExceeded { .. } => "discovery_response_limit_exceeded",
            Self::InvalidDiscoveryMetadata => "invalid_discovery_metadata",
            Self::RequestBodyTooLarge { .. } => "request_body_too_large",
            Self::ResponseTooLarge { .. } => "response_too_large",
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
            Self::Connection { reason } => {
                write!(formatter, "managed MCP connection is unavailable: {reason}")
            }
            Self::AuthenticationRejected => {
                formatter.write_str("managed MCP authentication failed")
            }
            Self::DiscoveryPageLimitExceeded { max } => write!(
                formatter,
                "upstream MCP tools/list pagination exceeded {max} pages"
            ),
            Self::DiscoveryToolLimitExceeded { max } => write!(
                formatter,
                "upstream MCP tools/list discovery exceeded {max} tools"
            ),
            Self::DiscoveryResourceLimitExceeded { max } => write!(
                formatter,
                "upstream MCP resources/list discovery exceeded {max} resources"
            ),
            Self::DiscoveryResourceTemplateLimitExceeded { max } => write!(
                formatter,
                "upstream MCP resources/templates/list discovery exceeded {max} templates"
            ),
            Self::DiscoveryCapabilityLimitExceeded { max } => write!(
                formatter,
                "upstream MCP discovery exceeded {max} aggregate capabilities"
            ),
            Self::DiscoveryResponseLimitExceeded { max } => write!(
                formatter,
                "upstream MCP discovery exceeded {max} aggregate response bytes"
            ),
            Self::InvalidDiscoveryMetadata => {
                formatter.write_str("upstream MCP discovery returned invalid metadata")
            }
            Self::RequestBodyTooLarge { size, max } => {
                write!(
                    formatter,
                    "upstream MCP request body is too large: {size} > {max}"
                )
            }
            Self::ResponseTooLarge { max } => {
                write!(formatter, "upstream MCP response body exceeded {max} bytes")
            }
        }
    }
}

impl Error for McpUpstreamCallError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionProtocolProbeError {
    stage: ConnectionTestStageName,
    reason: ConnectionTestReason,
    status_reason: ConnectionStatusReason,
}

impl ConnectionProtocolProbeError {
    pub const fn stage(self) -> ConnectionTestStageName {
        self.stage
    }

    pub const fn safe_reason(self) -> ConnectionTestReason {
        self.reason
    }

    pub const fn status_reason(self) -> ConnectionStatusReason {
        self.status_reason
    }

    pub const fn operational_state(self) -> ConnectionOperationalState {
        match self.status_reason {
            ConnectionStatusReason::InvalidResponse => ConnectionOperationalState::Degraded,
            _ => ConnectionOperationalState::Unavailable,
        }
    }

    const fn new(
        stage: ConnectionTestStageName,
        reason: ConnectionTestReason,
        status_reason: ConnectionStatusReason,
    ) -> Self {
        Self {
            stage,
            reason,
            status_reason,
        }
    }
}

impl fmt::Display for ConnectionProtocolProbeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "managed MCP protocol probe failed at {:?}: {:?}",
            self.stage, self.reason
        )
    }
}

impl Error for ConnectionProtocolProbeError {}

#[derive(Clone)]
pub struct McpUpstreamRuntimeConfig {
    pub timeout: Duration,
    pub response_idle_timeout: Duration,
    pub connect_timeout: Duration,
    pub max_request_body_bytes: usize,
    pub max_response_bytes: usize,
}

impl McpUpstreamRuntimeConfig {
    pub fn from_config(config: &Config) -> Self {
        Self {
            timeout: Duration::from_millis(config.egress_timeout_ms),
            response_idle_timeout: Duration::from_millis(config.egress_response_idle_timeout_ms),
            connect_timeout: Duration::from_millis(config.egress_connect_timeout_ms),
            max_request_body_bytes: config.egress_max_request_body_bytes,
            max_response_bytes: config.egress_max_response_bytes,
        }
    }

    fn from_connection_target(target: &ConnectionHttpTarget) -> Self {
        Self {
            timeout: target.client().request_timeout(),
            response_idle_timeout: target.client().response_idle_timeout(),
            connect_timeout: target.client().connect_timeout(),
            max_request_body_bytes: target.client().max_request_body_bytes(),
            max_response_bytes: target.client().max_response_bytes(),
        }
    }
}

pub fn discover_upstream_tools_blocking(
    config: &Config,
    egress_client: Arc<EgressClient>,
) -> Result<Vec<ToolDefinition>, McpUpstreamDiscoveryError> {
    discover_upstream_tools_blocking_with_failure_mode(
        config,
        egress_client,
        DiscoveryFailureMode::WarnAndSkip,
    )
}

pub fn discover_upstream_tools_strict_blocking(
    config: &Config,
    egress_client: Arc<EgressClient>,
) -> Result<Vec<ToolDefinition>, McpUpstreamDiscoveryError> {
    discover_upstream_tools_blocking_with_failure_mode(
        config,
        egress_client,
        DiscoveryFailureMode::FailOnListError,
    )
}

#[derive(Clone, Copy)]
enum DiscoveryFailureMode {
    WarnAndSkip,
    FailOnListError,
}

fn discover_upstream_tools_blocking_with_failure_mode(
    config: &Config,
    egress_client: Arc<EgressClient>,
    failure_mode: DiscoveryFailureMode,
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
            .block_on(discover_upstream_tools(
                &config,
                egress_client,
                failure_mode,
            ))
    });

    handle
        .join()
        .map_err(|_| McpUpstreamDiscoveryError::ThreadPanicked)?
}

async fn discover_upstream_tools(
    config: &Config,
    egress_client: Arc<EgressClient>,
    failure_mode: DiscoveryFailureMode,
) -> Result<Vec<ToolDefinition>, McpUpstreamDiscoveryError> {
    let runtime_config = McpUpstreamRuntimeConfig::from_config(config);
    let mut definitions = Vec::new();

    for server in &config.mcp_upstream_servers {
        let destination = egress_client
            .checked_destination(&server.url)
            .await
            .map_err(|source| mcp_discovery_egress_error(server.name.clone(), source))?;

        match list_tools(server, &runtime_config, &destination).await {
            Ok(tools) => {
                definitions.extend(tools.into_iter().map(|tool| proxy_definition(server, tool)));
            }
            Err(error) => match failure_mode {
                DiscoveryFailureMode::WarnAndSkip => {
                    tracing::warn!(
                        server_name = %server.name,
                        reason = %error,
                        "MCP upstream discovery failed; no tools imported from this server"
                    );
                }
                DiscoveryFailureMode::FailOnListError => {
                    return Err(McpUpstreamDiscoveryError::UpstreamListFailed {
                        server_name: server.name.clone(),
                        source: error,
                    });
                }
            },
        }
    }

    Ok(definitions)
}

fn mcp_discovery_egress_error(
    server_name: String,
    source: EgressError,
) -> McpUpstreamDiscoveryError {
    McpUpstreamDiscoveryError::EgressRejected {
        server_name,
        reason: source.safe_category(),
    }
}

pub async fn call_tool(
    server: &McpUpstreamServerConfig,
    runtime_config: &McpUpstreamRuntimeConfig,
    egress_client: Arc<EgressClient>,
    remote_tool_name: &str,
    args: Value,
) -> Result<CallToolResult, McpUpstreamCallError> {
    let arguments = match args {
        Value::Object(arguments) => arguments,
        _ => JsonObject::new(),
    };
    let request = CallToolRequestParams::new(remote_tool_name.to_owned()).with_arguments(arguments);
    enforce_mcp_call_request_size_before_egress(&request, runtime_config.max_request_body_bytes)?;
    let destination = egress_client
        .checked_destination(&server.url)
        .await
        .map_err(|_| McpUpstreamCallError::EgressRejected)?;
    let mut service = connect(server, runtime_config, &destination).await?;
    let result = service
        .call_tool(request)
        .await
        .map_err(|error| mcp_service_error(error, McpUpstreamCallError::Call))?;
    let _ = service.close_with_timeout(Duration::from_millis(250)).await;

    Ok(result)
}

pub async fn discover_connection_catalog(
    runtime: &ConnectionHttpRuntime,
    connection_id: &str,
    expected_connection_etag: &str,
) -> Result<McpDiscoveredCatalog, McpUpstreamCallError> {
    let target = runtime
        .mcp_target(connection_id)
        .map_err(connection_mcp_error)?;
    if target.connection_etag() != expected_connection_etag {
        return Err(McpUpstreamCallError::Connection {
            reason: "connection_changed",
        });
    }
    let runtime_config = McpUpstreamRuntimeConfig::from_connection_target(&target);
    let client = managed_mcp_http_client(runtime, &target).await?;
    let credential = runtime
        .resolve_credential(&target)
        .await
        .map_err(connection_mcp_error)?
        .map(Arc::new);
    let response_budget = DiscoveryResponseByteBudget::new(MAX_DISCOVERY_RESPONSE_BYTES);
    let mut service = connect_connection(
        &target,
        &runtime_config,
        client,
        credential,
        Some(response_budget.clone()),
    )
    .await?;
    let discovered = discover_catalog_with_limits(&mut service).await;
    let close_result = service.close_with_timeout(Duration::from_millis(250)).await;
    drop(service);
    response_budget.seal()?;
    let discovered = discovered?;
    if !discovery_shutdown_completed_cleanly(&close_result) {
        return Err(McpUpstreamCallError::Call);
    }
    let catalog = McpDiscoveredCatalog {
        tools: discovered
            .tools
            .into_iter()
            .map(|tool| connection_proxy_definition(connection_id, tool))
            .collect(),
        resources: discovered.resources,
        resource_templates: discovered.resource_templates,
    };
    if catalog.total_count() > MAX_CATALOG_ENTRIES {
        return Err(McpUpstreamCallError::DiscoveryCapabilityLimitExceeded {
            max: MAX_CATALOG_ENTRIES,
        });
    }
    Ok(catalog)
}

/// Verifies a managed MCP endpoint without publishing discovery metadata.
///
/// The probe initializes one RMCP session, requests at most one advertised
/// metadata page, and closes the session. Tools take precedence over resources;
/// pagination cursors are deliberately ignored. The probe never publishes
/// metadata, calls a tool, or reads a resource.
pub async fn probe_connection_protocol_before(
    runtime: &ConnectionHttpRuntime,
    connection_id: &str,
    expected_connection_etag: &str,
    hard_deadline: tokio::time::Instant,
) -> Result<(), ConnectionProtocolProbeError> {
    let target = runtime
        .mcp_test_target(connection_id, expected_connection_etag)
        .map_err(|error| {
            protocol_probe_connection_error(error, ConnectionTestStageName::ProtocolValid)
        })?;
    let Some(target) = target else {
        return Err(ConnectionProtocolProbeError::new(
            ConnectionTestStageName::ProtocolValid,
            ConnectionTestReason::ConnectionChanged,
            ConnectionStatusReason::RequestFailed,
        ));
    };

    let runtime_config = McpUpstreamRuntimeConfig::from_connection_target(&target);
    let operation_deadline =
        protocol_probe_operation_deadline(runtime_config.timeout, hard_deadline)?;
    let checked = tokio::time::timeout_at(
        operation_deadline,
        target.preflight_client().checked_destination(target.url()),
    )
    .await
    .map_err(|_| protocol_probe_timeout(ConnectionTestStageName::EgressPolicy))?
    .map_err(|error| protocol_probe_egress_error(&error))?;
    let prepared = tokio::time::timeout_at(
        operation_deadline,
        runtime.prepare_transport(&target, &checked),
    )
    .await
    .map_err(|_| protocol_probe_timeout(ConnectionTestStageName::SecretAvailable))?
    .map_err(|error| {
        protocol_probe_connection_error(error, ConnectionTestStageName::SecretAvailable)
    })?;
    let client = prepared
        .client()
        .mcp_reqwest_client_at_checked_destination(prepared.destination(), target.url())
        .map_err(|error| protocol_probe_egress_error(&error))?;
    let credential =
        tokio::time::timeout_at(operation_deadline, runtime.resolve_credential(&target))
            .await
            .map_err(|_| protocol_probe_timeout(ConnectionTestStageName::SecretAvailable))?
            .map_err(|error| {
                protocol_probe_connection_error(error, ConnectionTestStageName::SecretAvailable)
            })?
            .map(Arc::new);
    run_bounded_protocol_probe(
        target.connection_id().as_str().to_owned(),
        target.url().to_owned(),
        runtime_config,
        client,
        ManagedMcpAuthentication {
            credential,
            credential_header_name: target.credential_header_name().cloned(),
        },
        operation_deadline,
        hard_deadline,
    )
    .await
}

fn protocol_probe_operation_deadline(
    configured_timeout: Duration,
    hard_deadline: tokio::time::Instant,
) -> Result<tokio::time::Instant, ConnectionProtocolProbeError> {
    let now = tokio::time::Instant::now();
    let remaining = hard_deadline.saturating_duration_since(now);
    let Some(operation_budget) = remaining.checked_sub(PROTOCOL_PROBE_CLEANUP_RESERVE) else {
        return Err(protocol_probe_timeout(ConnectionTestStageName::Connected));
    };
    if operation_budget.is_zero() {
        return Err(protocol_probe_timeout(ConnectionTestStageName::Connected));
    }
    Ok(now + configured_timeout.min(operation_budget))
}

#[allow(clippy::too_many_arguments)]
async fn run_bounded_protocol_probe(
    server_name: String,
    url: String,
    runtime_config: McpUpstreamRuntimeConfig,
    client: rmcp_http::Client,
    managed_authentication: ManagedMcpAuthentication,
    operation_deadline: tokio::time::Instant,
    hard_deadline: tokio::time::Instant,
) -> Result<(), ConnectionProtocolProbeError> {
    let control = ProtocolProbeTransportControl::new(operation_deadline);
    let worker_control = control.clone();
    let worker = tokio::spawn(async move {
        run_protocol_probe_worker(
            server_name,
            url,
            runtime_config,
            client,
            managed_authentication,
            worker_control,
        )
        .await
    });
    ProtocolProbeWorkerGuard::new(worker, control)
        .finish_before(hard_deadline)
        .await
}

async fn run_protocol_probe_worker(
    server_name: String,
    url: String,
    runtime_config: McpUpstreamRuntimeConfig,
    client: rmcp_http::Client,
    managed_authentication: ManagedMcpAuthentication,
    control: ProtocolProbeTransportControl,
) -> Result<(), ConnectionProtocolProbeError> {
    let response_budget = DiscoveryResponseByteBudget::new(MAX_DISCOVERY_RESPONSE_BYTES);
    let connect_result = tokio::time::timeout_at(
        control.deadline(),
        connect_endpoint_with_client(
            &server_name,
            &url,
            &runtime_config,
            client,
            Some(managed_authentication),
            Some(response_budget.clone()),
            Some(control.clone()),
        ),
    )
    .await;
    let mut service = match connect_result {
        Ok(Ok(service)) => service,
        Ok(Err(error)) => {
            return Err(protocol_probe_mcp_error(
                error,
                ConnectionTestStageName::Connected,
            ));
        }
        Err(_) => {
            let error = protocol_probe_timeout(ConnectionTestStageName::Connected);
            control.record_failure(error);
            return Err(error);
        }
    };

    let page_result = tokio::time::timeout_at(
        control.deadline(),
        probe_one_advertised_metadata_page(&mut service),
    )
    .await
    .map_err(|_| protocol_probe_timeout(ConnectionTestStageName::ProtocolValid))
    .and_then(|result| {
        result.map_err(|error| {
            protocol_probe_mcp_error(error, ConnectionTestStageName::ProtocolValid)
        })
    });
    if let Err(error) = page_result {
        control.record_failure(error);
    }
    let common_get_result = if page_result.is_ok() {
        control.wait_for_common_get().await
    } else {
        Ok(())
    };
    let close_result = service.close().await.map(Some);
    drop(service);
    let response_budget_result = response_budget
        .seal()
        .map_err(|error| protocol_probe_mcp_error(error, ConnectionTestStageName::ProtocolValid));

    if let Some(error) = control.failure() {
        return Err(error);
    }
    response_budget_result?;
    page_result?;
    common_get_result?;
    if !discovery_shutdown_completed_cleanly(&close_result) {
        return Err(ConnectionProtocolProbeError::new(
            ConnectionTestStageName::ProtocolValid,
            ConnectionTestReason::ProtocolError,
            ConnectionStatusReason::InvalidResponse,
        ));
    }
    Ok(())
}

struct ProtocolProbeWorkerGuard {
    handle: Option<tokio::task::JoinHandle<Result<(), ConnectionProtocolProbeError>>>,
    control: ProtocolProbeTransportControl,
}

impl ProtocolProbeWorkerGuard {
    fn new(
        handle: tokio::task::JoinHandle<Result<(), ConnectionProtocolProbeError>>,
        control: ProtocolProbeTransportControl,
    ) -> Self {
        Self {
            handle: Some(handle),
            control,
        }
    }

    async fn finish_before(
        mut self,
        hard_deadline: tokio::time::Instant,
    ) -> Result<(), ConnectionProtocolProbeError> {
        let Some(handle) = self.handle.as_mut() else {
            return Err(protocol_probe_internal_error());
        };
        let joined = tokio::time::timeout_at(hard_deadline, handle).await;
        match joined {
            Ok(Ok(result)) => {
                self.handle.take();
                self.control.wait_for_idle_io().await;
                result
            }
            Ok(Err(_)) => {
                self.handle.take();
                self.control.wait_for_idle_io().await;
                Err(protocol_probe_internal_error())
            }
            Err(_) => {
                self.control.cancel();
                if let Some(handle) = self.handle.take() {
                    handle.abort();
                    let _ = handle.await;
                }
                self.control.wait_for_idle_io().await;
                Err(protocol_probe_timeout(
                    ConnectionTestStageName::ProtocolValid,
                ))
            }
        }
    }
}

impl Drop for ProtocolProbeWorkerGuard {
    fn drop(&mut self) {
        self.control.cancel();
        if let Some(handle) = self.handle.as_ref() {
            handle.abort();
        }
    }
}

#[derive(Clone)]
struct ProtocolProbeTransportControl {
    state: Arc<ProtocolProbeTransportState>,
}

struct ProtocolProbeTransportState {
    deadline: tokio::time::Instant,
    cancellation: tokio_util::sync::CancellationToken,
    failure: Mutex<Option<ConnectionProtocolProbeError>>,
    common_get_expected: AtomicBool,
    common_get_completed: AtomicBool,
    common_get_notify: tokio::sync::Notify,
    active_io: AtomicUsize,
    idle_io_notify: tokio::sync::Notify,
}

impl ProtocolProbeTransportControl {
    fn new(deadline: tokio::time::Instant) -> Self {
        Self {
            state: Arc::new(ProtocolProbeTransportState {
                deadline,
                cancellation: tokio_util::sync::CancellationToken::new(),
                failure: Mutex::new(None),
                common_get_expected: AtomicBool::new(false),
                common_get_completed: AtomicBool::new(false),
                common_get_notify: tokio::sync::Notify::new(),
                active_io: AtomicUsize::new(0),
                idle_io_notify: tokio::sync::Notify::new(),
            }),
        }
    }

    fn deadline(&self) -> tokio::time::Instant {
        self.state.deadline
    }

    fn cancellation(&self) -> &tokio_util::sync::CancellationToken {
        &self.state.cancellation
    }

    fn cancel(&self) {
        self.state.cancellation.cancel();
    }

    fn record_failure(&self, error: ConnectionProtocolProbeError) {
        let mut failure = match self.state.failure.lock() {
            Ok(failure) => failure,
            Err(poisoned) => poisoned.into_inner(),
        };
        if failure.is_none() {
            *failure = Some(error);
        }
    }

    fn failure(&self) -> Option<ConnectionProtocolProbeError> {
        match self.state.failure.lock() {
            Ok(failure) => *failure,
            Err(_) => Some(protocol_probe_internal_error()),
        }
    }

    fn record_limited_error(&self, error: &LimitedMcpHttpError) {
        let error = match error {
            LimitedMcpHttpError::Http("http_timeout") => {
                protocol_probe_timeout(ConnectionTestStageName::ProtocolValid)
            }
            LimitedMcpHttpError::Http(category) => ConnectionProtocolProbeError::new(
                ConnectionTestStageName::ProtocolValid,
                protocol_probe_http_reason(category),
                ConnectionStatusReason::RequestFailed,
            ),
            LimitedMcpHttpError::Connection(error) => {
                protocol_probe_connection_error(*error, ConnectionTestStageName::ProtocolValid)
            }
            LimitedMcpHttpError::AuthenticationRejected => ConnectionProtocolProbeError::new(
                ConnectionTestStageName::Authenticated,
                ConnectionTestReason::AuthenticationFailed,
                ConnectionStatusReason::InvalidResponse,
            ),
            LimitedMcpHttpError::RequestBodyTooLarge { .. } => ConnectionProtocolProbeError::new(
                ConnectionTestStageName::ProtocolValid,
                ConnectionTestReason::RequestBodyTooLarge,
                ConnectionStatusReason::RequestFailed,
            ),
            LimitedMcpHttpError::ResponseTooLarge { .. }
            | LimitedMcpHttpError::DiscoveryResponseTooLarge { .. } => {
                ConnectionProtocolProbeError::new(
                    ConnectionTestStageName::ProtocolValid,
                    ConnectionTestReason::ResponseTooLarge,
                    ConnectionStatusReason::InvalidResponse,
                )
            }
            LimitedMcpHttpError::Serialize(_) => ConnectionProtocolProbeError::new(
                ConnectionTestStageName::ProtocolValid,
                ConnectionTestReason::ProtocolError,
                ConnectionStatusReason::InvalidResponse,
            ),
        };
        self.record_failure(error);
    }

    fn observe_streamable_error(&self, error: &StreamableHttpError<LimitedMcpHttpError>) {
        match error {
            StreamableHttpError::ServerDoesNotSupportSse
            | StreamableHttpError::ServerDoesNotSupportDeleteSession => {}
            StreamableHttpError::Client(error) => self.record_limited_error(error),
            _ => self.record_failure(ConnectionProtocolProbeError::new(
                ConnectionTestStageName::ProtocolValid,
                ConnectionTestReason::ProtocolError,
                ConnectionStatusReason::InvalidResponse,
            )),
        }
    }

    fn expect_common_get(&self) {
        self.state
            .common_get_expected
            .store(true, Ordering::Release);
    }

    fn complete_common_get(&self) {
        self.state
            .common_get_completed
            .store(true, Ordering::Release);
        self.state.common_get_notify.notify_waiters();
    }

    async fn wait_for_common_get(&self) -> Result<(), ConnectionProtocolProbeError> {
        if !self.state.common_get_expected.load(Ordering::Acquire) {
            return Ok(());
        }
        loop {
            let notified = self.state.common_get_notify.notified();
            if self.state.common_get_completed.load(Ordering::Acquire) {
                return self.failure().map_or(Ok(()), Err);
            }
            tokio::select! {
                _ = self.cancellation().cancelled() => {
                    return Err(protocol_probe_timeout(ConnectionTestStageName::ProtocolValid));
                }
                _ = tokio::time::sleep_until(self.deadline()) => {
                    let error = protocol_probe_timeout(ConnectionTestStageName::ProtocolValid);
                    self.record_failure(error);
                    return Err(error);
                }
                _ = notified => {}
            }
        }
    }

    fn begin_io(&self) -> ProtocolProbeIoGuard {
        self.state.active_io.fetch_add(1, Ordering::AcqRel);
        ProtocolProbeIoGuard {
            control: self.clone(),
        }
    }

    async fn wait_for_idle_io(&self) {
        loop {
            let notified = self.state.idle_io_notify.notified();
            if self.state.active_io.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

struct ProtocolProbeIoGuard {
    control: ProtocolProbeTransportControl,
}

impl Drop for ProtocolProbeIoGuard {
    fn drop(&mut self) {
        if self.control.state.active_io.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.control.state.idle_io_notify.notify_waiters();
        }
    }
}

fn protocol_probe_http_reason(category: &str) -> ConnectionTestReason {
    match category {
        "http_timeout" => ConnectionTestReason::HttpTimeout,
        "http_connect" => ConnectionTestReason::HttpConnect,
        "http_request" => ConnectionTestReason::HttpRequest,
        "http_body" => ConnectionTestReason::HttpBody,
        "http_decode" => ConnectionTestReason::HttpDecode,
        "http_status" => ConnectionTestReason::HttpStatus,
        _ => ConnectionTestReason::HttpOther,
    }
}

fn protocol_probe_internal_error() -> ConnectionProtocolProbeError {
    ConnectionProtocolProbeError::new(
        ConnectionTestStageName::ProtocolValid,
        ConnectionTestReason::InternalError,
        ConnectionStatusReason::RequestFailed,
    )
}

fn discovery_shutdown_completed_cleanly<E>(close_result: &Result<Option<QuitReason>, E>) -> bool {
    matches!(
        close_result,
        Ok(Some(QuitReason::Cancelled | QuitReason::Closed))
    )
}

pub async fn call_connection_tool(
    runtime: &ConnectionHttpRuntime,
    connection_id: &str,
    expected_connection_etag: &str,
    remote_tool_name: &str,
    args: Value,
) -> Result<CallToolResult, McpUpstreamCallError> {
    let target = runtime
        .mcp_target(connection_id)
        .map_err(connection_mcp_error)?;
    if target.connection_etag() != expected_connection_etag {
        return Err(McpUpstreamCallError::Connection {
            reason: "catalog_stale",
        });
    }
    let runtime_config = McpUpstreamRuntimeConfig::from_connection_target(&target);
    let arguments = match args {
        Value::Object(arguments) => arguments,
        _ => JsonObject::new(),
    };
    let request = CallToolRequestParams::new(remote_tool_name.to_owned()).with_arguments(arguments);
    enforce_mcp_call_request_size_before_egress(&request, runtime_config.max_request_body_bytes)?;
    let client = managed_mcp_http_client(runtime, &target).await?;
    let credential = runtime
        .resolve_credential(&target)
        .await
        .map_err(connection_mcp_error)?
        .map(Arc::new);
    let mut service =
        connect_connection(&target, &runtime_config, client, credential, None).await?;
    let result = service
        .call_tool(request)
        .await
        .map_err(|error| mcp_service_error(error, McpUpstreamCallError::Call))?;
    let _ = service.close_with_timeout(Duration::from_millis(250)).await;
    Ok(result)
}

fn connection_mcp_error(error: ConnectionHttpError) -> McpUpstreamCallError {
    McpUpstreamCallError::Connection {
        reason: error.safe_reason(),
    }
}

async fn managed_mcp_http_client(
    runtime: &ConnectionHttpRuntime,
    target: &ConnectionHttpTarget,
) -> Result<rmcp_http::Client, McpUpstreamCallError> {
    let checked = target
        .preflight_client()
        .checked_destination(target.url())
        .await
        .map_err(|_| McpUpstreamCallError::EgressRejected)?;
    let prepared = runtime
        .prepare_transport(target, &checked)
        .await
        .map_err(connection_mcp_error)?;
    prepared
        .client()
        .mcp_reqwest_client_at_checked_destination(prepared.destination(), target.url())
        .map_err(|_| McpUpstreamCallError::EgressRejected)
}

fn protocol_probe_timeout(stage: ConnectionTestStageName) -> ConnectionProtocolProbeError {
    ConnectionProtocolProbeError::new(
        stage,
        ConnectionTestReason::DeadlineExceeded,
        ConnectionStatusReason::RequestFailed,
    )
}

fn protocol_probe_egress_error(error: &EgressError) -> ConnectionProtocolProbeError {
    let reason = match error.safe_category() {
        "host_not_allowed" => ConnectionTestReason::HostNotAllowed,
        "port_not_allowed" => ConnectionTestReason::PortNotAllowed,
        "non_global_ip_blocked" => ConnectionTestReason::NonGlobalIpBlocked,
        "invalid_policy" => ConnectionTestReason::InvalidPolicy,
        "dns_resolution_failed" => ConnectionTestReason::DnsResolutionFailed,
        "invalid_url" => ConnectionTestReason::InvalidUrl,
        "scheme_not_allowed" => ConnectionTestReason::SchemeNotAllowed,
        "request_body_too_large" => ConnectionTestReason::RequestBodyTooLarge,
        "request_body_read_failed" => ConnectionTestReason::RequestBodyReadFailed,
        "unexpected_status" => ConnectionTestReason::UnexpectedStatus,
        "response_too_large" => ConnectionTestReason::ResponseTooLarge,
        "response_idle_timeout" => ConnectionTestReason::ResponseIdleTimeout,
        "invalid_tls_ca_bundle" => ConnectionTestReason::InvalidTlsCaBundle,
        "invalid_tls_client_identity" => ConnectionTestReason::InvalidTlsClientIdentity,
        "http_timeout" => ConnectionTestReason::HttpTimeout,
        "http_connect" => ConnectionTestReason::HttpConnect,
        "http_request" => ConnectionTestReason::HttpRequest,
        "http_body" => ConnectionTestReason::HttpBody,
        "http_decode" => ConnectionTestReason::HttpDecode,
        "http_status" => ConnectionTestReason::HttpStatus,
        "http_other" => ConnectionTestReason::HttpOther,
        _ => ConnectionTestReason::InternalError,
    };
    ConnectionProtocolProbeError::new(
        ConnectionTestStageName::EgressPolicy,
        reason,
        ConnectionStatusReason::EgressDenied,
    )
}

fn protocol_probe_connection_error(
    error: ConnectionHttpError,
    default_stage: ConnectionTestStageName,
) -> ConnectionProtocolProbeError {
    let (stage, reason, status_reason) = match error {
        ConnectionHttpError::InvalidConnectionId
        | ConnectionHttpError::ConnectionNotFound
        | ConnectionHttpError::ConnectionDisabled => (
            default_stage,
            ConnectionTestReason::ConnectionChanged,
            ConnectionStatusReason::RequestFailed,
        ),
        ConnectionHttpError::WrongConnectionKind => (
            default_stage,
            ConnectionTestReason::ConnectionKindMismatch,
            ConnectionStatusReason::RequestFailed,
        ),
        ConnectionHttpError::UnsupportedAuthentication => (
            ConnectionTestStageName::SecretAvailable,
            ConnectionTestReason::AuthenticationNotSupported,
            ConnectionStatusReason::SecretUnavailable,
        ),
        ConnectionHttpError::TlsInvalid => (
            ConnectionTestStageName::SecretAvailable,
            ConnectionTestReason::TlsInvalid,
            ConnectionStatusReason::SecretUnavailable,
        ),
        ConnectionHttpError::TlsUnavailable => (
            ConnectionTestStageName::SecretAvailable,
            ConnectionTestReason::TlsUnavailable,
            ConnectionStatusReason::SecretUnavailable,
        ),
        ConnectionHttpError::InvalidTargetPath => (
            default_stage,
            ConnectionTestReason::TestProfileNotConfigured,
            ConnectionStatusReason::RequestFailed,
        ),
        ConnectionHttpError::CredentialHeaderConflict | ConnectionHttpError::CredentialInvalid => (
            ConnectionTestStageName::SecretAvailable,
            ConnectionTestReason::CredentialInvalid,
            ConnectionStatusReason::SecretUnavailable,
        ),
        ConnectionHttpError::CredentialUnavailable => (
            ConnectionTestStageName::SecretAvailable,
            ConnectionTestReason::CredentialUnavailable,
            ConnectionStatusReason::SecretUnavailable,
        ),
        ConnectionHttpError::OAuthTokenEgressDenied => (
            ConnectionTestStageName::EgressPolicy,
            ConnectionTestReason::OauthTokenEgressDenied,
            ConnectionStatusReason::EgressDenied,
        ),
        ConnectionHttpError::OAuthTokenUnavailable => (
            ConnectionTestStageName::SecretAvailable,
            ConnectionTestReason::OauthTokenUnavailable,
            ConnectionStatusReason::SecretUnavailable,
        ),
        ConnectionHttpError::OAuthTokenRejected => (
            ConnectionTestStageName::SecretAvailable,
            ConnectionTestReason::OauthTokenRejected,
            ConnectionStatusReason::SecretUnavailable,
        ),
        ConnectionHttpError::OAuthTokenInvalidResponse => (
            ConnectionTestStageName::SecretAvailable,
            ConnectionTestReason::OauthTokenInvalidResponse,
            ConnectionStatusReason::SecretUnavailable,
        ),
        ConnectionHttpError::UpstreamAuthenticationRejected => (
            ConnectionTestStageName::Authenticated,
            ConnectionTestReason::AuthenticationFailed,
            ConnectionStatusReason::InvalidResponse,
        ),
        ConnectionHttpError::TransportUnavailable => (
            default_stage,
            ConnectionTestReason::TransportUnavailable,
            ConnectionStatusReason::RequestFailed,
        ),
    };
    ConnectionProtocolProbeError::new(stage, reason, status_reason)
}

fn protocol_probe_mcp_error(
    error: McpUpstreamCallError,
    default_stage: ConnectionTestStageName,
) -> ConnectionProtocolProbeError {
    match error {
        McpUpstreamCallError::EgressRejected => ConnectionProtocolProbeError::new(
            ConnectionTestStageName::EgressPolicy,
            ConnectionTestReason::InvalidPolicy,
            ConnectionStatusReason::EgressDenied,
        ),
        McpUpstreamCallError::ClientBuild => ConnectionProtocolProbeError::new(
            ConnectionTestStageName::Connected,
            ConnectionTestReason::TransportUnavailable,
            ConnectionStatusReason::RequestFailed,
        ),
        McpUpstreamCallError::Connect => ConnectionProtocolProbeError::new(
            ConnectionTestStageName::Connected,
            ConnectionTestReason::HttpConnect,
            ConnectionStatusReason::RequestFailed,
        ),
        McpUpstreamCallError::AuthenticationRejected => ConnectionProtocolProbeError::new(
            ConnectionTestStageName::Authenticated,
            ConnectionTestReason::AuthenticationFailed,
            ConnectionStatusReason::InvalidResponse,
        ),
        McpUpstreamCallError::Connection { reason } => {
            protocol_probe_connection_reason(reason, default_stage)
        }
        McpUpstreamCallError::RequestBodyTooLarge { .. } => ConnectionProtocolProbeError::new(
            default_stage,
            ConnectionTestReason::RequestBodyTooLarge,
            ConnectionStatusReason::RequestFailed,
        ),
        McpUpstreamCallError::ResponseTooLarge { .. }
        | McpUpstreamCallError::DiscoveryResponseLimitExceeded { .. } => {
            ConnectionProtocolProbeError::new(
                default_stage,
                ConnectionTestReason::ResponseTooLarge,
                ConnectionStatusReason::InvalidResponse,
            )
        }
        McpUpstreamCallError::Call
        | McpUpstreamCallError::DiscoveryPageLimitExceeded { .. }
        | McpUpstreamCallError::DiscoveryToolLimitExceeded { .. }
        | McpUpstreamCallError::DiscoveryResourceLimitExceeded { .. }
        | McpUpstreamCallError::DiscoveryResourceTemplateLimitExceeded { .. }
        | McpUpstreamCallError::DiscoveryCapabilityLimitExceeded { .. }
        | McpUpstreamCallError::InvalidDiscoveryMetadata => ConnectionProtocolProbeError::new(
            default_stage,
            ConnectionTestReason::ProtocolError,
            ConnectionStatusReason::InvalidResponse,
        ),
    }
}

fn protocol_probe_connection_reason(
    reason: &'static str,
    default_stage: ConnectionTestStageName,
) -> ConnectionProtocolProbeError {
    let error = match reason {
        "connection_changed"
        | "catalog_stale"
        | "connection_not_found"
        | "invalid_connection_id"
        | "connection_disabled" => (
            default_stage,
            ConnectionTestReason::ConnectionChanged,
            ConnectionStatusReason::RequestFailed,
        ),
        "connection_kind_mismatch" => (
            default_stage,
            ConnectionTestReason::ConnectionKindMismatch,
            ConnectionStatusReason::RequestFailed,
        ),
        "authentication_not_supported" => (
            ConnectionTestStageName::SecretAvailable,
            ConnectionTestReason::AuthenticationNotSupported,
            ConnectionStatusReason::SecretUnavailable,
        ),
        "tls_invalid" => (
            ConnectionTestStageName::SecretAvailable,
            ConnectionTestReason::TlsInvalid,
            ConnectionStatusReason::SecretUnavailable,
        ),
        "tls_unavailable" => (
            ConnectionTestStageName::SecretAvailable,
            ConnectionTestReason::TlsUnavailable,
            ConnectionStatusReason::SecretUnavailable,
        ),
        "credential_invalid" | "credential_header_conflict" => (
            ConnectionTestStageName::SecretAvailable,
            ConnectionTestReason::CredentialInvalid,
            ConnectionStatusReason::SecretUnavailable,
        ),
        "credential_unavailable" => (
            ConnectionTestStageName::SecretAvailable,
            ConnectionTestReason::CredentialUnavailable,
            ConnectionStatusReason::SecretUnavailable,
        ),
        "oauth_token_egress_denied" => (
            ConnectionTestStageName::EgressPolicy,
            ConnectionTestReason::OauthTokenEgressDenied,
            ConnectionStatusReason::EgressDenied,
        ),
        "oauth_token_unavailable" => (
            ConnectionTestStageName::SecretAvailable,
            ConnectionTestReason::OauthTokenUnavailable,
            ConnectionStatusReason::SecretUnavailable,
        ),
        "oauth_token_rejected" => (
            ConnectionTestStageName::SecretAvailable,
            ConnectionTestReason::OauthTokenRejected,
            ConnectionStatusReason::SecretUnavailable,
        ),
        "oauth_token_invalid_response" => (
            ConnectionTestStageName::SecretAvailable,
            ConnectionTestReason::OauthTokenInvalidResponse,
            ConnectionStatusReason::SecretUnavailable,
        ),
        "auth_failed" => (
            ConnectionTestStageName::Authenticated,
            ConnectionTestReason::AuthenticationFailed,
            ConnectionStatusReason::InvalidResponse,
        ),
        "transport_unavailable" => (
            default_stage,
            ConnectionTestReason::TransportUnavailable,
            ConnectionStatusReason::RequestFailed,
        ),
        _ => (
            default_stage,
            ConnectionTestReason::InternalError,
            ConnectionStatusReason::RequestFailed,
        ),
    };
    ConnectionProtocolProbeError::new(error.0, error.1, error.2)
}

fn enforce_mcp_call_request_size_before_egress(
    request: &CallToolRequestParams,
    max_request_body_bytes: usize,
) -> Result<(), McpUpstreamCallError> {
    // RMCP adds both a request ID and a progress token before transport serialization. Use the
    // longest numeric forms so a request accepted here cannot cross the configured cap later when
    // RMCP assigns its smaller runtime counters.
    let size = serialized_mcp_call_request_size(request, i64::MIN, i64::MIN)?;

    if size > max_request_body_bytes {
        tracing::warn!(
            size,
            max = max_request_body_bytes,
            "egress blocked oversized MCP call before destination resolution"
        );
        return Err(McpUpstreamCallError::RequestBodyTooLarge {
            size,
            max: max_request_body_bytes,
        });
    }

    Ok(())
}

fn serialized_mcp_call_request_size(
    request: &CallToolRequestParams,
    request_id: i64,
    progress_token: i64,
) -> Result<usize, McpUpstreamCallError> {
    let mut bounded_request = request.clone();
    bounded_request.meta = Some(Meta::with_progress_token(ProgressToken(
        NumberOrString::Number(progress_token),
    )));
    let message = ClientJsonRpcMessage::request(
        ClientRequest::CallToolRequest(CallToolRequest::new(bounded_request)),
        NumberOrString::Number(request_id),
    );
    let size = serde_json::to_vec(&message)
        .map_err(|_| McpUpstreamCallError::Call)?
        .len();
    Ok(size)
}

async fn list_tools(
    server: &McpUpstreamServerConfig,
    runtime_config: &McpUpstreamRuntimeConfig,
    destination: &CheckedEgressDestination,
) -> Result<Vec<Tool>, McpUpstreamCallError> {
    let mut service = connect(server, runtime_config, destination).await?;
    let tools = list_tools_with_limits(&mut service).await;
    let _ = service.close_with_timeout(Duration::from_millis(250)).await;
    tools
}

async fn list_tools_with_limits(
    service: &mut rmcp::service::RunningService<rmcp::RoleClient, ()>,
) -> Result<Vec<Tool>, McpUpstreamCallError> {
    let mut budget = DiscoveryPageBudget::new();
    list_tools_with_limits_and_budget(service, &mut budget).await
}

async fn probe_one_advertised_metadata_page(
    service: &mut rmcp::service::RunningService<rmcp::RoleClient, ()>,
) -> Result<(), McpUpstreamCallError> {
    let (supports_tools, supports_resources) = service
        .peer_info()
        .map(|info| {
            (
                info.capabilities.tools.is_some(),
                info.capabilities.resources.is_some(),
            )
        })
        .unwrap_or((false, false));
    if supports_tools {
        let result = service
            .list_tools(Some(PaginatedRequestParams::default()))
            .await
            .map_err(|error| mcp_service_error(error, McpUpstreamCallError::Call))?;
        if result.tools.len() > MAX_DISCOVERY_TOOLS_PER_UPSTREAM {
            return Err(McpUpstreamCallError::DiscoveryToolLimitExceeded {
                max: MAX_DISCOVERY_TOOLS_PER_UPSTREAM,
            });
        }
    } else if supports_resources {
        let result = service
            .list_resources(Some(PaginatedRequestParams::default()))
            .await
            .map_err(|error| mcp_service_error(error, McpUpstreamCallError::Call))?;
        if result.resources.len() > MAX_DISCOVERY_RESOURCES_PER_UPSTREAM {
            return Err(McpUpstreamCallError::DiscoveryResourceLimitExceeded {
                max: MAX_DISCOVERY_RESOURCES_PER_UPSTREAM,
            });
        }
    }
    Ok(())
}

struct RawMcpDiscoveredCatalog {
    tools: Vec<Tool>,
    resources: Vec<StoredMcpResource>,
    resource_templates: Vec<StoredMcpResourceTemplate>,
}

struct DiscoveryPageBudget {
    consumed: usize,
}

impl DiscoveryPageBudget {
    fn new() -> Self {
        Self { consumed: 0 }
    }

    fn consume(&mut self) -> Result<(), McpUpstreamCallError> {
        if self.consumed >= MAX_DISCOVERY_PAGES_PER_UPSTREAM {
            tracing::warn!(
                max_pages = MAX_DISCOVERY_PAGES_PER_UPSTREAM,
                "MCP upstream discovery exceeded aggregate page limit"
            );
            return Err(McpUpstreamCallError::DiscoveryPageLimitExceeded {
                max: MAX_DISCOVERY_PAGES_PER_UPSTREAM,
            });
        }
        self.consumed += 1;
        Ok(())
    }
}

async fn discover_catalog_with_limits(
    service: &mut rmcp::service::RunningService<rmcp::RoleClient, ()>,
) -> Result<RawMcpDiscoveredCatalog, McpUpstreamCallError> {
    let mut budget = DiscoveryPageBudget::new();
    let (supports_tools, supports_resources) = service
        .peer_info()
        .map(|info| {
            (
                info.capabilities.tools.is_some(),
                info.capabilities.resources.is_some(),
            )
        })
        .unwrap_or((false, false));
    let tools = if supports_tools {
        list_tools_with_limits_and_budget(service, &mut budget).await?
    } else {
        Vec::new()
    };
    let (resources, resource_templates) = if supports_resources {
        (
            list_resources_with_limits(service, &mut budget).await?,
            list_resource_templates_with_limits(service, &mut budget).await?,
        )
    } else {
        (Vec::new(), Vec::new())
    };
    if tools
        .len()
        .saturating_add(resources.len())
        .saturating_add(resource_templates.len())
        > MAX_CATALOG_ENTRIES
    {
        return Err(McpUpstreamCallError::DiscoveryCapabilityLimitExceeded {
            max: MAX_CATALOG_ENTRIES,
        });
    }
    validate_mcp_resource_metadata(&resources, &resource_templates)
        .map_err(|_| McpUpstreamCallError::InvalidDiscoveryMetadata)?;
    Ok(RawMcpDiscoveredCatalog {
        tools,
        resources,
        resource_templates,
    })
}

async fn list_tools_with_limits_and_budget(
    service: &mut rmcp::service::RunningService<rmcp::RoleClient, ()>,
    budget: &mut DiscoveryPageBudget,
) -> Result<Vec<Tool>, McpUpstreamCallError> {
    let mut tools = Vec::new();
    let mut cursor = None;

    loop {
        budget.consume()?;
        let result = service
            .list_tools(Some(PaginatedRequestParams::default().with_cursor(cursor)))
            .await
            .map_err(|error| mcp_service_error(error, McpUpstreamCallError::Call))?;

        if tools.len().saturating_add(result.tools.len()) > MAX_DISCOVERY_TOOLS_PER_UPSTREAM {
            tracing::warn!(
                max_tools = MAX_DISCOVERY_TOOLS_PER_UPSTREAM,
                "MCP upstream discovery exceeded aggregate tool limit"
            );
            return Err(McpUpstreamCallError::DiscoveryToolLimitExceeded {
                max: MAX_DISCOVERY_TOOLS_PER_UPSTREAM,
            });
        }

        tools.extend(result.tools);
        cursor = result.next_cursor;
        if cursor.is_none() {
            return Ok(tools);
        }
    }
}

async fn list_resources_with_limits(
    service: &mut rmcp::service::RunningService<rmcp::RoleClient, ()>,
    budget: &mut DiscoveryPageBudget,
) -> Result<Vec<StoredMcpResource>, McpUpstreamCallError> {
    let mut resources = Vec::new();
    let mut cursor = None;
    loop {
        budget.consume()?;
        let result = service
            .list_resources(Some(PaginatedRequestParams::default().with_cursor(cursor)))
            .await
            .map_err(|error| mcp_service_error(error, McpUpstreamCallError::Call))?;
        if resources.len().saturating_add(result.resources.len())
            > MAX_DISCOVERY_RESOURCES_PER_UPSTREAM
        {
            return Err(McpUpstreamCallError::DiscoveryResourceLimitExceeded {
                max: MAX_DISCOVERY_RESOURCES_PER_UPSTREAM,
            });
        }
        resources.extend(result.resources.into_iter().map(stored_mcp_resource));
        cursor = result.next_cursor;
        if cursor.is_none() {
            return Ok(resources);
        }
    }
}

async fn list_resource_templates_with_limits(
    service: &mut rmcp::service::RunningService<rmcp::RoleClient, ()>,
    budget: &mut DiscoveryPageBudget,
) -> Result<Vec<StoredMcpResourceTemplate>, McpUpstreamCallError> {
    let mut resource_templates = Vec::new();
    let mut cursor = None;
    loop {
        budget.consume()?;
        let result = service
            .list_resource_templates(Some(PaginatedRequestParams::default().with_cursor(cursor)))
            .await
            .map_err(|error| mcp_service_error(error, McpUpstreamCallError::Call))?;
        if resource_templates
            .len()
            .saturating_add(result.resource_templates.len())
            > MAX_DISCOVERY_RESOURCE_TEMPLATES_PER_UPSTREAM
        {
            return Err(
                McpUpstreamCallError::DiscoveryResourceTemplateLimitExceeded {
                    max: MAX_DISCOVERY_RESOURCE_TEMPLATES_PER_UPSTREAM,
                },
            );
        }
        resource_templates.extend(
            result
                .resource_templates
                .into_iter()
                .map(stored_mcp_resource_template),
        );
        cursor = result.next_cursor;
        if cursor.is_none() {
            return Ok(resource_templates);
        }
    }
}

fn stored_mcp_resource(resource: McpResource) -> StoredMcpResource {
    StoredMcpResource {
        uri: resource.uri,
        name: resource.name,
        title: resource.title,
        description: resource.description,
        mime_type: resource.mime_type,
        size: resource.size,
    }
}

fn stored_mcp_resource_template(
    resource_template: McpResourceTemplate,
) -> StoredMcpResourceTemplate {
    StoredMcpResourceTemplate {
        uri_template: resource_template.uri_template,
        name: resource_template.name,
        title: resource_template.title,
        description: resource_template.description,
        mime_type: resource_template.mime_type,
    }
}

async fn connect(
    server: &McpUpstreamServerConfig,
    runtime_config: &McpUpstreamRuntimeConfig,
    destination: &CheckedEgressDestination,
) -> Result<rmcp::service::RunningService<rmcp::RoleClient, ()>, McpUpstreamCallError> {
    connect_endpoint(
        &server.name,
        &server.url,
        server_timeout(server, runtime_config),
        server_response_idle_timeout(server, runtime_config),
        server_connect_timeout(server, runtime_config),
        runtime_config,
        destination,
        None,
        None,
    )
    .await
}

async fn connect_connection(
    target: &ConnectionHttpTarget,
    runtime_config: &McpUpstreamRuntimeConfig,
    client: rmcp_http::Client,
    credential: Option<Arc<ResolvedConnectionCredential>>,
    discovery_response_budget: Option<DiscoveryResponseByteBudget>,
) -> Result<rmcp::service::RunningService<rmcp::RoleClient, ()>, McpUpstreamCallError> {
    connect_endpoint_with_client(
        target.connection_id().as_str(),
        target.url(),
        runtime_config,
        client,
        Some(ManagedMcpAuthentication {
            credential,
            credential_header_name: target.credential_header_name().cloned(),
        }),
        discovery_response_budget,
        None,
    )
    .await
}

struct ManagedMcpAuthentication {
    credential: Option<Arc<ResolvedConnectionCredential>>,
    credential_header_name: Option<HeaderName>,
}

#[allow(clippy::too_many_arguments)]
async fn connect_endpoint(
    server_name: &str,
    url: &str,
    timeout: Duration,
    response_idle_timeout: Duration,
    connect_timeout: Duration,
    runtime_config: &McpUpstreamRuntimeConfig,
    destination: &CheckedEgressDestination,
    managed_authentication: Option<ManagedMcpAuthentication>,
    discovery_response_budget: Option<DiscoveryResponseByteBudget>,
) -> Result<rmcp::service::RunningService<rmcp::RoleClient, ()>, McpUpstreamCallError> {
    let client = mcp_http_client(timeout, response_idle_timeout, connect_timeout, destination)?;
    connect_endpoint_with_client(
        server_name,
        url,
        runtime_config,
        client,
        managed_authentication,
        discovery_response_budget,
        None,
    )
    .await
}

async fn connect_endpoint_with_client(
    server_name: &str,
    url: &str,
    runtime_config: &McpUpstreamRuntimeConfig,
    client: rmcp_http::Client,
    managed_authentication: Option<ManagedMcpAuthentication>,
    discovery_response_budget: Option<DiscoveryResponseByteBudget>,
    protocol_probe_control: Option<ProtocolProbeTransportControl>,
) -> Result<rmcp::service::RunningService<rmcp::RoleClient, ()>, McpUpstreamCallError> {
    let mut client = LimitedMcpHttpClient::new(
        client,
        runtime_config.max_request_body_bytes,
        runtime_config.max_response_bytes,
    );
    if managed_authentication.is_some() {
        client = client
            .with_transport_timeouts(runtime_config.timeout, runtime_config.response_idle_timeout);
    }
    if let Some(discovery_response_budget) = discovery_response_budget {
        client = client.with_discovery_response_budget(discovery_response_budget);
    }
    if let Some(protocol_probe_control) = protocol_probe_control.as_ref() {
        client = client.with_protocol_probe_control(protocol_probe_control.clone());
    }
    let client = if let Some(authentication) = managed_authentication {
        client.with_connection_credential(
            authentication.credential,
            authentication.credential_header_name,
        )
    } else {
        client
    };
    let mut transport_config = StreamableHttpClientTransportConfig::with_uri(url.to_owned());
    if protocol_probe_control.is_some() {
        transport_config.retry_config = Arc::new(NeverRetry::default());
        transport_config = transport_config.reinit_on_expired_session(false);
    }
    let transport = StreamableHttpClientTransport::with_client(client, transport_config);

    let started = Instant::now();
    let result = rmcp::serve_client((), transport).await;
    tracing::debug!(
        server_name,
        latency_ms = duration_millis(started.elapsed()),
        "MCP upstream client initialized"
    );
    result.map_err(|error| mcp_service_error(error, McpUpstreamCallError::Connect))
}

fn mcp_http_client(
    timeout: Duration,
    response_idle_timeout: Duration,
    connect_timeout: Duration,
    destination: &CheckedEgressDestination,
) -> Result<rmcp_http::Client, McpUpstreamCallError> {
    rmcp_http::Client::builder()
        .no_proxy()
        .timeout(timeout)
        .read_timeout(response_idle_timeout)
        .connect_timeout(connect_timeout)
        .redirect(rmcp_http::redirect::Policy::none())
        .resolve(&destination.host, destination.pinned_addr)
        .build()
        .map_err(|_| McpUpstreamCallError::ClientBuild)
}

#[derive(Clone)]
struct DiscoveryResponseByteBudget {
    state: Arc<AtomicUsize>,
    maximum: usize,
}

impl DiscoveryResponseByteBudget {
    const SEALED: usize = usize::MAX - 1;
    const EXCEEDED: usize = usize::MAX;

    fn new(maximum: usize) -> Self {
        assert!(
            maximum < Self::SEALED,
            "MCP discovery response byte limit must leave room for internal states"
        );
        Self {
            state: Arc::new(AtomicUsize::new(0)),
            maximum,
        }
    }

    fn charge(&self, bytes: usize) -> Result<(), LimitedMcpHttpError> {
        let mut current = self.state.load(Ordering::Acquire);
        loop {
            if matches!(current, Self::SEALED | Self::EXCEEDED) {
                return Err(self.limit_error());
            }
            let next = current
                .checked_add(bytes)
                .filter(|next| *next <= self.maximum)
                .unwrap_or(Self::EXCEEDED);
            match self.state.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) if next == Self::EXCEEDED => return Err(self.limit_error()),
                Ok(_) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
    }

    fn seal(&self) -> Result<(), McpUpstreamCallError> {
        let mut current = self.state.load(Ordering::Acquire);
        loop {
            match current {
                Self::EXCEEDED => {
                    return Err(McpUpstreamCallError::DiscoveryResponseLimitExceeded {
                        max: self.maximum,
                    });
                }
                Self::SEALED => return Ok(()),
                _ => {
                    match self.state.compare_exchange_weak(
                        current,
                        Self::SEALED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return Ok(()),
                        Err(observed) => current = observed,
                    }
                }
            }
        }
    }

    fn limit_error(&self) -> LimitedMcpHttpError {
        LimitedMcpHttpError::DiscoveryResponseTooLarge { max: self.maximum }
    }
}

#[derive(Clone)]
struct LimitedMcpHttpClient {
    inner: rmcp_http::Client,
    max_request_body_bytes: usize,
    max_response_bytes: usize,
    discovery_response_budget: Option<DiscoveryResponseByteBudget>,
    request_timeout: Option<Duration>,
    response_idle_timeout: Option<Duration>,
    protocol_probe_control: Option<ProtocolProbeTransportControl>,
    managed_connection: bool,
    connection_credential: Option<Arc<ResolvedConnectionCredential>>,
    credential_header_name: Option<HeaderName>,
}

impl LimitedMcpHttpClient {
    fn new(
        inner: rmcp_http::Client,
        max_request_body_bytes: usize,
        max_response_bytes: usize,
    ) -> Self {
        Self {
            inner,
            max_request_body_bytes,
            max_response_bytes,
            discovery_response_budget: None,
            request_timeout: None,
            response_idle_timeout: None,
            protocol_probe_control: None,
            managed_connection: false,
            connection_credential: None,
            credential_header_name: None,
        }
    }

    fn with_discovery_response_budget(
        mut self,
        discovery_response_budget: DiscoveryResponseByteBudget,
    ) -> Self {
        self.discovery_response_budget = Some(discovery_response_budget);
        self
    }

    fn with_transport_timeouts(
        mut self,
        request_timeout: Duration,
        response_idle_timeout: Duration,
    ) -> Self {
        self.request_timeout = Some(request_timeout);
        self.response_idle_timeout = Some(response_idle_timeout);
        self
    }

    fn with_protocol_probe_control(
        mut self,
        protocol_probe_control: ProtocolProbeTransportControl,
    ) -> Self {
        self.protocol_probe_control = Some(protocol_probe_control);
        self
    }

    fn with_connection_credential(
        mut self,
        connection_credential: Option<Arc<ResolvedConnectionCredential>>,
        credential_header_name: Option<HeaderName>,
    ) -> Self {
        self.managed_connection = true;
        self.connection_credential = connection_credential;
        self.credential_header_name = credential_header_name;
        self
    }

    fn apply_connection_credential(
        &self,
        builder: rmcp_http::RequestBuilder,
    ) -> Result<rmcp_http::RequestBuilder, StreamableHttpError<LimitedMcpHttpError>> {
        let Some(credential) = self.connection_credential.as_ref() else {
            return Ok(builder);
        };
        let mut headers = http::HeaderMap::new();
        credential
            .inject(&mut headers)
            .map_err(|error| StreamableHttpError::Client(LimitedMcpHttpError::Connection(error)))?;
        Ok(builder.headers(headers))
    }

    async fn reject_connection_authentication(
        &self,
        response: rmcp_http::Response,
    ) -> Result<rmcp_http::Response, StreamableHttpError<LimitedMcpHttpError>> {
        if self.managed_connection
            && matches!(
                response.status(),
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
            )
        {
            if response.status() == StatusCode::UNAUTHORIZED {
                if let Some(credential) = self
                    .connection_credential
                    .as_ref()
                    .filter(|credential| credential.is_oauth())
                {
                    credential.invalidate_after_unauthorized().await;
                }
            }
            return Err(StreamableHttpError::Client(
                LimitedMcpHttpError::AuthenticationRejected,
            ));
        }
        Ok(response)
    }

    async fn send_request(
        &self,
        request: rmcp_http::RequestBuilder,
    ) -> Result<
        (rmcp_http::Response, Option<tokio::time::Instant>),
        StreamableHttpError<LimitedMcpHttpError>,
    > {
        let request_deadline = self
            .request_timeout
            .map(|timeout| tokio::time::Instant::now() + timeout);
        let deadline = match (
            request_deadline,
            self.protocol_probe_control
                .as_ref()
                .map(ProtocolProbeTransportControl::deadline),
        ) {
            (Some(request_deadline), Some(probe_deadline)) => {
                Some(request_deadline.min(probe_deadline))
            }
            (Some(request_deadline), None) => Some(request_deadline),
            (None, Some(probe_deadline)) => Some(probe_deadline),
            (None, None) => None,
        };
        let result = match (deadline, self.protocol_probe_control.as_ref()) {
            (Some(deadline), Some(control)) => {
                let _io_guard = control.begin_io();
                tokio::select! {
                    biased;
                    _ = control.cancellation().cancelled() => Err(mcp_timeout_error()),
                    result = tokio::time::timeout_at(deadline, request.send()) => {
                        result
                            .map_err(|_| mcp_timeout_error())
                            .and_then(|result| result.map_err(mcp_http_error))
                    }
                }
            }
            (Some(deadline), None) => tokio::time::timeout_at(deadline, request.send())
                .await
                .map_err(|_| mcp_timeout_error())
                .and_then(|result| result.map_err(mcp_http_error)),
            (None, Some(control)) => {
                let _io_guard = control.begin_io();
                tokio::select! {
                    biased;
                    _ = control.cancellation().cancelled() => Err(mcp_timeout_error()),
                    result = request.send() => result.map_err(mcp_http_error),
                }
            }
            (None, None) => request.send().await.map_err(mcp_http_error),
        };
        if let (Some(control), Err(error)) = (self.protocol_probe_control.as_ref(), &result) {
            control.observe_streamable_error(error);
        }
        result.map(|response| (response, deadline))
    }
}

#[derive(Debug)]
enum LimitedMcpHttpError {
    Http(&'static str),
    Connection(ConnectionHttpError),
    AuthenticationRejected,
    Serialize(serde_json::Error),
    RequestBodyTooLarge { size: usize, max: usize },
    ResponseTooLarge { max: usize },
    DiscoveryResponseTooLarge { max: usize },
}

impl fmt::Display for LimitedMcpHttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(category) => write!(formatter, "MCP upstream HTTP error: {category}"),
            Self::Connection(error) => write!(formatter, "MCP connection error: {error}"),
            Self::AuthenticationRejected => {
                formatter.write_str("MCP connection authentication rejected")
            }
            Self::Serialize(error) => {
                write!(formatter, "MCP upstream JSON serialize error: {error}")
            }
            Self::RequestBodyTooLarge { size, max } => {
                write!(
                    formatter,
                    "egress request body is too large: {size} > {max}"
                )
            }
            Self::ResponseTooLarge { max } => {
                write!(formatter, "egress response body exceeded {max} bytes")
            }
            Self::DiscoveryResponseTooLarge { max } => {
                write!(
                    formatter,
                    "MCP discovery response bodies exceeded {max} bytes"
                )
            }
        }
    }
}

impl Error for LimitedMcpHttpError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Serialize(error) => Some(error),
            Self::Connection(error) => Some(error),
            Self::Http(_)
            | Self::AuthenticationRejected
            | Self::RequestBodyTooLarge { .. }
            | Self::ResponseTooLarge { .. }
            | Self::DiscoveryResponseTooLarge { .. } => None,
        }
    }
}

impl From<rmcp_http::Error> for LimitedMcpHttpError {
    fn from(error: rmcp_http::Error) -> Self {
        Self::Http(mcp_http_error_category(&error))
    }
}

impl From<serde_json::Error> for LimitedMcpHttpError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialize(error)
    }
}

impl StreamableHttpClient for LimitedMcpHttpClient {
    type Error = LimitedMcpHttpError;

    async fn get_stream(
        &self,
        uri: Arc<str>,
        session_id: Arc<str>,
        last_event_id: Option<String>,
        auth_token: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<BoxStream<'static, Result<Sse, SseError>>, StreamableHttpError<Self::Error>> {
        let result = async {
            let mut request_builder = self
                .inner
                .get(uri.as_ref())
                .header(ACCEPT, [EVENT_STREAM_MIME, JSON_MIME].join(", "))
                .header(HEADER_SESSION_ID, session_id.as_ref());
            if let Some(last_event_id) = last_event_id {
                request_builder = request_builder.header(HEADER_LAST_EVENT_ID, last_event_id);
            }
            if !self.managed_connection {
                if let Some(auth_header) = auth_token {
                    request_builder = request_builder.bearer_auth(auth_header);
                }
            }
            request_builder = apply_mcp_custom_headers(
                request_builder,
                custom_headers,
                self.credential_header_name.as_ref(),
                self.managed_connection,
            )?;
            request_builder = self.apply_connection_credential(request_builder)?;
            let (response, deadline) = self.send_request(request_builder).await?;
            let response = self.reject_connection_authentication(response).await?;
            if response.status() == StatusCode::METHOD_NOT_ALLOWED {
                return Err(StreamableHttpError::ServerDoesNotSupportSse);
            }
            let response = response.error_for_status().map_err(mcp_http_error)?;
            validate_mcp_response_content_type(&response)?;
            enforce_mcp_response_content_length(&response, self.max_response_bytes)?;

            let event_stream = SseStream::from_byte_stream(limited_mcp_response_stream(
                response,
                self.max_response_bytes,
                self.discovery_response_budget.clone(),
                deadline,
                self.response_idle_timeout,
                self.protocol_probe_control.clone(),
            ));
            let event_stream = if self.protocol_probe_control.is_some() {
                event_stream
                    .map(|event| {
                        event.map(|mut event| {
                            // RMCP gives a server-provided `retry` interval precedence over
                            // NeverRetry. Strip that control field only for the bounded probe
                            // so a peer cannot force a reconnect after its initial GET closes.
                            event.retry = None;
                            event
                        })
                    })
                    .boxed()
            } else {
                event_stream.boxed()
            };
            Ok(event_stream)
        }
        .await;
        if let Some(control) = self.protocol_probe_control.as_ref() {
            if let Err(error) = &result {
                control.observe_streamable_error(error);
            }
            control.complete_common_get();
        }
        result
    }

    async fn delete_session(
        &self,
        uri: Arc<str>,
        session: Arc<str>,
        auth_token: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<(), StreamableHttpError<Self::Error>> {
        let result = async {
            let mut request_builder = self.inner.delete(uri.as_ref());
            if !self.managed_connection {
                if let Some(auth_header) = auth_token {
                    request_builder = request_builder.bearer_auth(auth_header);
                }
            }
            request_builder = request_builder.header(HEADER_SESSION_ID, session.as_ref());
            request_builder = apply_mcp_custom_headers(
                request_builder,
                custom_headers,
                self.credential_header_name.as_ref(),
                self.managed_connection,
            )?;
            request_builder = self.apply_connection_credential(request_builder)?;
            let (response, _deadline) = self.send_request(request_builder).await?;
            let response = self.reject_connection_authentication(response).await?;

            if response.status() == StatusCode::METHOD_NOT_ALLOWED {
                tracing::debug!("upstream MCP server does not support deleting sessions");
                return Ok(());
            }
            let _response = response.error_for_status().map_err(mcp_http_error)?;
            Ok(())
        }
        .await;
        if let (Some(control), Err(error)) = (self.protocol_probe_control.as_ref(), &result) {
            control.observe_streamable_error(error);
        }
        result
    }

    async fn post_message(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_token: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        let result = async {
            let mut request = self
                .inner
                .post(uri.as_ref())
                .header(ACCEPT, [EVENT_STREAM_MIME, JSON_MIME].join(", "));
            if !self.managed_connection {
                if let Some(auth_header) = auth_token {
                    request = request.bearer_auth(auth_header);
                }
            }

            let custom_content_type = custom_headers
                .keys()
                .any(|name| name.as_str().eq_ignore_ascii_case(CONTENT_TYPE.as_str()));
            request = apply_mcp_custom_headers(
                request,
                custom_headers,
                self.credential_header_name.as_ref(),
                self.managed_connection,
            )?;
            let session_was_attached = session_id.is_some();
            if let Some(session_id) = session_id {
                request = request.header(HEADER_SESSION_ID, session_id.as_ref());
            }
            let body = serialize_mcp_request_body(&message)?;
            enforce_mcp_request_body_size(body.len(), self.max_request_body_bytes)?;
            if !custom_content_type {
                request = request.header(CONTENT_TYPE, JSON_MIME);
            }
            request = self.apply_connection_credential(request)?;
            let (response, deadline) = self.send_request(request.body(body)).await?;
            let response = self.reject_connection_authentication(response).await?;
            if response.status() == StatusCode::UNAUTHORIZED
                && response.headers().contains_key(WWW_AUTHENTICATE)
            {
                return Err(StreamableHttpError::AuthRequired(AuthRequiredError::new(
                    REDACTED_MCP_UPSTREAM_VALUE.to_owned(),
                )));
            }
            if response.status() == StatusCode::FORBIDDEN
                && response.headers().contains_key(WWW_AUTHENTICATE)
            {
                return Err(StreamableHttpError::InsufficientScope(
                    InsufficientScopeError::new(REDACTED_MCP_UPSTREAM_VALUE.to_owned(), None),
                ));
            }

            let status = response.status();
            if matches!(status, StatusCode::ACCEPTED | StatusCode::NO_CONTENT) {
                return Ok(StreamableHttpPostResponse::Accepted);
            }
            if status == StatusCode::NOT_FOUND && session_was_attached {
                return Err(StreamableHttpError::SessionExpired);
            }

            let content_type = response
                .headers()
                .get(CONTENT_TYPE)
                .map(|ct| String::from_utf8_lossy(ct.as_bytes()).to_string());
            let content_length = response.content_length();
            let response_session_id = response
                .headers()
                .get(HEADER_SESSION_ID)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            if !session_was_attached && response_session_id.is_some() {
                if let Some(control) = self.protocol_probe_control.as_ref() {
                    control.expect_common_get();
                }
            }

            if status.is_success()
                && content_length == Some(0)
                && matches!(
                    message,
                    ClientJsonRpcMessage::Notification(_)
                        | ClientJsonRpcMessage::Response(_)
                        | ClientJsonRpcMessage::Error(_)
                )
            {
                return Ok(StreamableHttpPostResponse::Accepted);
            }

            if !status.is_success() {
                match read_limited_mcp_response_body(
                    response,
                    self.max_response_bytes,
                    self.discovery_response_budget.clone(),
                    deadline,
                    self.response_idle_timeout,
                    self.protocol_probe_control.clone(),
                )
                .await
                {
                    Ok(_) => {}
                    Err(error) if mcp_streamable_error_response_too_large(&error).is_some() => {
                        return Err(error);
                    }
                    Err(_) => {}
                }
                return Err(redacted_mcp_status_error(status));
            }

            match content_type.as_deref() {
                Some(ct) if ct.as_bytes().starts_with(EVENT_STREAM_MIME.as_bytes()) => {
                    enforce_mcp_response_content_length(&response, self.max_response_bytes)?;
                    let event_stream = SseStream::from_byte_stream(limited_mcp_response_stream(
                        response,
                        self.max_response_bytes,
                        self.discovery_response_budget.clone(),
                        deadline,
                        self.response_idle_timeout,
                        self.protocol_probe_control.clone(),
                    ))
                    .boxed();
                    Ok(StreamableHttpPostResponse::Sse(
                        event_stream,
                        response_session_id,
                    ))
                }
                Some(ct) if ct.as_bytes().starts_with(JSON_MIME.as_bytes()) => {
                    match read_limited_mcp_response_json::<ServerJsonRpcMessage>(
                        response,
                        self.max_response_bytes,
                        self.discovery_response_budget.clone(),
                        deadline,
                        self.response_idle_timeout,
                        self.protocol_probe_control.clone(),
                    )
                    .await
                    {
                        Ok(message) => Ok(StreamableHttpPostResponse::Json(
                            message,
                            response_session_id,
                        )),
                        Err(error) if mcp_streamable_error_response_too_large(&error).is_some() => {
                            Err(error)
                        }
                        Err(_) => {
                            tracing::warn!(
                                "could not parse MCP JSON response; treating as accepted"
                            );
                            Ok(StreamableHttpPostResponse::Accepted)
                        }
                    }
                }
                _ => {
                    tracing::error!(
                        content_type_present = content_type.is_some(),
                        "unexpected MCP upstream content type"
                    );
                    Err(redacted_mcp_content_type_error(content_type.is_some()))
                }
            }
        }
        .await;
        if let (Some(control), Err(error)) = (self.protocol_probe_control.as_ref(), &result) {
            control.observe_streamable_error(error);
        }
        result
    }
}

type LimitedMcpByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, LimitedMcpHttpError>> + Send>>;

fn limited_mcp_response_stream(
    response: rmcp_http::Response,
    max_response_bytes: usize,
    discovery_response_budget: Option<DiscoveryResponseByteBudget>,
    deadline: Option<tokio::time::Instant>,
    response_idle_timeout: Option<Duration>,
    protocol_probe_control: Option<ProtocolProbeTransportControl>,
) -> LimitedMcpByteStream {
    let body = Box::pin(response.bytes_stream());
    limited_mcp_body_stream_with_timeouts(
        body,
        max_response_bytes,
        discovery_response_budget,
        deadline,
        response_idle_timeout,
        protocol_probe_control,
    )
}

#[cfg(test)]
fn limited_mcp_body_stream(
    body: Pin<Box<dyn Stream<Item = Result<Bytes, rmcp_http::Error>> + Send>>,
    max_response_bytes: usize,
    discovery_response_budget: Option<DiscoveryResponseByteBudget>,
) -> LimitedMcpByteStream {
    limited_mcp_body_stream_with_timeouts(
        body,
        max_response_bytes,
        discovery_response_budget,
        None,
        None,
        None,
    )
}

fn limited_mcp_body_stream_with_timeouts(
    body: Pin<Box<dyn Stream<Item = Result<Bytes, rmcp_http::Error>> + Send>>,
    max_response_bytes: usize,
    discovery_response_budget: Option<DiscoveryResponseByteBudget>,
    deadline: Option<tokio::time::Instant>,
    response_idle_timeout: Option<Duration>,
    protocol_probe_control: Option<ProtocolProbeTransportControl>,
) -> LimitedMcpByteStream {
    Box::pin(stream::unfold(
        (
            body,
            0usize,
            false,
            discovery_response_budget,
            deadline,
            response_idle_timeout,
            protocol_probe_control,
        ),
        move |state| async move {
            let (
                mut body,
                mut streamed_bytes,
                done,
                discovery_response_budget,
                deadline,
                response_idle_timeout,
                protocol_probe_control,
            ) = state;
            if done {
                return None;
            }

            let next = match next_mcp_body_chunk(
                &mut body,
                deadline,
                response_idle_timeout,
                protocol_probe_control.as_ref(),
            )
            .await
            {
                Ok(next) => next,
                Err(error) => {
                    if let Some(control) = protocol_probe_control.as_ref() {
                        control.record_limited_error(&error);
                    }
                    return Some((
                        Err(error),
                        (
                            body,
                            streamed_bytes,
                            true,
                            discovery_response_budget,
                            deadline,
                            response_idle_timeout,
                            protocol_probe_control,
                        ),
                    ));
                }
            };

            match next {
                Some(Ok(chunk)) => {
                    if streamed_bytes.saturating_add(chunk.len()) > max_response_bytes {
                        tracing::warn!(
                            max = max_response_bytes,
                            "egress blocked oversized MCP upstream response"
                        );
                        let error = LimitedMcpHttpError::ResponseTooLarge {
                            max: max_response_bytes,
                        };
                        if let Some(control) = protocol_probe_control.as_ref() {
                            control.record_limited_error(&error);
                        }
                        return Some((
                            Err(error),
                            (
                                body,
                                streamed_bytes,
                                true,
                                discovery_response_budget,
                                deadline,
                                response_idle_timeout,
                                protocol_probe_control,
                            ),
                        ));
                    }

                    if let Some(budget) = discovery_response_budget.as_ref() {
                        if let Err(error) = budget.charge(chunk.len()) {
                            tracing::warn!(
                                max = budget.maximum,
                                "MCP discovery exceeded aggregate raw response byte limit"
                            );
                            if let Some(control) = protocol_probe_control.as_ref() {
                                control.record_limited_error(&error);
                            }
                            return Some((
                                Err(error),
                                (
                                    body,
                                    streamed_bytes,
                                    true,
                                    discovery_response_budget,
                                    deadline,
                                    response_idle_timeout,
                                    protocol_probe_control,
                                ),
                            ));
                        }
                    }
                    streamed_bytes += chunk.len();
                    Some((
                        Ok(chunk),
                        (
                            body,
                            streamed_bytes,
                            false,
                            discovery_response_budget,
                            deadline,
                            response_idle_timeout,
                            protocol_probe_control,
                        ),
                    ))
                }
                Some(Err(error)) => {
                    let error = LimitedMcpHttpError::from(error);
                    if let Some(control) = protocol_probe_control.as_ref() {
                        control.record_limited_error(&error);
                    }
                    Some((
                        Err(error),
                        (
                            body,
                            streamed_bytes,
                            true,
                            discovery_response_budget,
                            deadline,
                            response_idle_timeout,
                            protocol_probe_control,
                        ),
                    ))
                }
                None => None,
            }
        },
    ))
}

async fn next_mcp_body_chunk(
    body: &mut Pin<Box<dyn Stream<Item = Result<Bytes, rmcp_http::Error>> + Send>>,
    deadline: Option<tokio::time::Instant>,
    response_idle_timeout: Option<Duration>,
    protocol_probe_control: Option<&ProtocolProbeTransportControl>,
) -> Result<Option<Result<Bytes, rmcp_http::Error>>, LimitedMcpHttpError> {
    let idle_deadline = response_idle_timeout.map(|timeout| tokio::time::Instant::now() + timeout);
    let wait_deadline = match (deadline, idle_deadline) {
        (Some(deadline), Some(idle_deadline)) => Some(deadline.min(idle_deadline)),
        (Some(deadline), None) => Some(deadline),
        (None, Some(idle_deadline)) => Some(idle_deadline),
        (None, None) => None,
    };
    match (wait_deadline, protocol_probe_control) {
        (Some(wait_deadline), Some(control)) => {
            let _io_guard = control.begin_io();
            tokio::select! {
                biased;
                _ = control.cancellation().cancelled() => {
                    Err(LimitedMcpHttpError::Http("http_timeout"))
                }
                result = tokio::time::timeout_at(wait_deadline, body.next()) => {
                    result.map_err(|_| LimitedMcpHttpError::Http("http_timeout"))
                }
            }
        }
        (Some(wait_deadline), None) => tokio::time::timeout_at(wait_deadline, body.next())
            .await
            .map_err(|_| LimitedMcpHttpError::Http("http_timeout")),
        (None, Some(control)) => {
            let _io_guard = control.begin_io();
            tokio::select! {
                biased;
                _ = control.cancellation().cancelled() => {
                    Err(LimitedMcpHttpError::Http("http_timeout"))
                }
                result = body.next() => Ok(result),
            }
        }
        (None, None) => Ok(body.next().await),
    }
}

async fn read_limited_mcp_response_body(
    response: rmcp_http::Response,
    max_response_bytes: usize,
    discovery_response_budget: Option<DiscoveryResponseByteBudget>,
    deadline: Option<tokio::time::Instant>,
    response_idle_timeout: Option<Duration>,
    protocol_probe_control: Option<ProtocolProbeTransportControl>,
) -> Result<Bytes, StreamableHttpError<LimitedMcpHttpError>> {
    enforce_mcp_response_content_length(&response, max_response_bytes)?;
    let mut stream = limited_mcp_response_stream(
        response,
        max_response_bytes,
        discovery_response_budget,
        deadline,
        response_idle_timeout,
        protocol_probe_control,
    );
    let mut body = Vec::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(StreamableHttpError::Client)?;
        body.extend_from_slice(&chunk);
    }

    Ok(Bytes::from(body))
}

async fn read_limited_mcp_response_json<T: serde::de::DeserializeOwned>(
    response: rmcp_http::Response,
    max_response_bytes: usize,
    discovery_response_budget: Option<DiscoveryResponseByteBudget>,
    deadline: Option<tokio::time::Instant>,
    response_idle_timeout: Option<Duration>,
    protocol_probe_control: Option<ProtocolProbeTransportControl>,
) -> Result<T, StreamableHttpError<LimitedMcpHttpError>> {
    let body = read_limited_mcp_response_body(
        response,
        max_response_bytes,
        discovery_response_budget,
        deadline,
        response_idle_timeout,
        protocol_probe_control,
    )
    .await?;
    serde_json::from_slice(&body).map_err(StreamableHttpError::Deserialize)
}

fn serialize_mcp_request_body(
    message: &ClientJsonRpcMessage,
) -> Result<Vec<u8>, StreamableHttpError<LimitedMcpHttpError>> {
    serde_json::to_vec(message)
        .map_err(|error| StreamableHttpError::Client(LimitedMcpHttpError::Serialize(error)))
}

fn enforce_mcp_request_body_size(
    size: usize,
    max_request_body_bytes: usize,
) -> Result<(), StreamableHttpError<LimitedMcpHttpError>> {
    if size > max_request_body_bytes {
        tracing::warn!(
            size,
            max = max_request_body_bytes,
            "egress blocked oversized request body"
        );
        return Err(StreamableHttpError::Client(
            LimitedMcpHttpError::RequestBodyTooLarge {
                size,
                max: max_request_body_bytes,
            },
        ));
    }

    Ok(())
}

fn enforce_mcp_response_content_length(
    response: &rmcp_http::Response,
    max_response_bytes: usize,
) -> Result<(), StreamableHttpError<LimitedMcpHttpError>> {
    let max_response_bytes_u64 = u64::try_from(max_response_bytes).unwrap_or(u64::MAX);
    if response
        .content_length()
        .is_some_and(|length| length > max_response_bytes_u64)
    {
        tracing::warn!(
            max = max_response_bytes,
            "egress blocked oversized MCP upstream response"
        );
        return Err(StreamableHttpError::Client(
            LimitedMcpHttpError::ResponseTooLarge {
                max: max_response_bytes,
            },
        ));
    }

    Ok(())
}

fn validate_mcp_response_content_type(
    response: &rmcp_http::Response,
) -> Result<(), StreamableHttpError<LimitedMcpHttpError>> {
    match response.headers().get(CONTENT_TYPE) {
        Some(content_type) => {
            if !content_type
                .as_bytes()
                .starts_with(EVENT_STREAM_MIME.as_bytes())
                && !content_type.as_bytes().starts_with(JSON_MIME.as_bytes())
            {
                return Err(redacted_mcp_content_type_error(true));
            }
        }
        None => return Err(redacted_mcp_content_type_error(false)),
    }

    Ok(())
}

fn apply_mcp_custom_headers(
    mut builder: rmcp_http::RequestBuilder,
    custom_headers: HashMap<HeaderName, HeaderValue>,
    credential_header_name: Option<&HeaderName>,
    managed_connection: bool,
) -> Result<rmcp_http::RequestBuilder, StreamableHttpError<LimitedMcpHttpError>> {
    for (name, value) in custom_headers {
        validate_mcp_custom_header(&name, credential_header_name, managed_connection)
            .map_err(StreamableHttpError::ReservedHeaderConflict)?;
        builder = builder.header(name, value);
    }

    Ok(builder)
}

fn validate_mcp_custom_header(
    name: &HeaderName,
    credential_header_name: Option<&HeaderName>,
    managed_connection: bool,
) -> Result<(), String> {
    let is_reserved = name.as_str().eq_ignore_ascii_case("accept")
        || name.as_str().eq_ignore_ascii_case(HEADER_SESSION_ID)
        || name.as_str().eq_ignore_ascii_case(HEADER_LAST_EVENT_ID)
        || (managed_connection
            && (name.as_str().eq_ignore_ascii_case("authorization")
                || name.as_str().eq_ignore_ascii_case("cookie")
                || name.as_str().eq_ignore_ascii_case("host")
                || name.as_str().eq_ignore_ascii_case("content-length")))
        || credential_header_name.is_some_and(|credential_header| credential_header == name);
    if is_reserved {
        return Err(name.to_string());
    }

    Ok(())
}

fn redacted_mcp_status_error(status: StatusCode) -> StreamableHttpError<LimitedMcpHttpError> {
    StreamableHttpError::UnexpectedServerResponse(Cow::Owned(format!(
        "HTTP {status}: upstream response details redacted"
    )))
}

fn redacted_mcp_content_type_error(
    content_type_present: bool,
) -> StreamableHttpError<LimitedMcpHttpError> {
    StreamableHttpError::UnexpectedContentType(
        content_type_present.then(|| REDACTED_MCP_UPSTREAM_VALUE.to_owned()),
    )
}

fn mcp_http_error(error: rmcp_http::Error) -> StreamableHttpError<LimitedMcpHttpError> {
    StreamableHttpError::Client(LimitedMcpHttpError::from(error))
}

fn mcp_timeout_error() -> StreamableHttpError<LimitedMcpHttpError> {
    StreamableHttpError::Client(LimitedMcpHttpError::Http("http_timeout"))
}

fn mcp_http_error_category(error: &rmcp_http::Error) -> &'static str {
    if error.is_timeout() {
        "http_timeout"
    } else if error.is_connect() {
        "http_connect"
    } else if error.is_request() {
        "http_request"
    } else if error.is_body() {
        "http_body"
    } else if error.is_decode() {
        "http_decode"
    } else if error.is_status() {
        "http_status"
    } else {
        "http_other"
    }
}

fn mcp_service_error<E>(error: E, fallback: McpUpstreamCallError) -> McpUpstreamCallError
where
    E: Error + 'static,
{
    if mcp_authentication_rejected(&error) {
        McpUpstreamCallError::AuthenticationRejected
    } else if let Some((size, max)) = mcp_request_body_too_large_size_max(&error) {
        McpUpstreamCallError::RequestBodyTooLarge { size, max }
    } else if let Some(max) = mcp_discovery_response_too_large_max(&error) {
        McpUpstreamCallError::DiscoveryResponseLimitExceeded { max }
    } else if let Some(max) = mcp_response_too_large_max(&error) {
        McpUpstreamCallError::ResponseTooLarge { max }
    } else {
        fallback
    }
}

fn mcp_authentication_rejected(error: &(dyn Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(ServiceError::TransportSend(error)) = error.downcast_ref::<ServiceError>() {
            if mcp_authentication_rejected(error.error.as_ref()) {
                return true;
            }
        }
        if let Some(ClientInitializeError::TransportError { error, .. }) =
            error.downcast_ref::<ClientInitializeError>()
        {
            if mcp_authentication_rejected(error.error.as_ref()) {
                return true;
            }
        }
        if let Some(error) = error.downcast_ref::<DynamicTransportError>() {
            if mcp_authentication_rejected(error.error.as_ref()) {
                return true;
            }
        }
        if matches!(
            error.downcast_ref::<LimitedMcpHttpError>(),
            Some(LimitedMcpHttpError::AuthenticationRejected)
        ) || matches!(
            error.downcast_ref::<StreamableHttpError<LimitedMcpHttpError>>(),
            Some(StreamableHttpError::Client(
                LimitedMcpHttpError::AuthenticationRejected
            ))
        ) {
            return true;
        }
        current = error.source();
    }
    false
}

fn mcp_streamable_error_response_too_large(
    error: &StreamableHttpError<LimitedMcpHttpError>,
) -> Option<usize> {
    mcp_response_too_large_max(error).or_else(|| mcp_discovery_response_too_large_max(error))
}

fn mcp_request_body_too_large_size_max(error: &(dyn Error + 'static)) -> Option<(usize, usize)> {
    let mut current = Some(error);

    while let Some(error) = current {
        if let Some(ServiceError::TransportSend(error)) = error.downcast_ref::<ServiceError>() {
            if let Some(size_max) = mcp_request_body_too_large_size_max(error.error.as_ref()) {
                return Some(size_max);
            }
        }
        if let Some(ClientInitializeError::TransportError { error, .. }) =
            error.downcast_ref::<ClientInitializeError>()
        {
            if let Some(size_max) = mcp_request_body_too_large_size_max(error.error.as_ref()) {
                return Some(size_max);
            }
        }
        if let Some(error) = error.downcast_ref::<DynamicTransportError>() {
            if let Some(size_max) = mcp_request_body_too_large_size_max(error.error.as_ref()) {
                return Some(size_max);
            }
        }
        if let Some(LimitedMcpHttpError::RequestBodyTooLarge { size, max }) =
            error.downcast_ref::<LimitedMcpHttpError>()
        {
            return Some((*size, *max));
        }
        if let Some(StreamableHttpError::Client(LimitedMcpHttpError::RequestBodyTooLarge {
            size,
            max,
        })) = error.downcast_ref::<StreamableHttpError<LimitedMcpHttpError>>()
        {
            return Some((*size, *max));
        }

        current = error.source();
    }

    None
}

fn mcp_response_too_large_max(error: &(dyn Error + 'static)) -> Option<usize> {
    let mut current = Some(error);

    while let Some(error) = current {
        if let Some(ServiceError::TransportSend(error)) = error.downcast_ref::<ServiceError>() {
            if let Some(max) = mcp_response_too_large_max(error.error.as_ref()) {
                return Some(max);
            }
        }
        if let Some(ClientInitializeError::TransportError { error, .. }) =
            error.downcast_ref::<ClientInitializeError>()
        {
            if let Some(max) = mcp_response_too_large_max(error.error.as_ref()) {
                return Some(max);
            }
        }
        if let Some(error) = error.downcast_ref::<DynamicTransportError>() {
            if let Some(max) = mcp_response_too_large_max(error.error.as_ref()) {
                return Some(max);
            }
        }
        if let Some(LimitedMcpHttpError::ResponseTooLarge { max }) =
            error.downcast_ref::<LimitedMcpHttpError>()
        {
            return Some(*max);
        }
        if let Some(StreamableHttpError::Client(LimitedMcpHttpError::ResponseTooLarge { max })) =
            error.downcast_ref::<StreamableHttpError<LimitedMcpHttpError>>()
        {
            return Some(*max);
        }

        current = error.source();
    }

    None
}

fn mcp_discovery_response_too_large_max(error: &(dyn Error + 'static)) -> Option<usize> {
    let mut current = Some(error);

    while let Some(error) = current {
        if let Some(ServiceError::TransportSend(error)) = error.downcast_ref::<ServiceError>() {
            if let Some(max) = mcp_discovery_response_too_large_max(error.error.as_ref()) {
                return Some(max);
            }
        }
        if let Some(ClientInitializeError::TransportError { error, .. }) =
            error.downcast_ref::<ClientInitializeError>()
        {
            if let Some(max) = mcp_discovery_response_too_large_max(error.error.as_ref()) {
                return Some(max);
            }
        }
        if let Some(error) = error.downcast_ref::<DynamicTransportError>() {
            if let Some(max) = mcp_discovery_response_too_large_max(error.error.as_ref()) {
                return Some(max);
            }
        }
        if let Some(LimitedMcpHttpError::DiscoveryResponseTooLarge { max }) =
            error.downcast_ref::<LimitedMcpHttpError>()
        {
            return Some(*max);
        }
        if let Some(StreamableHttpError::Client(LimitedMcpHttpError::DiscoveryResponseTooLarge {
            max,
        })) = error.downcast_ref::<StreamableHttpError<LimitedMcpHttpError>>()
        {
            return Some(*max);
        }

        current = error.source();
    }

    None
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

fn connection_proxy_definition(connection_id: &str, tool: Tool) -> ToolDefinition {
    let remote_tool_name = tool.name.to_string();
    let description = tool
        .description
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_else(|| remote_tool_name.clone());
    ToolDefinition::mcp_connection(
        connection_id.to_owned(),
        description,
        Value::Object(tool.input_schema.as_ref().clone()),
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::connections::test::connection_failure_classification;

    use std::{
        collections::HashSet,
        io::{self, ErrorKind},
        net::{IpAddr, Ipv4Addr, SocketAddr},
        process::Command,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    use rmcp::{
        model::{
            ListResourcesResult, ListToolsResult, ReadResourceRequestParams, ReadResourceResult,
            ServerCapabilities, ServerInfo,
        },
        service::RequestContext,
        ErrorData, RoleServer, ServerHandler, ServiceExt,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };
    use tracing_subscriber::{fmt::MakeWriter, prelude::*};

    const TEST_RESPONSE_LIMIT: usize = 64;

    #[test]
    fn http_and_mcp_oauth_mint_failures_share_unavailable_dependency_classification() {
        for (error, expected_reason) in [
            (
                ConnectionHttpError::OAuthTokenRejected,
                ConnectionTestReason::OauthTokenRejected,
            ),
            (
                ConnectionHttpError::OAuthTokenInvalidResponse,
                ConnectionTestReason::OauthTokenInvalidResponse,
            ),
        ] {
            let (http_stage, http_state, http_status_reason) =
                connection_failure_classification(error);
            let mcp =
                protocol_probe_connection_error(error, ConnectionTestStageName::ProtocolValid);

            assert_eq!(http_stage, ConnectionTestStageName::SecretAvailable);
            assert_eq!(http_state, ConnectionOperationalState::Unavailable);
            assert_eq!(
                mcp.operational_state(),
                ConnectionOperationalState::Unavailable
            );
            assert_eq!(
                (http_stage, http_status_reason),
                (mcp.stage(), mcp.status_reason())
            );
            assert_eq!(mcp.safe_reason(), expected_reason);
        }
    }

    #[derive(Default)]
    struct ProbeRequestCounts {
        list_tools: AtomicUsize,
        list_resources: AtomicUsize,
        call_tool: AtomicUsize,
        read_resource: AtomicUsize,
    }

    #[derive(Clone)]
    struct PaginatedProbeServer {
        counts: Arc<ProbeRequestCounts>,
    }

    impl ServerHandler for PaginatedProbeServer {
        fn get_info(&self) -> ServerInfo {
            ServerInfo::new(
                ServerCapabilities::builder()
                    .enable_tools()
                    .enable_resources()
                    .build(),
            )
        }

        async fn list_tools(
            &self,
            _request: Option<PaginatedRequestParams>,
            _context: RequestContext<RoleServer>,
        ) -> Result<ListToolsResult, ErrorData> {
            self.counts.list_tools.fetch_add(1, Ordering::SeqCst);
            Ok(ListToolsResult {
                next_cursor: Some("second-page-must-not-be-read".to_owned()),
                ..ListToolsResult::default()
            })
        }

        async fn list_resources(
            &self,
            _request: Option<PaginatedRequestParams>,
            _context: RequestContext<RoleServer>,
        ) -> Result<ListResourcesResult, ErrorData> {
            self.counts.list_resources.fetch_add(1, Ordering::SeqCst);
            Ok(ListResourcesResult {
                next_cursor: Some("resource-page-must-not-be-read".to_owned()),
                ..ListResourcesResult::default()
            })
        }

        async fn call_tool(
            &self,
            _request: CallToolRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<CallToolResult, ErrorData> {
            self.counts.call_tool.fetch_add(1, Ordering::SeqCst);
            Ok(CallToolResult::default())
        }

        async fn read_resource(
            &self,
            _request: ReadResourceRequestParams,
            _context: RequestContext<RoleServer>,
        ) -> Result<ReadResourceResult, ErrorData> {
            self.counts.read_resource.fetch_add(1, Ordering::SeqCst);
            Ok(ReadResourceResult::new(Vec::new()))
        }
    }

    #[tokio::test]
    async fn protocol_probe_reads_exactly_one_advertised_tool_page() {
        let counts = Arc::new(ProbeRequestCounts::default());
        let server = PaginatedProbeServer {
            counts: Arc::clone(&counts),
        };
        let (server_transport, client_transport) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let server = server
                .serve(server_transport)
                .await
                .expect("probe test server should initialize");
            server
                .waiting()
                .await
                .expect("probe test server should close cleanly");
        });
        let mut client =
            ().serve(client_transport)
                .await
                .expect("probe test client should initialize");

        probe_one_advertised_metadata_page(&mut client)
            .await
            .expect("one advertised metadata page should validate");
        let close = client
            .close_with_timeout(Duration::from_secs(1))
            .await
            .expect("probe test client close should join");
        assert!(discovery_shutdown_completed_cleanly::<()>(&Ok(close)));
        server_task
            .await
            .expect("probe test server task should join");

        assert_eq!(counts.list_tools.load(Ordering::SeqCst), 1);
        assert_eq!(counts.list_resources.load(Ordering::SeqCst), 0);
        assert_eq!(counts.call_tool.load(Ordering::SeqCst), 0);
        assert_eq!(counts.read_resource.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn protocol_probe_does_not_retry_list_after_session_404() {
        let upstream =
            RawProtocolProbeUpstream::spawn(RawProtocolProbeScenario::ListSessionExpired).await;

        let error = run_raw_protocol_probe(&upstream.url, Duration::from_secs(2))
            .await
            .expect_err("session-expired inventory response must fail the bounded probe");
        assert_eq!(error.safe_reason(), ConnectionTestReason::ProtocolError);
        assert_eq!(upstream.counts.initialize.load(Ordering::SeqCst), 1);
        assert_eq!(upstream.counts.list_tools.load(Ordering::SeqCst), 1);

        upstream.join().await;
    }

    #[tokio::test]
    async fn protocol_probe_refuses_server_requested_sse_reconnect() {
        let upstream =
            RawProtocolProbeUpstream::spawn(RawProtocolProbeScenario::ImmediateSseRetry).await;

        run_raw_protocol_probe(&upstream.url, Duration::from_secs(2))
            .await
            .expect("one inventory page should succeed without reconnecting SSE");
        tokio::time::sleep(Duration::from_millis(75)).await;
        assert_eq!(
            upstream.counts.get_stream.load(Ordering::SeqCst),
            1,
            "probe-specific NeverRetry must refuse the server's retry: 0 reconnect"
        );

        upstream.join().await;
    }

    #[tokio::test]
    async fn protocol_probe_cancels_stalled_initialize_and_list_without_live_io() {
        for scenario in [
            RawProtocolProbeScenario::StallInitialize,
            RawProtocolProbeScenario::StallList,
        ] {
            let upstream = RawProtocolProbeUpstream::spawn(scenario).await;
            let started = Instant::now();
            let error = run_raw_protocol_probe(&upstream.url, Duration::from_millis(150))
                .await
                .expect_err("stalled probe I/O must hit the shared absolute deadline");

            assert_eq!(error.safe_reason(), ConnectionTestReason::DeadlineExceeded);
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "probe worker must be aborted and joined within its hard deadline"
            );
            tokio::time::timeout(
                Duration::from_secs(1),
                upstream.stalled_disconnect.notified(),
            )
            .await
            .expect("the timed-out credential-bearing HTTP request must be dropped");
            let requests_after_return = upstream.counts.total();
            tokio::time::sleep(Duration::from_millis(75)).await;
            assert_eq!(
                upstream.counts.total(),
                requests_after_return,
                "no RMCP HTTP request may survive or start after probe return"
            );

            upstream.join().await;
        }
    }

    #[tokio::test]
    async fn protocol_probe_consumes_prior_endpoint_time_and_finishes_io_before_return() {
        let upstream =
            RawProtocolProbeUpstream::spawn(RawProtocolProbeScenario::StallInitialize).await;
        let endpoint_started = tokio::time::Instant::now();
        let endpoint_deadline = endpoint_started + Duration::from_millis(900);
        tokio::time::sleep(Duration::from_millis(200)).await;

        let error = run_raw_protocol_probe_before(&upstream.url, endpoint_deadline)
            .await
            .expect_err("remaining endpoint budget must bound the delayed MCP probe");
        assert_eq!(error.safe_reason(), ConnectionTestReason::DeadlineExceeded);
        assert!(
            tokio::time::Instant::now() < endpoint_deadline,
            "cleanup reserve should join the timed-out worker before the endpoint deadline"
        );
        tokio::time::timeout(
            Duration::from_secs(1),
            upstream.stalled_disconnect.notified(),
        )
        .await
        .expect("the stalled initialize request must be closed before probe return");
        assert_eq!(upstream.counts.initialize.load(Ordering::SeqCst), 1);
        let requests_after_return = upstream.counts.total();
        tokio::time::sleep_until(endpoint_deadline + Duration::from_millis(75)).await;
        assert_eq!(
            upstream.counts.total(),
            requests_after_return,
            "no request or credential-bearing I/O may survive the shared endpoint deadline"
        );

        upstream.join().await;
    }

    #[tokio::test]
    async fn protocol_probe_fails_get_delete_auth_and_allows_method_not_allowed() {
        for scenario in [
            RawProtocolProbeScenario::GetUnauthorized,
            RawProtocolProbeScenario::GetForbidden,
            RawProtocolProbeScenario::DeleteUnauthorized,
            RawProtocolProbeScenario::DeleteForbidden,
        ] {
            let upstream = RawProtocolProbeUpstream::spawn(scenario).await;
            let error = run_raw_protocol_probe(&upstream.url, Duration::from_secs(2))
                .await
                .expect_err("background GET/DELETE authentication rejection must fail the probe");
            assert_eq!(error.stage(), ConnectionTestStageName::Authenticated);
            assert_eq!(
                error.safe_reason(),
                ConnectionTestReason::AuthenticationFailed
            );
            assert_eq!(
                error.operational_state(),
                ConnectionOperationalState::Degraded,
                "an actual upstream authentication rejection is degraded, not a missing dependency"
            );
            upstream.join().await;
        }

        let upstream =
            RawProtocolProbeUpstream::spawn(RawProtocolProbeScenario::MethodNotAllowed).await;
        run_raw_protocol_probe(&upstream.url, Duration::from_secs(2))
            .await
            .expect("protocol-defined GET and DELETE 405 responses must remain allowed");
        assert_eq!(upstream.counts.get_stream.load(Ordering::SeqCst), 1);
        assert_eq!(upstream.counts.delete_session.load(Ordering::SeqCst), 1);
        upstream.join().await;
    }

    #[test]
    fn managed_discovery_page_budget_is_shared_across_all_collections() {
        let mut budget = DiscoveryPageBudget::new();

        for _ in 0..10 {
            budget.consume().expect("tool page should fit");
        }
        for _ in 0..10 {
            budget.consume().expect("resource page should fit");
        }
        for _ in 0..12 {
            budget.consume().expect("resource-template page should fit");
        }

        assert!(matches!(
            budget.consume(),
            Err(McpUpstreamCallError::DiscoveryPageLimitExceeded {
                max: MAX_DISCOVERY_PAGES_PER_UPSTREAM
            })
        ));
    }

    #[tokio::test]
    async fn discovery_raw_response_budget_counts_unknown_json_and_sse_across_responses() {
        let unknown_json = Bytes::from(format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"tools":[],"unknown":"{}"}}}}"#,
            "x".repeat(48)
        ));
        let unknown_sse = Bytes::from(format!(
            "event: message\ndata: {{\"unknown\":\"{}\"}}\n\n",
            "y".repeat(48)
        ));
        let maximum = unknown_json
            .len()
            .saturating_add(unknown_sse.len())
            .saturating_sub(1);
        let budget = DiscoveryResponseByteBudget::new(maximum);

        let first_body = stream::iter([Ok::<_, rmcp_http::Error>(unknown_json.clone())]);
        let mut first =
            limited_mcp_body_stream(Box::pin(first_body), usize::MAX, Some(budget.clone()));
        assert_eq!(
            first
                .next()
                .await
                .expect("JSON response should yield")
                .expect("first raw response should fit"),
            unknown_json
        );
        assert!(first.next().await.is_none());

        let second_body = stream::iter([Ok::<_, rmcp_http::Error>(unknown_sse)]);
        let mut second = limited_mcp_body_stream(Box::pin(second_body), usize::MAX, Some(budget));
        let error = second
            .next()
            .await
            .expect("SSE response should yield a bounded error")
            .expect_err("raw bytes across responses must share one budget");
        assert!(matches!(
            mcp_service_error(error, McpUpstreamCallError::Call),
            McpUpstreamCallError::DiscoveryResponseLimitExceeded { max }
                if max == maximum
        ));
    }

    #[tokio::test]
    async fn managed_transport_adapter_enforces_total_and_idle_response_deadlines() {
        for (deadline, response_idle_timeout) in [
            (
                Some(tokio::time::Instant::now() + Duration::from_millis(25)),
                None,
            ),
            (None, Some(Duration::from_millis(25))),
        ] {
            let mut body: Pin<Box<dyn Stream<Item = Result<Bytes, rmcp_http::Error>> + Send>> =
                Box::pin(stream::pending());
            let started = Instant::now();
            let error = next_mcp_body_chunk(&mut body, deadline, response_idle_timeout, None)
                .await
                .expect_err("a silent managed MCP response must time out");

            assert!(matches!(error, LimitedMcpHttpError::Http("http_timeout")));
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "managed MCP response deadline must remain bounded"
            );
        }
    }

    #[test]
    fn discovery_raw_response_budget_exceeded_state_is_shared_and_sticky() {
        let budget = DiscoveryResponseByteBudget::new(8);
        let shared = budget.clone();

        budget
            .charge(8)
            .expect("bytes at the discovery response limit should fit");
        assert!(matches!(
            shared.charge(1),
            Err(LimitedMcpHttpError::DiscoveryResponseTooLarge { max: 8 })
        ));
        assert!(matches!(
            budget.charge(0),
            Err(LimitedMcpHttpError::DiscoveryResponseTooLarge { max: 8 })
        ));
        assert!(matches!(
            shared.seal(),
            Err(McpUpstreamCallError::DiscoveryResponseLimitExceeded { max: 8 })
        ));
    }

    #[tokio::test]
    async fn discovery_shutdown_gate_rejects_join_failures_and_incomplete_close() {
        assert!(discovery_shutdown_completed_cleanly::<()>(&Ok(Some(
            QuitReason::Cancelled,
        ))));
        assert!(discovery_shutdown_completed_cleanly::<()>(&Ok(Some(
            QuitReason::Closed,
        ))));
        assert!(!discovery_shutdown_completed_cleanly::<()>(&Ok(None)));
        assert!(!discovery_shutdown_completed_cleanly::<()>(&Err(())));

        let handle = tokio::spawn(std::future::pending::<()>());
        handle.abort();
        let join_error = handle
            .await
            .expect_err("aborted task should produce a join error");
        assert!(!discovery_shutdown_completed_cleanly::<()>(&Ok(Some(
            QuitReason::JoinError(join_error),
        ))));
    }

    struct CountingDnsResolver {
        calls: AtomicUsize,
        address: IpAddr,
    }

    #[async_trait::async_trait]
    impl crate::egress::DnsResolver for CountingDnsResolver {
        async fn resolve(&self, _host: &str, port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![SocketAddr::new(self.address, port)])
        }
    }

    #[test]
    fn discovery_egress_error_keeps_only_the_safe_category() {
        let secret_host = "secret-discovery-host.example.test";
        let error = mcp_discovery_egress_error(
            "configured-upstream".to_owned(),
            EgressError::HostNotAllowed(secret_host.to_owned()),
        );
        let output = format!("{error} {error:?}");

        assert!(output.contains("host_not_allowed"));
        assert!(!output.contains(secret_host));
        assert!(error.source().is_none());
    }

    #[test]
    fn production_filter_suppresses_rmcp_dependency_secrets() {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .without_time()
                    .with_writer(logs.clone()),
            )
            .with(crate::production_tracing_filter());
        let _guard = tracing::subscriber::set_default(subscriber);

        tracing::info!(target: "gateway::mcp_filter_test", "green-gateway-marker");
        tracing::error!(
            target: "rmcp::service",
            peer_info = "secret-server-instructions",
            "dependency peer metadata"
        );
        tracing::error!(
            target: "rmcp::transport::streamable_http_client",
            session_id = "secret-session-id",
            error = "https://secret-upstream.example/private?token=secret-query",
            "dependency transport failure"
        );
        drop(_guard);

        let output = logs.contents();
        assert!(output.contains("green-gateway-marker"));
        for secret in [
            "secret-server-instructions",
            "secret-session-id",
            "secret-upstream.example",
            "secret-query",
        ] {
            assert!(
                !output.contains(secret),
                "production tracing filter leaked rmcp value {secret}: {output}"
            );
        }
    }

    #[test]
    fn conservative_mcp_call_size_bounds_runtime_numeric_identifiers() {
        let arguments = serde_json::json!({
            "escaped": "quotes: \" and slash: \\",
            "nested": { "value": 42 }
        })
        .as_object()
        .expect("test arguments should be an object")
        .clone();
        let request =
            CallToolRequestParams::new("boundary_tool".to_owned()).with_arguments(arguments);
        let conservative = serialized_mcp_call_request_size(&request, i64::MIN, i64::MIN)
            .expect("conservative MCP request should serialize");

        for (request_id, progress_token) in [
            (i64::MIN, i64::MIN),
            (i64::MIN + 1, i64::MAX),
            (-1, 0),
            (0, -1),
            (i64::from(u32::MAX), i64::from(u32::MAX)),
            (i64::MAX, i64::MAX),
        ] {
            let actual = serialized_mcp_call_request_size(&request, request_id, progress_token)
                .expect("runtime-shaped MCP request should serialize");
            assert!(
                actual <= conservative,
                "runtime identifiers ({request_id}, {progress_token}) produced {actual} bytes, exceeding conservative {conservative}-byte preflight"
            );
        }

        enforce_mcp_call_request_size_before_egress(&request, conservative)
            .expect("request at the conservative bound should be accepted");
        assert!(matches!(
            enforce_mcp_call_request_size_before_egress(&request, conservative - 1),
            Err(McpUpstreamCallError::RequestBodyTooLarge { size, max })
                if size == conservative && max == conservative - 1
        ));
    }

    #[tokio::test]
    async fn oversized_call_tool_request_is_rejected_before_dns_or_connection() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("MCP connection sentinel should bind");
        let address = listener
            .local_addr()
            .expect("MCP connection sentinel address should be available");
        let host = "oversized-mcp.example.test";
        let upstream = McpUpstreamServerConfig {
            name: "oversized-request-test".to_owned(),
            url: format!("http://{host}:{}/mcp", address.port()),
            timeout_ms: Some(500),
            response_idle_timeout_ms: Some(500),
            connect_timeout_ms: Some(100),
        };
        let runtime = McpUpstreamRuntimeConfig {
            timeout: Duration::from_millis(500),
            response_idle_timeout: Duration::from_millis(500),
            connect_timeout: Duration::from_millis(100),
            max_request_body_bytes: 128,
            max_response_bytes: 1024,
        };
        let resolver = Arc::new(CountingDnsResolver {
            calls: AtomicUsize::new(0),
            address: address.ip(),
        });
        let resolver_for_client: Arc<dyn crate::egress::DnsResolver> = resolver.clone();
        let egress_client = Arc::new(
            EgressClient::new_with_resolver(
                crate::egress::EgressConfig {
                    allowed_hosts: HashSet::from([host.to_owned()]),
                    deny_private_ips: false,
                    ..crate::egress::EgressConfig::default()
                },
                resolver_for_client,
            )
            .expect("MCP egress client should build"),
        );

        let error = call_tool(
            &upstream,
            &runtime,
            egress_client,
            "oversized_tool",
            serde_json::json!({ "payload": "x".repeat(1024) }),
        )
        .await
        .expect_err("oversized MCP call should fail before destination work");

        assert!(matches!(
            error,
            McpUpstreamCallError::RequestBodyTooLarge { size, max: 128 } if size > 128
        ));
        assert_eq!(
            resolver.calls.load(Ordering::SeqCst),
            0,
            "oversized MCP call denial must not resolve DNS"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err(),
            "oversized MCP call denial must not open a connection"
        );
    }

    #[tokio::test]
    async fn mcp_client_sends_directly_with_proxy_discovery_disabled() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("direct MCP test listener should bind");
        let direct_addr = listener
            .local_addr()
            .expect("direct MCP test address should be available");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("direct MCP server should accept a request");
            let mut request = vec![0_u8; 1024];
            let _ = stream
                .read(&mut request)
                .await
                .expect("direct MCP server should read a request");
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndirect",
                )
                .await
                .expect("direct MCP server should write a response");
        });
        let host = "mcp-proxy-test.example";
        let upstream = McpUpstreamServerConfig {
            name: "proxy-test".to_owned(),
            url: format!("http://{host}:{}/", direct_addr.port()),
            timeout_ms: Some(2_000),
            response_idle_timeout_ms: Some(2_000),
            connect_timeout_ms: Some(500),
        };
        let runtime = McpUpstreamRuntimeConfig {
            timeout: Duration::from_secs(2),
            response_idle_timeout: Duration::from_secs(2),
            connect_timeout: Duration::from_millis(500),
            max_request_body_bytes: 1024,
            max_response_bytes: 1024,
        };
        let client = mcp_http_client(
            server_timeout(&upstream, &runtime),
            server_response_idle_timeout(&upstream, &runtime),
            server_connect_timeout(&upstream, &runtime),
            &CheckedEgressDestination::for_test(host, direct_addr),
        )
        .expect("MCP client should build");

        let body = client
            .get(&upstream.url)
            .send()
            .await
            .expect("ambient proxy must not intercept the MCP request")
            .text()
            .await
            .expect("direct MCP response should have a body");

        assert_eq!(body, "direct");
        server.await.expect("direct MCP server should finish");
    }

    #[tokio::test]
    async fn legacy_connect_keeps_rmcp_auth_required_behavior() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("legacy MCP auth listener should bind");
        let address = listener
            .local_addr()
            .expect("legacy MCP auth address should be available");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("legacy MCP auth server should accept initialization");
            let _request = read_raw_http_request_headers(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"legacy\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("legacy MCP auth challenge should write");
        });
        let upstream = McpUpstreamServerConfig {
            name: "legacy-auth".to_owned(),
            url: format!("http://{address}/mcp"),
            timeout_ms: Some(1_000),
            response_idle_timeout_ms: Some(1_000),
            connect_timeout_ms: Some(1_000),
        };
        let runtime = McpUpstreamRuntimeConfig {
            timeout: Duration::from_secs(1),
            response_idle_timeout: Duration::from_secs(1),
            connect_timeout: Duration::from_secs(1),
            max_request_body_bytes: 1_024,
            max_response_bytes: 1_024,
        };
        let destination =
            CheckedEgressDestination::for_test(Ipv4Addr::LOCALHOST.to_string(), address);

        let error = match connect(&upstream, &runtime, &destination).await {
            Ok(_) => panic!("legacy authentication challenge should stop initialization"),
            Err(error) => error,
        };
        assert!(
            matches!(error, McpUpstreamCallError::Connect),
            "legacy challenge handling must not be replaced by managed auth rejection: {error:?}"
        );
        server
            .await
            .expect("legacy MCP auth server should finish cleanly");
    }

    #[test]
    fn mcp_client_ignores_ambient_proxy_environment() {
        let proxy_listener = std::net::TcpListener::bind(("127.0.0.1", 0))
            .expect("ambient MCP proxy sentinel should bind");
        let proxy_addr = proxy_listener
            .local_addr()
            .expect("ambient MCP proxy address should be available");
        let proxy_url = format!("http://{proxy_addr}");
        let output = Command::new(std::env::current_exe().expect("test executable should exist"))
            .args([
                "--exact",
                "tools::mcp_upstream::tests::mcp_client_sends_directly_with_proxy_discovery_disabled",
                "--nocapture",
            ])
            .env("HTTP_PROXY", &proxy_url)
            .env("HTTPS_PROXY", &proxy_url)
            .env("ALL_PROXY", &proxy_url)
            .env("http_proxy", &proxy_url)
            .env("https_proxy", &proxy_url)
            .env("all_proxy", &proxy_url)
            .env("NO_PROXY", "")
            .env("no_proxy", "")
            .output()
            .expect("MCP proxy-isolation child test should start");

        assert!(
            output.status.success(),
            "MCP proxy-isolation child failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("running 1 test"),
            "MCP proxy-isolation child must execute exactly one helper test: {stdout}"
        );
        proxy_listener
            .set_nonblocking(true)
            .expect("MCP proxy sentinel should become nonblocking");
        assert!(
            matches!(proxy_listener.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock),
            "ambient MCP proxy sentinel must receive zero connections"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mcp_http_failures_expose_only_bounded_categories() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("timeout sentinel should bind");
        let address = listener
            .local_addr()
            .expect("timeout sentinel address should be available");
        let host = "secret-mcp.example.test";
        let inner = rmcp_http::Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(100))
            .read_timeout(Duration::from_millis(50))
            .connect_timeout(Duration::from_millis(50))
            .resolve(host, address)
            .build()
            .expect("limited MCP test client should build");
        let client = LimitedMcpHttpClient::new(inner, 1024, 1024);
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(logs.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let error = match client
            .get_stream(
                Arc::<str>::from(format!(
                    "http://{host}:{}/private?token=secret-query",
                    address.port()
                )),
                Arc::<str>::from("test-session"),
                None,
                None,
                HashMap::new(),
            )
            .await
        {
            Ok(_) => panic!("silent MCP upstream should time out"),
            Err(error) => error,
        };
        tracing::warn!(error = %error, "captured sanitized MCP transport failure");
        drop(_guard);
        drop(listener);

        let output = format!("{error} {}", logs.contents());
        let address_text = address.ip().to_string();
        assert!(output.contains("http_timeout"));
        for secret in [
            host,
            "private",
            "secret-query",
            address_text.as_str(),
            "http://",
        ] {
            assert!(
                !output.contains(secret),
                "MCP transport error leaked {secret}: {output}"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mcp_http_response_details_are_redacted() {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(logs.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let auth_error = post_message_against_raw_response(
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"secret-auth-challenge\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .as_bytes()
                .to_vec(),
        )
        .await
        .expect_err("401 MCP response should require authentication");
        let body = "secret-error-body";
        let status_error = post_message_against_raw_response(
            format!(
                "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; marker=secret-error-content-type\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .into_bytes(),
        )
        .await
        .expect_err("non-success MCP response should fail");
        let content_type_error = post_message_against_raw_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/secret-content-type\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
                .to_vec(),
        )
        .await
        .expect_err("unsupported MCP content type should fail");
        let get_content_type_error = match get_stream_against_raw_response(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/secret-get-content-type\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
                .to_vec(),
        )
        .await
        {
            Ok(_) => panic!("unsupported MCP GET content type should fail"),
            Err(error) => error,
        };
        drop(_guard);

        let output = format!(
            "{auth_error} {auth_error:?} {status_error} {status_error:?} {content_type_error} {content_type_error:?} {get_content_type_error} {get_content_type_error:?} {}",
            logs.contents()
        );
        assert!(output.contains(REDACTED_MCP_UPSTREAM_VALUE));
        assert!(output.contains("502 Bad Gateway"));
        for secret in [
            "secret-auth-challenge",
            "secret-error-body",
            "secret-error-content-type",
            "secret-content-type",
            "secret-get-content-type",
        ] {
            assert!(
                !output.contains(secret),
                "MCP response error or log leaked {secret}: {output}"
            );
        }
    }

    #[tokio::test]
    async fn managed_connection_credential_is_injected_on_post_get_and_delete() {
        let api_key_header = HeaderName::from_static("x-managed-mcp-key");
        let credential = Arc::new(ResolvedConnectionCredential::header_api_key_for_test(
            api_key_header.clone(),
            b"managed-mcp-key-canary",
        ));
        let request = ClientJsonRpcMessage::request(
            ClientRequest::CallToolRequest(CallToolRequest::new(CallToolRequestParams::new(
                "credential_test".to_owned(),
            ))),
            NumberOrString::Number(1),
        );

        let (post_client, post_url, post_server) = managed_client_capture(
            Arc::clone(&credential),
            api_key_header.clone(),
            b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        post_client
            .post_message(
                Arc::from(post_url),
                request,
                None,
                Some("attacker-transport-token".to_owned()),
                HashMap::new(),
            )
            .await
            .expect("managed MCP POST should succeed");
        assert_managed_credential_headers(post_server.await.expect("POST capture should finish"));

        let (get_client, get_url, get_server) = managed_client_capture(
            Arc::clone(&credential),
            api_key_header.clone(),
            b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(matches!(
            get_client
                .get_stream(
                    Arc::from(get_url),
                    Arc::from("test-session"),
                    None,
                    Some("attacker-transport-token".to_owned()),
                    HashMap::new(),
                )
                .await,
            Err(StreamableHttpError::ServerDoesNotSupportSse)
        ));
        assert_managed_credential_headers(get_server.await.expect("GET capture should finish"));

        let (delete_client, delete_url, delete_server) = managed_client_capture(
            credential,
            api_key_header,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await;
        delete_client
            .delete_session(
                Arc::from(delete_url),
                Arc::from("test-session"),
                Some("attacker-transport-token".to_owned()),
                HashMap::new(),
            )
            .await
            .expect("managed MCP DELETE should succeed");
        assert_managed_credential_headers(
            delete_server.await.expect("DELETE capture should finish"),
        );
    }

    #[tokio::test]
    async fn managed_authentication_rejection_discards_challenge_and_body() {
        let api_key_header = HeaderName::from_static("x-managed-mcp-key");
        let credential = Arc::new(ResolvedConnectionCredential::header_api_key_for_test(
            api_key_header.clone(),
            b"managed-mcp-key-canary",
        ));
        let (client, url, server) = managed_client_capture(
            credential,
            api_key_header,
            b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"challenge-canary\"\r\nContent-Type: text/plain\r\nContent-Length: 18\r\nConnection: close\r\n\r\ndenial-body-canary",
        )
        .await;
        let request = ClientJsonRpcMessage::request(
            ClientRequest::CallToolRequest(CallToolRequest::new(CallToolRequestParams::new(
                "credential_test".to_owned(),
            ))),
            NumberOrString::Number(1),
        );
        let error = client
            .post_message(Arc::from(url), request, None, None, HashMap::new())
            .await
            .expect_err("managed authentication denial should fail");
        let output = format!("{error} {error:?}");
        assert!(output.contains("authentication rejected"));
        assert!(!output.contains("challenge-canary"));
        assert!(!output.contains("denial-body-canary"));
        assert_managed_credential_headers(server.await.expect("denial capture should finish"));
    }

    async fn managed_client_capture(
        credential: Arc<ResolvedConnectionCredential>,
        credential_header_name: HeaderName,
        response: &'static [u8],
    ) -> (LimitedMcpHttpClient, String, JoinHandle<String>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("managed MCP capture listener should bind");
        let address = listener
            .local_addr()
            .expect("managed MCP capture address should be available");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("managed MCP capture server should accept a request");
            let request = read_raw_http_request_headers(&mut stream).await;
            stream
                .write_all(response)
                .await
                .expect("managed MCP capture response should write");
            request
        });
        let inner = rmcp_http::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(1))
            .build()
            .expect("managed MCP capture client should build");
        (
            LimitedMcpHttpClient::new(inner, 1024, 1024)
                .with_connection_credential(Some(credential), Some(credential_header_name)),
            format!("http://{address}/mcp"),
            server,
        )
    }

    fn assert_managed_credential_headers(request: String) {
        let request = request.to_ascii_lowercase();
        assert!(request.contains("\r\nx-managed-mcp-key: managed-mcp-key-canary\r\n"));
        assert!(
            !request.contains("authorization: bearer attacker-transport-token"),
            "transport-provided auth must not override managed Connection authority"
        );
    }

    async fn post_message_against_raw_response(
        response: Vec<u8>,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<LimitedMcpHttpError>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("raw MCP response listener should bind");
        let address = listener
            .local_addr()
            .expect("raw MCP response address should be available");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("raw MCP response server should accept a request");
            let _request = read_raw_http_request_headers(&mut stream).await;
            stream
                .write_all(&response)
                .await
                .expect("raw MCP response server should write its response");
        });
        let inner = rmcp_http::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(1))
            .build()
            .expect("raw-response MCP client should build");
        let client = LimitedMcpHttpClient::new(inner, 1024, 1024);
        let request = ClientJsonRpcMessage::request(
            ClientRequest::CallToolRequest(CallToolRequest::new(CallToolRequestParams::new(
                "redaction_test".to_owned(),
            ))),
            NumberOrString::Number(1),
        );

        let result = client
            .post_message(
                Arc::from(format!("http://{address}/mcp")),
                request,
                None,
                None,
                HashMap::new(),
            )
            .await;
        server.await.expect("raw MCP response server should finish");
        result
    }

    async fn get_stream_against_raw_response(
        response: Vec<u8>,
    ) -> Result<BoxStream<'static, Result<Sse, SseError>>, StreamableHttpError<LimitedMcpHttpError>>
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("raw MCP GET response listener should bind");
        let address = listener
            .local_addr()
            .expect("raw MCP GET response address should be available");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("raw MCP GET response server should accept a request");
            let _request = read_raw_http_request_headers(&mut stream).await;
            stream
                .write_all(&response)
                .await
                .expect("raw MCP GET response server should write its response");
        });
        let inner = rmcp_http::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(1))
            .build()
            .expect("raw-response MCP GET client should build");
        let client = LimitedMcpHttpClient::new(inner, 1024, 1024);

        let result = client
            .get_stream(
                Arc::from(format!("http://{address}/mcp")),
                Arc::from("redaction-test-session"),
                None,
                None,
                HashMap::new(),
            )
            .await;
        server
            .await
            .expect("raw MCP GET response server should finish");
        result
    }

    #[derive(Clone, Copy)]
    enum RawProtocolProbeScenario {
        ListSessionExpired,
        ImmediateSseRetry,
        StallInitialize,
        StallList,
        GetUnauthorized,
        GetForbidden,
        DeleteUnauthorized,
        DeleteForbidden,
        MethodNotAllowed,
    }

    #[derive(Default)]
    struct RawProtocolProbeCounts {
        initialize: AtomicUsize,
        initialized: AtomicUsize,
        list_tools: AtomicUsize,
        get_stream: AtomicUsize,
        delete_session: AtomicUsize,
    }

    impl RawProtocolProbeCounts {
        fn total(&self) -> usize {
            self.initialize
                .load(Ordering::SeqCst)
                .saturating_add(self.initialized.load(Ordering::SeqCst))
                .saturating_add(self.list_tools.load(Ordering::SeqCst))
                .saturating_add(self.get_stream.load(Ordering::SeqCst))
                .saturating_add(self.delete_session.load(Ordering::SeqCst))
        }
    }

    struct RawProtocolProbeUpstream {
        url: String,
        counts: Arc<RawProtocolProbeCounts>,
        stalled_disconnect: Arc<tokio::sync::Notify>,
        stop: tokio_util::sync::CancellationToken,
        handle: JoinHandle<()>,
    }

    impl RawProtocolProbeUpstream {
        async fn spawn(scenario: RawProtocolProbeScenario) -> Self {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("raw protocol-probe listener should bind");
            let address = listener
                .local_addr()
                .expect("raw protocol-probe address should be available");
            let counts = Arc::new(RawProtocolProbeCounts::default());
            let stalled_disconnect = Arc::new(tokio::sync::Notify::new());
            let stop = tokio_util::sync::CancellationToken::new();
            let server_counts = Arc::clone(&counts);
            let server_disconnect = Arc::clone(&stalled_disconnect);
            let server_stop = stop.clone();
            let handle = tokio::spawn(async move {
                let mut handlers = tokio::task::JoinSet::new();
                loop {
                    tokio::select! {
                        _ = server_stop.cancelled() => break,
                        accepted = listener.accept() => {
                            let Ok((stream, _)) = accepted else {
                                break;
                            };
                            handlers.spawn(handle_raw_protocol_probe_request(
                                stream,
                                scenario,
                                Arc::clone(&server_counts),
                                Arc::clone(&server_disconnect),
                                server_stop.clone(),
                            ));
                        }
                    }
                }
                while handlers.join_next().await.is_some() {}
            });

            Self {
                url: format!("http://{address}/mcp"),
                counts,
                stalled_disconnect,
                stop,
                handle,
            }
        }

        async fn join(self) {
            self.stop.cancel();
            tokio::time::timeout(Duration::from_secs(2), self.handle)
                .await
                .expect("raw protocol-probe server should stop")
                .expect("raw protocol-probe server task should join");
        }
    }

    async fn run_raw_protocol_probe(
        url: &str,
        operation_timeout: Duration,
    ) -> Result<(), ConnectionProtocolProbeError> {
        run_raw_protocol_probe_before(
            url,
            tokio::time::Instant::now() + operation_timeout + PROTOCOL_PROBE_CLEANUP_RESERVE,
        )
        .await
    }

    async fn run_raw_protocol_probe_before(
        url: &str,
        hard_deadline: tokio::time::Instant,
    ) -> Result<(), ConnectionProtocolProbeError> {
        let runtime_config = McpUpstreamRuntimeConfig {
            timeout: Duration::from_secs(5),
            response_idle_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(1),
            max_request_body_bytes: 64 * 1024,
            max_response_bytes: 64 * 1024,
        };
        let client = rmcp_http::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .read_timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(1))
            .build()
            .expect("raw protocol-probe client should build");
        let operation_deadline =
            protocol_probe_operation_deadline(runtime_config.timeout, hard_deadline)?;
        run_bounded_protocol_probe(
            "raw-protocol-probe".to_owned(),
            url.to_owned(),
            runtime_config,
            client,
            ManagedMcpAuthentication {
                credential: None,
                credential_header_name: None,
            },
            operation_deadline,
            hard_deadline,
        )
        .await
    }

    struct RawProtocolProbeRequest {
        method: String,
        body: Option<Value>,
    }

    async fn handle_raw_protocol_probe_request(
        mut stream: tokio::net::TcpStream,
        scenario: RawProtocolProbeScenario,
        counts: Arc<RawProtocolProbeCounts>,
        stalled_disconnect: Arc<tokio::sync::Notify>,
        stop: tokio_util::sync::CancellationToken,
    ) {
        let Some(request) = read_raw_protocol_probe_request(&mut stream).await else {
            return;
        };
        match request.method.as_str() {
            "GET" => {
                counts.get_stream.fetch_add(1, Ordering::SeqCst);
                match scenario {
                    RawProtocolProbeScenario::ImmediateSseRetry => {
                        stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 10\r\nConnection: close\r\n\r\nretry: 0\n\n",
                            )
                            .await
                            .expect("raw protocol-probe SSE response should write");
                    }
                    RawProtocolProbeScenario::GetUnauthorized => {
                        write_raw_protocol_probe_status(&mut stream, "401 Unauthorized").await;
                    }
                    RawProtocolProbeScenario::GetForbidden => {
                        write_raw_protocol_probe_status(&mut stream, "403 Forbidden").await;
                    }
                    _ => {
                        write_raw_protocol_probe_status(&mut stream, "405 Method Not Allowed")
                            .await;
                    }
                }
            }
            "DELETE" => {
                counts.delete_session.fetch_add(1, Ordering::SeqCst);
                match scenario {
                    RawProtocolProbeScenario::DeleteUnauthorized => {
                        write_raw_protocol_probe_status(&mut stream, "401 Unauthorized").await;
                    }
                    RawProtocolProbeScenario::DeleteForbidden => {
                        write_raw_protocol_probe_status(&mut stream, "403 Forbidden").await;
                    }
                    _ => {
                        write_raw_protocol_probe_status(&mut stream, "405 Method Not Allowed")
                            .await;
                    }
                }
            }
            "POST" => {
                let rpc_method = request
                    .body
                    .as_ref()
                    .and_then(|body| body.get("method"))
                    .and_then(Value::as_str);
                match rpc_method {
                    Some("initialize") => {
                        counts.initialize.fetch_add(1, Ordering::SeqCst);
                        if matches!(scenario, RawProtocolProbeScenario::StallInitialize) {
                            wait_for_raw_protocol_probe_disconnect(
                                &mut stream,
                                &stalled_disconnect,
                                &stop,
                            )
                            .await;
                            return;
                        }
                        let id = request
                            .body
                            .as_ref()
                            .and_then(|body| body.get("id"))
                            .cloned()
                            .unwrap_or(Value::Null);
                        write_raw_protocol_probe_json(
                            &mut stream,
                            serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "protocolVersion": "2025-06-18",
                                    "capabilities": {"tools": {}},
                                    "serverInfo": {
                                        "name": "raw-protocol-probe",
                                        "version": "0.0.0"
                                    }
                                }
                            }),
                            true,
                        )
                        .await;
                    }
                    Some("notifications/initialized") => {
                        counts.initialized.fetch_add(1, Ordering::SeqCst);
                        write_raw_protocol_probe_status(&mut stream, "202 Accepted").await;
                    }
                    Some("tools/list") => {
                        counts.list_tools.fetch_add(1, Ordering::SeqCst);
                        if matches!(scenario, RawProtocolProbeScenario::StallList) {
                            wait_for_raw_protocol_probe_disconnect(
                                &mut stream,
                                &stalled_disconnect,
                                &stop,
                            )
                            .await;
                            return;
                        }
                        if matches!(scenario, RawProtocolProbeScenario::ListSessionExpired) {
                            write_raw_protocol_probe_status(&mut stream, "404 Not Found").await;
                            return;
                        }
                        if matches!(scenario, RawProtocolProbeScenario::ImmediateSseRetry) {
                            tokio::time::sleep(Duration::from_millis(150)).await;
                        }
                        let id = request
                            .body
                            .as_ref()
                            .and_then(|body| body.get("id"))
                            .cloned()
                            .unwrap_or(Value::Null);
                        write_raw_protocol_probe_json(
                            &mut stream,
                            serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {"tools": []}
                            }),
                            false,
                        )
                        .await;
                    }
                    _ => {
                        write_raw_protocol_probe_status(&mut stream, "400 Bad Request").await;
                    }
                }
            }
            _ => write_raw_protocol_probe_status(&mut stream, "400 Bad Request").await,
        }
    }

    async fn read_raw_protocol_probe_request(
        stream: &mut tokio::net::TcpStream,
    ) -> Option<RawProtocolProbeRequest> {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        let header_end = loop {
            let read = stream
                .read(&mut chunk)
                .await
                .expect("raw protocol-probe server should read request");
            if read == 0 {
                return None;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if let Some(offset) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break offset;
            }
            assert!(
                buffer.len() <= 16 * 1024,
                "raw protocol-probe request headers should stay bounded"
            );
        };
        let headers = std::str::from_utf8(&buffer[..header_end])
            .expect("raw protocol-probe headers should be UTF-8");
        let method = headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().next())
            .unwrap_or_default()
            .to_owned();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        let body_start = header_end + 4;
        while buffer.len() < body_start.saturating_add(content_length) {
            let read = stream
                .read(&mut chunk)
                .await
                .expect("raw protocol-probe server should read request body");
            if read == 0 {
                return None;
            }
            buffer.extend_from_slice(&chunk[..read]);
        }
        let body = (content_length > 0).then(|| {
            serde_json::from_slice(&buffer[body_start..body_start + content_length])
                .expect("raw protocol-probe request body should be JSON")
        });
        Some(RawProtocolProbeRequest { method, body })
    }

    async fn write_raw_protocol_probe_json(
        stream: &mut tokio::net::TcpStream,
        body: Value,
        include_session: bool,
    ) {
        let body = body.to_string();
        let session = if include_session {
            "Mcp-Session-Id: raw-protocol-probe-session\r\n"
        } else {
            ""
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{session}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("raw protocol-probe JSON response should write");
    }

    async fn write_raw_protocol_probe_status(stream: &mut tokio::net::TcpStream, status: &str) {
        let response =
            format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        stream
            .write_all(response.as_bytes())
            .await
            .expect("raw protocol-probe status response should write");
    }

    async fn wait_for_raw_protocol_probe_disconnect(
        stream: &mut tokio::net::TcpStream,
        disconnected: &tokio::sync::Notify,
        stop: &tokio_util::sync::CancellationToken,
    ) {
        let mut byte = [0_u8; 1];
        loop {
            tokio::select! {
                _ = stop.cancelled() => return,
                read = stream.read(&mut byte) => {
                    match read {
                        Ok(0) | Err(_) => {
                            disconnected.notify_one();
                            return;
                        }
                        Ok(_) => {}
                    }
                }
            }
        }
    }

    #[derive(Clone, Default)]
    struct CapturedLogs {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl CapturedLogs {
        fn contents(&self) -> String {
            String::from_utf8(
                self.buffer
                    .lock()
                    .expect("captured logs should not be poisoned")
                    .clone(),
            )
            .expect("captured logs should be UTF-8")
        }
    }

    impl<'a> MakeWriter<'a> for CapturedLogs {
        type Writer = CapturedLogWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedLogWriter {
                buffer: Arc::clone(&self.buffer),
            }
        }
    }

    struct CapturedLogWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl io::Write for CapturedLogWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.buffer
                .lock()
                .map_err(|_| io::Error::other("captured logs lock poisoned"))?
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn get_stream_rejects_oversized_sse_without_content_length() {
        let upstream = spawn_raw_sse_upstream().await;
        let mut stream = oversized_sse_get_stream(&upstream.url).await;

        assert_first_sse_event(&mut stream).await;
        assert_sse_stream_response_too_large(&mut stream, TEST_RESPONSE_LIMIT).await;

        upstream.join().await;
    }

    #[tokio::test]
    async fn sse_streaming_cap_rejects_body_after_understated_content_length_hint() {
        let first_chunk = "event: message\ndata: under-limit\n\n";
        assert!(first_chunk.len() < TEST_RESPONSE_LIMIT);
        let overflow_chunk = format!(": {}\n\n", "x".repeat(TEST_RESPONSE_LIMIT));

        // HTTP/1.1 frames the body at Content-Length, so extra bytes after an
        // understated header are not delivered through the HTTP response. This
        // covers the production fallback that matters once bytes are delivered:
        // an under-cap length hint cannot bypass the streaming byte counter.
        let declared_content_length = first_chunk.len();
        assert!(declared_content_length < TEST_RESPONSE_LIMIT);
        let body = stream::iter([
            Ok::<_, rmcp_http::Error>(Bytes::copy_from_slice(first_chunk.as_bytes())),
            Ok(Bytes::from(overflow_chunk)),
        ]);
        let mut stream: BoxStream<'static, Result<Sse, SseError>> =
            Box::pin(SseStream::from_byte_stream(limited_mcp_body_stream(
                Box::pin(body),
                TEST_RESPONSE_LIMIT,
                None,
            )));

        assert_first_sse_event(&mut stream).await;
        assert_sse_stream_response_too_large(&mut stream, TEST_RESPONSE_LIMIT).await;
    }

    async fn oversized_sse_get_stream(url: &str) -> BoxStream<'static, Result<Sse, SseError>> {
        let client = rmcp_http::Client::builder()
            .no_proxy()
            .build()
            .expect("test MCP HTTP client should build");
        let client = LimitedMcpHttpClient::new(client, usize::MAX, TEST_RESPONSE_LIMIT);

        client
            .get_stream(
                Arc::from(url.to_owned()),
                Arc::from("test-session"),
                None,
                None,
                HashMap::new(),
            )
            .await
            .expect("oversized SSE GET response should pass header checks")
    }

    async fn assert_first_sse_event(stream: &mut BoxStream<'static, Result<Sse, SseError>>) {
        let event = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("SSE stream should yield before timing out")
            .expect("SSE stream should yield an initial event")
            .expect("initial SSE event should parse");

        assert_eq!(event.event.as_deref(), Some("message"));
        assert_eq!(event.data.as_deref(), Some("under-limit"));
    }

    async fn assert_sse_stream_response_too_large(
        stream: &mut BoxStream<'static, Result<Sse, SseError>>,
        expected_max: usize,
    ) {
        let error = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("SSE stream should yield oversized-body error before timing out")
            .expect("SSE stream should yield oversized-body error")
            .expect_err("SSE stream should reject once cumulative bytes exceed the cap");

        assert_eq!(mcp_response_too_large_max(&error), Some(expected_max));
    }

    struct RawSseUpstream {
        url: String,
        handle: JoinHandle<()>,
    }

    impl RawSseUpstream {
        async fn join(self) {
            self.handle
                .await
                .expect("raw SSE upstream task should finish cleanly");
        }
    }

    async fn spawn_raw_sse_upstream() -> RawSseUpstream {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("raw SSE upstream should bind");
        let addr = listener
            .local_addr()
            .expect("raw SSE upstream address should be available");

        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("raw SSE upstream should accept one connection");
            let request = read_raw_http_request_headers(&mut stream).await;
            assert!(
                request.starts_with("GET /mcp HTTP/1.1\r\n"),
                "get_stream should issue an MCP SSE GET request: {request:?}"
            );

            let first_chunk = "event: message\ndata: under-limit\n\n";
            assert!(first_chunk.len() < TEST_RESPONSE_LIMIT);
            let overflow_chunk = format!(": {}\n\n", "x".repeat(TEST_RESPONSE_LIMIT));
            write_chunked_sse_response(&mut stream, first_chunk, &overflow_chunk).await;
        });

        RawSseUpstream {
            url: format!("http://{addr}/mcp"),
            handle,
        }
    }

    async fn read_raw_http_request_headers(stream: &mut tokio::net::TcpStream) -> String {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = stream
                .read(&mut chunk)
                .await
                .expect("raw SSE upstream should read request headers");
            assert_ne!(read, 0, "client should send HTTP request headers");
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                return String::from_utf8(buffer).expect("raw SSE request headers should be UTF-8");
            }
            assert!(
                buffer.len() <= 16 * 1024,
                "raw SSE request headers should stay bounded"
            );
        }
    }

    async fn write_chunked_sse_response(
        stream: &mut tokio::net::TcpStream,
        first_chunk: &str,
        overflow_chunk: &str,
    ) {
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("raw SSE upstream should write response headers");
        write_chunked_body_chunk(stream, first_chunk).await;
        write_chunked_body_chunk(stream, overflow_chunk).await;
        stream
            .write_all(b"0\r\n\r\n")
            .await
            .expect("raw SSE upstream should finish chunked response");
    }

    async fn write_chunked_body_chunk(stream: &mut tokio::net::TcpStream, chunk: &str) {
        let prefix = format!("{:x}\r\n", chunk.len());
        stream
            .write_all(prefix.as_bytes())
            .await
            .expect("raw SSE upstream should write chunk prefix");
        stream
            .write_all(chunk.as_bytes())
            .await
            .expect("raw SSE upstream should write chunk body");
        stream
            .write_all(b"\r\n")
            .await
            .expect("raw SSE upstream should write chunk suffix");
    }
}
