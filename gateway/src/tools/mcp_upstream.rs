use std::{
    borrow::Cow,
    collections::HashMap,
    error::Error,
    fmt,
    pin::Pin,
    sync::Arc,
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
        CallToolRequestParams, CallToolResult, ClientJsonRpcMessage, JsonObject, JsonRpcMessage,
        PaginatedRequestParams, ServerJsonRpcMessage, Tool,
    },
    service::{ClientInitializeError, ServiceError},
    transport::{
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
    egress::{CheckedEgressDestination, EgressClient, EgressError},
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
    DiscoveryPageLimitExceeded { max: usize },
    DiscoveryToolLimitExceeded { max: usize },
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
            Self::DiscoveryPageLimitExceeded { .. } => "discovery_page_limit_exceeded",
            Self::DiscoveryToolLimitExceeded { .. } => "discovery_tool_limit_exceeded",
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
            Self::DiscoveryPageLimitExceeded { max } => write!(
                formatter,
                "upstream MCP tools/list pagination exceeded {max} pages"
            ),
            Self::DiscoveryToolLimitExceeded { max } => write!(
                formatter,
                "upstream MCP tools/list discovery exceeded {max} tools"
            ),
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
) -> Result<CallToolResult, McpUpstreamCallError> {
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
        .map_err(|error| mcp_service_error(error, McpUpstreamCallError::Call))?;
    let _ = service.close_with_timeout(Duration::from_millis(250)).await;

    Ok(result)
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
    let mut tools = Vec::new();
    let mut cursor = None;

    for _ in 0..MAX_DISCOVERY_PAGES_PER_UPSTREAM {
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

    tracing::warn!(
        max_pages = MAX_DISCOVERY_PAGES_PER_UPSTREAM,
        "MCP upstream discovery exceeded aggregate page limit"
    );
    Err(McpUpstreamCallError::DiscoveryPageLimitExceeded {
        max: MAX_DISCOVERY_PAGES_PER_UPSTREAM,
    })
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
    let client = LimitedMcpHttpClient::new(
        client,
        runtime_config.max_request_body_bytes,
        runtime_config.max_response_bytes,
    );
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
    result.map_err(|error| mcp_service_error(error, McpUpstreamCallError::Connect))
}

#[derive(Clone)]
struct LimitedMcpHttpClient {
    inner: rmcp_reqwest::Client,
    max_request_body_bytes: usize,
    max_response_bytes: usize,
}

impl LimitedMcpHttpClient {
    fn new(
        inner: rmcp_reqwest::Client,
        max_request_body_bytes: usize,
        max_response_bytes: usize,
    ) -> Self {
        Self {
            inner,
            max_request_body_bytes,
            max_response_bytes,
        }
    }
}

#[derive(Debug)]
enum LimitedMcpHttpError {
    Http(rmcp_reqwest::Error),
    Serialize(serde_json::Error),
    RequestBodyTooLarge { size: usize, max: usize },
    ResponseTooLarge { max: usize },
}

impl fmt::Display for LimitedMcpHttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(error) => write!(formatter, "MCP upstream HTTP error: {error}"),
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
        }
    }
}

impl Error for LimitedMcpHttpError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Http(error) => Some(error),
            Self::Serialize(error) => Some(error),
            Self::RequestBodyTooLarge { .. } | Self::ResponseTooLarge { .. } => None,
        }
    }
}

impl From<rmcp_reqwest::Error> for LimitedMcpHttpError {
    fn from(error: rmcp_reqwest::Error) -> Self {
        Self::Http(error)
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
        let mut request_builder = self
            .inner
            .get(uri.as_ref())
            .header(ACCEPT, [EVENT_STREAM_MIME, JSON_MIME].join(", "))
            .header(HEADER_SESSION_ID, session_id.as_ref());
        if let Some(last_event_id) = last_event_id {
            request_builder = request_builder.header(HEADER_LAST_EVENT_ID, last_event_id);
        }
        if let Some(auth_header) = auth_token {
            request_builder = request_builder.bearer_auth(auth_header);
        }
        request_builder = apply_mcp_custom_headers(request_builder, custom_headers)?;
        let response = request_builder.send().await.map_err(mcp_http_error)?;
        if response.status() == StatusCode::METHOD_NOT_ALLOWED {
            return Err(StreamableHttpError::ServerDoesNotSupportSse);
        }
        let response = response.error_for_status().map_err(mcp_http_error)?;
        validate_mcp_response_content_type(&response)?;
        enforce_mcp_response_content_length(&response, self.max_response_bytes)?;

        let event_stream = SseStream::from_byte_stream(limited_mcp_response_stream(
            response,
            self.max_response_bytes,
        ))
        .boxed();
        Ok(event_stream)
    }

    async fn delete_session(
        &self,
        uri: Arc<str>,
        session: Arc<str>,
        auth_token: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<(), StreamableHttpError<Self::Error>> {
        let mut request_builder = self.inner.delete(uri.as_ref());
        if let Some(auth_header) = auth_token {
            request_builder = request_builder.bearer_auth(auth_header);
        }
        request_builder = request_builder.header(HEADER_SESSION_ID, session.as_ref());
        request_builder = apply_mcp_custom_headers(request_builder, custom_headers)?;
        let response = request_builder.send().await.map_err(mcp_http_error)?;

        if response.status() == StatusCode::METHOD_NOT_ALLOWED {
            tracing::debug!("upstream MCP server does not support deleting sessions");
            return Ok(());
        }
        let _response = response.error_for_status().map_err(mcp_http_error)?;
        Ok(())
    }

    async fn post_message(
        &self,
        uri: Arc<str>,
        message: ClientJsonRpcMessage,
        session_id: Option<Arc<str>>,
        auth_token: Option<String>,
        custom_headers: HashMap<HeaderName, HeaderValue>,
    ) -> Result<StreamableHttpPostResponse, StreamableHttpError<Self::Error>> {
        let mut request = self
            .inner
            .post(uri.as_ref())
            .header(ACCEPT, [EVENT_STREAM_MIME, JSON_MIME].join(", "));
        if let Some(auth_header) = auth_token {
            request = request.bearer_auth(auth_header);
        }

        let custom_content_type = custom_headers
            .keys()
            .any(|name| name.as_str().eq_ignore_ascii_case(CONTENT_TYPE.as_str()));
        request = apply_mcp_custom_headers(request, custom_headers)?;
        let session_was_attached = session_id.is_some();
        if let Some(session_id) = session_id {
            request = request.header(HEADER_SESSION_ID, session_id.as_ref());
        }
        let body = serialize_mcp_request_body(&message)?;
        enforce_mcp_request_body_size(body.len(), self.max_request_body_bytes)?;
        if !custom_content_type {
            request = request.header(CONTENT_TYPE, JSON_MIME);
        }
        let response = request.body(body).send().await.map_err(mcp_http_error)?;
        if response.status() == StatusCode::UNAUTHORIZED {
            if let Some(header) = response.headers().get(WWW_AUTHENTICATE) {
                let header = header
                    .to_str()
                    .map_err(|_| {
                        StreamableHttpError::UnexpectedServerResponse(Cow::from(
                            "invalid www-authenticate header value",
                        ))
                    })?
                    .to_string();
                return Err(StreamableHttpError::AuthRequired(AuthRequiredError::new(
                    header,
                )));
            }
        }
        if response.status() == StatusCode::FORBIDDEN {
            if let Some(header) = response.headers().get(WWW_AUTHENTICATE) {
                let header_str = header.to_str().map_err(|_| {
                    StreamableHttpError::UnexpectedServerResponse(Cow::from(
                        "invalid www-authenticate header value",
                    ))
                })?;
                return Err(StreamableHttpError::InsufficientScope(
                    InsufficientScopeError::new(
                        header_str.to_owned(),
                        extract_mcp_scope_from_header(header_str),
                    ),
                ));
            }
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
        let session_id = response
            .headers()
            .get(HEADER_SESSION_ID)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);

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
            let body = match read_limited_mcp_response_text(response, self.max_response_bytes).await
            {
                Ok(body) => body,
                Err(error) if mcp_streamable_error_response_too_large(&error).is_some() => {
                    return Err(error);
                }
                Err(_) => "<failed to read response body>".to_owned(),
            };
            if content_type
                .as_deref()
                .is_some_and(|ct| ct.as_bytes().starts_with(JSON_MIME.as_bytes()))
            {
                match parse_json_rpc_error(&body) {
                    Some(message) => {
                        return Ok(StreamableHttpPostResponse::Json(message, session_id));
                    }
                    None => tracing::warn!(
                        "HTTP {status}: could not parse JSON body as a JSON-RPC error"
                    ),
                }
            }
            return Err(StreamableHttpError::UnexpectedServerResponse(Cow::Owned(
                format!("HTTP {status}: {body}"),
            )));
        }

        match content_type.as_deref() {
            Some(ct) if ct.as_bytes().starts_with(EVENT_STREAM_MIME.as_bytes()) => {
                enforce_mcp_response_content_length(&response, self.max_response_bytes)?;
                let event_stream = SseStream::from_byte_stream(limited_mcp_response_stream(
                    response,
                    self.max_response_bytes,
                ))
                .boxed();
                Ok(StreamableHttpPostResponse::Sse(event_stream, session_id))
            }
            Some(ct) if ct.as_bytes().starts_with(JSON_MIME.as_bytes()) => {
                match read_limited_mcp_response_json::<ServerJsonRpcMessage>(
                    response,
                    self.max_response_bytes,
                )
                .await
                {
                    Ok(message) => Ok(StreamableHttpPostResponse::Json(message, session_id)),
                    Err(error) if mcp_streamable_error_response_too_large(&error).is_some() => {
                        Err(error)
                    }
                    Err(error) => {
                        tracing::warn!(
                            "could not parse JSON response as ServerJsonRpcMessage, treating as accepted: {error}"
                        );
                        Ok(StreamableHttpPostResponse::Accepted)
                    }
                }
            }
            _ => {
                tracing::error!("unexpected content type: {:?}", content_type);
                Err(StreamableHttpError::UnexpectedContentType(content_type))
            }
        }
    }
}

type LimitedMcpByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, LimitedMcpHttpError>> + Send>>;

fn limited_mcp_response_stream(
    response: rmcp_reqwest::Response,
    max_response_bytes: usize,
) -> LimitedMcpByteStream {
    let body = Box::pin(response.bytes_stream());
    limited_mcp_body_stream(body, max_response_bytes)
}

fn limited_mcp_body_stream(
    body: Pin<Box<dyn Stream<Item = Result<Bytes, rmcp_reqwest::Error>> + Send>>,
    max_response_bytes: usize,
) -> LimitedMcpByteStream {
    Box::pin(stream::unfold(
        (body, 0usize, false),
        move |state| async move {
            let (mut body, mut streamed_bytes, done) = state;
            if done {
                return None;
            }

            match body.next().await {
                Some(Ok(chunk)) => {
                    if streamed_bytes.saturating_add(chunk.len()) > max_response_bytes {
                        tracing::warn!(
                            max = max_response_bytes,
                            "egress blocked oversized MCP upstream response"
                        );
                        return Some((
                            Err(LimitedMcpHttpError::ResponseTooLarge {
                                max: max_response_bytes,
                            }),
                            (body, streamed_bytes, true),
                        ));
                    }

                    streamed_bytes += chunk.len();
                    Some((Ok(chunk), (body, streamed_bytes, false)))
                }
                Some(Err(error)) => Some((
                    Err(LimitedMcpHttpError::Http(error)),
                    (body, streamed_bytes, true),
                )),
                None => None,
            }
        },
    ))
}

async fn read_limited_mcp_response_body(
    response: rmcp_reqwest::Response,
    max_response_bytes: usize,
) -> Result<Bytes, StreamableHttpError<LimitedMcpHttpError>> {
    enforce_mcp_response_content_length(&response, max_response_bytes)?;
    let mut stream = limited_mcp_response_stream(response, max_response_bytes);
    let mut body = Vec::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(StreamableHttpError::Client)?;
        body.extend_from_slice(&chunk);
    }

    Ok(Bytes::from(body))
}

async fn read_limited_mcp_response_text(
    response: rmcp_reqwest::Response,
    max_response_bytes: usize,
) -> Result<String, StreamableHttpError<LimitedMcpHttpError>> {
    let body = read_limited_mcp_response_body(response, max_response_bytes).await?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

async fn read_limited_mcp_response_json<T: serde::de::DeserializeOwned>(
    response: rmcp_reqwest::Response,
    max_response_bytes: usize,
) -> Result<T, StreamableHttpError<LimitedMcpHttpError>> {
    let body = read_limited_mcp_response_body(response, max_response_bytes).await?;
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
    response: &rmcp_reqwest::Response,
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
    response: &rmcp_reqwest::Response,
) -> Result<(), StreamableHttpError<LimitedMcpHttpError>> {
    match response.headers().get(CONTENT_TYPE) {
        Some(content_type) => {
            if !content_type
                .as_bytes()
                .starts_with(EVENT_STREAM_MIME.as_bytes())
                && !content_type.as_bytes().starts_with(JSON_MIME.as_bytes())
            {
                return Err(StreamableHttpError::UnexpectedContentType(Some(
                    String::from_utf8_lossy(content_type.as_bytes()).to_string(),
                )));
            }
        }
        None => return Err(StreamableHttpError::UnexpectedContentType(None)),
    }

    Ok(())
}

fn apply_mcp_custom_headers(
    mut builder: rmcp_reqwest::RequestBuilder,
    custom_headers: HashMap<HeaderName, HeaderValue>,
) -> Result<rmcp_reqwest::RequestBuilder, StreamableHttpError<LimitedMcpHttpError>> {
    for (name, value) in custom_headers {
        validate_mcp_custom_header(&name).map_err(StreamableHttpError::ReservedHeaderConflict)?;
        builder = builder.header(name, value);
    }

    Ok(builder)
}

fn validate_mcp_custom_header(name: &HeaderName) -> Result<(), String> {
    let is_reserved = name.as_str().eq_ignore_ascii_case("accept")
        || name.as_str().eq_ignore_ascii_case(HEADER_SESSION_ID)
        || name.as_str().eq_ignore_ascii_case(HEADER_LAST_EVENT_ID);
    if is_reserved {
        return Err(name.to_string());
    }

    Ok(())
}

fn extract_mcp_scope_from_header(header: &str) -> Option<String> {
    let header_lowercase = header.to_ascii_lowercase();
    let scope_key = "scope=";
    let position = header_lowercase.find(scope_key)?;
    let value_slice = &header[position + scope_key.len()..];

    if let Some(stripped) = value_slice.strip_prefix('"') {
        let end_quote = stripped.find('"')?;
        return Some(stripped[..end_quote].to_owned());
    }

    let end = value_slice
        .find(|character: char| character == ',' || character == ';' || character.is_whitespace())
        .unwrap_or(value_slice.len());
    (end > 0).then(|| value_slice[..end].to_owned())
}

fn parse_json_rpc_error(body: &str) -> Option<ServerJsonRpcMessage> {
    match serde_json::from_str::<ServerJsonRpcMessage>(body) {
        Ok(message @ JsonRpcMessage::Error(_)) => Some(message),
        _ => None,
    }
}

fn mcp_http_error(error: rmcp_reqwest::Error) -> StreamableHttpError<LimitedMcpHttpError> {
    StreamableHttpError::Client(LimitedMcpHttpError::Http(error))
}

fn mcp_service_error<E>(error: E, fallback: McpUpstreamCallError) -> McpUpstreamCallError
where
    E: Error + 'static,
{
    if let Some((size, max)) = mcp_request_body_too_large_size_max(&error) {
        McpUpstreamCallError::RequestBodyTooLarge { size, max }
    } else if let Some(max) = mcp_response_too_large_max(&error) {
        McpUpstreamCallError::ResponseTooLarge { max }
    } else {
        fallback
    }
}

fn mcp_streamable_error_response_too_large(
    error: &StreamableHttpError<LimitedMcpHttpError>,
) -> Option<usize> {
    mcp_response_too_large_max(error)
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    const TEST_RESPONSE_LIMIT: usize = 64;

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
        // understated header are not delivered through reqwest::Response. This
        // covers the production fallback that matters once bytes are delivered:
        // an under-cap length hint cannot bypass the streaming byte counter.
        let declared_content_length = first_chunk.len();
        assert!(declared_content_length < TEST_RESPONSE_LIMIT);
        let body = stream::iter([
            Ok::<_, rmcp_reqwest::Error>(Bytes::copy_from_slice(first_chunk.as_bytes())),
            Ok(Bytes::from(overflow_chunk)),
        ]);
        let mut stream: BoxStream<'static, Result<Sse, SseError>> =
            Box::pin(SseStream::from_byte_stream(limited_mcp_body_stream(
                Box::pin(body),
                TEST_RESPONSE_LIMIT,
            )));

        assert_first_sse_event(&mut stream).await;
        assert_sse_stream_response_too_large(&mut stream, TEST_RESPONSE_LIMIT).await;
    }

    async fn oversized_sse_get_stream(url: &str) -> BoxStream<'static, Result<Sse, SseError>> {
        let client = rmcp_reqwest::Client::builder()
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
