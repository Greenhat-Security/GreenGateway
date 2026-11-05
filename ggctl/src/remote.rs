//! The admin API client: `ggctl`'s only network capability.
//!
//! `ggctl` talks to exactly one server, the admin API base the operator names
//! with `--server`, and to nothing else: there is no telemetry, update check
//! or discovery. The client is built in one place, [`admin_http_client`],
//! with the properties ADR-0008 ("Remote client") requires:
//!
//! - HTTPS with the platform's certificate and hostname verification, plus
//!   any `--ca-file` trust anchors; plain HTTP only to a loopback IP literal
//!   (an SSH tunnel or `kubectl port-forward`), and no option disables
//!   verification;
//! - redirects refused, ambient proxy variables ignored, HTTP/1.1 only, no
//!   transparent retries, no compression, no `Referer`;
//! - every response bounded in bytes and every request in time;
//! - idempotent reads retried at most twice, and only when the connection
//!   was never established, so nothing that reached the server is resent.
//!
//! Diagnostics carry codes only: no URL, address, header, body or library
//! error text from a failed request reaches the operator's terminal or a
//! report.

use std::{
    future::Future,
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use gateway_config::{
    capabilities::{self, GatewayCapabilities, ReadError, MAX_CAPABILITIES_BYTES},
    mcp_client_configs::{self, McpClientConfigs, ServerName, MAX_MCP_CLIENT_CONFIGS_BYTES},
};
use url::{Host, Url};

use crate::{
    cli::Invocation,
    credential::{self, read_regular_file, FilePermissions, FileProblem, Token},
    diagnostic::{Code, Diagnostic},
};

/// The default time allowed for each request.
pub(crate) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest `--timeout` accepted, in seconds.
pub(crate) const MAX_TIMEOUT_SECONDS: u64 = 300;
/// The connection phase never gets longer than this, within the timeout.
const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Retries of an idempotent read whose connection was never established.
const READ_RETRIES: usize = 2;
/// The ceiling on any response body `ggctl` reads.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// The largest `--ca-file`.
const MAX_CA_FILE_BYTES: usize = 1024 * 1024;
/// The capability document, relative to the admin API base.
const CAPABILITIES_PATH: &str = "/config/capabilities";
/// The MCP client configuration templates, relative to the admin API base.
const MCP_CLIENT_CONFIGS_PATH: &str = "/mcp/client-configs";
const USER_AGENT: &str = concat!("ggctl/", env!("CARGO_PKG_VERSION"));

/// A validated admin API base: `https://HOST[:PORT]/v1<ADMIN_PREFIX>`, or
/// `http://` to a loopback IP literal, with no user information, query or
/// fragment. `ggctl` never derives the prefix; it uses the one given.
#[derive(Clone, Debug)]
pub(crate) struct ServerUrl(Url);

impl ServerUrl {
    pub(crate) fn parse(text: &str) -> Result<Self, Code> {
        // URL parsing would silently resolve dot segments, decode or
        // re-encode escapes, trim surrounding spaces and drop tabs and line
        // breaks; refuse all of them so the base used is the one typed.
        if text.contains(['%', '\\'])
            || text
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
            || text
                .split(['/', '?', '#'])
                .any(|segment| segment == "." || segment == "..")
        {
            return Err(Code::InvalidServerUrl);
        }
        let mut url = Url::parse(text).map_err(|_| Code::InvalidServerUrl)?;
        if !url.username().is_empty() || url.password().is_some() {
            return Err(Code::UserinfoRefused);
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(Code::QueryOrFragmentRefused);
        }
        match url.scheme() {
            "https" => {}
            "http" if is_loopback_literal(url.host()) => {}
            "http" => return Err(Code::PlaintextRefused),
            _ => return Err(Code::InvalidServerUrl),
        }
        let path = url
            .path()
            .strip_suffix('/')
            .unwrap_or(url.path())
            .to_owned();
        if !is_admin_base(&path) {
            return Err(Code::InvalidServerUrl);
        }
        url.set_path(&path);
        Ok(Self(url))
    }

    pub(crate) fn is_https(&self) -> bool {
        self.0.scheme() == "https"
    }

    fn endpoint(&self, suffix: &str) -> Url {
        let mut url = self.0.clone();
        url.set_path(&format!("{}{suffix}", self.0.path()));
        url
    }
}

fn is_loopback_literal(host: Option<Host<&str>>) -> bool {
    match host {
        Some(Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
        Some(Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
        _ => false,
    }
}

/// `/v1` followed by an admin prefix in the gateway's own grammar.
fn is_admin_base(path: &str) -> bool {
    let Some(prefix) = path.strip_prefix("/v1/") else {
        return false;
    };
    prefix.split('/').all(|segment| {
        !segment.is_empty()
            && segment.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'~')
            })
    })
}

/// Trust anchors added to the platform's.
pub(crate) type TrustAnchors = Vec<reqwest::Certificate>;

/// Loads `--ca-file`: a regular file of at most 1 MiB holding at least one
/// PEM certificate. These anchors decide which server receives the bearer
/// token, so on Unix no other account may be able to change the file or
/// what its path resolves to ([`FilePermissions::TrustAnchor`]).
pub(crate) fn load_roots(path: &Path) -> Result<TrustAnchors, Code> {
    let bytes = read_regular_file(path, MAX_CA_FILE_BYTES, FilePermissions::TrustAnchor).map_err(
        |problem| match problem {
            FileProblem::Unreadable => Code::CaFileUnreadable,
            FileProblem::NotRegularFile => Code::CaFileNotRegularFile,
            FileProblem::UnsafePermissions => Code::CaFileUnsafePermissions,
            FileProblem::TooLarge => Code::CaFileTooLarge,
        },
    )?;
    roots_from_pem(&bytes)
}

fn roots_from_pem(pem: &[u8]) -> Result<TrustAnchors, Code> {
    match reqwest::Certificate::from_pem_bundle(pem) {
        Ok(roots) if !roots.is_empty() => Ok(roots),
        _ => Err(Code::CaFileInvalid),
    }
}

/// Everything a remote command needs to reach the server.
pub(crate) struct Target {
    pub(crate) server: ServerUrl,
    pub(crate) roots: TrustAnchors,
    pub(crate) token: Option<Token>,
    pub(crate) timeout: Duration,
}

/// The one HTTP client constructor in `ggctl`. `scripts/check-egress-only.sh`
/// pins the properties set here.
fn admin_http_client(
    server: &ServerUrl,
    roots: TrustAnchors,
    timeout: Duration,
) -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .http1_only()
        .referer(false)
        .https_only(server.is_https())
        .tls_certs_merge(roots)
        .timeout(timeout)
        .connect_timeout(timeout.min(MAX_CONNECT_TIMEOUT))
        .pool_max_idle_per_host(0)
        .user_agent(USER_AGENT)
        .build()
}

/// A client bound to one admin API base and credential.
pub(crate) struct AdminClient {
    http: reqwest::Client,
    server: ServerUrl,
    token: Option<Token>,
}

impl AdminClient {
    pub(crate) fn new(target: Target) -> Result<Self, Code> {
        let had_roots = !target.roots.is_empty();
        let http =
            admin_http_client(&target.server, target.roots, target.timeout).map_err(|_| {
                // With a fixed configuration the builder fails only on trust
                // anchors it cannot use.
                if had_roots {
                    Code::CaFileInvalid
                } else {
                    Code::ClientUnavailable
                }
            })?;
        Ok(Self {
            http,
            server: target.server,
            token: target.token,
        })
    }

    /// An idempotent `GET` of a JSON document below the admin API base, with
    /// `query` form-encoded. `refusals` names the code for each status the
    /// route defines beyond those every admin route shares.
    async fn get_json(
        &self,
        suffix: &str,
        query: &[(&str, &str)],
        maximum: usize,
        refusals: &[(u16, Code)],
    ) -> Result<Vec<u8>, Code> {
        let mut url = self.server.endpoint(suffix);
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        let reply = self.send(url, &Exchange::get(suffix, maximum)).await?;
        match reply.status {
            200 => reply.body.ok_or(Code::UnexpectedContentType),
            503 => Err(Code::ServerUnavailable),
            status => Err(refusals
                .iter()
                .find(|(refused, _)| *refused == status)
                .map_or(Code::UnexpectedStatus, |(_, code)| *code)),
        }
    }

    /// Sends one request below the admin API base and reads its answer.
    ///
    /// A redirect, `401` and `403` are refused here, for every command alike;
    /// every other status is the caller's to interpret. A success's body is
    /// read only when it has the media type the request accepts, and any
    /// other status's only when it is JSON, so an error page is never read
    /// as a document. Only a `GET` is ever sent twice, and only when its
    /// connection was never established.
    pub(crate) async fn exchange(&self, exchange: &Exchange<'_>) -> Result<Reply, Code> {
        self.send(self.server.endpoint(exchange.path), exchange)
            .await
    }

    /// [`AdminClient::exchange`] to `url`: `exchange.path` below the admin
    /// API base, with the query [`AdminClient::get_json`] adds when it has
    /// one.
    async fn send(&self, url: Url, exchange: &Exchange<'_>) -> Result<Reply, Code> {
        let retries = if exchange.method == Method::Get {
            READ_RETRIES
        } else {
            0
        };
        let mut attempt = 0;
        let response = loop {
            let method = match exchange.method {
                Method::Get => reqwest::Method::GET,
                Method::Post => reqwest::Method::POST,
                Method::Delete => reqwest::Method::DELETE,
            };
            let mut request = self
                .http
                .request(method, url.clone())
                .header(reqwest::header::ACCEPT, exchange.accept);
            if let Some(token) = &self.token {
                request = request.bearer_auth(token.expose());
            }
            if let Some(body) = &exchange.body {
                request = request
                    .header(reqwest::header::CONTENT_TYPE, JSON_MEDIA_TYPE)
                    .body(body.clone());
            }
            match request.send().await {
                Ok(response) => break response,
                Err(error) if error.is_connect() && attempt < retries => attempt += 1,
                Err(error) => return Err(transport_code(&error)),
            }
        };
        let status = response.status().as_u16();
        match status {
            300..=399 => return Err(Code::RedirectRefused),
            401 => return Err(Code::Unauthenticated),
            403 => return Err(Code::Forbidden),
            _ => {}
        }
        let success = (200..300).contains(&status);
        let headers = exchange
            .headers
            .iter()
            .filter_map(|name| {
                let value = response.headers().get(*name)?.to_str().ok()?;
                value
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic())
                    .then(|| (*name, value.to_owned()))
            })
            .collect();
        let wanted = if success {
            exchange.accept
        } else {
            JSON_MEDIA_TYPE
        };
        let body = if has_media_type(response.headers(), wanted) {
            Some(read_body(response, exchange.maximum.min(MAX_RESPONSE_BYTES)).await?)
        } else if success && status != 204 {
            return Err(Code::UnexpectedContentType);
        } else {
            None
        };
        Ok(Reply {
            status,
            headers,
            body,
        })
    }
}

/// The JSON media type every request body has and most answers have.
pub(crate) const JSON_MEDIA_TYPE: &str = "application/json";

/// The methods the admin API client sends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Method {
    /// An idempotent read: the only request ever sent twice.
    Get,
    Post,
    Delete,
}

/// One request a command makes.
pub(crate) struct Exchange<'a> {
    pub(crate) method: Method,
    /// The path below the admin API base, such as `/policy/validate`.
    pub(crate) path: &'a str,
    /// A JSON body, sent as these exact bytes.
    pub(crate) body: Option<Vec<u8>>,
    /// The one media type a successful answer may have.
    pub(crate) accept: &'static str,
    /// The response headers the command reads.
    pub(crate) headers: &'static [&'static str],
    /// The most response body bytes read, at most 8 MiB.
    pub(crate) maximum: usize,
}

impl<'a> Exchange<'a> {
    /// A `GET` of a JSON document.
    pub(crate) fn get(path: &'a str, maximum: usize) -> Self {
        Self {
            method: Method::Get,
            path,
            body: None,
            accept: JSON_MEDIA_TYPE,
            headers: &[],
            maximum,
        }
    }
}

/// What the server answered.
#[derive(Debug)]
pub(crate) struct Reply {
    pub(crate) status: u16,
    /// The requested headers the answer had, with visible-ASCII values.
    pub(crate) headers: Vec<(&'static str, String)>,
    /// The body, when it had the media type [`AdminClient::exchange`] reads.
    pub(crate) body: Option<Vec<u8>>,
}

impl Reply {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn transport_code(error: &reqwest::Error) -> Code {
    if error.is_connect() {
        Code::ConnectFailed
    } else if error.is_timeout() {
        Code::Timeout
    } else if error.is_redirect() {
        Code::RedirectRefused
    } else {
        Code::TransportFailed
    }
}

fn has_media_type(headers: &reqwest::header::HeaderMap, wanted: &str) -> bool {
    headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case(wanted))
}

async fn read_body(mut response: reqwest::Response, maximum: usize) -> Result<Vec<u8>, Code> {
    let limit = u64::try_from(maximum).unwrap_or(u64::MAX);
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        return Err(Code::ResponseTooLarge);
    }
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len().saturating_add(chunk.len()) > maximum {
                    return Err(Code::ResponseTooLarge);
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(body),
            Err(error) => return Err(transport_code(&error)),
        }
    }
}

/// What the version handshake found.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Handshake {
    /// The server's capability document is one this `ggctl` reads.
    Compatible(GatewayCapabilities),
    /// It is not. The gateway version is kept when the document stated a
    /// well-formed one.
    Incompatible {
        gateway_version: Option<String>,
        reason: Code,
    },
}

/// Reads the server's capability document (ADR-0008: before any mutation,
/// and for `ggctl version --server`).
pub(crate) async fn handshake(client: &AdminClient) -> Result<Handshake, Code> {
    let body = client
        .get_json(
            CAPABILITIES_PATH,
            &[],
            MAX_CAPABILITIES_BYTES,
            &[(404, Code::CapabilitiesUnavailable)],
        )
        .await?;
    Ok(match capabilities::read(&body) {
        Ok(capabilities) => Handshake::Compatible(capabilities),
        Err(ReadError::UnsupportedVersion { gateway_version }) => Handshake::Incompatible {
            gateway_version,
            reason: Code::UnsupportedCapabilitiesVersion,
        },
        Err(ReadError::Invalid { gateway_version }) => Handshake::Incompatible {
            gateway_version,
            reason: Code::CapabilitiesInvalid,
        },
        Err(ReadError::TooLarge | ReadError::NotADocument) => Handshake::Incompatible {
            gateway_version: None,
            reason: Code::CapabilitiesInvalid,
        },
    })
}

/// Reads the server's MCP client configuration templates for `ggctl
/// mcp-config`, naming the server entry `name` when one is given. The shared
/// reader accepts the document only when every template in it is exactly
/// what this `ggctl` renders for the URL, name and OAuth flag it states, so a
/// server can never hand a template through `ggctl` that it would not have
/// written itself. Neither the version handshake nor `admin:config:read` is
/// needed: the route has its own permission, `admin:mcp:clients:read`.
pub(crate) async fn mcp_client_configs(
    client: &AdminClient,
    name: Option<&ServerName>,
) -> Result<McpClientConfigs, Code> {
    let query: Vec<(&str, &str)> = name
        .map(|name| ("name", name.as_str()))
        .into_iter()
        .collect();
    let body = client
        .get_json(
            MCP_CLIENT_CONFIGS_PATH,
            &query,
            MAX_MCP_CLIENT_CONFIGS_BYTES,
            &[
                (404, Code::McpConfigsUnavailable),
                (409, Code::McpPublicUrlUnusable),
            ],
        )
        .await?;
    mcp_client_configs::read(&body).map_err(|error| match error {
        mcp_client_configs::ReadError::UnsupportedVersion => Code::McpUnsupportedVersion,
        mcp_client_configs::ReadError::TooLarge
        | mcp_client_configs::ReadError::NotADocument
        | mcp_client_configs::ReadError::Invalid => Code::McpConfigsInvalid,
    })
}

/// The remote options of a command line, checked before anything is read
/// or sent.
#[derive(Debug)]
pub(crate) struct RemoteArguments {
    server: ServerUrl,
    ca_file: Option<PathBuf>,
    token: TokenSource,
    timeout: Duration,
}

#[derive(Debug)]
enum TokenSource {
    None,
    Stdin,
    File(PathBuf),
}

const REMOTE_OPTIONS: &[&str] = &["--ca-file", "--token-stdin", "--token-file", "--timeout"];

impl RemoteArguments {
    /// `None` when the command line names no server. Every refusal here is
    /// an argument error.
    pub(crate) fn from_invocation(invocation: &Invocation) -> Result<Option<Self>, Diagnostic> {
        let Some((server_position, server)) = invocation.text("--server") else {
            return match REMOTE_OPTIONS
                .iter()
                .filter_map(|name| invocation.flag(name))
                .min()
            {
                Some(position) => Err(Diagnostic::at(Code::OptionRequiresServer, position)),
                None => Ok(None),
            };
        };
        let server =
            ServerUrl::parse(server).map_err(|code| Diagnostic::at(code, server_position))?;
        let token = match (
            invocation.flag("--token-stdin"),
            invocation.value("--token-file"),
        ) {
            (Some(stdin), Some((file, _))) => {
                return Err(Diagnostic::at(Code::ConflictingOptions, stdin.max(file)))
            }
            (Some(_), None) => TokenSource::Stdin,
            (None, Some((_, path))) => TokenSource::File(PathBuf::from(path)),
            (None, None) => TokenSource::None,
        };
        let ca_file = match invocation.value("--ca-file") {
            Some((position, _)) if !server.is_https() => {
                return Err(Diagnostic::at(Code::CaFileRequiresHttps, position))
            }
            Some((_, path)) => Some(PathBuf::from(path)),
            None => None,
        };
        let timeout = match invocation.text("--timeout") {
            None => DEFAULT_TIMEOUT,
            Some((position, text)) => match text.parse::<u64>() {
                Ok(seconds) if (1..=MAX_TIMEOUT_SECONDS).contains(&seconds) => {
                    Duration::from_secs(seconds)
                }
                _ => return Err(Diagnostic::at(Code::InvalidValue, position)),
            },
        };
        Ok(Some(Self {
            server,
            ca_file,
            token,
            timeout,
        }))
    }

    /// The remote options of a command that has no offline form: one
    /// without `--server` is refused.
    pub(crate) fn required(invocation: &Invocation) -> Result<Self, Diagnostic> {
        Self::from_invocation(invocation)?.ok_or(Diagnostic::new(Code::ServerRequired))
    }

    /// Reads the credential and trust anchors the arguments name.
    pub(crate) fn load(
        self,
        stdin_is_terminal: bool,
        stdin: &mut dyn Read,
    ) -> Result<Target, Code> {
        let token = match &self.token {
            TokenSource::None => None,
            TokenSource::Stdin => Some(credential::from_stdin(stdin_is_terminal, stdin)?),
            TokenSource::File(path) => Some(credential::from_file(path)?),
        };
        let roots = match &self.ca_file {
            Some(path) => load_roots(path)?,
            None => Vec::new(),
        };
        Ok(Target {
            server: self.server,
            roots,
            token,
            timeout: self.timeout,
        })
    }
}

/// Runs one remote operation to completion on a current-thread runtime:
/// commands make sequential requests and need no worker pool.
pub(crate) fn block_on<F: Future>(future: F) -> Result<F::Output, Code> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Code::RuntimeUnavailable)?;
    Ok(runtime.block_on(future))
}

#[cfg(test)]
mod tests;
