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

use gateway_config::capabilities::{self, GatewayCapabilities, ReadError, MAX_CAPABILITIES_BYTES};
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
/// token, so on Unix neither the file nor a directory holding it may be
/// writable by another account ([`FilePermissions::NotWritableByOthers`]).
pub(crate) fn load_roots(path: &Path) -> Result<TrustAnchors, Code> {
    let bytes = read_regular_file(
        path,
        MAX_CA_FILE_BYTES,
        FilePermissions::NotWritableByOthers,
    )
    .map_err(|problem| match problem {
        FileProblem::Unreadable => Code::CaFileUnreadable,
        FileProblem::NotRegularFile => Code::CaFileNotRegularFile,
        FileProblem::UnsafePermissions => Code::CaFileUnsafePermissions,
        FileProblem::TooLarge => Code::CaFileTooLarge,
    })?;
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

    /// An idempotent `GET` of a JSON document below the admin API base.
    async fn get_json(
        &self,
        suffix: &str,
        maximum: usize,
        not_found: Code,
    ) -> Result<Vec<u8>, Code> {
        let url = self.server.endpoint(suffix);
        let mut retries = 0;
        let response = loop {
            let mut request = self
                .http
                .get(url.clone())
                .header(reqwest::header::ACCEPT, "application/json");
            if let Some(token) = &self.token {
                request = request.bearer_auth(token.expose());
            }
            match request.send().await {
                Ok(response) => break response,
                Err(error) if error.is_connect() && retries < READ_RETRIES => retries += 1,
                Err(error) => return Err(transport_code(&error)),
            }
        };
        match response.status().as_u16() {
            200 => {}
            300..=399 => return Err(Code::RedirectRefused),
            401 => return Err(Code::Unauthenticated),
            403 => return Err(Code::Forbidden),
            404 => return Err(not_found),
            503 => return Err(Code::ServerUnavailable),
            _ => return Err(Code::UnexpectedStatus),
        }
        if !is_json(response.headers()) {
            return Err(Code::UnexpectedContentType);
        }
        read_body(response, maximum.min(MAX_RESPONSE_BYTES)).await
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

fn is_json(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
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
            MAX_CAPABILITIES_BYTES,
            Code::CapabilitiesUnavailable,
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
