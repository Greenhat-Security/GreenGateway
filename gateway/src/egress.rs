use std::{
    collections::HashSet,
    error::Error,
    fmt, fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    time::Duration,
};

use bytes::Bytes;
use futures_util::{stream, Stream, StreamExt};
use ipnet::IpNet;
use reqwest::{header::HeaderMap, Method, StatusCode, Url};
use tokio::net::lookup_host;

use crate::{config::Config, rbac::EgressPolicy};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_RESPONSE_BYTES: usize = 5 * 1024 * 1024;
const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub enum EgressError {
    HostNotAllowed(String),
    PortNotAllowed(u16),
    PrivateIpBlocked(IpAddr),
    InvalidPolicy(String),
    DnsResolutionFailed(String),
    InvalidUrl(String),
    SchemeNotAllowed(String),
    RequestBodyTooLarge { size: usize, max: usize },
    ResponseTooLarge { max: usize },
    ResponseIdleTimeout { timeout: Duration },
    InvalidTlsCaBundle { path: PathBuf, message: String },
    Http(reqwest::Error),
}

impl fmt::Display for EgressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostNotAllowed(host) => write!(formatter, "egress host is not allowed: {host}"),
            Self::PortNotAllowed(port) => write!(formatter, "egress port is not allowed: {port}"),
            Self::PrivateIpBlocked(ip) => write!(formatter, "egress private IP is blocked: {ip}"),
            Self::InvalidPolicy(message) => {
                write!(formatter, "egress policy is invalid: {message}")
            }
            Self::DnsResolutionFailed(host) => {
                write!(formatter, "egress DNS resolution failed for {host}")
            }
            Self::InvalidUrl(url) => write!(formatter, "egress URL is invalid: {url}"),
            Self::SchemeNotAllowed(scheme) => {
                write!(formatter, "egress URL scheme is not allowed: {scheme}")
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
            Self::ResponseIdleTimeout { timeout } => write!(
                formatter,
                "egress response body was idle for {}ms",
                timeout.as_millis()
            ),
            Self::InvalidTlsCaBundle { path, message } => write!(
                formatter,
                "egress TLS CA bundle '{}' is invalid: {message}",
                path.display()
            ),
            Self::Http(err) => write!(formatter, "egress HTTP error: {err}"),
        }
    }
}

impl Error for EgressError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Http(err) => Some(err),
            _ => None,
        }
    }
}

impl From<reqwest::Error> for EgressError {
    fn from(err: reqwest::Error) -> Self {
        Self::Http(err)
    }
}

impl EgressError {
    pub fn is_timeout(&self) -> bool {
        match self {
            Self::ResponseIdleTimeout { .. } => true,
            Self::Http(err) => err.is_timeout(),
            _ => false,
        }
    }
}

/// Effective outbound egress controls.
///
/// `allowed_hosts` contains exact bootstrap hosts from `EGRESS_ALLOWED_HOSTS`
/// and auto-seeded infrastructure endpoint URLs. `allowed_host_globs`,
/// `private_ip_allow_cidrs`, and `allowed_ports` are layered from the optional
/// policy `egress` section. Host patterns are additive: an outbound request
/// must match either an exact bootstrap host or a policy host pattern. If
/// `allowed_ports` is non-empty, the URL's destination port must be listed.
/// If `deny_private_ips` is true, any private resolved address still blocks
/// the request unless that private IP is explicitly covered by one of the
/// policy CIDRs; policy CIDRs do not disable private-IP blocking globally.
#[derive(Clone)]
pub struct EgressConfig {
    pub allowed_hosts: HashSet<String>,
    pub allowed_host_globs: Vec<String>,
    pub private_ip_allow_cidrs: Vec<IpNet>,
    pub allowed_ports: HashSet<u16>,
    pub timeout: Duration,
    pub response_idle_timeout: Duration,
    pub connect_timeout: Duration,
    pub max_response_bytes: usize,
    pub max_request_body_bytes: usize,
    pub deny_private_ips: bool,
    pub tls_ca_bundle_path: Option<PathBuf>,
    pub tls_root_certificates: Vec<reqwest::Certificate>,
}

impl fmt::Debug for EgressConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EgressConfig")
            .field("allowed_hosts", &self.allowed_hosts)
            .field("allowed_host_globs", &self.allowed_host_globs)
            .field("private_ip_allow_cidrs", &self.private_ip_allow_cidrs)
            .field("allowed_ports", &self.allowed_ports)
            .field("timeout", &self.timeout)
            .field("response_idle_timeout", &self.response_idle_timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_request_body_bytes", &self.max_request_body_bytes)
            .field("deny_private_ips", &self.deny_private_ips)
            .field("tls_ca_bundle_path", &self.tls_ca_bundle_path)
            .field(
                "tls_root_certificate_count",
                &self.tls_root_certificates.len(),
            )
            .finish()
    }
}

impl PartialEq for EgressConfig {
    fn eq(&self, other: &Self) -> bool {
        self.allowed_hosts == other.allowed_hosts
            && self.allowed_host_globs == other.allowed_host_globs
            && self.private_ip_allow_cidrs == other.private_ip_allow_cidrs
            && self.allowed_ports == other.allowed_ports
            && self.timeout == other.timeout
            && self.response_idle_timeout == other.response_idle_timeout
            && self.connect_timeout == other.connect_timeout
            && self.max_response_bytes == other.max_response_bytes
            && self.max_request_body_bytes == other.max_request_body_bytes
            && self.deny_private_ips == other.deny_private_ips
            && self.tls_ca_bundle_path == other.tls_ca_bundle_path
            && self.tls_root_certificates.len() == other.tls_root_certificates.len()
    }
}

impl Eq for EgressConfig {}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            allowed_hosts: HashSet::new(),
            allowed_host_globs: Vec::new(),
            private_ip_allow_cidrs: Vec::new(),
            allowed_ports: HashSet::new(),
            timeout: DEFAULT_TIMEOUT,
            response_idle_timeout: DEFAULT_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            deny_private_ips: true,
            tls_ca_bundle_path: None,
            tls_root_certificates: Vec::new(),
        }
    }
}

impl EgressConfig {
    pub fn from_config(config: &Config) -> Self {
        let mut allowed_hosts: HashSet<String> = config
            .egress_allowed_hosts
            .iter()
            .map(|host| host.to_ascii_lowercase())
            .collect();
        let mut auto_seeded_hosts = Vec::new();

        auto_seed_endpoint_host(
            config.jwt_jwks_url.as_deref(),
            &mut allowed_hosts,
            &mut auto_seeded_hosts,
        );
        auto_seed_endpoint_host(
            config.jwt_issuer.as_deref(),
            &mut allowed_hosts,
            &mut auto_seeded_hosts,
        );
        auto_seed_endpoint_host(
            config.upstream_url.as_deref(),
            &mut allowed_hosts,
            &mut auto_seeded_hosts,
        );
        for route in &config.upstream_routes {
            auto_seed_endpoint_host(
                Some(route.upstream_url.as_str()),
                &mut allowed_hosts,
                &mut auto_seeded_hosts,
            );
        }

        if !auto_seeded_hosts.is_empty() {
            tracing::debug!(
                hosts = ?auto_seeded_hosts,
                "auto-seeded egress allowlist from infrastructure endpoints"
            );
        }

        Self {
            allowed_hosts,
            allowed_host_globs: Vec::new(),
            private_ip_allow_cidrs: Vec::new(),
            allowed_ports: HashSet::new(),
            timeout: Duration::from_millis(config.egress_timeout_ms),
            response_idle_timeout: Duration::from_millis(config.egress_response_idle_timeout_ms),
            connect_timeout: Duration::from_millis(config.egress_connect_timeout_ms),
            max_response_bytes: config.egress_max_response_bytes,
            max_request_body_bytes: config.egress_max_request_body_bytes,
            deny_private_ips: config.egress_deny_private_ips,
            tls_ca_bundle_path: None,
            tls_root_certificates: Vec::new(),
        }
    }

    pub fn from_config_and_policy(
        config: &Config,
        policy: Option<&EgressPolicy>,
    ) -> Result<Self, EgressError> {
        let mut effective = Self::from_config(config);
        if let Some(policy) = policy {
            effective.apply_policy(policy)?;
        }

        Ok(effective)
    }

    pub fn allowed_host_rule_count(&self) -> usize {
        self.allowed_hosts.len() + self.allowed_host_globs.len()
    }

    fn apply_policy(&mut self, policy: &EgressPolicy) -> Result<(), EgressError> {
        self.allowed_host_globs
            .extend(policy.hosts.iter().map(|host| host.to_ascii_lowercase()));
        for cidr in &policy.cidrs {
            self.private_ip_allow_cidrs
                .push(cidr.parse::<IpNet>().map_err(|err| {
                    EgressError::InvalidPolicy(format!("CIDR '{cidr}' is invalid: {err}"))
                })?);
        }
        self.allowed_ports.extend(policy.ports.iter().copied());

        Ok(())
    }

    pub fn apply_upstream_timeout_overrides(&mut self, config: &Config) {
        if let Some(timeout_ms) = config.upstream_timeout_ms {
            self.timeout = Duration::from_millis(timeout_ms);
        }
        if let Some(timeout_ms) = config.upstream_response_idle_timeout_ms {
            self.response_idle_timeout = Duration::from_millis(timeout_ms);
        }
        if let Some(timeout_ms) = config.upstream_connect_timeout_ms {
            self.connect_timeout = Duration::from_millis(timeout_ms);
        }
    }

    pub fn apply_timeout_overrides(
        &mut self,
        timeout_ms: Option<u64>,
        response_idle_timeout_ms: Option<u64>,
        connect_timeout_ms: Option<u64>,
    ) {
        if let Some(timeout_ms) = timeout_ms {
            self.timeout = Duration::from_millis(timeout_ms);
        }
        if let Some(timeout_ms) = response_idle_timeout_ms {
            self.response_idle_timeout = Duration::from_millis(timeout_ms);
        }
        if let Some(timeout_ms) = connect_timeout_ms {
            self.connect_timeout = Duration::from_millis(timeout_ms);
        }
    }

    pub fn apply_tls_ca_bundle_path(&mut self, path: PathBuf) -> Result<(), EgressError> {
        let bytes = fs::read(&path).map_err(|err| EgressError::InvalidTlsCaBundle {
            path: path.clone(),
            message: err.to_string(),
        })?;
        let certificates = reqwest::Certificate::from_pem_bundle(&bytes).map_err(|err| {
            EgressError::InvalidTlsCaBundle {
                path: path.clone(),
                message: err.to_string(),
            }
        })?;

        if certificates.is_empty() {
            return Err(EgressError::InvalidTlsCaBundle {
                path,
                message: "PEM bundle did not contain any certificates".to_owned(),
            });
        }

        self.tls_ca_bundle_path = Some(path);
        self.tls_root_certificates = certificates;
        Ok(())
    }
}

fn auto_seed_endpoint_host(
    endpoint: Option<&str>,
    allowed_hosts: &mut HashSet<String>,
    auto_seeded_hosts: &mut Vec<String>,
) {
    let Some(endpoint) = endpoint else {
        return;
    };
    let Ok(url) = Url::parse(endpoint) else {
        return;
    };
    let Some(host) = url.host_str() else {
        return;
    };

    let host = host.to_ascii_lowercase();
    if allowed_hosts.insert(host.clone()) {
        auto_seeded_hosts.push(host);
    }
}

#[derive(Debug)]
pub struct EgressResponse {
    pub status: StatusCode,
    #[allow(dead_code)] // Retained for callers that need upstream response headers.
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

pub type EgressBodyStream = Pin<Box<dyn Stream<Item = Result<Bytes, EgressError>> + Send>>;

pub struct EgressStreamResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: EgressBodyStream,
}

impl fmt::Debug for EgressStreamResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EgressStreamResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct EgressClient {
    config: EgressConfig,
    #[allow(dead_code)]
    // Base settings are validated at construction; per-request clients add DNS pins.
    base_client: reqwest::Client,
}

impl EgressClient {
    pub fn new(config: EgressConfig) -> Result<Self, EgressError> {
        let base_client = base_client_builder(&config).build()?;

        Ok(Self {
            config,
            base_client,
        })
    }

    pub async fn request(&self, method: Method, url: &str) -> Result<EgressResponse, EgressError> {
        self.request_with_headers(method, url, HeaderMap::new(), None)
            .await
    }

    pub async fn request_with_headers(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<EgressResponse, EgressError> {
        let parsed = self.checked_url(url)?;
        let host = checked_host(
            &parsed,
            &self.config.allowed_hosts,
            &self.config.allowed_host_globs,
        )?;
        let port = checked_port(&parsed)?;
        checked_policy_port(port, &self.config.allowed_ports)?;
        let resolved = resolve_host(&host, port).await?;
        let pinned_addr = checked_socket_addr(
            &host,
            &resolved,
            self.config.deny_private_ips,
            &self.config.private_ip_allow_cidrs,
        )?;
        enforce_request_body_size(
            body.as_ref().map_or(0, Vec::len),
            self.config.max_request_body_bytes,
        )?;
        let client = self.pinned_client(&host, pinned_addr)?;

        tracing::debug!(
            host = %host,
            pinned_addr = %pinned_addr,
            "egress request pinned to checked address"
        );

        self.send_with_client(client, method, parsed, headers, body)
            .await
    }

    pub async fn stream_request_with_headers(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<EgressStreamResponse, EgressError> {
        let parsed = self.checked_url(url)?;
        let host = checked_host(
            &parsed,
            &self.config.allowed_hosts,
            &self.config.allowed_host_globs,
        )?;
        let port = checked_port(&parsed)?;
        checked_policy_port(port, &self.config.allowed_ports)?;
        let resolved = resolve_host(&host, port).await?;
        let pinned_addr = checked_socket_addr(
            &host,
            &resolved,
            self.config.deny_private_ips,
            &self.config.private_ip_allow_cidrs,
        )?;
        enforce_request_body_size(
            body.as_ref().map_or(0, Vec::len),
            self.config.max_request_body_bytes,
        )?;
        let client = self.pinned_client(&host, pinned_addr)?;

        tracing::debug!(
            host = %host,
            pinned_addr = %pinned_addr,
            "egress streaming request pinned to checked address"
        );

        self.send_stream_with_client(client, method, parsed, headers, body)
            .await
    }

    fn checked_url(&self, url: &str) -> Result<Url, EgressError> {
        let parsed = Url::parse(url).map_err(|err| EgressError::InvalidUrl(err.to_string()))?;

        if parsed.host_str().is_none() {
            tracing::warn!(url = %redacted_url(&parsed), "egress blocked URL without host");
            return Err(EgressError::InvalidUrl("missing host".to_owned()));
        }

        match parsed.scheme() {
            "http" | "https" => Ok(parsed),
            scheme => {
                tracing::warn!(scheme, "egress blocked URL scheme");
                Err(EgressError::SchemeNotAllowed(scheme.to_owned()))
            }
        }
    }

    fn pinned_client(
        &self,
        host: &str,
        pinned_addr: SocketAddr,
    ) -> Result<reqwest::Client, EgressError> {
        // Per-request clients are deliberate here: reqwest DNS overrides are
        // configured on ClientBuilder, and egress is not a hot path in this PR.
        Ok(base_client_builder(&self.config)
            .resolve(host, pinned_addr)
            .build()?)
    }

    async fn send_with_client(
        &self,
        client: reqwest::Client,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<EgressResponse, EgressError> {
        let mut request = client.request(method, url).headers(headers);

        if let Some(body) = body {
            request = request.body(body);
        }

        let mut response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let mut body = Vec::new();

        while let Some(chunk) = response.chunk().await? {
            if body.len().saturating_add(chunk.len()) > self.config.max_response_bytes {
                tracing::warn!(
                    max = self.config.max_response_bytes,
                    "egress blocked oversized response"
                );
                return Err(EgressError::ResponseTooLarge {
                    max: self.config.max_response_bytes,
                });
            }

            body.extend_from_slice(&chunk);
        }

        Ok(EgressResponse {
            status,
            headers,
            body,
        })
    }

    async fn send_stream_with_client(
        &self,
        client: reqwest::Client,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<EgressStreamResponse, EgressError> {
        let mut request = client.request(method, url).headers(headers);

        if let Some(body) = body {
            request = request.body(body);
        }

        let response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let max_response_bytes = self.config.max_response_bytes;
        let response_idle_timeout = self.config.response_idle_timeout;
        let body = Box::pin(response.bytes_stream());
        let body = stream::unfold((body, 0usize, false), move |state| async move {
            let (mut body, mut streamed_bytes, done) = state;
            if done {
                return None;
            }

            match tokio::time::timeout(response_idle_timeout, body.next()).await {
                Ok(Some(Ok(chunk))) => {
                    if streamed_bytes.saturating_add(chunk.len()) > max_response_bytes {
                        tracing::warn!(
                            max = max_response_bytes,
                            "egress blocked oversized response"
                        );
                        return Some((
                            Err(EgressError::ResponseTooLarge {
                                max: max_response_bytes,
                            }),
                            (body, streamed_bytes, true),
                        ));
                    }

                    streamed_bytes += chunk.len();
                    Some((Ok(chunk), (body, streamed_bytes, false)))
                }
                Ok(Some(Err(err))) => {
                    Some((Err(EgressError::from(err)), (body, streamed_bytes, true)))
                }
                Ok(None) => None,
                Err(_) => {
                    tracing::warn!(
                        timeout_ms = response_idle_timeout.as_millis(),
                        "egress streaming response body idle timeout"
                    );
                    Some((
                        Err(EgressError::ResponseIdleTimeout {
                            timeout: response_idle_timeout,
                        }),
                        (body, streamed_bytes, true),
                    ))
                }
            }
        });

        Ok(EgressStreamResponse {
            status,
            headers,
            body: Box::pin(body),
        })
    }
}

pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let ip = u32::from(ip);

            (ip & 0xff00_0000) == 0x0a00_0000
                || (ip & 0xff00_0000) == 0x7f00_0000
                || (ip & 0xfff0_0000) == 0xac10_0000
                || (ip & 0xffff_0000) == 0xc0a8_0000
                || (ip & 0xffc0_0000) == 0x6440_0000
                || (ip & 0xffff_0000) == 0xa9fe_0000
                || (ip & 0xff00_0000) == 0x0000_0000
                // 240.0.0.0/4 is reserved and includes 255.255.255.255 broadcast.
                || (ip & 0xf000_0000) == 0xf000_0000
        }
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_private_ip(IpAddr::V4(v4));
            }

            if let Some(v4) = nat64_embedded_ipv4(ip) {
                return is_private_ip(IpAddr::V4(v4));
            }

            ip.is_unspecified()
                || ip == Ipv6Addr::LOCALHOST
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn nat64_embedded_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let segments = ip.segments();

    if segments[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        Some(Ipv4Addr::from(
            ((segments[6] as u32) << 16) | segments[7] as u32,
        ))
    } else {
        None
    }
}

fn base_client_builder(config: &EgressConfig) -> reqwest::ClientBuilder {
    let mut builder = reqwest::Client::builder()
        .timeout(config.timeout)
        .connect_timeout(config.connect_timeout)
        .redirect(reqwest::redirect::Policy::none());

    for certificate in &config.tls_root_certificates {
        builder = builder.add_root_certificate(certificate.clone());
    }

    builder
}

fn checked_host(
    url: &Url,
    allowed_hosts: &HashSet<String>,
    allowed_host_globs: &[String],
) -> Result<String, EgressError> {
    let host = url
        .host_str()
        .ok_or_else(|| EgressError::InvalidUrl("missing host".to_owned()))?
        .to_ascii_lowercase();

    // IPv6 literal URL hosts may enter the allowlist through auto-seeded
    // infrastructure endpoints. They still fail closed today because the
    // resolver is given the bracketed form, so IPv6 literal JWKS and endpoint
    // URLs remain unsupported for now.
    if allowed_hosts.contains(&host)
        || allowed_host_globs
            .iter()
            .any(|pattern| host_glob_matches(pattern, &host))
    {
        Ok(host)
    } else {
        tracing::warn!(host = %host, "egress blocked non-allowlisted host");
        Err(EgressError::HostNotAllowed(host))
    }
}

fn host_glob_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();

    if let Some(suffix) = pattern.strip_prefix("*.") {
        host.len() > suffix.len()
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
    } else {
        host == pattern
    }
}

fn checked_port(url: &Url) -> Result<u16, EgressError> {
    url.port_or_known_default()
        .ok_or_else(|| EgressError::InvalidUrl("missing port for URL scheme".to_owned()))
}

fn checked_policy_port(port: u16, allowed_ports: &HashSet<u16>) -> Result<(), EgressError> {
    if allowed_ports.is_empty() || allowed_ports.contains(&port) {
        Ok(())
    } else {
        tracing::warn!(port, "egress blocked non-allowlisted port");
        Err(EgressError::PortNotAllowed(port))
    }
}

async fn resolve_host(host: &str, port: u16) -> Result<Vec<SocketAddr>, EgressError> {
    let resolved = lookup_host((host, port))
        .await
        .map_err(|err| EgressError::DnsResolutionFailed(format!("{host}:{port}: {err}")))?
        .collect::<Vec<_>>();

    if resolved.is_empty() {
        Err(EgressError::DnsResolutionFailed(format!("{host}:{port}")))
    } else {
        Ok(resolved)
    }
}

fn checked_socket_addr(
    host: &str,
    resolved: &[SocketAddr],
    deny_private_ips: bool,
    private_ip_allow_cidrs: &[IpNet],
) -> Result<SocketAddr, EgressError> {
    if resolved.is_empty() {
        return Err(EgressError::DnsResolutionFailed(host.to_owned()));
    }

    if deny_private_ips {
        if let Some(blocked) = resolved
            .iter()
            .map(SocketAddr::ip)
            .find(|ip| is_private_ip(*ip) && !ip_matches_policy_cidr(*ip, private_ip_allow_cidrs))
        {
            tracing::warn!(
                host,
                ip = %blocked,
                "egress blocked private resolved address outside policy CIDRs"
            );
            return Err(EgressError::PrivateIpBlocked(blocked));
        }
    }

    Ok(resolved[0])
}

fn ip_matches_policy_cidr(ip: IpAddr, private_ip_allow_cidrs: &[IpNet]) -> bool {
    private_ip_allow_cidrs.iter().any(|cidr| cidr.contains(&ip))
}

fn enforce_request_body_size(size: usize, max: usize) -> Result<(), EgressError> {
    if size > max {
        tracing::warn!(size, max, "egress blocked oversized request body");
        Err(EgressError::RequestBodyTooLarge { size, max })
    } else {
        Ok(())
    }
}

fn redacted_url(url: &Url) -> String {
    let mut redacted = url.clone();
    let _ = redacted.set_username("");
    let _ = redacted.set_password(None);
    redacted.to_string()
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, io::ErrorKind, net::IpAddr, path::PathBuf, time::Duration};

    use futures_util::StreamExt;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    #[test]
    fn private_ip_detects_ipv4_loopback_range_and_adjacent_public() {
        assert!(is_private_ip(ip("127.0.0.1")));
        assert!(is_private_ip(ip("127.255.255.255")));
        assert!(!is_private_ip(ip("126.255.255.255")));
        assert!(!is_private_ip(ip("128.0.0.1")));
    }

    #[test]
    fn private_ip_detects_ipv4_ten_range_and_adjacent_public() {
        assert!(is_private_ip(ip("10.0.0.1")));
        assert!(is_private_ip(ip("10.255.255.255")));
        assert!(!is_private_ip(ip("9.255.255.255")));
        assert!(!is_private_ip(ip("11.0.0.1")));
    }

    #[test]
    fn private_ip_detects_ipv4_172_16_range_and_adjacent_public() {
        assert!(is_private_ip(ip("172.16.0.1")));
        assert!(is_private_ip(ip("172.31.255.255")));
        assert!(!is_private_ip(ip("172.15.255.255")));
        assert!(!is_private_ip(ip("172.32.0.1")));
    }

    #[test]
    fn private_ip_detects_ipv4_192_168_range_and_adjacent_public() {
        assert!(is_private_ip(ip("192.168.0.1")));
        assert!(is_private_ip(ip("192.168.255.255")));
        assert!(!is_private_ip(ip("192.167.255.255")));
        assert!(!is_private_ip(ip("192.169.0.1")));
    }

    #[test]
    fn private_ip_detects_ipv4_cgnat_range_and_adjacent_public() {
        assert!(is_private_ip(ip("100.64.0.1")));
        assert!(is_private_ip(ip("100.127.255.255")));
        assert!(!is_private_ip(ip("100.63.255.255")));
        assert!(!is_private_ip(ip("100.128.0.1")));
    }

    #[test]
    fn private_ip_detects_ipv4_link_local_range_and_adjacent_public() {
        assert!(is_private_ip(ip("169.254.0.1")));
        assert!(is_private_ip(ip("169.254.255.255")));
        assert!(!is_private_ip(ip("169.253.255.255")));
        assert!(!is_private_ip(ip("169.255.0.1")));
    }

    #[test]
    fn private_ip_detects_ipv4_zero_range_and_adjacent_public() {
        assert!(is_private_ip(ip("0.0.0.0")));
        assert!(is_private_ip(ip("0.255.255.255")));
        assert!(!is_private_ip(ip("1.0.0.0")));
    }

    #[test]
    fn private_ip_detects_ipv4_reserved_range_and_broadcast() {
        assert!(is_private_ip(ip("240.0.0.1")));
        assert!(is_private_ip(ip("255.255.255.255")));
        assert!(!is_private_ip(ip("239.255.255.255")));
    }

    #[test]
    fn private_ip_allows_public_ipv4_examples() {
        assert!(!is_private_ip(ip("8.8.8.8")));
        assert!(!is_private_ip(ip("1.1.1.1")));
    }

    #[test]
    fn private_ip_detects_ipv4_mapped_ipv6_private_addresses() {
        assert!(is_private_ip(ip("::ffff:127.0.0.1")));
        assert!(is_private_ip(ip("::ffff:169.254.169.254")));
        assert!(is_private_ip(ip("::ffff:10.0.0.1")));
        assert!(is_private_ip(ip("::ffff:192.168.1.1")));
        assert!(!is_private_ip(ip("::ffff:8.8.8.8")));
    }

    #[test]
    fn private_ip_detects_ipv6_loopback() {
        assert!(is_private_ip(ip("::1")));
        assert!(!is_private_ip(ip("::2")));
    }

    #[test]
    fn private_ip_detects_ipv6_unspecified() {
        assert!(is_private_ip(ip("::")));
    }

    #[test]
    fn private_ip_detects_ipv6_ula_range_and_adjacent_public() {
        assert!(is_private_ip(ip("fc00::1")));
        assert!(is_private_ip(ip("fdff:ffff::1")));
        assert!(!is_private_ip(ip("fbff:ffff::1")));
        assert!(!is_private_ip(ip("fe00::1")));
    }

    #[test]
    fn private_ip_detects_ipv6_link_local_range_and_adjacent_public() {
        assert!(is_private_ip(ip("fe80::1")));
        assert!(is_private_ip(ip("febf:ffff::1")));
        assert!(!is_private_ip(ip("fe7f:ffff::1")));
        assert!(!is_private_ip(ip("fec0::1")));
    }

    #[test]
    fn private_ip_detects_nat64_embedded_private_addresses() {
        assert!(is_private_ip(ip("64:ff9b::a9fe:a9fe")));
        assert!(!is_private_ip(ip("64:ff9b::808:808")));
    }

    #[test]
    fn host_glob_matching_supports_exact_and_leading_wildcard_patterns() {
        assert!(host_glob_matches("api.example.test", "api.example.test"));
        assert!(host_glob_matches("API.EXAMPLE.TEST", "api.example.test"));
        assert!(!host_glob_matches("api.example.test", "other.example.test"));

        assert!(host_glob_matches("*.example.test", "api.example.test"));
        assert!(host_glob_matches("*.example.test", "v1.api.example.test"));
        assert!(!host_glob_matches("*.example.test", "example.test"));
        assert!(!host_glob_matches("*.example.test", "badexample.test"));
    }

    #[test]
    fn policy_host_globs_extend_exact_env_allowlist() {
        let allowed_hosts = HashSet::from(["api.example.test".to_owned()]);
        let allowed_host_globs = vec!["*.svc.example.test".to_owned()];

        for url in [
            "https://api.example.test/resource",
            "https://worker.svc.example.test/resource",
            "https://v1.worker.svc.example.test/resource",
        ] {
            let url = Url::parse(url).expect("URL should parse");
            checked_host(&url, &allowed_hosts, &allowed_host_globs)
                .expect("exact env host or policy glob should allow");
        }

        let url = Url::parse("https://svc.example.test/resource").expect("URL should parse");
        let error = checked_host(&url, &allowed_hosts, &allowed_host_globs)
            .expect_err("wildcard should not match the suffix itself");

        assert!(matches!(
            error,
            EgressError::HostNotAllowed(host) if host == "svc.example.test"
        ));
    }

    #[test]
    fn cidr_matching_covers_ipv4_edges() {
        let cidrs = vec!["192.168.1.0/24".parse().expect("CIDR should parse")];

        assert!(ip_matches_policy_cidr(ip("192.168.1.0"), &cidrs));
        assert!(ip_matches_policy_cidr(ip("192.168.1.255"), &cidrs));
        assert!(!ip_matches_policy_cidr(ip("192.168.0.255"), &cidrs));
        assert!(!ip_matches_policy_cidr(ip("192.168.2.0"), &cidrs));
    }

    #[test]
    fn cidr_matching_covers_ipv6_edges() {
        let cidrs = vec!["2001:db8:abcd::/48".parse().expect("CIDR should parse")];

        assert!(ip_matches_policy_cidr(ip("2001:db8:abcd::"), &cidrs));
        assert!(ip_matches_policy_cidr(
            ip("2001:db8:abcd:ffff:ffff:ffff:ffff:ffff"),
            &cidrs
        ));
        assert!(!ip_matches_policy_cidr(
            ip("2001:db8:abcc:ffff:ffff:ffff:ffff:ffff"),
            &cidrs
        ));
        assert!(!ip_matches_policy_cidr(ip("2001:db8:abce::"), &cidrs));
    }

    #[test]
    fn policy_ports_restrict_only_when_non_empty() {
        checked_policy_port(8080, &HashSet::new())
            .expect("empty policy port set should preserve prior behavior");

        let allowed_ports = HashSet::from([443, 8443]);
        checked_policy_port(443, &allowed_ports).expect("listed port should be allowed");
        let error =
            checked_policy_port(8080, &allowed_ports).expect_err("unlisted port should be denied");

        assert!(matches!(error, EgressError::PortNotAllowed(8080)));
    }

    #[tokio::test]
    async fn request_to_disallowed_policy_port_is_blocked() {
        let client = EgressClient::new(EgressConfig {
            allowed_hosts: HashSet::from(["api.example.test".to_owned()]),
            allowed_ports: HashSet::from([443]),
            ..EgressConfig::default()
        })
        .expect("client should build");

        let error = client
            .request(Method::GET, "https://api.example.test:8443/resource")
            .await
            .expect_err("unlisted destination port should be denied");

        assert!(matches!(error, EgressError::PortNotAllowed(8443)));
    }

    #[tokio::test]
    async fn request_to_any_port_is_allowed_when_policy_ports_are_empty() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener local address should be available");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("test server should accept one connection");
            read_one_request(&stream).await;
            write_all(
                &stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            )
            .await;
        });
        let client = EgressClient::new(EgressConfig {
            allowed_hosts: HashSet::from(["127.0.0.1".to_owned()]),
            deny_private_ips: false,
            max_response_bytes: 2,
            ..EgressConfig::default()
        })
        .expect("client should build");

        let response = client
            .request(Method::GET, &format!("http://127.0.0.1:{}/", addr.port()))
            .await
            .expect("empty policy ports should not restrict the request port");

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, b"ok");
        server.await.expect("test server task should finish");
    }

    #[test]
    fn policy_cidr_exempts_only_matching_private_resolved_ips() {
        let allowed_cidrs = vec!["10.0.0.0/8".parse().expect("CIDR should parse")];
        let resolved = vec![socket("10.1.2.3:443")];
        let pinned = checked_socket_addr("internal.example.test", &resolved, true, &allowed_cidrs)
            .expect("private IP covered by policy CIDR should be allowed");

        assert_eq!(pinned, socket("10.1.2.3:443"));

        let resolved = vec![socket("192.168.1.10:443")];
        let error = checked_socket_addr("internal.example.test", &resolved, true, &allowed_cidrs)
            .expect_err("private IP outside policy CIDR should still be blocked");

        assert!(matches!(
            error,
            EgressError::PrivateIpBlocked(blocked) if blocked == ip("192.168.1.10")
        ));
    }

    #[test]
    fn no_policy_egress_section_preserves_env_only_config() {
        let mut config = test_config();
        config.egress_allowed_hosts = vec!["API.EXAMPLE.TEST".to_owned()];

        let env_only = EgressConfig::from_config(&config);
        let no_policy = EgressConfig::from_config_and_policy(&config, None)
            .expect("no policy should build egress config");
        let empty_policy =
            EgressConfig::from_config_and_policy(&config, Some(&EgressPolicy::default()))
                .expect("empty policy should build egress config");

        assert_eq!(env_only, no_policy);
        assert_eq!(env_only, empty_policy);
        assert_eq!(
            env_only.allowed_hosts,
            HashSet::from(["api.example.test".to_owned()])
        );
        assert!(env_only.allowed_host_globs.is_empty());
        assert!(env_only.private_ip_allow_cidrs.is_empty());
        assert!(env_only.allowed_ports.is_empty());
    }

    #[test]
    fn policy_egress_is_startup_snapshot_until_config_is_rebuilt() {
        let config = test_config();
        let initial_policy = EgressPolicy {
            hosts: vec!["*.initial.example.test".to_owned()],
            cidrs: vec!["10.0.0.0/8".to_owned()],
            ports: vec![443],
        };
        let updated_policy = EgressPolicy {
            hosts: vec!["*.updated.example.test".to_owned()],
            cidrs: vec!["192.168.0.0/16".to_owned()],
            ports: vec![8443],
        };

        let startup_config = EgressConfig::from_config_and_policy(&config, Some(&initial_policy))
            .expect("initial policy should build egress config");

        assert!(host_glob_matches(
            &startup_config.allowed_host_globs[0],
            "api.initial.example.test"
        ));
        assert!(!startup_config
            .allowed_host_globs
            .iter()
            .any(|pattern| host_glob_matches(pattern, "api.updated.example.test")));
        assert!(startup_config.allowed_ports.contains(&443));
        assert!(!startup_config.allowed_ports.contains(&8443));
        assert!(ip_matches_policy_cidr(
            ip("10.1.2.3"),
            &startup_config.private_ip_allow_cidrs
        ));
        assert!(!ip_matches_policy_cidr(
            ip("192.168.1.10"),
            &startup_config.private_ip_allow_cidrs
        ));

        let rebuilt_config = EgressConfig::from_config_and_policy(&config, Some(&updated_policy))
            .expect("updated policy should build egress config");

        assert!(rebuilt_config
            .allowed_host_globs
            .iter()
            .any(|pattern| host_glob_matches(pattern, "api.updated.example.test")));
        assert!(rebuilt_config.allowed_ports.contains(&8443));
        assert!(ip_matches_policy_cidr(
            ip("192.168.1.10"),
            &rebuilt_config.private_ip_allow_cidrs
        ));
    }

    #[test]
    fn empty_allowlist_denies_everything() {
        let client = EgressClient::new(EgressConfig::default()).expect("client should build");
        let url = client
            .checked_url("https://api.example.test/resource")
            .expect("URL should parse");

        let error = checked_host(
            &url,
            &client.config.allowed_hosts,
            &client.config.allowed_host_globs,
        )
        .expect_err("empty allowlist should deny");

        assert!(matches!(
            error,
            EgressError::HostNotAllowed(host) if host == "api.example.test"
        ));
    }

    #[test]
    fn from_config_auto_seeds_jwks_host_into_allowlist() {
        let mut config = test_config();
        config.jwt_jwks_url = Some("https://idp.example.test/.well-known/jwks.json".to_owned());

        let egress = EgressConfig::from_config(&config);

        assert!(egress.allowed_hosts.contains("idp.example.test"));
    }

    #[test]
    fn from_config_auto_seeds_upstream_host_into_allowlist() {
        let mut config = test_config();
        config.upstream_url = Some("https://upstream.example.test:8443/base".to_owned());

        let egress = EgressConfig::from_config(&config);

        assert!(egress.allowed_hosts.contains("upstream.example.test"));
        assert!(config.egress_allowed_hosts.is_empty());
    }

    #[test]
    fn from_config_auto_seeds_all_route_upstream_hosts_into_allowlist() {
        let mut config = test_config();
        config.upstream_routes = vec![
            crate::config::UpstreamRouteConfig {
                path_prefix: Some("/api".to_owned()),
                host: None,
                upstream_url: "https://api-upstream.example.test/base".to_owned(),
                timeout_ms: None,
                response_idle_timeout_ms: None,
                connect_timeout_ms: None,
                add_request_headers: HashMap::new(),
                strip_request_headers: Vec::new(),
                tls_ca_bundle_path: None,
            },
            crate::config::UpstreamRouteConfig {
                path_prefix: Some("/assets".to_owned()),
                host: None,
                upstream_url: "http://assets-upstream.example.test".to_owned(),
                timeout_ms: None,
                response_idle_timeout_ms: None,
                connect_timeout_ms: None,
                add_request_headers: HashMap::new(),
                strip_request_headers: Vec::new(),
                tls_ca_bundle_path: None,
            },
        ];

        let egress = EgressConfig::from_config(&config);

        assert!(egress.allowed_hosts.contains("api-upstream.example.test"));
        assert!(egress
            .allowed_hosts
            .contains("assets-upstream.example.test"));
    }

    #[test]
    fn from_config_merges_explicit_and_auto_seeded_upstream_hosts() {
        let mut config = test_config();
        config.egress_allowed_hosts = vec!["api.example.test".to_owned()];
        config.upstream_url = Some("https://upstream.example.test/base".to_owned());

        let egress = EgressConfig::from_config(&config);

        assert_eq!(egress.allowed_hosts.len(), 2);
        assert!(egress.allowed_hosts.contains("api.example.test"));
        assert!(egress.allowed_hosts.contains("upstream.example.test"));
    }

    #[test]
    fn upstream_timeout_overrides_only_replace_timeout_fields() {
        let mut config = test_config();
        config.egress_allowed_hosts = vec!["api.example.test".to_owned()];
        config.upstream_timeout_ms = Some(1500);
        config.upstream_response_idle_timeout_ms = Some(400);
        config.upstream_connect_timeout_ms = Some(300);

        let mut egress = EgressConfig::from_config(&config);
        egress.apply_upstream_timeout_overrides(&config);

        assert_eq!(egress.timeout, Duration::from_millis(1500));
        assert_eq!(egress.response_idle_timeout, Duration::from_millis(400));
        assert_eq!(egress.connect_timeout, Duration::from_millis(300));
        assert_eq!(
            egress.allowed_hosts,
            HashSet::from(["api.example.test".to_owned()])
        );
        assert_eq!(egress.max_response_bytes, config.egress_max_response_bytes);
        assert_eq!(
            egress.max_request_body_bytes,
            config.egress_max_request_body_bytes
        );
        assert!(egress.deny_private_ips);
    }

    #[tokio::test]
    async fn auto_seeded_upstream_host_still_blocks_private_ips_by_default() {
        let mut config = test_config();
        config.upstream_url = Some("http://127.0.0.1:1/".to_owned());
        let egress_config = EgressConfig::from_config(&config);
        assert!(egress_config.allowed_hosts.contains("127.0.0.1"));
        assert!(egress_config.deny_private_ips);
        let client = EgressClient::new(egress_config).expect("client should build");

        let error = client
            .stream_request_with_headers(Method::GET, "http://127.0.0.1:1/", HeaderMap::new(), None)
            .await
            .expect_err("auto-seeded private upstream should still be blocked");

        assert!(matches!(
            error,
            EgressError::PrivateIpBlocked(blocked) if blocked == ip("127.0.0.1")
        ));
    }

    #[test]
    fn host_not_in_allowlist_is_denied() {
        let allowed_hosts = HashSet::from(["api.example.test".to_owned()]);
        let url = Url::parse("https://other.example.test/resource").expect("URL should parse");
        let error =
            checked_host(&url, &allowed_hosts, &[]).expect_err("non-allowlisted host should deny");

        assert!(matches!(
            error,
            EgressError::HostNotAllowed(host) if host == "other.example.test"
        ));
    }

    #[test]
    fn scheme_other_than_http_or_https_is_denied() {
        let client = EgressClient::new(EgressConfig::default()).expect("client should build");
        let error = client
            .checked_url("ftp://api.example.test/resource")
            .expect_err("ftp scheme should deny");

        assert!(matches!(
            error,
            EgressError::SchemeNotAllowed(scheme) if scheme == "ftp"
        ));
    }

    #[test]
    fn url_without_host_is_invalid() {
        let client = EgressClient::new(EgressConfig::default()).expect("client should build");
        let error = client
            .checked_url("data:text/plain,hello")
            .expect_err("URL without host should be invalid");

        assert!(matches!(error, EgressError::InvalidUrl(_)));
    }

    #[tokio::test]
    async fn ipv6_literal_url_is_denied() {
        let config = EgressConfig {
            allowed_hosts: HashSet::from(["[::1]".to_owned()]),
            ..EgressConfig::default()
        };
        let client = EgressClient::new(config).expect("client should build");

        let result = client.request(Method::GET, "http://[::1]/").await;

        assert!(result.is_err(), "IPv6 literal URL should be denied");
    }

    #[test]
    fn any_private_resolved_ip_blocks_the_host() {
        let resolved = vec![
            socket("93.184.216.34:443"),
            socket("10.0.0.1:443"),
            socket("1.1.1.1:443"),
        ];
        let error = checked_socket_addr("api.example.test", &resolved, true, &[])
            .expect_err("mixed public and private answers should deny");

        assert!(matches!(
            error,
            EgressError::PrivateIpBlocked(blocked) if blocked == ip("10.0.0.1")
        ));
    }

    #[test]
    fn all_public_resolved_ips_select_exact_pinned_addr() {
        let resolved = vec![socket("93.184.216.34:443"), socket("1.1.1.1:443")];
        let pinned = checked_socket_addr("api.example.test", &resolved, true, &[])
            .expect("public resolved addresses should be allowed");

        assert_eq!(pinned, socket("93.184.216.34:443"));
    }

    #[test]
    fn private_resolved_ip_is_allowed_when_private_deny_is_disabled() {
        let resolved = vec![socket("10.0.0.1:443")];
        let pinned = checked_socket_addr("internal.example.test", &resolved, false, &[])
            .expect("private address should be allowed when private deny is disabled");

        assert_eq!(pinned, socket("10.0.0.1:443"));
    }

    #[test]
    fn empty_resolution_fails_closed() {
        let error = checked_socket_addr("api.example.test", &[], true, &[])
            .expect_err("empty resolution should deny");

        assert!(matches!(
            error,
            EgressError::DnsResolutionFailed(host) if host == "api.example.test"
        ));
    }

    #[test]
    fn request_body_size_is_enforced_before_send() {
        let error = enforce_request_body_size(4, 3).expect_err("oversized body should deny");

        assert!(matches!(
            error,
            EgressError::RequestBodyTooLarge { size: 4, max: 3 }
        ));
        enforce_request_body_size(3, 3).expect("body at limit should be allowed");
    }

    #[tokio::test]
    async fn pinned_client_uses_checked_socket_addr_for_connection() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener local address should be available");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("test server should accept one connection");
            read_one_request(&stream).await;
            write_all(
                &stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\npinned",
            )
            .await;
        });
        let mut config = EgressConfig {
            allowed_hosts: HashSet::from(["egress-pinned.test".to_owned()]),
            deny_private_ips: false,
            ..EgressConfig::default()
        };
        config.max_response_bytes = 6;
        let client = EgressClient::new(config).expect("client should build");
        let pinned_client = client
            .pinned_client("egress-pinned.test", addr)
            .expect("pinned client should build");
        let url = Url::parse(&format!("http://egress-pinned.test:{}/", addr.port()))
            .expect("test URL should parse");

        let response = client
            .send_with_client(pinned_client, Method::GET, url, HeaderMap::new(), None)
            .await
            .expect("pinned request should reach the test server");

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, b"pinned");
        server.await.expect("test server task should finish");
    }

    #[tokio::test]
    async fn pinned_client_uses_checked_socket_addr_with_custom_tls_roots() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener local address should be available");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("test server should accept one connection");
            read_one_request(&stream).await;
            write_all(
                &stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\ncustom tls",
            )
            .await;
        });
        let certified = rcgen::generate_simple_self_signed(vec!["egress-pinned.test".to_owned()])
            .expect("test root certificate should generate");
        let tls_root_certificates =
            reqwest::Certificate::from_pem_bundle(certified.cert.pem().as_bytes())
                .expect("test root certificate should parse");
        let config = EgressConfig {
            allowed_hosts: HashSet::from(["egress-pinned.test".to_owned()]),
            max_response_bytes: 10,
            deny_private_ips: false,
            tls_ca_bundle_path: Some(PathBuf::from("test-ca.pem")),
            tls_root_certificates,
            ..EgressConfig::default()
        };
        let client = EgressClient::new(config).expect("client should build");
        let pinned_client = client
            .pinned_client("egress-pinned.test", addr)
            .expect("pinned client should build");
        let url = Url::parse(&format!("http://egress-pinned.test:{}/", addr.port()))
            .expect("test URL should parse");

        let response = client
            .send_with_client(pinned_client, Method::GET, url, HeaderMap::new(), None)
            .await
            .expect("pinned request should reach the test server");

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, b"custom tls");
        server.await.expect("test server task should finish");
    }

    #[tokio::test]
    async fn response_body_size_is_enforced_while_streaming() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener local address should be available");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("test server should accept one connection");
            read_one_request(&stream).await;
            write_all(
                &stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\ntoo-big",
            )
            .await;
        });
        let config = EgressConfig {
            allowed_hosts: HashSet::from(["egress-pinned.test".to_owned()]),
            max_response_bytes: 6,
            deny_private_ips: false,
            ..EgressConfig::default()
        };
        let client = EgressClient::new(config).expect("client should build");
        let pinned_client = client
            .pinned_client("egress-pinned.test", addr)
            .expect("pinned client should build");
        let url = Url::parse(&format!("http://egress-pinned.test:{}/", addr.port()))
            .expect("test URL should parse");

        let error = client
            .send_with_client(pinned_client, Method::GET, url, HeaderMap::new(), None)
            .await
            .expect_err("oversized response should deny");

        assert!(matches!(error, EgressError::ResponseTooLarge { max: 6 }));
        server.await.expect("test server task should finish");
    }

    #[tokio::test]
    async fn stream_request_returns_after_headers_before_full_body() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener local address should be available");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("test server should accept one connection");
            read_one_request(&stream).await;
            write_all(
                &stream,
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n",
            )
            .await;
            tokio::time::sleep(Duration::from_millis(700)).await;
            write_all(&stream, b"5\r\nworld\r\n0\r\n\r\n").await;
        });
        let client = EgressClient::new(EgressConfig {
            allowed_hosts: HashSet::from(["127.0.0.1".to_owned()]),
            max_response_bytes: 10,
            deny_private_ips: false,
            ..EgressConfig::default()
        })
        .expect("client should build");
        let url = format!("http://127.0.0.1:{}/stream", addr.port());

        let response = tokio::time::timeout(
            Duration::from_millis(500),
            client.stream_request_with_headers(Method::GET, &url, HeaderMap::new(), None),
        )
        .await
        .expect("streaming response should return before full body is sent")
        .expect("streaming request should succeed");

        assert_eq!(response.status, StatusCode::OK);

        let mut body = response.body;
        let first = tokio::time::timeout(Duration::from_millis(200), body.next())
            .await
            .expect("first chunk should be available")
            .expect("stream should yield a first chunk")
            .expect("first chunk should be ok");
        assert_eq!(&first[..], b"hello");

        assert!(
            tokio::time::timeout(Duration::from_millis(100), body.next())
                .await
                .is_err(),
            "second chunk should not be buffered before the upstream sends it"
        );

        let second = tokio::time::timeout(Duration::from_secs(1), body.next())
            .await
            .expect("second chunk should arrive")
            .expect("stream should yield a second chunk")
            .expect("second chunk should be ok");
        assert_eq!(&second[..], b"world");

        assert!(
            tokio::time::timeout(Duration::from_millis(200), body.next())
                .await
                .expect("stream end should arrive")
                .is_none()
        );
        server.await.expect("test server task should finish");
    }

    #[tokio::test]
    async fn stream_response_body_size_is_enforced_while_consuming() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener local address should be available");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("test server should accept one connection");
            read_one_request(&stream).await;
            write_all(
                &stream,
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n",
            )
            .await;
        });
        let client = EgressClient::new(EgressConfig {
            allowed_hosts: HashSet::from(["127.0.0.1".to_owned()]),
            max_response_bytes: 5,
            deny_private_ips: false,
            ..EgressConfig::default()
        })
        .expect("client should build");
        let url = format!("http://127.0.0.1:{}/stream", addr.port());
        let response = client
            .stream_request_with_headers(Method::GET, &url, HeaderMap::new(), None)
            .await
            .expect("headers should be returned before oversized body is consumed");

        let mut body = response.body;
        let mut saw_limit_error = false;
        while let Some(chunk) = body.next().await {
            match chunk {
                Ok(_) => {}
                Err(EgressError::ResponseTooLarge { max }) => {
                    assert_eq!(max, 5);
                    saw_limit_error = true;
                    break;
                }
                Err(err) => panic!("unexpected stream error: {err}"),
            }
        }

        assert!(
            saw_limit_error,
            "stream should fail once the cap is exceeded"
        );
        server.await.expect("test server task should finish");
    }

    #[tokio::test]
    async fn stream_response_body_idle_timeout_is_enforced_while_consuming() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener local address should be available");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("test server should accept one connection");
            read_one_request(&stream).await;
            write_all(
                &stream,
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nhi\r\n",
            )
            .await;
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let client = EgressClient::new(EgressConfig {
            allowed_hosts: HashSet::from(["127.0.0.1".to_owned()]),
            timeout: Duration::from_secs(5),
            response_idle_timeout: Duration::from_millis(100),
            max_response_bytes: 10,
            deny_private_ips: false,
            ..EgressConfig::default()
        })
        .expect("client should build");
        let url = format!("http://127.0.0.1:{}/stream", addr.port());
        let response = client
            .stream_request_with_headers(Method::GET, &url, HeaderMap::new(), None)
            .await
            .expect("headers should be returned before stalled body is consumed");

        let mut body = response.body;
        let first = tokio::time::timeout(Duration::from_millis(200), body.next())
            .await
            .expect("first chunk should arrive")
            .expect("stream should yield a first chunk")
            .expect("first chunk should be ok");
        assert_eq!(&first[..], b"hi");

        let error = tokio::time::timeout(Duration::from_millis(500), body.next())
            .await
            .expect("idle timeout error should arrive before the outer test timeout")
            .expect("stream should yield an idle timeout error")
            .expect_err("stalled stream should fail");
        assert!(matches!(
            error,
            EgressError::ResponseIdleTimeout { timeout }
                if timeout == Duration::from_millis(100)
        ));
        server.abort();
    }

    #[tokio::test]
    async fn stream_request_reuses_allowlist_and_private_ip_checks() {
        let client = EgressClient::new(EgressConfig::default()).expect("client should build");
        let error = client
            .stream_request_with_headers(Method::GET, "http://127.0.0.1:1/", HeaderMap::new(), None)
            .await
            .expect_err("non-allowlisted stream host should deny");

        assert!(matches!(
            error,
            EgressError::HostNotAllowed(host) if host == "127.0.0.1"
        ));

        let client = EgressClient::new(EgressConfig {
            allowed_hosts: HashSet::from(["127.0.0.1".to_owned()]),
            deny_private_ips: true,
            ..EgressConfig::default()
        })
        .expect("client should build");
        let error = client
            .stream_request_with_headers(Method::GET, "http://127.0.0.1:1/", HeaderMap::new(), None)
            .await
            .expect_err("private stream host should deny");

        assert!(matches!(
            error,
            EgressError::PrivateIpBlocked(blocked) if blocked == ip("127.0.0.1")
        ));
    }

    async fn read_one_request(stream: &TcpStream) {
        let mut buffer = [0; 1024];

        loop {
            stream
                .readable()
                .await
                .expect("test stream should become readable");

            match stream.try_read(&mut buffer) {
                Ok(_) => return,
                Err(err) if err.kind() == ErrorKind::WouldBlock => continue,
                Err(err) => panic!("failed to read test request: {err}"),
            }
        }
    }

    async fn write_all(stream: &TcpStream, bytes: &[u8]) {
        let mut written = 0;

        while written < bytes.len() {
            stream
                .writable()
                .await
                .expect("test stream should become writable");

            match stream.try_write(&bytes[written..]) {
                Ok(0) => panic!("test stream closed before response was written"),
                Ok(count) => written += count,
                Err(err) if err.kind() == ErrorKind::WouldBlock => continue,
                Err(err) => panic!("failed to write test response: {err}"),
            }
        }
    }

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("test IP should parse")
    }

    fn socket(value: &str) -> SocketAddr {
        value.parse().expect("test socket address should parse")
    }

    fn test_config() -> Config {
        Config {
            listen_addr: "127.0.0.1:0"
                .parse()
                .expect("test listen address should parse"),
            admin_listen_addr: None,
            admin_prefix: "/admin".to_owned(),
            audit_log_file: None,
            audit_sqlite_path: None,
            audit_sqlite_retention_days: None,
            policy_file: None,
            cors_allow_origins: Vec::new(),
            max_body_size: 1_048_576,
            rate_limit_read_rps: 50.0,
            rate_limit_read_burst: 100,
            rate_limit_write_rps: 10.0,
            rate_limit_write_burst: 20,
            trust_proxy_headers: false,
            rbac_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
            session_cookie_name: String::new(),
            validation_allowed_content_types: vec!["application/json".to_owned()],
            auth_enabled: true,
            auth_mode: crate::config::AuthMode::Required,
            auth_cookie_name: "session".to_owned(),
            auth_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
            jwt_jwks_url: None,
            jwt_issuer: None,
            jwt_audience: None,
            jwt_jwks_timeout_ms: 2000,
            jwt_require_jti: false,
            roles_claim: "roles".to_owned(),
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
            upstream_timeout_ms: None,
            upstream_response_idle_timeout_ms: None,
            upstream_connect_timeout_ms: None,
            egress_allowed_hosts: Vec::new(),
            egress_timeout_ms: 30_000,
            egress_response_idle_timeout_ms: 30_000,
            egress_connect_timeout_ms: 10_000,
            egress_max_response_bytes: 5_242_880,
            egress_max_request_body_bytes: 1_048_576,
            egress_deny_private_ips: true,
        }
    }
}
