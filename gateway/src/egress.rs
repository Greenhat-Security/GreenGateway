use std::{
    collections::HashSet,
    error::Error,
    fmt, fs,
    io::{ErrorKind, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, LazyLock,
    },
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{stream, Stream, StreamExt};
use ipnet::IpNet;
use reqwest::{header::HeaderMap, Method, StatusCode, Url};
use sha2::{Digest, Sha256};
use tokio::net::lookup_host;
use zeroize::Zeroizing;

use crate::{config::Config, rbac::EgressPolicy};

// MCP's transport adapter needs the same HTTP types as the exact-pinned egress
// client. Keeping the crate alias here makes that dependency cross the egress
// boundary without creating a second, independently versioned HTTP stack.
pub(crate) use reqwest as rmcp_http;

mod client_cache;
#[cfg(test)]
mod mtls_tests;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_RESPONSE_BYTES: usize = 5 * 1024 * 1024;
const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const MAX_TLS_CA_BUNDLE_PEM_BYTES: usize = 1024 * 1024;
const MAX_TLS_CLIENT_IDENTITY_PEM_BYTES: usize = 1024 * 1024;
static PROCESS_PINNED_CLIENT_CACHE: LazyLock<Arc<client_cache::PinnedClientCache>> =
    LazyLock::new(|| Arc::new(client_cache::PinnedClientCache::new()));

// Snapshot: IANA IPv4 and IPv6 Special-Purpose Address Registries, 2026-07-14.
// Explicit global exceptions are checked before their enclosing special-use blocks.
static IPV4_GLOBAL_EXCEPTIONS: LazyLock<Vec<IpNet>> =
    LazyLock::new(|| cidr_list(&["192.0.0.9/32", "192.0.0.10/32"]));
static IPV4_NON_GLOBAL_RANGES: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    cidr_list(&[
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        // Multicast is not a unicast destination and is outside the special registry.
        "224.0.0.0/4",
        "240.0.0.0/4",
    ])
});
static IPV6_GLOBAL_EXCEPTIONS: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    cidr_list(&[
        "2001:1::1/128",
        "2001:1::2/128",
        "2001:1::3/128",
        "2001:3::/32",
        "2001:4:112::/48",
        "2001:20::/28",
        "2001:30::/28",
    ])
});
static IPV6_NON_GLOBAL_RANGES: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    cidr_list(&[
        "::/128",
        "::1/128",
        "64:ff9b:1::/48",
        "100::/64",
        "100:0:0:1::/64",
        "2001::/23",
        "2001:db8::/32",
        // 6to4 is deprecated and has conditional rather than global reachability.
        "2002::/16",
        "3fff::/20",
        "5f00::/16",
        "fc00::/7",
        "fe80::/10",
        // Deprecated site-local and multicast addresses are never valid HTTP origins.
        "fec0::/10",
        "ff00::/8",
    ])
});
static IPV6_GLOBAL_UNICAST: LazyLock<IpNet> = LazyLock::new(|| {
    "2000::/3"
        .parse()
        .expect("hard-coded global IPv6 unicast prefix should parse")
});
static WELL_KNOWN_NAT64_PREFIX: LazyLock<IpNet> = LazyLock::new(|| {
    "64:ff9b::/96"
        .parse()
        .expect("hard-coded well-known NAT64 prefix should parse")
});

#[derive(Debug)]
pub enum TlsCaBundleErrorSource {
    Path(PathBuf),
    Material,
}

impl From<PathBuf> for TlsCaBundleErrorSource {
    fn from(path: PathBuf) -> Self {
        Self::Path(path)
    }
}

impl From<&str> for TlsCaBundleErrorSource {
    fn from(path: &str) -> Self {
        Self::Path(PathBuf::from(path))
    }
}

#[derive(Debug)]
pub enum EgressError {
    HostNotAllowed(String),
    PortNotAllowed(u16),
    NonGlobalIpBlocked(IpAddr),
    InvalidPolicy(String),
    DnsResolutionFailed(String),
    InvalidUrl(String),
    SchemeNotAllowed(String),
    RequestBodyTooLarge {
        size: usize,
        max: usize,
    },
    RequestBodyReadFailed,
    UnexpectedStatus(u16),
    ResponseTooLarge {
        size: usize,
        max: usize,
    },
    ResponseIdleTimeout {
        timeout: Duration,
    },
    InvalidTlsCaBundle {
        path: TlsCaBundleErrorSource,
        message: String,
    },
    InvalidTlsClientIdentity,
    Http(reqwest::Error),
}

impl fmt::Display for EgressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostNotAllowed(host) => write!(formatter, "egress host is not allowed: {host}"),
            Self::PortNotAllowed(port) => write!(formatter, "egress port is not allowed: {port}"),
            Self::NonGlobalIpBlocked(ip) => {
                write!(formatter, "egress non-global IP is blocked: {ip}")
            }
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
            Self::RequestBodyReadFailed => {
                write!(formatter, "egress request body could not be read")
            }
            Self::UnexpectedStatus(status) => {
                write!(formatter, "egress response had unexpected status {status}")
            }
            Self::ResponseTooLarge { max, .. } => {
                write!(formatter, "egress response body exceeded {max} bytes")
            }
            Self::ResponseIdleTimeout { timeout } => write!(
                formatter,
                "egress response body was idle for {}ms",
                timeout.as_millis()
            ),
            Self::InvalidTlsCaBundle {
                path: TlsCaBundleErrorSource::Path(path),
                message,
            } => write!(
                formatter,
                "egress TLS CA bundle '{}' is invalid: {message}",
                path.display()
            ),
            Self::InvalidTlsCaBundle {
                path: TlsCaBundleErrorSource::Material,
                message,
            } => write!(formatter, "egress TLS CA bundle is invalid: {message}"),
            Self::InvalidTlsClientIdentity => {
                formatter.write_str("egress TLS client identity is invalid")
            }
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

    /// Returns a bounded classification that is safe to emit in logs and audit fields.
    ///
    /// Error display strings can contain destination or transport details and must not be
    /// treated as safe telemetry values.
    pub(crate) fn safe_category(&self) -> &'static str {
        match self {
            Self::HostNotAllowed(_) => "host_not_allowed",
            Self::PortNotAllowed(_) => "port_not_allowed",
            Self::NonGlobalIpBlocked(_) => "non_global_ip_blocked",
            Self::InvalidPolicy(_) => "invalid_policy",
            Self::DnsResolutionFailed(_) => "dns_resolution_failed",
            Self::InvalidUrl(_) => "invalid_url",
            Self::SchemeNotAllowed(_) => "scheme_not_allowed",
            Self::RequestBodyTooLarge { .. } => "request_body_too_large",
            Self::RequestBodyReadFailed => "request_body_read_failed",
            Self::UnexpectedStatus(_) => "unexpected_status",
            Self::ResponseTooLarge { .. } => "response_too_large",
            Self::ResponseIdleTimeout { .. } => "response_idle_timeout",
            Self::InvalidTlsCaBundle { .. } => "invalid_tls_ca_bundle",
            Self::InvalidTlsClientIdentity => "invalid_tls_client_identity",
            Self::Http(err) if err.is_timeout() => "http_timeout",
            Self::Http(err) if err.is_connect() => "http_connect",
            Self::Http(err) if err.is_request() => "http_request",
            Self::Http(err) if err.is_body() => "http_body",
            Self::Http(err) if err.is_decode() => "http_decode",
            Self::Http(err) if err.is_status() => "http_status",
            Self::Http(_) => "http_other",
        }
    }

    pub(crate) fn is_passive_health_failure(&self) -> bool {
        match self {
            Self::DnsResolutionFailed(_) | Self::ResponseIdleTimeout { .. } => true,
            Self::Http(error) => {
                !error.is_body() && (error.is_connect() || error.is_timeout() || error.is_request())
            }
            Self::HostNotAllowed(_)
            | Self::PortNotAllowed(_)
            | Self::NonGlobalIpBlocked(_)
            | Self::InvalidPolicy(_)
            | Self::InvalidUrl(_)
            | Self::SchemeNotAllowed(_)
            | Self::RequestBodyTooLarge { .. }
            | Self::RequestBodyReadFailed
            | Self::UnexpectedStatus(_)
            | Self::ResponseTooLarge { .. }
            | Self::InvalidTlsCaBundle { .. }
            | Self::InvalidTlsClientIdentity => false,
        }
    }

    pub(crate) fn is_retryable_transport_failure(&self) -> bool {
        match self {
            Self::ResponseIdleTimeout { .. } => true,
            Self::Http(error) if error.is_timeout() => true,
            Self::Http(error) if error.is_connect() => error_chain_has_retryable_io(error),
            // A reused HTTP/1.1 connection can disappear after selection but before
            // response headers arrive. Reqwest reports that as a request error rather
            // than a connect error. The proxy still applies its independently
            // configured safe-method and replayable-body gates before consulting this
            // transport classification.
            Self::Http(error) if error.is_request() && !error.is_body() => true,
            Self::HostNotAllowed(_)
            | Self::PortNotAllowed(_)
            | Self::NonGlobalIpBlocked(_)
            | Self::InvalidPolicy(_)
            | Self::DnsResolutionFailed(_)
            | Self::InvalidUrl(_)
            | Self::SchemeNotAllowed(_)
            | Self::RequestBodyTooLarge { .. }
            | Self::RequestBodyReadFailed
            | Self::UnexpectedStatus(_)
            | Self::ResponseTooLarge { .. }
            | Self::InvalidTlsCaBundle { .. }
            | Self::InvalidTlsClientIdentity
            | Self::Http(_) => false,
        }
    }
}

fn error_chain_has_retryable_io(error: &reqwest::Error) -> bool {
    let mut source = error.source();
    while let Some(error) = source {
        if let Some(io_error) = error.downcast_ref::<std::io::Error>() {
            return matches!(
                io_error.kind(),
                ErrorKind::ConnectionRefused
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::NotConnected
                    | ErrorKind::BrokenPipe
                    | ErrorKind::TimedOut
                    | ErrorKind::UnexpectedEof
            );
        }
        source = error.source();
    }
    false
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct EgressRequestBodySourceError;

impl fmt::Display for EgressRequestBodySourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("request body source failed")
    }
}

impl Error for EgressRequestBodySourceError {}

pub(crate) type EgressRequestBodyStream =
    Pin<Box<dyn Stream<Item = Result<Bytes, EgressRequestBodySourceError>> + Send>>;

pub(crate) enum EgressRequestBody {
    Empty,
    Buffered(Vec<u8>),
    Streaming {
        stream: EgressRequestBodyStream,
        known_length: Option<u64>,
    },
}

impl EgressRequestBody {
    pub(crate) fn streaming(stream: EgressRequestBodyStream, known_length: Option<u64>) -> Self {
        Self::Streaming {
            stream,
            known_length,
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
/// If `deny_private_ips` is true, any non-global or special-use resolved
/// address still blocks the request unless that address is explicitly covered
/// by one of the policy CIDRs. The legacy field name is retained for config
/// compatibility; policy CIDRs do not disable non-global blocking globally.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct TransportPartition([u8; 32]);

impl TransportPartition {
    fn from_opaque(value: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"greengateway:egress-transport-partition:v1\0");
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
        Self(hasher.finalize().into())
    }
}

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
    pub nat64_prefixes: Vec<IpNet>,
    pub deny_private_ips: bool,
    pub tls_ca_bundle_path: Option<PathBuf>,
    pub tls_root_certificates: Vec<reqwest::Certificate>,
    pub(crate) tls_root_set_fingerprint: [u8; 32],
    pub(crate) client_identity: Option<reqwest::Identity>,
    pub(crate) client_identity_fingerprint: Option<[u8; 32]>,
    pub(crate) transport_partition: Option<TransportPartition>,
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
            .field("nat64_prefixes", &self.nat64_prefixes)
            .field("deny_private_ips", &self.deny_private_ips)
            .field("tls_ca_bundle_path", &self.tls_ca_bundle_path)
            .field(
                "tls_root_certificate_count",
                &self.tls_root_certificates.len(),
            )
            .field(
                "client_identity_configured",
                &self.client_identity.is_some(),
            )
            .field("transport_partitioned", &self.transport_partition.is_some())
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
            && self.nat64_prefixes == other.nat64_prefixes
            && self.deny_private_ips == other.deny_private_ips
            && self.tls_ca_bundle_path == other.tls_ca_bundle_path
            && self.tls_root_certificates.len() == other.tls_root_certificates.len()
            && self.tls_root_set_fingerprint == other.tls_root_set_fingerprint
            && self.client_identity_fingerprint == other.client_identity_fingerprint
            && self.transport_partition == other.transport_partition
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
            nat64_prefixes: Vec::new(),
            deny_private_ips: true,
            tls_ca_bundle_path: None,
            tls_root_certificates: Vec::new(),
            tls_root_set_fingerprint: empty_tls_root_set_fingerprint(),
            client_identity: None,
            client_identity_fingerprint: None,
            transport_partition: None,
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
        for provider in &config.auth_providers {
            match provider.provider_type {
                crate::config::AuthProviderType::Jwt => {
                    auto_seed_endpoint_host(
                        provider.jwks_url.as_deref(),
                        &mut allowed_hosts,
                        &mut auto_seeded_hosts,
                    );
                    auto_seed_endpoint_host(
                        provider.issuer.as_deref(),
                        &mut allowed_hosts,
                        &mut auto_seeded_hosts,
                    );
                }
                crate::config::AuthProviderType::CookieSession => {
                    auto_seed_endpoint_host(
                        provider.introspection_url.as_deref(),
                        &mut allowed_hosts,
                        &mut auto_seeded_hosts,
                    );
                }
            }
        }
        auto_seed_endpoint_host(
            config.upstream_url.as_deref(),
            &mut allowed_hosts,
            &mut auto_seeded_hosts,
        );
        for route in &config.upstream_routes {
            if !route.upstream_url.is_empty() {
                auto_seed_endpoint_host(
                    Some(route.upstream_url.as_str()),
                    &mut allowed_hosts,
                    &mut auto_seeded_hosts,
                );
            }
            for endpoint in &route.upstreams {
                auto_seed_endpoint_host(
                    Some(endpoint.url.as_str()),
                    &mut allowed_hosts,
                    &mut auto_seeded_hosts,
                );
            }
        }

        if !auto_seeded_hosts.is_empty() {
            tracing::debug!(
                host_count = auto_seeded_hosts.len(),
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
            nat64_prefixes: config.egress_nat64_prefixes.clone(),
            deny_private_ips: config.egress_deny_private_ips,
            tls_ca_bundle_path: None,
            tls_root_certificates: Vec::new(),
            tls_root_set_fingerprint: empty_tls_root_set_fingerprint(),
            client_identity: None,
            client_identity_fingerprint: None,
            transport_partition: None,
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

    pub fn auto_seed_endpoint_host(&mut self, endpoint: &str) -> Option<String> {
        let mut auto_seeded_hosts = Vec::new();
        auto_seed_endpoint_host(
            Some(endpoint),
            &mut self.allowed_hosts,
            &mut auto_seeded_hosts,
        );
        auto_seeded_hosts.into_iter().next()
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

    /// Applies an opaque caller-provided partition to transport cache identity.
    ///
    /// The opaque value is domain-separated and hashed immediately. It is never
    /// retained or rendered by `Debug`.
    pub(crate) fn apply_transport_partition(&mut self, partition: &[u8]) {
        self.transport_partition = Some(TransportPartition::from_opaque(partition));
    }

    /// Applies an in-memory PEM CA bundle without retaining a source locator.
    pub(crate) fn apply_tls_ca_bundle_pem(&mut self, pem_bundle: &[u8]) -> Result<(), EgressError> {
        if pem_bundle.len() > MAX_TLS_CA_BUNDLE_PEM_BYTES {
            return Err(in_memory_tls_ca_bundle_error(
                "PEM bundle exceeds the supported size limit",
            ));
        }
        let certificates = reqwest::Certificate::from_pem_bundle(pem_bundle)
            .map_err(|_| in_memory_tls_ca_bundle_error("PEM bundle could not be parsed"))?;

        if certificates.is_empty() {
            return Err(in_memory_tls_ca_bundle_error(
                "PEM bundle did not contain any certificates",
            ));
        }

        self.tls_ca_bundle_path = None;
        self.tls_root_certificates = certificates;
        self.tls_root_set_fingerprint = tls_root_set_fingerprint(pem_bundle);
        Ok(())
    }

    pub fn apply_tls_ca_bundle_path(&mut self, path: PathBuf) -> Result<(), EgressError> {
        let bytes = fs::read(&path).map_err(|err| EgressError::InvalidTlsCaBundle {
            path: path.clone().into(),
            message: err.to_string(),
        })?;
        self.apply_tls_ca_bundle_pem(&bytes)
            .map_err(|error| with_tls_ca_bundle_path(error, &path))?;
        self.tls_ca_bundle_path = Some(path);
        Ok(())
    }

    /// Applies an in-memory combined certificate-chain and private-key PEM.
    pub(crate) fn apply_tls_client_identity_pem(
        &mut self,
        pem_identity: &[u8],
    ) -> Result<(), EgressError> {
        if pem_identity.len() > MAX_TLS_CLIENT_IDENTITY_PEM_BYTES
            || !tls_client_identity_pem_shape_is_valid(pem_identity)
        {
            return Err(EgressError::InvalidTlsClientIdentity);
        }
        let identity = reqwest::Identity::from_pem(pem_identity)
            .map_err(|_| EgressError::InvalidTlsClientIdentity)?;

        reqwest::Client::builder()
            .no_proxy()
            .identity(identity.clone())
            .build()
            .map_err(|_| EgressError::InvalidTlsClientIdentity)?;

        self.client_identity = Some(identity);
        self.client_identity_fingerprint = Some(tls_client_identity_fingerprint(pem_identity));
        Ok(())
    }

    pub fn apply_tls_client_identity_pem_path(&mut self, path: PathBuf) -> Result<(), EgressError> {
        let bytes = read_tls_client_identity_pem(&path)?;
        self.apply_tls_client_identity_pem(&bytes)
    }
}

fn in_memory_tls_ca_bundle_error(message: &str) -> EgressError {
    EgressError::InvalidTlsCaBundle {
        path: TlsCaBundleErrorSource::Material,
        message: message.to_owned(),
    }
}

fn with_tls_ca_bundle_path(error: EgressError, path: &Path) -> EgressError {
    match error {
        EgressError::InvalidTlsCaBundle { message, .. } => EgressError::InvalidTlsCaBundle {
            path: path.to_path_buf().into(),
            message,
        },
        error => error,
    }
}

fn read_tls_client_identity_pem(path: &Path) -> Result<Vec<u8>, EgressError> {
    let metadata = fs::metadata(path).map_err(|_| EgressError::InvalidTlsClientIdentity)?;
    if !metadata.is_file() || metadata.len() > MAX_TLS_CLIENT_IDENTITY_PEM_BYTES as u64 {
        return Err(EgressError::InvalidTlsClientIdentity);
    }

    let file = fs::File::open(path).map_err(|_| EgressError::InvalidTlsClientIdentity)?;
    let metadata = file
        .metadata()
        .map_err(|_| EgressError::InvalidTlsClientIdentity)?;
    if !metadata.is_file() || metadata.len() > MAX_TLS_CLIENT_IDENTITY_PEM_BYTES as u64 {
        return Err(EgressError::InvalidTlsClientIdentity);
    }

    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(MAX_TLS_CLIENT_IDENTITY_PEM_BYTES)
            .min(MAX_TLS_CLIENT_IDENTITY_PEM_BYTES),
    );
    file.take(MAX_TLS_CLIENT_IDENTITY_PEM_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| EgressError::InvalidTlsClientIdentity)?;
    if bytes.len() > MAX_TLS_CLIENT_IDENTITY_PEM_BYTES {
        return Err(EgressError::InvalidTlsClientIdentity);
    }

    Ok(bytes)
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

pub(crate) struct SensitiveEgressResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for SensitiveEgressResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveEgressResponse")
            .field("status", &self.status)
            .field("headers", &"<redacted>")
            .field("body", &"<redacted>")
            .finish()
    }
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
    resolver: Arc<dyn DnsResolver>,
    config_generation: [u8; 32],
    policy_generation: [u8; 32],
    client_cache: Arc<client_cache::PinnedClientCache>,
}

#[async_trait]
pub(crate) trait DnsResolver: Send + Sync {
    /// Returns the complete DNS answer set in resolver order.
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, std::io::Error>;
}

#[derive(Debug, Default)]
pub(crate) struct SystemDnsResolver;

#[async_trait]
impl DnsResolver for SystemDnsResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
        Ok(lookup_host((host, port)).await?.collect())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CheckedEgressDestination {
    scheme: String,
    pub host: String,
    pub pinned_addr: SocketAddr,
    config_generation: [u8; 32],
    policy_generation: [u8; 32],
}

impl fmt::Debug for CheckedEgressDestination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CheckedEgressDestination")
            .field("scheme", &self.scheme)
            .field("host", &self.host)
            .field("pinned_addr", &self.pinned_addr)
            .finish_non_exhaustive()
    }
}

impl CheckedEgressDestination {
    #[cfg(test)]
    pub(crate) fn for_test(host: impl Into<String>, pinned_addr: SocketAddr) -> Self {
        Self {
            scheme: "http".to_owned(),
            host: host.into(),
            pinned_addr,
            config_generation: [0; 32],
            policy_generation: [0; 32],
        }
    }
}

impl EgressClient {
    pub(crate) fn request_timeout(&self) -> Duration {
        self.config.timeout
    }

    pub(crate) fn response_idle_timeout(&self) -> Duration {
        self.config.response_idle_timeout
    }

    pub(crate) fn connect_timeout(&self) -> Duration {
        self.config.connect_timeout
    }

    pub(crate) fn max_request_body_bytes(&self) -> usize {
        self.config.max_request_body_bytes
    }

    pub(crate) fn max_response_bytes(&self) -> usize {
        self.config.max_response_bytes
    }

    pub(crate) fn configuration_generation(&self) -> [u8; 32] {
        self.config_generation
    }

    #[cfg(test)]
    pub(crate) fn client_identity_fingerprint(&self) -> Option<[u8; 32]> {
        self.config.client_identity_fingerprint
    }

    pub fn new(config: EgressConfig) -> Result<Self, EgressError> {
        Self::new_with_resolver(config, Arc::new(SystemDnsResolver))
    }

    pub(crate) fn new_with_resolver(
        config: EgressConfig,
        resolver: Arc<dyn DnsResolver>,
    ) -> Result<Self, EgressError> {
        Self::new_with_resolver_and_cache(
            config,
            resolver,
            Arc::clone(&PROCESS_PINNED_CLIENT_CACHE),
        )
    }

    fn new_with_resolver_and_cache(
        config: EgressConfig,
        resolver: Arc<dyn DnsResolver>,
        client_cache: Arc<client_cache::PinnedClientCache>,
    ) -> Result<Self, EgressError> {
        // Validate the complete transport profile at construction. Actual
        // exact-pinned clients are created lazily after DNS validation.
        base_client_builder(&config).build()?;
        let config_generation = egress_config_generation(&config);
        let policy_generation = egress_policy_generation(&config);

        Ok(Self {
            config,
            resolver,
            config_generation,
            policy_generation,
            client_cache,
        })
    }

    pub(crate) fn reconfigured(&self, config: EgressConfig) -> Result<Self, EgressError> {
        Self::new_with_resolver_and_cache(
            config,
            Arc::clone(&self.resolver),
            Arc::clone(&self.client_cache),
        )
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
        enforce_request_body_size(
            body.as_ref().map_or(0, Vec::len),
            self.config.max_request_body_bytes,
        )?;
        let destination = self.checked_destination(url).await?;
        self.request_with_headers_at_checked_destination(&destination, method, url, headers, body)
            .await
    }

    pub async fn checked_destination(
        &self,
        url: &str,
    ) -> Result<CheckedEgressDestination, EgressError> {
        let parsed = self.checked_url(url)?;
        let host = checked_host(
            &parsed,
            &self.config.allowed_hosts,
            &self.config.allowed_host_globs,
        )?;
        let port = checked_port(&parsed)?;
        checked_policy_port(port, &self.config.allowed_ports)?;
        let pinned_addr = self.resolve_and_check(&host, port).await?;

        Ok(CheckedEgressDestination {
            scheme: parsed.scheme().to_owned(),
            host,
            pinned_addr,
            config_generation: self.config_generation,
            policy_generation: self.policy_generation,
        })
    }

    /// Rebinds an already checked exact destination to this client's transport profile.
    ///
    /// This performs no DNS lookup. It succeeds only when the destination was
    /// checked under the exact same effective egress policy and still matches
    /// the supplied request authority. The pinned socket is revalidated before
    /// it receives this client's configuration generation.
    pub(crate) fn rebind_checked_destination(
        &self,
        destination: &CheckedEgressDestination,
        url: &str,
    ) -> Result<CheckedEgressDestination, EgressError> {
        if destination.policy_generation != self.policy_generation {
            return Err(EgressError::InvalidPolicy(
                "checked destination belongs to a different egress policy".to_owned(),
            ));
        }

        let parsed = self.checked_url(url)?;
        let host = checked_host(
            &parsed,
            &self.config.allowed_hosts,
            &self.config.allowed_host_globs,
        )?;
        let port = checked_port(&parsed)?;
        checked_policy_port(port, &self.config.allowed_ports)?;
        if destination.scheme != parsed.scheme()
            || destination.host != host
            || destination.pinned_addr.port() != port
        {
            return Err(EgressError::InvalidPolicy(
                "checked destination does not match the request authority".to_owned(),
            ));
        }
        checked_socket_addr(
            &host,
            &[destination.pinned_addr],
            self.config.deny_private_ips,
            &self.config.nat64_prefixes,
            &self.config.private_ip_allow_cidrs,
        )?;

        Ok(CheckedEgressDestination {
            scheme: destination.scheme.clone(),
            host: destination.host.clone(),
            pinned_addr: destination.pinned_addr,
            config_generation: self.config_generation,
            policy_generation: self.policy_generation,
        })
    }

    /// Returns the shared exact-pinned client for MCP's long-lived SSE profile.
    ///
    /// Authority, policy, socket, and configuration binding are rechecked
    /// before the cached client is selected. Request and response bounds remain
    /// the responsibility of the Egress-backed MCP adapter.
    pub(crate) fn mcp_reqwest_client_at_checked_destination(
        &self,
        destination: &CheckedEgressDestination,
        url: &str,
    ) -> Result<reqwest::Client, EgressError> {
        let (_, client) = self.client_for_checked_destination(destination, url, true)?;
        Ok(client)
    }

    pub(crate) async fn request_with_headers_at_checked_destination(
        &self,
        destination: &CheckedEgressDestination,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<EgressResponse, EgressError> {
        enforce_request_body_size(
            body.as_ref().map_or(0, Vec::len),
            self.config.max_request_body_bytes,
        )?;
        let (parsed, client) = self.client_for_checked_destination(destination, url, false)?;

        tracing::debug!("egress request using previously validated pinned destination");

        self.send_with_client(client, method, parsed, headers, body)
            .await
    }

    pub(crate) async fn sensitive_request_with_headers_at_checked_destination(
        &self,
        destination: &CheckedEgressDestination,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<SensitiveEgressResponse, EgressError> {
        enforce_request_body_size(
            body.as_ref().map_or(0, Vec::len),
            self.config.max_request_body_bytes,
        )?;
        let (parsed, client) = self.client_for_checked_destination(destination, url, false)?;

        tracing::debug!("sensitive egress request using previously validated pinned destination");

        self.send_sensitive_with_client(client, method, parsed, headers, body)
            .await
    }

    #[cfg(test)]
    pub async fn stream_request_with_headers(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<EgressStreamResponse, EgressError> {
        let body = body.map_or(EgressRequestBody::Empty, EgressRequestBody::Buffered);
        self.stream_request_with_body(method, url, headers, body)
            .await
    }

    pub(crate) async fn stream_request_with_body(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: EgressRequestBody,
    ) -> Result<EgressStreamResponse, EgressError> {
        self.stream_request_with_body_policy(method, url, headers, body, None)
            .await
    }

    pub(crate) async fn stream_request_with_body_for_sse(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: EgressRequestBody,
        max_response_bytes: Option<usize>,
    ) -> Result<EgressStreamResponse, EgressError> {
        self.stream_request_with_body_policy(method, url, headers, body, Some(max_response_bytes))
            .await
    }

    async fn stream_request_with_body_policy(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: EgressRequestBody,
        sse_max_response_bytes: Option<Option<usize>>,
    ) -> Result<EgressStreamResponse, EgressError> {
        body.enforce_known_size(self.config.max_request_body_bytes)?;
        let destination = self.checked_destination(url).await?;
        self.stream_request_with_body_at_checked_destination_policy(
            &destination,
            method,
            url,
            headers,
            body,
            sse_max_response_bytes,
        )
        .await
    }

    pub(crate) async fn stream_request_with_body_at_checked_destination(
        &self,
        destination: &CheckedEgressDestination,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: EgressRequestBody,
    ) -> Result<EgressStreamResponse, EgressError> {
        self.stream_request_with_body_at_checked_destination_policy(
            destination,
            method,
            url,
            headers,
            body,
            None,
        )
        .await
    }

    pub(crate) async fn stream_request_with_body_for_sse_at_checked_destination(
        &self,
        destination: &CheckedEgressDestination,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: EgressRequestBody,
        max_response_bytes: Option<usize>,
    ) -> Result<EgressStreamResponse, EgressError> {
        self.stream_request_with_body_at_checked_destination_policy(
            destination,
            method,
            url,
            headers,
            body,
            Some(max_response_bytes),
        )
        .await
    }

    async fn stream_request_with_body_at_checked_destination_policy(
        &self,
        destination: &CheckedEgressDestination,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: EgressRequestBody,
        sse_max_response_bytes: Option<Option<usize>>,
    ) -> Result<EgressStreamResponse, EgressError> {
        body.enforce_known_size(self.config.max_request_body_bytes)?;
        let (parsed, client) = self.client_for_checked_destination(
            destination,
            url,
            sse_max_response_bytes.is_some(),
        )?;

        tracing::debug!("egress streaming request using previously validated pinned destination");

        self.send_stream_with_client(
            client,
            method,
            parsed,
            headers,
            body,
            sse_max_response_bytes,
        )
        .await
    }

    fn client_for_checked_destination(
        &self,
        destination: &CheckedEgressDestination,
        url: &str,
        sse: bool,
    ) -> Result<(Url, reqwest::Client), EgressError> {
        if destination.config_generation != self.config_generation {
            return Err(EgressError::InvalidPolicy(
                "checked destination belongs to a different egress configuration".to_owned(),
            ));
        }
        let parsed = self.checked_url(url)?;
        let host = checked_host(
            &parsed,
            &self.config.allowed_hosts,
            &self.config.allowed_host_globs,
        )?;
        let port = checked_port(&parsed)?;
        checked_policy_port(port, &self.config.allowed_ports)?;
        if destination.scheme != parsed.scheme()
            || destination.host != host
            || destination.pinned_addr.port() != port
        {
            return Err(EgressError::InvalidPolicy(
                "checked destination does not match the request authority".to_owned(),
            ));
        }
        checked_socket_addr(
            &host,
            &[destination.pinned_addr],
            self.config.deny_private_ips,
            &self.config.nat64_prefixes,
            &self.config.private_ip_allow_cidrs,
        )?;
        let client =
            self.pinned_client_with_profile(&parsed, &host, destination.pinned_addr, sse)?;
        Ok((parsed, client))
    }

    fn checked_url(&self, url: &str) -> Result<Url, EgressError> {
        let parsed = Url::parse(url).map_err(|err| EgressError::InvalidUrl(err.to_string()))?;

        if parsed.host_str().is_none() {
            tracing::warn!(
                error_category = "invalid_url",
                "egress blocked URL without host"
            );
            return Err(EgressError::InvalidUrl("missing host".to_owned()));
        }

        match parsed.scheme() {
            "http" | "https" => Ok(parsed),
            scheme => {
                tracing::warn!(
                    error_category = "scheme_not_allowed",
                    "egress blocked URL scheme"
                );
                Err(EgressError::SchemeNotAllowed(scheme.to_owned()))
            }
        }
    }

    fn pinned_client_with_profile(
        &self,
        url: &Url,
        host: &str,
        pinned_addr: SocketAddr,
        sse: bool,
    ) -> Result<reqwest::Client, EgressError> {
        let port = checked_port(url)?;
        let key = client_cache::PinnedClientCacheKey {
            scheme: url.scheme().to_owned(),
            host: host.to_owned(),
            port,
            pinned_addr,
            egress_generation: self.config_generation,
            request_timeout: self.config.timeout,
            response_idle_timeout: self.config.response_idle_timeout,
            connect_timeout: self.config.connect_timeout,
            tls_root_set_fingerprint: self.config.tls_root_set_fingerprint,
            client_identity_fingerprint: self.config.client_identity_fingerprint,
            transport_partition: self.config.transport_partition,
            protocol_profile: if sse {
                client_cache::ProtocolProfile::Sse
            } else {
                client_cache::ProtocolProfile::Http1AndHttp2
            },
            outbound_proxy_policy: client_cache::OutboundProxyPolicy::Disabled,
        };

        self.client_cache.get_or_build(key, || {
            Ok(base_client_builder_for_profile(&self.config, sse)
                .resolve(host, pinned_addr)
                .build()?)
        })
    }

    #[cfg(test)]
    fn pinned_client(
        &self,
        url: &Url,
        host: &str,
        pinned_addr: SocketAddr,
    ) -> Result<reqwest::Client, EgressError> {
        self.pinned_client_with_profile(url, host, pinned_addr, false)
    }

    async fn resolve_and_check(&self, host: &str, port: u16) -> Result<SocketAddr, EgressError> {
        let resolved = self
            .resolver
            .resolve(host, port)
            .await
            .map_err(|err| EgressError::DnsResolutionFailed(format!("{host}:{port}: {err}")))?;

        if resolved.is_empty() {
            return Err(EgressError::DnsResolutionFailed(format!("{host}:{port}")));
        }
        if resolved.iter().any(|address| address.port() != port) {
            return Err(EgressError::DnsResolutionFailed(format!(
                "{host}:{port}: resolver returned an unexpected port"
            )));
        }

        checked_socket_addr(
            host,
            &resolved,
            self.config.deny_private_ips,
            &self.config.nat64_prefixes,
            &self.config.private_ip_allow_cidrs,
        )
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
                    size: body.len().saturating_add(chunk.len()),
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

    async fn send_sensitive_with_client(
        &self,
        client: reqwest::Client,
        method: Method,
        url: Url,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<SensitiveEgressResponse, EgressError> {
        let mut request = client.request(method, url).headers(headers);

        if let Some(body) = body {
            request = request.body(body);
        }

        let mut response = request.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        let mut body = Zeroizing::new(Vec::new());

        while let Some(chunk) = response.chunk().await? {
            if body.len().saturating_add(chunk.len()) > self.config.max_response_bytes {
                tracing::warn!(
                    max = self.config.max_response_bytes,
                    "egress blocked oversized sensitive response"
                );
                return Err(EgressError::ResponseTooLarge {
                    size: body.len().saturating_add(chunk.len()),
                    max: self.config.max_response_bytes,
                });
            }

            body.extend_from_slice(&chunk);
        }

        Ok(SensitiveEgressResponse {
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
        body: EgressRequestBody,
        sse_max_response_bytes: Option<Option<usize>>,
    ) -> Result<EgressStreamResponse, EgressError> {
        let mut request = client.request(method, url).headers(headers);
        let body_failure = Arc::new(AtomicU8::new(REQUEST_BODY_OK));
        match body {
            EgressRequestBody::Empty => {}
            EgressRequestBody::Buffered(body) => request = request.body(body),
            EgressRequestBody::Streaming { stream, .. } => {
                let stream = counted_request_body_stream(
                    stream,
                    self.config.max_request_body_bytes,
                    Arc::clone(&body_failure),
                );
                request = request.body(reqwest::Body::wrap_stream(stream));
            }
        }

        let response =
            request
                .send()
                .await
                .map_err(|error| match body_failure.load(Ordering::Acquire) {
                    REQUEST_BODY_TOO_LARGE => EgressError::RequestBodyTooLarge {
                        size: self.config.max_request_body_bytes.saturating_add(1),
                        max: self.config.max_request_body_bytes,
                    },
                    REQUEST_BODY_READ_FAILED => EgressError::RequestBodyReadFailed,
                    _ => EgressError::Http(error),
                })?;
        let status = response.status();
        let headers = response.headers().clone();
        let max_response_bytes =
            sse_max_response_bytes.unwrap_or(Some(self.config.max_response_bytes));
        let response_idle_timeout = self.config.response_idle_timeout;
        let body = Box::pin(response.bytes_stream());
        let body = stream::unfold((body, 0usize, false), move |state| async move {
            let (mut body, mut streamed_bytes, done) = state;
            if done {
                return None;
            }

            match tokio::time::timeout(response_idle_timeout, body.next()).await {
                Ok(Some(Ok(chunk))) => {
                    if max_response_bytes
                        .is_some_and(|maximum| streamed_bytes.saturating_add(chunk.len()) > maximum)
                    {
                        tracing::warn!(
                            max = max_response_bytes.unwrap_or_default(),
                            "egress blocked oversized response"
                        );
                        return Some((
                            Err(EgressError::ResponseTooLarge {
                                size: streamed_bytes.saturating_add(chunk.len()),
                                max: max_response_bytes.unwrap_or_default(),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Nat64Address {
    NotNat64,
    Embedded(Ipv4Addr),
    Malformed,
}

fn cidr_list(values: &[&str]) -> Vec<IpNet> {
    values
        .iter()
        .map(|value| {
            value
                .parse()
                .expect("hard-coded special-purpose CIDR should parse")
        })
        .collect()
}

pub fn is_non_global_ip(ip: IpAddr, nat64_prefixes: &[IpNet]) -> bool {
    match ip {
        IpAddr::V4(ip) => is_non_global_ipv4(ip),
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_non_global_ipv4(v4);
            }

            match classify_nat64_address(ip, nat64_prefixes) {
                Nat64Address::Embedded(v4) => return is_non_global_ipv4(v4),
                Nat64Address::Malformed => return true,
                Nat64Address::NotNat64 => {}
            }

            let ip = IpAddr::V6(ip);
            if IPV6_GLOBAL_EXCEPTIONS
                .iter()
                .any(|prefix| prefix.contains(&ip))
            {
                return false;
            }

            IPV6_NON_GLOBAL_RANGES
                .iter()
                .any(|prefix| prefix.contains(&ip))
                || !IPV6_GLOBAL_UNICAST.contains(&ip)
        }
    }
}

fn is_non_global_ipv4(ip: Ipv4Addr) -> bool {
    let ip = IpAddr::V4(ip);
    if IPV4_GLOBAL_EXCEPTIONS
        .iter()
        .any(|prefix| prefix.contains(&ip))
    {
        return false;
    }

    IPV4_NON_GLOBAL_RANGES
        .iter()
        .any(|prefix| prefix.contains(&ip))
}

fn classify_nat64_address(ip: Ipv6Addr, configured_prefixes: &[IpNet]) -> Nat64Address {
    let ip_addr = IpAddr::V6(ip);
    let prefix = if WELL_KNOWN_NAT64_PREFIX.contains(&ip_addr) {
        Some(&*WELL_KNOWN_NAT64_PREFIX)
    } else {
        configured_prefixes
            .iter()
            .find(|prefix| prefix.contains(&ip_addr))
    };

    let Some(prefix) = prefix else {
        return Nat64Address::NotNat64;
    };

    match extract_rfc6052_ipv4(ip, prefix.prefix_len()) {
        Some(v4) => Nat64Address::Embedded(v4),
        None => Nat64Address::Malformed,
    }
}

fn extract_rfc6052_ipv4(ip: Ipv6Addr, prefix_len: u8) -> Option<Ipv4Addr> {
    let bits = u128::from(ip);
    if !matches!(prefix_len, 32 | 40 | 48 | 56 | 64 | 96) || ip.octets()[8] != 0 {
        return None;
    }
    if prefix_len == 96 {
        return Some(Ipv4Addr::from(bits as u32));
    }

    let leading_bits = 64 - prefix_len;
    let trailing_bits = 32 - leading_bits;
    let leading = if leading_bits == 0 {
        0
    } else {
        ((bits >> 64) & ((1_u128 << leading_bits) - 1)) as u32
    };
    let trailing = if trailing_bits == 0 {
        0
    } else {
        let shift = 128 - (72 + trailing_bits);
        ((bits >> shift) & ((1_u128 << trailing_bits) - 1)) as u32
    };

    let value = ((leading as u64) << trailing_bits) | trailing as u64;
    Some(Ipv4Addr::from(value as u32))
}

fn base_client_builder(config: &EgressConfig) -> reqwest::ClientBuilder {
    base_client_builder_for_profile(config, false)
}

fn base_client_builder_for_profile(config: &EgressConfig, sse: bool) -> reqwest::ClientBuilder {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(config.connect_timeout)
        .pool_idle_timeout(Some(client_cache::CLIENT_POOL_IDLE_TIMEOUT))
        .pool_max_idle_per_host(client_cache::CLIENT_POOL_MAX_IDLE_PER_HOST)
        .tcp_keepalive(Some(client_cache::CLIENT_TCP_KEEPALIVE))
        .redirect(reqwest::redirect::Policy::none());
    if !sse {
        builder = builder.timeout(config.timeout);
    }

    for certificate in &config.tls_root_certificates {
        builder = builder.add_root_certificate(certificate.clone());
    }
    if let Some(identity) = &config.client_identity {
        builder = builder.identity(identity.clone());
    }

    builder
}

fn empty_tls_root_set_fingerprint() -> [u8; 32] {
    tls_root_set_fingerprint(&[])
}

fn tls_root_set_fingerprint(pem_bundle: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"greengateway:tls-root-set:v1\0");
    hasher.update((pem_bundle.len() as u64).to_be_bytes());
    hasher.update(pem_bundle);
    hasher.finalize().into()
}

fn tls_client_identity_fingerprint(pem_identity: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"greengateway:tls-client-identity:v1\0");
    hasher.update((pem_identity.len() as u64).to_be_bytes());
    hasher.update(pem_identity);
    hasher.finalize().into()
}

fn tls_client_identity_pem_shape_is_valid(pem_identity: &[u8]) -> bool {
    let Ok(pem_identity) = std::str::from_utf8(pem_identity) else {
        return false;
    };
    let certificate_count = pem_identity.matches("-----BEGIN CERTIFICATE-----").count();
    let private_key_count = [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
    ]
    .into_iter()
    .map(|label| pem_identity.matches(label).count())
    .sum::<usize>();

    certificate_count >= 1 && private_key_count == 1
}

pub(crate) fn tls_ca_bundle_pem_is_valid(pem_bundle: &[u8]) -> bool {
    let Ok(certificates) = reqwest::Certificate::from_pem_bundle(pem_bundle) else {
        return false;
    };
    if certificates.is_empty() {
        return false;
    }

    certificates
        .into_iter()
        .fold(
            reqwest::Client::builder().no_proxy(),
            |builder, certificate| builder.add_root_certificate(certificate),
        )
        .build()
        .is_ok()
}

pub(crate) fn tls_client_identity_pem_is_valid(pem_identity: &[u8]) -> bool {
    if !tls_client_identity_pem_shape_is_valid(pem_identity) {
        return false;
    }
    let Ok(identity) = reqwest::Identity::from_pem(pem_identity) else {
        return false;
    };
    reqwest::Client::builder()
        .no_proxy()
        .identity(identity)
        .build()
        .is_ok()
}

fn egress_config_generation(config: &EgressConfig) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"greengateway:egress-config-generation:v2\0");
    hash_egress_policy(&mut hasher, config);

    hash_duration(&mut hasher, config.timeout);
    hash_duration(&mut hasher, config.response_idle_timeout);
    hash_duration(&mut hasher, config.connect_timeout);
    hasher.update((config.max_response_bytes as u64).to_be_bytes());
    hasher.update((config.max_request_body_bytes as u64).to_be_bytes());
    hasher.update(config.tls_root_set_fingerprint);
    match config.client_identity_fingerprint {
        Some(fingerprint) => {
            hasher.update([1]);
            hasher.update(fingerprint);
        }
        None => hasher.update([0]),
    }
    match config.transport_partition {
        Some(partition) => {
            hasher.update([1]);
            hasher.update(partition.0);
        }
        None => hasher.update([0]),
    }

    hasher.finalize().into()
}

fn egress_policy_generation(config: &EgressConfig) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"greengateway:egress-policy-generation:v1\0");
    hash_egress_policy(&mut hasher, config);
    hasher.finalize().into()
}

fn hash_egress_policy(hasher: &mut Sha256, config: &EgressConfig) {
    let mut allowed_hosts: Vec<_> = config.allowed_hosts.iter().collect();
    allowed_hosts.sort_unstable();
    hash_strings(hasher, allowed_hosts.into_iter().map(String::as_str));

    let mut allowed_host_globs: Vec<_> = config
        .allowed_host_globs
        .iter()
        .map(String::as_str)
        .collect();
    allowed_host_globs.sort_unstable();
    hash_strings(hasher, allowed_host_globs);

    let mut private_cidrs: Vec<_> = config
        .private_ip_allow_cidrs
        .iter()
        .map(ToString::to_string)
        .collect();
    private_cidrs.sort_unstable();
    hash_strings(hasher, private_cidrs.iter().map(String::as_str));

    let mut allowed_ports: Vec<_> = config.allowed_ports.iter().copied().collect();
    allowed_ports.sort_unstable();
    hasher.update((allowed_ports.len() as u64).to_be_bytes());
    for port in allowed_ports {
        hasher.update(port.to_be_bytes());
    }

    let mut nat64_prefixes: Vec<_> = config
        .nat64_prefixes
        .iter()
        .map(ToString::to_string)
        .collect();
    nat64_prefixes.sort_unstable();
    hash_strings(hasher, nat64_prefixes.iter().map(String::as_str));
    hasher.update([u8::from(config.deny_private_ips)]);
}

fn hash_strings<'a>(hasher: &mut Sha256, values: impl IntoIterator<Item = &'a str>) {
    let values: Vec<_> = values.into_iter().collect();
    hasher.update((values.len() as u64).to_be_bytes());
    for value in values {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }
}

fn hash_duration(hasher: &mut Sha256, duration: Duration) {
    hasher.update(duration.as_secs().to_be_bytes());
    hasher.update(duration.subsec_nanos().to_be_bytes());
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
        tracing::warn!(
            error_category = "host_not_allowed",
            "egress blocked non-allowlisted host"
        );
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
        tracing::warn!(
            error_category = "port_not_allowed",
            "egress blocked non-allowlisted port"
        );
        Err(EgressError::PortNotAllowed(port))
    }
}

fn checked_socket_addr(
    host: &str,
    resolved: &[SocketAddr],
    deny_private_ips: bool,
    nat64_prefixes: &[IpNet],
    private_ip_allow_cidrs: &[IpNet],
) -> Result<SocketAddr, EgressError> {
    if resolved.is_empty() {
        return Err(EgressError::DnsResolutionFailed(host.to_owned()));
    }

    if deny_private_ips {
        if let Some(blocked) = resolved.iter().map(SocketAddr::ip).find(|ip| {
            is_non_global_ip(*ip, nat64_prefixes)
                && !ip_matches_policy_cidr(*ip, private_ip_allow_cidrs)
        }) {
            tracing::warn!(
                error_category = "non_global_ip_blocked",
                "egress blocked non-global resolved address outside policy CIDRs"
            );
            return Err(EgressError::NonGlobalIpBlocked(blocked));
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

const REQUEST_BODY_OK: u8 = 0;
const REQUEST_BODY_TOO_LARGE: u8 = 1;
const REQUEST_BODY_READ_FAILED: u8 = 2;

impl EgressRequestBody {
    fn enforce_known_size(&self, max: usize) -> Result<(), EgressError> {
        match self {
            Self::Empty => Ok(()),
            Self::Buffered(body) => enforce_request_body_size(body.len(), max),
            Self::Streaming {
                known_length: Some(size),
                ..
            } if *size > max as u64 => {
                let size = usize::try_from(*size).unwrap_or(usize::MAX);
                enforce_request_body_size(size, max)
            }
            Self::Streaming { .. } => Ok(()),
        }
    }
}

struct CountedRequestBodyState {
    stream: EgressRequestBodyStream,
    streamed_bytes: usize,
    overflow_pending: bool,
}

fn counted_request_body_stream(
    stream: EgressRequestBodyStream,
    max: usize,
    failure: Arc<AtomicU8>,
) -> impl Stream<Item = Result<Bytes, EgressRequestBodySourceError>> + Send {
    stream::unfold(
        CountedRequestBodyState {
            stream,
            streamed_bytes: 0,
            overflow_pending: false,
        },
        move |mut state| {
            let failure = Arc::clone(&failure);
            async move {
                if state.overflow_pending {
                    failure.store(REQUEST_BODY_TOO_LARGE, Ordering::Release);
                    return Some((Err(EgressRequestBodySourceError), state));
                }

                match state.stream.next().await {
                    Some(Ok(chunk)) => {
                        let remaining = max.saturating_sub(state.streamed_bytes);
                        if chunk.len() <= remaining {
                            state.streamed_bytes += chunk.len();
                            Some((Ok(chunk), state))
                        } else if remaining == 0 {
                            failure.store(REQUEST_BODY_TOO_LARGE, Ordering::Release);
                            Some((Err(EgressRequestBodySourceError), state))
                        } else {
                            state.streamed_bytes = max;
                            state.overflow_pending = true;
                            Some((Ok(chunk.slice(..remaining)), state))
                        }
                    }
                    Some(Err(_)) => {
                        failure.store(REQUEST_BODY_READ_FAILED, Ordering::Release);
                        Some((Err(EgressRequestBodySourceError), state))
                    }
                    None => None,
                }
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, VecDeque},
        io::{self, ErrorKind},
        net::IpAddr,
        path::PathBuf,
        process::Command,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Mutex,
        },
        time::Duration,
    };

    use futures_util::StreamExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

    #[tokio::test]
    async fn request_phase_disconnect_is_a_retryable_transport_failure() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("test connection");
            let mut request = vec![0_u8; 4096];
            let _ = stream.read(&mut request).await;
            // Close without response headers, modelling a pooled upstream that
            // disappears while an otherwise replay-safe request is in flight.
        });

        let error = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("test client")
            .get(format!("http://{address}/disconnect"))
            .send()
            .await
            .expect_err("closed upstream should fail before response headers");
        server.await.expect("test server should finish");

        assert!(error.is_request());
        assert!(!error.is_connect());
        assert!(EgressError::Http(error).is_retryable_transport_failure());
    }

    #[tokio::test]
    async fn counted_stream_allows_exact_limit_with_backpressure() {
        let source_polls = Arc::new(AtomicUsize::new(0));
        let polls = Arc::clone(&source_polls);
        let source = stream::iter([Bytes::from_static(b"ab"), Bytes::from_static(b"cd")])
            .inspect(move |_| {
                polls.fetch_add(1, Ordering::SeqCst);
            })
            .map(Ok);
        let failure = Arc::new(AtomicU8::new(REQUEST_BODY_OK));
        let counted = counted_request_body_stream(Box::pin(source), 4, Arc::clone(&failure));
        futures_util::pin_mut!(counted);

        assert_eq!(
            counted.next().await.expect("first chunk").expect("success"),
            Bytes::from_static(b"ab")
        );
        assert_eq!(source_polls.load(Ordering::SeqCst), 1);
        assert_eq!(
            counted
                .next()
                .await
                .expect("second chunk")
                .expect("success"),
            Bytes::from_static(b"cd")
        );
        assert!(counted.next().await.is_none());
        assert_eq!(failure.load(Ordering::Acquire), REQUEST_BODY_OK);
    }

    #[tokio::test]
    async fn counted_stream_caps_underdeclared_or_chunked_body_before_error() {
        let source = stream::iter([
            Ok(Bytes::from_static(b"abc")),
            Ok(Bytes::from_static(b"def")),
        ]);
        let failure = Arc::new(AtomicU8::new(REQUEST_BODY_OK));
        let counted = counted_request_body_stream(Box::pin(source), 4, Arc::clone(&failure));
        futures_util::pin_mut!(counted);

        assert_eq!(
            counted.next().await.expect("first chunk").expect("success"),
            Bytes::from_static(b"abc")
        );
        assert_eq!(
            counted
                .next()
                .await
                .expect("bounded partial chunk")
                .expect("success"),
            Bytes::from_static(b"d")
        );
        assert!(counted.next().await.expect("overflow marker").is_err());
        assert_eq!(failure.load(Ordering::Acquire), REQUEST_BODY_TOO_LARGE);
    }

    #[tokio::test]
    async fn known_stream_length_over_limit_fails_before_dns_or_dial() {
        let resolver = Arc::new(FakeDnsResolver::with_addresses(vec![socket(
            "93.184.216.34:80",
        )]));
        let mut config = egress_config_for_host("api.example.test");
        config.max_request_body_bytes = 3;
        let client =
            EgressClient::new_with_resolver(config, resolver.clone()).expect("client should build");
        let body = EgressRequestBody::streaming(Box::pin(stream::empty()), Some(4));

        let result = client
            .stream_request_with_body(
                Method::POST,
                "http://api.example.test/",
                HeaderMap::new(),
                body,
            )
            .await;

        assert!(matches!(
            result,
            Err(EgressError::RequestBodyTooLarge { size: 4, max: 3 })
        ));
        assert!(resolver.calls().is_empty());
    }

    #[tokio::test]
    async fn dropping_counted_stream_cancels_and_drops_its_source() {
        struct DropSignal(Arc<AtomicBool>);

        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let guard = DropSignal(Arc::clone(&dropped));
        let source = stream::unfold(Some(guard), |state| async move {
            let _state = state;
            std::future::pending::<
                Option<(
                    Result<Bytes, EgressRequestBodySourceError>,
                    Option<DropSignal>,
                )>,
            >()
            .await
        });
        let failure = Arc::new(AtomicU8::new(REQUEST_BODY_OK));
        let counted = counted_request_body_stream(Box::pin(source), 4, failure);

        drop(counted);

        assert!(dropped.load(Ordering::SeqCst));
    }

    #[derive(Clone)]
    enum FakeResolution {
        Addresses(Vec<SocketAddr>),
        Error(ErrorKind),
    }

    struct FakeDnsResolver {
        resolution: FakeResolution,
        calls: Mutex<Vec<(String, u16)>>,
    }

    impl FakeDnsResolver {
        fn with_addresses(addresses: Vec<SocketAddr>) -> Self {
            Self {
                resolution: FakeResolution::Addresses(addresses),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn with_error(kind: ErrorKind) -> Self {
            Self {
                resolution: FakeResolution::Error(kind),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<(String, u16)> {
            self.calls
                .lock()
                .expect("fake resolver calls lock should not be poisoned")
                .clone()
        }
    }

    #[async_trait]
    impl DnsResolver for FakeDnsResolver {
        async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
            self.calls
                .lock()
                .expect("fake resolver calls lock should not be poisoned")
                .push((host.to_owned(), port));

            match &self.resolution {
                FakeResolution::Addresses(addresses) => Ok(addresses.clone()),
                FakeResolution::Error(kind) => {
                    Err(std::io::Error::new(*kind, "synthetic DNS failure"))
                }
            }
        }
    }

    struct SequencedDnsResolver {
        resolutions: Mutex<VecDeque<FakeResolution>>,
        calls: AtomicUsize,
    }

    impl SequencedDnsResolver {
        fn new(resolutions: impl IntoIterator<Item = FakeResolution>) -> Self {
            Self {
                resolutions: Mutex::new(resolutions.into_iter().collect()),
                calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl DnsResolver for SequencedDnsResolver {
        async fn resolve(
            &self,
            _host: &str,
            _port: u16,
        ) -> Result<Vec<SocketAddr>, std::io::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let resolution = self
                .resolutions
                .lock()
                .expect("sequenced resolver lock should not be poisoned")
                .pop_front()
                .expect("test resolver should have one resolution per call");
            match resolution {
                FakeResolution::Addresses(addresses) => Ok(addresses),
                FakeResolution::Error(kind) => {
                    Err(std::io::Error::new(kind, "synthetic DNS failure"))
                }
            }
        }
    }

    fn egress_config_for_host(host: &str) -> EgressConfig {
        EgressConfig {
            allowed_hosts: HashSet::from([host.to_owned()]),
            ..EgressConfig::default()
        }
    }

    #[test]
    fn egress_generation_is_order_independent_and_change_sensitive() {
        let mut first = EgressConfig {
            allowed_hosts: HashSet::from([
                "a.example.test".to_owned(),
                "b.example.test".to_owned(),
            ]),
            allowed_host_globs: vec!["*.one.example".to_owned(), "*.two.example".to_owned()],
            private_ip_allow_cidrs: vec![
                "10.0.0.0/8".parse().expect("first CIDR should parse"),
                "192.168.0.0/16".parse().expect("second CIDR should parse"),
            ],
            allowed_ports: HashSet::from([443, 8443]),
            nat64_prefixes: vec![
                "64:ff9b:1::/48"
                    .parse()
                    .expect("first NAT64 prefix should parse"),
                "2001:db8:64::/96"
                    .parse()
                    .expect("second NAT64 prefix should parse"),
            ],
            ..EgressConfig::default()
        };
        let mut second = first.clone();
        second.allowed_host_globs.reverse();
        second.private_ip_allow_cidrs.reverse();
        second.nat64_prefixes.reverse();

        assert_eq!(
            egress_config_generation(&first),
            egress_config_generation(&second),
            "semantically unordered policy collections should hash identically"
        );

        first.connect_timeout += Duration::from_millis(1);
        assert_ne!(
            egress_config_generation(&first),
            egress_config_generation(&second),
            "transport-relevant changes must produce another generation"
        );

        first = second.clone();
        first.client_identity_fingerprint = Some([7; 32]);
        assert_ne!(
            egress_config_generation(&first),
            egress_config_generation(&second),
            "client identity changes must produce another egress generation"
        );
    }

    #[test]
    fn in_memory_tls_material_is_validated_without_retaining_or_rendering_input() {
        let certified =
            rcgen::generate_simple_self_signed(vec!["tls-material.example.test".to_owned()])
                .expect("test certificate should generate");
        let ca_pem = certified.cert.pem();
        let identity_pem = format!("{}{}", ca_pem, certified.key_pair.serialize_pem());

        let mut config = EgressConfig {
            tls_ca_bundle_path: Some(PathBuf::from("old-locator-canary.pem")),
            ..EgressConfig::default()
        };
        config
            .apply_tls_ca_bundle_pem(ca_pem.as_bytes())
            .expect("in-memory CA bundle should be accepted");
        config
            .apply_tls_client_identity_pem(identity_pem.as_bytes())
            .expect("in-memory combined identity should be accepted");

        assert!(config.tls_ca_bundle_path.is_none());
        assert!(!config.tls_root_certificates.is_empty());
        assert!(config.client_identity.is_some());
        assert!(config.client_identity_fingerprint.is_some());
        let debug = format!("{config:?}");
        assert!(!debug.contains("old-locator-canary"));
        assert!(!debug.contains("BEGIN CERTIFICATE"));
        assert!(!debug.contains("BEGIN PRIVATE KEY"));
        assert!(!debug.contains("tls_root_set_fingerprint"));
        assert!(!debug.contains("client_identity_fingerprint"));

        let invalid_ca = b"TOP_SECRET_INVALID_CA_MATERIAL";
        let ca_error = EgressConfig::default()
            .apply_tls_ca_bundle_pem(invalid_ca)
            .expect_err("invalid in-memory CA material must fail");
        let rendered_ca_error = format!("{ca_error:?}\n{ca_error}");
        assert_eq!(ca_error.safe_category(), "invalid_tls_ca_bundle");
        assert!(!rendered_ca_error.contains(std::str::from_utf8(invalid_ca).expect("ASCII marker")));
        assert!(!rendered_ca_error.contains("memory"));

        let invalid_identity = b"TOP_SECRET_INVALID_IDENTITY_MATERIAL";
        let identity_error = EgressConfig::default()
            .apply_tls_client_identity_pem(invalid_identity)
            .expect_err("invalid in-memory identity material must fail");
        let rendered_identity_error = format!("{identity_error:?}\n{identity_error}");
        assert_eq!(
            identity_error.safe_category(),
            "invalid_tls_client_identity"
        );
        assert!(!rendered_identity_error
            .contains(std::str::from_utf8(invalid_identity).expect("ASCII marker")));

        let ca_path = std::env::temp_dir().join(format!(
            "greengateway-in-memory-ca-delegation-{}.pem",
            uuid::Uuid::new_v4()
        ));
        fs::write(&ca_path, ca_pem.as_bytes()).expect("test CA file should be written");
        let mut from_path = EgressConfig::default();
        from_path
            .apply_tls_ca_bundle_path(ca_path.clone())
            .expect("path CA setter should delegate to the PEM validator");
        assert_eq!(from_path.tls_ca_bundle_path.as_ref(), Some(&ca_path));
        assert_eq!(
            from_path.tls_root_set_fingerprint,
            config.tls_root_set_fingerprint
        );
        let _ = fs::remove_file(ca_path);
    }

    #[test]
    fn opaque_transport_partition_changes_transport_but_not_policy_identity() {
        let base = egress_config_for_host("partition.example.test");
        let mut first = base.clone();
        first.apply_transport_partition(b"connection-partition-a-canary");
        let mut same = base.clone();
        same.apply_transport_partition(b"connection-partition-a-canary");
        let mut different = base.clone();
        different.apply_transport_partition(b"connection-partition-b-canary");

        assert_ne!(base, first);
        assert_eq!(first, same);
        assert_ne!(first, different);
        assert_eq!(
            egress_policy_generation(&first),
            egress_policy_generation(&different),
            "transport partitioning must not alter effective egress policy"
        );
        assert_eq!(
            egress_config_generation(&first),
            egress_config_generation(&same)
        );
        assert_ne!(
            egress_config_generation(&first),
            egress_config_generation(&different)
        );

        let debug = format!("{first:?}");
        assert!(debug.contains("transport_partitioned: true"));
        assert!(!debug.contains("transport_partition:"));
        assert!(!debug.contains("connection-partition-a-canary"));
    }

    #[tokio::test]
    async fn rebind_adopts_only_same_policy_and_authority_without_dns() {
        let resolver = Arc::new(FakeDnsResolver::with_addresses(vec![socket("8.8.8.8:443")]));
        let base_config = EgressConfig {
            allowed_hosts: HashSet::from([
                "rebind.example.test".to_owned(),
                "other.example.test".to_owned(),
            ]),
            ..EgressConfig::default()
        };
        let client = isolated_egress_client(base_config.clone(), resolver.clone());
        let url = "https://rebind.example.test/resource";
        let destination = client
            .checked_destination(url)
            .await
            .expect("initial egress policy and DNS check should succeed");

        let mut transport_config = base_config.clone();
        transport_config.timeout += Duration::from_secs(1);
        transport_config.apply_transport_partition(b"reconfigured-transport");
        let reconfigured = client
            .reconfigured(transport_config)
            .expect("transport-only reconfiguration should build");

        assert_eq!(
            destination.policy_generation,
            reconfigured.policy_generation
        );
        assert_ne!(
            destination.config_generation,
            reconfigured.config_generation
        );
        let rebound = reconfigured
            .rebind_checked_destination(&destination, url)
            .expect("same-policy exact destination should be rebound");
        assert_eq!(rebound.pinned_addr, destination.pinned_addr);
        assert_eq!(rebound.config_generation, reconfigured.config_generation);
        assert_eq!(
            resolver.calls(),
            vec![("rebind.example.test".to_owned(), 443)],
            "rebind must not perform DNS"
        );

        reconfigured
            .mcp_reqwest_client_at_checked_destination(&rebound, url)
            .expect("rebound destination should select an MCP-safe pinned client");
        reconfigured
            .mcp_reqwest_client_at_checked_destination(&rebound, url)
            .expect("identical MCP transport should reuse the pinned client");
        assert_eq!(reconfigured.client_cache.len(), 1);
        assert_eq!(
            resolver.calls().len(),
            1,
            "cached MCP client selection must not perform DNS"
        );

        let old_generation_error = reconfigured
            .mcp_reqwest_client_at_checked_destination(&destination, url)
            .expect_err("an un-rebound destination must not cross configurations");
        assert!(matches!(
            old_generation_error,
            EgressError::InvalidPolicy(_)
        ));

        let authority_error = reconfigured
            .rebind_checked_destination(&destination, "https://other.example.test/resource")
            .expect_err("rebind must not authorize another authority");
        assert!(matches!(authority_error, EgressError::InvalidPolicy(_)));

        let mut changed_policy = base_config;
        changed_policy
            .allowed_hosts
            .insert("policy-change.example.test".to_owned());
        let changed_policy_client = client
            .reconfigured(changed_policy)
            .expect("changed-policy client should build");
        let policy_error = changed_policy_client
            .rebind_checked_destination(&destination, url)
            .expect_err("destination must not cross effective egress policies");
        assert!(matches!(policy_error, EgressError::InvalidPolicy(_)));

        let mut tampered_destination = destination;
        tampered_destination.pinned_addr = socket("10.0.0.1:443");
        let socket_error = reconfigured
            .rebind_checked_destination(&tampered_destination, url)
            .expect_err("pinned socket must be revalidated without DNS");
        assert!(matches!(
            socket_error,
            EgressError::NonGlobalIpBlocked(blocked) if blocked == ip("10.0.0.1")
        ));
        assert_eq!(resolver.calls().len(), 1);

        let destination_debug = format!("{rebound:?}");
        assert!(!destination_debug.contains("generation"));
        assert!(!destination_debug.contains("transport_partition"));
    }

    fn isolated_egress_client(
        config: EgressConfig,
        resolver: Arc<dyn DnsResolver>,
    ) -> EgressClient {
        EgressClient::new_with_resolver_and_cache(
            config,
            resolver,
            Arc::new(client_cache::PinnedClientCache::new()),
        )
        .expect("isolated test client should build")
    }

    #[test]
    fn egress_error_safe_categories_are_bounded_constants() {
        let errors = vec![
            (
                EgressError::HostNotAllowed("secret-host".to_owned()),
                "host_not_allowed",
            ),
            (EgressError::PortNotAllowed(1234), "port_not_allowed"),
            (
                EgressError::NonGlobalIpBlocked(ip("127.0.0.1")),
                "non_global_ip_blocked",
            ),
            (
                EgressError::InvalidPolicy("secret-policy".to_owned()),
                "invalid_policy",
            ),
            (
                EgressError::DnsResolutionFailed("secret-dns-detail".to_owned()),
                "dns_resolution_failed",
            ),
            (
                EgressError::InvalidUrl("secret-url".to_owned()),
                "invalid_url",
            ),
            (
                EgressError::SchemeNotAllowed("secret-scheme".to_owned()),
                "scheme_not_allowed",
            ),
            (
                EgressError::RequestBodyTooLarge { size: 2, max: 1 },
                "request_body_too_large",
            ),
            (
                EgressError::ResponseTooLarge { size: 2, max: 1 },
                "response_too_large",
            ),
            (
                EgressError::ResponseIdleTimeout {
                    timeout: Duration::from_millis(1),
                },
                "response_idle_timeout",
            ),
            (
                EgressError::InvalidTlsCaBundle {
                    path: PathBuf::from("secret-ca-path").into(),
                    message: "secret-ca-error".to_owned(),
                },
                "invalid_tls_ca_bundle",
            ),
            (
                EgressError::InvalidTlsClientIdentity,
                "invalid_tls_client_identity",
            ),
        ];

        for (error, expected) in errors {
            let category = error.safe_category();
            assert_eq!(category, expected);
            assert!(category.len() <= 32);
            assert!(
                category
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
                "unsafe category characters in {category}"
            );
            assert!(!category.contains("secret"));
        }

        let http_error = reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("test client should build")
            .get("http://[")
            .build()
            .expect_err("invalid URL should create a reqwest error");
        let http_category = EgressError::Http(http_error).safe_category();
        assert!(matches!(
            http_category,
            "http_timeout"
                | "http_connect"
                | "http_request"
                | "http_body"
                | "http_decode"
                | "http_status"
                | "http_other"
        ));
    }

    #[test]
    fn mounted_tls_client_identity_is_validated_and_redacted() {
        let key = rcgen::KeyPair::generate().expect("test identity key should generate");
        let certificate = rcgen::CertificateParams::new(vec!["client.example.test".to_owned()])
            .expect("test identity parameters should build")
            .self_signed(&key)
            .expect("test identity certificate should build");
        let valid_pem = format!("{}{}", certificate.pem(), key.serialize_pem());
        let valid_path = std::env::temp_dir().join(format!(
            "greengateway-valid-client-identity-{}.pem",
            uuid::Uuid::new_v4()
        ));
        fs::write(&valid_path, valid_pem.as_bytes())
            .expect("valid test identity should be written");

        let mut config = EgressConfig::default();
        config
            .apply_tls_client_identity_pem_path(valid_path.clone())
            .expect("matching certificate and key should be accepted");
        assert!(config.client_identity.is_some());
        assert!(config.client_identity_fingerprint.is_some());
        let debug = format!("{config:?}");
        assert!(debug.contains("client_identity_configured: true"));
        assert!(!debug.contains("BEGIN CERTIFICATE"));
        assert!(!debug.contains("BEGIN PRIVATE KEY"));

        let other_key =
            rcgen::KeyPair::generate().expect("mismatched test identity key should generate");
        let mismatched_pem = format!("{}{}", certificate.pem(), other_key.serialize_pem());
        let mismatched_path = std::env::temp_dir().join(format!(
            "greengateway-mismatched-client-identity-{}.pem",
            uuid::Uuid::new_v4()
        ));
        fs::write(&mismatched_path, mismatched_pem.as_bytes())
            .expect("mismatched test identity should be written");

        let error = EgressConfig::default()
            .apply_tls_client_identity_pem_path(mismatched_path.clone())
            .expect_err("a certificate and unrelated private key must fail startup validation");
        assert_eq!(error.safe_category(), "invalid_tls_client_identity");
        let rendered = format!("{error:?}\n{error}");
        assert!(!rendered.contains("BEGIN CERTIFICATE"));
        assert!(!rendered.contains("BEGIN PRIVATE KEY"));
        assert!(!rendered.contains(&other_key.serialize_pem()));

        let duplicate_key_pem = format!("{valid_pem}{}", key.serialize_pem());
        let duplicate_key_path = std::env::temp_dir().join(format!(
            "greengateway-duplicate-client-key-{}.pem",
            uuid::Uuid::new_v4()
        ));
        fs::write(&duplicate_key_path, duplicate_key_pem.as_bytes())
            .expect("duplicate-key test identity should be written");
        EgressConfig::default()
            .apply_tls_client_identity_pem_path(duplicate_key_path.clone())
            .expect_err("an identity PEM with multiple private keys must fail validation");

        let secret_marker = "TOP_SECRET_CLIENT_IDENTITY_BYTES";
        let invalid_path = std::env::temp_dir().join(format!(
            "greengateway-invalid-client-identity-{}.pem",
            uuid::Uuid::new_v4()
        ));
        fs::write(&invalid_path, secret_marker).expect("invalid test identity should be written");
        let error = EgressConfig::default()
            .apply_tls_client_identity_pem_path(invalid_path.clone())
            .expect_err("non-PEM identity bytes must fail startup validation");
        assert!(!format!("{error:?}\n{error}").contains(secret_marker));

        let oversized_path = std::env::temp_dir().join(format!(
            "greengateway-oversized-client-identity-{}.pem",
            uuid::Uuid::new_v4()
        ));
        fs::write(
            &oversized_path,
            vec![b'x'; MAX_TLS_CLIENT_IDENTITY_PEM_BYTES + 1],
        )
        .expect("oversized test identity should be written");
        let error = EgressConfig::default()
            .apply_tls_client_identity_pem_path(oversized_path.clone())
            .expect_err("an oversized identity PEM must fail bounded startup validation");
        assert_eq!(error.safe_category(), "invalid_tls_client_identity");
        assert!(!format!("{error:?}\n{error}").contains(
            oversized_path
                .file_name()
                .expect("oversized test file should have a name")
                .to_string_lossy()
                .as_ref()
        ));

        let _ = fs::remove_file(valid_path);
        let _ = fs::remove_file(mismatched_path);
        let _ = fs::remove_file(duplicate_key_path);
        let _ = fs::remove_file(invalid_path);
        let _ = fs::remove_file(oversized_path);
    }

    #[test]
    fn rejected_scheme_log_exposes_only_a_bounded_category() {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(logs.clone())
            .finish();
        let _guard = crate::tracing_test_guard(subscriber);
        let client = EgressClient::new(EgressConfig::default())
            .expect("scheme log test client should build");

        // Touch the rejection callsite once while our subscriber is installed.
        // `rebuild_interest_cache` only revisits callsites that have already
        // registered, and this one is reached by many other egress tests -- if
        // one of them registers it first with no subscriber in place, tracing
        // caches `Interest::never` for every thread and the assertion below
        // fails for reasons that have nothing to do with the rejection path.
        let _ = client.checked_url("warmup-scheme://warmup.invalid/warmup");
        logs.clear();

        let error = client
            .checked_url("secret-scheme://secret-host.example/private?token=secret-query")
            .expect_err("unsupported URL scheme should fail closed");
        assert!(matches!(error, EgressError::SchemeNotAllowed(_)));
        drop(_guard);

        let output = logs.contents();
        assert!(output.contains("scheme_not_allowed"));
        for secret in ["secret-scheme", "secret-host", "private", "secret-query"] {
            assert!(
                !output.contains(secret),
                "scheme rejection log leaked {secret}: {output}"
            );
        }
    }

    #[test]
    fn sensitive_response_debug_redacts_headers_and_body() {
        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::WWW_AUTHENTICATE,
            reqwest::header::HeaderValue::from_static("Bearer realm=\"challenge-canary\""),
        );
        let response = SensitiveEgressResponse {
            status: StatusCode::UNAUTHORIZED,
            headers,
            body: Zeroizing::new(b"access-token-canary".to_vec()),
        };

        let rendered = format!("{response:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("challenge-canary"));
        assert!(!rendered.contains("access-token-canary"));
    }

    #[tokio::test]
    async fn injected_resolver_preserves_answer_order_and_records_host_and_port() {
        let resolver = Arc::new(FakeDnsResolver::with_addresses(vec![
            socket("8.8.8.8:8443"),
            socket("1.1.1.1:8443"),
        ]));
        let client = EgressClient::new_with_resolver(
            egress_config_for_host("api.example.test"),
            resolver.clone(),
        )
        .expect("client should build");

        let destination = client
            .checked_destination("https://api.example.test:8443/resource")
            .await
            .expect("public answer set should be accepted");

        assert_eq!(destination.host, "api.example.test");
        assert_eq!(destination.pinned_addr, socket("8.8.8.8:8443"));
        assert_eq!(
            resolver.calls(),
            vec![("api.example.test".to_owned(), 8443)]
        );
    }

    #[tokio::test]
    async fn every_dns_path_rejects_a_mixed_public_and_private_answer_set() {
        let resolver = Arc::new(FakeDnsResolver::with_addresses(vec![
            socket("8.8.8.8:443"),
            socket("10.0.0.8:443"),
        ]));
        let client = EgressClient::new_with_resolver(
            egress_config_for_host("api.example.test"),
            resolver.clone(),
        )
        .expect("client should build");

        let destination_error = client
            .checked_destination("https://api.example.test/resource")
            .await
            .expect_err("destination check should reject a mixed answer set");
        let request_error = client
            .request_with_headers(
                Method::GET,
                "https://api.example.test/resource",
                HeaderMap::new(),
                None,
            )
            .await
            .expect_err("buffered request should reject a mixed answer set");
        let stream_error = client
            .stream_request_with_headers(
                Method::GET,
                "https://api.example.test/resource",
                HeaderMap::new(),
                None,
            )
            .await
            .expect_err("streaming request should reject a mixed answer set");

        for error in [destination_error, request_error, stream_error] {
            assert!(matches!(
                error,
                EgressError::NonGlobalIpBlocked(blocked) if blocked == ip("10.0.0.8")
            ));
        }
        assert_eq!(
            resolver.calls(),
            vec![("api.example.test".to_owned(), 443); 3]
        );
    }

    #[tokio::test]
    async fn injected_resolver_empty_answer_fails_closed() {
        let resolver = Arc::new(FakeDnsResolver::with_addresses(Vec::new()));
        let client =
            EgressClient::new_with_resolver(egress_config_for_host("empty.example.test"), resolver)
                .expect("client should build");

        let error = client
            .checked_destination("https://empty.example.test/resource")
            .await
            .expect_err("empty DNS answers should deny");

        assert!(matches!(
            error,
            EgressError::DnsResolutionFailed(message)
                if message == "empty.example.test:443"
        ));
    }

    #[tokio::test]
    async fn injected_resolver_error_fails_closed() {
        let resolver = Arc::new(FakeDnsResolver::with_error(ErrorKind::TimedOut));
        let client =
            EgressClient::new_with_resolver(egress_config_for_host("error.example.test"), resolver)
                .expect("client should build");

        let error = client
            .checked_destination("https://error.example.test:8443/resource")
            .await
            .expect_err("resolver errors should deny");

        assert!(matches!(
            error,
            EgressError::DnsResolutionFailed(message)
                if message.starts_with("error.example.test:8443:")
        ));
    }

    #[tokio::test]
    async fn injected_resolver_wrong_port_fails_closed() {
        let resolver = Arc::new(FakeDnsResolver::with_addresses(vec![socket(
            "8.8.8.8:9443",
        )]));
        let client =
            EgressClient::new_with_resolver(egress_config_for_host("port.example.test"), resolver)
                .expect("client should build");

        let error = client
            .checked_destination("https://port.example.test:8443/resource")
            .await
            .expect_err("resolver answers for a different port should deny");

        assert!(matches!(
            error,
            EgressError::DnsResolutionFailed(message)
                if message.starts_with("port.example.test:8443:")
        ));
    }

    #[tokio::test]
    async fn reconfigured_client_preserves_injected_resolver() {
        let resolver = Arc::new(FakeDnsResolver::with_addresses(vec![socket("8.8.8.8:443")]));
        let client = EgressClient::new_with_resolver(
            egress_config_for_host("first.example.test"),
            resolver.clone(),
        )
        .expect("client should build");
        client
            .checked_destination("https://first.example.test/resource")
            .await
            .expect("original client should use injected resolver");

        let reconfigured = client
            .reconfigured(egress_config_for_host("second.example.test"))
            .expect("reconfigured client should build");
        reconfigured
            .checked_destination("https://second.example.test/resource")
            .await
            .expect("reconfigured client should retain injected resolver");

        assert_eq!(
            resolver.calls(),
            vec![
                ("first.example.test".to_owned(), 443),
                ("second.example.test".to_owned(), 443),
            ]
        );
    }

    #[tokio::test]
    async fn egress_client_sends_directly_with_proxy_discovery_disabled() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("direct test listener should bind");
        let addr = listener
            .local_addr()
            .expect("direct listener address should be available");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("direct server should accept one connection");
            read_one_request(&stream).await;
            write_all(
                &stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndirect",
            )
            .await;
        });
        let client = EgressClient::new(EgressConfig {
            allowed_hosts: HashSet::from(["127.0.0.1".to_owned()]),
            deny_private_ips: false,
            timeout: Duration::from_secs(2),
            connect_timeout: Duration::from_millis(500),
            max_response_bytes: 6,
            ..EgressConfig::default()
        })
        .expect("client should build");

        let response = client
            .request(Method::GET, &format!("http://{addr}/"))
            .await
            .expect("ambient proxy settings must not intercept egress");

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, b"direct");
        server.await.expect("direct server should finish");
    }

    #[tokio::test]
    async fn checked_destination_send_reuses_one_dns_decision_and_rejects_mismatches() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("checked-destination listener should bind");
        let addr = listener
            .local_addr()
            .expect("checked-destination address should be available");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("checked-destination server should accept one connection");
            read_one_request(&stream).await;
            write_all(
                &stream,
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            )
            .await;
        });
        let resolver = Arc::new(FakeDnsResolver::with_addresses(vec![addr]));
        let config = EgressConfig {
            allowed_hosts: HashSet::from([
                "checked.example.test".to_owned(),
                "other.example.test".to_owned(),
            ]),
            deny_private_ips: false,
            timeout: Duration::from_secs(2),
            connect_timeout: Duration::from_millis(500),
            ..EgressConfig::default()
        };
        let client = EgressClient::new_with_resolver(config.clone(), resolver.clone())
            .expect("checked-destination client should build");
        let url = format!("http://checked.example.test:{}/resource", addr.port());
        let destination = client
            .checked_destination(&url)
            .await
            .expect("destination should pass one DNS and policy check");

        let response = client
            .request_with_headers_at_checked_destination(
                &destination,
                Method::GET,
                &url,
                HeaderMap::new(),
                None,
            )
            .await
            .expect("checked destination should send without another DNS lookup");
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            resolver.calls(),
            vec![("checked.example.test".to_owned(), addr.port())]
        );
        server
            .await
            .expect("checked-destination server should finish");

        let authority_error = client
            .request_with_headers_at_checked_destination(
                &destination,
                Method::GET,
                &format!("http://other.example.test:{}/resource", addr.port()),
                HeaderMap::new(),
                None,
            )
            .await
            .expect_err("a checked destination must not authorize another authority");
        assert!(matches!(authority_error, EgressError::InvalidPolicy(_)));

        let scheme_error = client
            .request_with_headers_at_checked_destination(
                &destination,
                Method::GET,
                &format!("https://checked.example.test:{}/resource", addr.port()),
                HeaderMap::new(),
                None,
            )
            .await
            .expect_err("a checked destination must not authorize a scheme change");
        assert!(matches!(scheme_error, EgressError::InvalidPolicy(_)));

        let mut changed_config = config;
        changed_config.timeout = Duration::from_secs(3);
        let changed_client = client
            .reconfigured(changed_config)
            .expect("changed egress client should build");
        let generation_error = changed_client
            .request_with_headers_at_checked_destination(
                &destination,
                Method::GET,
                &url,
                HeaderMap::new(),
                None,
            )
            .await
            .expect_err("a checked destination must not cross egress configurations");
        assert!(matches!(generation_error, EgressError::InvalidPolicy(_)));
    }

    #[test]
    fn egress_client_ignores_ambient_proxy_environment() {
        let proxy_listener = std::net::TcpListener::bind(("127.0.0.1", 0))
            .expect("ambient proxy sentinel listener should bind");
        let proxy_addr = proxy_listener
            .local_addr()
            .expect("ambient proxy sentinel address should be available");
        let proxy_url = format!("http://{proxy_addr}");
        let output = Command::new(std::env::current_exe().expect("test executable should exist"))
            .args([
                "--exact",
                "egress::tests::egress_client_sends_directly_with_proxy_discovery_disabled",
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
            .expect("proxy-isolation child test should start");

        assert!(
            output.status.success(),
            "proxy-isolation child failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("running 1 test"),
            "proxy-isolation child must execute exactly one helper test: {stdout}"
        );
        proxy_listener
            .set_nonblocking(true)
            .expect("proxy sentinel should become nonblocking");
        assert!(
            matches!(proxy_listener.accept(), Err(error) if error.kind() == ErrorKind::WouldBlock),
            "ambient proxy sentinel must receive zero connections"
        );
    }

    #[test]
    fn non_global_ipv4_matches_registry_snapshot_and_multicast_policy() {
        for (address, expected_non_global) in [
            ("0.0.0.0", true),
            ("0.255.255.255", true),
            ("1.0.0.0", false),
            ("10.0.0.0", true),
            ("10.255.255.255", true),
            ("100.63.255.255", false),
            ("100.64.0.0", true),
            ("100.127.255.255", true),
            ("100.128.0.0", false),
            ("127.0.0.0", true),
            ("127.255.255.255", true),
            ("169.254.0.0", true),
            ("169.254.255.255", true),
            ("172.15.255.255", false),
            ("172.16.0.0", true),
            ("172.31.255.255", true),
            ("172.32.0.0", false),
            ("192.0.0.8", true),
            ("192.0.0.9", false),
            ("192.0.0.10", false),
            ("192.0.0.11", true),
            ("192.0.2.1", true),
            ("192.31.196.1", false),
            ("192.88.99.1", true),
            ("192.168.0.0", true),
            ("192.168.255.255", true),
            ("192.175.48.1", false),
            ("198.18.0.0", true),
            ("198.19.255.255", true),
            ("198.51.100.1", true),
            ("203.0.113.1", true),
            ("223.255.255.255", false),
            ("224.0.0.0", true),
            ("239.255.255.255", true),
            ("240.0.0.0", true),
            ("255.255.255.255", true),
            ("8.8.8.8", false),
        ] {
            assert_eq!(
                is_non_global_ip(ip(address), &[]),
                expected_non_global,
                "unexpected classification for {address}"
            );
        }
    }

    #[test]
    fn non_global_ipv6_matches_registry_snapshot_and_global_unicast_policy() {
        for (address, expected_non_global) in [
            ("::", true),
            ("::1", true),
            ("::2", true),
            ("::ffff:127.0.0.1", true),
            ("::ffff:8.8.8.8", false),
            ("100::1", true),
            ("100:0:0:1::1", true),
            ("2001::1", true),
            ("2001:1::1", false),
            ("2001:1::2", false),
            ("2001:1::3", false),
            ("2001:2::1", true),
            ("2001:3::1", false),
            ("2001:4:112::1", false),
            ("2001:10::1", true),
            ("2001:20::1", false),
            ("2001:30::1", false),
            ("2001:db8::1", true),
            ("2002::1", true),
            ("2620:4f:8000::1", false),
            ("3fff::1", true),
            ("5f00::1", true),
            ("fc00::1", true),
            ("fe80::1", true),
            ("fec0::1", true),
            ("ff02::1", true),
            ("2606:4700:4700::1111", false),
            ("4000::1", true),
        ] {
            assert_eq!(
                is_non_global_ip(ip(address), &[]),
                expected_non_global,
                "unexpected classification for {address}"
            );
        }
    }

    #[test]
    fn nat64_classification_uses_embedded_ipv4_and_requires_configured_local_prefixes() {
        assert!(is_non_global_ip(ip("64:ff9b::a9fe:a9fe"), &[]));
        assert!(!is_non_global_ip(ip("64:ff9b::808:808"), &[]));

        let local_use_public = ip("64:ff9b:1:808:8:800::");
        let local_use_private = ip("64:ff9b:1:a9fe:a9:fe00::");
        assert!(is_non_global_ip(local_use_public, &[]));

        let configured = vec!["64:ff9b:1::/48"
            .parse::<IpNet>()
            .expect("test NAT64 prefix should parse")];
        assert!(!is_non_global_ip(local_use_public, &configured));
        assert!(is_non_global_ip(local_use_private, &configured));
        assert!(is_non_global_ip(ip("64:ff9b:1:808:108:800::"), &configured));
    }

    #[test]
    fn rfc6052_extraction_supports_every_standard_prefix_length() {
        let expected = Ipv4Addr::new(192, 0, 2, 33);
        for (prefix, address) in [
            ("2001:db8::/32", "2001:db8:c000:221::"),
            ("2001:db8:100::/40", "2001:db8:1c0:2:21::"),
            ("2001:db8:122::/48", "2001:db8:122:c000:2:2100::"),
            ("2001:db8:122:300::/56", "2001:db8:122:3c0:0:221::"),
            ("2001:db8:122:344::/64", "2001:db8:122:344:c0:2:2100::"),
            ("2001:db8:122:344::/96", "2001:db8:122:344::192.0.2.33"),
        ] {
            let prefix = prefix
                .parse::<IpNet>()
                .expect("RFC 6052 example prefix should parse");
            let address = address
                .parse::<Ipv6Addr>()
                .expect("RFC 6052 example address should parse");
            assert!(prefix.contains(&IpAddr::V6(address)));
            assert_eq!(
                extract_rfc6052_ipv4(address, prefix.prefix_len()),
                Some(expected),
                "unexpected extraction for {prefix}"
            );
        }
    }

    #[test]
    fn rfc6052_extraction_rejects_nonzero_u_octet_for_96_prefixes() {
        let prefix = "2001:db8:122:344:100::/96"
            .parse::<IpNet>()
            .expect("test prefix should parse");
        let address = "2001:db8:122:344:100:0:808:808"
            .parse::<Ipv6Addr>()
            .expect("test address should parse");

        assert!(prefix.contains(&IpAddr::V6(address)));
        assert_eq!(address.octets()[8], 1);
        assert_eq!(extract_rfc6052_ipv4(address, 96), None);
        assert!(is_non_global_ip(IpAddr::V6(address), &[prefix]));
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
        let pinned = checked_socket_addr(
            "internal.example.test",
            &resolved,
            true,
            &[],
            &allowed_cidrs,
        )
        .expect("private IP covered by policy CIDR should be allowed");

        assert_eq!(pinned, socket("10.1.2.3:443"));

        let resolved = vec![socket("192.168.1.10:443")];
        let error = checked_socket_addr(
            "internal.example.test",
            &resolved,
            true,
            &[],
            &allowed_cidrs,
        )
        .expect_err("private IP outside policy CIDR should still be blocked");

        assert!(matches!(
            error,
            EgressError::NonGlobalIpBlocked(blocked) if blocked == ip("192.168.1.10")
        ));
    }

    #[test]
    fn no_policy_egress_section_preserves_env_only_config() {
        let mut config = test_config();
        config.egress_allowed_hosts = vec!["API.EXAMPLE.TEST".to_owned()];
        config.egress_nat64_prefixes = vec!["64:ff9b:1::/48"
            .parse()
            .expect("test NAT64 prefix should parse")];

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
        assert_eq!(env_only.nat64_prefixes, config.egress_nat64_prefixes);
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
    fn from_config_auto_seeds_auth_provider_hosts_into_allowlist() {
        let mut config = test_config();
        config.auth_providers = vec![crate::config::AuthProviderConfig {
            name: "primary".to_owned(),
            provider_type: crate::config::AuthProviderType::Jwt,
            jwks_url: Some("https://idp.example.test/.well-known/jwks.json".to_owned()),
            issuer: Some("https://issuer.example.test/".to_owned()),
            audience: None,
            jwks_timeout_ms: 2000,
            require_jti: false,
            roles_claim: "roles".to_owned(),
            roles_claim_delimiter: None,
            org_claim: None,
            introspection_url: None,
            introspection_timeout_ms:
                crate::config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
            cache_ttl_ms: crate::config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
            user_id_claim: None,
            email_claim: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
        }];

        let egress = EgressConfig::from_config(&config);

        assert!(egress.allowed_hosts.contains("idp.example.test"));
        assert!(egress.allowed_hosts.contains("issuer.example.test"));
    }

    #[test]
    fn from_config_auto_seeds_cookie_session_introspection_host_into_allowlist() {
        let mut config = test_config();
        config.auth_providers = vec![crate::config::AuthProviderConfig {
            name: "app-session".to_owned(),
            provider_type: crate::config::AuthProviderType::CookieSession,
            jwks_url: None,
            issuer: None,
            audience: None,
            jwks_timeout_ms: 2000,
            require_jti: false,
            roles_claim: "roles".to_owned(),
            roles_claim_delimiter: None,
            org_claim: None,
            introspection_url: Some("https://sessions.example.test/introspect".to_owned()),
            introspection_timeout_ms:
                crate::config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
            cache_ttl_ms: crate::config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
            user_id_claim: Some("user_id".to_owned()),
            email_claim: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
        }];

        let egress = EgressConfig::from_config(&config);

        assert!(egress.allowed_hosts.contains("sessions.example.test"));
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
                id: None,
                connection_id: None,
                path_prefix: Some("/api".to_owned()),
                host: None,
                upstream_url: "https://api-upstream.example.test/base".to_owned(),
                upstreams: Vec::new(),
                load_balancing: crate::config::UpstreamLoadBalancingConfig::default(),
                request_body: crate::config::UpstreamRequestBodyConfig::default(),
                sse: None,
                limits: crate::config::UpstreamPoolLimitsConfig::default(),
                health_check: None,
                retry: None,
                circuit_breaker: None,
                timeout_ms: None,
                response_idle_timeout_ms: None,
                connect_timeout_ms: None,
                add_request_headers: HashMap::new(),
                strip_request_headers: Vec::new(),
                tls_ca_bundle_path: None,
                openapi_spec_path: None,
            },
            crate::config::UpstreamRouteConfig {
                id: None,
                connection_id: None,
                path_prefix: Some("/assets".to_owned()),
                host: None,
                upstream_url: "http://assets-upstream.example.test".to_owned(),
                upstreams: Vec::new(),
                load_balancing: crate::config::UpstreamLoadBalancingConfig::default(),
                request_body: crate::config::UpstreamRequestBodyConfig::default(),
                sse: None,
                limits: crate::config::UpstreamPoolLimitsConfig::default(),
                health_check: None,
                retry: None,
                circuit_breaker: None,
                timeout_ms: None,
                response_idle_timeout_ms: None,
                connect_timeout_ms: None,
                add_request_headers: HashMap::new(),
                strip_request_headers: Vec::new(),
                tls_ca_bundle_path: None,
                openapi_spec_path: None,
            },
            crate::config::UpstreamRouteConfig {
                id: Some("payments".to_owned()),
                connection_id: None,
                path_prefix: Some("/payments".to_owned()),
                host: None,
                upstream_url: String::new(),
                upstreams: vec![
                    crate::config::UpstreamEndpointConfig {
                        id: "payments-a".to_owned(),
                        url: "https://payments-a.example.test".to_owned(),
                        weight: 3,
                        tls_ca_bundle_path: None,
                        client_identity_pem_path: None,
                    },
                    crate::config::UpstreamEndpointConfig {
                        id: "payments-b".to_owned(),
                        url: "https://payments-b.example.test".to_owned(),
                        weight: 1,
                        tls_ca_bundle_path: None,
                        client_identity_pem_path: None,
                    },
                ],
                load_balancing: crate::config::UpstreamLoadBalancingConfig::default(),
                request_body: crate::config::UpstreamRequestBodyConfig::default(),
                sse: None,
                limits: crate::config::UpstreamPoolLimitsConfig::default(),
                health_check: None,
                retry: None,
                circuit_breaker: None,
                timeout_ms: None,
                response_idle_timeout_ms: None,
                connect_timeout_ms: None,
                add_request_headers: HashMap::new(),
                strip_request_headers: Vec::new(),
                tls_ca_bundle_path: None,
                openapi_spec_path: None,
            },
        ];

        let egress = EgressConfig::from_config(&config);

        assert!(egress.allowed_hosts.contains("api-upstream.example.test"));
        assert!(egress
            .allowed_hosts
            .contains("assets-upstream.example.test"));
        assert!(egress.allowed_hosts.contains("payments-a.example.test"));
        assert!(egress.allowed_hosts.contains("payments-b.example.test"));
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
            EgressError::NonGlobalIpBlocked(blocked) if blocked == ip("127.0.0.1")
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
    fn any_non_global_resolved_ip_blocks_the_host() {
        let resolved = vec![
            socket("93.184.216.34:443"),
            socket("198.18.0.1:443"),
            socket("1.1.1.1:443"),
        ];
        let error = checked_socket_addr("api.example.test", &resolved, true, &[], &[])
            .expect_err("mixed public and non-global answers should deny");

        assert!(matches!(
            error,
            EgressError::NonGlobalIpBlocked(blocked) if blocked == ip("198.18.0.1")
        ));
    }

    #[test]
    fn configured_nat64_prefix_is_applied_before_address_pinning() {
        let prefixes = vec!["64:ff9b:1::/48"
            .parse::<IpNet>()
            .expect("test NAT64 prefix should parse")];
        let public = vec![socket("[64:ff9b:1:808:8:800::]:443")];
        let pinned = checked_socket_addr("api.example.test", &public, true, &prefixes, &[])
            .expect("public embedded IPv4 should be allowed");
        assert_eq!(pinned, public[0]);

        let private = vec![socket("[64:ff9b:1:a9fe:a9:fe00::]:443")];
        let error = checked_socket_addr("api.example.test", &private, true, &prefixes, &[])
            .expect_err("private embedded IPv4 should be blocked");
        assert!(matches!(
            error,
            EgressError::NonGlobalIpBlocked(blocked)
                if blocked == ip("64:ff9b:1:a9fe:a9:fe00::")
        ));
    }

    #[test]
    fn all_public_resolved_ips_select_exact_pinned_addr() {
        let resolved = vec![socket("93.184.216.34:443"), socket("1.1.1.1:443")];
        let pinned = checked_socket_addr("api.example.test", &resolved, true, &[], &[])
            .expect("public resolved addresses should be allowed");

        assert_eq!(pinned, socket("93.184.216.34:443"));
    }

    #[test]
    fn private_resolved_ip_is_allowed_when_private_deny_is_disabled() {
        let resolved = vec![socket("10.0.0.1:443")];
        let pinned = checked_socket_addr("internal.example.test", &resolved, false, &[], &[])
            .expect("private address should be allowed when private deny is disabled");

        assert_eq!(pinned, socket("10.0.0.1:443"));
    }

    #[test]
    fn empty_resolution_fails_closed() {
        let error = checked_socket_addr("api.example.test", &[], true, &[], &[])
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
    async fn oversized_request_bodies_are_rejected_before_dns_resolution() {
        let resolver = Arc::new(FakeDnsResolver::with_addresses(vec![socket("8.8.8.8:443")]));
        let client = EgressClient::new_with_resolver(
            EgressConfig {
                max_request_body_bytes: 3,
                ..egress_config_for_host("oversized.example.test")
            },
            resolver.clone(),
        )
        .expect("client should build");

        let buffered_error = client
            .request_with_headers(
                Method::POST,
                "https://oversized.example.test/resource",
                HeaderMap::new(),
                Some(vec![0; 4]),
            )
            .await
            .expect_err("oversized buffered request should fail");
        let streaming_error = client
            .stream_request_with_headers(
                Method::POST,
                "https://oversized.example.test/resource",
                HeaderMap::new(),
                Some(vec![0; 4]),
            )
            .await
            .expect_err("oversized streaming request should fail");

        for error in [buffered_error, streaming_error] {
            assert!(matches!(
                error,
                EgressError::RequestBodyTooLarge { size: 4, max: 3 }
            ));
        }
        assert!(
            resolver.calls().is_empty(),
            "oversized request denial must not resolve DNS"
        );
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
        let url = Url::parse(&format!("http://egress-pinned.test:{}/", addr.port()))
            .expect("test URL should parse");
        let pinned_client = client
            .pinned_client(&url, "egress-pinned.test", addr)
            .expect("pinned client should build");

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
            tls_root_set_fingerprint: tls_root_set_fingerprint(certified.cert.pem().as_bytes()),
            ..EgressConfig::default()
        };
        let client = EgressClient::new(config).expect("client should build");
        let url = Url::parse(&format!("http://egress-pinned.test:{}/", addr.port()))
            .expect("test URL should parse");
        let pinned_client = client
            .pinned_client(&url, "egress-pinned.test", addr)
            .expect("pinned client should build");

        let response = client
            .send_with_client(pinned_client, Method::GET, url, HeaderMap::new(), None)
            .await
            .expect("pinned request should reach the test server");

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, b"custom tls");
        server.await.expect("test server task should finish");
    }

    #[tokio::test]
    async fn sequential_requests_reuse_connections_but_revalidate_dns() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener local address should be available");
        let accepted_connections = Arc::new(AtomicUsize::new(0));
        let served_requests = Arc::new(AtomicUsize::new(0));
        let server = tokio::spawn(serve_keep_alive(
            listener,
            Arc::clone(&accepted_connections),
            Arc::clone(&served_requests),
        ));
        let resolver = Arc::new(FakeDnsResolver::with_addresses(vec![addr]));
        let client = isolated_egress_client(
            EgressConfig {
                allowed_hosts: HashSet::from(["reuse.example.test".to_owned()]),
                deny_private_ips: false,
                max_response_bytes: 2,
                ..EgressConfig::default()
            },
            resolver.clone(),
        );
        let url = format!("http://reuse.example.test:{}/", addr.port());

        for _ in 0..100 {
            let response = client
                .request(Method::GET, &url)
                .await
                .expect("sequential request should succeed");
            assert_eq!(response.status, StatusCode::OK);
            assert_eq!(response.body, b"ok");
        }

        assert_eq!(
            resolver.calls().len(),
            100,
            "DNS must be checked every time"
        );
        assert_eq!(served_requests.load(Ordering::SeqCst), 100);
        assert!(
            accepted_connections.load(Ordering::SeqCst) <= 2,
            "100 sequential requests should reuse a bounded number of TCP connections"
        );
        assert_eq!(client.client_cache.len(), 1);
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn safe_to_private_dns_change_never_reuses_cached_destination() {
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
        let resolver = Arc::new(SequencedDnsResolver::new([
            FakeResolution::Addresses(vec![addr]),
            FakeResolution::Addresses(vec![SocketAddr::from(([10, 0, 0, 1], addr.port()))]),
        ]));
        let client = isolated_egress_client(
            EgressConfig {
                allowed_hosts: HashSet::from(["rebind.example.test".to_owned()]),
                private_ip_allow_cidrs: vec!["127.0.0.0/8"
                    .parse()
                    .expect("test CIDR should parse")],
                deny_private_ips: true,
                max_response_bytes: 2,
                ..EgressConfig::default()
            },
            resolver.clone(),
        );
        let url = format!("http://rebind.example.test:{}/", addr.port());

        let first = client
            .request(Method::GET, &url)
            .await
            .expect("first validated destination should succeed");
        assert_eq!(first.body, b"ok");
        let error = client
            .request(Method::GET, &url)
            .await
            .expect_err("private rebound destination must fail closed");

        assert!(matches!(
            error,
            EgressError::NonGlobalIpBlocked(blocked) if blocked == ip("10.0.0.1")
        ));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            client.client_cache.len(),
            1,
            "the old client may remain idle but must not be selected after failed validation"
        );
        server.await.expect("test server task should finish");
    }

    #[test]
    fn cache_partitions_address_timeout_trust_identity_and_egress_generations() {
        let base_config = EgressConfig {
            allowed_hosts: HashSet::from(["partition.example.test".to_owned()]),
            deny_private_ips: false,
            ..EgressConfig::default()
        };
        let client = isolated_egress_client(base_config.clone(), Arc::new(SystemDnsResolver));
        let url = Url::parse("https://partition.example.test/").expect("test URL should parse");
        let first_addr = socket("8.8.8.8:443");
        client
            .pinned_client(&url, "partition.example.test", first_addr)
            .expect("first client should build");
        client
            .pinned_client(&url, "partition.example.test", first_addr)
            .expect("identical profile should reuse");
        assert_eq!(client.client_cache.len(), 1);

        client
            .pinned_client(&url, "partition.example.test", socket("1.1.1.1:443"))
            .expect("a new exact address should build a separate client");
        assert_eq!(client.client_cache.len(), 2);

        let mut timeout_config = base_config.clone();
        timeout_config.timeout += Duration::from_secs(1);
        let timeout_client = client
            .reconfigured(timeout_config)
            .expect("timeout client should build");
        timeout_client
            .pinned_client(&url, "partition.example.test", first_addr)
            .expect("a new timeout profile should build a separate client");
        assert_eq!(client.client_cache.len(), 3);

        let certified =
            rcgen::generate_simple_self_signed(vec!["partition.example.test".to_owned()])
                .expect("test root certificate should generate");
        let pem = certified.cert.pem();
        let mut trust_config = base_config.clone();
        trust_config.tls_root_certificates = reqwest::Certificate::from_pem_bundle(pem.as_bytes())
            .expect("test root certificate should parse");
        trust_config.tls_root_set_fingerprint = tls_root_set_fingerprint(pem.as_bytes());
        let trust_client = client
            .reconfigured(trust_config)
            .expect("trust-profile client should build");
        trust_client
            .pinned_client(&url, "partition.example.test", first_addr)
            .expect("a new trust profile should build a separate client");
        assert_eq!(client.client_cache.len(), 4);

        let mut first_identity_config = base_config.clone();
        let first_identity =
            rcgen::generate_simple_self_signed(vec!["client-a.example.test".to_owned()])
                .expect("first test identity should generate");
        let first_identity_pem = format!(
            "{}{}",
            first_identity.cert.pem(),
            first_identity.key_pair.serialize_pem()
        );
        first_identity_config.client_identity = Some(
            reqwest::Identity::from_pem(first_identity_pem.as_bytes())
                .expect("first test identity should parse"),
        );
        first_identity_config.client_identity_fingerprint = Some(tls_client_identity_fingerprint(
            first_identity_pem.as_bytes(),
        ));
        let first_identity_client = client
            .reconfigured(first_identity_config)
            .expect("first identity client should build");
        first_identity_client
            .pinned_client(&url, "partition.example.test", first_addr)
            .expect("a client identity should build a separate client");
        assert_eq!(client.client_cache.len(), 5);

        let mut second_identity_config = base_config.clone();
        let second_identity =
            rcgen::generate_simple_self_signed(vec!["client-b.example.test".to_owned()])
                .expect("second test identity should generate");
        let second_identity_pem = format!(
            "{}{}",
            second_identity.cert.pem(),
            second_identity.key_pair.serialize_pem()
        );
        second_identity_config.client_identity = Some(
            reqwest::Identity::from_pem(second_identity_pem.as_bytes())
                .expect("second test identity should parse"),
        );
        second_identity_config.client_identity_fingerprint = Some(tls_client_identity_fingerprint(
            second_identity_pem.as_bytes(),
        ));
        let second_identity_client = client
            .reconfigured(second_identity_config)
            .expect("second identity client should build");
        second_identity_client
            .pinned_client(&url, "partition.example.test", first_addr)
            .expect("another client identity should build a separate client");
        assert_eq!(client.client_cache.len(), 6);

        let mut egress_config = base_config;
        egress_config
            .allowed_hosts
            .insert("additional.example.test".to_owned());
        let egress_client = client
            .reconfigured(egress_config)
            .expect("egress-generation client should build");
        egress_client
            .pinned_client(&url, "partition.example.test", first_addr)
            .expect("a new egress generation should build a separate client");
        assert_eq!(client.client_cache.len(), 7);
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
        let url = Url::parse(&format!("http://egress-pinned.test:{}/", addr.port()))
            .expect("test URL should parse");
        let pinned_client = client
            .pinned_client(&url, "egress-pinned.test", addr)
            .expect("pinned client should build");

        let error = client
            .send_with_client(pinned_client, Method::GET, url, HeaderMap::new(), None)
            .await
            .expect_err("oversized response should deny");

        assert!(matches!(
            error,
            EgressError::ResponseTooLarge { size: 7, max: 6 }
        ));
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
                Err(EgressError::ResponseTooLarge { size, max }) => {
                    assert_eq!(size, 6);
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
            EgressError::NonGlobalIpBlocked(blocked) if blocked == ip("127.0.0.1")
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

    async fn serve_keep_alive(
        listener: TcpListener,
        accepted_connections: Arc<AtomicUsize>,
        served_requests: Arc<AtomicUsize>,
    ) {
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .expect("keep-alive test server should accept connections");
            accepted_connections.fetch_add(1, Ordering::SeqCst);
            let served_requests = Arc::clone(&served_requests);
            tokio::spawn(async move {
                serve_keep_alive_connection(stream, served_requests).await;
            });
        }
    }

    async fn serve_keep_alive_connection(mut stream: TcpStream, served_requests: Arc<AtomicUsize>) {
        let mut pending = Vec::new();
        loop {
            let header_end = loop {
                if let Some(position) = pending.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    break position + 4;
                }

                let mut buffer = [0_u8; 1024];
                let read = stream
                    .read(&mut buffer)
                    .await
                    .expect("keep-alive test request should read");
                if read == 0 {
                    return;
                }
                pending.extend_from_slice(&buffer[..read]);
            };
            pending.drain(..header_end);

            served_requests.fetch_add(1, Ordering::SeqCst);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
                )
                .await
                .expect("keep-alive test response should write");
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

    #[derive(Clone, Default)]
    struct CapturedLogs {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl CapturedLogs {
        fn clear(&self) {
            self.buffer
                .lock()
                .expect("captured logs should not be poisoned")
                .clear();
        }

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

    fn test_config() -> Config {
        Config {
            listen_addr: "127.0.0.1:0"
                .parse()
                .expect("test listen address should parse"),
            admin_listen_addr: None,
            admin_prefix: "/admin".to_owned(),
            admin_login_provider: None,
            admin_login_pending_ttl_secs: crate::config::DEFAULT_ADMIN_LOGIN_PENDING_TTL_SECS,
            admin_login_pending_max_entries: crate::config::DEFAULT_ADMIN_LOGIN_PENDING_MAX_ENTRIES,
            admin_login_pending_max_per_ip: crate::config::DEFAULT_ADMIN_LOGIN_PENDING_MAX_PER_IP,
            gateway_public_url: None,
            audit_log_file: None,
            audit_sqlite_path: None,
            audit_sqlite_retention_days: None,
            shutdown_drain_delay_ms: crate::config::DEFAULT_SHUTDOWN_DRAIN_DELAY_MS,
            shutdown_timeout_ms: crate::config::DEFAULT_SHUTDOWN_TIMEOUT_MS,
            audit_drain_timeout_ms: crate::config::DEFAULT_AUDIT_DRAIN_TIMEOUT_MS,
            discovery_sqlite_path: None,
            discovery_endpoint_limit: crate::config::DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
            principal_sqlite_path: None,
            connections_sqlite_path: None,
            connection_local_secret_keyring: Vec::new(),
            connection_secret_aliases: Vec::new(),
            connection_secrets_root: None,
            payload_capture_enabled: false,
            payload_capture_sample_rate: crate::config::DEFAULT_PAYLOAD_CAPTURE_SAMPLE_RATE,
            schema_mismatch_signal_threshold:
                crate::discovery::signals::DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
            error_rate_spike_signal_threshold:
                crate::discovery::signals::DEFAULT_ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
            principal_new_to_endpoint_signal_threshold:
                crate::discovery::signals::DEFAULT_PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
            volume_outlier_signal_threshold:
                crate::discovery::signals::DEFAULT_VOLUME_OUTLIER_SIGNAL_THRESHOLD,
            rule_suggestion_baseline_window_hours:
                crate::discovery::suggestions::DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
            openapi_spec_path: None,
            policy_file: None,
            tools_file: None,
            policy_history_sqlite_path: None,
            cors_allow_origins: Vec::new(),
            max_body_size: 1_048_576,
            rate_limit_read_rps: 50.0,
            rate_limit_read_burst: 100,
            rate_limit_write_rps: 10.0,
            rate_limit_write_burst: 20,
            trust_proxy_headers: false,
            trusted_proxy_cidrs: Vec::new(),
            rbac_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
            validation_allowed_content_types: vec!["application/json".to_owned()],
            auth_enabled: true,
            auth_mode: crate::config::AuthMode::Required,
            auth_cookie_name: "session".to_owned(),
            auth_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
            auth_providers: Vec::new(),
            jwt_jwks_url: None,
            jwt_issuer: None,
            jwt_audience: None,
            jwt_jwks_timeout_ms: 2000,
            jwt_require_jti: false,
            roles_claim: "roles".to_owned(),
            service_token_sqlite_path: None,
            service_token_cache_ttl_ms: crate::config::DEFAULT_SERVICE_TOKEN_CACHE_TTL_MS,
            tool_runtime_queue_depth: crate::config::DEFAULT_TOOL_RUNTIME_QUEUE_DEPTH,
            tool_runtime_global_concurrency: crate::config::DEFAULT_TOOL_RUNTIME_GLOBAL_CONCURRENCY,
            tool_runtime_queue_timeout_ms: crate::config::DEFAULT_TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
            tool_runtime_default_timeout_ms: crate::config::DEFAULT_TOOL_RUNTIME_DEFAULT_TIMEOUT_MS,
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
        }
    }
}
