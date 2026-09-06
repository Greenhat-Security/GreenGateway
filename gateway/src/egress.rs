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

#[cfg(test)]
pub(crate) use grpc::test_client as grpc_test_client;
pub(crate) use grpc::{GrpcFailure, GrpcRequestBody, GrpcResponseBody};
// The PostgreSQL foundation builds its TLS connector on the same explicitly
// resolved crypto provider and the same CA-bundle parser the outbound path
// uses, so there is exactly one trust-decision construction site in the
// process, not two that could drift. Unused in builds without the `postgres`
// feature, where no second TLS consumer exists.
#[cfg(feature = "postgres")]
pub(crate) use tls::{crypto_provider, parse_ca_bundle_pem};

mod client_cache;
mod grpc;
#[cfg(test)]
mod grpc_tests;
#[cfg(test)]
mod mtls_tests;
mod tls;
#[cfg(test)]
mod tls_tests;

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
    /// A bounded gRPC transport failure.
    ///
    /// Carries a category and nothing else, on purpose: hyper's own error text
    /// can name the destination, the negotiated protocol, or bytes the upstream
    /// sent, and #257 forbids any of that reaching a log, a metric label, an
    /// audit field, or a client. The variant makes that structural.
    Grpc(GrpcFailure),
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
            Self::Grpc(failure) => write!(formatter, "egress gRPC transport error: {failure}"),
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

impl From<tls::TlsConfigError> for EgressError {
    fn from(error: tls::TlsConfigError) -> Self {
        // The two kinds of TLS material a deployment supplies already have a
        // variant each, and both are reported without echoing the material.
        match error {
            tls::TlsConfigError::TrustAnchors(message) => in_memory_tls_ca_bundle_error(message),
            tls::TlsConfigError::ClientIdentity => Self::InvalidTlsClientIdentity,
        }
    }
}

impl EgressError {
    pub fn is_timeout(&self) -> bool {
        match self {
            Self::ResponseIdleTimeout { .. } => true,
            Self::Grpc(GrpcFailure::ConnectTimeout) => true,
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
            Self::Grpc(failure) => failure.category(),
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
            // Reaching the endpoint at all is what passive health measures. A
            // connect, TLS, ALPN, or handshake failure never got there; a reset
            // or protocol error is the upstream answering badly, which is an
            // application fault rather than an endpoint being down.
            Self::Grpc(
                GrpcFailure::Connect
                | GrpcFailure::Tls
                | GrpcFailure::AlpnNotH2
                | GrpcFailure::Handshake
                | GrpcFailure::ConnectionClosed
                | GrpcFailure::ConnectTimeout,
            ) => true,
            Self::Grpc(GrpcFailure::StreamReset | GrpcFailure::Protocol) => false,
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
            // #257 disables retry for gRPC outright, and a streaming call is
            // never replayable in any case. Saying so here rather than only at
            // the call site means a future caller that consults this
            // classification cannot accidentally opt gRPC back in.
            Self::Grpc(_) => false,
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
    /// Extra trust anchors, on top of the platform trust store rather than
    /// instead of it. See [`tls`] for why that distinction is load-bearing.
    pub(crate) tls_root_certificates: Vec<tls::CertificateDer<'static>>,
    pub(crate) tls_root_set_fingerprint: [u8; 32],
    pub(crate) client_identity: Option<tls::TlsClientIdentity>,
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
        let certificates = tls::parse_ca_bundle_pem(pem_bundle).map_err(EgressError::from)?;

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
        // `parse_client_identity_pem` runs the TLS stack's own acceptance check,
        // so an identity that lands in the configuration is one the handshake
        // can actually present.
        let identity = tls::parse_client_identity_pem(pem_identity)
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

/// An upstream response to an upgrade attempt, before any protocol switch.
///
/// The body is deliberately not exposed: a non-101 response is a failed
/// upgrade whose body must never reach the client, and a 101 has no body. The
/// caller inspects `status` and `headers`, and on acceptance consumes
/// `into_upgraded` to take the raw bidirectional stream.
/// The upgraded byte stream handed back by a successful protocol upgrade.
///
/// Named here so a consumer can spell the type without importing the HTTP
/// client crate itself. That import is what `scripts/check-egress-only.sh`
/// refuses outside this module, and the refusal is the point: a module able to
/// name the crate is a module able to build its own client and bypass
/// destination validation.
pub type EgressUpgradedStream = reqwest::Upgraded;

pub struct EgressUpgradeResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    response: reqwest::Response,
}

impl fmt::Debug for EgressUpgradeResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EgressUpgradeResponse")
            .field("status", &self.status)
            .field("headers", &"<redacted>")
            .finish()
    }
}

impl EgressUpgradeResponse {
    /// Takes the upgraded bidirectional stream.
    ///
    /// Only meaningful after the caller has verified the response actually
    /// switched protocols; calling it otherwise fails rather than handing back
    /// a half-open connection.
    pub async fn into_upgraded(self) -> Result<EgressUpgradedStream, EgressError> {
        if self.status != StatusCode::SWITCHING_PROTOCOLS {
            return Err(EgressError::InvalidPolicy(
                "upstream did not switch protocols".to_owned(),
            ));
        }
        self.response.upgrade().await.map_err(|error| {
            tracing::warn!(
                error_category = "upgrade_failed",
                "egress upstream upgrade did not complete"
            );
            EgressError::Http(error)
        })
    }
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
        base_client_builder(&config)?.build()?;
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

    /// Derives a client that additionally trusts the given PEM CA bundle when
    /// verifying server certificates (for providers whose endpoints chain to a
    /// private CA) and/or presents the given combined certificate-chain and
    /// private-key PEM as its mutual-TLS client identity. Host allowlisting,
    /// DNS pinning, redirect refusal, hostname verification, timeouts, and
    /// size bounds are inherited unchanged; oversized, unparsable, or empty
    /// material fails closed.
    pub(crate) fn with_tls_material(
        &self,
        ca_bundle_pem: Option<&[u8]>,
        client_identity_pem: Option<&[u8]>,
    ) -> Result<Self, EgressError> {
        let mut config = self.config.clone();
        if let Some(pem_bundle) = ca_bundle_pem {
            config.apply_tls_ca_bundle_pem(pem_bundle)?;
        }
        if let Some(pem_identity) = client_identity_pem {
            config.apply_tls_client_identity_pem(pem_identity)?;
        }
        self.reconfigured(config)
    }

    /// Derives a client whose maximum response size is clamped to `maximum`
    /// when that is tighter than the deployment egress bound. The cap is
    /// enforced while the response is being received, never after buffering.
    /// A deployment bound that is already tighter is kept, so a caller can
    /// only narrow the limit.
    pub(crate) fn with_response_cap(&self, maximum: usize) -> Result<Self, EgressError> {
        let mut config = self.config.clone();
        config.max_response_bytes = config.max_response_bytes.min(maximum);
        self.reconfigured(config)
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
        let (_, client) = self.client_for_checked_destination(
            destination,
            url,
            client_cache::ProtocolProfile::Sse,
        )?;
        Ok(client)
    }

    /// Sends a bodyless GET that may be answered with a protocol upgrade.
    ///
    /// Reuses the same validated-destination path as every other egress call —
    /// authority, policy port, private-IP rules, and pinned socket address are
    /// all rechecked against the current configuration generation — so exact
    /// pinning, SNI, certificate verification, route-local roots, and endpoint
    /// mTLS identity apply to an upgraded connection exactly as they do to an
    /// ordinary request.
    ///
    /// No response body is read. A non-101 answer is a failed upgrade whose
    /// body must not reach the client, and a 101 has none. Deliberately does
    /// not retry: an upgrade attempt is not replayable once the upstream has
    /// begun switching protocols.
    pub(crate) async fn upgrade_request_at_checked_destination(
        &self,
        destination: &CheckedEgressDestination,
        url: &str,
        headers: HeaderMap,
    ) -> Result<EgressUpgradeResponse, EgressError> {
        let (parsed, client) = self.client_for_checked_destination(
            destination,
            url,
            client_cache::ProtocolProfile::UpgradeHttp1,
        )?;

        tracing::debug!("egress upgrade request using previously validated pinned destination");

        let response = client
            .request(Method::GET, parsed)
            .headers(headers)
            .send()
            .await?;
        Ok(EgressUpgradeResponse {
            status: response.status(),
            headers: response.headers().clone(),
            response,
        })
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
        let (parsed, client) = self.client_for_checked_destination(
            destination,
            url,
            client_cache::ProtocolProfile::Http1AndHttp2,
        )?;

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
        let (parsed, client) = self.client_for_checked_destination(
            destination,
            url,
            client_cache::ProtocolProfile::Http1AndHttp2,
        )?;

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
            if sse_max_response_bytes.is_some() {
                client_cache::ProtocolProfile::Sse
            } else {
                client_cache::ProtocolProfile::Http1AndHttp2
            },
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
        profile: client_cache::ProtocolProfile,
    ) -> Result<(Url, reqwest::Client), EgressError> {
        let (parsed, host, _) = self.revalidated_destination(destination, url)?;
        let client =
            self.pinned_client_with_profile(&parsed, &host, destination.pinned_addr, profile)?;
        Ok((parsed, client))
    }

    /// Revalidates an already checked destination against this client's current
    /// configuration and the URL about to be requested.
    ///
    /// Factored out rather than duplicated because the gRPC transport
    /// (`egress::grpc`) cannot go through `reqwest::ClientBuilder` and therefore
    /// cannot reuse the pinned-client path. Two independently written
    /// revalidations would be two things that have to keep agreeing forever;
    /// one function is a thing that cannot disagree with itself. Everything the
    /// pinned reqwest clients check -- configuration generation, allowed host,
    /// allowed port, authority match against the checked destination, and the
    /// private-IP rules applied to the pinned socket -- is checked here, for
    /// both transports, in this order.
    fn revalidated_destination(
        &self,
        destination: &CheckedEgressDestination,
        url: &str,
    ) -> Result<(Url, String, u16), EgressError> {
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

        Ok((parsed, host, port))
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

        if !parsed.username().is_empty() || parsed.password().is_some() {
            tracing::warn!(
                error_category = "invalid_url",
                "egress blocked URL containing userinfo"
            );
            return Err(EgressError::InvalidUrl(
                "URL userinfo is not allowed".to_owned(),
            ));
        }
        if parsed.fragment().is_some() {
            tracing::warn!(
                error_category = "invalid_url",
                "egress blocked URL containing a fragment"
            );
            return Err(EgressError::InvalidUrl(
                "URL fragments are not allowed".to_owned(),
            ));
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
        profile: client_cache::ProtocolProfile,
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
            protocol_profile: profile,
            outbound_proxy_policy: client_cache::OutboundProxyPolicy::Disabled,
        };

        self.client_cache.get_or_build(key, || {
            Ok(base_client_builder_for_profile(&self.config, profile)?
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
        self.pinned_client_with_profile(
            url,
            host,
            pinned_addr,
            client_cache::ProtocolProfile::Http1AndHttp2,
        )
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

fn base_client_builder(config: &EgressConfig) -> Result<reqwest::ClientBuilder, EgressError> {
    base_client_builder_for_profile(config, client_cache::ProtocolProfile::Http1AndHttp2)
}

fn base_client_builder_for_profile(
    config: &EgressConfig,
    profile: client_cache::ProtocolProfile,
) -> Result<reqwest::ClientBuilder, EgressError> {
    // The gRPC profile negotiates ALPN `h2`, and this build deliberately does
    // not enable `hyper-util/http2`. Handing that config to reqwest does not
    // error, it PANICS at request time inside hyper-util
    // (`hyper-util-0.1.20/src/client/legacy/client.rs:562-563`), long after the
    // mistake was made and on whatever task happened to make the call. Refusing
    // it here turns a panic into a configuration error at the point of
    // construction. `egress::grpc` is the only transport for this profile.
    if matches!(profile, client_cache::ProtocolProfile::Grpc) {
        return Err(EgressError::InvalidPolicy(
            "the gRPC protocol profile has no reqwest transport".to_owned(),
        ));
    }

    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(config.connect_timeout)
        .pool_idle_timeout(Some(client_cache::CLIENT_POOL_IDLE_TIMEOUT))
        .pool_max_idle_per_host(client_cache::CLIENT_POOL_MAX_IDLE_PER_HOST)
        .tcp_keepalive(Some(client_cache::CLIENT_TCP_KEEPALIVE))
        .redirect(reqwest::redirect::Policy::none());
    // A total request timeout would cut a long-lived stream or an upgraded
    // connection; both bound their lifetime at the caller instead.
    if matches!(profile, client_cache::ProtocolProfile::Http1AndHttp2) {
        builder = builder.timeout(config.timeout);
    }
    // Every profile pins HTTP/1.1 explicitly, and the reason differs by profile.
    //
    // For UpgradeHttp1 it is semantic: an upgrade is an HTTP/1.1 mechanism, and
    // ALPN selecting h2 would leave the handshake meaningless.
    //
    // For the other two it is a blast-radius pin: an h2 transport has to be an
    // explicit new profile that opts out, rather than something existing traffic
    // is opted into by a dependency edge. Every HTTPS upstream that supports h2
    // would otherwise switch protocol with no code change and no configuration
    // change, and hyper strips hop-by-hop headers on h2 rather than erroring, so
    // this gateway's curated header handling would change shape at the same
    // time.
    //
    // This call now pins only the HTTP version reqwest will speak on the
    // connection. It no longer pins ALPN: that half applies only to the TLS
    // backend reqwest builds itself (`client.rs:823-827`), and the config below
    // is built here instead. `tls::client_config` states the ALPN list per
    // profile, and `egress::tls_tests` observes the negotiated protocol rather
    // than assuming this line still covers it.
    builder = builder.http1_only();

    // The gateway builds the TLS configuration and hands the finished thing to
    // reqwest, rather than letting reqwest assemble one from `add_root_certificate`
    // and `identity`. [`tls`] explains why; the consequence here is that this is
    // the ONLY place outbound trust is configured. Under
    // `TlsBackend::BuiltRustls` reqwest never reads `root_certs` or `identity`
    // (`reqwest-0.13.4/src/async_impl/client.rs:642-685`), so calling those
    // builder methods as well would be dead code that still reads as the thing
    // establishing trust.
    let tls_config = tls::client_config(
        &config.tls_root_certificates,
        config.client_identity.as_ref(),
        profile,
    )
    .map_err(|error| {
        let error = EgressError::from(error);
        match &config.tls_ca_bundle_path {
            Some(path) => with_tls_ca_bundle_path(error, path),
            None => error,
        }
    })?;

    Ok(builder.tls_backend_preconfigured(tls_config))
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

/// Counts the certificate and private-key blocks in a PEM document.
///
/// The block labels live here only, so the several shape checks cannot drift
/// apart on which key encodings they recognise. Returns `None` when the bytes
/// are not UTF-8, which no PEM document is.
fn count_pem_blocks(pem: &[u8]) -> Option<(usize, usize)> {
    const CERTIFICATE_LABEL: &str = "-----BEGIN CERTIFICATE-----";
    const PRIVATE_KEY_LABELS: [&str; 3] = [
        concat!("-----BEGIN ", "PRIVATE KEY-----"),
        concat!("-----BEGIN ", "RSA PRIVATE KEY-----"),
        concat!("-----BEGIN ", "EC PRIVATE KEY-----"),
    ];
    let text = std::str::from_utf8(pem).ok()?;
    let certificates = text.matches(CERTIFICATE_LABEL).count();
    let private_keys = PRIVATE_KEY_LABELS
        .into_iter()
        .map(|label| text.matches(label).count())
        .sum::<usize>();
    Some((certificates, private_keys))
}

fn tls_client_identity_pem_shape_is_valid(pem_identity: &[u8]) -> bool {
    let Some((certificate_count, private_key_count)) = count_pem_blocks(pem_identity) else {
        return false;
    };

    certificate_count >= 1 && private_key_count == 1
}

/// Validates a CA bundle exactly as [`EgressConfig::apply_tls_ca_bundle_pem`]
/// will.
///
/// Both call the one parser, so a preflight cannot bless a bundle the transport
/// later refuses.
pub(crate) fn tls_ca_bundle_pem_is_valid(pem_bundle: &[u8]) -> bool {
    match tls::parse_ca_bundle_pem(pem_bundle) {
        Ok(certificates) => !certificates.is_empty(),
        Err(_) => false,
    }
}

/// Joins a client certificate and private key into the single PEM document the
/// TLS stack expects.
///
/// PEM parsing is line-oriented: a `-----BEGIN` marker must start a line, so a
/// certificate that does not end in a newline would run straight into the key's
/// header and the key would silently not parse. Preflight validation and the
/// request path must therefore build the identity the same way — validating one
/// byte sequence and then transmitting a different one means a valid pair can be
/// rejected at write time, or an invalid one accepted. Both call this.
pub(crate) fn join_tls_client_identity_pem(
    certificate: &[u8],
    private_key: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let separator_len = usize::from(!certificate.ends_with(b"\n"));
    let identity_len = certificate
        .len()
        .checked_add(separator_len)
        .and_then(|length| length.checked_add(private_key.len()))?;
    let mut identity = Zeroizing::new(Vec::with_capacity(identity_len));
    identity.extend_from_slice(certificate);
    if separator_len == 1 {
        identity.push(b'\n');
    }
    identity.extend_from_slice(private_key);
    Some(identity)
}

/// Validates one half of a client identity on its own.
///
/// Deliberately weaker than [`tls_client_identity_pem_is_valid`], which is the
/// real check because a certificate and key are only meaningful as a matched
/// pair. This exists for the synchronous rotation preflight, which cannot reach
/// a network provider to fetch the counterpart half: rejecting material that is
/// not even the right kind of PEM is worth more than accepting anything, and it
/// is the difference between a rotation failing at the API and a connection
/// failing on every subsequent request. A pair mismatch still surfaces when the
/// transport assembles the identity.
pub(crate) fn tls_client_identity_half_is_valid(pem_half: &[u8], is_certificate: bool) -> bool {
    if pem_half.len() > MAX_TLS_CLIENT_IDENTITY_PEM_BYTES {
        return false;
    }
    let Some((certificate_count, private_key_count)) = count_pem_blocks(pem_half) else {
        return false;
    };

    if is_certificate {
        // The certificate half must carry no key material, and every entry has
        // to parse as real X.509 DER rather than merely look like a PEM block.
        certificate_count >= 1 && private_key_count == 0 && tls_ca_bundle_pem_is_valid(pem_half)
    } else {
        // Marker counting alone would accept a truncated or corrupt body, which
        // the transport then rejects on every request. Requiring the section to
        // close and its body to base64-decode catches that here instead. This
        // still cannot prove the DER is a loadable key of the labelled type —
        // only pairing it with its certificate does, which the async rotation
        // preflight performs when the counterpart is reachable.
        certificate_count == 0 && private_key_count == 1 && pem_section_body_decodes(pem_half)
    }
}

/// Whether the single PEM section in `pem` closes and its body is valid base64.
fn pem_section_body_decodes(pem: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(pem) else {
        return false;
    };
    let Some(begin) = text.find("-----BEGIN ") else {
        return false;
    };
    let Some(header_end) = text[begin..]
        .find("-----\n")
        .map(|offset| begin + offset + 6)
    else {
        // Tolerate CRLF and a header terminated at end of input.
        let Some(offset) = text[begin..].find("-----\r\n") else {
            return false;
        };
        return decode_pem_body(&text[begin + offset + 7..]);
    };
    decode_pem_body(&text[header_end..])
}

fn decode_pem_body(rest: &str) -> bool {
    use base64::Engine as _;

    let Some(end) = rest.find("-----END ") else {
        return false;
    };
    let body: String = rest[..end].chars().filter(|c| !c.is_whitespace()).collect();
    !body.is_empty()
        && base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .is_ok()
}

/// Validates a joined client identity exactly as the transport will.
///
/// The size gate matters as much as the parse: the certificate and key are
/// bounded separately by their purposes, whose sum exceeds what
/// `apply_tls_client_identity_pem` accepts, so without it a preflight can bless
/// an identity the transport later refuses.
pub(crate) fn tls_client_identity_pem_is_valid(pem_identity: &[u8]) -> bool {
    if pem_identity.len() > MAX_TLS_CLIENT_IDENTITY_PEM_BYTES {
        return false;
    }
    tls_client_identity_pem_parses(pem_identity)
}

fn tls_client_identity_pem_parses(pem_identity: &[u8]) -> bool {
    if !tls_client_identity_pem_shape_is_valid(pem_identity) {
        return false;
    }
    tls::parse_client_identity_pem(pem_identity).is_ok()
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
#[path = "egress/tests.rs"]
mod tests;
