use std::{
    collections::HashSet,
    error::Error,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use reqwest::{header::HeaderMap, Method, StatusCode, Url};
use tokio::net::lookup_host;

use crate::config::Config;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_RESPONSE_BYTES: usize = 5 * 1024 * 1024;
const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub enum EgressError {
    HostNotAllowed(String),
    PrivateIpBlocked(IpAddr),
    DnsResolutionFailed(String),
    InvalidUrl(String),
    SchemeNotAllowed(String),
    RequestBodyTooLarge { size: usize, max: usize },
    ResponseTooLarge { max: usize },
    Http(reqwest::Error),
}

impl fmt::Display for EgressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostNotAllowed(host) => write!(formatter, "egress host is not allowed: {host}"),
            Self::PrivateIpBlocked(ip) => write!(formatter, "egress private IP is blocked: {ip}"),
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressConfig {
    pub allowed_hosts: HashSet<String>,
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub max_response_bytes: usize,
    pub max_request_body_bytes: usize,
    pub deny_private_ips: bool,
}

impl Default for EgressConfig {
    fn default() -> Self {
        Self {
            allowed_hosts: HashSet::new(),
            timeout: DEFAULT_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            deny_private_ips: true,
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

        if !auto_seeded_hosts.is_empty() {
            tracing::debug!(
                hosts = ?auto_seeded_hosts,
                "auto-seeded egress allowlist from infrastructure endpoints"
            );
        }

        Self {
            allowed_hosts,
            timeout: Duration::from_millis(config.egress_timeout_ms),
            connect_timeout: Duration::from_millis(config.egress_connect_timeout_ms),
            max_response_bytes: config.egress_max_response_bytes,
            max_request_body_bytes: config.egress_max_request_body_bytes,
            deny_private_ips: config.egress_deny_private_ips,
        }
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
        let host = checked_host(&parsed, &self.config.allowed_hosts)?;
        let port = checked_port(&parsed)?;
        let resolved = resolve_host(&host, port).await?;
        let pinned_addr = checked_socket_addr(&host, &resolved, self.config.deny_private_ips)?;
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
    reqwest::Client::builder()
        .timeout(config.timeout)
        .connect_timeout(config.connect_timeout)
        .redirect(reqwest::redirect::Policy::none())
}

fn checked_host(url: &Url, allowed_hosts: &HashSet<String>) -> Result<String, EgressError> {
    let host = url
        .host_str()
        .ok_or_else(|| EgressError::InvalidUrl("missing host".to_owned()))?
        .to_ascii_lowercase();

    // IPv6 literal URL hosts may enter the allowlist through auto-seeded
    // infrastructure endpoints. They still fail closed today because the
    // resolver is given the bracketed form, so IPv6 literal JWKS and endpoint
    // URLs remain unsupported for now.
    if allowed_hosts.contains(&host) {
        Ok(host)
    } else {
        tracing::warn!(host = %host, "egress blocked non-allowlisted host");
        Err(EgressError::HostNotAllowed(host))
    }
}

fn checked_port(url: &Url) -> Result<u16, EgressError> {
    url.port_or_known_default()
        .ok_or_else(|| EgressError::InvalidUrl("missing port for URL scheme".to_owned()))
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
) -> Result<SocketAddr, EgressError> {
    if resolved.is_empty() {
        return Err(EgressError::DnsResolutionFailed(host.to_owned()));
    }

    if deny_private_ips {
        if let Some(blocked) = resolved
            .iter()
            .map(SocketAddr::ip)
            .find(|ip| is_private_ip(*ip))
        {
            tracing::warn!(
                host,
                ip = %blocked,
                "egress blocked private resolved address"
            );
            return Err(EgressError::PrivateIpBlocked(blocked));
        }
    }

    Ok(resolved[0])
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
    use std::{io::ErrorKind, net::IpAddr};

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
    fn empty_allowlist_denies_everything() {
        let client = EgressClient::new(EgressConfig::default()).expect("client should build");
        let url = client
            .checked_url("https://api.example.test/resource")
            .expect("URL should parse");

        let error = checked_host(&url, &client.config.allowed_hosts)
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
    fn host_not_in_allowlist_is_denied() {
        let allowed_hosts = HashSet::from(["api.example.test".to_owned()]);
        let url = Url::parse("https://other.example.test/resource").expect("URL should parse");
        let error =
            checked_host(&url, &allowed_hosts).expect_err("non-allowlisted host should deny");

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
        let error = checked_socket_addr("api.example.test", &resolved, true)
            .expect_err("mixed public and private answers should deny");

        assert!(matches!(
            error,
            EgressError::PrivateIpBlocked(blocked) if blocked == ip("10.0.0.1")
        ));
    }

    #[test]
    fn all_public_resolved_ips_select_exact_pinned_addr() {
        let resolved = vec![socket("93.184.216.34:443"), socket("1.1.1.1:443")];
        let pinned = checked_socket_addr("api.example.test", &resolved, true)
            .expect("public resolved addresses should be allowed");

        assert_eq!(pinned, socket("93.184.216.34:443"));
    }

    #[test]
    fn private_resolved_ip_is_allowed_when_private_deny_is_disabled() {
        let resolved = vec![socket("10.0.0.1:443")];
        let pinned = checked_socket_addr("internal.example.test", &resolved, false)
            .expect("private address should be allowed when private deny is disabled");

        assert_eq!(pinned, socket("10.0.0.1:443"));
    }

    #[test]
    fn empty_resolution_fails_closed() {
        let error = checked_socket_addr("api.example.test", &[], true)
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
            egress_allowed_hosts: Vec::new(),
            egress_timeout_ms: 30_000,
            egress_connect_timeout_ms: 10_000,
            egress_max_response_bytes: 5_242_880,
            egress_max_request_body_bytes: 1_048_576,
            egress_deny_private_ips: true,
        }
    }
}
