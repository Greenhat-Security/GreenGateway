//! Canonical client IP extraction.

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use axum::extract::ConnectInfo;
use http::{header::HeaderName, Extensions, HeaderMap, HeaderValue};
use ipnet::IpNet;
use tower_http::request_id::RequestId;

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");

/// Immutable trust boundary used by every canonical client-IP consumer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClientIpPolicy {
    trusted_proxy_cidrs: Arc<[IpNet]>,
}

impl ClientIpPolicy {
    pub fn from_config(config: &crate::config::Config) -> Self {
        if !config.trust_proxy_headers {
            return Self::default();
        }

        Self::from_trusted_proxy_cidrs(config.trusted_proxy_cidrs.clone())
    }

    pub(crate) fn from_trusted_proxy_cidrs(trusted_proxy_cidrs: Vec<IpNet>) -> Self {
        Self {
            trusted_proxy_cidrs: Arc::from(trusted_proxy_cidrs),
        }
    }

    fn trusts(&self, ip: IpAddr) -> bool {
        let ip = canonical_ip(ip);
        self.trusted_proxy_cidrs
            .iter()
            .any(|cidr| cidr.contains(&ip))
    }
}

/// Returns the canonical client IP for request policy, audit, and observation code.
///
/// Forwarded proxy headers are honored only when the connection peer belongs to
/// an explicitly configured trusted proxy CIDR. Otherwise caller-supplied proxy
/// headers are ignored and the connection peer address is used instead.
pub fn canonical_client_ip(
    headers: &HeaderMap,
    extensions: &Extensions,
    policy: &ClientIpPolicy,
) -> String {
    let Some(peer_ip) = peer_ip(extensions).map(canonical_ip) else {
        return "unknown".to_owned();
    };

    if !policy.trusts(peer_ip) {
        return peer_ip.to_string();
    }

    match forwarded_for(headers) {
        Ok(Some(chain)) => return forwarded_client_ip(&chain, policy).to_string(),
        Err(()) => return peer_ip.to_string(),
        Ok(None) => {}
    }

    match single_ip_header(headers, &X_REAL_IP) {
        Ok(Some(ip)) => ip.to_string(),
        Ok(None) | Err(()) => peer_ip.to_string(),
    }
}

pub fn request_id(headers: &HeaderMap, extensions: &Extensions) -> String {
    headers
        .get(crate::REQUEST_ID_HEADER)
        .and_then(header_value_to_str)
        .or_else(|| {
            extensions
                .get::<RequestId>()
                .and_then(|request_id| request_id.header_value().to_str().ok())
        })
        .map(str::trim)
        .filter(|request_id| !request_id.is_empty())
        .unwrap_or("unknown")
        .to_owned()
}

fn forwarded_for(headers: &HeaderMap) -> Result<Option<Vec<IpAddr>>, ()> {
    let mut chain = Vec::new();
    let mut present = false;

    for value in headers.get_all(&X_FORWARDED_FOR) {
        present = true;
        let value = value.to_str().map_err(|_| ())?;
        for entry in value.split(',').map(str::trim) {
            if entry.is_empty() {
                return Err(());
            }
            chain.push(forwarded_entry_ip(entry).map(canonical_ip)?);
        }
    }

    if present {
        Ok(Some(chain))
    } else {
        Ok(None)
    }
}

fn forwarded_entry_ip(entry: &str) -> Result<IpAddr, ()> {
    // A bare IPv6 address is all colons and never carries a port, so it has to be
    // recognized before any `address:port` form is considered.
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Ok(ip);
    }

    // Some proxies append the source port, which carries no identity. Rejecting
    // those entries would mark the whole chain malformed and collapse every client
    // behind such a proxy onto the peer address. `SocketAddr` supplies the port
    // grammar so the IPv4 and bracketed-IPv6 forms are not split by hand.
    if let Ok(addr) = entry.parse::<SocketAddr>() {
        return Ok(addr.ip());
    }

    entry
        .strip_prefix('[')
        .and_then(|entry| entry.strip_suffix(']'))
        .ok_or(())?
        .parse::<Ipv6Addr>()
        .map(IpAddr::V6)
        .map_err(|_| ())
}

fn forwarded_client_ip(chain: &[IpAddr], policy: &ClientIpPolicy) -> IpAddr {
    chain
        .iter()
        .rev()
        .copied()
        .find(|ip| !policy.trusts(*ip))
        .unwrap_or(chain[0])
}

fn single_ip_header(headers: &HeaderMap, name: &HeaderName) -> Result<Option<IpAddr>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }

    let value = value.to_str().map_err(|_| ())?.trim();
    if value.is_empty() {
        return Err(());
    }

    value
        .parse::<IpAddr>()
        .map(canonical_ip)
        .map(Some)
        .map_err(|_| ())
}

fn header_value_to_str(value: &HeaderValue) -> Option<&str> {
    value.to_str().ok()
}

fn peer_ip(extensions: &Extensions) -> Option<IpAddr> {
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ipv6) => ipv6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        IpAddr::V4(_) => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(cidrs: &[&str]) -> ClientIpPolicy {
        ClientIpPolicy {
            trusted_proxy_cidrs: Arc::from(
                cidrs
                    .iter()
                    .map(|cidr| cidr.parse::<IpNet>().expect("test CIDR should parse"))
                    .collect::<Vec<_>>(),
            ),
        }
    }

    fn extensions_with_peer(addr: &str) -> Extensions {
        let mut extensions = Extensions::new();
        extensions.insert(ConnectInfo(
            addr.parse::<SocketAddr>()
                .expect("test socket address should parse"),
        ));
        extensions
    }

    #[test]
    fn ignores_forwarded_headers_when_proxy_headers_are_not_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, "198.51.100.10".parse().unwrap());
        headers.insert(X_REAL_IP, "198.51.100.11".parse().unwrap());
        let extensions = extensions_with_peer("203.0.113.20:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &ClientIpPolicy::default()),
            "203.0.113.20"
        );
    }

    #[test]
    fn ignores_forwarded_headers_from_an_untrusted_peer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            X_FORWARDED_FOR,
            " 198.51.100.10, 10.0.0.5 ".parse().unwrap(),
        );
        headers.insert(X_REAL_IP, "198.51.100.11".parse().unwrap());
        let extensions = extensions_with_peer("203.0.113.20:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["10.0.0.0/8"])),
            "203.0.113.20"
        );
    }

    #[test]
    fn append_only_forwarded_chain_uses_nearest_untrusted_hop() {
        let mut headers = HeaderMap::new();
        headers.insert(
            X_FORWARDED_FOR,
            "192.0.2.66, 198.51.100.10, 10.0.0.5".parse().unwrap(),
        );
        let extensions = extensions_with_peer("10.0.0.6:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["10.0.0.0/8"])),
            "198.51.100.10"
        );
    }

    #[test]
    fn multiple_forwarded_header_lines_preserve_chain_order() {
        let mut headers = HeaderMap::new();
        headers.append(
            X_FORWARDED_FOR,
            "192.0.2.66, 198.51.100.10".parse().unwrap(),
        );
        headers.append(X_FORWARDED_FOR, "10.0.0.5".parse().unwrap());
        let extensions = extensions_with_peer("10.0.0.6:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["10.0.0.0/8"])),
            "198.51.100.10"
        );
    }

    #[test]
    fn malformed_forwarded_chain_falls_back_to_peer_instead_of_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, "198.51.100.10, invalid".parse().unwrap());
        headers.insert(X_REAL_IP, "198.51.100.11".parse().unwrap());
        let extensions = extensions_with_peer("10.0.0.6:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["10.0.0.0/8"])),
            "10.0.0.6"
        );
    }

    #[test]
    fn falls_back_to_valid_real_ip_when_forwarded_for_is_absent() {
        let mut headers = HeaderMap::new();
        headers.insert(X_REAL_IP, "198.51.100.11".parse().unwrap());
        let extensions = extensions_with_peer("10.0.0.6:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["10.0.0.0/8"])),
            "198.51.100.11"
        );
    }

    #[test]
    fn invalid_real_ip_falls_back_to_peer() {
        let mut headers = HeaderMap::new();
        headers.insert(X_REAL_IP, "198.51.100.11, 192.0.2.1".parse().unwrap());
        let extensions = extensions_with_peer("10.0.0.6:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["10.0.0.0/8"])),
            "10.0.0.6"
        );
    }

    #[test]
    fn duplicate_real_ip_headers_fall_back_to_peer() {
        let mut headers = HeaderMap::new();
        headers.append(X_REAL_IP, "192.0.2.66".parse().unwrap());
        headers.append(X_REAL_IP, "198.51.100.10".parse().unwrap());
        let extensions = extensions_with_peer("10.0.0.6:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["10.0.0.0/8"])),
            "10.0.0.6"
        );
    }

    #[test]
    fn ipv4_mapped_peer_matches_ipv4_trusted_proxy_cidr() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, "198.51.100.10".parse().unwrap());
        let extensions = extensions_with_peer("[::ffff:10.0.0.6]:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["10.0.0.0/8"])),
            "198.51.100.10"
        );
    }

    #[test]
    fn forwarded_ipv4_entry_with_a_port_uses_the_client_address() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, "203.0.113.5:41234".parse().unwrap());
        let extensions = extensions_with_peer("10.0.0.6:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["10.0.0.0/8"])),
            "203.0.113.5"
        );
    }

    #[test]
    fn forwarded_bracketed_ipv6_entry_with_a_port_uses_the_client_address() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, "[2001:db8::5]:41234".parse().unwrap());
        let extensions = extensions_with_peer("10.0.0.6:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["10.0.0.0/8"])),
            "2001:db8::5"
        );
    }

    #[test]
    fn forwarded_bracketed_ipv6_entry_without_a_port_uses_the_client_address() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, "[2001:db8::5]".parse().unwrap());
        let extensions = extensions_with_peer("10.0.0.6:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["10.0.0.0/8"])),
            "2001:db8::5"
        );
    }

    #[test]
    fn forwarded_bare_ipv6_entry_is_not_split_on_its_own_colons() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, "2001:db8::5".parse().unwrap());
        let extensions = extensions_with_peer("10.0.0.6:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["10.0.0.0/8"])),
            "2001:db8::5"
        );
    }

    #[test]
    fn forwarded_bare_ipv6_loopback_entry_is_not_split_on_its_own_colons() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, "::1".parse().unwrap());
        let extensions = extensions_with_peer("10.0.0.6:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["10.0.0.0/8"])),
            "::1"
        );
    }

    #[test]
    fn ported_chain_still_skips_trusted_hops_on_the_parsed_address() {
        let mut headers = HeaderMap::new();
        headers.insert(
            X_FORWARDED_FOR,
            "192.0.2.66:9000, 198.51.100.10:443, [::ffff:10.0.0.7]:8443, 10.0.0.5:80"
                .parse()
                .unwrap(),
        );
        let extensions = extensions_with_peer("10.0.0.6:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["10.0.0.0/8"])),
            "198.51.100.10"
        );
    }

    #[test]
    fn forwarded_entry_with_a_non_numeric_port_falls_back_to_peer() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, "203.0.113.5:https".parse().unwrap());
        headers.insert(X_REAL_IP, "198.51.100.11".parse().unwrap());
        let extensions = extensions_with_peer("10.0.0.6:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["10.0.0.0/8"])),
            "10.0.0.6"
        );
    }

    #[test]
    fn forwarded_entry_with_an_out_of_range_port_falls_back_to_peer() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, "203.0.113.5:99999".parse().unwrap());
        let extensions = extensions_with_peer("10.0.0.6:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["10.0.0.0/8"])),
            "10.0.0.6"
        );
    }

    #[test]
    fn forwarded_entry_with_an_unterminated_bracket_falls_back_to_peer() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, "[2001:db8::5:41234".parse().unwrap());
        let extensions = extensions_with_peer("10.0.0.6:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["10.0.0.0/8"])),
            "10.0.0.6"
        );
    }

    #[test]
    fn forwarded_entry_with_trailing_junk_after_the_bracket_falls_back_to_peer() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, "[2001:db8::5]41234".parse().unwrap());
        let extensions = extensions_with_peer("10.0.0.6:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["10.0.0.0/8"])),
            "10.0.0.6"
        );
    }

    #[test]
    fn forwarded_entry_that_is_a_bracketed_ipv4_falls_back_to_peer() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, "[203.0.113.5]:41234".parse().unwrap());
        let extensions = extensions_with_peer("10.0.0.6:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["10.0.0.0/8"])),
            "10.0.0.6"
        );
    }

    #[test]
    fn forwarded_entry_with_an_empty_port_falls_back_to_peer() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, "203.0.113.5:".parse().unwrap());
        let extensions = extensions_with_peer("10.0.0.6:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["10.0.0.0/8"])),
            "10.0.0.6"
        );
    }

    #[test]
    fn ported_forwarded_entry_from_an_untrusted_peer_is_still_ignored() {
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, "198.51.100.10:41234".parse().unwrap());
        let extensions = extensions_with_peer("203.0.113.20:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["10.0.0.0/8"])),
            "203.0.113.20"
        );
    }

    #[test]
    fn returns_unknown_when_peer_info_is_absent() {
        let headers = HeaderMap::new();
        let extensions = Extensions::new();

        assert_eq!(
            canonical_client_ip(&headers, &extensions, &policy(&["0.0.0.0/0"])),
            "unknown"
        );
    }

    #[test]
    fn request_id_prefers_non_empty_header_value() {
        let mut headers = HeaderMap::new();
        headers.insert(crate::REQUEST_ID_HEADER, " request-123 ".parse().unwrap());
        let extensions = Extensions::new();

        assert_eq!(request_id(&headers, &extensions), "request-123");
    }

    #[test]
    fn request_id_returns_unknown_when_absent() {
        let headers = HeaderMap::new();
        let extensions = Extensions::new();

        assert_eq!(request_id(&headers, &extensions), "unknown");
    }
}
