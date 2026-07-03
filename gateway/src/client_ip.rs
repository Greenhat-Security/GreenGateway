//! Canonical client IP extraction.

use std::net::SocketAddr;

use axum::extract::ConnectInfo;
use http::{header::HeaderName, Extensions, HeaderMap};

const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");

/// Returns the canonical client IP for request policy, audit, and observation code.
///
/// Forwarded proxy headers are honored only when `trust_proxy_headers` is true.
/// With the default false setting, caller-supplied proxy headers are ignored and
/// the connection peer address is used instead.
///
/// When proxy headers are trusted, the deploying operator must ensure the
/// trusted proxy strips or replaces any client-supplied `X-Forwarded-For`
/// header. If the proxy appends to inbound values, a client can still inject
/// the leftmost entry used here.
pub fn canonical_client_ip(
    headers: &HeaderMap,
    extensions: &Extensions,
    trust_proxy_headers: bool,
) -> String {
    if trust_proxy_headers {
        if let Some(ip) = forwarded_for(headers) {
            return ip.to_owned();
        }

        if let Some(ip) = header_value(headers, &X_REAL_IP) {
            return ip.to_owned();
        }
    }

    peer_ip(extensions).unwrap_or_else(|| "unknown".to_owned())
}

fn forwarded_for(headers: &HeaderMap) -> Option<&str> {
    let value = header_value(headers, &X_FORWARDED_FOR)?;
    value
        .split(',')
        .map(str::trim)
        .find(|entry| !entry.is_empty())
}

fn header_value<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn peer_ip(extensions: &Extensions) -> Option<String> {
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            canonical_client_ip(&headers, &extensions, false),
            "203.0.113.20"
        );
    }

    #[test]
    fn honors_first_forwarded_for_entry_when_proxy_headers_are_trusted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            X_FORWARDED_FOR,
            " 198.51.100.10, 10.0.0.5 ".parse().unwrap(),
        );
        headers.insert(X_REAL_IP, "198.51.100.11".parse().unwrap());
        let extensions = extensions_with_peer("203.0.113.20:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, true),
            "198.51.100.10"
        );
    }

    #[test]
    fn falls_back_to_real_ip_when_forwarded_for_is_absent() {
        let mut headers = HeaderMap::new();
        headers.insert(X_REAL_IP, "198.51.100.11".parse().unwrap());
        let extensions = extensions_with_peer("203.0.113.20:12345");

        assert_eq!(
            canonical_client_ip(&headers, &extensions, true),
            "198.51.100.11"
        );
    }

    #[test]
    fn returns_unknown_when_peer_info_is_absent() {
        let headers = HeaderMap::new();
        let extensions = Extensions::new();

        assert_eq!(canonical_client_ip(&headers, &extensions, false), "unknown");
    }
}
