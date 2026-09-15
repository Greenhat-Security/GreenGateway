//! Shared upstream-route selection used by authorization and proxy forwarding.

use std::net::Ipv6Addr;

use http::{header, HeaderMap};

use crate::{path_match::path_prefix_matches, request_bounds::MAX_REQUEST_HOST_BYTES};

pub(crate) const STABLE_ROUTE_ID_MAX_LEN: usize = 64;

pub(crate) fn is_valid_stable_route_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= STABLE_ROUTE_ID_MAX_LEN
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
}

pub(crate) trait RouteMatch {
    fn path_prefix(&self) -> Option<&str>;
    fn host(&self) -> Option<&str>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProxyRouteAuthorizationContext {
    pub(crate) route_id: Option<String>,
    pub(crate) host: String,
    pub(crate) path_prefix: Option<String>,
    pub(crate) upstream_origin: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProxyRouteObservationContext {
    pub(crate) route_id: Option<String>,
    pub(crate) route_host: Option<String>,
    pub(crate) route_path_prefix: Option<String>,
    pub(crate) upstream_origin: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProxyRouteClassificationCompleted;

impl ProxyRouteObservationContext {
    #[cfg(test)]
    pub(crate) fn new(
        route_host: Option<String>,
        route_path_prefix: Option<String>,
        upstream_origin: String,
    ) -> Self {
        Self {
            route_id: None,
            route_host,
            route_path_prefix,
            upstream_origin,
        }
    }

    pub(crate) fn new_with_route_id(
        route_id: String,
        route_host: Option<String>,
        route_path_prefix: Option<String>,
        upstream_origin: String,
    ) -> Self {
        Self {
            route_id: Some(route_id),
            route_host,
            route_path_prefix,
            upstream_origin,
        }
    }

    pub(crate) fn authorization_context(&self) -> Option<ProxyRouteAuthorizationContext> {
        Some(
            ProxyRouteAuthorizationContext::new(
                self.route_host.clone()?,
                self.route_path_prefix.clone(),
                self.upstream_origin.clone(),
            )
            .with_route_id(self.route_id.clone()),
        )
    }
}

impl ProxyRouteAuthorizationContext {
    pub(crate) fn new(host: String, path_prefix: Option<String>, upstream_origin: String) -> Self {
        Self {
            route_id: None,
            host,
            path_prefix,
            upstream_origin,
        }
    }

    fn with_route_id(mut self, route_id: Option<String>) -> Self {
        self.route_id = route_id;
        self
    }
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthorizationRouteMatch {
    path_prefix: Option<String>,
    host: Option<String>,
}

#[cfg(test)]
impl AuthorizationRouteMatch {
    pub(crate) fn new(path_prefix: Option<String>, host: Option<String>) -> Self {
        Self { path_prefix, host }
    }
}

#[cfg(test)]
impl RouteMatch for AuthorizationRouteMatch {
    fn path_prefix(&self) -> Option<&str> {
        self.path_prefix.as_deref()
    }

    fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }
}

pub(crate) fn matching_route<'a, T: RouteMatch>(
    routes: &'a [T],
    path: &str,
    request_host: Option<&str>,
) -> Option<&'a T> {
    let mut best = None::<(&T, usize, bool)>;

    for route in routes {
        if !route_matches(route, path, request_host) {
            continue;
        }

        let prefix_len = route.path_prefix().map_or(0, str::len);
        let host_specific = route.host().is_some();
        let should_replace = match best {
            Some((_, best_prefix_len, best_host_specific)) => {
                prefix_len > best_prefix_len
                    || (prefix_len == best_prefix_len && host_specific && !best_host_specific)
            }
            None => true,
        };

        if should_replace {
            best = Some((route, prefix_len, host_specific));
        }
    }

    best.map(|(route, _, _)| route)
}

/// The `Host` header as request admission and routing read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HostHeader {
    /// No `Host` header, or one whose value is empty. RFC 9110 permits an
    /// empty host, so an empty value names no host without being malformed.
    Absent,
    /// Exactly one syntactically valid `Host`, reduced to its host: port and
    /// IPv6 brackets removed, ASCII lower-cased.
    Present(String),
    /// A `Host` that names no host: repeated, not visible ASCII, a bracketed
    /// value that is not an IPv6 literal, a port that is not a port, or a
    /// character RFC 3986 does not allow in a host.
    Malformed,
    /// A well-formed host longer than [`MAX_REQUEST_HOST_BYTES`].
    TooLong,
}

/// Classifies the request's `Host` header.
///
/// Request admission answers `Malformed` with `400` and `TooLong` with `431`,
/// so every consumer after it -- route classification, authorization, the
/// policy kernel -- sees either no host or a bare one within the bound. The
/// parse is strict where its predecessor was lenient (`[a:b:c]` no longer
/// yields `a:b:c`, and `host:x` no longer yields `host`), because a host that
/// is not a host is malformed input rather than a request for the unbound
/// routes.
pub(crate) fn host_header(headers: &HeaderMap) -> HostHeader {
    let mut values = headers.get_all(header::HOST).iter();
    let Some(value) = values.next() else {
        return HostHeader::Absent;
    };
    if values.next().is_some() {
        // RFC 9110 section 7.2: more than one Host is a 400, and which one to
        // believe is exactly the question a request smuggler wants answered.
        return HostHeader::Malformed;
    }
    let Ok(value) = value.to_str() else {
        return HostHeader::Malformed;
    };
    let value = value.trim();
    if value.is_empty() {
        return HostHeader::Absent;
    }
    match parse_host_without_port(value) {
        Some(host) if host.len() > MAX_REQUEST_HOST_BYTES => HostHeader::TooLong,
        Some(host) => HostHeader::Present(host),
        None => HostHeader::Malformed,
    }
}

/// The request host with port and brackets removed, or `None` when the request
/// names no usable host.
///
/// Callers that must tell "no host" from "not a host" read [`host_header`].
/// Admission does, so by the time routing and authorization run the two have
/// already been answered differently, and a `None` here is a request with no
/// host.
pub(crate) fn request_host_without_port(headers: &HeaderMap) -> Option<String> {
    match host_header(headers) {
        HostHeader::Present(host) => Some(host),
        HostHeader::Absent | HostHeader::Malformed | HostHeader::TooLong => None,
    }
}

/// Parses `uri-host [ ":" port ]` (RFC 9110 section 7.2) into the lower-cased
/// host, refusing anything the grammar does not admit.
///
/// The value returned always satisfies [`is_bare_host`]: an unbracketed host
/// is a `reg-name` or an IPv4 literal, neither of which contains a colon or a
/// slash, and a bracketed host is accepted only if it parses as an IPv6
/// address. `IPvFuture` is refused rather than guessed at.
fn parse_host_without_port(value: &str) -> Option<String> {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = match &rest[end + 1..] {
            "" => "",
            after => after.strip_prefix(':')?,
        };
        if host.parse::<Ipv6Addr>().is_err() {
            return None;
        }
        (host, port)
    } else {
        let (host, port) = value.split_once(':').unwrap_or((value, ""));
        if host.is_empty() || !is_reg_name(host) {
            return None;
        }
        (host, port)
    };
    // `port = *DIGIT` in the grammar; a value a socket could never bind is
    // refused too. Checked as digits first because `u16::from_str` accepts a
    // sign.
    if !port.is_empty()
        && (!port.bytes().all(|byte| byte.is_ascii_digit()) || port.parse::<u16>().is_err())
    {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

/// RFC 3986 `reg-name`: unreserved, percent-encoded and sub-delimiter bytes.
/// IPv4 literals are a subset, so they need no separate rule.
fn is_reg_name(host: &str) -> bool {
    let bytes = host.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let encoded = bytes.get(index + 1..index + 3);
            if !encoded.is_some_and(|pair| pair.iter().all(u8::is_ascii_hexdigit)) {
                return false;
            }
            index += 3;
            continue;
        }
        if !(byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=".contains(&byte)) {
            return false;
        }
        index += 1;
    }
    true
}

/// Whether a value is a host with its port and brackets already removed, the
/// form [`request_host_without_port`] produces.
///
/// Colons cannot simply be refused. That helper strips the brackets from
/// `[2001:db8::1]:8443` and returns `2001:db8::1`, so rejecting every colon
/// would make the policy kernel unable to answer for an IPv6-addressed request
/// at all -- including one whose policy has no host-qualified routes and for
/// which the host could not have changed the decision. A bare IPv6 literal is
/// recognized by parsing it, rather than by guessing at colon counts.
pub(crate) fn is_bare_host(host: &str) -> bool {
    if host.is_empty() || host.contains('/') {
        return false;
    }
    if host.contains(':') {
        return host.parse::<Ipv6Addr>().is_ok();
    }
    true
}

fn route_matches<T: RouteMatch>(route: &T, path: &str, request_host: Option<&str>) -> bool {
    let host_matches = route.host().is_none_or(|host| request_host == Some(host));
    let path_matches = route
        .path_prefix()
        .is_none_or(|path_prefix| path_prefix_matches(path, path_prefix));

    host_matches && path_matches
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    #[test]
    fn longest_prefix_and_host_specific_tiebreak_match_proxy_contract() {
        let routes = vec![
            AuthorizationRouteMatch::new(Some("/api".to_owned()), None),
            AuthorizationRouteMatch::new(
                Some("/api".to_owned()),
                Some("admin.example.test".to_owned()),
            ),
            AuthorizationRouteMatch::new(Some("/api/reports".to_owned()), None),
        ];

        let host_specific = matching_route(&routes, "/api/users", Some("admin.example.test"))
            .expect("host-specific route should match equal prefix");
        assert_eq!(host_specific.host(), Some("admin.example.test"));

        let longer_path = matching_route(&routes, "/api/reports/daily", Some("admin.example.test"))
            .expect("longer path route should win");
        assert_eq!(longer_path.path_prefix(), Some("/api/reports"));
        assert_eq!(longer_path.host(), None);
    }

    #[test]
    fn host_parser_lowercases_and_ignores_ports() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "API.EXAMPLE.TEST:8443".parse().unwrap());

        assert_eq!(
            request_host_without_port(&headers).as_deref(),
            Some("api.example.test")
        );
    }

    #[test]
    fn host_header_reduces_every_valid_form_to_a_bare_lowercase_host() {
        for (raw, expected) in [
            ("api.example.test", "api.example.test"),
            ("API.EXAMPLE.TEST:8443", "api.example.test"),
            ("api.example.test:", "api.example.test"),
            ("192.0.2.10:80", "192.0.2.10"),
            ("[2001:DB8::1]", "2001:db8::1"),
            ("[2001:db8::1]:8443", "2001:db8::1"),
            ("  api.example.test  ", "api.example.test"),
            ("under_score.example", "under_score.example"),
            ("xn--bcher-kva.example", "xn--bcher-kva.example"),
            ("a%41b.example", "a%41b.example"),
            ("trailing.dot.", "trailing.dot."),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::HOST, raw.parse().unwrap());

            assert_eq!(
                host_header(&headers),
                HostHeader::Present(expected.to_owned()),
                "{raw:?}"
            );
            // The kernel's predicate must hold for everything admission
            // lets through; a Present host that failed it would be refused
            // at evaluation as malformed after being admitted as fine.
            assert!(is_bare_host(expected), "{raw:?}");
        }
    }

    #[test]
    fn host_header_tells_no_host_from_not_a_host() {
        assert_eq!(host_header(&HeaderMap::new()), HostHeader::Absent);
        for raw in ["", "   "] {
            let mut headers = HeaderMap::new();
            headers.insert(header::HOST, raw.parse().unwrap());
            assert_eq!(host_header(&headers), HostHeader::Absent, "{raw:?}");
        }

        for raw in [
            // Bracketed but not an IPv6 literal: the lenient parser yielded
            // `a:b:c`, which the kernel refuses as InvalidHost.
            "[a:b:c]",
            "[2001:db8::1",
            "[2001:db8::1]x",
            "[2001:db8::1]:x",
            "[]",
            "api.example.test:x",
            "api.example.test:+80",
            "api.example.test:65536",
            "api.example.test/data",
            "a b",
            "host@evil.example",
            "a%zz.example",
            "a%4",
            // An unbracketed IPv6 literal reads as host `2001` with port
            // `db8::1`, and that is no port. The literal must be bracketed.
            "2001:db8::1",
            ":8443",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::HOST, raw.parse().unwrap());
            assert_eq!(host_header(&headers), HostHeader::Malformed, "{raw:?}");
            assert_eq!(request_host_without_port(&headers), None, "{raw:?}");
        }

        let mut headers = HeaderMap::new();
        headers.append(header::HOST, "a.example".parse().unwrap());
        headers.append(header::HOST, "b.example".parse().unwrap());
        assert_eq!(host_header(&headers), HostHeader::Malformed, "two hosts");

        let mut headers = HeaderMap::new();
        headers.insert(
            header::HOST,
            HeaderValue::from_bytes(b"caf\xc3\xa9.example").unwrap(),
        );
        assert_eq!(host_header(&headers), HostHeader::Malformed, "non-ASCII");
    }

    #[test]
    fn host_header_bounds_the_host_without_counting_its_port() {
        let at_limit = "a".repeat(MAX_REQUEST_HOST_BYTES);
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, at_limit.parse().unwrap());
        assert_eq!(host_header(&headers), HostHeader::Present(at_limit.clone()));

        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, format!("{at_limit}:8443").parse().unwrap());
        assert_eq!(host_header(&headers), HostHeader::Present(at_limit.clone()));

        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, format!("{at_limit}a").parse().unwrap());
        assert_eq!(host_header(&headers), HostHeader::TooLong);
        assert_eq!(request_host_without_port(&headers), None);
    }
}
