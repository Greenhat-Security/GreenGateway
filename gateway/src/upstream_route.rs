//! Shared upstream-route selection used by authorization and proxy forwarding.

use http::{header, HeaderMap};

use crate::path_match::path_prefix_matches;

pub(crate) trait RouteMatch {
    fn path_prefix(&self) -> Option<&str>;
    fn host(&self) -> Option<&str>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthorizationRouteMatch {
    path_prefix: Option<String>,
    host: Option<String>,
}

impl AuthorizationRouteMatch {
    pub(crate) fn new(path_prefix: Option<String>, host: Option<String>) -> Self {
        Self { path_prefix, host }
    }
}

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

pub(crate) fn request_host_without_port(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::HOST)?.to_str().ok()?.trim();
    if value.is_empty() {
        return None;
    }

    let host = if let Some(rest) = value.strip_prefix('[') {
        let end = rest.find(']')?;
        &rest[..end]
    } else {
        value.split_once(':').map_or(value, |(host, _)| host)
    };

    (!host.is_empty()).then(|| host.to_ascii_lowercase())
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
}
