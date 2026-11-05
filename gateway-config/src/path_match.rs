//! Shared request path matching helpers.

/// Request paths the gateway router serves as fixed, exact routes.
///
/// The proxy fallback reserves these by exact comparison, so anything below
/// them (`/health/v1/orders`) is not gateway-owned and is forwarded upstream.
pub const GATEWAY_EXACT_ROUTE_PATHS: &[&str] = &[
    "/health",
    "/livez",
    "/startupz",
    "/readyz",
    "/version",
    "/metrics",
];

/// Matches a request path against an auth or RBAC exempt-list entry.
///
/// Exempt entries are segment-boundary prefixes so a single entry can cover a
/// subtree the gateway itself serves, such as the admin UI and its assets.
/// Entries naming a fixed probe route are the exception: the router serves
/// those paths exactly and the proxy fallback reserves them exactly, so a
/// prefix exemption there would hand `/health/<anything>` to the upstream with
/// authentication and authorization skipped. Matching those entries exactly
/// keeps every exemption a gateway-owned entry grants inside gateway-owned
/// space, where it can never reach the proxy.
pub fn exempt_path_matches(path: &str, exempt_path: &str) -> bool {
    if GATEWAY_EXACT_ROUTE_PATHS.contains(&exempt_path) {
        return path == exempt_path;
    }

    path_prefix_matches(path, exempt_path)
}

pub fn path_prefix_matches(path: &str, path_prefix: &str) -> bool {
    if !path_prefix.starts_with('/') {
        return false;
    }

    if path == path_prefix {
        return true;
    }

    if path_prefix.ends_with('/') {
        return path.starts_with(path_prefix);
    }

    path.strip_prefix(path_prefix)
        .is_some_and(|remaining| remaining.starts_with('/'))
}

pub fn is_unsafe_request_path(path: &str) -> bool {
    path.contains('%')
        || path.contains('\\')
        // An empty interior segment desynchronizes this gateway's matching
        // from the path the upstream resolves. `path_prefix_matches(
        // "//admin/x", "/admin")` is false, so a rule protecting `/admin`
        // does not match and the request is authorized under whatever weaker
        // rule applies, while an upstream that collapses duplicate slashes
        // serves the protected resource. Each side is individually
        // reasonable; the disagreement is the bypass.
        //
        // Written as a `//` search rather than an empty-segment scan because
        // every absolute path splits with an empty leading segment, and a
        // single trailing slash is ordinary traffic that must keep working.
        || path.contains("//")
        || path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_probe_paths_keep_exact_lookalike_behavior() {
        for path in ["/health", "/version", "/metrics"] {
            assert!(path_prefix_matches(path, path));
        }

        assert!(!path_prefix_matches("/healthz", "/health"));
        assert!(!path_prefix_matches("/versions", "/version"));
        assert!(!path_prefix_matches("/metrics.json", "/metrics"));
    }

    #[test]
    fn probe_exempt_entries_cover_only_themselves() {
        for probe in GATEWAY_EXACT_ROUTE_PATHS {
            assert!(exempt_path_matches(probe, probe), "{probe}");

            for suffix in ["/x", "/v1/orders", "/"] {
                let path = format!("{probe}{suffix}");
                assert!(
                    !exempt_path_matches(&path, probe),
                    "{path} must not be exempt via {probe}"
                );
            }
        }
    }
}
