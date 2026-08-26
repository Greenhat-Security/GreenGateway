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
        || path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_matches_at_segment_boundary_only() {
        assert!(path_prefix_matches("/admin", "/admin"));
        assert!(path_prefix_matches("/admin/assets/index.js", "/admin"));
        assert!(path_prefix_matches("/admin/", "/admin"));

        assert!(!path_prefix_matches("/administrator", "/admin"));
        assert!(!path_prefix_matches("/admin-panel", "/admin"));
        assert!(!path_prefix_matches("/adminish/path", "/admin"));
    }

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

    #[test]
    fn non_probe_exempt_entries_keep_subtree_semantics() {
        assert!(exempt_path_matches("/admin", "/admin"));
        assert!(exempt_path_matches("/admin/assets/app.js", "/admin"));
        assert!(exempt_path_matches(
            "/v1/admin/auth/callback",
            "/v1/admin/auth/callback"
        ));
        assert!(exempt_path_matches("/public/docs", "/public"));

        assert!(!exempt_path_matches("/administrator", "/admin"));
    }

    #[test]
    fn non_absolute_prefixes_do_not_match() {
        assert!(!path_prefix_matches("/admin", "admin"));
        assert!(!path_prefix_matches("/admin", ""));
    }

    #[test]
    fn unsafe_paths_include_encoding_dot_segments_and_backslashes() {
        for path in [
            "/%61dmin",
            "/admin%2Fassets",
            "/a/./b",
            "/a/../b",
            "/public/..\\admin",
            "/admin\\assets",
        ] {
            assert!(is_unsafe_request_path(path), "{path}");
        }

        for path in ["/admin", "/files/report.json", "/files/v1.2/report"] {
            assert!(!is_unsafe_request_path(path), "{path}");
        }
    }
}
