//! Shared request path matching helpers.

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
