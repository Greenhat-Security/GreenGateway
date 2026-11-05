//! The gateway's request path matching, which the configuration compiler
//! shares with `ggctl` through `gateway-config` (issue #242).
//!
//! The functions live in `gateway_config::path_match`. The tests
//! `security-mutations.json` selects, and the property tests, stay here: the
//! mutation campaign builds and runs only the gateway's test binary, so they
//! exercise the shared functions through this re-export.

pub(crate) use gateway_config::path_match::{
    exempt_path_matches, is_unsafe_request_path, path_prefix_matches, GATEWAY_EXACT_ROUTE_PATHS,
};

#[cfg(test)]
#[path = "path_match_property_tests.rs"]
mod property_tests;

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
    fn slash_ended_prefixes_keep_their_subtree_boundary() {
        for path in ["/admin/", "/admin/assets", "/admin/assets/index.js"] {
            assert!(path_prefix_matches(path, "/admin/"), "{path}");
        }
        for path in ["/admin", "/administrator/", "/admin-panel/assets"] {
            assert!(!path_prefix_matches(path, "/admin/"), "{path}");
        }

        for path in ["/", "/admin", "/admin/assets"] {
            assert!(path_prefix_matches(path, "/"), "{path}");
        }
        assert!(!path_prefix_matches("admin/assets", "/"));
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
    fn empty_interior_segments_are_unsafe_but_ordinary_paths_are_not() {
        // The bypass shape: this gateway does not match the protected prefix,
        // while an upstream that collapses `//` does.
        assert!(!path_prefix_matches("//admin/secrets", "/admin"));
        assert!(is_unsafe_request_path("//admin/secrets"));
        assert!(is_unsafe_request_path("/admin//secrets"));
        assert!(is_unsafe_request_path("//"));

        // Ordinary traffic must keep working. Every absolute path splits with an
        // empty leading segment, and a trailing slash is not an ambiguity:
        // `/admin/` already matches the `/admin` prefix the same way `/admin`
        // does, so both sides agree about it.
        assert!(!is_unsafe_request_path("/"));
        assert!(!is_unsafe_request_path("/admin"));
        assert!(!is_unsafe_request_path("/admin/"));
        assert!(!is_unsafe_request_path("/v1/orders/42"));
        assert!(path_prefix_matches("/admin/", "/admin"));
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
