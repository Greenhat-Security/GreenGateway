//! Literal path contracts; these properties deliberately do not URL-decode.

use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, RngSeed};

use super::{
    exempt_path_matches, is_unsafe_request_path, path_prefix_matches, GATEWAY_EXACT_ROUTE_PATHS,
};

fn property_config() -> Config {
    Config {
        cases: 128,
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(435_003),
        max_shrink_iters: 2_048,
        ..Config::default()
    }
}

fn segments() -> impl Strategy<Value = Vec<String>> {
    proptest::collection::vec("[a-zA-Z0-9_-]{1,24}", 1..9)
}

proptest! {
    #![proptest_config(property_config())]

    #[test]
    fn safe_segments_match_only_on_literal_segment_boundaries(
        components in segments(), suffix in "[a-zA-Z0-9_-]{1,24}",
    ) {
        let path = format!("/{}", components.join("/"));
        let trailing = format!("{path}/");
        let descendant = format!("{path}/{suffix}");
        let lookalike = format!("{path}{suffix}");
        prop_assert!(!is_unsafe_request_path(&path));
        prop_assert!(!is_unsafe_request_path(&trailing));
        prop_assert!(path_prefix_matches(&path, &path));
        prop_assert!(path_prefix_matches(&descendant, &path));
        prop_assert!(path_prefix_matches(&trailing, &path));
        prop_assert!(!path_prefix_matches(&lookalike, &path));
        prop_assert!(!path_prefix_matches(&path, path.trim_start_matches('/')));
        prop_assert!(!path_prefix_matches(&path, ""));
        prop_assert!(path_prefix_matches(&path, "/"));
    }

    #[test]
    fn ambiguous_representation_insertion_remains_unsafe(
        components in segments(), position in 0usize..9,
    ) {
        let boundary = position % (components.len() + 1);
        // Insert between segments rather than assuming a dot inside a filename is unsafe.
        for marker in [".", "..", "%2e", "%2F", "%", "\\", ""] {
            let mut altered = components.clone();
            altered.insert(boundary, marker.to_owned());
            let path = format!("/{}/tail", altered.join("/"));
            prop_assert!(is_unsafe_request_path(&path), "missed ambiguity: {path:?}");
        }
    }

    #[test]
    fn exact_probe_exemptions_never_expand_to_generated_descendants(
        components in segments(), lookalike in "[a-z]{1,16}",
    ) {
        for probe in GATEWAY_EXACT_ROUTE_PATHS {
            let descendant = format!("{probe}/{}", components.join("/"));
            let trailing = format!("{probe}/");
            let concatenated = format!("{probe}{lookalike}");
            prop_assert!(exempt_path_matches(probe, probe));
            prop_assert!(!exempt_path_matches(&descendant, probe));
            prop_assert!(!exempt_path_matches(&trailing, probe));
            prop_assert!(!exempt_path_matches(&concatenated, probe));
        }
    }

    #[test]
    fn ordinary_exemption_and_trailing_slash_keep_subtree_semantics(
        components in segments(), child in "[a-z]{1,24}",
    ) {
        // The fixed /synthetic prefix cannot coincide with any exact probe route.
        let prefix = format!("/synthetic/{}", components.join("/"));
        let descendant = format!("{prefix}/{child}");
        let lookalike = format!("{prefix}{child}");
        prop_assert!(exempt_path_matches(&prefix, &prefix));
        prop_assert!(exempt_path_matches(&descendant, &prefix));
        prop_assert!(!exempt_path_matches(&lookalike, &prefix));
        let directory = format!("{prefix}/");
        prop_assert!(path_prefix_matches(&descendant, &directory));
        prop_assert!(!path_prefix_matches(&prefix, &directory));
    }
}
