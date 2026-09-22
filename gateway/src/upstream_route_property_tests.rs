//! Pure host/route properties: no router, resolver, client, or gateway state.

use http::{header, HeaderMap, HeaderValue, Uri};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, RngSeed};
use std::net::Ipv6Addr;

use super::{
    classify_host_value, host_header, is_bare_host, matching_route, request_host_without_port,
    AuthorizationRouteMatch, HostHeader,
};
use crate::request_bounds::MAX_REQUEST_HOST_BYTES;

fn property_config() -> Config {
    Config {
        cases: 128,
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(435_002),
        max_shrink_iters: 2_048,
        ..Config::default()
    }
}

fn hostname() -> impl Strategy<Value = String> {
    ("[a-z][a-z0-9]{0,15}", "[a-z][a-z0-9]{0,15}")
        .prop_map(|(left, right)| format!("{left}.{right}.test"))
}

fn host_value() -> impl Strategy<Value = String> {
    prop_oneof![
        hostname(),
        "[ -~]{0,256}",
        proptest::collection::vec(any::<char>(), 0..257)
            .prop_map(|characters| characters.into_iter().collect()),
    ]
}

proptest! {
    #![proptest_config(property_config())]

    #[test]
    fn ascii_case_and_numeric_port_preserve_the_bare_host(
        host in hostname(), port in any::<u16>(),
    ) {
        let value = format!("{}:{port}", host.to_ascii_uppercase());
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_str(&value).unwrap());
        let uri = Uri::from_static("/synthetic");
        prop_assert_eq!(host_header(&uri, &headers), HostHeader::Present(host.clone()));
        prop_assert_eq!(request_host_without_port(&uri, &headers), Some(host.clone()));
        prop_assert_eq!(classify_host_value(&format!("  {value}\t")).0, HostHeader::Present(host));
    }

    #[test]
    fn bracketed_ipv6_loses_only_brackets_port_and_ascii_case(
        octets in any::<[u8; 16]>(), port in any::<u16>(),
    ) {
        let bare = Ipv6Addr::from(octets).to_string();
        let input = format!("[{}]:{port}", bare.to_ascii_uppercase());
        prop_assert_eq!(classify_host_value(&input).0, HostHeader::Present(bare));
    }

    #[test]
    fn field_and_authority_must_agree_including_the_raw_port(
        host in hostname(), port in any::<u16>(),
    ) {
        let uri: Uri = format!("http://{host}:{port}/synthetic").parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST,
            HeaderValue::from_str(&format!("{}:{port}", host.to_ascii_uppercase())).unwrap());
        prop_assert_eq!(host_header(&uri, &headers), HostHeader::Present(host.clone()));
        // Even two valid authorities must not be silently reconciled.
        let other_port = port.wrapping_add(1);
        headers.insert(header::HOST,
            HeaderValue::from_str(&format!("{host}:{other_port}")).unwrap());
        prop_assert_eq!(host_header(&uri, &headers), HostHeader::Malformed);
        prop_assert_eq!(request_host_without_port(&uri, &headers), None);
        // Numeric equality is not raw authority equality: leading zeros stay significant.
        headers.insert(header::HOST,
            HeaderValue::from_str(&format!("{host}:0{port}")).unwrap());
        prop_assert_eq!(host_header(&uri, &headers), HostHeader::Malformed);
    }

    #[test]
    fn duplicate_host_fields_fail_even_when_identical(host in hostname()) {
        let value = HeaderValue::from_str(&host).unwrap();
        let mut headers = HeaderMap::new();
        headers.append(header::HOST, value.clone());
        headers.append(header::HOST, value);
        let uri = Uri::from_static("/synthetic");
        prop_assert_eq!(host_header(&uri, &headers), HostHeader::Malformed);
        prop_assert_eq!(request_host_without_port(&uri, &headers), None);
    }

    #[test]
    fn percent_escapes_and_trailing_dots_are_not_dns_canonicalized(
        host in hostname(), byte in any::<u8>(),
    ) {
        let escaped = format!("%{byte:02X}{host}.");
        prop_assert_eq!(classify_host_value(&escaped).0,
            HostHeader::Present(escaped.to_ascii_lowercase()));
        // There is no decoding of percent escapes, trailing-dot removal, or DNS lookup.
        prop_assert_ne!(classify_host_value(&escaped).0, classify_host_value(&host).0);
    }

    #[test]
    fn host_result_is_bounded_even_when_a_valid_port_is_appended(
        generated_length in 1usize..=MAX_REQUEST_HOST_BYTES + 32, port in any::<u16>(),
    ) {
        // Every generated port exercises both sides of the exact boundary;
        // the broad generated length is additional coverage, not a probability
        // that the rejection branch will happen to run.
        for length in [generated_length, MAX_REQUEST_HOST_BYTES - 1,
                       MAX_REQUEST_HOST_BYTES, MAX_REQUEST_HOST_BYTES + 1] {
            let host = "h".repeat(length);
            let actual = classify_host_value(&format!("{host}:{port}")).0;
            if length > MAX_REQUEST_HOST_BYTES {
                prop_assert_eq!(actual, HostHeader::TooLong);
            } else {
                prop_assert_eq!(actual, HostHeader::Present(host));
            }
        }
    }

    #[test]
    fn bounded_arbitrary_values_have_deterministic_canonical_outputs(value in host_value()) {
        let (first, raw) = classify_host_value(&value);
        let second = classify_host_value(&value);
        prop_assert_eq!(&first, &second.0);
        prop_assert_eq!(&raw, &second.1);
        prop_assert!(raw.len() <= value.len());
        if let HostHeader::Present(host) = first {
            prop_assert!(host.len() <= MAX_REQUEST_HOST_BYTES);
            prop_assert!(host.is_ascii());
            prop_assert!(host.bytes().all(|byte| !byte.is_ascii_uppercase()));
            prop_assert!(is_bare_host(&host));
        }
        // Invalid HeaderValue bytes are outside host_header's input contract.
        if let Ok(header_value) = HeaderValue::from_bytes(value.as_bytes()) {
            let mut headers = HeaderMap::new();
            headers.insert(header::HOST, header_value);
            let uri = Uri::from_static("/synthetic");
            let classified = host_header(&uri, &headers);
            prop_assert_eq!(&classified, &host_header(&uri, &headers));
            match classified {
                HostHeader::Present(host) => {
                    prop_assert!(host.len() <= MAX_REQUEST_HOST_BYTES);
                    prop_assert_eq!(request_host_without_port(&uri, &headers), Some(host));
                }
                _ => prop_assert_eq!(request_host_without_port(&uri, &headers), None),
            }
        }
    }

    #[test]
    fn route_selection_prefers_length_then_host_then_first_tie(
        segment in "[a-z]{1,24}", child in "[a-z]{1,24}", host in hostname(),
    ) {
        let prefix = format!("/{segment}");
        let deeper = format!("{prefix}/{child}");
        let path = format!("{deeper}/item");
        let shorter_host = AuthorizationRouteMatch::new(Some(prefix), Some(host.clone()));
        let longer_generic = AuthorizationRouteMatch::new(Some(deeper.clone()), None);
        let longer_host = AuthorizationRouteMatch::new(Some(deeper), Some(host.clone()));
        let routes = vec![shorter_host, longer_generic.clone()];
        prop_assert!(std::ptr::eq(matching_route(&routes, &path, Some(&host)).unwrap(), &routes[1]));
        let routes = vec![longer_generic, longer_host.clone(), longer_host];
        prop_assert!(std::ptr::eq(matching_route(&routes, &path, Some(&host)).unwrap(), &routes[1]));
        prop_assert!(std::ptr::eq(matching_route(&routes, &path, Some("other.invalid")).unwrap(), &routes[0]));
    }
}
