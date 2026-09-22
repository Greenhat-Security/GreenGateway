//! Pure egress properties: no resolver, client, runtime, or network is created.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use ipnet::IpNet;
use proptest::{
    arbitrary::any,
    collection::vec,
    prop_assert, prop_assert_eq, proptest,
    strategy::Strategy,
    test_runner::{Config, RngAlgorithm, RngSeed},
};

use super::{
    checked_socket_addr, classify_nat64_address, extract_rfc6052_ipv4, host_glob_matches,
    is_non_global_ip, EgressError, Nat64Address,
};

// RFC 6052's byte placements are an independent fixture, not a copy of the
// implementation's integer shifts. Every generated IPv4 visits all six layouts.
const RFC6052_LAYOUTS: [(u8, [usize; 4]); 6] = [
    (32, [4, 5, 6, 7]),
    (40, [5, 6, 7, 9]),
    (48, [6, 7, 9, 10]),
    (56, [7, 9, 10, 11]),
    (64, [9, 10, 11, 12]),
    (96, [12, 13, 14, 15]),
];

fn embed_well_known_nat64(ipv4: Ipv4Addr) -> Ipv6Addr {
    let [a, b, c, d] = ipv4.octets();
    Ipv6Addr::from([0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, a, b, c, d])
}

fn embed_rfc6052(
    ipv4: Ipv4Addr,
    prefix_len: u8,
    positions: [usize; 4],
    mut octets: [u8; 16],
) -> (Ipv6Addr, IpNet) {
    let prefix_octets = [
        0x20, 0x01, 0x48, 0x60, 0x01, 0x22, 0x03, 0x44, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let prefix_bytes = usize::from(prefix_len / 8);
    octets[..prefix_bytes].copy_from_slice(&prefix_octets[..prefix_bytes]);
    octets[8] = 0;
    for (position, value) in positions.into_iter().zip(ipv4.octets()) {
        octets[position] = value;
    }
    let prefix = IpNet::new(IpAddr::V6(Ipv6Addr::from(prefix_octets)), prefix_len)
        .expect("fixture prefix length is valid")
        .trunc();
    (Ipv6Addr::from(octets), prefix)
}

// Generate a member of every blocked IPv4 class on every case. This makes deny
// preservation non-vacuous even if arbitrary IPv4 generation favors public IPs.
fn blocked_ipv4_samples([a, b, c, d]: [u8; 4]) -> [Ipv4Addr; 15] {
    [
        Ipv4Addr::new(0, b, c, d),
        Ipv4Addr::new(10, b, c, d),
        Ipv4Addr::new(100, 64 + b % 64, c, d),
        Ipv4Addr::new(127, b, c, d),
        Ipv4Addr::new(169, 254, c, d),
        Ipv4Addr::new(172, 16 + b % 16, c, d),
        // Keep clear of the two global exceptions, 192.0.0.9 and .10.
        Ipv4Addr::new(192, 0, 0, d % 9),
        Ipv4Addr::new(192, 0, 2, d),
        Ipv4Addr::new(192, 88, 99, d),
        Ipv4Addr::new(192, 168, c, d),
        Ipv4Addr::new(198, 18 + b % 2, c, d),
        Ipv4Addr::new(198, 51, 100, d),
        Ipv4Addr::new(203, 0, 113, d),
        Ipv4Addr::new(224 + a % 16, b, c, d),
        Ipv4Addr::new(240 + a % 16, b, c, d),
    ]
}

#[derive(Clone, Debug)]
struct GeneratedAnswer {
    socket: SocketAddr,
    non_global: bool,
    // Indices correspond to the literal-family CIDRs in private_exceptions.
    exception: Option<usize>,
}

fn answer_strategy(include_unexempted: bool) -> impl Strategy<Value = GeneratedAnswer> {
    let kinds = if include_unexempted { 0_u8..7 } else { 0_u8..5 };
    (kinds, any::<[u8; 16]>(), any::<u16>()).prop_map(|(kind, mut bytes, port)| {
        let private = Ipv4Addr::new(10, bytes[0], bytes[1], bytes[2]);
        let loopback = Ipv4Addr::new(127, bytes[0], bytes[1], bytes[2]);
        // These expected classifications follow directly from the generated
        // address classes, without asking either production policy helper.
        let (ip, non_global, exception) = match kind {
            0 => (
                IpAddr::V4(Ipv4Addr::new(8, bytes[0], bytes[1], bytes[2])),
                false,
                None,
            ),
            1 => {
                bytes[..4].copy_from_slice(&[0x26, 0x06, 0x47, 0x00]);
                (IpAddr::V6(Ipv6Addr::from(bytes)), false, None)
            }
            2 => (IpAddr::V4(private), true, Some(0)),
            3 => (IpAddr::V6(private.to_ipv6_mapped()), true, Some(1)),
            4 => {
                bytes[0] = 0xfd;
                (IpAddr::V6(Ipv6Addr::from(bytes)), true, Some(2))
            }
            5 => (IpAddr::V4(loopback), true, None),
            _ => (IpAddr::V6(loopback.to_ipv6_mapped()), true, None),
        };
        GeneratedAnswer {
            socket: SocketAddr::new(ip, port),
            non_global,
            exception,
        }
    })
}

fn private_exceptions(enabled: [bool; 3]) -> Vec<IpNet> {
    ["10.0.0.0/8", "::ffff:a00:0/104", "fd00::/8"]
        .into_iter()
        .zip(enabled)
        .filter(|(_, enabled)| *enabled)
        .map(|(cidr, _)| cidr.parse().expect("fixture policy CIDR is valid"))
        .collect()
}

proptest! {
    // Fixed seed 435001 makes CI runs repeatable; each property has 128 cases
    // and at most 2048 shrink iterations. Inputs are 4/16-byte addresses,
    // answer sets of at most 12 sockets, and DNS labels of at most 12 bytes.
    #![proptest_config(Config {
        cases: 128,
        max_shrink_iters: 2048,
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(435_001),
        ..Config::default()
    })]

    #[test]
    fn mapped_ipv6_preserves_arbitrary_ipv4_classification(octets in any::<[u8; 4]>()) {
        let ipv4 = Ipv4Addr::from(octets);
        prop_assert_eq!(
            is_non_global_ip(IpAddr::V6(ipv4.to_ipv6_mapped()), &[]),
            is_non_global_ip(IpAddr::V4(ipv4), &[])
        );
    }

    #[test]
    fn mapped_ipv6_cannot_escape_any_blocked_ipv4_class(octets in any::<[u8; 4]>()) {
        for ipv4 in blocked_ipv4_samples(octets) {
            prop_assert!(is_non_global_ip(IpAddr::V4(ipv4), &[]), "{ipv4}");
            prop_assert!(is_non_global_ip(IpAddr::V6(ipv4.to_ipv6_mapped()), &[]), "{ipv4}");
        }
    }

    #[test]
    fn every_rfc6052_layout_extracts_and_classifies_arbitrary_ipv4(
        ipv4_octets in any::<[u8; 4]>(),
        suffix in any::<[u8; 16]>(),
    ) {
        let ipv4 = Ipv4Addr::from(ipv4_octets);
        let well_known = embed_well_known_nat64(ipv4);
        prop_assert_eq!(classify_nat64_address(well_known, &[]), Nat64Address::Embedded(ipv4));
        prop_assert_eq!(
            is_non_global_ip(IpAddr::V6(well_known), &[]),
            is_non_global_ip(IpAddr::V4(ipv4), &[])
        );
        for (prefix_len, positions) in RFC6052_LAYOUTS {
            // Unused suffix octets remain arbitrary: extraction does not
            // require a zero suffix, and this test must not imply otherwise.
            let (address, prefix) = embed_rfc6052(ipv4, prefix_len, positions, suffix);
            prop_assert!(prefix.contains(&IpAddr::V6(address)));
            prop_assert_eq!(extract_rfc6052_ipv4(address, prefix_len), Some(ipv4));
            prop_assert_eq!(classify_nat64_address(address, &[prefix]), Nat64Address::Embedded(ipv4));
            prop_assert_eq!(
                is_non_global_ip(IpAddr::V6(address), &[prefix]),
                is_non_global_ip(IpAddr::V4(ipv4), &[])
            );
        }
    }

    #[test]
    fn every_rfc6052_layout_preserves_each_blocked_ipv4_class(
        ipv4_octets in any::<[u8; 4]>(),
        suffix in any::<[u8; 16]>(),
    ) {
        for ipv4 in blocked_ipv4_samples(ipv4_octets) {
            prop_assert!(is_non_global_ip(IpAddr::V6(embed_well_known_nat64(ipv4)), &[]));
            for (prefix_len, positions) in RFC6052_LAYOUTS {
                let (address, prefix) = embed_rfc6052(ipv4, prefix_len, positions, suffix);
                prop_assert_eq!(extract_rfc6052_ipv4(address, prefix_len), Some(ipv4));
                prop_assert!(is_non_global_ip(IpAddr::V6(address), &[prefix]), "{address}");
            }
        }
    }

    #[test]
    fn nonzero_u_octet_fails_closed_for_every_rfc6052_layout(
        host_octets in any::<[u8; 3]>(),
        suffix in any::<[u8; 16]>(),
        u_octet in 1_u8..=u8::MAX,
    ) {
        let public_ipv4 = Ipv4Addr::new(8, host_octets[0], host_octets[1], host_octets[2]);
        for (prefix_len, positions) in RFC6052_LAYOUTS {
            let (valid, prefix) = embed_rfc6052(public_ipv4, prefix_len, positions, suffix);
            prop_assert!(!is_non_global_ip(IpAddr::V6(valid), &[prefix]));
            let mut malformed = valid.octets();
            malformed[8] = u_octet;
            let malformed = Ipv6Addr::from(malformed);
            prop_assert_eq!(extract_rfc6052_ipv4(malformed, prefix_len), None);
            if prefix_len != 96 {
                prop_assert!(prefix.contains(&IpAddr::V6(malformed)));
                prop_assert_eq!(classify_nat64_address(malformed, &[prefix]), Nat64Address::Malformed);
                prop_assert!(is_non_global_ip(IpAddr::V6(malformed), &[prefix]));
            }
            // In /96 the u octet is part of the prefix, so mutating it leaves
            // this configured prefix. Only the extractor's rejection applies;
            // startup does not accept a /96 prefix with a nonzero u octet.
        }
    }

    #[test]
    fn unsupported_rfc6052_prefix_lengths_never_extract(mut octets in any::<[u8; 16]>()) {
        // Keep u valid so rejection is caused solely by the prefix length.
        octets[8] = 0;
        let address = Ipv6Addr::from(octets);
        for prefix_len in 0_u8..=u8::MAX {
            if !RFC6052_LAYOUTS.iter().any(|(supported, _)| *supported == prefix_len) {
                prop_assert_eq!(extract_rfc6052_ipv4(address, prefix_len), None);
            }
        }
    }

    #[test]
    fn answer_set_admission_and_permutations_follow_the_whole_set_oracle(
        mut answers in vec((answer_strategy(true), any::<u64>()), 0..=12),
        exceptions in any::<[bool; 3]>(),
        deny_private in any::<bool>(),
    ) {
        let cidrs = private_exceptions(exceptions);
        let mut original_admission = None;
        // Sorting independent generated keys permutes the same multiset.
        for permutation in 0..2 {
            if permutation == 1 {
                answers.sort_by_key(|(_, key)| *key);
            }
            let sockets: Vec<_> = answers.iter().map(|(answer, _)| answer.socket).collect();
            let first_blocked = answers.iter().find_map(|(answer, _)| {
                let exempted = answer.exception.is_some_and(|index| exceptions[index]);
                (deny_private && answer.non_global && !exempted).then_some(answer.socket.ip())
            });
            let result = checked_socket_addr("property.example.test", &sockets, deny_private, &[], &cidrs);
            let expected_admission = !sockets.is_empty() && first_blocked.is_none();
            prop_assert_eq!(result.is_ok(), expected_admission);
            if let Some(original) = original_admission {
                prop_assert_eq!(result.is_ok(), original);
            } else {
                original_admission = Some(result.is_ok());
            }
            match (sockets.first(), first_blocked, result) {
                (None, _, Err(EgressError::DnsResolutionFailed(host))) => {
                    prop_assert_eq!(host, "property.example.test");
                }
                (Some(_), Some(expected), Err(EgressError::NonGlobalIpBlocked(actual))) => {
                    prop_assert_eq!(actual, expected);
                }
                (Some(expected), None, Ok(actual)) => prop_assert_eq!(actual, *expected),
                (_, _, unexpected) => prop_assert!(false, "unexpected answer-set result: {unexpected:?}"),
            }
        }
    }

    #[test]
    fn every_safe_answer_set_pins_its_first_socket(
        answers in vec(answer_strategy(false), 1..=12),
    ) {
        let cidrs = private_exceptions([true; 3]);
        let mut sockets: Vec<_> = answers.iter().map(|answer| answer.socket).collect();
        for _ in 0..sockets.len() {
            let pinned = checked_socket_addr("property.example.test", &sockets, true, &[], &cidrs)
                .expect("all generated answers are public or explicitly exempted");
            prop_assert_eq!(pinned, sockets[0]);
            sockets.rotate_left(1);
        }
    }

    #[test]
    fn private_cidr_exceptions_respect_the_literal_address_family(
        octets in any::<[u8; 3]>(),
        port in any::<u16>(),
    ) {
        let ipv4 = Ipv4Addr::new(10, octets[0], octets[1], octets[2]);
        let v4_socket = SocketAddr::new(IpAddr::V4(ipv4), port);
        let mapped_socket = SocketAddr::new(IpAddr::V6(ipv4.to_ipv6_mapped()), port);
        for allow_v4 in [false, true] {
            for allow_mapped in [false, true] {
                let cidrs = private_exceptions([allow_v4, allow_mapped, false]);
                prop_assert_eq!(
                    checked_socket_addr("property.example.test", &[v4_socket], true, &[], &cidrs).is_ok(),
                    allow_v4
                );
                prop_assert_eq!(
                    checked_socket_addr("property.example.test", &[mapped_socket], true, &[], &cidrs).is_ok(),
                    allow_mapped
                );
                for pair in [[v4_socket, mapped_socket], [mapped_socket, v4_socket]] {
                    prop_assert_eq!(
                        checked_socket_addr("property.example.test", &pair, true, &[], &cidrs).is_ok(),
                        allow_v4 && allow_mapped
                    );
                }
            }
        }
    }

    #[test]
    fn hostname_globs_ignore_ascii_case_but_preserve_label_boundaries(
        label in "[a-z]{1,12}",
        subdomain in "[a-z]{1,12}",
    ) {
        let suffix = format!("{label}.example.test");
        let pattern = format!("*.{suffix}");
        let host = format!("{subdomain}.{suffix}");
        let nested = format!("nested.{host}");
        let concatenated = format!("{subdomain}{suffix}");
        let outside = format!("{host}.outside.test");
        prop_assert!(host_glob_matches(&pattern.to_ascii_uppercase(), &host));
        prop_assert!(host_glob_matches(&pattern, &host.to_ascii_uppercase()));
        prop_assert!(host_glob_matches(&host.to_ascii_uppercase(), &host));
        prop_assert!(host_glob_matches(&pattern, &nested));
        prop_assert!(!host_glob_matches(&pattern, &suffix));
        prop_assert!(!host_glob_matches(&pattern, &concatenated));
        prop_assert!(!host_glob_matches(&pattern, &outside));
    }
}
