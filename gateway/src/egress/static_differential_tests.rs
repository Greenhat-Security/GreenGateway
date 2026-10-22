//! Differential evidence for the static egress cutover (#422 PR 3b).
//!
//! The frozen pre-cutover checks (`static_legacy_tests.rs`) and the live
//! adapter are asked the same questions on one installed client, which means
//! one configuration and one resolver, and compared answer by answer: the
//! checked destination or the error (its safe category and its full text), and
//! every name each side asked the resolver for. Destinations that pass are then
//! rebound and revalidated by both, against every URL of the case and against
//! pinned addresses an attacker might have substituted. The oracle is the
//! original implementation, never a hand-written expectation.
//!
//! The zero-DNS harness at the end is the cutover's acceptance criterion: a
//! destination the static checks refuse never reaches the resolver, on any
//! entry point.

use std::sync::Mutex;

use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, RngAlgorithm, RngSeed};

use super::*;

/// How the resolver answers every lookup in a case.
#[derive(Clone, Debug)]
enum Answer {
    /// These addresses, on the port the caller asked for.
    Addresses(Vec<IpAddr>),
    /// These addresses, on a port the caller did not ask for.
    WrongPort(Vec<IpAddr>),
    Failure,
}

struct RecordingResolver {
    answer: Answer,
    calls: Mutex<Vec<(String, u16)>>,
}

impl RecordingResolver {
    fn new(answer: Answer) -> Self {
        Self {
            answer,
            calls: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<(String, u16)> {
        self.calls
            .lock()
            .expect("recording resolver lock should not be poisoned")
            .clone()
    }
}

#[async_trait]
impl DnsResolver for RecordingResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
        self.calls
            .lock()
            .expect("recording resolver lock should not be poisoned")
            .push((host.to_owned(), port));
        match &self.answer {
            Answer::Addresses(addresses) => Ok(addresses
                .iter()
                .map(|address| SocketAddr::new(*address, port))
                .collect()),
            Answer::WrongPort(addresses) => Ok(addresses
                .iter()
                .map(|address| SocketAddr::new(*address, port.wrapping_add(1)))
                .collect()),
            Answer::Failure => Err(std::io::Error::other("synthetic resolver failure")),
        }
    }
}

/// A resolver that must never be reached.
struct PanickingResolver;

#[async_trait]
impl DnsResolver for PanickingResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, std::io::Error> {
        panic!("a statically refused egress destination reached the resolver");
    }
}

/// An answer as both sides are compared on it: the value, or the error's safe
/// category and its full text.
#[derive(Debug, PartialEq, Eq)]
enum Observed<T> {
    Value(T),
    Refused {
        category: &'static str,
        message: String,
    },
}

fn observe<T>(result: Result<T, EgressError>) -> Observed<T> {
    match result {
        Ok(value) => Observed::Value(value),
        Err(error) => Observed::Refused {
            category: error.safe_category(),
            message: error.to_string(),
        },
    }
}

fn observe_revalidated(
    result: Result<(Url, String, u16), EgressError>,
) -> Observed<(String, String, u16)> {
    observe(result.map(|(url, host, port)| (url.to_string(), host, port)))
}

fn client(config: EgressConfig, resolver: Arc<dyn DnsResolver>) -> EgressClient {
    EgressClient::new_with_resolver_and_cache(
        config,
        resolver,
        Arc::new(client_cache::PinnedClientCache::new()),
    )
    .expect("differential client should build")
}

fn calls_since(resolver: &RecordingResolver, before: usize) -> Vec<(String, u16)> {
    resolver.calls().split_off(before)
}

/// Asks both sides every question for one configuration and answer set.
async fn assert_frozen_and_live_agree(
    config: &EgressConfig,
    answer: &Answer,
    urls: &[String],
    substitutes: &[IpAddr],
) -> Vec<Observed<CheckedEgressDestination>> {
    let resolver = Arc::new(RecordingResolver::new(answer.clone()));
    let installed = client(config.clone(), resolver.clone());
    // A client under other controls, for the generation checks.
    let mut other_config = config.clone();
    other_config
        .allowed_hosts
        .insert("generation.example.test".to_owned());
    let other = client(other_config, resolver.clone());

    let mut observed = Vec::new();
    for url in urls {
        let before = resolver.calls().len();
        let frozen = observe(installed.legacy_checked_destination(url).await);
        let frozen_calls = calls_since(&resolver, before);
        let before = resolver.calls().len();
        let live = observe(installed.checked_destination(url).await);
        let live_calls = calls_since(&resolver, before);
        assert_eq!(frozen, live, "checked destination for {url}");
        assert_eq!(frozen_calls, live_calls, "resolver calls for {url}");

        if let Observed::Value(destination) = &live {
            let before = resolver.calls().len();
            let mut candidates = vec![destination.clone()];
            for substitute in substitutes {
                let mut substituted = destination.clone();
                substituted.pinned_addr =
                    SocketAddr::new(*substitute, destination.pinned_addr.port());
                candidates.push(substituted);
            }
            for candidate in &candidates {
                for target in urls {
                    for checker in [&installed, &other] {
                        assert_eq!(
                            observe(checker.legacy_rebind_checked_destination(candidate, target)),
                            observe(checker.rebind_checked_destination(candidate, target)),
                            "rebind of {url} to {target}"
                        );
                        assert_eq!(
                            observe_revalidated(
                                checker.legacy_revalidated_destination(candidate, target)
                            ),
                            observe_revalidated(checker.revalidated_destination(candidate, target)),
                            "revalidation of {url} for {target}"
                        );
                    }
                }
            }
            assert_eq!(
                calls_since(&resolver, before),
                Vec::new(),
                "rebind and revalidation resolve nothing"
            );
        }
        observed.push(live);
    }
    observed
}

const EXACT_HOSTS: &[&str] = &[
    "api.example.test",
    "svc.example.test",
    "127.0.0.1",
    "[::1]",
    // Built by hand rather than loaded, so never lowercased: it never matched.
    "API.EXAMPLE.TEST",
];
const HOST_GLOBS: &[&str] = &[
    "*.example.test",
    "*.svc.example.test",
    "*.EXAMPLE.TEST",
    "api.example.test",
];
const PORT_LISTS: &[u16] = &[80, 443, 8443];
const NAT64_PREFIXES: &[&str] = &["64:ff9b:1::/48"];
const POLICY_CIDRS: &[&str] = &[
    "10.0.0.0/8",
    "192.168.1.0/24",
    "fd00::/8",
    "::ffff:10.0.0.0/104",
];
const SCHEMES: &[&str] = &["http", "https", "HTTPS", "ftp", "ws"];
const URL_HOSTS: &[&str] = &[
    "api.example.test",
    "API.Example.Test",
    "evil-api.example.test",
    "v1.api.example.test",
    "svc.example.test",
    "a.svc.example.test",
    "example.test",
    "badexample.test",
    "127.0.0.1",
    "[::1]",
    "other.test",
];
const URL_PORTS: &[Option<u16>] = &[None, Some(80), Some(443), Some(8443), Some(9443)];
/// Inputs no generated URL reaches: no host, no parse, an out-of-range port.
const IRREGULAR_URLS: &[&str] = &[
    "data:text/plain,hello",
    "mailto:someone@example.test",
    "file:///etc/hosts",
    "http://",
    "not a url",
    "http://api.example.test:99999/",
];

fn address(value: &str) -> IpAddr {
    value.parse().expect("test address should parse")
}

fn answer_sets() -> Vec<Vec<IpAddr>> {
    [
        &[][..],
        &["93.184.216.34"],
        &["93.184.216.34", "1.1.1.1"],
        &["93.184.216.34", "10.1.2.3"],
        &["10.1.2.3"],
        &["192.168.1.10"],
        &["192.168.2.10", "93.184.216.34"],
        &["127.0.0.1"],
        &["100.64.0.1"],
        &["2606:4700:4700::1111"],
        &["fd00::1"],
        &["::ffff:10.0.0.7"],
        // Configured NAT64 prefix: an embedded public, then a private, IPv4.
        &["64:ff9b:1:808:8:800::"],
        &["64:ff9b:1:a9fe:a9:fe00::"],
    ]
    .iter()
    .map(|set| set.iter().map(|value| address(value)).collect())
    .collect()
}

fn substitutes() -> Vec<IpAddr> {
    [
        "8.8.8.8",
        "10.0.0.1",
        "192.168.1.5",
        "127.0.0.1",
        "fd00::1",
        "::ffff:10.0.0.1",
    ]
    .iter()
    .map(|value| address(value))
    .collect()
}

fn generated_config(
    exact: &[usize],
    globs: &[usize],
    ports: &[usize],
    deny_private_ips: bool,
    nat64: bool,
    cidrs: &[usize],
) -> EgressConfig {
    EgressConfig {
        allowed_hosts: exact
            .iter()
            .map(|index| EXACT_HOSTS[*index].to_owned())
            .collect(),
        allowed_host_globs: globs
            .iter()
            .map(|index| HOST_GLOBS[*index].to_owned())
            .collect(),
        allowed_ports: ports.iter().map(|index| PORT_LISTS[*index]).collect(),
        deny_private_ips,
        nat64_prefixes: if nat64 {
            NAT64_PREFIXES
                .iter()
                .map(|prefix| prefix.parse().expect("test NAT64 prefix should parse"))
                .collect()
        } else {
            Vec::new()
        },
        private_ip_allow_cidrs: cidrs
            .iter()
            .map(|index| {
                POLICY_CIDRS[*index]
                    .parse()
                    .expect("test policy CIDR should parse")
            })
            .collect(),
        ..EgressConfig::default()
    }
}

/// (scheme, userinfo, host, port, query, fragment) as indexes into the pools;
/// a scheme index past the pool picks an irregular URL instead.
type GeneratedUrl = (usize, u8, usize, usize, bool, bool);

fn generated_url((scheme, userinfo, host, port, query, fragment): GeneratedUrl) -> String {
    if scheme >= SCHEMES.len() {
        return IRREGULAR_URLS[(scheme - SCHEMES.len()) % IRREGULAR_URLS.len()].to_owned();
    }
    let userinfo = match userinfo {
        0 => "",
        1 => "operator@",
        _ => "operator:canary@",
    };
    let port = URL_PORTS[port].map_or_else(String::new, |port| format!(":{port}"));
    format!(
        "{}://{userinfo}{}{port}/resource{}{}",
        SCHEMES[scheme],
        URL_HOSTS[host],
        if query { "?page=2" } else { "" },
        if fragment { "#section" } else { "" },
    )
}

fn generated_answer(mode: u8, set: usize) -> Answer {
    let addresses = answer_sets().swap_remove(set % answer_sets().len());
    match mode {
        0 | 1 => Answer::Addresses(addresses),
        2 => Answer::WrongPort(addresses),
        _ => Answer::Failure,
    }
}

fn index_subset(len: usize) -> impl Strategy<Value = Vec<usize>> {
    proptest::sample::subsequence((0..len).collect::<Vec<_>>(), 0..=len)
}

fn differential_config() -> ProptestConfig {
    ProptestConfig {
        cases: 128,
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(422_004),
        max_shrink_iters: 1_024,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(differential_config())]

    #[test]
    fn generated_controls_and_answers_are_decided_alike_by_the_frozen_and_live_checks(
        exact in index_subset(EXACT_HOSTS.len()),
        globs in index_subset(HOST_GLOBS.len()),
        ports in index_subset(PORT_LISTS.len()),
        deny_private_ips in any::<bool>(),
        nat64 in any::<bool>(),
        cidrs in index_subset(POLICY_CIDRS.len()),
        answer_mode in 0u8..4,
        answer_set in 0usize..14,
        urls in proptest::collection::vec(
            (
                0..SCHEMES.len() + IRREGULAR_URLS.len(),
                0u8..3,
                0..URL_HOSTS.len(),
                0..URL_PORTS.len(),
                any::<bool>(),
                // Mostly fragment-free, so most URLs reach the host check.
                proptest::bool::weighted(0.15),
            ),
            1..5,
        ),
    ) {
        let config = generated_config(&exact, &globs, &ports, deny_private_ips, nat64, &cidrs);
        let answer = generated_answer(answer_mode, answer_set);
        let urls: Vec<String> = urls.into_iter().map(generated_url).collect();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a test runtime")
            .block_on(async {
                assert_frozen_and_live_agree(&config, &answer, &urls, &substitutes()).await;
            });
    }
}

fn config_with(edit: impl FnOnce(&mut EgressConfig)) -> EgressConfig {
    let mut config = EgressConfig {
        allowed_hosts: HashSet::from(["api.example.test".to_owned()]),
        allowed_host_globs: vec!["*.svc.example.test".to_owned()],
        ..EgressConfig::default()
    };
    edit(&mut config);
    config
}

fn public() -> Answer {
    Answer::Addresses(vec![address("93.184.216.34"), address("1.1.1.1")])
}

/// The category each named case must end in, so the matrix cannot pass by
/// both sides agreeing on something other than what it names.
fn expected_category(observed: &Observed<CheckedEgressDestination>) -> &'static str {
    match observed {
        Observed::Value(_) => "allowed",
        Observed::Refused { category, .. } => category,
    }
}

#[tokio::test]
async fn the_frozen_and_live_checks_agree_across_the_named_matrix() {
    let private = Answer::Addresses(vec![address("10.1.2.3")]);
    let mixed = Answer::Addresses(vec![address("93.184.216.34"), address("10.1.2.3")]);
    let cases: Vec<(&str, EgressConfig, Answer, &str, &str)> = vec![
        // Each refusal on its own.
        (
            "unparseable",
            config_with(|_| {}),
            public(),
            "http://",
            "invalid_url",
        ),
        (
            "no host",
            config_with(|_| {}),
            public(),
            "data:text/plain,hello",
            "invalid_url",
        ),
        (
            "userinfo",
            config_with(|_| {}),
            public(),
            "https://operator@api.example.test/",
            "invalid_url",
        ),
        (
            "fragment",
            config_with(|_| {}),
            public(),
            "https://api.example.test/#part",
            "invalid_url",
        ),
        (
            "scheme",
            config_with(|_| {}),
            public(),
            "ftp://api.example.test/",
            "scheme_not_allowed",
        ),
        (
            "host",
            config_with(|_| {}),
            public(),
            "https://other.example.test/",
            "host_not_allowed",
        ),
        (
            "port",
            config_with(|config| config.allowed_ports = HashSet::from([443])),
            public(),
            "https://api.example.test:8443/",
            "port_not_allowed",
        ),
        (
            "resolver failure",
            config_with(|_| {}),
            Answer::Failure,
            "https://api.example.test/",
            "dns_resolution_failed",
        ),
        (
            "empty answer",
            config_with(|_| {}),
            Answer::Addresses(Vec::new()),
            "https://api.example.test/",
            "dns_resolution_failed",
        ),
        (
            "wrong port",
            config_with(|_| {}),
            Answer::WrongPort(vec![address("93.184.216.34")]),
            "https://api.example.test/",
            "dns_resolution_failed",
        ),
        (
            "private answer",
            config_with(|_| {}),
            private.clone(),
            "https://api.example.test/",
            "non_global_ip_blocked",
        ),
        (
            "mixed answers",
            config_with(|_| {}),
            mixed.clone(),
            "https://api.example.test/",
            "non_global_ip_blocked",
        ),
        // Two failures at once report the earlier check.
        (
            "userinfo before scheme",
            config_with(|_| {}),
            public(),
            "ftp://operator@api.example.test/",
            "invalid_url",
        ),
        (
            "fragment before host",
            config_with(|_| {}),
            public(),
            "https://other.example.test/#part",
            "invalid_url",
        ),
        (
            "scheme before host",
            config_with(|_| {}),
            public(),
            "ftp://other.example.test/",
            "scheme_not_allowed",
        ),
        (
            "host before port",
            config_with(|config| config.allowed_ports = HashSet::from([443])),
            public(),
            "https://other.example.test:8443/",
            "host_not_allowed",
        ),
        // Admissions.
        (
            "exact host",
            config_with(|_| {}),
            public(),
            "https://api.example.test/",
            "allowed",
        ),
        (
            "folded exact host",
            config_with(|_| {}),
            public(),
            "https://API.Example.TEST/",
            "allowed",
        ),
        (
            "pattern host",
            config_with(|_| {}),
            public(),
            "https://worker.svc.example.test/",
            "allowed",
        ),
        (
            "pattern does not cover its suffix",
            config_with(|_| {}),
            public(),
            "https://svc.example.test/",
            "host_not_allowed",
        ),
        (
            "exact host does not cover its subdomains",
            config_with(|_| {}),
            public(),
            "https://v1.api.example.test/",
            "host_not_allowed",
        ),
        (
            "exact host is not a suffix",
            config_with(|_| {}),
            public(),
            "https://evil-api.example.test/",
            "host_not_allowed",
        ),
        (
            "listed port",
            config_with(|config| config.allowed_ports = HashSet::from([443, 8443])),
            public(),
            "https://api.example.test:8443/",
            "allowed",
        ),
        (
            "a CIDR exempts its private answer",
            config_with(|config| {
                config.private_ip_allow_cidrs = vec!["10.0.0.0/8".parse().expect("CIDR")]
            }),
            mixed.clone(),
            "https://api.example.test/",
            "allowed",
        ),
        (
            "a CIDR exempts only its own range",
            config_with(|config| {
                config.private_ip_allow_cidrs = vec!["192.168.1.0/24".parse().expect("CIDR")]
            }),
            mixed.clone(),
            "https://api.example.test/",
            "non_global_ip_blocked",
        ),
        (
            "private answers allowed when non-global blocking is off",
            config_with(|config| config.deny_private_ips = false),
            private,
            "https://api.example.test/",
            "allowed",
        ),
        (
            "a configured NAT64 prefix embeds a private address",
            config_with(|config| {
                config.nat64_prefixes = vec!["64:ff9b:1::/48".parse().expect("prefix")]
            }),
            Answer::Addresses(vec![address("64:ff9b:1:a9fe:a9:fe00::")]),
            "https://api.example.test/",
            "non_global_ip_blocked",
        ),
        (
            "an IPv6 literal host reaches the resolver bracketed",
            config_with(|config| {
                config.allowed_hosts.insert("[::1]".to_owned());
            }),
            Answer::Failure,
            "http://[::1]/",
            "dns_resolution_failed",
        ),
    ];
    for (name, config, answer, url, expected) in cases {
        let observed =
            assert_frozen_and_live_agree(&config, &answer, &[url.to_owned()], &substitutes()).await;
        assert_eq!(expected_category(&observed[0]), expected, "{name}");
    }
}

/// Every entry point that resolves a destination name, driven with a URL.
async fn every_resolving_entry_point(client: &EgressClient, url: &str) -> Vec<EgressError> {
    let mut errors = Vec::new();
    if let Err(error) = client.checked_destination(url).await {
        errors.push(error);
    }
    if let Err(error) = client.request(Method::GET, url).await {
        errors.push(error);
    }
    if let Err(error) = client
        .request_with_headers(Method::POST, url, HeaderMap::new(), Some(b"{}".to_vec()))
        .await
    {
        errors.push(error);
    }
    if let Err(error) = client
        .stream_request_with_body(Method::GET, url, HeaderMap::new(), EgressRequestBody::Empty)
        .await
    {
        errors.push(error);
    }
    if let Err(error) = client
        .stream_request_with_body_for_sse(
            Method::GET,
            url,
            HeaderMap::new(),
            EgressRequestBody::Empty,
            Some(1024),
        )
        .await
    {
        errors.push(error);
    }
    errors
}

#[tokio::test]
async fn a_statically_refused_destination_never_reaches_the_resolver_on_any_entry_point() {
    let config = config_with(|config| {
        config.allowed_ports = HashSet::from([443]);
    });
    let refusing = client(config.clone(), Arc::new(PanickingResolver));
    let refusals = [
        ("data:text/plain,hello", "invalid_url"),
        ("https://operator@api.example.test/", "invalid_url"),
        ("https://api.example.test/#part", "invalid_url"),
        ("ftp://api.example.test/", "scheme_not_allowed"),
        ("https://other.example.test/", "host_not_allowed"),
        ("https://svc.example.test/", "host_not_allowed"),
        ("https://api.example.test:8443/", "port_not_allowed"),
        ("http://api.example.test/", "port_not_allowed"),
    ];
    for (url, category) in refusals {
        let errors = every_resolving_entry_point(&refusing, url).await;
        assert_eq!(errors.len(), 5, "every entry point refuses {url}");
        for error in errors {
            assert_eq!(error.safe_category(), category, "{url}");
        }
    }

    // The same controls with a resolver that answers: an admitted destination
    // is resolved exactly once per decision, and only then.
    let resolver = Arc::new(RecordingResolver::new(public()));
    let answering = client(config, resolver.clone());
    for (url, _) in refusals {
        assert!(answering.checked_destination(url).await.is_err());
    }
    assert!(
        resolver.calls().is_empty(),
        "no refused destination was resolved"
    );
    answering
        .checked_destination("https://api.example.test/")
        .await
        .expect("an admitted destination is resolved and pinned");
    assert_eq!(resolver.calls(), vec![("api.example.test".to_owned(), 443)]);
}

#[tokio::test]
async fn rebinding_and_revalidation_never_reach_the_resolver_even_when_they_admit() {
    let config = config_with(|_| {});
    let resolver = Arc::new(RecordingResolver::new(public()));
    let checking = client(config.clone(), resolver.clone());
    let url = "https://api.example.test/resource";
    let destination = checking
        .checked_destination(url)
        .await
        .expect("the destination is admitted");
    assert_eq!(resolver.calls().len(), 1);

    let rebinding = client(config, Arc::new(PanickingResolver));
    let rebound = rebinding
        .rebind_checked_destination(&destination, url)
        .expect("the same controls admit the pinned address again");
    assert_eq!(rebound.pinned_addr, destination.pinned_addr);
    let (_, host, port) = rebinding
        .revalidated_destination(&rebound, url)
        .expect("the rebound destination revalidates");
    assert_eq!((host.as_str(), port), ("api.example.test", 443));

    let mut substituted = rebound;
    substituted.pinned_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443);
    assert!(matches!(
        rebinding.revalidated_destination(&substituted, url),
        Err(EgressError::NonGlobalIpBlocked(blocked)) if blocked == IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    ));
    substituted.pinned_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
    assert!(matches!(
        rebinding.revalidated_destination(&substituted, url),
        Err(EgressError::NonGlobalIpBlocked(_))
    ));
}
