//! The static egress lane's answers, stated outright. The live adapter asks this
//! same lane, so comparing the two would compare the lane with itself; the
//! frozen pre-cutover checks are the oracle in `egress::static_differential_tests`.

use std::net::SocketAddr;

use super::*;

fn controls() -> EgressControls {
    EgressControls {
        allowed_hosts: HashSet::from(["api.example.test".to_owned()]),
        allowed_host_globs: vec!["*.svc.example.test".to_owned()],
        allowed_ports: HashSet::new(),
        deny_private_ips: true,
        nat64_prefixes: Vec::new(),
        private_ip_allow_cidrs: Vec::new(),
    }
}

fn destination(url: &str) -> EgressDestination {
    EgressDestination::from_url(&Url::parse(url).unwrap())
}

fn context<'a>(
    policy: &CompiledEgressPolicy,
    destination: &'a EgressDestination,
    resolution: ResolutionFact<'a>,
) -> EgressEvaluationContext<'a> {
    EgressEvaluationContext {
        version: EGRESS_CONTEXT_VERSION,
        snapshot: policy.snapshot(),
        destination,
        resolution,
    }
}

fn ask(
    policy: &CompiledEgressPolicy,
    url: &str,
    resolution: ResolutionFact<'_>,
) -> EgressEvaluation {
    let destination = destination(url);
    policy
        .evaluate(&context(policy, &destination, resolution))
        .unwrap()
}

fn outcome(
    policy: &CompiledEgressPolicy,
    url: &str,
    answers: Option<&[SocketAddr]>,
) -> EgressOutcome {
    let resolution = answers.map_or(ResolutionFact::Missing, ResolutionFact::Resolved);
    ask(policy, url, resolution).outcome()
}

fn socket(value: &str) -> SocketAddr {
    value.parse().unwrap()
}

fn admitted() -> EgressOutcome {
    EgressOutcome::Indeterminate(EgressLimitation::MissingResolution)
}

fn denied(denial: EgressDenial) -> EgressOutcome {
    EgressOutcome::Deny(denial)
}

const PUBLIC: &str = "93.184.216.34:443";

#[test]
fn a_refused_destination_is_decided_without_resolution_facts() {
    let policy = CompiledEgressPolicy::new(EgressControls {
        allowed_ports: HashSet::from([443]),
        ..controls()
    });
    let public = [socket(PUBLIC)];
    for (url, denial) in [
        ("data:text/plain,hello", EgressDenial::MissingHost),
        ("https://operator@api.example.test/", EgressDenial::Userinfo),
        ("https://api.example.test/#part", EgressDenial::Fragment),
        ("ftp://api.example.test/", EgressDenial::SchemeNotAllowed),
        ("https://other.example.test/", EgressDenial::HostNotAllowed),
        (
            "https://api.example.test:8443/",
            EgressDenial::PortNotAllowed,
        ),
    ] {
        // Refused without the facts an allow would need, and the refusal is a
        // complete answer: there is nothing to resolve.
        let evaluation = ask(&policy, url, ResolutionFact::Missing);
        assert_eq!(evaluation.outcome(), denied(denial), "{url}");
        assert!(evaluation.complete, "{url}");
        assert_eq!(evaluation.logical, LogicalDecision::Deny);
        assert_eq!(evaluation.effect, PolicyEffect::Block);
        // Supplying facts afterwards cannot change a static refusal.
        assert_eq!(
            outcome(&policy, url, Some(&public)),
            denied(denial),
            "{url}"
        );
        assert_eq!(outcome(&policy, url, Some(&[])), denied(denial), "{url}");
    }
}

#[test]
fn an_admitted_destination_asks_for_resolution_and_is_never_complete_without_it() {
    let policy = CompiledEgressPolicy::new(controls());
    let evaluation = ask(
        &policy,
        "https://api.example.test/",
        ResolutionFact::Missing,
    );

    assert_eq!(evaluation.outcome(), admitted());
    assert!(!evaluation.complete);
    assert_eq!(evaluation.logical, LogicalDecision::Indeterminate);
    assert_eq!(evaluation.effect, PolicyEffect::Block);
    let destination = destination("https://api.example.test/");
    assert!(!evaluation.reusable_for(&context(&policy, &destination, ResolutionFact::Missing)));
}

#[test]
fn static_checks_refuse_in_the_pre_cutover_order() {
    let policy = CompiledEgressPolicy::new(EgressControls {
        allowed_ports: HashSet::from([443]),
        ..controls()
    });
    for (url, denial) in [
        (
            "ftp://operator@api.example.test/#part",
            EgressDenial::Userinfo,
        ),
        ("ftp://api.example.test/#part", EgressDenial::Fragment),
        (
            "ftp://other.example.test:8443/",
            EgressDenial::SchemeNotAllowed,
        ),
        (
            "https://other.example.test:8443/",
            EgressDenial::HostNotAllowed,
        ),
    ] {
        assert_eq!(outcome(&policy, url, None), denied(denial), "{url}");
    }
}

#[test]
fn an_exact_host_admits_only_itself_and_a_pattern_only_its_subdomains() {
    let policy = CompiledEgressPolicy::new(controls());
    for url in [
        "https://api.example.test/",
        // The URL's host is lowercased before it is compared.
        "https://API.Example.TEST/",
        "https://worker.svc.example.test/",
        "https://v1.worker.svc.example.test/",
    ] {
        assert_eq!(outcome(&policy, url, None), admitted(), "{url}");
    }
    for url in [
        "https://evil-api.example.test/",
        "https://xapi.example.test/",
        "https://v1.api.example.test/",
        "https://example.test/",
        "https://api.example.test.evil/",
        "https://svc.example.test/",
        "https://badsvc.example.test/",
    ] {
        assert_eq!(
            outcome(&policy, url, None),
            denied(EgressDenial::HostNotAllowed),
            "{url}"
        );
    }

    // The exact set is compared as held, so an entry the configuration loader
    // would have lowercased, built by hand, never matched and still does not.
    let upper = CompiledEgressPolicy::new(EgressControls {
        allowed_hosts: HashSet::from(["API.EXAMPLE.TEST".to_owned()]),
        allowed_host_globs: Vec::new(),
        ..controls()
    });
    assert_eq!(
        outcome(&upper, "https://api.example.test/", None),
        denied(EgressDenial::HostNotAllowed)
    );
    // An IPv6 literal keeps its brackets, as the allowlist and the resolver see it.
    assert_eq!(destination("http://[::1]/").host(), Some("[::1]"));
}

#[test]
fn a_port_list_admits_only_its_own_ports_and_an_empty_one_admits_every_port() {
    let open = CompiledEgressPolicy::new(controls());
    for url in [
        "http://api.example.test/",
        "https://api.example.test/",
        "https://api.example.test:8443/",
        "http://api.example.test:1/",
    ] {
        assert_eq!(outcome(&open, url, None), admitted(), "{url}");
    }

    let listed = CompiledEgressPolicy::new(EgressControls {
        allowed_ports: HashSet::from([443, 8443]),
        ..controls()
    });
    for url in ["https://api.example.test/", "http://api.example.test:8443/"] {
        assert_eq!(outcome(&listed, url, None), admitted(), "{url}");
    }
    for url in [
        "http://api.example.test/",
        "https://api.example.test:9443/",
        "https://api.example.test:444/",
    ] {
        assert_eq!(
            outcome(&listed, url, None),
            denied(EgressDenial::PortNotAllowed),
            "{url}"
        );
    }
}

#[test]
fn every_answer_is_judged_and_the_first_is_pinned() {
    let policy = CompiledEgressPolicy::new(controls());
    let url = "https://api.example.test/";
    let public = socket(PUBLIC);
    let second_public = socket("1.1.1.1:443");
    let private = socket("10.1.2.3:443");

    assert_eq!(
        outcome(&policy, url, Some(&[public, second_public])),
        EgressOutcome::Allow { pinned: 0 }
    );
    assert_eq!(
        outcome(&policy, url, Some(&[second_public, public])),
        EgressOutcome::Allow { pinned: 0 }
    );
    // A private answer behind a public one refuses the set; the pinned answer
    // being public is not enough.
    assert_eq!(
        outcome(&policy, url, Some(&[public, private])),
        denied(EgressDenial::NonGlobalAddress { index: 1 })
    );
    assert_eq!(
        outcome(&policy, url, Some(&[public, second_public, private])),
        denied(EgressDenial::NonGlobalAddress { index: 2 })
    );
    assert_eq!(
        outcome(&policy, url, Some(&[private, public])),
        denied(EgressDenial::NonGlobalAddress { index: 0 })
    );

    // A CIDR exempts the answers it covers, and only those.
    let exempting = CompiledEgressPolicy::new(EgressControls {
        private_ip_allow_cidrs: vec!["10.0.0.0/8".parse().unwrap()],
        ..controls()
    });
    assert_eq!(
        outcome(&exempting, url, Some(&[public, private])),
        EgressOutcome::Allow { pinned: 0 }
    );
    assert_eq!(
        outcome(
            &exempting,
            url,
            Some(&[private, socket("192.168.1.10:443")])
        ),
        denied(EgressDenial::NonGlobalAddress { index: 1 })
    );

    // With non-global blocking off, addresses do not refuse.
    let permissive = CompiledEgressPolicy::new(EgressControls {
        deny_private_ips: false,
        ..controls()
    });
    assert_eq!(
        outcome(&permissive, url, Some(&[private, socket("127.0.0.1:443")])),
        EgressOutcome::Allow { pinned: 0 }
    );
}

#[test]
fn an_empty_or_misdirected_answer_set_is_refused() {
    let policy = CompiledEgressPolicy::new(controls());
    let url = "https://api.example.test:8443/";
    assert_eq!(
        outcome(&policy, url, Some(&[])),
        denied(EgressDenial::EmptyResolution)
    );
    assert_eq!(
        outcome(&policy, url, Some(&[socket("93.184.216.34:9443")])),
        denied(EgressDenial::UnexpectedResolvedPort)
    );
    // One misdirected answer refuses the set, ahead of the address checks.
    assert_eq!(
        outcome(
            &policy,
            url,
            Some(&[socket("93.184.216.34:8443"), socket("10.1.2.3:443")])
        ),
        denied(EgressDenial::UnexpectedResolvedPort)
    );
    // Even with non-global blocking off.
    let permissive = CompiledEgressPolicy::new(EgressControls {
        deny_private_ips: false,
        ..controls()
    });
    assert_eq!(
        outcome(&permissive, url, Some(&[socket("10.1.2.3:443")])),
        denied(EgressDenial::UnexpectedResolvedPort)
    );
}

#[test]
fn embedded_ipv4_answers_are_judged_by_the_address_they_embed() {
    let url = "https://api.example.test/";
    let policy = CompiledEgressPolicy::new(EgressControls {
        nat64_prefixes: vec!["64:ff9b:1::/48".parse().unwrap()],
        ..controls()
    });
    assert_eq!(
        outcome(&policy, url, Some(&[socket("[64:ff9b:1:808:8:800::]:443")])),
        EgressOutcome::Allow { pinned: 0 }
    );
    assert_eq!(
        outcome(
            &policy,
            url,
            Some(&[socket("[64:ff9b:1:a9fe:a9:fe00::]:443")])
        ),
        denied(EgressDenial::NonGlobalAddress { index: 0 })
    );
    // An IPv4-mapped private address, and the CIDR family that exempts it.
    let mapped = [socket("[::ffff:10.0.0.7]:443")];
    assert_eq!(
        outcome(&policy, url, Some(&mapped)),
        denied(EgressDenial::NonGlobalAddress { index: 0 })
    );
    let v4_only = CompiledEgressPolicy::new(EgressControls {
        private_ip_allow_cidrs: vec!["10.0.0.0/8".parse().unwrap()],
        ..controls()
    });
    assert_eq!(
        outcome(&v4_only, url, Some(&mapped)),
        denied(EgressDenial::NonGlobalAddress { index: 0 })
    );
}

#[test]
fn a_question_for_other_controls_or_another_context_version_is_refused() {
    let policy = CompiledEgressPolicy::new(controls());
    let other = CompiledEgressPolicy::new(EgressControls {
        allowed_ports: HashSet::from([443]),
        ..controls()
    });
    let destination = destination("https://api.example.test/");

    let mut question = context(&other, &destination, ResolutionFact::Missing);
    assert_eq!(
        policy.evaluate(&question),
        Err(EvaluationError::SnapshotMismatch)
    );
    question = context(&policy, &destination, ResolutionFact::Missing);
    question.version = EGRESS_CONTEXT_VERSION + 1;
    assert_eq!(
        policy.evaluate(&question),
        Err(EvaluationError::UnsupportedContextVersion)
    );
}

#[test]
fn the_controls_identity_ignores_listing_order_and_changes_with_every_control() {
    let first = EgressControls {
        allowed_hosts: HashSet::from(["a.example.test".to_owned(), "b.example.test".to_owned()]),
        allowed_host_globs: vec!["*.one.example".to_owned(), "*.two.example".to_owned()],
        allowed_ports: HashSet::from([443, 8443]),
        deny_private_ips: true,
        nat64_prefixes: vec![
            "64:ff9b:1::/48".parse().unwrap(),
            "2001:db8:64::/96".parse().unwrap(),
        ],
        private_ip_allow_cidrs: vec![
            "10.0.0.0/8".parse().unwrap(),
            "192.168.0.0/16".parse().unwrap(),
        ],
    };
    let mut reordered = first.clone();
    reordered.allowed_host_globs.reverse();
    reordered.nat64_prefixes.reverse();
    reordered.private_ip_allow_cidrs.reverse();
    let snapshot = CompiledEgressPolicy::new(first.clone()).snapshot();
    assert_eq!(snapshot, CompiledEgressPolicy::new(reordered).snapshot());

    let edits: [fn(&mut EgressControls); 6] = [
        |controls| {
            controls.allowed_hosts.insert("c.example.test".to_owned());
        },
        |controls| {
            controls
                .allowed_host_globs
                .push("*.three.example".to_owned())
        },
        |controls| {
            controls.allowed_ports.insert(80);
        },
        |controls| controls.deny_private_ips = false,
        |controls| controls.nat64_prefixes.clear(),
        |controls| {
            controls.private_ip_allow_cidrs.pop();
        },
    ];
    for edit in edits {
        let mut changed = first.clone();
        edit(&mut changed);
        assert_ne!(snapshot, CompiledEgressPolicy::new(changed).snapshot());
    }
}

#[test]
fn results_bind_the_destination_and_the_resolution_facts() {
    let policy = CompiledEgressPolicy::new(controls());
    let destination = destination("https://api.example.test/");
    let public = [socket(PUBLIC)];
    let other = [socket("1.1.1.1:443")];
    let resolved = context(&policy, &destination, ResolutionFact::Resolved(&public));
    let evaluation = policy.evaluate(&resolved).unwrap();

    assert!(evaluation.reusable_for(&resolved));
    assert!(!evaluation.reusable_for(&context(
        &policy,
        &destination,
        ResolutionFact::Resolved(&other)
    )));
    let elsewhere = super::tests::destination("https://worker.svc.example.test/");
    assert!(!evaluation.reusable_for(&context(
        &policy,
        &elsewhere,
        ResolutionFact::Resolved(&public)
    )));
    let replaced = CompiledEgressPolicy::new(EgressControls {
        allowed_ports: HashSet::from([443]),
        ..controls()
    });
    assert!(!evaluation.reusable_for(&context(
        &replaced,
        &destination,
        ResolutionFact::Resolved(&public)
    )));
    // A complete refusal binds its facts too.
    let narrow = CompiledEgressPolicy::new(EgressControls {
        allowed_host_globs: Vec::new(),
        ..controls()
    });
    let refused = context(&narrow, &elsewhere, ResolutionFact::Missing);
    let evaluation = narrow.evaluate(&refused).unwrap();
    assert_eq!(evaluation.outcome(), denied(EgressDenial::HostNotAllowed));
    assert!(evaluation.reusable_for(&refused));
    assert!(!evaluation.reusable_for(&context(&narrow, &destination, ResolutionFact::Missing)));
}

#[test]
fn the_trace_is_bounded_and_carries_no_destination_or_address() {
    let policy = CompiledEgressPolicy::new(controls());
    let answers = [socket(PUBLIC), socket("10.1.2.3:443")];
    for evaluation in [
        ask(
            &policy,
            "https://api.example.test:8443/r?q=1",
            ResolutionFact::Missing,
        ),
        ask(
            &policy,
            "https://api.example.test/",
            ResolutionFact::Resolved(&answers),
        ),
        ask(
            &policy,
            "https://other.example.test/",
            ResolutionFact::Missing,
        ),
    ] {
        let trace = String::from_utf8(evaluation.canonical_trace_bytes().unwrap()).unwrap();
        assert!(trace.len() <= MAX_TRACE_BYTES);
        assert!(trace.contains("static_egress_v1"));
        for value in [
            "example.test",
            "8443",
            "93.184",
            "10.1.2.3",
            "https:",
            "?q=1",
        ] {
            assert!(!trace.contains(value), "trace leaked {value}: {trace}");
        }
    }
    assert!(!format!(
        "{:?}{:?}{:?}",
        policy,
        destination("https://api.example.test/"),
        context(
            &policy,
            &destination("https://api.example.test/"),
            ResolutionFact::Missing
        )
    )
    .contains("example.test"));
}

#[test]
fn evaluation_is_pure_deterministic_and_thread_safe_without_a_runtime() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<CompiledEgressPolicy>();
    assert!(tokio::runtime::Handle::try_current().is_err());

    let policy = std::sync::Arc::new(CompiledEgressPolicy::new(controls()));
    let answers = [socket(PUBLIC), socket("[2606:4700:4700::1111]:443")];
    let expected = ask(
        &policy,
        "https://api.example.test/",
        ResolutionFact::Resolved(&answers),
    );
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let policy = std::sync::Arc::clone(&policy);
            std::thread::spawn(move || {
                let answers = [socket(PUBLIC), socket("[2606:4700:4700::1111]:443")];
                ask(
                    &policy,
                    "https://api.example.test/",
                    ResolutionFact::Resolved(&answers),
                )
            })
        })
        .collect();
    for thread in threads {
        assert_eq!(thread.join().unwrap(), expected);
    }
    assert_eq!(expected.outcome(), EgressOutcome::Allow { pinned: 0 });
}
