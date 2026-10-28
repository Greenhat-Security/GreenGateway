use std::{
    collections::{BTreeMap, BTreeSet},
    env::VarError,
};

use gateway_config::semantic_diff::{
    ChangeClass, Display, Effect, RiskCode, SemanticDiff, Severity, DEFAULT_TOOL_MAX_CONCURRENT,
    DEFAULT_TOOL_TIMEOUT_MS, POLICY_TOP_LEVEL_MEMBERS,
};

use super::{plans, SETTINGS};
use crate::{
    config::{inventory::CONFIG_INPUTS, plan, plan::ConfigPlan},
    rbac::policy::{
        DEFAULT_TOOL_POLICY_MAX_CONCURRENT, DEFAULT_TOOL_POLICY_TIMEOUT_MS, KNOWN_TOP_LEVEL_KEYS,
    },
};

const CANARY: &str = "zqcanary";

type Fixture = BTreeMap<&'static str, &'static str>;

/// A strict starting point: loopback only, TLS 1.3 floor, one egress host,
/// a policy, an audit file and a discovery store.
fn base() -> Fixture {
    BTreeMap::from([
        ("LISTEN_ADDR", "127.0.0.1:8080"),
        ("TLS_MIN_VERSION", "1.3"),
        ("EGRESS_ALLOWED_HOSTS", "api.example.test"),
        ("POLICY_FILE", "/etc/greengateway/policy.json"),
        ("AUDIT_LOG_FILE", "/var/log/greengateway/audit.jsonl"),
        (
            "DISCOVERY_SQLITE_PATH",
            "/var/lib/greengateway/discovery.db",
        ),
    ])
}

/// The fixture with `overrides` applied; `None` unsets the variable.
fn with(mut fixture: Fixture, overrides: &[(&'static str, Option<&'static str>)]) -> Fixture {
    for &(name, value) in overrides {
        match value {
            Some(value) => fixture.insert(name, value),
            None => fixture.remove(name),
        };
    }
    fixture
}

fn compiled(fixture: &Fixture) -> ConfigPlan {
    plan::compile(|name| {
        fixture
            .get(name)
            .map(|value| (*value).to_owned())
            .ok_or(VarError::NotPresent)
    })
    .unwrap_or_else(|error| panic!("{fixture:?} should compile: {error:?}"))
}

fn diff(base: &Fixture, candidate: &Fixture) -> SemanticDiff {
    plans(&compiled(base), &compiled(candidate))
}

fn codes(diff: &SemanticDiff) -> BTreeSet<&'static str> {
    diff.risks().into_iter().map(RiskCode::as_str).collect()
}

fn fields(diff: &SemanticDiff) -> Vec<&'static str> {
    diff.changes().iter().map(|change| change.field()).collect()
}

#[test]
fn every_compiler_input_is_compared_exactly_once() {
    let ids: Vec<&str> = SETTINGS.iter().map(|field| field.id).collect();
    let unique: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(unique.len(), ids.len(), "a setting is listed twice");
    let inputs: BTreeSet<&str> = CONFIG_INPUTS.iter().copied().collect();
    assert_eq!(unique, inputs);
    // Only a change of state backend or deployment is a cluster operation.
    for field in SETTINGS {
        let expected = if matches!(field.id, "STATE_BACKEND" | "DEPLOYMENT_ID") {
            ChangeClass::ClusterOperation
        } else {
            ChangeClass::Restart
        };
        assert_eq!(field.class, expected, "{}", field.id);
    }
}

#[test]
fn the_policy_model_matches_the_policy_loader() {
    let mut members = KNOWN_TOP_LEVEL_KEYS.to_vec();
    let mut modelled = POLICY_TOP_LEVEL_MEMBERS.to_vec();
    members.sort_unstable();
    modelled.sort_unstable();
    assert_eq!(modelled, members);
    assert_eq!(DEFAULT_TOOL_TIMEOUT_MS, DEFAULT_TOOL_POLICY_TIMEOUT_MS);
    assert_eq!(
        DEFAULT_TOOL_MAX_CONCURRENT,
        u64::from(DEFAULT_TOOL_POLICY_MAX_CONCURRENT)
    );
}

#[test]
fn a_configuration_has_no_change_against_itself_or_a_respelling() {
    assert!(diff(&Fixture::new(), &Fixture::new()).is_empty());
    assert!(diff(&base(), &base()).is_empty());
    let hosts = |hosts| with(base(), &[("EGRESS_ALLOWED_HOSTS", Some(hosts))]);
    let reordered = diff(
        &hosts("api.example.test,b.example.test"),
        &hosts("B.Example.test,api.example.test"),
    );
    assert!(reordered.is_empty(), "{:?}", fields(&reordered));
    // An unset upstream timeout inherits the egress one.
    let explicit = diff(
        &base(),
        &with(
            base(),
            &[
                ("EGRESS_TIMEOUT_MS", Some("30000")),
                ("UPSTREAM_TIMEOUT_MS", Some("30000")),
            ],
        ),
    );
    assert!(explicit.is_empty(), "{:?}", fields(&explicit));
}

/// Settings to set (`Some`) or unset (`None`).
type Overrides = &'static [(&'static str, Option<&'static str>)];

/// A known weakening of the base: its overrides, the codes it must carry,
/// and whether undoing it is a pure tightening.
type Weakening = (Overrides, &'static [&'static str], bool);

/// Each weakening touches its own settings.
const WEAKENINGS: &[Weakening] = &[
    (
        &[("AUTH_ENABLED", Some("false"))],
        &["risk.auth_disabled"],
        true,
    ),
    (
        &[("AUTH_MODE", Some("observe"))],
        &["risk.auth_observe_only"],
        true,
    ),
    (
        &[(
            "EGRESS_ALLOWED_HOSTS",
            Some("api.example.test,more.example.test"),
        )],
        &["risk.egress_broadened"],
        true,
    ),
    (
        &[("EGRESS_DENY_PRIVATE_IPS", Some("false"))],
        &["risk.private_egress_allowed"],
        true,
    ),
    (
        &[("LISTEN_ADDR", Some("0.0.0.0:8080"))],
        &["risk.listener_exposed"],
        true,
    ),
    (
        &[("TLS_MIN_VERSION", Some("1.2"))],
        &["risk.tls_weakened"],
        true,
    ),
    (
        &[("CSRF_ENABLED", Some("false"))],
        &["risk.cookie_or_csrf_weakened"],
        true,
    ),
    (
        &[("CORS_ALLOW_ORIGINS", Some("https://app.example.test"))],
        &["risk.cors_broadened"],
        true,
    ),
    (
        &[(
            "AUTH_EXEMPT_PATHS",
            Some("/health,/livez,/startupz,/readyz,/version,/metrics,/open"),
        )],
        &["risk.exemptions_broadened"],
        false,
    ),
    (
        &[
            ("TRUST_PROXY_HEADERS", Some("true")),
            ("TRUSTED_PROXY_CIDRS", Some("10.0.0.0/8")),
        ],
        &["risk.trusted_proxies_changed"],
        true,
    ),
    (
        &[("AUDIT_DURABILITY", Some("best_effort"))],
        &["risk.audit_durability_reduced"],
        true,
    ),
    (
        &[("AUDIT_LOG_FILE", None)],
        &["risk.audit_durability_reduced"],
        true,
    ),
    (
        &[("PAYLOAD_CAPTURE_ENABLED", Some("true"))],
        &["risk.data_exposure_increased"],
        true,
    ),
    (
        &[("MAX_BODY_SIZE", Some("10485760"))],
        &["risk.limits_loosened"],
        true,
    ),
    (
        &[("RATE_LIMIT_READ_RPS", Some("500.0"))],
        &["risk.limits_loosened"],
        true,
    ),
    (
        &[("POLICY_FILE", None)],
        &["risk.policy_default_allow"],
        true,
    ),
    (
        &[("GATEWAY_PUBLIC_URL", Some("https://gateway.example.test"))],
        &["risk.public_origin_changed"],
        false,
    ),
];

#[test]
fn each_known_weakening_carries_its_code_and_undoing_it_carries_none() {
    for (overrides, expected, reversible) in WEAKENINGS {
        let weakened = with(base(), overrides);
        let forward = diff(&base(), &weakened);
        assert_eq!(
            codes(&forward),
            expected.iter().copied().collect::<BTreeSet<_>>(),
            "{overrides:?}: {:?}",
            fields(&forward)
        );
        for change in forward.changes() {
            assert_eq!(change.effect(), Effect::Loosened, "{}", change.field());
        }
        if *reversible {
            let back = diff(&weakened, &base());
            assert!(back.risks().is_empty(), "{overrides:?}: {:?}", codes(&back));
            for change in back.changes() {
                assert_eq!(change.effect(), Effect::Tightened, "{}", change.field());
            }
        }
    }
}

/// A small deterministic generator, so the property below needs no
/// dependency and fails the same way every time.
struct Seeded(u64);

impl Seeded {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

#[test]
fn combined_weakenings_carry_every_code_and_risk_never_falls_as_more_are_applied() {
    let mut seeded = Seeded(0x9e37_79b9_7f4a_7c15);
    for _ in 0..40 {
        let mut order: Vec<usize> = (0..WEAKENINGS.len()).collect();
        for index in (1..order.len()).rev() {
            order.swap(index, (seeded.next() % (index as u64 + 1)) as usize);
        }
        let mut candidate = base();
        let mut expected = BTreeSet::new();
        let mut previous_severity = None;
        for &index in order.iter().take((seeded.next() % 6 + 1) as usize) {
            let (overrides, codes_of_step, _) = WEAKENINGS[index];
            candidate = with(candidate, overrides);
            expected.extend(codes_of_step.iter().copied());
            let combined = diff(&base(), &candidate);
            assert_eq!(codes(&combined), expected, "{:?}", fields(&combined));
            assert!(combined.severity() >= previous_severity);
            previous_severity = combined.severity();
        }
    }
}

#[test]
fn authentication_egress_and_policy_weakenings_are_high() {
    for (name, value) in [
        ("AUTH_ENABLED", Some("false")),
        ("AUTH_MODE", Some("observe")),
        ("EGRESS_DENY_PRIVATE_IPS", Some("false")),
        ("POLICY_FILE", None),
    ] {
        let weakened = diff(&base(), &with(base(), &[(name, value)]));
        assert_eq!(weakened.severity(), Some(Severity::High), "{name}");
    }
}

#[test]
fn no_value_secret_or_locator_reaches_the_report() {
    let candidate = with(
        base(),
        &[
            ("TLS_CERT_FILE", Some("/run/zqcanary/cert.pem")),
            ("TLS_KEY_FILE", Some("/run/zqcanary/key.pem")),
            ("EGRESS_ALLOWED_HOSTS", Some("zqcanary.example.test")),
            ("AUDIT_LOG_FILE", Some("/var/zqcanary/audit.jsonl")),
            ("GATEWAY_PUBLIC_URL", Some("https://zqcanary.example.test")),
        ],
    );
    let diff = diff(&base(), &candidate);
    assert_eq!(
        fields(&diff),
        [
            "TLS_CERT_FILE",
            "TLS_KEY_FILE",
            "GATEWAY_PUBLIC_URL",
            "EGRESS_ALLOWED_HOSTS",
            "AUDIT_LOG_FILE",
        ]
    );
    let report = serde_json::to_string(&diff).expect("a diff serializes");
    assert!(!report.contains(CANARY), "{report}");
    assert!(!format!("{diff:?}").contains(CANARY));
    let key = diff
        .changes()
        .iter()
        .find(|change| change.field() == "TLS_KEY_FILE")
        .expect("the key changed");
    assert_eq!(key.display(), Display::Reference);
    assert_eq!(
        codes(&diff),
        BTreeSet::from([
            "risk.credential_binding_changed",
            "risk.egress_broadened",
            "risk.public_origin_changed",
        ])
    );
}
