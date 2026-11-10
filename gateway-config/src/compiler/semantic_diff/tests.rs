use std::{
    collections::{BTreeMap, BTreeSet},
    env::VarError,
};

use super::{plans, SETTINGS};
use crate::{
    compiler::{inventory::CONFIG_INPUTS, plan, plan::ConfigPlan},
    semantic_diff::{ChangeClass, Display, Effect, RiskCode, SemanticDiff, Severity, Shown},
};

const CANARY: &str = "zqcanary";

type Fixture = BTreeMap<&'static str, &'static str>;

/// A strict starting point: loopback only, TLS 1.3 floor, one egress host,
/// a policy, an audit file, a discovery store, and required authority
/// evidence with the sink it needs (audit durability is `required` by
/// default).
fn base() -> Fixture {
    BTreeMap::from([
        ("LISTEN_ADDR", "127.0.0.1:8080"),
        ("AUTHORITY_EVIDENCE_DURABILITY", "required"),
        ("AUTHORITY_EVENT_SINK", "log"),
        ("AUTHORITY_PSEUDONYM_KEY_ALIAS", "pseudonym-a"),
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

#[test]
fn exemption_risk_measures_coverage_of_the_served_paths() {
    for (field, before, after, effect) in [
        (
            "AUTH_EXEMPT_PATHS",
            "/admin",
            "/admin/assets",
            Effect::Tightened,
        ),
        (
            "RBAC_EXEMPT_PATHS",
            "/admin",
            "/admin,/admin/assets",
            Effect::Neutral,
        ),
        ("AUTH_EXEMPT_PATHS", "/admin/", "/admin", Effect::Loosened),
        ("RBAC_EXEMPT_PATHS", "/admin", "/adminx", Effect::Loosened),
        (
            "AUTH_EXEMPT_PATHS",
            "/health",
            "/health/x",
            Effect::Loosened,
        ),
        ("RBAC_EXEMPT_PATHS", "/health", "/health/", Effect::Loosened),
        (
            "CSRF_EXEMPT_PATHS",
            "/admin",
            "/admin/assets",
            Effect::Loosened,
        ),
    ] {
        let strict = base();
        let diff = diff(
            &with(strict.clone(), &[(field, Some(before))]),
            &with(strict, &[(field, Some(after))]),
        );
        let [change] = diff.changes() else {
            panic!("expected one change for {field}")
        };
        assert_eq!(change.effect(), effect, "{field} {before} -> {after}");
        assert_eq!(
            change.risks().contains(&RiskCode::ExemptionsBroadened),
            effect == Effect::Loosened
        );
        assert_eq!(change.display(), Display::Withheld);
    }
}

#[test]
fn profile_exemptions_follow_the_configured_admin_surface() {
    let document = |prefix, auth, rbac, csrf| {
        serde_json::json!({
            "spec": {
                "listeners": {"admin": {"prefix": prefix}},
                "authentication": {"exempt_paths": auth},
                "authorization": {"exempt_paths": rbac},
                "csrf": {"exempt_paths": csrf}
            }
        })
    };
    let safe = document(
        "/ops",
        vec!["/ops/assets", "/readyz", "/ops/assets"],
        vec![],
        vec!["/metrics", "/health"],
    );
    assert_eq!(super::broadened_profile_exemptions(&safe).count(), 0);
    // A probe used as the admin prefix still matches exactly in the middleware.
    let probe_prefix = document("/health", vec!["/health/ui"], vec![], vec![]);
    assert_eq!(
        super::broadened_profile_exemptions(&probe_prefix).count(),
        1
    );
    let mut changed = document(
        "/ops",
        vec!["/v1/ops/auth/login/child"],
        vec!["/v1/ops/auth/config"],
        vec!["/ops"],
    );
    let broadened = |doc: &serde_json::Value| {
        super::broadened_profile_exemptions(doc)
            .map(|(_, path)| path)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        broadened(&changed),
        [
            "/spec/authentication/exempt_paths",
            "/spec/authorization/exempt_paths",
            "/spec/csrf/exempt_paths"
        ]
    );
    changed["spec"]["admin_login"] = serde_json::json!({"provider":"test"});
    assert_eq!(
        broadened(&changed),
        [
            "/spec/authorization/exempt_paths",
            "/spec/csrf/exempt_paths"
        ]
    );
    changed["spec"]["admin_sessions"] = serde_json::json!({"mode":"standalone_memory"});
    assert_eq!(broadened(&changed), ["/spec/csrf/exempt_paths"]);
    changed["spec"]["authentication"]["exempt_paths"] =
        serde_json::json!(["/admin/assets", "/opsx", "/health/private"]);
    assert_eq!(
        broadened(&changed),
        [
            "/spec/authentication/exempt_paths",
            "/spec/csrf/exempt_paths"
        ]
    );
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
    // Each durability mode spelled out as its default.
    let defaults = diff(
        &with(base(), &[("AUTHORITY_EVIDENCE_DURABILITY", None)]),
        &with(
            base(),
            &[
                ("AUTHORITY_EVIDENCE_DURABILITY", Some("best_effort")),
                ("AUTHORITY_EVENT_FORMAT", Some("delivery_v1")),
                ("AUDIT_DURABILITY", Some("required")),
            ],
        ),
    );
    assert!(defaults.is_empty(), "{:?}", fields(&defaults));
}

#[test]
fn authority_event_format_diff_shows_the_consumer_contract_change() {
    let negotiated = with(base(), &[("AUTHORITY_EVENT_FORMAT", Some("qualified_v1"))]);
    let change = diff(&base(), &negotiated);
    assert_eq!(fields(&change), ["AUTHORITY_EVENT_FORMAT"]);
    assert_eq!(change.changes()[0].effect(), Effect::Neutral);
    assert_eq!(
        change.changes()[0].display(),
        Display::Shown {
            before: Shown::Word("delivery_v1"),
            after: Shown::Word("qualified_v1"),
        }
    );
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
        &["risk.evidence_not_required"],
        true,
    ),
    (
        &[("AUTHORITY_EVIDENCE_DURABILITY", Some("best_effort"))],
        &["risk.evidence_not_required"],
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

/// Leaving `required` lets a request be served, or an authority change be
/// made, without a durable record of it: that is high, whichever way the
/// weaker mode is reached. Returning to `required` carries no risk.
#[test]
fn weakening_audit_or_authority_evidence_durability_is_high_and_strengthening_carries_no_risk() {
    let strict = base();
    for (name, weaker) in [
        ("AUDIT_DURABILITY", Some("best_effort")),
        ("AUTHORITY_EVIDENCE_DURABILITY", Some("best_effort")),
        // Unset is `best_effort` here.
        ("AUTHORITY_EVIDENCE_DURABILITY", None),
    ] {
        let relaxed = with(base(), &[(name, weaker)]);
        let forward = diff(&strict, &relaxed);
        assert_eq!(fields(&forward), [name], "{name}={weaker:?}");
        let change = &forward.changes()[0];
        assert_eq!(change.effect(), Effect::Loosened, "{name}");
        assert_eq!(
            change.risks().iter().copied().collect::<Vec<_>>(),
            [RiskCode::EvidenceNotRequired],
            "{name}"
        );
        assert_eq!(change.severity(), Some(Severity::High), "{name}");
        assert_eq!(forward.severity(), Some(Severity::High), "{name}");
        assert_eq!(
            change.display(),
            Display::Shown {
                before: Shown::Word("required"),
                after: Shown::Word("best_effort"),
            },
            "{name}"
        );

        let back = diff(&relaxed, &strict);
        assert_eq!(fields(&back), [name], "{name}={weaker:?}");
        let change = &back.changes()[0];
        assert_eq!(change.effect(), Effect::Tightened, "{name}");
        assert!(change.risks().is_empty(), "{name}: {:?}", codes(&back));
        assert_eq!(back.severity(), None, "{name}");
    }

    // Relaxing both is still one code at the same severity, and adding any
    // other weakening on top never lowers it.
    let both = with(
        base(),
        &[
            ("AUDIT_DURABILITY", Some("best_effort")),
            ("AUTHORITY_EVIDENCE_DURABILITY", Some("best_effort")),
        ],
    );
    let relaxed = diff(&strict, &both);
    assert_eq!(
        codes(&relaxed),
        BTreeSet::from(["risk.evidence_not_required"])
    );
    assert_eq!(relaxed.severity(), Some(Severity::High));
    for (overrides, _, _) in WEAKENINGS {
        let more = diff(&strict, &with(both.clone(), overrides));
        assert!(more.severity() >= relaxed.severity(), "{overrides:?}");
        assert!(more.risks().contains(&RiskCode::EvidenceNotRequired));
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
