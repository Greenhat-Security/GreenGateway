use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::*;
use crate::documents::{published_schema, API_VERSION_V1ALPHA1, REPORT_KIND};

const fn test_field(id: &'static str, risk: RiskCode, rule: Rule) -> Field {
    Field {
        id,
        section: Section::Lifecycle,
        class: ChangeClass::Restart,
        risk,
        rule,
    }
}

static ENABLED: Field = test_field(
    "TEST_ENABLED",
    RiskCode::AuthDisabled,
    Rule::LooserWhen(false),
);
static MODE: Field = test_field(
    "TEST_MODE",
    RiskCode::AuthObserveOnly,
    Rule::Ranked(&["required", "observe"]),
);
static LIMIT: Field = test_field("TEST_LIMIT", RiskCode::LimitsLoosened, Rule::HigherIsLooser);
static RETENTION: Field = test_field(
    "TEST_RETENTION",
    RiskCode::AuditDurabilityReduced,
    Rule::LowerIsLooser,
);
static HOSTS: Field = test_field(
    "TEST_HOSTS",
    RiskCode::EgressBroadened,
    Rule::GrowthIsLooser,
);
static ISSUERS: Field = test_field("TEST_ISSUERS", RiskCode::PolicyBroadened, Rule::Restriction);
static SINK: Field = test_field(
    "TEST_SINK",
    RiskCode::AuditDurabilityReduced,
    Rule::AbsenceIsLooser,
);
static ALIAS: Field = test_field(
    "TEST_ALIAS",
    RiskCode::CredentialBindingChanged,
    Rule::AnyChange,
);
static LABEL: Field = test_field("TEST_LABEL", RiskCode::UnknownImpact, Rule::Neutral);
static ROUTES: Field = test_field("TEST_ROUTES", RiskCode::RoutingChanged, Rule::AnyChange);
static ORDERED: Field = test_field(
    "TEST_ORDERED",
    RiskCode::LimitsLoosened,
    Rule::HigherIsLooser,
);
static PROVIDERS: Field = test_field(
    "TEST_PROVIDERS",
    RiskCode::AuthTrustChanged,
    Rule::Unclassified,
);

fn report(diff: &SemanticDiff) -> Value {
    serde_json::to_value(diff).expect("a diff serializes")
}

fn only(diff: &SemanticDiff) -> &Change {
    assert_eq!(diff.changes().len(), 1, "{:?}", report(diff));
    &diff.changes()[0]
}

fn risks(diff: &SemanticDiff) -> Vec<&'static str> {
    diff.risks().into_iter().map(RiskCode::as_str).collect()
}

#[test]
fn every_risk_code_is_stable_sorted_unique_and_described() {
    let texts: Vec<&str> = RiskCode::ALL.iter().map(|code| code.as_str()).collect();
    let mut sorted = texts.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(texts, sorted, "ALL is sorted by text and has no duplicate");
    for code in RiskCode::ALL {
        let reason = code
            .as_str()
            .strip_prefix("risk.")
            .expect("every code is in the risk family");
        assert!(!reason.is_empty());
        assert!(reason.starts_with(|c: char| c.is_ascii_lowercase()));
        assert!(reason
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'));
        assert!(!code.description().is_empty());
    }
    // The ADR's minimum set exists.
    for required in [
        "risk.auth_disabled",
        "risk.auth_observe_only",
        "risk.policy_default_allow",
        "risk.shadow_enabled",
        "risk.exemptions_broadened",
        "risk.listener_exposed",
        "risk.trusted_proxies_changed",
        "risk.public_origin_changed",
        "risk.cookie_or_csrf_weakened",
        "risk.cors_broadened",
        "risk.egress_broadened",
        "risk.private_egress_allowed",
        "risk.plaintext_transport",
        "risk.credential_binding_changed",
        "risk.audit_durability_reduced",
        "risk.limits_loosened",
        "risk.storage_changed",
        "risk.profile_changed",
        "risk.admin_access_path_removed",
        "risk.unknown_impact",
    ] {
        assert!(texts.contains(&required), "{required} is missing");
    }
}

#[test]
fn authentication_egress_policy_and_unknown_risks_are_high() {
    for code in [
        RiskCode::AuthDisabled,
        RiskCode::AuthObserveOnly,
        RiskCode::AuthTrustChanged,
        RiskCode::AdminAccessPathRemoved,
        RiskCode::EgressBroadened,
        RiskCode::PrivateEgressAllowed,
        RiskCode::PolicyDefaultAllow,
        RiskCode::ShadowEnabled,
        RiskCode::PolicyBroadened,
        RiskCode::ExemptionsBroadened,
        RiskCode::UnknownImpact,
    ] {
        assert_eq!(code.severity(), Severity::High, "{}", code.as_str());
    }
    assert_eq!(RiskCode::LimitsLoosened.severity(), Severity::Low);
}

#[test]
fn identical_values_record_nothing() {
    let mut comparison = Comparison::new();
    comparison.flag(&ENABLED, true, true);
    comparison.word(&MODE, "required", "required");
    comparison.count(&LIMIT, Some(5), Some(5));
    comparison.count(&RETENTION, None, None);
    comparison.rate(&LIMIT, 0.0, -0.0);
    comparison.set(&HOSTS, ["b", "a", "a"], ["a", "b"]);
    comparison.sequence(&ROUTES, &[1, 2], &[1, 2]);
    comparison.value(&LABEL, Some("x"), Some("x"));
    comparison.secret::<str>(&ALIAS, None, None);
    let entries = BTreeMap::from([("k", 1)]);
    comparison.entries(
        &PROVIDERS,
        Redaction::Withheld,
        &entries,
        &entries.clone(),
        |_, _| panic!("no entry differs"),
    );
    let diff = comparison.finish();
    assert!(diff.is_empty());
    assert_eq!(diff.severity(), None);
    assert_eq!(
        report(&diff),
        json!({"changed": false, "severity": "none", "riskCodes": [], "sections": [], "changes": []})
    );
}

#[test]
fn a_flag_loosens_only_towards_its_looser_value() {
    let mut comparison = Comparison::new();
    comparison.flag(&ENABLED, true, false);
    let diff = comparison.finish();
    let change = only(&diff);
    assert_eq!(change.effect(), Effect::Loosened);
    assert_eq!(risks(&diff), ["risk.auth_disabled"]);
    assert_eq!(
        change.display(),
        Display::Shown {
            before: Shown::Flag(true),
            after: Shown::Flag(false)
        }
    );

    let mut comparison = Comparison::new();
    comparison.flag(&ENABLED, false, true);
    let diff = comparison.finish();
    assert_eq!(only(&diff).effect(), Effect::Tightened);
    assert!(diff.risks().is_empty());
}

#[test]
fn ranked_words_order_and_an_unlisted_word_is_unknown() {
    let mut comparison = Comparison::new();
    comparison.word(&MODE, "required", "observe");
    assert_eq!(risks(&comparison.finish()), ["risk.auth_observe_only"]);

    let mut comparison = Comparison::new();
    comparison.word(&MODE, "observe", "required");
    assert_eq!(only(&comparison.finish()).effect(), Effect::Tightened);

    let mut comparison = Comparison::new();
    comparison.word(&MODE, "required", "something-else");
    let diff = comparison.finish();
    assert_eq!(only(&diff).effect(), Effect::Unknown);
    assert_eq!(risks(&diff), ["risk.unknown_impact"]);
}

#[test]
fn quantities_treat_unbounded_as_the_highest() {
    for (base, candidate, expected) in [
        (Some(10), Some(11), Effect::Loosened),
        (Some(11), Some(10), Effect::Tightened),
        (Some(10), None, Effect::Loosened),
        (None, Some(10), Effect::Tightened),
        (Some(u64::MAX - 1), Some(u64::MAX), Effect::Loosened),
    ] {
        let mut comparison = Comparison::new();
        comparison.count(&LIMIT, base, candidate);
        assert_eq!(only(&comparison.finish()).effect(), expected);
    }
    let mut comparison = Comparison::new();
    comparison.count(&RETENTION, None, Some(30));
    let diff = comparison.finish();
    assert_eq!(risks(&diff), ["risk.audit_durability_reduced"]);
    assert_eq!(
        report(&diff)["changes"][0]["value"],
        json!({"display": "shown", "before": "unbounded", "after": 30})
    );

    let mut comparison = Comparison::new();
    comparison.rate(&LIMIT, 50.0, 50.5);
    assert_eq!(risks(&comparison.finish()), ["risk.limits_loosened"]);
}

#[test]
fn a_set_is_judged_by_what_was_added_and_removed() {
    let mut comparison = Comparison::new();
    comparison.set(&HOSTS, ["a.test"], ["b.test"]);
    let diff = comparison.finish();
    let change = only(&diff);
    assert_eq!(change.effect(), Effect::Loosened);
    assert_eq!(change.display(), Display::Withheld);
    assert_eq!(
        change.entries(),
        Some(EntryCounts {
            added: 1,
            removed: 1,
            changed: 0
        })
    );

    let mut comparison = Comparison::new();
    comparison.set(&HOSTS, ["a.test", "b.test"], ["b.test"]);
    assert_eq!(only(&comparison.finish()).effect(), Effect::Tightened);
}

#[test]
fn an_emptied_restriction_is_unrestricted() {
    for (base, candidate, expected) in [
        (vec!["a"], vec![], Effect::Loosened),
        (vec![], vec!["a"], Effect::Tightened),
        (vec!["a"], vec!["a", "b"], Effect::Loosened),
        (vec!["a", "b"], vec!["a"], Effect::Tightened),
    ] {
        let mut comparison = Comparison::new();
        comparison.set(&ISSUERS, base, candidate);
        assert_eq!(only(&comparison.finish()).effect(), expected);
    }
}

#[test]
fn optional_values_follow_their_presence_rule() {
    for (base, candidate, kind, effect) in [
        (Some("a"), None, ChangeKind::Removed, Effect::Loosened),
        (None, Some("a"), ChangeKind::Added, Effect::Tightened),
        (Some("a"), Some("b"), ChangeKind::Modified, Effect::Neutral),
    ] {
        let mut comparison = Comparison::new();
        comparison.value(&SINK, base, candidate);
        let diff = comparison.finish();
        let change = only(&diff);
        assert_eq!((change.kind(), change.effect()), (kind, effect));
    }
}

#[test]
fn an_ordered_list_is_counted_and_only_any_change_or_neutral_orders_it() {
    for (field, base, candidate, effect, added, removed) in [
        (&ROUTES, vec![1, 2], vec![1, 2, 3], Effect::Loosened, 1, 0),
        (&ROUTES, vec![1, 2], vec![2, 1], Effect::Loosened, 0, 0),
        (&LABEL, vec![1, 2], vec![2], Effect::Neutral, 0, 1),
        (&ORDERED, vec![1, 2], vec![1, 2, 3], Effect::Unknown, 1, 0),
        (
            &ORDERED,
            vec![1, 1, 2],
            vec![1, 3, 3],
            Effect::Unknown,
            2,
            2,
        ),
    ] {
        let mut comparison = Comparison::new();
        comparison.sequence(field, &base, &candidate);
        let diff = comparison.finish();
        let change = only(&diff);
        assert_eq!(change.effect(), effect);
        assert_eq!(
            change.entries(),
            Some(EntryCounts {
                added,
                removed,
                changed: 0
            })
        );
    }
}

#[test]
fn a_secret_is_only_ever_a_changed_reference() {
    const CANARY: &str = "zqcanary-secret-value";
    let mut comparison = Comparison::new();
    comparison.secret(&ALIAS, Some(CANARY), Some("zqcanary-other"));
    let entries =
        |value: &str| BTreeMap::from([("zqcanary-key-name".to_owned(), value.to_owned())]);
    comparison.entries(
        &PROVIDERS,
        Redaction::Reference,
        &entries(CANARY),
        &entries("zqcanary-replacement"),
        |_, _| vec![Impact::Loosened(RiskCode::CredentialBindingChanged)],
    );
    let diff = comparison.finish();
    let text = serde_json::to_string(&diff).expect("serializes");
    assert!(!text.contains("zqcanary"), "{text}");
    assert!(!format!("{diff:?}").contains("zqcanary"));
    for change in diff.changes() {
        assert_eq!(change.display(), Display::Reference);
    }
    assert_eq!(risks(&diff), ["risk.credential_binding_changed"]);
}

#[test]
fn an_entry_that_differs_without_an_assessed_impact_is_unknown() {
    let mut comparison = Comparison::new();
    comparison.entries(
        &PROVIDERS,
        Redaction::Withheld,
        &BTreeMap::from([("a", 1), ("b", 2)]),
        &BTreeMap::from([("a", 1), ("b", 3), ("c", 4)]),
        |before, after| match (before, after) {
            (None, Some(_)) => vec![Impact::Loosened(RiskCode::AuthTrustChanged)],
            _ => Vec::new(),
        },
    );
    let diff = comparison.finish();
    let change = only(&diff);
    assert_eq!(change.effect(), Effect::Loosened);
    assert_eq!(
        risks(&diff),
        ["risk.auth_trust_changed", "risk.unknown_impact"]
    );
    assert_eq!(
        change.entries(),
        Some(EntryCounts {
            added: 1,
            removed: 0,
            changed: 1
        })
    );
}

#[test]
fn the_report_lists_sorted_risks_sections_and_value_free_changes() {
    let mut comparison = Comparison::new();
    comparison.set(&HOSTS, ["a.test"], ["a.test", "zqcanary.test"]);
    comparison.flag(&ENABLED, true, false);
    let diff = comparison.finish();
    assert_eq!(diff.severity(), Some(Severity::High));
    let report = report(&diff);
    assert_eq!(
        report,
        json!({
            "changed": true,
            "severity": "high",
            "riskCodes": ["risk.auth_disabled", "risk.egress_broadened"],
            "sections": ["lifecycle"],
            "changes": [
                {
                    "field": "TEST_ENABLED",
                    "section": "lifecycle",
                    "kind": "modified",
                    "class": "restart",
                    "effect": "loosened",
                    "severity": "high",
                    "riskCodes": ["risk.auth_disabled"],
                    "value": {"display": "shown", "before": true, "after": false}
                },
                {
                    "field": "TEST_HOSTS",
                    "section": "lifecycle",
                    "kind": "modified",
                    "class": "restart",
                    "effect": "loosened",
                    "severity": "high",
                    "riskCodes": ["risk.egress_broadened"],
                    "value": {"display": "withheld"},
                    "entries": {"added": 1, "removed": 0, "changed": 0}
                }
            ]
        })
    );
    assert!(!report.to_string().contains("zqcanary"));
}

#[test]
fn every_report_fits_the_published_diff_result_schema() {
    let schema = published_schema(API_VERSION_V1ALPHA1, REPORT_KIND).expect("published");
    let mut schema: Value = serde_json::from_str(schema.json).expect("JSON");
    // Validate against the `diffResult` definition with the report schema's
    // other definitions in scope.
    schema["$ref"] = json!("#/$defs/diffResult");
    for member in [
        "type",
        "additionalProperties",
        "required",
        "properties",
        "allOf",
    ] {
        schema
            .as_object_mut()
            .expect("an object schema")
            .remove(member);
    }
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");

    let mut comparison = Comparison::new();
    comparison.flag(&ENABLED, true, false);
    comparison.word(&MODE, "required", "unlisted");
    comparison.count(&RETENTION, None, Some(3));
    comparison.rate(&LIMIT, 1.0, 2.5);
    comparison.set(&HOSTS, ["a"], ["b"]);
    comparison.sequence(&ROUTES, &[1], &[1, 2]);
    comparison.value(&SINK, Some("a"), None);
    comparison.secret(&ALIAS, None, Some("b"));
    let samples = [comparison.finish(), Comparison::new().finish()];
    for diff in samples {
        let report = report(&diff);
        let errors: Vec<String> = validator
            .iter_errors(&report)
            .map(|error| error.to_string())
            .collect();
        assert!(errors.is_empty(), "{errors:?}\n{report}");
    }
}

// --- Bundles and documents ----------------------------------------------------

fn policy_diff(base: &Value, candidate: &Value) -> SemanticDiff {
    let mut comparison = Comparison::new();
    compare_policy(&mut comparison, base, candidate);
    comparison.finish()
}

fn fields(diff: &SemanticDiff) -> Vec<&'static str> {
    diff.changes().iter().map(Change::field).collect()
}

fn base_policy() -> Value {
    json!({
        "schema_version": "0.1.0",
        "default_action": "deny",
        "roles": {
            "operator": {"permissions": ["admin:status:read"], "issuers": ["provider:primary"]},
            "reader": {"permissions": ["mcp:tools"]}
        },
        "routes": [
            {"methods": ["GET"], "path_prefix": "/v1/admin/status", "permission": "admin:status:read"}
        ],
        "egress": {"hosts": ["api.example.test"], "ports": [443]},
        "rate_limits": [{"requests_per_second": 5.0, "burst": 10}],
        "tools": {"search": {"allowed_roles": ["reader"]}}
    })
}

fn edited(edit: impl FnOnce(&mut Value)) -> Value {
    let mut policy = base_policy();
    edit(&mut policy);
    policy
}

#[test]
fn a_policy_compared_with_itself_or_its_spelled_out_defaults_has_no_change() {
    assert!(policy_diff(&base_policy(), &base_policy()).is_empty());
    let spelled_out = edited(|policy| {
        policy["enforcement_mode"] = json!("enforce");
        policy["rules"] = json!([]);
        policy["egress"]["hosts"] = json!(["API.Example.test", "api.example.test"]);
        policy["egress"]["cidrs"] = json!([]);
        policy["roles"]["reader"]["issuers"] = json!([]);
        policy["tools"]["search"] = json!({
            "enabled": true,
            "allowed_roles": ["reader"],
            "timeout_ms": 30000,
            "max_concurrent": 8
        });
    });
    let diff = policy_diff(&base_policy(), &spelled_out);
    assert!(diff.is_empty(), "{}", report(&diff));
}

#[test]
fn each_known_policy_weakening_carries_its_code() {
    type Edit = fn(&mut Value);
    let cases: &[(Edit, &str, &[&str])] = &[
        (
            |p| p["default_action"] = json!("allow"),
            "policy.default_action",
            &["risk.policy_default_allow"],
        ),
        (
            |p| p["enforcement_mode"] = json!("shadow"),
            "policy.enforcement_mode",
            &["risk.shadow_enabled"],
        ),
        (
            |p| p["roles"]["reader"]["permissions"] = json!(["mcp:tools", "admin:policy:write"]),
            "policy.roles",
            &["risk.policy_broadened"],
        ),
        (
            |p| p["roles"]["operator"]["issuers"] = json!([]),
            "policy.roles",
            &["risk.policy_broadened"],
        ),
        (
            |p| p["roles"]["new"] = json!({"permissions": ["admin:config:read"]}),
            "policy.roles",
            &["risk.policy_broadened"],
        ),
        (
            |p| p["egress"]["hosts"] = json!(["api.example.test", "*.example.test"]),
            "policy.egress.hosts",
            &["risk.egress_broadened"],
        ),
        (
            |p| p["egress"]["cidrs"] = json!(["10.0.0.0/8"]),
            "policy.egress.cidrs",
            &["risk.private_egress_allowed"],
        ),
        (
            |p| p["egress"]["ports"] = json!([]),
            "policy.egress.ports",
            &["risk.egress_broadened"],
        ),
        (
            |p| p["rate_limits"][0]["requests_per_second"] = json!(50.0),
            "policy.rate_limits",
            &["risk.limits_loosened"],
        ),
        (
            |p| p["rate_limits"][0]["burst"] = json!(11),
            "policy.rate_limits",
            &["risk.limits_loosened"],
        ),
        (
            |p| p["rate_limits"] = json!([]),
            "policy.rate_limits",
            &["risk.unknown_impact"],
        ),
        (
            |p| p["rate_limits"][0]["methods"] = json!(["GET"]),
            "policy.rate_limits",
            &["risk.unknown_impact"],
        ),
        (
            |p| p["tools"]["search"]["allowed_roles"] = json!([]),
            "policy.tools",
            &["risk.policy_broadened"],
        ),
        (
            |p| p["tools"]["write"] = json!({}),
            "policy.tools",
            &["risk.policy_broadened"],
        ),
        (
            |p| p["tools"]["search"]["timeout_ms"] = json!(60000),
            "policy.tools",
            &["risk.limits_loosened"],
        ),
        (
            |p| p["routes"][0]["permission"] = json!("admin:status:write"),
            "policy.routes",
            &["risk.unknown_impact"],
        ),
        (
            |p| p["future_member"] = json!(true),
            "policy.unmodelled_members",
            &["risk.unknown_impact"],
        ),
    ];
    for (edit, field, expected) in cases {
        let diff = policy_diff(&base_policy(), &edited(*edit));
        assert_eq!(fields(&diff), [*field], "{}", report(&diff));
        assert_eq!(risks(&diff), *expected, "{field}");
    }
}

#[test]
fn a_route_shadow_override_is_a_shadow_risk() {
    let diff = policy_diff(
        &base_policy(),
        &edited(|p| p["routes"][0]["enforcement_mode"] = json!("shadow")),
    );
    assert_eq!(
        fields(&diff),
        ["policy.routes", "policy.routes.shadow_overrides"]
    );
    assert_eq!(risks(&diff), ["risk.shadow_enabled", "risk.unknown_impact"]);
}

#[test]
fn tightening_a_policy_carries_no_risk() {
    let tightened = edited(|p| {
        p["roles"]["reader"]["permissions"] = json!([]);
        p["egress"]["hosts"] = json!([]);
        p["rate_limits"] = json!([{"requests_per_second": 1.0, "burst": 2}]);
        p["tools"]["search"]["enabled"] = json!(false);
        p["tools"]["search"]["max_concurrent"] = json!(0);
    });
    let diff = policy_diff(&base_policy(), &tightened);
    assert!(!diff.is_empty());
    assert!(diff.risks().is_empty(), "{}", report(&diff));
    for change in diff.changes() {
        assert_eq!(change.effect(), Effect::Tightened, "{}", change.field());
    }
}

#[test]
fn policy_names_and_values_never_reach_the_report() {
    let base = edited(|p| {
        p["id"] = json!("zqcanary-policy-id");
        p["roles"]["zqcanary-role"] = json!({"permissions": ["zqcanary:permission"]});
    });
    let candidate = edited(|p| {
        p["id"] = json!("zqcanary-other-id");
        p["roles"]["zqcanary-role"] = json!({"permissions": ["zqcanary:other"]});
        p["egress"]["hosts"] = json!(["zqcanary.example.test"]);
    });
    let diff = policy_diff(&base, &candidate);
    assert!(!diff.is_empty());
    assert!(!report(&diff).to_string().contains("zqcanary"));
}

fn tools(names: &[(&str, &str)]) -> Value {
    json!({
        "schema_version": "0.1.0",
        "tools": names
            .iter()
            .map(|(name, path)| json!({"name": name, "path": path}))
            .collect::<Vec<_>>()
    })
}

#[test]
fn tool_definitions_are_compared_by_name() {
    let run = |base: Value, candidate: Value| {
        let mut comparison = Comparison::new();
        compare_tools(&mut comparison, &base, &candidate);
        comparison.finish()
    };
    let base = tools(&[("a", "/a"), ("b", "/b")]);
    assert!(run(base.clone(), tools(&[("b", "/b"), ("a", "/a")])).is_empty());
    let added = run(
        base.clone(),
        tools(&[("a", "/a"), ("b", "/b"), ("c", "/c")]),
    );
    assert_eq!(risks(&added), ["risk.tool_surface_broadened"]);
    let removed = run(base.clone(), tools(&[("a", "/a")]));
    assert_eq!(only(&removed).effect(), Effect::Tightened);
    let changed = run(base, tools(&[("a", "/a"), ("b", "/elsewhere")]));
    assert_eq!(risks(&changed), ["risk.unknown_impact"]);
}

const PRODUCTION: &[u8] = br#"{"apiVersion":"greengateway.dev/v1alpha1","kind":"GatewayDeployment","spec":{"profile":"production"}}"#;
const DEVELOPMENT: &[u8] = br#"{"apiVersion":"greengateway.dev/v1alpha1","kind":"GatewayDeployment","spec":{"profile":"development"}}"#;

fn bundle<'a>(policy: ResourceView<'a>) -> BundleView<'a> {
    BundleView {
        api_version: API_VERSION_V1ALPHA1,
        name: "local",
        profile: "production",
        deployment_sha256: "aa",
        deployment_canonical_json: PRODUCTION,
        policy,
        tools: ResourceView::Undeclared,
        connections_from_server: true,
    }
}

fn bundle_diff(base: &BundleView<'_>, candidate: &BundleView<'_>) -> SemanticDiff {
    let mut comparison = Comparison::new();
    compare_bundles(&mut comparison, base, candidate);
    comparison.finish()
}

#[test]
fn bundle_settings_and_resource_sources_are_compared() {
    let policy = base_policy();
    let pinned = |sha256, document| ResourceView::Bundle { sha256, document };
    let base = bundle(pinned("11", Some(&policy)));
    assert!(bundle_diff(&base, &base).is_empty());

    let development = BundleView {
        profile: "development",
        deployment_sha256: "bb",
        deployment_canonical_json: DEVELOPMENT,
        ..base
    };
    let diff = bundle_diff(&base, &development);
    assert_eq!(fields(&diff), ["deployment.profile", "deployment.sha256"]);
    assert_eq!(risks(&diff), ["risk.profile_changed"]);
    let back = bundle_diff(&development, &base);
    assert_eq!(back.changes()[0].field(), "deployment.profile");
    assert_eq!(back.changes()[0].effect(), Effect::Tightened);
    assert!(back.risks().is_empty());

    let reformatted = BundleView {
        policy: pinned("22", Some(&policy)),
        ..base
    };
    let diff = bundle_diff(&base, &reformatted);
    assert_eq!(fields(&diff), ["resources.policy.sha256"]);
    assert_eq!(only(&diff).effect(), Effect::Neutral);

    let unreadable = BundleView {
        policy: pinned("22", None),
        ..base
    };
    let diff = bundle_diff(&base, &unreadable);
    assert_eq!(
        fields(&diff),
        ["policy.document", "resources.policy.sha256"]
    );
    assert_eq!(risks(&diff), ["risk.unknown_impact"]);

    let server = BundleView {
        policy: ResourceView::Server,
        ..base
    };
    assert_eq!(risks(&bundle_diff(&base, &server)), ["risk.unknown_impact"]);

    let other_member = BundleView {
        deployment_sha256: "cc",
        deployment_canonical_json: br#"{"apiVersion":"greengateway.dev/v1alpha1","kind":"GatewayDeployment","spec":{"later":1,"profile":"production"}}"#,
        ..base
    };
    let diff = bundle_diff(&base, &other_member);
    assert_eq!(fields(&diff), ["deployment.document", "deployment.sha256"]);
    assert_eq!(risks(&diff), ["risk.unknown_impact"]);

    // A profile change does not hide another member's.
    let both = BundleView {
        profile: "development",
        deployment_sha256: "dd",
        deployment_canonical_json: br#"{"apiVersion":"greengateway.dev/v1alpha1","kind":"GatewayDeployment","spec":{"later":1,"profile":"development"}}"#,
        ..base
    };
    let diff = bundle_diff(&base, &both);
    assert_eq!(
        fields(&diff),
        [
            "deployment.document",
            "deployment.profile",
            "deployment.sha256"
        ]
    );
    assert_eq!(
        risks(&diff),
        ["risk.profile_changed", "risk.unknown_impact"]
    );
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

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    fn pick<'a>(&mut self, words: &[&'a str]) -> &'a str {
        words[self.below(words.len() as u64) as usize]
    }

    fn words(&mut self, words: &[&'static str]) -> Vec<&'static str> {
        (0..self.below(4)).map(|_| self.pick(words)).collect()
    }

    fn policy(&mut self) -> Value {
        const PERMISSIONS: &[&str] = &["mcp:tools", "admin:status:read", "admin:policy:write"];
        const HOSTS: &[&str] = &["a.test", "B.test", "*.c.test"];
        let mut roles = serde_json::Map::new();
        for name in ["one", "two", "three"] {
            if self.below(2) == 0 {
                roles.insert(
                    name.to_owned(),
                    json!({"permissions": self.words(PERMISSIONS), "auth_methods": self.words(&["bearer_token", "service_token"])}),
                );
            }
        }
        json!({
            "schema_version": "0.1.0",
            "default_action": self.pick(&["allow", "deny"]),
            "enforcement_mode": self.pick(&["enforce", "shadow"]),
            "roles": roles,
            "routes": (0..self.below(3)).map(|index| json!({"path_prefix": format!("/r{index}"), "permission": self.pick(PERMISSIONS)})).collect::<Vec<_>>(),
            "egress": {"hosts": self.words(HOSTS), "ports": (0..self.below(3)).map(|_| 400 + self.below(3)).collect::<Vec<_>>()},
            "tools": {"t": {"enabled": self.below(2) == 0, "max_concurrent": self.below(3)}}
        })
    }
}

/// The same policy with every unordered list reversed and its host patterns
/// in another case.
fn reordered(policy: &Value) -> Value {
    let mut policy = policy.clone();
    let reverse = |value: &mut Value| {
        if let Some(items) = value.as_array_mut() {
            items.reverse();
        }
    };
    if let Some(roles) = policy["roles"].as_object_mut() {
        for role in roles.values_mut() {
            reverse(&mut role["permissions"]);
            reverse(&mut role["auth_methods"]);
        }
    }
    reverse(&mut policy["egress"]["ports"]);
    if let Some(hosts) = policy["egress"]["hosts"].as_array_mut() {
        hosts.reverse();
        for host in hosts.iter_mut() {
            if let Some(text) = host.as_str() {
                *host = json!(text.to_ascii_uppercase());
            }
        }
    }
    policy
}

#[test]
fn generated_policies_have_no_change_against_themselves_or_their_reordering() {
    let mut seeded = Seeded(0x9e37_79b9_7f4a_7c15);
    for _ in 0..500 {
        let policy = seeded.policy();
        assert!(policy_diff(&policy, &policy).is_empty());
        let diff = policy_diff(&policy, &reordered(&policy));
        assert!(diff.is_empty(), "{policy}\n{}", report(&diff));
        // A diff and its reverse name the same fields.
        let other = seeded.policy();
        assert_eq!(
            fields(&policy_diff(&policy, &other)),
            fields(&policy_diff(&other, &policy))
        );
    }
}

/// Known weakenings of a policy, each with the risk code it must carry. Each
/// only adds to what a policy allows, so applying more of them never removes
/// a risk.
const WEAKENINGS: &[(fn(&mut Value), &str)] = &[
    (
        |p| p["default_action"] = json!("allow"),
        "risk.policy_default_allow",
    ),
    (
        |p| p["enforcement_mode"] = json!("shadow"),
        "risk.shadow_enabled",
    ),
    (
        |p| push(&mut p["egress"]["hosts"], json!("weaker.test")),
        "risk.egress_broadened",
    ),
    (
        |p| push(&mut p["egress"]["cidrs"], json!("10.9.0.0/16")),
        "risk.private_egress_allowed",
    ),
    (
        |p| {
            p["roles"]["weaker"] = json!({"permissions": ["admin:policy:write"]});
        },
        "risk.policy_broadened",
    ),
    (
        |p| {
            p["tools"]["weaker"] = json!({"enabled": true});
        },
        "risk.policy_broadened",
    ),
    (
        |p| {
            p["tools"]["t"]["timeout_ms"] = json!(3_600_000);
        },
        "risk.limits_loosened",
    ),
];

fn push(list: &mut Value, item: Value) {
    match list.as_array_mut() {
        Some(items) => items.push(item),
        None => *list = json!([item]),
    }
}

#[test]
fn generated_known_weakenings_are_detected_and_risk_never_falls_as_more_are_applied() {
    let mut seeded = Seeded(0x2545_f491_4f6c_dd1d);
    for _ in 0..300 {
        let base = seeded.policy();
        let mut candidate = base.clone();
        let mut previous = BTreeSet::new();
        let mut previous_severity = None;
        let mut steps = BTreeSet::new();
        for _ in 0..=seeded.below(6) {
            let (weaken, code) = WEAKENINGS[seeded.below(WEAKENINGS.len() as u64) as usize];
            let before = candidate.clone();
            weaken(&mut candidate);
            // A weakening that changed anything is reported by its code.
            let step = policy_diff(&before, &candidate);
            if !step.is_empty() {
                assert!(
                    risks(&step).contains(&code),
                    "{code}\n{before}\n{candidate}"
                );
                steps.insert(code);
            }
            let diff = policy_diff(&base, &candidate);
            let codes: BTreeSet<&'static str> =
                diff.risks().into_iter().map(RiskCode::as_str).collect();
            assert!(
                codes.is_superset(&previous),
                "{previous:?} -> {codes:?}\n{base}\n{candidate}"
            );
            assert!(diff.severity() >= previous_severity);
            previous = codes;
            previous_severity = diff.severity();
        }
        // Against the base, every step's code is still there at the end.
        assert!(previous.is_superset(&steps), "{steps:?} {previous:?}");
    }
}

#[test]
fn the_reference_describes_every_risk_code_with_its_severity() {
    let reference = include_str!("../../../docs/semantic-diff.md");
    for code in RiskCode::ALL {
        let row = format!("| `{}` | {} |", code.as_str(), code.severity().as_str());
        assert!(
            reference.contains(&row),
            "docs/semantic-diff.md lacks {row}"
        );
    }
}
