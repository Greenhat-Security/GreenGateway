//! Identity mappings and typed rule conditions in the kernel (issue #243,
//! item 16): differential tests against the existing matchers, the
//! three-valued answer for uncaptured facts in every lane, issuer binding and
//! spoofing, and what a trace may carry.

use std::net::{IpAddr, Ipv4Addr};

use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, RngSeed};
use serde_json::json;

use super::{
    tools::{
        SourceRequestContext, SourceRequestDecision, ToolEvaluationContext, ToolLimitation,
        ToolOperation, ToolReason, TOOL_CONTEXT_VERSION,
    },
    *,
};
use crate::rbac::policy_document::parse_v1_with_typed_matchers;

const ISSUER: &str = "https://idp.example.test";
/// 2026-01-01T00:00:00Z.
const NOW: i64 = 1_767_225_600;
const ALWAYS: &str = "1970-01-01T00:00:00Z";
const NEVER_AFTER: &str = "1970-01-01T00:00:01Z";

fn property_config() -> Config {
    Config {
        cases: 96,
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(243_016),
        max_shrink_iters: 2_048,
        ..Config::default()
    }
}

fn compile(document: Value) -> CompiledPolicy {
    let policy = parse_v1_with_typed_matchers(&document)
        .unwrap_or_else(|issues| panic!("fixture should validate: {issues:?}"));
    CompiledPolicy::from_validated_policy(policy, PolicyAuthority::Standalone)
        .expect("a standalone authority is valid")
}

fn person(issuer: Option<&str>, roles: &[&str], auth_method: AuthMethod) -> Principal {
    Principal {
        user_id: "synthetic-subject".to_owned(),
        issuer: issuer.map(str::to_owned),
        email: None,
        org_id: None,
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        session_id: String::new(),
        auth_method,
    }
}

fn authenticated(principal: &Principal) -> PrincipalFact {
    PrincipalFact::Authenticated(PrincipalIdentity::from_principal(principal))
}

fn http(
    compiled: &CompiledPolicy,
    path: &str,
    principal: PrincipalFact,
) -> PolicyEvaluationContext {
    PolicyEvaluationContext {
        version: CONTEXT_VERSION,
        snapshot: compiled.snapshot(),
        method: Some(Method::GET),
        path: Some(path.to_owned()),
        principal,
        target: HttpTarget::Contextless,
        request_host: HostFact::Absent,
        dispatch: None,
    }
}

fn tool(compiled: &CompiledPolicy, principal: PrincipalFact) -> ToolEvaluationContext {
    ToolEvaluationContext {
        version: TOOL_CONTEXT_VERSION,
        snapshot: compiled.snapshot(),
        operation: ToolOperation::Invocation,
        tool_name: Some("lookup".to_owned()),
        principal,
        method: None,
        path: None,
    }
}

fn at(now: i64) -> PolicyFacts {
    let mut facts = PolicyFacts::uncaptured();
    facts.now = Fact::Captured(now);
    facts
}

/// Facts carrying a canary in every value a matcher can read.
fn canary_facts() -> PolicyFacts {
    PolicyFacts {
        organization: Fact::Captured(Some("canary-organization".to_owned())),
        source_ip: Fact::Captured(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77))),
        headers: Fact::Captured(vec![(
            "x-environment".to_owned(),
            "canary-header-value".to_owned(),
        )]),
        query: Fact::Captured(vec![("mode".to_owned(), "canary-query-value".to_owned())]),
        tool_arguments: Fact::Captured(json!({ "region": "canary-argument-value" })),
        now: Fact::Captured(NOW),
    }
}

/// A condition `kind` 1 certainly holds at [`NOW`] and kind 2 certainly
/// fails; kind 0 is no condition.
fn condition(kind: u8) -> Option<Value> {
    match kind {
        1 => Some(json!({ "time_window": { "from": ALWAYS } })),
        2 => Some(json!({ "any": [{ "time_window": { "until": NEVER_AFTER } }] })),
        _ => None,
    }
}

fn action_name(code: u8) -> &'static str {
    match code {
        0 => "deny",
        1 => "shadow",
        _ => "allow",
    }
}

fn same_http_answer(left: &Evaluation, right: &Evaluation) -> bool {
    left.logical() == right.logical()
        && left.effect() == right.effect()
        && left.reason() == right.reason()
        && left.matched() == right.matched()
        && left.observation() == right.observation()
        && left.is_complete() == right.is_complete()
        && left.limitation() == right.limitation()
}

proptest! {
    #![proptest_config(property_config())]

    /// A condition that certainly holds is the same rule without it, and one
    /// that certainly fails is the same rule disabled, under both the
    /// single-identity and the alias precedence order and for every
    /// principal constraint the existing matcher applies.
    #[test]
    fn a_settled_condition_decides_exactly_as_the_existing_matcher_without_it(
        entries in proptest::collection::vec((0u8..3, 0u8..3, any::<bool>(), 0u8..3, any::<bool>()), 1..8),
        alias in any::<bool>(),
        anonymous in any::<bool>(),
        default_allow in any::<bool>(),
    ) {
        let mut with_conditions = Vec::new();
        let mut without = Vec::new();
        for (index, (action, path, enabled, kind, role_bound)) in entries.iter().enumerate() {
            let path = match path {
                0 => "/synthetic/item",
                1 => "/canonical/item",
                _ => "/elsewhere",
            };
            let mut rule = json!({
                "id": format!("rule-{index}"),
                "path": path,
                "enabled": enabled,
                "action": action_name(*action),
            });
            if *role_bound {
                rule["principal"] = json!({ "roles": ["reader"] });
            }
            let mut plain = rule.clone();
            if *kind == 2 {
                plain["enabled"] = json!(false);
            }
            if let Some(condition) = condition(*kind) {
                rule["conditions"] = condition;
            }
            with_conditions.push(rule);
            without.push(plain);
        }
        let document = |rules: Vec<Value>| json!({
            "schema_version": "1.0.0",
            "default_action": if default_allow { "allow" } else { "deny" },
            "rules": rules,
        });
        let conditioned = compile(document(with_conditions));
        let plain = compile(document(without));
        let reader = person(Some(ISSUER), &["reader"], AuthMethod::Bearer);
        let principal = if anonymous { PrincipalFact::Anonymous } else { authenticated(&reader) };
        let mut conditioned_input = http(&conditioned, "/synthetic/item", principal.clone());
        let mut plain_input = http(&plain, "/synthetic/item", principal);
        if alias {
            let target = HttpTarget::McpAlias { canonical_path: "/canonical/item".to_owned() };
            conditioned_input.target = target.clone();
            plain_input.target = target;
        }
        let with_facts = conditioned.evaluate_with_facts(&conditioned_input, &at(NOW)).unwrap();
        let expected = plain.evaluate(&plain_input).unwrap();
        prop_assert!(same_http_answer(&with_facts, &expected), "{with_facts:?} != {expected:?}");
    }

    /// The tool lane's tool-name rules obey the same equivalence.
    #[test]
    fn a_settled_tool_rule_condition_decides_exactly_as_the_existing_matcher_without_it(
        entries in proptest::collection::vec((0u8..3, any::<bool>(), 0u8..3), 1..8),
    ) {
        let mut with_conditions = Vec::new();
        let mut without = Vec::new();
        for (index, (action, enabled, kind)) in entries.iter().enumerate() {
            let mut rule = json!({
                "id": format!("rule-{index}"),
                "tool_name": "lookup",
                "enabled": enabled,
                "action": action_name(*action),
            });
            let mut plain = rule.clone();
            if *kind == 2 {
                plain["enabled"] = json!(false);
            }
            if let Some(condition) = condition(*kind) {
                rule["conditions"] = condition;
            }
            with_conditions.push(rule);
            without.push(plain);
        }
        let document = |rules: Vec<Value>| json!({
            "schema_version": "1.0.0",
            "rules": rules,
            "tools": { "lookup": {} },
        });
        let conditioned = compile(document(with_conditions));
        let plain = compile(document(without));
        let reader = person(Some(ISSUER), &["reader"], AuthMethod::Bearer);
        let with_facts = conditioned
            .evaluate_tool_with_facts(&tool(&conditioned, authenticated(&reader)), &at(NOW))
            .unwrap();
        let expected = plain.evaluate_tool(&tool(&plain, authenticated(&reader))).unwrap();
        prop_assert_eq!(with_facts.logical(), expected.logical());
        prop_assert_eq!(with_facts.effect(), expected.effect());
        prop_assert_eq!(with_facts.reason(), expected.reason());
        prop_assert_eq!(with_facts.matched(), expected.matched());
    }

    /// Mapping every claimed role to the internal role of the same name, for
    /// the principal's own issuer, is claimed-role mode: every lane that reads
    /// roles -- route permissions, rule principals, tool roles and rate
    /// overrides -- decides exactly as it does without the mappings.
    #[test]
    fn mapping_each_claimed_role_to_itself_decides_exactly_as_claimed_role_mode(
        held in proptest::sample::subsequence(&["a", "b", "c", "unmapped"][..], 0..=4),
        rules in proptest::collection::vec((0u8..3, 0usize..3), 0..5),
        route_permission in 0usize..3,
        tool_roles in proptest::sample::subsequence(&["a", "b", "c"][..], 0..=3),
        rate_roles in proptest::collection::vec(0usize..3, 0..4),
    ) {
        const ROLES: [&str; 3] = ["a", "b", "c"];
        let rules: Vec<Value> = rules.iter().enumerate().map(|(index, (action, role))| json!({
            "id": format!("rule-{index}"),
            "path": "/synthetic/item",
            "principal": { "roles": [ROLES[*role]] },
            "action": action_name(*action),
        })).collect();
        let rate_limits: Vec<Value> = rate_roles.iter().enumerate().map(|(index, role)| json!({
            "id": format!("rate-{index}"),
            "principal": { "roles": [ROLES[*role]] },
            "requests_per_second": index + 1,
            "burst": 1,
        })).collect();
        let permission = ["perm-a", "perm-b", "perm-c"][route_permission];
        let claimed = json!({
            "schema_version": "1.0.0",
            "roles": {
                "a": { "permissions": ["perm-a"] },
                "b": { "permissions": ["perm-b"] },
                "c": { "permissions": ["*"] },
            },
            "routes": [{ "id": "route", "path_prefix": "/synthetic", "permission": permission }],
            "rules": rules,
            "rate_limits": rate_limits,
            "tools": { "lookup": { "allowed_roles": tool_roles } },
        });
        let mut mapped = claimed.clone();
        mapped["identity_mappings"] = Value::Array(ROLES.iter().map(|role| json!({
            "id": format!("pass-{role}"),
            "issuer": ISSUER,
            "claimed_roles": [role],
            "grant_roles": [role],
        })).collect());
        let claimed = compile(claimed);
        let mapped = compile(mapped);
        let principal = person(Some(ISSUER), &held, AuthMethod::Bearer);

        let expected = claimed.evaluate(&http(&claimed, "/synthetic/item", authenticated(&principal))).unwrap();
        let actual = mapped.evaluate(&http(&mapped, "/synthetic/item", authenticated(&principal))).unwrap();
        prop_assert!(same_http_answer(&actual, &expected), "{actual:?} != {expected:?}");

        let expected = claimed.evaluate_tool(&tool(&claimed, authenticated(&principal))).unwrap();
        let actual = mapped.evaluate_tool(&tool(&mapped, authenticated(&principal))).unwrap();
        prop_assert_eq!((actual.logical(), actual.reason(), actual.matched()),
            (expected.logical(), expected.reason(), expected.matched()));

        let expected = claimed.select_rate_lane(&http(&claimed, "/synthetic/item", authenticated(&principal))).unwrap();
        let actual = mapped.select_rate_lane(&http(&mapped, "/synthetic/item", authenticated(&principal))).unwrap();
        prop_assert_eq!(actual.outcome(), expected.outcome());

        for permission in ["perm-a", "perm-b", "perm-z"] {
            prop_assert_eq!(
                mapped.engine().principal_has_permission(&mapped.management_principal(&principal), permission),
                claimed.engine().principal_has_permission(&claimed.management_principal(&principal), permission),
            );
        }
    }
}

#[test]
fn an_uncaptured_condition_is_indeterminate_only_where_the_order_reaches_it() {
    let policy = |rules: Value| {
        compile(json!({
            "schema_version": "1.0.0",
            "default_action": "allow",
            "rules": rules,
        }))
    };
    let unknown = json!({ "header": { "name": "x-environment", "in": ["prod"] } });
    let anonymous = PrincipalFact::Anonymous;

    // Reached first: which rule decides cannot be told, and the answer is
    // never the permissive default.
    for action in ["allow", "deny", "shadow"] {
        let compiled = policy(json!([
            { "id": "conditional", "path": "/x", "action": action, "conditions": unknown },
            { "id": "deny", "path": "/x", "action": "deny" },
        ]));
        let result = compiled
            .evaluate(&http(&compiled, "/x", anonymous.clone()))
            .unwrap();
        assert_eq!(result.logical(), LogicalDecision::Indeterminate, "{action}");
        assert_eq!(result.effect(), PolicyEffect::Block);
        assert_eq!(result.limitation(), Some(Limitation::MissingMatcherFact));
        assert!(!result.is_complete());
    }

    // An earlier certain match decides, so the condition is never read; and
    // a conditional rule whose other predicates fail is certainly no match.
    let compiled = policy(json!([
        { "id": "deny", "path": "/x", "action": "deny" },
        { "id": "conditional", "path": "/x", "action": "allow", "conditions": unknown },
    ]));
    let result = compiled
        .evaluate(&http(&compiled, "/x", anonymous.clone()))
        .unwrap();
    assert_eq!(result.logical(), LogicalDecision::Deny);
    assert!(result.is_complete());
    let compiled = policy(json!([
        { "id": "elsewhere", "path": "/y", "action": "allow", "conditions": unknown },
        { "id": "disabled", "path": "/x", "enabled": false, "action": "allow", "conditions": unknown },
    ]));
    let result = compiled
        .evaluate(&http(&compiled, "/x", anonymous.clone()))
        .unwrap();
    assert_eq!(result.reason(), Reason::DefaultAllow);

    // Alias precedence is action-major: an undetermined deny is reached
    // before any allow, while an undetermined allow is never reached when a
    // deny certainly matches.
    let alias = |compiled: &CompiledPolicy| {
        let mut input = http(compiled, "/x", PrincipalFact::Anonymous);
        input.target = HttpTarget::McpAlias {
            canonical_path: "/mcp".to_owned(),
        };
        compiled.evaluate(&input).unwrap()
    };
    let compiled = policy(json!([
        { "id": "allow", "path": "/x", "action": "allow" },
        { "id": "conditional-deny", "path": "/mcp", "action": "deny", "conditions": unknown },
    ]));
    assert_eq!(alias(&compiled).logical(), LogicalDecision::Indeterminate);
    let compiled = policy(json!([
        { "id": "conditional-allow", "path": "/x", "action": "allow", "conditions": unknown },
        { "id": "deny", "path": "/mcp", "action": "deny" },
    ]));
    let result = alias(&compiled);
    assert_eq!(result.logical(), LogicalDecision::Deny);
    assert_eq!(result.matched(), Some(RuleReference::Direct(1)));
}

#[test]
fn every_lane_refuses_to_guess_a_conditional_rule_it_cannot_evaluate() {
    let compiled = compile(json!({
        "schema_version": "1.0.0",
        "rules": [
            {
                "id": "tool-in-eu",
                "tool_name": "lookup",
                "action": "allow",
                "conditions": { "tool_argument": { "pointer": "/region", "in": ["eu"] } }
            },
            {
                "id": "rendered",
                "path": "/reports/**",
                "action": "deny",
                "conditions": { "query": { "name": "mode", "in": ["export"] } }
            }
        ],
        "tools": { "lookup": {} }
    }));
    let reader = person(Some(ISSUER), &["reader"], AuthMethod::Bearer);
    let result = compiled
        .evaluate_tool(&tool(&compiled, authenticated(&reader)))
        .unwrap();
    assert_eq!(result.logical(), LogicalDecision::Indeterminate);
    assert_eq!(result.limitation(), Some(ToolLimitation::MatcherFact));
    assert_eq!(result.effect(), PolicyEffect::Block);
    // With the argument captured, it is answered either way.
    let mut facts = PolicyFacts::uncaptured();
    facts.tool_arguments = Fact::Captured(json!({ "region": "eu" }));
    let result = compiled
        .evaluate_tool_with_facts(&tool(&compiled, authenticated(&reader)), &facts)
        .unwrap();
    assert_eq!(
        (result.logical(), result.reason()),
        (LogicalDecision::Allow, ToolReason::MatchedRule)
    );
    facts.tool_arguments = Fact::Captured(json!({ "region": "us" }));
    let result = compiled
        .evaluate_tool_with_facts(&tool(&compiled, authenticated(&reader)), &facts)
        .unwrap();
    assert_eq!(result.matched(), None);

    // A rendered tool HTTP operation is judged by the path rules too.
    let mut rendered = tool(&compiled, authenticated(&reader));
    rendered.operation = ToolOperation::RenderedHttp;
    rendered.method = Some(Method::GET);
    rendered.path = Some("/reports/42".to_owned());
    let result = compiled.evaluate_tool(&rendered).unwrap();
    assert_eq!(result.limitation(), Some(ToolLimitation::MatcherFact));

    // An enum-source request has no facts at all, so a conditional deny it
    // reaches refuses the source rather than letting it through.
    let source = SourceRequestContext {
        version: TOOL_CONTEXT_VERSION,
        snapshot: compiled.snapshot(),
        tool_name: Some("lookup".to_owned()),
        path: "/reports/42".to_owned(),
    };
    assert_eq!(
        compiled.evaluate_source_request(&source).unwrap(),
        SourceRequestDecision::Undetermined
    );

    // The analysis consumers report it as indeterminate, never as a count.
    let mut input = http(&compiled, "/reports/42", PrincipalFact::Anonymous);
    input.target = HttpTarget::Contextless;
    assert_eq!(
        compiled.match_direct_rules(&input).unwrap(),
        analysis::DirectRuleOutcome::Indeterminate(Limitation::MissingMatcherFact)
    );
    assert_eq!(
        compiled
            .match_tool_rules("lookup", &authenticated(&reader))
            .unwrap(),
        analysis::DirectRuleOutcome::Indeterminate(Limitation::MissingMatcherFact)
    );
}

fn mapped_policy() -> CompiledPolicy {
    compile(json!({
        "schema_version": "1.0.0",
        "roles": {
            "admin": { "permissions": ["admin:policy:write", "data:read"] },
            "reader": { "permissions": ["data:read"] }
        },
        "identity_mappings": [
            {
                "id": "idp-admins",
                "issuer": ISSUER,
                "auth_methods": ["bearer_token"],
                "claimed_roles": ["Platform-Admins"],
                "grant_roles": ["admin"]
            },
            {
                "id": "idp-everyone",
                "issuer": ISSUER,
                "grant_roles": ["reader"]
            }
        ],
        "routes": [{ "id": "data", "path_prefix": "/data", "permission": "data:read" }],
        "rules": [
            { "id": "admins-only", "path": "/admin/**", "principal": { "roles": ["admin"] }, "action": "allow" },
            { "id": "deny-admin", "path": "/admin/**", "action": "deny" }
        ],
        "rate_limits": [
            { "id": "admin-lane", "principal": { "roles": ["admin"] }, "requests_per_second": 50, "burst": 10 }
        ],
        "tools": { "lookup": { "allowed_roles": ["admin"] } }
    }))
}

#[test]
fn mapped_role_mode_judges_every_lane_by_the_internal_roles_alone() {
    let compiled = mapped_policy();
    let admin = person(Some(ISSUER), &["Platform-Admins"], AuthMethod::Bearer);
    let cookie_admin = person(Some(ISSUER), &["Platform-Admins"], AuthMethod::Cookie);
    let reader = person(Some(ISSUER), &[], AuthMethod::Bearer);

    let decide = |principal: &Principal, path: &str| {
        compiled
            .evaluate(&http(&compiled, path, authenticated(principal)))
            .unwrap()
    };
    assert_eq!(
        decide(&admin, "/admin/settings").matched(),
        Some(RuleReference::Direct(0))
    );
    assert_eq!(
        decide(&cookie_admin, "/admin/settings").matched(),
        Some(RuleReference::Direct(1))
    );
    assert_eq!(decide(&reader, "/data/1").logical(), LogicalDecision::Allow);

    let rate = |principal: &Principal| {
        compiled
            .select_rate_lane(&http(&compiled, "/data/1", authenticated(principal)))
            .unwrap()
            .matched()
    };
    assert_eq!(rate(&admin), Some(0));
    assert_eq!(rate(&reader), None);

    let invoke = |principal: &Principal| {
        compiled
            .evaluate_tool(&tool(&compiled, authenticated(principal)))
            .unwrap()
            .reason()
    };
    assert_eq!(invoke(&admin), ToolReason::Allowed);
    assert_eq!(invoke(&reader), ToolReason::RoleNotAllowed);

    let engine = compiled.engine();
    assert!(engine
        .principal_has_permission(&compiled.management_principal(&admin), "admin:policy:write"));
    assert!(!engine.principal_has_permission(
        &compiled.management_principal(&reader),
        "admin:policy:write"
    ));
}

#[test]
fn a_claimed_role_named_like_an_internal_role_grants_nothing_in_mapped_role_mode() {
    let compiled = mapped_policy();
    // Every spoof the claim alone could attempt: the internal role's own
    // name from the trusted issuer, the mapped claim from another issuer or
    // one that only shares a prefix, and a service token whose scopes name
    // the internal role.
    for (principal, label) in [
        (
            person(Some(ISSUER), &["admin"], AuthMethod::Bearer),
            "internal name claimed",
        ),
        (
            person(
                Some("https://attacker.example.test"),
                &["Platform-Admins", "admin"],
                AuthMethod::Bearer,
            ),
            "another issuer",
        ),
        (
            person(
                Some("https://idp.example.test.attacker.example"),
                &["Platform-Admins"],
                AuthMethod::Bearer,
            ),
            "a lookalike issuer",
        ),
        (
            person(None, &["admin"], AuthMethod::ServiceToken),
            "a service token",
        ),
    ] {
        let admin_page = compiled
            .evaluate(&http(
                &compiled,
                "/admin/settings",
                authenticated(&principal),
            ))
            .unwrap();
        assert_eq!(
            admin_page.matched(),
            Some(RuleReference::Direct(1)),
            "{label}"
        );
        assert!(
            !compiled.engine().principal_has_permission(
                &compiled.management_principal(&principal),
                "admin:policy:write"
            ),
            "{label}"
        );
        assert_eq!(
            compiled
                .evaluate_tool(&tool(&compiled, authenticated(&principal)))
                .unwrap()
                .reason(),
            ToolReason::RoleNotAllowed,
            "{label}"
        );
    }
}

#[test]
fn an_organization_mapping_without_its_fact_is_indeterminate_in_every_lane() {
    let compiled = compile(json!({
        "schema_version": "1.0.0",
        "roles": { "reader": { "permissions": ["data:read"] } },
        "identity_mappings": [{
            "id": "acme-readers",
            "issuer": ISSUER,
            "organizations": ["acme"],
            "grant_roles": ["reader"]
        }],
        "routes": [{ "id": "data", "path_prefix": "/data", "permission": "data:read" }],
        "rate_limits": [{ "id": "readers", "principal": { "roles": ["reader"] }, "requests_per_second": 1, "burst": 1 }],
        "tools": { "lookup": { "allowed_roles": ["reader"] } }
    }));
    let alice = person(Some(ISSUER), &[], AuthMethod::Bearer);

    let mut stages = Vec::new();
    let result = compiled
        .evaluate_with_stages(
            &http(&compiled, "/data/1", authenticated(&alice)),
            &mut stages,
        )
        .unwrap();
    assert_eq!(result.limitation(), Some(Limitation::MissingMatcherFact));
    assert_eq!(
        stages,
        vec![stages::HttpStage::Facts(Some(
            Limitation::MissingMatcherFact
        ))]
    );
    assert_eq!(
        compiled
            .select_rate_lane(&http(&compiled, "/data/1", authenticated(&alice)))
            .unwrap()
            .limitation(),
        Some(Limitation::MissingMatcherFact)
    );
    assert_eq!(
        compiled
            .evaluate_tool(&tool(&compiled, authenticated(&alice)))
            .unwrap()
            .limitation(),
        Some(ToolLimitation::MatcherFact)
    );
    // The management lane has no indeterminate answer: no permission.
    assert!(compiled.management_principal(&alice).roles.is_empty());
    // An anonymous caller holds no role in either mode, so nothing is unknown.
    let anonymous = compiled
        .evaluate(&http(&compiled, "/data/1", PrincipalFact::Anonymous))
        .unwrap();
    assert_eq!(anonymous.reason(), Reason::MissingPrincipal);

    // Captured, the mapping is answered.
    let mut facts = PolicyFacts::uncaptured();
    facts.organization = Fact::Captured(Some("acme".to_owned()));
    let input = http(&compiled, "/data/1", authenticated(&alice));
    assert_eq!(
        compiled
            .evaluate_with_facts(&input, &facts)
            .unwrap()
            .logical(),
        LogicalDecision::Allow
    );
    assert_eq!(
        compiled
            .select_rate_lane_with_facts(&input, &facts)
            .unwrap()
            .matched(),
        Some(0)
    );
    facts.organization = Fact::Captured(Some("globex".to_owned()));
    assert_eq!(
        compiled
            .evaluate_with_facts(&input, &facts)
            .unwrap()
            .reason(),
        Reason::MissingPermission
    );
}

#[test]
fn no_fact_value_reaches_a_trace_and_a_fact_bound_answer_is_never_reused() {
    let compiled = compile(json!({
        "schema_version": "1.0.0",
        "roles": { "reader": { "permissions": ["data:read"] } },
        "identity_mappings": [{
            "id": "canaries",
            "issuer": ISSUER,
            "organizations": ["canary-organization"],
            "grant_roles": ["reader"]
        }],
        "rules": [{
            "id": "canary-rule",
            "path": "/data/**",
            "action": "allow",
            "conditions": { "all": [
                { "header": { "name": "x-environment", "in": ["canary-header-value"] } },
                { "query": { "name": "mode", "in": ["canary-query-value"] } },
                { "source_network": { "cidrs": ["203.0.113.0/24"] } },
                { "organization": { "issuer": ISSUER, "in": ["canary-organization"] } },
                { "time_window": { "from": ALWAYS } }
            ] }
        }]
    }));
    let alice = person(Some(ISSUER), &[], AuthMethod::Bearer);
    let input = http(&compiled, "/data/1", authenticated(&alice));
    let facts = canary_facts();
    let result = compiled.evaluate_with_facts(&input, &facts).unwrap();
    assert_eq!(result.matched(), Some(RuleReference::Direct(0)));
    let trace = String::from_utf8(result.canonical_trace_bytes().unwrap()).unwrap();
    for canary in [
        "canary-organization",
        "canary-header-value",
        "canary-query-value",
        "canary-argument-value",
        "203.0.113.77",
        "x-environment",
    ] {
        assert!(!trace.contains(canary), "{canary} leaked into {trace}");
    }
    assert!(trace.contains("\"facts\":\"captured\""), "{trace}");
    assert!(!result.reusable_for(&input));

    // Without facts the trace keeps its earlier shape exactly.
    let plain = compile(json!({ "schema_version": "1.0.0" }));
    let plain_input = http(&plain, "/data/1", PrincipalFact::Anonymous);
    let plain_result = plain.evaluate(&plain_input).unwrap();
    let plain_trace = String::from_utf8(plain_result.canonical_trace_bytes().unwrap()).unwrap();
    assert!(!plain_trace.contains("facts"), "{plain_trace}");
    assert!(plain_result.reusable_for(&plain_input));
    assert_eq!(
        plain
            .evaluate_with_facts(&plain_input, &UNCAPTURED_FACTS)
            .unwrap(),
        plain_result
    );
}

#[test]
fn facts_past_the_kernel_work_bounds_are_refused() {
    let compiled = compile(json!({ "schema_version": "1.0.0" }));
    let input = http(&compiled, "/x", PrincipalFact::Anonymous);
    let mut too_many = PolicyFacts::uncaptured();
    too_many.headers = Fact::Captured(
        (0..=MAX_FACT_ENTRIES)
            .map(|n| (format!("x-h{n}"), "v".to_owned()))
            .collect(),
    );
    let mut too_long = PolicyFacts::uncaptured();
    too_long.query = Fact::Captured(vec![("q".to_owned(), "v".repeat(MAX_FACT_VALUE_BYTES + 1))]);
    let mut long_name = PolicyFacts::uncaptured();
    long_name.headers = Fact::Captured(vec![("h".repeat(MAX_FACT_NAME_BYTES + 1), "v".to_owned())]);
    let mut long_organization = PolicyFacts::uncaptured();
    long_organization.organization = Fact::Captured(Some("o".repeat(MAX_FACT_VALUE_BYTES + 1)));
    for facts in [too_many, too_long, long_name, long_organization] {
        assert_eq!(
            compiled.evaluate_with_facts(&input, &facts),
            Err(EvaluationError::ContextTooLarge)
        );
        assert_eq!(
            compiled
                .evaluate_tool_with_facts(&tool(&compiled, PrincipalFact::Anonymous), &facts)
                .map(|_| ()),
            Err(EvaluationError::ContextTooLarge)
        );
        assert_eq!(
            compiled
                .select_rate_lane_with_facts(&input, &facts)
                .map(|_| ()),
            Err(EvaluationError::ContextTooLarge)
        );
    }
}
