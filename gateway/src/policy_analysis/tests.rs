//! One test per finding class, the analyzer's bounds and renderings, and
//! brute-force checks of every proven claim and patch against the canonical
//! evaluator over small policy universes.

use std::time::{Duration, Instant};

use http::Method;
use proptest::prelude::*;
use serde_json::{json, Value};

use super::{
    checks::{analyze, AnalysisResources},
    coverage::{pattern_covers, segments},
    report::{to_json, to_sarif, AnalysisBinding},
    request::{parse_request, AnalysisFormat},
    AccessEffect, AnalysisLimitation, AnalysisOutcome, Finding, FindingCode, Lane, ProofBasis,
    Severity, MAX_FINDINGS,
};
use crate::{
    auth::{AuthMethod, Principal},
    policy_eval::{
        tools::{
            SourceRequestContext, SourceRequestDecision, ToolEvaluationContext, ToolOperation,
            TOOL_CONTEXT_VERSION,
        },
        CompiledPolicy, DispatchFacts, HostFact, HttpTarget, PolicyEffect, PolicyEvaluationContext,
        PrincipalFact, PrincipalIdentity, RuleReference, CONTEXT_VERSION,
    },
    policy_simulation::edits::{apply_edits, parse_edits},
    policy_testing::suite::Diagnostics,
    rbac::{matcher::path_pattern_matches, Policy},
};

fn policy(value: Value) -> Policy {
    Policy::validate_json_value(value).expect("test policy validates")
}

fn far_deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

fn run_with(policy: &Policy, aliases: &[String], deadline: Instant) -> AnalysisOutcome {
    analyze(
        policy,
        &AnalysisResources {
            mcp_alias_paths: aliases,
        },
        deadline,
    )
    .expect("analysis succeeds")
}

fn run(policy: &Policy) -> AnalysisOutcome {
    run_with(policy, &[], far_deadline())
}

fn codes(outcome: &AnalysisOutcome) -> Vec<&'static str> {
    outcome
        .findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect()
}

/// The single finding with `code`.
fn only(outcome: &AnalysisOutcome, code: FindingCode) -> &Finding {
    let matching: Vec<&Finding> = outcome
        .findings
        .iter()
        .filter(|finding| finding.code == code)
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "one {} in {:?}",
        code.as_str(),
        codes(outcome)
    );
    matching[0]
}

fn lanes(lanes: &[Lane]) -> Vec<&'static str> {
    lanes.iter().map(|lane| lane.as_str()).collect()
}

fn base(rules: Value, routes: Value) -> Value {
    json!({
        "schema_version": "0.1.0",
        "default_action": "deny",
        "roles": {
            "reader": { "permissions": ["api:read"] },
            "admin": { "permissions": ["api:read", "api:admin"], "issuers": ["https://idp.example.test"] }
        },
        "rules": rules,
        "routes": routes,
    })
}

// ---------------------------------------------------------------------------
// Risky defaults
// ---------------------------------------------------------------------------

#[test]
fn a_permissive_default_is_reported_with_a_narrowing_patch() {
    let mut document = base(
        json!([]),
        json!([{ "path_prefix": "/api", "permission": "api:read" }]),
    );
    document["default_action"] = json!("allow");
    let outcome = run(&policy(document));
    let finding = only(&outcome, FindingCode::DefaultAllow);
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.proof_basis, ProofBasis::Proven);
    assert_eq!(finding.element.pointer, "/default_action");
    assert_eq!(finding.details["masked"], json!(false));
    let patch = finding.patch.as_ref().expect("a patch");
    assert_eq!(patch.access_effect, AccessEffect::Narrowing);
    assert_eq!(
        patch.edits,
        vec![json!({ "op": "set", "field": "default_action", "value": "deny" })]
    );
    assert!(outcome.complete);
}

#[test]
fn a_permissive_default_a_catch_all_route_masks_is_low_and_its_patch_equivalent() {
    let mut document = base(
        json!([]),
        json!([{ "path_prefix": "/", "permission": "api:read" }]),
    );
    document["default_action"] = json!("allow");
    let outcome = run(&policy(document));
    let finding = only(&outcome, FindingCode::DefaultAllow);
    assert_eq!(finding.severity, Severity::Low);
    assert_eq!(finding.details["masked"], json!(true));
    assert_eq!(
        finding
            .related
            .as_ref()
            .map(|related| related.pointer.as_str()),
        Some("/routes/0")
    );
    assert_eq!(
        finding.patch.as_ref().map(|patch| patch.access_effect),
        Some(AccessEffect::Equivalent)
    );
}

#[test]
fn global_shadow_enforcement_is_reported_and_inert_only_when_nothing_inherits_it() {
    let mut document = base(
        json!([]),
        json!([{ "path_prefix": "/api", "permission": "api:read" }]),
    );
    document["enforcement_mode"] = json!("shadow");
    let outcome = run(&policy(document.clone()));
    let finding = only(&outcome, FindingCode::GlobalShadowEnforcement);
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.details["inheriting_routes"], json!(1));
    assert_eq!(finding.details["default_softened"], json!(true));
    assert_eq!(
        finding.patch.as_ref().map(|patch| patch.access_effect),
        Some(AccessEffect::Narrowing)
    );

    // Every route sets its own mode and the default allows, so the global
    // mode softens nothing.
    document["routes"] = json!([
        { "path_prefix": "/api", "permission": "api:read", "enforcement_mode": "enforce" }
    ]);
    document["default_action"] = json!("allow");
    let outcome = run(&policy(document));
    let finding = only(&outcome, FindingCode::GlobalShadowEnforcement);
    assert_eq!(finding.severity, Severity::Low);
    assert_eq!(
        finding.patch.as_ref().map(|patch| patch.access_effect),
        Some(AccessEffect::Equivalent)
    );
}

// ---------------------------------------------------------------------------
// Overly broad grants
// ---------------------------------------------------------------------------

#[test]
fn an_allow_for_every_caller_on_every_path_is_reported_with_a_delete_patch() {
    let document = json!({
        "schema_version": "1.0.0",
        "default_action": "deny",
        "rules": [{ "id": "everything", "path": "/**", "action": "allow" }],
    });
    let outcome = run(&policy(document));
    let finding = only(&outcome, FindingCode::BroadUnconstrainedAllow);
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.proof_basis, ProofBasis::Proven);
    assert_eq!(finding.element.id.as_deref(), Some("everything"));
    assert_eq!(finding.details["all_methods"], json!(true));
    let patch = finding.patch.as_ref().expect("a patch");
    assert_eq!(patch.access_effect, AccessEffect::Narrowing);
    assert_eq!(
        patch.edits,
        vec![
            json!({ "op": "delete", "section": "rules", "position": 0, "expect_id": "everything" })
        ]
    );
}

#[test]
fn a_shadow_for_every_caller_on_every_path_is_reported() {
    let outcome = run(&policy(base(
        json!([{ "methods": ["GET"], "path": "/**", "action": "shadow" }]),
        json!([]),
    )));
    let finding = only(&outcome, FindingCode::BroadUnconstrainedShadow);
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.details["all_methods"], json!(false));
}

#[test]
fn constrained_scoped_or_narrower_allows_are_not_broad() {
    for rule in [
        json!({ "path": "/**", "action": "allow", "principal": { "roles": ["reader"] } }),
        json!({ "path": "/**", "action": "allow", "dispatch": { "kind": "contextless" } }),
        json!({ "path": "/public/**", "action": "allow" }),
        json!({ "path": "/**", "action": "deny" }),
        json!({ "path": "/**", "action": "allow", "enabled": false }),
    ] {
        let outcome = run(&policy(base(json!([rule]), json!([]))));
        assert!(
            !codes(&outcome)
                .iter()
                .any(|code| code.starts_with("broad_")),
            "{rule}: {:?}",
            codes(&outcome)
        );
    }
}

#[test]
fn a_wildcard_grant_without_an_issuer_is_a_heuristic_without_a_patch() {
    let mut document = base(json!([]), json!([]));
    document["roles"] = json!({
        "operator": { "permissions": ["status:read", "*"] },
        "bound": { "permissions": ["*"], "issuers": ["https://idp.example.test"] }
    });
    let outcome = run(&policy(document));
    let finding = only(&outcome, FindingCode::WildcardGrantWithoutIssuer);
    assert_eq!(finding.proof_basis, ProofBasis::Heuristic);
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.element.pointer, "/roles/operator/permissions/1");
    assert_eq!(finding.element.name.as_deref(), Some("operator"));
    assert!(finding.patch.is_none());
}

// ---------------------------------------------------------------------------
// Direct rules
// ---------------------------------------------------------------------------

#[test]
fn a_duplicate_rule_is_unreachable_in_every_lane_and_its_removal_equivalent() {
    let document = json!({
        "schema_version": "1.0.0",
        "default_action": "deny",
        "rules": [
            { "id": "block-admin", "methods": ["GET", "POST"], "path": "/admin/**", "action": "deny" },
            { "id": "block-admin-again", "methods": ["get"], "path": "/admin/{page}", "action": "deny" }
        ],
    });
    let outcome = run(&policy(document));
    let finding = only(&outcome, FindingCode::RuleUnreachable);
    assert_eq!(finding.severity, Severity::Low);
    assert_eq!(finding.proof_basis, ProofBasis::Proven);
    assert_eq!(finding.element.position, Some(1));
    assert_eq!(
        finding.related.as_ref().and_then(|r| r.id.as_deref()),
        Some("block-admin")
    );
    assert_eq!(finding.details["relation"], json!("covered"));
    assert_eq!(
        lanes(&finding.never_decides_in),
        [
            "http",
            "mcp_alias",
            "selected_upstream",
            "rendered_tool_http",
            "source_request"
        ]
    );
    assert!(finding.may_decide_in.is_empty());
    let patch = finding.patch.as_ref().expect("a patch");
    assert_eq!(patch.access_effect, AccessEffect::Equivalent);
    assert_eq!(
        patch.edits,
        vec![
            json!({ "op": "delete", "section": "rules", "position": 1, "expect_id": "block-admin-again" })
        ]
    );
}

#[test]
fn an_exact_duplicate_says_so() {
    let rule = json!({ "methods": ["GET"], "path": "/a/*", "action": "allow", "principal": { "roles": ["reader"] } });
    let outcome = run(&policy(base(json!([rule.clone(), rule]), json!([]))));
    assert_eq!(
        only(&outcome, FindingCode::RuleUnreachable).details["relation"],
        json!("duplicate")
    );
}

#[test]
fn an_exception_after_the_deny_that_covers_it_is_unreachable_and_medium() {
    let outcome = run(&policy(base(
        json!([
            { "path": "/admin/**", "action": "deny" },
            { "methods": ["GET"], "path": "/admin/health", "action": "allow" }
        ]),
        json!([]),
    )));
    let finding = only(&outcome, FindingCode::RuleUnreachable);
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.details["action"], json!("allow"));
    assert_eq!(finding.details["covering_action"], json!("deny"));
}

#[test]
fn a_deny_after_an_allow_that_covers_it_is_shadowed_with_a_narrowing_move() {
    let outcome = run(&policy(base(
        json!([
            { "path": "/api/**", "action": "allow" },
            { "path": "/api/admin/**", "action": "deny", "principal": { "roles": ["reader"] } }
        ]),
        json!([]),
    )));
    let finding = only(&outcome, FindingCode::RuleShadowed);
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.proof_basis, ProofBasis::Proven);
    assert_eq!(
        lanes(&finding.never_decides_in),
        ["http", "rendered_tool_http"]
    );
    assert_eq!(
        lanes(&finding.may_decide_in),
        ["mcp_alias", "selected_upstream", "source_request"]
    );
    let patch = finding.patch.as_ref().expect("a patch");
    assert_eq!(patch.access_effect, AccessEffect::Narrowing);
    assert_eq!(
        patch.edits,
        vec![json!({ "op": "move", "section": "rules", "from": 1, "to": 0 })]
    );
}

#[test]
fn a_shadow_after_an_allow_that_covers_it_is_shadowed_and_low() {
    let outcome = run(&policy(base(
        json!([
            { "path": "/api/**", "action": "allow", "principal": { "roles": ["reader"] } },
            { "path": "/api/orders", "action": "shadow", "principal": { "roles": ["reader"], "auth_methods": ["bearer_token"] } }
        ]),
        json!([]),
    )));
    let finding = only(&outcome, FindingCode::RuleShadowed);
    assert_eq!(finding.severity, Severity::Low);
    assert_eq!(lanes(&finding.may_decide_in), ["mcp_alias"]);
}

#[test]
fn rules_an_earlier_rule_does_not_fully_cover_are_not_reported() {
    for (earlier, later) in [
        // Narrower caller.
        (
            json!({ "path": "/api/**", "action": "allow", "principal": { "roles": ["reader"] } }),
            json!({ "path": "/api/admin", "action": "deny" }),
        ),
        // Narrower methods.
        (
            json!({ "methods": ["GET"], "path": "/api/**", "action": "allow" }),
            json!({ "path": "/api/admin", "action": "deny" }),
        ),
        // Narrower path: a single wildcard never matches an empty segment.
        (
            json!({ "path": "/api/*", "action": "allow" }),
            json!({ "path": "/api/**", "action": "deny" }),
        ),
        // A dispatch-bound rule does not cover an unbound one.
        (
            json!({ "path": "/**", "action": "deny", "dispatch": { "kind": "contextless" } }),
            json!({ "path": "/api", "action": "deny" }),
        ),
        // A disabled rule covers nothing.
        (
            json!({ "path": "/**", "action": "deny", "enabled": false }),
            json!({ "path": "/api", "action": "deny" }),
        ),
        // A tool-name rule never covers an HTTP rule.
        (
            json!({ "tool_name": "echo", "action": "deny" }),
            json!({ "path": "/api", "action": "deny" }),
        ),
    ] {
        let outcome = run(&policy(base(json!([earlier, later]), json!([]))));
        assert!(
            !codes(&outcome).iter().any(|code| code.starts_with("rule_")),
            "{earlier} / {later}: {:?}",
            codes(&outcome)
        );
    }
}

#[test]
fn tool_name_rules_are_analyzed_in_their_own_lane() {
    let mut document = base(
        json!([
            { "tool_name": "echo", "action": "allow" },
            { "tool_name": "echo", "action": "deny", "principal": { "roles": ["reader"] } },
            { "tool_name": "other", "action": "deny" },
            { "tool_name": "other", "action": "deny", "principal": { "roles": ["reader"] } }
        ]),
        json!([]),
    );
    document["tools"] = json!({ "echo": {}, "other": {} });
    let outcome = run(&policy(document));
    let shadowed = only(&outcome, FindingCode::RuleShadowed);
    assert_eq!(shadowed.element.position, Some(1));
    assert_eq!(lanes(&shadowed.never_decides_in), ["tool"]);
    assert!(shadowed.may_decide_in.is_empty());
    let unreachable = only(&outcome, FindingCode::RuleUnreachable);
    assert_eq!(unreachable.element.position, Some(3));
    assert_eq!(lanes(&unreachable.never_decides_in), ["tool"]);
    assert_eq!(
        unreachable.patch.as_ref().map(|patch| patch.access_effect),
        Some(AccessEffect::Equivalent)
    );
}

#[test]
fn a_claim_the_evaluator_cannot_confirm_is_inconclusive_and_carries_no_patch() {
    // A literal empty interior segment: the evaluator refuses the only path
    // the pattern matches, so the witness can never confirm the claim.
    let outcome = run(&policy(base(
        json!([
            { "path": "/a//b", "action": "deny" },
            { "path": "/a//b", "action": "deny" }
        ]),
        json!([]),
    )));
    let finding = only(&outcome, FindingCode::RuleUnreachable);
    assert_eq!(finding.proof_basis, ProofBasis::Inconclusive);
    assert!(finding.patch.is_none());
    assert_eq!(finding.limitations, ["witness_unconfirmed"]);
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

#[test]
fn a_route_an_identical_earlier_route_covers_is_unreachable() {
    let outcome = run(&policy(base(
        json!([]),
        json!([
            { "methods": ["GET", "POST"], "path_prefix": "/api", "permission": "api:read" },
            { "methods": ["GET"], "path_prefix": "/api/orders/", "permission": "api:read" }
        ]),
    )));
    let finding = only(&outcome, FindingCode::RouteUnreachable);
    assert_eq!(finding.severity, Severity::Low);
    assert_eq!(finding.element.pointer, "/routes/1");
    assert_eq!(finding.details["decided_by"], json!("route"));
    assert_eq!(
        lanes(&finding.never_decides_in),
        ["http", "mcp_alias", "selected_upstream"]
    );
    assert_eq!(
        finding.patch.as_ref().map(|patch| patch.access_effect),
        Some(AccessEffect::Equivalent)
    );
}

#[test]
fn a_specific_route_after_a_broader_one_is_shadowed_and_its_move_effect_is_judged_by_roles() {
    // Every role granting api:admin also grants api:read: moving the admin
    // route first can only take access away.
    let outcome = run(&policy(base(
        json!([]),
        json!([
            { "path_prefix": "/api", "permission": "api:read" },
            { "path_prefix": "/api/admin", "permission": "api:admin" }
        ]),
    )));
    let finding = only(&outcome, FindingCode::RouteShadowed);
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.details["permission_differs"], json!(true));
    assert_eq!(finding.details["mode_differs"], json!(false));
    let patch = finding.patch.as_ref().expect("a patch");
    assert_eq!(patch.access_effect, AccessEffect::Narrowing);
    assert_eq!(
        patch.edits,
        vec![json!({ "op": "move", "section": "routes", "from": 1, "to": 0 })]
    );

    // A role holding only the later permission makes the move's effect
    // unknowable from the roles.
    let mut document = base(
        json!([]),
        json!([
            { "path_prefix": "/api", "permission": "api:read" },
            { "path_prefix": "/api/admin", "permission": "api:admin" }
        ]),
    );
    document["roles"]["auditor"] = json!({ "permissions": ["api:admin"] });
    let outcome = run(&policy(document));
    assert_eq!(
        only(&outcome, FindingCode::RouteShadowed)
            .patch
            .as_ref()
            .map(|patch| patch.access_effect),
        Some(AccessEffect::Unknown)
    );
}

#[test]
fn a_route_at_an_mcp_alias_path_is_not_claimed_unreachable_by_a_broader_route() {
    let document = base(
        json!([]),
        json!([
            { "path_prefix": "/v1", "permission": "api:read" },
            { "path_prefix": "/v1/mcp", "permission": "api:admin" }
        ]),
    );
    let aliases = ["/v1/mcp".to_owned()];
    let outcome = run_with(&policy(document.clone()), &aliases, far_deadline());
    assert!(codes(&outcome).is_empty(), "{:?}", codes(&outcome));
    // Without the alias it is shadowed.
    assert_eq!(codes(&run(&policy(document))), ["route_shadowed"]);

    // An identical earlier prefix still decides the alias first.
    let identical = base(
        json!([]),
        json!([
            { "path_prefix": "/v1/mcp", "permission": "api:read" },
            { "path_prefix": "/v1/mcp", "permission": "api:read" }
        ]),
    );
    let outcome = run_with(&policy(identical), &aliases, far_deadline());
    assert_eq!(codes(&outcome), ["route_unreachable"]);
}

#[test]
fn routes_with_different_hosts_or_methods_are_not_reported() {
    for (earlier, later) in [
        (
            json!({ "path_prefix": "/api", "permission": "api:read" }),
            json!({ "path_prefix": "/api/x", "hosts": ["api.example.test"], "permission": "api:admin" }),
        ),
        (
            json!({ "path_prefix": "/api", "hosts": ["api.example.test"], "permission": "api:read" }),
            json!({ "path_prefix": "/api/x", "permission": "api:admin" }),
        ),
        (
            json!({ "methods": ["GET"], "path_prefix": "/api", "permission": "api:read" }),
            json!({ "path_prefix": "/api/x", "permission": "api:admin" }),
        ),
        (
            json!({ "path_prefix": "/api/", "permission": "api:read" }),
            json!({ "path_prefix": "/api", "permission": "api:admin" }),
        ),
        (
            json!({ "path_prefix": "/api", "permission": "api:read" }),
            json!({ "path_prefix": "/apix", "permission": "api:admin" }),
        ),
    ] {
        let outcome = run(&policy(base(json!([]), json!([earlier, later]))));
        assert!(
            !codes(&outcome)
                .iter()
                .any(|code| code.starts_with("route_")),
            "{earlier} / {later}: {:?}",
            codes(&outcome)
        );
    }
}

#[test]
fn a_route_every_caller_reaches_through_a_direct_allow_is_bypassed() {
    let outcome = run(&policy(base(
        json!([{ "methods": ["GET"], "path": "/admin/**", "action": "allow" }]),
        json!([
            { "methods": ["GET"], "path_prefix": "/admin", "permission": "api:admin" },
            { "methods": ["GET"], "path_prefix": "/admin/reports", "hosts": ["admin.example.test"], "permission": "api:admin" }
        ]),
    )));
    let bypassed: Vec<&Finding> = outcome
        .findings
        .iter()
        .filter(|finding| finding.code == FindingCode::RouteBypassed)
        .collect();
    assert_eq!(bypassed.len(), 2, "{:?}", codes(&outcome));
    for finding in &bypassed {
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.proof_basis, ProofBasis::Proven);
        assert_eq!(lanes(&finding.never_decides_in), ["http", "mcp_alias"]);
        assert_eq!(finding.details["rule_action"], json!("allow"));
        let patch = finding.patch.as_ref().expect("a patch");
        assert_eq!(patch.access_effect, AccessEffect::Narrowing);
        assert_eq!(
            patch.edits,
            vec![json!({ "op": "delete", "section": "rules", "position": 0 })]
        );
    }
    // Only the host-bound route still decides a selected virtual upstream.
    assert!(bypassed[0].may_decide_in.is_empty());
    assert_eq!(lanes(&bypassed[1].may_decide_in), ["selected_upstream"]);
}

#[test]
fn a_route_a_direct_deny_for_every_caller_decides_is_unreachable() {
    let outcome = run(&policy(base(
        json!([{ "path": "/legacy/**", "action": "deny" }]),
        json!([{ "path_prefix": "/legacy", "permission": "api:read" }]),
    )));
    let finding = only(&outcome, FindingCode::RouteUnreachable);
    assert_eq!(finding.details["decided_by"], json!("rule"));
    assert_eq!(
        finding
            .related
            .as_ref()
            .map(|related| related.pointer.as_str()),
        Some("/rules/0")
    );
    assert_eq!(
        finding.patch.as_ref().map(|patch| patch.access_effect),
        Some(AccessEffect::Equivalent)
    );
}

// ---------------------------------------------------------------------------
// Rate overrides
// ---------------------------------------------------------------------------

fn rate_policy(limits: Value) -> Policy {
    let mut document = base(json!([]), json!([]));
    document["rate_limits"] = limits;
    policy(document)
}

#[test]
fn a_rate_override_an_identical_earlier_one_covers_is_unreachable() {
    let outcome = run(&rate_policy(json!([
        { "requests_per_second": 5.0, "burst": 10 },
        { "methods": ["GET"], "path": "/api/**", "requests_per_second": 5.0, "burst": 10 }
    ])));
    let finding = only(&outcome, FindingCode::RateOverrideUnreachable);
    assert_eq!(lanes(&finding.never_decides_in), ["rate"]);
    assert_eq!(
        finding.patch.as_ref().map(|patch| patch.access_effect),
        Some(AccessEffect::Equivalent)
    );
}

#[test]
fn a_shadowed_rate_override_is_judged_by_its_limits() {
    for (later, severity, limits, effect) in [
        (
            json!({ "path": "/api/**", "requests_per_second": 1.0, "burst": 2 }),
            Severity::Medium,
            "stricter",
            AccessEffect::Narrowing,
        ),
        (
            json!({ "path": "/api/**", "requests_per_second": 9.0, "burst": 20 }),
            Severity::Low,
            "looser",
            AccessEffect::Expanding,
        ),
        (
            json!({ "path": "/api/**", "requests_per_second": 1.0, "burst": 20 }),
            Severity::Low,
            "mixed",
            AccessEffect::Unknown,
        ),
    ] {
        let outcome = run(&rate_policy(json!([
            { "path": "/api/**", "requests_per_second": 5.0, "burst": 10 },
            later
        ])));
        let finding = only(&outcome, FindingCode::RateOverrideShadowed);
        assert_eq!(finding.severity, severity);
        assert_eq!(finding.details["limits"], json!(limits));
        let patch = finding.patch.as_ref().expect("a patch");
        assert_eq!(patch.access_effect, effect);
        assert_eq!(
            patch.edits,
            vec![json!({ "op": "move", "section": "rate_limits", "from": 1, "to": 0 })]
        );
    }
}

#[test]
fn a_narrower_earlier_rate_override_covers_nothing() {
    let outcome = run(&rate_policy(json!([
        { "path": "/api/*", "requests_per_second": 5.0, "burst": 10 },
        { "requests_per_second": 1.0, "burst": 1 }
    ])));
    assert!(codes(&outcome).is_empty(), "{:?}", codes(&outcome));
}

// ---------------------------------------------------------------------------
// Bounds, identity and renderings
// ---------------------------------------------------------------------------

#[test]
fn a_passed_deadline_stops_pairwise_checks_and_marks_the_result_incomplete() {
    let mut document = base(
        json!([
            { "path": "/a/**", "action": "deny" },
            { "path": "/a/b", "action": "deny" }
        ]),
        json!([]),
    );
    document["default_action"] = json!("allow");
    let outcome = run_with(&policy(document), &[], Instant::now());
    assert!(!outcome.complete);
    assert_eq!(outcome.limitations, [AnalysisLimitation::DeadlineExceeded]);
    // The linear checks ran before the deadline was read.
    assert_eq!(codes(&outcome), ["default_allow"]);
}

#[test]
fn findings_beyond_the_cap_truncate_the_result() {
    let rules: Vec<Value> = (0..=MAX_FINDINGS + 1)
        .map(|_| json!({ "path": "/a", "action": "deny" }))
        .collect();
    let outcome = run(&policy(base(json!(rules), json!([]))));
    assert_eq!(outcome.findings.len(), MAX_FINDINGS);
    assert!(!outcome.complete);
    assert_eq!(outcome.limitations, [AnalysisLimitation::FindingsTruncated]);
}

#[test]
fn a_fingerprint_follows_stable_ids_across_reorders_and_differs_by_code() {
    let first = json!({
        "schema_version": "1.0.0",
        "default_action": "deny",
        "rules": [
            { "id": "unrelated", "path": "/z", "action": "deny" },
            { "id": "broad", "path": "/api/**", "action": "allow" },
            { "id": "narrow", "path": "/api/admin", "action": "deny" }
        ],
    });
    let mut second = first.clone();
    second["rules"] = json!([
        { "id": "broad", "path": "/api/**", "action": "allow" },
        { "id": "narrow", "path": "/api/admin", "action": "deny" },
        { "id": "unrelated", "path": "/z", "action": "deny" }
    ]);
    let fingerprint = |document: Value| {
        only(&run(&policy(document)), FindingCode::RuleShadowed)
            .fingerprint()
            .expect("fingerprint")
    };
    let before = fingerprint(first);
    assert!(before.starts_with("sha256:"));
    assert_eq!(before, fingerprint(second));

    let mut other = only(
        &run(&policy(json!({
            "schema_version": "1.0.0",
            "default_action": "deny",
            "rules": [
                { "id": "broad", "path": "/api/**", "action": "allow" },
                { "id": "narrow", "path": "/api/admin", "action": "deny" }
            ],
        }))),
        FindingCode::RuleShadowed,
    )
    .clone();
    other.code = FindingCode::RuleUnreachable;
    assert_ne!(before, other.fingerprint().expect("fingerprint"));
}

fn binding<'a>(digest: &'a str, etag: &'a str) -> AnalysisBinding<'a> {
    AnalysisBinding {
        request_digest: digest,
        base_etag: etag,
        security_revision: None,
        source: "active",
        analyzed_etag: etag,
        edit_count: 0,
        mcp_alias_paths: 0,
    }
}

#[test]
fn the_json_report_is_deterministic_and_names_no_policy_value() {
    let document = base(
        json!([
            { "path": "/secret-area/**", "action": "allow" },
            { "path": "/secret-area/vault", "action": "deny", "principal": { "roles": ["reader"] } }
        ]),
        json!([]),
    );
    let render = || {
        let outcome = run(&policy(document.clone()));
        to_json(&outcome, &binding("sha256:digest", "\"sha256:etag\"")).expect("renders")
    };
    let first = render();
    assert_eq!(first, render());
    let text = first.to_string();
    for value in ["secret-area", "vault", "reader"] {
        assert!(!text.contains(value), "{value} leaked into {text}");
    }
    assert_eq!(first["schema_version"], json!("policy-analysis-results.v1"));
    assert_eq!(first["complete"], json!(true));
    assert_eq!(first["summary"]["findings"], json!(1));
    assert_eq!(first["summary"]["by_code"]["rule_shadowed"], json!(1));
    let finding = &first["findings"][0];
    assert_eq!(
        finding["patch"]["format"],
        json!("policy-simulation.v1/edits")
    );
    assert_eq!(
        finding["patch"]["applies_to_etag"],
        json!("\"sha256:etag\"")
    );
    assert_eq!(finding["patch"]["access_effect"], json!("narrowing"));
}

#[test]
fn sarif_carries_one_rule_per_code_and_one_result_per_finding() {
    let outcome = run(&policy(base(
        json!([
            { "path": "/api/**", "action": "allow" },
            { "path": "/api/admin", "action": "deny" }
        ]),
        json!([]),
    )));
    let sarif = to_sarif(&outcome, &binding("sha256:digest", "\"sha256:etag\"")).expect("renders");
    let run = &sarif["runs"][0];
    assert_eq!(sarif["version"], json!("2.1.0"));
    assert_eq!(
        run["tool"]["driver"]["rules"].as_array().map(Vec::len),
        Some(FindingCode::ALL.len())
    );
    let results = run["results"].as_array().expect("results");
    assert_eq!(results.len(), outcome.findings.len());
    let shadowed = results
        .iter()
        .find(|result| result["ruleId"] == json!("policy-analysis/rule_shadowed"))
        .expect("the shadowed rule");
    assert_eq!(shadowed["level"], json!("error"));
    assert_eq!(shadowed["kind"], json!("fail"));
    assert_eq!(
        shadowed["locations"][0]["logicalLocations"][0]["fullyQualifiedName"],
        json!("/rules/1")
    );
    assert!(shadowed["partialFingerprints"]["policyAnalysisFinding/v1"]
        .as_str()
        .is_some_and(|fingerprint| fingerprint.starts_with("sha256:")));
    assert_eq!(run["properties"]["complete"], json!(true));
}

#[test]
fn every_patch_is_a_simulation_edit_list_that_applies_and_validates_and_resolves_its_finding() {
    let document = json!({
        "schema_version": "1.0.0",
        "default_action": "allow",
        "enforcement_mode": "shadow",
        "roles": { "reader": { "permissions": ["api:read"] } },
        "rules": [
            { "id": "everything-get", "methods": ["GET"], "path": "/**", "action": "allow" },
            { "id": "api-allow", "path": "/api/**", "action": "allow" },
            { "id": "api-admin-deny", "path": "/api/admin/**", "action": "deny" },
            { "id": "api-admin-deny-again", "path": "/api/admin/x", "action": "deny" }
        ],
        "routes": [
            { "id": "api", "path_prefix": "/api", "permission": "api:read" },
            { "id": "api-again", "path_prefix": "/api", "permission": "api:read" }
        ],
        "rate_limits": [
            { "id": "all", "requests_per_second": 5.0, "burst": 10 },
            { "id": "api-strict", "path": "/api/**", "requests_per_second": 1.0, "burst": 1 }
        ],
    });
    let analyzed = policy(document.clone());
    let outcome = run(&analyzed);
    assert!(outcome.findings.len() >= 5, "{:?}", codes(&outcome));
    for finding in outcome
        .findings
        .iter()
        .filter(|finding| finding.patch.is_some())
    {
        let Some(patch) = &finding.patch else {
            continue;
        };
        let mut diagnostics = Diagnostics::new();
        let edits = parse_edits(Some(&json!(patch.edits)), "/edits", &mut diagnostics);
        assert!(
            diagnostics.is_empty(),
            "{}: edits parse",
            finding.code.as_str()
        );
        let patched = apply_edits(
            &serde_json::to_value(&analyzed).expect("serializes"),
            &edits,
            "/edits",
        )
        .unwrap_or_else(|_| panic!("{}: edits apply", finding.code.as_str()));
        let patched = Policy::validate_json_value(patched)
            .unwrap_or_else(|_| panic!("{}: patched policy validates", finding.code.as_str()));
        let after = run(&patched);
        assert!(
            !after.findings.iter().any(|other| other.code == finding.code
                && other.fingerprint().ok() == finding.fingerprint().ok()),
            "{}: the patch resolves its finding",
            finding.code.as_str()
        );
    }
}

#[test]
fn the_request_dispatches_its_version_exactly_and_refuses_unknown_members() {
    let parse = |value: Value| {
        let bytes = serde_json::to_vec(&value).expect("serializes");
        parse_request(&bytes, &value)
    };
    let accepted = parse(json!({
        "schema_version": "policy-analysis.v1",
        "base_etag": "\"sha256:x\"",
        "candidate": { "source": "active" },
        "format": "sarif",
    }))
    .unwrap_or_else(|_| panic!("accepted"));
    assert_eq!(accepted.format, AnalysisFormat::Sarif);
    assert!(accepted.digest.starts_with("sha256:"));

    for (value, code) in [
        (
            json!({ "schema_version": "policy-analysis.v2" }),
            "unsupported_schema_version",
        ),
        (
            json!({ "schema_version": "policy-analysis.v1", "candidate": { "source": "active" } }),
            "missing_field",
        ),
        (
            json!({
                "schema_version": "policy-analysis.v1", "base_etag": "\"e\"",
                "candidate": { "source": "active" }, "apply": true
            }),
            "unknown_field",
        ),
        (
            json!({
                "schema_version": "policy-analysis.v1", "base_etag": "\"e\"",
                "candidate": { "source": "active" }, "format": "junit"
            }),
            "invalid_value",
        ),
    ] {
        let Err(diagnostics) = parse(value.clone()) else {
            panic!("{value} is refused");
        };
        assert!(
            diagnostics
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == code),
            "{value}: {code}"
        );
    }
}

fn request_schema() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/schemas/policy-analysis.v1.schema.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

/// The published schema and the parser agree on the requests both can
/// judge, and every patch the analyzer emits is an edit list both accept as
/// an edits candidate.
#[test]
fn the_published_schema_agrees_with_the_parser_and_admits_every_patch() {
    let schema = request_schema();
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let mut document = base(
        json!([
            { "path": "/**", "action": "shadow" },
            { "path": "/api/admin", "action": "deny" }
        ]),
        json!([
            { "path_prefix": "/api", "permission": "api:read" },
            { "path_prefix": "/api/admin", "permission": "api:admin" }
        ]),
    );
    document["default_action"] = json!("allow");
    document["enforcement_mode"] = json!("shadow");
    document["rate_limits"] = json!([
        { "requests_per_second": 5.0, "burst": 10 },
        { "path": "/api/**", "requests_per_second": 1.0, "burst": 1 }
    ]);
    let outcome = run(&policy(document));
    let edits: Vec<Value> = outcome
        .findings
        .iter()
        .filter_map(|finding| finding.patch.as_ref())
        .flat_map(|patch| patch.edits.clone())
        .collect();
    assert!(edits.len() >= 5, "{:?}", codes(&outcome));
    let request = |candidate: Value| {
        json!({
            "schema_version": "policy-analysis.v1",
            "description": "review",
            "base_etag": "\"sha256:x\"",
            "candidate": candidate,
            "format": "json",
        })
    };
    for accepted in [
        request(json!({ "source": "active" })),
        request(json!({ "source": "edits", "edits": edits })),
        request(json!({ "source": "inline", "policy": { "schema_version": "0.1.0" } })),
    ] {
        let bytes = serde_json::to_vec(&accepted).expect("serializes");
        assert!(validator.is_valid(&accepted), "schema accepts {accepted}");
        assert!(
            parse_request(&bytes, &accepted).is_ok(),
            "parser accepts {accepted}"
        );
    }
    let mut unknown = request(json!({ "source": "active" }));
    unknown["apply"] = json!(true);
    let mut format = request(json!({ "source": "active" }));
    format["format"] = json!("junit");
    let mut version = request(json!({ "source": "active" }));
    version["schema_version"] = json!("policy-analysis.v2");
    let mut unpinned = request(json!({ "source": "active" }));
    unpinned
        .as_object_mut()
        .expect("object")
        .remove("base_etag");
    for refused in [
        unknown,
        format,
        version,
        unpinned,
        request(json!({ "source": "edits", "edits": [] })),
        request(json!({ "source": "draft" })),
    ] {
        let bytes = serde_json::to_vec(&refused).expect("serializes");
        assert!(!validator.is_valid(&refused), "schema refuses {refused}");
        assert!(
            parse_request(&bytes, &refused).is_err(),
            "parser refuses {refused}"
        );
    }
}

// ---------------------------------------------------------------------------
// Brute force: inclusion proofs over small universes
// ---------------------------------------------------------------------------

/// Every path of at most four segments over a vocabulary that holds each
/// literal the generated patterns use, a non-literal and the empty segment.
fn path_universe() -> Vec<String> {
    let vocabulary = ["", "a", "b", "c"];
    let mut paths = vec!["/".to_owned()];
    let mut layer: Vec<Vec<&str>> = vec![Vec::new()];
    for _ in 0..4 {
        let mut next = Vec::new();
        for prefix in &layer {
            for segment in vocabulary {
                let mut path = prefix.clone();
                path.push(segment);
                paths.push(format!("/{}", path.join("/")));
                next.push(path);
            }
        }
        layer = next;
    }
    paths
}

fn pattern_strategy(deep: bool) -> impl Strategy<Value = String> {
    let segment = if deep {
        prop_oneof![
            Just("a"),
            Just("b"),
            Just(""),
            Just("*"),
            Just("**"),
            Just("{id}")
        ]
        .boxed()
    } else {
        prop_oneof![Just("a"), Just("b"), Just(""), Just("*"), Just("{id}")].boxed()
    };
    prop::collection::vec(segment, 0..4).prop_map(|segments| format!("/{}", segments.join("/")))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn pattern_inclusion_is_never_claimed_where_the_matcher_disagrees(
        covering in pattern_strategy(true),
        covered in pattern_strategy(true),
    ) {
        if pattern_covers(&segments(&covering), &segments(&covered)) {
            for path in path_universe() {
                prop_assert!(
                    !path_pattern_matches(&covered, &path) || path_pattern_matches(&covering, &path),
                    "{covering} claimed to cover {covered}, but not {path}"
                );
            }
        }
    }

    #[test]
    fn pattern_inclusion_is_exact_without_deep_wildcards(
        covering in pattern_strategy(false),
        covered in pattern_strategy(false),
    ) {
        let included = path_universe().iter().all(|path| {
            !path_pattern_matches(&covered, path) || path_pattern_matches(&covering, path)
        });
        prop_assert_eq!(pattern_covers(&segments(&covering), &segments(&covered)), included);
    }
}

// ---------------------------------------------------------------------------
// Brute force: proven claims and patch effects against the evaluator
// ---------------------------------------------------------------------------

const UNIVERSE_SEGMENTS: [&str; 3] = ["a", "b", "w"];
const SELECTED_HOST: &str = "h1.example.test";
/// The universe's MCP alias paths, which the analyzer is told about. Every
/// path is also evaluated as an alias, which direct-rule claims must survive
/// whatever the configured aliases are; route claims depend on them, and are
/// checked only where a live request could be an alias.
const ALIAS_PATHS: [&str; 2] = ["/a/b", "/w"];

fn alias_paths() -> Vec<String> {
    ALIAS_PATHS.iter().map(|path| (*path).to_owned()).collect()
}

fn http_paths() -> Vec<String> {
    let mut paths = vec!["/".to_owned()];
    let mut layer: Vec<String> = vec![String::new()];
    for _ in 0..3 {
        let mut next = Vec::new();
        for prefix in &layer {
            for segment in UNIVERSE_SEGMENTS {
                let path = format!("{prefix}/{segment}");
                paths.push(path.clone());
                next.push(path);
            }
        }
        layer = next;
    }
    paths
}

fn universe_principals() -> Vec<PrincipalFact> {
    let mut principals = vec![PrincipalFact::Anonymous];
    for roles in [&[][..], &["r1"][..], &["r2"][..], &["r1", "r2"][..]] {
        for issuer in [None, Some("i1")] {
            principals.push(PrincipalFact::Authenticated(
                PrincipalIdentity::from_principal(&Principal {
                    user_id: "u1".to_owned(),
                    issuer: issuer.map(str::to_owned),
                    email: None,
                    org_id: None,
                    roles: roles.iter().map(|role| (*role).to_owned()).collect(),
                    session_id: String::new(),
                    auth_method: AuthMethod::Bearer,
                }),
            ));
        }
    }
    principals
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decider {
    Rule(usize),
    Route(usize),
    Nothing,
}

/// One answer over the universe: the lane, whether the request would be
/// forwarded, and which element decided it.
#[derive(Clone, Copy, Debug)]
struct Answer {
    lane: Lane,
    /// False for an alias answer at a path that is not a configured alias.
    realistic: bool,
    forwards: bool,
    decider: Decider,
    observation: Option<usize>,
}

fn decider(matched: Option<RuleReference>) -> Decider {
    match matched {
        Some(RuleReference::Direct(index)) => Decider::Rule(index),
        Some(RuleReference::Route(index)) => Decider::Route(index),
        None => Decider::Nothing,
    }
}

/// Every lane's answers for `policy`, in a fixed order, so two policies'
/// answers can be compared point by point.
fn answers(policy: &Policy) -> Vec<Answer> {
    let compiled = CompiledPolicy::for_analysis(policy.clone());
    let snapshot = compiled.snapshot();
    let mut answers = Vec::new();
    let methods = [Method::GET, Method::POST, Method::PUT];
    let principals = universe_principals();
    for path in http_paths() {
        for method in &methods {
            for principal in &principals {
                for lane in [Lane::Http, Lane::McpAlias, Lane::SelectedUpstream] {
                    let (target, dispatch) = match lane {
                        Lane::McpAlias => (
                            HttpTarget::McpAlias {
                                canonical_path: "/mcp".to_owned(),
                            },
                            None,
                        ),
                        Lane::SelectedUpstream => (
                            HttpTarget::ProxyDispatch,
                            Some(DispatchFacts {
                                route_id: Some("pooled".to_owned()),
                                route_host: Some(SELECTED_HOST.to_owned()),
                                route_path_prefix: None,
                                upstream_origin: "pool:pooled".to_owned(),
                            }),
                        ),
                        _ => (HttpTarget::Contextless, None),
                    };
                    let evaluation = compiled
                        .evaluate(&PolicyEvaluationContext {
                            version: CONTEXT_VERSION,
                            snapshot,
                            method: Some(method.clone()),
                            path: Some(path.clone()),
                            principal: principal.clone(),
                            target,
                            request_host: HostFact::Absent,
                            dispatch,
                        })
                        .expect("the universe is well formed");
                    answers.push(Answer {
                        lane,
                        realistic: lane != Lane::McpAlias || ALIAS_PATHS.contains(&path.as_str()),
                        forwards: evaluation.effect() != PolicyEffect::Block,
                        decider: decider(evaluation.matched()),
                        observation: match evaluation.observation() {
                            Some(RuleReference::Direct(index)) => Some(index),
                            _ => None,
                        },
                    });
                }
                for (operation, tool_name, lane) in [
                    (ToolOperation::RenderedHttp, "t1", Lane::RenderedToolHttp),
                    (ToolOperation::Invocation, "t1", Lane::Tool),
                    (ToolOperation::Invocation, "t2", Lane::Tool),
                ] {
                    let rendered = operation == ToolOperation::RenderedHttp;
                    let evaluation = compiled
                        .evaluate_tool(&ToolEvaluationContext {
                            version: TOOL_CONTEXT_VERSION,
                            snapshot,
                            operation,
                            tool_name: Some(tool_name.to_owned()),
                            principal: principal.clone(),
                            method: rendered.then(|| method.clone()),
                            path: rendered.then(|| path.clone()),
                        })
                        .expect("the universe is well formed");
                    answers.push(Answer {
                        lane,
                        realistic: true,
                        forwards: evaluation.effect() != PolicyEffect::Block,
                        decider: decider(evaluation.matched()),
                        observation: None,
                    });
                }
            }
        }
        let decision = compiled
            .evaluate_source_request(&SourceRequestContext {
                version: TOOL_CONTEXT_VERSION,
                snapshot,
                tool_name: None,
                path: path.clone(),
            })
            .expect("the universe is well formed");
        answers.push(match decision {
            SourceRequestDecision::Denied { index } => Answer {
                lane: Lane::SourceRequest,
                realistic: true,
                forwards: false,
                decider: Decider::Rule(index),
                observation: None,
            },
            _ => Answer {
                lane: Lane::SourceRequest,
                realistic: true,
                forwards: true,
                decider: Decider::Nothing,
                observation: None,
            },
        });
    }
    answers
}

fn rule_strategy() -> impl Strategy<Value = Value> {
    (
        prop_oneof![
            Just(json!([])),
            Just(json!(["GET"])),
            Just(json!(["POST"])),
            Just(json!(["GET", "POST"]))
        ],
        prop_oneof![
            Just("/**"),
            Just("/a/**"),
            Just("/a/*"),
            Just("/a/b"),
            Just("/a"),
            Just("/*/b"),
            Just("/b/**"),
            Just("/{x}/**")
        ],
        prop_oneof![
            Just(json!({})),
            Just(json!({ "roles": ["r1"] })),
            Just(json!({ "roles": ["r1", "r2"] })),
            Just(json!({ "roles": ["r1"], "issuers": ["i1"] }))
        ],
        prop_oneof![Just("allow"), Just("deny"), Just("shadow")],
        prop_oneof![
            4 => Just(None),
            1 => Just(Some("t1")),
            1 => Just(Some("t2"))
        ],
    )
        .prop_map(|(methods, path, principal, action, tool)| match tool {
            Some(tool) => json!({ "tool_name": tool, "principal": principal, "action": action }),
            None => json!({ "methods": methods, "path": path, "principal": principal, "action": action }),
        })
}

fn route_strategy() -> impl Strategy<Value = Value> {
    (
        prop_oneof![
            Just(json!([])),
            Just(json!(["GET"])),
            Just(json!(["GET", "POST"]))
        ],
        prop_oneof![Just("/"), Just("/a"), Just("/a/"), Just("/a/b"), Just("/b")],
        prop_oneof![3 => Just(json!([])), 1 => Just(json!([SELECTED_HOST]))],
        prop_oneof![Just("p1"), Just("p2")],
        prop_oneof![3 => Just(None), 1 => Just(Some("shadow")), 1 => Just(Some("enforce"))],
    )
        .prop_map(|(methods, prefix, hosts, permission, mode)| {
            let mut route = json!({
                "methods": methods, "path_prefix": prefix, "hosts": hosts, "permission": permission
            });
            if let (Some(mode), Some(route)) = (mode, route.as_object_mut()) {
                route.insert("enforcement_mode".to_owned(), json!(mode));
            }
            route
        })
}

fn policy_strategy() -> impl Strategy<Value = Value> {
    (
        prop::collection::vec(rule_strategy(), 0..5),
        prop::collection::vec(route_strategy(), 0..4),
        prop_oneof![Just("allow"), Just("deny")],
        prop_oneof![3 => Just("enforce"), 1 => Just("shadow")],
        prop_oneof![
            Just(json!(["p1"])),
            Just(json!(["p1", "p2"])),
            Just(json!(["*"]))
        ],
    )
        .prop_map(|(rules, routes, default_action, mode, r1)| {
            json!({
                "schema_version": "0.1.0",
                "default_action": default_action,
                "enforcement_mode": mode,
                "roles": {
                    "r1": { "permissions": r1 },
                    "r2": { "permissions": ["p2"], "issuers": ["i1"] }
                },
                "rules": rules,
                "routes": routes,
                "tools": { "t1": {}, "t2": { "allowed_roles": ["r1"] } },
            })
        })
}

fn patched(policy: &Policy, edits: &[Value]) -> Policy {
    let mut diagnostics = Diagnostics::new();
    let edits = parse_edits(Some(&json!(edits)), "/edits", &mut diagnostics);
    assert!(diagnostics.is_empty(), "patch edits parse");
    let document = apply_edits(
        &serde_json::to_value(policy).expect("serializes"),
        &edits,
        "/edits",
    )
    .unwrap_or_else(|_| panic!("patch edits apply"));
    Policy::validate_json_value(document).unwrap_or_else(|_| panic!("patched policy validates"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Every proven reachability claim holds for every request of the
    /// universe in every lane it names, and every patch has the access
    /// effect it claims there.
    #[test]
    fn proven_claims_and_patch_effects_hold_against_the_evaluator(document in policy_strategy()) {
        let analyzed = policy(document);
        let outcome = run_with(&analyzed, &alias_paths(), far_deadline());
        prop_assert!(outcome.complete);
        let before = answers(&analyzed);
        for finding in &outcome.findings {
            if finding.proof_basis != ProofBasis::Proven {
                continue;
            }
            // Route claims depend on the configured aliases.
            let about_routes = finding.element.section == super::Section::Routes;
            let element = match (finding.element.section, finding.element.position) {
                (super::Section::Rules, Some(position)) => Some(Decider::Rule(position)),
                (super::Section::Routes, Some(position)) => Some(Decider::Route(position)),
                _ => None,
            };
            if let Some(element) = element {
                for answer in before.iter().filter(|answer| {
                    finding.never_decides_in.contains(&answer.lane) && (answer.realistic || !about_routes)
                }) {
                    prop_assert_ne!(
                        answer.decider, element,
                        "{} claims {:?} never decides in {:?}", finding.code.as_str(), element, answer.lane
                    );
                    if let Decider::Rule(position) = element {
                        prop_assert_ne!(answer.observation, Some(position));
                    }
                }
            }
            let Some(patch) = &finding.patch else { continue };
            let after = answers(&patched(&analyzed, &patch.edits));
            prop_assert_eq!(before.len(), after.len());
            for (old, new) in before.iter().zip(&after) {
                if about_routes && !old.realistic {
                    continue;
                }
                match patch.access_effect {
                    AccessEffect::Equivalent => prop_assert_eq!(
                        old.forwards, new.forwards,
                        "{}: equivalent patch changed {:?}", finding.code.as_str(), old.lane
                    ),
                    AccessEffect::Narrowing => prop_assert!(
                        old.forwards || !new.forwards,
                        "{}: narrowing patch forwarded a blocked request in {:?}", finding.code.as_str(), old.lane
                    ),
                    AccessEffect::Expanding | AccessEffect::Unknown => {}
                }
            }
        }
    }
}

fn rate_strategy() -> impl Strategy<Value = Value> {
    (
        prop_oneof![
            Just(json!({})),
            Just(json!({ "roles": ["r1"] })),
            Just(json!({ "roles": ["r1", "r2"] }))
        ],
        prop_oneof![
            Just(json!([])),
            Just(json!(["GET"])),
            Just(json!(["GET", "POST"]))
        ],
        prop_oneof![
            Just(None),
            Just(Some("/**")),
            Just(Some("/a/**")),
            Just(Some("/a/*")),
            Just(Some("/b"))
        ],
        prop_oneof![Just(1.0), Just(2.0)],
        prop_oneof![Just(1u32), Just(2u32)],
    )
        .prop_map(|(principal, methods, path, rps, burst)| {
            let mut limit = json!({
                "principal": principal, "methods": methods,
                "requests_per_second": rps, "burst": burst
            });
            if let (Some(path), Some(limit)) = (path, limit.as_object_mut()) {
                limit.insert("path".to_owned(), json!(path));
            }
            limit
        })
}

/// The selected override's position and limits for every authenticated
/// caller, method and path of the universe.
fn rate_answers(policy: &Policy) -> Vec<Option<(usize, f64, u32)>> {
    let compiled = CompiledPolicy::for_analysis(policy.clone());
    let mut answers = Vec::new();
    for path in http_paths() {
        for method in [Method::GET, Method::POST, Method::PUT] {
            for principal in universe_principals().into_iter().skip(1) {
                let selection = compiled
                    .select_rate_lane(&PolicyEvaluationContext {
                        version: CONTEXT_VERSION,
                        snapshot: compiled.snapshot(),
                        method: Some(method.clone()),
                        path: Some(path.clone()),
                        principal,
                        target: HttpTarget::Missing,
                        request_host: HostFact::Missing,
                        dispatch: None,
                    })
                    .expect("the universe is well formed");
                answers.push(selection.matched().map(|index| {
                    let limit = &policy.rate_limits[index];
                    (index, limit.requests_per_second, limit.burst)
                }));
            }
        }
    }
    answers
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn proven_rate_claims_and_patch_effects_hold_against_the_evaluator(
        limits in prop::collection::vec(rate_strategy(), 1..5),
    ) {
        let analyzed = rate_policy(json!(limits));
        let outcome = run(&analyzed);
        let before = rate_answers(&analyzed);
        for finding in outcome.findings.iter().filter(|finding| {
            finding.proof_basis == ProofBasis::Proven && finding.element.section == super::Section::RateLimits
        }) {
            let position = finding.element.position.expect("a rate override has a position");
            prop_assert!(before.iter().all(|answer| answer.map(|(index, _, _)| index) != Some(position)));
            let Some(patch) = &finding.patch else { continue };
            let after = rate_answers(&patched(&analyzed, &patch.edits));
            for (old, new) in before.iter().zip(&after) {
                let limits = |answer: &Option<(usize, f64, u32)>| answer.map(|(_, rps, burst)| (rps, burst));
                match patch.access_effect {
                    AccessEffect::Equivalent => prop_assert_eq!(limits(old), limits(new)),
                    AccessEffect::Narrowing => match (limits(old), limits(new)) {
                        (Some((old_rps, old_burst)), Some((new_rps, new_burst))) => {
                            prop_assert!(new_rps <= old_rps && new_burst <= old_burst);
                        }
                        (old, new) => prop_assert_eq!(old, new),
                    },
                    AccessEffect::Expanding | AccessEffect::Unknown => {}
                }
            }
        }
    }
}
