//! One test per finding class, the analyzer's bounds and renderings, and
//! brute-force checks of every proven claim and patch against the canonical
//! evaluator over small policy universes.

use std::{
    collections::{BTreeSet, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use http::Method;
use ipnet::IpNet;
use proptest::prelude::*;
use serde_json::{json, Value};
use url::Url;

use super::{
    checks::{analyze, AnalysisResources},
    coverage::{pattern_covers, pattern_intersection, segments},
    report::{to_json, to_sarif, AnalysisBinding},
    request::{parse_request, AnalysisFormat},
    AccessEffect, AnalysisLimitation, AnalysisOutcome, Finding, FindingCode, Lane, ProofBasis,
    Section, Severity, MAX_FINDINGS,
};
use crate::{
    auth::{AuthMethod, Principal},
    middleware::rate_limit::{GlobalRateLanes, LaneLimit},
    policy_eval::{
        analysis::DirectRuleOutcome,
        egress::{
            CompiledEgressPolicy, EgressControls, EgressDestination, EgressEvaluationContext,
            EgressOutcome, ResolutionFact, EGRESS_CONTEXT_VERSION,
        },
        tools::{
            SourceRequestContext, SourceRequestDecision, ToolEvaluationContext, ToolOperation,
            ToolReason, TOOL_CONTEXT_VERSION,
        },
        CompiledPolicy, DispatchFacts, HostFact, HttpTarget, PolicyEffect, PolicyEvaluationContext,
        PrincipalFact, PrincipalIdentity, RuleReference, CONTEXT_VERSION,
    },
    policy_simulation::{
        edits::{apply_edits, parse_edits},
        request::StoredCandidate,
    },
    policy_testing::suite::Diagnostics,
    rbac::{
        matcher::path_pattern_matches,
        policy_document::parse_v1_with_typed_matchers,
        policy_resources::{AdminSurface, ConnectionInventory, PolicyResourceView, ToolInventory},
        Policy, RuleAction,
    },
};

fn policy(value: Value) -> Policy {
    Policy::validate_json_value(value).expect("test policy validates")
}

/// A policy v1 document with typed matchers, which this build validates but
/// does not yet accept for enforcement: parsed as the typed-matcher tests
/// parse one, so the analyzer's handling of them is pinned before they are.
fn typed_matcher_policy(value: Value) -> Policy {
    parse_v1_with_typed_matchers(&value).unwrap_or_else(|issues| panic!("validates: {issues:?}"))
}

fn far_deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

/// Global rate lanes no override in these tests exceeds unless it means to.
fn generous_rate_lanes() -> GlobalRateLanes {
    GlobalRateLanes::new(
        LaneLimit {
            requests_per_second: 100.0,
            burst: 200,
        },
        LaneLimit {
            requests_per_second: 100.0,
            burst: 200,
        },
    )
}

/// A complete resource view: a tool registry holding every tool `policy`
/// names, no Connections, and a static egress lane admitting nothing.
fn resource_view_for(policy: &Policy) -> PolicyResourceView {
    let mut names: BTreeSet<String> = policy.tools.keys().cloned().collect();
    names.extend(
        policy
            .rules
            .iter()
            .filter_map(|rule| rule.tool_name.clone()),
    );
    PolicyResourceView {
        configuration: Some("sha256:configuration".to_owned()),
        egress: Some(Arc::new(CompiledEgressPolicy::new(EgressControls {
            allowed_hosts: HashSet::new(),
            allowed_host_globs: Vec::new(),
            allowed_ports: HashSet::new(),
            deny_private_ips: true,
            nat64_prefixes: Vec::new(),
            private_ip_allow_cidrs: Vec::new(),
        }))),
        tools: Some(ToolInventory {
            names,
            digest: "sha256:tools".to_owned(),
        }),
        connections: Some(ConnectionInventory {
            etag: "\"connections\"".to_owned(),
            endpoints: Vec::new(),
        }),
        admin: Some(AdminSurface {
            policy_route: "/v1/admin/policy".to_owned(),
            policy_route_exempt: false,
        }),
        security_revision: None,
    }
}

/// The resources an analysis reads, all present: `policy` is its own
/// active policy, so nothing is a change from it.
struct Resources<'a> {
    aliases: &'a [String],
    active: Option<&'a Policy>,
    lanes: Option<GlobalRateLanes>,
    view: Option<PolicyResourceView>,
}

impl<'a> Resources<'a> {
    fn new(aliases: &'a [String]) -> Self {
        Self {
            aliases,
            active: None,
            lanes: Some(generous_rate_lanes()),
            view: None,
        }
    }

    fn run(&self, policy: &Policy, deadline: Instant) -> AnalysisOutcome {
        let view = self
            .view
            .clone()
            .unwrap_or_else(|| resource_view_for(policy));
        analyze(
            policy,
            &AnalysisResources {
                mcp_alias_paths: self.aliases,
                active: self.active.unwrap_or(policy),
                global_rate_lanes: self.lanes,
                resource_view: &view,
            },
            deadline,
        )
        .expect("analysis succeeds")
    }
}

fn run_with(policy: &Policy, aliases: &[String], deadline: Instant) -> AnalysisOutcome {
    Resources::new(aliases).run(policy, deadline)
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
fn constrained_scoped_or_narrower_allows_are_not_broad_for_every_caller() {
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
                .any(|code| code.starts_with("broad_unconstrained_")),
            "{rule}: {:?}",
            codes(&outcome)
        );
    }
}

#[test]
fn an_allow_on_every_path_for_named_callers_is_a_broad_path_grant() {
    let outcome = run(&policy(base(
        json!([{ "methods": ["GET"], "path": "/**", "action": "allow", "principal": { "roles": ["reader"] } }]),
        json!([]),
    )));
    let finding = only(&outcome, FindingCode::BroadPathGrant);
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.proof_basis, ProofBasis::Proven);
    assert_eq!(finding.details["action"], json!("allow"));
    assert_eq!(finding.details["all_methods"], json!(false));
    assert!(finding.patch.is_none());
    // Scoped to a dispatch, narrower than every path, or a deny: not broad.
    for rule in [
        json!({ "path": "/**", "action": "allow", "principal": { "roles": ["reader"] }, "dispatch": { "kind": "contextless" } }),
        json!({ "path": "/api/**", "action": "allow", "principal": { "roles": ["reader"] } }),
        json!({ "path": "/**", "action": "deny", "principal": { "roles": ["reader"] } }),
    ] {
        let outcome = run(&policy(base(json!([rule]), json!([]))));
        assert!(
            !codes(&outcome).contains(&"broad_path_grant"),
            "{rule}: {:?}",
            codes(&outcome)
        );
    }
}

#[test]
fn an_allow_for_every_caller_and_every_method_is_an_all_methods_grant() {
    let outcome = run(&policy(base(
        json!([
            { "path": "/public/**", "action": "allow" },
            { "methods": ["GET"], "path": "/docs/**", "action": "allow" },
            { "path": "/team/**", "action": "allow", "principal": { "roles": ["reader"] } }
        ]),
        json!([]),
    )));
    let finding = only(&outcome, FindingCode::AllMethodsGrant);
    assert_eq!(finding.element.position, Some(0));
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.proof_basis, ProofBasis::Proven);
    // Every path too is broad_unconstrained_allow's, not this.
    let outcome = run(&policy(base(
        json!([{ "path": "/**", "action": "allow" }]),
        json!([]),
    )));
    assert_eq!(
        codes(&outcome),
        ["broad_unconstrained_allow"],
        "{:?}",
        codes(&outcome)
    );
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
fn rules_an_earlier_rule_does_not_fully_cover_are_not_reported_as_covered() {
    for (earlier, later, partial) in [
        // Narrower caller.
        (
            json!({ "path": "/api/**", "action": "allow", "principal": { "roles": ["reader"] } }),
            json!({ "path": "/api/admin", "action": "deny" }),
            true,
        ),
        // Narrower methods.
        (
            json!({ "methods": ["GET"], "path": "/api/**", "action": "allow" }),
            json!({ "path": "/api/admin", "action": "deny" }),
            true,
        ),
        // Narrower path: a single wildcard never matches an empty segment.
        (
            json!({ "path": "/api/*", "action": "allow" }),
            json!({ "path": "/api/**", "action": "deny" }),
            true,
        ),
        // A dispatch-bound rule does not cover an unbound one.
        (
            json!({ "path": "/**", "action": "deny", "dispatch": { "kind": "contextless" } }),
            json!({ "path": "/api", "action": "deny" }),
            false,
        ),
        // A disabled rule covers nothing.
        (
            json!({ "path": "/**", "action": "deny", "enabled": false }),
            json!({ "path": "/api", "action": "deny" }),
            false,
        ),
        // A tool-name rule never covers an HTTP rule.
        (
            json!({ "tool_name": "echo", "action": "deny" }),
            json!({ "path": "/api", "action": "deny" }),
            false,
        ),
    ] {
        let outcome = run(&policy(base(json!([earlier, later]), json!([]))));
        let codes = codes(&outcome);
        assert!(
            !codes.contains(&"rule_unreachable") && !codes.contains(&"rule_shadowed"),
            "{earlier} / {later}: {codes:?}",
        );
        // A less restrictive earlier rule that decides part of what the
        // later one matches is a partial overlap, and nothing else is.
        assert_eq!(
            codes.contains(&"rule_partially_shadowed"),
            partial,
            "{earlier} / {later}: {codes:?}",
        );
    }
}

#[test]
fn a_deny_an_earlier_allow_pre_empts_in_part_is_partially_shadowed() {
    let mut document = base(
        json!([
            { "id": "readers", "path": "/api/**", "action": "allow", "principal": { "roles": ["reader"] } },
            { "id": "admin-deny", "path": "/api/admin/**", "action": "deny" }
        ]),
        json!([]),
    );
    document["schema_version"] = json!("1.0.0");
    let outcome = run(&policy(document));
    let finding = only(&outcome, FindingCode::RulePartiallyShadowed);
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.proof_basis, ProofBasis::Proven);
    assert_eq!(finding.element.position, Some(1));
    assert_eq!(
        finding
            .related
            .as_ref()
            .and_then(|related| related.id.as_deref()),
        Some("readers")
    );
    assert_eq!(finding.details["action"], json!("deny"));
    assert_eq!(finding.details["preempting_action"], json!("allow"));
    assert_eq!(
        finding.details["pre_empted_in"],
        json!(["http", "rendered_tool_http"])
    );
    assert!(finding.never_decides_in.is_empty());
    assert!(finding.patch.is_none());

    // A deny before the allow, or a later rule no more restrictive than
    // the earlier one, is the ordinary exception pattern: not reported.
    for rules in [
        json!([
            { "path": "/api/admin/**", "action": "deny" },
            { "path": "/api/**", "action": "allow", "principal": { "roles": ["reader"] } }
        ]),
        json!([
            { "path": "/api/**", "action": "deny", "principal": { "roles": ["reader"] } },
            { "path": "/api/admin/**", "action": "allow" }
        ]),
        json!([
            { "path": "/api/**", "action": "allow", "principal": { "roles": ["reader"] } },
            { "path": "/other/**", "action": "deny" }
        ]),
    ] {
        let outcome = run(&policy(base(rules.clone(), json!([]))));
        assert!(
            !codes(&outcome).contains(&"rule_partially_shadowed"),
            "{rules}: {:?}",
            codes(&outcome)
        );
    }
}

#[test]
fn a_partial_overlap_the_evaluator_does_not_confirm_is_inconclusive() {
    // The only path both patterns match has an empty interior segment,
    // which the evaluator refuses: the overlap is not confirmed.
    let outcome = run(&policy(base(
        json!([
            { "path": "/a//*", "action": "allow", "principal": { "roles": ["reader"] } },
            { "path": "/a//b", "action": "deny" }
        ]),
        json!([]),
    )));
    let finding = only(&outcome, FindingCode::RulePartiallyShadowed);
    assert_eq!(finding.proof_basis, ProofBasis::Inconclusive);
    assert_eq!(finding.limitations, ["witness_unconfirmed"]);
}

#[test]
fn pattern_intersections_are_built_by_alignment() {
    let meet = |left: &str, right: &str| {
        pattern_intersection(&segments(left), &segments(right), "w")
            .map(|segments| format!("/{}", segments.join("/")))
    };
    assert_eq!(meet("/a/**", "/*/b").as_deref(), Some("/a/b"));
    assert_eq!(meet("/**", "/a/{id}").as_deref(), Some("/a/w"));
    assert_eq!(meet("/a/**", "/**").as_deref(), Some("/a"));
    assert_eq!(meet("/a/*", "/b/*"), None);
    assert_eq!(meet("/a/*", "/a"), None);
    assert_eq!(meet("relative", "/**"), None);
}

#[test]
fn a_rule_with_conditions_covers_nothing_and_is_never_broad() {
    let document = json!({
        "schema_version": "1.0.0",
        "default_action": "deny",
        "rules": [
            {
                "id": "canary-everything", "path": "/**", "action": "allow",
                "conditions": { "header": { "name": "x-environment", "in": ["canary"] } }
            },
            { "id": "admin-deny", "path": "/admin/**", "action": "deny" },
            {
                "id": "admin-deny-canary", "path": "/admin/x", "action": "deny",
                "conditions": { "query": { "name": "mode", "in": ["export"] } }
            }
        ],
    });
    let outcome = run(&typed_matcher_policy(document));
    // The conditioned allow is not broad and covers neither later rule; the
    // conditioned deny is still covered by the unconditioned one before it.
    assert_eq!(
        codes(&outcome),
        ["rule_unreachable"],
        "{:?}",
        codes(&outcome)
    );
    let finding = only(&outcome, FindingCode::RuleUnreachable);
    assert_eq!(finding.element.id.as_deref(), Some("admin-deny-canary"));
    assert_eq!(finding.details["relation"], json!("covered"));
}

#[test]
fn in_mapped_role_mode_a_claim_needing_a_role_holder_is_inconclusive() {
    // With identity mappings, a caller's claimed roles are not its roles, and
    // the analyzer does not synthesize a caller the mappings grant one: the
    // evaluator cannot confirm the claim, so it is not reported as proven.
    let document = json!({
        "schema_version": "1.0.0",
        "default_action": "deny",
        "roles": { "reader": { "permissions": ["api:read"] } },
        "identity_mappings": [
            { "id": "readers", "issuer": "https://idp.example.test", "claimed_roles": ["reader"], "grant_roles": ["reader"] }
        ],
        "rules": [
            { "id": "api-allow", "path": "/api/**", "action": "allow" },
            { "id": "reader-deny", "path": "/api/admin", "action": "deny", "principal": { "roles": ["reader"] } },
            { "id": "anyone-deny", "path": "/api/other", "action": "deny" }
        ],
    });
    let outcome = run(&typed_matcher_policy(document));
    let by_id = |id: &str| {
        outcome
            .findings
            .iter()
            .find(|finding| finding.element.id.as_deref() == Some(id))
            .unwrap_or_else(|| panic!("a finding for {id}: {:?}", codes(&outcome)))
    };
    assert_eq!(by_id("reader-deny").proof_basis, ProofBasis::Inconclusive);
    assert!(by_id("reader-deny").patch.is_none());
    assert_eq!(by_id("anyone-deny").proof_basis, ProofBasis::Proven);
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

#[test]
fn a_rate_override_looser_than_its_global_lane_is_reported_by_lane() {
    let lanes = GlobalRateLanes::new(
        LaneLimit {
            requests_per_second: 10.0,
            burst: 20,
        },
        LaneLimit {
            requests_per_second: 5.0,
            burst: 10,
        },
    );
    let analyzed = rate_policy(json!([
        { "methods": ["get"], "path": "/reads/**", "requests_per_second": 50.0, "burst": 10 },
        { "methods": ["POST"], "path": "/writes/**", "requests_per_second": 1.0, "burst": 1 },
        { "requests_per_second": 6.0, "burst": 5 }
    ]));
    let mut resources = Resources::new(&[]);
    resources.lanes = Some(lanes);
    let outcome = resources.run(&analyzed, far_deadline());
    let looser: Vec<&Finding> = outcome
        .findings
        .iter()
        .filter(|finding| finding.code == FindingCode::RateOverrideLooserThanGlobal)
        .collect();
    assert_eq!(looser.len(), 2, "{:?}", codes(&outcome));
    assert_eq!(looser[0].element.position, Some(0));
    assert_eq!(looser[0].details["lanes"], json!(["read"]));
    assert_eq!(looser[0].details["requests_per_second_higher"], json!(true));
    assert_eq!(looser[0].details["burst_higher"], json!(false));
    assert_eq!(looser[1].element.position, Some(2));
    assert_eq!(looser[1].details["lanes"], json!(["write"]));
    for finding in looser {
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.proof_basis, ProofBasis::Proven);
        assert!(finding.patch.is_none());
    }
    assert!(outcome.complete);

    // Without the global lanes the check cannot run, and says so; a policy
    // without overrides does not need them.
    resources.lanes = None;
    let outcome = resources.run(&analyzed, far_deadline());
    assert!(!outcome.complete);
    assert_eq!(
        outcome.limitations,
        [AnalysisLimitation::ResourcesUnavailable]
    );
    assert!(!codes(&outcome).contains(&"rate_override_looser_than_global"));
    assert!(
        resources
            .run(&rate_policy(json!([])), far_deadline())
            .complete
    );
}

// ---------------------------------------------------------------------------
// MCP alias and host-qualified lane effects
// ---------------------------------------------------------------------------

#[test]
fn an_allow_a_later_deny_overrides_for_mcp_aliases_is_reported() {
    let document = json!({
        "schema_version": "1.0.0",
        "default_action": "deny",
        "rules": [
            { "id": "mcp-allow", "methods": ["POST"], "path": "/mcp", "action": "allow" },
            { "id": "catch-all-deny", "path": "/**", "action": "deny" }
        ],
    });
    let aliases = ["/v1/mcp".to_owned()];
    let outcome = run_with(&policy(document.clone()), &aliases, far_deadline());
    let finding = only(&outcome, FindingCode::McpAliasRuleOverridden);
    assert_eq!(finding.severity, Severity::Low);
    assert_eq!(finding.proof_basis, ProofBasis::Proven);
    assert_eq!(finding.element.id.as_deref(), Some("mcp-allow"));
    assert_eq!(
        finding
            .related
            .as_ref()
            .and_then(|related| related.id.as_deref()),
        Some("catch-all-deny")
    );
    assert_eq!(finding.details["deciding_action"], json!("deny"));
    assert_eq!(finding.details["lane"], json!("mcp_alias"));
    assert!(finding.patch.is_none());

    // Without a configured alias there is no alias lane to report.
    let outcome = run(&policy(document));
    assert!(!codes(&outcome).contains(&"mcp_alias_rule_overridden"));
}

#[test]
fn an_alias_route_weaker_than_the_canonical_route_is_reported() {
    let document = base(
        json!([]),
        json!([
            { "path_prefix": "/mcp", "permission": "api:admin" },
            { "path_prefix": "/v1/mcp", "permission": "api:read" }
        ]),
    );
    let aliases = ["/v1/mcp".to_owned()];
    let outcome = run_with(&policy(document), &aliases, far_deadline());
    let finding = only(&outcome, FindingCode::McpAliasRoutePrecedence);
    assert_eq!(finding.severity, Severity::Medium);
    assert_eq!(finding.proof_basis, ProofBasis::Proven);
    assert_eq!(finding.element.pointer, "/routes/1");
    assert_eq!(
        finding
            .related
            .as_ref()
            .map(|related| related.pointer.as_str()),
        Some("/routes/0")
    );
    assert_eq!(finding.details["permission_differs"], json!(true));
    assert_eq!(finding.details["mode_differs"], json!(false));

    // An alias route at least as strict as the canonical one is not.
    let stricter = base(
        json!([]),
        json!([
            { "path_prefix": "/mcp", "permission": "api:read" },
            { "path_prefix": "/v1/mcp", "permission": "api:admin" }
        ]),
    );
    let outcome = run_with(&policy(stricter), &aliases, far_deadline());
    assert!(!codes(&outcome).contains(&"mcp_alias_route_precedence"));
}

#[test]
fn an_allow_a_selected_upstream_ignores_is_reported_with_the_host_route() {
    let mut document = base(
        json!([{ "id": "partners", "path": "/partner/**", "action": "allow", "principal": { "roles": ["reader"] } }]),
        json!([
            { "id": "partner-host", "path_prefix": "/partner", "hosts": ["partner.example.test"], "permission": "api:admin" }
        ]),
    );
    document["schema_version"] = json!("1.0.0");
    let outcome = run(&policy(document));
    let finding = only(&outcome, FindingCode::SelectedUpstreamAllowIgnored);
    assert_eq!(finding.severity, Severity::Low);
    assert_eq!(finding.proof_basis, ProofBasis::Proven);
    assert_eq!(finding.element.id.as_deref(), Some("partners"));
    assert_eq!(
        finding
            .related
            .as_ref()
            .and_then(|related| related.id.as_deref()),
        Some("partner-host")
    );
    assert_eq!(finding.details["lane"], json!("selected_upstream"));

    // A route the caller passes anyway, or no host-bound route, changes
    // nothing a selected upstream decides.
    for routes in [
        json!([{ "path_prefix": "/partner", "hosts": ["partner.example.test"], "permission": "api:read" }]),
        json!([{ "path_prefix": "/partner", "permission": "api:admin" }]),
    ] {
        let outcome = run(&policy(base(
            json!([{ "path": "/partner/**", "action": "allow", "principal": { "roles": ["reader"] } }]),
            routes.clone(),
        )));
        assert!(
            !codes(&outcome).contains(&"selected_upstream_allow_ignored"),
            "{routes}: {:?}",
            codes(&outcome)
        );
    }
}

// ---------------------------------------------------------------------------
// Tool policy and grant lints
// ---------------------------------------------------------------------------

#[test]
fn a_tool_rule_its_tool_entry_refuses_every_caller_of_never_decides() {
    let mut document = base(
        json!([
            { "id": "echo-other-issuer", "tool_name": "echo", "action": "allow", "principal": { "issuers": ["https://other.example.test"] } },
            { "id": "off-deny", "tool_name": "off", "action": "deny" },
            { "id": "missing-deny", "tool_name": "missing", "action": "deny" },
            { "id": "cookie-only", "tool_name": "web", "action": "deny", "principal": { "auth_methods": ["bearer_token"] } },
            { "id": "echo-ok", "tool_name": "echo", "action": "deny", "principal": { "issuers": ["https://idp.example.test"] } }
        ]),
        json!([]),
    );
    document["schema_version"] = json!("1.0.0");
    document["tools"] = json!({
        "echo": { "issuers": ["https://idp.example.test"] },
        "off": { "enabled": false },
        "web": { "auth_methods": ["session_cookie"] }
    });
    let outcome = run(&policy(document));
    let never: Vec<&Finding> = outcome
        .findings
        .iter()
        .filter(|finding| finding.code == FindingCode::ToolRuleNeverDecides)
        .collect();
    let reasons: Vec<(Option<&str>, &Value)> = never
        .iter()
        .map(|finding| (finding.element.id.as_deref(), &finding.details["reason"]))
        .collect();
    assert_eq!(
        reasons,
        [
            (Some("echo-other-issuer"), &json!("issuers_disjoint")),
            (Some("off-deny"), &json!("tool_disabled")),
            (Some("missing-deny"), &json!("tool_absent")),
            (Some("cookie-only"), &json!("auth_methods_disjoint")),
        ]
    );
    for finding in &never {
        assert_eq!(finding.proof_basis, ProofBasis::Proven);
        assert_eq!(lanes(&finding.never_decides_in), ["tool"]);
        assert_eq!(
            finding.patch.as_ref().map(|patch| patch.access_effect),
            Some(AccessEffect::Equivalent)
        );
    }
}

#[test]
fn a_tool_rule_naming_a_caller_its_entry_refuses_grants_less_than_it_names() {
    let mut document = base(
        json!([
            { "tool_name": "ops", "action": "allow", "principal": { "roles": ["reader"] } },
            { "tool_name": "ops", "action": "allow", "principal": { "roles": ["operator"] } }
        ]),
        json!([]),
    );
    document["roles"]["operator"] = json!({ "permissions": ["api:read"] });
    document["tools"] = json!({ "ops": { "allowed_roles": ["operator"] } });
    let outcome = run(&policy(document));
    let finding = only(&outcome, FindingCode::ToolRuleGrantNarrowed);
    assert_eq!(finding.element.position, Some(0));
    assert_eq!(finding.severity, Severity::Low);
    assert_eq!(finding.proof_basis, ProofBasis::Proven);
    assert!(!codes(&outcome).contains(&"tool_rule_never_decides"));
}

#[test]
fn a_grant_by_an_issuer_bound_role_without_its_issuers_is_reported() {
    let mut document = base(
        json!([
            { "id": "admin-pages", "path": "/admin/**", "action": "allow", "principal": { "roles": ["reader", "admin"] } },
            { "id": "bound", "path": "/admin/**", "action": "allow", "principal": { "roles": ["admin"], "issuers": ["https://idp.example.test"] } },
            { "id": "deny", "path": "/admin/x", "action": "deny", "principal": { "roles": ["admin"] } }
        ]),
        json!([]),
    );
    document["schema_version"] = json!("1.0.0");
    document["tools"] = json!({ "ops": { "allowed_roles": ["admin"] } });
    let outcome = run(&policy(document.clone()));
    let grants: Vec<&Finding> = outcome
        .findings
        .iter()
        .filter(|finding| finding.code == FindingCode::IssuerlessRoleGrant)
        .collect();
    assert_eq!(grants.len(), 2, "{:?}", codes(&outcome));
    let rule = grants
        .iter()
        .find(|finding| finding.element.section == Section::Rules)
        .expect("the rule grant");
    assert_eq!(rule.severity, Severity::High);
    assert_eq!(rule.proof_basis, ProofBasis::Proven);
    assert_eq!(rule.element.id.as_deref(), Some("admin-pages"));
    assert_eq!(rule.element.pointer, "/rules/0/principal/roles/1");
    assert_eq!(rule.details["lane"], json!("http"));
    let tool = grants
        .iter()
        .find(|finding| finding.element.section == Section::Tools)
        .expect("the tool grant");
    assert_eq!(tool.severity, Severity::Medium);
    assert_eq!(tool.element.pointer, "/tools/ops/allowed_roles/0");
    assert_eq!(tool.element.name.as_deref(), Some("ops"));

    // In mapped-role mode a caller holds only what its issuer's mappings
    // grant, so nothing is granted by a bare claim.
    document["identity_mappings"] = json!([
        { "id": "admins", "issuer": "https://idp.example.test", "claimed_roles": ["admin"], "grant_roles": ["admin"] }
    ]);
    let outcome = run(&typed_matcher_policy(document));
    assert!(!codes(&outcome).contains(&"issuerless_role_grant"));
}

#[test]
fn a_wildcard_grant_bound_to_an_issuer_is_still_a_wildcard_permission() {
    let mut document = base(json!([]), json!([]));
    document["roles"] = json!({
        "root": { "permissions": ["*"], "issuers": ["https://idp.example.test"] },
        "anyone": { "permissions": ["*"] }
    });
    let outcome = run(&policy(document));
    let finding = only(&outcome, FindingCode::WildcardPermission);
    assert_eq!(finding.element.name.as_deref(), Some("root"));
    assert_eq!(finding.element.pointer, "/roles/root/permissions/0");
    assert_eq!(finding.proof_basis, ProofBasis::Heuristic);
    assert_eq!(finding.severity, Severity::Low);
    assert_eq!(
        only(&outcome, FindingCode::WildcardGrantWithoutIssuer)
            .element
            .name
            .as_deref(),
        Some("anyone")
    );
}

// ---------------------------------------------------------------------------
// Egress lints
// ---------------------------------------------------------------------------

fn egress_findings(outcome: &AnalysisOutcome, code: FindingCode) -> Vec<(&str, &Finding)> {
    outcome
        .findings
        .iter()
        .filter(|finding| finding.code == code)
        .map(|finding| (finding.element.pointer.as_str(), finding))
        .collect()
}

#[test]
fn egress_wildcards_non_public_cidrs_and_unusual_ports_are_reported() {
    let mut document = base(json!([]), json!([]));
    document["egress"] = json!({
        "hosts": ["*.com", "*.example.test", "api.example.test"],
        "cidrs": ["169.254.169.254/32", "10.0.0.0/8", "10.1.2.0/24", "8.8.8.0/24", "127.0.0.0/8", "::/0"],
        "ports": [443, 22, 8443]
    });
    let outcome = run(&policy(document));
    let wildcards = egress_findings(&outcome, FindingCode::EgressBroadWildcardHost);
    assert_eq!(wildcards.len(), 1);
    assert_eq!(wildcards[0].0, "/egress/hosts/0");
    assert_eq!(wildcards[0].1.proof_basis, ProofBasis::Heuristic);

    let cidrs: Vec<(&str, Severity, Value, Value)> =
        egress_findings(&outcome, FindingCode::EgressNonPublicCidr)
            .into_iter()
            .map(|(pointer, finding)| {
                assert_eq!(finding.proof_basis, ProofBasis::Proven, "{pointer}");
                (
                    pointer,
                    finding.severity,
                    finding.details["categories"].clone(),
                    finding.details["covers_whole_range"].clone(),
                )
            })
            .collect();
    let expected = [
        (
            "/egress/cidrs/0",
            Severity::High,
            json!(["link_local"]),
            json!(false),
        ),
        (
            "/egress/cidrs/4",
            Severity::High,
            json!(["loopback"]),
            json!(false),
        ),
        (
            "/egress/cidrs/5",
            Severity::High,
            json!(["loopback", "link_local", "private"]),
            json!(true),
        ),
        (
            "/egress/cidrs/1",
            Severity::Medium,
            json!(["private"]),
            json!(true),
        ),
        (
            "/egress/cidrs/2",
            Severity::Low,
            json!(["private"]),
            json!(false),
        ),
    ];
    assert_eq!(cidrs.len(), expected.len(), "{cidrs:?}");
    for entry in expected {
        assert!(cidrs.contains(&entry), "{entry:?} in {cidrs:?}");
    }

    let ports = egress_findings(&outcome, FindingCode::EgressUnusualPort);
    assert_eq!(ports.len(), 1);
    assert_eq!(ports[0].0, "/egress/ports/1");
    // The report names list members by pointer, never their values.
    let text = to_json(&outcome, &binding("sha256:digest", "\"sha256:etag\""))
        .expect("renders")
        .to_string();
    for value in ["169.254", "10.0.0.0", "*.com", "\"22\""] {
        assert!(!text.contains(value), "{value} leaked into {text}");
    }
}

#[test]
fn an_egress_change_from_the_active_policy_needs_a_restart() {
    let active = policy(base(json!([]), json!([])));
    let mut document = base(json!([]), json!([]));
    document["egress"] = json!({ "hosts": ["api.example.test"] });
    let analyzed = policy(document);
    let mut resources = Resources::new(&[]);
    resources.active = Some(&active);
    let outcome = resources.run(&analyzed, far_deadline());
    let finding = only(&outcome, FindingCode::EgressChangeRequiresRestart);
    assert_eq!(finding.element.pointer, "/egress");
    assert_eq!(finding.proof_basis, ProofBasis::Proven);
    assert_eq!(finding.severity, Severity::Medium);
    // Analyzed as itself, nothing changed.
    assert!(!codes(&run(&analyzed)).contains(&"egress_change_requires_restart"));
}

// ---------------------------------------------------------------------------
// Cross-resource references and lockout
// ---------------------------------------------------------------------------

#[test]
fn unknown_references_and_case_collisions_are_reported_as_heuristics() {
    let mut document = base(
        json!([{ "id": "ghosts", "path": "/x", "action": "deny", "principal": { "roles": ["reader", "ghost"] } }]),
        json!([{ "id": "nobody", "path_prefix": "/locked", "permission": "nobody:holds" }]),
    );
    document["schema_version"] = json!("1.0.0");
    document["roles"]["Reader"] = json!({ "permissions": ["api:read"] });
    document["tools"] = json!({ "unregistered": {} });
    let analyzed = policy(document);
    let mut view = resource_view_for(&analyzed);
    view.tools = Some(ToolInventory {
        names: BTreeSet::new(),
        digest: "sha256:tools".to_owned(),
    });
    view.connections = Some(ConnectionInventory {
        etag: "\"connections\"".to_owned(),
        endpoints: vec!["https://upstream.example.test".to_owned()],
    });
    let mut resources = Resources::new(&[]);
    resources.view = Some(view);
    let outcome = resources.run(&analyzed, far_deadline());
    let role = only(&outcome, FindingCode::RoleNotDefined);
    assert_eq!(role.element.pointer, "/rules/0/principal/roles/1");
    assert_eq!(role.element.id.as_deref(), Some("ghosts"));
    assert_eq!(role.element.member.as_deref(), Some("/principal/roles/1"));
    let route = only(&outcome, FindingCode::RoutePermissionUngranted);
    assert_eq!(route.element.pointer, "/routes/0/permission");
    assert_eq!(route.element.id.as_deref(), Some("nobody"));
    let tool = only(&outcome, FindingCode::ToolNotRegistered);
    assert_eq!(tool.element.pointer, "/tools/unregistered");
    assert_eq!(tool.element.name.as_deref(), Some("unregistered"));
    assert_eq!(
        only(&outcome, FindingCode::NameCaseCollision)
            .element
            .section,
        Section::Roles
    );
    assert_eq!(
        only(&outcome, FindingCode::ConnectionEndpointEgressDenied)
            .element
            .pointer,
        "/egress"
    );
    for code in [
        FindingCode::RoleNotDefined,
        FindingCode::RoutePermissionUngranted,
        FindingCode::ToolNotRegistered,
        FindingCode::NameCaseCollision,
        FindingCode::ConnectionEndpointEgressDenied,
    ] {
        assert_eq!(only(&outcome, code).proof_basis, ProofBasis::Heuristic);
    }
    assert!(outcome.complete);
}

#[test]
fn losing_every_policy_writer_is_a_likely_lockout() {
    let mut active = base(json!([]), json!([]));
    active["roles"]["policy-admin"] = json!({ "permissions": ["admin:policy:write"] });
    let active = policy(active);
    let analyzed = policy(base(json!([]), json!([])));
    let mut resources = Resources::new(&[]);
    resources.active = Some(&active);
    let outcome = resources.run(&analyzed, far_deadline());
    let finding = only(&outcome, FindingCode::PolicyWriteUnreachable);
    assert_eq!(finding.severity, Severity::High);
    assert_eq!(finding.proof_basis, ProofBasis::Heuristic);
    assert_eq!(finding.element.pointer, "/roles");
    // The active policy analyzed as itself loses nothing.
    assert!(!codes(&resources.run(&active, far_deadline())).contains(&"policy_write_unreachable"));
}

#[test]
fn a_resource_view_that_was_not_read_makes_the_analysis_incomplete() {
    let analyzed = policy(base(json!([]), json!([])));
    let mut resources = Resources::new(&[]);
    resources.view = Some(PolicyResourceView::default());
    let outcome = resources.run(&analyzed, far_deadline());
    assert!(!outcome.complete);
    assert_eq!(
        outcome.limitations,
        [AnalysisLimitation::ResourcesUnavailable]
    );
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
fn a_passed_deadline_also_stops_the_linear_checks_that_ask_the_evaluator() {
    let mut document = base(
        json!([
            { "path": "/**", "action": "allow" },
            { "tool_name": "missing", "action": "deny" }
        ]),
        json!([]),
    );
    document["egress"] = json!({ "cidrs": ["127.0.0.0/8"] });
    let outcome = run_with(&policy(document), &[], Instant::now());
    assert!(!outcome.complete);
    assert_eq!(outcome.limitations, [AnalysisLimitation::DeadlineExceeded]);
    // No witness was asked for, so nothing that needs one is reported.
    assert!(outcome.findings.is_empty(), "{:?}", codes(&outcome));
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
        stored: None,
        mcp_alias_paths: 0,
    }
}

/// A stored candidate is named in both renderings by its identifiers, and
/// only there: a draft by id and revision, a history version by number.
#[test]
fn both_renderings_name_the_stored_candidate_they_analyzed() {
    let outcome = run(&policy(base(
        json!([
            { "path": "/api/**", "action": "allow" },
            { "path": "/api/admin", "action": "deny" }
        ]),
        json!([]),
    )));
    let draft = StoredCandidate::Draft {
        draft_id: "pd_0123456789abcdef0123456789abcdef".to_owned(),
        revision: 3,
    };
    let mut drafted = binding("sha256:digest", "\"sha256:etag\"");
    drafted.source = "draft";
    drafted.stored = Some(&draft);
    let json = to_json(&outcome, &drafted).expect("renders");
    assert_eq!(
        json["analyzed"],
        json!({
            "source": "draft",
            "etag": "\"sha256:etag\"",
            "draft_id": "pd_0123456789abcdef0123456789abcdef",
            "draft_revision": 3
        })
    );
    let sarif = to_sarif(&outcome, &drafted).expect("renders");
    let properties = &sarif["runs"][0]["properties"];
    assert_eq!(properties["analyzed_source"], json!("draft"));
    assert_eq!(
        properties["analyzed_draft_id"],
        json!("pd_0123456789abcdef0123456789abcdef")
    );
    assert_eq!(properties["analyzed_draft_revision"], json!(3));

    let revision = StoredCandidate::Revision { version: 7 };
    let mut revised = binding("sha256:digest", "\"sha256:etag\"");
    revised.source = "revision";
    revised.stored = Some(&revision);
    let json = to_json(&outcome, &revised).expect("renders");
    assert_eq!(
        json["analyzed"],
        json!({ "source": "revision", "etag": "\"sha256:etag\"", "version": 7 })
    );
    let sarif = to_sarif(&outcome, &revised).expect("renders");
    assert_eq!(sarif["runs"][0]["properties"]["analyzed_version"], json!(7));
    assert!(sarif["runs"][0]["properties"]
        .get("analyzed_draft_id")
        .is_none());

    // A candidate the request carried has no stored identity to name.
    let json = to_json(&outcome, &binding("sha256:digest", "\"sha256:etag\"")).expect("renders");
    assert_eq!(
        json["analyzed"],
        json!({ "source": "active", "etag": "\"sha256:etag\"" })
    );
}

#[test]
fn the_json_report_is_deterministic_and_names_no_policy_value() {
    let document = base(
        json!([
            { "path": "/secret-area/**", "action": "allow", "principal": { "auth_methods": ["bearer_token"] } },
            { "path": "/secret-area/vault", "action": "deny", "principal": { "roles": ["reader"], "auth_methods": ["bearer_token"] } }
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

fn results_schema() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/schemas/policy-analysis-results.v1.schema.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

fn schema_enum(schema: &Value, name: &str) -> Vec<String> {
    schema["$defs"][name]["enum"]
        .as_array()
        .unwrap_or_else(|| panic!("$defs/{name} is an enum"))
        .iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect()
}

/// The published result schema closes the vocabularies the analyzer
/// renders -- codes in SARIF rule order, limitations, lanes and sections --
/// and admits a rendered report that exercises most of them.
#[test]
fn the_published_result_schema_names_every_code_and_admits_a_rendered_report() {
    let schema = results_schema();
    let codes_in_order: Vec<String> = FindingCode::ALL
        .iter()
        .map(|code| code.as_str().to_owned())
        .collect();
    assert_eq!(schema_enum(&schema, "code"), codes_in_order);
    assert_eq!(
        schema_enum(&schema, "limitation"),
        [
            AnalysisLimitation::ComparisonBudgetExhausted,
            AnalysisLimitation::DeadlineExceeded,
            AnalysisLimitation::FindingsTruncated,
            AnalysisLimitation::ResourcesUnavailable,
        ]
        .map(|limitation| limitation.as_str())
    );
    assert_eq!(
        schema_enum(&schema, "lane"),
        [
            Lane::Http,
            Lane::McpAlias,
            Lane::SelectedUpstream,
            Lane::RenderedToolHttp,
            Lane::SourceRequest,
            Lane::Tool,
            Lane::Rate,
        ]
        .map(|lane| lane.as_str())
    );
    assert_eq!(
        schema_enum(&schema, "section"),
        [
            Section::DefaultAction,
            Section::EnforcementMode,
            Section::Roles,
            Section::Rules,
            Section::Routes,
            Section::RateLimits,
            Section::Tools,
            Section::Egress,
            Section::IdentityMappings,
        ]
        .map(|section| section.as_str())
    );

    let mut document = base(
        json!([
            { "path": "/api/**", "action": "allow", "principal": { "roles": ["reader"] } },
            { "path": "/api/admin/**", "action": "deny" },
            { "path": "/public/**", "action": "allow" },
            { "path": "/a//*", "action": "allow", "principal": { "roles": ["reader"] } },
            { "path": "/a//b", "action": "deny" },
            { "path": "/admin/**", "action": "allow", "principal": { "roles": ["admin"] } },
            { "tool_name": "missing", "action": "deny" }
        ]),
        json!([{ "path_prefix": "/locked", "permission": "nobody:holds" }]),
    );
    document["default_action"] = json!("allow");
    document["egress"] = json!({ "hosts": ["*.com"], "cidrs": ["127.0.0.0/8"], "ports": [22] });
    let outcome = run(&policy(document));
    let digest = format!("sha256:{}", "0".repeat(64));
    let report = to_json(&outcome, &binding(&digest, "\"sha256:etag\"")).expect("renders");
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let errors: Vec<String> = validator
        .iter_errors(&report)
        .map(|error| format!("{} at {}", error, error.instance_path()))
        .collect();
    assert!(errors.is_empty(), "{errors:?}");
    let rendered: BTreeSet<&str> = codes(&outcome).into_iter().collect();
    for code in [
        "default_allow",
        "rule_partially_shadowed",
        "all_methods_grant",
        "issuerless_role_grant",
        "tool_rule_never_decides",
        "egress_broad_wildcard_host",
        "egress_non_public_cidr",
        "egress_unusual_port",
        "route_permission_ungranted",
    ] {
        assert!(rendered.contains(code), "{code} in {rendered:?}");
    }
    assert!(outcome
        .findings
        .iter()
        .any(|finding| finding.proof_basis == ProofBasis::Inconclusive));
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

/// The universe's authenticated callers: every role set over the two
/// roles, from no issuer, the issuer `r2` is bound to, and another.
fn universe_identities() -> Vec<Principal> {
    let mut identities = Vec::new();
    for roles in [&[][..], &["r1"][..], &["r2"][..], &["r1", "r2"][..]] {
        for issuer in [None, Some("i1"), Some("i2")] {
            identities.push(Principal {
                user_id: "u1".to_owned(),
                issuer: issuer.map(str::to_owned),
                email: None,
                org_id: None,
                roles: roles.iter().map(|role| (*role).to_owned()).collect(),
                session_id: String::new(),
                auth_method: AuthMethod::Bearer,
            });
        }
    }
    identities
}

fn universe_principals() -> Vec<PrincipalFact> {
    std::iter::once(PrincipalFact::Anonymous)
        .chain(universe_identities().iter().map(|principal| {
            PrincipalFact::Authenticated(PrincipalIdentity::from_principal(principal))
        }))
        .collect()
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
            Just(json!({ "roles": ["r1"], "issuers": ["i1"] })),
            Just(json!({ "issuers": ["i2"] })),
            Just(json!({ "roles": ["r2"], "auth_methods": ["bearer_token"] }))
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

/// The tool entries: each admits every caller, a role, an issuer or an
/// authentication method no universe caller has, or is disabled.
fn tools_strategy() -> impl Strategy<Value = Value> {
    (
        prop_oneof![
            2 => Just(json!({})),
            1 => Just(json!({ "enabled": false })),
            1 => Just(json!({ "issuers": ["i1"] }))
        ],
        prop_oneof![
            2 => Just(json!({ "allowed_roles": ["r1"] })),
            1 => Just(json!({ "allowed_roles": ["r2"] })),
            1 => Just(json!({ "auth_methods": ["session_cookie"] }))
        ],
    )
        .prop_map(|(t1, t2)| json!({ "t1": t1, "t2": t2 }))
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
        tools_strategy(),
    )
        .prop_map(|(rules, routes, default_action, mode, r1, tools)| {
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
                "tools": tools,
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

// ---------------------------------------------------------------------------
// Brute force: proven overlap, lane-effect and grant claims
// ---------------------------------------------------------------------------

fn universe_methods() -> [Method; 3] {
    [Method::GET, Method::POST, Method::PUT]
}

fn restrictiveness(action: &RuleAction) -> u8 {
    match action {
        RuleAction::Allow => 0,
        RuleAction::Shadow => 1,
        RuleAction::Deny => 2,
    }
}

/// The rule at `position` compiled alone, under the policy's roles.
fn rule_alone(policy: &Policy, position: usize) -> CompiledPolicy {
    CompiledPolicy::for_analysis(Policy {
        rules: vec![policy.rules[position].clone()],
        routes: Vec::new(),
        rate_limits: Vec::new(),
        tools: std::collections::HashMap::new(),
        default_action: crate::rbac::DefaultAction::Deny,
        enforcement_mode: crate::rbac::EnforcementMode::Enforce,
        egress: crate::rbac::EgressPolicy::default(),
        id: None,
        ..policy.clone()
    })
}

fn question(
    compiled: &CompiledPolicy,
    method: &Method,
    path: &str,
    principal: &PrincipalFact,
    target: HttpTarget,
    request_host: HostFact,
    dispatch: Option<DispatchFacts>,
) -> PolicyEvaluationContext {
    PolicyEvaluationContext {
        version: CONTEXT_VERSION,
        snapshot: compiled.snapshot(),
        method: Some(method.clone()),
        path: Some(path.to_owned()),
        principal: principal.clone(),
        target,
        request_host,
        dispatch,
    }
}

fn first_direct(
    compiled: &CompiledPolicy,
    method: &Method,
    path: &str,
    principal: &PrincipalFact,
) -> Option<usize> {
    match compiled.match_direct_rules(&question(
        compiled,
        method,
        path,
        principal,
        HttpTarget::Contextless,
        HostFact::Absent,
        None,
    )) {
        Ok(DirectRuleOutcome::Matched { index }) => Some(index),
        _ => None,
    }
}

fn alias_target() -> HttpTarget {
    HttpTarget::McpAlias {
        canonical_path: "/mcp".to_owned(),
    }
}

fn tool_reason(
    compiled: &CompiledPolicy,
    tool_name: &str,
    principal: &PrincipalFact,
) -> ToolReason {
    compiled
        .evaluate_tool(&ToolEvaluationContext {
            version: TOOL_CONTEXT_VERSION,
            snapshot: compiled.snapshot(),
            operation: ToolOperation::Invocation,
            tool_name: Some(tool_name.to_owned()),
            principal: principal.clone(),
            method: None,
            path: None,
        })
        .expect("the universe is well formed")
        .reason()
}

fn refused_at_admission(reason: ToolReason) -> bool {
    matches!(
        reason,
        ToolReason::UnknownTool | ToolReason::Disabled | ToolReason::RoleNotAllowed
    )
}

/// An earlier, less restrictive rule decides a request the rule matches.
fn partially_shadowed_shown(policy: &Policy, compiled: &CompiledPolicy, position: usize) -> bool {
    let alone = rule_alone(policy, position);
    let action = &policy.rules[position].action;
    http_paths().iter().any(|path| {
        universe_methods().iter().any(|method| {
            universe_principals().iter().any(|principal| {
                first_direct(&alone, method, path, principal) == Some(0)
                    && first_direct(compiled, method, path, principal).is_some_and(|index| {
                        index < position
                            && restrictiveness(&policy.rules[index].action)
                                < restrictiveness(action)
                    })
            })
        })
    })
}

/// A later, more restrictive rule decides an alias request the rule alone
/// decides.
fn alias_override_shown(policy: &Policy, compiled: &CompiledPolicy, position: usize) -> bool {
    let alone = rule_alone(policy, position);
    let action = &policy.rules[position].action;
    ALIAS_PATHS.iter().any(|alias| {
        universe_methods().iter().any(|method| {
            universe_principals().iter().any(|principal| {
                let ask = |compiled: &CompiledPolicy| {
                    compiled
                        .evaluate(&question(
                            compiled,
                            method,
                            alias,
                            principal,
                            alias_target(),
                            HostFact::Absent,
                            None,
                        ))
                        .ok()
                        .and_then(|evaluation| evaluation.matched())
                };
                ask(&alone) == Some(RuleReference::Direct(0))
                    && matches!(ask(compiled), Some(RuleReference::Direct(index))
                        if index > position
                            && restrictiveness(&policy.rules[index].action) > restrictiveness(action))
            })
        })
    })
}

/// The route lane forwards an alias request by the alias route and blocks
/// the same caller's request to the canonical path by the canonical route.
fn alias_route_shown(policy: &Policy, route: usize, canonical: usize) -> bool {
    let routes_only = CompiledPolicy::for_analysis(Policy {
        rules: Vec::new(),
        ..policy.clone()
    });
    ALIAS_PATHS.iter().any(|alias| {
        universe_methods().iter().any(|method| {
            universe_principals().iter().any(|principal| {
                let ask = |path: &str, target: HttpTarget| {
                    routes_only
                        .evaluate(&question(
                            &routes_only,
                            method,
                            path,
                            principal,
                            target,
                            HostFact::Absent,
                            None,
                        ))
                        .expect("the universe is well formed")
                };
                let at_alias = ask(alias, alias_target());
                let at_canonical = ask("/mcp", HttpTarget::Contextless);
                at_alias.matched() == Some(RuleReference::Route(route))
                    && at_alias.effect() != PolicyEffect::Block
                    && at_canonical.matched() == Some(RuleReference::Route(canonical))
                    && at_canonical.effect() == PolicyEffect::Block
            })
        })
    })
}

/// A request the rule decides and forwards when addressed to the selected
/// host is blocked once that host's upstream is selected.
fn selected_upstream_shown(compiled: &CompiledPolicy, position: usize) -> bool {
    http_paths().iter().any(|path| {
        universe_methods().iter().any(|method| {
            universe_principals().iter().any(|principal| {
                let addressed = compiled
                    .evaluate(&question(
                        compiled,
                        method,
                        path,
                        principal,
                        HttpTarget::Contextless,
                        HostFact::Present(SELECTED_HOST.to_owned()),
                        None,
                    ))
                    .expect("the universe is well formed");
                let selected = compiled
                    .evaluate(&question(
                        compiled,
                        method,
                        path,
                        principal,
                        HttpTarget::ProxyDispatch,
                        HostFact::Absent,
                        Some(DispatchFacts {
                            route_id: Some("pooled".to_owned()),
                            route_host: Some(SELECTED_HOST.to_owned()),
                            route_path_prefix: None,
                            upstream_origin: "pool:pooled".to_owned(),
                        }),
                    ))
                    .expect("the universe is well formed");
                addressed.matched() == Some(RuleReference::Direct(position))
                    && addressed.effect() != PolicyEffect::Block
                    && selected.effect() == PolicyEffect::Block
            })
        })
    })
}

/// A caller the tool rule alone matches is refused by its tool's entry.
fn tool_grant_narrowed_shown(policy: &Policy, compiled: &CompiledPolicy, position: usize) -> bool {
    let alone = rule_alone(policy, position);
    let Some(tool_name) = policy.rules[position].tool_name.as_deref() else {
        return false;
    };
    universe_principals().iter().any(|principal| {
        alone.match_tool_rules(tool_name, principal) == Ok(DirectRuleOutcome::Matched { index: 0 })
            && refused_at_admission(tool_reason(compiled, tool_name, principal))
    })
}

/// A caller claiming one of `roles` from an issuer the role is not bound to
/// is admitted by `admits`.
fn issuerless_shown(
    policy: &Policy,
    compiled: &CompiledPolicy,
    roles: &[String],
    admits: impl Fn(&PrincipalFact) -> bool,
) -> bool {
    universe_identities().iter().any(|identity| {
        let inactive_bound_role = roles.iter().any(|role| {
            identity.roles.contains(role)
                && policy
                    .roles
                    .get(role)
                    .is_some_and(|entry| !entry.issuers.is_empty())
                && !compiled.engine().principal_has_active_role(identity, role)
        });
        inactive_bound_role
            && admits(&PrincipalFact::Authenticated(
                PrincipalIdentity::from_principal(identity),
            ))
    })
}

/// The rule alone matches every universe path for some caller and method.
fn broad_path_shown(policy: &Policy, position: usize) -> bool {
    let alone = rule_alone(policy, position);
    universe_principals().iter().any(|principal| {
        universe_methods().iter().any(|method| {
            http_paths()
                .iter()
                .all(|path| first_direct(&alone, method, path, principal) == Some(0))
        })
    })
}

/// The rule alone matches every universe method, and `DELETE`, for an
/// anonymous caller on some path.
fn all_methods_shown(policy: &Policy, position: usize) -> bool {
    let alone = rule_alone(policy, position);
    http_paths().iter().any(|path| {
        universe_methods()
            .iter()
            .chain([&Method::DELETE])
            .all(|method| first_direct(&alone, method, path, &PrincipalFact::Anonymous) == Some(0))
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Every proven overlap, MCP alias, selected-upstream, tool-entry and
    /// grant claim is shown by a request of the universe, asked of the
    /// evaluator directly: the claims are existential, and the universe
    /// holds the witness the analyzer built.
    #[test]
    fn proven_overlap_lane_and_grant_claims_have_a_witness_in_the_universe(document in policy_strategy()) {
        let analyzed = policy(document);
        let outcome = run_with(&analyzed, &alias_paths(), far_deadline());
        prop_assert!(outcome.complete);
        let compiled = CompiledPolicy::for_analysis(analyzed.clone());
        for finding in outcome.findings.iter().filter(|finding| finding.proof_basis == ProofBasis::Proven) {
            let position = finding.element.position;
            let related = finding.related.as_ref().and_then(|related| related.position);
            let shown = match (finding.code, finding.element.section, position) {
                (FindingCode::RulePartiallyShadowed, _, Some(position)) => {
                    partially_shadowed_shown(&analyzed, &compiled, position)
                }
                (FindingCode::McpAliasRuleOverridden, _, Some(position)) => {
                    alias_override_shown(&analyzed, &compiled, position)
                }
                (FindingCode::McpAliasRoutePrecedence, _, Some(position)) => {
                    related.is_some_and(|canonical| alias_route_shown(&analyzed, position, canonical))
                }
                (FindingCode::SelectedUpstreamAllowIgnored, _, Some(position)) => {
                    selected_upstream_shown(&compiled, position)
                }
                (FindingCode::ToolRuleGrantNarrowed, _, Some(position)) => {
                    tool_grant_narrowed_shown(&analyzed, &compiled, position)
                }
                (FindingCode::IssuerlessRoleGrant, Section::Rules, Some(position)) => {
                    let rule = &analyzed.rules[position];
                    let alone = rule_alone(&analyzed, position);
                    issuerless_shown(&analyzed, &compiled, &rule.principal.roles, |principal| {
                        match rule.tool_name.as_deref() {
                            Some(tool_name) => alone.match_tool_rules(tool_name, principal)
                                == Ok(DirectRuleOutcome::Matched { index: 0 }),
                            None => http_paths().iter().any(|path| {
                                universe_methods()
                                    .iter()
                                    .any(|method| first_direct(&alone, method, path, principal) == Some(0))
                            }),
                        }
                    })
                }
                (FindingCode::IssuerlessRoleGrant, Section::Tools, _) => {
                    let name = finding.element.name.clone().unwrap_or_default();
                    let entry = &analyzed.tools[&name];
                    issuerless_shown(&analyzed, &compiled, &entry.allowed_roles, |principal| {
                        !refused_at_admission(tool_reason(&compiled, &name, principal))
                    })
                }
                (FindingCode::BroadPathGrant, _, Some(position)) => broad_path_shown(&analyzed, position),
                (FindingCode::AllMethodsGrant, _, Some(position)) => all_methods_shown(&analyzed, position),
                _ => true,
            };
            prop_assert!(
                shown,
                "{} at {} has no witness in the universe",
                finding.code.as_str(),
                finding.element.pointer
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Brute force: egress CIDRs against the static egress lane
// ---------------------------------------------------------------------------

/// The categories a universe address belongs to, by the published ranges.
fn address_category(address: IpAddr) -> Option<&'static str> {
    [
        ("loopback", "127.0.0.0/8"),
        ("loopback", "::1/128"),
        ("link_local", "169.254.0.0/16"),
        ("link_local", "fe80::/10"),
        ("private", "10.0.0.0/8"),
        ("private", "172.16.0.0/12"),
        ("private", "192.168.0.0/16"),
        ("private", "100.64.0.0/10"),
        ("private", "fc00::/7"),
    ]
    .into_iter()
    .find(|(_, range)| {
        range
            .parse::<IpNet>()
            .is_ok_and(|range| range.contains(&address))
    })
    .map(|(category, _)| category)
}

fn egress_addresses() -> Vec<IpAddr> {
    [
        "127.0.0.1",
        "127.255.255.254",
        "169.254.169.254",
        "169.254.1.1",
        "10.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "100.64.0.1",
        "8.8.8.8",
        "::1",
        "fe80::1",
        "fd00::1",
        "fc00::1",
        "2606:4700::1",
    ]
    .iter()
    .filter_map(|address| address.parse().ok())
    .collect()
}

/// Whether the static egress lane, refusing non-global addresses outside
/// `cidrs`, connects to the witness host resolved to `address`.
fn egress_lane_admits(cidrs: &[IpNet], address: IpAddr) -> bool {
    let lane = CompiledEgressPolicy::new(EgressControls {
        allowed_hosts: HashSet::from(["witness.invalid".to_owned()]),
        allowed_host_globs: Vec::new(),
        allowed_ports: HashSet::new(),
        deny_private_ips: true,
        nat64_prefixes: Vec::new(),
        private_ip_allow_cidrs: cidrs.to_vec(),
    });
    let url = Url::parse("https://witness.invalid/").expect("url parses");
    let destination = EgressDestination::from_url(&url);
    let answers = [SocketAddr::new(address, 443)];
    matches!(
        lane.evaluate(&EgressEvaluationContext {
            version: EGRESS_CONTEXT_VERSION,
            snapshot: lane.snapshot(),
            destination: &destination,
            resolution: ResolutionFact::Resolved(&answers),
        })
        .expect("the question is well formed")
        .outcome(),
        EgressOutcome::Allow { .. }
    )
}

fn cidr_strategy() -> impl Strategy<Value = &'static str> {
    prop_oneof![
        Just("127.0.0.0/8"),
        Just("127.0.0.1/32"),
        Just("169.254.0.0/16"),
        Just("169.254.169.254/32"),
        Just("10.0.0.0/8"),
        Just("10.1.0.0/16"),
        Just("172.16.0.0/12"),
        Just("192.168.1.0/24"),
        Just("100.64.0.0/10"),
        Just("8.8.8.0/24"),
        Just("0.0.0.0/0"),
        Just("::1/128"),
        Just("fe80::/10"),
        Just("fd00::/8"),
        Just("2606:4700::/32"),
        Just("::/0"),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Every proven non-public CIDR finding names exactly the categories of
    /// the universe addresses the CIDR holds, and for each the egress lane
    /// refuses such an address without the CIDR and connects with it.
    #[test]
    fn proven_egress_cidr_claims_hold_against_the_egress_lane(
        cidrs in prop::collection::vec(cidr_strategy(), 1..4),
    ) {
        let mut document = base(json!([]), json!([]));
        document["egress"] = json!({ "cidrs": cidrs });
        let outcome = run(&policy(document));
        for (index, cidr) in cidrs.iter().enumerate() {
            let cidr: IpNet = cidr.parse().expect("the strategy's CIDRs parse");
            let pointer = format!("/egress/cidrs/{index}");
            let finding = outcome.findings.iter().find(|finding| {
                finding.code == FindingCode::EgressNonPublicCidr && finding.element.pointer == pointer
            });
            let held: BTreeSet<&str> = egress_addresses()
                .into_iter()
                .filter(|address| cidr.contains(address))
                .filter_map(address_category)
                .collect();
            let Some(finding) = finding else {
                prop_assert!(held.is_empty(), "{cidr} holds {held:?} and was not reported");
                continue;
            };
            prop_assert_eq!(finding.proof_basis, ProofBasis::Proven);
            let named: BTreeSet<&str> = finding.details["categories"]
                .as_array()
                .expect("categories")
                .iter()
                .filter_map(Value::as_str)
                .collect();
            prop_assert_eq!(&named, &held, "{}", cidr);
            for category in named {
                prop_assert!(egress_addresses().into_iter().any(|address| {
                    cidr.contains(&address)
                        && address_category(address) == Some(category)
                        && !egress_lane_admits(&[], address)
                        && egress_lane_admits(&[cidr], address)
                }), "{cidr}: {category}");
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
