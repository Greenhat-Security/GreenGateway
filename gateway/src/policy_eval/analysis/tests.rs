use super::*;
use crate::{
    auth::{AuthMethod, Principal},
    policy_eval::{HostFact, LogicalDecision, PrincipalIdentity, Reason, CONTEXT_VERSION},
};
use http::Method;
use serde_json::{json, Value};

fn policy(value: Value) -> Policy {
    Policy::validate_json_value(value).unwrap()
}

fn rule(value: Value) -> Rule {
    serde_json::from_value(value).unwrap()
}

fn principal(roles: &[&str]) -> Principal {
    Principal {
        user_id: "synthetic-user".to_owned(),
        issuer: Some("https://idp.example.test".to_owned()),
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        auth_method: AuthMethod::Bearer,
        email: None,
        org_id: None,
        session_id: "synthetic-session".to_owned(),
    }
}

fn context(compiled: &CompiledPolicy) -> PolicyEvaluationContext {
    PolicyEvaluationContext {
        version: CONTEXT_VERSION,
        snapshot: compiled.snapshot(),
        method: Some(Method::GET),
        path: Some("/data/item".to_owned()),
        principal: PrincipalFact::Anonymous,
        target: HttpTarget::Contextless,
        request_host: HostFact::Missing,
        dispatch: None,
    }
}

fn host_bound_dispatch() -> DispatchFacts {
    DispatchFacts {
        route_id: Some("payments".to_owned()),
        route_host: Some("api.example.test".to_owned()),
        route_path_prefix: None,
        upstream_origin: "pool:payments".to_owned(),
    }
}

#[test]
fn a_candidate_rule_matches_on_its_own_predicates_without_live_narrowing() {
    // A selected virtual upstream narrows live evaluation to direct denies, so
    // an allow rule never decides such a request. The preview asks whether the
    // rule's predicates match, which they do.
    let compiled = CompiledPolicy::for_candidate_rule(rule(json!({
        "methods": ["GET"], "path": "/data/**", "action": "allow"
    })));
    let mut input = context(&compiled);
    input.target = HttpTarget::ProxyDispatch;
    input.dispatch = Some(host_bound_dispatch());
    assert_eq!(
        compiled.match_direct_rules(&input).unwrap(),
        DirectRuleOutcome::Matched { index: 0 }
    );

    let live = compiled.evaluate(&input).unwrap();
    assert_eq!(live.matched(), None);
    assert_eq!(live.reason(), Reason::HostPolicyRequired);
    assert_eq!(live.logical(), LogicalDecision::Deny);
}

#[test]
fn direct_rule_matching_is_first_match_in_source_order_with_source_ordinals() {
    let compiled = CompiledPolicy::for_analysis(policy(json!({
        "schema_version": "0.1.0",
        "rules": [
            {"tool_name": "reports.export", "action": "deny"},
            {"enabled": false, "path": "/data/**", "action": "deny"},
            {"methods": ["POST"], "path": "/data/**", "action": "deny"},
            {"path": "/data/item", "action": "shadow"},
            {"path": "/data/**", "action": "deny"}
        ]
    })));
    // The tool rule, the disabled rule and the POST rule keep their ordinals
    // and are skipped; the shadow rule matches before the later deny.
    assert_eq!(
        compiled.match_direct_rules(&context(&compiled)).unwrap(),
        DirectRuleOutcome::Matched { index: 3 }
    );
    let mut other = context(&compiled);
    other.path = Some("/data/other".to_owned());
    assert_eq!(
        compiled.match_direct_rules(&other).unwrap(),
        DirectRuleOutcome::Matched { index: 4 }
    );
    let mut unmatched = context(&compiled);
    unmatched.path = Some("/elsewhere".to_owned());
    assert_eq!(
        compiled.match_direct_rules(&unmatched).unwrap(),
        DirectRuleOutcome::NoMatch
    );
}

#[test]
fn a_missing_fact_is_demanded_only_when_an_enabled_http_rule_reads_it() {
    let cases = [
        // (rule, principal missing, routing unclassified, expected)
        (
            json!({"path": "/data/**", "action": "deny"}),
            true,
            true,
            DirectRuleOutcome::Matched { index: 0 },
        ),
        (
            json!({"path": "/data/**", "principal": {"roles": ["reader"]}, "action": "deny"}),
            true,
            false,
            DirectRuleOutcome::Indeterminate(Limitation::MissingPrincipalFact),
        ),
        (
            json!({"enabled": false, "path": "/data/**", "principal": {"roles": ["reader"]}, "action": "deny"}),
            true,
            false,
            DirectRuleOutcome::NoMatch,
        ),
        (
            json!({"tool_name": "reports.export", "principal": {"roles": ["reader"]}, "action": "deny"}),
            true,
            false,
            DirectRuleOutcome::NoMatch,
        ),
        (
            json!({"path": "/data/**", "dispatch": {"kind": "contextless"}, "action": "deny"}),
            false,
            true,
            DirectRuleOutcome::Indeterminate(Limitation::MissingDispatchFact),
        ),
        (
            json!({"enabled": false, "path": "/data/**", "dispatch": {"kind": "contextless"}, "action": "deny"}),
            false,
            true,
            DirectRuleOutcome::NoMatch,
        ),
    ];
    for (candidate, principal_missing, unclassified, expected) in cases {
        let compiled = CompiledPolicy::for_candidate_rule(rule(candidate.clone()));
        let mut input = context(&compiled);
        if principal_missing {
            input.principal = PrincipalFact::Missing;
        }
        if unclassified {
            input.target = HttpTarget::Missing;
        }
        assert_eq!(
            compiled.match_direct_rules(&input).unwrap(),
            expected,
            "{candidate}"
        );
    }

    // A dispatch named without its facts is as unanswerable as no
    // classification, for a rule bound to one.
    let bound = CompiledPolicy::for_candidate_rule(rule(json!({
        "path": "/data/**", "dispatch": {"kind": "route", "route_id": "payments"}, "action": "deny"
    })));
    let mut input = context(&bound);
    input.target = HttpTarget::ProxyDispatch;
    assert_eq!(
        bound.match_direct_rules(&input).unwrap(),
        DirectRuleOutcome::Indeterminate(Limitation::MissingDispatchFact)
    );
    input.dispatch = Some(host_bound_dispatch());
    assert_eq!(
        bound.match_direct_rules(&input).unwrap(),
        DirectRuleOutcome::Matched { index: 0 }
    );

    let compiled =
        CompiledPolicy::for_candidate_rule(rule(json!({"path": "/data/**", "action": "deny"})));
    let mut input = context(&compiled);
    input.method = None;
    assert_eq!(
        compiled.match_direct_rules(&input).unwrap(),
        DirectRuleOutcome::Indeterminate(Limitation::MissingMethod)
    );
    let mut input = context(&compiled);
    input.path = None;
    assert_eq!(
        compiled.match_direct_rules(&input).unwrap(),
        DirectRuleOutcome::Indeterminate(Limitation::MissingPath)
    );
}

#[test]
fn a_supplied_principal_is_judged_and_an_anonymous_one_matches_no_constrained_rule() {
    let compiled = CompiledPolicy::for_candidate_rule(rule(json!({
        "path": "/data/**", "principal": {"roles": ["reader"]}, "action": "deny"
    })));
    let mut input = context(&compiled);
    assert_eq!(
        compiled.match_direct_rules(&input).unwrap(),
        DirectRuleOutcome::NoMatch
    );
    input.principal =
        PrincipalFact::Authenticated(PrincipalIdentity::from_principal(&principal(&["reader"])));
    assert_eq!(
        compiled.match_direct_rules(&input).unwrap(),
        DirectRuleOutcome::Matched { index: 0 }
    );
    input.principal =
        PrincipalFact::Authenticated(PrincipalIdentity::from_principal(&principal(&["writer"])));
    assert_eq!(
        compiled.match_direct_rules(&input).unwrap(),
        DirectRuleOutcome::NoMatch
    );
}

#[test]
fn facts_the_evaluator_refuses_are_refused_before_any_rule_is_read() {
    let compiled =
        CompiledPolicy::for_candidate_rule(rule(json!({"path": "/**", "action": "deny"})));

    for path in ["/data/%2e%2e/item", "/data//item", "/data/../item", "data"] {
        let mut input = context(&compiled);
        input.path = Some(path.to_owned());
        let error = compiled.match_direct_rules(&input).unwrap_err();
        assert_eq!(error, EvaluationError::MalformedPath, "{path}");
        assert!(error.rejects_supplied_facts());
    }

    let mut input = context(&compiled);
    input.target = HttpTarget::McpAlias {
        canonical_path: "/mcp".to_owned(),
    };
    assert_eq!(
        compiled.match_direct_rules(&input).unwrap_err(),
        EvaluationError::InconsistentContext
    );

    // A question built against another snapshot or context version is the
    // caller's own mistake, never a property of the facts.
    let other = CompiledPolicy::for_candidate_rule(rule(json!({"path": "/x", "action": "deny"})));
    let mut input = context(&compiled);
    input.snapshot = other.snapshot();
    let error = compiled.match_direct_rules(&input).unwrap_err();
    assert_eq!(error, EvaluationError::SnapshotMismatch);
    assert!(!error.rejects_supplied_facts());
    let mut input = context(&compiled);
    input.version = CONTEXT_VERSION - 1;
    let error = compiled.match_direct_rules(&input).unwrap_err();
    assert_eq!(error, EvaluationError::UnsupportedContextVersion);
    assert!(!error.rejects_supplied_facts());
}

#[test]
fn only_refusals_of_supplied_facts_are_reported_as_unevaluable_records() {
    for (error, rejects) in [
        (EvaluationError::UnsupportedContextVersion, false),
        (EvaluationError::SnapshotMismatch, false),
        (EvaluationError::MalformedPath, true),
        (EvaluationError::ContextTooLarge, true),
        (EvaluationError::InvalidPrincipal, true),
        (EvaluationError::InvalidHost, true),
        (EvaluationError::InconsistentContext, true),
        (EvaluationError::InternalInvariant, false),
        (EvaluationError::TraceEncoding, false),
        (EvaluationError::TraceTooLarge, false),
    ] {
        assert_eq!(error.rejects_supplied_facts(), rejects, "{error:?}");
    }
}

#[test]
fn recorded_dispatch_reads_an_origin_as_a_dispatch_and_no_route_facts_as_contextless() {
    assert_eq!(
        recorded_dispatch(None, None, None, None).unwrap(),
        (HttpTarget::Contextless, None)
    );
    assert_eq!(
        recorded_dispatch(
            Some("payments"),
            Some("api.example.test"),
            Some("/pay"),
            Some("pool:payments"),
        )
        .unwrap(),
        (
            HttpTarget::ProxyDispatch,
            Some(DispatchFacts {
                route_id: Some("payments".to_owned()),
                route_host: Some("api.example.test".to_owned()),
                route_path_prefix: Some("/pay".to_owned()),
                upstream_origin: "pool:payments".to_owned(),
            })
        )
    );
    for (route_id, route_host, route_path_prefix) in [
        (Some("payments"), None, None),
        (None, Some("api.example.test"), None),
        (None, None, Some("/pay")),
    ] {
        assert_eq!(
            recorded_dispatch(route_id, route_host, route_path_prefix, None).unwrap_err(),
            EvaluationError::InconsistentContext
        );
    }
}

#[test]
fn limitation_codes_are_the_codes_the_trace_serializes() {
    for limitation in [
        Limitation::MissingMethod,
        Limitation::MissingPath,
        Limitation::MissingPrincipalFact,
        Limitation::MissingDispatchFact,
        Limitation::MissingHostFact,
    ] {
        assert_eq!(
            serde_json::to_value(limitation).unwrap(),
            json!(limitation.as_str())
        );
    }
}

#[test]
fn an_analysis_snapshot_binds_the_policy_digest_and_claims_no_revision() {
    let value = json!({
        "schema_version": "0.1.0",
        "roles": {"reader": {"permissions": ["read"]}},
        "rules": [{"path": "/data/**", "action": "deny"}]
    });
    let analysis = CompiledPolicy::for_analysis(policy(value.clone()));
    let installed =
        CompiledPolicy::from_validated_policy(policy(value), PolicyAuthority::Standalone).unwrap();
    assert_eq!(analysis.snapshot(), installed.snapshot());
    assert_eq!(analysis.snapshot().authority, PolicyAuthority::Standalone);
    assert!(matches!(
        analysis.snapshot().digest,
        PolicyDigest::ValidatedPolicy(_)
    ));
    assert_eq!(analysis.direct_rules().len(), 1);
    assert!(analysis.roles().contains_key("reader"));

    // Two candidate rules are two policies, never one snapshot.
    let first = CompiledPolicy::for_candidate_rule(rule(json!({"path": "/a", "action": "deny"})));
    let second = CompiledPolicy::for_candidate_rule(rule(json!({"path": "/b", "action": "deny"})));
    assert_ne!(first.snapshot(), second.snapshot());
}

fn authenticated(principal: Principal) -> PrincipalFact {
    PrincipalFact::Authenticated(PrincipalIdentity::from_principal(&principal))
}

#[test]
fn tool_rule_matching_is_the_first_enabled_tool_rule_its_principal_accepts() {
    let compiled = CompiledPolicy::for_analysis(policy(json!({
        "schema_version": "0.1.0",
        // No entry for the tool: admission is not what this asks.
        "rules": [
            {"path": "/mcp/tools/reports.export", "action": "deny"},
            {"tool_name": "reports.export", "enabled": false, "action": "deny"},
            {"tool_name": "reports.import", "action": "deny"},
            {"tool_name": "reports.export", "principal": {"roles": ["admin"]}, "action": "deny"},
            {"tool_name": "reports.export", "principal": {"roles": ["reader"]}, "action": "shadow"},
            {"tool_name": "reports.export", "action": "allow"}
        ]
    })));
    let matched = |principal: PrincipalFact| {
        compiled
            .match_tool_rules("reports.export", &principal)
            .unwrap()
    };
    assert_eq!(
        matched(authenticated(principal(&["admin"]))),
        DirectRuleOutcome::Matched { index: 3 }
    );
    assert_eq!(
        matched(authenticated(principal(&["reader"]))),
        DirectRuleOutcome::Matched { index: 4 }
    );
    assert_eq!(
        matched(PrincipalFact::Anonymous),
        DirectRuleOutcome::Matched { index: 5 }
    );
    assert_eq!(
        compiled
            .match_tool_rules("reports.unknown", &PrincipalFact::Anonymous)
            .unwrap(),
        DirectRuleOutcome::NoMatch
    );
    // An enabled tool rule reads the principal, so a missing one is unanswerable.
    assert_eq!(
        matched(PrincipalFact::Missing),
        DirectRuleOutcome::Indeterminate(Limitation::MissingPrincipalFact)
    );
}

#[test]
fn a_missing_principal_is_demanded_only_when_an_enabled_tool_rule_reads_it() {
    let compiled = CompiledPolicy::for_analysis(policy(json!({
        "schema_version": "0.1.0",
        "rules": [
            {"path": "/data/**", "principal": {"roles": ["reader"]}, "action": "deny"},
            {"tool_name": "reports.export", "enabled": false, "principal": {"roles": ["reader"]}, "action": "deny"},
            {"tool_name": "reports.export", "action": "allow"}
        ]
    })));
    assert_eq!(
        compiled
            .match_tool_rules("reports.export", &PrincipalFact::Missing)
            .unwrap(),
        DirectRuleOutcome::Matched { index: 2 }
    );
}

#[test]
fn a_tool_rule_question_the_evaluator_cannot_accept_is_refused() {
    let compiled = CompiledPolicy::for_analysis(policy(json!({
        "schema_version": "0.1.0",
        "rules": [{"tool_name": "reports.export", "action": "allow"}]
    })));
    let at_bound = "t".repeat(MAX_TOOL_NAME_BYTES);
    assert_eq!(
        compiled
            .match_tool_rules(&at_bound, &PrincipalFact::Anonymous)
            .unwrap(),
        DirectRuleOutcome::NoMatch
    );
    let over_bound = "t".repeat(MAX_TOOL_NAME_BYTES + 1);
    assert_eq!(
        compiled.match_tool_rules(&over_bound, &PrincipalFact::Anonymous),
        Err(EvaluationError::ContextTooLarge)
    );
    assert_eq!(
        compiled.match_tool_rules("reports.export", &authenticated(principal(&[""]))),
        Err(EvaluationError::InvalidPrincipal)
    );
    let too_many: Vec<String> = (0..257).map(|index| format!("role-{index}")).collect();
    let too_many: Vec<&str> = too_many.iter().map(String::as_str).collect();
    assert_eq!(
        compiled.match_tool_rules("reports.export", &authenticated(principal(&too_many))),
        Err(EvaluationError::ContextTooLarge)
    );
}
