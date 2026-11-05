//! The impact comparison (issue #243, slice 14): base-to-candidate
//! transitions per lane and projection, the recorded-to-base comparison, the
//! statement a result may make, row caps, determinism and the privacy
//! projection. The live-path proof that a recorded result agrees with the
//! base that recorded it is in `live_tests`.

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::{
    impact::{ReplayPolicies, MAX_IMPACT_ELEMENT_ROWS},
    job::{
        run, ReplayControl, ReplayOutcome, ReplayScope, ReplaySource, ReplaySourceCheck,
        ReplaySourceError,
    },
};
use crate::{
    audit::{
        event,
        query::{ReplayCutoff, ReplayPageQuery, ReplayRow},
        Actor, AuditEvent,
    },
    canonical_json,
    middleware::decision::{
        facts_available, POLICY_DECISION_FACTS_MEMBER, POLICY_DECISION_FACTS_VERSION,
    },
    policy_eval::{
        tools::{TOOL_CONTEXT_VERSION, TOOL_SEMANTICS_VERSION},
        CONTEXT_VERSION, HTTP_SEMANTICS_VERSION,
    },
    policy_simulation::Projection,
    rbac::Policy,
};

const SUBJECT_CANARY: &str = "impact-subject-canary-31d0";
const REQUEST_ID_CANARY: &str = "impact-request-id-canary-77ab";
const SOURCE_IP_CANARY: &str = "198.51.100.77";
const USER_AGENT_CANARY: &str = "impact-user-agent-canary-0c19";
const PATH_CANARY: &str = "/orders/impact-path-canary-e2f4";
const RECORDED_RULE_CANARY: &str = "impact-recorded-rule-canary-5b6a";
const UNLISTED_TOOL_CANARY: &str = "impact-unlisted-tool-canary-9d3e";
const ISSUER: &str = "https://issuer.example";
/// 2027-01-15T08:00:00Z in audit epoch microseconds.
const WINDOW_START_US: i64 = 1_800_000_000_000_000;

fn base_document() -> Value {
    json!({
        "schema_version": "0.1.0",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": { "reader": { "permissions": ["orders:read"] } },
        "rules": [
            { "id": "public-allow", "methods": ["GET"], "path": "/public/**", "action": "allow" },
            { "id": "orders-watch", "methods": ["GET"], "path": "/orders/watched", "action": "shadow" },
            { "id": "search-tool", "tool_name": "search", "action": "allow" },
            { "methods": ["GET"], "path": "/docs/**", "action": "allow" }
        ],
        "routes": [
            { "methods": ["GET"], "path_prefix": "/orders", "permission": "orders:read" }
        ],
        "rate_limits": [
            { "path": "/public/**", "requests_per_second": 1, "burst": 1 }
        ],
        "tools": {
            "search": { "enabled": true },
            "archive": { "enabled": false }
        }
    })
}

/// The base with a lockdown rule inserted ahead of every other, a default
/// allow, the archive tool enabled and a looser public override. Every
/// other element keeps its content, and the direct rules move one place.
fn candidate_document() -> Value {
    let mut candidate = base_document();
    candidate["default_action"] = json!("allow");
    candidate["rules"].as_array_mut().expect("rules").insert(
        0,
        json!({ "id": "lockdown", "methods": ["GET"], "path": "/orders/**", "action": "deny" }),
    );
    candidate["tools"]["archive"]["enabled"] = json!(true);
    candidate["rate_limits"][0]["burst"] = json!(5);
    candidate
}

fn validated(document: Value) -> Policy {
    Policy::validate_json_value(document).expect("the test policy validates")
}

fn compared(projections: &[Projection]) -> ReplayPolicies {
    ReplayPolicies::compile(
        &validated(base_document()),
        Some(&validated(candidate_document())),
        projections,
    )
    .expect("the test policies compile")
}

fn reader() -> Actor {
    Actor {
        user_id: SUBJECT_CANARY.to_owned(),
        issuer: Some(ISSUER.to_owned()),
        email: None,
        roles: Some(vec!["reader".to_owned()]),
        auth_mode: "bearer_token".to_owned(),
    }
}

fn audit_event(event_type: &str, actor: Option<Actor>, payload: Value) -> AuditEvent {
    AuditEvent::new(
        event_type,
        REQUEST_ID_CANARY,
        SOURCE_IP_CANARY,
        actor,
        payload,
    )
    .with_user_agent(USER_AGENT_CANARY)
}

/// An HTTP observation recording `decision` for `reason`, with the
/// attribution members `attribution` names.
fn observed(
    path: &str,
    actor: Option<Actor>,
    decision: &str,
    reason: &str,
    attribution: Value,
) -> AuditEvent {
    let mut payload = json!({
        "method": "GET",
        "path": path,
        "status": 200,
        "policy_decision": decision,
        "policy_reason": reason,
        "routing_context_known": true,
    });
    if let (Some(payload), Some(attribution)) = (payload.as_object_mut(), attribution.as_object()) {
        payload.extend(attribution.clone());
    }
    audit_event("http.request_observed", actor, payload)
}

fn route_attribution() -> Value {
    json!({ "permission": "orders:read", "path_prefix": "/orders" })
}

/// What the gateway recorded for traffic under the base, with three records
/// that do not match what the base decides today.
fn window() -> Vec<AuditEvent> {
    vec![
        observed(
            "/public/a",
            Some(reader()),
            "allowed",
            "matched_rule",
            json!({ "matched_rule_id": "public-allow" }),
        ),
        // The id-less docs rule is recorded by its position in the base.
        observed(
            "/docs/a",
            Some(reader()),
            "allowed",
            "matched_rule",
            json!({ "matched_rule_id": "3" }),
        ),
        observed(
            "/orders/1",
            Some(reader()),
            "allowed",
            "matched_rule",
            route_attribution(),
        ),
        observed(
            PATH_CANARY,
            Some(reader()),
            "allowed",
            "matched_rule",
            route_attribution(),
        ),
        observed(
            "/orders/watched",
            Some(reader()),
            "would_deny",
            "matched_rule",
            json!({ "matched_rule_id": "orders-watch" }),
        ),
        observed(
            "/orders/2",
            None,
            "denied",
            "missing_principal",
            route_attribution(),
        ),
        observed("/other", None, "denied", "default_deny", json!({})),
        // Recorded under an older policy: the base allows it now.
        observed(
            "/public/b",
            Some(reader()),
            "denied",
            "default_deny",
            json!({}),
        ),
        // Recorded by a rule the base does not have.
        observed(
            "/public/c",
            Some(reader()),
            "allowed",
            "matched_rule",
            json!({ "matched_rule_id": RECORDED_RULE_CANARY }),
        ),
        // The policy stage did not answer this one.
        observed(
            "/orders/3",
            Some(reader()),
            "denied",
            "policy_evaluation_incomplete",
            json!({}),
        ),
        audit_event(
            event::TOOL_INVOKE_START,
            Some(reader()),
            json!({ "tool_name": "search", "outcome": "started" }),
        ),
        audit_event(
            event::TOOL_INVOKE_REJECTED,
            Some(reader()),
            json!({ "tool_name": "archive", "reason": "disabled" }),
        ),
        audit_event(
            event::TOOL_INVOKE_REJECTED,
            Some(reader()),
            json!({ "tool_name": UNLISTED_TOOL_CANARY, "reason": "unknown_tool" }),
        ),
    ]
}

/// A window's events in id order, every one inside the scope, paged at most
/// `page_cap` rows at a time.
struct Window {
    events: Vec<AuditEvent>,
    page_cap: usize,
}

impl Window {
    fn new(events: Vec<AuditEvent>) -> Self {
        Self {
            events,
            page_cap: usize::MAX,
        }
    }

    fn last_id(&self) -> i64 {
        i64::try_from(self.events.len()).expect("a test length fits")
    }

    fn scope(&self, max_records: usize) -> ReplayScope {
        ReplayScope {
            from: "2027-01-15T08:00:00Z".to_owned(),
            to: "2027-01-15T08:00:01Z".to_owned(),
            from_epoch_us: WINDOW_START_US,
            to_epoch_us: WINDOW_START_US + 1_000_000,
            cutoff: ReplayCutoff {
                high_water: self.last_id(),
                selected: u64::try_from(self.events.len()).expect("a test count fits"),
                first_id: (!self.events.is_empty()).then_some(1),
                last_id: (!self.events.is_empty()).then_some(self.last_id()),
            },
            max_records,
        }
    }
}

impl ReplaySource for Window {
    fn kind(&self) -> &'static str {
        "test_rows"
    }

    fn page(&self, query: &ReplayPageQuery) -> Result<Vec<(i64, ReplayRow)>, ReplaySourceError> {
        Ok(self
            .events
            .iter()
            .zip(1_i64..)
            .filter(|(_, id)| *id > query.after_id && *id <= query.through_id)
            .take(query.limit.min(self.page_cap))
            .map(|(event, id)| (id, ReplayRow::Event(Box::new(event.clone()))))
            .collect())
    }

    fn check(&self, _scope: &ReplayScope) -> Result<ReplaySourceCheck, ReplaySourceError> {
        Ok(ReplaySourceCheck {
            stored: u64::try_from(self.events.len()).expect("a test count fits"),
            pruned: false,
        })
    }
}

fn run_over(source: &Window, policies: &ReplayPolicies, max_records: usize) -> ReplayOutcome {
    run(
        source,
        policies,
        &source.scope(max_records),
        Instant::now() + Duration::from_secs(60),
        &ReplayControl::default(),
    )
    .expect("the run completes")
}

fn transitions(lane: &Value) -> &Value {
    &lane["transitions"]
}

fn element_row<'a>(lane: &'a Value, transition: &str) -> Vec<&'a Value> {
    lane["changed_elements"]
        .as_array()
        .expect("changed elements")
        .iter()
        .filter(|row| row["transition"] == json!(transition))
        .collect()
}

#[test]
fn a_candidate_is_compared_with_its_base_record_by_record() {
    let source = Window::new(window());
    let outcome = run_over(&source, &compared(&[Projection::AsAuthored]), 1_000);
    assert!(outcome.complete, "{:?}", outcome.limitations);
    let impact = &outcome.result["impact"];
    assert_eq!(impact["candidate_is_base"], json!(false));
    let projection = &impact["projections"]["as_authored"];
    assert!(impact["projections"].get("enforce_all_shadow").is_none());

    let http = &projection["http"];
    assert_eq!(http["records"], json!(10));
    assert_eq!(http["compared"], json!(10));
    assert_eq!(
        *transitions(http),
        json!({
            // The anonymous request the base defaulted to deny.
            "newly_allowed": 1,
            // The watched order: shadowed under the base, blocked by lockdown.
            "enforcement_only_change": 1,
            // The reader's orders the route allowed, now locked down; the
            // policy-unanswered record is decided again like any other.
            "newly_denied": 3,
            // Still denied and blocked, now by lockdown instead of the route.
            "attribution_only_change": 1,
            "unchanged_deny": 0,
            // The public and docs rules moved one place and are unchanged.
            "unchanged_allow": 4,
            "indeterminate": 0,
            "unsupported_context": 0,
        })
    );
    assert_eq!(
        http["forwarding"],
        json!({ "newly_forwarded": 1, "newly_blocked": 4 })
    );
    // Rows come in review priority: newly allowed first.
    let matrix = http["matrix"].as_array().expect("matrix");
    assert_eq!(matrix[0]["transition"], json!("newly_allowed"));
    assert_eq!(matrix[0]["forwarding"], json!("newly_forwarded"));
    assert_eq!(
        matrix[0]["base"],
        json!({ "logical": "deny", "enforcement": "enforced",
                "effective_action": "would_block", "reason": "default_deny" })
    );
    assert_eq!(
        matrix[0]["candidate"],
        json!({ "logical": "allow", "enforcement": "not_applicable",
                "effective_action": "would_forward", "reason": "default_allow" })
    );
    assert_eq!(http["matrix_omitted"], json!(0));
    let enforcement = element_row(http, "enforcement_only_change");
    assert_eq!(enforcement.len(), 1);
    assert_eq!(
        enforcement[0]["base"],
        json!({ "kind": "rule", "position": 1, "id": "orders-watch" })
    );
    assert_eq!(
        enforcement[0]["candidate"],
        json!({ "kind": "rule", "position": 0, "id": "lockdown" })
    );
    assert_eq!(enforcement[0]["forwarding"], json!("newly_blocked"));
    let denied = element_row(http, "newly_denied");
    assert_eq!(denied.len(), 1);
    assert_eq!(denied[0]["base"], json!({ "kind": "route", "position": 0 }));
    assert_eq!(denied[0]["count"], json!(3));
    let allowed = element_row(http, "newly_allowed");
    assert_eq!(allowed[0]["base"], json!({ "kind": "default" }));
    // Unchanged records name no element.
    assert!(element_row(http, "unchanged_allow").is_empty());
    assert_eq!(http["changed_elements_omitted"], json!(0));

    let tool = &projection["tool"];
    assert_eq!(tool["records"], json!(3));
    assert_eq!(transitions(tool)["newly_allowed"], json!(1));
    assert_eq!(transitions(tool)["unchanged_allow"], json!(1));
    assert_eq!(transitions(tool)["unchanged_deny"], json!(1));
    let enabled = element_row(tool, "newly_allowed");
    assert_eq!(
        enabled[0]["base"],
        json!({ "kind": "tool_entry", "tool": "archive" })
    );
    assert_eq!(enabled[0]["forwarding"], json!("newly_forwarded"));

    // A newly allowed decision is reported, and the safe sentence is not.
    assert_eq!(
        projection["statement"],
        json!({ "code": "newly_allowed_observed", "newly_allowed": 2,
                "newly_forwarded": 2, "replayable_events": 13 })
    );

    // Rate selection, never capacity: the public override's burst grew.
    let rate = &impact["rate"];
    assert_eq!(rate["records"], json!(10));
    assert_eq!(rate["transitions"]["override_changed"], json!(3));
    assert_eq!(rate["transitions"]["unchanged"], json!(7));
    assert_eq!(rate["limits"]["looser"], json!(3));
    let changed = rate["changed_elements"].as_array().expect("rate rows");
    assert_eq!(
        changed[0]["base"],
        json!({ "kind": "rate_override", "position": 0 })
    );

    // What was recorded, against the base decided today.
    let recorded = &impact["recorded"]["http"];
    assert_eq!(
        recorded["comparisons"],
        json!({
            "agrees": 7,
            "outcome_differs": 1,
            "attribution_differs": 1,
            "evaluator_changed": 0,
            "recorded_under_other_policy": 0,
            "recorded_not_policy_verdict": 1,
            "base_indeterminate": 0,
            "base_refused": 0,
        })
    );
    // None of these records carries decision facts, so no difference is
    // explained by one.
    assert_eq!(
        recorded["provenance"],
        json!({ "base_policy": 0, "other_policy": 0, "other_evaluator": 0, "not_recorded": 10 })
    );
    let differs = recorded["matrix"]
        .as_array()
        .expect("recorded rows")
        .iter()
        .find(|row| row["comparison"] == json!("outcome_differs"))
        .expect("the outcome difference has a row");
    assert_eq!(
        differs["recorded"],
        json!({ "policy": "denied", "reason": "default_deny" })
    );
    assert_eq!(
        differs["base"],
        json!({ "policy": "allowed", "reason": "matched_rule" })
    );
    assert_eq!(
        impact["recorded"]["tool"]["comparisons"]["agrees"],
        json!(3)
    );

    // The candidate's own counts are unchanged in meaning.
    assert_eq!(outcome.result["replayed"]["total"], json!(13));
    // The completion record's counts carry no element and no value.
    assert_eq!(outcome.impact["as_authored"]["newly_allowed"], json!(2));
    assert_eq!(outcome.impact["as_authored"]["newly_denied"], json!(3));
    assert_eq!(outcome.impact["as_authored"]["newly_blocked"], json!(4));
    assert!(!outcome.impact.to_string().contains("lockdown"));
}

#[test]
fn every_shadow_projected_as_enforced_is_its_own_comparison() {
    let source = Window::new(window());
    let outcome = run_over(
        &source,
        &compared(&[Projection::AsAuthored, Projection::EnforceAllShadow]),
        1_000,
    );
    let projections = &outcome.result["impact"]["projections"];
    let projected = &projections["enforce_all_shadow"];
    // The watched order is blocked by its own rule once every shadow
    // enforces, so lockdown only changes which rule blocks it.
    let http = &projected["http"];
    assert_eq!(transitions(http)["enforcement_only_change"], json!(0));
    assert_eq!(transitions(http)["attribution_only_change"], json!(2));
    assert_eq!(transitions(http)["newly_denied"], json!(3));
    // The projection makes no statement: it is a hypothetical, not traffic.
    assert!(projected.get("statement").is_none());
    assert!(projections["as_authored"].get("statement").is_some());
    // And it leaves the as-authored comparison as it was.
    let alone = run_over(&source, &compared(&[Projection::AsAuthored]), 1_000);
    assert_eq!(
        projections["as_authored"],
        alone.result["impact"]["projections"]["as_authored"]
    );
    assert_eq!(
        outcome.impact["enforce_all_shadow"]["enforcement_only_change"],
        json!(0)
    );
}

/// Records the base decides exactly as the gateway recorded them.
fn agreeing_window() -> Vec<AuditEvent> {
    window().into_iter().take(7).collect()
}

#[test]
fn a_candidate_that_is_its_base_changes_nothing_and_says_so_only_when_complete() {
    let source = Window::new(agreeing_window());
    let policies =
        ReplayPolicies::compile(&validated(base_document()), None, &[Projection::AsAuthored])
            .expect("the base compiles");
    let outcome = run_over(&source, &policies, 1_000);
    assert!(outcome.complete);
    let impact = &outcome.result["impact"];
    assert_eq!(impact["candidate_is_base"], json!(true));
    let http = &impact["projections"]["as_authored"]["http"];
    assert_eq!(transitions(http)["unchanged_allow"], json!(4));
    assert_eq!(transitions(http)["unchanged_deny"], json!(3));
    assert_eq!(http["changed_elements"], json!([]));
    assert_eq!(
        impact["projections"]["as_authored"]["statement"],
        json!({
            "code": "no_newly_allowed_observed",
            "replayable_events": 7,
            "text": "No newly allowed decisions were observed among 7 replayable events.",
        })
    );
    assert_eq!(
        impact["recorded"]["http"]["comparisons"]["agrees"],
        json!(7)
    );
    assert!(!outcome.result.to_string().contains("safe"));

    // A scan that stopped at its bound establishes nothing.
    let truncated = run_over(&source, &policies, 3);
    assert!(!truncated.complete);
    assert_eq!(
        truncated.result["impact"]["projections"]["as_authored"]["statement"],
        json!({ "code": "not_established", "reason": "incomplete" })
    );
    // Neither does a window with nothing to compare.
    let empty = run_over(&Window::new(Vec::new()), &policies, 1_000);
    assert_eq!(
        empty.result["impact"]["projections"]["as_authored"]["statement"],
        json!({ "code": "not_established", "reason": "incomplete" })
    );
}

#[test]
fn a_record_no_policy_can_answer_is_indeterminate_on_both_sides() {
    // An actor from before the audit envelope recorded issuers: the route's
    // permission check cannot be judged under either policy.
    let mut old = observed(
        "/orders/1",
        Some(reader()),
        "allowed",
        "matched_rule",
        route_attribution(),
    );
    old.schema_version = "0.1.0".to_owned();
    let source = Window::new(vec![old]);
    let mut candidate = base_document();
    candidate["default_action"] = json!("allow");
    let policies = ReplayPolicies::compile(
        &validated(base_document()),
        Some(&validated(candidate)),
        &[Projection::AsAuthored],
    )
    .expect("the test policies compile");
    let impact = &run_over(&source, &policies, 1_000).result["impact"];
    let http = &impact["projections"]["as_authored"]["http"];
    assert_eq!(transitions(http)["indeterminate"], json!(1));
    assert_eq!(http["compared"], json!(0));
    assert_eq!(
        http["limitations"],
        json!({
            "base": { "missing_principal_fact": 1 },
            "candidate": { "missing_principal_fact": 1 },
        })
    );
    assert_eq!(
        impact["recorded"]["http"]["comparisons"]["base_indeterminate"],
        json!(1)
    );
    assert_eq!(
        impact["projections"]["as_authored"]["statement"],
        json!({ "code": "not_established", "reason": "nothing_compared" })
    );
}

#[test]
fn rows_past_a_cap_are_counted_never_dropped() {
    let extra = MAX_IMPACT_ELEMENT_ROWS + 8;
    let mut base = base_document();
    base["default_action"] = json!("allow");
    let mut candidate = base.clone();
    let rules = candidate["rules"].as_array_mut().expect("rules");
    for index in 0..extra {
        rules.push(json!({
            "id": format!("deny-{index}"),
            "methods": ["GET"],
            "path": format!("/many/{index}"),
            "action": "deny",
        }));
    }
    let events = (0..extra)
        .map(|index| {
            observed(
                &format!("/many/{index}"),
                None,
                "allowed",
                "default_allow",
                json!({}),
            )
        })
        .collect();
    let policies = ReplayPolicies::compile(
        &validated(base),
        Some(&validated(candidate)),
        &[Projection::AsAuthored],
    )
    .expect("the test policies compile");
    let outcome = run_over(&Window::new(events), &policies, 1_000);
    let http = &outcome.result["impact"]["projections"]["as_authored"]["http"];
    assert_eq!(
        transitions(http)["newly_denied"],
        json!(u64::try_from(extra).expect("fits"))
    );
    let rows = http["changed_elements"].as_array().expect("rows");
    assert_eq!(rows.len(), MAX_IMPACT_ELEMENT_ROWS);
    assert_eq!(http["changed_elements_omitted"], json!(8));
    // Equal counts keep the earliest elements.
    assert_eq!(rows[0]["candidate"]["id"], json!("deny-0"));
}

#[test]
fn the_comparison_is_deterministic_and_bound_into_the_result_digest() {
    let policies = compared(&[Projection::AsAuthored, Projection::EnforceAllShadow]);
    let whole = run_over(&Window::new(window()), &policies, 1_000);
    let mut paged = Window::new(window());
    paged.page_cap = 2;
    let paged = run_over(&paged, &policies, 1_000);
    assert_eq!(paged.digest, whole.digest);
    assert_eq!(
        canonical_json::canonical_json_bytes(&paged.result).expect("canonical"),
        canonical_json::canonical_json_bytes(&whole.result).expect("canonical"),
    );
    // A different projection set is a different result.
    let fewer = run_over(
        &Window::new(window()),
        &compared(&[Projection::AsAuthored]),
        1_000,
    );
    assert_ne!(fewer.digest, whole.digest);
}

#[test]
fn a_comparison_never_repeats_a_record_value() {
    let outcome = run_over(
        &Window::new(window()),
        &compared(&[Projection::AsAuthored, Projection::EnforceAllShadow]),
        1_000,
    );
    let rendered = format!("{}{}", outcome.result, outcome.impact);
    for canary in [
        SUBJECT_CANARY,
        REQUEST_ID_CANARY,
        SOURCE_IP_CANARY,
        USER_AGENT_CANARY,
        PATH_CANARY,
        RECORDED_RULE_CANARY,
        UNLISTED_TOOL_CANARY,
        ISSUER,
        "policy_evaluation_incomplete",
        "/public/",
        "orders:read",
    ] {
        assert!(!rendered.contains(canary), "the result repeats {canary}");
    }
    // Policy elements are named by what the policies themselves say.
    assert!(rendered.contains("\"lockdown\""));
}

/// Decision facts as the request path writes them, for an HTTP verdict of
/// a classified contextless request.
fn http_decision(
    policy_etag: &str,
    semantics_version: &str,
    context_version: u16,
    reason: &str,
    element: Value,
) -> Value {
    json!({
        "schema_version": POLICY_DECISION_FACTS_VERSION,
        "lane": "http",
        "policy_etag": policy_etag,
        "semantics_version": semantics_version,
        "context_version": context_version,
        "facts_available": facts_available::METHOD
            | facts_available::PATH
            | facts_available::PRINCIPAL
            | facts_available::ROUTING
            | facts_available::REQUEST_HOST,
        "routing": "contextless",
        "reason": reason,
        "element": element,
    })
}

fn with_decision(mut event: AuditEvent, decision: Value) -> AuditEvent {
    event
        .payload
        .as_object_mut()
        .expect("an object payload")
        .insert(POLICY_DECISION_FACTS_MEMBER.to_owned(), decision);
    event
}

#[test]
fn a_difference_the_decision_facts_explain_is_labelled_and_never_a_candidate_change() {
    let base = validated(base_document());
    let base_etag = crate::policy_etag(&base).expect("the base has an ETag");
    // Another policy's ETag, computed rather than invented.
    let other_etag =
        crate::policy_etag(&validated(candidate_document())).expect("the other has an ETag");
    let older_semantics = "gg-http-alias-v0";
    // Recorded denied by the default; the base allows `/public/**` by a rule.
    let denied_by_default = || {
        observed(
            "/public/b",
            Some(reader()),
            "denied",
            "default_deny",
            json!({}),
        )
    };
    let default_decision = |policy_etag: &str, semantics_version: &str, context_version: u16| {
        http_decision(
            policy_etag,
            semantics_version,
            context_version,
            "default_deny",
            json!({ "kind": "default" }),
        )
    };
    let tool_decision = |policy_etag: &str, reason: &str| {
        json!({
            "schema_version": POLICY_DECISION_FACTS_VERSION,
            "lane": "tool",
            "policy_etag": policy_etag,
            "semantics_version": TOOL_SEMANTICS_VERSION,
            "context_version": TOOL_CONTEXT_VERSION,
            "facts_available": facts_available::TOOL_NAME | facts_available::PRINCIPAL,
            "reason": reason,
            "element": { "kind": "tool_entry" },
        })
    };
    let records = vec![
        // Decided by the base under this evaluator, and still different:
        // nothing the record states explains it.
        with_decision(
            denied_by_default(),
            default_decision(&base_etag, HTTP_SEMANTICS_VERSION, CONTEXT_VERSION),
        ),
        // Decided under another policy.
        with_decision(
            denied_by_default(),
            default_decision(&other_etag, HTTP_SEMANTICS_VERSION, CONTEXT_VERSION),
        ),
        // Decided by the base under another evaluator semantics, and under
        // another context version.
        with_decision(
            denied_by_default(),
            default_decision(&base_etag, older_semantics, CONTEXT_VERSION),
        ),
        with_decision(
            denied_by_default(),
            default_decision(&base_etag, HTTP_SEMANTICS_VERSION, CONTEXT_VERSION - 1),
        ),
        // Decided by a rule of another policy: an attribution difference.
        with_decision(
            observed(
                "/public/c",
                Some(reader()),
                "allowed",
                "matched_rule",
                json!({ "matched_rule_id": RECORDED_RULE_CANARY }),
            ),
            http_decision(
                &other_etag,
                HTTP_SEMANTICS_VERSION,
                CONTEXT_VERSION,
                "matched_rule",
                json!({ "kind": "rule", "position": 7, "id": RECORDED_RULE_CANARY }),
            ),
        ),
        // Recorded under another policy, and the base agrees anyway.
        with_decision(
            observed(
                "/public/a",
                Some(reader()),
                "allowed",
                "matched_rule",
                json!({ "matched_rule_id": "public-allow" }),
            ),
            http_decision(
                &other_etag,
                HTTP_SEMANTICS_VERSION,
                CONTEXT_VERSION,
                "matched_rule",
                json!({ "kind": "rule", "position": 1, "id": "public-allow" }),
            ),
        ),
        // A record from before decision facts: unexplained, as before.
        denied_by_default(),
        // An invocation another policy admitted, which the base refuses.
        with_decision(
            audit_event(
                event::TOOL_INVOKE_START,
                Some(reader()),
                json!({ "tool_name": "archive", "outcome": "started" }),
            ),
            tool_decision(&other_etag, "allowed"),
        ),
        // One the base refused, and refuses still.
        with_decision(
            audit_event(
                event::TOOL_INVOKE_REJECTED,
                Some(reader()),
                json!({ "tool_name": "archive", "reason": "disabled" }),
            ),
            tool_decision(&base_etag, "disabled"),
        ),
    ];
    let policies =
        ReplayPolicies::compile(&base, None, &[Projection::AsAuthored]).expect("the base compiles");
    let outcome = run_over(&Window::new(records), &policies, 1_000);
    assert!(outcome.complete);
    assert_eq!(outcome.result["records"]["replayable"], json!(9));
    let recorded = &outcome.result["impact"]["recorded"];
    assert_eq!(
        recorded["http"]["comparisons"],
        json!({
            "outcome_differs": 2,
            "attribution_differs": 0,
            "evaluator_changed": 2,
            "recorded_under_other_policy": 2,
            "agrees": 1,
            "recorded_not_policy_verdict": 0,
            "base_indeterminate": 0,
            "base_refused": 0,
        })
    );
    assert_eq!(
        recorded["http"]["provenance"],
        json!({ "base_policy": 1, "other_policy": 3, "other_evaluator": 2, "not_recorded": 1 })
    );
    assert_eq!(
        recorded["tool"]["comparisons"]["recorded_under_other_policy"],
        json!(1)
    );
    assert_eq!(recorded["tool"]["comparisons"]["agrees"], json!(1));
    assert_eq!(
        recorded["tool"]["provenance"],
        json!({ "base_policy": 1, "other_policy": 1, "other_evaluator": 0, "not_recorded": 0 })
    );
    // An explained difference keeps its row, under its own label.
    assert!(recorded["http"]["matrix"]
        .as_array()
        .expect("recorded rows")
        .iter()
        .any(
            |row| row["comparison"] == json!("recorded_under_other_policy")
                && row["recorded"] == json!({ "policy": "allowed", "reason": "matched_rule" })
        ));

    // None of it is a candidate change: the candidate is its base, every
    // record is unchanged, and the statement counts every compared record.
    let projection = &outcome.result["impact"]["projections"]["as_authored"];
    for lane in ["http", "tool"] {
        let transitions = transitions(&projection[lane]);
        for code in [
            "newly_allowed",
            "enforcement_only_change",
            "newly_denied",
            "attribution_only_change",
        ] {
            assert_eq!(transitions[code], json!(0), "{lane} {code}");
        }
        assert_eq!(projection[lane]["changed_elements"], json!([]), "{lane}");
    }
    assert_eq!(
        projection["statement"]["code"],
        json!("no_newly_allowed_observed")
    );
    assert_eq!(projection["statement"]["replayable_events"], json!(9));
    for count in [
        "newly_allowed",
        "newly_denied",
        "newly_forwarded",
        "newly_blocked",
    ] {
        assert_eq!(outcome.impact["as_authored"][count], json!(0), "{count}");
    }

    // The result counts provenance by code and never repeats what a record
    // named: no ETag, no evaluator version, no element id.
    let rendered = format!("{}{}", outcome.result, outcome.impact);
    for value in [
        other_etag.trim_matches('"'),
        base_etag.trim_matches('"'),
        older_semantics,
        RECORDED_RULE_CANARY,
    ] {
        assert!(!rendered.contains(value), "the result repeats {value}");
    }
}
