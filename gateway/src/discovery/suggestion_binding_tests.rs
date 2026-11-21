use serde_json::json;

use super::*;
use crate::rbac::policy_resources::{PolicyResourceSnapshot, PolicyResourceView};

const LIVE_ETAG: &str =
    "\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"";
const OTHER_ETAG: &str =
    "\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"";
const CUTOFF: &str = "2026-11-20T12:00:00Z";

fn components() -> Value {
    json!({
        "gateway_build": "1.2.3",
        "evaluator": { "http": "http.v1", "http_context": 1 },
        "configuration": format!("sha256:{}", "c".repeat(64)),
        "egress": format!("sha256:{}", "e".repeat(64)),
        "tools": format!("sha256:{}", "7".repeat(64)),
        "connections": "\"connections:sha256:0\"",
    })
}

fn context(etag: &str, components: &Value, complete: bool) -> SuggestionGenerationContext {
    SuggestionGenerationContext::new(
        etag.to_owned(),
        None,
        Some(format!("sha256:{}", "d".repeat(64))),
        complete,
        components,
    )
    .expect("the context is canonical")
}

fn binding(etag: &str, components: &Value, complete: bool) -> SuggestionGenerationBinding {
    context(etag, components, complete)
        .binding_for(CUTOFF, &json!({ "observation_count": 3 }))
        .expect("the evidence is canonical")
}

fn live(etag: &str, components: &Value, complete: bool) -> LiveGenerationState {
    LiveGenerationState::new(etag.to_owned(), complete, components)
}

#[test]
fn freshness_is_current_only_when_policy_resources_and_generator_all_match() {
    let recorded = binding(LIVE_ETAG, &components(), true);
    let freshness = suggestion_freshness(
        Some(&recorded),
        Some(&live(LIVE_ETAG, &components(), true)),
        false,
    );
    assert_eq!(freshness.status, Some(FreshnessStatus::Current));
    assert!(freshness.reasons.is_empty());
    assert!(freshness.is_current());

    // Each input alone moves it off `current`.
    let changed_policy = suggestion_freshness(
        Some(&recorded),
        Some(&live(OTHER_ETAG, &components(), true)),
        false,
    );
    assert_eq!(changed_policy.status, Some(FreshnessStatus::Stale));
    assert_eq!(changed_policy.reasons, vec!["policy_changed"]);

    let mut older_generator = recorded.clone();
    older_generator.generator_version = "rule-suggestions.v0".to_owned();
    let freshness = suggestion_freshness(
        Some(&older_generator),
        Some(&live(LIVE_ETAG, &components(), true)),
        false,
    );
    assert_eq!(freshness.reasons, vec!["generator_changed"]);

    let mut older_evidence = recorded;
    older_evidence.evidence_schema_version = "rule-suggestion-evidence.v0".to_owned();
    let freshness = suggestion_freshness(
        Some(&older_evidence),
        Some(&live(LIVE_ETAG, &components(), true)),
        false,
    );
    assert_eq!(freshness.reasons, vec!["evidence_schema_changed"]);
}

#[test]
fn freshness_names_every_changed_component() {
    let recorded = binding(LIVE_ETAG, &components(), true);
    for (component, reason) in [
        ("gateway_build", "gateway_build_changed"),
        ("evaluator", "evaluator_changed"),
        ("configuration", "configuration_changed"),
        ("egress", "egress_changed"),
        ("tools", "tools_changed"),
        ("connections", "connections_changed"),
    ] {
        let mut now = components();
        now[component] = json!("changed");
        let freshness =
            suggestion_freshness(Some(&recorded), Some(&live(LIVE_ETAG, &now, true)), false);
        assert_eq!(
            freshness.status,
            Some(FreshnessStatus::Stale),
            "{component}"
        );
        assert_eq!(freshness.reasons, vec![reason], "{component}");
    }

    let mut now = components();
    now["tools"] = json!("changed");
    now["connections"] = Value::Null;
    let freshness =
        suggestion_freshness(Some(&recorded), Some(&live(OTHER_ETAG, &now, true)), false);
    assert_eq!(
        freshness.reasons,
        vec!["policy_changed", "tools_changed", "connections_changed"]
    );
}

#[test]
fn a_security_revision_advance_alone_does_not_make_a_suggestion_stale() {
    let at_generation = PolicyResourceSnapshot::of(&PolicyResourceView {
        security_revision: Some(7),
        ..PolicyResourceView::default()
    });
    let now = PolicyResourceSnapshot::of(&PolicyResourceView {
        security_revision: Some(9),
        ..PolicyResourceView::default()
    });
    // The snapshot digest covers the security revision, so it moved...
    assert_ne!(at_generation.digest(), now.digest());
    // ...and the components a binding compares did not.
    assert!(at_generation
        .binding_components()
        .get("security_revision")
        .is_none());
    assert_eq!(at_generation.binding_components(), now.binding_components());

    // Completeness is the comparator's other input; taken as complete here
    // so that the security revision is the only difference.
    let recorded = SuggestionGenerationContext::new(
        LIVE_ETAG.to_owned(),
        None,
        at_generation.digest().map(str::to_owned),
        true,
        &at_generation.binding_components(),
    )
    .expect("canonical")
    .binding_for(CUTOFF, &json!({}))
    .expect("canonical");
    let freshness = suggestion_freshness(
        Some(&recorded),
        Some(&LiveGenerationState::new(
            LIVE_ETAG.to_owned(),
            true,
            &now.binding_components(),
        )),
        false,
    );
    assert_eq!(freshness.status, Some(FreshnessStatus::Current));
}

#[test]
fn a_row_without_a_binding_is_unbound_and_never_current() {
    let freshness = suggestion_freshness(None, Some(&live(LIVE_ETAG, &components(), true)), false);
    assert_eq!(freshness.status, Some(FreshnessStatus::Unbound));
    assert_eq!(freshness.reasons, vec!["binding_not_recorded"]);
    let freshness = suggestion_freshness(None, None, false);
    assert_eq!(freshness.status, Some(FreshnessStatus::Unbound));
}

#[test]
fn an_incomplete_resource_snapshot_is_never_current() {
    let incomplete_then = binding(LIVE_ETAG, &components(), false);
    let freshness = suggestion_freshness(
        Some(&incomplete_then),
        Some(&live(LIVE_ETAG, &components(), true)),
        false,
    );
    assert_eq!(freshness.status, Some(FreshnessStatus::Stale));
    assert_eq!(freshness.reasons, vec!["resource_snapshot_incomplete"]);

    let complete_then = binding(LIVE_ETAG, &components(), true);
    let freshness = suggestion_freshness(
        Some(&complete_then),
        Some(&live(LIVE_ETAG, &components(), false)),
        false,
    );
    assert_eq!(freshness.reasons, vec!["resource_snapshot_incomplete"]);

    // Live components without a canonical form cannot be shown to match.
    let unreadable = LiveGenerationState::new(LIVE_ETAG.to_owned(), true, &json!("not an object"));
    let freshness = suggestion_freshness(Some(&complete_then), Some(&unreadable), false);
    assert_eq!(freshness.status, Some(FreshnessStatus::Stale));
    assert_eq!(freshness.reasons, vec!["resource_snapshot_incomplete"]);
}

#[test]
fn an_unreadable_policy_authority_is_unknown_not_current() {
    let recorded = binding(LIVE_ETAG, &components(), true);
    let freshness = suggestion_freshness(Some(&recorded), None, false);
    assert_eq!(freshness.status, Some(FreshnessStatus::Unknown));
    assert_eq!(freshness.reasons, vec!["policy_unavailable"]);
}

#[test]
fn a_rule_the_live_policy_already_holds_is_superseded_under_any_id() {
    // The caller compares rules by meaning (any id); the comparator puts
    // that answer above every binding outcome.
    let recorded = binding(LIVE_ETAG, &components(), true);
    for (binding, live_state) in [
        (Some(&recorded), Some(live(LIVE_ETAG, &components(), true))),
        (Some(&recorded), Some(live(OTHER_ETAG, &components(), true))),
        (None, None),
    ] {
        let freshness = suggestion_freshness(binding, live_state.as_ref(), true);
        assert_eq!(freshness.status, Some(FreshnessStatus::Superseded));
        assert_eq!(freshness.reasons, vec!["rule_already_live"]);
    }
}

#[test]
fn the_evidence_digest_is_the_adr_0004_semantic_digest_of_the_evidence() {
    // Key order and whitespace do not matter: the digest is over the RFC
    // 8785 form, framed with the evidence media type and schema version.
    let one = evidence_digest(&json!({ "b": 2, "a": "x" })).expect("canonical");
    let two = evidence_digest(&serde_json::from_str("{ \"a\" : \"x\", \"b\" : 2 }").expect("json"))
        .expect("canonical");
    assert_eq!(one, two);
    assert_eq!(
        one,
        canonical_json::semantic_digest(
            "application/vnd.greengateway.rule-suggestion-evidence+json",
            "rule-suggestion-evidence.v1",
            &json!({ "a": "x", "b": 2 }),
        )
        .expect("canonical")
    );
    assert!(is_digest(&one));
    assert_ne!(
        one,
        evidence_digest(&json!({ "a": "x", "b": 3 })).expect("canonical")
    );
    // A number outside the I-JSON range has no canonical form, so no digest.
    assert_eq!(evidence_digest(&json!({ "count": u64::MAX })), None);
}

#[test]
fn a_partial_or_malformed_stored_binding_decodes_as_no_binding() {
    let recorded = binding(LIVE_ETAG, &components(), true);
    let stored = StoredGenerationBinding::of(Some(&recorded));
    assert_eq!(stored.clone().decode(), Some(recorded));
    assert!(StoredGenerationBinding::of(None).decode().is_none());

    let mut partial = stored.clone();
    partial.evidence_digest = None;
    assert!(partial.decode().is_none());

    let mut bad_etag = stored.clone();
    bad_etag.policy_etag = Some("sha256:not-quoted".to_owned());
    assert!(bad_etag.decode().is_none());

    let mut bad_cutoff = stored.clone();
    bad_cutoff.evidence_cutoff = Some("yesterday".to_owned());
    assert!(bad_cutoff.decode().is_none());

    let mut bad_components = stored.clone();
    bad_components.resource_components = Some("[1,2".to_owned());
    assert!(bad_components.decode().is_none());

    let mut long_version = stored;
    long_version.generator_version = Some("v".repeat(65));
    assert!(long_version.decode().is_none());
}

#[test]
fn a_serialized_binding_never_carries_the_policy_etag_or_components() {
    let mut recorded = binding(LIVE_ETAG, &components(), true);
    recorded.policy_semantic_digest = Some(format!("sha256:{}", "5".repeat(64)));
    let serialized = serde_json::to_value(&recorded).expect("serializes");
    let text = serialized.to_string();
    assert!(!text.contains("aaaaaaaa"), "{text}");
    assert!(!text.contains("55555555"), "{text}");
    assert!(serialized.get("policy_etag").is_none());
    assert!(serialized.get("resource_components").is_none());
    assert_eq!(
        serialized["generator_version"],
        json!(RULE_SUGGESTION_GENERATOR_VERSION)
    );
    assert_eq!(serialized["evidence_cutoff"], json!(CUTOFF));
    assert_eq!(serialized["resource_snapshot_complete"], json!(true));
}

#[test]
fn a_planned_context_still_holds_only_while_its_freshness_inputs_are_live() {
    let planned = context(LIVE_ETAG, &components(), true);
    assert!(planned.still_holds(&live(LIVE_ETAG, &components(), true)));

    // A policy write, a resource change or a snapshot that became
    // incomplete between planning and persisting each fail the check.
    assert!(!planned.still_holds(&live(OTHER_ETAG, &components(), true)));
    let mut tools_changed = components();
    tools_changed["tools"] = json!(format!("sha256:{}", "8".repeat(64)));
    assert!(!planned.still_holds(&live(LIVE_ETAG, &tools_changed, true)));
    assert!(!planned.still_holds(&live(LIVE_ETAG, &components(), false)));
    assert!(!planned.still_holds(&live(LIVE_ETAG, &json!("not an object"), true)));

    // The snapshot digest, which covers the security revision, is not
    // compared.
    let other_digest = SuggestionGenerationContext::new(
        LIVE_ETAG.to_owned(),
        None,
        Some(format!("sha256:{}", "f".repeat(64))),
        true,
        &components(),
    )
    .expect("the context is canonical");
    assert!(other_digest.still_holds(&live(LIVE_ETAG, &components(), true)));
}
