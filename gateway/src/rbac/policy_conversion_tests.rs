//! Golden tests for the 0.x to v1 conversion.
//!
//! `testdata/policy-conversion-golden/expected.json` pins, for each 0.x
//! fixture beside it, the v1 document the conversion produces, every change
//! it lists and the v1 semantic digest, which does not depend on how the
//! fixture's bytes are spelled (or on the checkout's line endings). A
//! difference here changes the ids operators' audit history is keyed by and
//! needs its own review, not a fixture refresh.
//!
//! The parity tests then ask both documents of every fixture, and every 0.x
//! policy the repository ships, the same questions through the shared
//! evaluator the live gateway decides with: every HTTP lane target, the rate
//! lane, every tool operation and the static egress lane.

use std::{
    collections::{BTreeSet, HashSet},
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use http::Method;
use ipnet::IpNet;
use serde_json::{json, Value};
use url::Url;

use super::*;
use crate::{
    auth::{AuthMethod, Principal},
    canonical_json,
    policy_eval::{
        egress::{
            CompiledEgressPolicy, EgressControls, EgressDestination, EgressEvaluationContext,
            ResolutionFact, EGRESS_CONTEXT_VERSION,
        },
        tools::{ToolEvaluationContext, ToolOperation, TOOL_CONTEXT_VERSION},
        CompiledPolicy, DispatchFacts, HostFact, HttpTarget, PolicyAuthority,
        PolicyEvaluationContext, PrincipalFact, PrincipalIdentity, CONTEXT_VERSION,
    },
    rbac::{policy_document::DiagnosticSeverity, RuleAction},
};

const EXPECTED: &str = include_str!("testdata/policy-conversion-golden/expected.json");

fn golden_fixtures() -> [(&'static str, &'static str); 2] {
    [
        (
            "full",
            include_str!("testdata/policy-conversion-golden/full.v0.json"),
        ),
        (
            "ids",
            include_str!("testdata/policy-conversion-golden/ids.v0.json"),
        ),
    ]
}

fn convert(source: &[u8]) -> PolicyConversion {
    match convert_v0_source(source) {
        Ok(conversion) => conversion,
        Err(ConversionError::Refused(inspection)) => {
            panic!("conversion refused: {:?}", inspection.diagnostics())
        }
        Err(error) => panic!("conversion failed: {error:?}"),
    }
}

fn convert_value(document: &Value) -> PolicyConversion {
    convert(&serde_json::to_vec(document).expect("fixture should serialize"))
}

fn refusal(source: &[u8]) -> PolicyInspection {
    match convert_v0_source(source) {
        Err(ConversionError::Refused(inspection)) => *inspection,
        Ok(conversion) => panic!("expected a refusal, got {:?}", conversion.changes()),
        Err(error) => panic!("expected a refusal, got {error:?}"),
    }
}

fn refusal_codes(inspection: &PolicyInspection) -> Vec<(&'static str, String)> {
    inspection
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .map(|diagnostic| (diagnostic.code, diagnostic.pointer.clone()))
        .collect()
}

fn document_bytes(conversion: &PolicyConversion) -> Vec<u8> {
    serde_json::to_vec(&conversion.document()).expect("the document should serialize")
}

fn document_value(conversion: &PolicyConversion) -> Value {
    serde_json::from_slice(&document_bytes(conversion)).expect("the document should parse")
}

/// The converted document as the v1 reader reads it.
fn converted_policy(conversion: &PolicyConversion) -> Policy {
    Policy::from_source(&document_bytes(conversion), None).expect("the conversion should read")
}

fn source_policy(source: &[u8]) -> Policy {
    Policy::from_source(source, None).expect("the 0.x fixture should read")
}

/// The pinned shape of a conversion: what `expected.json` records per
/// fixture. Messages are left out; the code vocabulary test pins them.
fn golden_record(conversion: &PolicyConversion) -> Value {
    let changes: Vec<Value> = conversion
        .changes()
        .iter()
        .map(|change| {
            let mut record = json!({ "code": change.code.as_str(), "pointer": change.pointer });
            if let Some(id) = &change.element_id {
                record["element_id"] = json!(id);
            }
            if let Some(id) = &change.previous_id {
                record["previous_id"] = json!(id);
            }
            record
        })
        .collect();
    json!({
        "source_schema_version": conversion.source_schema_version(),
        "semantic_digest": conversion.semantic_digest(),
        "changes": changes,
        "policy": document_value(conversion),
    })
}

#[test]
fn golden_fixtures_convert_to_the_pinned_documents_ids_and_digests() {
    let expected: Value = serde_json::from_str(EXPECTED).expect("expected.json should parse");
    for (name, source) in golden_fixtures() {
        let conversion = convert(source.as_bytes());
        assert_eq!(
            golden_record(&conversion),
            expected[name],
            "{name}: {}",
            serde_json::to_string_pretty(&golden_record(&conversion)).unwrap_or_default()
        );
        // The source digest frames the exact bytes converted, under their
        // own 0.x version.
        assert_eq!(
            conversion.source_digest(),
            canonical_json::source_digest(
                "application/json",
                conversion.source_schema_version(),
                source.as_bytes()
            )
        );
    }
}

#[test]
fn the_converted_document_validates_with_the_pinned_semantic_digest() {
    for (name, source) in golden_fixtures() {
        let conversion = convert(source.as_bytes());
        let pretty =
            serde_json::to_vec_pretty(&conversion.document()).expect("the document serializes");
        let inspection = inspect_source(&pretty);
        assert!(
            inspection.is_valid(),
            "{name}: {:?}",
            inspection.diagnostics()
        );
        assert_eq!(inspection.schema_version(), Some("1.0.0"));
        assert_eq!(
            inspection.semantic_digest(),
            Some(conversion.semantic_digest()),
            "{name}: however it is spelled, the converted document has one semantic digest"
        );
        assert!(
            inspection.diagnostics().is_empty(),
            "{name}: a converted document has nothing left to warn about: {:?}",
            inspection.diagnostics()
        );
        // And it is not converted twice.
        assert_eq!(
            refusal_codes(&refusal(&pretty)),
            vec![("conversion_requires_v0", "/schema_version".to_owned())]
        );
    }
}

#[test]
fn the_converted_document_passes_the_published_v1_schema() {
    let schema: Value = serde_json::from_str(
        &fs::read_to_string(repo_root().join("docs/schemas/policy.v1.schema.json"))
            .expect("the published v1 schema should read"),
    )
    .expect("the published v1 schema should parse");
    let validator =
        jsonschema::validator_for(&schema).expect("the published v1 schema should compile");
    for (name, source) in corpus() {
        let document = document_value(&convert(&source));
        if let Err(error) = validator.validate(&document) {
            panic!("{name}: the published v1 schema refuses the conversion: {error}");
        }
    }
}

#[test]
fn members_are_written_in_schema_order_with_ids_first() {
    let conversion = convert(golden_fixtures()[0].1.as_bytes());
    let text = String::from_utf8(document_bytes(&conversion)).expect("JSON is UTF-8");

    let position = |needle: &str| {
        text.find(needle)
            .unwrap_or_else(|| panic!("{needle} should appear in {text}"))
    };
    // Top-level members in the policy's own order, not alphabetically.
    assert!(text.starts_with(r#"{"schema_version":"1.0.0","id":"golden-full","#));
    assert!(position(r#""default_action""#) < position(r#""enforcement_mode""#));
    assert!(position(r#""roles""#) < position(r#""routes""#));
    assert!(position(r#""routes""#) < position(r#""rules""#));
    assert!(position(r#""rules""#) < position(r#""egress""#));
    assert!(position(r#""egress""#) < position(r#""rate_limits""#));
    assert!(position(r#""rate_limits""#) < position(r#""tools""#));
    // Every identified element starts with its id; maps are sorted by name.
    assert!(text.contains(r#""routes":[{"id":"route-0","methods":["GET"],"path_prefix":"/data""#));
    assert!(text.contains(r#""rules":[{"id":"0","methods":[],"path":"/data/secret/**""#));
    assert!(text.contains(r#""rate_limits":[{"id":"rate-limit-0","principal":{"roles":["reader"]"#));
    assert!(position(r#""admin":{"#) < position(r#""ops":{"#));
    assert!(position(r#""delete_record":{"#) < position(r#""lookup":{"#));
}

#[test]
fn conversion_is_deterministic_whatever_the_source_spelling() {
    let source = golden_fixtures()[0].1;
    let first = convert(source.as_bytes());
    let again = convert(source.as_bytes());
    assert_eq!(document_bytes(&first), document_bytes(&again));
    assert_eq!(first.changes(), again.changes());

    // The same 0.x policy respelled: compact, members in another order,
    // defaults written out, issuers spelled with and without their slash,
    // and `null` where the 0.x reader takes it for "omitted".
    let mut respelled: Value = serde_json::from_str(source).expect("fixture parses");
    respelled["rules"][0]["enabled"] = json!(true);
    respelled["rules"][0]["methods"] = json!([]);
    respelled["rules"][0]["id"] = Value::Null;
    respelled["roles"]["reader"]["issuers"] = json!(["https://idp.example.test"]);
    respelled["tools"]["lookup"]["timeout_ms"] = json!(30_000);
    respelled["tools"]["lookup"]["enabled"] = json!(true);
    let compact = serde_json::to_vec(&respelled).expect("serialize");
    assert_ne!(compact, source.as_bytes());
    let respelled = convert(&compact);

    assert_eq!(document_bytes(&respelled), document_bytes(&first));
    assert_eq!(respelled.semantic_digest(), first.semantic_digest());
    assert_eq!(respelled.changes(), first.changes());
    assert_ne!(respelled.source_digest(), first.source_digest());
}

#[test]
fn rules_keep_the_id_the_gateway_already_attributes_them_to() {
    let conversion = convert_value(&json!({
        "schema_version": "0.1.0",
        "rules": [
            { "path": "/zero", "action": "deny" },
            { "id": "named", "path": "/one", "action": "allow" },
            { "path": "/two", "action": "shadow" }
        ]
    }));
    let policy = converted_policy(&conversion);
    let ids: Vec<_> = policy.rules.iter().map(|rule| rule.id.as_deref()).collect();
    assert_eq!(ids, vec![Some("0"), Some("named"), Some("2")]);
    // The effective rule id the admin routes, hit counts and shadow review
    // use is the same before and after for every rule.
    let source = Policy::validate_json_value(json!({
        "schema_version": "0.1.0",
        "rules": [
            { "path": "/zero", "action": "deny" },
            { "id": "named", "path": "/one", "action": "allow" },
            { "path": "/two", "action": "shadow" }
        ]
    }))
    .expect("source parses");
    let effective = |policy: &Policy| -> Vec<String> {
        policy
            .rules
            .iter()
            .enumerate()
            .map(|(index, rule)| rule.id.clone().unwrap_or_else(|| index.to_string()))
            .collect()
    };
    assert_eq!(effective(&policy), effective(&source));
    let written: Vec<_> = conversion
        .changes()
        .iter()
        .filter(|change| change.code == ChangeCode::RuleIdWritten)
        .map(|change| (change.pointer.as_str(), change.element_id.as_deref()))
        .collect();
    assert_eq!(
        written,
        vec![("/rules/0/id", Some("0")), ("/rules/2/id", Some("2"))]
    );
}

#[test]
fn an_id_that_cannot_be_kept_is_replaced_and_listed_with_its_previous_value() {
    let source = golden_fixtures()[1].1;
    let conversion = convert(source.as_bytes());
    let policy = converted_policy(&conversion);

    let rule_ids: Vec<_> = policy
        .rules
        .iter()
        .map(|rule| rule.id.clone().unwrap_or_default())
        .collect();
    assert_eq!(
        rule_ids,
        vec![
            "1",        // kept: claimed before the unnamed rule at index 1
            "rule-1",   // its effective id "1" was already claimed
            "rule-2-2", // "allow public" is not an id, and "rule-2" is taken
            "dup",      // the first "dup" keeps it
            "rule-4",   // the second does not
            "route-0",  // an operator's id is kept even in a generated form
            "rule-2", "7", // `"id": null` is no id; the index is written
        ]
    );
    let route_ids: Vec<_> = policy
        .routes
        .iter()
        .map(|route| route.id.clone().unwrap_or_default())
        .collect();
    assert_eq!(route_ids, vec!["route-0-2", "route-1"]);

    let replaced: Vec<_> = conversion
        .changes()
        .iter()
        .filter(|change| change.code == ChangeCode::RuleIdReplaced)
        .map(|change| {
            (
                change.pointer.as_str(),
                change.element_id.as_deref(),
                change.previous_id.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        replaced,
        vec![
            ("/rules/1/id", Some("rule-1"), Some("1")),
            ("/rules/2/id", Some("rule-2-2"), Some("allow public")),
            ("/rules/4/id", Some("rule-4"), Some("dup")),
        ]
    );

    // Every element has a valid id, unique across all three sections.
    let all: Vec<String> = policy
        .routes
        .iter()
        .filter_map(|route| route.id.clone())
        .chain(policy.rules.iter().filter_map(|rule| rule.id.clone()))
        .chain(
            policy
                .rate_limits
                .iter()
                .filter_map(|limit| limit.id.clone()),
        )
        .collect();
    assert_eq!(
        all.len(),
        policy.routes.len() + policy.rules.len() + policy.rate_limits.len()
    );
    assert!(all.iter().all(|id| is_valid_element_id(id)));
    assert_eq!(all.iter().collect::<HashSet<_>>().len(), all.len());
}

#[test]
fn what_the_0x_reader_ignored_is_listed_not_carried_over() {
    let conversion = convert(golden_fixtures()[1].1.as_bytes());
    let document = document_value(&conversion);

    assert!(document.get("x-owner").is_none());
    // The last copy of a repeated member is the one the 0.x reader used.
    assert_eq!(document["enforcement_mode"], json!("enforce"));
    assert_eq!(document["rules"][7]["action"], json!("deny"));
    let listed: Vec<_> = conversion
        .changes()
        .iter()
        .filter(|change| {
            matches!(
                change.code,
                ChangeCode::UnknownMemberRemoved | ChangeCode::DuplicateMemberResolved
            )
        })
        .map(|change| (change.code, change.pointer.as_str()))
        .collect();
    assert_eq!(
        listed,
        vec![
            (ChangeCode::UnknownMemberRemoved, "/x-owner"),
            (ChangeCode::DuplicateMemberResolved, "/enforcement_mode"),
            (ChangeCode::DuplicateMemberResolved, "/rules/7/action"),
        ]
    );
}

#[test]
fn a_repeat_inside_a_removed_member_is_listed_only_as_the_removal() {
    // Nothing of `x-owner` is kept, so no copy of its repeated members is
    // either; `x-ownership` merely shares its prefix and is removed on its own.
    let source = br#"{
        "schema_version": "0.1.0",
        "x-owner": { "team": "a", "team": "b" },
        "x-owner": 1,
        "x-ownership": { "team": "a" },
        "default_action": "deny",
        "default_action": "allow"
    }"#;
    let conversion = convert(source);
    let listed: Vec<_> = conversion
        .changes()
        .iter()
        .filter(|change| {
            matches!(
                change.code,
                ChangeCode::UnknownMemberRemoved | ChangeCode::DuplicateMemberResolved
            )
        })
        .map(|change| (change.code, change.pointer.as_str()))
        .collect();
    assert_eq!(
        listed,
        vec![
            (ChangeCode::UnknownMemberRemoved, "/x-owner"),
            (ChangeCode::UnknownMemberRemoved, "/x-ownership"),
            (ChangeCode::DuplicateMemberResolved, "/default_action"),
        ]
    );
    let document = document_value(&conversion);
    assert!(document.get("x-owner").is_none());
    assert_eq!(document["default_action"], json!("allow"));
}

#[test]
fn a_flood_of_repeated_members_is_listed_up_to_the_bound() {
    let mut source = String::from(r#"{"schema_version":"0.1.0","roles":{"#);
    for index in 0..150 {
        if index > 0 {
            source.push(',');
        }
        source.push_str(&format!(
            r#""r{index}":{{"permissions":["a"],"permissions":["b"]}}"#
        ));
    }
    source.push_str("}}");
    let conversion = convert(source.as_bytes());

    let repeats = conversion
        .changes()
        .iter()
        .filter(|change| change.code == ChangeCode::DuplicateMemberResolved)
        .count();
    assert_eq!(repeats, policy_document::MAX_REPORTED_ISSUES);
    assert_eq!(
        conversion.changes().last().map(|change| change.code),
        Some(ChangeCode::MoreDuplicateMembersResolved)
    );
    assert_eq!(
        document_value(&conversion)["roles"]["r149"]["permissions"],
        json!(["b"])
    );
}

#[test]
fn a_document_that_is_not_a_convertible_0x_document_is_refused() {
    // Already v1.
    let v1 = json!({ "schema_version": "1.0.0", "rules": [{ "id": "a", "path": "/a", "action": "deny" }] });
    let refused = refusal(&serde_json::to_vec(&v1).expect("serialize"));
    assert_eq!(
        refusal_codes(&refused),
        vec![("conversion_requires_v0", "/schema_version".to_owned())]
    );
    assert_eq!(refused.schema_version(), Some("1.0.0"));

    // Not JSON, no implemented schema, and an invalid 0.x document: the
    // same diagnostics, in the same words, validation reports.
    for (source, code, pointer) in [
        (&b"{"[..], "invalid_json", ""),
        (
            &br#"{"schema_version":"2.0.0"}"#[..],
            "schema_version_unsupported",
            "/schema_version",
        ),
        (
            &br#"{"schema_version":"0.1.0","routes":[{"path_prefix":"data","permission":"p"}]}"#[..],
            "path_not_absolute",
            "/routes/0/path_prefix",
        ),
    ] {
        let refused = refusal(source);
        assert_eq!(
            refusal_codes(&refused),
            vec![(code, pointer.to_owned())],
            "{}",
            String::from_utf8_lossy(source)
        );
        assert_eq!(
            refused.error_details(),
            inspect_source(source).error_details(),
            "a refusal keeps validation's wording"
        );
    }
}

#[test]
fn a_document_whose_v1_form_the_reader_would_refuse_is_not_converted() {
    // 0.x accepts any finite rate and any u64 timeout; v1 has no canonical
    // form for numbers beyond 2^53 - 1.
    let refused = refusal(
        &serde_json::to_vec(&json!({
            "schema_version": "0.1.0",
            "rate_limits": [{ "requests_per_second": 1e300, "burst": 1 }],
            "tools": { "slow": { "timeout_ms": 9_007_199_254_740_992_u64 } }
        }))
        .expect("serialize"),
    );
    assert_eq!(
        refusal_codes(&refused),
        vec![
            (
                "number_out_of_range",
                "/rate_limits/0/requests_per_second".to_owned()
            ),
            ("number_out_of_range", "/tools/slow/timeout_ms".to_owned()),
        ]
    );
    assert!(
        refused
            .diagnostics()
            .iter()
            .all(|diagnostic| diagnostic.element_id.is_none()),
        "an id assigned only in the refused conversion names nothing in the source"
    );

    // A 0.x document under 1 MiB whose normalized form, with every default
    // written out, is larger than a v1 document may be.
    let rules: Vec<Value> = (0..12_000)
        .map(|_| json!({ "path": "/a", "action": "deny" }))
        .collect();
    let source = serde_json::to_vec(&json!({ "schema_version": "0.1.0", "rules": rules }))
        .expect("serialize");
    assert!(source.len() < 1_048_576);
    assert_eq!(
        refusal_codes(&refusal(&source)),
        vec![("document_too_large", String::new())]
    );
}

#[test]
fn the_change_vocabulary_is_closed_unique_and_stable_text() {
    let mut seen = HashSet::new();
    for code in ChangeCode::ALL {
        let name = code.as_str();
        assert!(seen.insert(name), "{name} is listed twice");
        assert!(
            name.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
            "{name} is not a snake_case code"
        );
        assert!(!code.message().is_empty() && !code.message().contains('{'));
        assert_eq!(serde_json::to_value(code).expect("serialize"), json!(name));
    }
}

#[test]
fn every_golden_and_repository_policy_decides_identically_after_conversion() {
    for (name, source) in corpus() {
        let conversion = convert(&source);
        let before = source_policy(&source);
        let after = converted_policy(&conversion);
        let compared = assert_same_decisions(&name, &before, &after);
        assert!(compared > 0, "{name}: no question was asked");
    }
}

#[test]
fn the_full_fixture_reaches_every_outcome_the_lanes_have() {
    // Parity over a corpus that only ever allowed would prove little: the
    // full fixture must reach blocks, observations, overrides and tool
    // refusals, so a conversion that changed any of them would be seen.
    let policy = source_policy(golden_fixtures()[0].1.as_bytes());
    let decisions = decisions(&policy);
    for expected in [
        "http Allow Allow",
        "http Deny Block",
        "http Deny Observe",
        "rate Override",
        "rate NoOverride",
        "tool Allow Allow",
        "tool Deny Block",
        "tool Deny Observe",
        "egress Allow",
        "egress Deny",
    ] {
        assert!(
            decisions
                .iter()
                .any(|decision| decision.starts_with(expected)),
            "the full fixture never reaches {expected}"
        );
    }
    assert!(decisions.len() > 10_000, "{}", decisions.len());
}

#[test]
fn the_parity_harness_sees_a_reordered_rule() {
    // A control: the harness must tell two policies apart when they decide
    // differently, or its agreement above would mean nothing.
    let before = source_policy(golden_fixtures()[0].1.as_bytes());
    let mut reordered = before.clone();
    reordered.rules.swap(0, 2);
    assert_ne!(decisions(&before), decisions(&reordered));
    let mut loosened = before.clone();
    if let Some(rule) = loosened.rules.first_mut() {
        rule.action = RuleAction::Allow;
    }
    assert_ne!(decisions(&before), decisions(&loosened));
}

/// The golden fixtures and every 0.x policy the repository ships.
fn corpus() -> Vec<(String, Vec<u8>)> {
    let mut corpus: Vec<(String, Vec<u8>)> = golden_fixtures()
        .into_iter()
        .map(|(name, source)| (name.to_owned(), source.as_bytes().to_vec()))
        .collect();
    for relative_path in [
        "docs/examples/policy.starter.json",
        "dev/policy.json",
        "fuzz/corpus/policy/allow.json",
        "fuzz/corpus/policy/deny.json",
        "fuzz/corpus/policy/duplicate.json",
    ] {
        let source = fs::read(repo_root().join(relative_path))
            .unwrap_or_else(|error| panic!("{relative_path}: {error}"));
        corpus.push((relative_path.to_owned(), source));
    }
    corpus
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("gateway crate should live directly under the repo root")
        .to_owned()
}

/// Asks `before` and `after` the same questions and requires the same
/// answers, returning how many were asked.
fn assert_same_decisions(name: &str, before: &Policy, after: &Policy) -> usize {
    let questions = Questions::of(before);
    let expected = questions.ask(before);
    let actual = questions.ask(after);
    assert_eq!(expected.len(), actual.len(), "{name}");
    for (index, (expected, actual)) in expected.iter().zip(&actual).enumerate() {
        assert_eq!(
            actual, expected,
            "{name}: question {index} decides differently"
        );
    }
    expected.len()
}

/// Every answer `policy` gives to the questions its own members suggest.
fn decisions(policy: &Policy) -> Vec<String> {
    Questions::of(policy).ask(policy)
}

/// The questions a policy's members suggest: every method, path, principal,
/// routing target, tool name and egress destination they mention, plus one
/// of each that none of them matches.
struct Questions {
    methods: Vec<Method>,
    paths: Vec<String>,
    principals: Vec<Option<Principal>>,
    targets: Vec<(HttpTarget, HostFact, Option<DispatchFacts>)>,
    tools: Vec<String>,
    destinations: Vec<String>,
    answers: Vec<Vec<SocketAddr>>,
}

impl Questions {
    fn of(policy: &Policy) -> Self {
        let mut methods: BTreeSet<String> = ["GET", "POST", "PUT", "DELETE", "PATCH"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let mut paths: BTreeSet<String> = ["/", "/unmatched/path"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let mut hosts = BTreeSet::new();
        for route in &policy.routes {
            methods.extend(route.methods.iter().filter(|m| *m != "*").cloned());
            paths.insert(route.path_prefix.clone());
            paths.insert(child_of(&route.path_prefix));
            hosts.extend(route.hosts.iter().cloned());
        }
        for rule in &policy.rules {
            methods.extend(rule.methods.iter().filter(|m| *m != "*").cloned());
            paths.extend(instances(&rule.path));
        }
        for limit in &policy.rate_limits {
            methods.extend(limit.methods.iter().filter(|m| *m != "*").cloned());
            if let Some(path) = &limit.path {
                paths.extend(instances(path));
            }
        }

        let mut roles: BTreeSet<String> = policy.roles.keys().cloned().collect();
        let mut issuers: BTreeSet<String> = ["https://other-idp.example.test".to_owned()].into();
        let mut principal_ids: BTreeSet<String> = BTreeSet::new();
        for role in policy.roles.values() {
            issuers.extend(role.issuers.iter().cloned());
        }
        for matcher in policy
            .rules
            .iter()
            .map(|rule| &rule.principal)
            .chain(policy.rate_limits.iter().map(|limit| &limit.principal))
        {
            roles.extend(matcher.roles.iter().cloned());
            issuers.extend(matcher.issuers.iter().cloned());
            principal_ids.extend(matcher.principal_ids.iter().cloned());
        }
        for tool in policy.tools.values() {
            roles.extend(tool.allowed_roles.iter().cloned());
            issuers.extend(tool.issuers.iter().cloned());
        }
        roles.remove("*");
        let all_roles: Vec<&str> = roles.iter().map(String::as_str).collect();
        let home_issuer = issuers
            .iter()
            .find(|issuer| !issuer.contains("other-idp"))
            .cloned()
            .unwrap_or_else(|| "https://idp.example.test".to_owned());
        let mut principals = vec![
            None,
            Some(principal("nobody", &home_issuer, &[], AuthMethod::Bearer)),
        ];
        for role in &roles {
            principals.push(Some(principal(
                "user",
                &home_issuer,
                &[role],
                AuthMethod::Bearer,
            )));
        }
        for method in [
            AuthMethod::Bearer,
            AuthMethod::Cookie,
            AuthMethod::ServiceToken,
            AuthMethod::ClientCertificate,
        ] {
            principals.push(Some(principal("user", &home_issuer, &all_roles, method)));
        }
        for issuer in &issuers {
            principals.push(Some(principal(
                "user",
                issuer,
                &all_roles,
                AuthMethod::Bearer,
            )));
        }
        for id in &principal_ids {
            principals.push(Some(principal(
                id,
                &home_issuer,
                &all_roles,
                AuthMethod::ServiceToken,
            )));
        }

        let upstream = "https://upstream.example.test".to_owned();
        let mut targets = vec![
            (HttpTarget::Contextless, HostFact::Absent, None),
            (
                HttpTarget::McpAlias {
                    canonical_path: "/mcp".to_owned(),
                },
                HostFact::Absent,
                None,
            ),
            (
                HttpTarget::ProxyDispatch,
                HostFact::Absent,
                Some(dispatch(Some("unbound-route"), None, &upstream)),
            ),
        ];
        for host in &hosts {
            targets.push((
                HttpTarget::Contextless,
                HostFact::Present(host.clone()),
                None,
            ));
            targets.push((
                HttpTarget::ProxyDispatch,
                HostFact::Present(host.clone()),
                Some(dispatch(Some("virtual-route"), Some(host), &upstream)),
            ));
        }
        for rule in &policy.rules {
            if let Some(binding) = &rule.dispatch {
                let origin = binding
                    .upstream_origin
                    .clone()
                    .unwrap_or_else(|| upstream.clone());
                targets.push((
                    HttpTarget::ProxyDispatch,
                    HostFact::Absent,
                    Some(dispatch(binding.route_id.as_deref(), None, &origin)),
                ));
            }
        }

        let mut tools: BTreeSet<String> = policy.tools.keys().cloned().collect();
        tools.extend(
            policy
                .rules
                .iter()
                .filter_map(|rule| rule.tool_name.clone()),
        );
        tools.insert("unlisted_tool".to_owned());

        let mut ports: BTreeSet<u16> = [80, 443].into();
        ports.extend(policy.egress.ports.iter().copied());
        let mut destination_hosts: BTreeSet<String> = ["unlisted.example.test".to_owned()].into();
        for pattern in &policy.egress.hosts {
            destination_hosts.insert(match pattern.strip_prefix("*.") {
                Some(suffix) => format!("edge.{suffix}"),
                None => pattern.clone(),
            });
        }
        let destinations = destination_hosts
            .iter()
            .flat_map(|host| {
                ports
                    .iter()
                    .map(move |port| format!("https://{host}:{port}/"))
            })
            .collect();
        let mut addresses = vec![
            IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14)),
            IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1)),
        ];
        for cidr in &policy.egress.cidrs {
            if let Ok(network) = cidr.parse::<IpNet>() {
                addresses.push(network.network());
            }
        }
        let answers = addresses
            .into_iter()
            .map(|address| vec![SocketAddr::new(address, 443)])
            .collect();

        Self {
            methods: methods
                .iter()
                .filter_map(|method| Method::from_bytes(method.as_bytes()).ok())
                .collect(),
            paths: paths.into_iter().collect(),
            principals,
            targets,
            tools: tools.into_iter().collect(),
            destinations,
            answers,
        }
    }

    fn ask(&self, policy: &Policy) -> Vec<String> {
        let compiled =
            CompiledPolicy::from_validated_policy(policy.clone(), PolicyAuthority::Standalone)
                .expect("a standalone policy compiles");
        let mut answers = Vec::new();
        for method in &self.methods {
            for path in &self.paths {
                for who in &self.principals {
                    for (target, host, dispatch) in &self.targets {
                        let context = PolicyEvaluationContext {
                            version: CONTEXT_VERSION,
                            snapshot: compiled.snapshot(),
                            method: Some(method.clone()),
                            path: Some(path.clone()),
                            principal: principal_fact(who.as_ref()),
                            target: target.clone(),
                            request_host: host.clone(),
                            dispatch: dispatch.clone(),
                        };
                        answers.push(match compiled.evaluate(&context) {
                            Ok(evaluation) => format!(
                                "http {:?} {:?} {:?} {:?} {:?} {} {:?}",
                                evaluation.logical(),
                                evaluation.effect(),
                                evaluation.reason(),
                                evaluation.matched(),
                                evaluation.observation(),
                                evaluation.is_complete(),
                                evaluation.limitation()
                            ),
                            Err(error) => format!("http error {error:?}"),
                        });
                        if *target == HttpTarget::Contextless {
                            answers.push(match compiled.select_rate_lane(&context) {
                                Ok(selection) => format!("rate {:?}", selection.outcome()),
                                Err(error) => format!("rate error {error:?}"),
                            });
                        }
                    }
                    let rendered = ToolEvaluationContext {
                        version: TOOL_CONTEXT_VERSION,
                        snapshot: compiled.snapshot(),
                        operation: ToolOperation::RenderedHttp,
                        tool_name: Some("rendered".to_owned()),
                        principal: principal_fact(who.as_ref()),
                        method: Some(method.clone()),
                        path: Some(path.clone()),
                    };
                    answers.push(tool_answer(&compiled, &rendered));
                }
            }
        }
        for tool in &self.tools {
            for who in &self.principals {
                for operation in [
                    ToolOperation::Invocation,
                    ToolOperation::Visibility,
                    ToolOperation::PolicyEligibility,
                    ToolOperation::CompositeLeaf,
                ] {
                    let context = ToolEvaluationContext {
                        version: TOOL_CONTEXT_VERSION,
                        snapshot: compiled.snapshot(),
                        operation,
                        tool_name: Some(tool.clone()),
                        principal: if operation == ToolOperation::CompositeLeaf {
                            PrincipalFact::Missing
                        } else {
                            principal_fact(who.as_ref())
                        },
                        method: None,
                        path: None,
                    };
                    answers.push(tool_answer(&compiled, &context));
                }
            }
        }
        let egress = CompiledEgressPolicy::new(egress_controls(policy));
        for destination in &self.destinations {
            let Ok(url) = Url::parse(destination) else {
                continue;
            };
            let destination = EgressDestination::from_url(&url);
            for resolved in &self.answers {
                let context = EgressEvaluationContext {
                    version: EGRESS_CONTEXT_VERSION,
                    snapshot: egress.snapshot(),
                    destination: &destination,
                    resolution: ResolutionFact::Resolved(resolved),
                };
                answers.push(match egress.evaluate(&context) {
                    Ok(evaluation) => format!("egress {:?}", evaluation.outcome()),
                    Err(error) => format!("egress error {error:?}"),
                });
            }
        }
        answers
    }
}

fn tool_answer(compiled: &CompiledPolicy, context: &ToolEvaluationContext) -> String {
    match compiled.evaluate_tool(context) {
        Ok(evaluation) => format!(
            "tool {:?} {:?} {:?} {:?} {} {:?}",
            evaluation.logical(),
            evaluation.effect(),
            evaluation.reason(),
            evaluation.matched(),
            evaluation.is_complete(),
            evaluation.limitation()
        ),
        Err(error) => format!("tool error {error:?}"),
    }
}

/// The static controls the live egress client builds from a policy's
/// `egress` section over an environment that adds nothing: patterns
/// lowercased, CIDRs parsed, ports as listed, private addresses denied.
fn egress_controls(policy: &Policy) -> EgressControls {
    EgressControls {
        allowed_hosts: HashSet::new(),
        allowed_host_globs: policy
            .egress
            .hosts
            .iter()
            .map(|host| host.to_ascii_lowercase())
            .collect(),
        allowed_ports: policy.egress.ports.iter().copied().collect(),
        deny_private_ips: true,
        nat64_prefixes: Vec::new(),
        private_ip_allow_cidrs: policy
            .egress
            .cidrs
            .iter()
            .filter_map(|cidr| cidr.parse::<IpNet>().ok())
            .collect(),
    }
}

fn principal_fact(principal: Option<&Principal>) -> PrincipalFact {
    principal.map_or(PrincipalFact::Anonymous, |principal| {
        PrincipalFact::Authenticated(PrincipalIdentity::from_principal(principal))
    })
}

fn principal(user_id: &str, issuer: &str, roles: &[&str], auth_method: AuthMethod) -> Principal {
    Principal {
        user_id: user_id.to_owned(),
        issuer: Some(issuer.to_owned()),
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        auth_method,
        email: None,
        org_id: None,
        session_id: String::new(),
    }
}

fn dispatch(route_id: Option<&str>, route_host: Option<&str>, origin: &str) -> DispatchFacts {
    DispatchFacts {
        route_id: route_id.map(str::to_owned),
        route_host: route_host.map(str::to_owned),
        route_path_prefix: None,
        upstream_origin: origin.to_owned(),
    }
}

fn child_of(prefix: &str) -> String {
    if prefix.ends_with('/') {
        format!("{prefix}child")
    } else {
        format!("{prefix}/child")
    }
}

/// Concrete paths a rule path pattern matches: `**` as no segments and as
/// two, `*` and `{capture}` as one segment.
fn instances(pattern: &str) -> Vec<String> {
    if pattern.is_empty() {
        return Vec::new();
    }
    [Vec::new(), vec!["deep", "er"]]
        .iter()
        .map(|globstar| {
            let segments: Vec<&str> = pattern
                .split('/')
                .flat_map(|segment| match segment {
                    "**" => globstar.clone(),
                    "*" => vec!["seg"],
                    capture if capture.starts_with('{') => vec!["seg"],
                    literal => vec![literal],
                })
                .filter(|segment| !segment.is_empty())
                .collect();
            format!("/{}", segments.join("/"))
        })
        .collect()
}
