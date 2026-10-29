//! The evidence request parser and the package assembler, without the admin
//! API. The endpoint, its authorization, its history and replay bindings and
//! its audit record are covered in `admin_policy_evidence_tests`.

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::{
    package::{
        assemble, EvidenceInputs, PackageError, PolicyIdentity, PredecessorRecord,
        PublicationRecord, ReplayEvidence, SimulationEvidence, ValidationOutcome,
    },
    request::{parse_request, EvidenceRequest},
    LIMITATION_CODES, MAX_EVIDENCE_DIAGNOSTICS, PACKAGE_SCHEMA_VERSION, REDACTION_PROFILE,
    REPORT_MEDIA_TYPE, REPORT_SCHEMA_VERSION, REQUEST_SCHEMA_VERSION, TRUST_STATEMENT,
};
use crate::{
    canonical_json,
    policy_eval::PolicyAuthority,
    policy_simulation::{
        run::{compile_pairs, simulate},
        Projection, TraceLevel,
    },
    policy_testing::{
        self,
        report::{PolicyBinding, PolicySource, RunReport},
        suite::{parse_suite, Diagnostics},
    },
    rbac::{policy_document::inspect_source, Policy},
};

/// Values the request and history fixtures carry that no report may repeat.
const SUBJECT_CANARY: &str = "evidence-subject-canary-5d2e";
const PATH_CANARY: &str = "evidence-path-canary-a41c";
const SUMMARY_CANARY: &str = "evidence-summary-canary-90f3";
const HEADER_CANARY: &str = "evidence-header-canary-c7b8";

const PUBLICATION_ETAG: &str =
    "\"sha256:1111111111111111111111111111111111111111111111111111111111111111\"";
const PREDECESSOR_ETAG: &str =
    "\"sha256:2222222222222222222222222222222222222222222222222222222222222222\"";
const OTHER_ETAG: &str =
    "\"sha256:3333333333333333333333333333333333333333333333333333333333333333\"";
const SEMANTIC_DIGEST: &str =
    "sha256:4444444444444444444444444444444444444444444444444444444444444444";
const GENERATED_AT: &str = "2026-10-28T12:00:00Z";

fn publication_document() -> Value {
    json!({
        "schema_version": "1.0.0",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": { "reader": { "permissions": ["orders:read"] } },
        "rules": [
            { "id": "public", "methods": ["GET"], "path": "/public/**", "action": "allow" },
            { "id": "lockdown", "methods": ["GET"], "path": "/orders/restricted", "action": "deny" }
        ],
        "routes": [
            { "id": "orders", "path_prefix": "/orders", "permission": "orders:read" }
        ]
    })
}

fn predecessor_document() -> Value {
    let mut document = publication_document();
    document["rules"] = json!([
        { "id": "public", "methods": ["GET"], "path": "/public/**", "action": "allow" }
    ]);
    document
}

fn policy(document: Value) -> Policy {
    Policy::validate_json_value(document).expect("fixture policy validates")
}

fn reader() -> Value {
    json!({ "subject": SUBJECT_CANARY, "roles": ["reader"], "auth_method": "bearer_token" })
}

fn suite_document() -> Value {
    json!({
        "schema_version": "policy-tests.v1",
        "cases": [
            {
                "id": "public-is-open",
                "kind": "http",
                "request": { "method": "GET", "path": format!("/public/{PATH_CANARY}") },
                "principal": "anonymous",
                "expect": { "logical": "allow" }
            },
            {
                "id": "restricted-is-closed",
                "kind": "http",
                "request": { "method": "GET", "path": "/orders/restricted" },
                "principal": reader(),
                "expect": { "logical": "deny", "matched": { "rule": "lockdown" } }
            }
        ]
    })
}

fn simulation_cases() -> Value {
    json!([
        {
            "id": "restricted-order",
            "kind": "http",
            "request": { "method": "GET", "path": "/orders/restricted" },
            "principal": reader()
        },
        {
            "id": "plain-order",
            "kind": "http",
            "request": { "method": "GET", "path": "/orders/7" },
            "principal": reader()
        }
    ])
}

fn full_request() -> Value {
    json!({
        "schema_version": REQUEST_SCHEMA_VERSION,
        "publication": { "version": 12, "etag": PUBLICATION_ETAG },
        "suite": suite_document(),
        "simulation": {
            "trace": "matched",
            "projections": ["as_authored", "enforce_all_shadow"],
            "cases": simulation_cases()
        },
        "replay_job_id": "rpl_0123456789abcdef0123456789abcdef"
    })
}

fn parsed(value: &Value) -> EvidenceRequest {
    match parse_request(value) {
        Ok(request) => request,
        Err(diagnostics) => panic!("request should parse: {diagnostics:?}"),
    }
}

fn refused(value: &Value) -> Diagnostics {
    match parse_request(value) {
        Ok(_) => panic!("request should be refused"),
        Err(diagnostics) => diagnostics,
    }
}

fn has(diagnostics: &Diagnostics, code: &str, pointer: &str) -> bool {
    diagnostics
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == code && diagnostic.pointer == pointer)
}

#[test]
fn a_full_request_parses_and_its_digest_ignores_representation() {
    let request = parsed(&full_request());
    assert_eq!(request.publication.version, 12);
    assert_eq!(request.publication.etag.as_deref(), Some(PUBLICATION_ETAG));
    assert_eq!(
        request.suite.as_ref().map(|suite| suite.cases.len()),
        Some(2)
    );
    let simulation = request.simulation.as_ref().expect("simulation section");
    assert_eq!(simulation.trace, TraceLevel::Matched);
    assert_eq!(
        simulation.projections,
        vec![Projection::AsAuthored, Projection::EnforceAllShadow]
    );
    assert_eq!(simulation.cases.len(), 2);
    assert_eq!(
        request.replay_job_id.as_deref(),
        Some("rpl_0123456789abcdef0123456789abcdef")
    );
    assert!(request.evaluates_synthetic_cases());
    assert!(request.digest.starts_with("sha256:"));

    // The same request written differently names the same inputs.
    let respelled: Value =
        serde_json::from_str(&serde_json::to_string_pretty(&full_request()).expect("serializes"))
            .expect("parses");
    assert_eq!(parsed(&respelled).digest, request.digest);
    let mut changed = full_request();
    changed["publication"]["version"] = json!(13);
    assert_ne!(parsed(&changed).digest, request.digest);
}

#[test]
fn only_the_publication_is_required() {
    let request = parsed(&json!({
        "schema_version": REQUEST_SCHEMA_VERSION,
        "publication": { "version": 1 }
    }));
    assert_eq!(request.publication.version, 1);
    assert!(request.publication.etag.is_none());
    assert!(request.suite.is_none());
    assert!(request.simulation.is_none());
    assert!(request.replay_job_id.is_none());
    assert!(!request.evaluates_synthetic_cases());

    let simulation_only = parsed(&json!({
        "schema_version": REQUEST_SCHEMA_VERSION,
        "publication": { "version": 1 },
        "simulation": { "cases": simulation_cases() }
    }));
    let simulation = simulation_only.simulation.expect("simulation section");
    assert_eq!(simulation.trace, TraceLevel::Terminal);
    assert_eq!(simulation.projections, vec![Projection::AsAuthored]);
}

#[test]
fn the_request_version_is_exact_and_members_are_strict() {
    let mut wrong = full_request();
    wrong["schema_version"] = json!("policy-evidence-request.v2");
    let diagnostics = refused(&wrong);
    assert!(has(
        &diagnostics,
        "unsupported_schema_version",
        "/schema_version"
    ));
    assert_eq!(diagnostics.diagnostics.len(), 1, "nothing else is read");

    let diagnostics = refused(&json!({ "publication": { "version": 1 } }));
    assert!(has(&diagnostics, "missing_field", "/schema_version"));

    let diagnostics = refused(&json!({ "schema_version": REQUEST_SCHEMA_VERSION }));
    assert!(has(&diagnostics, "missing_field", "/publication"));

    let mut extra = full_request();
    extra["signature"] = json!("self-asserted");
    extra["publication"]["digest"] = json!(SEMANTIC_DIGEST);
    extra["simulation"]["base_etag"] = json!(OTHER_ETAG);
    extra["token"] = json!("value");
    let diagnostics = refused(&extra);
    assert!(has(&diagnostics, "unknown_field", "/signature"));
    assert!(has(&diagnostics, "unknown_field", "/publication/digest"));
    assert!(has(&diagnostics, "unknown_field", "/simulation/base_etag"));
    assert!(has(&diagnostics, "forbidden_field", "/token"));
}

#[test]
fn the_publication_version_is_a_positive_safe_integer() {
    for version in [
        json!(0),
        json!(-1),
        json!(1.5),
        json!("12"),
        json!(9_007_199_254_740_992_u64),
        Value::Null,
    ] {
        let diagnostics = refused(&json!({
            "schema_version": REQUEST_SCHEMA_VERSION,
            "publication": { "version": version }
        }));
        assert!(
            has(&diagnostics, "invalid_value", "/publication/version"),
            "{version} is refused: {diagnostics:?}"
        );
    }
    let largest = parsed(&json!({
        "schema_version": REQUEST_SCHEMA_VERSION,
        "publication": { "version": 9_007_199_254_740_991_u64 }
    }));
    assert_eq!(largest.publication.version, 9_007_199_254_740_991);

    let diagnostics = refused(&json!({
        "schema_version": REQUEST_SCHEMA_VERSION,
        "publication": { "version": 1, "etag": "" }
    }));
    assert!(has(&diagnostics, "invalid_value", "/publication/etag"));
    let diagnostics = refused(&json!({
        "schema_version": REQUEST_SCHEMA_VERSION,
        "publication": { "version": 1, "etag": "x".repeat(257) }
    }));
    assert!(has(&diagnostics, "too_long", "/publication/etag"));
}

#[test]
fn section_diagnostics_are_located_in_the_request() {
    let mut request = full_request();
    request["suite"]["cases"][0]["expect"]["logical"] = json!("indeterminate");
    request["suite"]["cases"][1]["headers"] = json!({ "authorization": HEADER_CANARY });
    request["simulation"]["cases"][0]["expect"] = json!({ "logical": "allow" });
    request["simulation"]["projections"] = json!(["as_authored", "as_authored"]);
    let diagnostics = refused(&request);
    assert!(
        diagnostics
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.pointer.starts_with("/suite/cases/0/expect")),
        "{diagnostics:?}"
    );
    assert!(has(
        &diagnostics,
        "forbidden_field",
        "/suite/cases/1/headers"
    ));
    assert!(has(
        &diagnostics,
        "unknown_field",
        "/simulation/cases/0/expect"
    ));
    assert!(has(
        &diagnostics,
        "duplicate_projection",
        "/simulation/projections/1"
    ));
    let rendered = serde_json::to_string(&diagnostics).expect("diagnostics serialize");
    assert!(!rendered.contains(SUBJECT_CANARY));
    assert!(!rendered.contains(HEADER_CANARY));

    let mut empty = full_request();
    empty["simulation"]["cases"] = json!([]);
    empty["suite"]["cases"] = json!([]);
    let diagnostics = refused(&empty);
    assert!(has(&diagnostics, "empty_simulation", "/simulation/cases"));
    assert!(has(&diagnostics, "empty_suite", "/suite/cases"));

    let mut null_sections = full_request();
    null_sections["suite"] = Value::Null;
    null_sections["simulation"] = Value::Null;
    null_sections["replay_job_id"] = Value::Null;
    let diagnostics = refused(&null_sections);
    assert!(has(&diagnostics, "invalid_type", "/suite"));
    assert!(has(&diagnostics, "invalid_type", "/simulation"));
    assert!(has(&diagnostics, "invalid_type", "/replay_job_id"));
}

#[test]
fn a_full_trace_is_not_part_of_an_evidence_package() {
    let mut request = full_request();
    request["simulation"]["trace"] = json!("full");
    let diagnostics = refused(&request);
    assert!(has(&diagnostics, "invalid_value", "/simulation/trace"));

    let mut request = full_request();
    request["replay_job_id"] = json!("r".repeat(65));
    let diagnostics = refused(&request);
    assert!(has(&diagnostics, "too_long", "/replay_job_id"));
}

fn identity(etag: &str, semantic_digest: Option<&str>) -> PolicyIdentity {
    PolicyIdentity {
        schema_version: "1.0.0".to_owned(),
        etag: etag.to_owned(),
        semantic_digest: semantic_digest.map(str::to_owned),
    }
}

fn draft_summary(base_etag: &str) -> Value {
    json!({
        "action": "policy_draft_published",
        "draft_id": format!("pdr_{SUMMARY_CANARY}"),
        "draft_revision": 3,
        "base_etag": base_etag,
    })
}

fn validation_of(document: &Value) -> ValidationOutcome {
    let source = serde_json::to_vec(document).expect("document serializes");
    let inspection = inspect_source(&source);
    ValidationOutcome {
        valid: inspection.is_valid(),
        diagnostics: inspection.diagnostics().to_vec(),
        resource_snapshot: Some(resource_snapshot()),
    }
}

/// A complete resource snapshot as the cross-resource checks report one.
fn resource_snapshot() -> Value {
    json!({
        "schema_version": "1.0.0",
        "digest": SEMANTIC_DIGEST,
        "complete": true,
        "components": { "gateway_build": "test", "tools": SEMANTIC_DIGEST }
    })
}

fn test_report() -> RunReport {
    let suite = parse_suite(&suite_document()).expect("suite parses");
    let outcome = policy_testing::run_against_policy(
        policy(publication_document()),
        PolicyAuthority::Standalone,
        &suite,
        Instant::now() + Duration::from_secs(5),
    )
    .expect("suite runs");
    RunReport::new(
        suite.digest.clone(),
        PolicyBinding {
            source: PolicySource::Publication,
            etag: PUBLICATION_ETAG.to_owned(),
            security_revision: None,
        },
        outcome,
    )
}

fn simulation_evidence() -> SimulationEvidence {
    let request = parsed(&full_request());
    let selection = request.simulation.expect("simulation section");
    let pairs = compile_pairs(
        &policy(predecessor_document()),
        PolicyAuthority::Standalone,
        Some(&policy(publication_document())),
        &selection.projections,
    )
    .expect("policies compile");
    let outcome = simulate(
        &pairs,
        &selection.cases,
        selection.trace,
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap_or_else(|error| panic!("cases simulate: {error:?}"));
    SimulationEvidence {
        trace: selection.trace,
        projections: selection.projections,
        compared_with_predecessor: true,
        outcome,
    }
}

fn replay_evidence(complete: bool) -> ReplayEvidence {
    ReplayEvidence {
        complete,
        compared_with_predecessor: true,
        view: json!({
            "included": true,
            "mode": "historical_replay",
            "state": if complete { "completed" } else { "completed_incomplete" },
            "candidate": { "source": "active", "etag": PUBLICATION_ETAG },
            "result_digest": SEMANTIC_DIGEST,
            "result": { "records": { "replayable": 3 } }
        }),
    }
}

/// Every section present and complete: the only shape a complete report has.
fn complete_inputs() -> EvidenceInputs {
    EvidenceInputs {
        request_digest: parsed(&full_request()).digest,
        publication: PublicationRecord {
            version: 12,
            recorded_at: "2026-10-28T11:00:00Z".to_owned(),
            diff_summary: draft_summary(PREDECESSOR_ETAG),
            policy: identity(PUBLICATION_ETAG, Some(SEMANTIC_DIGEST)),
        },
        predecessor: Some(PredecessorRecord {
            version: 11,
            policy: identity(PREDECESSOR_ETAG, Some(SEMANTIC_DIGEST)),
        }),
        validation: validation_of(&publication_document()),
        tests: Some(test_report()),
        simulation: Some(simulation_evidence()),
        replay: Some(replay_evidence(true)),
    }
}

fn package_value(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("a package is JSON")
}

#[test]
fn a_package_is_canonical_and_its_manifest_binds_the_report() {
    let package = assemble(complete_inputs(), GENERATED_AT).expect("package assembles");
    let value = package_value(&package.bytes);
    assert_eq!(
        canonical_json::canonical_json_bytes(&value).expect("canonical"),
        package.bytes,
        "a package is served as its own RFC 8785 bytes"
    );
    assert_eq!(value["schema_version"], PACKAGE_SCHEMA_VERSION);
    assert_eq!(value["generated_at"], GENERATED_AT);
    let manifest = value["manifest"].as_array().expect("manifest");
    assert_eq!(manifest.len(), 1);
    let entry = &manifest[0];
    assert_eq!(entry["name"], "report");
    assert_eq!(entry["media_type"], REPORT_MEDIA_TYPE);
    assert_eq!(entry["schema_version"], REPORT_SCHEMA_VERSION);
    let report = &value["report"];
    let report_bytes = canonical_json::canonical_json_bytes(report).expect("canonical");
    assert_eq!(entry["size"], json!(report_bytes.len()));
    let digest = canonical_json::semantic_digest(REPORT_MEDIA_TYPE, REPORT_SCHEMA_VERSION, report)
        .expect("digest");
    assert_eq!(entry["digest"], json!(digest));
    assert_eq!(package.report_digest, digest);

    assert_eq!(report["schema_version"], REPORT_SCHEMA_VERSION);
    assert_eq!(report["redaction_profile"], REDACTION_PROFILE);
    assert_eq!(report["trust"]["signed"], false);
    assert_eq!(report["trust"]["statement"], TRUST_STATEMENT);
    assert_eq!(report["completeness"], "complete");
    assert_eq!(report["limitations"], json!([]));
    assert!(package.complete);
    assert!(package.limitations.is_empty());
    assert_eq!(report["tests"]["results"]["status"], "passed");
    assert_eq!(
        report["tests"]["results"]["policy"]["source"],
        "publication"
    );
    assert_eq!(report["simulation"]["base"]["version"], 11);
    assert_eq!(report["simulation"]["candidate"]["etag"], PUBLICATION_ETAG);
    assert_eq!(report["replay"]["result_digest"], SEMANTIC_DIGEST);
    assert_eq!(
        report["validation"]["resource_snapshot"],
        resource_snapshot()
    );
}

#[test]
fn the_same_inputs_produce_the_same_report_bytes() {
    let first = assemble(complete_inputs(), GENERATED_AT).expect("package assembles");
    let second = assemble(complete_inputs(), "2026-10-28T13:30:00Z").expect("package assembles");
    assert_eq!(first.report_digest, second.report_digest);
    let first = package_value(&first.bytes);
    let second = package_value(&second.bytes);
    assert_eq!(first["report"], second["report"]);
    assert_eq!(first["manifest"], second["manifest"]);
    assert_ne!(first["generated_at"], second["generated_at"]);
}

#[test]
fn every_missing_or_incomplete_section_is_a_limitation() {
    let inputs = EvidenceInputs {
        tests: None,
        simulation: None,
        replay: None,
        ..complete_inputs()
    };
    let package = assemble(inputs, GENERATED_AT).expect("package assembles");
    assert!(!package.complete);
    assert_eq!(
        package.limitations,
        vec![
            "replay_not_included",
            "simulation_not_included",
            "tests_not_included"
        ]
    );
    let report = package_value(&package.bytes)["report"].clone();
    assert_eq!(report["completeness"], "incomplete");
    assert_eq!(report["tests"], json!({ "included": false }));
    assert_eq!(report["simulation"], json!({ "included": false }));
    assert_eq!(report["replay"], json!({ "included": false }));

    let incomplete = EvidenceInputs {
        replay: Some(replay_evidence(false)),
        ..complete_inputs()
    };
    let package = assemble(incomplete, GENERATED_AT).expect("package assembles");
    assert_eq!(package.limitations, vec!["replay_incomplete"]);
    assert_eq!(
        package_value(&package.bytes)["report"]["replay"]["predecessor_check"],
        "matches_predecessor"
    );

    // A job that compared the publication with some other base is reported,
    // and its impact is not the publication's own.
    let mut other_base = replay_evidence(true);
    other_base.compared_with_predecessor = false;
    let package = assemble(
        EvidenceInputs {
            replay: Some(other_base),
            ..complete_inputs()
        },
        GENERATED_AT,
    )
    .expect("package assembles");
    assert_eq!(package.limitations, vec!["replay_base_not_predecessor"]);
    assert_eq!(
        package_value(&package.bytes)["report"]["replay"]["predecessor_check"],
        "differs_from_predecessor"
    );

    // A suite whose case the evaluator could not decide never completes
    // evidence; one that decided every case and found a failure does.
    let mut undecided = test_report();
    undecided.status = policy_testing::runner::RunStatus::Incomplete;
    let package = assemble(
        EvidenceInputs {
            tests: Some(undecided),
            ..complete_inputs()
        },
        GENERATED_AT,
    )
    .expect("package assembles");
    assert_eq!(package.limitations, vec!["tests_incomplete"]);
    let mut failed = test_report();
    failed.status = policy_testing::runner::RunStatus::Failed;
    let package = assemble(
        EvidenceInputs {
            tests: Some(failed),
            ..complete_inputs()
        },
        GENERATED_AT,
    )
    .expect("package assembles");
    assert!(
        package.complete,
        "a failed suite is complete evidence of the failure"
    );

    let mut uncompared = simulation_evidence();
    uncompared.compared_with_predecessor = false;
    let package = assemble(
        EvidenceInputs {
            simulation: Some(uncompared),
            ..complete_inputs()
        },
        GENERATED_AT,
    )
    .expect("package assembles");
    assert_eq!(package.limitations, vec!["simulation_base_not_evaluable"]);
    assert_eq!(
        package_value(&package.bytes)["report"]["simulation"]["base"],
        Value::Null
    );
}

#[test]
fn a_document_without_a_semantic_digest_or_predecessor_is_incomplete() {
    let mut inputs = complete_inputs();
    inputs.publication.policy = PolicyIdentity {
        schema_version: "0.1.0".to_owned(),
        etag: PUBLICATION_ETAG.to_owned(),
        semantic_digest: None,
    };
    inputs.predecessor = None;
    let package = assemble(inputs, GENERATED_AT).expect("package assembles");
    assert_eq!(
        package.limitations,
        vec![
            "policy_semantic_digest_unavailable",
            "predecessor_not_in_history"
        ]
    );
    let report = package_value(&package.bytes)["report"].clone();
    assert_eq!(
        report["publication"]["policy"]["semantic_digest"],
        Value::Null
    );
    assert_eq!(report["publication"]["predecessor"], Value::Null);
    assert_eq!(report["publication"]["predecessor_check"], "no_predecessor");
    // The simulation still ran, against the publication alone.
    assert_eq!(report["simulation"]["base"], Value::Null);
}

#[test]
fn the_predecessor_is_checked_against_the_recorded_base() {
    let check = |summary: Value| {
        let mut inputs = complete_inputs();
        inputs.publication.diff_summary = summary;
        let package = assemble(inputs, GENERATED_AT).expect("package assembles");
        let report = package_value(&package.bytes)["report"].clone();
        (
            report["publication"]["predecessor_check"].clone(),
            package.limitations,
        )
    };
    assert_eq!(
        check(draft_summary(PREDECESSOR_ETAG)),
        (json!("matches_recorded_base"), Vec::<&str>::new())
    );
    assert_eq!(
        check(draft_summary(OTHER_ETAG)),
        (
            json!("differs_from_recorded_base"),
            vec!["predecessor_differs_from_recorded_base"]
        )
    );
    assert_eq!(
        check(json!({ "action": "policy_replaced" })),
        (json!("no_recorded_base"), Vec::<&str>::new())
    );
    // A shadow review's reviewed policy is the base its change was bound to.
    assert_eq!(
        check(json!({
            "action": "rule_updated",
            "rule_id": "watched",
            "changed_fields": ["action"],
            "shadow_review": {
                "transition": "promote",
                "policy_etag": OTHER_ETAG,
                "evidence_window": { "from": null, "to": null },
                "evidence_digest": SEMANTIC_DIGEST
            }
        })),
        (
            json!("differs_from_recorded_base"),
            vec!["predecessor_differs_from_recorded_base"]
        )
    );
}

#[test]
fn the_approval_repeats_only_what_the_gateway_records_in_its_own_shapes() {
    let approval = |summary: Value| {
        let mut inputs = complete_inputs();
        inputs.publication.diff_summary = summary;
        let package = assemble(inputs, GENERATED_AT).expect("package assembles");
        let text = String::from_utf8(package.bytes.clone()).expect("UTF-8");
        assert!(
            !text.contains(SUMMARY_CANARY),
            "no unrecognized or unshaped value is repeated"
        );
        package_value(&package.bytes)["report"]["approval"].clone()
    };

    let draft = approval(draft_summary(PREDECESSOR_ETAG));
    assert_eq!(
        draft,
        json!({
            "basis": "authorized_commit",
            "recorded_at": "2026-10-28T11:00:00Z",
            "actor": "withheld",
            "operation": "policy_draft_published",
            "draft": { "revision": 3, "base_etag": PREDECESSOR_ETAG }
        })
    );

    let malformed = approval(json!({
        "action": "policy_draft_published",
        "draft_revision": 3,
        "base_etag": SUMMARY_CANARY,
    }));
    assert!(malformed.get("draft").is_none());

    let unknown = approval(json!({ "action": SUMMARY_CANARY, "note": SUMMARY_CANARY }));
    assert_eq!(unknown["operation"], "unrecognized");
    let unrecorded = approval(json!({ "note": SUMMARY_CANARY }));
    assert_eq!(unrecorded["operation"], "not_recorded");
    let not_an_object = approval(json!(SUMMARY_CANARY));
    assert_eq!(not_an_object["operation"], "not_recorded");

    let rollback = approval(json!({ "action": "policy_rolled_back", "target_version": 7 }));
    assert_eq!(rollback["rollback_target_version"], 7);

    let promotion = approval(json!({
        "action": "rule_updated",
        "rule_id": "watched",
        "changed_fields": [SUMMARY_CANARY],
        "shadow_review": {
            "transition": "promote",
            "policy_etag": PREDECESSOR_ETAG,
            "evidence_window": { "from": SUMMARY_CANARY, "to": null },
            "evidence_digest": SEMANTIC_DIGEST
        }
    }));
    assert_eq!(promotion["rule_id"], "watched");
    assert_eq!(
        promotion["shadow_review"],
        json!({
            "transition": "promote",
            "policy_etag": PREDECESSOR_ETAG,
            "evidence_digest": SEMANTIC_DIGEST
        })
    );
    let long_id = approval(json!({ "action": "rule_created", "rule_id": "r".repeat(129) }));
    assert!(long_id.get("rule_id").is_none());
    let bad_transition = approval(json!({
        "action": "rule_updated",
        "shadow_review": {
            "transition": SUMMARY_CANARY,
            "policy_etag": PREDECESSOR_ETAG,
            "evidence_digest": SEMANTIC_DIGEST
        }
    }));
    assert!(bad_transition.get("shadow_review").is_none());
}

#[test]
fn revalidation_diagnostics_are_bounded_and_can_block_completeness() {
    // A 0.x document without element ids is accepted with warnings, and a
    // warning blocks complete evidence.
    let warned = validation_of(&json!({
        "schema_version": "0.1.0",
        "rules": [{ "path": "/x", "action": "deny" }]
    }));
    assert!(warned.valid);
    assert!(warned
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.blocks.evidence));
    let package = assemble(
        EvidenceInputs {
            validation: warned,
            ..complete_inputs()
        },
        GENERATED_AT,
    )
    .expect("package assembles");
    assert_eq!(package.limitations, vec!["validation_blocks_evidence"]);
    let report = package_value(&package.bytes)["report"].clone();
    assert_eq!(report["validation"]["basis"], "revalidated_by_this_build");
    assert_eq!(report["validation"]["valid"], true);
    assert_eq!(report["validation"]["diagnostics_truncated"], false);

    let one = validation_of(&json!({
        "schema_version": "0.1.0",
        "rules": [{ "path": "/x", "action": "deny" }]
    }))
    .diagnostics
    .remove(0);
    let many = ValidationOutcome {
        valid: true,
        diagnostics: vec![one; MAX_EVIDENCE_DIAGNOSTICS + 1],
        resource_snapshot: Some(resource_snapshot()),
    };
    let package = assemble(
        EvidenceInputs {
            validation: many,
            ..complete_inputs()
        },
        GENERATED_AT,
    )
    .expect("package assembles");
    assert_eq!(
        package.limitations,
        vec![
            "validation_blocks_evidence",
            "validation_diagnostics_truncated"
        ]
    );
    let report = package_value(&package.bytes)["report"].clone();
    assert_eq!(
        report["validation"]["diagnostics"].as_array().map(Vec::len),
        Some(MAX_EVIDENCE_DIAGNOSTICS)
    );
    assert_eq!(report["validation"]["diagnostics_truncated"], true);
}

#[test]
fn every_limitation_a_report_states_is_a_documented_code() {
    let mut inputs = complete_inputs();
    inputs.publication.policy.semantic_digest = None;
    inputs.publication.diff_summary = draft_summary(OTHER_ETAG);
    inputs.tests = None;
    inputs.simulation = None;
    inputs.replay = Some(replay_evidence(false));
    let package = assemble(inputs, GENERATED_AT).expect("package assembles");
    let mut sorted = package.limitations.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, package.limitations, "limitations are sorted");
    for code in &package.limitations {
        assert!(LIMITATION_CODES.contains(code), "{code} is documented");
    }
    let docs = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/policy-evidence.md"),
    )
    .expect("the evidence documentation is readable");
    for code in LIMITATION_CODES {
        assert!(
            docs.contains(&format!("`{code}`")),
            "{code} is documented in docs/policy-evidence.md"
        );
    }
}

#[test]
fn a_report_repeats_no_fixture_value() {
    let package = assemble(complete_inputs(), GENERATED_AT).expect("package assembles");
    let text = String::from_utf8(package.bytes).expect("UTF-8");
    for canary in [SUBJECT_CANARY, PATH_CANARY, SUMMARY_CANARY] {
        assert!(!text.contains(canary), "{canary} is not repeated");
    }
}

#[test]
fn an_oversized_package_is_refused_whole() {
    let oversized = ReplayEvidence {
        complete: true,
        compared_with_predecessor: true,
        view: json!({
            "included": true,
            "result": "x".repeat(super::MAX_PACKAGE_BYTES)
        }),
    };
    let error = assemble(
        EvidenceInputs {
            replay: Some(oversized),
            ..complete_inputs()
        },
        GENERATED_AT,
    )
    .expect_err("an oversized package is refused");
    assert_eq!(error, PackageError::TooLarge);
}

fn published_schema(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/schemas")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

/// The published request schema and the parser agree on the requests both can
/// judge: every request the parser accepts here, the schema accepts, and the
/// refusals JSON Schema can express are refused by both.
#[test]
fn the_published_request_schema_agrees_with_the_parser() {
    let schema = published_schema("policy-evidence-request.v1.schema.json");
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let minimal = json!({
        "schema_version": REQUEST_SCHEMA_VERSION,
        "publication": { "version": 1 }
    });
    let mut cases_only = minimal.clone();
    cases_only["simulation"] = json!({ "cases": simulation_cases() });
    for request in [full_request(), minimal.clone(), cases_only] {
        parsed(&request);
        if let Err(error) = validator.validate(&request) {
            panic!("the schema refuses an accepted request: {error}\n{request}");
        }
    }

    let mut refusals = Vec::new();
    let mut variant = |change: &dyn Fn(&mut Value)| {
        let mut request = full_request();
        change(&mut request);
        refusals.push(request);
    };
    variant(&|request| request["schema_version"] = json!("policy-evidence-request.v2"));
    variant(&|request| {
        if let Some(members) = request.as_object_mut() {
            members.remove("publication");
        }
    });
    variant(&|request| request["signature"] = json!("self-asserted"));
    variant(&|request| request["publication"]["digest"] = json!(SEMANTIC_DIGEST));
    variant(&|request| request["publication"]["version"] = json!(0));
    variant(&|request| request["publication"]["version"] = json!(9_007_199_254_740_992_u64));
    variant(&|request| request["publication"]["etag"] = json!(""));
    variant(&|request| request["simulation"]["trace"] = json!("full"));
    variant(&|request| {
        request["simulation"]["projections"] = json!(["as_authored", "as_authored"]);
    });
    variant(&|request| request["simulation"]["cases"] = json!([]));
    variant(&|request| request["simulation"]["base_etag"] = json!(OTHER_ETAG));
    variant(&|request| request["suite"] = Value::Null);
    variant(&|request| request["replay_job_id"] = json!(""));
    variant(&|request| request["replay_job_id"] = json!("r".repeat(65)));
    for request in refusals {
        assert!(parse_request(&request).is_err(), "parser: {request}");
        assert!(!validator.is_valid(&request), "schema: {request}");
    }
}

/// Every package the assembler produces is one the published package schema
/// describes.
#[test]
fn a_package_matches_the_published_package_schema() {
    let schema = published_schema("policy-evidence.v1.schema.json");
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let mut bare = complete_inputs();
    bare.publication.policy.semantic_digest = None;
    bare.publication.diff_summary = json!({ "action": "policy_rolled_back", "target_version": 7 });
    bare.predecessor = None;
    bare.tests = None;
    bare.simulation = None;
    bare.replay = None;
    let mut uncompared = complete_inputs();
    if let Some(simulation) = uncompared.simulation.as_mut() {
        simulation.compared_with_predecessor = false;
    }
    uncompared.replay = Some(replay_evidence(false));
    for inputs in [complete_inputs(), bare, uncompared] {
        let package = assemble(inputs, GENERATED_AT).expect("package assembles");
        let value = package_value(&package.bytes);
        let errors = validator
            .iter_errors(&value)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        assert!(errors.is_empty(), "{errors:?}");
    }
}
