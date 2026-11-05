//! The evidence request parser, the package assembler and the Markdown
//! renderer, without the admin API. The endpoint, its authorization, its
//! history, draft and replay bindings and its audit record are covered in
//! `admin_policy_evidence_tests`.

use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

use serde_json::{json, Value};

use super::{
    markdown::{code_span, render, MarkdownError},
    package::{
        assemble, AnalysisEvidence, CandidateRecord, DraftRecord, EvidenceInputs, PackageError,
        PolicyIdentity, PredecessorRecord, PublicationRecord, ReplayEvidence, SimulationEvidence,
        ValidationOutcome, ANALYSIS_ARTIFACT, MARKDOWN_ARTIFACT, REPORT_ARTIFACT,
    },
    request::{parse_request, CandidateSelector, EvidenceRequest},
    ANALYSIS_MEDIA_TYPE, DRAFT_TRUST_STATEMENT, LIMITATION_CODES, MARKDOWN_MEDIA_TYPE,
    MARKDOWN_SCHEMA_VERSION, MAX_EVIDENCE_DIAGNOSTICS, PACKAGE_SCHEMA_VERSION, REDACTION_PROFILE,
    REPORT_MEDIA_TYPE, REPORT_SCHEMA_VERSION, REQUEST_SCHEMA_VERSION, TRUST_STATEMENT,
};
use crate::{
    canonical_json,
    policy_analysis::{
        checks::{analyze, AnalysisResources},
        report::{to_json as analysis_json, AnalysisBinding},
        suppression::{apply, Suppression, SuppressionBinding, SuppressionRead},
        FindingCode, RESULT_SCHEMA_VERSION as ANALYSIS_SCHEMA_VERSION,
    },
    policy_eval::PolicyAuthority,
    policy_simulation::{
        request::StoredCandidate,
        run::{compile_pairs, simulate},
        Projection, TraceLevel,
    },
    policy_testing::{
        self,
        report::{PolicyBinding, PolicySource, RunReport},
        suite::{parse_suite, Diagnostics},
    },
    rbac::{
        policy_document::inspect_source,
        policy_resources::{PolicyResourceSnapshot, PolicyResourceView},
        Policy,
    },
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
const DRAFT_ETAG: &str =
    "\"sha256:5555555555555555555555555555555555555555555555555555555555555555\"";
const DRAFT_ID: &str = "pd_0123456789abcdef0123456789abcdef";
const SUPPRESSION_ID: &str = "pas_0123456789abcdef0123456789abcdef";
const GENERATED_AT: &str = "2026-10-28T12:00:00Z";

fn publication_document() -> Value {
    json!({
        "schema_version": "1.0.0",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": { "reader": { "permissions": ["orders:read"] } },
        "rules": [
            { "id": "public", "methods": ["GET"], "path": "/public/**", "action": "allow" },
            { "id": "lockdown", "methods": ["GET"], "path": "/orders/restricted", "action": "deny" },
            // A duplicate of `public`, so the analyzer has a proven finding.
            { "id": "public-copy", "methods": ["GET"], "path": "/public/**", "action": "allow" }
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
        "replay_job_id": "rpl_0123456789abcdef0123456789abcdef",
        "analysis": true
    })
}

fn draft_request() -> Value {
    let mut request = full_request();
    if let Some(members) = request.as_object_mut() {
        members.remove("publication");
    }
    request["draft"] = json!({ "draft_id": DRAFT_ID, "draft_etag": DRAFT_ETAG });
    request
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

/// The publication a request names; a panic for a draft request.
fn publication_of(request: &EvidenceRequest) -> (i64, Option<&str>) {
    match &request.candidate {
        CandidateSelector::Publication(selector) => (selector.version, selector.etag.as_deref()),
        CandidateSelector::Draft(_) => panic!("the request names a draft"),
    }
}

#[test]
fn a_full_request_parses_and_its_digest_ignores_representation() {
    let request = parsed(&full_request());
    assert_eq!(publication_of(&request), (12, Some(PUBLICATION_ETAG)));
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
    assert!(request.analysis);
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
    let mut unanalyzed = full_request();
    unanalyzed["analysis"] = json!(false);
    let unanalyzed = parsed(&unanalyzed);
    assert!(!unanalyzed.analysis);
    assert_ne!(unanalyzed.digest, request.digest);
}

#[test]
fn only_the_candidate_is_required() {
    let request = parsed(&json!({
        "schema_version": REQUEST_SCHEMA_VERSION,
        "publication": { "version": 1 }
    }));
    assert_eq!(publication_of(&request), (1, None));
    assert!(request.suite.is_none());
    assert!(request.simulation.is_none());
    assert!(request.replay_job_id.is_none());
    assert!(!request.analysis);
    assert!(!request.evaluates_synthetic_cases());

    let draft = parsed(&json!({
        "schema_version": REQUEST_SCHEMA_VERSION,
        "draft": { "draft_id": DRAFT_ID, "draft_etag": DRAFT_ETAG }
    }));
    let CandidateSelector::Draft(selector) = &draft.candidate else {
        panic!("the request names a draft");
    };
    assert_eq!(selector.draft_id, DRAFT_ID);
    assert_eq!(selector.draft_etag, DRAFT_ETAG);
    assert!(!draft.analysis);

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
fn a_request_names_exactly_one_candidate() {
    let diagnostics = refused(&json!({ "schema_version": REQUEST_SCHEMA_VERSION }));
    assert!(has(&diagnostics, "missing_field", "/publication"));

    let mut both = full_request();
    both["draft"] = json!({ "draft_id": DRAFT_ID, "draft_etag": DRAFT_ETAG });
    let diagnostics = refused(&both);
    assert!(has(&diagnostics, "conflicting_field", "/draft"));

    let mut request = draft_request();
    request["draft"] = json!({ "draft_id": DRAFT_ID });
    assert!(has(
        &refused(&request),
        "missing_field",
        "/draft/draft_etag"
    ));
    request["draft"] = json!({ "draft_etag": DRAFT_ETAG });
    assert!(has(&refused(&request), "missing_field", "/draft/draft_id"));
    request["draft"] = json!({
        "draft_id": DRAFT_ID,
        "draft_etag": DRAFT_ETAG,
        "base_etag": PREDECESSOR_ETAG
    });
    assert!(has(&refused(&request), "unknown_field", "/draft/base_etag"));
    request["draft"] = json!({ "draft_id": "d".repeat(65), "draft_etag": DRAFT_ETAG });
    assert!(has(&refused(&request), "too_long", "/draft/draft_id"));
    request["draft"] = json!({ "draft_id": DRAFT_ID, "draft_etag": "e".repeat(257) });
    assert!(has(&refused(&request), "too_long", "/draft/draft_etag"));
    request["draft"] = Value::Null;
    assert!(has(&refused(&request), "invalid_type", "/draft"));

    let mut analysis = full_request();
    analysis["analysis"] = json!("yes");
    assert!(has(&refused(&analysis), "invalid_type", "/analysis"));
    analysis["analysis"] = Value::Null;
    assert!(has(&refused(&analysis), "invalid_type", "/analysis"));
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
    assert_eq!(publication_of(&largest).0, 9_007_199_254_740_991);

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

fn test_report(source: PolicySource) -> RunReport {
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
            source,
            etag: PUBLICATION_ETAG.to_owned(),
            security_revision: None,
            stored: None,
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
            "base": { "source": "active", "etag": PREDECESSOR_ETAG },
            "candidate": { "source": "active", "etag": PUBLICATION_ETAG },
            "window": { "from": "2026-10-28T10:00:00Z", "to": null },
            "result_digest": SEMANTIC_DIGEST,
            "result": { "records": { "replayable": 3 } }
        }),
    }
}

/// The suppression record naming the publication's `public-copy` finding,
/// bound exactly to what [`analysis_evidence`] analyzes.
fn suppression_of_duplicate(ended: bool) -> Suppression {
    let outcome = analyze(
        &policy(publication_document()),
        &AnalysisResources {
            mcp_alias_paths: &[],
        },
        Instant::now() + Duration::from_secs(5),
    )
    .expect("analysis runs");
    let finding = outcome
        .findings
        .iter()
        .find(|finding| finding.code == FindingCode::RuleUnreachable)
        .expect("the duplicate rule is found");
    Suppression {
        id: SUPPRESSION_ID.to_owned(),
        fingerprint: finding.fingerprint().expect("fingerprint"),
        code: finding.code.as_str().to_owned(),
        policy_etag: PUBLICATION_ETAG.to_owned(),
        policy_semantic_digest: Some(SEMANTIC_DIGEST.to_owned()),
        resource_snapshot_digest: SEMANTIC_DIGEST.to_owned(),
        created_at: 1,
        ended,
    }
}

/// The analyzer's results over the publication document, as the endpoint
/// renders them: `stored` names it, `read` holds the suppression records.
fn analysis_evidence(stored: &StoredCandidate, read: &SuppressionRead) -> AnalysisEvidence {
    let outcome = analyze(
        &policy(publication_document()),
        &AnalysisResources {
            mcp_alias_paths: &[],
        },
        Instant::now() + Duration::from_secs(5),
    )
    .expect("analysis runs");
    let suppressions = apply(
        &outcome.findings,
        read,
        &SuppressionBinding {
            policy_etag: PUBLICATION_ETAG,
            policy_semantic_digest: Some(SEMANTIC_DIGEST),
            resource_snapshot_digest: Some(SEMANTIC_DIGEST),
        },
    )
    .expect("suppressions apply");
    let snapshot = PolicyResourceSnapshot::of(&PolicyResourceView::default());
    let request_digest = parsed(&full_request()).digest;
    let results = analysis_json(
        &outcome,
        &AnalysisBinding {
            request_digest: &request_digest,
            base_etag: None,
            security_revision: None,
            source: match stored {
                StoredCandidate::Draft { .. } => "draft",
                StoredCandidate::Revision { .. } => "revision",
            },
            analyzed_etag: PUBLICATION_ETAG,
            analyzed_semantic_digest: Some(SEMANTIC_DIGEST),
            edit_count: 0,
            stored: Some(stored),
            mcp_alias_paths: 0,
            resource_snapshot: &snapshot,
        },
        &suppressions,
    )
    .expect("analysis renders");
    AnalysisEvidence { results }
}

fn publication_analysis() -> AnalysisEvidence {
    analysis_evidence(
        &StoredCandidate::Revision { version: 12 },
        &SuppressionRead::Available(vec![suppression_of_duplicate(false)]),
    )
}

fn publication_candidate() -> CandidateRecord {
    CandidateRecord::Publication {
        record: PublicationRecord {
            version: 12,
            recorded_at: "2026-10-28T11:00:00Z".to_owned(),
            diff_summary: draft_summary(PREDECESSOR_ETAG),
            policy: identity(PUBLICATION_ETAG, Some(SEMANTIC_DIGEST)),
        },
        predecessor: Some(PredecessorRecord {
            version: 11,
            policy: identity(PREDECESSOR_ETAG, Some(SEMANTIC_DIGEST)),
        }),
    }
}

/// Every section present and complete: the only shape a complete report has.
fn complete_inputs() -> EvidenceInputs {
    EvidenceInputs {
        request_digest: parsed(&full_request()).digest,
        candidate: publication_candidate(),
        validation: validation_of(&publication_document()),
        tests: Some(test_report(PolicySource::Publication)),
        simulation: Some(simulation_evidence()),
        replay: Some(replay_evidence(true)),
        analysis: Some(publication_analysis()),
    }
}

/// The same sections about a draft pinned to the live policy.
fn draft_inputs() -> EvidenceInputs {
    EvidenceInputs {
        request_digest: parsed(&draft_request()).digest,
        candidate: CandidateRecord::Draft(DraftRecord {
            draft_id: DRAFT_ID.to_owned(),
            revision: 3,
            draft_etag: DRAFT_ETAG.to_owned(),
            policy: identity(PUBLICATION_ETAG, Some(SEMANTIC_DIGEST)),
            base: identity(PREDECESSOR_ETAG, Some(SEMANTIC_DIGEST)),
        }),
        tests: Some(test_report(PolicySource::Draft)),
        analysis: Some(analysis_evidence(
            &StoredCandidate::Draft {
                draft_id: DRAFT_ID.to_owned(),
                revision: 3,
            },
            &SuppressionRead::Available(vec![suppression_of_duplicate(false)]),
        )),
        ..complete_inputs()
    }
}

/// `inputs` with its publication changed by `change`.
fn with_publication(
    mut inputs: EvidenceInputs,
    change: impl FnOnce(&mut PublicationRecord, &mut Option<PredecessorRecord>),
) -> EvidenceInputs {
    let CandidateRecord::Publication {
        record,
        predecessor,
    } = &mut inputs.candidate
    else {
        panic!("the inputs are a publication's");
    };
    change(record, predecessor);
    inputs
}

fn package_value(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("a package is JSON")
}

fn report_of(inputs: EvidenceInputs) -> Value {
    let package = assemble(inputs, GENERATED_AT).expect("package assembles");
    package_value(&package.bytes)["report"].clone()
}

#[test]
fn a_package_is_canonical_and_its_manifest_binds_every_artifact() {
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
    let names = manifest
        .iter()
        .map(|entry| entry["name"].as_str().expect("a name"))
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![REPORT_ARTIFACT, ANALYSIS_ARTIFACT, MARKDOWN_ARTIFACT]
    );

    // The report: a semantic digest over its JCS bytes.
    let report = &value["report"];
    let report_bytes = canonical_json::canonical_json_bytes(report).expect("canonical");
    let entry = &manifest[0];
    assert_eq!(entry["media_type"], REPORT_MEDIA_TYPE);
    assert_eq!(entry["schema_version"], REPORT_SCHEMA_VERSION);
    assert_eq!(entry["size"], json!(report_bytes.len()));
    let digest = canonical_json::semantic_digest(REPORT_MEDIA_TYPE, REPORT_SCHEMA_VERSION, report)
        .expect("digest");
    assert_eq!(entry["digest"], json!(digest));
    assert_eq!(package.report_digest, digest);

    // The analysis: the analyzer's own results document, bound by the
    // manifest and by the report, which repeats the entry.
    let analysis = &value["analysis"];
    let entry = &manifest[1];
    assert_eq!(entry["media_type"], ANALYSIS_MEDIA_TYPE);
    assert_eq!(entry["schema_version"], ANALYSIS_SCHEMA_VERSION);
    assert_eq!(analysis, &publication_analysis().results);
    let analysis_digest =
        canonical_json::semantic_digest(ANALYSIS_MEDIA_TYPE, ANALYSIS_SCHEMA_VERSION, analysis)
            .expect("digest");
    assert_eq!(entry["digest"], json!(analysis_digest));
    assert_eq!(
        entry["size"],
        json!(canonical_json::canonical_json_bytes(analysis)
            .expect("canonical")
            .len())
    );
    assert_eq!(
        package.analysis_digest.as_deref(),
        Some(analysis_digest.as_str())
    );
    assert_eq!(&report["analysis"]["artifact"], entry);
    assert!(
        analysis.get("base").is_none(),
        "no active policy was pinned"
    );
    assert_eq!(analysis["analyzed"]["source"], "revision");
    assert_eq!(analysis["analyzed"]["version"], 12);

    // The Markdown: a source digest over its UTF-8 bytes, rendered from the
    // report's JCS bytes alone.
    let markdown = value[MARKDOWN_ARTIFACT].as_str().expect("Markdown text");
    let entry = &manifest[2];
    assert_eq!(entry["media_type"], MARKDOWN_MEDIA_TYPE);
    assert_eq!(entry["schema_version"], MARKDOWN_SCHEMA_VERSION);
    assert_eq!(entry["size"], json!(markdown.len()));
    let markdown_digest = canonical_json::source_digest(
        MARKDOWN_MEDIA_TYPE,
        MARKDOWN_SCHEMA_VERSION,
        markdown.as_bytes(),
    );
    assert_eq!(entry["digest"], json!(markdown_digest));
    assert_eq!(package.markdown_digest, markdown_digest);
    assert_eq!(render(&report_bytes).expect("renders"), markdown);

    assert_eq!(report["schema_version"], REPORT_SCHEMA_VERSION);
    assert_eq!(report["redaction_profile"], REDACTION_PROFILE);
    assert_eq!(report["candidate_kind"], "publication");
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
fn the_same_inputs_produce_byte_identical_packages_across_runs_and_threads() {
    let first = assemble(complete_inputs(), GENERATED_AT).expect("package assembles");
    // Each worker evaluates the suite, the cases and the analysis itself,
    // concurrently with the others.
    let concurrent = std::thread::scope(|scope| {
        let workers = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    assemble(complete_inputs(), GENERATED_AT)
                        .expect("package assembles")
                        .bytes
                })
            })
            .collect::<Vec<_>>();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("worker finishes"))
            .collect::<Vec<_>>()
    });
    for bytes in &concurrent {
        assert_eq!(bytes, &first.bytes, "byte-identical package");
    }
    let drafts = std::thread::scope(|scope| {
        let workers = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    assemble(draft_inputs(), GENERATED_AT)
                        .expect("package assembles")
                        .bytes
                })
            })
            .collect::<Vec<_>>();
        workers
            .into_iter()
            .map(|worker| worker.join().expect("worker finishes"))
            .collect::<Vec<_>>()
    });
    assert_eq!(drafts[0], drafts[1], "byte-identical draft package");

    // A later export differs only in when it was generated.
    let later = assemble(complete_inputs(), "2026-10-28T13:30:00Z").expect("package assembles");
    assert_eq!(first.report_digest, later.report_digest);
    assert_eq!(first.analysis_digest, later.analysis_digest);
    assert_eq!(first.markdown_digest, later.markdown_digest);
    let mut first = package_value(&first.bytes);
    let mut later = package_value(&later.bytes);
    assert_ne!(first["generated_at"], later["generated_at"]);
    first["generated_at"] = Value::Null;
    later["generated_at"] = Value::Null;
    assert_eq!(first, later);
}

#[test]
fn every_missing_or_incomplete_section_is_a_limitation() {
    let inputs = EvidenceInputs {
        tests: None,
        simulation: None,
        replay: None,
        analysis: None,
        ..complete_inputs()
    };
    let package = assemble(inputs, GENERATED_AT).expect("package assembles");
    assert!(!package.complete);
    assert_eq!(
        package.limitations,
        vec![
            "analysis_not_included",
            "replay_not_included",
            "simulation_not_included",
            "tests_not_included"
        ]
    );
    assert!(package.analysis_digest.is_none());
    let value = package_value(&package.bytes);
    assert!(value.get(ANALYSIS_ARTIFACT).is_none());
    assert_eq!(
        value["manifest"]
            .as_array()
            .expect("manifest")
            .iter()
            .map(|entry| entry["name"].clone())
            .collect::<Vec<_>>(),
        vec![json!(REPORT_ARTIFACT), json!(MARKDOWN_ARTIFACT)]
    );
    let report = &value["report"];
    assert_eq!(report["completeness"], "incomplete");
    assert_eq!(report["tests"], json!({ "included": false }));
    assert_eq!(report["simulation"], json!({ "included": false }));
    assert_eq!(report["replay"], json!({ "included": false }));
    assert_eq!(report["analysis"], json!({ "included": false }));

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
    let mut undecided = test_report(PolicySource::Publication);
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
    let mut failed = test_report(PolicySource::Publication);
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
fn the_analysis_section_reports_findings_proof_basis_suppressions_and_completeness() {
    let report = report_of(complete_inputs());
    let analysis = &report["analysis"];
    assert_eq!(analysis["included"], true);
    assert_eq!(analysis["complete"], true);
    assert_eq!(analysis["limitations"], json!([]));
    assert_eq!(analysis["analyzer"]["version"], "gg-policy-analyzer-v1");
    assert_eq!(analysis["analyzed"]["etag"], PUBLICATION_ETAG);
    assert_eq!(
        analysis["suppressions"],
        json!({ "available": true, "records": 1 })
    );
    let findings = analysis["findings"].as_array().expect("findings");
    let duplicate = findings
        .iter()
        .find(|finding| finding["code"] == "rule_unreachable")
        .expect("the duplicate rule is reported");
    assert_eq!(duplicate["proof_basis"], "proven");
    assert_eq!(duplicate["element"]["id"], "public-copy");
    assert_eq!(duplicate["element"]["pointer"], "/rules/2");
    assert_eq!(
        duplicate["suppression"],
        json!({ "state": "suppressed", "suppression_id": SUPPRESSION_ID })
    );
    assert!(duplicate["fingerprint"]
        .as_str()
        .is_some_and(|fingerprint| fingerprint.starts_with("sha256:")));
    // A suppressed finding is still reported and counted.
    assert_eq!(analysis["summary"]["by_suppression_state"]["suppressed"], 1);
    // What the report leaves to the artifact.
    for member in [
        "rationale",
        "remediation",
        "patch",
        "details",
        "never_decides_in",
    ] {
        assert!(
            duplicate.get(member).is_none(),
            "{member} stays in the artifact"
        );
    }

    // An ended suppression hides nothing.
    let expired = analysis_evidence(
        &StoredCandidate::Revision { version: 12 },
        &SuppressionRead::Available(vec![suppression_of_duplicate(true)]),
    );
    let report = report_of(EvidenceInputs {
        analysis: Some(expired),
        ..complete_inputs()
    });
    let duplicate = report["analysis"]["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .find(|finding| finding["code"] == "rule_unreachable")
        .cloned()
        .expect("still reported");
    assert_eq!(duplicate["suppression"]["state"], "suppression_expired");
    assert_eq!(report["completeness"], "complete");

    // Records that could not be read suppress nothing, and the package is
    // incomplete: no finding's state is known.
    let unread = analysis_evidence(
        &StoredCandidate::Revision { version: 12 },
        &SuppressionRead::Unavailable,
    );
    let package = assemble(
        EvidenceInputs {
            analysis: Some(unread),
            ..complete_inputs()
        },
        GENERATED_AT,
    )
    .expect("package assembles");
    assert_eq!(
        package.limitations,
        vec!["analysis_suppressions_unavailable"]
    );
    let report = package_value(&package.bytes)["report"].clone();
    assert_eq!(report["analysis"]["suppressions"]["available"], false);
    assert!(report["analysis"]["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .all(|finding| finding["suppression"].is_null()));

    // An analysis that ran out of its budget says nothing about the rest.
    let mut truncated = publication_analysis();
    truncated.results["complete"] = json!(false);
    truncated.results["limitations"] = json!(["deadline_exceeded"]);
    let package = assemble(
        EvidenceInputs {
            analysis: Some(truncated),
            ..complete_inputs()
        },
        GENERATED_AT,
    )
    .expect("package assembles");
    assert_eq!(package.limitations, vec!["analysis_incomplete"]);
    let report = package_value(&package.bytes)["report"].clone();
    assert_eq!(
        report["analysis"]["limitations"],
        json!(["deadline_exceeded"])
    );

    // Results without a member the report repeats are no package at all.
    let mut malformed = publication_analysis();
    if let Some(results) = malformed.results.as_object_mut() {
        results.remove("findings");
    }
    let error = assemble(
        EvidenceInputs {
            analysis: Some(malformed),
            ..complete_inputs()
        },
        GENERATED_AT,
    )
    .expect_err("refused");
    assert_eq!(error, PackageError::Encoding);
}

#[test]
fn a_draft_package_is_labelled_and_never_presented_as_a_publication() {
    let package = assemble(draft_inputs(), GENERATED_AT).expect("package assembles");
    assert!(package.complete, "{:?}", package.limitations);
    let value = package_value(&package.bytes);
    let report = &value["report"];
    assert_eq!(report["candidate_kind"], "draft");
    assert!(report.get("publication").is_none());
    assert!(report.get("approval").is_none());
    assert_eq!(
        report["draft"],
        json!({
            "draft_id": DRAFT_ID,
            "revision": 3,
            "draft_etag": DRAFT_ETAG,
            "policy": {
                "schema_version": "1.0.0",
                "etag": PUBLICATION_ETAG,
                "semantic_digest": SEMANTIC_DIGEST
            },
            "base": {
                "source": "active",
                "policy": {
                    "schema_version": "1.0.0",
                    "etag": PREDECESSOR_ETAG,
                    "semantic_digest": SEMANTIC_DIGEST
                }
            }
        })
    );
    assert_eq!(report["trust"]["statement"], DRAFT_TRUST_STATEMENT);
    assert_eq!(report["tests"]["results"]["policy"]["source"], "draft");
    assert_eq!(
        report["simulation"]["base"],
        json!({ "etag": PREDECESSOR_ETAG })
    );
    assert_eq!(
        report["simulation"]["candidate"],
        json!({ "draft_revision": 3, "etag": PUBLICATION_ETAG })
    );
    assert_eq!(report["replay"]["predecessor_check"], "matches_predecessor");
    assert_eq!(value["analysis"]["analyzed"]["source"], "draft");
    assert_eq!(value["analysis"]["analyzed"]["draft_id"], DRAFT_ID);

    let markdown = value[MARKDOWN_ARTIFACT].as_str().expect("Markdown");
    assert!(markdown.contains(DRAFT_TRUST_STATEMENT));
    assert!(!markdown.contains(TRUST_STATEMENT));
    assert!(markdown.contains("\n## Draft\n"));
    assert!(!markdown.contains("Publication"));
    assert!(!markdown.contains("Approval"));

    // What the draft replaces is always known; one that no longer compiles
    // leaves the cases judged under the draft alone.
    let mut uncompared = simulation_evidence();
    uncompared.compared_with_predecessor = false;
    let package = assemble(
        EvidenceInputs {
            simulation: Some(uncompared),
            ..draft_inputs()
        },
        GENERATED_AT,
    )
    .expect("package assembles");
    assert_eq!(package.limitations, vec!["simulation_base_not_evaluable"]);
}

#[test]
fn a_document_without_a_semantic_digest_or_predecessor_is_incomplete() {
    let inputs = with_publication(complete_inputs(), |record, predecessor| {
        record.policy = PolicyIdentity {
            schema_version: "0.1.0".to_owned(),
            etag: PUBLICATION_ETAG.to_owned(),
            semantic_digest: None,
        };
        *predecessor = None;
    });
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
    assert_eq!(report["replay"]["predecessor_check"], "no_predecessor");
}

#[test]
fn the_predecessor_is_checked_against_the_recorded_base() {
    let check = |summary: Value| {
        let inputs = with_publication(complete_inputs(), |record, _| {
            record.diff_summary = summary;
        });
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
        let inputs = with_publication(complete_inputs(), |record, _| {
            record.diff_summary = summary;
        });
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
    let mut inputs = with_publication(complete_inputs(), |record, _| {
        record.policy.semantic_digest = None;
        record.diff_summary = draft_summary(OTHER_ETAG);
    });
    inputs.tests = None;
    inputs.simulation = None;
    inputs.replay = Some(replay_evidence(false));
    inputs.analysis = Some(analysis_evidence(
        &StoredCandidate::Revision { version: 12 },
        &SuppressionRead::Unavailable,
    ));
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
    let schema = published_schema("policy-evidence.v1.schema.json");
    let listed = schema
        .pointer("/$defs/report/properties/limitations/items/enum")
        .and_then(Value::as_array)
        .expect("the schema lists the limitation codes");
    assert_eq!(
        listed.iter().filter_map(Value::as_str).collect::<Vec<_>>(),
        LIMITATION_CODES.to_vec(),
        "the schema lists exactly the codes, in the same order"
    );
}

#[test]
fn a_report_repeats_no_fixture_value() {
    for inputs in [complete_inputs(), draft_inputs()] {
        let package = assemble(inputs, GENERATED_AT).expect("package assembles");
        let text = String::from_utf8(package.bytes).expect("UTF-8");
        for canary in [SUBJECT_CANARY, PATH_CANARY, SUMMARY_CANARY] {
            assert!(!text.contains(canary), "{canary} is not repeated");
        }
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

    let mut oversized = publication_analysis();
    oversized.results["padding"] = json!("x".repeat(super::MAX_PACKAGE_BYTES));
    let error = assemble(
        EvidenceInputs {
            analysis: Some(oversized),
            ..complete_inputs()
        },
        GENERATED_AT,
    )
    .expect_err("an oversized analysis is refused");
    assert_eq!(error, PackageError::TooLarge);
}

/// The content of every inline code span in `markdown`, its `\u{XXXX}`
/// notation undone; every line's spans are closed.
fn code_spans(markdown: &str) -> Vec<String> {
    let mut spans = Vec::new();
    for line in markdown.lines() {
        let parts = line.split('`').collect::<Vec<_>>();
        assert_eq!(parts.len() % 2, 1, "every code span is closed: {line}");
        for part in parts.iter().skip(1).step_by(2) {
            spans.push(unescape(part));
        }
    }
    spans
}

/// `markdown` without its code spans: the template's own text.
fn template_text(markdown: &str) -> String {
    markdown
        .lines()
        .map(|line| line.split('`').step_by(2).collect::<Vec<_>>().join("VALUE"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn unescape(text: &str) -> String {
    let mut unescaped = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("\\u{") {
        unescaped.push_str(&rest[..start]);
        let after = &rest[start + 3..];
        let end = after.find('}').expect("the notation is closed");
        let code = u32::from_str_radix(&after[..end], 16).expect("hexadecimal");
        unescaped.push(char::from_u32(code).expect("a character"));
        rest = &after[end + 1..];
    }
    unescaped.push_str(rest);
    unescaped
}

/// Every scalar `value` holds, as the template would write it.
fn scalar_leaves(value: &Value, leaves: &mut BTreeSet<String>) {
    match value {
        Value::Null => {}
        Value::Bool(flag) => {
            leaves.insert(flag.to_string());
        }
        Value::Number(number) => {
            leaves.insert(number.to_string());
        }
        Value::String(text) => {
            leaves.insert(text.clone());
        }
        Value::Array(items) => {
            for item in items {
                scalar_leaves(item, leaves);
            }
        }
        Value::Object(members) => {
            for member in members.values() {
                scalar_leaves(member, leaves);
            }
        }
    }
}

#[test]
fn the_markdown_carries_no_value_the_report_does_not_hold() {
    for inputs in [complete_inputs(), draft_inputs()] {
        let package = assemble(inputs, GENERATED_AT).expect("package assembles");
        let value = package_value(&package.bytes);
        let report = &value["report"];
        let markdown = value[MARKDOWN_ARTIFACT].as_str().expect("Markdown");
        let mut leaves = BTreeSet::new();
        scalar_leaves(report, &mut leaves);
        let spans = code_spans(markdown);
        assert!(spans.len() > 40, "the template repeats the report's values");
        for span in &spans {
            assert!(leaves.contains(span), "{span:?} is a value of the report");
        }
        // Everything else is the template's own text: no digest, ETag, id or
        // code is written outside a span.
        let template = template_text(markdown);
        for data in ["sha256:", "public-copy", "rule_unreachable", DRAFT_ID] {
            assert!(!template.contains(data), "{data} appears only as a value");
        }
        // The artifact's texts are not in the report, so not here either.
        assert!(!markdown.contains(FindingCode::RuleUnreachable.rationale()));
        assert!(!markdown.contains(FindingCode::RuleUnreachable.remediation()));
        for canary in [SUBJECT_CANARY, PATH_CANARY, SUMMARY_CANARY] {
            assert!(!markdown.contains(canary));
        }
    }

    // A member the template does not name is never rendered, wherever the
    // report holds it.
    let package = assemble(complete_inputs(), GENERATED_AT).expect("package assembles");
    let mut report = package_value(&package.bytes)["report"].clone();
    report["extension"] = json!(SUMMARY_CANARY);
    report["analysis"]["findings"][0]["note"] = json!(SUMMARY_CANARY);
    report["simulation"]["cases"][0]["id"] = json!(SUMMARY_CANARY);
    report["validation"]["resource_snapshot"]["components"]["tools"] = json!(SUMMARY_CANARY);
    let bytes = canonical_json::canonical_json_bytes(&report).expect("canonical");
    let markdown = render(&bytes).expect("renders");
    assert!(!markdown.contains(SUMMARY_CANARY));
}

#[test]
fn the_markdown_is_deterministic_and_carries_the_trust_statement_verbatim() {
    let package = assemble(complete_inputs(), GENERATED_AT).expect("package assembles");
    let value = package_value(&package.bytes);
    let report_bytes = canonical_json::canonical_json_bytes(&value["report"]).expect("canonical");
    let markdown = render(&report_bytes).expect("renders");
    assert_eq!(render(&report_bytes).expect("renders"), markdown);
    assert!(markdown.starts_with("# Policy evidence report\n"));
    assert!(markdown.ends_with('\n'));
    assert!(markdown.contains(&format!("\n> {TRUST_STATEMENT}\n")));
    for heading in [
        "Summary",
        "Evaluator",
        "Publication",
        "Approval as recorded",
        "Validation",
        "Tests",
        "Simulation",
        "Historical impact",
        "Analysis",
    ] {
        assert!(
            markdown.contains(&format!("\n## {heading}\n")),
            "{heading} is rendered"
        );
    }
    // The fixed statements are plain prose: nothing in them is Markdown.
    for statement in [TRUST_STATEMENT, DRAFT_TRUST_STATEMENT] {
        assert!(!statement.contains(['*', '_', '[', ']', '<', '>', '|', '`', '#', '\\', '\n']));
    }

    // A report whose statement is not the fixed one for its kind, or of a
    // kind the template does not know, is refused, never rendered.
    for (pointer, replacement) in [
        ("/trust/statement", json!(DRAFT_TRUST_STATEMENT)),
        ("/trust/statement", json!("This policy is safe.")),
        ("/candidate_kind", json!("draft")),
        ("/candidate_kind", json!("candidate")),
        ("/tests/included", json!("yes")),
    ] {
        let mut report = value["report"].clone();
        if let Some(member) = report.pointer_mut(pointer) {
            *member = replacement;
        }
        let bytes = canonical_json::canonical_json_bytes(&report).expect("canonical");
        assert_eq!(
            render(&bytes),
            Err(MarkdownError::Unrecognized),
            "{pointer}"
        );
    }
    assert_eq!(render(b"not json"), Err(MarkdownError::Unrecognized));
}

#[test]
fn the_markdown_escapes_every_value_it_repeats() {
    let hostile = "/roles/a`b|c\\d<script>&amp;\n\r\u{202e}\u{200b}\u{7f}é ";
    let package = assemble(complete_inputs(), GENERATED_AT).expect("package assembles");
    let mut report = package_value(&package.bytes)["report"].clone();
    report["validation"]["diagnostics"] = json!([{
        "code": "role_unknown",
        "severity": "warning",
        "pointer": hostile,
        "element_id": " padded ",
        "message": "fixed",
        "remediation": "fixed",
        "blocks": { "simulation": false, "tests": false, "publication": false, "evidence": true }
    }]);
    report["analysis"]["findings"][0]["element"]["pointer"] = json!(hostile);
    let bytes = canonical_json::canonical_json_bytes(&report).expect("canonical");
    let markdown = render(&bytes).expect("renders");

    // One line per row, the header's cell count on every row, and nothing
    // the value held outside its span.
    let rows = markdown
        .lines()
        .filter(|line| line.contains(&code_span(hostile)))
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 2, "{markdown}");
    assert_eq!(rows[0].matches('|').count(), 6, "{}", rows[0]);
    assert_eq!(rows[1].matches('|').count(), 8, "{}", rows[1]);
    let template = template_text(&markdown);
    for raw in ["<", "&", "\r", "\u{202e}", "\u{200b}", "\u{7f}", "é"] {
        assert!(
            !template.contains(raw),
            "{raw:?} is written only inside a span"
        );
    }
    for span in code_spans(&markdown) {
        assert!(span.is_ascii() || span == hostile);
    }
    assert!(code_spans(&markdown).contains(&hostile.to_owned()));
    assert!(code_spans(&markdown).contains(&" padded ".to_owned()));
    assert_eq!(code_span("a b"), "`a b`");
    assert_eq!(code_span(" a "), "`\\u{0020}a\\u{0020}`");
    assert_eq!(code_span("`|\\"), "`\\u{0060}\\u{007C}\\u{005C}`");
    assert_eq!(code_span("\u{1f600}"), "`\\u{1F600}`");
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
    let minimal_draft = json!({
        "schema_version": REQUEST_SCHEMA_VERSION,
        "draft": { "draft_id": DRAFT_ID, "draft_etag": DRAFT_ETAG },
        "analysis": false
    });
    for request in [
        full_request(),
        draft_request(),
        minimal.clone(),
        cases_only,
        minimal_draft,
    ] {
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
    variant(&|request| {
        request["draft"] = json!({ "draft_id": DRAFT_ID, "draft_etag": DRAFT_ETAG });
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
    variant(&|request| request["analysis"] = json!("yes"));
    for request in refusals {
        assert!(parse_request(&request).is_err(), "parser: {request}");
        assert!(!validator.is_valid(&request), "schema: {request}");
    }
    for draft in [
        json!({ "draft_id": DRAFT_ID }),
        json!({ "draft_id": "", "draft_etag": DRAFT_ETAG }),
        json!({ "draft_id": "d".repeat(65), "draft_etag": DRAFT_ETAG }),
        json!({ "draft_id": DRAFT_ID, "draft_etag": DRAFT_ETAG, "base_etag": OTHER_ETAG }),
    ] {
        let mut request = draft_request();
        request["draft"] = draft;
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
    let mut bare = with_publication(complete_inputs(), |record, predecessor| {
        record.policy.semantic_digest = None;
        record.diff_summary = json!({ "action": "policy_rolled_back", "target_version": 7 });
        *predecessor = None;
    });
    bare.tests = None;
    bare.simulation = None;
    bare.replay = None;
    bare.analysis = None;
    let mut uncompared = complete_inputs();
    if let Some(simulation) = uncompared.simulation.as_mut() {
        simulation.compared_with_predecessor = false;
    }
    uncompared.replay = Some(replay_evidence(false));
    uncompared.analysis = Some(analysis_evidence(
        &StoredCandidate::Revision { version: 12 },
        &SuppressionRead::Unavailable,
    ));
    let mut bare_draft = draft_inputs();
    bare_draft.analysis = None;
    bare_draft.replay = None;
    for inputs in [
        complete_inputs(),
        bare,
        uncompared,
        draft_inputs(),
        bare_draft,
    ] {
        let package = assemble(inputs, GENERATED_AT).expect("package assembles");
        let value = package_value(&package.bytes);
        let errors = validator
            .iter_errors(&value)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        assert!(errors.is_empty(), "{errors:?}");
    }

    // A draft is never a publication, and a publication never a draft.
    let mut value = package_value(
        &assemble(draft_inputs(), GENERATED_AT)
            .expect("package assembles")
            .bytes,
    );
    value["report"]["candidate_kind"] = json!("publication");
    assert!(!validator.is_valid(&value));
    let mut value = package_value(
        &assemble(complete_inputs(), GENERATED_AT)
            .expect("package assembles")
            .bytes,
    );
    value["report"]["candidate_kind"] = json!("draft");
    assert!(!validator.is_valid(&value));
}
