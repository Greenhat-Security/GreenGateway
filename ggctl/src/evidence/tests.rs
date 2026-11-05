//! Packages are built here exactly as the gateway assembles them
//! (`gateway/src/policy_evidence/package.rs`), with the same digest code,
//! then tampered with one change at a time.

use serde_json::{json, Value};

use super::*;

const REPORT_MEDIA_TYPE: &str = "application/vnd.greengateway.policy-evidence-report+json";
const ANALYSIS_MEDIA_TYPE: &str = "application/vnd.greengateway.policy-analysis-results+json";
const MARKDOWN_MEDIA_TYPE: &str = "text/markdown; charset=utf-8; variant=GFM";

fn report(analysis_entry: Option<&Value>) -> Value {
    let mut report = json!({
        "schema_version": "policy-evidence-report.v1",
        "redaction_profile": "policy-evidence-aggregate.v1",
        "gateway_version": "1.0.1",
        "request_digest": format!("sha256:{}", "1".repeat(64)),
        "publication": {"version": 12, "predecessor_check": "no_recorded_base"},
        "tests": {"included": false},
        "simulation": {"included": false},
        "replay": {"included": false},
        "completeness": "incomplete",
        "limitations": ["replay_not_included", "simulation_not_included", "tests_not_included"],
        "trust": {"signed": false, "statement": "This package is unsigned."}
    });
    report["analysis"] = match analysis_entry {
        Some(entry) => json!({"included": true, "artifact": entry, "complete": true}),
        None => json!({"included": false}),
    };
    report
}

fn analysis() -> Value {
    json!({
        "schema_version": "policy-analysis-results.v1",
        "mode": "structural",
        "complete": true,
        "findings": [{"code": "wildcard_permission", "severity": "risk"}]
    })
}

fn json_entry(name: &str, media_type: &str, schema_version: &str, value: &Value) -> Value {
    let bytes = canonical_json::canonical_json_bytes(value).expect("canonical");
    json!({
        "name": name,
        "media_type": media_type,
        "schema_version": schema_version,
        "digest": canonical_json::semantic_digest(media_type, schema_version, value).expect("digest"),
        "size": bytes.len(),
    })
}

fn markdown_entry(text: &str) -> Value {
    json!({
        "name": "report_markdown",
        "media_type": MARKDOWN_MEDIA_TYPE,
        "schema_version": "policy-evidence-report-markdown.v1",
        "digest": canonical_json::source_digest(
            MARKDOWN_MEDIA_TYPE,
            "policy-evidence-report-markdown.v1",
            text.as_bytes(),
        ),
        "size": text.len(),
    })
}

/// A package with the report alone, as the first evidence slice serves.
fn report_only() -> Value {
    let report = report(None);
    json!({
        "schema_version": "policy-evidence.v1",
        "generated_at": "2026-10-28T12:00:00Z",
        "manifest": [json_entry("report", REPORT_MEDIA_TYPE, "policy-evidence-report.v1", &report)],
        "report": report,
    })
}

/// A package with every artifact: the report, the analysis it binds, and
/// the Markdown rendering.
fn full() -> Value {
    let analysis = analysis();
    let analysis_entry = json_entry(
        "analysis",
        ANALYSIS_MEDIA_TYPE,
        "policy-analysis-results.v1",
        &analysis,
    );
    let report = report(Some(&analysis_entry));
    let markdown = "# Policy evidence report\n\nThis package is unsigned.\n";
    json!({
        "schema_version": "policy-evidence.v1",
        "generated_at": "2026-10-28T12:00:00Z",
        "manifest": [
            json_entry("report", REPORT_MEDIA_TYPE, "policy-evidence-report.v1", &report),
            analysis_entry,
            markdown_entry(markdown),
        ],
        "report": report,
        "analysis": analysis,
        "report_markdown": markdown,
    })
}

/// A package's bytes as a gateway serves them.
fn served(package: &Value) -> Vec<u8> {
    canonical_json::canonical_json_bytes(package).expect("canonical")
}

fn codes(bytes: &[u8]) -> (VerifyResult, Vec<Code>) {
    let (result, diagnostics) = verify_bytes(bytes);
    (
        result,
        diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect(),
    )
}

#[test]
fn a_package_as_served_is_integrity_valid_and_unsigned_never_trusted() {
    for package in [report_only(), full()] {
        let bytes = served(&package);
        let (result, codes) = codes(&bytes);
        assert_eq!(codes, [Code::EvidenceUnsigned], "{package}");
        assert_eq!(result.verdict, "integrity_valid");
        assert_eq!(result.signature, "unsigned");
        assert!(!result.trusted);
        let listed = package["manifest"].as_array().expect("manifest").len();
        assert_eq!(result.artifacts.len(), listed);
        assert!(result.artifacts.iter().all(|artifact| artifact.verified));
        let record = result.package.as_ref().expect("the envelope was read");
        assert_eq!(record.size, bytes.len());
        assert_eq!(record.generated_at, "2026-10-28T12:00:00Z");
        assert_eq!(
            record.source_digest,
            canonical_json::source_digest(PACKAGE_MEDIA_TYPE, PACKAGE_SCHEMA_VERSION, &bytes)
        );
        let summary = result.report.as_ref().expect("a summary");
        assert_eq!(summary.completeness, "incomplete");
        assert_eq!(summary.limitations.len(), 3);
        // The unsigned notice is information: it leaves the exit at 0.
        assert_eq!(Exit::of(&verify_bytes(&bytes).1), Exit::Success);
    }
}

/// One change to a served package, and the codes it must be refused with.
fn tampered(package: Value, change: impl FnOnce(&mut Value)) -> Vec<Code> {
    let mut package = package;
    change(&mut package);
    let (result, codes) = codes(&served(&package));
    assert_ne!(result.verdict, "integrity_valid", "{codes:?}");
    assert!(result.report.is_none());
    assert!(!codes.contains(&Code::EvidenceUnsigned));
    codes
}

#[test]
fn tampering_with_an_artifact_or_its_entry_is_an_integrity_failure() {
    assert_eq!(
        tampered(report_only(), |package| {
            package["report"]["completeness"] = json!("complete");
        }),
        [Code::EvidenceDigestMismatch]
    );
    assert_eq!(
        tampered(report_only(), |package| {
            package["report"]["limitations"] = json!([]);
        }),
        [Code::EvidenceDigestMismatch]
    );
    assert_eq!(
        tampered(report_only(), |package| {
            package["manifest"][0]["size"] = json!(1);
        }),
        [Code::EvidenceSizeMismatch]
    );
    assert_eq!(
        tampered(report_only(), |package| {
            package["manifest"][0]["digest"] = json!(format!("sha256:{}", "0".repeat(64)));
        }),
        [Code::EvidenceDigestMismatch]
    );
    assert_eq!(
        tampered(full(), |package| {
            package["report_markdown"] = json!("# Policy evidence report\n\nTrusted.\n");
        }),
        [Code::EvidenceDigestMismatch]
    );
    assert_eq!(
        tampered(full(), |package| {
            package["analysis"]["findings"] = json!([]);
        }),
        [Code::EvidenceDigestMismatch]
    );
    // An analysis with its entry rewritten to match still disagrees with the
    // entry the report digest binds.
    assert_eq!(
        tampered(full(), |package| {
            package["analysis"]["findings"] = json!([]);
            package["manifest"][1] = json_entry(
                "analysis",
                ANALYSIS_MEDIA_TYPE,
                "policy-analysis-results.v1",
                &package["analysis"],
            );
        }),
        [Code::EvidenceBindingMismatch]
    );
    // A report that names an analysis the package does not carry.
    assert_eq!(
        tampered(full(), |package| {
            if let Some(manifest) = package["manifest"].as_array_mut() {
                manifest.remove(1);
            }
            if let Some(envelope) = package.as_object_mut() {
                envelope.remove("analysis");
            }
        }),
        [Code::EvidenceBindingMismatch]
    );
}

#[test]
fn duplicate_unlisted_missing_or_unknown_entries_are_refused() {
    assert_eq!(
        tampered(report_only(), |package| {
            let entry = package["manifest"][0].clone();
            if let Some(manifest) = package["manifest"].as_array_mut() {
                manifest.push(entry);
            }
        }),
        [Code::EvidenceDuplicateEntry]
    );
    // An extra member the manifest does not list, such as a signature a
    // verifier could be tempted to read.
    assert_eq!(
        tampered(report_only(), |package| {
            package["signatures"] = json!([{"keyid": "k", "sig": "x"}]);
        }),
        [Code::EvidenceUnlistedMember]
    );
    assert_eq!(
        tampered(full(), |package| {
            if let Some(envelope) = package.as_object_mut() {
                envelope.remove("report_markdown");
            }
        }),
        [Code::EvidenceMissingArtifact]
    );
    assert_eq!(
        tampered(full(), |package| {
            if let Some(manifest) = package["manifest"].as_array_mut() {
                manifest.remove(0);
            }
        }),
        [Code::EvidenceMissingArtifact, Code::EvidenceUnlistedMember]
    );
    assert_eq!(
        tampered(report_only(), |package| {
            let mut entry = package["manifest"][0].clone();
            entry["name"] = json!("attachment");
            if let Some(manifest) = package["manifest"].as_array_mut() {
                manifest.push(entry);
            }
            package["attachment"] = package["report"].clone();
        }),
        [Code::EvidenceUnsupportedArtifact]
    );
    assert_eq!(
        tampered(report_only(), |package| {
            package["manifest"][0]["media_type"] = json!("application/json");
        }),
        [Code::EvidenceArtifactTypeMismatch]
    );
    assert_eq!(
        tampered(report_only(), |package| {
            package["manifest"][0]["schema_version"] = json!("policy-evidence-report.v2");
        }),
        [Code::EvidenceArtifactTypeMismatch]
    );
    // A report that states another version than its entry frames it with.
    assert_eq!(
        tampered(report_only(), |package| {
            package["report"]["schema_version"] = json!("policy-evidence-report.v2");
            package["manifest"][0] = json_entry(
                "report",
                REPORT_MEDIA_TYPE,
                "policy-evidence-report.v1",
                &package["report"],
            );
        }),
        [Code::EvidenceArtifactTypeMismatch]
    );
    assert_eq!(
        tampered(full(), |package| {
            package["report_markdown"] = json!({"text": "not a string"});
        }),
        [Code::EvidenceArtifactTypeMismatch]
    );
}

#[test]
fn a_malformed_envelope_is_refused_before_any_digest_is_trusted() {
    assert_eq!(
        tampered(full(), |package| {
            if let Some(manifest) = package["manifest"].as_array_mut() {
                manifest.swap(0, 2);
            }
        }),
        [Code::EvidenceMalformed]
    );
    for change in [
        (|package: &mut Value| package["manifest"] = json!([])) as fn(&mut Value),
        |package| package["manifest"] = json!({}),
        |package| package["manifest"][0]["extra"] = json!(true),
        |package| package["manifest"][0]["size"] = json!(-1),
        |package| package["manifest"][0]["digest"] = json!("sha256:ABC"),
        |package| package["generated_at"] = json!(17),
        |package| package["schema_version"] = json!(1),
        |package| {
            if let Some(envelope) = package.as_object_mut() {
                envelope.remove("manifest");
            }
        },
    ] {
        assert_eq!(tampered(report_only(), change), [Code::EvidenceMalformed]);
    }
    for bytes in [&b"not json"[..], b"[]", b"\"policy-evidence.v1\"", b""] {
        assert_eq!(codes(bytes).1, [Code::EvidenceMalformed], "{bytes:?}");
    }
    // A byte-order mark is not JSON.
    let mut with_bom = b"\xef\xbb\xbf".to_vec();
    with_bom.extend(served(&report_only()));
    assert_eq!(codes(&with_bom).1, [Code::EvidenceMalformed]);
    assert_eq!(
        tampered(report_only(), |package| {
            package["report"]["trust"] = json!({"statement": "no signed member"});
            package["manifest"][0] = json_entry(
                "report",
                REPORT_MEDIA_TYPE,
                "policy-evidence-report.v1",
                &package["report"],
            );
        }),
        [Code::EvidenceMalformed]
    );
}

#[test]
fn a_package_that_is_not_its_canonical_bytes_is_not_the_one_served() {
    let package = report_only();
    // Pretty-printed: every digest still matches, and it is still refused.
    let pretty = serde_json::to_vec_pretty(&package).expect("JSON");
    let (result, found) = codes(&pretty);
    assert_eq!(found, [Code::EvidenceNotCanonical]);
    assert_eq!(result.verdict, "integrity_invalid");
    assert!(result.artifacts.iter().all(|artifact| artifact.verified));
    // A repeated member: a reader keeping the first and one keeping the
    // last would see two different reports.
    let bytes = served(&package);
    let text = String::from_utf8(bytes).expect("UTF-8");
    let duplicated = text.replacen(
        "\"generated_at\":",
        "\"generated_at\":\"2026-01-01T00:00:00Z\",\"generated_at\":",
        1,
    );
    assert_eq!(codes(duplicated.as_bytes()).1, [Code::EvidenceNotCanonical]);
    // A number spelled another way.
    let spelled = text.replacen("\"version\":12", "\"version\":12.0", 1);
    assert_ne!(spelled, text);
    assert_eq!(codes(spelled.as_bytes()).1, [Code::EvidenceNotCanonical]);
}

#[test]
fn an_unsupported_version_or_a_signature_claim_is_not_verified() {
    let mut package = report_only();
    package["schema_version"] = json!("policy-evidence.v2");
    let (result, found) = codes(&served(&package));
    assert_eq!(found, [Code::EvidenceUnsupportedVersion]);
    assert_eq!(result.verdict, "not_verified");
    assert_eq!(Exit::of(&verify_bytes(&served(&package)).1), Exit::Invalid);

    let mut package = report_only();
    package["report"]["trust"]["signed"] = json!(true);
    package["manifest"][0] = json_entry(
        "report",
        REPORT_MEDIA_TYPE,
        "policy-evidence-report.v1",
        &package["report"],
    );
    let (result, found) = codes(&served(&package));
    assert_eq!(found, [Code::EvidenceSignatureUnsupported]);
    assert_eq!(result.verdict, "not_verified");
    assert!(!result.trusted);
}

/// The artifacts this verifier knows are the ones the published package
/// schema lists, with the same media types and versions, so the two cannot
/// drift apart unnoticed.
#[test]
fn every_artifact_the_published_schema_lists_is_verified_as_it_states() {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../docs/schemas/policy-evidence.v1.schema.json"
    ))
    .expect("the schema is JSON");
    let mut listed = Vec::new();
    collect_entries(&schema, &mut listed);
    assert!(listed.iter().any(|(name, _, _)| name == "report"));
    for (name, media_type, schema_version) in listed {
        let artifact = ARTIFACTS
            .iter()
            .find(|artifact| artifact.name == name)
            .unwrap_or_else(|| panic!("{name} is not verified"));
        assert_eq!(artifact.media_type, media_type, "{name}");
        assert_eq!(artifact.schema_version, schema_version, "{name}");
    }
    assert_eq!(
        schema["properties"]["schema_version"]["const"],
        PACKAGE_SCHEMA_VERSION
    );
}

/// Every object in the schema that fixes an entry's name, media type and
/// schema version.
fn collect_entries(value: &Value, listed: &mut Vec<(String, String, String)>) {
    match value {
        Value::Object(members) => {
            if let Some(properties) = members.get("properties") {
                let constant = |name: &str| properties[name]["const"].as_str().map(str::to_owned);
                if let (Some(name), Some(media_type), Some(schema_version)) = (
                    constant("name"),
                    constant("media_type"),
                    constant("schema_version"),
                ) {
                    listed.push((name, media_type, schema_version));
                }
            }
            for member in members.values() {
                collect_entries(member, listed);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_entries(item, listed);
            }
        }
        _ => {}
    }
}

/// The command reads nothing but its one file: no remote option, and no
/// network capability is named anywhere in this module.
#[test]
fn verification_has_no_network_capability() {
    let command = crate::cli::COMMANDS
        .iter()
        .find(|command| command.name == "evidence verify")
        .expect("evidence verify");
    assert!(command
        .options
        .iter()
        .all(|option| option.name == "--format"));
    let source = include_str!("../evidence.rs");
    // The client crate's name is assembled, so that no file but the remote
    // client names it (scripts/check-egress-only.sh).
    for capability in [
        "remote",
        concat!("req", "west"),
        "tokio",
        "std::net",
        "TcpStream",
        "Command",
    ] {
        assert!(!source.contains(capability), "{capability}");
    }
}

#[test]
fn the_human_form_says_unsigned_and_not_trusted() {
    let (result, _) = verify_bytes(&served(&full()));
    let mut out = Vec::new();
    write_human(&result, &mut out).expect("writes");
    let text = String::from_utf8(out).expect("UTF-8");
    assert!(
        text.starts_with("evidence package: integrity_valid, unsigned (not trusted)\n"),
        "{text}"
    );
    assert!(text.contains("\n  report        sha256:"));
    assert!(text.contains("bytes, verified\n"));
    assert!(text.contains(
        "\n  completeness  incomplete: replay_not_included, simulation_not_included, tests_not_included\n"
    ));
    assert!(text.contains("Without a signature nothing shows who produced the package."));

    let (result, _) = verify_bytes(b"[]");
    let mut out = Vec::new();
    write_human(&result, &mut out).expect("writes");
    assert_eq!(
        String::from_utf8(out).expect("UTF-8"),
        "evidence package: integrity_invalid, unsigned (not trusted)\n"
    );
}
