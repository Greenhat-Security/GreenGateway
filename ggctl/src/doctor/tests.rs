use serde_json::Value;

use super::*;
use crate::validate::tests::{assert_no_canary, codes, report, run, Fixture, CANARY, DENY_POLICY};

/// `(id, status, reason)` for every check of a doctor report.
fn statuses(report: &Value) -> Vec<(String, String, String)> {
    report["result"]["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .map(|check| {
            let field = |name: &str| check[name].as_str().expect(name).to_owned();
            (field("id"), field("status"), field("reason"))
        })
        .collect()
}

fn expected(rows: &[(&str, &str, &str)]) -> Vec<(String, String, String)> {
    rows.iter()
        .map(|(id, status, reason)| ((*id).to_owned(), (*status).to_owned(), (*reason).to_owned()))
        .collect()
}

#[test]
fn a_valid_production_bundle_passes_every_check_it_can_run() {
    let fixture = Fixture::valid();
    let (exit, captured) = run(&["doctor", fixture.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Success);
    let report = report(&captured);
    assert_eq!(report["command"], "doctor");
    assert!(codes(&report).is_empty());
    assert_eq!(
        statuses(&report),
        expected(&[
            ("bundle.files", "pass", "doctor.passed"),
            ("bundle.syntax", "pass", "doctor.passed"),
            ("bundle.compatibility", "pass", "doctor.passed"),
            ("bundle.structure", "pass", "doctor.passed"),
            ("bundle.references", "pass", "doctor.passed"),
            ("bundle.resources", "pass", "doctor.passed"),
            ("bundle.profile", "pass", "doctor.passed"),
            ("bundle.unreferenced_entries", "pass", "doctor.passed"),
            (
                "resources.production_validators",
                "skipped",
                "doctor.validator_unavailable"
            ),
            ("deployment.profile", "pass", "doctor.passed"),
        ])
    );
    let checks = report["result"]["checks"].as_array().expect("checks");
    assert_eq!(checks[7]["severity"], "warning");
    assert_eq!(checks[8]["severity"], "error");
    assert_eq!(checks[9]["severity"], "warning");
    assert!(checks.iter().all(
        |check| check["remediation"] == "docs/ggctl.md#doctor-checks"
            && check["durationMs"].is_u64()
    ));
    assert_eq!(report["result"]["bundle"]["name"], "payments-production");

    let (exit, captured) = run(&["doctor", fixture.path()]);
    assert_eq!(exit, Exit::Success);
    let stdout = captured.stdout();
    assert!(stdout
        .starts_with("bundle payments-production (greengateway.dev/v1alpha1): offline checks\n"));
    assert!(stdout
        .contains("\n  skipped  resources.production_validators  doctor.validator_unavailable\n"));
    assert!(stdout.ends_with("\nno required check failed\n"));
    assert!(captured.stderr().is_empty());
}

#[test]
fn a_failed_stage_fails_the_doctor_and_unproven_stages_are_skipped_not_passed() {
    let fixture = Fixture::valid();
    fixture.write(
        "policy.json",
        &format!("{{\"schema_version\": \"0.1.0\", \"{CANARY}\": true}}\n"),
    );
    let (exit, captured) = run(&["doctor", fixture.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Invalid);
    let report = report(&captured);
    assert_eq!(
        codes(&report),
        ["bundle.digest_mismatch", "doctor.required_check_failed"]
    );
    assert_eq!(
        statuses(&report),
        expected(&[
            ("bundle.files", "skipped", "doctor.incomplete"),
            ("bundle.syntax", "skipped", "doctor.incomplete"),
            ("bundle.compatibility", "skipped", "doctor.incomplete"),
            ("bundle.structure", "skipped", "doctor.incomplete"),
            ("bundle.references", "fail", "bundle.digest_mismatch"),
            ("bundle.resources", "skipped", "doctor.incomplete"),
            ("bundle.profile", "skipped", "doctor.incomplete"),
            (
                "bundle.unreferenced_entries",
                "skipped",
                "doctor.incomplete"
            ),
            (
                "resources.production_validators",
                "skipped",
                "doctor.validator_unavailable"
            ),
            ("deployment.profile", "skipped", "doctor.incomplete"),
        ])
    );
    assert_eq!(
        report["result"]["checks"][4]["remediation"],
        "docs/configuration-bundles.md#diagnostics"
    );
    assert_no_canary(&captured);

    let (exit, captured) = run(&["doctor", fixture.path()]);
    assert_eq!(exit, Exit::Invalid);
    assert!(captured.stdout().ends_with("\na required check failed\n"));
    assert!(captured
        .stderr()
        .starts_with("ggctl: error: bundle.digest_mismatch: "));
    assert!(captured
        .stderr()
        .contains("ggctl: error: doctor.required_check_failed: a required doctor check failed\n"));
}

#[test]
fn advice_and_skips_never_fail_the_doctor() {
    // A development bundle: the policy invariants do not apply, and the
    // profile is reported as advice.
    let allow = "{\"schema_version\": \"0.1.0\", \"default_action\": \"allow\"}\n";
    let fixture = Fixture::with("development", allow);
    fixture.write("notes.txt", "unreferenced\n");
    let (exit, captured) = run(&["doctor", fixture.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Success);
    assert_eq!(
        statuses(&report(&captured))[6..],
        expected(&[
            ("bundle.profile", "pass", "doctor.passed"),
            (
                "bundle.unreferenced_entries",
                "warning",
                "bundle.unreferenced_entry"
            ),
            (
                "resources.production_validators",
                "skipped",
                "doctor.validator_unavailable"
            ),
            (
                "deployment.profile",
                "warning",
                "doctor.development_profile"
            ),
        ])[..]
    );

    let fixture = Fixture::with("migration", DENY_POLICY);
    let (exit, captured) = run(&["doctor", fixture.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Success);
    assert_eq!(
        statuses(&report(&captured))[9],
        (
            "deployment.profile".to_owned(),
            "warning".to_owned(),
            "doctor.migration_profile".to_owned()
        )
    );

    // A policy left to the server is not checked here.
    let fixture = Fixture::valid();
    fixture.pin("      source: server\n");
    let (exit, captured) = run(&["doctor", fixture.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Success);
    let found = statuses(&report(&captured));
    assert_eq!(
        found[6],
        (
            "bundle.profile".to_owned(),
            "skipped".to_owned(),
            "doctor.server_managed".to_owned()
        )
    );
    // The tools document is still the bundle's.
    assert_eq!(
        found[8],
        (
            "resources.production_validators".to_owned(),
            "skipped".to_owned(),
            "doctor.validator_unavailable".to_owned()
        )
    );
}

#[test]
fn a_bundle_that_cannot_be_read_fails_with_exit_1() {
    let fixture = Fixture::empty();
    let missing = fixture.root.join("missing");
    let (exit, captured) = run(&[
        "doctor",
        missing.to_str().expect("UTF-8"),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Failure);
    let found = report(&captured);
    assert!(found["result"].get("bundle").is_none());
    let found = statuses(&found);
    assert_eq!(
        found[0],
        (
            "bundle.files".to_owned(),
            "fail".to_owned(),
            "bundle.root_unavailable".to_owned()
        )
    );
    assert_eq!(
        found[8],
        (
            "resources.production_validators".to_owned(),
            "skipped".to_owned(),
            "doctor.incomplete".to_owned()
        )
    );
}

#[test]
fn every_check_and_reason_is_documented() {
    let reference =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/ggctl.md"))
            .expect("docs/ggctl.md should be readable")
            .replace("\r\n", "\n");
    let section = |heading: &str| -> String {
        let start = reference
            .find(&format!("\n### {heading}\n"))
            .unwrap_or_else(|| panic!("docs/ggctl.md has no `### {heading}` section"));
        let body = &reference[start + heading.len() + 6..];
        body.find("\n#").map_or(body, |end| &body[..end]).to_owned()
    };
    let rows = |section: &str| -> Vec<String> {
        section
            .lines()
            .filter_map(|line| line.strip_prefix("| `"))
            .filter_map(|line| line.split_once('`'))
            .map(|(name, _)| name.to_owned())
            .collect()
    };
    let checks: Vec<_> = Stage::ALL
        .iter()
        .map(|stage| stage.id())
        .chain(OTHER_CHECKS.iter().copied())
        .collect();
    assert_eq!(rows(&section("Doctor checks")), checks);
    let reasons: Vec<_> = Reason::ALL.iter().map(|reason| reason.as_str()).collect();
    assert_eq!(rows(&section("Doctor reasons")), reasons);
}
