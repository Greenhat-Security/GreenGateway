use serde_json::Value;

use super::*;
use crate::{
    diagnostic::Exit,
    validate::tests::{assert_no_canary, codes, report, run, Fixture, CANARY},
};

/// An environment file in a directory of its own, removed with the fixture.
struct EnvFixture {
    fixture: Fixture,
    path: String,
}

impl EnvFixture {
    fn new(text: &str) -> Self {
        let fixture = Fixture::empty();
        fixture.write("gateway.env", text);
        let path = fixture
            .root
            .join("gateway.env")
            .to_str()
            .expect("the temporary path is UTF-8")
            .to_owned();
        Self { fixture, path }
    }

    fn path(&self) -> &str {
        &self.path
    }

    /// Fails when the file's path, or the directory holding it, reached the
    /// output: no argument is echoed.
    fn assert_not_echoed(&self, captured: &crate::report::tests::Captured) {
        let directory = self
            .fixture
            .root
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a UTF-8 directory name");
        for stream in [captured.stdout(), captured.stderr()] {
            assert!(!stream.contains(directory), "the path was echoed: {stream}");
        }
    }
}

/// A standalone configuration the compiler accepts, with the canary in a
/// client secret, a key path, an upstream URL, a route header and a key
/// outside the inventory.
fn accepted() -> String {
    format!(
        "# the gateway's environment\n\
         LISTEN_ADDR=127.0.0.1:8080\n\
         export POLICY_FILE=/srv/{CANARY}/policy.json\n\
         TLS_CERT_FILE=/run/tls/data.crt\n\
         TLS_KEY_FILE=/run/secrets/{CANARY}.key\n\
         AUTH_PROVIDERS=[{{\"name\":\"primary\",\"type\":\"jwt\",\"issuer\":\"https://issuer.example.test\",\"client_id\":\"admin-ui\",\"client_secret\":\"{CANARY}\",\"redirect_uri\":\"https://management.example.test/v1/admin/auth/callback\"}}]\n\
         UPSTREAM_ROUTES=[{{\"id\":\"billing\",\"path_prefix\":\"/billing\",\"upstreams\":[{{\"id\":\"primary\",\"url\":\"https://{CANARY}.example.test\"}}],\"add_request_headers\":{{\"x-route-label\":\"{CANARY}\"}}}}]\n\
         {CANARY}_NOT_A_SETTING={CANARY}\n"
    )
}

/// What every diagnostic of a report says, as `(code, severity, line,
/// field, rule)`.
fn findings(report: &Value) -> Vec<(String, String, Option<u64>, Option<String>, Option<String>)> {
    report["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .map(|diagnostic| {
            let text = |name: &str| diagnostic[name].as_str().map(str::to_owned);
            (
                text("code").expect("code"),
                text("severity").expect("severity"),
                diagnostic["location"]["line"].as_u64(),
                text("field"),
                text("rule"),
            )
        })
        .collect()
}

fn finding(
    code: &str,
    severity: &str,
    line: Option<u64>,
    field: Option<&str>,
    rule: Option<&str>,
) -> (String, String, Option<u64>, Option<String>, Option<String>) {
    (
        code.to_owned(),
        severity.to_owned(),
        line,
        field.map(str::to_owned),
        rule.map(str::to_owned),
    )
}

#[test]
fn a_valid_file_exits_0_and_names_only_the_settings_it_sets() {
    let file = EnvFixture::new(&accepted());
    let (exit, captured) = run(&["validate", "--env", file.path()]);
    assert_eq!(exit, Exit::Success, "{}", captured.stderr());
    assert_eq!(
        captured.stdout(),
        "environment file: valid\n  \
         settings       6 set\n  \
         other keys     1 (not gateway settings, never named)\n"
    );
    assert!(captured.stderr().is_empty());
    assert_no_canary(&captured);
    file.assert_not_echoed(&captured);

    let (exit, captured) = run(&["validate", "--env", file.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Success);
    let report = report(&captured);
    assert_eq!(report["command"], "validate");
    assert_eq!(
        report["result"],
        serde_json::json!({
            "valid": true,
            "environment": {
                "settings": [
                    "LISTEN_ADDR",
                    "TLS_CERT_FILE",
                    "TLS_KEY_FILE",
                    "POLICY_FILE",
                    "AUTH_PROVIDERS",
                    "UPSTREAM_ROUTES",
                ],
                "otherVariables": 1,
                "duplicateKeys": 0,
            },
        })
    );
    assert!(codes(&report).is_empty());
    assert_no_canary(&captured);
    file.assert_not_echoed(&captured);
}

/// Refused values, a malformed line and a repeated key, each holding the
/// canary, are reported by line, setting and rule, and the canary reaches no
/// output format.
#[test]
fn findings_are_located_by_line_and_setting_and_never_carry_a_value() {
    let text = format!(
        "AUTH_MODE={CANARY}\n\
         \n\
         {CANARY} is not an assignment\n\
         ADMIN_LISTEN_ADDR=0.0.0.0:8080\n\
         AUTH_PROVIDERS=[{{\"name\":\"corp\",\"type\":\"{CANARY}\",\"client_secret\":\"{CANARY}\"}}]\n\
         AUTH_MODE={CANARY}-again\n"
    );
    let file = EnvFixture::new(&text);

    let (exit, captured) = run(&["validate", "--env", file.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Invalid);
    let found = report(&captured);
    assert_eq!(found["result"]["valid"], false);
    assert_eq!(found["result"]["environment"]["duplicateKeys"], 1);
    let rows = findings(&found);
    assert_eq!(rows[0], finding("env.malformed_line", "error", Some(3), None, None));
    assert_eq!(
        rows[1],
        finding(
            "env.duplicate_key",
            "warning",
            Some(6),
            Some("AUTH_MODE"),
            None
        )
    );
    // The compiler's findings follow, each at the line that set its setting.
    assert!(rows.contains(&finding(
        "config.refused",
        "error",
        Some(4),
        Some("ADMIN_LISTEN_ADDR"),
        Some("admin_listener_collision")
    )));
    assert!(rows.contains(&finding(
        "config.refused",
        "error",
        Some(6),
        Some("AUTH_MODE"),
        Some("value")
    )));
    assert!(rows.contains(&finding(
        "config.refused",
        "error",
        Some(5),
        Some("AUTH_PROVIDERS"),
        Some("value")
    )));
    let first = &found["diagnostics"][0];
    assert_eq!(first["location"], serde_json::json!({"argument": 2, "line": 3}));
    assert_eq!(first["remediation"], "docs/ggctl.md#env-diagnostics");
    assert_no_canary(&captured);
    file.assert_not_echoed(&captured);

    let (exit, captured) = run(&["validate", "--env", file.path()]);
    assert_eq!(exit, Exit::Invalid);
    assert!(captured.stdout().starts_with("environment file: invalid, "));
    let stderr = captured.stderr();
    assert!(stderr.contains(
        "ggctl: error: config.refused: the configuration compiler refused a setting's value, on its own or together with another setting\n  \
         at: argument 2, line 4\n  \
         setting: ADMIN_LISTEN_ADDR\n  \
         rule: admin_listener_collision\n  \
         see: docs/ggctl.md#config-diagnostics\n"
    ));
    assert!(stderr.contains("ggctl: warning: env.duplicate_key: "));
    assert_no_canary(&captured);
    file.assert_not_echoed(&captured);

    let (exit, captured) = run(&["validate", "--env", file.path(), "--format", "sarif"]);
    assert_eq!(exit, Exit::Invalid);
    assert!(captured.stderr().is_empty());
    let log: Value = serde_json::from_str(captured.stdout()).expect("one SARIF log");
    let run = &log["runs"][0];
    assert!(run.get("originalUriBaseIds").is_none());
    assert_eq!(
        run["artifacts"],
        serde_json::json!([{
            "description": {"text": "The environment file named by argument 2."},
            "roles": ["analysisTarget"],
        }])
    );
    let results = run["results"].as_array().expect("results");
    assert_eq!(results.len(), rows.len());
    assert_eq!(
        results[1]["locations"],
        serde_json::json!([{
            "physicalLocation": {
                "artifactLocation": {"index": 0},
                "region": {"startLine": 6},
            },
            "logicalLocations": [{"fullyQualifiedName": "AUTH_MODE", "kind": "variable"}],
        }])
    );
    assert_eq!(results[1]["level"], "warning");
    assert!(run["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .any(|rule| rule["id"] == "config.refused"));
    assert_no_canary(&captured);
    file.assert_not_echoed(&captured);
}

#[test]
fn a_repeated_key_warns_and_is_an_error_under_strict() {
    let file = EnvFixture::new(&format!(
        "LISTEN_ADDR=127.0.0.1:1\nLISTEN_ADDR=127.0.0.1:2\n{CANARY}=1\n{CANARY}=2\n"
    ));
    let (exit, captured) = run(&["validate", "--env", file.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Success);
    let found = report(&captured);
    assert_eq!(found["result"]["valid"], true);
    assert_eq!(found["outcome"], "success");
    assert_eq!(
        findings(&found),
        [
            finding(
                "env.duplicate_key",
                "warning",
                Some(2),
                Some("LISTEN_ADDR"),
                None
            ),
            // A key outside the inventory is located but never named.
            finding("env.duplicate_key", "warning", Some(4), None, None),
        ]
    );
    assert_eq!(
        found["diagnostics"][0]["hint"],
        "keep one assignment of each key"
    );

    let (exit, captured) = run(&[
        "validate",
        "--env",
        file.path(),
        "--strict",
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Invalid);
    let found = report(&captured);
    assert_eq!(found["result"]["valid"], false);
    assert!(findings(&found)
        .iter()
        .all(|(code, severity, ..)| code == "env.duplicate_key" && severity == "error"));

    let (exit, captured) = run(&[
        "validate",
        "--env",
        file.path(),
        "--warnings-as-errors",
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Invalid);
    let found = report(&captured);
    assert_eq!(found["result"]["valid"], true);
    assert_eq!(
        codes(&found),
        [
            "env.duplicate_key",
            "env.duplicate_key",
            "validate.warnings_as_errors"
        ]
    );
    assert_no_canary(&captured);
}

#[test]
fn the_file_must_be_a_bounded_utf8_regular_file() {
    let fixture = Fixture::empty();
    let missing = fixture.root.join("missing.env");
    let (exit, captured) = run(&[
        "validate",
        "--env",
        missing.to_str().expect("UTF-8"),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Failure);
    let found = report(&captured);
    assert_eq!(codes(&found), ["env.unreadable"]);
    assert_eq!(found["diagnostics"][0]["location"], serde_json::json!({"argument": 2}));
    assert!(found["result"].get("environment").is_none());

    let (exit, captured) = run(&[
        "validate",
        "--env",
        fixture.path(),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Invalid);
    assert_eq!(codes(&report(&captured)), ["env.not_regular_file"]);

    let large = EnvFixture::new(&"#".repeat(MAX_ENV_FILE_BYTES + 1));
    let (exit, captured) = run(&["validate", "--env", large.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Invalid);
    assert_eq!(codes(&report(&captured)), ["env.too_large"]);

    let bounded = EnvFixture::new(&"#".repeat(MAX_ENV_FILE_BYTES));
    let (exit, _) = run(&["validate", "--env", bounded.path()]);
    assert_eq!(exit, Exit::Success);

    let binary = EnvFixture::new("");
    std::fs::write(binary.path(), b"LISTEN_ADDR=\xff\n").expect("the file should write");
    let (exit, captured) = run(&["validate", "--env", binary.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Invalid);
    assert_eq!(codes(&report(&captured)), ["env.not_utf8"]);
}

#[cfg(unix)]
#[test]
fn a_file_another_account_can_change_is_refused_like_a_bundle_file() {
    use std::os::unix::fs::PermissionsExt;
    let file = EnvFixture::new("LISTEN_ADDR=127.0.0.1:8080\n");
    std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o664))
        .expect("the mode should change");
    let (exit, captured) = run(&["validate", "--env", file.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Invalid);
    assert_eq!(codes(&report(&captured)), ["env.unsafe_permissions"]);
}

#[test]
fn exactly_one_source_is_required_and_usage_errors_write_no_report() {
    let bundle = Fixture::valid();
    let file = EnvFixture::new("LISTEN_ADDR=127.0.0.1:8080\n");
    for words in [
        &["validate", "--format", "json"][..],
        &["doctor", "--format", "json"],
        &["validate", bundle.path(), "--env", file.path(), "--format", "json"],
        &["doctor", bundle.path(), "--env", file.path()],
        &["diff", "--env", file.path(), "--format", "json"],
        &["diff", bundle.path(), "--env", file.path(), "--against", bundle.path()],
        &[
            "diff",
            "--env",
            file.path(),
            "--against",
            bundle.path(),
            "--against-env",
            file.path(),
        ],
    ] {
        let (exit, captured) = run(words);
        assert_eq!(exit, Exit::Usage, "{words:?}");
        assert!(captured.stdout().is_empty(), "{words:?}");
        let stderr = captured.stderr();
        assert!(
            stderr.starts_with("ggctl: error: usage.missing_argument: ")
                || stderr.starts_with("ggctl: error: usage.conflicting_options: "),
            "{words:?}: {stderr}"
        );
        file.assert_not_echoed(&captured);
    }
}

#[test]
fn the_doctor_requires_a_compiling_file_and_only_advises_on_the_production_profile() {
    let file = EnvFixture::new(&accepted());
    let (exit, captured) = run(&["doctor", "--env", file.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Success);
    let found = report(&captured);
    let statuses: Vec<_> = found["result"]["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .map(|check| {
            (
                check["id"].as_str().expect("id").to_owned(),
                check["severity"].as_str().expect("severity").to_owned(),
                check["status"].as_str().expect("status").to_owned(),
                check["reason"].as_str().expect("reason").to_owned(),
            )
        })
        .collect();
    let expected = |rows: &[(&str, &str, &str, &str)]| -> Vec<(String, String, String, String)> {
        rows.iter()
            .map(|(id, severity, status, reason)| {
                (
                    (*id).to_owned(),
                    (*severity).to_owned(),
                    (*status).to_owned(),
                    (*reason).to_owned(),
                )
            })
            .collect()
    };
    assert_eq!(
        statuses,
        expected(&[
            ("environment.file", "error", "pass", "doctor.passed"),
            ("environment.duplicate_keys", "warning", "pass", "doctor.passed"),
            ("environment.compiler", "error", "pass", "doctor.passed"),
            ("production.authentication", "warning", "pass", "doctor.passed"),
            ("production.policy", "warning", "skipped", "doctor.policy_not_read"),
            ("production.csrf", "warning", "pass", "doctor.passed"),
            ("production.private_egress", "warning", "pass", "doctor.passed"),
            ("production.audit_durability", "warning", "pass", "doctor.passed"),
            (
                "production.client_secrets",
                "warning",
                "warning",
                "doctor.inline_client_secret"
            ),
        ])
    );
    assert_eq!(found["result"]["environment"]["otherVariables"], 1);
    assert_no_canary(&captured);
    file.assert_not_echoed(&captured);

    // Every production invariant the plan shows is broken: the doctor
    // warns about each and still passes.
    let weak = EnvFixture::new(&format!(
        "AUTH_ENABLED=false\nCSRF_ENABLED=false\nEGRESS_DENY_PRIVATE_IPS=false\n\
         AUDIT_DURABILITY=best_effort\nLISTEN_ADDR=127.0.0.1:8080\nLISTEN_ADDR=127.0.0.1:8081\n\
         {CANARY}={CANARY}\n"
    ));
    let (exit, captured) = run(&["doctor", "--env", weak.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Success, "advice never fails the doctor");
    let found = report(&captured);
    let reasons: Vec<_> = found["result"]["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .map(|check| check["reason"].as_str().expect("reason").to_owned())
        .collect();
    assert_eq!(
        reasons,
        [
            "doctor.passed",
            "env.duplicate_key",
            "doctor.passed",
            "doctor.authentication_not_required",
            "doctor.policy_not_configured",
            "doctor.csrf_disabled",
            "doctor.private_egress_allowed",
            "doctor.audit_best_effort",
            "doctor.passed",
        ]
    );
    assert_eq!(
        found["result"]["checks"][1]["remediation"],
        "docs/ggctl.md#env-diagnostics"
    );
    assert_eq!(codes(&found), ["env.duplicate_key"]);
    assert_no_canary(&captured);

    let (exit, captured) = run(&["doctor", "--env", weak.path()]);
    assert_eq!(exit, Exit::Success);
    let stdout = captured.stdout();
    assert!(stdout.starts_with("environment file: offline checks\n"));
    assert!(stdout.contains("\n  warning  production.csrf              doctor.csrf_disabled\n"));
    assert!(stdout.ends_with("\nno required check failed\n"));
}

#[test]
fn a_refused_or_unreadable_file_fails_the_doctor_and_skips_the_advice() {
    let file = EnvFixture::new(&format!("AUTH_MODE={CANARY}\n{CANARY}\n"));
    let (exit, captured) = run(&["doctor", "--env", file.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Invalid);
    let found = report(&captured);
    let checks = found["result"]["checks"].as_array().expect("checks");
    assert_eq!(checks[0]["status"], "fail");
    assert_eq!(checks[0]["reason"], "env.malformed_line");
    assert_eq!(checks[2]["status"], "fail");
    assert_eq!(checks[2]["reason"], "config.refused");
    assert_eq!(checks[2]["remediation"], "docs/ggctl.md#config-diagnostics");
    assert!(checks[3..]
        .iter()
        .all(|check| check["status"] == "skipped" && check["reason"] == "doctor.incomplete"));
    assert_eq!(
        codes(&found).last().map(String::as_str),
        Some("doctor.required_check_failed")
    );
    assert_no_canary(&captured);

    let fixture = Fixture::empty();
    let missing = fixture.root.join("missing.env");
    let (exit, captured) = run(&[
        "doctor",
        "--env",
        missing.to_str().expect("UTF-8"),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Failure);
    let found = report(&captured);
    let checks = found["result"]["checks"].as_array().expect("checks");
    assert_eq!(checks[0]["reason"], "env.unreadable");
    assert!(checks[1..]
        .iter()
        .all(|check| check["status"] == "skipped" && check["reason"] == "doctor.incomplete"));
}

#[test]
fn two_files_are_compared_by_their_compiled_plans() {
    let base = EnvFixture::new(&format!(
        "AUTH_ENABLED=true\nTLS_CERT_FILE=/run/tls/a.crt\nTLS_KEY_FILE=/run/secrets/{CANARY}-a.key\n"
    ));
    // Spelling, order and comments do not register; the weakened settings do.
    let candidate = EnvFixture::new(&format!(
        "# reordered\nexport TLS_KEY_FILE=/run/secrets/{CANARY}-b.key\nTLS_CERT_FILE=/run/tls/a.crt\n\
         AUTH_ENABLED=false\n"
    ));
    let (exit, captured) = run(&[
        "diff",
        "--env",
        candidate.path(),
        "--against-env",
        base.path(),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Success);
    let found = report(&captured);
    assert_eq!(found["result"]["valid"], true);
    assert_eq!(
        found["result"]["environment"]["settings"],
        serde_json::json!(["TLS_CERT_FILE", "TLS_KEY_FILE", "AUTH_ENABLED"])
    );
    assert!(found["result"]["againstEnvironment"].is_object());
    let diff = &found["result"]["diff"];
    let fields: Vec<_> = diff["changes"]
        .as_array()
        .expect("changes")
        .iter()
        .map(|change| change["field"].as_str().expect("field").to_owned())
        .collect();
    assert_eq!(fields, ["TLS_KEY_FILE", "AUTH_ENABLED"]);
    assert_eq!(
        diff["riskCodes"],
        serde_json::json!(["risk.auth_disabled", "risk.credential_binding_changed"])
    );
    assert_no_canary(&captured);
    candidate.assert_not_echoed(&captured);
    base.assert_not_echoed(&captured);

    let (exit, captured) = run(&[
        "diff",
        "--env",
        candidate.path(),
        "--against-env",
        base.path(),
        "--check",
    ]);
    assert_eq!(exit, Exit::Drift);
    assert!(captured
        .stdout()
        .contains("AUTH_ENABLED  modified true -> false, restart, loosened  [risk.auth_disabled]"));
    assert!(captured.stderr().starts_with("ggctl: error: diff.drift_found: "));
    assert_no_canary(&captured);

    let (exit, captured) = run(&[
        "diff",
        "--env",
        candidate.path(),
        "--against-env",
        base.path(),
        "--format",
        "sarif",
    ]);
    assert_eq!(exit, Exit::Success);
    let log: Value = serde_json::from_str(captured.stdout()).expect("one SARIF log");
    let results = log["runs"][0]["results"].as_array().expect("results");
    assert_eq!(results.len(), 2);
    assert!(log["runs"][0].get("originalUriBaseIds").is_none());
    assert_no_canary(&captured);

    let (exit, captured) = run(&[
        "diff",
        "--env",
        base.path(),
        "--against-env",
        base.path(),
        "--check",
    ]);
    assert_eq!(exit, Exit::Success);
    assert_eq!(captured.stdout(), "no changes\n");
}

#[test]
fn an_invalid_file_or_a_bundle_on_the_other_side_is_not_compared() {
    let valid = EnvFixture::new("LISTEN_ADDR=127.0.0.1:8080\n");
    let refused = EnvFixture::new(&format!("AUTH_MODE={CANARY}\n"));
    let (exit, captured) = run(&[
        "diff",
        "--env",
        refused.path(),
        "--against-env",
        valid.path(),
        "--check",
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Invalid);
    let found = report(&captured);
    assert_eq!(found["result"]["valid"], false);
    assert!(found["result"].get("diff").is_none());
    assert_eq!(codes(&found), ["config.refused"]);
    assert_no_canary(&captured);

    let bundle = Fixture::valid();
    for words in [
        &["diff", "--env", valid.path(), "--against", bundle.path()][..],
        &["diff", bundle.path(), "--against-env", valid.path()],
    ] {
        let mut words = words.to_vec();
        words.extend(["--format", "json"]);
        let (exit, captured) = run(&words);
        assert_eq!(exit, Exit::Invalid, "{words:?}");
        let found = report(&captured);
        assert_eq!(found["result"]["valid"], false);
        assert!(found["result"]["environment"].is_object()
            || found["result"]["againstEnvironment"].is_object());
        assert!(found["result"]["bundle"].is_object() || found["result"]["against"].is_object());
        assert!(found["result"].get("diff").is_none());
        let not_comparable = found["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .find(|diagnostic| diagnostic["code"] == "diff.not_comparable")
            .expect("diff.not_comparable");
        let position = words
            .iter()
            .position(|word| *word == "--env" || *word == "--against-env")
            .expect("an environment option")
            + 1;
        assert_eq!(not_comparable["location"]["argument"], position);
    }
    let (exit, captured) = run(&["diff", "--env", valid.path(), "--against", bundle.path()]);
    assert_eq!(exit, Exit::Invalid);
    assert_eq!(
        captured.stdout(),
        "not compared: an environment file and a bundle cannot be compared\n"
    );
}

/// What ggctl decides about the repository's own `.env.example`, which
/// documents every setting: it is a valid environment configuration. A copy
/// is validated, so the checkout's file modes do not matter on Unix.
#[test]
fn the_shipped_example_environment_is_valid() {
    let example = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../.env.example"))
        .expect(".env.example should be readable");
    let file = EnvFixture::new(&example);
    let (exit, captured) = run(&[
        "validate",
        "--env",
        file.path(),
        "--strict",
        "--format",
        "json",
    ]);
    let found = report(&captured);
    assert_eq!(exit, Exit::Success, "{found:#}");
    assert_eq!(found["result"]["environment"]["otherVariables"], 0);
}

/// Every compiler rule is published by its stable name, in declaration
/// order, in the reference and in the report schema, so a report can carry
/// no rule a reader cannot look up.
#[test]
fn every_compiler_rule_is_documented_and_in_the_report_schema() {
    use gateway_config::compiler::diagnostic::ConfigRule;
    let names: Vec<_> = ConfigRule::ALL.iter().map(|rule| rule.as_str()).collect();

    let reference =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/ggctl.md"))
            .expect("docs/ggctl.md should be readable")
            .replace("\r\n", "\n");
    let start = reference
        .find("\n### Configuration rules\n")
        .expect("docs/ggctl.md has a `### Configuration rules` section");
    let section = &reference[start + 1..];
    let section = &section[..section[1..].find("\n#").map_or(section.len(), |end| end + 1)];
    let documented: Vec<_> = section
        .lines()
        .filter_map(|line| line.strip_prefix("| `"))
        .filter_map(|line| line.split_once('`'))
        .map(|(name, _)| name)
        .collect();
    assert_eq!(documented, names);

    let schema = gateway_config::documents::published_schema(
        gateway_config::documents::API_VERSION_V1ALPHA1,
        gateway_config::documents::REPORT_KIND,
    )
    .expect("the report schema is published");
    let schema: Value = serde_json::from_str(schema.json).expect("JSON");
    let listed: Vec<_> = schema["$defs"]["configRule"]["enum"]
        .as_array()
        .expect("an enum of rule names")
        .iter()
        .map(|name| name.as_str().expect("a rule name"))
        .collect();
    assert_eq!(listed, names);
}
