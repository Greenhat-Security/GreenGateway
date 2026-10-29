use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use gateway_config::{bundle::sha256_pin, documents::published_schema};
use serde_json::{json, Value};

use crate::{
    cli::{self, Parsed},
    diagnostic::{Code, Exit},
    report::tests::Captured,
};

pub(crate) const CANARY: &str = "zqcanaryggctl";

pub(crate) const DENY_POLICY: &str =
    "{\n  \"schema_version\": \"0.1.0\",\n  \"default_action\": \"deny\"\n}\n";
pub(crate) const TOOLS: &str = "{\n  \"schema_version\": \"0.1.0\",\n  \"tools\": []\n}\n";

/// A bundle directory under the system temporary directory, removed on drop.
pub(crate) struct Fixture {
    pub(crate) root: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Fixture {
    pub(crate) fn empty() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "ggctl-bundle-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("the bundle directory should create");
        #[cfg(unix)]
        set_mode(&root, 0o755);
        Self { root }
    }

    /// A bundle of `profile` that supplies `policy` and the empty tools
    /// document, and leaves Connections to the server.
    pub(crate) fn with(profile: &str, policy: &str) -> Self {
        let fixture = Self::empty();
        fixture.write(
            "deployment.yaml",
            &format!(
                "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayDeployment\nspec:\n  profile: {profile}\n"
            ),
        );
        fixture.write("policy.json", policy);
        fixture.write("tools.json", TOOLS);
        fixture.pin(
            "      source: bundle\n      path: policy.json\n      schema_version: \"0.1.0\"\n      sha256: \"POLICY\"\n",
        );
        fixture
    }

    pub(crate) fn valid() -> Self {
        Self::with("production", DENY_POLICY)
    }

    pub(crate) fn write(&self, name: &str, contents: &str) {
        let path = self.root.join(name);
        fs::write(&path, contents).expect("the bundle file should write");
        #[cfg(unix)]
        set_mode(&path, 0o644);
    }

    fn pin_of(&self, name: &str) -> String {
        sha256_pin(&fs::read(self.root.join(name)).expect("the bundle file should read"))
    }

    /// Writes the manifest, pinning the files as they are now; `policy` is
    /// the body of its policy declaration, where `POLICY` stands for the
    /// policy file's pin.
    pub(crate) fn pin(&self, policy: &str) {
        let policy = if policy.contains("POLICY") {
            policy.replace("POLICY", &self.pin_of("policy.json"))
        } else {
            policy.to_owned()
        };
        self.write(
            "bundle.yaml",
            &format!(
                concat!(
                    "apiVersion: greengateway.dev/v1alpha1\n",
                    "kind: GatewayBundle\n",
                    "metadata:\n",
                    "  name: payments-production\n",
                    "spec:\n",
                    "  deployment:\n",
                    "    path: deployment.yaml\n",
                    "    sha256: \"{deployment}\"\n",
                    "  resources:\n",
                    "    policy:\n",
                    "{policy}",
                    "    tools:\n",
                    "      source: bundle\n",
                    "      path: tools.json\n",
                    "      schema_version: \"0.1.0\"\n",
                    "      sha256: \"{tools}\"\n",
                    "    connections:\n",
                    "      source: server\n",
                ),
                deployment = self.pin_of("deployment.yaml"),
                policy = policy,
                tools = self.pin_of("tools.json"),
            ),
        );
    }

    pub(crate) fn path(&self) -> &str {
        self.root
            .to_str()
            .expect("the temporary directory should be UTF-8")
    }
}

#[cfg(unix)]
fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("permissions should set");
}

/// Parses and runs one command line, which must parse.
pub(crate) fn run(words: &[&str]) -> (Exit, Captured) {
    let arguments: Vec<OsString> = words.iter().map(OsString::from).collect();
    let mut captured = Captured::default();
    let exit = captured.run(b"", false, |io| match cli::parse(&arguments) {
        Ok(Parsed::Run(invocation)) => (invocation.command.run)(&invocation, io),
        other => panic!("{words:?} should run, got {other:?}"),
    });
    (exit, captured)
}

/// Parses a `--format json` report and holds it to the published schema.
pub(crate) fn report(captured: &Captured) -> Value {
    let report: Value = serde_json::from_str(captured.stdout()).expect("one JSON document");
    let schema = published_schema("greengateway.dev/v1alpha1", "GgctlReport").expect("published");
    let schema: Value = serde_json::from_str(schema.json).expect("JSON");
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let errors: Vec<_> = validator
        .iter_errors(&report)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}\n{report:#}");
    assert!(captured.stderr().is_empty(), "{}", captured.stderr());
    report
}

pub(crate) fn codes(found: &Value) -> Vec<String> {
    found["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .map(|diagnostic| diagnostic["code"].as_str().expect("code").to_owned())
        .collect()
}

pub(crate) fn assert_no_canary(captured: &Captured) {
    let all = format!("{}{}", captured.stdout(), captured.stderr());
    assert!(
        !all.contains(CANARY),
        "a document value reached the output: {all}"
    );
}

#[test]
fn a_valid_bundle_exits_0_and_says_the_production_validators_did_not_run() {
    let fixture = Fixture::valid();
    let (exit, captured) = run(&["validate", fixture.path()]);
    assert_eq!(exit, Exit::Success);
    let stdout = captured.stdout();
    let digest = format!(
        "  source digest  sha256:{}",
        &stdout.split("sha256:").nth(1).expect("a source digest")[..64]
    );
    assert_eq!(
        stdout,
        format!(
            "bundle payments-production (greengateway.dev/v1alpha1): valid\n\
             {digest}\n  \
             deployment     deployment.yaml (profile production)\n  \
             policy         policy.json (schema_version 0.1.0)\n  \
             tools          tools.json (schema_version 0.1.0)\n  \
             connections    server\n"
        )
    );
    assert_eq!(
        captured.stderr(),
        format!(
            "ggctl: info: validate.production_validators_not_run: {}\n  see: docs/ggctl.md#validate-diagnostics\n",
            Code::ProductionValidatorsNotRun.message()
        )
    );

    let (exit, captured) = run(&["validate", fixture.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Success);
    let found = report(&captured);
    assert_eq!(found["command"], "validate");
    assert_eq!(found["outcome"], "success");
    assert_eq!(codes(&found), ["validate.production_validators_not_run"]);
    assert_eq!(found["diagnostics"][0]["severity"], "info");
    let result = &found["result"];
    assert_eq!(result["valid"], true);
    let bundle = &result["bundle"];
    assert_eq!(bundle["apiVersion"], "greengateway.dev/v1alpha1");
    assert_eq!(bundle["name"], "payments-production");
    assert!(bundle["sourceDigest"]
        .as_str()
        .is_some_and(|digest| digest.starts_with("sha256:") && digest.len() == 71));
    assert_eq!(
        bundle["deployment"],
        json!({
            "file": "deployment.yaml",
            "sha256": fixture.pin_of("deployment.yaml"),
            "profile": "production",
        })
    );
    assert_eq!(
        bundle["policy"],
        json!({
            "source": "bundle",
            "file": "policy.json",
            "schemaVersion": "0.1.0",
            "sha256": fixture.pin_of("policy.json"),
            "productionValidator": "not_run",
        })
    );
    assert_eq!(bundle["connections"], "server");
}

#[test]
fn an_invalid_bundle_exits_3_with_located_value_free_diagnostics() {
    let fixture = Fixture::valid();
    // The policy changes after it was pinned, and its unknown member names a
    // value that must never be echoed.
    fixture.write(
        "policy.json",
        &format!("{{\"schema_version\": \"0.1.0\", \"{CANARY}\": \"{CANARY}\"}}\n"),
    );
    let (exit, captured) = run(&["validate", fixture.path()]);
    assert_eq!(exit, Exit::Invalid);
    assert_eq!(
        captured.stdout(),
        "bundle payments-production (greengateway.dev/v1alpha1): invalid, 1 error\n  \
         deployment     deployment.yaml\n  \
         policy         policy.json (schema_version 0.1.0)\n  \
         tools          tools.json (schema_version 0.1.0)\n  \
         connections    server\n"
    );
    assert!(captured.stderr().starts_with(
        "ggctl: error: bundle.digest_mismatch: a file's SHA-256 digest differs from the digest the manifest pins\n  at: policy.json\n  see: docs/configuration-bundles.md#diagnostics\n"
    ));
    assert_no_canary(&captured);

    // Pinned again, the unknown member itself is reported by position.
    fixture.pin("      source: bundle\n      path: policy.json\n      schema_version: \"0.1.0\"\n      sha256: \"POLICY\"\n");
    let (exit, captured) = run(&["validate", fixture.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Invalid);
    let found = report(&captured);
    assert_eq!(found["outcome"], "invalid");
    assert_eq!(found["result"]["valid"], false);
    assert!(found["result"]["bundle"].get("sourceDigest").is_none());
    assert_eq!(
        found["diagnostics"][0],
        json!({
            "code": "resource.unknown_member",
            "severity": "error",
            "message": "the resource document has a top-level member its validator would ignore",
            "remediation": "docs/configuration-bundles.md#diagnostics",
            "location": {"file": "policy.json", "pointer": "", "line": 1, "column": 29},
        })
    );
    assert_no_canary(&captured);
}

#[test]
fn a_production_policy_is_held_to_the_profile_invariants() {
    let policy = "{\n  \"schema_version\": \"0.1.0\",\n  \"default_action\": \"allow\",\n  \"enforcement_mode\": \"shadow\",\n  \"roles\": {\"ops\": {\"permissions\": [\"read\", \"*\"]}},\n  \"routes\": [{\"path_prefix\": \"/a\", \"permission\": \"read\", \"enforcement_mode\": \"shadow\"}]\n}\n";
    for profile in ["production", "migration"] {
        let fixture = Fixture::with(profile, policy);
        let (exit, captured) = run(&["validate", fixture.path(), "--format", "json"]);
        assert_eq!(exit, Exit::Invalid, "{profile}");
        let found = report(&captured);
        let located: Vec<_> = found["diagnostics"]
            .as_array()
            .expect("diagnostics")
            .iter()
            .filter(|diagnostic| {
                diagnostic["code"].as_str() != Some("validate.production_validators_not_run")
            })
            .map(|diagnostic| {
                (
                    diagnostic["code"].as_str().expect("code").to_owned(),
                    diagnostic["location"]["pointer"]
                        .as_str()
                        .expect("pointer")
                        .to_owned(),
                    diagnostic["location"]["line"].as_u64().expect("line"),
                )
            })
            .collect();
        assert_eq!(
            located,
            [
                (
                    "profile.policy_default_allow".to_owned(),
                    "/default_action".to_owned(),
                    3
                ),
                (
                    "profile.policy_shadow_mode".to_owned(),
                    "/enforcement_mode".to_owned(),
                    4
                ),
                ("profile.wildcard_role".to_owned(), "/roles".to_owned(), 5),
                (
                    "profile.policy_shadow_mode".to_owned(),
                    "/routes/0/enforcement_mode".to_owned(),
                    6
                ),
            ],
            "{profile}"
        );
    }

    // The development profile adds no policy invariant, and every report
    // labels it non-production.
    let fixture = Fixture::with("development", policy);
    let (exit, captured) = run(&["validate", fixture.path()]);
    assert_eq!(exit, Exit::Success);
    assert!(captured
        .stdout()
        .contains("  deployment     deployment.yaml (profile development, non-production)\n"));
}

#[test]
fn warnings_pass_unless_strict_or_warnings_as_errors() {
    let fixture = Fixture::valid();
    fixture.write("notes.txt", "an entry the manifest does not reference\n");

    let (exit, captured) = run(&["validate", fixture.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Success);
    let found = report(&captured);
    assert_eq!(found["result"]["valid"], true);
    assert_eq!(
        codes(&found),
        [
            "bundle.unreferenced_entry",
            "validate.production_validators_not_run"
        ]
    );
    assert_eq!(found["diagnostics"][0]["severity"], "warning");
    assert_eq!(
        found["diagnostics"][0]["location"],
        json!({"file": "notes.txt", "pointer": ""})
    );

    let (exit, captured) = run(&[
        "validate",
        fixture.path(),
        "--warnings-as-errors",
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Invalid);
    let found = report(&captured);
    assert_eq!(found["outcome"], "invalid");
    assert_eq!(found["result"]["valid"], true);
    assert_eq!(
        found["diagnostics"][2],
        json!({
            "code": "validate.warnings_as_errors",
            "severity": "error",
            "message": "--warnings-as-errors was given and a warning was reported",
            "remediation": "docs/ggctl.md#validate-diagnostics",
            "location": {"argument": 3},
        })
    );

    let (exit, captured) = run(&["validate", "--strict", fixture.path()]);
    assert_eq!(exit, Exit::Invalid);
    assert!(
        captured.stdout().ends_with("invalid, 1 error\n")
            || captured.stdout().contains(": invalid, 1 error\n")
    );
    assert!(captured
        .stderr()
        .starts_with("ggctl: error: bundle.unreferenced_entry: "));

    // Without warnings the flag changes nothing.
    let clean = Fixture::valid();
    let (exit, _) = run(&["validate", clean.path(), "--warnings-as-errors"]);
    assert_eq!(exit, Exit::Success);
}

#[test]
fn a_bundle_that_cannot_be_read_exits_1() {
    let fixture = Fixture::empty();
    let missing = fixture.root.join("missing");
    let missing = missing.to_str().expect("UTF-8");
    let (exit, captured) = run(&["validate", missing, "--format", "json"]);
    assert_eq!(exit, Exit::Failure);
    let found = report(&captured);
    assert_eq!(found["outcome"], "failure");
    assert_eq!(found["result"], json!({"valid": false}));
    assert_eq!(codes(&found), ["bundle.root_unavailable"]);
    assert!(found["diagnostics"][0].get("location").is_none());
    // The path is an argument and is never echoed.
    assert!(!captured.stdout().contains(missing));

    let (exit, captured) = run(&["validate", missing]);
    assert_eq!(exit, Exit::Failure);
    assert_eq!(captured.stdout(), "bundle: invalid, 1 error\n");

    // An empty directory is a bundle without a manifest: invalid, not I/O.
    let (exit, captured) = run(&["validate", fixture.path()]);
    assert_eq!(exit, Exit::Invalid);
    assert!(captured
        .stderr()
        .starts_with("ggctl: error: bundle.manifest_missing: "));
}

#[test]
fn sarif_carries_the_diagnostics_alone_and_keeps_the_exit_code() {
    let fixture = Fixture::valid();
    fixture.write("notes.txt", "unreferenced\n");
    fixture.write(
        "tools.json",
        "{\"schema_version\": \"0.1.0\", \"tools\": []}\n",
    );
    let (exit, captured) = run(&["validate", fixture.path(), "--format", "sarif"]);
    assert_eq!(exit, Exit::Invalid);
    assert!(captured.stderr().is_empty());
    let log: Value = serde_json::from_str(captured.stdout()).expect("one SARIF log");
    assert_eq!(log["version"], "2.1.0");
    let results = log["runs"][0]["results"].as_array().expect("results");
    let summary: Vec<_> = results
        .iter()
        .map(|result| {
            (
                result["ruleId"].as_str().expect("rule"),
                result["level"].as_str().expect("level"),
                result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].as_str(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            ("bundle.digest_mismatch", "error", Some("tools.json")),
            ("bundle.unreferenced_entry", "warning", Some("notes.txt")),
            ("validate.production_validators_not_run", "note", None),
        ]
    );
    assert!(!captured.stdout().contains(fixture.path()));
}

#[test]
fn only_validate_and_diff_offer_sarif() {
    for words in [
        &["doctor", "x", "--format", "sarif"][..],
        &["schema", "--format", "sarif"],
    ] {
        let arguments: Vec<OsString> = words.iter().map(OsString::from).collect();
        match cli::parse(&arguments) {
            Err(diagnostic) => assert_eq!(diagnostic.code, Code::InvalidValue, "{words:?}"),
            Ok(parsed) => panic!("{words:?} should be refused, got {parsed:?}"),
        }
    }
}

#[test]
fn ggctl_and_bundle_reader_codes_never_share_a_spelling() {
    // A report carries both catalogs, so a code must name one meaning.
    let mut seen = BTreeSet::new();
    for code in Code::ALL {
        assert!(seen.insert(code.as_str()), "{}", code.as_str());
    }
    for code in gateway_config::bundle::Code::ALL {
        assert!(
            seen.insert(code.as_str()),
            "{} is also a ggctl code",
            code.as_str()
        );
    }
    for reason in crate::doctor::Reason::ALL {
        assert!(seen.insert(reason.as_str()), "{}", reason.as_str());
    }
}
