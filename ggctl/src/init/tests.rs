use std::fs;

use gateway_config::bundle::{
    self,
    init::{self, read_answers, scaffold, Answers, AnswersSyntax, GITATTRIBUTES},
    Profile, PublishedSchemasOnly, ReadOptions,
};
use serde_json::{json, Value};

use crate::{
    diagnostic::{Code, Exit},
    validate::tests::{codes, report, run, Fixture, CANARY},
};

/// A parent directory holding the `--output` directory, its UTF-8 path, and
/// the output's path.
fn parent() -> (Fixture, String) {
    let parent = Fixture::empty();
    let output = parent
        .root
        .join("bundle")
        .to_str()
        .expect("the temporary directory should be UTF-8")
        .to_owned();
    (parent, output)
}

fn entries(parent: &Fixture) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(&parent.root)
        .expect("the parent lists")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .into_string()
                .expect("UTF-8")
        })
        .collect();
    names.sort();
    names
}

fn assert_path_not_echoed(captured: &crate::report::tests::Captured, path: &str) {
    for text in [captured.stdout(), captured.stderr()] {
        assert!(!text.contains(path), "a path reached the output: {text}");
    }
}

const OPERATOR_ANSWERS: &str = "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayInitAnswers\nspec:\n  name: payments\n  operator:\n    issuer: \"provider:corporate\"\n    auth_methods: [bearer_token]\n";

#[test]
fn init_writes_the_profile_bundle_and_says_what_it_wrote() {
    for profile in Profile::ALL.iter().copied() {
        let (parent, output) = parent();
        let (exit, captured) = run(&["init", "--profile", profile.as_str(), "--output", &output]);
        assert_eq!(exit, Exit::Success, "{}", captured.stderr());
        let expected = scaffold(profile, &Answers::default());
        for file in &expected {
            assert_eq!(
                fs::read(parent.root.join("bundle").join(file.name.as_str())).expect("written"),
                file.bytes
            );
        }
        assert_eq!(
            fs::read_to_string(parent.root.join("bundle").join(".gitattributes"))
                .expect("attributes"),
            GITATTRIBUTES
        );
        assert_eq!(entries(&parent), ["bundle"]);
        let stdout = captured.stdout();
        assert!(
            stdout.starts_with(
                "created bundle greengateway (greengateway.dev/v1alpha1), standalone topology\n"
            ),
            "{stdout}"
        );
        let label = if profile == Profile::Development {
            format!("(profile {}, non-production)", profile.as_str())
        } else {
            format!("(profile {})", profile.as_str())
        };
        assert!(stdout.contains(&format!("  deployment     deployment.yaml {label}\n")));
        assert!(stdout.ends_with(
            "next: review the files, then run `ggctl validate --strict` on the --output directory\n"
        ));
        assert!(captured
            .stderr()
            .contains("validate.production_validators_not_run"));
        assert_path_not_echoed(&captured, &output);

        // What init wrote, validate accepts strictly.
        let (exit, _) = run(&["validate", &output, "--strict", "--warnings-as-errors"]);
        assert_eq!(exit, Exit::Success);
    }
}

#[test]
fn the_json_report_describes_the_bundle_read_back() {
    let (parent, output) = parent();
    let answers = parent.root.join("answers.yaml");
    fs::write(&answers, OPERATOR_ANSWERS).expect("answers write");
    let answers = answers.to_str().expect("UTF-8").to_owned();
    let (exit, captured) = run(&[
        "init",
        "--profile",
        "production",
        "--output",
        &output,
        "--answers",
        &answers,
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Success);
    let found = report(&captured);
    assert_eq!(found["command"], "init");
    assert_eq!(codes(&found), ["validate.production_validators_not_run"]);
    let result = &found["result"];
    assert_eq!(result["created"], true);
    assert_eq!(result["profile"], "production");
    assert_eq!(result["topology"], "standalone");
    assert_eq!(result["operator"], true);
    assert_eq!(result["bundle"]["name"], "payments");
    assert_eq!(result["bundle"]["deployment"]["profile"], "production");
    assert_eq!(result["bundle"]["policy"]["productionValidator"], "not_run");
    let policy: Value = serde_json::from_slice(
        &fs::read(parent.root.join("bundle").join("policy.json")).expect("policy"),
    )
    .expect("JSON");
    assert_eq!(
        policy["roles"]["operator"]["issuers"],
        json!(["provider:corporate"])
    );
    assert_path_not_echoed(&captured, &output);
    assert_path_not_echoed(&captured, &answers);
}

#[test]
fn a_cluster_bundle_leaves_policy_tools_and_connections_to_the_server() {
    let (parent, output) = parent();
    let answers = parent.root.join("answers.json");
    fs::write(
        &answers,
        r#"{"apiVersion": "greengateway.dev/v1alpha1", "kind": "GatewayInitAnswers", "spec": {"name": "fleet", "topology": "cluster"}}"#,
    )
    .expect("answers write");
    let (exit, captured) = run(&[
        "init",
        "--profile",
        "production",
        "--output",
        &output,
        "--answers",
        answers.to_str().expect("UTF-8"),
    ]);
    assert_eq!(exit, Exit::Success, "{}", captured.stderr());
    assert!(captured
        .stdout()
        .starts_with("created bundle fleet (greengateway.dev/v1alpha1), cluster topology\n"));
    assert!(captured.stdout().contains("  policy         server\n"));
    // Nothing is bundled, so no production validator was skipped.
    assert!(captured.stderr().is_empty(), "{}", captured.stderr());
    let read = bundle::read_bundle(
        &parent.root.join("bundle"),
        ReadOptions { strict: true },
        &PublishedSchemasOnly,
    );
    let read = read.bundle.expect("a valid bundle");
    assert_eq!(read.source_files().len(), 2);
    let answers = read_answers(&fs::read(&answers).expect("answers"), AnswersSyntax::Json)
        .expect("the answers read");
    assert_eq!(read.source_files(), scaffold(Profile::Production, &answers));
}

#[test]
fn invalid_answers_are_located_by_argument_and_nothing_is_written() {
    let (parent, output) = parent();
    let answers = parent.root.join("answers.yaml");
    fs::write(
        &answers,
        format!(
            "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayInitAnswers\nspec:\n  topology: cluster\n  client_secret: {CANARY}\n"
        ),
    )
    .expect("answers write");
    let answers = answers.to_str().expect("UTF-8").to_owned();
    let words = [
        "init",
        "--profile",
        "production",
        "--answers",
        &answers,
        "--output",
        &output,
    ];
    let (exit, captured) = run(&words);
    assert_eq!(exit, Exit::Invalid);
    assert_eq!(captured.stdout(), "init: no bundle was written\n");
    assert!(captured
        .stderr()
        .contains("ggctl: error: schema.unknown_member: "));
    assert!(captured.stderr().contains("\n  at: argument 4:5:3 /spec\n"));
    crate::validate::tests::assert_no_canary(&captured);
    assert_path_not_echoed(&captured, &answers);

    let mut json_words = words.to_vec();
    json_words.extend(["--format", "json"]);
    let (exit, captured) = run(&json_words);
    assert_eq!(exit, Exit::Invalid);
    let found = report(&captured);
    assert_eq!(
        found["result"],
        json!({"created": false, "profile": "production"})
    );
    assert_eq!(
        found["diagnostics"][0]["location"],
        json!({"argument": 4, "pointer": "/spec", "line": 5, "column": 3})
    );
    assert_eq!(
        found["diagnostics"][0]["remediation"],
        "docs/configuration-bundles.md#diagnostics"
    );
    assert_eq!(entries(&parent), ["answers.yaml"]);
}

#[test]
fn an_answers_file_that_cannot_be_used_is_refused_with_its_own_code() {
    let (parent, output) = parent();
    let missing = parent.root.join("missing.yaml");
    let directory = parent.root.join("directory.yaml");
    fs::create_dir(&directory).expect("a directory");
    let large = parent.root.join("large.yaml");
    fs::write(&large, vec![b'#'; init::MAX_ANSWERS_BYTES + 1]).expect("a large file");
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut cases = vec![
        (missing, Code::AnswersUnreadable, Exit::Failure),
        (directory, Code::AnswersNotRegularFile, Exit::Usage),
        (large, Code::AnswersTooLarge, Exit::Invalid),
    ];
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let writable = parent.root.join("writable.yaml");
        fs::write(&writable, OPERATOR_ANSWERS).expect("answers write");
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o666)).expect("mode");
        cases.push((writable, Code::AnswersUnsafePermissions, Exit::Usage));
    }
    for (path, code, expected) in cases {
        let (exit, captured) = run(&[
            "init",
            "--profile",
            "production",
            "--output",
            &output,
            "--answers",
            path.to_str().expect("UTF-8"),
        ]);
        assert_eq!(exit, expected, "{}", code.as_str());
        assert!(
            captured
                .stderr()
                .starts_with(&format!("ggctl: error: {}: ", code.as_str())),
            "{}",
            captured.stderr()
        );
        assert!(captured.stderr().contains("(argument 6)"));
        assert!(!parent.root.join("bundle").exists());
    }
}

#[test]
fn an_output_that_holds_anything_is_refused_with_exit_5_and_kept() {
    let (parent, output) = parent();
    fs::create_dir(parent.root.join("bundle")).expect("a directory");
    fs::write(parent.root.join("bundle").join("notes.txt"), CANARY).expect("a file");
    let (exit, captured) = run(&["init", "--profile", "production", "--output", &output]);
    assert_eq!(exit, Exit::Conflict);
    assert!(captured
        .stderr()
        .starts_with("ggctl: error: output.destination_exists: "));
    assert!(captured.stderr().contains("(argument 4)"));
    assert_eq!(
        fs::read_to_string(parent.root.join("bundle").join("notes.txt")).expect("kept"),
        CANARY
    );
    assert_eq!(
        fs::read_dir(parent.root.join("bundle"))
            .expect("lists")
            .count(),
        1
    );
    assert_eq!(entries(&parent), ["bundle"]);
    assert_path_not_echoed(&captured, &output);
}

#[test]
fn init_needs_a_profile_and_an_output_and_has_no_web_wizard_yet() {
    let (_parent, output) = parent();
    for words in [
        &["init", "--output", output.as_str()][..],
        &["init", "--profile", "production"],
    ] {
        let (exit, captured) = run(words);
        assert_eq!(exit, Exit::Usage, "{words:?}");
        assert!(captured.stderr().contains("usage.missing_argument"));
    }
    for words in [
        &["init", "--profile", "staging", "--output", output.as_str()][..],
        &[
            "init",
            "--profile",
            "production",
            "--output",
            output.as_str(),
            "--web",
        ],
    ] {
        let arguments: Vec<std::ffi::OsString> =
            words.iter().map(std::ffi::OsString::from).collect();
        assert!(crate::cli::parse(&arguments).is_err(), "{words:?}");
    }
}
