use std::fs;

use serde_json::json;

use crate::{
    diagnostic::Exit,
    validate::tests::{codes, report, run, Fixture},
};

const V1ALPHA1: &str = "greengateway.dev/v1alpha1";

/// The files of a bundle directory, sorted by name, with their bytes.
fn contents(root: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<_> = fs::read_dir(root)
        .expect("the directory lists")
        .map(|entry| {
            let entry = entry.expect("an entry");
            (
                entry.file_name().into_string().expect("UTF-8"),
                fs::read(entry.path()).expect("the file reads"),
            )
        })
        .collect();
    files.sort();
    files
}

#[test]
fn converting_to_the_bundles_own_version_copies_it_unchanged_and_again_changes_nothing() {
    let source = Fixture::valid();
    let parent = Fixture::empty();
    let first = parent.root.join("first");
    let second = parent.root.join("second");
    let (exit, captured) = run(&[
        "convert",
        source.path(),
        "--to",
        V1ALPHA1,
        "--output",
        first.to_str().expect("UTF-8"),
    ]);
    assert_eq!(exit, Exit::Success, "{}", captured.stderr());
    assert_eq!(
        captured.stdout(),
        "bundle payments-production (greengateway.dev/v1alpha1): converted from \
         greengateway.dev/v1alpha1 to greengateway.dev/v1alpha1, written to the --output \
         directory with its files unchanged (it was already at greengateway.dev/v1alpha1)\n"
    );
    let mut expected = contents(&source.root);
    expected.push((".gitattributes".to_owned(), b"* text eol=lf\n".to_vec()));
    expected.sort();
    assert_eq!(contents(&first), expected);

    // Converting the converted bundle is converting once.
    let (exit, captured) = run(&[
        "convert",
        first.to_str().expect("UTF-8"),
        "--to",
        V1ALPHA1,
        "--output",
        second.to_str().expect("UTF-8"),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Success);
    assert_eq!(contents(&second), contents(&first));
    let found = report(&captured);
    assert_eq!(found["command"], "convert");
    assert_eq!(codes(&found), ["validate.production_validators_not_run"]);
    let result = &found["result"];
    assert_eq!(result["valid"], true);
    assert_eq!(result["from"], V1ALPHA1);
    assert_eq!(result["to"], V1ALPHA1);
    assert_eq!(result["changed"], false);
    assert_eq!(result["written"], true);
    assert_eq!(
        result["converted"]["sourceDigest"],
        result["bundle"]["sourceDigest"]
    );
}

#[test]
fn in_place_conversion_to_the_bundles_own_version_writes_nothing() {
    let source = Fixture::valid();
    let before = contents(&source.root);
    let (exit, captured) = run(&["convert", source.path(), "--to", V1ALPHA1, "--in-place"]);
    assert_eq!(exit, Exit::Success);
    assert_eq!(
        captured.stdout(),
        "bundle payments-production (greengateway.dev/v1alpha1): already at \
         greengateway.dev/v1alpha1; nothing to convert\n"
    );
    assert_eq!(contents(&source.root), before);
    let (exit, captured) = run(&[
        "convert",
        source.path(),
        "--to",
        V1ALPHA1,
        "--in-place",
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Success);
    let found = report(&captured);
    assert_eq!(found["result"]["written"], false);
    assert_eq!(found["result"]["changed"], false);
}

#[test]
fn an_unknown_target_is_refused_without_echoing_it_and_nothing_is_written() {
    let source = Fixture::valid();
    let parent = Fixture::empty();
    let output = parent.root.join("out");
    for target in [
        "greengateway.dev/v1alpha2",
        "greengateway.dev/v1",
        "greengateway.dev/v1alpha0",
        "zqcanaryversion",
    ] {
        let (exit, captured) = run(&[
            "convert",
            source.path(),
            "--to",
            target,
            "--output",
            output.to_str().expect("UTF-8"),
            "--format",
            "json",
        ]);
        assert_eq!(exit, Exit::Invalid, "{target}");
        let found = report(&captured);
        assert_eq!(
            codes(&found),
            [
                "validate.production_validators_not_run",
                "convert.unsupported_version"
            ]
        );
        assert_eq!(found["diagnostics"][1]["location"], json!({"argument": 3}));
        assert!(found["result"].get("to").is_none());
        if !V1ALPHA1.contains(target) {
            assert!(!captured.stdout().contains(target), "{target}");
        }
        assert!(!output.exists());
    }
}

#[test]
fn an_invalid_bundle_is_not_converted() {
    let source = Fixture::with(
        "production",
        "{\"schema_version\": \"0.1.0\", \"default_action\": \"allow\"}\n",
    );
    let parent = Fixture::empty();
    let output = parent.root.join("out");
    let (exit, captured) = run(&[
        "convert",
        source.path(),
        "--to",
        V1ALPHA1,
        "--output",
        output.to_str().expect("UTF-8"),
    ]);
    assert_eq!(exit, Exit::Invalid);
    assert!(captured.stdout().ends_with(": not converted\n"));
    assert!(captured.stderr().contains("profile.policy_default_allow"));
    assert!(!output.exists());
}

#[test]
fn an_output_that_holds_anything_is_refused_and_options_are_checked() {
    let source = Fixture::valid();
    let (exit, captured) = run(&[
        "convert",
        source.path(),
        "--to",
        V1ALPHA1,
        "--output",
        source.path(),
    ]);
    assert_eq!(exit, Exit::Conflict);
    assert!(captured.stderr().contains("output.destination_exists"));
    for (words, code) in [
        (
            vec![
                "convert",
                source.path(),
                "--to",
                V1ALPHA1,
                "--output",
                "x",
                "--in-place",
            ],
            "usage.conflicting_options",
        ),
        (
            vec!["convert", source.path(), "--to", V1ALPHA1],
            "usage.missing_argument",
        ),
        (
            vec!["convert", source.path(), "--in-place"],
            "usage.missing_argument",
        ),
    ] {
        let (exit, captured) = run(&words);
        assert_eq!(exit, Exit::Usage, "{words:?}");
        assert!(captured.stderr().contains(code), "{}", captured.stderr());
        assert!(captured.stdout().is_empty());
    }
}
