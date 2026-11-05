use std::{
    ffi::{OsStr, OsString},
    fs, io,
    path::Path,
};

use gateway_config::bundle::sha256_pin;
use serde_json::json;

use super::execute;
use crate::{
    cli::{self, Parsed},
    diagnostic::Exit,
    output::Rename,
    report::tests::Captured,
    validate::tests::{assert_no_canary, codes, report, run, Fixture, CANARY, DENY_POLICY},
};

/// A deny-by-default policy that differs from [`DENY_POLICY`].
const EDITED_POLICY: &str = "{\n  \"schema_version\": \"0.1.0\",\n  \"default_action\": \"deny\",\n  \"enforcement_mode\": \"enforce\"\n}\n";

/// Runs `ggctl pin` with `rename` putting the new manifest in place.
fn run_with(words: &[&str], rename: Rename) -> (Exit, Captured) {
    let arguments: Vec<OsString> = words.iter().map(OsString::from).collect();
    let mut captured = Captured::default();
    let exit = captured.run(b"", false, |io| match cli::parse(&arguments) {
        Ok(Parsed::Run(invocation)) => execute(&invocation, io, rename),
        other => panic!("{words:?} should run, got {other:?}"),
    });
    (exit, captured)
}

/// Every entry of a directory with its bytes, sorted by name.
fn contents(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut entries: Vec<_> = fs::read_dir(root)
        .expect("the directory lists")
        .map(|entry| {
            let entry = entry.expect("an entry");
            (
                entry.file_name().into_string().expect("UTF-8"),
                fs::read(entry.path()).expect("the file reads"),
            )
        })
        .collect();
    entries.sort();
    entries
}

fn manifest(fixture: &Fixture) -> Vec<u8> {
    fs::read(fixture.root.join("bundle.yaml")).expect("the manifest reads")
}

#[test]
fn editing_the_policy_then_pinning_makes_validate_pass() {
    let fixture = Fixture::valid();
    let previous = sha256_pin(DENY_POLICY.as_bytes());
    fixture.write("policy.json", EDITED_POLICY);
    let (exit, captured) = run(&["validate", fixture.path()]);
    assert_eq!(exit, Exit::Invalid);
    assert!(captured.stderr().contains("bundle.digest_mismatch"));

    let (exit, captured) = run(&["pin", fixture.path()]);
    assert_eq!(exit, Exit::Success, "{}", captured.stderr());
    let stdout = captured.stdout();
    let digest = &stdout.split("sha256:").nth(1).expect("a source digest")[..64];
    assert_eq!(
        stdout,
        format!(
            "bundle payments-production (greengateway.dev/v1alpha1): pinned, 1 pin changed and \
             bundle.yaml rewritten\n  \
             source digest  sha256:{digest}\n  \
             deployment     deployment.yaml (pin unchanged)\n  \
             policy         policy.json (pin changed)\n  \
             tools          tools.json (pin unchanged)\n"
        )
    );
    assert!(captured
        .stderr()
        .starts_with("ggctl: info: validate.production_validators_not_run: "));

    let (exit, captured) = run(&["validate", fixture.path(), "--strict", "--format", "json"]);
    assert_eq!(exit, Exit::Success);
    let validated = report(&captured);
    assert_eq!(
        validated["result"]["bundle"]["sourceDigest"],
        format!("sha256:{digest}")
    );

    // Pinning again finds every pin current and writes nothing.
    let before = contents(&fixture.root);
    let (exit, captured) = run(&["pin", fixture.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Success);
    assert_eq!(contents(&fixture.root), before);
    let found = report(&captured);
    assert_eq!(found["command"], "pin");
    assert_eq!(found["outcome"], "success");
    assert_eq!(codes(&found), ["validate.production_validators_not_run"]);
    let result = &found["result"];
    assert_eq!(result["valid"], true);
    assert_eq!(result["changed"], false);
    assert_eq!(result["written"], false);
    assert!(result["bundle"].get("sourceDigest").is_none());
    assert_eq!(result["pinned"]["sourceDigest"], format!("sha256:{digest}"));
    assert_eq!(
        result["files"][1],
        json!({
            "role": "policy",
            "file": "policy.json",
            "previous": sha256_pin(EDITED_POLICY.as_bytes()),
            "sha256": sha256_pin(EDITED_POLICY.as_bytes()),
            "changed": false,
        })
    );
    assert_ne!(previous, sha256_pin(EDITED_POLICY.as_bytes()));
}

#[test]
fn a_json_report_names_each_pin_it_changed() {
    let fixture = Fixture::valid();
    let previous = sha256_pin(DENY_POLICY.as_bytes());
    fixture.write("policy.json", EDITED_POLICY);
    let (exit, captured) = run(&["pin", fixture.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Success);
    let found = report(&captured);
    let result = &found["result"];
    assert_eq!(result["changed"], true);
    assert_eq!(result["written"], true);
    assert_eq!(result["bundle"]["name"], "payments-production");
    assert_eq!(
        result["files"]
            .as_array()
            .expect("files")
            .iter()
            .map(|file| (file["role"].clone(), file["changed"].clone()))
            .collect::<Vec<_>>(),
        [
            (json!("deployment"), json!(false)),
            (json!("policy"), json!(true)),
            (json!("tools"), json!(false)),
        ]
    );
    assert_eq!(result["files"][1]["previous"], previous);
    assert_eq!(
        result["files"][1]["sha256"],
        sha256_pin(EDITED_POLICY.as_bytes())
    );
    assert_eq!(
        result["pinned"]["policy"]["sha256"],
        sha256_pin(EDITED_POLICY.as_bytes())
    );
}

#[test]
fn manifest_bytes_outside_the_pins_are_unchanged() {
    let fixture = Fixture::valid();
    let template = concat!(
        "# Reviewed by hand.\n",
        "apiVersion: greengateway.dev/v1alpha1\n",
        "kind: GatewayBundle\n",
        "metadata:\n",
        "  name: payments-production    # the ConfigMap prefix\n",
        "spec:\n",
        "  deployment: { path: deployment.yaml, sha256: 'DEPLOYMENT' }\n",
        "  resources:\n",
        "    tools:   # tools before the policy\n",
        "      sha256: \"TOOLS\"\n",
        "      source: bundle\n",
        "      schema_version: \"0.1.0\"\n",
        "      path: tools.json\n",
        "    policy:\n",
        "      source: bundle\n",
        "      path: policy.json\n",
        "      schema_version: \"0.1.0\"\n",
        "      sha256: 'POLICY'   # reviewed\n",
        "    connections:\n",
        "      source: server\n",
    );
    let pinned = |deployment: &str, policy: &str, tools: &str| {
        template
            .replace("DEPLOYMENT", &sha256_pin(deployment.as_bytes()))
            .replace("POLICY", &sha256_pin(policy.as_bytes()))
            .replace("TOOLS", &sha256_pin(tools.as_bytes()))
    };
    let deployment =
        "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayDeployment\nspec:\n  profile: production\n";
    let tools = crate::validate::tests::TOOLS;
    fixture.write("bundle.yaml", &pinned(deployment, DENY_POLICY, tools));
    let (exit, _) = run(&["validate", fixture.path()]);
    assert_eq!(exit, Exit::Success);

    let edited_tools = "{\"schema_version\": \"0.1.0\", \"tools\": []}\n";
    fixture.write("policy.json", EDITED_POLICY);
    fixture.write("tools.json", edited_tools);
    let before = manifest(&fixture);
    let (exit, captured) = run(&["pin", fixture.path()]);
    assert_eq!(exit, Exit::Success, "{}", captured.stderr());
    assert!(captured
        .stdout()
        .contains(": pinned, 2 pins changed and bundle.yaml rewritten\n"));
    let after = manifest(&fixture);
    assert_eq!(
        after,
        pinned(deployment, EDITED_POLICY, edited_tools).into_bytes()
    );
    // Only bytes inside the two replaced pins differ.
    let text = std::str::from_utf8(&before).expect("UTF-8");
    let windows: Vec<usize> = [DENY_POLICY, tools]
        .iter()
        .map(|old| text.find(&sha256_pin(old.as_bytes())).expect("old pin"))
        .collect();
    assert_eq!(before.len(), after.len());
    for (index, (old, new)) in before.iter().zip(&after).enumerate() {
        if old != new {
            assert!(
                windows
                    .iter()
                    .any(|start| (*start..start + 64).contains(&index)),
                "byte {index} outside a pin changed"
            );
        }
    }
}

#[test]
fn an_invalid_file_leaves_the_manifest_unchanged() {
    let fixture = Fixture::valid();
    // An allow-by-default policy breaks the production profile, and its
    // unknown member names a value that must never be echoed.
    fixture.write(
        "policy.json",
        &format!(
            "{{\"schema_version\": \"0.1.0\", \"id\": \"{CANARY}\", \"default_action\": \"allow\"}}\n"
        ),
    );
    let before = contents(&fixture.root);
    let (exit, captured) = run(&["pin", fixture.path()]);
    assert_eq!(exit, Exit::Invalid);
    assert_eq!(
        captured.stdout(),
        "bundle payments-production (greengateway.dev/v1alpha1): not pinned, nothing was written\n"
    );
    assert!(captured.stderr().contains("profile.policy_default_allow"));
    assert!(!captured.stderr().contains("bundle.digest_mismatch"));
    assert_no_canary(&captured);
    assert_eq!(contents(&fixture.root), before);

    let (exit, captured) = run(&["pin", fixture.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Invalid);
    let found = report(&captured);
    assert_eq!(found["outcome"], "invalid");
    assert_eq!(
        codes(&found),
        [
            "profile.policy_default_allow",
            "validate.production_validators_not_run"
        ]
    );
    let result = &found["result"];
    assert_eq!(result["valid"], false);
    assert_eq!(result["files"], json!([]));
    assert_eq!(result["written"], false);
    assert!(result.get("pinned").is_none());
    assert_no_canary(&captured);
    assert_eq!(contents(&fixture.root), before);

    // A manifest that cannot be read at all is not pinned either.
    let missing = fixture.root.join("missing");
    let (exit, captured) = run(&["pin", missing.to_str().expect("UTF-8")]);
    assert_eq!(exit, Exit::Failure);
    assert!(captured.stderr().contains("bundle.root_unavailable"));
}

#[test]
fn strict_pinning_refuses_an_unreferenced_entry_and_writes_nothing() {
    let fixture = Fixture::valid();
    fixture.write("policy.json", EDITED_POLICY);
    fixture.write("notes.txt", "reviewed\n");
    let before = contents(&fixture.root);
    let (exit, captured) = run(&["pin", fixture.path(), "--strict"]);
    assert_eq!(exit, Exit::Invalid);
    assert!(captured.stderr().contains("bundle.unreferenced_entry"));
    assert_eq!(contents(&fixture.root), before);

    // Without --strict it is a warning, and the bundle is pinned.
    let (exit, captured) = run(&["pin", fixture.path()]);
    assert_eq!(exit, Exit::Success);
    assert!(captured
        .stderr()
        .contains("ggctl: warning: bundle.unreferenced_entry"));
    assert_ne!(manifest(&fixture), before[0].1);
}

/// Interrupts the write at its last step, after checking what an
/// interruption there leaves: the whole new manifest in its hidden file,
/// owner-only, and `bundle.yaml` untouched.
fn interrupted(from: &Path, to: &Path) -> io::Result<()> {
    let name = from
        .file_name()
        .and_then(OsStr::to_str)
        .expect("a UTF-8 name");
    assert!(name.starts_with(".bundle.yaml.ggctl-pin-"), "{name}");
    assert_eq!(to.file_name(), Some(OsStr::new("bundle.yaml")));
    let pending = fs::read(from).expect("the new manifest is written");
    let current = fs::read(to).expect("the old manifest is in place");
    assert_eq!(pending.len(), current.len());
    assert_ne!(pending, current);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(from).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // A process killed here leaves only the hidden file, which the reader
    // never opens: the bundle still reads as before.
    let root = to.parent().expect("the bundle directory");
    let read = gateway_config::bundle::read_bundle(
        root,
        gateway_config::bundle::ReadOptions { strict: true },
        &gateway_config::bundle::PublishedSchemasOnly,
    );
    let found: Vec<_> = read.diagnostics.iter().map(|d| d.code.as_str()).collect();
    assert_eq!(found, ["bundle.digest_mismatch"]);
    Err(io::Error::other("interrupted"))
}

#[test]
fn an_interrupted_write_leaves_no_partial_manifest() {
    let fixture = Fixture::valid();
    fixture.write("policy.json", EDITED_POLICY);
    let before = contents(&fixture.root);
    let (exit, captured) = run_with(&["pin", fixture.path(), "--format", "json"], interrupted);
    assert_eq!(exit, Exit::Failure);
    let found = report(&captured);
    assert_eq!(
        codes(&found),
        ["validate.production_validators_not_run", "pin.write_failed"]
    );
    assert_eq!(found["result"]["valid"], true);
    assert_eq!(found["result"]["changed"], true);
    assert_eq!(found["result"]["written"], false);
    assert!(found["result"].get("pinned").is_none());
    // The manifest is as it was, and the hidden file is gone.
    assert_eq!(contents(&fixture.root), before);

    // Uninterrupted, the same bundle is pinned.
    let (exit, _) = run(&["pin", fixture.path()]);
    assert_eq!(exit, Exit::Success);
    let (exit, _) = run(&["validate", fixture.path(), "--strict"]);
    assert_eq!(exit, Exit::Success);
}

#[cfg(unix)]
#[test]
fn a_linked_manifest_is_refused_and_its_target_left_alone() {
    let fixture = Fixture::valid();
    fixture.write("policy.json", EDITED_POLICY);
    let elsewhere = Fixture::empty();
    let target = elsewhere.root.join("bundle.yaml");
    fs::rename(fixture.root.join("bundle.yaml"), &target).expect("moves");
    std::os::unix::fs::symlink(&target, fixture.root.join("bundle.yaml")).expect("links");
    let before = fs::read(&target).expect("reads");
    let (exit, captured) = run(&["pin", fixture.path(), "--format", "json"]);
    assert_eq!(exit, Exit::Invalid);
    let found = report(&captured);
    assert_eq!(codes(&found), ["pin.manifest_link"]);
    assert_eq!(found["result"]["valid"], false);
    assert_eq!(fs::read(&target).expect("reads"), before);
    assert!(fs::symlink_metadata(fixture.root.join("bundle.yaml"))
        .expect("metadata")
        .file_type()
        .is_symlink());
}

/// A Kubernetes atomic-writer volume reads as a bundle, but its manifest is
/// a per-key link into a generation the kubelet owns: pin refuses it.
#[cfg(unix)]
#[test]
fn an_atomic_writer_volume_is_never_pinned() {
    use std::os::unix::fs::symlink;
    let source = Fixture::valid();
    let volume = Fixture::empty();
    let generation = volume.root.join("..2026_11_04_00_00_00.000000001");
    fs::create_dir(&generation).expect("creates");
    for (name, bytes) in contents(&source.root) {
        fs::write(generation.join(&name), bytes).expect("writes");
        symlink(format!("..data/{name}"), volume.root.join(&name)).expect("links");
    }
    symlink(
        "..2026_11_04_00_00_00.000000001",
        volume.root.join("..data"),
    )
    .expect("links");
    let (exit, _) = run(&["validate", volume.path()]);
    assert_eq!(exit, Exit::Success);
    let (exit, captured) = run(&["pin", volume.path()]);
    assert_eq!(exit, Exit::Invalid);
    assert!(captured.stderr().contains("pin.manifest_link"));
}
