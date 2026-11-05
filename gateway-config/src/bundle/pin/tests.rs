use std::{fs, path::PathBuf};

use super::{pin_bundle, FilePin, PinReport};
use crate::bundle::{
    read_bundle, sha256_pin, BundleDiagnostic, Code, FileName, FileRole, Position,
    PublishedSchemasOnly, ReadOptions,
};

const DEPLOYMENT: &str =
    "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayDeployment\nspec:\n  profile: production\n";
const POLICY: &str = "{\n  \"schema_version\": \"0.1.0\",\n  \"default_action\": \"deny\"\n}\n";
const EDITED_POLICY: &str = "{\n  \"schema_version\": \"0.1.0\",\n  \"default_action\": \"deny\",\n  \"enforcement_mode\": \"enforce\"\n}\n";
const TOOLS: &str = "{\n  \"schema_version\": \"0.1.0\",\n  \"tools\": []\n}\n";

/// A manifest in the forms an operator may write by hand: comments, a flow
/// mapping, single and double quotes, and members in an unusual order. The
/// placeholders stand for each file's pin.
const MANIFEST: &str = concat!(
    "# Reviewed by hand: comments and layout must survive pinning.\n",
    "apiVersion: greengateway.dev/v1alpha1\n",
    "kind: GatewayBundle\n",
    "metadata:\n",
    "  name: payments-production   # the ConfigMap prefix\n",
    "spec:\n",
    "  deployment: { path: deployment.yaml, sha256: 'DEPLOYMENT' }\n",
    "  resources:\n",
    "    # The security team reviews the policy.\n",
    "    policy:\n",
    "      source: bundle\n",
    "      sha256: \"POLICY\"   # pinned\n",
    "      path: policy.json\n",
    "      schema_version: \"0.1.0\"\n",
    "    tools:\n",
    "      source: bundle\n",
    "      path: tools.json\n",
    "      schema_version: \"0.1.0\"\n",
    "      sha256: \"TOOLS\"\n",
    "    connections:\n",
    "      source: server\n",
);

/// A bundle directory under the system temporary directory, removed on drop.
struct Fixture {
    root: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Fixture {
    /// The three files, pinned by [`MANIFEST`] as they are written.
    fn pinned() -> Self {
        let root = std::env::temp_dir().join(format!(
            "greengateway-pin-{}",
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir_all(&root).expect("the bundle directory should create");
        #[cfg(unix)]
        set_mode(&root, 0o755);
        let fixture = Self { root };
        fixture.write("deployment.yaml", DEPLOYMENT);
        fixture.write("policy.json", POLICY);
        fixture.write("tools.json", TOOLS);
        fixture.write("bundle.yaml", &fixture.manifest(MANIFEST));
        fixture
    }

    fn write(&self, name: &str, contents: &str) {
        let path = self.root.join(name);
        fs::write(&path, contents).expect("the bundle file should write");
        #[cfg(unix)]
        set_mode(&path, 0o644);
    }

    fn bytes(&self, name: &str) -> Vec<u8> {
        fs::read(self.root.join(name)).expect("the bundle file should read")
    }

    fn pin_of(&self, name: &str) -> String {
        sha256_pin(&self.bytes(name))
    }

    /// `template` with each placeholder replaced by its file's current pin.
    fn manifest(&self, template: &str) -> String {
        template
            .replace("DEPLOYMENT", &self.pin_of("deployment.yaml"))
            .replace("POLICY", &self.pin_of("policy.json"))
            .replace("TOOLS", &self.pin_of("tools.json"))
    }

    fn pin(&self) -> PinReport {
        pin_bundle(&self.root, ReadOptions::default(), &PublishedSchemasOnly)
    }
}

#[cfg(unix)]
fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("permissions should set");
}

fn codes(diagnostics: &[BundleDiagnostic]) -> Vec<Code> {
    diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code)
        .collect()
}

/// The byte ranges in which two equally long byte strings differ.
fn differing_ranges(left: &[u8], right: &[u8]) -> Vec<(usize, usize)> {
    assert_eq!(left.len(), right.len());
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for (index, (a, b)) in left.iter().zip(right).enumerate() {
        if a != b {
            match ranges.last_mut() {
                Some((_, end)) if *end == index => *end = index + 1,
                _ => ranges.push((index, index + 1)),
            }
        }
    }
    ranges
}

#[test]
fn an_edited_file_is_repinned_and_only_its_digits_change() {
    let fixture = Fixture::pinned();
    let before = fixture.bytes("bundle.yaml");
    let previous = fixture.pin_of("policy.json");
    fixture.write("policy.json", EDITED_POLICY);
    // The edited policy no longer matches its pin, so the reader refuses it.
    let read = read_bundle(&fixture.root, ReadOptions::default(), &PublishedSchemasOnly);
    assert_eq!(codes(&read.diagnostics), [Code::DigestMismatch]);

    let report = fixture.pin();
    assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
    let plan = report.plan.expect("a plan");
    assert_eq!(plan.original_manifest(), before.as_slice());
    assert!(plan.changed());
    assert_eq!(
        plan.pins,
        [
            FilePin {
                role: FileRole::Deployment,
                file: FileName::parse("deployment.yaml").expect("valid"),
                previous: fixture.pin_of("deployment.yaml"),
                sha256: fixture.pin_of("deployment.yaml"),
            },
            FilePin {
                role: FileRole::Policy,
                file: FileName::parse("policy.json").expect("valid"),
                previous: previous.clone(),
                sha256: fixture.pin_of("policy.json"),
            },
            FilePin {
                role: FileRole::Tools,
                file: FileName::parse("tools.json").expect("valid"),
                previous: fixture.pin_of("tools.json"),
                sha256: fixture.pin_of("tools.json"),
            },
        ]
    );
    assert_eq!(
        plan.pins.iter().map(FilePin::changed).collect::<Vec<_>>(),
        [false, true, false]
    );

    // Every byte outside the policy pin's digits is kept: comments, order,
    // quoting and spacing.
    let after = plan.manifest().to_vec();
    assert_eq!(after, fixture.manifest(MANIFEST).into_bytes());
    let digits = std::str::from_utf8(&before)
        .expect("UTF-8")
        .find(&previous)
        .expect("the old pin is in the manifest");
    let ranges = differing_ranges(&before, &after);
    assert!(
        ranges
            .iter()
            .all(|(start, end)| *start >= digits && *end <= digits + 64),
        "{ranges:?}"
    );
    assert!(!ranges.is_empty());

    // Written, the manifest reads back as exactly the planned bundle.
    fs::write(fixture.root.join("bundle.yaml"), &after).expect("the manifest writes");
    let read = read_bundle(
        &fixture.root,
        ReadOptions { strict: true },
        &PublishedSchemasOnly,
    );
    let bundle = read.bundle.expect("the pinned bundle is valid");
    assert!(plan.is_read_back_by(&bundle));
    assert_eq!(bundle.source_digest, plan.source_digest);
}

#[test]
fn every_stale_pin_is_replaced_and_current_pins_plan_no_change() {
    let fixture = Fixture::pinned();
    let report = fixture.pin();
    let plan = report.plan.expect("a plan");
    assert!(report.diagnostics.is_empty());
    assert!(!plan.changed());
    assert_eq!(plan.manifest(), plan.original_manifest());
    assert!(plan.pins.iter().all(|pin| !pin.changed()));

    // Every file changes, in each quoting form the manifest uses.
    fixture.write("deployment.yaml", &format!("# edited\n{DEPLOYMENT}"));
    fixture.write("policy.json", EDITED_POLICY);
    fixture.write(
        "tools.json",
        "{\"schema_version\": \"0.1.0\", \"tools\": []}\n",
    );
    let report = fixture.pin();
    assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
    let plan = report.plan.expect("a plan");
    assert!(plan.pins.iter().all(FilePin::changed));
    assert_eq!(plan.manifest(), fixture.manifest(MANIFEST).as_bytes());
}

#[test]
fn a_file_that_fails_its_own_checks_is_never_pinned() {
    for (name, contents, expected) in [
        (
            "policy.json",
            "{\"schema_version\": \"0.1.0\", \"default_action\": \"allow\"}\n",
            Code::PolicyDefaultAllow,
        ),
        (
            "tools.json",
            "{\"schema_version\": \"0.1.0\", \"tools\": [}\n",
            Code::JsonSyntax,
        ),
        (
            "deployment.yaml",
            "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayDeployment\nspec:\n  profile: staging\n",
            Code::InvalidValue,
        ),
        ("policy.json", "{\"schema_version\": \"0.1.0\"}\r\n", Code::CarriageReturn),
    ] {
        let fixture = Fixture::pinned();
        fixture.write(name, contents);
        let report = fixture.pin();
        assert!(report.plan.is_none(), "{name}");
        // The stale pin is not itself reported: only the file's own problem.
        assert_eq!(codes(&report.diagnostics), [expected], "{name}");
        assert!(report.manifest.is_some(), "{name}");
    }

    let fixture = Fixture::pinned();
    fs::remove_file(fixture.root.join("tools.json")).expect("removes");
    let report = fixture.pin();
    assert!(report.plan.is_none());
    assert_eq!(codes(&report.diagnostics), [Code::FileMissing]);
}

#[test]
fn the_manifest_itself_must_be_valid_its_pins_included() {
    let fixture = Fixture::pinned();
    fixture.write(
        "bundle.yaml",
        &fixture
            .manifest(MANIFEST)
            .replace(&fixture.pin_of("tools.json"), "not-a-digest"),
    );
    let report = fixture.pin();
    assert!(report.plan.is_none());
    assert!(report.manifest.is_none());
    assert_eq!(codes(&report.diagnostics), [Code::InvalidDigest]);

    let fixture = Fixture::pinned();
    fs::remove_file(fixture.root.join("bundle.yaml")).expect("removes");
    assert_eq!(codes(&fixture.pin().diagnostics), [Code::ManifestMissing]);
}

#[test]
fn a_pin_that_must_change_is_replaced_only_between_quotes() {
    // A stale pin written plain, or with escapes, has no replacement of the
    // same length that the YAML subset reads the same way.
    let stale = "a".repeat(64);
    let escaped = format!("\\u0061{}", "a".repeat(63));
    for (spelling, column) in [(stale.clone(), 15), (format!("\"{escaped}\""), 15)] {
        let fixture = Fixture::pinned();
        let manifest = fixture.manifest(MANIFEST).replace(
            &format!("sha256: \"{}\"", fixture.pin_of("tools.json")),
            &format!("sha256: {spelling}"),
        );
        fixture.write("bundle.yaml", &manifest);
        let report = fixture.pin();
        assert!(report.plan.is_none(), "{spelling}");
        assert_eq!(report.diagnostics.len(), 1, "{:?}", report.diagnostics);
        let diagnostic = &report.diagnostics[0];
        assert_eq!(diagnostic.code, Code::PinNotRewritable);
        assert_eq!(
            diagnostic.file.as_ref().map(FileName::as_str),
            Some("bundle.yaml")
        );
        assert_eq!(
            diagnostic.pointer.to_string(),
            "/spec/resources/tools/sha256"
        );
        assert_eq!(diagnostic.position, Some(Position::new(19, column)));
        assert!(!diagnostic.to_string().contains(&stale));
    }
}

#[test]
fn the_read_back_check_refuses_a_bundle_that_changed_after_planning() {
    let fixture = Fixture::pinned();
    fixture.write("policy.json", EDITED_POLICY);
    let plan = fixture.pin().plan.expect("a plan");
    fs::write(fixture.root.join("bundle.yaml"), plan.manifest()).expect("the manifest writes");
    // The policy changes again between the plan and the read back.
    fixture.write("policy.json", POLICY);
    let read = read_bundle(&fixture.root, ReadOptions::default(), &PublishedSchemasOnly);
    assert_eq!(codes(&read.diagnostics), [Code::DigestMismatch]);

    // A read back that is valid but differs from the plan is refused too.
    fixture.write("bundle.yaml", &fixture.manifest(MANIFEST));
    let read = read_bundle(&fixture.root, ReadOptions::default(), &PublishedSchemasOnly);
    let bundle = read.bundle.expect("valid");
    assert!(!plan.is_read_back_by(&bundle));
}
