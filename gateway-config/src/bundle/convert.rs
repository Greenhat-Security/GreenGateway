//! Explicit, versioned bundle conversion (issue #242 PR 6; ADR-0008,
//! "Compatibility and versions"): what `ggctl convert` performs.
//!
//! Every document version the reader implements has one place on a ladder,
//! oldest first ([`ApiVersion::ALL`]), and each pair of neighbours has one
//! conversion step. Converting a bundle runs the steps from its version up
//! to the target, in order, so the result depends on nothing but the bundle
//! and the target; a bundle already at the target runs none and comes back
//! byte for byte, so converting twice is converting once. A target older
//! than the bundle is refused rather than approximated, and so is any
//! version the ladder does not hold: there is no prefix match and no
//! downgrade.
//!
//! Conversion starts from a bundle the reader accepted, so nothing it has
//! not validated is carried along, and `ggctl convert` reads its output back
//! with the reader before anything treats it as a bundle.
//!
//! `v1alpha1` is the only version today, so the ladder has one rung and no
//! step: the only conversion is the identity and every other target is
//! refused. A release that adds a version adds its rung and its step here,
//! and keeps reading the previous version for at least one minor release.

use super::{ApiVersion, Bundle, SourceFile};

/// Why a conversion was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// The target is not a version this reader implements, or no step leads
    /// to it.
    UnsupportedVersion,
    /// The target is older than the bundle.
    Downgrade,
}

/// A bundle converted to a target version.
#[derive(Debug)]
pub struct Conversion {
    pub from: ApiVersion,
    pub to: ApiVersion,
    /// The converted bundle's files, the manifest first.
    pub files: Vec<SourceFile>,
    /// How many steps ran; none when the bundle was already at the target.
    pub steps: usize,
}

impl Conversion {
    /// Whether the files differ from the bundle's: a step ran.
    pub fn changed(&self) -> bool {
        self.steps > 0
    }
}

/// One conversion between neighbouring versions. A step is total: a version
/// that cannot represent something its predecessor could is refused when it
/// is planned, never converted with a loss.
struct Step {
    from: &'static str,
    to: &'static str,
    apply: fn(Vec<SourceFile>) -> Vec<SourceFile>,
}

/// The steps between neighbouring rungs of [`ApiVersion::ALL`].
const STEPS: &[Step] = &[];

/// Converts `bundle` to the version `target` names exactly.
pub fn convert<P, T>(bundle: &Bundle<P, T>, target: &str) -> Result<Conversion, Refusal> {
    let ladder: Vec<_> = ApiVersion::ALL
        .iter()
        .map(|version| version.as_str())
        .collect();
    let steps = plan(&ladder, STEPS, bundle.api_version.as_str(), target)?;
    let to = ApiVersion::parse(target).ok_or(Refusal::UnsupportedVersion)?;
    let files = steps
        .iter()
        .fold(bundle.source_files().to_vec(), |files, step| {
            (step.apply)(files)
        });
    Ok(Conversion {
        from: bundle.api_version,
        to,
        files,
        steps: steps.len(),
    })
}

/// The steps from `from` to `to` on `ladder`, in order.
fn plan<'s>(
    ladder: &[&str],
    steps: &'s [Step],
    from: &str,
    to: &str,
) -> Result<Vec<&'s Step>, Refusal> {
    let rung = |version: &str| ladder.iter().position(|rung| *rung == version);
    let (Some(from), Some(to)) = (rung(from), rung(to)) else {
        return Err(Refusal::UnsupportedVersion);
    };
    if to < from {
        return Err(Refusal::Downgrade);
    }
    ladder[from..=to]
        .windows(2)
        .map(|pair| {
            steps
                .iter()
                .find(|step| step.from == pair[0] && step.to == pair[1])
                .ok_or(Refusal::UnsupportedVersion)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::bundle::{
        init::{scaffold, Answers, GITATTRIBUTES},
        read_bundle,
        source::FileName,
        FileRole, Profile, PublishedSchemasOnly, ReadOptions,
    };

    fn marked(mut files: Vec<SourceFile>, marker: &'static str) -> Vec<SourceFile> {
        files.push(SourceFile {
            role: FileRole::Tools,
            name: FileName::fixed(marker),
            bytes: marker.as_bytes().to_vec(),
        });
        files
    }

    const LADDER: &[&str] = &["test/v1alpha1", "test/v1alpha2", "test/v1beta1"];
    const TEST_STEPS: &[Step] = &[
        Step {
            from: "test/v1alpha2",
            to: "test/v1beta1",
            apply: |files| marked(files, "beta1.json"),
        },
        Step {
            from: "test/v1alpha1",
            to: "test/v1alpha2",
            apply: |files| marked(files, "alpha2.json"),
        },
    ];

    /// The markers the planned steps leave, in the order they ran.
    fn run(from: &str, to: &str) -> Result<Vec<String>, Refusal> {
        let steps = plan(LADDER, TEST_STEPS, from, to)?;
        let files = steps
            .iter()
            .fold(Vec::new(), |files, step| (step.apply)(files));
        Ok(files
            .iter()
            .map(|file| file.name.as_str().to_owned())
            .collect())
    }

    #[test]
    fn steps_run_in_ladder_order_from_the_bundle_up_to_the_target() {
        assert_eq!(
            run("test/v1alpha1", "test/v1beta1"),
            Ok(vec!["alpha2.json".to_owned(), "beta1.json".to_owned()])
        );
        assert_eq!(
            run("test/v1alpha2", "test/v1beta1"),
            Ok(vec!["beta1.json".to_owned()])
        );
        assert_eq!(
            run("test/v1alpha1", "test/v1alpha2"),
            Ok(vec!["alpha2.json".to_owned()])
        );
        for version in LADDER {
            assert_eq!(run(version, version), Ok(Vec::new()), "{version}");
        }
    }

    #[test]
    fn a_downgrade_an_unknown_version_and_a_missing_step_are_refused() {
        assert_eq!(
            run("test/v1beta1", "test/v1alpha1"),
            Err(Refusal::Downgrade)
        );
        assert_eq!(
            run("test/v1alpha2", "test/v1alpha1"),
            Err(Refusal::Downgrade)
        );
        for target in [
            "test/v1",
            "test/v1alpha",
            "TEST/v1alpha2",
            "test/v1alpha2 ",
            "",
        ] {
            assert_eq!(
                run("test/v1alpha1", target),
                Err(Refusal::UnsupportedVersion),
                "{target:?}"
            );
        }
        assert_eq!(
            plan(LADDER, &TEST_STEPS[..1], "test/v1alpha1", "test/v1beta1")
                .map(|steps| steps.len()),
            Err(Refusal::UnsupportedVersion)
        );
    }

    #[test]
    fn the_one_real_version_converts_to_itself_unchanged_and_refuses_every_other_target() {
        assert!(
            STEPS.is_empty(),
            "a new step needs its own conversion tests"
        );
        let files = scaffold(Profile::Production, &Answers::default());
        let root = std::env::temp_dir().join(format!(
            "greengateway-bundle-convert-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).expect("temporary bundle directory should create");
        for file in &files {
            fs::write(root.join(file.name.as_str()), &file.bytes)
                .expect("bundle file should write");
        }
        fs::write(root.join(".gitattributes"), GITATTRIBUTES).expect("attributes should write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for entry in fs::read_dir(&root).expect("the bundle lists") {
                let path = entry.expect("an entry").path();
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                    .expect("permissions should set");
            }
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("permissions should set");
        }
        let read = read_bundle(&root, ReadOptions { strict: true }, &PublishedSchemasOnly);
        let _ = fs::remove_dir_all(&root);
        let bundle = read.bundle.expect("the scaffold reads as a bundle");
        let conversion = convert(&bundle, "greengateway.dev/v1alpha1").expect("the identity");
        assert_eq!(conversion.from, ApiVersion::V1Alpha1);
        assert_eq!(conversion.to, ApiVersion::V1Alpha1);
        assert!(!conversion.changed());
        assert_eq!(conversion.files, files);
        for target in [
            "greengateway.dev/v1alpha2",
            "greengateway.dev/v1",
            "greengateway.dev/v1alpha",
            "greengateway.dev/v1alpha0",
            "GreenGateway.dev/v1alpha1",
            "v1alpha1",
        ] {
            assert_eq!(
                convert(&bundle, target).map(|conversion| conversion.steps),
                Err(Refusal::UnsupportedVersion),
                "{target}"
            );
        }
    }
}
