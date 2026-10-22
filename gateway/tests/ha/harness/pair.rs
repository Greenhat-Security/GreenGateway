//! Issue #426's pinned upgrade pair: two real gateway binaries, each built
//! from its own pinned commit.
//!
//! `gateway/tests/ha/rolling-upgrade-pair.json` names the commits.
//! `scripts/build_upgrade_pair.py` checks each one out into a detached
//! worktree, builds it there with that commit's own sources, `Cargo.lock`
//! and default features, and writes `manifest.json` recording each
//! binary's commit and SHA-256 into the directory named by
//! [`PAIR_DIR_VARIABLE`]. [`UpgradePair::load`] trusts none of that by
//! assertion: it compares the manifest's commits with the pin compiled into
//! this suite, hashes both binaries again, and refuses two identical
//! binaries, because two instances of one build are not an adjacent-version
//! proof.
//!
//! The rows record what they observed with [`UpgradePair::write_evidence`]:
//! one JSON file per row under the pair directory's `evidence/`, each
//! carrying both binaries' identities. The release gate retains that
//! directory as a build artifact.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Where `scripts/build_upgrade_pair.py --out` put the pair.
pub const PAIR_DIR_VARIABLE: &str = "GATEWAY_TEST_UPGRADE_PAIR_DIR";

/// The pin, compiled in, so the commits a row claims to have run are the
/// ones this revision of the suite was reviewed against.
const PIN: &str = include_str!("../rolling-upgrade-pair.json");

/// One side of the pair.
#[derive(Clone, Debug)]
pub struct PairBinary {
    /// `prepared` or `successor`.
    pub role: &'static str,
    pub commit: String,
    pub path: PathBuf,
    pub sha256: String,
}

impl PairBinary {
    fn identity(&self) -> Value {
        json!({ "commit": self.commit, "binary_sha256": self.sha256 })
    }
}

/// The prepared release and its successor, verified.
pub struct UpgradePair {
    pub prepared: PairBinary,
    pub successor: PairBinary,
    /// The operation the successor registers and the capability it needs.
    pub operation: String,
    pub capability: String,
    /// The schema version both binaries serve, as the pin states it.
    pub schema_version: i64,
    substitution: String,
    evidence: PathBuf,
}

fn sha256_file(path: &Path) -> String {
    let bytes = std::fs::read(path)
        .unwrap_or_else(|error| panic!("the pair binary {} should read: {error}", path.display()));
    hex::encode(Sha256::digest(&bytes))
}

fn text<'a>(value: &'a Value, pointer: &str, source: &str) -> &'a str {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{source} carries no {pointer}: {value}"))
}

impl UpgradePair {
    /// The pair the release gate built.
    ///
    /// Panics, rather than skipping, when it is missing: this is only
    /// called once the database locator and `GATEWAY_TEST_HA_GATE` say the
    /// run is the gate, and a gate that skipped its pair rows would report
    /// the same pass as one that ran them.
    pub fn load() -> Self {
        let directory = std::env::var(PAIR_DIR_VARIABLE)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                panic!(
                    "{PAIR_DIR_VARIABLE} is unset, so the issue #426 pair rows have no binaries. \
                     CI's ha-upgrade-pair job builds them; locally, run `python \
                     scripts/build_upgrade_pair.py --out <dir>` and point {PAIR_DIR_VARIABLE} at \
                     <dir>"
                )
            });
        let pin: Value = serde_json::from_str(PIN).expect("the pair pin is JSON");
        let manifest_path = directory.join("manifest.json");
        let manifest: Value = serde_json::from_str(
            &std::fs::read_to_string(&manifest_path).unwrap_or_else(|error| {
                panic!(
                    "the pair manifest {} should read: {error}",
                    manifest_path.display()
                )
            }),
        )
        .unwrap_or_else(|error| panic!("the pair manifest should be JSON: {error}"));
        assert_eq!(manifest["schema"], 1, "unknown pair manifest: {manifest}");

        let side = |role: &'static str| {
            let pinned = text(&pin, &format!("/{role}/commit"), "the pair pin");
            let built = text(&manifest, &format!("/{role}/commit"), "the pair manifest");
            assert_eq!(
                built, pinned,
                "the {role} binary was built from {built}, but this suite pins {pinned}; rebuild \
                 the pair"
            );
            let path = directory.join(text(&manifest, &format!("/{role}/binary"), "the manifest"));
            let recorded = text(&manifest, &format!("/{role}/sha256"), "the pair manifest");
            let sha256 = sha256_file(&path);
            assert_eq!(
                sha256,
                recorded,
                "the {role} binary at {} is not the one the build recorded",
                path.display()
            );
            PairBinary {
                role,
                commit: built.to_owned(),
                path,
                sha256,
            }
        };
        let prepared = side("prepared");
        let successor = side("successor");
        assert_ne!(
            prepared.commit, successor.commit,
            "one commit twice is not an adjacent-version pair"
        );
        assert_ne!(
            prepared.sha256, successor.sha256,
            "the two pinned builds are the same binary"
        );

        let evidence = directory.join("evidence");
        std::fs::create_dir_all(&evidence).unwrap_or_else(|error| {
            panic!(
                "the evidence directory {} should create: {error}",
                evidence.display()
            )
        });
        Self {
            prepared,
            successor,
            operation: text(&pin, "/operation", "the pair pin").to_owned(),
            capability: text(&pin, "/capability", "the pair pin").to_owned(),
            schema_version: pin["schema_version"]
                .as_i64()
                .expect("the pair pin states the schema version"),
            substitution: text(&manifest, "/substitution", "the pair manifest").to_owned(),
            evidence,
        }
    }

    /// Which side a binary path is, for a row that reports per replica.
    pub fn role_of(&self, binary: &Path) -> &'static str {
        if binary == self.prepared.path {
            self.prepared.role
        } else if binary == self.successor.path {
            self.successor.role
        } else {
            "unpinned"
        }
    }

    /// Write one row's record to `evidence/<row>.json`, with both binaries'
    /// identities and the build substitution stated beside it.
    pub fn write_evidence(&self, row: &str, observed: Value) {
        let record = json!({
            "schema": 1,
            "issue": 426,
            "row": row,
            "prepared": self.prepared.identity(),
            "successor": self.successor.identity(),
            "build_substitution": self.substitution,
            "observed": observed,
        });
        let path = self.evidence.join(format!("{row}.json"));
        let text = serde_json::to_string_pretty(&record).expect("evidence serializes");
        std::fs::write(&path, format!("{text}\n")).unwrap_or_else(|error| {
            panic!("the evidence {} should write: {error}", path.display())
        });
    }
}
