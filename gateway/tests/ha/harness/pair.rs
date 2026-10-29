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
//! carrying both binaries' identities. The release gate checks that
//! directory against `docs/deployment/upgrade-support-matrix.json` with
//! `scripts/upgrade_pair_evidence.py` and retains it, with the summary that
//! check writes, as a build artifact.

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

/// The one migration a pair crosses: the successor applies it, and the
/// prepared release approved it, by exactly this checksum, before any build
/// applied it.
#[derive(Clone, Debug)]
pub struct SchemaStep {
    /// The schema point the prepared release's manifest ends at.
    pub from: i64,
    /// The schema point the successor's manifest ends at: `from + 1`.
    pub to: i64,
    pub migration: String,
    /// The SHA-256 of the migration's SQL, as both builds' ledger checks
    /// compute it.
    pub checksum: String,
}

/// The prepared release and its successor, verified.
pub struct UpgradePair {
    pub prepared: PairBinary,
    pub successor: PairBinary,
    /// The operation the successor registers and the capability it needs,
    /// when it registers one. A pair that crosses a schema step may add no
    /// operation.
    pub operation: Option<String>,
    pub capability: Option<String>,
    /// The schema point the prepared release migrates the deployment to, as
    /// the pin states it: where its manifest ends.
    pub schema_version: i64,
    /// The migration the successor applies, when the pair crosses one. Absent
    /// when both builds serve one schema point and the successor carries no
    /// migration.
    pub schema_step: Option<SchemaStep>,
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

/// A pin member that is a string or `null`, and nothing else.
fn optional_text(value: &Value, pointer: &str) -> Option<String> {
    match value.pointer(pointer) {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
        Some(other) => panic!("the pair pin's {pointer} must be a name or null, not {other}"),
    }
}

/// The pin's `schema_step`, checked: one migration, numbered right after the
/// prepared release's schema point, named, with a full SHA-256.
fn schema_step(pin: &Value, schema_version: i64) -> Option<SchemaStep> {
    let step = match pin.get("schema_step") {
        None | Some(Value::Null) => return None,
        Some(step) => step,
    };
    let number = |key: &str| {
        step[key]
            .as_i64()
            .unwrap_or_else(|| panic!("the pair pin's schema_step carries no {key}: {step}"))
    };
    let (from, to) = (number("from"), number("to"));
    assert_eq!(
        (from, to),
        (schema_version, schema_version + 1),
        "a pair crosses one migration, from the prepared release's schema point: {step}"
    );
    let checksum = text(step, "/checksum", "the pair pin's schema_step").to_owned();
    assert!(
        checksum.len() == 64
            && checksum
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "the schema step's checksum must be one lowercase SHA-256: {step}"
    );
    Some(SchemaStep {
        from,
        to,
        migration: text(step, "/migration", "the pair pin's schema_step").to_owned(),
        checksum,
    })
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
        let operation = optional_text(&pin, "/operation");
        let capability = optional_text(&pin, "/capability");
        assert_eq!(
            operation.is_some(),
            capability.is_some(),
            "the pair pin names an operation and its capability together, or neither"
        );
        let schema_version = pin["schema_version"]
            .as_i64()
            .expect("the pair pin states the schema version");
        let schema_step = schema_step(&pin, schema_version);
        assert!(
            operation.is_some() || schema_step.is_some(),
            "the successor must differ from the prepared release by an operation or a migration"
        );
        Self {
            prepared,
            successor,
            operation,
            capability,
            schema_version,
            schema_step,
            substitution: text(&manifest, "/substitution", "the pair manifest").to_owned(),
            evidence,
        }
    }

    /// The schema point the deployment reaches once the successor has
    /// migrated it, and which both builds then serve: the step's target, or
    /// the one schema point of a pair that crosses none.
    pub fn shared_schema(&self) -> i64 {
        self.schema_step
            .as_ref()
            .map_or(self.schema_version, |step| step.to)
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
