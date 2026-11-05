use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, UNIX_EPOCH},
};

use super::*;
use crate::validate::tests::{assert_no_canary, codes, report, run, Fixture, CANARY};
use gateway_config::{
    archive::{ArchiveCode, ArchiveRefusal},
    bundle::{read_bundle, PublishedSchemasOnly, ReadOptions},
    ledger::{LedgerActor, RevisionLedger},
    state_dir::{StateDirectory, StateFile},
};

/// A directory whose name carries the canary, so a path that reaches any
/// output is caught.
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl TempDir {
    fn new(label: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "ggctl-backup-{CANARY}-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("the directory should create");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("permissions should set");
        }
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn text(&self) -> &str {
        self.0.to_str().expect("UTF-8")
    }

    fn names(&self) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(&self.0)
            .expect("lists")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .into_string()
                    .expect("UTF-8")
            })
            .collect();
        names.sort();
        names
    }
}

fn text(path: &Path) -> &str {
    path.to_str().expect("UTF-8")
}

/// A state directory with a seeded ledger and, as a second store, a copy of
/// that ledger's database under the Connections store's name: any SQLite database
/// is a store to a backup.
fn state() -> TempDir {
    let state = TempDir::new("state");
    let bundle = Fixture::valid();
    let read = read_bundle(&bundle.root, ReadOptions::default(), &PublishedSchemasOnly);
    let bundle = read.bundle.expect("the fixture bundle reads");
    let held = StateDirectory::acquire(&state.0).expect("the state directory locks");
    let actor = LedgerActor::system("ggctl-ledger-seed").expect("recordable");
    let (ledger, _) = RevisionLedger::seed(
        &held,
        &bundle,
        actor,
        UNIX_EPOCH + Duration::from_secs(1_800_000_000),
    )
    .expect("seed");
    drop(ledger);
    drop(held);
    fs::copy(
        state.join(StateFile::ConfigLedger.file_name()),
        state.join(StateFile::Connections.file_name()),
    )
    .expect("a second store");
    // Key material beside the stores is never read.
    fs::write(state.join("connection-master.key"), CANARY).expect("a key file");
    state
}

#[test]
fn create_then_verify_reports_the_backup_and_never_a_path() {
    let state = state();
    let out = TempDir::new("out");
    let output = out.join("state.ggbk");
    let (exit, captured) = run(&[
        "backup",
        "create",
        "--state-dir",
        state.text(),
        "--output",
        text(&output),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Success, "{}", captured.stdout());
    let created = report(&captured);
    assert_no_canary(&captured);
    assert_eq!(created["command"], "backup create");
    assert_eq!(created["result"]["created"], true);
    // Including the Connections store says its keys are not included.
    assert_eq!(codes(&created), ["backup.secret_keys_not_included"]);
    assert_eq!(created["diagnostics"][0]["severity"], "info");
    let backup = &created["result"]["backup"];
    assert_eq!(backup["apiVersion"], "greengateway.dev/v1alpha1");
    assert_eq!(backup["createdBy"]["program"], "ggctl");
    assert_eq!(backup["entries"], 2);
    assert_eq!(backup["stores"][3]["store"], "connections");
    assert_eq!(backup["stores"][3]["entry"], "connections.sqlite3");
    assert_eq!(backup["stores"][6]["store"], "config_ledger");
    assert_eq!(backup["ledger"]["revisions"], 1);
    assert_eq!(backup["ledger"]["restartPending"], true);
    assert_eq!(out.names(), ["state.ggbk"]);
    let archive = fs::read(&output).expect("archive");
    assert!(!String::from_utf8_lossy(&archive).contains(CANARY));

    let (exit, captured) = run(&["backup", "verify", text(&output), "--format", "json"]);
    assert_eq!(exit, Exit::Success, "{}", captured.stdout());
    let verified = report(&captured);
    assert_no_canary(&captured);
    assert_eq!(verified["command"], "backup verify");
    assert_eq!(verified["result"]["verified"], true);
    assert!(codes(&verified).is_empty());
    assert_eq!(verified["result"]["backup"], *backup);

    // The human forms name stores and counts, on standard output.
    let (exit, captured) = run(&["backup", "verify", text(&output)]);
    assert_eq!(exit, Exit::Success);
    assert!(captured
        .stdout()
        .starts_with("verified a backup of 2 stores"));
    assert!(captured
        .stdout()
        .contains("  connections      connections.sqlite3: 4 tables"));
    assert!(captured
        .stdout()
        .contains("  audit            not in the state directory"));
    assert!(captured.stderr().is_empty());
    assert_no_canary(&captured);
}

#[test]
fn a_locked_state_directory_is_refused_with_exit_5_and_nothing_is_written() {
    let state = state();
    let held = StateDirectory::acquire(&state.0).expect("a gateway holds the lock");
    let out = TempDir::new("out");
    let output = out.join("state.ggbk");
    let (exit, captured) = run(&[
        "backup",
        "create",
        "--state-dir",
        state.text(),
        "--output",
        text(&output),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Conflict);
    let refused = report(&captured);
    assert_eq!(codes(&refused), ["state_dir.locked"]);
    assert_eq!(refused["diagnostics"][0]["location"]["argument"], 3);
    assert_eq!(refused["result"], serde_json::json!({"created": false}));
    assert!(out.names().is_empty());
    drop(held);
}

#[test]
fn a_backup_is_never_written_to_standard_output_or_over_a_file() {
    let state = state();
    let (exit, captured) = run(&[
        "backup",
        "create",
        "--state-dir",
        state.text(),
        "--output",
        "-",
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Usage);
    assert!(captured.stdout().is_empty());
    assert!(captured.stderr().contains("backup.stdout_refused"));

    let out = TempDir::new("out");
    let output = out.join("state.ggbk");
    fs::write(&output, CANARY).expect("an existing file");
    let (exit, captured) = run(&[
        "backup",
        "create",
        "--state-dir",
        state.text(),
        "--output",
        text(&output),
    ]);
    assert_eq!(exit, Exit::Conflict);
    assert_eq!(captured.stdout(), "backup create: no backup was written\n");
    assert!(captured.stderr().contains("backup.output_exists"));
    assert_no_canary(&captured);
    assert_eq!(fs::read_to_string(&output).expect("kept"), CANARY);
    assert_eq!(out.names(), ["state.ggbk"]);
}

#[test]
fn an_empty_state_directory_or_a_missing_one_is_refused() {
    let empty = TempDir::new("empty");
    let out = TempDir::new("out");
    let output = out.join("state.ggbk");
    let (exit, captured) = run(&[
        "backup",
        "create",
        "--state-dir",
        empty.text(),
        "--output",
        text(&output),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Invalid);
    assert_eq!(codes(&report(&captured)), ["backup.nothing_to_back_up"]);
    let (exit, captured) = run(&[
        "backup",
        "create",
        "--state-dir",
        text(&empty.join("missing")),
        "--output",
        text(&output),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Invalid);
    assert_eq!(codes(&report(&captured)), ["state_dir.missing"]);
    assert!(out.names().is_empty());
}

#[test]
fn a_damaged_archive_exits_7_with_the_code_that_found_it() {
    let state = state();
    let out = TempDir::new("out");
    let output = out.join("state.ggbk");
    let (exit, _) = run(&[
        "backup",
        "create",
        "--state-dir",
        state.text(),
        "--output",
        text(&output),
    ]);
    assert_eq!(exit, Exit::Success);
    let bytes = fs::read(&output).expect("archive");

    let truncated = out.join("truncated.ggbk");
    fs::write(&truncated, &bytes[..bytes.len() / 2]).expect("truncated copy");
    let (exit, captured) = run(&["backup", "verify", text(&truncated), "--format", "json"]);
    assert_eq!(exit, Exit::Integrity);
    let refused = report(&captured);
    assert_eq!(codes(&refused), ["archive.truncated"]);
    assert_eq!(
        refused["diagnostics"][0]["remediation"],
        "docs/archive-admission.md#codes"
    );
    assert_eq!(refused["result"], serde_json::json!({"verified": false}));

    let tampered = out.join("tampered.ggbk");
    let mut damaged = bytes.clone();
    let middle = damaged.len() - 4096;
    damaged[middle] ^= 0x01;
    fs::write(&tampered, &damaged).expect("tampered copy");
    let (exit, captured) = run(&["backup", "verify", text(&tampered), "--format", "json"]);
    assert_eq!(exit, Exit::Integrity);
    let refused = report(&captured);
    assert_eq!(codes(&refused), ["backup.checksum_mismatch"]);
    assert_eq!(refused["result"]["store"], "config_ledger");

    let foreign = out.join("foreign.ggbk");
    fs::write(&foreign, b"not a backup").expect("foreign file");
    let (exit, captured) = run(&["backup", "verify", text(&foreign)]);
    assert_eq!(exit, Exit::Integrity);
    assert_eq!(
        captured.stdout(),
        "backup verify: the backup did not verify\n"
    );
    assert!(captured
        .stderr()
        .starts_with("ggctl: error: backup.not_a_backup: "));
    assert_no_canary(&captured);

    let (exit, captured) = run(&["backup", "verify", text(&out.join("missing.ggbk"))]);
    assert_eq!(exit, Exit::Failure);
    assert!(captured.stderr().contains("backup.archive_unreadable"));
    let (exit, captured) = run(&["backup", "verify", state.text()]);
    assert_eq!(exit, Exit::Invalid);
    assert!(captured
        .stderr()
        .contains("backup.archive_not_regular_file"));
    assert_eq!(
        out.names(),
        [
            "foreign.ggbk",
            "state.ggbk",
            "tampered.ggbk",
            "truncated.ggbk"
        ]
    );
}

#[test]
fn an_archive_refusal_is_located_by_its_entry_and_the_entry_it_clashes_with() {
    let diagnostic = ReportDiagnostic::Archive(ArchiveRefusal {
        code: ArchiveCode::CaseFoldCollision,
        entry: Some(3),
        conflicts_with: Some(2),
    });
    assert_eq!(diagnostic.exit(), Exit::Integrity);
    assert_eq!(
        serde_json::to_value(diagnostic.location()).expect("JSON"),
        serde_json::json!({"entry": 3, "conflictsWith": 2})
    );
    assert_eq!(
        diagnostic.to_string(),
        "ggctl: error: archive.case_fold_collision: two entries name paths that differ only in letter case\n  at: archive entry 3 (conflicts with entry 2)\n  see: docs/archive-admission.md#codes"
    );
    for code in [ArchiveCode::ReadFailed, ArchiveCode::WriteFailed] {
        assert_eq!(
            ReportDiagnostic::Archive(ArchiveRefusal::archive(code)).exit(),
            Exit::Failure
        );
    }
}

#[test]
fn every_backup_error_reports_the_code_gateway_config_gives_it() {
    let stores = [
        StoreProblem::Link,
        StoreProblem::NotRegularFile,
        StoreProblem::UnsafePermissions,
        StoreProblem::Unavailable,
        StoreProblem::Corrupt,
        StoreProblem::LedgerInvalid,
        StoreProblem::LedgerShared,
    ]
    .map(|problem| BackupError::Store {
        store: StateFile::Audit,
        problem,
    });
    let entries = [
        EntryProblem::ChecksumMismatch,
        EntryProblem::IntegrityFailed,
        EntryProblem::DescriptionMismatch,
        EntryProblem::LedgerInvalid,
        EntryProblem::LedgerMismatch,
    ]
    .map(|problem| BackupError::Entry {
        store: StateFile::Audit,
        problem,
    });
    let others = [
        BackupError::StateDirUnavailable,
        BackupError::NothingToBackUp,
        BackupError::OutputExists,
        BackupError::OutputUnusable,
        BackupError::PermissionsUnavailable,
        BackupError::ArchiveUnreadable,
        BackupError::ArchiveNotRegularFile,
        BackupError::ArchiveTooLarge,
        BackupError::StagingUnavailable,
        BackupError::Refused(ArchiveRefusal::archive(ArchiveCode::Malformed)),
        BackupError::NotABackup,
        BackupError::UnsupportedArchiveVersion,
        BackupError::ManifestMissing,
        BackupError::ManifestInvalid,
        BackupError::UnsupportedManifestVersion,
        BackupError::UnexpectedEntry { position: 2 },
        BackupError::EntryMissing,
        BackupError::ArchiveDigestMismatch,
    ];
    for error in stores.iter().chain(&entries).chain(&others) {
        let diagnostic = diagnostic(error, None);
        assert_eq!(diagnostic.code(), error.code(), "{error:?}");
        // An integrity failure of an archive is 7; nothing about a state
        // directory or an output is.
        let integrity = matches!(
            error,
            BackupError::Entry { .. }
                | BackupError::Refused(_)
                | BackupError::ArchiveTooLarge
                | BackupError::NotABackup
                | BackupError::UnsupportedArchiveVersion
                | BackupError::ManifestMissing
                | BackupError::ManifestInvalid
                | BackupError::UnsupportedManifestVersion
                | BackupError::UnexpectedEntry { .. }
                | BackupError::EntryMissing
                | BackupError::ArchiveDigestMismatch
        );
        assert_eq!(diagnostic.exit() == Exit::Integrity, integrity, "{error:?}");
    }
}

#[test]
fn the_backup_result_fits_the_published_report_schema_when_refused_too() {
    // A store refusal names the store, never its path.
    let state = state();
    let corrupt = state.join(StateFile::Discovery.file_name());
    fs::write(&corrupt, format!("not a database {CANARY}")).expect("garbage");
    let out = TempDir::new("out");
    let (exit, captured) = run(&[
        "backup",
        "create",
        "--state-dir",
        state.text(),
        "--output",
        text(&out.join("state.ggbk")),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Invalid);
    let refused = report(&captured);
    assert_no_canary(&captured);
    assert_eq!(codes(&refused), ["backup.store_corrupt"]);
    assert_eq!(refused["result"]["store"], "discovery");
    assert_eq!(refused["result"]["created"], false);
    assert!(out.names().is_empty());
}
