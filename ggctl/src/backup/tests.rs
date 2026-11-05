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

// --- restore ---------------------------------------------------------------------

/// A state directory a restore can put back: a seeded ledger and, as the
/// Connections store, a copy of the ledger's database with its application
/// ID cleared, as the gateway's stores carry none.
fn restorable_state() -> TempDir {
    let state = state();
    let connections = state.join(StateFile::Connections.file_name());
    let mut database = fs::read(&connections).expect("the copy reads");
    // The header's application ID, at offset 68.
    database[68..72].copy_from_slice(&[0; 4]);
    fs::write(&connections, database).expect("the copy writes");
    fs::remove_file(state.join("connection-master.key")).expect("the key file goes");
    state
}

/// `state()`, whose Connections store is the ledger's own database.
fn state_with_ledger_copy() -> TempDir {
    let state = state();
    fs::remove_file(state.join("connection-master.key")).expect("the key file goes");
    state
}

/// A backup of `state` in a new directory.
fn backup_of(state: &TempDir) -> (TempDir, PathBuf) {
    let out = TempDir::new("out");
    let archive = out.join("state.ggbk");
    let (exit, captured) = run(&[
        "backup",
        "create",
        "--state-dir",
        state.text(),
        "--output",
        text(&archive),
    ]);
    assert_eq!(exit, Exit::Success, "{}", captured.stderr());
    (out, archive)
}

/// `parent/state`: an empty directory to restore into.
fn empty_target(parent: &TempDir) -> PathBuf {
    let target = parent.join("state");
    fs::create_dir(&target).expect("the target creates");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
            .expect("permissions should set");
    }
    target
}

fn listing(directory: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(directory)
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

#[test]
fn restore_puts_a_backup_in_place_and_reports_it_without_a_path() {
    let state = restorable_state();
    let (_out, archive) = backup_of(&state);
    let parent = TempDir::new("parent");
    let target = empty_target(&parent);
    let (exit, captured) = run(&[
        "backup",
        "restore",
        text(&archive),
        "--state-dir",
        text(&target),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Success, "{}", captured.stdout());
    let restored = report(&captured);
    assert_no_canary(&captured);
    assert_eq!(restored["command"], "backup restore");
    assert_eq!(restored["result"]["restored"], true);
    assert_eq!(restored["result"]["replaced"], false);
    assert!(restored["result"]["restoreId"]
        .as_str()
        .is_some_and(|id| id.starts_with("rst-") && id.len() == 36));
    assert_eq!(restored["result"]["backup"]["entries"], 2);
    // Restoring the Connections store says its keys must come back too.
    assert_eq!(codes(&restored), ["restore.secret_keys_required"]);
    assert_eq!(restored["diagnostics"][0]["severity"], "info");
    assert_eq!(parent.names(), ["state"], "nothing is left beside it");
    assert_eq!(
        listing(&target),
        [
            "config-ledger.sqlite3",
            "connections.sqlite3",
            "restore-marker.json",
            "state.lock"
        ]
    );
    let (exit, captured) = run(&["ledger", "verify", "--state-dir", text(&target)]);
    assert_eq!(exit, Exit::Success, "{}", captured.stderr());

    // Two restores never share their hidden names or their ID.
    let other = TempDir::new("other");
    let second = empty_target(&other);
    let (exit, captured) = run(&[
        "backup",
        "restore",
        text(&archive),
        "--state-dir",
        text(&second),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Success);
    assert_ne!(
        report(&captured)["result"]["restoreId"],
        restored["result"]["restoreId"]
    );

    // The human result names the stores and the restore, never a path.
    let third = TempDir::new("third");
    let target = empty_target(&third);
    let (exit, captured) = run(&[
        "backup",
        "restore",
        text(&archive),
        "--state-dir",
        text(&target),
    ]);
    assert_eq!(exit, Exit::Success);
    assert!(captured
        .stdout()
        .starts_with("restored a backup of 2 stores, created at Unix time "));
    assert!(captured.stdout().contains("\n  restore rst-"));
    assert!(captured
        .stderr()
        .starts_with("ggctl: info: restore.secret_keys_required: "));
    assert_no_canary(&captured);
}

#[test]
fn restore_replaces_a_stopped_state_directory_only_when_asked() {
    let state = restorable_state();
    let (_out, archive) = backup_of(&state);
    // The source itself is a stopped state directory holding stores.
    let (exit, captured) = run(&[
        "backup",
        "restore",
        text(&archive),
        "--state-dir",
        state.text(),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Conflict);
    let refused = report(&captured);
    assert_eq!(codes(&refused), ["restore.target_not_empty"]);
    assert_eq!(refused["diagnostics"][0]["location"]["argument"], 4);
    assert_eq!(refused["result"]["restored"], false);
    assert_eq!(refused["result"]["targetUnchanged"], true);

    let (exit, captured) = run(&[
        "backup",
        "restore",
        text(&archive),
        "--state-dir",
        state.text(),
        "--replace-existing-state",
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Success, "{}", captured.stdout());
    assert_eq!(report(&captured)["result"]["replaced"], true);

    // Anything the layout does not name is never replaced.
    fs::write(state.join("notes.txt"), CANARY).expect("a foreign file");
    let (exit, captured) = run(&[
        "backup",
        "restore",
        text(&archive),
        "--state-dir",
        state.text(),
        "--replace-existing-state",
    ]);
    assert_eq!(exit, Exit::Invalid);
    assert!(captured
        .stderr()
        .starts_with("ggctl: error: restore.target_not_state_dir: "));
    assert_eq!(
        captured.stdout(),
        "backup restore: nothing was restored; the state directory was left as it was\n"
    );
    assert_no_canary(&captured);
}

#[test]
fn restore_of_a_corrupt_hostile_or_newer_archive_exits_7_and_changes_nothing() {
    let state = restorable_state();
    let (out, archive) = backup_of(&state);
    let bytes = fs::read(&archive).expect("archive");
    let name = StateFile::ConfigLedger.file_name().as_bytes();
    // The ledger's record header: the last occurrence of its name, then its
    // size.
    let at = bytes
        .windows(name.len())
        .rposition(|window| window == name)
        .expect("the ledger's record");

    let mut tampered = bytes.clone();
    let middle = tampered.len() - 4096;
    tampered[middle] ^= 0x01;
    let mut traversal = bytes.clone();
    traversal[at..at + name.len()].copy_from_slice(b"../config-ledger.sqli");
    let mut bomb = bytes.clone();
    bomb[at + name.len()..at + name.len() + 8].copy_from_slice(&(1_u64 << 40).to_be_bytes());
    let mut newer = bytes.clone();
    newer[8..10].copy_from_slice(&2_u16.to_be_bytes());
    let truncated = bytes[..bytes.len() / 2].to_vec();

    for (label, candidate, code) in [
        ("tampered", tampered, "backup.checksum_mismatch"),
        ("traversal", traversal, "archive.entry_outside_root"),
        ("bomb", bomb, "archive.entry_too_large"),
        ("newer", newer, "backup.unsupported_archive_version"),
        ("truncated", truncated, "archive.truncated"),
    ] {
        let path = out.join(&format!("{label}.ggbk"));
        fs::write(&path, &candidate).expect("the candidate writes");
        let parent = TempDir::new("parent");
        let target = empty_target(&parent);
        let (exit, captured) = run(&[
            "backup",
            "restore",
            text(&path),
            "--state-dir",
            text(&target),
            "--format",
            "json",
        ]);
        assert_eq!(exit, Exit::Integrity, "{label}: {}", captured.stdout());
        let refused = report(&captured);
        assert_eq!(codes(&refused), [code], "{label}");
        assert_eq!(refused["result"]["restored"], false, "{label}");
        assert_eq!(refused["result"]["targetUnchanged"], true, "{label}");
        assert!(listing(&target).is_empty(), "{label}");
        assert_eq!(parent.names(), ["state"], "{label}");
        assert_no_canary(&captured);
    }

    // A store claiming another store's identity verifies as a backup, but
    // is never restored.
    let (_identity_out, identity) = backup_of(&state_with_ledger_copy());
    let parent = TempDir::new("parent");
    let target = empty_target(&parent);
    let (exit, captured) = run(&[
        "backup",
        "restore",
        text(&identity),
        "--state-dir",
        text(&target),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Integrity);
    let refused = report(&captured);
    assert_eq!(codes(&refused), ["restore.store_identity_mismatch"]);
    assert_eq!(refused["result"]["store"], "connections");
    assert_eq!(refused["diagnostics"][0]["location"]["argument"], 3);
    assert!(listing(&target).is_empty());
}

#[test]
fn restore_refuses_a_locked_target_and_a_postgres_dump() {
    let state = restorable_state();
    let (out, archive) = backup_of(&state);
    let parent = TempDir::new("parent");
    let target = empty_target(&parent);
    let held = StateDirectory::acquire(&target).expect("another process's lock");
    let (exit, captured) = run(&[
        "backup",
        "restore",
        text(&archive),
        "--state-dir",
        text(&target),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Conflict);
    assert_eq!(codes(&report(&captured)), ["state_dir.locked"]);
    drop(held);

    let dump = out.join("cluster.dump");
    fs::write(&dump, b"PGDMP\x01\x0e\x00\x04\x08\x08\x01").expect("a dump");
    let (exit, captured) = run(&[
        "backup",
        "restore",
        text(&dump),
        "--state-dir",
        text(&target),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Invalid);
    let refused = report(&captured);
    assert_eq!(codes(&refused), ["backup.postgres_unsupported"]);
    assert_eq!(refused["diagnostics"][0]["location"]["argument"], 3);
    let (exit, _) = run(&["backup", "verify", text(&dump)]);
    assert_eq!(exit, Exit::Invalid);
    assert_eq!(listing(&target), ["state.lock"]);

    // --state-dir is required.
    let (exit, captured) = run(&["backup", "restore", text(&archive)]);
    assert_eq!(exit, Exit::Usage);
    assert!(captured
        .stderr()
        .starts_with("ggctl: error: usage.missing_argument: "));
}

#[test]
fn every_restore_error_reports_the_code_gateway_config_gives_it() {
    use gateway_config::state_dir::StateDirError;
    let errors = [
        RestoreError::StateDir(StateDirError::Locked),
        RestoreError::Backup(BackupError::PostgresDump),
        RestoreError::TargetNotEmpty,
        RestoreError::TargetNotStateDirectory,
        RestoreError::TargetMountPoint,
        RestoreError::TargetUnavailable,
        RestoreError::StagingUnavailable,
        RestoreError::PermissionsUnavailable,
        RestoreError::StoreIdentity {
            store: StateFile::Audit,
        },
        RestoreError::TargetChanged,
        RestoreError::SwitchFailed,
        RestoreError::RollbackFailed,
    ];
    for error in &errors {
        let diagnostic = restore_diagnostic(error, 3, 4);
        assert_eq!(diagnostic.code(), error.code(), "{error:?}");
        let integrity = matches!(error, RestoreError::StoreIdentity { .. });
        assert_eq!(diagnostic.exit() == Exit::Integrity, integrity, "{error:?}");
    }
    for warning in [
        RestoreWarning::DirectoryNotFlushed,
        RestoreWarning::PreviousNotRemoved,
    ] {
        let code = warning_code(warning);
        assert_eq!(code.as_str(), warning.code());
        assert_eq!(code.exit(), Exit::Success);
    }
    // Every nonce is new.
    assert_ne!(nonce(), nonce());
}
