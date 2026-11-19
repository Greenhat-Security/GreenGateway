use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, UNIX_EPOCH},
};

use gateway_config::{
    bundle::{read_bundle, PublishedSchemasOnly, ReadOptions},
    ledger::{LedgerActor, RevisionLedger},
    state_dir::{filesystem_kind, FilesystemKind, StateDirectory, StateFile},
};
use serde_json::Value;

use super::*;
use crate::{
    diagnostic::Exit,
    report::tests::Captured,
    validate::tests::{assert_no_canary, codes, report, run, Fixture, CANARY},
};

/// A state directory whose name carries the canary, so a path that reaches
/// any output is caught.
struct State(PathBuf);

impl Drop for State {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl State {
    fn new(label: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "ggctl-doctor-{CANARY}-{label}-{}-{}",
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

    /// A state directory with a seeded ledger and, as the audit store, a
    /// copy of the ledger's database with the application ID the gateway's
    /// stores carry: any SQLite database is a store to these checks.
    fn seeded(label: &str) -> Self {
        let state = Self::new(label);
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
        let mut database = fs::read(state.store(StateFile::ConfigLedger)).expect("the ledger");
        // The header's application ID, at offset 68.
        database[68..72].copy_from_slice(&[0; 4]);
        fs::write(state.store(StateFile::Audit), database).expect("the audit store");
        // Key material beside the stores is never read.
        fs::write(state.0.join("connection-master.key"), CANARY).expect("a key file");
        state
    }

    fn text(&self) -> &str {
        self.0.to_str().expect("UTF-8")
    }

    fn store(&self, store: StateFile) -> PathBuf {
        self.0.join(store.file_name())
    }

    fn beside(&self, store: StateFile, suffix: &str) -> PathBuf {
        self.0.join(format!("{}{suffix}", store.file_name()))
    }

    /// Every entry and its bytes, except the ones a reader may create: the
    /// lock file and SQLite's empty `-wal` and `-shm` files.
    fn contents(&self) -> Vec<(String, Vec<u8>)> {
        let mut contents: Vec<_> = fs::read_dir(&self.0)
            .expect("lists")
            .map(|entry| {
                let entry = entry.expect("entry");
                let name = entry.file_name().into_string().expect("UTF-8");
                let bytes = fs::read(entry.path()).expect("reads");
                (name, bytes)
            })
            .filter(|(name, bytes)| {
                name != "state.lock"
                    && !name.ends_with("-shm")
                    && !(name.ends_with("-wal") && bytes.is_empty())
            })
            .collect();
        contents.sort();
        contents
    }
}

/// `(id, status, reason)` for every check of a doctor report.
fn statuses(report: &Value) -> Vec<(String, String, String)> {
    report["result"]["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .map(|check| {
            let field = |name: &str| check[name].as_str().expect(name).to_owned();
            (field("id"), field("status"), field("reason"))
        })
        .collect()
}

/// The statuses `stores` gives the store checks, with every other store
/// `skipped` because the directory does not hold it.
fn expected(state: &Path, stores: &[(StateFile, &str, &str)]) -> Vec<(String, String, String)> {
    let filesystem = match filesystem_kind(state) {
        FilesystemKind::Local => ("pass", "doctor.passed"),
        FilesystemKind::Network => ("warning", "state_dir.network_filesystem"),
        FilesystemKind::Unchecked => ("skipped", "doctor.filesystem_unchecked"),
    };
    let mut rows = vec![
        ("state_dir.lock".to_owned(), "pass", "doctor.passed"),
        (
            "state_dir.filesystem".to_owned(),
            filesystem.0,
            filesystem.1,
        ),
        ("state_dir.stores".to_owned(), "pass", "doctor.passed"),
    ];
    for store in StateFile::ALL {
        let (status, reason) = stores
            .iter()
            .find(|(found, _, _)| *found == store)
            .map_or(("skipped", "doctor.not_present"), |(_, status, reason)| {
                (*status, *reason)
            });
        rows.push((format!("store.{}", store.id()), status, reason));
    }
    rows.into_iter()
        .map(|(id, status, reason)| (id, status.to_owned(), reason.to_owned()))
        .collect()
}

fn doctor(state: &State) -> (Exit, Value, Captured) {
    let (exit, captured) = run(&["doctor", "--state-dir", state.text(), "--format", "json"]);
    let found = report(&captured);
    assert_no_canary(&captured);
    assert_eq!(found["command"], "doctor");
    (exit, found, captured)
}

#[test]
fn a_healthy_state_directory_passes_and_nothing_in_it_is_written() {
    let state = State::seeded("healthy");
    let before = state.contents();
    let (exit, found, _) = doctor(&state);
    assert_eq!(exit, Exit::Success, "{found}");
    assert_eq!(
        statuses(&found),
        expected(
            &state.0,
            &[
                (StateFile::Audit, "pass", "doctor.passed"),
                (StateFile::ConfigLedger, "pass", "doctor.passed"),
            ]
        )
    );
    assert!(found["result"].get("bundle").is_none());
    assert!(found["result"].get("environment").is_none());
    let checks = found["result"]["checks"].as_array().expect("checks");
    assert!(checks.iter().all(|check| check["severity"]
        == if check["id"] == "state_dir.filesystem" {
            "warning"
        } else {
            "error"
        }));
    assert_eq!(state.contents(), before);

    // The human form lists every check on standard output.
    let (exit, captured) = run(&["doctor", "--state-dir", state.text()]);
    assert_eq!(exit, Exit::Success);
    assert!(captured
        .stdout()
        .starts_with("state directory: offline checks\n"));
    assert!(captured
        .stdout()
        .contains("  pass     store.config_ledger   doctor.passed\n"));
    assert!(captured
        .stdout()
        .contains("  skipped  store.discovery       doctor.not_present\n"));
    assert!(captured.stdout().ends_with("no required check failed\n"));
    assert_no_canary(&captured);
    assert_eq!(state.contents(), before);
}

#[test]
fn a_locked_or_unusable_state_directory_fails_the_lock_check_and_skips_the_rest() {
    let state = State::seeded("locked");
    let held = StateDirectory::acquire(&state.0).expect("a gateway holds the lock");
    let (exit, found, _) = doctor(&state);
    assert_eq!(exit, Exit::Conflict);
    assert_eq!(
        codes(&found),
        ["state_dir.locked", "doctor.required_check_failed"]
    );
    assert_eq!(found["diagnostics"][0]["location"]["argument"], 2);
    let checks = statuses(&found);
    assert_eq!(
        checks[0],
        (
            "state_dir.lock".to_owned(),
            "fail".to_owned(),
            "state_dir.locked".to_owned()
        )
    );
    assert_eq!(
        found["result"]["checks"][0]["remediation"],
        "docs/ggctl.md#state_dir-diagnostics"
    );
    assert_eq!(checks.len(), CHECKS.len());
    assert!(checks[1..]
        .iter()
        .all(|(_, status, reason)| status == "skipped" && reason == "doctor.incomplete"));
    drop(held);

    let missing = State::new("missing");
    let path = missing.0.join("absent");
    let (exit, captured) = run(&[
        "doctor",
        "--state-dir",
        path.to_str().expect("UTF-8"),
        "--format",
        "json",
    ]);
    assert_eq!(exit, Exit::Invalid);
    let found = report(&captured);
    assert_eq!(
        codes(&found),
        ["state_dir.missing", "doctor.required_check_failed"]
    );
    assert_no_canary(&captured);
}

#[test]
fn a_corrupt_or_misnamed_store_fails_its_check_and_the_doctor() {
    let state = State::seeded("corrupt");
    fs::write(state.store(StateFile::Principals), CANARY.repeat(256)).expect("not a database");
    // The ledger's database under the Connections store's name.
    fs::copy(
        state.store(StateFile::ConfigLedger),
        state.store(StateFile::Connections),
    )
    .expect("a misnamed store");
    let (exit, found, _) = doctor(&state);
    assert_eq!(exit, Exit::Invalid);
    assert_eq!(
        statuses(&found),
        expected(
            &state.0,
            &[
                (StateFile::Audit, "pass", "doctor.passed"),
                (StateFile::Principals, "fail", "backup.store_corrupt"),
                (
                    StateFile::Connections,
                    "fail",
                    "doctor.store_identity_mismatch"
                ),
                (StateFile::ConfigLedger, "pass", "doctor.passed"),
            ]
        )
    );
    assert_eq!(
        codes(&found),
        ["backup.store_corrupt", "doctor.required_check_failed"]
    );
    assert_eq!(found["diagnostics"][0]["location"]["argument"], 2);
    assert_eq!(
        found["result"]["checks"][5]["remediation"],
        "docs/ggctl.md#backup-diagnostics"
    );
    assert_eq!(
        found["result"]["checks"][6]["remediation"],
        "docs/ggctl.md#doctor-checks"
    );
}

#[test]
fn a_ledger_that_does_not_verify_fails_with_the_ledger_code() {
    let state = State::seeded("ledger");
    let ledger = state.store(StateFile::ConfigLedger);
    let mut database = fs::read(&ledger).expect("the ledger");
    // The header's user version, at offset 60: a ledger format this build
    // does not read. SQLite's integrity check does not cover the header.
    database[60..64].copy_from_slice(&99_u32.to_be_bytes());
    fs::write(&ledger, database).expect("the ledger writes");
    let (exit, found, _) = doctor(&state);
    assert_eq!(exit, Exit::Invalid);
    let checks = statuses(&found);
    let (id, status, reason) = checks.last().expect("the ledger's check");
    assert_eq!(id, "store.config_ledger");
    assert_eq!(status, "fail");
    assert!(reason.starts_with("ledger."), "{reason}");
    assert_eq!(
        found["result"]["checks"][9]["remediation"],
        "docs/ggctl.md#ledger-diagnostics"
    );
    assert_eq!(codes(&found)[1], "doctor.required_check_failed");
    assert_eq!(found["diagnostics"][0]["location"]["argument"], 2);
}

#[test]
fn journals_are_reported_and_never_replayed_or_removed() {
    let state = State::seeded("journals");
    // A pending rollback journal: the store is not opened.
    let journal = state.beside(StateFile::Audit, "-journal");
    fs::write(&journal, CANARY).expect("journal");
    // A write-ahead log beside the ledger: whatever it holds, it is not
    // checkpointed into the ledger, and the ledger still verifies.
    let wal = state.beside(StateFile::ConfigLedger, "-wal");
    fs::write(&wal, CANARY).expect("log");
    let before = state.contents();
    // A store that could not be checked fails: never a silent pass.
    let (exit, found, _) = doctor(&state);
    assert_eq!(exit, Exit::Invalid, "{found}");
    assert_eq!(
        statuses(&found),
        expected(
            &state.0,
            &[
                (StateFile::Audit, "fail", "doctor.journal_pending"),
                (StateFile::ConfigLedger, "warning", "doctor.wal_pending"),
            ]
        )
    );
    assert_eq!(codes(&found), ["doctor.required_check_failed"]);
    assert_eq!(state.contents(), before);
    assert_eq!(fs::read(&journal).expect("journal"), CANARY.as_bytes());

    // A journal whose header a commit in PERSIST mode zeroed holds no
    // interrupted transaction: the store is opened and checked.
    fs::write(&journal, [0_u8; 512]).expect("journal");
    let (exit, found, _) = doctor(&state);
    assert_eq!(exit, Exit::Success, "{found}");
    assert_eq!(
        statuses(&found),
        expected(
            &state.0,
            &[
                (StateFile::Audit, "pass", "doctor.passed"),
                (StateFile::ConfigLedger, "warning", "doctor.wal_pending"),
            ]
        )
    );
}

#[test]
fn a_directory_that_holds_no_store_fails() {
    // An admissible directory with no store in it, as a mistyped path or an
    // unmounted volume gives: nothing was checked, so it does not pass.
    let state = State::new("empty");
    fs::write(state.0.join("unrelated.txt"), CANARY).expect("an unrelated file");
    let (exit, found, _) = doctor(&state);
    assert_eq!(exit, Exit::Invalid, "{found}");
    let mut wanted = expected(&state.0, &[]);
    wanted[2] = (
        "state_dir.stores".to_owned(),
        "fail".to_owned(),
        "doctor.no_store".to_owned(),
    );
    assert_eq!(statuses(&found), wanted);
    assert_eq!(found["result"]["checks"][2]["severity"], "error");
    assert_eq!(codes(&found), ["doctor.required_check_failed"]);

    let (exit, captured) = run(&["doctor", "--state-dir", state.text()]);
    assert_eq!(exit, Exit::Invalid);
    assert!(captured
        .stdout()
        .contains("  fail     state_dir.stores      doctor.no_store\n"));
    assert_no_canary(&captured);
}

#[test]
fn a_state_directory_is_one_source_among_three() {
    let state = State::seeded("conflict");
    let bundle = Fixture::valid();
    for words in [
        vec!["doctor", bundle.path(), "--state-dir", state.text()],
        vec![
            "doctor",
            "--env",
            bundle.path(),
            "--state-dir",
            state.text(),
        ],
    ] {
        let (exit, captured) = run(&words);
        assert_eq!(exit, Exit::Usage, "{words:?}");
        assert!(captured.stderr().contains("usage.conflicting_options"));
        assert!(captured.stderr().contains("--state-dir"));
        assert!(captured.stdout().is_empty());
    }
    // Every source error of the doctor names all three sources, the missing
    // one and a bundle beside --env included.
    for words in [
        vec!["doctor"],
        vec!["doctor", bundle.path(), "--env", bundle.path()],
    ] {
        let (exit, captured) = run(&words);
        assert_eq!(exit, Exit::Usage, "{words:?}");
        assert!(
            captured.stderr().contains("--state-dir"),
            "{words:?}: {}",
            captured.stderr()
        );
    }
}

#[test]
fn every_store_has_a_check_named_after_it() {
    let ids: Vec<_> = StateFile::ALL
        .iter()
        .map(|store| format!("store.{}", store.id()))
        .collect();
    // The directory's three checks come first.
    assert_eq!(CHECKS[3..], ids);
    for store in StateFile::ALL {
        assert_eq!(store_check_id(store), format!("store.{}", store.id()));
    }
    assert_eq!(
        Code::StateDirNetworkFilesystem.as_str(),
        gateway_config::state_dir::NETWORK_FILESYSTEM_CODE
    );
}
