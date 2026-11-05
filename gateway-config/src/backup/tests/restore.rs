//! `restore` and the restore marker: a restore lands exactly the archive's
//! stores and its marker, or leaves the target as it was, whichever step
//! fails.

use super::*;
use crate::backup::restore::{restore_with, Step};
use crate::state_dir::{StateDirError, LOCK_FILE_NAME, RESTORE_MARKER_FILE_NAME};

const RESTORED_AT_MS: u64 = 1_800_000_100_000;

fn restore_request<'a>(
    archive: &'a Path,
    target: &'a Path,
    replace_existing: bool,
) -> RestoreRequest<'a> {
    RestoreRequest {
        archive,
        target,
        replace_existing,
        producer: PRODUCER,
        restored_at: UNIX_EPOCH + Duration::from_millis(RESTORED_AT_MS),
        nonce: [0xab; 16],
    }
}

/// Every entry name in `directory`, sorted.
fn listing(directory: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(directory)
        .expect("the directory should list")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("UTF-8 name")
        })
        .collect();
    names.sort();
    names
}

/// Every entry of `directory` with its bytes, a directory's as `None`:
/// what "left as it was" compares.
fn snapshot(directory: &Path) -> Vec<(String, Option<Vec<u8>>)> {
    listing(directory)
        .into_iter()
        .map(|name| {
            let path = directory.join(&name);
            let metadata = fs::symlink_metadata(&path).expect("entry");
            let bytes = metadata.is_file().then(|| {
                if name == LOCK_FILE_NAME {
                    // Never read: Windows refuses to read a locked file, and
                    // nothing writes its content. Its length stands in.
                    metadata.len().to_be_bytes().to_vec()
                } else {
                    fs::read(&path).expect("the entry should read")
                }
            });
            (name, bytes)
        })
        .collect()
}

/// What a restore is asked to restore into.
#[derive(Clone, Copy, Debug)]
enum Kind {
    /// A new, empty directory.
    Empty,
    /// An empty state directory something once locked.
    EmptyWithLockFile,
    /// A stopped state directory with a store, its write-ahead log and a
    /// marker a previous restore left.
    Prepared,
}

const KINDS: [Kind; 3] = [Kind::Empty, Kind::EmptyWithLockFile, Kind::Prepared];

/// `parent/state`, of `kind`.
fn new_target(parent: &TempDir, kind: Kind) -> PathBuf {
    let target = parent.join("state");
    fs::create_dir(&target).expect("the target should create");
    #[cfg(unix)]
    set_mode(&target, 0o700);
    match kind {
        Kind::Empty => {}
        Kind::EmptyWithLockFile => {
            drop(StateDirectory::acquire(&target).expect("the target should lock"));
        }
        Kind::Prepared => {
            drop(StateDirectory::acquire(&target).expect("the target should lock"));
            store(
                &target.join(StateFile::Audit.file_name()),
                &[("old_events", 2)],
            );
            fs::write(target.join("audit.sqlite3-wal"), b"").expect("a write-ahead log");
            fs::write(target.join(RESTORE_MARKER_FILE_NAME), b"{}").expect("an old marker");
            #[cfg(unix)]
            for name in ["audit.sqlite3-wal", RESTORE_MARKER_FILE_NAME] {
                set_mode(&target.join(name), 0o600);
            }
        }
    }
    target
}

/// A populated state directory's backup, with its bytes.
fn archive(label: &str) -> (TempDir, PathBuf, BackupSummary, RevisionId) {
    let (state, revision) = populated(label);
    let out = TempDir::new("out");
    let archive = out.join("state.ggbk");
    let created = create(state.held(), &request(&archive)).expect("the backup should be created");
    (out, archive, created, revision)
}

#[test]
fn a_backup_restores_into_an_empty_directory_byte_for_byte_with_its_marker() {
    let (out, archive, created, revision) = archive("restore");
    let bytes = fs::read(&archive).expect("archive");
    let parent = TempDir::new("parent");
    let target = new_target(&parent, Kind::Empty);

    let restored =
        restore(&restore_request(&archive, &target, false)).expect("the backup should restore");
    assert_eq!(restored.backup, created);
    assert_eq!(restored.restore_id, format!("rst-{}", "ab".repeat(16)));
    assert!(!restored.replaced);
    assert!(restored.warnings.is_empty());
    assert_eq!(
        parent.names(),
        ["state"],
        "nothing is left beside the target"
    );
    assert_eq!(
        listing(&target),
        [
            "audit.sqlite3",
            "config-ledger.sqlite3",
            "connections.sqlite3",
            "principals.sqlite3",
            RESTORE_MARKER_FILE_NAME,
            "service-tokens.sqlite3",
            LOCK_FILE_NAME,
        ]
    );
    // Each store is the archive's entry, byte for byte.
    for record in &records_of(&bytes)[1..] {
        let name = String::from_utf8(record.name.clone()).expect("UTF-8");
        assert_eq!(fs::read(target.join(&name)).expect("restored"), record.data);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path| fs::metadata(path).expect("mode").permissions().mode() & 0o777;
        assert_eq!(mode(&target), 0o700);
        for name in listing(&target) {
            assert_eq!(mode(&target.join(&name)), 0o600, "{name}");
        }
    }
    assert_eq!(out.names(), ["state.ggbk"], "the archive is never changed");
    assert_eq!(fs::read(&archive).expect("archive"), bytes);

    // The marker records the restore, value-free.
    let held = StateDirectory::acquire(&target).expect("the restored directory should lock");
    let marker = read_restore_marker(&held)
        .expect("the marker should read")
        .expect("a restored directory carries a marker");
    assert_eq!(
        marker,
        RestoreMarker {
            restore_id: restored.restore_id.clone(),
            restored_at_ms: RESTORED_AT_MS,
            restored_by_program: "ggctl".to_owned(),
            restored_by_version: "0.1.0".to_owned(),
            replaced: false,
            backup_api_version: "greengateway.dev/v1alpha1".to_owned(),
            backup_created_at_ms: 1_800_000_000_123,
            backup_created_by_program: "ggctl".to_owned(),
            backup_created_by_version: "0.1.0".to_owned(),
            stores: vec![
                StateFile::Audit,
                StateFile::Principals,
                StateFile::Connections,
                StateFile::ServiceTokens,
                StateFile::ConfigLedger,
            ],
            ledger: Some((revision.clone(), None)),
        }
    );
    let text = fs::read_to_string(target.join(RESTORE_MARKER_FILE_NAME)).expect("marker");
    assert!(!text.contains(CANARY) && !text.contains("ggbk"), "{text}");

    // The restored ledger opens as a gateway opens it, and the restored
    // directory backs up into the same stores again.
    let mut ledger = RevisionLedger::open(&held).expect("the restored ledger should verify");
    assert_eq!(ledger.state().expect("state").desired.revision, revision);
    drop(ledger);
    acknowledge_restore_marker(&held).expect("the marker should go");
    assert_eq!(read_restore_marker(&held), Ok(None));
    let again = create(&held, &request(&out.join("again.ggbk"))).expect("it backs up again");
    assert_eq!(again.stores, created.stores);
    assert_eq!(again.ledger, created.ledger);
}

#[test]
fn a_target_holding_stores_is_replaced_only_when_asked() {
    let (_out, archive, created, _) = archive("replace");
    let parent = TempDir::new("parent");
    let target = new_target(&parent, Kind::Prepared);
    let before = snapshot(&target);
    assert_eq!(
        restore(&restore_request(&archive, &target, false)),
        Err(RestoreError::TargetNotEmpty)
    );
    assert_eq!(snapshot(&target), before);
    assert_eq!(parent.names(), ["state"]);

    let restored =
        restore(&restore_request(&archive, &target, true)).expect("the backup should restore");
    assert!(restored.replaced);
    assert_eq!(restored.backup, created);
    assert!(restored.warnings.is_empty());
    assert_eq!(
        parent.names(),
        ["state"],
        "the replaced directory is removed"
    );
    let names = listing(&target);
    assert!(
        !names.contains(&"audit.sqlite3-wal".to_owned()),
        "{names:?}"
    );
    let connection = Connection::open(target.join("audit.sqlite3")).expect("restored store");
    let tables: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name = 'old_events'",
            [],
            |row| row.get(0),
        )
        .expect("count");
    assert_eq!(tables, 0, "the replaced store is gone");
    drop(connection);
    let held = StateDirectory::acquire(&target).expect("lock");
    let marker = read_restore_marker(&held).expect("read").expect("marker");
    assert!(marker.replaced);

    // An empty target may be named with the flag too.
    let empty = TempDir::new("empty-parent");
    let target = new_target(&empty, Kind::Empty);
    assert!(
        !restore(&restore_request(&archive, &target, true))
            .expect("restored")
            .replaced
    );
}

/// Puts something into a target.
type Plant = fn(&Path);

#[test]
fn a_target_holding_anything_else_is_never_touched() {
    let (_out, archive, _, _) = archive("foreign");
    let cases: [(&str, Plant); 3] = [
        ("a file the layout does not name", |target| {
            fs::write(target.join("notes.txt"), CANARY).expect("foreign file");
        }),
        ("a directory under a store's name", |target| {
            fs::create_dir(target.join("discovery.sqlite3-wal")).expect("a directory");
        }),
        ("a store's seed temporary", |target| {
            fs::write(target.join("config-ledger.sqlite3.seed"), b"").expect("seed file");
        }),
    ];
    for (label, plant) in cases {
        let parent = TempDir::new("parent");
        let target = new_target(&parent, Kind::Prepared);
        plant(&target);
        let before = snapshot(&target);
        for replace in [false, true] {
            assert_eq!(
                restore(&restore_request(&archive, &target, replace)),
                Err(RestoreError::TargetNotStateDirectory),
                "{label}"
            );
            assert_eq!(snapshot(&target), before, "{label}");
            assert_eq!(parent.names(), ["state"], "{label}");
        }
    }
    #[cfg(unix)]
    {
        let parent = TempDir::new("parent");
        let target = new_target(&parent, Kind::Empty);
        std::os::unix::fs::symlink(&archive, target.join("audit.sqlite3")).expect("symlink");
        let before = snapshot(&target);
        assert_eq!(
            restore(&restore_request(&archive, &target, true)),
            Err(RestoreError::TargetNotStateDirectory)
        );
        assert_eq!(snapshot(&target), before);
    }
}

#[test]
fn a_failure_at_any_step_leaves_the_target_as_it_was() {
    let (_out, archive, _, _) = archive("faults");
    for kind in KINDS {
        for step in [
            Step::Verified,
            Step::Checked,
            Step::Staged,
            Step::MovedAside,
        ] {
            let parent = TempDir::new("parent");
            let target = new_target(&parent, kind);
            let before = snapshot(&target);
            let injected = RestoreError::StagingUnavailable;
            let outcome = restore_with(&restore_request(&archive, &target, true), &mut |at| {
                if at == step {
                    Err(injected.clone())
                } else {
                    Ok(())
                }
            });
            assert_eq!(outcome, Err(injected), "{kind:?} at {step:?}");
            assert_eq!(snapshot(&target), before, "{kind:?} at {step:?}");
            assert_eq!(parent.names(), ["state"], "{kind:?} at {step:?}");
            // Nothing a failure leaves stops the next restore.
            restore(&restore_request(&archive, &target, true))
                .unwrap_or_else(|error| panic!("{kind:?} after {step:?}: {error:?}"));
        }
    }
}

#[test]
fn a_damaged_hostile_or_newer_archive_leaves_the_target_as_it_was() {
    let (_out, bytes) = good_archive("hostile");
    let records = records_of(&bytes);
    let manifest = records[0].clone();
    let last = records.len() - 1;

    // Cut short inside the last entry, after the others were staged.
    let truncated = bytes[..bytes.len() - 100].to_vec();
    // The last entry, the ledger, changed after the others were staged.
    let mut changed = records.clone();
    changed[last].data[200] ^= 0x01;
    let changed = raw_archive(&changed);
    let traversal = raw_archive(&[manifest.clone(), Raw::file("../audit.sqlite3", b"x")]);
    let bomb = raw_archive(&[
        manifest.clone(),
        Raw {
            size: 1 << 30,
            ..Raw::file("audit.sqlite3", b"tiny")
        },
    ]);
    let newer_manifest = with_manifest(&bytes, |manifest| {
        manifest["apiVersion"] = Value::from("greengateway.dev/v1beta1");
    });
    let mut newer_container = bytes.clone();
    newer_container[8..10].copy_from_slice(&2_u16.to_be_bytes());
    // A ledger of a newer format, consistent with its manifest otherwise.
    let mut newer_ledger = records.clone();
    newer_ledger[last].data[60..64].copy_from_slice(&2_i32.to_be_bytes());
    let mut edited = manifest_of(&bytes);
    edited["entries"][last - 1]["sha256"] =
        Value::from(hex::encode(Sha256::digest(&newer_ledger[last].data)));
    edited["entries"][last - 1]["database"]["userVersion"] = Value::from(2);
    newer_ledger[0] = Raw::file(
        MANIFEST_ENTRY,
        &serde_json::to_vec(&edited).expect("the edited manifest serializes"),
    );
    let newer_ledger = raw_archive(&newer_ledger);

    for (label, candidate, code) in [
        ("truncated", truncated, "archive.truncated"),
        ("changed", changed, "backup.checksum_mismatch"),
        ("traversal", traversal, "archive.entry_outside_root"),
        ("bomb", bomb, "archive.truncated"),
        (
            "newer manifest",
            newer_manifest,
            "backup.unsupported_manifest_version",
        ),
        (
            "newer container",
            newer_container,
            "backup.unsupported_archive_version",
        ),
        (
            "newer ledger",
            newer_ledger,
            "backup.ledger_verification_failed",
        ),
    ] {
        for kind in KINDS {
            let parent = TempDir::new("parent");
            let target = new_target(&parent, kind);
            let candidates = TempDir::new("candidate");
            let path = candidates.join("candidate.ggbk");
            fs::write(&path, &candidate).expect("the candidate should write");
            let before = snapshot(&target);
            match restore(&restore_request(&path, &target, true)) {
                Err(RestoreError::Backup(error)) => {
                    assert_eq!(error.code(), code, "{label} into {kind:?}")
                }
                other => panic!("{label} into {kind:?}: {other:?}"),
            }
            assert_eq!(snapshot(&target), before, "{label} into {kind:?}");
            assert_eq!(parent.names(), ["state"], "{label} into {kind:?}");
            assert_eq!(candidates.names(), ["candidate.ggbk"], "{label}");
        }
    }
}

#[test]
fn a_store_claiming_another_stores_identity_is_refused() {
    // The ledger's database under the Connections store's name verifies as
    // a backup, since any database is a store to one, but no restore puts
    // it in place.
    let state = State::new("identity");
    seed(&state);
    fs::copy(
        state.file(StateFile::ConfigLedger),
        state.file(StateFile::Connections),
    )
    .expect("a copy of the ledger");
    #[cfg(unix)]
    set_mode(&state.file(StateFile::Connections), 0o600);
    let out = TempDir::new("out");
    let archive = out.join("state.ggbk");
    create(state.held(), &request(&archive)).expect("the backup should be created");
    verify(&archive).expect("it verifies");
    let parent = TempDir::new("parent");
    let target = new_target(&parent, Kind::Empty);
    assert_eq!(
        restore(&restore_request(&archive, &target, false)),
        Err(RestoreError::StoreIdentity {
            store: StateFile::Connections
        })
    );
    assert!(listing(&target).is_empty());
    assert_eq!(parent.names(), ["state"]);
    assert_eq!(
        StateFile::ConfigLedger.application_id(),
        0x4747_4C47,
        "the ledger's own header"
    );
}

#[test]
fn second_names_of_one_file_are_restored_as_one_file() {
    let state = State::new("dedupe");
    store(&state.file(StateFile::Audit), &[("audit_events", 2)]);
    fs::hard_link(
        state.file(StateFile::Audit),
        state.file(StateFile::Discovery),
    )
    .expect("a second name for the audit store");
    let out = TempDir::new("out");
    let archive = out.join("state.ggbk");
    create(state.held(), &request(&archive)).expect("the backup should be created");
    let parent = TempDir::new("parent");
    let target = new_target(&parent, Kind::Empty);
    restore(&restore_request(&archive, &target, false)).expect("restored");
    // One file under both names: a write through one is read through the
    // other.
    let audit = Connection::open(target.join("audit.sqlite3")).expect("audit");
    audit
        .execute("INSERT INTO audit_events (value) VALUES ('after')", [])
        .expect("insert");
    drop(audit);
    let discovery = Connection::open(target.join("discovery.sqlite3")).expect("discovery");
    let rows: i64 = discovery
        .query_row("SELECT count(*) FROM audit_events", [], |row| row.get(0))
        .expect("count");
    assert_eq!(rows, 3);
}

#[test]
fn a_locked_missing_or_unreadable_target_or_archive_is_refused_first() {
    let (_out, archive, _, _) = archive("refusals");
    let parent = TempDir::new("parent");
    let target = new_target(&parent, Kind::Empty);

    // The archive is checked before the target is touched: no lock file.
    let missing = parent.join("missing.ggbk");
    assert_eq!(
        restore(&restore_request(&missing, &target, false)),
        Err(RestoreError::Backup(BackupError::ArchiveUnreadable))
    );
    assert!(listing(&target).is_empty());
    assert_eq!(
        restore(&restore_request(&target, &target, false)),
        Err(RestoreError::Backup(BackupError::ArchiveNotRegularFile))
    );
    assert_eq!(
        restore(&restore_request(&archive, &parent.join("absent"), false)),
        Err(RestoreError::StateDir(StateDirError::Missing))
    );

    let held = StateDirectory::acquire(&target).expect("another process's lock");
    let before = snapshot(&target);
    assert_eq!(
        restore(&restore_request(&archive, &target, false)),
        Err(RestoreError::StateDir(StateDirError::Locked))
    );
    assert_eq!(snapshot(&target), before);
    drop(held);
    assert_eq!(parent.names(), ["state"]);
}

#[test]
fn a_postgres_dump_is_refused_as_unsupported() {
    let mut dump = b"PGDMP".to_vec();
    dump.extend_from_slice(&[1, 14, 0, 4, 8, 8, 1]);
    assert_eq!(verify_bytes(&dump), Err(BackupError::PostgresDump));
    assert_eq!(
        BackupError::PostgresDump.code(),
        "backup.postgres_unsupported"
    );
    let candidates = TempDir::new("candidate");
    let path = candidates.join("cluster.dump");
    fs::write(&path, &dump).expect("dump");
    let parent = TempDir::new("parent");
    let target = new_target(&parent, Kind::Empty);
    assert_eq!(
        restore(&restore_request(&path, &target, false)),
        Err(RestoreError::Backup(BackupError::PostgresDump))
    );
    assert!(listing(&target).is_empty());
    assert_eq!(parent.names(), ["state"]);
}

#[cfg(windows)]
#[test]
fn a_target_a_process_holds_open_is_never_moved_on_windows() {
    let (_out, archive, _, _) = archive("held-open");
    let parent = TempDir::new("parent");
    let target = new_target(&parent, Kind::Prepared);
    let before = snapshot(&target);
    // A gateway that took the lock after the restore let it go holds files
    // open beneath the target, and Windows will not rename it then.
    let open = fs::File::open(target.join("audit.sqlite3")).expect("an open store");
    assert_eq!(
        restore(&restore_request(&archive, &target, true)),
        Err(RestoreError::SwitchFailed)
    );
    drop(open);
    assert_eq!(snapshot(&target), before);
    assert_eq!(parent.names(), ["state"]);
}

#[cfg(unix)]
#[test]
fn an_unsafe_restore_marker_is_refused() {
    let (_out, archive, _, _) = archive("marker");
    let parent = TempDir::new("parent");
    let target = new_target(&parent, Kind::Empty);
    restore(&restore_request(&archive, &target, false)).expect("restored");
    let held = StateDirectory::acquire(&target).expect("lock");
    let marker = target.join(RESTORE_MARKER_FILE_NAME);
    set_mode(&marker, 0o620);
    assert_eq!(read_restore_marker(&held), Err(MarkerError::Unsafe));
    set_mode(&marker, 0o600);
    let moved = target.join("marker-elsewhere");
    fs::rename(&marker, &moved).expect("moved");
    std::os::unix::fs::symlink(&moved, &marker).expect("symlink");
    assert_eq!(read_restore_marker(&held), Err(MarkerError::Unsafe));
}

#[test]
fn restore_errors_are_value_free() {
    let errors = [
        RestoreError::StateDir(StateDirError::Locked),
        RestoreError::Backup(BackupError::Entry {
            store: StateFile::Audit,
            problem: EntryProblem::ChecksumMismatch,
        }),
        RestoreError::TargetNotEmpty,
        RestoreError::TargetNotStateDirectory,
        RestoreError::TargetMountPoint,
        RestoreError::TargetUnavailable,
        RestoreError::StagingUnavailable,
        RestoreError::PermissionsUnavailable,
        RestoreError::StoreIdentity {
            store: StateFile::Connections,
        },
        RestoreError::TargetChanged,
        RestoreError::SwitchFailed,
        RestoreError::RollbackFailed,
    ];
    let mut codes = std::collections::BTreeSet::new();
    for error in &errors {
        let text = error.to_string();
        assert!(text.contains(error.code()), "{text}");
        assert!(!text.contains('/') && !text.contains('\\'), "{text}");
        assert!(codes.insert(error.code()), "{}", error.code());
    }
    assert_eq!(
        errors[8].to_string(),
        "store connections: error[restore.store_identity_mismatch]"
    );
    for warning in [
        RestoreWarning::DirectoryNotFlushed,
        RestoreWarning::PreviousNotRemoved,
    ] {
        assert!(warning.code().starts_with("restore."));
    }
    for error in [
        MarkerError::Unsafe,
        MarkerError::Invalid,
        MarkerError::Unavailable,
    ] {
        assert_eq!(error.to_string(), format!("error[{}]", error.code()));
    }
}
