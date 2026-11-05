use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, UNIX_EPOCH},
};

use rusqlite::{params, Connection};
use serde_json::Value;

use super::*;
use crate::archive::ArchiveCode;
use crate::bundle::{read_bundle, sha256_pin, Bundle, PublishedSchemasOnly, ReadOptions};
use crate::documents::published_schema;
use crate::ledger::LedgerActor;

/// A value that must never reach an archive, a report or an error: it names
/// every temporary directory and every file that is not a store.
const CANARY: &str = "zqcanary";
const PRODUCER: Producer = Producer {
    program: "ggctl",
    version: "0.1.0",
};

// --- fixtures -------------------------------------------------------------------

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "greengateway-backup-{CANARY}-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).expect("temporary directory should create");
        #[cfg(unix)]
        set_mode(&path, 0o700);
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Every entry name in the directory, sorted.
    fn names(&self) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(&self.0)
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
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("permissions should set");
}

/// A state directory held under its lock, as `ggctl` holds it.
struct State {
    held: Option<StateDirectory>,
    directory: TempDir,
}

impl Drop for State {
    fn drop(&mut self) {
        // Released before the directory goes: Windows will not remove a
        // directory with an open file in it.
        self.held.take();
    }
}

impl State {
    fn new(label: &str) -> Self {
        let directory = TempDir::new(label);
        let held = StateDirectory::acquire(directory.path()).expect("the state directory locks");
        Self {
            held: Some(held),
            directory,
        }
    }

    fn held(&self) -> &StateDirectory {
        self.held.as_ref().expect("held until the fixture drops")
    }

    fn file(&self, store: StateFile) -> PathBuf {
        self.directory.join(store.file_name())
    }
}

/// A store as the gateway keeps one: WAL mode, with `rows` rows in each
/// table.
fn store(path: &Path, tables: &[(&str, usize)]) {
    let connection = Connection::open(path).expect("the store should open");
    connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| {
            row.get::<_, String>(0)
        })
        .expect("WAL mode");
    for (table, rows) in tables {
        connection
            .execute_batch(&format!(
                "CREATE TABLE {table} (id INTEGER PRIMARY KEY, value TEXT NOT NULL)"
            ))
            .expect("table");
        for row in 0..*rows {
            connection
                .execute(
                    &format!("INSERT INTO {table} (value) VALUES (?1)"),
                    params![format!("row-{row}")],
                )
                .expect("row");
        }
    }
    connection.close().expect("the store should close");
    // The gateway creates its stores under the process umask; group and
    // other must not be able to write one.
    #[cfg(unix)]
    set_mode(path, 0o600);
}

const DEPLOYMENT_YAML: &str = concat!(
    "apiVersion: greengateway.dev/v1alpha1\n",
    "kind: GatewayDeployment\n",
    "spec:\n",
    "  profile: production\n",
);
const POLICY_JSON: &str = "{\n  \"schema_version\": \"0.1.0\",\n  \"default_action\": \"deny\",\n  \"roles\": {\"operator\": {\"permissions\": [\"admin:policy:read\"]}}\n}\n";
const TOOLS_JSON: &str = "{\n  \"schema_version\": \"0.1.0\",\n  \"tools\": []\n}\n";

/// A complete bundle, read the way `ggctl` reads one.
fn bundle() -> Bundle<Value, Value> {
    let directory = TempDir::new("bundle");
    let manifest = format!(
        concat!(
            "apiVersion: greengateway.dev/v1alpha1\n",
            "kind: GatewayBundle\n",
            "metadata:\n",
            "  name: payments-production\n",
            "spec:\n",
            "  deployment:\n",
            "    path: deployment.yaml\n",
            "    sha256: \"{}\"\n",
            "  resources:\n",
            "    policy:\n",
            "      source: bundle\n",
            "      path: policy.json\n",
            "      schema_version: \"0.1.0\"\n",
            "      sha256: \"{}\"\n",
            "    tools:\n",
            "      source: bundle\n",
            "      path: tools.json\n",
            "      schema_version: \"0.1.0\"\n",
            "      sha256: \"{}\"\n",
            "    connections:\n",
            "      source: server\n",
        ),
        sha256_pin(DEPLOYMENT_YAML.as_bytes()),
        sha256_pin(POLICY_JSON.as_bytes()),
        sha256_pin(TOOLS_JSON.as_bytes()),
    );
    for (name, contents) in [
        ("deployment.yaml", DEPLOYMENT_YAML),
        ("policy.json", POLICY_JSON),
        ("tools.json", TOOLS_JSON),
        ("bundle.yaml", manifest.as_str()),
    ] {
        let path = directory.join(name);
        fs::write(&path, contents).expect("bundle file should write");
        #[cfg(unix)]
        set_mode(&path, 0o644);
    }
    #[cfg(unix)]
    set_mode(directory.path(), 0o755);
    let report = read_bundle(
        directory.path(),
        ReadOptions::default(),
        &PublishedSchemasOnly,
    );
    report
        .bundle
        .unwrap_or_else(|| panic!("fixture bundle should read: {:?}", report.diagnostics))
}

/// Seeds the state directory's ledger.
fn seed(state: &State) -> RevisionId {
    let actor = LedgerActor::system("ggctl-ledger-seed").expect("recordable");
    let at = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
    let (ledger, seed) = RevisionLedger::seed(state.held(), &bundle(), actor, at).expect("seed");
    drop(ledger);
    seed.revision
}

/// A state directory holding four gateway stores and a seeded ledger.
fn populated(label: &str) -> (State, RevisionId) {
    let state = State::new(label);
    store(&state.file(StateFile::Audit), &[("audit_events", 25)]);
    store(
        &state.file(StateFile::Principals),
        &[("principal_directory", 3)],
    );
    store(
        &state.file(StateFile::Connections),
        &[("connection_records", 2), ("connection_local_secrets", 1)],
    );
    store(
        &state.file(StateFile::ServiceTokens),
        &[("service_tokens", 4)],
    );
    let revision = seed(&state);
    (state, revision)
}

fn request(output: &Path) -> CreateRequest<'_> {
    CreateRequest {
        output,
        producer: PRODUCER,
        created_at: UNIX_EPOCH + Duration::from_millis(1_800_000_000_123),
    }
}

/// One record of a raw archive, which may say anything.
#[derive(Clone)]
struct Raw {
    kind: u8,
    name: Vec<u8>,
    /// The size the header declares.
    size: u64,
    data: Vec<u8>,
}

impl Raw {
    fn file(name: &str, data: &[u8]) -> Self {
        Self {
            kind: 1,
            name: name.as_bytes().to_vec(),
            size: data.len() as u64,
            data: data.to_vec(),
        }
    }
}

/// A container holding `records`, with a correct end record unless the
/// caller damages it afterwards.
fn raw_archive(records: &[Raw]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"GGBACKUP");
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    for record in records {
        bytes.push(record.kind);
        bytes.extend_from_slice(&(record.name.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&record.name);
        bytes.extend_from_slice(&record.size.to_be_bytes());
        bytes.extend_from_slice(&record.data);
    }
    bytes.push(0);
    bytes.extend_from_slice(&(records.len() as u32).to_be_bytes());
    let digest = Sha256::digest(&bytes);
    bytes.extend_from_slice(&digest);
    bytes
}

/// The records of a well-formed archive.
fn records_of(archive: &[u8]) -> Vec<Raw> {
    let mut records = Vec::new();
    let mut at = 12;
    loop {
        let kind = archive[at];
        if kind == 0 {
            return records;
        }
        let name_length = usize::from(u16::from_be_bytes([archive[at + 1], archive[at + 2]]));
        let name = archive[at + 3..at + 3 + name_length].to_vec();
        at += 3 + name_length;
        let size = u64::from_be_bytes(archive[at..at + 8].try_into().expect("eight bytes"));
        at += 8;
        let length = usize::try_from(size).expect("a test archive fits in memory");
        let data = archive[at..at + length].to_vec();
        at += length;
        records.push(Raw {
            kind,
            name,
            size,
            data,
        });
    }
}

/// The manifest of a well-formed archive, as JSON.
fn manifest_of(archive: &[u8]) -> Value {
    serde_json::from_slice(&records_of(archive)[0].data).expect("the manifest is JSON")
}

/// A complete backup of a populated state directory, as bytes, with the
/// directory it was written in.
fn good_archive(label: &str) -> (TempDir, Vec<u8>) {
    let (state, _) = populated(label);
    let out = TempDir::new("out");
    let output = out.join("state.ggbk");
    create(state.held(), &request(&output)).expect("the backup should be created");
    let bytes = fs::read(&output).expect("the archive should read");
    (out, bytes)
}

/// Writes `bytes` as an archive in a new directory and verifies it; the
/// directory must hold only the archive afterwards, whatever the outcome.
fn verify_bytes(bytes: &[u8]) -> Result<BackupSummary, BackupError> {
    let directory = TempDir::new("verify");
    let archive = directory.join("candidate.ggbk");
    fs::write(&archive, bytes).expect("the archive should write");
    let verified = verify(&archive);
    assert_eq!(
        directory.names(),
        ["candidate.ggbk"],
        "verification left something beside the archive"
    );
    verified
}

fn refused_with(bytes: &[u8]) -> ArchiveCode {
    match verify_bytes(bytes) {
        Err(BackupError::Refused(refusal)) => refusal.code,
        other => panic!("expected an archive refusal, got {other:?}"),
    }
}

/// Rebuilds an archive from a good one's records with its manifest edited.
fn with_manifest(archive: &[u8], edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut records = records_of(archive);
    let mut manifest = manifest_of(archive);
    edit(&mut manifest);
    records[0] = Raw::file(
        MANIFEST_ENTRY,
        &serde_json::to_vec(&manifest).expect("the edited manifest serializes"),
    );
    raw_archive(&records)
}

// --- create --------------------------------------------------------------------

#[test]
fn a_backup_holds_every_store_with_versions_counts_and_checksums_and_verifies() {
    let (state, revision) = populated("round-trip");
    let out = TempDir::new("out");
    let output = out.join("state.ggbk");
    let created = create(state.held(), &request(&output)).expect("the backup should be created");
    assert_eq!(out.names(), ["state.ggbk"], "only the archive is left");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&output).expect("archive").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    assert_eq!(created.api_version, "greengateway.dev/v1alpha1");
    assert_eq!(created.archive_version, 1);
    assert_eq!(created.created_at_ms, 1_800_000_000_123);
    assert_eq!(created.producer_program, "ggctl");
    assert_eq!(created.producer_version, "0.1.0");
    assert_eq!(created.sqlite_version, rusqlite::version());
    let included: Vec<_> = created
        .stores
        .iter()
        .filter(|store| store.included)
        .map(|store| (store.store, store.tables, store.rows))
        .collect();
    assert_eq!(
        included,
        [
            (StateFile::Audit, 1, 25),
            (StateFile::Principals, 1, 3),
            (StateFile::Connections, 2, 3),
            (StateFile::ServiceTokens, 1, 4),
            (StateFile::ConfigLedger, 4, 6),
        ]
    );
    assert_eq!(created.entries, 5);
    let ledger = created.ledger.clone().expect("the ledger is included");
    assert_eq!(ledger.revisions, 1);
    assert_eq!(ledger.desired, revision);
    assert_eq!(ledger.active, None);
    assert_eq!(ledger.bundle_api_version, "greengateway.dev/v1alpha1");

    assert_eq!(verify(&output), Ok(created));

    // The manifest is the first entry, holds to its published schema, and
    // pins every entry by length and SHA-256.
    let bytes = fs::read(&output).expect("archive");
    let records = records_of(&bytes);
    assert_eq!(records[0].name, MANIFEST_ENTRY.as_bytes());
    let manifest = manifest_of(&bytes);
    let schema = published_schema("greengateway.dev/v1alpha1", "GatewayBackup")
        .expect("the backup manifest schema is published");
    let schema: Value = serde_json::from_str(schema.json).expect("JSON");
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let errors: Vec<_> = validator
        .iter_errors(&manifest)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}\n{manifest:#}");
    for (record, entry) in records[1..]
        .iter()
        .zip(manifest["entries"].as_array().expect("entries"))
    {
        assert_eq!(
            entry["name"],
            String::from_utf8_lossy(&record.name).as_ref()
        );
        assert_eq!(entry["bytes"], record.data.len());
        assert_eq!(entry["sha256"], hex::encode(Sha256::digest(&record.data)));
        assert_eq!(&record.data[..16], b"SQLite format 3\0");
        // Every entry is in rollback-journal mode.
        assert_eq!(record.data[18..20], [1, 1]);
    }
    assert_eq!(
        manifest["entries"][4]["database"]["applicationId"],
        0x4747_4C47
    );
    assert_eq!(manifest["entries"][4]["database"]["userVersion"], 1);
    assert_eq!(
        manifest["stores"][1],
        serde_json::json!({"store": "discovery", "file": "discovery.sqlite3", "included": false})
    );
}

#[test]
fn nothing_but_the_layouts_stores_reaches_the_archive() {
    let (state, _) = populated("canary");
    let directory = state.directory.path();
    // Key material, environment files and anything else beside the stores,
    // and a store's own write-ahead log of a file that is not in the
    // layout, are never read.
    fs::write(directory.join("connection-master.key"), CANARY).expect("key file");
    fs::write(directory.join(".env"), format!("ADMIN_TOKEN={CANARY}")).expect("env file");
    fs::write(directory.join("tokens.txt"), CANARY).expect("token file");
    fs::create_dir(directory.join("connection-secrets")).expect("secrets directory");
    fs::write(
        directory.join("connection-secrets").join("keyring.json"),
        CANARY,
    )
    .expect("keyring");
    fs::write(directory.join("notes.sqlite3-wal"), CANARY).expect("stray journal");
    let out = TempDir::new("out");
    let output = out.join("state.ggbk");
    create(state.held(), &request(&output)).expect("the backup should be created");
    let bytes = fs::read(&output).expect("archive");
    let canary = CANARY.as_bytes();
    assert!(
        !bytes.windows(canary.len()).any(|window| window == canary),
        "an excluded file, or a path, reached the archive"
    );
    let path = directory.to_string_lossy().into_owned();
    assert!(!String::from_utf8_lossy(&bytes).contains(&path));
    let names: Vec<_> = records_of(&bytes)
        .into_iter()
        .map(|record| String::from_utf8(record.name).expect("UTF-8"))
        .collect();
    assert_eq!(
        names,
        [
            MANIFEST_ENTRY,
            "audit.sqlite3",
            "principals.sqlite3",
            "connections.sqlite3",
            "service-tokens.sqlite3",
            "config-ledger.sqlite3"
        ]
    );
}

#[test]
fn a_snapshot_holds_what_the_write_ahead_log_holds_and_changes_nothing() {
    let state = State::new("wal");
    let path = state.file(StateFile::Audit);
    store(&path, &[("audit_events", 1)]);
    // A connection that keeps ten more rows in the write-ahead log: nothing
    // is checkpointed into the main file while it is open.
    let writer = Connection::open(&path).expect("writer");
    writer
        .execute_batch("PRAGMA wal_autocheckpoint = 0;")
        .expect("no checkpoints");
    for row in 0..10 {
        writer
            .execute(
                "INSERT INTO audit_events (value) VALUES (?1)",
                params![format!("logged-{row}")],
            )
            .expect("row");
    }
    let wal = PathBuf::from(format!("{}-wal", path.display()));
    let main_before = fs::read(&path).expect("main file");
    let wal_before = fs::read(&wal).expect("the log holds the rows");
    assert!(!wal_before.is_empty());

    let out = TempDir::new("out");
    let output = out.join("state.ggbk");
    let created = create(state.held(), &request(&output)).expect("the backup should be created");
    assert_eq!(
        created.stores[0].rows, 11,
        "the log's rows are in the snapshot"
    );
    assert_eq!(fs::read(&path).expect("main file"), main_before);
    assert_eq!(fs::read(&wal).expect("log"), wal_before);
    drop(writer);
    assert!(verify(&output).is_ok());
}

#[test]
fn a_writer_committing_meanwhile_never_tears_a_snapshot() {
    // The lock keeps the gateway and ggctl apart; a writer that ignores it
    // still cannot tear a snapshot, because VACUUM INTO reads one committed
    // state.
    let state = State::new("concurrent");
    let path = state.file(StateFile::Discovery);
    store(&path, &[("left_rows", 0), ("right_rows", 0)]);
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let stop = Arc::clone(&stop);
        let path = path.clone();
        std::thread::spawn(move || {
            let mut connection = Connection::open(&path).expect("writer");
            connection
                .busy_timeout(Duration::from_secs(5))
                .expect("busy timeout");
            let mut commits = 0_u64;
            while !stop.load(Ordering::Relaxed) || commits < 20 {
                let transaction = connection.transaction().expect("transaction");
                transaction
                    .execute("INSERT INTO left_rows (value) VALUES ('l')", [])
                    .expect("left");
                transaction
                    .execute("INSERT INTO right_rows (value) VALUES ('r')", [])
                    .expect("right");
                transaction.commit().expect("commit");
                commits += 1;
            }
        })
    };
    let out = TempDir::new("out");
    for attempt in 0..3 {
        let output = out.join(&format!("state-{attempt}.ggbk"));
        let created =
            create(state.held(), &request(&output)).expect("the backup should be created");
        let bytes = fs::read(&output).expect("archive");
        let tables = &manifest_of(&bytes)["entries"][0]["database"]["tables"];
        assert_eq!(tables[0]["name"], "left_rows");
        assert_eq!(tables[0]["rows"], tables[1]["rows"], "a torn snapshot");
        assert_eq!(created.stores[1].rows % 2, 0);
    }
    stop.store(true, Ordering::Relaxed);
    writer.join().expect("the writer should finish");
}

#[test]
fn an_existing_output_is_never_replaced() {
    let (state, _) = populated("exists");
    let out = TempDir::new("out");
    let output = out.join("state.ggbk");
    fs::write(&output, CANARY).expect("an existing file");
    assert_eq!(
        create(state.held(), &request(&output)),
        Err(BackupError::OutputExists)
    );
    assert_eq!(fs::read_to_string(&output).expect("kept"), CANARY);
    fs::remove_file(&output).expect("removed");
    fs::create_dir(&output).expect("a directory");
    assert_eq!(
        create(state.held(), &request(&output)),
        Err(BackupError::OutputExists)
    );
    assert_eq!(out.names(), ["state.ggbk"]);
    #[cfg(unix)]
    {
        // A dangling link is something too, and its target is never made.
        let linked = out.join("linked.ggbk");
        std::os::unix::fs::symlink(out.join("elsewhere"), &linked).expect("symlink");
        assert_eq!(
            create(state.held(), &request(&linked)),
            Err(BackupError::OutputExists)
        );
        assert!(!out.join("elsewhere").exists());
    }
    // An output whose directory does not exist leaves nothing anywhere.
    assert_eq!(
        create(
            state.held(),
            &request(&out.join("missing").join("state.ggbk"))
        ),
        Err(BackupError::OutputUnusable)
    );
}

#[test]
fn an_empty_state_directory_has_nothing_to_back_up() {
    let state = State::new("empty");
    fs::write(state.directory.join("unrelated.txt"), CANARY).expect("unrelated");
    let out = TempDir::new("out");
    assert_eq!(
        create(state.held(), &request(&out.join("state.ggbk"))),
        Err(BackupError::NothingToBackUp)
    );
    assert!(out.names().is_empty());
}

#[test]
fn a_corrupt_store_or_ledger_is_refused_and_nothing_is_left() {
    let (state, _) = populated("corrupt");
    let out = TempDir::new("out");
    let output = out.join("state.ggbk");

    let principals = state.file(StateFile::Principals);
    let good = fs::read(&principals).expect("store");
    fs::write(&principals, b"not a database at all, not even close to one").expect("garbage");
    let refused = create(state.held(), &request(&output)).expect_err("a corrupt store");
    assert_eq!(
        refused,
        BackupError::Store {
            store: StateFile::Principals,
            problem: StoreProblem::Corrupt
        }
    );
    assert!(out.names().is_empty(), "{:?}", out.names());
    fs::write(&principals, good).expect("restored");

    // A ledger edited outside the gateway no longer verifies.
    let ledger = Connection::open(state.file(StateFile::ConfigLedger)).expect("outside edit");
    ledger
        .execute_batch(
            "DROP TRIGGER config_revisions_no_update; UPDATE config_revisions SET record = X'7B7D';",
        )
        .expect("edit");
    drop(ledger);
    assert_eq!(
        create(state.held(), &request(&output)),
        Err(BackupError::Store {
            store: StateFile::ConfigLedger,
            problem: StoreProblem::LedgerInvalid
        })
    );
    assert!(out.names().is_empty(), "{:?}", out.names());
}

#[test]
fn stores_that_are_one_file_are_snapshotted_once_but_the_ledger_never_shares() {
    let state = State::new("dedupe");
    store(&state.file(StateFile::Audit), &[("audit_events", 2)]);
    fs::hard_link(
        state.file(StateFile::Audit),
        state.file(StateFile::Discovery),
    )
    .expect("a second name for the audit store");
    let out = TempDir::new("out");
    let output = out.join("state.ggbk");
    let created = create(state.held(), &request(&output)).expect("the backup should be created");
    assert_eq!(created.entries, 1);
    assert_eq!(created.stores[0].entry, Some(StateFile::Audit));
    assert_eq!(created.stores[1].entry, Some(StateFile::Audit));
    assert!(created.stores[1].included);
    let manifest = manifest_of(&fs::read(&output).expect("archive"));
    assert_eq!(manifest["stores"][1]["entry"], "audit.sqlite3");
    assert_eq!(verify(&output), Ok(created));

    fs::hard_link(
        state.file(StateFile::Audit),
        state.file(StateFile::ConfigLedger),
    )
    .expect("a ledger name for the audit store");
    assert_eq!(
        create(state.held(), &request(&out.join("shared.ggbk"))),
        Err(BackupError::Store {
            store: StateFile::ConfigLedger,
            problem: StoreProblem::LedgerShared
        })
    );
}

#[test]
fn a_store_that_is_not_a_regular_file_is_refused() {
    let state = State::new("kinds");
    fs::create_dir(state.file(StateFile::Audit)).expect("a directory in a store's place");
    let out = TempDir::new("out");
    assert_eq!(
        create(state.held(), &request(&out.join("state.ggbk"))),
        Err(BackupError::Store {
            store: StateFile::Audit,
            problem: StoreProblem::NotRegularFile
        })
    );
    assert!(out.names().is_empty());
}

#[cfg(unix)]
#[test]
fn linked_special_and_shared_writable_stores_are_refused_on_unix() {
    use std::os::unix::fs::symlink;
    let state = State::new("unix-stores");
    let elsewhere = TempDir::new("elsewhere");
    store(&elsewhere.join("audit.sqlite3"), &[("audit_events", 1)]);
    symlink(
        elsewhere.join("audit.sqlite3"),
        state.file(StateFile::Audit),
    )
    .expect("symlink");
    let out = TempDir::new("out");
    let output = out.join("state.ggbk");
    assert_eq!(
        create(state.held(), &request(&output)),
        Err(BackupError::Store {
            store: StateFile::Audit,
            problem: StoreProblem::Link
        })
    );
    fs::remove_file(state.file(StateFile::Audit)).expect("unlinked");

    let status = std::process::Command::new("mkfifo")
        .arg(state.file(StateFile::Audit))
        .status()
        .expect("mkfifo should run");
    assert!(status.success());
    assert_eq!(
        create(state.held(), &request(&output)),
        Err(BackupError::Store {
            store: StateFile::Audit,
            problem: StoreProblem::NotRegularFile
        })
    );
    fs::remove_file(state.file(StateFile::Audit)).expect("removed");

    store(&state.file(StateFile::Audit), &[("audit_events", 1)]);
    set_mode(&state.file(StateFile::Audit), 0o664);
    assert_eq!(
        create(state.held(), &request(&output)),
        Err(BackupError::Store {
            store: StateFile::Audit,
            problem: StoreProblem::UnsafePermissions
        })
    );
    assert!(out.names().is_empty());
}

#[cfg(windows)]
#[test]
fn a_junction_in_a_stores_place_is_refused_on_windows() {
    let state = State::new("windows-junction");
    let elsewhere = TempDir::new("elsewhere");
    let output = std::process::Command::new("cmd")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(state.file(StateFile::Audit))
        .arg(elsewhere.path())
        .output()
        .expect("the Windows command processor should start");
    assert!(output.status.success(), "the junction should create");
    let out = TempDir::new("out");
    assert_eq!(
        create(state.held(), &request(&out.join("state.ggbk"))),
        Err(BackupError::Store {
            store: StateFile::Audit,
            problem: StoreProblem::Link
        })
    );
}

// --- verify --------------------------------------------------------------------

#[test]
fn truncation_anywhere_is_refused() {
    let (_out, bytes) = good_archive("truncation");
    let records = records_of(&bytes);
    let manifest_end = 12 + 11 + MANIFEST_ENTRY.len() + records[0].data.len();
    let mut cuts: Vec<usize> = (0..manifest_end + 40).collect();
    cuts.extend((manifest_end + 40..bytes.len()).step_by(997));
    cuts.extend(bytes.len() - 40..bytes.len());
    for cut in cuts {
        match verify_bytes(&bytes[..cut]) {
            Err(BackupError::Refused(refusal)) => {
                assert_eq!(refusal.code, ArchiveCode::Truncated, "cut at {cut}");
            }
            other => panic!("cut at {cut}: {other:?}"),
        }
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(refused_with(&longer), ArchiveCode::Malformed);
}

#[test]
fn tampering_with_any_entry_the_manifest_or_the_end_record_is_detected() {
    let (_out, bytes) = good_archive("tamper");
    let records = records_of(&bytes);

    // An entry's data, changed in place.
    let audit_data_start =
        12 + 11 + MANIFEST_ENTRY.len() + records[0].data.len() + 11 + "audit.sqlite3".len();
    let mut damaged = bytes.clone();
    damaged[audit_data_start + 200] ^= 0x01;
    assert_eq!(
        verify_bytes(&damaged),
        Err(BackupError::Entry {
            store: StateFile::Audit,
            problem: EntryProblem::ChecksumMismatch
        })
    );

    // The manifest, changed in place: no longer the manifest it was.
    let mut damaged = bytes.clone();
    let position = 12 + 11 + MANIFEST_ENTRY.len() + 5;
    damaged[position] = b'X';
    assert!(matches!(
        verify_bytes(&damaged),
        Err(BackupError::ManifestInvalid | BackupError::UnsupportedManifestVersion)
    ));

    // The end record's count and digest.
    let mut damaged = bytes.clone();
    let count = bytes.len() - 33;
    damaged[count] ^= 0x01;
    assert_eq!(refused_with(&damaged), ArchiveCode::Malformed);
    let mut damaged = bytes.clone();
    let last = damaged.len() - 1;
    damaged[last] ^= 0x01;
    assert_eq!(
        verify_bytes(&damaged),
        Err(BackupError::ArchiveDigestMismatch)
    );

    // A consistent rewrite: another valid database under the audit entry's
    // name, with its length and digest recorded, still is not the database
    // the manifest describes.
    let other = TempDir::new("other");
    store(&other.join("audit.sqlite3"), &[("audit_events", 7)]);
    let replacement = {
        let snapshot = other.join("snapshot.sqlite3");
        fs::write(&snapshot, b"").expect("empty");
        store::snapshot(&other.join("audit.sqlite3"), &snapshot).expect("snapshot");
        store::normalize(&snapshot).expect("rollback journal");
        fs::read(&snapshot).expect("snapshot bytes")
    };
    let mut rebuilt = records_of(&with_manifest(&bytes, |manifest| {
        manifest["entries"][0]["bytes"] = replacement.len().into();
        manifest["entries"][0]["sha256"] = hex::encode(Sha256::digest(&replacement)).into();
        let pages = replacement.len() as u64 / 4096;
        manifest["entries"][0]["database"]["pages"] = pages.into();
        let bytes_total: u64 = manifest["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .map(|entry| entry["bytes"].as_u64().expect("bytes"))
            .sum();
        manifest["counts"]["bytes"] = bytes_total.into();
    }));
    rebuilt[1] = Raw::file("audit.sqlite3", &replacement);
    assert_eq!(
        verify_bytes(&raw_archive(&rebuilt)),
        Err(BackupError::Entry {
            store: StateFile::Audit,
            problem: EntryProblem::DescriptionMismatch
        })
    );

    // A database whose pages are damaged, recorded consistently, fails
    // SQLite's integrity check.
    let mut broken = records_of(&bytes)[1].data.clone();
    let last_page = broken.len() - 4096;
    for byte in &mut broken[last_page + 8..last_page + 64] {
        *byte = 0xFF;
    }
    let mut rebuilt = records_of(&with_manifest(&bytes, |manifest| {
        manifest["entries"][0]["sha256"] = hex::encode(Sha256::digest(&broken)).into();
    }));
    rebuilt[1] = Raw::file("audit.sqlite3", &broken);
    assert_eq!(
        verify_bytes(&raw_archive(&rebuilt)),
        Err(BackupError::Entry {
            store: StateFile::Audit,
            problem: EntryProblem::IntegrityFailed
        })
    );
}

#[test]
fn a_ledger_that_differs_from_its_manifest_or_does_not_verify_is_refused() {
    let (_out, bytes) = good_archive("ledger");
    let changed = with_manifest(&bytes, |manifest| {
        manifest["ledger"]["desired"] = "rev-00000000000000000000000000000000".into();
    });
    assert_eq!(
        verify_bytes(&changed),
        Err(BackupError::Entry {
            store: StateFile::ConfigLedger,
            problem: EntryProblem::LedgerMismatch
        })
    );

    // A ledger whose record was rewritten, recorded consistently in the
    // manifest, passes SQLite but not the ledger's own verification.
    let mut records = records_of(&bytes);
    let directory = TempDir::new("ledger-edit");
    let path = directory.join("ledger.sqlite3");
    fs::write(&path, &records[5].data).expect("ledger copy");
    let connection = Connection::open(&path).expect("open");
    connection
        .execute_batch(
            "DROP TRIGGER config_revisions_no_update; UPDATE config_revisions SET record = X'7B7D'; \
             CREATE TRIGGER config_revisions_no_update BEFORE UPDATE ON config_revisions BEGIN SELECT RAISE(ABORT, 'configuration revisions are append-only'); END;",
        )
        .expect("edit");
    drop(connection);
    let edited = fs::read(&path).expect("edited ledger");
    let database = store::describe(&path).expect("still a database");
    let mut manifest = manifest_of(&bytes);
    manifest["entries"][4]["sha256"] = hex::encode(Sha256::digest(&edited)).into();
    manifest["entries"][4]["bytes"] = edited.len().into();
    manifest["entries"][4]["database"] = serde_json::to_value(&database).expect("description");
    let total: u64 = manifest["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|entry| entry["bytes"].as_u64().expect("bytes"))
        .sum();
    manifest["counts"]["bytes"] = total.into();
    records[0] = Raw::file(
        MANIFEST_ENTRY,
        &serde_json::to_vec(&manifest).expect("JSON"),
    );
    records[5] = Raw::file("config-ledger.sqlite3", &edited);
    assert_eq!(
        verify_bytes(&raw_archive(&records)),
        Err(BackupError::Entry {
            store: StateFile::ConfigLedger,
            problem: EntryProblem::LedgerInvalid
        })
    );
}

#[test]
fn a_bomb_is_refused_before_its_data_is_read() {
    let (_out, bytes) = good_archive("bomb");
    let manifest = records_of(&bytes)[0].clone();
    // An entry declaring more than one entry may hold, and one declaring
    // more than the archive has left, are refused from their headers.
    let huge = Raw {
        size: MAX_ENTRY_BYTES + 1,
        ..Raw::file("audit.sqlite3", b"")
    };
    assert_eq!(
        refused_with(&raw_archive(&[manifest.clone(), huge])),
        ArchiveCode::EntryTooLarge
    );
    let beyond = Raw {
        size: 1 << 30,
        ..Raw::file("audit.sqlite3", b"tiny")
    };
    assert_eq!(
        refused_with(&raw_archive(&[manifest.clone(), beyond])),
        ArchiveCode::Truncated
    );
    // A manifest larger than any manifest may be.
    let oversized = Raw::file(MANIFEST_ENTRY, &vec![b' '; MAX_MANIFEST_BYTES as usize + 1]);
    assert_eq!(
        verify_bytes(&raw_archive(&[oversized])),
        Err(BackupError::ManifestInvalid)
    );
}

#[test]
fn the_container_admits_no_more_entries_than_a_backup_can_hold() {
    // The manifest and one entry per store: the next header is refused
    // before its data is read, whatever it names.
    let mut records = Vec::new();
    for index in 0..=StateFile::ALL.len() + 1 {
        records.push(Raw::file(&format!("entry-{index}"), b"x"));
    }
    let bytes = raw_archive(&records);
    let mut reader = ContainerReader::open(&bytes[..], bytes.len() as u64, archive_limits())
        .expect("the preamble reads");
    for _ in 0..=StateFile::ALL.len() {
        match reader.next().expect("admitted") {
            Some(AdmittedEntry::File(entry)) => {
                reader.copy(&entry, std::io::sink()).expect("copied");
            }
            other => panic!("{other:?}"),
        }
    }
    match reader.next() {
        Err(ContainerError::Refused(refusal)) => {
            assert_eq!(refusal.code, ArchiveCode::TooManyEntries);
            assert_eq!(refusal.entry, Some(StateFile::ALL.len() + 2));
        }
        other => panic!("{other:?}"),
    }
    // The archive length bound leaves room for the data bound and that many
    // entry headers.
    const _: () = assert!(MAX_ARCHIVE_BYTES > MAX_DATA_BYTES);
}

#[test]
fn traversal_absolute_reserved_and_stream_names_are_refused() {
    let (_out, bytes) = good_archive("names");
    let manifest = records_of(&bytes)[0].clone();
    for (name, code) in [
        ("../audit.sqlite3", ArchiveCode::EntryOutsideRoot),
        ("..", ArchiveCode::EntryOutsideRoot),
        ("/etc/passwd", ArchiveCode::AbsolutePath),
        ("\\\\server\\share", ArchiveCode::AbsolutePath),
        ("C:\\audit.sqlite3", ArchiveCode::AbsolutePath),
        ("audit.sqlite3:stream", ArchiveCode::AlternateDataStream),
        ("stores/audit.sqlite3", ArchiveCode::PathTooDeep),
        ("NUL.sqlite3", ArchiveCode::ReservedName),
        (".hidden", ArchiveCode::InvalidName),
        ("", ArchiveCode::InvalidName),
    ] {
        assert_eq!(
            refused_with(&raw_archive(&[manifest.clone(), Raw::file(name, b"x")])),
            code,
            "{name:?}"
        );
    }
    // The manifest itself is held to the same rules.
    assert_eq!(
        refused_with(&raw_archive(&[Raw::file("../gateway-backup.json", b"{}")])),
        ArchiveCode::EntryOutsideRoot
    );
}

#[test]
fn duplicate_and_case_colliding_entries_are_refused() {
    let (_out, bytes) = good_archive("duplicates");
    let records = records_of(&bytes);
    let mut duplicated = records.clone();
    duplicated.insert(2, records[1].clone());
    assert_eq!(
        refused_with(&raw_archive(&duplicated)),
        ArchiveCode::DuplicateEntry
    );
    let mut colliding = records.clone();
    let mut upper = records[1].clone();
    upper.name = b"AUDIT.sqlite3".to_vec();
    colliding.insert(2, upper);
    assert_eq!(
        refused_with(&raw_archive(&colliding)),
        ArchiveCode::CaseFoldCollision
    );
    let mut second_manifest = records.clone();
    let mut manifest = records[0].clone();
    manifest.name = b"Gateway-Backup.json".to_vec();
    second_manifest.insert(1, manifest);
    assert_eq!(
        refused_with(&raw_archive(&second_manifest)),
        ArchiveCode::CaseFoldCollision
    );
}

#[test]
fn link_special_and_unknown_entries_are_refused() {
    let (_out, bytes) = good_archive("kinds");
    let manifest = records_of(&bytes)[0].clone();
    for (kind, code) in [
        (3, ArchiveCode::SymlinkEntry),
        (4, ArchiveCode::HardLinkEntry),
        (5, ArchiveCode::SpecialEntry),
        (6, ArchiveCode::SpecialEntry),
        (7, ArchiveCode::SpecialEntry),
        (8, ArchiveCode::SpecialEntry),
        (9, ArchiveCode::UnsupportedEntry),
        (255, ArchiveCode::UnsupportedEntry),
    ] {
        let record = Raw {
            kind,
            ..Raw::file("audit.sqlite3", b"/etc/passwd")
        };
        assert_eq!(
            refused_with(&raw_archive(&[manifest.clone(), record])),
            code,
            "kind {kind}"
        );
    }
    // A directory is admitted by the guard but is no backup entry.
    let directory = Raw {
        kind: 2,
        ..Raw::file("audit.sqlite3", b"")
    };
    assert_eq!(
        verify_bytes(&raw_archive(&[manifest, directory])),
        Err(BackupError::UnexpectedEntry { position: 2 })
    );
}

#[test]
fn foreign_unsupported_and_invalid_documents_are_refused() {
    let (_out, bytes) = good_archive("versions");
    assert_eq!(
        verify_bytes(b"PK\x03\x04 a zip file"),
        Err(BackupError::NotABackup)
    );
    assert_eq!(
        verify_bytes(b""),
        Err(BackupError::Refused(ArchiveRefusal::archive(
            ArchiveCode::Truncated
        )))
    );
    let mut newer = bytes.clone();
    newer[9] = 2;
    assert_eq!(
        verify_bytes(&newer),
        Err(BackupError::UnsupportedArchiveVersion)
    );
    let mut flagged = bytes.clone();
    flagged[11] = 1;
    assert_eq!(refused_with(&flagged), ArchiveCode::Malformed);

    for (edit, expected) in [
        (
            Box::new(|manifest: &mut Value| manifest["apiVersion"] = "greengateway.dev/v1".into())
                as Box<dyn Fn(&mut Value)>,
            BackupError::UnsupportedManifestVersion,
        ),
        (
            Box::new(|manifest: &mut Value| manifest["kind"] = "GatewayBundle".into()),
            BackupError::UnsupportedManifestVersion,
        ),
        (
            Box::new(|manifest: &mut Value| manifest["extra"] = true.into()),
            BackupError::ManifestInvalid,
        ),
        (
            Box::new(|manifest: &mut Value| manifest["archive"]["version"] = 2.into()),
            BackupError::ManifestInvalid,
        ),
        (
            Box::new(|manifest: &mut Value| manifest["counts"]["rows"] = 1.into()),
            BackupError::ManifestInvalid,
        ),
        (
            Box::new(|manifest: &mut Value| manifest["stores"][0]["store"] = "audits".into()),
            BackupError::ManifestInvalid,
        ),
        (
            Box::new(|manifest: &mut Value| {
                manifest["stores"]
                    .as_array_mut()
                    .expect("stores")
                    .swap(0, 1);
            }),
            BackupError::ManifestInvalid,
        ),
        (
            Box::new(|manifest: &mut Value| {
                manifest["entries"][0]["database"]["tables"][0]["name"] = "a\"b".into();
            }),
            BackupError::ManifestInvalid,
        ),
        (
            Box::new(|manifest: &mut Value| {
                manifest["createdBy"]["program"] = "Bad Program".into()
            }),
            BackupError::ManifestInvalid,
        ),
        (
            Box::new(|manifest: &mut Value| {
                manifest.as_object_mut().expect("object").remove("ledger");
            }),
            BackupError::ManifestInvalid,
        ),
    ] {
        assert_eq!(verify_bytes(&with_manifest(&bytes, edit)), Err(expected));
    }
    // A duplicate member, which a lenient reader would resolve silently.
    let mut records = records_of(&bytes);
    let text = String::from_utf8(records[0].data.clone()).expect("UTF-8");
    let duplicated = text.replacen("{\"apiVersion\"", "{\"source\":\"x\",\"apiVersion\"", 1);
    assert_ne!(duplicated, text);
    let duplicated = duplicated.replacen(
        "\"source\":\"standalone_state_directory\"",
        "\"source\":\"standalone_state_directory\",\"source\":\"standalone_state_directory\"",
        1,
    );
    records[0] = Raw::file(MANIFEST_ENTRY, duplicated.as_bytes());
    assert_eq!(
        verify_bytes(&raw_archive(&records)),
        Err(BackupError::ManifestInvalid)
    );
}

#[test]
fn the_entries_must_be_exactly_the_manifests_in_order() {
    let (_out, bytes) = good_archive("order");
    let records = records_of(&bytes);
    let mut missing = records.clone();
    missing.pop();
    assert_eq!(
        verify_bytes(&raw_archive(&missing)),
        Err(BackupError::EntryMissing)
    );
    let mut extra = records.clone();
    extra.push(Raw::file("discovery.sqlite3", &records[1].data));
    assert_eq!(
        verify_bytes(&raw_archive(&extra)),
        Err(BackupError::UnexpectedEntry { position: 7 })
    );
    let mut reordered = records.clone();
    reordered.swap(1, 2);
    assert_eq!(
        verify_bytes(&raw_archive(&reordered)),
        Err(BackupError::UnexpectedEntry { position: 2 })
    );
    let mut manifest_last = records.clone();
    let manifest = manifest_last.remove(0);
    manifest_last.push(manifest);
    assert_eq!(
        verify_bytes(&raw_archive(&manifest_last)),
        Err(BackupError::ManifestMissing)
    );
    assert_eq!(
        verify_bytes(&raw_archive(&[])),
        Err(BackupError::ManifestMissing)
    );
}

#[test]
fn an_archive_that_is_not_a_regular_file_is_refused() {
    let directory = TempDir::new("archive-kinds");
    assert_eq!(
        verify(&directory.join("missing.ggbk")),
        Err(BackupError::ArchiveUnreadable)
    );
    fs::create_dir(directory.join("directory.ggbk")).expect("directory");
    assert_eq!(
        verify(&directory.join("directory.ggbk")),
        Err(BackupError::ArchiveNotRegularFile)
    );
    #[cfg(unix)]
    {
        let (_out, bytes) = good_archive("archive-link");
        fs::write(directory.join("real.ggbk"), &bytes).expect("archive");
        std::os::unix::fs::symlink(directory.join("real.ggbk"), directory.join("linked.ggbk"))
            .expect("symlink");
        assert_eq!(
            verify(&directory.join("linked.ggbk")),
            Err(BackupError::ArchiveNotRegularFile)
        );
    }
}

#[test]
fn errors_are_value_free_and_name_only_codes_stores_and_positions() {
    for (error, text) in [
        (
            BackupError::Store {
                store: StateFile::ServiceTokens,
                problem: StoreProblem::Corrupt,
            },
            "store service_tokens: error[backup.store_corrupt]",
        ),
        (
            BackupError::UnexpectedEntry { position: 3 },
            "entry 3: error[backup.unexpected_entry]",
        ),
        (BackupError::OutputExists, "error[backup.output_exists]"),
        (
            BackupError::Refused(ArchiveRefusal::entry(ArchiveCode::SymlinkEntry, 2)),
            "entry 2: error[archive.symlink_entry]: an entry is a symbolic link, junction or reparse point",
        ),
    ] {
        assert_eq!(error.to_string(), text);
    }
    let (state, _) = populated("value-free");
    let out = TempDir::new("out");
    fs::write(out.join("state.ggbk"), b"").expect("existing");
    let refused = create(state.held(), &request(&out.join("state.ggbk"))).expect_err("exists");
    assert!(!refused.to_string().contains(CANARY));
    assert!(!format!("{refused:?}").contains(CANARY));
}

mod restore;
