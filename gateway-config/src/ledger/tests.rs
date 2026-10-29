use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, UNIX_EPOCH},
};

use rusqlite::{params, Connection};
use serde_json::Value;

use super::{
    record::{RECORD_MEDIA_TYPE, RECORD_SCHEMA_VERSION},
    store, *,
};
use crate::bundle::{
    read_bundle, sha256_pin, PublishedSchemasOnly, ReadOptions, MANIFEST_MEDIA_TYPE,
};
use crate::canonical_json;

/// A role name that must never reach an error or a record's metadata.
const CANARY: &str = "zqcanary";

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
            "greengateway-ledger-{label}-{}",
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

    fn ledger(&self) -> PathBuf {
        self.0.join(LEDGER_FILE_NAME)
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("permissions should set");
}

const DEPLOYMENT_YAML: &str = concat!(
    "apiVersion: greengateway.dev/v1alpha1\n",
    "kind: GatewayDeployment\n",
    "spec:\n",
    "  profile: production\n",
);
const TOOLS_JSON: &str = "{\n  \"schema_version\": \"0.1.0\",\n  \"tools\": []\n}\n";

/// A deny-by-default policy with one role named `role`, so each name gives a
/// different bundle.
fn policy_json(role: &str) -> String {
    format!(
        "{{\n  \"schema_version\": \"0.1.0\",\n  \"default_action\": \"deny\",\n  \"roles\": {{\"{role}\": {{\"permissions\": [\"admin:policy:read\"]}}}}\n}}\n"
    )
}

fn manifest(deployment: &str, policy: &str, tools: &str) -> String {
    format!(
        concat!(
            "apiVersion: greengateway.dev/v1alpha1\n",
            "kind: GatewayBundle\n",
            "metadata:\n",
            "  name: payments-production\n",
            "spec:\n",
            "  deployment:\n",
            "    path: deployment.yaml\n",
            "    sha256: \"{deployment}\"\n",
            "  resources:\n",
            "    policy:\n",
            "      source: bundle\n",
            "      path: policy.json\n",
            "      schema_version: \"0.1.0\"\n",
            "      sha256: \"{policy}\"\n",
            "    tools:\n",
            "      source: bundle\n",
            "      path: tools.json\n",
            "      schema_version: \"0.1.0\"\n",
            "      sha256: \"{tools}\"\n",
            "    connections:\n",
            "      source: server\n",
        ),
        deployment = deployment,
        policy = policy,
        tools = tools,
    )
}

/// A complete bundle whose policy grants one role named `role`, read the way
/// `ggctl` reads one. The directory is gone once the bundle is read: the
/// ledger keeps the bytes the reader accepted, not a path.
fn bundle(role: &str) -> Bundle<Value, Value> {
    let directory = TempDir::new("bundle");
    let policy = policy_json(role);
    let write = |name: &str, contents: &[u8]| {
        let path = directory.path().join(name);
        fs::write(&path, contents).expect("bundle file should write");
        #[cfg(unix)]
        set_mode(&path, 0o644);
    };
    write("deployment.yaml", DEPLOYMENT_YAML.as_bytes());
    write("policy.json", policy.as_bytes());
    write("tools.json", TOOLS_JSON.as_bytes());
    write(
        "bundle.yaml",
        manifest(
            &sha256_pin(DEPLOYMENT_YAML.as_bytes()),
            &sha256_pin(policy.as_bytes()),
            &sha256_pin(TOOLS_JSON.as_bytes()),
        )
        .as_bytes(),
    );
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

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000 + seconds)
}

fn operator() -> LedgerActor {
    LedgerActor::system("ggctl-ledger-seed").expect("the label is recordable")
}

fn admin() -> LedgerActor {
    LedgerActor::principal("alice", Some("provider:corp"), AuthMode::SessionCookie)
        .expect("the principal is recordable")
}

fn proposal(
    bundle: &Bundle<Value, Value>,
    activation: ActivationClass,
) -> Proposal<'_, Value, Value> {
    Proposal {
        bundle,
        actor: admin(),
        operation: Operation::Apply,
        activation,
        codes: RevisionCodes::none(),
        recorded_at: at(60),
    }
}

fn rollback_proposal<'a>(
    target: &RevisionId,
    bundle: &'a Bundle<Value, Value>,
) -> Proposal<'a, Value, Value> {
    Proposal {
        operation: Operation::Rollback {
            target: target.clone(),
        },
        ..proposal(bundle, ActivationClass::Restart)
    }
}

fn seeded(label: &str, role: &str) -> (TempDir, RevisionLedger, RevisionSummary) {
    let state = TempDir::new(label);
    let (ledger, seed) =
        RevisionLedger::seed(state.path(), &bundle(role), operator(), at(0)).expect("seed");
    (state, ledger, seed)
}

/// A connection outside the ledger, as an edit outside the gateway would
/// use: no defensive mode, no foreign keys, and the append-only triggers in
/// the way only until it drops them.
fn outside(state: &TempDir) -> Connection {
    let connection = Connection::open(state.ledger()).expect("an outside connection should open");
    connection
        .execute_batch("PRAGMA foreign_keys = OFF;")
        .expect("foreign keys should turn off");
    connection
}

/// Runs `sql` with `trigger` dropped, then puts the trigger back exactly as
/// it was, so only the content differs from what the ledger wrote.
fn past_trigger(connection: &Connection, trigger: &str, sql: &str) {
    connection
        .execute_batch(&format!("DROP TRIGGER {trigger};"))
        .expect("the trigger should drop");
    connection
        .execute_batch(sql)
        .expect("the edit should apply");
    connection
        .execute_batch(store::schema_sql(trigger).expect("a ledger trigger"))
        .expect("the trigger should restore");
}

fn record_bytes(connection: &Connection, sequence: i64) -> Vec<u8> {
    connection
        .query_row(
            "SELECT record FROM config_revisions WHERE sequence = ?1",
            params![sequence],
            |row| row.get(0),
        )
        .expect("the record should read")
}

/// Replaces revision `sequence` with `value`, hashed and identified the way
/// the ledger would: a consistent forgery of that one row.
fn forge_record(connection: &Connection, sequence: i64, value: &Value) {
    let bytes = canonical_json::canonical_json_bytes(value).expect("canonical record");
    let hash = canonical_json::semantic_digest(RECORD_MEDIA_TYPE, RECORD_SCHEMA_VERSION, value)
        .expect("record hash");
    let id = RevisionId::of_record_hash(&hash).expect("revision id");
    connection
        .execute_batch("DROP TRIGGER config_revisions_no_update;")
        .expect("the trigger should drop");
    connection
        .execute(
            "UPDATE config_revisions SET record = ?1, record_hash = ?2, revision_id = ?3 WHERE sequence = ?4",
            params![bytes, hash, id.as_str(), sequence],
        )
        .expect("the forgery should apply");
    connection
        .execute_batch(store::schema_sql("config_revisions_no_update").expect("trigger"))
        .expect("the trigger should restore");
}

fn corruption(result: Result<RevisionLedger, LedgerError>) -> Corruption {
    match result {
        Err(LedgerError::Corrupt(kind)) => kind,
        Err(other) => panic!("expected corruption, found {other:?}"),
        Ok(_) => panic!("expected corruption, the ledger opened"),
    }
}

// --- seeding and opening -----------------------------------------------------------

#[test]
fn a_seeded_ledger_holds_its_bundle_as_the_desired_revision() {
    let bundle = bundle("first");
    let state = TempDir::new("seed");
    let (mut ledger, seed) =
        RevisionLedger::seed(state.path(), &bundle, operator(), at(0)).expect("seed");

    assert_eq!(seed.sequence, 1);
    assert_eq!(seed.parent, None);
    assert_eq!(seed.operation, Operation::Seed);
    assert_eq!(seed.activation, ActivationClass::Restart);
    assert_eq!(seed.actor, operator());
    assert_eq!(seed.codes, RevisionCodes::none());
    assert_eq!(seed.recorded_at_ms, 1_800_000_000_000);
    assert_eq!(
        RevisionId::of_record_hash(&seed.record_hash),
        Some(seed.revision.clone())
    );
    let recorded = &seed.bundle;
    assert_eq!(recorded.api_version, ApiVersion::V1Alpha1);
    assert_eq!(recorded.name, "payments-production");
    assert_eq!(recorded.profile, Profile::Production);
    assert_eq!(recorded.source_digest, bundle.source_digest);
    assert_eq!(recorded.policy, ResourceOrigin::Bundle);
    assert_eq!(recorded.tools, ResourceOrigin::Bundle);
    let files: Vec<_> = recorded
        .files
        .iter()
        .map(|file| (file.role, file.name.as_str(), file.schema_version))
        .collect();
    assert_eq!(
        files,
        [
            (FileRole::Manifest, "bundle.yaml", None),
            (FileRole::Deployment, "deployment.yaml", None),
            (FileRole::Policy, "policy.json", Some("0.1.0")),
            (FileRole::Tools, "tools.json", Some("0.1.0")),
        ]
    );

    // Desired, not yet active: the next start activates it.
    let state_now = ledger.state().expect("state");
    assert_eq!(state_now.revisions, 1);
    assert_eq!(state_now.desired, seed);
    assert_eq!(state_now.active, None);
    assert!(state_now.restart_pending());

    // The files come back exactly as the reader accepted them.
    let stored = ledger
        .revision(&seed.revision)
        .expect("revision read")
        .expect("the seed is stored");
    assert_eq!(stored.summary, seed);
    assert_eq!(stored.files, bundle.source_files());

    // And all of it survives a reopen.
    drop(ledger);
    let mut reopened = RevisionLedger::open(state.path()).expect("reopen");
    assert_eq!(reopened.verify().expect("verify").desired, seed);
    assert_eq!(
        reopened.revision(&seed.revision).expect("read"),
        Some(stored)
    );
}

#[test]
fn the_record_format_is_pinned() {
    let bundle = bundle("first");
    let state = TempDir::new("format");
    let (ledger, seed) =
        RevisionLedger::seed(state.path(), &bundle, operator(), at(0)).expect("seed");
    drop(ledger);
    let pin = |role: FileRole| {
        bundle
            .source_files()
            .iter()
            .find(|file| file.role == role)
            .map(|file| sha256_pin(&file.bytes))
            .expect("the bundle has the file")
    };
    let expected = format!(
        concat!(
            "{{\"activation\":\"restart\",",
            "\"actor\":{{\"auth_mode\":\"system\",\"issuer\":null,\"kind\":\"system\",\"subject\":\"ggctl-ledger-seed\"}},",
            "\"bundle\":{{\"api_version\":\"greengateway.dev/v1alpha1\",\"files\":[",
            "{{\"name\":\"bundle.yaml\",\"role\":\"manifest\",\"schema_version\":null,\"sha256\":\"{manifest}\"}},",
            "{{\"name\":\"deployment.yaml\",\"role\":\"deployment\",\"schema_version\":null,\"sha256\":\"{deployment}\"}},",
            "{{\"name\":\"policy.json\",\"role\":\"policy\",\"schema_version\":\"0.1.0\",\"sha256\":\"{policy}\"}},",
            "{{\"name\":\"tools.json\",\"role\":\"tools\",\"schema_version\":\"0.1.0\",\"sha256\":\"{tools}\"}}],",
            "\"name\":\"payments-production\",\"policy\":\"bundle\",\"profile\":\"production\",",
            "\"source_digest\":\"{source_digest}\",\"tools\":\"bundle\"}},",
            "\"changed_sections\":[],\"operation\":\"seed\",\"parent\":null,",
            "\"recorded_at_ms\":1800000000000,\"required_permissions\":[],\"risk_codes\":[],",
            "\"rollback_of\":null,\"sequence\":1}}"
        ),
        manifest = pin(FileRole::Manifest),
        deployment = pin(FileRole::Deployment),
        policy = pin(FileRole::Policy),
        tools = pin(FileRole::Tools),
        source_digest = bundle.source_digest,
    );
    let bytes = record_bytes(&outside(&state), 1);
    assert_eq!(String::from_utf8(bytes.clone()).expect("UTF-8"), expected);

    // The record hash is the GGDIGEST frame of exactly those bytes, and the
    // revision ID is its first 128 bits.
    let value: Value = serde_json::from_slice(&bytes).expect("JSON");
    assert_eq!(
        seed.record_hash,
        canonical_json::semantic_digest(
            "application/vnd.greengateway.config-revision+json",
            "v1",
            &value
        )
        .expect("digest")
    );
    assert_eq!(
        seed.revision.as_str(),
        format!("rev-{}", &seed.record_hash["sha256:".len()..][..32])
    );
    // No document value is in the record: only names, pins and codes.
    assert!(!expected.contains("first"));
}

#[test]
fn seeding_refuses_an_existing_ledger_or_journal_files() {
    let bundle = bundle("first");
    let (state, ledger, _) = seeded("seed-twice", "first");
    assert_eq!(
        RevisionLedger::seed(state.path(), &bundle, operator(), at(1)).map(|_| ()),
        Err(LedgerError::Exists)
    );
    drop(ledger);

    // A previous ledger's journal could be replayed into a new database of
    // the same name.
    for suffix in ["-wal", "-shm", "-journal"] {
        let state = TempDir::new("leftover-journal");
        let leftover = PathBuf::from(format!("{}{suffix}", state.ledger().display()));
        fs::write(&leftover, b"journal").expect("leftover should write");
        assert_eq!(
            RevisionLedger::seed(state.path(), &bundle, operator(), at(1)).map(|_| ()),
            Err(LedgerError::Exists),
            "{suffix}"
        );
        assert!(!state.ledger().exists(), "{suffix}");
    }
}

#[test]
fn an_interrupted_seed_leaves_no_ledger_and_is_discarded_by_the_next() {
    let state = TempDir::new("interrupted");
    // What a crash before publication leaves: a temporary database and its
    // hot journal, never the ledger's own name.
    let temporary = PathBuf::from(format!("{}.seed", state.ledger().display()));
    fs::write(&temporary, b"half-written").expect("temporary should write");
    fs::write(format!("{}-journal", temporary.display()), b"journal").expect("journal");
    assert_eq!(
        RevisionLedger::open(state.path()).map(|_| ()),
        Err(LedgerError::Missing)
    );

    let (_ledger, seed) =
        RevisionLedger::seed(state.path(), &bundle("first"), operator(), at(0)).expect("seed");
    assert_eq!(seed.sequence, 1);
    assert!(!temporary.exists());
    let mut names: Vec<_> = fs::read_dir(state.path())
        .expect("state directory")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .into_string()
                .expect("name")
        })
        .filter(|name| !name.ends_with("-wal") && !name.ends_with("-shm"))
        .collect();
    names.sort();
    assert_eq!(names, [LEDGER_FILE_NAME]);
}

#[test]
fn opening_refuses_a_missing_ledger_and_unsafe_locations() {
    let state = TempDir::new("locations");
    assert_eq!(
        RevisionLedger::open(state.path()).map(|_| ()),
        Err(LedgerError::Missing)
    );
    assert_eq!(
        RevisionLedger::open(&state.path().join("absent")).map(|_| ()),
        Err(LedgerError::UnsafeLocation)
    );
    let not_a_directory = state.path().join("file");
    fs::write(&not_a_directory, b"").expect("file should write");
    assert_eq!(
        RevisionLedger::open(&not_a_directory).map(|_| ()),
        Err(LedgerError::UnsafeLocation)
    );
    assert_eq!(
        RevisionLedger::seed(&not_a_directory, &bundle("first"), operator(), at(0)).map(|_| ()),
        Err(LedgerError::UnsafeLocation)
    );
    fs::create_dir(state.ledger()).expect("directory should create");
    let error = RevisionLedger::open(state.path()).map(|_| ());
    assert_eq!(error, Err(LedgerError::UnsafeLocation));
    // No error names a path.
    let shown = error.expect_err("refused").to_string();
    assert!(!shown.contains(LEDGER_FILE_NAME), "{shown}");
}

#[cfg(unix)]
#[test]
fn opening_refuses_linked_or_shared_writable_ledgers() {
    let (state, ledger, _) = seeded("unix-locations", "first");
    drop(ledger);
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(state.ledger())
            .expect("metadata")
            .permissions()
            .mode()
    };
    assert_eq!(mode & 0o077, 0, "a seeded ledger is owner-only");

    set_mode(&state.ledger(), 0o660);
    assert_eq!(
        RevisionLedger::open(state.path()).map(|_| ()),
        Err(LedgerError::UnsafeLocation)
    );
    set_mode(&state.ledger(), 0o600);

    set_mode(state.path(), 0o770);
    assert_eq!(
        RevisionLedger::open(state.path()).map(|_| ()),
        Err(LedgerError::UnsafeLocation)
    );
    set_mode(state.path(), 0o700);
    RevisionLedger::open(state.path()).expect("the restored ledger opens");

    let linked = TempDir::new("unix-link");
    std::os::unix::fs::symlink(state.ledger(), linked.ledger()).expect("symlink");
    assert_eq!(
        RevisionLedger::open(linked.path()).map(|_| ()),
        Err(LedgerError::UnsafeLocation)
    );
}

// --- appending -----------------------------------------------------------------

#[test]
fn revisions_chain_to_their_parents_and_a_stale_head_writes_nothing() {
    let (state, mut ledger, seed) = seeded("chain", "first");
    let second = bundle("second");
    let applied = ledger
        .append(&seed.revision, proposal(&second, ActivationClass::Restart))
        .expect("append");
    assert_eq!(applied.sequence, 2);
    assert_eq!(applied.operation, Operation::Apply);
    assert_eq!(applied.actor, admin());
    assert_eq!(
        applied.parent,
        Some(ParentLink {
            revision: seed.revision.clone(),
            record_hash: seed.record_hash.clone(),
        })
    );
    assert_eq!(applied.bundle.source_digest, second.source_digest);
    assert_ne!(applied.revision, seed.revision);

    // A writer that still believes the seed is the head loses, and writes
    // nothing.
    let third = bundle("third");
    assert_eq!(
        ledger.append(&seed.revision, proposal(&third, ActivationClass::Restart)),
        Err(LedgerError::Stale {
            head: applied.revision.clone()
        })
    );
    assert_eq!(ledger.state().expect("state").revisions, 2);

    // Unchanged documents are stored once.
    let documents: i64 = outside(&state)
        .query_row("SELECT COUNT(*) FROM config_ledger_documents", [], |row| {
            row.get(0)
        })
        .expect("count");
    // The seed's four, and the second bundle's manifest and policy.
    assert_eq!(documents, 6);
}

#[test]
fn two_handles_appending_on_one_head_have_exactly_one_winner() {
    let (state, mut first, seed) = seeded("two-handles", "first");
    let mut second = RevisionLedger::open(state.path()).expect("a second handle");
    let one = bundle("one");
    let other = bundle("other");
    let winner = first
        .append(&seed.revision, proposal(&one, ActivationClass::Restart))
        .expect("the first append wins");
    assert_eq!(
        second.append(&seed.revision, proposal(&other, ActivationClass::Restart)),
        Err(LedgerError::Stale {
            head: winner.revision.clone()
        })
    );
    // The loser can retry on the head it was told about.
    let retried = second
        .append(&winner.revision, proposal(&other, ActivationClass::Restart))
        .expect("the retry appends");
    assert_eq!(retried.sequence, 3);
    assert_eq!(first.verify().expect("verify").desired, retried);
}

#[test]
fn a_live_revision_activates_only_when_no_restart_is_pending() {
    let (_state, mut ledger, seed) = seeded("activation", "first");

    // The seed is not active yet, so even a live revision is only staged.
    let second = ledger
        .append(
            &seed.revision,
            proposal(&bundle("second"), ActivationClass::Live),
        )
        .expect("append");
    let state = ledger.state().expect("state");
    assert_eq!(state.active, None);
    assert!(state.restart_pending());

    // A start compiles and activates the desired revision, and only that one.
    assert_eq!(
        ledger.activate(&seed.revision).map(|_| ()),
        Err(LedgerError::Stale {
            head: second.revision.clone()
        })
    );
    let state = ledger.activate(&second.revision).expect("activate");
    assert_eq!(state.active, Some(second.revision.clone()));
    assert!(!state.restart_pending());
    assert_eq!(
        ledger.activate(&second.revision).expect("idempotent"),
        state
    );

    // Now a live revision activates with its commit.
    let third = ledger
        .append(
            &second.revision,
            proposal(&bundle("third"), ActivationClass::Live),
        )
        .expect("append");
    assert_eq!(
        ledger.state().expect("state").active,
        Some(third.revision.clone())
    );

    // A restart-class revision moves only the desired pointer, and while it
    // is pending a live revision is staged too.
    let fourth = ledger
        .append(
            &third.revision,
            proposal(&bundle("fourth"), ActivationClass::Restart),
        )
        .expect("append");
    let fifth = ledger
        .append(
            &fourth.revision,
            proposal(&bundle("fifth"), ActivationClass::Live),
        )
        .expect("append");
    let state = ledger.state().expect("state");
    assert_eq!(state.desired, fifth);
    assert_eq!(state.active, Some(third.revision.clone()));
    assert!(state.restart_pending());
    assert_eq!(
        ledger.verify().expect("verify").active,
        Some(third.revision)
    );
}

#[test]
fn a_rollback_is_a_new_revision_bound_to_its_targets_content() {
    let first = bundle("first");
    let state = TempDir::new("rollback");
    let (mut ledger, seed) =
        RevisionLedger::seed(state.path(), &first, operator(), at(0)).expect("seed");
    let second = bundle("second");
    let applied = ledger
        .append(&seed.revision, proposal(&second, ActivationClass::Restart))
        .expect("append");
    assert_eq!(
        ledger.append(
            &applied.revision,
            rollback_proposal(&seed.revision, &second)
        ),
        Err(LedgerError::Refused(Refusal::RollbackContentDiffers))
    );
    assert_eq!(
        ledger.append(
            &applied.revision,
            rollback_proposal(&applied.revision, &second)
        ),
        Err(LedgerError::Refused(Refusal::RollbackTargetIsHead))
    );
    let unknown = RevisionId::parse("rev-00000000000000000000000000000000").expect("ID");
    assert_eq!(
        ledger.append(&applied.revision, rollback_proposal(&unknown, &first)),
        Err(LedgerError::Refused(Refusal::RollbackTargetUnknown))
    );
    assert_eq!(ledger.state().expect("state").revisions, 2);

    let rolled_back = ledger
        .append(&applied.revision, rollback_proposal(&seed.revision, &first))
        .expect("rollback");
    assert_eq!(rolled_back.sequence, 3);
    assert_eq!(
        rolled_back.operation,
        Operation::Rollback {
            target: seed.revision.clone()
        }
    );
    assert_eq!(
        rolled_back.parent.as_ref().map(|parent| &parent.revision),
        Some(&applied.revision)
    );
    assert_eq!(rolled_back.bundle, seed.bundle);
    // History is never rewritten: every revision is still there, newest
    // first.
    let page: Vec<_> = ledger
        .revisions(None, MAX_REVISION_PAGE)
        .expect("page")
        .into_iter()
        .map(|summary| summary.revision)
        .collect();
    assert_eq!(
        page,
        [rolled_back.revision, applied.revision, seed.revision]
    );
    drop(ledger);
    RevisionLedger::open(state.path()).expect("the rolled-back ledger verifies");
}

#[test]
fn append_refuses_what_a_ledger_does_not_record() {
    let (_state, ledger, seed) = seeded("refusals", "first");
    let second = bundle("second");
    let mut ledger = ledger.with_revision_limit(2);
    assert_eq!(
        ledger.append(
            &seed.revision,
            Proposal {
                operation: Operation::Seed,
                ..proposal(&second, ActivationClass::Restart)
            }
        ),
        Err(LedgerError::Refused(Refusal::SeedNotAppendable))
    );
    assert_eq!(
        ledger.append(
            &seed.revision,
            Proposal {
                recorded_at: UNIX_EPOCH - Duration::from_secs(1),
                ..proposal(&second, ActivationClass::Restart)
            }
        ),
        Err(LedgerError::Refused(Refusal::TimeNotRecordable))
    );
    let applied = ledger
        .append(&seed.revision, proposal(&second, ActivationClass::Restart))
        .expect("the second revision fits");
    // At the retention bound the ledger refuses rather than drop history.
    assert_eq!(
        ledger.append(
            &applied.revision,
            proposal(&bundle("third"), ActivationClass::Restart)
        ),
        Err(LedgerError::Full)
    );
    assert_eq!(ledger.state().expect("state").revisions, 2);
}

#[test]
fn revisions_page_newest_first_within_the_bound() {
    let (_state, mut ledger, seed) = seeded("pages", "first");
    let mut head = seed.revision;
    for role in ["second", "third", "fourth", "fifth"] {
        head = ledger
            .append(&head, proposal(&bundle(role), ActivationClass::Restart))
            .expect("append")
            .revision;
    }
    let sequences = |page: Vec<RevisionSummary>| -> Vec<u64> {
        page.into_iter().map(|summary| summary.sequence).collect()
    };
    assert_eq!(sequences(ledger.revisions(None, 2).expect("page")), [5, 4]);
    assert_eq!(
        sequences(ledger.revisions(Some(4), 2).expect("page")),
        [3, 2]
    );
    assert_eq!(sequences(ledger.revisions(Some(2), 2).expect("page")), [1]);
    assert_eq!(
        sequences(ledger.revisions(None, usize::MAX).expect("page")),
        [5, 4, 3, 2, 1]
    );
    assert!(ledger.revisions(None, 0).expect("page").is_empty());
    let missing = RevisionId::parse("rev-ffffffffffffffffffffffffffffffff").expect("ID");
    assert_eq!(ledger.revision(&missing), Ok(None));
}

// --- actors, codes and identifiers --------------------------------------------------

#[test]
fn actors_are_recorded_exactly_within_the_evidence_vocabulary() {
    let (_state, mut ledger, seed) = seeded("actors", "first");
    let actors = [
        LedgerActor::principal("alice", Some("provider:corp"), AuthMode::BearerToken)
            .expect("principal"),
        LedgerActor::principal("bob", None, AuthMode::ClientCertificate).expect("principal"),
        LedgerActor::service_token("service-token:0123").expect("service token"),
        LedgerActor::system("ggctl-ledger-rollback").expect("system"),
    ];
    let mut head = seed.revision;
    for (index, actor) in actors.iter().enumerate() {
        let recorded = ledger
            .append(
                &head,
                Proposal {
                    actor: actor.clone(),
                    ..proposal(&bundle(&format!("role{index}")), ActivationClass::Restart)
                },
            )
            .expect("append");
        assert_eq!(&recorded.actor, actor);
        head = recorded.revision;
    }
    let page = ledger.revisions(None, 4).expect("page");
    let recorded: Vec<_> = page
        .iter()
        .rev()
        .map(|summary| summary.actor.clone())
        .collect();
    assert_eq!(recorded, actors);
    assert_eq!(page[0].actor.kind(), ActorKind::System);
    assert_eq!(page[0].actor.auth_mode(), AuthMode::System);

    let refused = Err(LedgerError::Refused(Refusal::ActorNotRecordable));
    let longest = "s".repeat(MAX_ACTOR_SUBJECT_BYTES);
    assert!(LedgerActor::principal(&longest, None, AuthMode::BearerToken).is_ok());
    let too_long = "s".repeat(MAX_ACTOR_SUBJECT_BYTES + 1);
    assert_eq!(
        LedgerActor::principal(&too_long, None, AuthMode::BearerToken),
        refused
    );
    assert_eq!(
        LedgerActor::principal("", None, AuthMode::BearerToken),
        refused
    );
    assert_eq!(
        LedgerActor::principal("alice", Some(""), AuthMode::BearerToken),
        refused
    );
    let long_issuer = "i".repeat(MAX_ACTOR_ISSUER_BYTES + 1);
    assert_eq!(
        LedgerActor::principal("alice", Some(&long_issuer), AuthMode::BearerToken),
        refused
    );
    for mode in [AuthMode::ServiceToken, AuthMode::System] {
        assert_eq!(LedgerActor::principal("alice", None, mode), refused);
    }
    assert_eq!(LedgerActor::service_token(""), refused);
    let long_label = "l".repeat(MAX_SYSTEM_LABEL_BYTES + 1);
    for label in ["", "with space", "-leading", "a/b", long_label.as_str()] {
        assert_eq!(LedgerActor::system(label), refused, "{label}");
    }
}

#[test]
fn codes_are_sorted_unique_and_held_to_their_grammar() {
    let codes = RevisionCodes::new(
        &["tools", "policy", "policy"],
        &["risk.policy_broadened", "risk.egress_broadened"],
        &["admin:policy:write", "admin:config:write"],
    )
    .expect("codes");
    assert_eq!(codes.changed_sections(), ["policy", "tools"]);
    assert_eq!(
        codes.risk_codes(),
        ["risk.egress_broadened", "risk.policy_broadened"]
    );
    assert_eq!(
        codes.required_permissions(),
        ["admin:config:write", "admin:policy:write"]
    );

    let (_state, mut ledger, seed) = seeded("codes", "first");
    let recorded = ledger
        .append(
            &seed.revision,
            Proposal {
                codes: codes.clone(),
                ..proposal(&bundle("second"), ActivationClass::Live)
            },
        )
        .expect("append");
    assert_eq!(recorded.codes, codes);
    assert_eq!(ledger.verify().expect("verify").desired.codes, codes);

    let refused = Err(LedgerError::Refused(Refusal::CodeNotRecordable));
    let none: [&str; 0] = [];
    for code in [
        "",
        "Policy",
        "1policy",
        "a b",
        "a/b",
        CANARY.to_uppercase().as_str(),
    ] {
        assert_eq!(RevisionCodes::new(&[code], &none, &none), refused, "{code}");
    }
    let longest = "c".repeat(MAX_CODE_BYTES);
    assert!(RevisionCodes::new(&[longest.as_str()], &none, &none).is_ok());
    let too_long = "c".repeat(MAX_CODE_BYTES + 1);
    assert_eq!(
        RevisionCodes::new(&none, &[too_long.as_str()], &none),
        refused
    );
    let many: Vec<String> = (0..=MAX_RECORDED_CODES)
        .map(|index| format!("c{index}"))
        .collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    assert_eq!(RevisionCodes::new(&none, &none, &many), refused);
    assert!(RevisionCodes::new(&none, &none, &many[1..]).is_ok());
}

#[test]
fn revision_ids_are_opaque_and_exact() {
    let id = RevisionId::parse("rev-0123456789abcdef0123456789abcdef").expect("a valid ID");
    assert_eq!(id.as_str(), "rev-0123456789abcdef0123456789abcdef");
    assert_eq!(id.to_string(), id.as_str());
    for invalid in [
        "",
        "rev-",
        "rev-0123456789abcdef0123456789abcde",
        "rev-0123456789abcdef0123456789abcdef0",
        "rev-0123456789ABCDEF0123456789abcdef",
        "REV-0123456789abcdef0123456789abcdef",
        "sha256:0123456789abcdef0123456789abcdef",
        " rev-0123456789abcdef0123456789abcdef",
    ] {
        assert!(RevisionId::parse(invalid).is_none(), "{invalid}");
    }
}

#[test]
fn errors_are_value_free_and_stable() {
    let head = RevisionId::parse("rev-0123456789abcdef0123456789abcdef").expect("ID");
    let cases = [
        (LedgerError::UnsafeLocation, "ledger.unsafe_location"),
        (LedgerError::Missing, "ledger.missing"),
        (LedgerError::Exists, "ledger.exists"),
        (LedgerError::Unsupported, "ledger.unsupported"),
        (LedgerError::Corrupt(Corruption::Chain), "ledger.corrupt"),
        (LedgerError::Stale { head: head.clone() }, "ledger.stale"),
        (
            LedgerError::Refused(Refusal::RollbackContentDiffers),
            "ledger.refused",
        ),
        (LedgerError::Full, "ledger.full"),
        (
            LedgerError::Unavailable {
                operation: "append commit",
            },
            "ledger.unavailable",
        ),
    ];
    for (error, code) in cases {
        assert_eq!(error.code(), code);
        let shown = error.to_string();
        assert!(!shown.contains(CANARY) && !shown.contains('/'), "{shown}");
    }
    assert!(LedgerError::Stale { head: head.clone() }
        .to_string()
        .ends_with(head.as_str()));
    assert_eq!(
        LedgerError::Corrupt(Corruption::RecordHash).to_string(),
        "the configuration ledger failed verification (record_hash)"
    );
}

// --- append-only and tamper detection -------------------------------------------

/// Three revisions: the seed's bundle, a second bundle, and the seed's
/// bundle again, so the newest revision shares every document with the
/// first.
fn three_revisions(label: &str) -> (TempDir, [RevisionSummary; 3]) {
    let first = bundle(CANARY);
    let state = TempDir::new(label);
    let (mut ledger, seed) =
        RevisionLedger::seed(state.path(), &first, operator(), at(0)).expect("seed");
    let second = ledger
        .append(
            &seed.revision,
            proposal(&bundle("second"), ActivationClass::Restart),
        )
        .expect("append");
    let third = ledger
        .append(&second.revision, proposal(&first, ActivationClass::Restart))
        .expect("append");
    (state, [seed, second, third])
}

#[test]
fn the_schema_refuses_updates_deletes_and_backward_pointer_moves() {
    let (state, [seed, ..]) = three_revisions("append-only");
    let connection = outside(&state);
    for sql in [
        "UPDATE config_revisions SET record = x'00' WHERE sequence = 1",
        "DELETE FROM config_revisions WHERE sequence = 3",
        "UPDATE config_ledger_documents SET content = x'00'",
        "DELETE FROM config_ledger_documents",
        "DELETE FROM config_ledger_pointer",
        "UPDATE config_ledger_pointer SET desired_sequence = 1",
        "INSERT INTO config_revisions (sequence, revision_id, record_hash, record) VALUES (9, 'a', 'b', x'00')",
    ] {
        assert!(connection.execute_batch(sql).is_err(), "{sql}");
    }
    connection
        .execute_batch("UPDATE config_ledger_pointer SET active_sequence = 2")
        .expect("the active pointer moves forward");
    assert!(connection
        .execute_batch("UPDATE config_ledger_pointer SET active_sequence = 1")
        .is_err());
    assert!(connection
        .execute_batch("UPDATE config_ledger_pointer SET active_sequence = NULL")
        .is_err());
    drop(connection);
    let mut ledger = RevisionLedger::open(state.path()).expect("nothing changed");
    assert_eq!(ledger.state().expect("state").revisions, 3);
    assert!(ledger.revision(&seed.revision).expect("read").is_some());
}

#[test]
fn an_edited_record_is_detected() {
    let (state, _) = three_revisions("edited-record");
    let connection = outside(&state);
    let bytes = record_bytes(&connection, 2);
    let edited = String::from_utf8(bytes)
        .expect("UTF-8")
        .replace("\"subject\":\"alice\"", "\"subject\":\"mallory\"");
    past_trigger(
        &connection,
        "config_revisions_no_update",
        &format!(
            "UPDATE config_revisions SET record = CAST('{edited}' AS BLOB) WHERE sequence = 2"
        ),
    );
    drop(connection);
    assert_eq!(
        corruption(RevisionLedger::open(state.path())),
        Corruption::RecordHash
    );
}

#[test]
fn a_consistently_forged_record_breaks_the_chain() {
    let (state, _) = three_revisions("forged-record");
    let connection = outside(&state);
    let mut value: Value =
        serde_json::from_slice(&record_bytes(&connection, 2)).expect("record JSON");
    value["actor"]["subject"] = Value::from("mallory");
    forge_record(&connection, 2, &value);
    drop(connection);
    // The forged row hashes correctly; its successor still names the
    // original.
    assert_eq!(
        corruption(RevisionLedger::open(state.path())),
        Corruption::Chain
    );
}

#[test]
fn a_forged_head_is_detected_by_the_pointer() {
    let (state, _) = three_revisions("forged-head");
    let connection = outside(&state);
    let mut value: Value =
        serde_json::from_slice(&record_bytes(&connection, 3)).expect("record JSON");
    value["activation"] = Value::from("live");
    forge_record(&connection, 3, &value);
    drop(connection);
    assert_eq!(
        corruption(RevisionLedger::open(state.path())),
        Corruption::Pointer
    );
}

#[test]
fn a_non_canonical_record_is_refused_even_though_it_hashes_correctly() {
    let (state, _) = three_revisions("non-canonical");
    let connection = outside(&state);
    let value: Value = serde_json::from_slice(&record_bytes(&connection, 2)).expect("record");
    let pretty = serde_json::to_vec_pretty(&value).expect("pretty");
    connection
        .execute_batch("DROP TRIGGER config_revisions_no_update;")
        .expect("drop");
    connection
        .execute(
            "UPDATE config_revisions SET record = ?1 WHERE sequence = 2",
            params![pretty],
        )
        .expect("update");
    connection
        .execute_batch(store::schema_sql("config_revisions_no_update").expect("trigger"))
        .expect("restore");
    drop(connection);
    assert_eq!(
        corruption(RevisionLedger::open(state.path())),
        Corruption::Record
    );
}

#[test]
fn an_edited_or_extra_document_is_detected() {
    let (state, [seed, ..]) = three_revisions("edited-document");
    let policy = seed
        .bundle
        .files
        .iter()
        .find(|file| file.role == FileRole::Policy)
        .map(|file| file.sha256.clone())
        .expect("policy pin");
    let connection = outside(&state);
    past_trigger(
        &connection,
        "config_ledger_documents_no_update",
        &format!(
            "UPDATE config_ledger_documents SET content = CAST('{}' AS BLOB) WHERE sha256 = '{policy}'",
            policy_json("allow-everything").replace('\n', "")
        ),
    );
    drop(connection);
    assert_eq!(
        corruption(RevisionLedger::open(state.path())),
        Corruption::Document
    );

    let (state, _) = three_revisions("extra-document");
    let extra = b"an unreferenced document";
    outside(&state)
        .execute(
            "INSERT INTO config_ledger_documents (sha256, content) VALUES (?1, ?2)",
            params![sha256_pin(extra), extra.as_slice()],
        )
        .expect("insert");
    assert_eq!(
        corruption(RevisionLedger::open(state.path())),
        Corruption::Document
    );
}

#[test]
fn a_removed_revision_is_detected() {
    // A gap in the middle breaks the chain.
    let (state, _) = three_revisions("removed-middle");
    past_trigger(
        &outside(&state),
        "config_revisions_no_delete",
        "DELETE FROM config_revisions WHERE sequence = 2",
    );
    assert_eq!(
        corruption(RevisionLedger::open(state.path())),
        Corruption::Chain
    );

    // A truncated tail leaves the pointer naming a revision that is gone.
    let (state, _) = three_revisions("removed-head");
    past_trigger(
        &outside(&state),
        "config_revisions_no_delete",
        "DELETE FROM config_revisions WHERE sequence = 3",
    );
    assert_eq!(
        corruption(RevisionLedger::open(state.path())),
        Corruption::Pointer
    );
}

#[test]
fn a_pointer_moved_behind_the_head_is_detected() {
    let (state, [seed, ..]) = three_revisions("moved-pointer");
    past_trigger(
        &outside(&state),
        "config_ledger_pointer_forward",
        &format!(
            "UPDATE config_ledger_pointer SET desired_sequence = 1, desired_record_hash = '{}'",
            seed.record_hash
        ),
    );
    assert_eq!(
        corruption(RevisionLedger::open(state.path())),
        Corruption::Pointer
    );
}

#[test]
fn a_changed_schema_is_detected() {
    let (state, _) = three_revisions("dropped-trigger");
    outside(&state)
        .execute_batch("DROP TRIGGER config_revisions_no_delete;")
        .expect("drop");
    assert_eq!(
        corruption(RevisionLedger::open(state.path())),
        Corruption::Schema
    );

    let (state, _) = three_revisions("added-trigger");
    outside(&state)
        .execute_batch(
            "CREATE TRIGGER config_revisions_echo AFTER INSERT ON config_revisions BEGIN SELECT 1; END;",
        )
        .expect("create");
    assert_eq!(
        corruption(RevisionLedger::open(state.path())),
        Corruption::Schema
    );
}

#[test]
fn a_damaged_database_file_is_refused() {
    let (state, _) = three_revisions("damaged");
    // Every handle is closed, so the log is already checkpointed into the
    // file; drop anything left so only the damaged file is read.
    for suffix in ["-wal", "-shm"] {
        let _ = fs::remove_file(format!("{}{suffix}", state.ledger().display()));
    }
    let mut bytes = fs::read(state.ledger()).expect("ledger bytes");
    assert!(bytes.len() > 8192, "the ledger spans several pages");
    for byte in &mut bytes[4096..] {
        *byte = 0x5a;
    }
    fs::write(state.ledger(), &bytes).expect("damage");
    assert!(matches!(
        RevisionLedger::open(state.path()),
        Err(LedgerError::Corrupt(_))
    ));
}

#[test]
fn a_foreign_or_newer_file_is_refused() {
    let (state, _) = three_revisions("foreign");
    outside(&state)
        .execute_batch("PRAGMA application_id = 1;")
        .expect("pragma");
    assert_eq!(
        corruption(RevisionLedger::open(state.path())),
        Corruption::Format
    );

    let (state, _) = three_revisions("newer");
    outside(&state)
        .execute_batch("PRAGMA user_version = 2;")
        .expect("pragma");
    assert_eq!(
        RevisionLedger::open(state.path()).map(|_| ()),
        Err(LedgerError::Unsupported)
    );

    let state = TempDir::new("empty-file");
    fs::write(state.ledger(), b"").expect("empty ledger file");
    assert_eq!(
        corruption(RevisionLedger::open(state.path())),
        Corruption::Format
    );
}

#[test]
fn a_handle_that_found_corruption_refuses_every_later_call() {
    let (state, [seed, second, third]) = three_revisions("poisoned");
    let mut ledger = RevisionLedger::open(state.path()).expect("open");
    let pin = second
        .bundle
        .files
        .iter()
        .find(|file| file.role == FileRole::Policy)
        .map(|file| file.sha256.clone())
        .expect("policy pin");
    past_trigger(
        &outside(&state),
        "config_ledger_documents_no_update",
        &format!("UPDATE config_ledger_documents SET content = x'00' WHERE sha256 = '{pin}'"),
    );
    assert_eq!(
        ledger.revision(&second.revision),
        Err(LedgerError::Corrupt(Corruption::Document))
    );
    // Even calls that would not have read the edited document now refuse.
    let corrupt = Err(LedgerError::Corrupt(Corruption::Document));
    assert_eq!(ledger.revision(&seed.revision).map(|_| ()), corrupt);
    assert_eq!(ledger.state().map(|_| ()), corrupt);
    assert_eq!(
        ledger
            .append(
                &third.revision,
                proposal(&bundle("fourth"), ActivationClass::Live)
            )
            .map(|_| ()),
        corrupt
    );
    assert_eq!(ledger.activate(&third.revision).map(|_| ()), corrupt);
    drop(ledger);
    let revisions: i64 = outside(&state)
        .query_row("SELECT COUNT(*) FROM config_revisions", [], |row| {
            row.get(0)
        })
        .expect("count");
    assert_eq!(revisions, 3);
}

#[test]
fn an_append_never_chains_onto_an_edited_head() {
    let (state, [_, _, third]) = three_revisions("edited-head");
    let mut ledger = RevisionLedger::open(state.path()).expect("open");
    let connection = outside(&state);
    let edited = String::from_utf8(record_bytes(&connection, 3))
        .expect("UTF-8")
        .replace("\"activation\":\"restart\"", "\"activation\":\"live\"");
    past_trigger(
        &connection,
        "config_revisions_no_update",
        &format!(
            "UPDATE config_revisions SET record = CAST('{edited}' AS BLOB) WHERE sequence = 3"
        ),
    );
    drop(connection);
    assert_eq!(
        ledger.append(
            &third.revision,
            proposal(&bundle("fourth"), ActivationClass::Live)
        ),
        Err(LedgerError::Corrupt(Corruption::RecordHash))
    );
    drop(ledger);
    let revisions: i64 = outside(&state)
        .query_row("SELECT COUNT(*) FROM config_revisions", [], |row| {
            row.get(0)
        })
        .expect("count");
    assert_eq!(revisions, 3);
}

#[test]
fn a_rollback_whose_content_was_swapped_is_detected() {
    let (state, [seed, second, third]) = three_revisions("swapped-rollback");
    let mut ledger = RevisionLedger::open(state.path()).expect("open");
    let rolled_back = ledger
        .append(
            &third.revision,
            rollback_proposal(&second.revision, &bundle("second")),
        )
        .expect("rollback");
    drop(ledger);
    // Re-point the rollback at the seed while keeping its content: a
    // consistent record and chain, except that the rollback no longer
    // restores its target.
    let connection = outside(&state);
    let mut value: Value =
        serde_json::from_slice(&record_bytes(&connection, 4)).expect("record JSON");
    value["rollback_of"] = Value::from(seed.revision.as_str());
    forge_record(&connection, 4, &value);
    let hash = canonical_json::semantic_digest(RECORD_MEDIA_TYPE, RECORD_SCHEMA_VERSION, &value)
        .expect("hash");
    past_trigger(
        &connection,
        "config_ledger_pointer_forward",
        &format!("UPDATE config_ledger_pointer SET desired_record_hash = '{hash}'"),
    );
    drop(connection);
    assert_ne!(hash, rolled_back.record_hash);
    assert_eq!(
        corruption(RevisionLedger::open(state.path())),
        Corruption::Chain
    );
}

#[test]
fn a_documents_source_digest_is_checked_against_the_manifest() {
    // A manifest stored under its pin but recorded with another source
    // digest: the record is consistent, the documents are not.
    let (state, [seed, ..]) = seeded_with_record_edit("source-digest", |value| {
        value["bundle"]["source_digest"] = Value::from(format!("sha256:{}", "0".repeat(64)));
    });
    assert_ne!(
        seed.bundle.source_digest,
        format!("sha256:{}", "0".repeat(64))
    );
    assert_eq!(
        corruption(RevisionLedger::open(state.path())),
        Corruption::Document
    );
    // Sanity: the frame the check uses is the bundle reader's.
    let stored = {
        let connection = outside(&state);
        let manifest_pin = &seed.bundle.files[0].sha256;
        connection
            .query_row(
                "SELECT content FROM config_ledger_documents WHERE sha256 = ?1",
                params![manifest_pin],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .expect("manifest")
    };
    assert_eq!(
        canonical_json::source_digest(MANIFEST_MEDIA_TYPE, "greengateway.dev/v1alpha1", &stored),
        seed.bundle.source_digest
    );
}

/// A one-revision ledger whose seed record was rewritten by `edit` and
/// consistently re-hashed, with the pointer following it.
fn seeded_with_record_edit(
    label: &str,
    edit: impl FnOnce(&mut Value),
) -> (TempDir, [RevisionSummary; 1]) {
    let (state, ledger, seed) = seeded(label, "first");
    drop(ledger);
    let connection = outside(&state);
    let mut value: Value = serde_json::from_slice(&record_bytes(&connection, 1)).expect("record");
    edit(&mut value);
    forge_record(&connection, 1, &value);
    let hash = canonical_json::semantic_digest(RECORD_MEDIA_TYPE, RECORD_SCHEMA_VERSION, &value)
        .expect("hash");
    past_trigger(
        &connection,
        "config_ledger_pointer_forward",
        &format!("UPDATE config_ledger_pointer SET desired_record_hash = '{hash}'"),
    );
    (state, [seed])
}

#[test]
fn a_record_naming_an_unknown_document_version_is_unsupported() {
    let (state, _) = seeded_with_record_edit("unknown-version", |value| {
        value["bundle"]["api_version"] = Value::from("greengateway.dev/v1beta1");
    });
    assert_eq!(
        RevisionLedger::open(state.path()).map(|_| ()),
        Err(LedgerError::Unsupported)
    );

    // An unknown member is not a newer format; it is not a record.
    let (state, _) = seeded_with_record_edit("unknown-member", |value| {
        value["note"] = Value::from("added");
    });
    assert_eq!(
        corruption(RevisionLedger::open(state.path())),
        Corruption::Record
    );
}
