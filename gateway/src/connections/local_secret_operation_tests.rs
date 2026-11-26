//! The store rows of the local-secret family's test matrix (issue #425,
//! plan P8): a keyed create, rotate and delete against the Connections
//! database's SQLite file, which is the only store local secrets have.
//! Every test ends by asserting I3 against its own file.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Barrier,
};

use rusqlite::{params, Connection};

use super::tests::{envelope, secret, TestEnvironment, PRIMARY_FILE};
use super::*;
use crate::authority_events::caller_operation::{
    test_caller_key, CallerKeyState, CallerOperation, CallerOutcome, OperationReceipt,
};

const ISSUER: &str = "https://issuer.local-secret.example.test";
const VALUE: &[u8] = b"keyed-local-secret-value";
const PURPOSE: SecretPurpose = SecretPurpose::StaticBearer;

fn operator() -> ChangeActor {
    ChangeActor::for_test_with_issuer("keyed-secret-operator", ISSUER)
}

struct Opened {
    environment: TestEnvironment,
    /// Kept open for the provider's lifetime.
    _store: SqliteConnectionStore,
    provider: LocalSecretProvider,
}

impl Opened {
    fn new(name: &str) -> Self {
        let environment = TestEnvironment::new(name);
        environment.write_key(PRIMARY_FILE, 41);
        let (store, provider) = environment
            .provider(&environment.primary_config())
            .expect("the provider opens");
        Self {
            environment,
            _store: store,
            provider,
        }
    }

    fn database(&self) -> &Path {
        &self.environment.database
    }

    /// A second provider on the same file, as a second writer.
    fn second_provider(&self) -> LocalSecretProvider {
        self.environment
            .provider(&self.environment.primary_config())
            .expect("a second provider opens")
            .1
    }
}

fn etag(metadata: &SecretAliasMetadata) -> String {
    super::super::admin::secret_metadata_etag(metadata)
}

/// The ETag the store compares a rotation's or a deletion's `If-Match` with
/// is the one the admin API hands out for the same secret, whatever its
/// label, purpose and rotation time.
#[test]
fn the_store_compares_the_item_etag_the_admin_api_hands_out() {
    let metadata = SecretAliasMetadata {
        id: "local-secret-etag".to_owned(),
        label: "A labelled secret".to_owned(),
        provider: SecretProviderKind::LocalEncrypted,
        configured: true,
        purpose: Some(SecretPurpose::StaticBearer),
        pinned: true,
        version: Some(7),
        rotated_at: Some("2026-11-21T00:00:00Z".to_owned()),
    };
    assert_eq!(item_etag("local-secret-etag", 7), etag(&metadata));
    assert_ne!(item_etag("local-secret-etag", 6), etag(&metadata));
}

fn create_key(seed: u8, actor: &ChangeActor, label: &str) -> CallerOperation {
    SecretChangeBinding {
        action: EVIDENCE_ACTION_CREATE,
        actor,
        secret_id: "",
        if_match: "",
        label: Some(label),
        purpose: Some(PURPOSE),
    }
    .bind(test_caller_key(seed))
    .expect("the create key binds")
}

fn rotate_key(seed: u8, actor: &ChangeActor, current: &SecretAliasMetadata) -> CallerOperation {
    SecretChangeBinding {
        action: EVIDENCE_ACTION_ROTATE,
        actor,
        secret_id: &current.id,
        if_match: &etag(current),
        label: None,
        purpose: Some(PURPOSE),
    }
    .bind(test_caller_key(seed))
    .expect("the rotate key binds")
}

fn delete_key(seed: u8, actor: &ChangeActor, current: &SecretAliasMetadata) -> CallerOperation {
    SecretChangeBinding {
        action: EVIDENCE_ACTION_DELETE,
        actor,
        secret_id: &current.id,
        if_match: &etag(current),
        label: None,
        purpose: None,
    }
    .bind(test_caller_key(seed))
    .expect("the delete key binds")
}

fn create(
    provider: &LocalSecretProvider,
    label: &str,
    value: &[u8],
    caller: Option<&CallerOperation>,
) -> Result<CallerOutcome<SecretAliasMetadata>, LocalSecretError> {
    provider.create_with_operation(label, secret(PURPOSE, value), &operator(), caller, &|| true)
}

/// Rotate `current` to `value` on condition that the stored ETag is still
/// `expected`'s.
fn rotate(
    provider: &LocalSecretProvider,
    current: &SecretAliasMetadata,
    expected: &str,
    value: &[u8],
    caller: Option<&CallerOperation>,
) -> Result<CallerOutcome<SecretAliasMetadata>, LocalSecretError> {
    provider.rotate_with_operation(
        &current.id,
        secret(PURPOSE, value),
        &operator(),
        caller,
        &|stored| stored == expected,
    )
}

fn delete(
    provider: &LocalSecretProvider,
    current: &SecretAliasMetadata,
    expected: &str,
    caller: Option<&CallerOperation>,
) -> Result<CallerOutcome<()>, LocalSecretError> {
    provider.delete_with_operation(&current.id, &operator(), caller, &|stored| {
        stored == expected
    })
}

fn committed<T: std::fmt::Debug>(
    outcome: Result<CallerOutcome<T>, LocalSecretError>,
    what: &str,
) -> T {
    match outcome {
        Ok(CallerOutcome::Committed(value)) => value,
        other => panic!("{what} should commit: {other:?}"),
    }
}

fn replayed<T: std::fmt::Debug>(
    outcome: Result<CallerOutcome<T>, LocalSecretError>,
    what: &str,
) -> OperationReceipt {
    match outcome {
        Ok(CallerOutcome::Replayed(receipt)) => receipt,
        other => panic!("{what} should be answered from its receipt: {other:?}"),
    }
}

fn conflicts<T: std::fmt::Debug>(outcome: Result<CallerOutcome<T>, LocalSecretError>, what: &str) {
    assert!(
        matches!(outcome, Err(LocalSecretError::CallerOperationConflict)),
        "{what} should conflict: {outcome:?}"
    );
}

/// `(operation_id, action, binding_digest)` of every reservation.
fn reservations(database: &Path) -> Vec<(String, String, Option<String>)> {
    let connection = Connection::open(database).expect("the database opens");
    let mut statement = connection
        .prepare(
            "SELECT operation_id, action, binding_digest FROM authority_caller_operation_ids \
             ORDER BY operation_id",
        )
        .expect("the reservation query prepares");
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("the reservations read")
        .collect::<Result<Vec<_>, _>>()
        .expect("the reservation rows read");
    rows
}

/// `(operation_id, action, secret_id, prior_version, new_version)` of every
/// local-secret evidence row, in commit order.
type EvidenceRow = (String, String, Option<String>, Option<i64>, Option<i64>);

fn evidence(database: &Path) -> Vec<EvidenceRow> {
    let connection = Connection::open(database).expect("the database opens");
    let mut statement = connection
        .prepare(
            "SELECT operation_id, action, secret_id, prior_version, new_version \
             FROM connection_local_secret_change_evidence ORDER BY sequence",
        )
        .expect("the evidence query prepares");
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .expect("the evidence reads")
        .collect::<Result<Vec<_>, _>>()
        .expect("the evidence rows read");
    rows
}

/// Every column of every local-secret evidence row, as text.
fn evidence_text(database: &Path) -> String {
    let connection = Connection::open(database).expect("the database opens");
    let mut statement = connection
        .prepare(
            "SELECT event_id, operation_id, actor_user_id, coalesce(actor_issuer, ''), \
                    actor_kind, actor_auth_mode, action, coalesce(secret_id, ''), \
                    coalesce(prior_version, ''), coalesce(new_version, ''), \
                    coalesce(reencrypted_count, ''), committed_at \
             FROM connection_local_secret_change_evidence ORDER BY sequence",
        )
        .expect("the evidence text query prepares");
    let rows = statement
        .query_map([], |row| {
            (0..12)
                .map(|index| row.get::<_, rusqlite::types::Value>(index))
                .collect::<Result<Vec<_>, _>>()
        })
        .expect("the evidence text reads")
        .collect::<Result<Vec<_>, _>>()
        .expect("the evidence text rows read");
    format!("{rows:?}")
}

fn rows_for(database: &Path, key: &CallerOperation) -> Vec<String> {
    let key = key.id().to_string();
    evidence(database)
        .into_iter()
        .filter(|row| row.0 == key)
        .map(|row| row.1)
        .collect()
}

/// I3: a local-secret action's reservation exists exactly when an evidence
/// row with that operation ID and action exists, for every caller key.
fn assert_reservations_match_evidence(database: &Path) {
    let reserved: BTreeSet<(String, String)> = reservations(database)
        .into_iter()
        .filter(|(_, action, _)| action.starts_with("secret."))
        .map(|(key, action, _)| (key, action))
        .collect();
    let evidenced: BTreeSet<(String, String)> = evidence(database)
        .into_iter()
        .filter(|(operation_id, action, ..)| {
            action.starts_with("secret.")
                && Uuid::parse_str(operation_id).map(|id| id.get_version_num()) == Ok(7)
        })
        .map(|(operation_id, action, ..)| (operation_id, action))
        .collect();
    assert_eq!(
        reserved, evidenced,
        "every keyed local-secret change is reserved exactly when it is evidenced"
    );
}

fn stored_value(provider: &LocalSecretProvider, id: &str) -> Vec<u8> {
    provider
        .resolve_blocking(id, PURPOSE)
        .expect("the secret resolves")
        .expose()
        .to_vec()
}

/// An exact retry of a keyed create, rotate and delete is answered with the
/// receipt read from the committed evidence row and makes no second change
/// and no second evidence row. A committed keyed retry gets its receipt even
/// though its `If-Match` no longer matches. An unkeyed change mints its own
/// operation ID and reserves nothing.
#[test]
fn local_secret_caller_operation_contract() {
    let db = Opened::new("contract");
    let actor = operator();
    let create_key = create_key(1, &actor, "Keyed");
    assert_eq!(
        db.provider.caller_operation_state(&create_key),
        Ok(CallerKeyState::Unused)
    );
    let created = committed(
        create(&db.provider, "Keyed", VALUE, Some(&create_key)),
        "the keyed create",
    );
    assert_eq!(
        db.provider.caller_operation_state(&create_key),
        Ok(CallerKeyState::SameBinding)
    );
    let receipt = replayed(
        create(&db.provider, "Keyed", VALUE, Some(&create_key)),
        "the create retry",
    );
    assert_eq!(receipt.operation_id, create_key.id().to_string());
    assert_eq!(receipt.operation, "secret.create");
    assert_eq!(receipt.resource_id, created.id);
    assert_eq!(receipt.revision, Some(1));
    assert_eq!(db.provider.metadata(), vec![created.clone()]);
    assert_eq!(rows_for(db.database(), &create_key), ["secret.create"]);

    let created_etag = etag(&created);
    let rotate_key = rotate_key(2, &actor, &created);
    let rotated = committed(
        rotate(
            &db.provider,
            &created,
            &created_etag,
            b"keyed-rotated-value",
            Some(&rotate_key),
        ),
        "the keyed rotation",
    );
    assert_eq!(rotated.version, Some(2));
    // The retry still names the ETag the rotation replaced: a committed keyed
    // retry is answered before the precondition is compared.
    let receipt = replayed(
        rotate(
            &db.provider,
            &created,
            &created_etag,
            b"keyed-rotated-value",
            Some(&rotate_key),
        ),
        "the rotation retry",
    );
    assert_eq!(
        (receipt.operation.as_str(), receipt.revision),
        ("secret.rotate", Some(2))
    );
    assert_eq!(db.provider.metadata(), vec![rotated.clone()]);
    assert_eq!(
        stored_value(&db.provider, &rotated.id),
        b"keyed-rotated-value"
    );

    let rotated_etag = etag(&rotated);
    let delete_key = delete_key(3, &actor, &rotated);
    committed(
        delete(&db.provider, &rotated, &rotated_etag, Some(&delete_key)),
        "the keyed delete",
    );
    let receipt = replayed(
        delete(&db.provider, &rotated, &rotated_etag, Some(&delete_key)),
        "the delete retry",
    );
    assert_eq!(
        (receipt.operation.as_str(), receipt.resource_id.as_str()),
        ("secret.delete", rotated.id.as_str())
    );
    assert_eq!(
        receipt.revision,
        Some(2),
        "a deletion names its last revision"
    );
    assert!(db.provider.metadata().is_empty());

    // An unkeyed change records a gateway-minted v4 operation ID.
    let unkeyed = committed(create(&db.provider, "Unkeyed", VALUE, None), "unkeyed");
    let rows = evidence(db.database());
    assert_eq!(rows.len(), 4);
    let unkeyed_row = rows.last().expect("the unkeyed row exists");
    assert_eq!(unkeyed_row.2.as_deref(), Some(unkeyed.id.as_str()));
    assert_eq!(
        Uuid::parse_str(&unkeyed_row.0).map(|id| id.get_version_num()),
        Ok(4)
    );
    assert_eq!(reservations(db.database()).len(), 3);
    assert_reservations_match_evidence(db.database());
}

/// The same key with another actor, label, target or `If-Match` is a
/// conflict that changes nothing.
#[test]
fn a_reused_key_with_a_different_binding_conflicts_and_changes_nothing() {
    let db = Opened::new("rebound");
    let actor = operator();
    let key = create_key(10, &actor, "Bound");
    let created = committed(
        create(&db.provider, "Bound", VALUE, Some(&key)),
        "the keyed create",
    );
    let stranger = ChangeActor::for_test_with_issuer("another-operator", ISSUER);
    let rebound = [
        create_key(10, &stranger, "Bound"),
        create_key(10, &actor, "Relabelled"),
    ];
    for other in &rebound {
        conflicts(
            create(&db.provider, "Relabelled", VALUE, Some(other)),
            "a create under a rebound key",
        );
    }

    let other_secret = committed(create(&db.provider, "Other", VALUE, None), "fixture");
    let rotate_key_seed = 11;
    let bound = rotate_key(rotate_key_seed, &actor, &created);
    committed(
        rotate(
            &db.provider,
            &created,
            &etag(&created),
            b"rotated",
            Some(&bound),
        ),
        "the keyed rotation",
    );
    let before = (
        envelope(db.database(), &created.id),
        envelope(db.database(), &other_secret.id),
        evidence(db.database()),
        reservations(db.database()),
    );
    let stale_precondition = SecretChangeBinding {
        action: EVIDENCE_ACTION_ROTATE,
        actor: &actor,
        secret_id: &created.id,
        if_match: "\"connection-secret:another:v9\"",
        label: None,
        purpose: Some(PURPOSE),
    }
    .bind(test_caller_key(rotate_key_seed))
    .expect("binds");
    let other_target = rotate_key(rotate_key_seed, &actor, &other_secret);
    conflicts(
        rotate(
            &db.provider,
            &created,
            &etag(&created),
            b"rotated",
            Some(&stale_precondition),
        ),
        "a rotation under another If-Match",
    );
    conflicts(
        rotate(
            &db.provider,
            &other_secret,
            &etag(&other_secret),
            b"rotated",
            Some(&other_target),
        ),
        "a rotation of another secret",
    );
    assert_eq!(
        (
            envelope(db.database(), &created.id),
            envelope(db.database(), &other_secret.id),
            evidence(db.database()),
            reservations(db.database()),
        ),
        before
    );
    assert_reservations_match_evidence(db.database());
}

/// A key reserved for another action, by a keyed revoke, by a Connection
/// change or by another local-secret operation, cannot take effect here.
#[test]
fn a_key_reserved_by_another_action_cannot_take_effect_here() {
    let db = Opened::new("cross-action");
    let actor = operator();
    let created = committed(create(&db.provider, "Target", VALUE, None), "fixture");

    // A key a keyed revoke reserved, with no digest.
    let revoke_key = test_caller_key(21);
    {
        let connection = Connection::open(db.database()).expect("the database opens");
        assert!(
            crate::storage::standalone_authority_events::reserve_unbound_operation(
                &connection,
                revoke_key,
                "service_token.revoke",
            )
            .expect("the revoke reservation writes")
        );
        connection
            .execute(
                "INSERT INTO authority_caller_operation_ids (operation_id, action, binding_digest) \
                 VALUES (?1, 'connection.create', ?2)",
                params![test_caller_key(22).to_string(), "a".repeat(64)],
            )
            .expect("the Connection reservation writes");
    }
    for seed in [21, 22] {
        let key = create_key(seed, &actor, "Target");
        assert_eq!(
            db.provider.caller_operation_state(&key),
            Ok(CallerKeyState::OtherBinding)
        );
        conflicts(
            create(&db.provider, "Target", VALUE, Some(&key)),
            "a create under another action's key",
        );
    }

    // A key a local-secret create used, offered to a rotation and a delete.
    let create_key = create_key(23, &actor, "Second");
    committed(
        create(&db.provider, "Second", VALUE, Some(&create_key)),
        "the keyed create",
    );
    let before = (
        envelope(db.database(), &created.id),
        evidence(db.database()),
        reservations(db.database()),
    );
    conflicts(
        rotate(
            &db.provider,
            &created,
            &etag(&created),
            b"rotated",
            Some(&rotate_key(23, &actor, &created)),
        ),
        "a rotation under a create's key",
    );
    conflicts(
        delete(
            &db.provider,
            &created,
            &etag(&created),
            Some(&delete_key(23, &actor, &created)),
        ),
        "a delete under a create's key",
    );
    assert_eq!(
        (
            envelope(db.database(), &created.id),
            evidence(db.database()),
            reservations(db.database()),
        ),
        before
    );
    assert_reservations_match_evidence(db.database());
}

/// A store call handed a key bound to another operation is a handler defect,
/// refused before anything is read or written.
#[test]
fn a_key_bound_to_another_operation_is_refused_by_the_store() {
    let db = Opened::new("misbound");
    let actor = operator();
    let created = committed(create(&db.provider, "Target", VALUE, None), "fixture");
    let rotation_key = rotate_key(25, &actor, &created);
    conflicts(
        create(&db.provider, "Target", VALUE, Some(&rotation_key)),
        "a create handed a rotation's key",
    );
    assert_eq!(db.provider.metadata().len(), 1);
    assert!(reservations(db.database()).is_empty());
    assert_reservations_match_evidence(db.database());
}

/// I1, I2: a failed evidence insert rolls back the keyed create, rotation and
/// delete together with their reservations, and each is counted once.
#[test]
fn a_failed_evidence_insert_rolls_back_the_keyed_secret_change_and_its_reservation() {
    let db = Opened::new("evidence-fault");
    let actor = operator();
    let created = committed(create(&db.provider, "Faulted", VALUE, None), "fixture");
    let before = envelope(db.database(), &created.id);
    let recorder = crate::audit::sink::tests::CountingRecorder::default();
    let _recording = ::metrics::set_default_local_recorder(&recorder);
    let failures = || {
        recorder.count(
            crate::metrics::STANDALONE_EVIDENCE_FAILURES_TOTAL,
            &[("store", "connections")],
        )
    };
    // Test-only fault injection through a second connection.
    Connection::open(db.database())
        .expect("the database opens")
        .execute_batch(
            "CREATE TRIGGER fail_secret_change_evidence \
             BEFORE INSERT ON connection_local_secret_change_evidence \
             BEGIN SELECT RAISE(ABORT, 'injected evidence failure'); END;",
        )
        .expect("the fault installs");
    let created_etag = etag(&created);
    assert_eq!(
        create(
            &db.provider,
            "Second",
            VALUE,
            Some(&create_key(30, &actor, "Second"))
        ),
        Err(LocalSecretError::ChangeEvidenceFailure)
    );
    assert_eq!(
        rotate(
            &db.provider,
            &created,
            &created_etag,
            b"faulted-rotation",
            Some(&rotate_key(31, &actor, &created)),
        ),
        Err(LocalSecretError::ChangeEvidenceFailure)
    );
    assert_eq!(
        delete(
            &db.provider,
            &created,
            &created_etag,
            Some(&delete_key(32, &actor, &created))
        ),
        Err(LocalSecretError::ChangeEvidenceFailure)
    );
    assert_eq!(failures(), 3);
    assert_eq!(envelope(db.database(), &created.id), before);
    assert_eq!(db.provider.metadata(), vec![created.clone()]);
    assert!(reservations(db.database()).is_empty());
    assert_eq!(evidence(db.database()).len(), 1);
    assert_reservations_match_evidence(db.database());
}

/// I2 and lesson (h): a reservation that cannot be written rolls the keyed
/// change back and is counted on the standalone evidence failure counter, as
/// a failed evidence insert is. An unkeyed change reserves nothing.
#[test]
fn a_failed_reservation_rolls_back_the_keyed_secret_change_and_is_counted() {
    let db = Opened::new("reservation-fault");
    let actor = operator();
    let created = committed(create(&db.provider, "Faulted", VALUE, None), "fixture");
    let before = envelope(db.database(), &created.id);
    let recorder = crate::audit::sink::tests::CountingRecorder::default();
    let _recording = ::metrics::set_default_local_recorder(&recorder);
    let failures = || {
        recorder.count(
            crate::metrics::STANDALONE_EVIDENCE_FAILURES_TOTAL,
            &[("store", "connections")],
        )
    };
    Connection::open(db.database())
        .expect("the database opens")
        .execute_batch(
            "CREATE TRIGGER fail_caller_key_reservation \
             BEFORE INSERT ON authority_caller_operation_ids \
             BEGIN SELECT RAISE(ABORT, 'injected reservation failure'); END;",
        )
        .expect("the fault installs");
    let created_etag = etag(&created);
    assert_eq!(
        create(
            &db.provider,
            "Second",
            VALUE,
            Some(&create_key(35, &actor, "Second"))
        ),
        Err(LocalSecretError::CallerOperationUnavailable)
    );
    assert_eq!(
        rotate(
            &db.provider,
            &created,
            &created_etag,
            b"faulted-rotation",
            Some(&rotate_key(36, &actor, &created)),
        ),
        Err(LocalSecretError::CallerOperationUnavailable)
    );
    assert_eq!(
        delete(
            &db.provider,
            &created,
            &created_etag,
            Some(&delete_key(37, &actor, &created))
        ),
        Err(LocalSecretError::CallerOperationUnavailable)
    );
    assert_eq!(failures(), 3);
    assert_eq!(envelope(db.database(), &created.id), before);
    assert_eq!(evidence(db.database()).len(), 1);
    committed(
        create(&db.provider, "Unkeyed", VALUE, None),
        "the unkeyed create",
    );
    assert_eq!(
        failures(),
        3,
        "an unkeyed change reserves and counts nothing"
    );
    assert_reservations_match_evidence(db.database());
}

/// A stale precondition under an unused key ends the create, rotation or
/// delete with `PreconditionFailed` and writes no change, evidence or
/// reservation.
#[test]
fn a_stale_etag_under_a_key_writes_no_change_evidence_or_reservation() {
    let db = Opened::new("stale");
    let actor = operator();
    let created = committed(create(&db.provider, "Current", VALUE, None), "fixture");
    let rotated = committed(
        rotate(&db.provider, &created, &etag(&created), b"second", None),
        "the unkeyed rotation",
    );
    let before = (
        envelope(db.database(), &rotated.id),
        evidence(db.database()),
        db.provider.metadata(),
    );
    let stale = etag(&created);
    assert_eq!(
        db.provider.create_with_operation(
            "Stale",
            secret(PURPOSE, VALUE),
            &actor,
            Some(&create_key(40, &actor, "Stale")),
            &|| false,
        ),
        Err(LocalSecretError::PreconditionFailed)
    );
    assert_eq!(
        rotate(
            &db.provider,
            &rotated,
            &stale,
            b"stale-rotation",
            Some(&rotate_key(41, &actor, &created)),
        ),
        Err(LocalSecretError::PreconditionFailed)
    );
    assert_eq!(
        delete(
            &db.provider,
            &rotated,
            &stale,
            Some(&delete_key(42, &actor, &created))
        ),
        Err(LocalSecretError::PreconditionFailed)
    );
    assert_eq!(
        (
            envelope(db.database(), &rotated.id),
            evidence(db.database()),
            db.provider.metadata(),
        ),
        before
    );
    assert!(reservations(db.database()).is_empty());
    assert_reservations_match_evidence(db.database());
}

/// Two writers on the same file racing one key: one commits, the other is
/// answered with the receipt.
#[test]
fn two_writers_racing_one_key_commit_one_change() {
    let db = Opened::new("racing-key");
    let second = db.second_provider();
    let actor = operator();
    let key = create_key(60, &actor, "Raced");
    let barrier = Barrier::new(2);
    let outcomes = std::thread::scope(|scope| {
        let writers = [&db.provider, &second].map(|provider| {
            let (barrier, key) = (&barrier, &key);
            scope.spawn(move || {
                barrier.wait();
                create(provider, "Raced", VALUE, Some(key))
            })
        });
        writers.map(|writer| writer.join().expect("the writer finishes"))
    });
    let committed_count = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Ok(CallerOutcome::Committed(_))))
        .count();
    let replayed_count = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Ok(CallerOutcome::Replayed(_))))
        .count();
    assert_eq!(
        (committed_count, replayed_count),
        (1, 1),
        "one commit and one receipt: {outcomes:?}"
    );
    let stored: i64 = Connection::open(db.database())
        .expect("the database opens")
        .query_row("SELECT COUNT(*) FROM connection_local_secrets", [], |row| {
            row.get(0)
        })
        .expect("the secrets count");
    assert_eq!(stored, 1);
    assert_eq!(rows_for(db.database(), &key), ["secret.create"]);
    assert_reservations_match_evidence(db.database());
}

/// Two keys racing one revision: one rotation wins, the other loses on its
/// precondition and leaves no evidence and no reservation.
#[test]
fn two_keys_racing_one_revision_leave_only_the_winners_rows() {
    let db = Opened::new("racing-revision");
    let second = db.second_provider();
    let actor = operator();
    let created = committed(create(&db.provider, "Contended", VALUE, None), "fixture");
    let expected = etag(&created);
    let keys = [
        rotate_key(70, &actor, &created),
        rotate_key(71, &actor, &created),
    ];
    let barrier = Barrier::new(2);
    let outcomes = std::thread::scope(|scope| {
        let writers = [(&db.provider, &keys[0]), (&second, &keys[1])].map(|(provider, key)| {
            let (barrier, created, expected) = (&barrier, &created, &expected);
            scope.spawn(move || {
                barrier.wait();
                rotate(provider, created, expected, b"contended", Some(key))
            })
        });
        writers.map(|writer| writer.join().expect("the writer finishes"))
    });
    let (winner, loser, lost) = match outcomes {
        [Ok(CallerOutcome::Committed(_)), lost] => (&keys[0], &keys[1], lost),
        [lost, Ok(CallerOutcome::Committed(_))] => (&keys[1], &keys[0], lost),
        other => panic!("one rotation must win: {other:?}"),
    };
    assert_eq!(lost, Err(LocalSecretError::PreconditionFailed));
    assert_eq!(rows_for(db.database(), winner), ["secret.rotate"]);
    assert!(rows_for(db.database(), loser).is_empty());
    let reserved: Vec<String> = reservations(db.database())
        .into_iter()
        .map(|(key, ..)| key)
        .collect();
    assert_eq!(reserved, [winner.id().to_string()]);
    assert_reservations_match_evidence(db.database());
}

/// Two requests that differ only in the secret value bind one digest: the
/// value is never an input of the binding.
#[test]
fn the_secret_value_never_enters_the_binding_digest() {
    let db = Opened::new("digest");
    let actor = operator();
    let first = create_key(80, &actor, "Digest");
    let second = create_key(80, &actor, "Digest");
    assert_eq!(first.binding_digest(), second.binding_digest());
    committed(
        create(&db.provider, "Digest", b"first-value", Some(&first)),
        "the keyed create",
    );
    let stored = reservations(db.database());
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].2.as_deref(), Some(second.binding_digest()));
    assert_reservations_match_evidence(db.database());
}

/// A retry of a keyed create or rotation that carries another value, while
/// the committed value is still current, is a conflict and keeps the stored
/// value; the same retry with the committed value is answered with the
/// receipt.
#[test]
fn a_different_value_under_the_same_key_conflicts_and_keeps_the_stored_value() {
    let db = Opened::new("value-mismatch");
    let actor = operator();
    let key = create_key(81, &actor, "Valued");
    let created = committed(
        create(&db.provider, "Valued", VALUE, Some(&key)),
        "the keyed create",
    );
    let before = (
        envelope(db.database(), &created.id),
        evidence(db.database()),
    );
    conflicts(
        create(&db.provider, "Valued", b"another-value", Some(&key)),
        "a create retry with another value",
    );
    assert_eq!(
        (
            envelope(db.database(), &created.id),
            evidence(db.database())
        ),
        before
    );
    assert_eq!(stored_value(&db.provider, &created.id), VALUE);
    replayed(
        create(&db.provider, "Valued", VALUE, Some(&key)),
        "the exact create retry",
    );

    let rotation = rotate_key(82, &actor, &created);
    let rotated = committed(
        rotate(
            &db.provider,
            &created,
            &etag(&created),
            b"rotated-value",
            Some(&rotation),
        ),
        "the keyed rotation",
    );
    let before = (
        envelope(db.database(), &rotated.id),
        evidence(db.database()),
    );
    conflicts(
        rotate(
            &db.provider,
            &created,
            &etag(&created),
            b"another-rotated-value",
            Some(&rotation),
        ),
        "a rotation retry with another value",
    );
    assert_eq!(
        (
            envelope(db.database(), &rotated.id),
            evidence(db.database())
        ),
        before
    );
    assert_eq!(stored_value(&db.provider, &rotated.id), b"rotated-value");
    replayed(
        rotate(
            &db.provider,
            &created,
            &etag(&created),
            b"rotated-value",
            Some(&rotation),
        ),
        "the exact rotation retry",
    );
    assert_reservations_match_evidence(db.database());
}

/// Once the secret has been rotated again or deleted, the value a keyed
/// create or rotation stored no longer exists and cannot be compared: the
/// retry gets the receipt, whose revision shows it is no longer current.
#[test]
fn a_replay_after_a_later_rotation_returns_the_superseded_receipt() {
    let db = Opened::new("superseded");
    let actor = operator();
    let key = create_key(83, &actor, "Superseded");
    let created = committed(
        create(&db.provider, "Superseded", VALUE, Some(&key)),
        "the keyed create",
    );
    let rotated = committed(
        rotate(
            &db.provider,
            &created,
            &etag(&created),
            b"later-value",
            None,
        ),
        "a later rotation",
    );
    assert_eq!(rotated.version, Some(2));
    for retried in [VALUE, b"a-value-nobody-stored".as_slice()] {
        let receipt = replayed(
            create(&db.provider, "Superseded", retried, Some(&key)),
            "the create retry after a later rotation",
        );
        assert_eq!(
            receipt.revision,
            Some(1),
            "the receipt names the superseded revision"
        );
    }
    committed(
        delete(&db.provider, &rotated, &etag(&rotated), None),
        "a later delete",
    );
    let receipt = replayed(
        create(&db.provider, "Superseded", b"after-delete", Some(&key)),
        "the create retry after the delete",
    );
    assert_eq!(
        (receipt.resource_id.as_str(), receipt.revision),
        (created.id.as_str(), Some(1))
    );
    assert_reservations_match_evidence(db.database());
}

const VALUE_MARKER: &str = "keyed-local-secret-value-marker";
const ROTATED_MARKER: &str = "keyed-local-secret-rotated-value-marker";

/// I5, store part: a marker in every secret-bearing request field (the
/// created and the rotated value) stays out of the reservations, the
/// receipts, every evidence column and the bytes of the SQLite file and its
/// WAL; the binding digest is stored only in the reservation row. The
/// ciphertext and nonce each change stored, read back from the secret's
/// row, reach no reservation, receipt or evidence column either.
#[test]
fn a_keyed_secret_change_keeps_synthetic_markers_out_of_the_reservation_receipt_evidence_and_file()
{
    let db = Opened::new("markers");
    let actor = operator();
    let create_key = create_key(90, &actor, "Marked");
    let created = committed(
        create(
            &db.provider,
            "Marked",
            VALUE_MARKER.as_bytes(),
            Some(&create_key),
        ),
        "the keyed create",
    );
    let mut sealed =
        crate::connections::test_support::stored_ciphertext_renderings(db.database(), &created.id);
    let rotation = rotate_key(91, &actor, &created);
    let rotated = committed(
        rotate(
            &db.provider,
            &created,
            &etag(&created),
            ROTATED_MARKER.as_bytes(),
            Some(&rotation),
        ),
        "the keyed rotation",
    );
    let rotated_sealed =
        crate::connections::test_support::stored_ciphertext_renderings(db.database(), &rotated.id);
    assert!(
        rotated_sealed.iter().all(|form| !sealed.contains(form)),
        "the rotation stored a fresh nonce and ciphertext"
    );
    sealed.extend(rotated_sealed);
    let receipts = [
        replayed(
            create(
                &db.provider,
                "Marked",
                VALUE_MARKER.as_bytes(),
                Some(&create_key),
            ),
            "the create retry",
        ),
        replayed(
            rotate(
                &db.provider,
                &created,
                &etag(&created),
                ROTATED_MARKER.as_bytes(),
                Some(&rotation),
            ),
            "the rotation retry",
        ),
    ];
    let deletion = delete_key(92, &actor, &rotated);
    committed(
        delete(&db.provider, &rotated, &etag(&rotated), Some(&deletion)),
        "the keyed delete",
    );

    let reservation_text = format!("{:?}", reservations(db.database()));
    let receipt_text = format!(
        "{receipts:?}{}",
        serde_json::to_string(&receipts).expect("the receipts serialize")
    );
    let evidence_text = evidence_text(db.database());
    for marker in [VALUE_MARKER, ROTATED_MARKER] {
        for (place, text) in [
            ("reservation", &reservation_text),
            ("receipt", &receipt_text),
            ("evidence", &evidence_text),
        ] {
            assert!(!text.contains(marker), "{marker} reached the {place}");
        }
    }
    for form in &sealed {
        for (place, text) in [
            ("reservation", &reservation_text),
            ("receipt", &receipt_text),
            ("evidence", &evidence_text),
        ] {
            assert!(
                !text.contains(form.as_str()),
                "a stored ciphertext or nonce reached the {place}"
            );
        }
    }
    for digest in [&create_key, &rotation, &deletion].map(CallerOperation::binding_digest) {
        assert!(reservation_text.contains(digest));
        assert!(!receipt_text.contains(digest), "a digest reached a receipt");
        assert!(
            !evidence_text.contains(digest),
            "a digest reached the evidence"
        );
        assert!(!format!("{create_key:?}{rotation:?}{deletion:?}").contains(digest));
    }

    let connection = Connection::open(db.database()).expect("the database opens");
    let mut files = Vec::new();
    for suffix in ["", "-wal"] {
        files.push(PathBuf::from(format!(
            "{}{suffix}",
            db.database().display()
        )));
    }
    let read_files = |files: &[PathBuf]| {
        for path in files {
            let Ok(bytes) = std::fs::read(path) else {
                continue;
            };
            for marker in [VALUE_MARKER, ROTATED_MARKER] {
                assert!(
                    !bytes
                        .windows(marker.len())
                        .any(|window| window == marker.as_bytes()),
                    "{marker} reached {}",
                    path.display()
                );
            }
        }
    };
    read_files(&files);
    connection
        .execute_batch("PRAGMA wal_checkpoint(FULL);")
        .expect("the checkpoint runs");
    read_files(&files);
    drop(connection);
    assert_reservations_match_evidence(db.database());
}
