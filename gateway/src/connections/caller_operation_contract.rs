//! The keyed Connection change contract (issue #425), written once and run
//! against both stores through [`ManagedConnectionStore`]: the standalone
//! SQLite store here, the PostgreSQL store in `pg_store_tests.rs`.
//!
//! A Connection create, replace or delete that carries a caller key reserves
//! the key in the change's own transaction and records it as the evidence's
//! operation ID. An exact retry is answered with the receipt read from that
//! evidence and changes nothing; any other use of the key is a conflict and
//! changes nothing. Every test ends by asserting I3 against its own database:
//! a Connection action's reservation exists exactly when an evidence row with
//! that operation ID and action exists.

use std::collections::BTreeSet;

use serde_json::json;
use uuid::Uuid;

use crate::auth::change_actor::ChangeActor;
use crate::authority_events::caller_operation::{
    test_caller_key, CallerOperation, CallerOperationBinding, CallerOutcome, OperationReceipt,
};

use super::managed_store::ManagedConnectionStore;
use super::model::ConnectionWrite;
use super::store::{ConnectionEtag, ConnectionStoreError, StoredConnection};

/// One evidence row: its operation ID, action and Connection ID.
pub(crate) type EvidenceRow = (String, String, String);
/// One reservation: its key, action and binding digest.
pub(crate) type Reservation = (String, String, Option<String>);

/// What the contract needs from a database besides the store under test.
#[allow(async_fn_in_trait)]
pub(crate) trait ContractDatabase {
    fn store(&self) -> &ManagedConnectionStore;
    /// Every Connection evidence row, in commit order.
    async fn evidence(&self) -> Vec<EvidenceRow>;
    /// Every reservation in the database.
    async fn reservations(&self) -> Vec<Reservation>;
    /// The text of every row of every table except the reservation table.
    async fn text_outside_reservations(&self) -> String;
    /// The text of every column of every Connection evidence row.
    async fn evidence_text(&self) -> String;
    /// Make every Connection evidence insert fail, or stop doing so.
    async fn fail_evidence_inserts(&self, fail: bool);
    /// Reserve `key` the way a keyed service-token revoke does: no digest.
    async fn reserve_for_a_keyed_revoke(&self, key: Uuid);
}

pub(crate) const ISSUER: &str = "https://keyed-connections.example.test";
pub(crate) const SECRET_MARKER: &str = "keyed-connection-secret-alias-marker";
/// One synthetic marker per credential reference a Connection body can
/// carry: the authentication alias, an additional header's alias, and the
/// TLS client certificate and private key aliases.
const REFERENCE_MARKERS: [&str; 4] = [
    SECRET_MARKER,
    "keyed-connection-header-alias-marker",
    "keyed-connection-tls-certificate-marker",
    "keyed-connection-tls-key-marker",
];

pub(crate) fn operator() -> ChangeActor {
    ChangeActor::for_test_with_issuer("keyed-connection-operator", ISSUER)
}

/// An HTTP Connection bound to `secret_id`.
pub(crate) fn candidate(display_name: &str, secret_id: &str) -> ConnectionWrite {
    serde_json::from_value(json!({
        "display_name": display_name,
        "enabled": false,
        "kind": "http_api",
        "endpoint": {"base_url": "https://keyed.example.test", "base_path": "/v1"},
        "authentication": {"type": "static_bearer", "secret_id": secret_id},
        "tls": {}
    }))
    .expect("the candidate deserializes")
}

/// The request bytes a key is bound to: the candidate as a handler sends it.
fn request(candidate: &ConnectionWrite) -> Vec<u8> {
    serde_json::to_vec(candidate).expect("the candidate serializes")
}

/// Key `seed` bound to one request.
pub(crate) fn keyed(
    seed: u8,
    action: &'static str,
    actor: &ChangeActor,
    target: &str,
    precondition: &str,
    request: &[u8],
) -> CallerOperation {
    CallerOperation::bind(
        test_caller_key(seed),
        &CallerOperationBinding {
            action,
            actor,
            target,
            precondition,
            request,
        },
    )
    .expect("the key binds")
}

fn create_key(seed: u8, actor: &ChangeActor, candidate: &ConnectionWrite) -> CallerOperation {
    keyed(
        seed,
        "connection.create",
        actor,
        "",
        "",
        &request(candidate),
    )
}

fn replace_key(
    seed: u8,
    actor: &ChangeActor,
    current: &StoredConnection,
    candidate: &ConnectionWrite,
) -> CallerOperation {
    keyed(
        seed,
        "connection.replace",
        actor,
        current.id.as_str(),
        current.etag().as_str(),
        &request(candidate),
    )
}

fn delete_key(seed: u8, actor: &ChangeActor, current: &StoredConnection) -> CallerOperation {
    keyed(
        seed,
        "connection.delete",
        actor,
        current.id.as_str(),
        current.etag().as_str(),
        b"",
    )
}

async fn create(
    db: &impl ContractDatabase,
    candidate: ConnectionWrite,
    caller: Option<&CallerOperation>,
) -> Result<CallerOutcome<StoredConnection>, ConnectionStoreError> {
    db.store()
        .create_with_operation(candidate, &operator(), None, caller)
        .await
}

async fn replace(
    db: &impl ContractDatabase,
    current: &StoredConnection,
    expected: &ConnectionEtag,
    candidate: ConnectionWrite,
    caller: Option<&CallerOperation>,
) -> Result<CallerOutcome<StoredConnection>, ConnectionStoreError> {
    db.store()
        .replace_with_operation(&current.id, expected, candidate, &operator(), caller)
        .await
}

async fn delete(
    db: &impl ContractDatabase,
    current: &StoredConnection,
    caller: Option<&CallerOperation>,
) -> Result<CallerOutcome<()>, ConnectionStoreError> {
    db.store()
        .delete_with_operation(&current.id, &current.etag(), &operator(), caller)
        .await
}

fn committed<T: std::fmt::Debug>(
    outcome: Result<CallerOutcome<T>, ConnectionStoreError>,
    what: &str,
) -> T {
    match outcome {
        Ok(CallerOutcome::Committed(value)) => value,
        other => panic!("{what} should commit: {other:?}"),
    }
}

fn replayed<T: std::fmt::Debug>(
    outcome: Result<CallerOutcome<T>, ConnectionStoreError>,
    what: &str,
) -> OperationReceipt {
    match outcome {
        Ok(CallerOutcome::Replayed(receipt)) => receipt,
        other => panic!("{what} should be answered from its receipt: {other:?}"),
    }
}

fn conflicts<T: std::fmt::Debug>(
    outcome: Result<CallerOutcome<T>, ConnectionStoreError>,
    what: &str,
) {
    assert!(
        matches!(outcome, Err(ConnectionStoreError::CallerOperationConflict)),
        "{what} should conflict: {outcome:?}"
    );
}

/// I3: a Connection action's reservation exists exactly when an evidence row
/// with that operation ID and action exists, for every caller key.
pub(crate) async fn assert_reservations_match_evidence(db: &impl ContractDatabase) {
    let reserved: BTreeSet<(String, String)> = db
        .reservations()
        .await
        .into_iter()
        .filter(|(_, action, _)| action.starts_with("connection."))
        .map(|(key, action, _)| (key, action))
        .collect();
    let evidenced: BTreeSet<(String, String)> = db
        .evidence()
        .await
        .into_iter()
        .filter(|(operation_id, action, _)| {
            action.starts_with("connection.")
                && Uuid::parse_str(operation_id).map(|id| id.get_version_num()) == Ok(7)
        })
        .map(|(operation_id, action, _)| (operation_id, action))
        .collect();
    assert_eq!(
        reserved, evidenced,
        "every keyed Connection change is reserved exactly when it is evidenced"
    );
}

/// The actions recorded under `key`, sorted: the two rows of one
/// replacement share a transaction, so their order is not theirs to keep.
async fn rows_for(db: &impl ContractDatabase, key: &CallerOperation) -> Vec<String> {
    let key = key.id().to_string();
    let mut actions: Vec<String> = db
        .evidence()
        .await
        .into_iter()
        .filter(|(operation_id, _, _)| *operation_id == key)
        .map(|(_, action, _)| action)
        .collect();
    actions.sort();
    actions
}

async fn count(db: &impl ContractDatabase) -> usize {
    db.store().count().await.expect("the store counts")
}

/// An exact retry of a keyed create, replace and delete is answered with the
/// receipt read from the committed evidence, and makes no second change and
/// no second evidence row. A replacement that advances the credential
/// revision records two rows under the one key; its receipt is the
/// replacement's. An unkeyed change still mints its own operation ID and
/// reserves nothing.
pub(crate) async fn connection_caller_operation_contract(db: &impl ContractDatabase) {
    let actor = operator();
    let first = candidate("Keyed API", "keyed-token");
    let create_op = create_key(1, &actor, &first);
    let created = committed(
        create(db, first.clone(), Some(&create_op)).await,
        "the keyed create",
    );
    assert_eq!(rows_for(db, &create_op).await, ["connection.create"]);
    let receipt = replayed(
        create(db, first.clone(), Some(&create_op)).await,
        "the retried create",
    );
    assert_eq!(receipt.operation_id, create_op.id().to_string());
    assert_eq!(receipt.operation, "connection.create");
    assert_eq!(receipt.resource_id, created.id.to_string());
    assert_eq!(receipt.revision, Some(1));
    assert!(!receipt.committed_at.is_empty());
    assert_eq!(count(db).await, 1, "the retry created nothing");
    assert_eq!(rows_for(db, &create_op).await, ["connection.create"]);

    let rebound = candidate("Keyed API", "keyed-token-next");
    let replace_op = replace_key(2, &actor, &created, &rebound);
    let updated = committed(
        replace(
            db,
            &created,
            &created.etag(),
            rebound.clone(),
            Some(&replace_op),
        )
        .await,
        "the keyed replace",
    );
    assert!(updated.revisions.credential > created.revisions.credential);
    assert_eq!(
        rows_for(db, &replace_op).await,
        ["connection.replace", "credential.binding_change"],
        "a credential-changing replacement records both rows under its one key"
    );
    let receipt = replayed(
        replace(
            db,
            &created,
            &created.etag(),
            rebound.clone(),
            Some(&replace_op),
        )
        .await,
        "the retried replace",
    );
    assert_eq!(receipt.operation, "connection.replace");
    assert_eq!(
        receipt.revision,
        Some(i64::try_from(updated.revisions.connection).unwrap())
    );
    assert_eq!(
        db.store()
            .get(&created.id)
            .await
            .expect("the store reads")
            .expect("the record exists"),
        updated,
        "the retry changed nothing"
    );

    let delete_op = delete_key(3, &actor, &updated);
    committed(
        delete(db, &updated, Some(&delete_op)).await,
        "the keyed delete",
    );
    let receipt = replayed(
        delete(db, &updated, Some(&delete_op)).await,
        "the retried delete",
    );
    assert_eq!(receipt.operation, "connection.delete");
    assert_eq!(receipt.resource_id, created.id.to_string());
    assert_eq!(
        receipt.revision,
        Some(i64::try_from(updated.revisions.connection).unwrap()),
        "a deletion's receipt carries the revision it removed"
    );
    assert_eq!(rows_for(db, &delete_op).await, ["connection.delete"]);
    assert_eq!(count(db).await, 0);

    let unkeyed = committed(
        create(db, candidate("Unkeyed API", "unkeyed-token"), None).await,
        "an unkeyed create",
    );
    let evidence = db.evidence().await;
    let (operation_id, _, _) = evidence
        .iter()
        .find(|(_, action, id)| action == "connection.create" && *id == unkeyed.id.to_string())
        .expect("the unkeyed create is evidenced");
    assert_eq!(
        Uuid::parse_str(operation_id).unwrap().get_version_num(),
        4,
        "an unkeyed change mints its own operation ID"
    );
    assert_eq!(
        db.reservations().await.len(),
        3,
        "only the three keyed changes reserved a key"
    );
    assert_reservations_match_evidence(db).await;
}

/// The same key with a different binding -- another body, target, actor or
/// precondition -- is a conflict, and nothing changes.
pub(crate) async fn a_reused_key_with_a_different_binding_conflicts_and_changes_nothing(
    db: &impl ContractDatabase,
) {
    let actor = operator();
    let original = candidate("Bound API", "bound-token");
    let create_op = create_key(10, &actor, &original);
    let created = committed(
        create(db, original.clone(), Some(&create_op)).await,
        "the keyed create",
    );
    let other = committed(
        create(db, candidate("Other API", "other-token"), None).await,
        "a second Connection",
    );
    let changed = candidate("Bound API", "bound-token-changed");
    conflicts(
        create(db, changed.clone(), Some(&create_key(10, &actor, &changed))).await,
        "the key over another body",
    );
    let stranger = ChangeActor::for_test_with_issuer("another-operator", ISSUER);
    conflicts(
        create(
            db,
            original.clone(),
            Some(&create_key(10, &stranger, &original)),
        )
        .await,
        "the key for another actor",
    );

    let replace_op = replace_key(11, &actor, &created, &changed);
    let replaced = committed(
        replace(
            db,
            &created,
            &created.etag(),
            changed.clone(),
            Some(&replace_op),
        )
        .await,
        "the keyed replace",
    );
    let bodies = candidate("Bound API", "bound-token-third");
    for (what, caller) in [
        ("another body", replace_key(11, &actor, &created, &bodies)),
        ("another target", replace_key(11, &actor, &other, &changed)),
        (
            "another actor",
            replace_key(11, &stranger, &created, &changed),
        ),
        (
            "another precondition",
            keyed(
                11,
                "connection.replace",
                &actor,
                created.id.as_str(),
                "\"another-etag\"",
                &request(&changed),
            ),
        ),
    ] {
        conflicts(
            replace(
                db,
                &replaced,
                &replaced.etag(),
                bodies.clone(),
                Some(&caller),
            )
            .await,
            what,
        );
    }
    assert_eq!(
        db.store().get(&created.id).await.unwrap().unwrap(),
        replaced,
        "no conflicting use changed the Connection"
    );
    assert_eq!(count(db).await, 2);
    assert_eq!(db.reservations().await.len(), 2);
    assert_reservations_match_evidence(db).await;
}

/// A key reserved by another action -- another Connection operation, or a
/// keyed service-token revoke in the same database -- cannot take effect
/// here.
pub(crate) async fn a_key_reserved_by_another_action_cannot_take_effect_here(
    db: &impl ContractDatabase,
) {
    let actor = operator();
    let first = candidate("Reserved API", "reserved-token");
    let create_op = create_key(20, &actor, &first);
    let created = committed(
        create(db, first.clone(), Some(&create_op)).await,
        "the keyed create",
    );
    let changed = candidate("Reserved API", "reserved-token-next");
    conflicts(
        replace(
            db,
            &created,
            &created.etag(),
            changed.clone(),
            Some(&replace_key(20, &actor, &created, &changed)),
        )
        .await,
        "the create's key on a replace",
    );
    conflicts(
        delete(db, &created, Some(&delete_key(20, &actor, &created))).await,
        "the create's key on a delete",
    );

    let revoke_key = test_caller_key(21);
    db.reserve_for_a_keyed_revoke(revoke_key).await;
    let fresh = candidate("Revoke API", "revoke-token");
    conflicts(
        create(db, fresh.clone(), Some(&create_key(21, &actor, &fresh))).await,
        "a keyed revoke's key on a create",
    );
    conflicts(
        delete(db, &created, Some(&delete_key(21, &actor, &created))).await,
        "a keyed revoke's key on a delete",
    );
    assert_eq!(count(db).await, 1, "nothing was created or deleted");
    assert_eq!(db.store().get(&created.id).await.unwrap().unwrap(), created);
    assert_reservations_match_evidence(db).await;
}

/// I1 and I2: a failed evidence insert rolls back the keyed create, replace
/// and delete together with their reservations, so the keys stay unused and
/// a later attempt with them commits.
pub(crate) async fn a_failed_evidence_insert_rolls_back_the_keyed_change_and_its_reservation(
    db: &impl ContractDatabase,
) {
    let actor = operator();
    let existing = committed(
        create(db, candidate("Faulted API", "faulted-token"), None).await,
        "the fixture",
    );
    let fresh = candidate("Faulted create", "faulted-create-token");
    let changed = candidate("Faulted API", "faulted-token-next");
    let create_op = create_key(30, &actor, &fresh);
    let replace_op = replace_key(31, &actor, &existing, &changed);
    let delete_op = delete_key(32, &actor, &existing);

    db.fail_evidence_inserts(true).await;
    let failures = [
        create(db, fresh.clone(), Some(&create_op))
            .await
            .map(|_| ()),
        replace(
            db,
            &existing,
            &existing.etag(),
            changed.clone(),
            Some(&replace_op),
        )
        .await
        .map(|_| ()),
        delete(db, &existing, Some(&delete_op)).await.map(|_| ()),
    ];
    db.fail_evidence_inserts(false).await;
    for failure in failures {
        let error = failure.expect_err("the change cannot commit without its evidence");
        assert!(
            !matches!(
                error,
                ConnectionStoreError::CallerOperationConflict
                    | ConnectionStoreError::Validation { .. }
                    | ConnectionStoreError::Conflict { .. }
            ),
            "an evidence failure is a store failure: {error:?}"
        );
    }
    assert!(db.reservations().await.is_empty(), "no key stayed reserved");
    assert_eq!(count(db).await, 1);
    assert_eq!(
        db.store().get(&existing.id).await.unwrap().unwrap(),
        existing
    );
    assert_reservations_match_evidence(db).await;

    let updated = committed(
        replace(db, &existing, &existing.etag(), changed, Some(&replace_op)).await,
        "the same keyed replace once evidence is writable",
    );
    committed(
        create(db, fresh, Some(&create_op)).await,
        "the same keyed create once evidence is writable",
    );
    assert_eq!(rows_for(db, &replace_op).await.len(), 2);
    assert_ne!(updated, existing);
    assert_reservations_match_evidence(db).await;
}

/// A stale ETag under a key writes no change, no evidence and no
/// reservation.
pub(crate) async fn a_stale_etag_under_a_key_writes_no_change_evidence_or_reservation(
    db: &impl ContractDatabase,
) {
    let actor = operator();
    let created = committed(
        create(db, candidate("Stale API", "stale-token"), None).await,
        "the fixture",
    );
    let moved = committed(
        replace(
            db,
            &created,
            &created.etag(),
            candidate("Stale API moved", "stale-token"),
            None,
        )
        .await,
        "the unkeyed replace",
    );
    let evidence = db.evidence().await;
    let changed = candidate("Stale API", "stale-token-next");
    let stale = replace(
        db,
        &created,
        &created.etag(),
        changed.clone(),
        Some(&replace_key(40, &actor, &created, &changed)),
    )
    .await;
    assert!(
        matches!(stale, Err(ConnectionStoreError::Conflict { .. })),
        "{stale:?}"
    );
    let stale = delete(db, &created, Some(&delete_key(41, &actor, &created))).await;
    assert!(
        matches!(stale, Err(ConnectionStoreError::Conflict { .. })),
        "{stale:?}"
    );
    assert_eq!(db.evidence().await, evidence);
    assert!(db.reservations().await.is_empty());
    assert_eq!(db.store().get(&created.id).await.unwrap().unwrap(), moved);
    assert_reservations_match_evidence(db).await;
}

/// An identical keyed replacement changes nothing, so it records nothing and
/// reserves nothing; its key stays free for a real change.
pub(crate) async fn an_identical_keyed_replace_records_and_reserves_nothing(
    db: &impl ContractDatabase,
) {
    let actor = operator();
    let same = candidate("Identical API", "identical-token");
    let created = committed(create(db, same.clone(), None).await, "the fixture");
    let evidence = db.evidence().await;
    let identical = replace_key(50, &actor, &created, &same);
    let unchanged = committed(
        replace(db, &created, &created.etag(), same, Some(&identical)).await,
        "the identical replace",
    );
    assert_eq!(unchanged, created);
    assert_eq!(db.evidence().await, evidence, "nothing recorded");
    assert!(db.reservations().await.is_empty(), "nothing reserved");
    assert_reservations_match_evidence(db).await;
}

/// Two writers racing one key and one binding commit one change: the other
/// is answered from the winner's receipt. Two keys racing one revision leave
/// only the winner's rows.
pub(crate) async fn two_writers_racing_one_key_commit_one_change(db: &impl ContractDatabase) {
    let actor = operator();
    let raced = candidate("Raced API", "raced-token");
    let key = create_key(60, &actor, &raced);
    let (left, right) = tokio::join!(
        create(db, raced.clone(), Some(&key)),
        create(db, raced.clone(), Some(&key))
    );
    let outcomes = [left, right];
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
    assert_eq!(count(db).await, 1);
    assert_eq!(rows_for(db, &key).await, ["connection.create"]);
    assert_reservations_match_evidence(db).await;
}

pub(crate) async fn two_keys_racing_one_revision_leave_only_the_winners_rows(
    db: &impl ContractDatabase,
) {
    let actor = operator();
    let created = committed(
        create(db, candidate("Contended API", "contended-token"), None).await,
        "the fixture",
    );
    let left_candidate = candidate("Contended API", "contended-left");
    let right_candidate = candidate("Contended API", "contended-right");
    let left_key = replace_key(70, &actor, &created, &left_candidate);
    let right_key = replace_key(71, &actor, &created, &right_candidate);
    let etag = created.etag();
    let (left, right) = tokio::join!(
        replace(db, &created, &etag, left_candidate, Some(&left_key)),
        replace(db, &created, &etag, right_candidate, Some(&right_key))
    );
    let (winner, loser, lost) = match (left, right) {
        (Ok(CallerOutcome::Committed(_)), lost) => (&left_key, &right_key, lost),
        (lost, Ok(CallerOutcome::Committed(_))) => (&right_key, &left_key, lost),
        other => panic!("one replacement must win: {other:?}"),
    };
    assert!(
        matches!(lost, Err(ConnectionStoreError::Conflict { .. })),
        "the other loses on its ETag: {lost:?}"
    );
    assert_eq!(rows_for(db, winner).await.len(), 2);
    assert!(rows_for(db, loser).await.is_empty());
    let reserved: Vec<String> = db
        .reservations()
        .await
        .into_iter()
        .map(|(key, _, _)| key)
        .collect();
    assert_eq!(reserved, [winner.id().to_string()]);
    assert_reservations_match_evidence(db).await;
}

/// A Connection whose every credential reference names a synthetic marker,
/// each suffixed with `suffix`.
fn marked_candidate(suffix: &str) -> ConnectionWrite {
    let [authentication, header, certificate, private_key] =
        REFERENCE_MARKERS.map(|marker| format!("{marker}{suffix}"));
    serde_json::from_value(json!({
        "display_name": "Marked API",
        "enabled": false,
        "kind": "http_api",
        "endpoint": {"base_url": "https://keyed.example.test", "base_path": "/v1"},
        "authentication": {"type": "static_bearer", "secret_id": authentication},
        "additional_headers": [{"header_name": "x-proxy-token", "secret_id": header}],
        "tls": {"client_certificate_id": certificate, "client_private_key_id": private_key}
    }))
    .expect("the marked candidate deserializes")
}

/// The references a delegated-issuer Connection carries instead of the ones
/// above: its client secret alias and its caller-assertion signing key alias.
const DELEGATED_MARKERS: [&str; 2] = [
    "keyed-connection-client-secret-alias-marker",
    "keyed-connection-caller-assertion-key-marker",
];

/// A delegated-issuer Connection whose client secret and caller-assertion
/// signing key aliases are [`DELEGATED_MARKERS`].
fn delegated_marked_candidate() -> ConnectionWrite {
    let [client_secret, signing_key] = DELEGATED_MARKERS;
    serde_json::from_value(json!({
        "display_name": "Marked API",
        "enabled": false,
        "kind": "http_api",
        "endpoint": {"base_url": "https://keyed.example.test", "base_path": "/v1"},
        "authentication": {
            "type": "delegated_issuer_token",
            "token_exchange_url": "https://keyed.example.test/oauth2/token-exchange",
            "client_id": "greengateway",
            "client_secret_id": client_secret,
            "subject_token_source": "caller_assertion"
        },
        "caller_assertion": {
            "signing_key_id": signing_key,
            "kid": "keyed-2026-11",
            "algorithm": "es256",
            "issuer": "https://gateway.keyed.example.test",
            "audience": "https://keyed.example.test",
            "token_type": "caller-assertion+jwt",
            "header_name": "x-caller-assertion",
            "lifetime_seconds": 60
        }
    }))
    .expect("the delegated marked candidate deserializes")
}

/// I5: the binding digest is stored only in the reservation row, and the
/// credential references the request names (one synthetic marker in each
/// reference field) stay out of the receipts and of every column of the
/// evidence, for a create, for a replacement that changes every reference,
/// and for a replacement to a delegated-issuer body that names a client
/// secret and a caller-assertion signing key; they are stored only where the
/// Connection itself keeps its binding.
pub(crate) async fn the_binding_digest_is_stored_only_in_the_reservation_row(
    db: &impl ContractDatabase,
) {
    let actor = operator();
    let marked = marked_candidate("");
    let create_op = create_key(80, &actor, &marked);
    let created = committed(
        create(db, marked.clone(), Some(&create_op)).await,
        "the keyed create",
    );
    let receipt = replayed(
        create(db, marked, Some(&create_op)).await,
        "the retried create",
    );
    let remarked = marked_candidate("-next");
    let replace_op = replace_key(81, &actor, &created, &remarked);
    let replaced = committed(
        replace(
            db,
            &created,
            &created.etag(),
            remarked.clone(),
            Some(&replace_op),
        )
        .await,
        "the keyed replace",
    );
    let replace_receipt = replayed(
        replace(db, &created, &created.etag(), remarked, Some(&replace_op)).await,
        "the retried replace",
    );
    assert_eq!(
        rows_for(db, &replace_op).await,
        ["connection.replace", "credential.binding_change"]
    );
    // The client secret and caller-assertion key aliases, the reference
    // fields a bearer body cannot carry.
    let delegated = delegated_marked_candidate();
    let delegated_op = replace_key(82, &actor, &replaced, &delegated);
    committed(
        replace(
            db,
            &replaced,
            &replaced.etag(),
            delegated.clone(),
            Some(&delegated_op),
        )
        .await,
        "the keyed delegated-issuer replace",
    );
    let delegated_receipt = replayed(
        replace(
            db,
            &replaced,
            &replaced.etag(),
            delegated,
            Some(&delegated_op),
        )
        .await,
        "the retried delegated-issuer replace",
    );
    assert_eq!(
        rows_for(db, &delegated_op).await,
        ["connection.replace", "credential.binding_change"]
    );
    let digests = [
        create_op.binding_digest().to_owned(),
        replace_op.binding_digest().to_owned(),
        delegated_op.binding_digest().to_owned(),
    ];
    let mut reserved = db.reservations().await;
    reserved.sort();
    let mut expected = vec![
        (
            create_op.id().to_string(),
            "connection.create".to_owned(),
            Some(digests[0].clone()),
        ),
        (
            replace_op.id().to_string(),
            "connection.replace".to_owned(),
            Some(digests[1].clone()),
        ),
        (
            delegated_op.id().to_string(),
            "connection.replace".to_owned(),
            Some(digests[2].clone()),
        ),
    ];
    expected.sort();
    assert_eq!(reserved, expected);
    let receipts = [&receipt, &replace_receipt, &delegated_receipt]
        .map(|receipt| serde_json::to_string(receipt).expect("the receipt serializes"))
        .concat();
    let outside = db.text_outside_reservations().await;
    let evidence = db.evidence_text().await;
    assert!(!evidence.is_empty(), "the evidence rows were read");
    for digest in &digests {
        assert!(
            !receipts.contains(digest.as_str()),
            "a digest reached a receipt"
        );
        assert!(
            !outside.contains(digest.as_str()),
            "a digest is stored outside the reservation"
        );
    }
    // Each marker is a prefix of its `-next` form too.
    for marker in REFERENCE_MARKERS.into_iter().chain(DELEGATED_MARKERS) {
        assert!(!receipts.contains(marker), "{marker} reached a receipt");
        assert!(!evidence.contains(marker), "{marker} reached the evidence");
    }
    for key in [&create_op, &replace_op, &delegated_op] {
        assert!(
            !format!("{key:?}").contains(key.binding_digest()),
            "a key's Debug never shows its digest"
        );
    }
    assert_reservations_match_evidence(db).await;
}

/// The standalone store runs the contract on its own Connections database.
mod sqlite {
    use std::path::PathBuf;

    use rusqlite::Connection;

    use super::*;
    use crate::connections::store::SqliteConnectionStore;

    struct SqliteDatabase {
        path: PathBuf,
        store: ManagedConnectionStore,
    }

    impl SqliteDatabase {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-keyed-connections-{name}-{}.sqlite",
                Uuid::new_v4()
            ));
            let store = SqliteConnectionStore::open(&path).expect("the store opens");
            Self {
                path,
                store: ManagedConnectionStore::Sqlite(store),
            }
        }

        fn open(&self) -> Connection {
            Connection::open(&self.path).expect("the database opens")
        }
    }

    impl Drop for SqliteDatabase {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_file(format!("{}-wal", self.path.display()));
            let _ = std::fs::remove_file(format!("{}-shm", self.path.display()));
        }
    }

    impl ContractDatabase for SqliteDatabase {
        fn store(&self) -> &ManagedConnectionStore {
            &self.store
        }

        async fn evidence(&self) -> Vec<EvidenceRow> {
            let connection = self.open();
            let mut statement = connection
                .prepare(
                    "SELECT operation_id, action, connection_id \
                     FROM connection_change_evidence ORDER BY sequence",
                )
                .unwrap();
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        }

        async fn reservations(&self) -> Vec<Reservation> {
            let connection = self.open();
            let mut statement = connection
                .prepare(
                    "SELECT operation_id, action, binding_digest \
                     FROM authority_caller_operation_ids ORDER BY operation_id",
                )
                .unwrap();
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        }

        async fn text_outside_reservations(&self) -> String {
            let connection = self.open();
            let tables: Vec<String> = connection
                .prepare(
                    "SELECT name FROM sqlite_master WHERE type = 'table' \
                     AND name <> 'authority_caller_operation_ids'",
                )
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            let mut text = String::new();
            for table in tables {
                let mut statement = connection
                    .prepare(&format!("SELECT * FROM \"{table}\""))
                    .unwrap();
                let columns = statement.column_count();
                let mut rows = statement.query([]).unwrap();
                while let Some(row) = rows.next().unwrap() {
                    for index in 0..columns {
                        text.push_str(&format!("{:?}|", row.get_ref(index).unwrap()));
                    }
                }
            }
            text
        }

        async fn evidence_text(&self) -> String {
            let connection = self.open();
            let mut statement = connection
                .prepare("SELECT * FROM connection_change_evidence")
                .unwrap();
            let columns = statement.column_count();
            let mut rows = statement.query([]).unwrap();
            let mut text = String::new();
            while let Some(row) = rows.next().unwrap() {
                for index in 0..columns {
                    text.push_str(&format!("{:?}|", row.get_ref(index).unwrap()));
                }
            }
            text
        }

        async fn fail_evidence_inserts(&self, fail: bool) {
            let statement = if fail {
                "CREATE TRIGGER fail_connection_change_evidence \
                 BEFORE INSERT ON connection_change_evidence \
                 BEGIN SELECT RAISE(ABORT, 'injected evidence failure'); END;"
            } else {
                "DROP TRIGGER fail_connection_change_evidence;"
            };
            self.open().execute_batch(statement).unwrap();
        }

        async fn reserve_for_a_keyed_revoke(&self, key: Uuid) {
            assert!(
                crate::storage::standalone_authority_events::reserve_unbound_operation(
                    &self.open(),
                    key,
                    "service_token.revoke",
                )
                .unwrap()
            );
        }
    }

    #[tokio::test]
    async fn sqlite_connection_caller_operation_contract() {
        connection_caller_operation_contract(&SqliteDatabase::new("contract")).await;
    }

    #[tokio::test]
    async fn sqlite_a_reused_key_with_a_different_binding_conflicts_and_changes_nothing() {
        a_reused_key_with_a_different_binding_conflicts_and_changes_nothing(&SqliteDatabase::new(
            "binding",
        ))
        .await;
    }

    #[tokio::test]
    async fn sqlite_a_key_reserved_by_another_action_cannot_take_effect_here() {
        a_key_reserved_by_another_action_cannot_take_effect_here(&SqliteDatabase::new(
            "other-action",
        ))
        .await;
    }

    #[tokio::test]
    async fn sqlite_a_failed_evidence_insert_rolls_back_the_keyed_change_and_its_reservation() {
        a_failed_evidence_insert_rolls_back_the_keyed_change_and_its_reservation(
            &SqliteDatabase::new("fault"),
        )
        .await;
    }

    #[tokio::test]
    async fn sqlite_a_stale_etag_under_a_key_writes_no_change_evidence_or_reservation() {
        a_stale_etag_under_a_key_writes_no_change_evidence_or_reservation(&SqliteDatabase::new(
            "stale",
        ))
        .await;
    }

    #[tokio::test]
    async fn sqlite_an_identical_keyed_replace_records_and_reserves_nothing() {
        an_identical_keyed_replace_records_and_reserves_nothing(&SqliteDatabase::new("identical"))
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sqlite_two_writers_racing_one_key_commit_one_change() {
        two_writers_racing_one_key_commit_one_change(&SqliteDatabase::new("race-key")).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sqlite_two_keys_racing_one_revision_leave_only_the_winners_rows() {
        two_keys_racing_one_revision_leave_only_the_winners_rows(&SqliteDatabase::new(
            "race-revision",
        ))
        .await;
    }

    #[tokio::test]
    async fn sqlite_the_binding_digest_is_stored_only_in_the_reservation_row() {
        the_binding_digest_is_stored_only_in_the_reservation_row(&SqliteDatabase::new("digest"))
            .await;
    }

    /// I2: a reservation that cannot be written rolls the keyed change back
    /// and is counted on the standalone evidence failure counter, as a
    /// failed evidence insert is. The store is called directly so that it
    /// runs on this thread, where this thread's recorder sees it.
    #[test]
    fn sqlite_a_failed_reservation_rolls_back_the_keyed_change_and_is_counted() {
        use crate::connections::store::ConnectionStore;

        let db = SqliteDatabase::new("reservation-fault");
        let store = SqliteConnectionStore::open(&db.path).expect("the store opens");
        let recorder = crate::audit::sink::tests::CountingRecorder::default();
        let _recording = ::metrics::set_default_local_recorder(&recorder);
        let failures = || {
            recorder.count(
                crate::metrics::STANDALONE_EVIDENCE_FAILURES_TOTAL,
                &[("store", "connections")],
            )
        };
        // Test-only fault injection through a second connection.
        db.open()
            .execute_batch(
                "CREATE TRIGGER fail_caller_key_reservation \
                 BEFORE INSERT ON authority_caller_operation_ids \
                 BEGIN SELECT RAISE(ABORT, 'injected reservation failure'); END;",
            )
            .expect("the fault installs");
        let actor = operator();
        let fresh = candidate("Unreserved API", "unreserved-token");
        let key = create_key(90, &actor, &fresh);
        let outcome = store.create_with_operation(fresh.clone(), &actor, Some(&key));
        assert!(
            matches!(outcome, Err(ConnectionStoreError::Unavailable { .. })),
            "{outcome:?}"
        );
        assert_eq!(failures(), 1);
        assert!(ConnectionStore::list(&store).expect("lists").is_empty());
        let evidence: i64 = db
            .open()
            .query_row(
                "SELECT COUNT(*) FROM connection_change_evidence",
                [],
                |row| row.get(0),
            )
            .expect("evidence counts");
        assert_eq!(evidence, 0, "the change and its evidence rolled back");

        // An unkeyed change reserves nothing and counts nothing.
        committed(
            store.create_with_operation(fresh, &actor, None),
            "the unkeyed create",
        );
        assert_eq!(failures(), 1);
    }
}
