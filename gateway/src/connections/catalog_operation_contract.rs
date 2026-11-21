//! The keyed catalog publication contract (issue #425, P7), written once and
//! run against both stores through [`ManagedConnectionStore`]: the standalone
//! SQLite store here, the PostgreSQL store in `pg_store_tests.rs`.
//!
//! An MCP catalog publication, an OpenAPI registration or refresh, and an
//! overlay put or delete that carry a caller key reserve the key in the
//! publication's own transaction and record it as the catalog evidence row's
//! operation ID. An exact retry is answered with the receipt read from that
//! row and changes nothing; any other use of the key is a conflict and
//! changes nothing. Every test ends by asserting I3 against its own database:
//! a catalog action's reservation exists exactly when a catalog evidence row
//! with that operation ID and action exists.
//!
//! A catalog publication always advances the catalog revision, so it has no
//! no-op form and no no-op test.

use std::collections::BTreeSet;

use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::change_actor::ChangeActor;
use crate::authority_events::caller_operation::{
    test_caller_key, CallerOperation, CallerOutcome, OperationReceipt,
};

use super::caller_operation_contract::{keyed, operator, ContractDatabase};
use super::model::ConnectionWrite;
use super::store::{
    ConnectionStoreError, StoredConnection, StoredMcpCatalog, StoredOpenApiCatalog,
    StoredOverlayWrite,
};

pub(crate) const MCP_PUBLISH: &str = "catalog.mcp.publish";
pub(crate) const OPENAPI_PUBLISH: &str = "catalog.openapi.publish";
pub(crate) const OVERLAY_REPLACE: &str = "catalog.overlay.replace";
pub(crate) const OVERLAY_DELETE: &str = "catalog.overlay.delete";

pub(crate) const SPEC: &str =
    r#"{"openapi":"3.1.0","info":{"title":"Keyed catalog","version":"1"}}"#;
const EMPTY_SOURCE_REPORTS: &str = r#"{"schema_version":"0.1.0","sources":[]}"#;
/// Synthetic markers for the request fields a catalog change binds: the
/// overlay document a put carries.
const OVERLAY_MARKERS: [&str; 2] = [
    "keyed-catalog-overlay-description-marker",
    "keyed-catalog-overlay-title-marker",
];

/// A managed MCP Connection named `display_name`.
pub(crate) fn mcp_candidate(display_name: &str) -> ConnectionWrite {
    serde_json::from_value(json!({
        "display_name": display_name,
        "enabled": true,
        "kind": "mcp_streamable_http",
        "endpoint": {"base_url": "https://keyed-mcp.example.test", "base_path": "/mcp"},
        "authentication": {"type": "none"},
        "tls": {},
        "discovery": {"type": "managed_mcp", "use_connection_authentication": false}
    }))
    .expect("the MCP candidate deserializes")
}

/// A managed OpenAPI Connection named `display_name`.
pub(crate) fn openapi_candidate(display_name: &str) -> ConnectionWrite {
    serde_json::from_value(json!({
        "display_name": display_name,
        "enabled": false,
        "kind": "http_api",
        "endpoint": {"base_url": "https://keyed-openapi.example.test", "base_path": "/v1"},
        "authentication": {"type": "static_bearer", "secret_id": "keyed-openapi-token"},
        "tls": {},
        "discovery": {
            "type": "managed_openapi",
            "path": "/openapi.json",
            "use_connection_authentication": true
        }
    }))
    .expect("the OpenAPI candidate deserializes")
}

pub(crate) fn spec_digest() -> String {
    hex::encode(Sha256::digest(SPEC.as_bytes()))
}

/// An overlay document; `description` lands in its only text field.
pub(crate) fn overlay_document(description: &str) -> String {
    json!({
        "schema_version": "0.1.0",
        "tools": {},
        "description": description
    })
    .to_string()
}

/// A key bound to an MCP publication of `connection` at its ETag.
pub(crate) fn mcp_key(
    seed: u8,
    actor: &ChangeActor,
    connection: &StoredConnection,
) -> CallerOperation {
    keyed(
        seed,
        MCP_PUBLISH,
        actor,
        connection.id.as_str(),
        connection.etag().as_str(),
        b"",
    )
}

/// A key bound to an OpenAPI registration of `connection` at its ETag.
pub(crate) fn openapi_key(
    seed: u8,
    actor: &ChangeActor,
    connection: &StoredConnection,
) -> CallerOperation {
    keyed(
        seed,
        OPENAPI_PUBLISH,
        actor,
        connection.id.as_str(),
        connection.etag().as_str(),
        SPEC.as_bytes(),
    )
}

/// A key bound to an overlay put of `document` over overlay revision
/// `overlay_revision` (the `If-Match` value is in the binding).
pub(crate) fn overlay_put_key(
    seed: u8,
    actor: &ChangeActor,
    connection: &StoredConnection,
    overlay_revision: u64,
    document: &str,
) -> CallerOperation {
    keyed(
        seed,
        OVERLAY_REPLACE,
        actor,
        connection.id.as_str(),
        &format!("\"overlay-{overlay_revision}\""),
        document.as_bytes(),
    )
}

/// A key bound to an overlay delete over overlay revision `overlay_revision`.
pub(crate) fn overlay_delete_key(
    seed: u8,
    actor: &ChangeActor,
    connection: &StoredConnection,
    overlay_revision: u64,
) -> CallerOperation {
    keyed(
        seed,
        OVERLAY_DELETE,
        actor,
        connection.id.as_str(),
        &format!("\"overlay-{overlay_revision}\""),
        b"",
    )
}

pub(crate) async fn create(
    db: &impl ContractDatabase,
    candidate: ConnectionWrite,
) -> StoredConnection {
    db.store()
        .create(candidate, &operator(), None)
        .await
        .expect("the fixture Connection creates")
}

/// Publish an empty MCP catalog over catalog revision `expected`.
pub(crate) async fn publish_mcp(
    db: &impl ContractDatabase,
    connection: &StoredConnection,
    expected: u64,
    caller: Option<&CallerOperation>,
) -> Result<CallerOutcome<StoredMcpCatalog>, ConnectionStoreError> {
    db.store()
        .replace_mcp_catalog_with_operation(
            &connection.id,
            &connection.etag(),
            &[],
            &[],
            &[],
            expected,
            &operator(),
            caller,
        )
        .await
}

/// Publish the OpenAPI catalog over spec and catalog revisions `spec` and
/// `catalog`, with `overlay` and the overlay revision it compiles to.
pub(crate) async fn publish_openapi(
    db: &impl ContractDatabase,
    connection: &StoredConnection,
    (spec, catalog): (u64, u64),
    overlay: Option<&StoredOverlayWrite>,
    compiled_overlay_revision: u64,
    caller: Option<&CallerOperation>,
) -> Result<CallerOutcome<StoredOpenApiCatalog>, ConnectionStoreError> {
    db.store()
        .replace_openapi_catalog_with_overlay_and_enum_values_with_operation(
            &connection.id,
            &connection.etag(),
            spec,
            catalog,
            SPEC,
            &spec_digest(),
            &[],
            overlay,
            compiled_overlay_revision,
            &operator(),
            &[],
            &[],
            caller,
        )
        .await
}

pub(crate) fn overlay_put(document: &str, expected_overlay_revision: u64) -> StoredOverlayWrite {
    StoredOverlayWrite::Put {
        schema_version: "0.1.0".to_owned(),
        overlay_json: document.to_owned(),
        source_reports_json: EMPTY_SOURCE_REPORTS.to_owned(),
        expected_overlay_revision,
    }
}

pub(crate) fn overlay_delete(expected_overlay_revision: u64) -> StoredOverlayWrite {
    StoredOverlayWrite::Delete {
        expected_overlay_revision,
    }
}

/// An OpenAPI Connection with its catalog registered unkeyed: spec and
/// catalog revision 1, no overlay.
pub(crate) async fn registered(db: &impl ContractDatabase, display_name: &str) -> StoredConnection {
    let connection = create(db, openapi_candidate(display_name)).await;
    committed(
        publish_openapi(db, &connection, (0, 0), None, 0, None).await,
        "the fixture registration",
    );
    connection
}

pub(crate) fn committed<T: std::fmt::Debug>(
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

/// I3 for catalogs: a catalog action's reservation exists exactly when a
/// catalog evidence row with that operation ID and action exists.
pub(crate) async fn assert_catalog_reservations_match_evidence(db: &impl ContractDatabase) {
    let reserved: BTreeSet<(String, String)> = db
        .reservations()
        .await
        .into_iter()
        .filter(|(_, action, _)| action.starts_with("catalog."))
        .map(|(key, action, _)| (key, action))
        .collect();
    let evidenced: BTreeSet<(String, String)> = db
        .catalog_evidence()
        .await
        .into_iter()
        .filter(|(operation_id, action, _)| {
            action.starts_with("catalog.")
                && Uuid::parse_str(operation_id).map(|id| id.get_version_num()) == Ok(7)
        })
        .map(|(operation_id, action, _)| (operation_id, action))
        .collect();
    assert_eq!(
        reserved, evidenced,
        "every keyed catalog publication is reserved exactly when it is evidenced"
    );
}

/// The catalog actions recorded under `key`.
async fn rows_for(db: &impl ContractDatabase, key: &CallerOperation) -> Vec<String> {
    let key = key.id().to_string();
    db.catalog_evidence()
        .await
        .into_iter()
        .filter(|(operation_id, _, _)| *operation_id == key)
        .map(|(_, action, _)| action)
        .collect()
}

fn assert_receipt(
    receipt: &OperationReceipt,
    key: &CallerOperation,
    connection: &StoredConnection,
    revision: u64,
) {
    assert_eq!(receipt.operation_id, key.id().to_string());
    assert_eq!(receipt.operation, key.action());
    assert_eq!(receipt.resource_id, connection.id.to_string());
    assert_eq!(receipt.revision, Some(i64::try_from(revision).unwrap()));
    assert!(!receipt.committed_at.is_empty());
}

/// An exact retry of a keyed MCP publication, OpenAPI registration, overlay
/// put and overlay delete is answered with the receipt read from the
/// committed catalog evidence -- the catalog revision it published -- even
/// though the revision it expected has since moved, and makes no second
/// publication and no second evidence row. An unkeyed publication still
/// mints its own operation ID and reserves nothing.
pub(crate) async fn catalog_caller_operation_contract(db: &impl ContractDatabase) {
    let actor = operator();
    let mcp = create(db, mcp_candidate("Keyed MCP")).await;
    let mcp_op = mcp_key(1, &actor, &mcp);
    let published = committed(
        publish_mcp(db, &mcp, 0, Some(&mcp_op)).await,
        "the keyed MCP publication",
    );
    assert_eq!(published.catalog_revision, 1);
    let receipt = replayed(
        publish_mcp(db, &mcp, 0, Some(&mcp_op)).await,
        "the retried MCP publication",
    );
    assert_receipt(&receipt, &mcp_op, &mcp, 1);
    assert_eq!(rows_for(db, &mcp_op).await, [MCP_PUBLISH]);
    assert_eq!(
        db.store()
            .mcp_catalog(&mcp.id)
            .await
            .unwrap()
            .expect("the catalog exists")
            .catalog_revision,
        1,
        "the retry published nothing"
    );

    let api = create(db, openapi_candidate("Keyed OpenAPI")).await;
    let register_op = openapi_key(2, &actor, &api);
    let registered = committed(
        publish_openapi(db, &api, (0, 0), None, 0, Some(&register_op)).await,
        "the keyed registration",
    );
    assert_eq!(registered.catalog_revision, 1);
    let receipt = replayed(
        publish_openapi(db, &api, (0, 0), None, 0, Some(&register_op)).await,
        "the retried registration",
    );
    assert_receipt(&receipt, &register_op, &api, 1);
    assert_eq!(rows_for(db, &register_op).await, [OPENAPI_PUBLISH]);

    let document = overlay_document("keyed overlay");
    let put_op = overlay_put_key(3, &actor, &api, 0, &document);
    let put = overlay_put(&document, 0);
    let overlaid = committed(
        publish_openapi(db, &api, (1, 1), Some(&put), 1, Some(&put_op)).await,
        "the keyed overlay put",
    );
    assert_eq!(
        (overlaid.catalog_revision, overlaid.overlay_revision),
        (2, 1)
    );
    let receipt = replayed(
        publish_openapi(db, &api, (1, 1), Some(&put), 1, Some(&put_op)).await,
        "the retried overlay put",
    );
    assert_receipt(&receipt, &put_op, &api, 2);
    assert_eq!(rows_for(db, &put_op).await, [OVERLAY_REPLACE]);

    let delete_op = overlay_delete_key(4, &actor, &api, 1);
    let delete = overlay_delete(1);
    let removed = committed(
        publish_openapi(db, &api, (1, 2), Some(&delete), 0, Some(&delete_op)).await,
        "the keyed overlay delete",
    );
    assert_eq!((removed.catalog_revision, removed.overlay_revision), (3, 0));
    let receipt = replayed(
        publish_openapi(db, &api, (1, 2), Some(&delete), 0, Some(&delete_op)).await,
        "the retried overlay delete",
    );
    assert_receipt(&receipt, &delete_op, &api, 3);
    assert_eq!(rows_for(db, &delete_op).await, [OVERLAY_DELETE]);
    let stored = db
        .store()
        .openapi_catalog(&api.id)
        .await
        .unwrap()
        .expect("the catalog exists");
    assert_eq!(
        (stored.catalog_revision, stored.overlay_revision),
        (3, 0),
        "no retry published anything"
    );

    committed(
        publish_mcp(db, &mcp, 1, None).await,
        "an unkeyed MCP publication",
    );
    let evidence = db.catalog_evidence().await;
    let (operation_id, _, _) = evidence
        .last()
        .expect("the unkeyed publication is evidenced");
    assert_eq!(
        Uuid::parse_str(operation_id).unwrap().get_version_num(),
        4,
        "an unkeyed publication mints its own operation ID"
    );
    assert_eq!(evidence.len(), 5, "one row per publication, none per retry");
    assert_eq!(
        db.reservations().await.len(),
        4,
        "only the four keyed publications reserved a key"
    );
    assert_catalog_reservations_match_evidence(db).await;
}

/// The same key with a different binding -- another target, precondition,
/// actor or request -- is a conflict, and nothing is published.
pub(crate) async fn a_reused_catalog_key_with_a_different_binding_conflicts_and_changes_nothing(
    db: &impl ContractDatabase,
) {
    let actor = operator();
    let mcp = create(db, mcp_candidate("Bound MCP")).await;
    let other = create(db, mcp_candidate("Other MCP")).await;
    let mcp_op = mcp_key(10, &actor, &mcp);
    committed(
        publish_mcp(db, &mcp, 0, Some(&mcp_op)).await,
        "the keyed MCP publication",
    );
    let stranger =
        ChangeActor::for_test_with_issuer("another-operator", "https://other.example.test");
    let rebinds = [
        mcp_key(10, &actor, &other),
        mcp_key(10, &stranger, &mcp),
        keyed(10, MCP_PUBLISH, &actor, mcp.id.as_str(), "\"stale\"", b""),
        keyed(
            10,
            MCP_PUBLISH,
            &actor,
            mcp.id.as_str(),
            mcp.etag().as_str(),
            b"{}",
        ),
    ];
    for (index, rebound) in rebinds.iter().enumerate() {
        let target = if index == 0 { &other } else { &mcp };
        let expected = if index == 0 { 0 } else { 1 };
        conflicts(
            publish_mcp(db, target, expected, Some(rebound)).await,
            &format!("rebinding {index}"),
        );
    }

    let api = registered(db, "Bound OpenAPI").await;
    let document = overlay_document("bound overlay");
    let put_op = overlay_put_key(11, &actor, &api, 0, &document);
    committed(
        publish_openapi(
            db,
            &api,
            (1, 1),
            Some(&overlay_put(&document, 0)),
            1,
            Some(&put_op),
        )
        .await,
        "the keyed overlay put",
    );
    let changed = overlay_document("another overlay");
    conflicts(
        publish_openapi(
            db,
            &api,
            (1, 2),
            Some(&overlay_put(&changed, 1)),
            2,
            Some(&overlay_put_key(11, &actor, &api, 1, &changed)),
        )
        .await,
        "the put's key with another document and If-Match",
    );
    assert_eq!(rows_for(db, &mcp_op).await, [MCP_PUBLISH]);
    assert_eq!(rows_for(db, &put_op).await, [OVERLAY_REPLACE]);
    assert!(
        db.store().mcp_catalog(&other.id).await.unwrap().is_none(),
        "nothing was published for the other Connection"
    );
    let stored = db.store().openapi_catalog(&api.id).await.unwrap().unwrap();
    assert_eq!((stored.catalog_revision, stored.overlay_revision), (2, 1));
    assert_eq!(db.reservations().await.len(), 2);
    assert_catalog_reservations_match_evidence(db).await;
}

/// A key reserved by another action cannot take effect on a catalog write:
/// not a keyed Connection create's, not a keyed revoke's, and not another
/// catalog action's. A key bound to an action other than the one the write
/// records is refused before anything is read. A catalog key cannot take
/// effect on a Connection change either.
pub(crate) async fn a_key_reserved_by_another_action_cannot_take_effect_on_a_catalog(
    db: &impl ContractDatabase,
) {
    let actor = operator();
    let candidate = mcp_candidate("Crossed MCP");
    let create_op = keyed(
        20,
        "connection.create",
        &actor,
        "",
        "",
        &serde_json::to_vec(&candidate).unwrap(),
    );
    let mcp = committed(
        db.store()
            .create_with_operation(candidate, &actor, None, Some(&create_op))
            .await,
        "the keyed Connection create",
    );
    conflicts(
        publish_mcp(db, &mcp, 0, Some(&mcp_key(20, &actor, &mcp))).await,
        "a Connection create's key on an MCP publication",
    );

    let revoke_key = test_caller_key(21);
    db.reserve_for_a_keyed_revoke(revoke_key).await;
    conflicts(
        publish_mcp(db, &mcp, 0, Some(&mcp_key(21, &actor, &mcp))).await,
        "a keyed revoke's key on an MCP publication",
    );

    let api = registered(db, "Crossed OpenAPI").await;
    let document = overlay_document("crossed overlay");
    let put_op = overlay_put_key(22, &actor, &api, 0, &document);
    committed(
        publish_openapi(
            db,
            &api,
            (1, 1),
            Some(&overlay_put(&document, 0)),
            1,
            Some(&put_op),
        )
        .await,
        "the keyed overlay put",
    );
    conflicts(
        publish_openapi(
            db,
            &api,
            (1, 2),
            Some(&overlay_delete(1)),
            0,
            Some(&overlay_delete_key(22, &actor, &api, 1)),
        )
        .await,
        "an overlay put's key on an overlay delete",
    );
    conflicts(
        publish_mcp(db, &mcp, 0, Some(&mcp_key(22, &actor, &mcp))).await,
        "an overlay put's key on an MCP publication",
    );
    let changed = mcp_candidate("Crossed MCP renamed");
    conflicts(
        db.store()
            .replace_with_operation(
                &mcp.id,
                &mcp.etag(),
                changed.clone(),
                &actor,
                Some(&keyed(
                    22,
                    "connection.replace",
                    &actor,
                    mcp.id.as_str(),
                    mcp.etag().as_str(),
                    &serde_json::to_vec(&changed).unwrap(),
                )),
            )
            .await,
        "an overlay put's key on a Connection replace",
    );

    // A handler defect: a key bound to the registration passed to an
    // overlay delete, and an overlay key passed to an MCP publication.
    conflicts(
        publish_openapi(
            db,
            &api,
            (1, 2),
            Some(&overlay_delete(1)),
            0,
            Some(&openapi_key(23, &actor, &api)),
        )
        .await,
        "a registration key on an overlay delete",
    );
    conflicts(
        publish_mcp(db, &mcp, 0, Some(&overlay_delete_key(24, &actor, &mcp, 0))).await,
        "an overlay key on an MCP publication",
    );

    assert!(db.store().mcp_catalog(&mcp.id).await.unwrap().is_none());
    let stored = db.store().openapi_catalog(&api.id).await.unwrap().unwrap();
    assert_eq!((stored.catalog_revision, stored.overlay_revision), (2, 1));
    assert_eq!(
        db.store().get(&mcp.id).await.unwrap().unwrap(),
        mcp,
        "the Connection did not change"
    );
    assert_eq!(rows_for(db, &put_op).await, [OVERLAY_REPLACE]);
    assert_eq!(db.reservations().await.len(), 3);
    assert_catalog_reservations_match_evidence(db).await;
}

/// I1 and I2: a failed catalog evidence insert rolls back the keyed MCP
/// publication, registration, overlay put and overlay delete together with
/// their reservations, so the keys stay unused and a later attempt with them
/// commits.
pub(crate) async fn a_failed_evidence_insert_rolls_back_the_keyed_publication_and_its_reservation(
    db: &impl ContractDatabase,
) {
    let actor = operator();
    let mcp = create(db, mcp_candidate("Faulted MCP")).await;
    let fresh = create(db, openapi_candidate("Faulted registration")).await;
    let api = registered(db, "Faulted OpenAPI").await;
    let document = overlay_document("faulted overlay");
    let overlaid = registered(db, "Faulted overlay delete").await;
    committed(
        publish_openapi(
            db,
            &overlaid,
            (1, 1),
            Some(&overlay_put(&document, 0)),
            1,
            None,
        )
        .await,
        "the unkeyed overlay put the delete removes",
    );
    let evidence = db.catalog_evidence().await;
    let mcp_op = mcp_key(30, &actor, &mcp);
    let register_op = openapi_key(31, &actor, &fresh);
    let put_op = overlay_put_key(32, &actor, &api, 0, &document);
    let put = overlay_put(&document, 0);
    let delete_op = overlay_delete_key(33, &actor, &overlaid, 1);
    let delete = overlay_delete(1);

    db.fail_catalog_evidence_inserts(true).await;
    let failures = [
        publish_mcp(db, &mcp, 0, Some(&mcp_op)).await.map(|_| ()),
        publish_openapi(db, &fresh, (0, 0), None, 0, Some(&register_op))
            .await
            .map(|_| ()),
        publish_openapi(db, &api, (1, 1), Some(&put), 1, Some(&put_op))
            .await
            .map(|_| ()),
        publish_openapi(db, &overlaid, (1, 2), Some(&delete), 0, Some(&delete_op))
            .await
            .map(|_| ()),
    ];
    db.fail_catalog_evidence_inserts(false).await;
    for failure in failures {
        let error = failure.expect_err("the publication cannot commit without its evidence");
        assert!(
            !matches!(
                error,
                ConnectionStoreError::CallerOperationConflict
                    | ConnectionStoreError::Validation { .. }
                    | ConnectionStoreError::Conflict { .. }
                    | ConnectionStoreError::OverlayConflict { .. }
            ),
            "an evidence failure is a store failure: {error:?}"
        );
    }
    assert!(db.reservations().await.is_empty(), "no key stayed reserved");
    assert_eq!(
        db.catalog_evidence().await,
        evidence,
        "nothing was recorded"
    );
    assert!(db.store().mcp_catalog(&mcp.id).await.unwrap().is_none());
    assert!(db
        .store()
        .openapi_catalog(&fresh.id)
        .await
        .unwrap()
        .is_none());
    let stored = db.store().openapi_catalog(&api.id).await.unwrap().unwrap();
    assert_eq!((stored.catalog_revision, stored.overlay_revision), (1, 0));
    let stored = db
        .store()
        .openapi_catalog(&overlaid.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (stored.catalog_revision, stored.overlay_revision),
        (2, 1),
        "the overlay was not removed"
    );
    assert_catalog_reservations_match_evidence(db).await;

    committed(
        publish_mcp(db, &mcp, 0, Some(&mcp_op)).await,
        "the same keyed MCP publication once evidence is writable",
    );
    committed(
        publish_openapi(db, &fresh, (0, 0), None, 0, Some(&register_op)).await,
        "the same keyed registration once evidence is writable",
    );
    committed(
        publish_openapi(db, &api, (1, 1), Some(&put), 1, Some(&put_op)).await,
        "the same keyed overlay put once evidence is writable",
    );
    committed(
        publish_openapi(db, &overlaid, (1, 2), Some(&delete), 0, Some(&delete_op)).await,
        "the same keyed overlay delete once evidence is writable",
    );
    assert_eq!(db.reservations().await.len(), 4);
    assert_catalog_reservations_match_evidence(db).await;
}

/// A stale catalog revision or overlay `If-Match` under a key publishes
/// nothing, records nothing and reserves nothing.
pub(crate) async fn a_stale_catalog_precondition_under_a_key_writes_no_change_evidence_or_reservation(
    db: &impl ContractDatabase,
) {
    let actor = operator();
    let mcp = create(db, mcp_candidate("Stale MCP")).await;
    committed(
        publish_mcp(db, &mcp, 0, None).await,
        "the unkeyed publication",
    );
    let api = registered(db, "Stale OpenAPI").await;
    let document = overlay_document("stale overlay");
    committed(
        publish_openapi(db, &api, (1, 1), Some(&overlay_put(&document, 0)), 1, None).await,
        "the unkeyed overlay put",
    );
    let evidence = db.catalog_evidence().await;

    let stale = publish_mcp(db, &mcp, 0, Some(&mcp_key(40, &actor, &mcp))).await;
    assert!(
        matches!(stale, Err(ConnectionStoreError::Conflict { .. })),
        "{stale:?}"
    );
    let stale = publish_openapi(
        db,
        &api,
        (0, 0),
        None,
        0,
        Some(&openapi_key(41, &actor, &api)),
    )
    .await;
    assert!(
        matches!(stale, Err(ConnectionStoreError::Conflict { .. })),
        "{stale:?}"
    );
    let changed = overlay_document("stale overlay changed");
    let stale = publish_openapi(
        db,
        &api,
        (1, 2),
        Some(&overlay_put(&changed, 0)),
        1,
        Some(&overlay_put_key(42, &actor, &api, 0, &changed)),
    )
    .await;
    assert!(
        matches!(stale, Err(ConnectionStoreError::OverlayConflict { .. })),
        "{stale:?}"
    );
    let stale = publish_openapi(
        db,
        &api,
        (1, 1),
        Some(&overlay_delete(1)),
        0,
        Some(&overlay_delete_key(43, &actor, &api, 1)),
    )
    .await;
    assert!(
        matches!(stale, Err(ConnectionStoreError::OverlayConflict { .. })),
        "{stale:?}"
    );
    assert_eq!(db.catalog_evidence().await, evidence);
    assert!(db.reservations().await.is_empty());
    let stored = db.store().openapi_catalog(&api.id).await.unwrap().unwrap();
    assert_eq!((stored.catalog_revision, stored.overlay_revision), (2, 1));
    assert_catalog_reservations_match_evidence(db).await;
}

/// Two writers racing one key and one binding publish once: the other is
/// answered from the winner's receipt.
pub(crate) async fn two_writers_racing_one_catalog_key_commit_one_change(
    db: &impl ContractDatabase,
) {
    let actor = operator();
    let mcp = create(db, mcp_candidate("Raced MCP")).await;
    let key = mcp_key(60, &actor, &mcp);
    let (left, right) = tokio::join!(
        publish_mcp(db, &mcp, 0, Some(&key)),
        publish_mcp(db, &mcp, 0, Some(&key))
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
        "one publication and one receipt: {outcomes:?}"
    );
    assert_eq!(rows_for(db, &key).await, [MCP_PUBLISH]);
    assert_eq!(
        db.store()
            .mcp_catalog(&mcp.id)
            .await
            .unwrap()
            .unwrap()
            .catalog_revision,
        1
    );
    assert_catalog_reservations_match_evidence(db).await;
}

/// Two keys racing one catalog revision leave only the winner's rows: the
/// other loses on the revision and reserves nothing.
pub(crate) async fn two_catalog_keys_racing_one_revision_leave_only_the_winners_rows(
    db: &impl ContractDatabase,
) {
    let actor = operator();
    let mcp = create(db, mcp_candidate("Contended MCP")).await;
    let left_key = mcp_key(70, &actor, &mcp);
    let right_key = mcp_key(71, &actor, &mcp);
    let (left, right) = tokio::join!(
        publish_mcp(db, &mcp, 0, Some(&left_key)),
        publish_mcp(db, &mcp, 0, Some(&right_key))
    );
    let (winner, loser, lost) = match (left, right) {
        (Ok(CallerOutcome::Committed(_)), lost) => (&left_key, &right_key, lost),
        (lost, Ok(CallerOutcome::Committed(_))) => (&right_key, &left_key, lost),
        other => panic!("one publication must win: {other:?}"),
    };
    assert!(
        matches!(lost, Err(ConnectionStoreError::Conflict { .. })),
        "the other loses on its catalog revision: {lost:?}"
    );
    assert_eq!(rows_for(db, winner).await, [MCP_PUBLISH]);
    assert!(rows_for(db, loser).await.is_empty());
    let reserved: Vec<String> = db
        .reservations()
        .await
        .into_iter()
        .map(|(key, _, _)| key)
        .collect();
    assert_eq!(reserved, [winner.id().to_string()]);
    assert_catalog_reservations_match_evidence(db).await;
}

/// I5 at the store: the binding digest of a keyed catalog change is stored
/// only in its reservation row, and the markers in the overlay document the
/// key is bound to reach neither the catalog evidence nor a receipt.
pub(crate) async fn a_keyed_catalog_change_keeps_synthetic_markers_out_of_the_reservation_receipt_and_record(
    db: &impl ContractDatabase,
) {
    let actor = operator();
    let api = registered(db, "Marked OpenAPI").await;
    let document = overlay_document(&OVERLAY_MARKERS.concat());
    let put_op = overlay_put_key(80, &actor, &api, 0, &document);
    let put = overlay_put(&document, 0);
    committed(
        publish_openapi(db, &api, (1, 1), Some(&put), 1, Some(&put_op)).await,
        "the keyed overlay put",
    );
    let put_receipt = replayed(
        publish_openapi(db, &api, (1, 1), Some(&put), 1, Some(&put_op)).await,
        "the retried overlay put",
    );
    let mcp = create(db, mcp_candidate("Marked MCP")).await;
    let mcp_op = mcp_key(81, &actor, &mcp);
    committed(
        publish_mcp(db, &mcp, 0, Some(&mcp_op)).await,
        "the keyed MCP publication",
    );
    let mcp_receipt = replayed(
        publish_mcp(db, &mcp, 0, Some(&mcp_op)).await,
        "the retried MCP publication",
    );

    let mut reserved = db.reservations().await;
    reserved.sort();
    let mut expected = vec![
        (
            put_op.id().to_string(),
            OVERLAY_REPLACE.to_owned(),
            Some(put_op.binding_digest().to_owned()),
        ),
        (
            mcp_op.id().to_string(),
            MCP_PUBLISH.to_owned(),
            Some(mcp_op.binding_digest().to_owned()),
        ),
    ];
    expected.sort();
    assert_eq!(reserved, expected);
    let receipts = [&put_receipt, &mcp_receipt]
        .map(|receipt| serde_json::to_string(receipt).expect("the receipt serializes"))
        .concat();
    let outside = db.text_outside_reservations().await;
    let evidence = db.catalog_evidence_text().await;
    assert!(!evidence.is_empty(), "the catalog evidence rows were read");
    for digest in [put_op.binding_digest(), mcp_op.binding_digest()] {
        assert!(!receipts.contains(digest), "a digest reached a receipt");
        assert!(
            !outside.contains(digest),
            "a digest is stored outside the reservation"
        );
    }
    for marker in OVERLAY_MARKERS {
        assert!(!receipts.contains(marker), "{marker} reached a receipt");
        assert!(!evidence.contains(marker), "{marker} reached the evidence");
    }
    assert_catalog_reservations_match_evidence(db).await;
}

/// The standalone store runs the catalog contract on its own Connections
/// database.
mod sqlite {
    use super::*;
    use crate::connections::caller_operation_contract::sqlite::SqliteDatabase;

    #[tokio::test]
    async fn sqlite_catalog_caller_operation_contract() {
        catalog_caller_operation_contract(&SqliteDatabase::new("catalog-contract")).await;
    }

    #[tokio::test]
    async fn sqlite_a_reused_catalog_key_with_a_different_binding_conflicts_and_changes_nothing() {
        a_reused_catalog_key_with_a_different_binding_conflicts_and_changes_nothing(
            &SqliteDatabase::new("catalog-binding"),
        )
        .await;
    }

    #[tokio::test]
    async fn sqlite_a_key_reserved_by_another_action_cannot_take_effect_on_a_catalog() {
        a_key_reserved_by_another_action_cannot_take_effect_on_a_catalog(&SqliteDatabase::new(
            "catalog-other-action",
        ))
        .await;
    }

    #[tokio::test]
    async fn sqlite_a_failed_evidence_insert_rolls_back_the_keyed_publication_and_its_reservation()
    {
        a_failed_evidence_insert_rolls_back_the_keyed_publication_and_its_reservation(
            &SqliteDatabase::new("catalog-fault"),
        )
        .await;
    }

    #[tokio::test]
    async fn sqlite_a_stale_catalog_precondition_under_a_key_writes_no_change_evidence_or_reservation(
    ) {
        a_stale_catalog_precondition_under_a_key_writes_no_change_evidence_or_reservation(
            &SqliteDatabase::new("catalog-stale"),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sqlite_two_writers_racing_one_catalog_key_commit_one_change() {
        two_writers_racing_one_catalog_key_commit_one_change(&SqliteDatabase::new(
            "catalog-race-key",
        ))
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sqlite_two_catalog_keys_racing_one_revision_leave_only_the_winners_rows() {
        two_catalog_keys_racing_one_revision_leave_only_the_winners_rows(&SqliteDatabase::new(
            "catalog-race-revision",
        ))
        .await;
    }

    #[tokio::test]
    async fn sqlite_a_keyed_catalog_change_keeps_synthetic_markers_out_of_the_reservation_receipt_and_record(
    ) {
        a_keyed_catalog_change_keeps_synthetic_markers_out_of_the_reservation_receipt_and_record(
            &SqliteDatabase::new("catalog-markers"),
        )
        .await;
    }
}
