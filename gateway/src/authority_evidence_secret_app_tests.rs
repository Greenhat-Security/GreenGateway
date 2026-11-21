//! Keyed local-secret changes through the real admin handlers (issue #425,
//! plan P8): the application rows of the family's test matrix. Local
//! secrets exist only in standalone mode (cluster mode rejects a local
//! secret keyring), so there is no PostgreSQL row and no contract fence:
//! the operation gate is never asked for them.

use super::*;

/// The stable value of the purpose every secret here is stored under.
const PURPOSE: &str = "static_bearer";

fn secret_create_body(label: &str, value: &str) -> String {
    json!({ "label": label, "purpose": PURPOSE, "value": value }).to_string()
}

fn secret_rotate_body(value: &str) -> String {
    json!({ "purpose": PURPOSE, "value": value }).to_string()
}

/// The connection-secret collection's mutation ETag, as the list names it.
async fn secret_collection_etag(router: &Router, principal: &auth::Principal) -> String {
    let response = router
        .clone()
        .oneshot(keyed_connection_request(
            Method::GET,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            principal.clone(),
            None,
            None,
            None,
        ))
        .await
        .expect("the secret list completes");
    assert_eq!(response.status(), StatusCode::OK);
    response
        .headers()
        .get(CONNECTION_SECRET_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("the list names the collection ETag")
        .to_owned()
}

/// The actions of the local-secret evidence rows, in commit order.
fn secret_evidence(path: &FsPath) -> Vec<String> {
    standalone_change_evidence(path, "connection_local_secret_change_evidence")
        .0
        .into_iter()
        .map(|change| change.action)
        .collect()
}

/// The reservations local-secret keys hold.
fn secret_reservations(path: &FsPath) -> Vec<(String, String, Option<String>)> {
    standalone_reservations(path)
        .into_iter()
        .filter(|(_, action, _)| action.starts_with("secret."))
        .collect()
}

fn secret_changes(capture: &audit::sink::tests::CaptureSink) -> usize {
    capture
        .events()
        .iter()
        .filter(|event| event.event_type == audit::event::CONNECTION_SECRET_CHANGED)
        .count()
}

/// Create a local secret without a key and return its ID and ETag.
async fn create_unkeyed(
    router: &Router,
    principal: &auth::Principal,
    label: &str,
    value: &str,
) -> (String, String) {
    let collection = secret_collection_etag(router, principal).await;
    let (status, etag, created) = exchange(
        router,
        keyed_connection_request(
            Method::POST,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            principal.clone(),
            Some(secret_create_body(label, value)),
            Some(&collection),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    (
        created["id"].as_str().expect("an ID").to_owned(),
        etag.expect("the create names its ETag"),
    )
}

fn assert_secret_receipt(receipt: &Value, key: &str, operation: &str, id: &str, revision: u64) {
    assert_eq!(receipt["operation_id"], json!(key), "{receipt}");
    assert_eq!(receipt["operation"], json!(operation), "{receipt}");
    assert_eq!(receipt["resource_id"], json!(id), "{receipt}");
    assert_eq!(receipt["revision"], json!(revision), "{receipt}");
    assert_eq!(
        receipt.as_object().map(|object| object.len()),
        Some(5),
        "{receipt}"
    );
}

/// An exact retry of a keyed create, rotate and delete is answered `200`
/// with the receipt of the committed change and repeats no side effect: no
/// second change, evidence row or audit event. The same key over another
/// value is `409` and stores nothing. The key is judged before the
/// precondition: a committed create is answered from its receipt after the
/// collection moved, while an unused key with the stale `If-Match` is `412`.
#[tokio::test]
async fn a_replayed_secret_change_repeats_no_side_effect() {
    let connection_db = TempDb::new("keyed-secret-replay");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let (audit_log, capture) = captured_audit();
    let router = keyed_connection_router(&connection_db, &policy, audit_log, |_| {});
    let admin = keyed_admin(&["connections-secret-manager"]);
    let collection = secret_collection_etag(&router, &admin).await;
    let create_key = caller_key(70);
    let create = |value: &str| {
        keyed_connection_request(
            Method::POST,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            admin.clone(),
            Some(secret_create_body("Keyed secret", value)),
            Some(&collection),
            Some(&create_key),
        )
    };
    let (status, etag, created) = exchange(&router, create("keyed-secret-value-one")).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().expect("an ID").to_owned();
    let etag = etag.expect("the create names its ETag");
    let (status, _, receipt) = exchange(&router, create("keyed-secret-value-one")).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_secret_receipt(&receipt, &create_key, "secret.create", &id, 1);
    // Another value under the same key is not acknowledged as stored.
    let (status, _, conflict) = exchange(&router, create("keyed-secret-value-other")).await;
    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
    assert_eq!(conflict["reason"], json!(CALLER_OPERATION_CONFLICT_REASON));
    // An unused key with the collection ETag the create moved is `412`.
    let (status, _, stale) = exchange(
        &router,
        keyed_connection_request(
            Method::POST,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            admin.clone(),
            Some(secret_create_body("Second secret", "second-value")),
            Some(&collection),
            Some(&caller_key(71)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED, "{stale}");

    let route = format!("{CONNECTION_SECRETS_ADMIN_ROUTE}/{id}");
    let rotate_key = caller_key(72);
    let rotate = |value: &str| {
        keyed_connection_request(
            Method::PUT,
            &route,
            admin.clone(),
            Some(secret_rotate_body(value)),
            Some(&etag),
            Some(&rotate_key),
        )
    };
    let (status, rotated_etag, rotated) = exchange(&router, rotate("keyed-secret-value-two")).await;
    assert_eq!(status, StatusCode::OK, "{rotated}");
    let rotated_etag = rotated_etag.expect("the rotation names its ETag");
    let (status, _, receipt) = exchange(&router, rotate("keyed-secret-value-two")).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_secret_receipt(&receipt, &rotate_key, "secret.rotate", &id, 2);
    let (status, _, conflict) = exchange(&router, rotate("keyed-secret-value-other")).await;
    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
    assert_eq!(conflict["reason"], json!(CALLER_OPERATION_CONFLICT_REASON));
    // The create's retry, whose secret was rotated since and whose
    // `If-Match` is stale, is still answered with its own receipt.
    let (status, _, receipt) = exchange(&router, create("keyed-secret-value-one")).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_secret_receipt(&receipt, &create_key, "secret.create", &id, 1);

    let delete_key = caller_key(73);
    let delete = || {
        keyed_connection_request(
            Method::DELETE,
            &route,
            admin.clone(),
            None,
            Some(&rotated_etag),
            Some(&delete_key),
        )
    };
    let (status, _, deleted) = exchange(&router, delete()).await;
    assert_eq!(status, StatusCode::OK, "{deleted}");
    let (status, _, receipt) = exchange(&router, delete()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a committed delete is answered after the secret is gone: {receipt}"
    );
    assert_secret_receipt(&receipt, &delete_key, "secret.delete", &id, 2);
    // Unkeyed, the same delete finds no secret.
    let (status, _, _) = exchange(
        &router,
        keyed_connection_request(
            Method::DELETE,
            &route,
            admin.clone(),
            None,
            Some(&rotated_etag),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    // A committed rotation is answered after the secret is gone too.
    let (status, _, receipt) = exchange(&router, rotate("keyed-secret-value-two")).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_secret_receipt(&receipt, &rotate_key, "secret.rotate", &id, 2);

    assert_eq!(
        secret_evidence(&connection_db.path),
        ["secret.create", "secret.rotate", "secret.delete"],
        "each change committed once"
    );
    let reservations = secret_reservations(&connection_db.path);
    assert_eq!(reservations.len(), 3);
    assert_eventually(Duration::from_secs(5), || secret_changes(&capture) >= 3);
    assert_eq!(
        secret_changes(&capture),
        3,
        "no replay emitted a second change event"
    );
    // I5: the binding digests stay in the reservation rows.
    let audited = format!("{:?}", capture.events());
    let receipts = format!("{receipt}");
    for (_, _, digest) in reservations {
        let digest = digest.expect("every local-secret key is bound by digest");
        assert!(
            !audited.contains(&digest),
            "a digest reached the audit stream"
        );
        assert!(!receipts.contains(&digest), "a digest reached a receipt");
    }
}

/// I4 end to end: required mode refuses the unkeyed local-secret create and
/// rotation before anything is written, and admits the keyed request of an
/// issuer-bound principal under `qualified_v1` with the file sink.
#[tokio::test]
#[cfg_attr(
    not(unix),
    ignore = "required mode admits keyed local-secret changes only on a Unix build, where the file sink syncs its directory"
)]
async fn required_mode_refuses_the_unkeyed_secret_create_and_rotate_and_admits_the_keyed_principal()
{
    let connection_db = TempDb::new("keyed-secret-required");
    let events = TempDb::new("keyed-secret-required-events");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let (audit_log, capture) = captured_audit();
    let router = keyed_connection_router(&connection_db, &policy, audit_log, |config| {
        qualified_required(config, &events)
    });
    let admin = keyed_admin(&["connections-secret-manager"]);
    let collection = secret_collection_etag(&router, &admin).await;
    let create = |key: Option<&str>| {
        keyed_connection_request(
            Method::POST,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            admin.clone(),
            Some(secret_create_body("Required secret", "required-value")),
            Some(&collection),
            key,
        )
    };
    let (status, _, refused) = exchange(&router, create(None)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["reason"], json!("authority_evidence_unsupported"));
    assert_eq!(
        refused["error"],
        json!("AUTHORITY_EVIDENCE_DURABILITY=required refuses secret.create: standalone mode admits it only with an Idempotency-Key, on a route that honours one; nothing was changed")
    );
    let (status, etag, created) = exchange(&router, create(Some(&caller_key(74)))).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let route = format!(
        "{CONNECTION_SECRETS_ADMIN_ROUTE}/{}",
        created["id"].as_str().expect("an ID")
    );
    let etag = etag.expect("an ETag");
    let rotate = |key: Option<&str>| {
        keyed_connection_request(
            Method::PUT,
            &route,
            admin.clone(),
            Some(secret_rotate_body("required-value-next")),
            Some(&etag),
            key,
        )
    };
    let (status, _, refused) = exchange(&router, rotate(None)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{refused}");
    assert_eq!(refused["operation"], json!("secret.rotate"));
    let (status, _, rotated) = exchange(&router, rotate(Some(&caller_key(75)))).await;
    assert_eq!(status, StatusCode::OK, "{rotated}");
    assert_eq!(
        secret_evidence(&connection_db.path),
        ["secret.create", "secret.rotate"]
    );
    assert_eq!(secret_reservations(&connection_db.path).len(), 2);
    assert_eq!(
        refused_operations(&capture, 2),
        ["secret.create", "secret.rotate"]
    );
}

/// The rest of the gate: required mode refuses a keyed local-secret create
/// by a gateway service token, under `delivery_v1`, or with the log sink,
/// and each refusal names the criterion; nothing is written or reserved.
#[tokio::test]
async fn required_mode_refuses_a_keyed_secret_change_by_a_service_token_or_under_delivery_v1_or_with_the_log_sink(
) {
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let events = TempDb::new("keyed-secret-refused-events");
    for (case, requirement) in [
        (
            "service token",
            "from a provider-authenticated principal with a canonical issuer",
        ),
        ("delivery_v1", "with AUTHORITY_EVENT_FORMAT=qualified_v1"),
        ("log sink", "with AUTHORITY_EVENT_SINK=file"),
    ] {
        let principal = match case {
            "service token" => service_token_admin(&["connections-secret-manager"]),
            _ => keyed_admin(&["connections-secret-manager"]),
        };
        let connection_db = TempDb::new("keyed-secret-refused");
        let router = keyed_connection_router(&connection_db, &policy, test_audit_log(), |config| {
            qualified_required(config, &events);
            match case {
                "delivery_v1" => {
                    config.authority_events.format = config::AuthorityEventFormat::DeliveryV1;
                }
                "log sink" => config.authority_events.sink = config::AuthorityEventSinkSetting::Log,
                _ => {}
            }
        });
        let collection = secret_collection_etag(&router, &principal).await;
        let (status, _, refused) = exchange(
            &router,
            keyed_connection_request(
                Method::POST,
                CONNECTION_SECRETS_ADMIN_ROUTE,
                principal,
                Some(secret_create_body("Refused secret", "refused-value")),
                Some(&collection),
                Some(&caller_key(76)),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{case}: {refused}");
        assert_eq!(
            refused["error"],
            json!(format!(
                "AUTHORITY_EVIDENCE_DURABILITY=required refuses secret.create: standalone mode admits it only {requirement}; nothing was changed"
            )),
            "{case}"
        );
        assert!(secret_evidence(&connection_db.path).is_empty(), "{case}");
        assert!(
            secret_reservations(&connection_db.path).is_empty(),
            "{case}"
        );
    }
}

/// Local-secret deletion is a withdrawal: required mode admits every form
/// of it -- unkeyed, keyed, and by a gateway service token -- even with the
/// log sink, and each records its evidence (owner ruling 4 on issue #425).
#[tokio::test]
async fn required_mode_admits_every_form_of_secret_delete() {
    let connection_db = TempDb::new("keyed-secret-withdrawal");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let best_effort = keyed_connection_router(&connection_db, &policy, test_audit_log(), |_| {});
    let admin = keyed_admin(&["connections-secret-manager"]);
    let mut created = Vec::new();
    for label in ["Unkeyed delete", "Keyed delete", "Service token delete"] {
        created.push(create_unkeyed(&best_effort, &admin, label, "withdrawn-value").await);
    }
    drop(best_effort);
    let events = TempDb::new("keyed-secret-withdrawal-events");
    let (audit_log, capture) = captured_audit();
    let router = keyed_connection_router(&connection_db, &policy, audit_log, |config| {
        qualified_required(config, &events);
        config.authority_events.sink = config::AuthorityEventSinkSetting::Log;
    });
    let forms = [
        (admin.clone(), None),
        (admin.clone(), Some(caller_key(77))),
        (service_token_admin(&["connections-secret-manager"]), None),
    ];
    for ((id, etag), (principal, key)) in created.iter().zip(forms) {
        let (status, _, body) = exchange(
            &router,
            keyed_connection_request(
                Method::DELETE,
                &format!("{CONNECTION_SECRETS_ADMIN_ROUTE}/{id}"),
                principal,
                None,
                Some(etag),
                key.as_deref(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let (evidence, _) = standalone_change_evidence(
        &connection_db.path,
        "connection_local_secret_change_evidence",
    );
    let deletes: Vec<_> = evidence
        .iter()
        .filter(|change| change.action == "secret.delete")
        .map(|change| change.kind.as_str())
        .collect();
    assert_eq!(deletes, ["principal", "principal", "service_token"]);
    assert_eq!(secret_reservations(&connection_db.path).len(), 1);
    assert_eventually(Duration::from_secs(5), || secret_changes(&capture) >= 3);
    assert!(capture
        .events()
        .iter()
        .all(|event| event.event_type != audit::event::AUTHORITY_EVIDENCE_OPERATION_REFUSED));
}

/// Authorization and validation come before the key: a keyed request from
/// a caller without the secrets permission is `403`, and a malformed keyed
/// request `400` (or `428` without `If-Match`); none asks a gate, reads the
/// key or reserves anything. The key below was first committed by an
/// authorized caller with another label, so a handler that bound and
/// pre-checked the key first would answer `409` instead. Local secrets have
/// no cluster mode, so there is no contract fence to leave unchanged.
#[tokio::test]
async fn a_keyed_secret_change_that_is_forbidden_or_malformed_reserves_nothing() {
    let connection_db = TempDb::new("keyed-secret-forbidden");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let router = keyed_connection_router(&connection_db, &policy, test_audit_log(), |_| {});
    let admin = keyed_admin(&["connections-secret-manager"]);
    let editor = keyed_admin(&["connections-editor"]);
    let key = caller_key(78);
    let collection = secret_collection_etag(&router, &admin).await;
    let (status, etag, created) = exchange(
        &router,
        keyed_connection_request(
            Method::POST,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            admin.clone(),
            Some(secret_create_body("Authorized", "authorized-value")),
            Some(&collection),
            Some(&key),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let route = format!(
        "{CONNECTION_SECRETS_ADMIN_ROUTE}/{}",
        created["id"].as_str().expect("an ID")
    );
    let etag = etag.expect("an ETag");
    let collection = secret_collection_etag(&router, &admin).await;
    let requests = [
        (
            "forbidden create",
            StatusCode::FORBIDDEN,
            keyed_connection_request(
                Method::POST,
                CONNECTION_SECRETS_ADMIN_ROUTE,
                editor.clone(),
                Some(secret_create_body("Forbidden", "forbidden-value")),
                Some(&collection),
                Some(&key),
            ),
        ),
        (
            "forbidden rotate",
            StatusCode::FORBIDDEN,
            keyed_connection_request(
                Method::PUT,
                &route,
                editor.clone(),
                Some(secret_rotate_body("forbidden-value")),
                Some(&etag),
                Some(&key),
            ),
        ),
        (
            "forbidden delete",
            StatusCode::FORBIDDEN,
            keyed_connection_request(
                Method::DELETE,
                &route,
                editor.clone(),
                None,
                Some(&etag),
                Some(&key),
            ),
        ),
        (
            "malformed create",
            StatusCode::BAD_REQUEST,
            keyed_connection_request(
                Method::POST,
                CONNECTION_SECRETS_ADMIN_ROUTE,
                admin.clone(),
                Some("{\"label\":".to_owned()),
                Some(&collection),
                Some(&caller_key(79)),
            ),
        ),
        (
            "malformed rotate",
            StatusCode::BAD_REQUEST,
            keyed_connection_request(
                Method::PUT,
                &route,
                admin.clone(),
                Some("not json".to_owned()),
                Some(&etag),
                Some(&caller_key(79)),
            ),
        ),
        (
            "delete with a body",
            StatusCode::BAD_REQUEST,
            keyed_connection_request(
                Method::DELETE,
                &route,
                admin.clone(),
                Some("{}".to_owned()),
                Some(&etag),
                Some(&caller_key(79)),
            ),
        ),
        (
            "rotate without If-Match",
            StatusCode::PRECONDITION_REQUIRED,
            keyed_connection_request(
                Method::PUT,
                &route,
                admin.clone(),
                Some(secret_rotate_body("unconditional-value")),
                None,
                Some(&caller_key(79)),
            ),
        ),
    ];
    for (case, expected, request) in requests {
        let (status, _, body) = exchange(&router, request).await;
        assert_eq!(status, expected, "{case}: {body}");
    }
    assert_eq!(secret_evidence(&connection_db.path), ["secret.create"]);
    assert_eq!(secret_reservations(&connection_db.path).len(), 1);

    // Under required mode with the log sink every keyed create reaches the
    // gate and is refused there; the forbidden one is answered first and
    // audits no refusal.
    drop(router);
    let events = TempDb::new("keyed-secret-forbidden-events");
    let (audit_log, capture) = captured_audit();
    let router = keyed_connection_router(&connection_db, &policy, audit_log, |config| {
        qualified_required(config, &events);
        config.authority_events.sink = config::AuthorityEventSinkSetting::Log;
    });
    for (principal, expected) in [
        (editor, StatusCode::FORBIDDEN),
        (admin.clone(), StatusCode::CONFLICT),
    ] {
        let (status, _, body) = exchange(
            &router,
            keyed_connection_request(
                Method::POST,
                CONNECTION_SECRETS_ADMIN_ROUTE,
                principal,
                Some(secret_create_body("Gated", "gated-value")),
                Some(&collection),
                Some(&caller_key(80)),
            ),
        )
        .await;
        assert_eq!(status, expected, "{body}");
    }
    assert_eq!(refused_operations(&capture, 1), ["secret.create"]);
    assert_eq!(secret_reservations(&connection_db.path).len(), 1);
}

/// A local-secret change runs to completion once admitted, even when its
/// client goes away while the store is committing it: its audit event is
/// emitted once, and the keyed retry is answered with its receipt.
#[tokio::test]
async fn an_admitted_secret_change_finishes_after_its_client_goes_away() {
    let connection_db = TempDb::new("keyed-secret-abandoned");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let (audit_log, capture) = captured_audit();
    let router = keyed_connection_router(&connection_db, &policy, audit_log, |_| {});
    let admin = keyed_admin(&["connections-secret-manager"]);
    let (id, etag) = create_unkeyed(&router, &admin, "Abandoned", "abandoned-value").await;
    let route = format!("{CONNECTION_SECRETS_ADMIN_ROUTE}/{id}");
    let recorded = |action: &'static str| {
        let path = connection_db.path.clone();
        move || {
            secret_evidence(&path)
                .iter()
                .any(|recorded| recorded == action)
        }
    };

    let rotate_key = caller_key(81);
    let rotate = || {
        keyed_connection_request(
            Method::PUT,
            &route,
            admin.clone(),
            Some(secret_rotate_body("abandoned-value-next")),
            Some(&etag),
            Some(&rotate_key),
        )
    };
    abandon_once_committed(&router, rotate(), recorded("secret.rotate")).await;
    let (status, _, receipt) = exchange(&router, rotate()).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_secret_receipt(&receipt, &rotate_key, "secret.rotate", &id, 2);
    assert_eventually(Duration::from_secs(5), || secret_changes(&capture) >= 2);

    let current = exchange(
        &router,
        keyed_connection_request(
            Method::GET,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            admin.clone(),
            None,
            None,
            None,
        ),
    )
    .await
    .2;
    let rotated_etag = current["secrets"]
        .as_array()
        .and_then(|secrets| secrets.iter().find(|secret| secret["id"] == json!(id)))
        .and_then(|secret| secret["etag"].as_str())
        .expect("the list names the rotated secret's ETag")
        .to_owned();
    let delete_key = caller_key(82);
    let delete = || {
        keyed_connection_request(
            Method::DELETE,
            &route,
            admin.clone(),
            None,
            Some(&rotated_etag),
            Some(&delete_key),
        )
    };
    abandon_once_committed(&router, delete(), recorded("secret.delete")).await;
    let (status, _, receipt) = exchange(&router, delete()).await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_secret_receipt(&receipt, &delete_key, "secret.delete", &id, 2);
    // Each change emitted its audit event once, though nobody waited for
    // its response.
    assert_eventually(Duration::from_secs(5), || secret_changes(&capture) >= 3);
    assert_eq!(secret_changes(&capture), 3);
}

/// I5 at the application boundary: markers in every secret-bearing request
/// field -- the created and rotated values, and the label -- reach no
/// receipt, conflict answer, audit event, log line or metric, and the values
/// reach neither the Connections database file nor its WAL. The store rows
/// (`local_secret_operation_tests`) check the reservation and evidence rows.
#[test]
fn a_keyed_secret_change_keeps_synthetic_markers_out_of_the_receipt_audit_logs_and_metrics() {
    const VALUE_MARKER: &str = "keyed-secret-value-marker-0f3a";
    const ROTATED_MARKER: &str = "keyed-secret-rotated-marker-91c2";
    const CONFLICT_MARKER: &str = "keyed-secret-conflict-marker-5d7e";
    const LABEL_MARKER: &str = "Keyed secret label marker 44b1";

    let recorder = PrometheusBuilder::new().build_recorder();
    let metrics = recorder.handle();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("the test runtime builds");
    let (logs, _logging) = super::super::admin_tokens_app_tests::capture_all_logs();
    let connection_db = TempDb::new("keyed-secret-markers");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let (audit_log, capture) = captured_audit();
    let answers = ::metrics::with_local_recorder(&recorder, || {
        runtime.block_on(async {
            let router = keyed_connection_router(&connection_db, &policy, audit_log, |_| {});
            let admin = keyed_admin(&["connections-secret-manager"]);
            let collection = secret_collection_etag(&router, &admin).await;
            let create_key = caller_key(83);
            let create = |value: &str| {
                keyed_connection_request(
                    Method::POST,
                    CONNECTION_SECRETS_ADMIN_ROUTE,
                    admin.clone(),
                    Some(secret_create_body(LABEL_MARKER, value)),
                    Some(&collection),
                    Some(&create_key),
                )
            };
            let mut answers = Vec::new();
            let (status, etag, created) = exchange(&router, create(VALUE_MARKER)).await;
            assert_eq!(status, StatusCode::CREATED, "{created}");
            let id = created["id"].as_str().expect("an ID").to_owned();
            for value in [VALUE_MARKER, CONFLICT_MARKER] {
                answers.push(exchange(&router, create(value)).await.2);
            }
            let route = format!("{CONNECTION_SECRETS_ADMIN_ROUTE}/{id}");
            let rotate_key = caller_key(84);
            let rotate = |value: &str| {
                keyed_connection_request(
                    Method::PUT,
                    &route,
                    admin.clone(),
                    Some(secret_rotate_body(value)),
                    etag.as_deref(),
                    Some(&rotate_key),
                )
            };
            // The rotation's own answer is the secret's view, label and all,
            // for the caller who rotated it; its retries answer from the key.
            let (status, _, rotated) = exchange(&router, rotate(ROTATED_MARKER)).await;
            assert_eq!(status, StatusCode::OK, "{rotated}");
            for value in [ROTATED_MARKER, CONFLICT_MARKER] {
                answers.push(exchange(&router, rotate(value)).await.2);
            }
            assert_eventually(Duration::from_secs(5), || secret_changes(&capture) >= 2);
            answers
        })
    });
    assert_eq!(answers[0]["operation"], json!("secret.create"));
    assert_eq!(
        answers[1]["reason"],
        json!(CALLER_OPERATION_CONFLICT_REASON)
    );
    assert_eq!(answers[2]["operation"], json!("secret.rotate"));
    assert_eq!(
        answers[3]["reason"],
        json!(CALLER_OPERATION_CONFLICT_REASON)
    );

    let answered = format!("{answers:?}");
    let audited = format!("{:?}", capture.events());
    let logged = logs.contents();
    let rendered = metrics.render();
    for marker in [VALUE_MARKER, ROTATED_MARKER, CONFLICT_MARKER, LABEL_MARKER] {
        assert!(!answered.contains(marker), "{marker} reached an answer");
        assert!(
            !audited.contains(marker),
            "{marker} reached the audit stream"
        );
        assert!(!logged.contains(marker), "{marker} reached the logs");
        assert!(!rendered.contains(marker), "{marker} reached the metrics");
    }
    for (_, _, digest) in secret_reservations(&connection_db.path) {
        let digest = digest.expect("every local-secret key is bound by digest");
        assert!(!answered.contains(&digest), "a digest reached an answer");
        assert!(
            !audited.contains(&digest),
            "a digest reached the audit stream"
        );
        assert!(!logged.contains(&digest), "a digest reached the logs");
        assert!(!rendered.contains(&digest), "a digest reached the metrics");
    }
    for file in [
        connection_db.path.clone(),
        connection_db.path.with_extension("sqlite-wal"),
        FsPath::new(&format!("{}-wal", connection_db.path.display())).to_path_buf(),
    ] {
        let Ok(bytes) = fs::read(&file) else {
            continue;
        };
        for marker in [VALUE_MARKER, ROTATED_MARKER, CONFLICT_MARKER] {
            assert!(
                !bytes
                    .windows(marker.len())
                    .any(|window| window == marker.as_bytes()),
                "{marker} reached {}",
                file.display()
            );
        }
    }
}
