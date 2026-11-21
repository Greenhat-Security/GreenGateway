//! I5 at the application boundary for the Connection and catalog families
//! (issue #425): with a synthetic marker in every secret-bearing request
//! field and every binding digest known, a keyed change, its exact retry, a
//! conflicting retry and a change whose caller-key reservation cannot be
//! written go through the real admin handlers while every log line is
//! captured at TRACE and the Prometheus metrics are rendered afterwards. No
//! marker and no digest reaches either, nor an answer other than the
//! changed resource's own view, nor the audit stream. The store contracts
//! (`the_binding_digest_is_stored_only_in_the_reservation_row`,
//! `a_keyed_catalog_change_keeps_synthetic_markers_out_of_the_reservation_receipt_and_record`)
//! check the reservation, receipt and evidence rows.
//!
//! The capture covers the runtime's blocking pool, where the SQLite store
//! runs: the failed reservation's count on
//! `greengateway_standalone_evidence_failures_total{store="connections"}`
//! is read from the same rendering, so a capture that missed that pool
//! would fail here rather than pass by seeing nothing.
//!
//! Not asserted absent, by design: Connection IDs (not secrets; a log line
//! may name the Connection a change is about) and the caller keys, which
//! each receipt and conflict answer names to its caller and which are not
//! secrets either. The digests bound to them are.

use super::*;

/// The credential aliases a bearer Connection can name: its authentication
/// secret, an additional header's secret, and its TLS client certificate
/// and private key.
pub(super) const REFERENCE_MARKERS: [&str; 4] = [
    "marked-connection-authentication-alias",
    "marked-connection-header-alias",
    "marked-connection-client-certificate-alias",
    "marked-connection-client-key-alias",
];

/// The references a delegated-issuer Connection names instead: its client
/// secret and its caller-assertion signing key.
pub(super) const DELEGATED_MARKERS: [&str; 2] = [
    "marked-connection-client-secret-alias",
    "marked-connection-signing-key-alias",
];

/// The overlay document's free text: its own description and a tool's.
pub(super) const OVERLAY_MARKERS: [&str; 2] = [
    "marked-catalog-overlay-description",
    "marked-catalog-overlay-tool-description",
];

/// Each request below suffixes every marker with one of these.
pub(super) const SUFFIXES: [&str; 3] = ["", "-conflict", "-failed"];

/// A disabled bearer Connection whose every credential reference is a
/// [`REFERENCE_MARKERS`] marker followed by `suffix`.
pub(super) fn marked_connection_body(suffix: &str) -> String {
    let [authentication, header, certificate, private_key] =
        REFERENCE_MARKERS.map(|marker| format!("{marker}{suffix}"));
    json!({
        "display_name": "Marked API",
        "enabled": false,
        "kind": "http_api",
        "endpoint": {"base_url": "https://keyed.example.test", "base_path": "/v1"},
        "authentication": {"type": "static_bearer", "secret_id": authentication},
        "additional_headers": [{"header_name": "x-proxy-token", "secret_id": header}],
        "tls": {"client_certificate_id": certificate, "client_private_key_id": private_key}
    })
    .to_string()
}

/// A disabled delegated-issuer Connection whose client secret and
/// caller-assertion signing key are [`DELEGATED_MARKERS`] markers followed
/// by `suffix`.
pub(super) fn delegated_connection_body(suffix: &str) -> String {
    let [client_secret, signing_key] = DELEGATED_MARKERS.map(|marker| format!("{marker}{suffix}"));
    json!({
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
    })
    .to_string()
}

/// An overlay over the widget catalog whose free text is the
/// [`OVERLAY_MARKERS`] followed by `suffix`.
pub(super) fn marked_overlay_document(suffix: &str) -> String {
    let [description, tool_description] = OVERLAY_MARKERS.map(|marker| format!("{marker}{suffix}"));
    json!({
        "schema_version": "0.1.0",
        "description": description,
        "tools": {
            "createWidget": {"description": tool_description, "visibility": "listed"}
        }
    })
    .to_string()
}

/// The binding digest the Connection handlers compute for a keyed request
/// by `actor` (`admit_keyed_connection_change`): the action, the
/// actor, the target, the `If-Match` value and the canonical body.
pub(super) fn bound_digest(
    actor: &auth::change_actor::ChangeActor,
    key: &str,
    action: &'static str,
    target: &str,
    if_match: &str,
    body: &str,
) -> String {
    let mut headers = HeaderMap::new();
    headers.insert("idempotency-key", key.parse().expect("the key is a header"));
    headers.insert(
        header::IF_MATCH,
        if_match.parse().expect("the ETag is a header"),
    );
    caller_operation(
        &headers,
        actor,
        action,
        target,
        if_match,
        &canonical_connection_request(body.as_bytes()).expect("the body is JSON"),
    )
    .expect("the key binds")
    .expect("the request is keyed")
    .binding_digest()
    .to_owned()
}

/// Test-only fault injection through a second connection: from here on no
/// caller key can be reserved in the Connections database at `path`.
fn fail_every_reservation(path: &FsPath) {
    rusqlite::Connection::open(path)
        .expect("the Connections database opens")
        .execute_batch(
            "CREATE TRIGGER fail_caller_key_reservation \
             BEFORE INSERT ON authority_caller_operation_ids \
             BEGIN SELECT RAISE(ABORT, 'injected reservation failure'); END;",
        )
        .expect("the fault installs");
}

/// The rendered count of standalone Connections evidence failures.
fn connection_evidence_failures(rendered: &str) -> Option<&str> {
    let prefix = format!(
        "{}{{store=\"connections\"}} ",
        crate::metrics::STANDALONE_EVIDENCE_FAILURES_TOTAL
    );
    rendered
        .lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
}

/// Asserts that no marker and no digest reached `answered`, `audited`,
/// `logged` or `rendered`, and that the capture saw the failed reservation.
fn assert_nothing_marked_escaped(
    markers: &[String],
    digests: &[String],
    answered: &str,
    audited: &str,
    logged: &str,
    rendered: &str,
) {
    assert!(!logged.is_empty(), "the handlers' log lines were captured");
    assert_eq!(
        connection_evidence_failures(rendered),
        Some("1"),
        "the failed reservation was counted where the capture saw it"
    );
    for marker in markers {
        assert!(!answered.contains(marker), "{marker} reached an answer");
        assert!(
            !audited.contains(marker),
            "{marker} reached the audit stream"
        );
        assert!(!logged.contains(marker), "{marker} reached the logs");
        assert!(!rendered.contains(marker), "{marker} reached the metrics");
    }
    for digest in digests {
        assert!(!answered.contains(digest), "a digest reached an answer");
        assert!(
            !audited.contains(digest),
            "a digest reached the audit stream"
        );
        assert!(!logged.contains(digest), "a digest reached the logs");
        assert!(!rendered.contains(digest), "a digest reached the metrics");
    }
}

/// I5 for the Connection family through the real handlers: a keyed create
/// naming a marker in each bearer credential reference (authentication and
/// additional-header secret aliases, TLS client certificate and key
/// aliases), its exact retry and a retry naming other markers; a keyed
/// replacement to a delegated-issuer body naming a marker as its client
/// secret and caller-assertion signing key aliases, with the same retries;
/// and a keyed create whose reservation cannot be written. No marker and no
/// binding digest reaches a log line at any level, the rendered metrics, a
/// receipt, a conflict or failure answer, or the audit stream. The create's
/// and the replacement's own answers are the Connection's view for the
/// caller who changed it, which names its references by design, so they are
/// not searched.
#[test]
fn a_keyed_connection_change_keeps_synthetic_markers_out_of_the_receipt_audit_logs_and_metrics() {
    let connection_db = TempDb::new("keyed-connection-markers");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let (audit_log, capture) = captured_audit();
    let ((answers, digests), logged, rendered) =
        super::super::admin_tokens_app_tests::capture_logs_and_metrics_on_every_runtime_thread(
            async {
                let router = keyed_connection_router(&connection_db, &policy, audit_log, |_| {});
                let admin = keyed_admin(&["connections-superadmin"]);
                let actor = auth::change_actor::ChangeActor::from_principal(&admin);
                let mut answers = Vec::new();
                let mut digests = Vec::new();

                let collection = connection_collection_etag(&router).await;
                let create_key = caller_key(90);
                let create = |body: &str, key: &str, collection: &str| {
                    keyed_connection_request(
                        Method::POST,
                        CONNECTIONS_ADMIN_ROUTE,
                        admin.clone(),
                        Some(body.to_owned()),
                        Some(collection),
                        Some(key),
                    )
                };
                let marked = marked_connection_body(SUFFIXES[0]);
                let (status, etag, created) =
                    exchange(&router, create(&marked, &create_key, &collection)).await;
                assert_eq!(status, StatusCode::CREATED, "{created}");
                let id = created["id"].as_str().expect("an ID").to_owned();
                let etag = etag.expect("the create names its ETag");
                let (status, _, receipt) =
                    exchange(&router, create(&marked, &create_key, &collection)).await;
                assert_eq!(status, StatusCode::OK, "{receipt}");
                answers.push(receipt);
                let conflicting = marked_connection_body(SUFFIXES[1]);
                let (status, _, conflict) =
                    exchange(&router, create(&conflicting, &create_key, &collection)).await;
                assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
                answers.push(conflict);
                let created_digest = bound_digest(
                    &actor,
                    &create_key,
                    "connection.create",
                    "",
                    &collection,
                    &marked,
                );
                digests.push(created_digest);
                digests.push(bound_digest(
                    &actor,
                    &create_key,
                    "connection.create",
                    "",
                    &collection,
                    &conflicting,
                ));

                let route = format!("{CONNECTIONS_ADMIN_ROUTE}/{id}");
                let replace_key = caller_key(91);
                let replace = |body: &str| {
                    keyed_connection_request(
                        Method::PUT,
                        &route,
                        admin.clone(),
                        Some(body.to_owned()),
                        Some(&etag),
                        Some(&replace_key),
                    )
                };
                let delegated = delegated_connection_body(SUFFIXES[0]);
                let (status, _, replaced) = exchange(&router, replace(&delegated)).await;
                assert_eq!(status, StatusCode::OK, "{replaced}");
                let (status, _, receipt) = exchange(&router, replace(&delegated)).await;
                assert_eq!(status, StatusCode::OK, "{receipt}");
                answers.push(receipt);
                let conflicting = delegated_connection_body(SUFFIXES[1]);
                let (status, _, conflict) = exchange(&router, replace(&conflicting)).await;
                assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
                answers.push(conflict);
                for body in [&delegated, &conflicting] {
                    digests.push(bound_digest(
                        &actor,
                        &replace_key,
                        "connection.replace",
                        &id,
                        &etag,
                        body,
                    ));
                }

                fail_every_reservation(&connection_db.path);
                let collection = connection_collection_etag(&router).await;
                let failed_key = caller_key(92);
                let failing = marked_connection_body(SUFFIXES[2]);
                let (status, _, failed) =
                    exchange(&router, create(&failing, &failed_key, &collection)).await;
                assert!(status.is_server_error(), "{status}: {failed}");
                answers.push(failed);
                digests.push(bound_digest(
                    &actor,
                    &failed_key,
                    "connection.create",
                    "",
                    &collection,
                    &failing,
                ));

                let changes = || {
                    capture
                        .events()
                        .into_iter()
                        .filter(|event| event.event_type == audit::event::CONNECTION_CHANGED)
                        .count()
                };
                assert_eventually(Duration::from_secs(5), || changes() >= 2);
                (answers, digests)
            },
        );

    // The digests computed here are the ones the handlers bound: each
    // committed key's reservation holds the one computed for its request.
    let mut reserved: Vec<String> = standalone_reservations(&connection_db.path)
        .into_iter()
        .map(|(_, _, digest)| digest.expect("every Connection key is bound by digest"))
        .collect();
    reserved.sort();
    let mut committed = vec![digests[0].clone(), digests[2].clone()];
    committed.sort();
    assert_eq!(reserved, committed);

    let markers: Vec<String> = SUFFIXES
        .iter()
        .flat_map(|suffix| {
            REFERENCE_MARKERS
                .iter()
                .chain(DELEGATED_MARKERS.iter())
                .map(move |marker| format!("{marker}{suffix}"))
        })
        .collect();
    assert_nothing_marked_escaped(
        &markers,
        &digests,
        &format!("{answers:?}"),
        &format!("{:?}", capture.events()),
        &logged,
        &rendered,
    );
}

/// I5 for the catalog family through the real handlers: a keyed OpenAPI
/// registration, its exact retry and its key reused on the refresh route; a
/// keyed overlay replacement whose document carries a marker in its own
/// description and in a tool's, its exact retry and a retry naming other
/// markers; and a keyed overlay replacement whose reservation cannot be
/// written. No marker and no binding digest reaches a log line at any level,
/// the rendered metrics, a receipt, a conflict or failure answer, or the
/// audit stream. No catalog request names a credential: the registration
/// carries its specification inline (published catalog content, not a
/// secret), a refresh has no body, and the upstream's credentials are the
/// Connection's own, never part of a catalog request. The registration's
/// and the overlay replacement's own answers are the catalog's view for the
/// caller who changed it, so they are not searched.
#[test]
fn a_keyed_catalog_change_keeps_synthetic_markers_out_of_the_receipt_audit_logs_and_metrics() {
    let connection_db = TempDb::new("keyed-catalog-markers");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let (audit_log, capture) = captured_audit();
    let ((answers, digests, registered_digest), logged, rendered) =
        super::super::admin_tokens_app_tests::capture_logs_and_metrics_on_every_runtime_thread(
            async {
                let router = keyed_connection_router(&connection_db, &policy, audit_log, |_| {});
                let admin = keyed_admin(CATALOG_ROLES);
                let actor = auth::change_actor::ChangeActor::from_principal(&admin);
                let mut answers = Vec::new();
                let mut digests = Vec::new();
                let (id, etag) = create_managed_openapi_connection(&router, "Marked catalog").await;

                let registration = openapi_registration_body(&router, &id, &["createWidget"]).await;
                let register_key = caller_key(93);
                let register = || {
                    CatalogCall::Register.request(
                        &id,
                        &etag,
                        Some(registration.clone()),
                        admin.clone(),
                        Some(&register_key),
                    )
                };
                let (status, _, registered) = exchange(&router, register()).await;
                assert_eq!(status, StatusCode::CREATED, "{registered}");
                let (status, _, receipt) = exchange(&router, register()).await;
                assert_eq!(status, StatusCode::OK, "{receipt}");
                answers.push(receipt);
                let (status, _, conflict) = exchange(
                    &router,
                    CatalogCall::Refresh.request(
                        &id,
                        &etag,
                        None,
                        admin.clone(),
                        Some(&register_key),
                    ),
                )
                .await;
                assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
                answers.push(conflict);
                let registered_digest = bound_digest(
                    &actor,
                    &register_key,
                    "catalog.openapi.publish",
                    &id,
                    &etag,
                    &registration,
                );

                let overlay = overlay_etag(&router, &id).await;
                let put_key = caller_key(94);
                let put = |document: &str, key: &str, overlay: &str| {
                    CatalogCall::OverlayPut.request(
                        &id,
                        overlay,
                        Some(document.to_owned()),
                        admin.clone(),
                        Some(key),
                    )
                };
                let marked = marked_overlay_document(SUFFIXES[0]);
                let (status, _, stored) = exchange(&router, put(&marked, &put_key, &overlay)).await;
                assert_eq!(status, StatusCode::OK, "{stored}");
                let (status, _, receipt) =
                    exchange(&router, put(&marked, &put_key, &overlay)).await;
                assert_eq!(status, StatusCode::OK, "{receipt}");
                answers.push(receipt);
                let conflicting = marked_overlay_document(SUFFIXES[1]);
                let (status, _, conflict) =
                    exchange(&router, put(&conflicting, &put_key, &overlay)).await;
                assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
                answers.push(conflict);
                for document in [&marked, &conflicting] {
                    digests.push(bound_digest(
                        &actor,
                        &put_key,
                        "catalog.overlay.replace",
                        &id,
                        &overlay,
                        document,
                    ));
                }

                fail_every_reservation(&connection_db.path);
                let overlay = overlay_etag(&router, &id).await;
                let failed_key = caller_key(95);
                let failing = marked_overlay_document(SUFFIXES[2]);
                let (status, _, failed) =
                    exchange(&router, put(&failing, &failed_key, &overlay)).await;
                assert!(status.is_server_error(), "{status}: {failed}");
                answers.push(failed);
                digests.push(bound_digest(
                    &actor,
                    &failed_key,
                    "catalog.overlay.replace",
                    &id,
                    &overlay,
                    &failing,
                ));

                assert!(catalog_changes_through(&capture, &id, 2) >= 2);
                (answers, digests, registered_digest)
            },
        );

    // The digests computed here are the ones the handlers bound.
    let mut reserved: Vec<String> = standalone_reservations(&connection_db.path)
        .into_iter()
        .map(|(_, _, digest)| digest.expect("every catalog key is bound by digest"))
        .collect();
    reserved.sort();
    let mut committed = vec![registered_digest.clone(), digests[0].clone()];
    committed.sort();
    assert_eq!(reserved, committed);

    let markers: Vec<String> = SUFFIXES
        .iter()
        .flat_map(|suffix| {
            OVERLAY_MARKERS
                .iter()
                .map(move |marker| format!("{marker}{suffix}"))
        })
        .collect();
    let digests: Vec<String> = digests
        .into_iter()
        .chain(std::iter::once(registered_digest))
        .collect();
    assert_nothing_marked_escaped(
        &markers,
        &digests,
        &format!("{answers:?}"),
        &format!("{:?}", capture.events()),
        &logged,
        &rendered,
    );
}
