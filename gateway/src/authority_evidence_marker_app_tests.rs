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
/// secret, its caller-assertion signing key and a key it publishes beside
/// that one.
pub(super) const DELEGATED_MARKERS: [&str; 3] = [
    "marked-connection-client-secret-alias",
    "marked-connection-signing-key-alias",
    "marked-connection-published-key-alias",
];

/// The client secret an OAuth client-credentials Connection names.
pub(super) const OAUTH_MARKERS: [&str; 1] = ["marked-connection-oauth-client-secret-alias"];

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
    let [client_secret, signing_key, published_key] =
        DELEGATED_MARKERS.map(|marker| format!("{marker}{suffix}"));
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
            "lifetime_seconds": 60,
            "published_keys": [
                {"signing_key_id": published_key, "kid": "keyed-2026-12", "algorithm": "es256"}
            ]
        }
    })
    .to_string()
}

/// A disabled OAuth client-credentials Connection whose client secret is
/// the [`OAUTH_MARKERS`] marker followed by `suffix`.
pub(super) fn oauth_connection_body(suffix: &str) -> String {
    let [client_secret] = OAUTH_MARKERS.map(|marker| format!("{marker}{suffix}"));
    json!({
        "display_name": "Marked API",
        "enabled": false,
        "kind": "http_api",
        "endpoint": {"base_url": "https://keyed.example.test", "base_path": "/v1"},
        "authentication": {
            "type": "oauth2_client_credentials",
            "client_id": "greengateway",
            "client_secret_id": client_secret,
            "token_url": "https://keyed.example.test/oauth2/token",
            "client_auth_method": "client_secret_basic"
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
/// secret, caller-assertion signing key and published key aliases, with the
/// same retries; a keyed replacement to an OAuth client-credentials body
/// naming a marker as its client secret alias and a keyed delete of the
/// Connection that still names it, each with its exact retry; and a keyed
/// create whose reservation cannot be written. Every marked body is a
/// disabled Connection: an enabled one naming an alias that is not
/// configured is refused before its key is bound, so its references could
/// not be marked. The enabled side (a credentialed Connection the runtime
/// serves) is the catalog test's. No marker and no
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
                let (status, delegated_etag, replaced) =
                    exchange(&router, replace(&delegated)).await;
                assert_eq!(status, StatusCode::OK, "{replaced}");
                let delegated_etag = delegated_etag.expect("the replacement names its ETag");
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

                // A replacement to an OAuth client-credentials body, then a
                // delete of the Connection that still names its client
                // secret, each with its exact retry.
                let oauth = oauth_connection_body(SUFFIXES[0]);
                let oauth_key = caller_key(96);
                let replace_oauth = || {
                    keyed_connection_request(
                        Method::PUT,
                        &route,
                        admin.clone(),
                        Some(oauth.clone()),
                        Some(&delegated_etag),
                        Some(&oauth_key),
                    )
                };
                let (status, oauth_etag, replaced) = exchange(&router, replace_oauth()).await;
                assert_eq!(status, StatusCode::OK, "{replaced}");
                let oauth_etag = oauth_etag.expect("the replacement names its ETag");
                let (status, _, receipt) = exchange(&router, replace_oauth()).await;
                assert_eq!(status, StatusCode::OK, "{receipt}");
                answers.push(receipt);
                digests.push(bound_digest(
                    &actor,
                    &oauth_key,
                    "connection.replace",
                    &id,
                    &delegated_etag,
                    &oauth,
                ));
                let delete_key = caller_key(97);
                let delete = || {
                    keyed_connection_request(
                        Method::DELETE,
                        &route,
                        admin.clone(),
                        None,
                        Some(&oauth_etag),
                        Some(&delete_key),
                    )
                };
                for _ in 0..2 {
                    let (status, _, answer) = exchange(&router, delete()).await;
                    assert!(status.is_success(), "{status}: {answer}");
                    answers.push(answer);
                }
                digests.push(bound_digest(
                    &actor,
                    &delete_key,
                    "connection.delete",
                    &id,
                    &oauth_etag,
                    "",
                ));

                fail_every_reservation(&connection_db.path);
                let collection = connection_collection_etag(&router).await;
                let failed_key = caller_key(92);
                let failing = marked_connection_body(SUFFIXES[2]);
                let (status, _, failed) =
                    exchange(&router, create(&failing, &failed_key, &collection)).await;
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{failed}");
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
                assert_eventually(Duration::from_secs(5), || changes() >= 4);
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
    let mut committed = vec![
        digests[0].clone(),
        digests[2].clone(),
        digests[4].clone(),
        digests[5].clone(),
    ];
    committed.sort();
    assert_eq!(reserved, committed);

    let markers: Vec<String> = SUFFIXES
        .iter()
        .flat_map(|suffix| {
            REFERENCE_MARKERS
                .iter()
                .chain(DELEGATED_MARKERS.iter())
                .chain(OAUTH_MARKERS.iter())
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

/// I5 for the catalog family through the real handlers. The catalog's
/// Connection is enabled and credentialed: its bearer and additional-header
/// secrets are operator aliases whose IDs, file locators and values are
/// [`CATALOG_SOURCE_MARKERS`], and its discovery uses the Connection's
/// authentication. Against it: a keyed OpenAPI registration, its exact
/// retry and its key reused on the refresh route; a keyed refresh, which
/// loads that Connection and republishes the stored specification, and its
/// exact retry; a keyed overlay replacement whose document carries a marker
/// in its own description and in a tool's, its exact retry and a retry
/// naming other markers; a keyed overlay replacement with
/// `allow_unresolved_enum_sources` whose enum source request names a marker
/// in its path and in a query value, and its exact retry; a keyed overlay
/// delete of an overlay holding those markers, and its exact retry. Then,
/// with the Connection replaced to name a discovery path: a keyed refresh
/// refused at the egress preflight (`502 egress_denied`: its host is not
/// admitted, so nothing is resolved or sent); a keyed refresh from a
/// loopback upstream the test controls, which records that it received the
/// bearer value and the additional header's value read from the aliases'
/// files, so the aliases were resolved and their files read; a keyed
/// refresh that fails after that (the upstream answers `500`, the refresh
/// `502 request_failed`, and the upstream again received both values); and
/// a keyed overlay replacement whose reservation cannot be written. The
/// upstream requires a TLS client certificate, which the Connection names
/// through two operator aliases whose IDs and file locators are
/// [`CLIENT_TLS_MARKERS`]; each fetch records that the certificate presented
/// is the one issued for the run, so both aliases were resolved and their
/// files read. No marker, no line of the client private key and no binding
/// digest reaches a log line, the rendered metrics, a receipt, a conflict
/// or failure answer, or the audit stream.
///
/// Not driven: `catalog.mcp.publish`, which needs an MCP upstream to list
/// tools from. The registration's and the first overlay replacement's own
/// answers are the catalog's view for the caller who changed it, so they
/// are not searched.
#[test]
fn a_keyed_catalog_change_keeps_synthetic_markers_out_of_the_receipt_audit_logs_and_metrics() {
    let connection_db = TempDb::new("keyed-catalog-markers");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let (audit_log, capture) = captured_audit();
    write_catalog_source_secrets(&connection_db);
    let ((answers, digests, committed), logged, rendered) =
        super::super::admin_tokens_app_tests::capture_logs_and_metrics_on_every_runtime_thread(
            async {
                let upstream = RecordingSpecUpstream::spawn(&connection_db).await;
                let router =
                    keyed_connection_router(&connection_db, &policy, audit_log, |config| {
                        configure_catalog_source_aliases(config);
                        // Loopback only, where the upstream listens.
                        config.egress_allowed_hosts = vec!["127.0.0.1".to_owned()];
                        config.egress_deny_private_ips = false;
                    });
                let roles: Vec<&str> = std::iter::once("connections-superadmin")
                    .chain(CATALOG_ROLES.iter().copied())
                    .collect();
                let admin = keyed_admin(&roles);
                let actor = auth::change_actor::ChangeActor::from_principal(&admin);
                let mut answers = Vec::new();
                let mut digests = Vec::new();
                let mut committed = Vec::new();
                let (id, etag) = create_credentialed_catalog_connection(&router, &admin).await;

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
                let refresh = |key: &str| {
                    CatalogCall::Refresh.request(&id, &etag, None, admin.clone(), Some(key))
                };
                let (status, _, conflict) = exchange(&router, refresh(&register_key)).await;
                assert_eq!(status, StatusCode::CONFLICT, "{conflict}");
                answers.push(conflict);
                committed.push(bound_digest(
                    &actor,
                    &register_key,
                    "catalog.openapi.publish",
                    &id,
                    &etag,
                    &registration,
                ));
                // The refresh route binds no body.
                digests.push(bound_digest(
                    &actor,
                    &register_key,
                    "catalog.openapi.publish",
                    &id,
                    &etag,
                    "",
                ));

                let refresh_key = caller_key(98);
                for _ in 0..2 {
                    let (status, _, answer) = exchange(&router, refresh(&refresh_key)).await;
                    assert_eq!(status, StatusCode::OK, "{answer}");
                    answers.push(answer);
                }
                committed.push(bound_digest(
                    &actor,
                    &refresh_key,
                    "catalog.openapi.publish",
                    &id,
                    &etag,
                    "",
                ));

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
                committed.push(bound_digest(
                    &actor,
                    &put_key,
                    "catalog.overlay.replace",
                    &id,
                    &overlay,
                    &marked,
                ));
                digests.push(bound_digest(
                    &actor,
                    &put_key,
                    "catalog.overlay.replace",
                    &id,
                    &overlay,
                    &conflicting,
                ));

                // An enum source the gateway would fetch with the
                // Connection's credentials, admitted unresolved.
                let overlay = overlay_etag(&router, &id).await;
                let sourced_key = caller_key(99);
                let sourced = enum_source_overlay_document();
                let (_, overlay_route) = CatalogCall::OverlayPut.route(&id);
                let put_sourced = || {
                    keyed_connection_request(
                        Method::PUT,
                        &format!("{overlay_route}?allow_unresolved_enum_sources=true"),
                        admin.clone(),
                        Some(sourced.clone()),
                        Some(&overlay),
                        Some(&sourced_key),
                    )
                };
                for _ in 0..2 {
                    let (status, _, answer) = exchange(&router, put_sourced()).await;
                    assert_eq!(status, StatusCode::OK, "{answer}");
                    answers.push(answer);
                }
                committed.push(bound_digest(
                    &actor,
                    &sourced_key,
                    "catalog.overlay.replace",
                    &id,
                    &overlay,
                    &json!([
                        serde_json::from_str::<Value>(&sourced).expect("the overlay is JSON"),
                        {"allow_unresolved_enum_sources": true}
                    ])
                    .to_string(),
                ));

                let overlay = overlay_etag(&router, &id).await;
                let delete_key = caller_key(100);
                for _ in 0..2 {
                    let (status, _, answer) = exchange(
                        &router,
                        CatalogCall::OverlayDelete.request(
                            &id,
                            &overlay,
                            None,
                            admin.clone(),
                            Some(&delete_key),
                        ),
                    )
                    .await;
                    assert_eq!(status, StatusCode::OK, "{answer}");
                    answers.push(answer);
                }
                committed.push(bound_digest(
                    &actor,
                    &delete_key,
                    "catalog.overlay.delete",
                    &id,
                    &overlay,
                    "",
                ));

                // The Connection, replaced without a key, names a discovery
                // path at a host the egress policy does not admit: a keyed
                // refresh is refused at the egress preflight, before any
                // secret is resolved, and the upstream hears nothing.
                let route = format!("{CONNECTIONS_ADMIN_ROUTE}/{id}");
                let replace = |body: String, if_match: &str| {
                    keyed_connection_request(
                        Method::PUT,
                        &route,
                        admin.clone(),
                        Some(body),
                        Some(if_match),
                        None,
                    )
                };
                let (status, refused_etag, replaced) = exchange(
                    &router,
                    replace(
                        credentialed_catalog_connection_body(Some("/openapi.json")),
                        &etag,
                    ),
                )
                .await;
                assert_eq!(status, StatusCode::OK, "{replaced}");
                let refused_etag = refused_etag.expect("the replacement names its ETag");
                let keyed_refresh = |key: &str, if_match: &str| {
                    CatalogCall::Refresh.request(&id, if_match, None, admin.clone(), Some(key))
                };
                let refused_key = caller_key(101);
                let (status, _, refused) =
                    exchange(&router, keyed_refresh(&refused_key, &refused_etag)).await;
                assert_eq!(status, StatusCode::BAD_GATEWAY, "{refused}");
                assert_eq!(refused["reason"], "egress_denied", "{refused}");
                assert!(upstream.take_received().is_empty());
                answers.push(refused);
                digests.push(bound_digest(
                    &actor,
                    &refused_key,
                    "catalog.openapi.publish",
                    &id,
                    &refused_etag,
                    "",
                ));

                // Replaced to fetch from the upstream the test controls, a
                // keyed refresh resolves both operator aliases, reads their
                // files and sends their values: the upstream received them.
                let (status, fetched_etag, replaced) = exchange(
                    &router,
                    replace(
                        credentialed_catalog_connection_body_at(
                            &upstream.base_url(),
                            Some("/openapi.json"),
                        ),
                        &refused_etag,
                    ),
                )
                .await;
                assert_eq!(status, StatusCode::OK, "{replaced}");
                let fetched_etag = fetched_etag.expect("the replacement names its ETag");
                let fetched_key = caller_key(102);
                let (status, _, fetched) =
                    exchange(&router, keyed_refresh(&fetched_key, &fetched_etag)).await;
                assert_eq!(status, StatusCode::OK, "{fetched}");
                assert_eq!(upstream.take_received(), [resolved_catalog_credentials()]);
                let fetched_revision = fetched["catalog_revision"]
                    .as_u64()
                    .expect("the refresh names its catalog revision");
                answers.push(fetched);
                committed.push(bound_digest(
                    &actor,
                    &fetched_key,
                    "catalog.openapi.publish",
                    &id,
                    &fetched_etag,
                    "",
                ));

                // A keyed refresh whose fetch fails after the credentials
                // were resolved and sent: the upstream answers `500`.
                upstream.fail();
                let failed_key = caller_key(103);
                let (status, _, failed) =
                    exchange(&router, keyed_refresh(&failed_key, &fetched_etag)).await;
                assert_eq!(status, StatusCode::BAD_GATEWAY, "{failed}");
                assert_eq!(failed["reason"], "request_failed", "{failed}");
                assert_eq!(upstream.take_received(), [resolved_catalog_credentials()]);
                answers.push(failed);
                digests.push(bound_digest(
                    &actor,
                    &failed_key,
                    "catalog.openapi.publish",
                    &id,
                    &fetched_etag,
                    "",
                ));

                fail_every_reservation(&connection_db.path);
                let overlay = overlay_etag(&router, &id).await;
                let failed_key = caller_key(95);
                let failing = marked_overlay_document(SUFFIXES[2]);
                let (status, _, failed) =
                    exchange(&router, put(&failing, &failed_key, &overlay)).await;
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{failed}");
                answers.push(failed);
                digests.push(bound_digest(
                    &actor,
                    &failed_key,
                    "catalog.overlay.replace",
                    &id,
                    &overlay,
                    &failing,
                ));

                // The audit writer delivers in order: wait until it has
                // delivered the publication of the fetched refresh, the last
                // this test commits, before the audit stream is searched.
                assert!(catalog_changes_through(&capture, &id, fetched_revision) >= 5);
                (answers, digests, committed)
            },
        );

    // The digests computed here are the ones the handlers bound.
    let mut reserved: Vec<String> = standalone_reservations(&connection_db.path)
        .into_iter()
        .map(|(_, _, digest)| digest.expect("every catalog key is bound by digest"))
        .collect();
    reserved.sort();
    let mut expected = committed.clone();
    expected.sort();
    assert_eq!(reserved, expected);

    let markers: Vec<String> = SUFFIXES
        .iter()
        .flat_map(|suffix| {
            OVERLAY_MARKERS
                .iter()
                .map(move |marker| format!("{marker}{suffix}"))
        })
        .chain(
            CATALOG_SOURCE_MARKERS
                .iter()
                .chain(ENUM_SOURCE_MARKERS.iter())
                .chain(CLIENT_TLS_MARKERS.iter())
                .map(|marker| (*marker).to_owned()),
        )
        .chain(client_private_key_lines(&connection_db))
        .collect();
    let digests: Vec<String> = digests.into_iter().chain(committed).collect();
    assert_nothing_marked_escaped(
        &markers,
        &digests,
        &format!("{answers:?}"),
        &format!("{:?}", capture.events()),
        &logged,
        &rendered,
    );
}

/// A catalog Connection's credentials: the IDs of its two operator secret
/// aliases (bearer, then additional header), the file each reads, and the
/// value in that file.
pub(super) const CATALOG_SOURCE_MARKERS: [&str; 6] = [
    "marked-catalog-authentication-alias",
    "marked-catalog-header-alias",
    "marked-catalog-authentication-locator",
    "marked-catalog-header-locator",
    "marked-catalog-authentication-secret-value",
    "marked-catalog-header-secret-value",
];

/// An overlay enum source's request path and query value.
pub(super) const ENUM_SOURCE_MARKERS: [&str; 2] = [
    "marked-catalog-enum-source-path",
    "marked-catalog-enum-source-query",
];

/// Writes each [`CATALOG_SOURCE_MARKERS`] value to its locator in the test
/// secret root of `connection_db`.
pub(super) fn write_catalog_source_secrets(connection_db: &TempDb) {
    let secret_root = connection_db.path.with_extension("secrets");
    fs::create_dir_all(&secret_root).expect("the test secret root creates");
    for (locator, value) in [
        (CATALOG_SOURCE_MARKERS[2], CATALOG_SOURCE_MARKERS[4]),
        (CATALOG_SOURCE_MARKERS[3], CATALOG_SOURCE_MARKERS[5]),
    ] {
        let file = secret_root.join(locator);
        fs::write(&file, value).expect("the test secret writes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600))
                .expect("the test secret permissions set");
        }
    }
}

/// Configures the two operator aliases of [`CATALOG_SOURCE_MARKERS`], the
/// two of [`CLIENT_TLS_MARKERS`] and [`UPSTREAM_CA_ALIAS`].
pub(super) fn configure_catalog_source_aliases(config: &mut config::Config) {
    for (id, locator) in [
        (CATALOG_SOURCE_MARKERS[0], CATALOG_SOURCE_MARKERS[2]),
        (CATALOG_SOURCE_MARKERS[1], CATALOG_SOURCE_MARKERS[3]),
        (CLIENT_TLS_MARKERS[0], CLIENT_TLS_MARKERS[2]),
        (CLIENT_TLS_MARKERS[1], CLIENT_TLS_MARKERS[3]),
    ] {
        config
            .connection_secret_aliases
            .push(connections::secret::OperatorSecretAliasConfig {
                id: id.to_owned(),
                label: "Marked catalog alias".to_owned(),
                source: connections::secret::OperatorSecretAliasSource::File {
                    key: locator.to_owned(),
                },
            });
    }
    config
        .connection_secret_aliases
        .push(connections::secret::OperatorSecretAliasConfig {
            id: UPSTREAM_CA_ALIAS.to_owned(),
            label: "Catalog upstream CA".to_owned(),
            source: connections::secret::OperatorSecretAliasSource::File {
                key: UPSTREAM_CA_LOCATOR.to_owned(),
            },
        });
}

/// The endpoint of [`credentialed_catalog_connection_body`]: a host no test
/// egress policy admits.
pub(super) const UNADMITTED_CATALOG_ENDPOINT: &str = "https://openapi.example.test";

/// The body of an enabled managed OpenAPI Connection whose discovery uses
/// its own bearer and additional-header secrets, the aliases of
/// [`CATALOG_SOURCE_MARKERS`], with `discovery_path` as its discovery path
/// at [`UNADMITTED_CATALOG_ENDPOINT`].
pub(super) fn credentialed_catalog_connection_body(discovery_path: Option<&str>) -> String {
    credentialed_catalog_connection_body_at(UNADMITTED_CATALOG_ENDPOINT, discovery_path)
}

/// [`credentialed_catalog_connection_body`] with `base_url` as its endpoint;
/// any other endpoint than [`UNADMITTED_CATALOG_ENDPOINT`] is a
/// [`RecordingSpecUpstream`], whose CA it trusts through
/// [`UPSTREAM_CA_ALIAS`] and to which it presents the client identity of
/// [`CLIENT_TLS_MARKERS`].
pub(super) fn credentialed_catalog_connection_body_at(
    base_url: &str,
    discovery_path: Option<&str>,
) -> String {
    let mut discovery = json!({"type": "managed_openapi", "use_connection_authentication": true});
    // Only the test's own upstream needs its CA trusted and a client identity.
    let tls = if base_url == UNADMITTED_CATALOG_ENDPOINT {
        json!({})
    } else {
        json!({
            "ca_bundle_alias": UPSTREAM_CA_ALIAS,
            "client_certificate_id": CLIENT_TLS_MARKERS[0],
            "client_private_key_id": CLIENT_TLS_MARKERS[1]
        })
    };
    if let Some(path) = discovery_path {
        discovery["path"] = json!(path);
    }
    json!({
        "display_name": format!("Marked catalog {}", discovery_path.unwrap_or("upload")),
        "enabled": true,
        "kind": "http_api",
        "endpoint": {"base_url": base_url, "base_path": "/v1"},
        "authentication": {"type": "static_bearer", "secret_id": CATALOG_SOURCE_MARKERS[0]},
        "additional_headers": [
            {"header_name": "x-proxy-token", "secret_id": CATALOG_SOURCE_MARKERS[1]}
        ],
        "tls": tls,
        "discovery": discovery
    })
    .to_string()
}

/// Creates the Connection of [`credentialed_catalog_connection_body`],
/// without a discovery path and without a key; returns its ID and ETag. Its
/// answer names its references to its creator and is not kept.
async fn create_credentialed_catalog_connection(
    router: &Router,
    admin: &auth::Principal,
) -> (String, String) {
    let collection = connection_collection_etag(router).await;
    let (status, etag, created) = exchange(
        router,
        keyed_connection_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            admin.clone(),
            Some(credentialed_catalog_connection_body(None)),
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

/// The credentials a catalog Connection's discovery sends, as one upstream
/// request carried them: the `authorization` and `x-proxy-token` headers,
/// and whether the TLS client certificate it presented is the one
/// [`RecordingSpecUpstream::spawn`] issued for the run.
pub(super) type ReceivedCredentials = (Option<String>, Option<String>, bool);

/// What a fetch of the catalog Connection's specification must carry: the
/// two secret values of [`CATALOG_SOURCE_MARKERS`], read from the files the
/// operator aliases name, over a connection authenticated with the client
/// identity the [`CLIENT_TLS_MARKERS`] aliases name.
pub(super) fn resolved_catalog_credentials() -> ReceivedCredentials {
    (
        Some(format!("Bearer {}", CATALOG_SOURCE_MARKERS[4])),
        Some(CATALOG_SOURCE_MARKERS[5].to_owned()),
        true,
    )
}

/// The operator alias, and the file it reads in the test secret root, of the
/// CA that [`RecordingSpecUpstream`]'s certificate chains to. A CA
/// certificate is not a secret, so these are not markers.
pub(super) const UPSTREAM_CA_ALIAS: &str = "catalog-upstream-ca";
const UPSTREAM_CA_LOCATOR: &str = "catalog-upstream-ca.pem";

/// The TLS client identity a credentialed catalog Connection presents to
/// [`RecordingSpecUpstream`], which requires one: the IDs of its operator
/// aliases (certificate, then private key) and the file each reads in the
/// test secret root. [`RecordingSpecUpstream::spawn`] writes a certificate
/// and key generated for the run to those files.
pub(super) const CLIENT_TLS_MARKERS: [&str; 4] = [
    "marked-catalog-client-certificate-alias",
    "marked-catalog-client-key-alias",
    "marked-catalog-client-certificate-locator",
    "marked-catalog-client-key-locator",
];

/// Each base64 line of the TLS client private key [`RecordingSpecUpstream`]
/// wrote for the run in the test secret root of `connection_db`: no line of
/// the key may reach anything a test searches.
pub(super) fn client_private_key_lines(connection_db: &TempDb) -> Vec<String> {
    let pem = fs::read_to_string(
        connection_db
            .path
            .with_extension("secrets")
            .join(CLIENT_TLS_MARKERS[3]),
    )
    .expect("the client key file reads");
    let lines: Vec<String> = pem
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with("-----"))
        .map(str::to_owned)
        .collect();
    assert!(!lines.is_empty(), "the client key has a body");
    lines
}

/// A loopback HTTPS upstream the test controls, standing in for a catalog
/// Connection's specification host (a credentialed Connection must use
/// HTTPS). It requires a TLS client certificate from a client CA generated
/// for the run, so a handshake without one fails and nothing is recorded.
/// It records the credentials of every request it receives and answers with
/// the widget specification, or with `500` once [`Self::fail`] was called.
pub(super) struct RecordingSpecUpstream {
    address: std::net::SocketAddr,
    received: Arc<std::sync::Mutex<Vec<ReceivedCredentials>>>,
    failing: Arc<std::sync::atomic::AtomicBool>,
}

impl RecordingSpecUpstream {
    /// Starts the upstream under a CA generated for this run, whose
    /// certificate it writes to [`UPSTREAM_CA_LOCATOR`] in the test secret
    /// root of `connection_db`, and writes the client certificate and key
    /// it will require to the [`CLIENT_TLS_MARKERS`] locators beside it.
    pub(super) async fn spawn(connection_db: &TempDb) -> Self {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let (ca_pem, server_cert_der, server_key_der) = test_ca_signed_server_certificate();
        let (client_ca_der, client_cert_pem, client_key_pem, client_cert_der) =
            test_ca_signed_client_identity();
        let secret_root = connection_db.path.with_extension("secrets");
        fs::create_dir_all(&secret_root).expect("the test secret root creates");
        for (locator, contents) in [
            (UPSTREAM_CA_LOCATOR, ca_pem),
            (CLIENT_TLS_MARKERS[2], client_cert_pem),
            (CLIENT_TLS_MARKERS[3], client_key_pem),
        ] {
            let file = secret_root.join(locator);
            fs::write(&file, contents).expect("the TLS file writes");
            // An operator file alias refuses a file others can read, so
            // these files need the same mode as the secret files beside them.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&file, fs::Permissions::from_mode(0o600))
                    .expect("the TLS file permissions set");
            }
        }
        let mut client_roots = tokio_rustls::rustls::RootCertStore::empty();
        client_roots
            .add(CertificateDer::from(client_ca_der))
            .expect("the client CA is accepted");
        let client_verifier =
            tokio_rustls::rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
                .build()
                .expect("the client certificate verifier builds");
        let acceptor = TlsAcceptor::from(Arc::new(
            ServerConfig::builder()
                .with_client_cert_verifier(client_verifier)
                .with_single_cert(
                    vec![CertificateDer::from(server_cert_der)],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key_der)),
                )
                .expect("the upstream TLS configuration builds"),
        ));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("the upstream binds");
        let address = listener.local_addr().expect("the upstream has an address");
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let failing = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (recorded, fails) = (Arc::clone(&received), Arc::clone(&failing));
        let issued = Arc::new(client_cert_der);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (acceptor, recorded, fails, issued) = (
                    acceptor.clone(),
                    Arc::clone(&recorded),
                    Arc::clone(&fails),
                    Arc::clone(&issued),
                );
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let presented_issued = stream
                        .get_ref()
                        .1
                        .peer_certificates()
                        .and_then(|chain| chain.first())
                        .is_some_and(|leaf| leaf.as_ref() == issued.as_slice());
                    let Some((authorization, proxy_token)) =
                        read_request_credentials(&mut stream).await
                    else {
                        return;
                    };
                    recorded.lock().expect("the record locks").push((
                        authorization,
                        proxy_token,
                        presented_issued,
                    ));
                    let response = if fails.load(std::sync::atomic::Ordering::SeqCst) {
                        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\
                         Connection: close\r\n\r\n"
                            .to_owned()
                    } else {
                        let spec = widget_openapi_spec();
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{spec}",
                            spec.len()
                        )
                    };
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Self {
            address,
            received,
            failing,
        }
    }

    /// The base URL a Connection names to fetch from this upstream.
    pub(super) fn base_url(&self) -> String {
        format!("https://{}", self.address)
    }

    /// From here on every request is answered `500`.
    pub(super) fn fail(&self) {
        self.failing
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// The requests received since the last call, oldest first.
    pub(super) fn take_received(&self) -> Vec<ReceivedCredentials> {
        std::mem::take(&mut *self.received.lock().expect("the record locks"))
    }
}

/// A client CA generated for the run and a client certificate it signed:
/// the CA's DER, the certificate and its private key as PEM, and the
/// certificate's DER.
fn test_ca_signed_client_identity() -> (Vec<u8>, String, String, Vec<u8>) {
    let mut ca_params = rcgen::CertificateParams::default();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "GreenGateway Test Client CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key = rcgen::KeyPair::generate().expect("the client CA key generates");
    let ca = ca_params
        .self_signed(&ca_key)
        .expect("the client CA certificate builds");
    let mut params = rcgen::CertificateParams::new(vec!["catalog-client.example.test".to_owned()])
        .expect("the client certificate parameters build");
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let key = rcgen::KeyPair::generate().expect("the client key generates");
    let certificate = params
        .signed_by(&key, &rcgen::Issuer::from_params(&ca_params, &ca_key))
        .expect("the client certificate builds");
    (
        ca.der().as_ref().to_vec(),
        certificate.pem(),
        key.serialize_pem(),
        certificate.der().as_ref().to_vec(),
    )
}

/// Reads one request's head from `stream` and returns its `authorization`
/// and `x-proxy-token` headers, or `None` if the stream closes first.
async fn read_request_credentials(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Option<(Option<String>, Option<String>)> {
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        head.extend_from_slice(&chunk[..read]);
        assert!(head.len() <= 16 * 1024, "the request head stays bounded");
    }
    let head = String::from_utf8(head).expect("the request head is text");
    let named = |name: &str| {
        head.split("\r\n").skip(1).find_map(|line| {
            let (header, value) = line.split_once(':')?;
            header
                .trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
    };
    Some((named("authorization"), named("x-proxy-token")))
}

/// An overlay whose one enum source requests a path and a query value that
/// are [`ENUM_SOURCE_MARKERS`].
pub(super) fn enum_source_overlay_document() -> String {
    json!({
        "schema_version": "0.1.0",
        "enum_sources": {
            "statuses": {
                "request": {
                    "path": format!("/{}", ENUM_SOURCE_MARKERS[0]),
                    "query": {"filter": ENUM_SOURCE_MARKERS[1]}
                },
                "select": {"items": "/items/*", "value": "/value"}
            }
        }
    })
    .to_string()
}
