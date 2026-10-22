//! Required audit durability end to end (issue #425): the real
//! authentication and authorization stages, the standalone SQLite store of
//! record, a proxy route bound to a Connection whose credential is an
//! encrypted local secret, and a capturing HTTPS upstream whose CA is an
//! encrypted local secret too.
//!
//! Two properties are proved against the stored rows rather than against a
//! capture sink. The decision records a request waits on reach the store
//! before the request is forwarded, and while the store cannot commit,
//! the request is refused with `503 audit_unavailable` and the upstream sees
//! nothing. And the records those producers write carry none of the
//! material the request handled: the caller's token, cookie, headers and
//! query, the Connection's secret value, its ciphertext and nonce, or where
//! the key that sealed it lives. Every marker is generated per run, so no
//! fixture value can be mistaken for a credential.

use base64::Engine as _;

use super::*;

/// A value no record may contain, generated for this run.
fn marker(label: &str) -> String {
    format!("synthetic-{label}-{}", uuid::Uuid::new_v4().simple())
}

/// Every audit row the store holds, each flattened to one string of all its
/// columns, with the event type alongside.
fn stored_rows(path: &std::path::Path) -> Vec<(String, String)> {
    let connection = Connection::open(path).expect("the audit store should open");
    let mut statement = connection
        .prepare(
            "SELECT event_type, event_id || ' ' || event_type || ' ' || timestamp || ' ' || \
                    request_id || ' ' || source_ip || ' ' || coalesce(user_agent, '') || ' ' || \
                    coalesce(actor_json, '') || ' ' || coalesce(payload_path, '') || ' ' || \
                    payload_json \
             FROM audit_events ORDER BY id",
        )
        .expect("the audit query should prepare");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("the audit rows should read")
        .collect::<Result<Vec<_>, _>>()
        .expect("every audit row should decode")
}

async fn wait_for_rows(
    path: &std::path::Path,
    wanted: &[&str],
    context: &str,
) -> Vec<(String, String)> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let rows = stored_rows(path);
        if wanted
            .iter()
            .all(|event_type| rows.iter().any(|(stored, _)| stored == event_type))
        {
            return rows;
        }
        assert!(
            Instant::now() < deadline,
            "{context}: the store never held {wanted:?}; it holds {:?}",
            rows.iter()
                .map(|(event_type, _)| event_type)
                .collect::<Vec<_>>()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn required_durability_forwards_only_durably_recorded_decisions_and_keeps_secrets_out_of_them(
) {
    let jwks_addr = spawn_test_jwks_server().await;
    // A credentialed Connection must use HTTPS, so the upstream terminates
    // TLS under a CA generated for this run.
    let TlsCaptureUpstream {
        addr: upstream_addr,
        ca_pem,
        mut captured,
    } = spawn_tls_capture_upstream().await;
    let audit_db = TempDb::new("audit-durability-required");
    let connection_db = TempDb::new("audit-durability-connections");
    let secret_root = connection_db.path.with_extension("secrets");
    fs::create_dir_all(&secret_root).expect("the secret root should create");
    let master_key_file = format!("{}.key", marker("master-key-file"));
    // A fresh key every run: two random UUIDs are the 32 key bytes.
    let master_key = [
        uuid::Uuid::new_v4().into_bytes(),
        uuid::Uuid::new_v4().into_bytes(),
    ]
    .concat();
    fs::write(secret_root.join(&master_key_file), &master_key)
        .expect("the local master key should write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
            .expect("the secret root permissions should set");
        fs::set_permissions(
            secret_root.join(&master_key_file),
            fs::Permissions::from_mode(0o600),
        )
        .expect("the master key permissions should set");
    }

    let policy = TempPolicyFile::new(
        &json!({
            "schema_version": "0.1.0",
            "default_action": "deny",
            "enforcement_mode": "enforce",
            "roles": { "billing-reader": { "permissions": ["billing:read"] } },
            "routes": [
                { "methods": ["GET"], "path_prefix": "/billing", "permission": "billing:read" }
            ]
        })
        .to_string(),
    );
    let mut config = routing_proxy_config(Vec::new());
    config.auth_enabled = true;
    configure_test_jwt_provider(&mut config, jwks_addr);
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.audit_sqlite_path = Some(audit_db.path.to_string_lossy().into_owned());
    config.connections_sqlite_path = Some(connection_db.path.to_string_lossy().into_owned());
    config.connection_secrets_root = Some(connections::secret::SecretRootConfig::new(
        secret_root.clone(),
    ));
    config.connection_local_secret_keyring =
        vec![connections::local_secret::LocalSecretKeyConfig {
            id: "durability-primary".to_owned(),
            file: master_key_file.clone(),
            role: connections::local_secret::LocalSecretKeyRole::Primary,
        }];
    config.egress_allowed_hosts = vec!["127.0.0.1".to_owned()];
    // A locked SQLite file holds a writer for its busy timeout, so the
    // stalled request below is refused at this bound rather than waiting
    // the default five seconds.
    config.audit_durability_timeout_ms = 1_000;
    assert_eq!(
        config.audit_durability,
        config::AuditDurability::Required,
        "this proves the default, so it must run under it"
    );

    // The Connection's credential: an encrypted local secret, sealed with
    // the key above, behind a proxy route the policy authorizes.
    let upstream_secret = marker("upstream-secret");
    let control_plane = Arc::new(
        connections::control_plane::ConnectionControlPlane::from_config(&config)
            .expect("the Connection control plane should build"),
    );
    // The local secret store is synchronous and takes a blocking lock, so it
    // is driven off the runtime, the way the admin handlers drive it.
    let seal = |label: &'static str, purpose, value: Vec<u8>| {
        let control_plane = Arc::clone(&control_plane);
        async move {
            tokio::task::spawn_blocking(move || {
                control_plane
                    .local_secret_manager()
                    .expect("the local secret store is configured")
                    .create(
                        label,
                        connections::secret::ResolvedSecret::new(purpose, value)
                            .expect("the secret value is valid"),
                    )
            })
            .await
            .expect("sealing should not panic")
            .expect("the local secret should seal")
        }
    };
    let sealed = seal(
        "Billing upstream token",
        connections::secret::SecretPurpose::StaticBearer,
        upstream_secret.clone().into_bytes(),
    )
    .await;
    let sealed_ca = seal(
        "Billing upstream CA",
        connections::secret::SecretPurpose::TlsCaBundle,
        ca_pem.into_bytes(),
    )
    .await;
    let created = control_plane
        .create_managed(
            control_plane.runtime_snapshot().collection_etag(),
            serde_json::from_value(json!({
                "display_name": "Billing API",
                "enabled": true,
                "kind": "http_api",
                "endpoint": {
                    "base_url": format!("https://127.0.0.1:{}", upstream_addr.port()),
                    "base_path": "/v1"
                },
                "authentication": { "type": "static_bearer", "secret_id": sealed.id },
                "tls": { "ca_bundle_alias": sealed_ca.id }
            }))
            .expect("the Connection should deserialize"),
            "test-admin",
        )
        .await
        .expect("the Connection should create");
    drop(control_plane);
    let (ciphertext, nonce): (Vec<u8>, Vec<u8>) = Connection::open(&connection_db.path)
        .expect("the Connection store should open")
        .query_row(
            "SELECT ciphertext, nonce FROM connection_local_secrets WHERE id = ?1",
            params![sealed.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the sealed secret should be stored");
    let mut route = path_route("/billing", upstream_addr);
    route.id = Some("billing-route".to_owned());
    route.connection_id = Some(created.id.to_string());
    route.upstream_url.clear();
    config.upstream_routes = vec![route];

    let (audit_log, audit_event_sender) =
        audit::AuditLog::from_config(&config).expect("required durability over SQLite builds");
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(config, recorder.handle(), audit_log, audit_event_sender)
        .expect("the required-durability app should build");

    let token = signed_token("durable-billing-reader", &["billing-reader"]);
    let cookie_secret = marker("cookie");
    let header_secret = marker("header");
    let query_secret = marker("query");
    let billing_request = || {
        Request::builder()
            .uri(format!("/billing/charges?api_key={query_secret}"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::COOKIE, format!("session={cookie_secret}"))
            .header("x-api-key", header_secret.as_str())
            .body(Body::empty())
            .expect("the billing request should build")
    };

    // 1. Served: the decisions are durable before the upstream is called,
    //    and the upstream gets the Connection's credential.
    let response = router
        .clone()
        .oneshot(billing_request())
        .await
        .expect("the billing request should complete");
    assert_eq!(response.status(), StatusCode::CREATED);
    let decisions = stored_rows(&audit_db.path);
    for event_type in ["auth.success", "authz.allowed"] {
        assert!(
            decisions.iter().any(|(stored, _)| stored == event_type),
            "{event_type} must be stored by the time the request is answered: {:?}",
            decisions
                .iter()
                .map(|(stored, _)| stored)
                .collect::<Vec<_>>()
        );
    }
    let upstream = next_proxied_request(&mut captured, "the served request").await;
    assert_eq!(
        upstream
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        Some(format!("Bearer {upstream_secret}").as_str()),
        "the secret was in play, so its absence from the records below is evidence"
    );

    // 2. Nothing the request handled reached a record.
    let rows = wait_for_rows(
        &audit_db.path,
        &["auth.success", "authz.allowed", "http.request_observed"],
        "the served request",
    )
    .await;
    let signature = token
        .rsplit('.')
        .next()
        .expect("a JWT has a signature segment")
        .to_owned();
    let forbidden = [
        ("the caller's bearer token", token.clone()),
        ("the caller's token signature", signature),
        ("the caller's cookie", cookie_secret.clone()),
        ("a caller header", header_secret.clone()),
        ("the caller's query", query_secret.clone()),
        ("the Connection's secret", upstream_secret.clone()),
        ("the sealed ciphertext (hex)", hex::encode(&ciphertext)),
        (
            "the sealed ciphertext (base64)",
            base64::engine::general_purpose::STANDARD.encode(&ciphertext),
        ),
        ("the seal's nonce (hex)", hex::encode(&nonce)),
        (
            "the seal's nonce (base64)",
            base64::engine::general_purpose::STANDARD.encode(&nonce),
        ),
        ("the master key's file", master_key_file.clone()),
        (
            "the secret root",
            secret_root.to_string_lossy().into_owned(),
        ),
        ("the local secret's id", sealed.id.clone()),
        ("the CA bundle's local secret id", sealed_ca.id.clone()),
    ];
    for (_, row) in &rows {
        for (what, value) in &forbidden {
            assert!(
                !row.contains(value.as_str()),
                "{what} reached an audit record: {row}"
            );
        }
    }

    // 3. The store cannot commit -- another writer holds it -- and the
    //    request is refused before any upstream I/O.
    let holder = Connection::open(&audit_db.path).expect("a second writer should open");
    holder
        .execute_batch("BEGIN EXCLUSIVE")
        .expect("the second writer should take the store");
    let response = router
        .clone()
        .oneshot(billing_request())
        .await
        .expect("the refused request should complete");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the refusal body should read"),
    )
    .expect("the refusal body is JSON");
    assert_eq!(
        body,
        json!({ "error": "audit unavailable", "reason": "audit_unavailable" })
    );
    assert_upstream_receives_no_request(
        &mut captured,
        "a request whose decision cannot be recorded must not reach the upstream",
    )
    .await;

    // 4. Recovery: the store is released and the same request is served,
    //    with no restart and nothing to reset.
    holder
        .execute_batch("ROLLBACK")
        .expect("the second writer should let go");
    drop(holder);
    let response = router
        .oneshot(billing_request())
        .await
        .expect("the recovered request should complete");
    assert_eq!(response.status(), StatusCode::CREATED);
    next_proxied_request(&mut captured, "the recovered request").await;
}
