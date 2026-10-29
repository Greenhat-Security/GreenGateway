use super::*;

#[tokio::test]
async fn auth_disabled_skips_non_exempt_route_without_principal() {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let recorder = PrometheusBuilder::new().build_recorder();

    let response = app(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("app should build")
    .oneshot(
        Request::builder()
            .uri("/__test/principal")
            .body(Body::empty())
            .expect("request should build"),
    )
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eventually(Duration::from_secs(1), || !capture.events().is_empty());
    let events = capture.events();
    assert_eq!(
        events
            .iter()
            .filter(|event| event.event_type == "http.request_observed")
            .count(),
        1
    );
    assert!(!events
        .iter()
        .any(|event| event.event_type.starts_with("auth.")));
}

#[tokio::test]
async fn observe_auth_forwards_anonymous_request_to_rbac_enforcement() {
    let policy = TempPolicyFile::new(
        r#"{
                "schema_version": "0.1.0",
                "default_action": "deny",
                "enforcement_mode": "enforce",
                "roles": {},
                "routes": [
                    {
                        "path_prefix": "/__test",
                        "permission": "test:read"
                    }
                ]
            }"#,
    );
    let mut config = test_config(Vec::new());
    config.auth_mode = config::AuthMode::Observe;
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("app should build");
    let request_id = "request-observe-auth-rbac-deny";

    let response = router
        .oneshot(
            Request::builder()
                .uri("/__test/principal")
                .header(REQUEST_ID_HEADER, request_id)
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(body_string(response).await, r#"{"error":"forbidden"}"#);
    assert_eventually(Duration::from_secs(1), || {
        let events = capture.events();
        events
            .iter()
            .any(|event| event.event_type == "auth.failure")
            && events
                .iter()
                .any(|event| event.event_type == "authz.denied")
            && events
                .iter()
                .any(|event| event.event_type == "http.request_observed")
    });

    let events = capture.events();
    let auth_failure = events
        .iter()
        .find(|event| event.event_type == "auth.failure")
        .expect("auth failure should be captured");
    assert_eq!(auth_failure.request_id, request_id);
    assert_eq!(auth_failure.payload["path"], json!("/__test/principal"));
    assert_eq!(auth_failure.payload["reason"], json!("missing_credential"));

    let authz_denied = events
        .iter()
        .find(|event| event.event_type == "authz.denied")
        .expect("authz denied should be captured");
    assert_eq!(authz_denied.request_id, request_id);
    assert_eq!(authz_denied.payload["path"], json!("/__test/principal"));
    assert_eq!(authz_denied.payload["path_prefix"], json!("/__test"));
    assert_eq!(authz_denied.payload["permission"], json!("test:read"));
    assert_eq!(authz_denied.payload["reason"], json!("missing_principal"));

    let observed = events
        .iter()
        .find(|event| event.event_type == "http.request_observed")
        .expect("observation event should be captured");
    assert_eq!(observed.request_id, request_id);
    assert_eq!(observed.payload["status"], json!(403));
    assert_eq!(
        observed.payload["auth_outcome"],
        json!("anonymous_or_failed")
    );
    assert_eq!(observed.payload["auth_reason"], json!("missing_credential"));
    assert_eq!(observed.payload["policy_decision"], json!("denied"));
    assert_eq!(
        observed.payload["policy_reason"],
        json!("missing_principal")
    );
}

#[tokio::test]
async fn real_service_token_authenticates_through_full_stack() {
    let token_db = TempDb::new("service-token-full-stack");
    let token_store =
        auth::tokens::SqliteTokenStore::open(&token_db.path).expect("token store should open");
    let created = token_store
        .create(auth::tokens::CreateTokenRequest {
            scopes: vec!["probe-reader".to_owned()],
            created_by: "bootstrap-admin".to_owned(),
            expires_at: None,
        })
        .expect("service token should create");
    let policy = TempPolicyFile::new(&service_token_policy_document());
    let mut config = test_config(Vec::new());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
    config.service_token_cache_ttl_ms = 20;
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");

    let response = authenticated_principal_probe(&router, &created.plaintext_token).await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(
        body["user_id"],
        json!(format!("service-token:{}", created.record.id))
    );
    assert_eq!(body["auth_method"], json!("service_token"));
    assert_eq!(body["roles"], json!(["probe-reader"]));
}

#[tokio::test]
async fn real_cookie_session_authenticates_through_full_stack() {
    let (introspection_url, introspection_server) =
        spawn_blocking_cookie_session_server(Ipv4Addr::LOCALHOST, 1);
    let mut config = test_config(Vec::new());
    configure_test_cookie_session_provider(&mut config, introspection_url);
    config.egress_deny_private_ips = false;
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");

    let response = router
        .oneshot(
            Request::builder()
                .uri("/__test/principal")
                .header(header::COOKIE, "session=session-secret-123")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["user_id"], json!("cookie-user"));
    assert_eq!(body["auth_method"], json!("session_cookie"));
    assert_eq!(body["roles"], json!(["admin", "member"]));
    assert_eq!(introspection_server.finish(), 1);
}

#[tokio::test]
async fn cookie_session_introspection_host_is_auto_seeded_for_cross_host_egress() {
    let (introspection_url, introspection_server) =
        spawn_blocking_cookie_session_server(Ipv4Addr::new(127, 0, 0, 2), 1);
    let mut config = test_config(Vec::new());
    configure_test_cookie_session_provider(&mut config, introspection_url);
    config.egress_deny_private_ips = false;
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");

    let response = router
        .oneshot(
            Request::builder()
                .uri("/__test/principal")
                .header(header::COOKIE, "session=session-secret-123")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["user_id"], json!("cookie-user"));
    assert_eq!(introspection_server.finish(), 1);
}

#[tokio::test]
async fn auth_runs_before_rbac_for_non_exempt_routes() {
    let policy = TempPolicyFile::new(
        r#"{
                "schema_version": "0.1.0",
                "default_action": "deny",
                "roles": {}
            }"#,
    );
    let mut config = test_config(Vec::new());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    let recorder = PrometheusBuilder::new().build_recorder();

    let response = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build")
    .oneshot(
        Request::builder()
            .uri("/__test/principal")
            .header(header::AUTHORIZATION, "Bearer token-123")
            .body(Body::empty())
            .expect("request should build"),
    )
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn auth_validator_resolves_oidc_discovery_for_issuer_only_provider() {
    let (issuer, server) = spawn_oidc_jwks_server();
    let issuer_claim = issuer.clone();
    let mut config = test_config(Vec::new());
    config.auth_providers = vec![config::AuthProviderConfig {
        name: "oidc".to_owned(),
        provider_type: config::AuthProviderType::Jwt,
        jwks_url: None,
        issuer: Some(issuer),
        audience: None,
        jwks_timeout_ms: 2000,
        jwks_max_key_age_secs: 300,
        require_jti: false,
        roles_claim: "roles".to_owned(),
        roles_claim_delimiter: None,
        org_claim: None,
        introspection_url: None,
        introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
        cache_ttl_ms: config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
        user_id_claim: None,
        email_claim: None,
        client_id: None,
        client_secret: None,
        redirect_uri: None,
    }];
    config.egress_deny_private_ips = false;
    let egress_client = Arc::new(
        egress::EgressClient::new(egress::EgressConfig::from_config(&config))
            .expect("egress client should build"),
    );
    let discovered_oidc_jwks_urls =
        discover_oidc_jwks_urls_from_config(&config, Arc::clone(&egress_client))
            .expect("issuer-only provider should discover JWKS URI");

    let validator = auth_validator_from_config(
        &config,
        egress_client,
        None,
        &discovered_oidc_jwks_urls,
        None,
        None,
        None,
    )
    .expect("issuer-only provider should build")
    .expect("auth validator should be configured");
    let principal = validator
        .validate_session(&auth::SessionCredential::Bearer(signed_token_with_issuer(
            "oidc-user",
            &["member"],
            &issuer_claim,
        )))
        .await
        .expect("token should validate through discovered JWKS URI");

    assert_eq!(principal.user_id, "oidc-user");
    server.finish();
}

/// Startup hands every JWT validator that has a denylist the observer it
/// passes in, so a JWT refused as revoked names its principal to the
/// Connection runtime, which purges that principal's delegated tokens (issue
/// #441).
#[tokio::test]
async fn a_denylisted_jwt_validator_reports_the_principal_of_a_revoked_token() {
    struct DenyEveryJti;

    #[async_trait::async_trait]
    impl auth::RevocationStore for DenyEveryJti {
        async fn is_revoked(&self, _jti: &str) -> Result<bool, auth::AuthError> {
            Ok(true)
        }
    }

    #[derive(Default)]
    struct RecordingObserver(std::sync::Mutex<Vec<(String, String)>>);

    impl auth::RevokedCredentialObserver for RecordingObserver {
        fn credential_revoked(&self, issuer: &str, subject: &str, _jti: &str) {
            self.0
                .lock()
                .expect("observer lock")
                .push((issuer.to_owned(), subject.to_owned()));
        }
    }

    let (issuer, server) = spawn_oidc_jwks_server();
    let issuer_claim = issuer.clone();
    let mut config = test_config(Vec::new());
    config.auth_providers = vec![config::AuthProviderConfig {
        name: "oidc".to_owned(),
        provider_type: config::AuthProviderType::Jwt,
        jwks_url: None,
        issuer: Some(issuer.clone()),
        audience: None,
        jwks_timeout_ms: 2000,
        jwks_max_key_age_secs: 300,
        require_jti: true,
        roles_claim: "roles".to_owned(),
        roles_claim_delimiter: None,
        org_claim: None,
        introspection_url: None,
        introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
        cache_ttl_ms: config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
        user_id_claim: None,
        email_claim: None,
        client_id: None,
        client_secret: None,
        redirect_uri: None,
    }];
    config.egress_deny_private_ips = false;
    let egress_client = Arc::new(
        egress::EgressClient::new(egress::EgressConfig::from_config(&config))
            .expect("egress client should build"),
    );
    let discovered_oidc_jwks_urls =
        discover_oidc_jwks_urls_from_config(&config, Arc::clone(&egress_client))
            .expect("issuer-only provider should discover JWKS URI");
    let denylist = |_issuer: &str| Arc::new(DenyEveryJti) as Arc<dyn auth::RevocationStore>;
    let observer = Arc::new(RecordingObserver::default());

    let validator = auth_validator_from_config(
        &config,
        egress_client,
        None,
        &discovered_oidc_jwks_urls,
        Some(&denylist as JwtRevocationStoreFactory<'_>),
        Some(Arc::clone(&observer) as Arc<dyn auth::RevokedCredentialObserver>),
        None,
    )
    .expect("issuer-only provider should build")
    .expect("auth validator should be configured");
    let error = validator
        .validate_session(&auth::SessionCredential::Bearer(signed_token_with_issuer(
            "oidc-user",
            &["member"],
            &issuer_claim,
        )))
        .await
        .expect_err("a denylisted jti is refused");

    // The provider chain reports every provider's refusal alike, so the
    // observer is what tells this one apart from a bad signature.
    assert!(
        matches!(&error, auth::AuthError::InvalidSession(_)),
        "{error:?}"
    );
    assert_eq!(
        *observer.0.lock().expect("observer lock"),
        [(issuer, "oidc-user".to_owned())]
    );
    server.finish();
}

/// A deployment whose only credential is a client certificate still gets an
/// auth chain.
///
/// `auth_validator_from_config` returns `None` when nothing is configured,
/// and `None` means the middleware fails closed on every request. Client
/// certificates had to be added to that emptiness test or a listener
/// configured with `CLIENT_CERT_MODE=required` and no token provider at all
/// would answer 401 to the very callers it was set up for -- a
/// misconfiguration that looks exactly like a broken certificate.
#[tokio::test]
async fn a_client_certificate_only_deployment_still_builds_an_auth_chain() {
    let mut config = test_config(Vec::new());
    assert!(
        config.auth_providers.is_empty(),
        "the premise is that nothing else is configured"
    );
    config.client_cert_auth = Some(config::InboundClientAuthConfig {
        mode_setting: "CLIENT_CERT_MODE",
        requirement: crate::inbound_tls::ClientCertRequirement::Required,
        ca_setting: "CLIENT_CERT_CA_FILE",
        ca_file: "client-ca.crt".to_owned(),
        crl_setting: "CLIENT_CERT_CRL_FILE",
        crl_file: None,
        identity_source: auth::ClientCertIdentitySource::Spiffe,
    });
    config.egress_deny_private_ips = false;
    let egress_client = Arc::new(
        egress::EgressClient::new(egress::EgressConfig::from_config(&config))
            .expect("egress client should build"),
    );

    let validator = auth_validator_from_config(
        &config,
        egress_client,
        None,
        &HashMap::new(),
        None,
        None,
        None,
    )
    .expect("a certificate-only configuration should build")
    .expect(
        "a certificate-only configuration must produce a validator, not None; None \
                     makes the auth middleware fail closed on every request",
    );

    assert!(
        validator.supports_client_certificate(),
        "the chain built for a certificate-only deployment must accept certificate credentials"
    );
}

#[tokio::test]
async fn auth_validator_accepts_slashless_oidc_issuer_when_config_has_trailing_slash() {
    let (issuer, document_issuer, server) =
        spawn_oidc_jwks_server_with_document_issuer(str::to_owned);
    let mut config = test_config(Vec::new());
    config.auth_providers = vec![oidc_jwt_provider(format!("{issuer}/"))];
    config.egress_deny_private_ips = false;
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build with slash-normalized OIDC issuer");

    let response = authenticated_principal_probe(
        &router,
        &signed_token_with_issuer("slashless-oidc-user", &["member"], &document_issuer),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await["user_id"],
        json!("slashless-oidc-user")
    );
    server.finish();
}

#[tokio::test]
async fn auth_validator_accepts_slash_retained_oidc_issuer_and_token() {
    let (_issuer, document_issuer, server) =
        spawn_oidc_jwks_server_with_document_issuer(|issuer| format!("{issuer}/"));
    let mut config = test_config(Vec::new());
    config.auth_providers = vec![oidc_jwt_provider(document_issuer.clone())];
    config.egress_deny_private_ips = false;
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build with slash-retained OIDC issuer");

    let response = authenticated_principal_probe(
        &router,
        &signed_token_with_issuer("slash-retained-oidc-user", &["member"], &document_issuer),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await["user_id"],
        json!("slash-retained-oidc-user")
    );
    server.finish();
}

#[test]
fn auth_validator_rejects_oidc_discovery_with_mismatched_issuer() {
    let (issuer, server) = spawn_oidc_discovery_server(
        json!({
            "issuer": "http://attacker.example.test",
            "jwks_uri": "http://127.0.0.1:1/jwks.json"
        }),
        1,
    );
    let mut config = test_config(Vec::new());
    config.auth_providers = vec![config::AuthProviderConfig {
        name: "oidc".to_owned(),
        provider_type: config::AuthProviderType::Jwt,
        jwks_url: None,
        issuer: Some(issuer),
        audience: None,
        jwks_timeout_ms: 2000,
        jwks_max_key_age_secs: 300,
        require_jti: false,
        roles_claim: "roles".to_owned(),
        roles_claim_delimiter: None,
        org_claim: None,
        introspection_url: None,
        introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
        cache_ttl_ms: config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
        user_id_claim: None,
        email_claim: None,
        client_id: None,
        client_secret: None,
        redirect_uri: None,
    }];
    config.egress_deny_private_ips = false;
    let egress_client = Arc::new(
        egress::EgressClient::new(egress::EgressConfig::from_config(&config))
            .expect("egress client should build"),
    );

    let error = discover_oidc_jwks_urls_from_config(&config, egress_client)
        .expect_err("mismatched discovery issuer should fail provider construction");

    assert!(matches!(
        error,
        auth::AuthError::Upstream(message)
            if message.contains("OIDC discovery issuer mismatch")
    ));
    server.finish();
}

#[test]
fn auth_validator_rejects_oidc_discovery_without_issuer() {
    let (issuer, server) = spawn_oidc_discovery_server(
        json!({
            "jwks_uri": "http://127.0.0.1:1/jwks.json"
        }),
        1,
    );
    let mut config = test_config(Vec::new());
    config.auth_providers = vec![config::AuthProviderConfig {
        name: "oidc".to_owned(),
        provider_type: config::AuthProviderType::Jwt,
        jwks_url: None,
        issuer: Some(issuer),
        audience: None,
        jwks_timeout_ms: 2000,
        jwks_max_key_age_secs: 300,
        require_jti: false,
        roles_claim: "roles".to_owned(),
        roles_claim_delimiter: None,
        org_claim: None,
        introspection_url: None,
        introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
        cache_ttl_ms: config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
        user_id_claim: None,
        email_claim: None,
        client_id: None,
        client_secret: None,
        redirect_uri: None,
    }];
    config.egress_deny_private_ips = false;
    let egress_client = Arc::new(
        egress::EgressClient::new(egress::EgressConfig::from_config(&config))
            .expect("egress client should build"),
    );

    let error = discover_oidc_jwks_urls_from_config(&config, egress_client)
        .expect_err("discovery without issuer should fail provider construction");

    assert!(matches!(
        error,
        auth::AuthError::Upstream(message)
            if message.contains("OIDC discovery response missing issuer")
    ));
    server.finish();
}

#[tokio::test]
async fn oidc_discovery_allowlists_jwks_uri_host_when_it_differs_from_issuer() {
    let (jwks_url, jwks_server) = spawn_blocking_jwks_server(Ipv4Addr::new(127, 0, 0, 2), 1);
    let (issuer, discovery_server) = spawn_blocking_oidc_discovery_server(jwks_url);
    let issuer_claim = issuer.clone();
    let mut config = test_config(Vec::new());
    config.auth_providers = vec![config::AuthProviderConfig {
        name: "oidc".to_owned(),
        provider_type: config::AuthProviderType::Jwt,
        jwks_url: None,
        issuer: Some(issuer),
        audience: None,
        jwks_timeout_ms: 2000,
        jwks_max_key_age_secs: 300,
        require_jti: false,
        roles_claim: "roles".to_owned(),
        roles_claim_delimiter: None,
        org_claim: None,
        introspection_url: None,
        introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
        cache_ttl_ms: config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
        user_id_claim: None,
        email_claim: None,
        client_id: None,
        client_secret: None,
        redirect_uri: None,
    }];
    config.egress_deny_private_ips = false;
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build with issuer-only OIDC provider");

    let response = router
        .oneshot(
            Request::builder()
                .uri("/__test/principal")
                .header(
                    header::AUTHORIZATION,
                    format!(
                        "Bearer {}",
                        signed_token_with_issuer("split-oidc-user", &["member"], &issuer_claim)
                    ),
                )
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json_body(response).await["user_id"],
        json!("split-oidc-user")
    );
    assert_eq!(discovery_server.finish(), 1);
    assert_eq!(jwks_server.finish(), 1);
}

#[tokio::test]
async fn oidc_discovery_jwks_uri_auto_seed_still_blocks_private_ip() {
    let (jwks_url, jwks_server) = spawn_blocking_jwks_server(Ipv4Addr::new(127, 0, 0, 2), 1);
    let (issuer, discovery_server) = spawn_blocking_oidc_discovery_server(jwks_url);
    let issuer_claim = issuer.clone();
    let policy = TempPolicyFile::new(
        r#"{
                "schema_version": "0.1.0",
                "default_action": "allow",
                "roles": {},
                "routes": [],
                "egress": {
                    "cidrs": ["127.0.0.1/32"]
                }
            }"#,
    );
    let mut config = test_config(Vec::new());
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.auth_providers = vec![config::AuthProviderConfig {
        name: "oidc".to_owned(),
        provider_type: config::AuthProviderType::Jwt,
        jwks_url: None,
        issuer: Some(issuer),
        audience: None,
        jwks_timeout_ms: 2000,
        jwks_max_key_age_secs: 300,
        require_jti: false,
        roles_claim: "roles".to_owned(),
        roles_claim_delimiter: None,
        org_claim: None,
        introspection_url: None,
        introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
        cache_ttl_ms: config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
        user_id_claim: None,
        email_claim: None,
        client_id: None,
        client_secret: None,
        redirect_uri: None,
    }];
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build after OIDC discovery");

    let response = router
        .oneshot(
            Request::builder()
                .uri("/__test/principal")
                .header(
                    header::AUTHORIZATION,
                    format!(
                        "Bearer {}",
                        signed_token_with_issuer("blocked-jwks-user", &["member"], &issuer_claim)
                    ),
                )
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("request should complete");

    // The egress guard makes the key set unfetchable, so the token is never
    // judged: the answer is "could not verify", not "credential rejected".
    // The property this test defends is that the blocked JWKS host is never
    // contacted, asserted below.
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(discovery_server.finish(), 1);
    assert_eq!(jwks_server.finish(), 0);
}

#[test]
fn auth_validator_reports_construction_error_when_oidc_discovery_lacks_jwks_uri() {
    let (issuer, server) = spawn_oidc_discovery_server_with(|issuer| json!({"issuer": issuer}), 1);
    let mut config = test_config(Vec::new());
    config.auth_providers = vec![config::AuthProviderConfig {
        name: "oidc".to_owned(),
        provider_type: config::AuthProviderType::Jwt,
        jwks_url: None,
        issuer: Some(issuer),
        audience: None,
        jwks_timeout_ms: 2000,
        jwks_max_key_age_secs: 300,
        require_jti: false,
        roles_claim: "roles".to_owned(),
        roles_claim_delimiter: None,
        org_claim: None,
        introspection_url: None,
        introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
        cache_ttl_ms: config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
        user_id_claim: None,
        email_claim: None,
        client_id: None,
        client_secret: None,
        redirect_uri: None,
    }];
    config.egress_deny_private_ips = false;
    let egress_client = Arc::new(
        egress::EgressClient::new(egress::EgressConfig::from_config(&config))
            .expect("egress client should build"),
    );

    let error = match discover_oidc_jwks_urls_from_config(&config, egress_client) {
        Ok(_) => panic!("missing jwks_uri should fail provider construction"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        auth::AuthError::Upstream(message)
            if message.contains("OIDC discovery response missing jwks_uri")
    ));
    server.finish();
}

fn spawn_oidc_jwks_server() -> (String, BlockingJsonServer) {
    let jwks = json!({
        "keys": [{
            "kty": "RSA",
            "kid": TEST_JWT_KID,
            "use": "sig",
            "alg": "RS256",
            "n": TEST_JWT_PUBLIC_KEY_N,
            "e": TEST_JWT_PUBLIC_KEY_E
        }]
    });
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("OIDC discovery test server should bind");
    let issuer = format!(
        "http://127.0.0.1:{}",
        listener
            .local_addr()
            .expect("OIDC discovery test server address should be available")
            .port()
    );
    let discovery = json!({
        "issuer": issuer,
        "jwks_uri": format!("{issuer}/jwks.json")
    });
    spawn_oidc_server(listener, discovery, Some(jwks), 2)
}

fn spawn_oidc_jwks_server_with_document_issuer(
    document_issuer: impl FnOnce(&str) -> String,
) -> (String, String, BlockingJsonServer) {
    let jwks = json!({
        "keys": [{
            "kty": "RSA",
            "kid": TEST_JWT_KID,
            "use": "sig",
            "alg": "RS256",
            "n": TEST_JWT_PUBLIC_KEY_N,
            "e": TEST_JWT_PUBLIC_KEY_E
        }]
    });
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("OIDC discovery test server should bind");
    let issuer = format!(
        "http://127.0.0.1:{}",
        listener
            .local_addr()
            .expect("OIDC discovery test server address should be available")
            .port()
    );
    let document_issuer = document_issuer(&issuer);
    let discovery = json!({
        "issuer": document_issuer.clone(),
        "jwks_uri": format!("{issuer}/jwks.json")
    });
    let (issuer, server) = spawn_oidc_server(listener, discovery, Some(jwks), 2);

    (issuer, document_issuer, server)
}

fn spawn_blocking_jwks_server(
    host: Ipv4Addr,
    request_count: usize,
) -> (String, BlockingJsonServer) {
    let listener =
        std::net::TcpListener::bind((host, 0)).expect("JWKS split-host test server should bind");
    let jwks_url = format!(
        "http://{}:{}/jwks.json",
        host,
        listener
            .local_addr()
            .expect("JWKS split-host test server address should be available")
            .port()
    );
    let jwks = json!({
        "keys": [{
            "kty": "RSA",
            "kid": TEST_JWT_KID,
            "use": "sig",
            "alg": "RS256",
            "n": TEST_JWT_PUBLIC_KEY_N,
            "e": TEST_JWT_PUBLIC_KEY_E
        }]
    });
    let server = spawn_blocking_json_server(
        listener,
        vec![("/jwks.json".to_owned(), jwks.to_string())],
        request_count,
    );

    (jwks_url, server)
}

fn spawn_blocking_oidc_discovery_server(jwks_url: String) -> (String, BlockingJsonServer) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .expect("OIDC split-host discovery test server should bind");
    let issuer = format!(
        "http://127.0.0.1:{}",
        listener
            .local_addr()
            .expect("OIDC split-host discovery test server address should be available")
            .port()
    );
    let discovery = json!({
        "issuer": issuer,
        "jwks_uri": jwks_url
    });
    let server = spawn_blocking_json_server(
        listener,
        vec![(
            "/.well-known/openid-configuration".to_owned(),
            discovery.to_string(),
        )],
        1,
    );

    (issuer, server)
}

fn oidc_jwt_provider(issuer: String) -> config::AuthProviderConfig {
    config::AuthProviderConfig {
        name: "oidc".to_owned(),
        provider_type: config::AuthProviderType::Jwt,
        jwks_url: None,
        issuer: Some(issuer),
        audience: None,
        jwks_timeout_ms: 2000,
        jwks_max_key_age_secs: 300,
        require_jti: false,
        roles_claim: "roles".to_owned(),
        roles_claim_delimiter: None,
        org_claim: None,
        introspection_url: None,
        introspection_timeout_ms: config::DEFAULT_COOKIE_SESSION_INTROSPECTION_TIMEOUT_MS,
        cache_ttl_ms: config::DEFAULT_COOKIE_SESSION_CACHE_TTL_MS,
        user_id_claim: None,
        email_claim: None,
        client_id: None,
        client_secret: None,
        redirect_uri: None,
    }
}
