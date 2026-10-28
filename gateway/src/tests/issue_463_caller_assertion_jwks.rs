//! Issue #463: the caller-assertion JWKS, end to end through the gateway's own router.
//!
//! An upstream verifying caller assertions holds no gateway credential: it fetches the published
//! set anonymously, caches it, and verifies tokens against the keys in it. These tests drive that
//! from the outside -- Connections saved before the gateway starts, so the set is built from what
//! a restarted gateway loaded -- and check what the set publishes, what it leaves out, and that
//! nothing about the private keys reaches a response or an audit event. Keys are generated per
//! test.

use super::*;
use crate::connections::{
    caller_assertion::{
        load_signing_key, sign_caller_assertion, AssertionAlgorithm, AssertionSigningKey,
        CallerAssertionConfig, CallerIdentity, JWKS_CACHE_CONTROL, JWKS_PATH,
    },
    control_plane::ConnectionControlPlane,
    model::ConnectionWrite,
    secret::{OperatorSecretAliasConfig, OperatorSecretAliasSource, SecretRootConfig},
    test_support::{generated_es256_pem, generated_rs256_pem, pem_body_lines},
};

const ISSUER: &str = "https://gateway.example.test";
const AUDIENCE: &str = "https://billing.example.test";
/// Members a JWK may carry that would be private key material.
const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// A secrets root holding the keys operator aliases point at. Removed on drop.
struct KeyRoot {
    root: PathBuf,
}

impl KeyRoot {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "greengateway-issue-463-jwks-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir(&root).expect("key root should create");
        restrict(&root, 0o700);
        Self { root }
    }

    fn alias(&self, alias: &str, pem: &str) -> OperatorSecretAliasConfig {
        let path = self.root.join(alias);
        fs::write(&path, pem).expect("key should write");
        restrict(&path, 0o600);
        OperatorSecretAliasConfig {
            id: alias.to_owned(),
            label: format!("Caller assertion key {alias}"),
            source: OperatorSecretAliasSource::File {
                key: alias.to_owned(),
            },
        }
    }
}

impl Drop for KeyRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(unix)]
fn restrict(path: &FsPath, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .expect("fixture permissions should set");
}

#[cfg(not(unix))]
fn restrict(_: &FsPath, _: u32) {}

fn attested(signing_key_id: &str, kid: &str, algorithm: &str, published_keys: Value) -> Value {
    json!({
        "display_name": "Attested API",
        "enabled": true,
        "kind": "http_api",
        "endpoint": {
            "base_url": AUDIENCE,
            "base_path": "/v1"
        },
        "authentication": { "type": "none" },
        "caller_assertion": {
            "signing_key_id": signing_key_id,
            "kid": kid,
            "algorithm": algorithm,
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "token_type": "at+jwt",
            "header_name": "x-caller-assertion",
            "lifetime_seconds": 60,
            "published_keys": published_keys
        }
    })
}

fn sign_as(key: &AssertionSigningKey, subject: &str) -> String {
    let caller = CallerIdentity {
        issuer: "https://idp.example.test",
        subject,
        email: None,
        roles: &[],
    };
    let config = CallerAssertionConfig {
        issuer: ISSUER,
        audience: AUDIENCE,
        token_type: "at+jwt",
        lifetime_seconds: 60,
        claims: &[],
        bind_request: false,
        bind_approval: false,
    };
    sign_caller_assertion(
        key,
        &config,
        Some(&caller),
        "req-issue-463",
        1_757_000_000,
        None,
        None,
    )
    .expect("signs")
}

/// What an upstream does with the fetched set: select the key by `kid`, take the algorithm from the
/// published key rather than the token, and check the signature, issuer and audience.
fn verify_against(token: &str, jwks: &str) -> Option<Value> {
    let set: jsonwebtoken::jwk::JwkSet =
        serde_json::from_str(jwks).expect("the published set is a standard JWK Set");
    let kid = jsonwebtoken::decode_header(token).ok()?.kid?;
    let jwk = set.find(&kid)?;
    let algorithm = match jwk.common.key_algorithm.as_ref()? {
        jsonwebtoken::jwk::KeyAlgorithm::ES256 => jsonwebtoken::Algorithm::ES256,
        jsonwebtoken::jwk::KeyAlgorithm::RS256 => jsonwebtoken::Algorithm::RS256,
        _ => return None,
    };
    let key = jsonwebtoken::DecodingKey::from_jwk(jwk).ok()?;
    let mut validation = jsonwebtoken::Validation::new(algorithm);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[AUDIENCE]);
    // The fixture timestamp is fixed, so this checks the signature and the bound claims rather than
    // the wall clock.
    validation.validate_exp = false;
    jsonwebtoken::decode::<Value>(token, &key, &validation)
        .ok()
        .map(|data| data.claims)
}

fn jwks_request() -> Request<Body> {
    Request::builder()
        .uri(JWKS_PATH)
        .body(Body::empty())
        .expect("JWKS request should build")
}

#[tokio::test]
async fn upstreams_fetch_the_published_keys_without_a_credential_and_verify_what_they_sign() {
    let keys = KeyRoot::new();
    let current_pem = generated_es256_pem();
    let next_pem = generated_rs256_pem();
    let disabled_pem = generated_es256_pem();
    let mut config = test_config(Vec::new());
    config.connections_sqlite_path =
        Some(keys.root.join("connections.sqlite").display().to_string());
    config.connection_secrets_root = Some(SecretRootConfig::new(keys.root.clone()));
    config.connection_secret_aliases = vec![
        keys.alias("key-current", &current_pem),
        keys.alias("key-next", &next_pem),
        keys.alias("key-disabled", &disabled_pem),
    ];

    // Saved before the gateway starts, as after a restart, so the set reads their keys anew. The
    // enabled Connection signs with an ES256 key and already publishes the RS256 key it will
    // rotate to; the disabled one publishes nothing.
    {
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        let snapshot = control_plane.runtime_snapshot();
        let rotating: ConnectionWrite = serde_json::from_value(attested(
            "key-current",
            "gw-current",
            "es256",
            json!([{ "signing_key_id": "key-next", "kid": "gw-next", "algorithm": "rs256" }]),
        ))
        .expect("attested Connection should deserialize");
        control_plane
            .create_managed(
                snapshot.collection_etag(),
                rotating,
                &crate::auth::change_actor::ChangeActor::for_test("test-admin"),
            )
            .await
            .expect("rotating Connection should create");
        let snapshot = control_plane.runtime_snapshot();
        let mut disabled = attested("key-disabled", "gw-disabled", "es256", json!([]));
        disabled["enabled"] = json!(false);
        control_plane
            .create_managed(
                snapshot.collection_etag(),
                serde_json::from_value(disabled).expect("disabled Connection should deserialize"),
                &crate::auth::change_actor::ChangeActor::for_test("test-admin"),
            )
            .await
            .expect("disabled Connection should create");
    }

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

    // Authentication is still required everywhere else.
    let protected = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/__test/principal")
                .body(Body::empty())
                .expect("protected request should build"),
        )
        .await
        .expect("protected request should complete");
    assert_eq!(protected.status(), StatusCode::UNAUTHORIZED);

    // The set is public, cacheable, and validated by a strong entity tag.
    let response = router
        .clone()
        .oneshot(jwks_request())
        .await
        .expect("JWKS request should complete");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE),
        Some(&HeaderValue::from_static("application/json"))
    );
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static(JWKS_CACHE_CONTROL))
    );
    let etag = response
        .headers()
        .get(header::ETAG)
        .cloned()
        .expect("the set carries an entity tag");
    assert!(etag
        .to_str()
        .is_ok_and(|value| value.starts_with('"') && value.ends_with('"')));
    let body = body_string(response).await;

    // Exactly the enabled Connection's keys, each with its kid, and only public members.
    let document: Value = serde_json::from_str(&body).expect("the JWKS is JSON");
    let published = document["keys"]
        .as_array()
        .expect("the JWKS has a key array");
    assert_eq!(
        published
            .iter()
            .map(|key| key["kid"].as_str().unwrap_or_default())
            .collect::<Vec<_>>(),
        vec!["gw-current", "gw-next"]
    );
    for jwk in published {
        for private in PRIVATE_MEMBERS {
            assert!(jwk.get(private).is_none(), "the JWKS published {private}");
        }
    }
    for line in pem_body_lines(&current_pem)
        .into_iter()
        .chain(pem_body_lines(&next_pem))
        .chain(pem_body_lines(&disabled_pem))
    {
        assert!(!body.contains(line), "the JWKS leaked private key material");
    }

    // A standard verifier holding only this set accepts what both published keys sign -- the
    // RS256 key before it ever signs a real call, which is the point of publishing it first --
    // and refuses what the disabled Connection's key signs.
    let current = load_signing_key(
        "gw-current",
        AssertionAlgorithm::Es256,
        current_pem.as_bytes(),
    )
    .expect("the current key loads");
    let next = load_signing_key("gw-next", AssertionAlgorithm::Rs256, next_pem.as_bytes())
        .expect("the next key loads");
    let disabled = load_signing_key(
        "gw-disabled",
        AssertionAlgorithm::Es256,
        disabled_pem.as_bytes(),
    )
    .expect("the disabled Connection's key loads");
    for (key, subject) in [(&current, "alice"), (&next, "bob")] {
        let claims = verify_against(&sign_as(key, subject), &body)
            .expect("an assertion signed by a published key verifies");
        assert_eq!(claims["caller_sub"], subject);
        assert_eq!(claims["sub"], format!("https://idp.example.test#{subject}"));
    }
    assert!(verify_against(&sign_as(&disabled, "mallory"), &body).is_none());

    // A verifier revalidating its cached copy is told nothing changed.
    let revalidated = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(JWKS_PATH)
                .header(header::IF_NONE_MATCH, etag.clone())
                .body(Body::empty())
                .expect("revalidation request should build"),
        )
        .await
        .expect("revalidation request should complete");
    assert_eq!(revalidated.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(revalidated.headers().get(header::ETAG), Some(&etag));
    assert!(body_string(revalidated).await.is_empty());

    // No fragment of any key reached the audit trail on the way.
    let rendered = serde_json::to_string(&capture.events()).expect("audit events serialize");
    for line in pem_body_lines(&current_pem)
        .into_iter()
        .chain(pem_body_lines(&next_pem))
        .chain(pem_body_lines(&disabled_pem))
    {
        assert!(
            !rendered.contains(line),
            "the audit trail leaked key material"
        );
    }
}

#[tokio::test]
async fn a_stored_connection_whose_key_cannot_be_used_does_not_stop_the_gateway() {
    // The upgrade case: #556 stored caller assertions whatever their alias held. The gateway has to
    // start, keep publishing every other Connection's keys, and leave only the broken one out.
    let keys = KeyRoot::new();
    let healthy_pem = generated_es256_pem();
    let mut config = test_config(Vec::new());
    config.connections_sqlite_path =
        Some(keys.root.join("connections.sqlite").display().to_string());
    config.connection_secrets_root = Some(SecretRootConfig::new(keys.root.clone()));
    config.connection_secret_aliases = vec![
        keys.alias("key-healthy", &healthy_pem),
        keys.alias("key-broken", &generated_es256_pem()),
    ];
    {
        let control_plane =
            ConnectionControlPlane::from_config(&config).expect("control plane should build");
        for (alias, kid) in [("key-healthy", "gw-healthy"), ("key-broken", "gw-broken")] {
            let snapshot = control_plane.runtime_snapshot();
            let write: ConnectionWrite =
                serde_json::from_value(attested(alias, kid, "es256", json!([])))
                    .expect("attested Connection should deserialize");
            control_plane
                .create_managed(
                    snapshot.collection_etag(),
                    write,
                    &crate::auth::change_actor::ChangeActor::for_test("test-admin"),
                )
                .await
                .expect("attested Connection should create");
        }
    }
    // The key behind one alias stops being a key before the gateway starts again.
    fs::write(keys.root.join("key-broken"), "not a key").expect("the broken key should write");

    let router = app(
        config,
        PrometheusBuilder::new().build_recorder().handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("an unusable caller-assertion key must not stop the gateway starting");
    let response = router
        .oneshot(jwks_request())
        .await
        .expect("JWKS request should complete");
    assert_eq!(response.status(), StatusCode::OK);
    let document: Value =
        serde_json::from_str(&body_string(response).await).expect("the JWKS is JSON");
    assert_eq!(
        document["keys"]
            .as_array()
            .expect("the JWKS has a key array")
            .iter()
            .map(|key| key["kid"].as_str().unwrap_or_default())
            .collect::<Vec<_>>(),
        vec!["gw-healthy"]
    );
}

#[tokio::test]
async fn a_proxy_route_at_the_root_cannot_answer_the_jwks_path() {
    // The path is gateway-owned on every listener: a catch-all route must never hand verifiers an
    // upstream's document in place of the gateway's keys.
    let (upstream_addr, mut captured) = spawn_capture_upstream().await;
    let policy = TempPolicyFile::new(
        r#"{
                "schema_version": "0.1.0",
                "default_action": "allow",
                "roles": {},
                "routes": []
            }"#,
    );
    let mut config = routing_proxy_config(vec![host_path_route(
        "app.example.test",
        "/",
        upstream_addr,
    )]);
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    let router = proxy_router(config, test_audit_log());

    let response = router
        .oneshot(
            Request::builder()
                .uri(JWKS_PATH)
                .header(header::HOST, "app.example.test")
                .body(Body::empty())
                .expect("JWKS request should build"),
        )
        .await
        .expect("JWKS request should complete");

    // No Connection attests its caller here, so the set is empty -- and it is still the gateway's.
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_string(response).await, r#"{"keys":[]}"#);
    assert_upstream_receives_no_request(
        &mut captured,
        "a proxy route must not answer the gateway's JWKS",
    )
    .await;
}
