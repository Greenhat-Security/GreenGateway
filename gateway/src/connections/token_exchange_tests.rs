//! Delegated issuer tokens without a network: the per-caller cache, the RFC 8693 request the
//! gateway writes, and how it reads what an issuer answers. The exchange against a stub issuer
//! over TLS, end to end through a tool call, is in `tools/executor_delegated_token_tests.rs`.

use std::sync::atomic::{AtomicUsize, Ordering};

use http::HeaderMap;

use super::*;
use crate::auth::{AuthMethod, Principal};

fn caller(subject: &str, issuer: &str, roles: &[&str]) -> AttestedCaller {
    AttestedCaller::from_principal(&Principal {
        user_id: subject.to_owned(),
        issuer: Some(issuer.to_owned()),
        email: Some(format!("{subject}@example.test")),
        org_id: None,
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        session_id: format!("session-{subject}"),
        auth_method: AuthMethod::Bearer,
    })
    .expect("a provider-vouched principal is attestable")
}

fn alice() -> AttestedCaller {
    caller("alice", "https://idp.example.test", &["mail:read"])
}

fn bob() -> AttestedCaller {
    caller("bob", "https://idp.example.test", &["mail:read"])
}

fn key_for(caller: &AttestedCaller, revision: u32) -> OAuthTokenCacheKey {
    key_on("mail", caller, revision)
}

fn key_on(connection_id: &str, caller: &AttestedCaller, revision: u32) -> OAuthTokenCacheKey {
    let identity = caller.identity();
    OAuthTokenCacheKey {
        connection_id: connection_id.to_owned(),
        connection_etag: format!("etag-{revision}"),
        subject: Some(subject_digest(caller)),
        principal: Some(principal_digest(identity.issuer, identity.subject)),
        secret_version: None,
        egress_generation: [7; 32],
    }
}

fn minted(value: &str, lifetime: Duration) -> MintedOAuthToken {
    MintedOAuthToken {
        access_token: Zeroizing::new(value.as_bytes().to_vec()),
        lifetime,
    }
}

fn bearer_of<C>(lease: &OAuthTokenLease<DelegatedTokenError, C>) -> String {
    let mut headers = HeaderMap::new();
    lease.inject(&mut headers).expect("a cached token injects");
    let value = headers
        .get(header::AUTHORIZATION)
        .expect("the token goes in Authorization");
    assert!(value.is_sensitive(), "the token header is marked sensitive");
    value
        .to_str()
        .expect("a bearer token is visible ASCII")
        .to_owned()
}

/// Mints through `cache` for `key`, counting the mint, and returns the lease.
async fn get(
    cache: &OAuthTokenCache<DelegatedTokenError>,
    key: OAuthTokenCacheKey,
    value: &'static str,
    lifetime: Duration,
    mints: &Arc<AtomicUsize>,
) -> Result<OAuthTokenLease<DelegatedTokenError>, DelegatedTokenError> {
    let mints = Arc::clone(mints);
    cache
        .get_or_mint(key, move || async move {
            mints.fetch_add(1, Ordering::AcqRel);
            Ok(minted(value, lifetime))
        })
        .await
}

#[tokio::test]
async fn two_callers_of_one_connection_never_share_a_token() {
    let cache = OAuthTokenCache::with_capacity(Arc::new(ManualTokenClock::new()), 8);
    let mints = Arc::new(AtomicUsize::new(0));
    let hour = Duration::from_secs(3_600);

    let first = get(&cache, key_for(&alice(), 1), "token-a", hour, &mints)
        .await
        .expect("alice's token is exchanged");
    let second = get(&cache, key_for(&bob(), 1), "token-b", hour, &mints)
        .await
        .expect("bob's token is exchanged");
    let again = get(&cache, key_for(&alice(), 1), "unexpected", hour, &mints)
        .await
        .expect("alice's token is cached");

    assert_eq!(bearer_of(&first), "Bearer token-a");
    assert_eq!(bearer_of(&second), "Bearer token-b");
    assert_eq!(bearer_of(&again), "Bearer token-a");
    assert_eq!(mints.load(Ordering::Acquire), 2, "one exchange per caller");
    assert_eq!(cache.slot_count(), 2);
}

#[tokio::test]
async fn a_cached_token_is_exchanged_again_shortly_before_it_expires() {
    let clock = Arc::new(ManualTokenClock::new());
    let cache = OAuthTokenCache::with_capacity(clock.clone(), 8);
    let mints = Arc::new(AtomicUsize::new(0));
    let lifetime = Duration::from_secs(60);

    drop(get(&cache, key_for(&alice(), 1), "first", lifetime, &mints).await);
    // A sixty-second token is refreshed between twelve and seventeen seconds
    // early: a fifth of its life, capped at thirty, plus up to five seconds
    // of jitter.
    clock.advance(Duration::from_secs(42));
    let cached = get(&cache, key_for(&alice(), 1), "early", lifetime, &mints)
        .await
        .expect("the token is still fresh");
    assert_eq!(bearer_of(&cached), "Bearer first");
    assert_eq!(mints.load(Ordering::Acquire), 1);
    drop(cached);

    clock.advance(Duration::from_secs(12));
    let refreshed = get(&cache, key_for(&alice(), 1), "second", lifetime, &mints)
        .await
        .expect("a token near expiry is exchanged again");
    assert_eq!(bearer_of(&refreshed), "Bearer second");
    assert_eq!(mints.load(Ordering::Acquire), 2);
}

#[test]
fn an_issuer_lifetime_is_honoured_up_to_the_cache_ceiling() {
    assert_eq!(cache_lifetime(60), Duration::from_secs(60));
    assert_eq!(
        cache_lifetime(MAX_DELEGATED_TOKEN_CACHE_SECONDS),
        Duration::from_secs(MAX_DELEGATED_TOKEN_CACHE_SECONDS)
    );
    assert_eq!(
        cache_lifetime(7 * 24 * 60 * 60),
        Duration::from_secs(MAX_DELEGATED_TOKEN_CACHE_SECONDS)
    );
}

#[tokio::test]
async fn a_full_cache_evicts_an_idle_caller_and_refuses_only_while_every_entry_is_held() {
    let cache = OAuthTokenCache::with_capacity(Arc::new(ManualTokenClock::new()), 2);
    let mints = Arc::new(AtomicUsize::new(0));
    let hour = Duration::from_secs(3_600);
    let carol = caller("carol", "https://idp.example.test", &[]);

    let held_alice = get(&cache, key_for(&alice(), 1), "token-a", hour, &mints)
        .await
        .expect("alice's token is exchanged");
    let held_bob = get(&cache, key_for(&bob(), 1), "token-b", hour, &mints)
        .await
        .expect("bob's token is exchanged");

    // Both entries are held by calls in flight: a third caller is refused
    // with its own reason, and nothing is exchanged for it.
    let refused = get(&cache, key_for(&carol, 1), "token-c", hour, &mints).await;
    assert_eq!(refused.err(), Some(DelegatedTokenError::Unavailable));
    assert_eq!(mints.load(Ordering::Acquire), 2);
    assert_eq!(cache.slot_count(), 2);

    // Once bob's call finishes, his entry is the idle one that makes room.
    drop(held_bob);
    let admitted = get(&cache, key_for(&carol, 1), "token-c", hour, &mints)
        .await
        .expect("an idle entry is evicted for a new caller");
    assert_eq!(bearer_of(&admitted), "Bearer token-c");
    assert_eq!(cache.slot_count(), 2);

    // Bob is exchanged for again, and is never handed alice's or carol's token.
    drop(admitted);
    let bob_again = get(&cache, key_for(&bob(), 1), "token-b2", hour, &mints)
        .await
        .expect("an evicted caller is exchanged for again");
    assert_eq!(bearer_of(&bob_again), "Bearer token-b2");
    assert_eq!(mints.load(Ordering::Acquire), 4);
    assert_eq!(cache.slot_count(), 2);
    drop(held_alice);
}

#[tokio::test]
async fn a_changed_connection_drops_every_idle_token_it_held() {
    let cache = OAuthTokenCache::with_capacity(Arc::new(ManualTokenClock::new()), 8);
    let mints = Arc::new(AtomicUsize::new(0));
    let hour = Duration::from_secs(3_600);

    drop(get(&cache, key_for(&alice(), 1), "token-a", hour, &mints).await);
    let held_bob = get(&cache, key_for(&bob(), 1), "token-b", hour, &mints)
        .await
        .expect("bob's token is exchanged");
    assert_eq!(cache.slot_count(), 2);

    // A save moves the etag. The first call under the new revision drops the
    // idle tokens of the old one; a token a call still holds stays until it
    // is released.
    let renewed = get(&cache, key_for(&alice(), 2), "token-a2", hour, &mints)
        .await
        .expect("the new revision exchanges again");
    assert_eq!(bearer_of(&renewed), "Bearer token-a2");
    assert_eq!(
        cache.slot_count(),
        2,
        "alice's old token is gone, bob's is held"
    );
    drop(held_bob);
    drop(renewed);

    drop(get(&cache, key_for(&bob(), 3), "token-b3", hour, &mints).await);
    assert_eq!(
        cache.slot_count(),
        1,
        "only the current revision's token is left"
    );
    assert_eq!(mints.load(Ordering::Acquire), 4);
}

#[tokio::test]
async fn concurrent_calls_of_one_caller_share_one_exchange() {
    let cache = Arc::new(OAuthTokenCache::with_capacity(
        Arc::new(ManualTokenClock::new()),
        8,
    ));
    let mints = Arc::new(AtomicUsize::new(0));
    let calls = (0..32).map(|_| {
        let cache = Arc::clone(&cache);
        let mints = Arc::clone(&mints);
        async move {
            let counted = Arc::clone(&mints);
            cache
                .get_or_mint(key_for(&alice(), 1), move || async move {
                    counted.fetch_add(1, Ordering::AcqRel);
                    tokio::task::yield_now().await;
                    Ok(minted("shared", Duration::from_secs(60)))
                })
                .await
                .map(|lease| bearer_of(&lease))
        }
    });
    let results = futures_util::future::join_all(calls).await;
    assert!(results
        .iter()
        .all(|result| result.as_deref() == Ok("Bearer shared")));
    assert_eq!(mints.load(Ordering::Acquire), 1);
}

#[test]
fn the_cache_key_names_the_whole_attested_identity() {
    let digest = subject_digest(&alice());
    assert_eq!(digest, subject_digest(&alice()));
    assert_ne!(digest, subject_digest(&bob()));
    // The same subject from another provider is another person.
    assert_ne!(
        digest,
        subject_digest(&caller(
            "alice",
            "https://other-idp.example.test",
            &["mail:read"]
        ))
    );
    // Claims that changed at the provider are exchanged for again.
    assert_ne!(
        digest,
        subject_digest(&caller(
            "alice",
            "https://idp.example.test",
            &["mail:admin"]
        ))
    );
    // Length prefixes keep two identities from sharing an encoding.
    assert_ne!(
        subject_digest(&caller("ab", "https://idp.example.test/c", &[])),
        subject_digest(&caller("b", "https://idp.example.test/ca", &[]))
    );
}

#[test]
fn a_purge_matches_the_principal_whatever_claims_it_carried() {
    let alice = alice();
    let identity = alice.identity();
    let digest = principal_digest(identity.issuer, identity.subject);
    // Every claim change is a cache key of its own, and one principal.
    let promoted = caller("alice", "https://idp.example.test", &["mail:admin"]);
    assert_ne!(subject_digest(&alice), subject_digest(&promoted));
    assert_eq!(
        key_for(&alice, 1).principal,
        key_for(&promoted, 1).principal
    );
    assert_eq!(key_for(&alice, 1).principal, Some(digest));
    // Another subject, or the same subject from another provider, is another
    // principal; length prefixes keep two of them from sharing an encoding.
    assert_ne!(digest, principal_digest(identity.issuer, "bob"));
    assert_ne!(
        digest,
        principal_digest("https://other-idp.example.test", "alice")
    );
    assert_ne!(
        principal_digest("https://idp.example.test/a", "b"),
        principal_digest("https://idp.example.test", "/ab")
    );
}

#[tokio::test]
async fn retiring_one_principal_takes_every_token_of_theirs_and_no_one_elses() {
    let cache = OAuthTokenCache::with_capacity(Arc::new(ManualTokenClock::new()), 8);
    let mints = Arc::new(AtomicUsize::new(0));
    let hour = Duration::from_secs(3_600);
    let promoted = caller("alice", "https://idp.example.test", &["mail:admin"]);

    drop(get(&cache, key_for(&alice(), 1), "alice-mail", hour, &mints).await);
    drop(get(&cache, key_for(&promoted, 1), "alice-admin", hour, &mints).await);
    drop(
        get(
            &cache,
            key_on("calendar", &alice(), 1),
            "alice-cal",
            hour,
            &mints,
        )
        .await,
    );
    let held_bob = get(&cache, key_for(&bob(), 1), "bob-mail", hour, &mints)
        .await
        .expect("bob's token is exchanged");
    // A token a call still holds is retired too: it must not serve again.
    let held_alice = get(&cache, key_for(&alice(), 1), "unexpected", hour, &mints)
        .await
        .expect("alice's token is cached");
    assert_eq!(cache.slot_count(), 4);

    let identity = alice();
    let identity = identity.identity();
    let target = principal_digest(identity.issuer, identity.subject);
    let retired = cache.retire_where(|key| key.principal == Some(target));
    assert_eq!(retired.len(), 3);
    assert_eq!(cache.slot_count(), 1, "only bob's entry is left");

    let mut taken = Vec::new();
    for slot in &retired {
        let token = slot
            .take_token()
            .await
            .expect("each retired slot held a token");
        taken.push(String::from_utf8(token.to_vec()).expect("test tokens are UTF-8"));
        assert!(slot.take_token().await.is_none(), "a token is taken once");
    }
    taken.sort();
    assert_eq!(taken, ["alice-admin", "alice-cal", "alice-mail"]);
    // The call already holding its copy finishes with it.
    assert_eq!(bearer_of(&held_alice), "Bearer alice-mail");

    // Alice is exchanged for again; bob keeps his token.
    let again = get(&cache, key_for(&alice(), 1), "alice-fresh", hour, &mints)
        .await
        .expect("a purged principal is exchanged for again");
    assert_eq!(bearer_of(&again), "Bearer alice-fresh");
    let bob_again = get(&cache, key_for(&bob(), 1), "unexpected", hour, &mints)
        .await
        .expect("bob's token is still cached");
    assert_eq!(bearer_of(&bob_again), "Bearer bob-mail");
    assert_eq!(mints.load(Ordering::Acquire), 5);
    drop(held_bob);
}

#[tokio::test]
async fn an_exchange_in_flight_when_its_principal_is_purged_is_revoked_once_it_lands() {
    let cache = Arc::new(OAuthTokenCache::<DelegatedTokenError>::with_capacity(
        Arc::new(ManualTokenClock::new()),
        8,
    ));
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let waiting = {
        let cache = Arc::clone(&cache);
        let started = Arc::clone(&started);
        let release = Arc::clone(&release);
        tokio::spawn(async move {
            cache
                .get_or_mint(key_for(&alice(), 1), move || async move {
                    started.notify_one();
                    release.notified().await;
                    Ok(minted("in-flight", Duration::from_secs(3_600)))
                })
                .await
                .map(|lease| bearer_of(&lease))
        })
    };
    started.notified().await;

    let identity = alice();
    let identity = identity.identity();
    let target = principal_digest(identity.issuer, identity.subject);
    let retired = cache.retire_where(|key| key.principal == Some(target));
    assert_eq!(retired.len(), 1);
    assert_eq!(cache.slot_count(), 0);
    let taking = tokio::spawn(async move { retired[0].take_token().await });
    tokio::task::yield_now().await;
    release.notify_one();

    // The call that was already waiting gets what it waited for; the purge
    // takes the same token to revoke it, and nothing keeps it in the cache.
    assert_eq!(
        waiting
            .await
            .expect("the waiting call completes")
            .as_deref(),
        Ok("Bearer in-flight")
    );
    let token = taking
        .await
        .expect("the purge completes")
        .expect("the exchange's token is taken");
    assert_eq!(token.as_slice(), b"in-flight");
    let mints = Arc::new(AtomicUsize::new(0));
    let fresh = get(
        &cache,
        key_for(&alice(), 1),
        "fresh",
        Duration::from_secs(60),
        &mints,
    )
    .await
    .expect("the next call exchanges again");
    assert_eq!(bearer_of(&fresh), "Bearer fresh");
    assert_eq!(mints.load(Ordering::Acquire), 1);
}

#[test]
fn the_revocation_request_is_an_rfc_7009_access_token_revocation() {
    let body = revocation_request_body(b"delegated-token+/=").expect("a bounded request builds");
    let fields: Vec<(String, String)> = form_urlencoded::parse(&body)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    assert_eq!(
        fields,
        vec![
            ("token".to_owned(), "delegated-token+/=".to_owned()),
            ("token_type_hint".to_owned(), "access_token".to_owned()),
        ]
    );
    assert_eq!(
        revocation_request_body(&[b'x'; OAUTH_MAX_REQUEST_BYTES]).err(),
        Some(RevocationError::Failed)
    );
    assert_eq!(
        revocation_request_body(&[0xff, 0xfe]).err(),
        Some(RevocationError::Failed)
    );
}

#[test]
fn every_revocation_outcome_has_a_fixed_reason_and_an_issuers_code_is_recorded_only_if_registered()
{
    let reasons = [
        RevocationError::NotConfigured,
        RevocationError::EgressDenied,
        RevocationError::CredentialInvalid,
        RevocationError::CredentialUnavailable,
        RevocationError::Refused,
        RevocationError::Failed,
    ]
    .map(|error| error.outcome_and_reason());
    let unique: std::collections::BTreeSet<_> = reasons.iter().map(|(_, reason)| reason).collect();
    assert_eq!(unique.len(), reasons.len());
    assert_eq!(
        RevocationError::NotConfigured.outcome_and_reason(),
        ("skipped", "revocation_not_configured")
    );
    assert!(reasons[1..]
        .iter()
        .all(|(outcome, _)| *outcome == "failure"));

    let code =
        |body: &str| registered_error_code(body.as_bytes(), REGISTERED_REVOCATION_ERROR_CODES);
    assert_eq!(
        code(r#"{"error":"unsupported_token_type"}"#),
        Some("unsupported_token_type")
    );
    assert_eq!(
        code(r#"{"error":"invalid_client"}"#),
        Some("invalid_client")
    );
    // Token exchange's own codes are not a revocation endpoint's.
    assert_eq!(code(r#"{"error":"invalid_target"}"#), Some("unregistered"));
    assert_eq!(
        code(r#"{"error":"token_already_gone_for_alice"}"#),
        Some("unregistered")
    );
}

fn binding_for_body() -> DelegatedTokenBinding {
    let egress = crate::egress::EgressConfig::default();
    DelegatedTokenBinding {
        connection_id: ConnectionId::parse("mail").expect("valid connection ID"),
        connection_etag: "etag-1".to_owned(),
        client_id: "greengateway".to_owned(),
        client_secret_id: "issuer-exchange-secret".to_owned(),
        token_exchange_url: "https://issuer.example.test/oauth2/token-exchange".to_owned(),
        requested_scopes: vec!["calendar.read".to_owned(), "mail.read".to_owned()],
        audience: Some("https://mail.example.test".to_owned()),
        resource: Some("https://mail.example.test/api".to_owned()),
        revocation_url: Some("https://issuer.example.test/oauth2/revoke".to_owned()),
        subject_token: SubjectTokenSettings {
            signing_key_id: "assertion-signing-key".to_owned(),
            kid: "gw-test-1".to_owned(),
            algorithm: AssertionAlgorithm::Es256,
            issuer: "https://gateway.example.test".to_owned(),
            audience: "https://issuer.example.test".to_owned(),
            token_type: "caller-assertion+jwt".to_owned(),
            lifetime_seconds: 60,
            claims: Vec::new(),
        },
        token_client: Arc::new(EgressClient::new(egress).expect("egress client builds")),
    }
}

#[test]
fn the_exchange_request_is_an_rfc_8693_token_exchange() {
    let body = exchange_request_body(&binding_for_body(), "header.payload.signature")
        .expect("a bounded request builds");
    let fields: Vec<(String, String)> = form_urlencoded::parse(&body)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    assert_eq!(
        fields,
        vec![
            (
                "grant_type".to_owned(),
                "urn:ietf:params:oauth:grant-type:token-exchange".to_owned()
            ),
            (
                "subject_token".to_owned(),
                "header.payload.signature".to_owned()
            ),
            (
                "subject_token_type".to_owned(),
                "urn:ietf:params:oauth:token-type:jwt".to_owned()
            ),
            (
                "requested_token_type".to_owned(),
                "urn:ietf:params:oauth:token-type:access_token".to_owned()
            ),
            ("scope".to_owned(), "calendar.read mail.read".to_owned()),
            (
                "audience".to_owned(),
                "https://mail.example.test".to_owned()
            ),
            (
                "resource".to_owned(),
                "https://mail.example.test/api".to_owned()
            ),
        ]
    );

    let oversized = "x".repeat(OAUTH_MAX_REQUEST_BYTES);
    assert_eq!(
        exchange_request_body(&binding_for_body(), &oversized).err(),
        Some(DelegatedTokenError::ExchangeFailed)
    );
}

fn response(json: &str) -> ExchangeResponse {
    serde_json::from_str(json).expect("the response parses")
}

#[test]
fn only_a_bounded_bearer_access_token_is_accepted() {
    let valid = response(
        r#"{"access_token":"delegated-token","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600,"scope":"mail.read","refresh_token":"discarded","session_state":"ignored"}"#,
    );
    assert_eq!(validate_exchange_response(&valid), Ok(3_600));

    for rejected in [
        // No stated lifetime: it could only be cached on a guess.
        r#"{"access_token":"t","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer"}"#,
        r#"{"access_token":"t","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":0}"#,
        r#"{"access_token":"t","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":604801}"#,
        // Something other than what was asked for.
        r#"{"access_token":"t","issued_token_type":"urn:ietf:params:oauth:token-type:id_token","token_type":"Bearer","expires_in":60}"#,
        r#"{"access_token":"t","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"DPoP","expires_in":60}"#,
        r#"{"access_token":"t","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"N_A","expires_in":60}"#,
        // Not usable as a header value.
        r#"{"access_token":"","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":60}"#,
        r#"{"access_token":"line\nbreak","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":60}"#,
    ] {
        assert_eq!(
            validate_exchange_response(&response(rejected)),
            Err(DelegatedTokenError::ExchangeFailed),
            "{rejected}"
        );
    }
    assert!(serde_json::from_str::<ExchangeResponse>(r#"{"token_type":"Bearer"}"#).is_err());
}

#[test]
fn an_issuer_refusal_is_a_denial_only_when_the_issuer_says_so() {
    let code = |body: &str| registered_error_code(body.as_bytes(), REGISTERED_ERROR_CODES);
    assert_eq!(
        code(r#"{"error":"invalid_grant","error_description":"no grant for alice"}"#),
        Some("invalid_grant")
    );
    // An issuer's own vocabulary is never recorded verbatim.
    assert_eq!(
        code(r#"{"error":"grant_revoked_for_alice"}"#),
        Some("unregistered")
    );
    assert_eq!(code(r#"{"error_description":"no code"}"#), None);
    assert_eq!(code("not json"), None);

    for (status, error, expected) in [
        (
            StatusCode::BAD_REQUEST,
            Some("invalid_grant"),
            DelegatedTokenError::Denied,
        ),
        (
            StatusCode::BAD_REQUEST,
            Some("access_denied"),
            DelegatedTokenError::Denied,
        ),
        (StatusCode::FORBIDDEN, None, DelegatedTokenError::Denied),
        // The gateway's own client authentication or request: no caller can
        // fix that by reconnecting.
        (
            StatusCode::UNAUTHORIZED,
            Some("invalid_client"),
            DelegatedTokenError::ExchangeFailed,
        ),
        (
            StatusCode::BAD_REQUEST,
            Some("invalid_request"),
            DelegatedTokenError::ExchangeFailed,
        ),
        (
            StatusCode::BAD_REQUEST,
            Some("unregistered"),
            DelegatedTokenError::ExchangeFailed,
        ),
        (
            StatusCode::BAD_REQUEST,
            None,
            DelegatedTokenError::ExchangeFailed,
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("invalid_grant"),
            DelegatedTokenError::ExchangeFailed,
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            None,
            DelegatedTokenError::ExchangeFailed,
        ),
    ] {
        assert_eq!(
            classify_refusal(status, error),
            expected,
            "{status} {error:?}"
        );
    }
}

#[test]
fn every_failure_has_a_fixed_reason_of_its_own() {
    let reasons = [
        DelegatedTokenError::NoPrincipal,
        DelegatedTokenError::EgressDenied,
        DelegatedTokenError::Denied,
        DelegatedTokenError::ExchangeFailed,
        DelegatedTokenError::Unavailable,
    ]
    .map(DelegatedTokenError::safe_reason);
    let unique: std::collections::BTreeSet<_> = reasons.iter().collect();
    assert_eq!(unique.len(), reasons.len());
    assert!(reasons
        .iter()
        .all(|reason| reason.starts_with("delegated_token_")));
    assert_eq!(
        DelegatedTokenError::Denied.to_string(),
        "delegated_token_denied"
    );
}

#[tokio::test]
async fn an_exchange_that_never_finishes_is_audited_as_cancelled_without_token_material() {
    use crate::audit::{sink::tests::CaptureSink, AuditSink};

    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    drop(ExchangeAttempt::new(
        Some(audit),
        &binding_for_body(),
        &alice(),
        "subject-jti-1",
    ));
    let started = Instant::now();
    while capture.len() < 1 && started.elapsed() < Duration::from_secs(1) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let events = capture.events();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(
        event.event_type,
        audit::event::CONNECTION_DELEGATED_TOKEN_EXCHANGE
    );
    assert_eq!(event.payload["outcome"], json!("failure"));
    assert_eq!(
        event.payload["reason"],
        json!("delegated_token_exchange_cancelled")
    );
    assert_eq!(
        event.payload["subject_token"],
        json!({ "kid": "gw-test-1", "jti": "subject-jti-1" })
    );
    let actor = event.actor.as_ref().expect("the caller is the actor");
    assert_eq!(actor.user_id, "alice");
    assert_eq!(actor.issuer.as_deref(), Some("https://idp.example.test"));
    assert_eq!(actor.auth_mode, "bearer_token");
    let rendered = serde_json::to_string(&events).expect("audit serializes");
    for absent in ["issuer-exchange-secret", "token-exchange", "client_id"] {
        assert!(!rendered.contains(absent), "audit leaked {absent:?}");
    }
}

#[test]
fn a_purge_key_is_a_digest_of_the_principal_under_the_deployment() {
    let alice = alice();
    let identity = alice.identity();
    let principal = principal_digest(identity.issuer, identity.subject);
    let key = purge_key("deploy-a", &principal);
    assert!(is_purge_key(&key), "{key}");
    assert_eq!(key, purge_key("deploy-a", &principal), "the key is stable");
    // Another deployment, or another principal, is another key; the key
    // carries neither the issuer nor the subject.
    assert_ne!(key, purge_key("deploy-b", &principal));
    assert_ne!(
        key,
        purge_key("deploy-a", &principal_digest(identity.issuer, "bob"))
    );
    assert!(!key.contains("alice") && !key.contains("idp"));
    assert!(is_purge_key(&"0".repeat(64)));
    assert!(is_purge_key(&"f".repeat(64)));
    for malformed in [
        String::new(),
        "F".repeat(64),
        "g".repeat(64),
        "a".repeat(63),
        "a".repeat(65),
        format!("{} ", "a".repeat(63)),
    ] {
        assert!(!is_purge_key(&malformed), "{malformed:?}");
    }
}

/// A ledger that takes nothing: the window tests never reach it.
struct UnreachedLedger;

#[async_trait::async_trait]
impl DelegatedTokenPurgeLedger for UnreachedLedger {
    async fn record(
        &self,
        _purge_key: &str,
        _origin: &DelegatedTokenPurgeTrigger,
    ) -> Result<i64, PurgeNotRecorded> {
        Err(PurgeNotRecorded::Unavailable)
    }
}

fn cluster_purges() -> ClusterPurges {
    ClusterPurges {
        ledger: Arc::new(UnreachedLedger),
        deployment_id: "deploy-window".to_owned(),
        revoked_credential_records: Mutex::new(HashMap::new()),
    }
}

/// The same refused credential can be presented any number of times, so a
/// replica records its principal's purge once per window, and every other
/// principal's on their own.
#[test]
fn a_revoked_credential_is_recorded_once_per_principal_per_window() {
    let cluster = cluster_purges();
    let alice = principal_digest("https://idp.example.test", "alice");
    let bob = principal_digest("https://idp.example.test", "bob");
    assert!(cluster.claim_revoked_credential_record(alice));
    assert!(!cluster.claim_revoked_credential_record(alice));
    assert!(cluster.claim_revoked_credential_record(bob));

    // Once the window has passed, the principal is recorded again.
    let expired = Instant::now()
        .checked_sub(REVOKED_CREDENTIAL_RECORD_WINDOW + Duration::from_secs(1))
        .expect("the test clock reaches back one window");
    cluster.records_guard().insert(alice, expired);
    assert!(cluster.claim_revoked_credential_record(alice));
    assert!(!cluster.claim_revoked_credential_record(alice));
}

/// A replica remembers a bounded number of principals. When every slot
/// holds a fresh record it records the next principal's purge anyway --
/// never skipping one it cannot remember -- and expired records make room.
#[test]
fn a_full_record_window_records_anyway_and_makes_room_from_expired_entries() {
    let cluster = cluster_purges();
    for index in 0..MAX_REMEMBERED_REVOKED_CREDENTIAL_RECORDS {
        assert!(cluster.claim_revoked_credential_record(principal_digest(
            "https://idp.example.test",
            &format!("user-{index}"),
        )));
    }
    let late = principal_digest("https://idp.example.test", "late");
    assert!(cluster.claim_revoked_credential_record(late));
    assert!(
        cluster.claim_revoked_credential_record(late),
        "a principal the full window could not remember is recorded every time"
    );
    assert_eq!(
        cluster.records_guard().len(),
        MAX_REMEMBERED_REVOKED_CREDENTIAL_RECORDS
    );

    let expired = Instant::now()
        .checked_sub(REVOKED_CREDENTIAL_RECORD_WINDOW + Duration::from_secs(1))
        .expect("the test clock reaches back one window");
    cluster
        .records_guard()
        .values_mut()
        .for_each(|at| *at = expired);
    assert!(cluster.claim_revoked_credential_record(late));
    assert!(!cluster.claim_revoked_credential_record(late));
    assert_eq!(
        cluster.records_guard().len(),
        1,
        "expired records made room"
    );
}

#[test]
fn a_purges_replication_is_audited_by_outcome() {
    assert_eq!(PurgeRecord::NotNeeded.audit(), serde_json::Value::Null);
    assert_eq!(
        PurgeRecord::Recorded(7).audit(),
        json!({ "outcome": "recorded", "security_revision": 7 })
    );
    assert_eq!(
        PurgeRecord::Applied(7).audit(),
        json!({ "outcome": "applied", "security_revision": 7 })
    );
    assert_eq!(
        PurgeRecord::RecentlyRecorded.audit(),
        json!({ "outcome": "recently_recorded" })
    );
    assert_eq!(
        PurgeRecord::NotRecorded(PurgeNotRecorded::Unavailable).audit(),
        json!({ "outcome": "not_recorded", "reason": "purge_not_recorded" })
    );
    assert_eq!(
        PurgeRecord::NotRecorded(PurgeNotRecorded::Refused {
            reason: "capability_not_advertised",
            detail: "a live member lacks it".to_owned(),
            members_lack_capability: true,
        })
        .audit(),
        json!({ "outcome": "not_recorded", "reason": "capability_not_advertised" })
    );
}
