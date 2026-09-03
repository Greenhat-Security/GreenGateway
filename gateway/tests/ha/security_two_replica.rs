//! The two-replica security matrix (issue #241, PR 16).
//!
//! Everything in this file is the same question asked of different
//! security state: **does a decision made on one replica bind the other,
//! at once, and exactly once?** A single-process gateway gets this for
//! free — one map, one lock, one answer. A cluster does not, and the
//! failures are the quiet kind: a token that stays valid on the replica
//! that did not revoke it, two admins who both "win" a write, a burst that
//! is permitted N times per replica instead of N times in total.
//!
//! Every test here therefore does its two halves on *different* replicas,
//! pinned through the harness balancer, and asserts on state the whole
//! deployment shares. Waits are bounded polls on observable conditions and
//! on database time; nothing sleeps for a guessed duration and nothing
//! moves a clock.
//!
//! Skips silently without `GATEWAY_TEST_POSTGRES_URL_FILE`, like every
//! other PostgreSQL-backed suite in this repository.

#![cfg(feature = "postgres")]

mod harness;

use std::time::Duration;

use serde_json::{json, Value};

use harness::{
    oidc, AuthShape, Cluster, ClusterOptions, FakeOidcIssuer, ADMIN_CALLBACK_PATH, ADMIN_LOGIN_PATH,
};

/// The role the suite's tokens carry, and the one the seeded policy grants
/// everything to. A wildcard because this suite is about *cluster*
/// agreement on security state, not about which permission guards which
/// route — the per-permission checks are unit-tested in `main.rs`.
const ADMIN_ROLE: &str = "ha-admin";

/// How long a cross-replica effect may take before the test calls it a
/// failure. Generous on purpose: this machine runs other builds, and every
/// wait here is a bounded poll that returns as soon as the condition holds.
const CONVERGENCE_BUDGET: Duration = Duration::from_secs(45);

/// A policy that grants [`ADMIN_ROLE`] everything and leaves the data
/// plane open, so a test that is about admin writes is not also about
/// route authorization.
///
/// Written with exactly the fields `rbac::Policy` serializes, so the
/// harness can compute the ETag the gateway will compute.
fn admin_policy() -> String {
    json!({
        "default_action": "allow",
        "enforcement_mode": "enforce",
        "roles": { ADMIN_ROLE: { "permissions": ["*"] } },
        "routes": [],
        "rules": [],
        "schema_version": "0.1.0",
    })
    .to_string()
}

/// Start a two-replica cluster with authentication on, or answer `None`
/// when there is no database to start it against.
async fn start_secure_cluster(options: ClusterOptions) -> Option<Cluster> {
    // Filled in rather than overridden with struct-update syntax: a listed
    // field WINS over `..options`, so spelling `seed_policy` here would
    // silently discard every caller's own policy.
    let mut options = options;
    options.auth = AuthShape::Oidc;
    if options.seed_policy.is_none() {
        options.seed_policy = Some(admin_policy());
    }
    let mut cluster = Cluster::start(options).await?;
    cluster.wait_until_all_ready().await;
    Some(cluster)
}

fn skipped() {
    eprintln!("skipping: no test database locator, or this run is not the gate; the ha-release-gate CI job runs this suite");
}

/// A token the seeded policy grants everything to.
fn admin_token(issuer: &FakeOidcIssuer, subject: &str) -> String {
    issuer.mint_role_token(
        oidc::PRIMARY_KID,
        subject,
        &format!("jti-{}", uuid::Uuid::new_v4().simple()),
        &[ADMIN_ROLE],
        3_600,
    )
}

/// The `Location` of a redirect, or a panic naming the response that had
/// none.
fn location(headers: &reqwest::header::HeaderMap, context: &str) -> String {
    headers
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("{context} carried no Location header"))
        .to_owned()
}

/// The path-and-query of an absolute URL, for re-issuing it through the
/// balancer against a chosen replica.
fn path_and_query(absolute: &str) -> String {
    let parsed = url::Url::parse(absolute)
        .unwrap_or_else(|error| panic!("{absolute} should be an absolute URL: {error}"));
    match parsed.query() {
        Some(query) => format!("{}?{query}", parsed.path()),
        None => parsed.path().to_owned(),
    }
}

// ---------------------------------------------------------------------
// OIDC login across replicas
// ---------------------------------------------------------------------

/// A login that starts on A and comes back to B completes, and the code it
/// carries is spent exactly once however many replicas race for it.
///
/// The pending login is the state that makes this hard: it holds the PKCE
/// verifier and the nonce, it must be readable by whichever replica the
/// browser's redirect happens to land on, and it must be consumable
/// exactly once — otherwise a captured callback URL is replayable, on the
/// same replica or a different one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_login_started_on_one_replica_completes_on_the_other_exactly_once() {
    let Some(cluster) = start_secure_cluster(ClusterOptions::default()).await else {
        return skipped();
    };

    // 1. Start on A. The redirect is to the issuer's authorization
    //    endpoint, and the pending state is now in the deployment's store,
    //    not in replica A's memory.
    let (status, headers, _) = cluster.get("a", ADMIN_LOGIN_PATH).send_with_headers().await;
    assert_eq!(status, 302, "the login endpoint should redirect to the IdP");
    let authorization_url = location(&headers, "the login redirect");
    assert!(
        authorization_url.starts_with(&cluster.oidc.authorize_url),
        "the login should redirect to the configured issuer, not {authorization_url}"
    );

    // 2. The browser visits the issuer, which mints a one-time code and
    //    redirects to the deployment's public callback — the balancer.
    let issuer_response = harness::http_client()
        .get(&authorization_url)
        .send()
        .await
        .expect("the fake issuer should answer the authorization request");
    assert_eq!(issuer_response.status().as_u16(), 302);
    let callback_url = location(issuer_response.headers(), "the issuer's redirect");
    let callback = path_and_query(&callback_url);

    // 3. Complete on B. Replica B never saw the start, so everything it
    //    needs — verifier, nonce — comes from the shared store.
    let (status, headers, _) = cluster.get("b", &callback).send_with_headers().await;
    assert_eq!(
        status, 302,
        "the callback should redirect; body-level failures are redirects too"
    );
    let completion = location(&headers, "the callback redirect");
    assert!(
        completion.contains("/#/auth/complete?token="),
        "the callback on B should complete the login, and instead said {completion}"
    );

    // Exactly one code exchange reached the issuer, and it was accepted.
    let exchanges = cluster.oidc.exchanges();
    assert_eq!(
        exchanges.len(),
        1,
        "one login should produce one token exchange, not {exchanges:?}"
    );
    assert!(exchanges[0].accepted);

    // 4. Replaying the very same callback — on either replica — must fail.
    //    The pending login was consumed, so the state is unknown, and the
    //    replay never reaches the issuer at all.
    for replica in ["a", "b"] {
        let (status, headers, _) = cluster.get(replica, &callback).send_with_headers().await;
        assert_eq!(status, 302);
        let replayed = location(&headers, "the replayed callback");
        assert!(
            replayed.contains("/#/auth/error?error=invalid_state"),
            "replaying a spent callback on {replica} must be refused, and instead said {replayed}"
        );
    }
    assert_eq!(
        cluster.oidc.exchanges().len(),
        1,
        "a replayed callback must not spend another code at the issuer"
    );
}

/// Two callbacks for one login, dispatched at the same moment to both
/// replicas: exactly one completes, and exactly one code exchange happens.
///
/// This is the race the single-process store never has to survive. Both
/// replicas read the same state value; the consume-once contract lives in
/// the database, and the loser must be told "unknown state" rather than
/// being allowed to exchange the code a second time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_callbacks_for_one_login_yield_one_exchange() {
    let Some(cluster) = start_secure_cluster(ClusterOptions::default()).await else {
        return skipped();
    };

    let (_, headers, _) = cluster.get("a", ADMIN_LOGIN_PATH).send_with_headers().await;
    let authorization_url = location(&headers, "the login redirect");
    let issuer_response = harness::http_client()
        .get(&authorization_url)
        .send()
        .await
        .expect("the fake issuer should answer the authorization request");
    let callback = path_and_query(&location(
        issuer_response.headers(),
        "the issuer's redirect",
    ));

    // Both in flight before either can finish.
    let (first, second) = tokio::join!(
        cluster.get("a", &callback).send_with_headers(),
        cluster.get("b", &callback).send_with_headers(),
    );

    let outcomes = [first, second].map(|(status, headers, _)| {
        assert_eq!(status, 302, "every callback answers with a redirect");
        location(&headers, "a simultaneous callback")
    });
    let completed = outcomes
        .iter()
        .filter(|target| target.contains("/#/auth/complete?token="))
        .count();
    let refused = outcomes
        .iter()
        .filter(|target| target.contains("/#/auth/error?error=invalid_state"))
        .count();
    assert_eq!(
        (completed, refused),
        (1, 1),
        "exactly one simultaneous callback may complete the login; got {outcomes:?}"
    );

    let exchanges = cluster.oidc.exchanges();
    assert_eq!(
        exchanges.len(),
        1,
        "the losing callback must never reach the issuer's token endpoint: {exchanges:?}"
    );
    assert!(
        exchanges[0].accepted,
        "the winning callback's exchange should have been accepted"
    );
}

/// The callback path is the deployment's, whichever replica answers it —
/// pinned here so a future change that made the redirect URI replica-local
/// (and so unroutable through a load balancer) fails loudly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_login_redirect_uri_is_the_deployments_public_callback() {
    let Some(cluster) = start_secure_cluster(ClusterOptions::default()).await else {
        return skipped();
    };

    for replica in ["a", "b"] {
        let (status, headers, _) = cluster
            .get(replica, ADMIN_LOGIN_PATH)
            .send_with_headers()
            .await;
        assert_eq!(status, 302);
        let authorization_url = location(&headers, "the login redirect");
        let parsed = url::Url::parse(&authorization_url).expect("an absolute authorization URL");
        let redirect_uri = parsed
            .query_pairs()
            .find(|(name, _)| name == "redirect_uri")
            .map(|(_, value)| value.into_owned())
            .expect("the authorization request should carry a redirect_uri");
        assert_eq!(
            redirect_uri,
            format!("{}{ADMIN_CALLBACK_PATH}", cluster.balancer.base_url),
            "replica {replica} must send the browser back to the deployment, not to itself"
        );
    }

    // Both replicas registered a pending login against the same
    // deployment: the store is shared, not per process.
    let pending: i64 = cluster
        .database
        .count("SELECT count(*)::bigint FROM greengateway.admin_pending_logins")
        .await;
    assert_eq!(
        pending, 2,
        "two started logins should leave two rows in the deployment's shared store"
    );
}

// ---------------------------------------------------------------------
// Service tokens across replicas
// ---------------------------------------------------------------------

const TOKENS_ROUTE: &str = "/v1/admin/tokens";
const STATUS_ROUTE: &str = "/v1/admin/status";

/// Create a service token on `replica`, returning its id and its one-time
/// plaintext.
async fn create_service_token(cluster: &Cluster, replica: &str, admin: &str) -> (String, String) {
    let (status, _, body) = send_settled(|| {
        cluster
            .post(replica, TOKENS_ROUTE)
            .bearer(admin)
            .json(&json!({ "scopes": [ADMIN_ROLE] }))
    })
    .await;
    assert_eq!(
        status, 201,
        "creating a service token on {replica} should succeed, said {body}"
    );
    let id = body["token"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("the created token should carry an id: {body}"))
        .to_owned();
    let secret = body["plaintext_token"]
        .as_str()
        .unwrap_or_else(|| panic!("the created token should carry a plaintext: {body}"))
        .to_owned();
    (id, secret)
}

/// Whether `credential` still authenticates on `replica`, judged by an
/// endpoint that needs nothing but a valid principal with the suite's
/// role.
async fn authenticates(cluster: &Cluster, replica: &str, credential: &str) -> bool {
    // A `503` is the replica saying it could not consult the authority —
    // "cannot judge", which is not an answer to "is this credential
    // accepted?". Asking again is therefore the honest thing, and the
    // bound is what keeps a genuinely unreachable authority a failure
    // rather than a hang. Every other status is decided at once: nothing
    // here waits for a *decision* to change, because the whole point of
    // the shared revision is that it does not need to.
    let deadline = std::time::Instant::now() + AUTHORITY_RETRY_BUDGET;
    loop {
        let (status, body) = cluster
            .get(replica, STATUS_ROUTE)
            .bearer(credential)
            .send()
            .await;
        match status {
            200 => return true,
            401 => return false,
            503 if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            other => panic!(
                "a credential probe on {replica} should be accepted or refused, not {other}: \
                 {body}"
            ),
        }
    }
}

/// Issue a request, re-issuing it while the replica answers `503`.
///
/// Same reasoning as [`authenticates`], applied to the *setup* steps: a
/// replica that could not consult the authority has declined to judge, and
/// repeating the step within a bound is the honest reading. Nothing whose
/// assertion is ABOUT `503` goes through here — those tests send their
/// request once and mean it.
async fn send_settled(
    build: impl Fn() -> harness::PinnedRequest,
) -> (u16, reqwest::header::HeaderMap, Value) {
    let deadline = std::time::Instant::now() + AUTHORITY_RETRY_BUDGET;
    loop {
        let outcome = build().send_with_headers().await;
        if outcome.0 != 503 || std::time::Instant::now() >= deadline {
            return outcome;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Dispatch two requests at once — the race every "exactly one winner"
/// claim in this file is made of — re-running it while BOTH sides answered
/// `503`.
///
/// Two replicas that could not reach the authority decided nothing: the
/// precondition they raced on is untouched, so racing again asks the same
/// question rather than a new one. One side deciding is a result, however
/// the other answered, and is returned as it is.
async fn race(
    first: impl Fn() -> harness::PinnedRequest,
    second: impl Fn() -> harness::PinnedRequest,
) -> [(u16, Value); 2] {
    let deadline = std::time::Instant::now() + AUTHORITY_RETRY_BUDGET;
    loop {
        let (left, right) = tokio::join!(first().send(), second().send());
        if left.0 != 503 || right.0 != 503 || std::time::Instant::now() >= deadline {
            return [left, right];
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// How long a probe re-asks a replica that answered "the authority is
/// unavailable". Generous because this suite shares its PostgreSQL server
/// with the rest of the build.
const AUTHORITY_RETRY_BUDGET: Duration = Duration::from_secs(20);

/// A token minted on one replica is a deployment credential, and
/// withdrawing it on one replica withdraws it on both — on the very next
/// request, not at the end of some cache's lifetime.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_service_token_created_on_one_replica_is_authenticated_and_revoked_on_the_other() {
    let Some(cluster) = start_secure_cluster(ClusterOptions::default()).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    // Created on A.
    let (token_id, secret) = create_service_token(&cluster, "a", &admin).await;

    // Authenticates on B, which never saw the creation.
    assert!(
        authenticates(&cluster, "b", &secret).await,
        "a token created on A must authenticate on B"
    );
    // And on A, so a later failure is about the revoke rather than about
    // the token never having worked there.
    assert!(authenticates(&cluster, "a", &secret).await);

    // Revoked on A.
    let (status, _, body) = send_settled(|| {
        cluster
            .delete("a", &format!("{TOKENS_ROUTE}/{token_id}"))
            .bearer(&admin)
    })
    .await;
    assert_eq!(status, 200, "revoking on A should succeed, said {body}");

    // Refused on B on the next request. No polling: the point of the
    // shared security revision is that this is immediate, so a loop here
    // would hide exactly the defect the row exists to catch.
    assert!(
        !authenticates(&cluster, "b", &secret).await,
        "a token revoked on A must be refused by B on the very next request"
    );
    assert!(!authenticates(&cluster, "a", &secret).await);
}

/// Rotating on one replica invalidates the old secret everywhere and makes
/// the new one usable everywhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotating_a_service_token_on_one_replica_binds_the_other() {
    let Some(cluster) = start_secure_cluster(ClusterOptions::default()).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");
    let (token_id, original) = create_service_token(&cluster, "a", &admin).await;
    assert!(authenticates(&cluster, "b", &original).await);

    let (status, _, body) = send_settled(|| {
        cluster
            .post("a", &format!("{TOKENS_ROUTE}/{token_id}/rotate"))
            .bearer(&admin)
            .empty_json()
    })
    .await;
    assert_eq!(status, 200, "rotating on A should succeed, said {body}");
    let rotated = body["plaintext_token"]
        .as_str()
        .expect("a rotation should return the new plaintext")
        .to_owned();
    assert_ne!(rotated, original, "a rotation must change the secret");

    assert!(
        !authenticates(&cluster, "b", &original).await,
        "the pre-rotation secret must be refused by B on the next request"
    );
    assert!(
        authenticates(&cluster, "b", &rotated).await,
        "the rotated secret must be accepted by B"
    );
}

/// Two rotations of one token, one per replica, dispatched together.
///
/// The claim is about what SURVIVES, not about who was accepted. A
/// rotation is not a compare-and-swap and does not promise both callers a
/// `200`: they serialize on the token's row, and a caller that waited too
/// long for it is entitled to be refused. What the deployment may never do
/// is leave two live secrets for one token — that would be a rotation that
/// did not retire what it replaced, and it would hand an operator a
/// credential they believe they have just rotated away.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_rotations_leave_exactly_one_live_secret() {
    let Some(cluster) = start_secure_cluster(ClusterOptions::default()).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");
    let (token_id, original) = create_service_token(&cluster, "a", &admin).await;
    let rotate_route = format!("{TOKENS_ROUTE}/{token_id}/rotate");

    let outcomes = race(
        || cluster.post("a", &rotate_route).bearer(&admin).empty_json(),
        || cluster.post("b", &rotate_route).bearer(&admin).empty_json(),
    )
    .await;
    let accepted = outcomes.iter().filter(|(status, _)| *status == 200).count();
    assert!(
        accepted >= 1,
        "at least one of two rotations of a live token must be accepted; got {:?}",
        outcomes
            .iter()
            .map(|(status, body)| (*status, body.clone()))
            .collect::<Vec<_>>()
    );
    let secrets = outcomes
        .iter()
        .filter_map(|(_, body)| body["plaintext_token"].as_str().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    assert_eq!(
        secrets.len(),
        accepted,
        "every accepted rotation returns its new plaintext, and a refused one returns none"
    );
    if secrets.len() == 2 {
        assert_ne!(
            secrets[0], secrets[1],
            "two rotations must mint two different secrets"
        );
    }

    // Exactly one of the minted secrets is live, on BOTH replicas — and the
    // secret the token had before either rotation is dead.
    for replica in ["a", "b"] {
        let live = live_secret_count(&cluster, replica, &secrets).await;
        assert_eq!(
            live,
            1,
            "replica {replica} should accept exactly one of the {} minted secrets",
            secrets.len()
        );
        assert!(
            !authenticates(&cluster, replica, &original).await,
            "the pre-rotation secret must be dead on {replica}"
        );
    }
}

/// How many of `candidates` `replica` still accepts.
async fn live_secret_count(cluster: &Cluster, replica: &str, candidates: &[String]) -> usize {
    let mut live = 0;
    for candidate in candidates {
        if authenticates(cluster, replica, candidate).await {
            live += 1;
        }
    }
    live
}

/// A revoke on one replica racing a rotation on the other.
///
/// Whichever order the authority settles them in, the safe outcome is the
/// same and is the only acceptable one: the token is revoked, and no
/// secret — the original or a rotation's — authenticates anywhere. A
/// rotation that could resurrect a withdrawn token would hand an operator
/// a live credential for something they had just taken away.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_revoke_racing_a_rotation_leaves_the_token_withdrawn() {
    let Some(cluster) = start_secure_cluster(ClusterOptions::default()).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");
    let (token_id, original) = create_service_token(&cluster, "a", &admin).await;

    let [revoke, rotate] = race(
        || {
            cluster
                .delete("a", &format!("{TOKENS_ROUTE}/{token_id}"))
                .bearer(&admin)
        },
        || {
            cluster
                .post("b", &format!("{TOKENS_ROUTE}/{token_id}/rotate"))
                .bearer(&admin)
                .empty_json()
        },
    )
    .await;

    // A revoke is the one operation an operator is entitled to keep
    // asking for, so a replica that could not reach the authority is asked
    // again rather than allowed to leave the token live.
    let revoke = if revoke.0 == 503 {
        let (status, _, body) = send_settled(|| {
            cluster
                .delete("a", &format!("{TOKENS_ROUTE}/{token_id}"))
                .bearer(&admin)
        })
        .await;
        (status, body)
    } else {
        revoke
    };
    assert_eq!(
        revoke.0, 200,
        "a revoke of a live token always succeeds: {}",
        revoke.1
    );
    // The rotation either landed first (200), found the token already
    // withdrawn (409), or could not reach the authority (503). All three
    // are correct; what matters is what survives.
    assert!(
        matches!(rotate.0, 200 | 409 | 503),
        "a rotation racing a revoke should succeed, conflict or fail closed, not {}: {}",
        rotate.0,
        rotate.1
    );

    let mut candidates = vec![original];
    if let Some(secret) = rotate.1["plaintext_token"].as_str() {
        candidates.push(secret.to_owned());
    }
    for replica in ["a", "b"] {
        assert_eq!(
            live_secret_count(&cluster, replica, &candidates).await,
            0,
            "no secret for a revoked token may authenticate on {replica}"
        );
    }

    let revoked: i64 = cluster
        .database
        .count(
            "SELECT count(*)::bigint FROM greengateway.service_tokens \
             WHERE revoked_at IS NOT NULL",
        )
        .await;
    assert_eq!(revoked, 1, "the token must be recorded as withdrawn");
}

// ---------------------------------------------------------------------
// JWT revocation and signing keys
// ---------------------------------------------------------------------

/// A `jti` names a token *within an issuer*, never globally. Two issuers
/// that happen to mint the same `jti` are two different tokens, and
/// withdrawing one must not withdraw the other.
///
/// This is a real collision risk rather than a theoretical one: `jti`
/// values are commonly short counters or per-tenant sequences, and a
/// denylist keyed on the bare value would let one identity provider revoke
/// another's sessions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_equal_jti_from_two_issuers_is_revoked_independently() {
    let Some(cluster) = start_secure_cluster(ClusterOptions {
        secondary_issuer: true,
        ..ClusterOptions::default()
    })
    .await
    else {
        return skipped();
    };

    // One `jti`, two issuers, two tokens.
    let shared_jti = format!("shared-{}", uuid::Uuid::new_v4().simple());
    let from_primary = cluster.oidc.mint_role_token(
        oidc::PRIMARY_KID,
        "collision@ha.test",
        &shared_jti,
        &[ADMIN_ROLE],
        3_600,
    );
    let from_secondary = cluster.secondary_issuer().mint_role_token(
        oidc::PRIMARY_KID,
        "collision@ha.test",
        &shared_jti,
        &[ADMIN_ROLE],
        3_600,
    );

    for replica in ["a", "b"] {
        assert!(
            authenticates(&cluster, replica, &from_primary).await,
            "the primary issuer's token should authenticate on {replica} before any revocation"
        );
        assert!(
            authenticates(&cluster, replica, &from_secondary).await,
            "the secondary issuer's token should authenticate on {replica} before any revocation"
        );
    }

    // Withdraw the primary issuer's token, by the operator's own one-shot
    // command against this deployment.
    let output = cluster.run_command(&["revoke-jwt", &cluster.oidc.issuer, &shared_jti]);
    assert!(
        output.status.success(),
        "revoke-jwt should succeed\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    for replica in ["a", "b"] {
        assert!(
            !authenticates(&cluster, replica, &from_primary).await,
            "the revoked token must be refused by {replica} on the next request"
        );
        assert!(
            authenticates(&cluster, replica, &from_secondary).await,
            "the other issuer's equal jti must be untouched on {replica}"
        );
    }

    // And the row itself is keyed per issuer: one withdrawal, not two.
    let revocations: i64 = cluster
        .database
        .count("SELECT count(*)::bigint FROM greengateway.jwt_revocations")
        .await;
    assert_eq!(
        revocations, 1,
        "one revocation should record exactly one row"
    );
}

/// Withdrawing a signing key from the issuer's JWKS stops acceptance of
/// tokens signed with it, on every replica, within the configured maximum
/// key age — and a flood of tokens carrying the withdrawn `kid` does not
/// turn into a flood of JWKS fetches.
///
/// The second half matters as much as the first: an unknown `kid` is
/// attacker-controlled, so a validator that refetched on every miss would
/// hand any caller a lever on the identity provider.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn withdrawing_a_signing_key_stops_acceptance_on_every_replica() {
    // Ten seconds is the smallest age the configuration admits, and it is
    // also the demand-refresh floor, so this is the shortest honest window
    // in which the property can be observed.
    const MAX_KEY_AGE_SECS: u64 = 10;
    let Some(cluster) = start_secure_cluster(ClusterOptions {
        jwks_max_key_age_secs: MAX_KEY_AGE_SECS,
        ..ClusterOptions::default()
    })
    .await
    else {
        return skipped();
    };

    // A second key, so removing it later leaves a NON-EMPTY key set. A
    // JWKS with no usable key is an issuer fault the validator refuses to
    // commit, which is a different behaviour (fail closed on staleness)
    // from the one this test is about.
    const RETIRED_KID: &str = "ha-retired";
    cluster.oidc.add_key(RETIRED_KID);
    let retired = cluster.oidc.mint_role_token(
        RETIRED_KID,
        "rotating@ha.test",
        &format!("jti-{}", uuid::Uuid::new_v4().simple()),
        &[ADMIN_ROLE],
        3_600,
    );
    let surviving = admin_token(&cluster.oidc, "surviving@ha.test");

    // Both replicas learn the new key on their own schedule.
    for replica in ["a", "b"] {
        wait_until_credential(&cluster, replica, &retired, true, CONVERGENCE_BUDGET).await;
    }

    // Withdraw it.
    cluster.oidc.remove_key(RETIRED_KID);
    let fetches_before = cluster.oidc.jwks_fetch_count();
    let withdrawn_at = cluster.database.epoch_seconds().await;

    // Acceptance stops on both replicas within the window the operator
    // configured, and the window is what is asserted.
    //
    // The bound is derived from `MAX_KEY_AGE_SECS` rather than from the
    // suite's general convergence budget: the age is the promise made to
    // the operator, and a wait of 45 seconds against a configured 10 would
    // pass a regression that kept a withdrawn key usable for most of a
    // minute. The worst honest case is one whole age (the key set may have
    // been refreshed a moment before the withdrawal) plus one refresh
    // interval (half the age, floored at ten seconds), and the slack on top
    // is for this machine's scheduling, not for the property.
    const REFRESH_INTERVAL_SECS: u64 = 10;
    const WITHDRAWAL_SLACK_SECS: u64 = 10;
    let withdrawal_budget =
        Duration::from_secs(MAX_KEY_AGE_SECS + REFRESH_INTERVAL_SECS + WITHDRAWAL_SLACK_SECS);
    // Both replicas are watched at once, so each is measured from the
    // withdrawal rather than from whenever its sibling happened to finish:
    // two sequential waits of one budget each would admit two budgets.
    tokio::join!(
        wait_until_credential(&cluster, "a", &retired, false, withdrawal_budget),
        wait_until_credential(&cluster, "b", &retired, false, withdrawal_budget),
    );
    // Read back on database time, so the window this test reports is
    // measured by the same clock every other deadline in the suite is.
    let elapsed = cluster.database.epoch_seconds().await - withdrawn_at;
    assert!(
        elapsed <= withdrawal_budget.as_secs_f64(),
        "a withdrawn key stayed acceptable for {elapsed:.1}s behind a configured maximum age \
         of {MAX_KEY_AGE_SECS}s"
    );
    // The surviving key is untouched: this was a key withdrawal, not an
    // outage.
    for replica in ["a", "b"] {
        assert!(
            authenticates(&cluster, replica, &surviving).await,
            "a token under a key that was NOT withdrawn must still authenticate on {replica}"
        );
    }

    // Now the demand floor: twenty rejected requests carrying the
    // withdrawn kid, as fast as they can be issued.
    let fetches_before_burst = cluster.oidc.jwks_fetch_count();
    for _ in 0..20 {
        assert!(!authenticates(&cluster, "a", &retired).await);
    }
    let burst_fetches = cluster.oidc.jwks_fetch_count() - fetches_before_burst;
    assert!(
        burst_fetches <= 4,
        "an unknown kid must not cost one JWKS fetch per request; the burst caused {burst_fetches}"
    );
    assert!(
        cluster.oidc.jwks_fetch_count() > fetches_before,
        "the replicas should have refreshed their key sets at all, or this test proves nothing \
         about the refresh path"
    );
}

/// Poll until `credential` is accepted (or refused) by `replica`.
async fn wait_until_credential(
    cluster: &Cluster,
    replica: &str,
    credential: &str,
    expected: bool,
    budget: Duration,
) {
    let deadline = std::time::Instant::now() + budget;
    loop {
        if authenticates(cluster, replica, credential).await == expected {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "replica {replica} did not reach accepted={expected} for this credential within {budget:?}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

// ---------------------------------------------------------------------
// Control-plane writes: one winner, one 412
// ---------------------------------------------------------------------

const POLICY_ROUTE: &str = "/v1/admin/policy";
const CONNECTIONS_ROUTE: &str = "/v1/admin/connections";
const TOOLS_REGISTER_ROUTE: &str = "/v1/admin/tools/openapi/register";
/// The Connection collection's own precondition, published beside the
/// ordinary `ETag` so a create can be conditional on the collection while
/// a replace is conditional on the row.
const CONNECTION_COLLECTION_ETAG_HEADER: &str = "x-greengateway-connections-etag";

/// The strong ETag a response carried, or a panic naming what had none.
fn etag(headers: &reqwest::header::HeaderMap, context: &str) -> String {
    headers
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("{context} carried no ETag"))
        .to_owned()
}

/// Classify a pair of racing writes as (winner, loser), failing with both
/// bodies when it is anything else.
///
/// The claim is "exactly one of these two commits". The winner is exact.
/// The loser is any of the three ways a write can fail to commit: `412`,
/// the precondition it raced for having moved (the ordinary case and the
/// one the matrix names); `409`, the same conflict reported by a resource
/// whose authority catches it on its own revision; and `503`, the replica
/// declining to judge because it could not reach the authority at all.
/// None of them wrote anything, which is what the caller goes on to assert
/// against the tables.
///
/// The `503` arm is not a loosening for its own sake. [`race`] re-runs a
/// pair only while BOTH sides answered `503` — once one side has decided,
/// the precondition is spent and re-racing would ask a different question —
/// so a `(success, 503)` pair is a legitimate, reachable outcome on a
/// loaded machine, and treating it as a failure would make these three
/// tests the flakiest assertions in the gate.
fn one_winner(
    outcomes: [(u16, Value); 2],
    success: u16,
    context: &str,
) -> ((u16, Value), (u16, Value)) {
    let statuses = [outcomes[0].0, outcomes[1].0];
    let winners = statuses.iter().filter(|status| **status == success).count();
    let losers = statuses
        .iter()
        .filter(|status| matches!(**status, 409 | 412 | 503))
        .count();
    assert_eq!(
        (winners, losers),
        (1, 1),
        "{context}: exactly one identical-precondition write may win and the other must be \
         refused (412), conflicted (409) or fail closed (503); got {statuses:?} with bodies \
         {:?} and {:?}",
        outcomes[0].1,
        outcomes[1].1
    );
    let [first, second] = outcomes;
    if first.0 == success {
        (first, second)
    } else {
        (second, first)
    }
}

/// A policy that grants [`ADMIN_ROLE`] everything and carries `marker` as a
/// second, harmless role, so two candidate documents differ.
fn marked_policy(marker: &str) -> Value {
    json!({
        "default_action": "allow",
        "enforcement_mode": "enforce",
        "roles": {
            ADMIN_ROLE: { "permissions": ["*"] },
            marker: { "permissions": [] },
        },
        "routes": [],
        "rules": [],
        "schema_version": "0.1.0",
    })
}

/// Two admins, two replicas, one ETag: the policy authority admits one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identical_if_match_policy_writes_admit_exactly_one() {
    let Some(cluster) = start_secure_cluster(ClusterOptions::default()).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    let (status, headers, _) = send_settled(|| cluster.get("a", POLICY_ROUTE).bearer(&admin)).await;
    assert_eq!(status, 200, "the policy should be readable");
    let precondition = etag(&headers, "the policy read");
    assert_eq!(
        precondition, cluster.seed_policy_etag,
        "the ETag a client reads must be the one the authority holds"
    );

    let outcomes = race(
        || {
            cluster
                .put("a", POLICY_ROUTE)
                .bearer(&admin)
                .if_match(&precondition)
                .json(&marked_policy("written-on-a"))
        },
        || {
            cluster
                .put("b", POLICY_ROUTE)
                .bearer(&admin)
                .if_match(&precondition)
                .json(&marked_policy("written-on-b"))
        },
    )
    .await;
    let (winner, _loser) = one_winner(outcomes, 200, "policy");

    // One commit, not two: the loser wrote nothing at all.
    let versions: i64 = cluster
        .database
        .count("SELECT count(*)::bigint FROM greengateway.policy_documents")
        .await;
    assert_eq!(
        versions, 2,
        "the seed plus one winning commit; a losing write must append no version"
    );
    let active_roles: i64 = cluster
        .database
        .count(
            "SELECT count(*)::bigint FROM greengateway.policy_active a \
             JOIN greengateway.policy_documents d ON d.version = a.active_version \
             WHERE a.singleton AND d.document ? 'roles'",
        )
        .await;
    assert_eq!(active_roles, 1, "the pointer names one active document");

    // The winner's document is what both replicas now serve.
    let marker = winner.1["roles"]
        .as_object()
        .expect("a policy response carries its roles")
        .keys()
        .find(|role| role.as_str() != ADMIN_ROLE)
        .expect("the winning document carries its marker role")
        .clone();
    for replica in ["a", "b"] {
        let (status, _, body) =
            send_settled(|| cluster.get(replica, POLICY_ROUTE).bearer(&admin)).await;
        assert_eq!(status, 200);
        assert!(
            body["roles"].get(&marker).is_some(),
            "replica {replica} should serve the winning document, and served {body}"
        );
    }
}

/// The same race on a Connection, whose authority is a different table and
/// a different compare-and-swap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identical_if_match_connection_writes_admit_exactly_one() {
    let Some(cluster) = start_secure_cluster(ClusterOptions::default()).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    let create = json!({
        "display_name": "ha fixture",
        "kind": "http_api",
        "endpoint": { "base_url": cluster.upstream.base_url, "base_path": "/" },
        "authentication": { "type": "none" },
        "enabled": false,
    });
    // Creating a Connection is itself a conditional write, against the
    // COLLECTION's ETag rather than any one connection's — the header the
    // list endpoint publishes beside the ordinary `ETag`.
    let (status, headers, body) =
        send_settled(|| cluster.get("a", CONNECTIONS_ROUTE).bearer(&admin)).await;
    assert_eq!(status, 200, "the connection list should read: {body}");
    let collection = headers
        .get(CONNECTION_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("the connection list should publish its collection ETag")
        .to_owned();

    let (status, headers, body) = send_settled(|| {
        cluster
            .post("a", CONNECTIONS_ROUTE)
            .bearer(&admin)
            .if_match(&collection)
            .json(&create)
    })
    .await;
    assert_eq!(status, 201, "creating a connection should succeed: {body}");
    let id = body["id"]
        .as_str()
        .unwrap_or_else(|| panic!("a created connection should carry an id: {body}"))
        .to_owned();
    let precondition = etag(&headers, "the connection creation");

    // Replica B reconciles the new connection on its own schedule; the
    // race is only meaningful once both replicas hold the same ETag.
    let route = format!("{CONNECTIONS_ROUTE}/{id}");
    wait_until_etag(
        &cluster,
        "b",
        &route,
        &admin,
        &precondition,
        CONVERGENCE_BUDGET,
    )
    .await;

    let replace = |name: &str| {
        json!({
            "display_name": name,
            "kind": "http_api",
            "endpoint": { "base_url": cluster.upstream.base_url, "base_path": "/" },
            "authentication": { "type": "none" },
            "enabled": false,
        })
    };
    let outcomes = race(
        || {
            cluster
                .put("a", &route)
                .bearer(&admin)
                .if_match(&precondition)
                .json(&replace("renamed on a"))
        },
        || {
            cluster
                .put("b", &route)
                .bearer(&admin)
                .if_match(&precondition)
                .json(&replace("renamed on b"))
        },
    )
    .await;
    let (winner, _loser) = one_winner(outcomes, 200, "connection");
    let winning_name = winner.1["display_name"]
        .as_str()
        .expect("the winning connection carries its display name")
        .to_owned();
    let losing_name = ["renamed on a", "renamed on b"]
        .into_iter()
        .find(|candidate| *candidate != winning_name)
        .expect("the winner is one of the two candidate names");

    for replica in ["a", "b"] {
        wait_until_display_name(&cluster, replica, &route, &admin, &winning_name).await;
    }

    // One commit, not two — asserted against the immutable version history
    // rather than against the current view, because a loser that committed
    // and was then overwritten would leave the view looking right.
    let versions: i64 = cluster
        .database
        .count(&format!(
            "SELECT count(*)::bigint FROM greengateway.connection_documents \
             WHERE connection_id = '{id}'"
        ))
        .await;
    assert_eq!(
        versions, 2,
        "the create plus one winning replace; a losing write must append no version"
    );
    let losing_versions: i64 = cluster
        .database
        .count(&format!(
            "SELECT count(*)::bigint FROM greengateway.connection_documents \
             WHERE connection_id = '{id}' AND spec LIKE '%{losing_name}%'"
        ))
        .await;
    assert_eq!(
        losing_versions, 0,
        "the losing replica's document ({losing_name}) must not appear in the history"
    );
}

/// And on the tools document, whose write path is the OpenAPI register
/// endpoint.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identical_if_match_tools_writes_admit_exactly_one() {
    let Some(cluster) = start_secure_cluster(ClusterOptions {
        seed_tools: Some(harness::database::SEED_TOOLS_DOCUMENT.to_owned()),
        ..ClusterOptions::default()
    })
    .await
    else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");
    let precondition = cluster
        .seed_tools_etag
        .clone()
        .expect("this cluster seeded a tools document");

    let register = |operation: &str| {
        json!({
            "spec": json!({
                "openapi": "3.0.3",
                "info": { "title": "ha fixture", "version": "1.0.0" },
                "paths": { format!("/ha/{operation}"): { "get": { "operationId": operation } } },
            })
            .to_string(),
            "selected_tool_names": [operation],
        })
    };
    let outcomes = race(
        || {
            cluster
                .post("a", TOOLS_REGISTER_ROUTE)
                .bearer(&admin)
                .if_match(&precondition)
                .json(&register("ha_probe_alpha"))
        },
        || {
            cluster
                .post("b", TOOLS_REGISTER_ROUTE)
                .bearer(&admin)
                .if_match(&precondition)
                .json(&register("ha_probe_beta"))
        },
    )
    .await;
    // A registration answers `201`: it appends a new immutable version
    // rather than replacing one in place.
    let (winner, _loser) = one_winner(outcomes, 201, "tools");
    let registered = winner.1["registered_tool_names"][0]
        .as_str()
        .expect("the winning registration names its tool")
        .to_owned();

    let versions: i64 = cluster
        .database
        .count("SELECT count(*)::bigint FROM greengateway.tool_documents")
        .await;
    assert_eq!(
        versions, 2,
        "the seed plus one winning commit; a losing registration must append no version"
    );
    let active_tools: i64 = cluster
        .database
        .count(&format!(
            "SELECT count(*)::bigint FROM greengateway.tool_active a \
             JOIN greengateway.tool_documents d ON d.version = a.active_version \
             WHERE a.singleton AND d.document->'tools' @> '[{{\"name\":\"{registered}\"}}]'"
        ))
        .await;
    assert_eq!(
        active_tools, 1,
        "the active tools document should be the winner's"
    );
}

/// Poll until `replica` serves `route` with `expected` as its ETag.
async fn wait_until_etag(
    cluster: &Cluster,
    replica: &str,
    route: &str,
    admin: &str,
    expected: &str,
    budget: Duration,
) {
    let deadline = std::time::Instant::now() + budget;
    loop {
        let (status, headers, _) = cluster
            .get(replica, route)
            .bearer(admin)
            .send_with_headers()
            .await;
        if status == 200
            && headers
                .get(reqwest::header::ETAG)
                .and_then(|value| value.to_str().ok())
                == Some(expected)
        {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "replica {replica} did not converge on {expected} for {route} within {budget:?} \
             (last status {status})"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Poll until `replica` serves `route` with `expected` as its display name.
async fn wait_until_display_name(
    cluster: &Cluster,
    replica: &str,
    route: &str,
    admin: &str,
    expected: &str,
) {
    let deadline = std::time::Instant::now() + CONVERGENCE_BUDGET;
    loop {
        let (status, body) = cluster.get(replica, route).bearer(admin).send().await;
        if status == 200 && body["display_name"].as_str() == Some(expected) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "replica {replica} never served the winning connection (last status {status}, \
             body {body})"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// A mutation committed on one replica binds the other's very next
/// request: it is authorized under the new revision, or it fails closed.
/// It is never authorized under the revision the mutation replaced.
///
/// The failure this refuses is the quiet one: a replica that kept serving
/// an `allow` for as long as its snapshot lagged would let a withdrawn
/// permission keep working, and nothing in the response would say so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_after_a_mutation_uses_the_new_revision_or_fails_closed() {
    let Some(cluster) = start_secure_cluster(ClusterOptions::default()).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    // Both replicas authorize this principal today.
    for replica in ["a", "b"] {
        let (status, _, body) =
            send_settled(|| cluster.get(replica, STATUS_ROUTE).bearer(&admin)).await;
        assert_eq!(
            status, 200,
            "replica {replica} should authorize now: {body}"
        );
    }

    // Withdraw every permission the role grants, on A.
    let stripped = json!({
        "default_action": "allow",
        "enforcement_mode": "enforce",
        "roles": { ADMIN_ROLE: { "permissions": [] } },
        "routes": [],
        "rules": [],
        "schema_version": "0.1.0",
    });
    let (status, _, body) = send_settled(|| {
        cluster
            .put("a", POLICY_ROUTE)
            .bearer(&admin)
            .if_match(&cluster.seed_policy_etag)
            .json(&stripped)
    })
    .await;
    assert_eq!(status, 200, "the policy write should commit: {body}");

    // B's next request. Not a poll: the gate reads the authority per
    // request, so "eventually" would be the wrong assertion and would hide
    // the defect.
    let (status, body) = cluster.get("b", STATUS_ROUTE).bearer(&admin).send().await;
    assert!(
        matches!(status, 403 | 503),
        "the next request on B must be refused under the new revision or fail closed, \
         and instead answered {status}: {body}"
    );
    let (status, body) = cluster.get("a", STATUS_ROUTE).bearer(&admin).send().await;
    assert!(
        matches!(status, 403 | 503),
        "the writing replica must refuse too, and instead answered {status}: {body}"
    );
}

/// The data-plane path the proxy routes to the fake upstream.
const PROXIED_PATH: &str = "/echo/partition-probe";

/// A policy that refuses everything the data plane could dispatch, while
/// leaving the admin role's permissions intact.
fn dispatch_denying_policy() -> Value {
    json!({
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": { ADMIN_ROLE: { "permissions": ["*"] } },
        "routes": [],
        "rules": [],
        "schema_version": "0.1.0",
    })
}

/// A replica that cannot reach the authority refuses rather than
/// dispatching under the allow it last saw.
///
/// This is the failure that makes a stale cache dangerous rather than
/// merely slow: A withdraws a permission, B loses its database before it
/// ever reads the new revision, and B goes on proxying under the old
/// answer. The upstream is the witness — not the status code — because the
/// defect is a request that *reached the backend*, whatever the caller was
/// eventually told.
///
/// The partition is the shape the matrix prescribes for a hosted runner
/// (`iptables` is unavailable there): the runtime role's `CONNECT` is
/// revoked and its established backends are terminated, so the replicas
/// can neither use nor reopen a connection. It is the whole database, not
/// one replica's link, which is if anything the harder case: both replicas
/// are blind, and neither may dispatch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_partitioned_replica_does_not_dispatch_under_the_allow_it_last_saw() {
    let Some(mut cluster) = start_secure_cluster(ClusterOptions::default()).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    // B dispatches today, under the seeded allow.
    cluster.upstream.clear();
    let (status, _, body) = send_settled(|| cluster.get("b", PROXIED_PATH).bearer(&admin)).await;
    assert_eq!(
        status, 200,
        "the seeded policy should let B proxy this path: {body}"
    );
    assert_eq!(
        cluster.upstream.requests().len(),
        1,
        "the warm-up request should have reached the upstream"
    );

    // A withdraws the allow. B is never asked, and never gets the chance:
    // its database goes away in the next step.
    let (status, _, body) = send_settled(|| {
        cluster
            .put("a", POLICY_ROUTE)
            .bearer(&admin)
            .if_match(&cluster.seed_policy_etag)
            .json(&dispatch_denying_policy())
    })
    .await;
    assert_eq!(status, 200, "the withdrawing write should commit: {body}");

    // The partition.
    cluster.upstream.clear();
    cluster.database.revoke_connect().await;
    let terminated = cluster.database.terminate_runtime_backends().await;
    assert!(
        terminated > 0,
        "the replicas should have held backends to terminate"
    );

    // Every request B answers while it is blind is a refusal, and none of
    // them is dispatched. The loop is bounded and its subject is the whole
    // window, not one sample: a replica that fell back to its cached allow
    // would do so at some point in this window, not necessarily the first.
    let mut refusals = 0_usize;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        let (status, body) = cluster.get("b", PROXIED_PATH).bearer(&admin).send().await;
        assert_ne!(
            status, 200,
            "a replica that cannot reach the authority must not serve this path: {body}"
        );
        if status >= 500 || status == 403 {
            refusals += 1;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        refusals > 0,
        "the partitioned replica should have been refusing, and answered nothing recognisable"
    );
    assert!(
        cluster.upstream.requests().is_empty(),
        "a partitioned replica dispatched {} request(s) to the upstream under the allow it \
         last saw",
        cluster.upstream.requests().len()
    );

    // Recovery, so the refusal above is the partition and not a broken
    // deployment: the grant back, both replicas ready, and the path now
    // refused on its merits under the new revision rather than for want of
    // an authority.
    //
    // Settled, not sampled once. Readiness is not a promise about the very
    // next request: the revision gate re-reads the authority per request
    // within its own bounded budget, so a replica that has just regained
    // its grant can still answer `503` for a moment while the pool replaces
    // the backends the partition killed. `send_settled` is what the rest of
    // this file uses for exactly that, and it does not weaken the claim --
    // a `503` is a refusal that dispatches nothing, and the assertion below
    // still requires the answer to settle on `403` on the merits.
    cluster.database.restore_connect().await;
    cluster.wait_until_all_ready().await;
    for replica in ["a", "b"] {
        let (status, _, body) =
            send_settled(|| cluster.get(replica, PROXIED_PATH).bearer(&admin)).await;
        assert_eq!(
            status, 403,
            "replica {replica} should refuse the withdrawn path under the new revision \
             once its database is back: {body}"
        );
    }
    assert!(
        cluster.upstream.requests().is_empty(),
        "nothing may be dispatched under a withdrawn allow, before or after recovery"
    );
}

/// A fault delivered inside a control-plane transaction leaves no partial
/// state: no version without its outbox row, no pointer to a version that
/// is not there, no revision counted twice.
///
/// The `policy_documents` / `security_revision_state` / `policy_active` /
/// `security_outbox` quartet is written by ONE transaction, and each of
/// those four writes is a step a connection can die between. What this test
/// cannot do is choose the step: it terminates the replica's backends
/// while a write is in flight and repeats, so the faults land where they
/// land. What it therefore asserts is the invariant that must hold after
/// EVERY step, rather than the outcome of any one attempt — and
/// deliberately does not assert how many writes survived, because a
/// connection killed after `COMMIT` but before the reply is a legitimate
/// unknown for the client and a fully committed transaction for the
/// database.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fault_inside_a_control_plane_transaction_leaves_no_partial_state() {
    const ATTEMPTS: usize = 6;
    let Some(cluster) = start_secure_cluster(ClusterOptions::default()).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");
    let mut terminated_total = 0_i64;

    for attempt in 0..ATTEMPTS {
        // The precondition is read fresh each time: a fault may or may not
        // have moved it, and a write that failed its precondition is a
        // refusal like any other, not a fault this test needs.
        let (status, headers, _) =
            send_settled(|| cluster.get("a", POLICY_ROUTE).bearer(&admin)).await;
        assert_eq!(status, 200, "the policy should stay readable under faults");
        let precondition = etag(&headers, "the policy read");
        let replica = if attempt % 2 == 0 { "a" } else { "b" };
        let document = marked_policy(&format!("fault-attempt-{attempt}"));

        // The write and the fault, together. The terminate is issued a
        // moment after the request so it lands somewhere inside the
        // transaction rather than before it opens; the pair is joined so
        // neither outlives the attempt.
        let write = cluster
            .put(replica, POLICY_ROUTE)
            .bearer(&admin)
            .if_match(&precondition)
            .json(&document)
            .send();
        let fault = async {
            tokio::time::sleep(Duration::from_millis(15 * (attempt as u64 + 1))).await;
            cluster.database.terminate_runtime_backends().await
        };
        let ((status, _), terminated) = tokio::join!(write, fault);
        terminated_total += terminated;
        // Any answer is admissible: committed, refused on its
        // precondition, or failed closed because the connection died. What
        // is not admissible is any of them leaving the quartet inconsistent.
        assert!(
            matches!(status, 200 | 409 | 412 | 500 | 502 | 503),
            "a faulted control-plane write should commit or fail cleanly, and answered {status}"
        );

        assert_no_partial_policy_state(&cluster, attempt).await;
    }
    // The faults were delivered: a run in which no backend was ever
    // signalled would be asserting the invariants of an undisturbed
    // control plane, which every other test in this file already does.
    assert!(
        terminated_total > 0,
        "no replica backend was terminated across {ATTEMPTS} attempts, so no fault was \
         actually injected"
    );

    // And the deployment still works afterwards: the invariants above would
    // also hold for a control plane that had simply stopped accepting
    // writes.
    let (status, headers, _) = send_settled(|| cluster.get("a", POLICY_ROUTE).bearer(&admin)).await;
    assert_eq!(status, 200);
    let precondition = etag(&headers, "the settled policy read");
    let (status, _, body) = send_settled(|| {
        cluster
            .put("b", POLICY_ROUTE)
            .bearer(&admin)
            .if_match(&precondition)
            .json(&marked_policy("after-the-faults"))
    })
    .await;
    assert_eq!(
        status, 200,
        "the control plane should accept a write once the faults stop: {body}"
    );
    assert_no_partial_policy_state(&cluster, ATTEMPTS).await;
}

/// The four rows one policy commit writes, checked against each other.
///
/// Every one of these is a partial commit made visible: a version with no
/// outbox row (the notification half lost), an outbox row with no version
/// (the reverse), a pointer whose ETag is not the document's, a pointer
/// whose revision is not the one the outbox recorded, or a reservation
/// counter that has fallen behind what was actually issued.
async fn assert_no_partial_policy_state(cluster: &Cluster, attempt: usize) {
    let orphan_versions: i64 = cluster
        .database
        .count(
            "SELECT count(*)::bigint FROM greengateway.policy_documents d \
             WHERE NOT EXISTS ( \
               SELECT 1 FROM greengateway.security_outbox o \
               WHERE o.resource_type = 'policy' AND o.to_version = d.version)",
        )
        .await;
    assert_eq!(
        orphan_versions, 0,
        "after attempt {attempt}: {orphan_versions} committed policy version(s) have no \
         outbox row, so a reader of the stream would never learn of them"
    );
    let orphan_outbox: i64 = cluster
        .database
        .count(
            "SELECT count(*)::bigint FROM greengateway.security_outbox o \
             WHERE o.resource_type = 'policy' AND NOT EXISTS ( \
               SELECT 1 FROM greengateway.policy_documents d WHERE d.version = o.to_version)",
        )
        .await;
    assert_eq!(
        orphan_outbox, 0,
        "after attempt {attempt}: {orphan_outbox} outbox row(s) announce a policy version \
         that was never committed"
    );
    let pointer_matches: i64 = cluster
        .database
        .count(
            "SELECT count(*)::bigint FROM greengateway.policy_active a \
             JOIN greengateway.policy_documents d ON d.version = a.active_version \
             JOIN greengateway.security_outbox o \
               ON o.resource_type = 'policy' AND o.to_version = a.active_version \
             WHERE a.singleton \
               AND a.document_etag = d.document_etag \
               AND a.security_revision = o.revision",
        )
        .await;
    assert_eq!(
        pointer_matches, 1,
        "after attempt {attempt}: the active pointer, its document and its outbox row should \
         agree on exactly one version"
    );
    let reservation_behind: i64 = cluster
        .database
        .count(
            "SELECT count(*)::bigint FROM greengateway.security_revision_state s \
             WHERE s.singleton \
               AND s.last_revision < coalesce( \
                 (SELECT max(revision) FROM greengateway.security_outbox), 0)",
        )
        .await;
    assert_eq!(
        reservation_behind, 0,
        "after attempt {attempt}: the revision counter is behind a revision that was already \
         issued, so the next write would reuse it"
    );
}

// ---------------------------------------------------------------------
// Suggestion acceptance (issue #241, PR 12)
// ---------------------------------------------------------------------

/// Accepting a rule suggestion installs a policy rule AND moves the
/// suggestion. Two replicas accepting the same suggestion at the same
/// moment must produce exactly one of each — never two rules, never a
/// rule with no transition, never a transition with no rule.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_suggestion_acceptance_yields_one_rule_and_one_transition() {
    let Some(cluster) = start_secure_cluster(ClusterOptions::default()).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    // The two rows the accept path re-validates against: an observed
    // endpoint whose routing context was classified before the suggestion
    // was raised, and the suggestion itself.
    const METHOD: &str = "GET";
    const TEMPLATE: &str = "/seeded/resource";
    cluster
        .database
        .seed_observed_endpoint(METHOD, TEMPLATE)
        .await;
    let suggestion_id = cluster
        .database
        .seed_rule_suggestion(
            "baseline_allow",
            METHOD,
            TEMPLATE,
            &json!({
                "action": "allow",
                "methods": [METHOD],
                "path": TEMPLATE,
                "principal": {
                    "roles": [ADMIN_ROLE],
                    "issuers": [cluster.oidc.issuer],
                    "auth_methods": ["bearer_token"],
                    "principal_ids": [],
                },
            }),
        )
        .await;

    // Accepting installs a policy RULE, so it carries the policy's own
    // precondition: both replicas race with the same `If-Match`, and the
    // loser can be refused either on the suggestion's revision or on that
    // ETag — the point is that it is refused, not which check caught it.
    let accept = format!("/v1/admin/suggestions/{suggestion_id}/accept");
    let precondition = cluster.seed_policy_etag.clone();
    let outcomes = race(
        || {
            cluster
                .post("a", &accept)
                .bearer(&admin)
                .if_match(&precondition)
                .empty_json()
        },
        || {
            cluster
                .post("b", &accept)
                .bearer(&admin)
                .if_match(&precondition)
                .empty_json()
        },
    )
    .await;

    let statuses = [outcomes[0].0, outcomes[1].0];
    let accepted = statuses.iter().filter(|status| **status == 201).count();
    assert_eq!(
        accepted, 1,
        "exactly one replica may accept the suggestion; got {statuses:?} with bodies {:?} and {:?}",
        outcomes[0].1, outcomes[1].1
    );
    let loser = statuses
        .iter()
        .copied()
        .find(|status| *status != 201)
        .expect("one of the two acceptances did not succeed");
    assert!(
        matches!(loser, 409 | 412 | 503),
        "the losing replica must be refused on the suggestion's revision or the policy's ETag \
         — or, if it could not reach the authority at all, fail closed — and instead answered \
         {loser}"
    );

    // One rule.
    let (status, _, body) = send_settled(|| cluster.get("a", POLICY_ROUTE).bearer(&admin)).await;
    assert_eq!(status, 200);
    let rules = body["rules"]
        .as_array()
        .expect("the policy carries its rules")
        .len();
    assert_eq!(rules, 1, "one acceptance must install exactly one rule");

    // One transition, and exactly one policy commit behind it.
    let row = cluster
        .database
        .query_one(&format!(
            "SELECT state, revision FROM greengateway.discovery_rule_suggestions \
             WHERE id = '{suggestion_id}'"
        ))
        .await;
    assert_eq!(
        row.get::<_, String>(0),
        "accepted",
        "the suggestion should be accepted"
    );
    assert_eq!(
        row.get::<_, i64>(1),
        2,
        "the suggestion should have moved exactly once"
    );
    let versions: i64 = cluster
        .database
        .count("SELECT count(*)::bigint FROM greengateway.policy_documents")
        .await;
    assert_eq!(
        versions, 2,
        "the seed plus one commit; the losing acceptance must have rolled back both halves"
    );
}

// ---------------------------------------------------------------------
// Distributed limits
// ---------------------------------------------------------------------

/// The path the rate-limit rule governs.
const RATE_LIMITED_PATH: &str = "/echo/limited";

/// A policy that publishes one per-principal rate-limit rule.
///
/// Every field `RateLimitRule` and `PrincipalMatcher` serialize is written
/// out, and `requests_per_second` carries a decimal point, so the document
/// round-trips to itself and the harness can compute the ETag the gateway
/// will compute.
fn rate_limited_policy(burst: u32) -> String {
    json!({
        "default_action": "allow",
        "enforcement_mode": "enforce",
        "roles": { ADMIN_ROLE: { "permissions": ["*"] } },
        "routes": [],
        "rules": [],
        "rate_limits": [{
            "principal": {
                "roles": [ADMIN_ROLE],
                "issuers": [],
                "auth_methods": [],
                "principal_ids": [],
            },
            "methods": ["GET"],
            "path": RATE_LIMITED_PATH,
            "requests_per_second": 0.5,
            "burst": burst,
        }],
        "schema_version": "0.1.0",
    })
    .to_string()
}

/// The per-principal burst the deployment publishes is the burst the
/// deployment enforces, not the burst each replica enforces.
///
/// This is the defect that a process-local token bucket has by
/// construction: with two replicas, a limit of N is silently a limit of
/// 2N, and it scales with the fleet. The burst is spread deliberately
/// across both replicas, so a per-replica bound would let 2N through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_across_both_replicas_permits_the_deployments_burst_in_total() {
    const BURST: u32 = 6;
    let Some(cluster) = start_secure_cluster(ClusterOptions {
        seed_policy: Some(rate_limited_policy(BURST)),
        ..ClusterOptions::default()
    })
    .await
    else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    // Twice the burst, alternating replicas, issued together so refill
    // cannot quietly grant an extra permit mid-run (the rule refills at
    // one request per second and the whole burst lands in well under one).
    let attempts = usize::try_from(BURST).expect("a small burst") * 2;
    let mut requests = Vec::with_capacity(attempts);
    for index in 0..attempts {
        let replica = if index % 2 == 0 { "a" } else { "b" };
        requests.push(
            cluster
                .get(replica, RATE_LIMITED_PATH)
                .bearer(&admin)
                .send(),
        );
    }
    let outcomes = futures_util::future::join_all(requests).await;

    let permitted = outcomes.iter().filter(|(status, _)| *status == 200).count();
    let limited = outcomes.iter().filter(|(status, _)| *status == 429).count();
    assert_eq!(
        permitted,
        usize::try_from(BURST).expect("a small burst"),
        "the deployment's burst is {BURST} in total across both replicas, and {permitted} \
         requests were permitted (statuses {:?})",
        outcomes
            .iter()
            .map(|(status, _)| *status)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        permitted + limited,
        attempts,
        "every request should have been permitted or limited"
    );

    // The bucket the policy decision was made in is the deployment's, not
    // a replica's: one row for one principal, whichever replica served
    // which request. (The pre-authentication `read` lane keeps its own
    // bucket, keyed by address; this counts only the policy lane, which is
    // the per-principal one the rule above governs.)
    let buckets: i64 = cluster
        .database
        .count(
            "SELECT count(*)::bigint FROM greengateway.rate_limit_buckets \
             WHERE lane = 'policy'",
        )
        .await;
    assert_eq!(
        buckets, 1,
        "one principal under one rule is one shared bucket for the whole deployment"
    );
}

// ---------------------------------------------------------------------
// Tool execution concurrency and execution leases (issue #241, PR 10)
// ---------------------------------------------------------------------

const TOOLS_ROUTE: &str = "/v1/admin/tools";
const ALPHA_TOOL: &str = "ha_alpha";
const BETA_TOOL: &str = "ha_beta";
/// How long the fake upstream holds an invocation open while a burst is
/// measured. Comfortably longer than the runtime's admission timeout, so a
/// request that is not admitted is refused rather than merely slower.
const SLOW_UPSTREAM: Duration = Duration::from_secs(5);
/// The runtime's admission timeout: an invocation that cannot take a slot
/// within this is refused with `429 queue_timeout` rather than queued.
const QUEUE_TIMEOUT_MS: u64 = 1_000;

/// A tools document with two legacy HTTP tools pointed at the harness's
/// upstream. Exactly the fields `ToolDefinition` serializes, so the
/// document round-trips to itself and its ETag is computable here.
fn two_tool_document() -> String {
    let tool = |name: &str, path: &str| {
        json!({
            "name": name,
            "description": "a release-gate fixture tool",
            "input_json_schema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false,
            },
            "upstream": { "method": "GET", "path_template": path },
        })
    };
    json!({
        "schema_version": "0.1.0",
        "tools": [tool(ALPHA_TOOL, "/alpha"), tool(BETA_TOOL, "/beta")],
    })
    .to_string()
}

/// A policy that admits both fixture tools at `max_concurrent` each.
fn tool_policy(max_concurrent: u32) -> String {
    let entry = json!({
        "enabled": true,
        "allowed_roles": [],
        // Longer than the slow upstream, so a bounded invocation is bounded
        // by the concurrency limit under test and not by its own timeout.
        "timeout_ms": 20_000,
        "max_concurrent": max_concurrent,
    });
    json!({
        "default_action": "allow",
        "enforcement_mode": "enforce",
        "roles": { ADMIN_ROLE: { "permissions": ["*"] } },
        "routes": [],
        "rules": [],
        "tools": { ALPHA_TOOL: entry, BETA_TOOL: entry },
        "schema_version": "0.1.0",
    })
    .to_string()
}

/// A cluster whose replicas can execute the two fixture tools.
async fn start_tool_cluster(global_concurrency: u32, per_tool: u32) -> Option<Cluster> {
    start_secure_cluster(ClusterOptions {
        proxy: harness::ProxyShape::LegacyUpstream,
        seed_policy: Some(tool_policy(per_tool)),
        seed_tools: Some(two_tool_document()),
        shared_env: vec![
            (
                "TOOL_RUNTIME_GLOBAL_CONCURRENCY".to_owned(),
                global_concurrency.to_string(),
            ),
            (
                "TOOL_RUNTIME_QUEUE_TIMEOUT_MS".to_owned(),
                QUEUE_TIMEOUT_MS.to_string(),
            ),
        ],
        ..ClusterOptions::default()
    })
    .await
}

/// The opaque capability id `replica` publishes for `tool`.
async fn capability_id(cluster: &Cluster, replica: &str, admin: &str, tool: &str) -> String {
    let (status, _, body) = send_settled(|| cluster.get(replica, TOOLS_ROUTE).bearer(admin)).await;
    assert_eq!(status, 200, "the capability inventory should list: {body}");
    body["capabilities"]
        .as_array()
        .unwrap_or_else(|| panic!("the inventory should carry capabilities: {body}"))
        .iter()
        .find(|capability| capability["name"].as_str() == Some(tool))
        .and_then(|capability| capability["id"].as_str())
        .unwrap_or_else(|| panic!("replica {replica} does not publish {tool}: {body}"))
        .to_owned()
}

/// One invocation of `tool` through `replica`, as an admin would run it
/// from the playground: read the capability, carry its execution ETag,
/// execute.
async fn execute_tool(cluster: &Cluster, replica: &str, admin: &str, tool: &str) -> (u16, Value) {
    let (id, execution_etag) =
        capability_execution_precondition(cluster, replica, admin, tool).await;
    cluster
        .post(replica, &format!("{TOOLS_ROUTE}/{id}/execute"))
        .bearer(admin)
        .if_match(&execution_etag)
        .json(&json!({ "arguments": {} }))
        .send()
        .await
}

/// The opaque id and execution ETag an invocation of `tool` must carry.
///
/// The ETag is a precondition, not an identifier: it binds the invocation
/// to the exact definition and permissions the caller read, so an
/// execution cannot ride a stale view of either.
async fn capability_execution_precondition(
    cluster: &Cluster,
    replica: &str,
    admin: &str,
    tool: &str,
) -> (String, String) {
    let id = capability_id(cluster, replica, admin, tool).await;
    let (status, headers, body) = send_settled(|| {
        cluster
            .get(replica, &format!("{TOOLS_ROUTE}/{id}"))
            .bearer(admin)
    })
    .await;
    assert_eq!(status, 200, "the capability detail should read: {body}");
    (id, etag(&headers, "the capability detail"))
}

/// The deployment's global tool-execution limit is the deployment's, not
/// each replica's.
///
/// With N replicas and a process-local semaphore a "global" limit of two
/// is really a limit of two per replica; the fix is a leased slot in a
/// shared scope, and this is what proves the slots are shared. The burst
/// is deliberately spread over both replicas and over both tools, so
/// neither per-replica nor per-tool bounding could produce the same
/// answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_burst_across_both_replicas_permits_the_global_tool_concurrency_in_total() {
    const GLOBAL: usize = 2;
    let Some(cluster) = start_tool_cluster(
        u32::try_from(GLOBAL).expect("a small limit"),
        // Per tool is deliberately NOT the binding constraint here.
        8,
    )
    .await
    else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    // A prior successful invocation on each replica, so the burst below
    // measures admission rather than a cold path.
    for replica in ["a", "b"] {
        let (status, body) = execute_tool(&cluster, replica, &admin, ALPHA_TOOL).await;
        assert_eq!(
            status, 200,
            "replica {replica} should be able to execute a fixture tool: {body}"
        );
    }

    cluster
        .upstream
        .set_behaviour(harness::Behaviour::Slow(SLOW_UPSTREAM));
    cluster.upstream.clear();
    let attempts = [
        ("a", ALPHA_TOOL),
        ("b", ALPHA_TOOL),
        ("a", BETA_TOOL),
        ("b", BETA_TOOL),
        ("a", ALPHA_TOOL),
        ("b", BETA_TOOL),
    ];
    let outcomes = futures_util::future::join_all(
        attempts
            .iter()
            .map(|(replica, tool)| execute_tool(&cluster, replica, &admin, tool)),
    )
    .await;
    cluster.upstream.set_behaviour(harness::Behaviour::Ok);

    let admitted = outcomes.iter().filter(|(status, _)| *status == 200).count();
    let refused = outcomes.iter().filter(|(status, _)| *status == 429).count();
    assert_eq!(
        admitted,
        GLOBAL,
        "the deployment permits {GLOBAL} concurrent invocations in total; {admitted} were \
         admitted (statuses {:?})",
        outcomes
            .iter()
            .map(|(status, _)| *status)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        admitted + refused,
        attempts.len(),
        "every invocation should have been admitted or refused admission"
    );
    assert!(
        cluster.upstream.peak_in_flight() <= GLOBAL,
        "no more than {GLOBAL} invocations may reach the upstream at once; the peak was {}",
        cluster.upstream.peak_in_flight()
    );
}

/// And the per-tool limit is per tool across the deployment: one slot for
/// `alpha` and one for `beta`, whichever replicas the callers reach.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_burst_across_both_replicas_permits_the_per_tool_concurrency_in_total() {
    let Some(cluster) = start_tool_cluster(
        // Global is deliberately NOT the binding constraint here: four
        // slots for what the per-tool limits cap at two.
        4, 1,
    )
    .await
    else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");
    for replica in ["a", "b"] {
        let (status, body) = execute_tool(&cluster, replica, &admin, ALPHA_TOOL).await;
        assert_eq!(status, 200, "replica {replica} warm-up: {body}");
    }

    cluster
        .upstream
        .set_behaviour(harness::Behaviour::Slow(SLOW_UPSTREAM));
    cluster.upstream.clear();
    let attempts = [
        ("a", ALPHA_TOOL),
        ("b", ALPHA_TOOL),
        ("a", BETA_TOOL),
        ("b", BETA_TOOL),
    ];
    let outcomes = futures_util::future::join_all(
        attempts
            .iter()
            .map(|(replica, tool)| execute_tool(&cluster, replica, &admin, tool)),
    )
    .await;
    cluster.upstream.set_behaviour(harness::Behaviour::Ok);

    let admitted = outcomes.iter().filter(|(status, _)| *status == 200).count();
    assert_eq!(
        admitted,
        2,
        "one slot per tool across the deployment admits two invocations, not four \
         (statuses {:?})",
        outcomes
            .iter()
            .map(|(status, _)| *status)
            .collect::<Vec<_>>()
    );
    // One of each tool reached the upstream, which is what makes this a
    // per-tool bound rather than a global one that happens to be two.
    let mut paths = cluster
        .upstream
        .requests()
        .iter()
        .map(|request| request.path.clone())
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    assert_eq!(
        paths,
        vec!["/alpha".to_owned(), "/beta".to_owned()],
        "both tools should have been admitted once each"
    );
}

/// A replica killed while it holds an execution lease does not take the
/// slot with it: the lease expires on the DATABASE clock, a successor on
/// the other replica takes the slot at a strictly greater fence, and the
/// deployment is back to full capacity.
///
/// Fencing is the part that makes the recovery safe rather than merely
/// convenient — the successor's fence is what a late write from the dead
/// holder would be refused against.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn killing_a_lease_holder_expires_the_lease_and_a_successor_takes_it_at_a_newer_fence() {
    // One slot, a short lease, and an admission timeout long enough for
    // the successor to outlast the dead holder's lease.
    let Some(mut cluster) = start_secure_cluster(ClusterOptions {
        proxy: harness::ProxyShape::LegacyUpstream,
        seed_policy: Some(tool_policy(4)),
        seed_tools: Some(two_tool_document()),
        shared_env: vec![
            ("TOOL_RUNTIME_GLOBAL_CONCURRENCY".to_owned(), "1".to_owned()),
            (
                "TOOL_RUNTIME_QUEUE_TIMEOUT_MS".to_owned(),
                "20000".to_owned(),
            ),
            ("TOOL_LEASE_TTL_MS".to_owned(), "2000".to_owned()),
        ],
        ..ClusterOptions::default()
    })
    .await
    else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    // Replica A takes the only slot and holds it: the upstream will not
    // answer until this test is done with it.
    cluster
        .upstream
        .set_behaviour(harness::Behaviour::Slow(Duration::from_secs(120)));
    let holder = {
        let base = cluster.balancer.base_url.clone();
        let (id, execution_etag) =
            capability_execution_precondition(&cluster, "a", &admin, ALPHA_TOOL).await;
        let admin = admin.clone();
        tokio::spawn(async move {
            let _ = harness::http_client()
                .post(format!("{base}{TOOLS_ROUTE}/{id}/execute"))
                .header(harness::PIN_HEADER, "a")
                .bearer_auth(&admin)
                .header("if-match", execution_etag)
                .json(&json!({ "arguments": {} }))
                .send()
                .await;
        })
    };
    // The lease exists, held by one instance at some fence. This is the
    // signal that A is really holding the slot — not the upstream's
    // in-flight count, which a proxy health probe can also raise.
    let first_fence = wait_for_lease_fence(&cluster, CONVERGENCE_BUDGET).await;

    // Kill the holder outright. No drain, no release: the slot can only
    // come back by expiry on the database clock.
    cluster.kill("a");
    holder.abort();
    // Slow enough that the successor still HOLDS its lease while the fence
    // is read: a released lease deletes its row, so a completed invocation
    // would leave nothing to compare.
    cluster
        .upstream
        .set_behaviour(harness::Behaviour::Slow(Duration::from_secs(15)));

    // A successor on B waits inside its admission timeout and takes the
    // slot once the abandoned lease lapses. The wait is the runtime's, not
    // the test's: nothing here sleeps for the lease's duration.
    let successor = {
        let admin = admin.clone();
        let base = cluster.balancer.base_url.clone();
        let (id, execution_etag) =
            capability_execution_precondition(&cluster, "b", &admin, ALPHA_TOOL).await;
        tokio::spawn(async move {
            harness::http_client()
                .post(format!("{base}{TOOLS_ROUTE}/{id}/execute"))
                .header(harness::PIN_HEADER, "b")
                .bearer_auth(&admin)
                .header("if-match", execution_etag)
                .json(&json!({ "arguments": {} }))
                .send()
                .await
                .map(|response| response.status().as_u16())
        })
    };

    // Read the fence while the successor still holds it. If the successor
    // finishes (or fails) before the fence moves, say what it answered:
    // "the fence did not advance" on its own would send a reader looking
    // at the lease store for a fault that is really in the request.
    let second_fence = wait_for_lease_fence_above(&cluster, first_fence, successor).await;
    assert!(
        second_fence > first_fence,
        "the successor must hold the slot at a strictly greater fence ({second_fence} \
         should exceed {first_fence})"
    );
}

/// The largest fence any lease of the global scope is held at, or zero
/// when the scope is free (a released lease deletes its row).
async fn global_lease_fence(cluster: &Cluster) -> i64 {
    cluster
        .database
        .count(
            "SELECT coalesce(max(fence), 0)::bigint FROM greengateway.execution_leases \
             WHERE scope = 'global'",
        )
        .await
}

/// The fence of the global scope's lease, once one is held.
async fn wait_for_lease_fence(cluster: &Cluster, budget: Duration) -> i64 {
    let deadline = std::time::Instant::now() + budget;
    loop {
        let fence = global_lease_fence(cluster).await;
        if fence > 0 {
            return fence;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no execution lease was taken within {budget:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The global scope's fence once it exceeds `previous`, while `successor`
/// is the in-flight invocation expected to take it.
///
/// The invocation is watched as well as the fence, because the two failure
/// modes look identical from the lease table alone: a successor that never
/// acquired, and a successor that was refused before it ever tried.
async fn wait_for_lease_fence_above(
    cluster: &Cluster,
    previous: i64,
    successor: tokio::task::JoinHandle<Result<u16, reqwest::Error>>,
) -> i64 {
    let deadline = std::time::Instant::now() + CONVERGENCE_BUDGET;
    loop {
        let fence = global_lease_fence(cluster).await;
        if fence > previous {
            return fence;
        }
        if successor.is_finished() {
            let outcome = successor
                .await
                .expect("the successor task should not panic")
                .map(|status| status.to_string())
                .unwrap_or_else(|error| format!("transport failure: {error}"));
            panic!(
                "the successor finished with {outcome} without ever holding the global scope \
                 above fence {previous}"
            );
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the global scope's fence never advanced past {previous} within \
             {CONVERGENCE_BUDGET:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
