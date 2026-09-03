//! Secret leakage across a running two-replica deployment (issue #241,
//! PR 16).
//!
//! Every other file in this gate asks whether the cluster *behaves*
//! correctly. This one asks what it *said* while doing so. The difference
//! matters because a leak is not a failure the deployment notices: the
//! request succeeds, the test passes, the invariant holds, and the secret
//! is in a log aggregator that a hundred people can read and that is
//! retained for a year. Cluster mode widens the surface — a DSN with a
//! password in it, a shared pending-login store, a keyed limiter digest,
//! sealed connection secrets, tokens minted on one replica and presented
//! to another — and every one of those crosses a process boundary where
//! something might helpfully print it.
//!
//! ## How the claim is made
//!
//! Canaries. Every input the deployment is given carries a value that
//! exists for no other reason than to be searched for afterwards: the
//! database password in the DSN the replicas read, a query parameter, a
//! request header, a JSON body field, a connection secret's plaintext, an
//! invalid bearer credential. Each is generated per run (never a literal —
//! a checked-in constant that looked like a credential would be a finding
//! of its own in a repository whose scanner reads history) and each is
//! prefixed `FAKE-` so it can never be mistaken for one.
//!
//! Alongside them go the secrets the *deployment itself* mints, which no
//! test can plant and which are the ones that actually matter: the OIDC
//! `state`, `nonce` and PKCE challenge of a real login, the session cookie
//! that login returns, a service token's one-time plaintext, a JWT and its
//! `jti`.
//!
//! The haystack is everything an operator or an incident responder can
//! read without the database: both replicas' stdout and stderr (the
//! structured logs, and anything a panic or a library wrote past them),
//! both `/metrics` scrapes, and both durable audit files. A needle found
//! in any of them fails, and the failure names which haystack and which
//! secret.
//!
//! ## The second half: what it says when it is broken
//!
//! Well-behaved code leaks under stress, not at rest — the connection
//! string appears in the error path, not the success path. So the second
//! test breaks the deployment's database access underneath it, lets both
//! replicas and a one-shot command fail and log their failures, and then
//! greps the same haystacks for the password and for any DSN at all.
//!
//! Skips silently without `GATEWAY_TEST_POSTGRES_URL_FILE`.

#![cfg(feature = "postgres")]

mod harness;

use std::time::Duration;

use serde_json::json;

use harness::{oidc, AuthShape, Cluster, ClusterOptions, ProxyShape, ADMIN_API_PREFIX};

const ADMIN_ROLE: &str = "ha-admin";
const TOKENS_ROUTE: &str = "/v1/admin/tokens";
const CONNECTION_SECRETS_ROUTE: &str = "/v1/admin/connection-secrets";
const STATUS_ROUTE: &str = "/v1/admin/status";
const ADMIN_LOGIN_PATH: &str = "/v1/admin/auth/login";
/// The connection-secret collection's own precondition, published beside
/// the ordinary `ETag` so a create can be conditional on the collection.
const CONNECTION_SECRET_COLLECTION_ETAG_HEADER: &str = "x-greengateway-connection-secrets-etag";
/// A proxied path, so the request crosses the whole stack — auth, policy,
/// the limiter, the observation middleware, the proxy — rather than
/// stopping at an admin handler.
const PROXIED_PATH: &str = "/echo/leak-probe";

/// How long the replicas are given to notice a broken database and say so.
const FAULT_BUDGET: Duration = Duration::from_secs(60);

fn skipped() {
    eprintln!("skipping: no test database locator, or this run is not the gate; the ha-release-gate CI job runs this suite");
}

/// A value that exists only so this suite can prove it never escaped.
///
/// Generated per run rather than written as a constant: a literal that
/// looked like a credential would be a finding in its own right in a
/// repository whose secret scanner reads history. The `FAKE-` prefix is
/// belt to that braces.
fn canary(label: &str) -> String {
    format!("FAKE-canary-{label}-{}", uuid::Uuid::new_v4().simple())
}

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

/// [`admin_policy`] with a second, unused role whose *name* is a canary.
///
/// Control-plane documents are not credentials, but they are the
/// deployment's private configuration: the policy API is meant to return
/// this string and nothing else is. Planting it proves the difference is
/// enforced rather than assumed — and the test asserts the policy API
/// really does return it, so the canary cannot pass by never having
/// arrived anywhere.
fn admin_policy_with_canary_role(role: &str) -> String {
    json!({
        "default_action": "allow",
        "enforcement_mode": "enforce",
        "roles": {
            ADMIN_ROLE: { "permissions": ["*"] },
            role: { "permissions": [] },
        },
        "routes": [],
        "rules": [],
        "schema_version": "0.1.0",
    })
    .to_string()
}

/// A tools document whose one tool carries a canary description: the same
/// claim as the policy role, for the other control-plane resource.
fn tools_with_canary_description(description: &str) -> String {
    json!({
        "schema_version": "0.1.0",
        "tools": [{
            "name": "ha_leak_probe",
            "description": description,
            "input_json_schema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false,
            },
            "upstream": { "method": "GET", "path_template": "/probe" },
        }],
    })
    .to_string()
}

/// Everything an operator can read without opening the database.
///
/// Deliberately raw text rather than parsed records: a leak that lands in
/// a field this suite did not think to decode is still a leak, and a
/// substring search over the bytes cannot miss it.
struct Haystack {
    sources: Vec<(String, String)>,
}

impl Haystack {
    /// Collect the current contents of every readable surface.
    async fn collect(cluster: &Cluster) -> Self {
        let mut sources = Vec::new();
        for replica in &cluster.replicas {
            sources.push((
                format!("replica {}'s stdout and stderr", replica.name),
                replica.captured_output(),
            ));
            sources.push((
                format!("replica {}'s audit log file", replica.name),
                std::fs::read_to_string(replica.audit_path()).unwrap_or_default(),
            ));
        }
        for replica in ["a", "b"] {
            sources.push((
                format!("replica {replica}'s /metrics scrape"),
                cluster.metrics(replica).await,
            ));
        }
        Self { sources }
    }

    /// Collect only what the processes have written, for a phase in which
    /// scraping over HTTP is not guaranteed to work (a replica whose
    /// database has been taken away may be refusing readiness, and
    /// `/metrics` is not the subject then).
    fn collect_process_output(cluster: &Cluster) -> Self {
        let sources = cluster
            .replicas
            .iter()
            .flat_map(|replica| {
                [
                    (
                        format!("replica {}'s stdout and stderr", replica.name),
                        replica.captured_output(),
                    ),
                    (
                        format!("replica {}'s audit log file", replica.name),
                        std::fs::read_to_string(replica.audit_path()).unwrap_or_default(),
                    ),
                ]
            })
            .collect();
        Self { sources }
    }

    /// Every admin and public API response this suite can read, whatever
    /// its status.
    ///
    /// A separate haystack from the process output because the two have
    /// different rules. An admin API may legitimately return a credential
    /// it has just minted, or a document it exists to serve, so the shape
    /// assertions do not apply here; it may never return the deployment's
    /// DSN, the material behind a digest, or a secret it was handed for
    /// safekeeping. Error bodies are collected too, since a `500` is
    /// where a connection string surfaces if one ever does.
    async fn collect_api(cluster: &Cluster, admin: &str) -> Self {
        const ADMIN_SURFACES: &[&str] = &[
            "/status",
            "/policy",
            "/policy/history",
            "/tools",
            "/tokens",
            "/connections",
            "/connection-secrets",
            "/audit",
            "/signals",
            "/suggestions",
            "/traffic/endpoints",
            "/principals",
        ];
        const PUBLIC_SURFACES: &[&str] =
            &["/livez", "/readyz", "/version", "/health", "/v1/admin/nope"];
        let mut sources = Vec::new();
        for replica in ["a", "b"] {
            for surface in ADMIN_SURFACES {
                let path = format!("{ADMIN_API_PREFIX}{surface}");
                let (status, headers, body) = cluster
                    .get(replica, &path)
                    .bearer(admin)
                    .send_with_headers()
                    .await;
                sources.push((
                    format!("the {path} response on replica {replica}"),
                    format!("status {status}\n{headers:?}\n{body}"),
                ));
            }
            for surface in PUBLIC_SURFACES {
                let (status, headers, body) =
                    cluster.get(replica, surface).send_with_headers().await;
                sources.push((
                    format!("the {surface} response on replica {replica}"),
                    format!("status {status}\n{headers:?}\n{body}"),
                ));
            }
            // The refusal paths, where a value is most often echoed back
            // "for debugging": no credential at all, and a tampered one.
            let (status, headers, body) =
                cluster.get(replica, STATUS_ROUTE).send_with_headers().await;
            sources.push((
                format!("the uncredentialed {STATUS_ROUTE} refusal on replica {replica}"),
                format!("status {status}\n{headers:?}\n{body}"),
            ));
            let (status, headers, body) = cluster
                .get(replica, STATUS_ROUTE)
                .bearer(&format!("{admin}tampered"))
                .send_with_headers()
                .await;
            sources.push((
                format!("the tampered-credential {STATUS_ROUTE} refusal on replica {replica}"),
                format!("status {status}\n{headers:?}\n{body}"),
            ));
        }
        Self { sources }
    }

    /// What the shared stores actually keep.
    ///
    /// This is where "the limiter key never reaches the database" and
    /// "the login state is stored as a digest" stop being module
    /// comments. The limiter's rows are read as their lane and the
    /// hexadecimal digest, and the pending-login rows as their digests,
    /// their key id and their sealed ciphertext — everything a reader of
    /// a backup would have.
    async fn collect_stored_rows(cluster: &Cluster) -> Self {
        let limiter = cluster
            .database
            .query_one(&format!(
                "SELECT coalesce(string_agg( \
                     lane || ' ' || encode(key_digest, 'hex'), E'\\n'), '') \
                 FROM greengateway.rate_limit_buckets WHERE deployment_id = '{}'",
                cluster.deployment_id
            ))
            .await
            .get::<_, String>(0);
        assert!(
            !limiter.is_empty(),
            "the shared limiter should have stored a bucket for the probe traffic; an \
             empty table would make the assertions against it vacuous"
        );
        let pending = cluster
            .database
            .query_one(
                "SELECT coalesce(string_agg( \
                     id::text || ' ' || state_hash || ' ' || client_key || ' ' || key_id \
                     || ' ' || encode(verifier_nonce, 'hex') \
                     || ' ' || encode(verifier_ct, 'hex') \
                     || ' ' || encode(nonce_nonce, 'hex') \
                     || ' ' || encode(nonce_ct, 'hex'), E'\\n'), '') \
                 FROM greengateway.admin_pending_logins",
            )
            .await
            .get::<_, String>(0);
        assert!(
            !pending.is_empty(),
            "a login should still be in flight; an empty table would make the assertions \
             against it vacuous"
        );
        Self {
            sources: vec![
                ("the shared limiter's stored rows".to_owned(), limiter),
                ("the shared pending-login store's rows".to_owned(), pending),
            ],
        }
    }

    /// Fail unless `needle` appears somewhere here: a positive control, so
    /// a canary that never reached the deployment at all cannot pass every
    /// absence assertion by simply not existing.
    fn assert_present(&self, description: &str, needle: &str) {
        assert!(
            self.sources.iter().any(|(_, text)| text.contains(needle)),
            "the {description} was never returned by any surface collected here, so the \
             assertions about where it must NOT appear would prove nothing"
        );
    }

    fn plus(mut self, label: &str, text: String) -> Self {
        self.sources.push((label.to_owned(), text));
        self
    }

    /// Fail if `needle` appears anywhere, naming the surface and quoting
    /// the surrounding line so the failure is actionable rather than a
    /// bare "a secret leaked".
    fn assert_absent(&self, description: &str, needle: &str) {
        assert!(
            !needle.is_empty(),
            "the {description} canary is empty, so this assertion would prove nothing"
        );
        for (source, text) in &self.sources {
            if let Some(offset) = text.find(needle) {
                let line = text[..offset].rfind('\n').map_or(0, |index| index + 1);
                let end = text[offset..]
                    .find('\n')
                    .map_or(text.len(), |index| offset + index);
                panic!(
                    "the {description} appeared in {source}:\n  {}",
                    &text[line..end]
                );
            }
        }
    }

    /// Fail if any substring matching a whole *class* of secret appears —
    /// the leaks no canary can anticipate, because the deployment made the
    /// value up itself.
    fn assert_absent_shape(&self, description: &str, needles: &[&str]) {
        for (source, text) in &self.sources {
            for needle in needles {
                assert!(
                    !text.contains(needle),
                    "a {description} appeared in {source} (matched {needle:?})"
                );
            }
        }
    }
}

/// How long a step re-asks a replica that answered "the authority is
/// unavailable".
const AUTHORITY_RETRY_BUDGET: Duration = Duration::from_secs(20);

/// Issue a request, re-issuing it while the replica answers `503`.
///
/// A `503` from the revision gate is the replica saying it could not
/// consult the authority — "cannot judge", which is not an answer to any
/// question this suite asks of a *setup* step. Re-asking within a bound is
/// the honest reading, and the bound keeps a genuinely unreachable
/// authority a failure rather than a hang. On an unloaded machine it never
/// fires; on one shared with other builds it is the difference between a
/// suite about secrets and a suite about contention.
///
/// The refusal probes go through it too, and for the same reason: a
/// replica that answered `503` to a nonsense credential never reached the
/// point of judging the credential, so "was it refused?" is still
/// unanswered. The one request that does NOT is the connection-secret
/// create, whose `503` is the deployment's real answer rather than a
/// failure to give one.
async fn send_settled(
    build: impl Fn() -> harness::PinnedRequest,
) -> (u16, reqwest::header::HeaderMap, serde_json::Value) {
    let deadline = std::time::Instant::now() + AUTHORITY_RETRY_BUDGET;
    loop {
        let outcome = build().send_with_headers().await;
        if outcome.0 != 503 || std::time::Instant::now() >= deadline {
            return outcome;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
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

/// A `name=value` pair from anywhere in a URL-shaped string, including the
/// part after a `#`.
///
/// The admin console's completion redirect puts the session in the
/// fragment so it never reaches a server log or a `Referer`; a URL parser
/// treats everything after `#` as one opaque string, so this reads it as
/// text rather than pretending it is a query.
fn fragment_param(url: &str, name: &str) -> String {
    let marker = format!("{name}=");
    let start = url
        .find(&marker)
        .unwrap_or_else(|| panic!("{url} carried no {name} parameter"))
        + marker.len();
    let rest = &url[start..];
    let end = rest.find(['&', '#']).unwrap_or(rest.len());
    rest[..end].to_owned()
}

/// One query parameter of an absolute URL.
fn query_value(absolute: &str, name: &str) -> String {
    url::Url::parse(absolute)
        .unwrap_or_else(|error| panic!("{absolute} should be an absolute URL: {error}"))
        .query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .unwrap_or_else(|| panic!("{absolute} carried no {name} parameter"))
}

/// Nothing the deployment is given, and nothing it mints, appears in any
/// surface an operator can read.
///
/// The flows exercised are the ones that handle secret material: an OIDC
/// login start and callback across two replicas (state, nonce, PKCE, and
/// the session the callback returns), a service token minted and
/// presented, a connection secret sealed, a JWT accepted, and a proxied
/// request whose query, headers and body are entirely canaries. Refusals
/// are driven too, because an error path is where a value most often gets
/// echoed back "for debugging".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_planted_or_minted_secret_reaches_the_logs_metrics_or_audit_files() {
    let database_password = canary("dsn-password");
    let policy_role_canary = canary("policy-role");
    let tool_description_canary = canary("tool-description");
    let Some(mut cluster) = Cluster::start(ClusterOptions {
        auth: AuthShape::Oidc,
        // The legacy catch-all upstream, because the tools document below
        // carries a legacy HTTP tool and the executor refuses to start
        // without `UPSTREAM_URL`. Nothing here needs to know which replica
        // proxied a request, so the per-route header the other shape
        // exists for would buy nothing.
        proxy: ProxyShape::LegacyUpstream,
        seed_policy: Some(admin_policy_with_canary_role(&policy_role_canary)),
        seed_tools: Some(tools_with_canary_description(&tool_description_canary)),
        // The DSN the replicas read carries a real password. Without one
        // there is nothing for this test to prove the gateway keeps out of
        // its logs; the local server authenticates by trust, so the value
        // is never exchanged and exists only to be a canary.
        database_password: Some(database_password.clone()),
        ..ClusterOptions::default()
    })
    .await
    else {
        return skipped();
    };
    cluster.wait_until_all_ready().await;
    let runtime_dsn = {
        let (_, files_root) = cluster.temporary_paths();
        std::fs::read_to_string(files_root.join("database-url"))
            .expect("the harness DSN file should be readable")
            .trim()
            .to_owned()
    };

    // ---- secrets the deployment mints for itself -------------------

    // A real login: the state, nonce and PKCE challenge below are the
    // gateway's own, and the cookie is what it hands back.
    let (status, headers, _) = cluster.get("a", ADMIN_LOGIN_PATH).send_with_headers().await;
    assert_eq!(status, 302, "the login endpoint should redirect to the IdP");
    let authorization_url = location(&headers, "the login redirect");
    let state = query_value(&authorization_url, "state");
    let nonce = query_value(&authorization_url, "nonce");
    let code_challenge = query_value(&authorization_url, "code_challenge");

    let issuer_response = harness::http_client()
        .get(&authorization_url)
        .send()
        .await
        .expect("the fake issuer should answer the authorization request");
    let callback = path_and_query(&location(
        issuer_response.headers(),
        "the issuer's redirect",
    ));
    // Completed on the other replica, so the sealed verifier and nonce
    // cross the shared store — the crossing this suite most wants to watch.
    let (status, headers, _) = cluster.get("b", &callback).send_with_headers().await;
    assert_eq!(status, 302, "the callback should complete the login");
    let completion = location(&headers, "the callback redirect");
    // The completion redirect carries the session in the URL *fragment*
    // (`/admin/#/auth/complete?token=...`), which a URL parser reports as
    // an opaque fragment rather than a query — so it is read as text.
    let session = fragment_param(&completion, "token");
    let cookies: String = headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");

    // A second login, deliberately left in flight, so the shared
    // pending-login store has a row to inspect below: its state must be
    // unreadable from the row (a digest) and its nonce unreadable too
    // (sealed).
    let (status, headers, _) = cluster.get("b", ADMIN_LOGIN_PATH).send_with_headers().await;
    assert_eq!(status, 302, "the second login should redirect to the IdP");
    let pending_url = location(&headers, "the second login redirect");
    let pending_state = query_value(&pending_url, "state");
    let pending_nonce = query_value(&pending_url, "nonce");

    // A JWT and its jti, minted for this deployment and presented to it.
    let jti = canary("jti");
    let admin = cluster.oidc.mint_role_token(
        oidc::PRIMARY_KID,
        "leak-probe@ha.test",
        &jti,
        &[ADMIN_ROLE],
        3_600,
    );
    let (status, _, body) = send_settled(|| cluster.get("a", STATUS_ROUTE).bearer(&admin)).await;
    assert_eq!(status, 200, "the admin token should be accepted: {body}");

    // A service token's one-time plaintext, created on one replica and
    // presented to the other.
    let (status, _, body) = send_settled(|| {
        cluster
            .post("a", TOKENS_ROUTE)
            .bearer(&admin)
            .json(&json!({ "scopes": [ADMIN_ROLE] }))
    })
    .await;
    assert_eq!(
        status, 201,
        "creating a service token should succeed: {body}"
    );
    let service_token = body["plaintext_token"]
        .as_str()
        .unwrap_or_else(|| panic!("a created token carries a plaintext: {body}"))
        .to_owned();
    let (status, _, body) =
        send_settled(|| cluster.get("b", STATUS_ROUTE).bearer(&service_token)).await;
    assert_eq!(
        status, 200,
        "the service token should authenticate on the other replica: {body}"
    );
    // What the deployment keeps instead of that plaintext. A digest is
    // only a protection while it stays in the table it was written to: a
    // hash in a log line is an offline attack, not an audit record.
    let stored_token_digest = cluster
        .database
        .query_one("SELECT token_hash FROM greengateway.service_tokens LIMIT 1")
        .await
        .get::<_, String>(0);

    // ---- secrets the deployment is handed ---------------------------

    // A connection secret's plaintext: sealed at rest, and it must never
    // be echoed by the API that took it or logged by the replica that
    // sealed it.
    let connection_secret = canary("connection-secret");
    // Storing one is a conditional write against the secret COLLECTION's
    // ETag, which the list endpoint publishes in its own header beside the
    // ordinary `ETag`.
    let (status, headers, body) =
        send_settled(|| cluster.get("a", CONNECTION_SECRETS_ROUTE).bearer(&admin)).await;
    assert_eq!(
        status, 200,
        "the connection-secret list should read: {body}"
    );
    let collection = headers
        .get(CONNECTION_SECRET_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| {
            panic!("the connection-secret list should publish its collection ETag: {headers:?}")
        })
        .to_owned();
    let (status, body) = cluster
        .post("a", CONNECTION_SECRETS_ROUTE)
        .bearer(&admin)
        .if_match(&collection)
        .json(&json!({
            "label": "ha-release-gate-probe",
            "purpose": "static_bearer",
            "value": connection_secret,
        }))
        .send()
        .await;
    // Cluster mode has no encrypted *local* secret store — migration 0006
    // deliberately omits the table and `CONNECTION_LOCAL_SECRET_KEYRING`
    // is rejected outright in postgres mode, because a cluster binds
    // credentials through an external provider instead. So the outcome
    // here is a refusal, not a write, and the claim narrows to the one
    // that still matters: a handler handed a secret it will not store
    // must not repeat it back, and must not log it on the way to saying
    // no. Both statuses are accepted so this stays true if the resource
    // ever gains a cluster-mode backend.
    assert!(
        matches!(status, 200 | 201 | 503),
        "storing a connection secret should succeed or be refused as unconfigured, and \
         said {status}: {body}"
    );
    assert!(
        !body.to_string().contains(&connection_secret),
        "the create response echoed the secret it was given: {body}"
    );

    // A proxied request whose query, header and body are canaries. The
    // path is not one: an observation record carries the path by design,
    // and a canary there would be asserting against the feature.
    let query_canary = canary("query");
    let header_canary = canary("header");
    let body_canary = canary("body");
    let (status, _, body) = send_settled(|| {
        cluster
            .post("b", &format!("{PROXIED_PATH}?opaque={query_canary}"))
            .bearer(&admin)
            .header("x-ha-probe", &header_canary)
            .json(&json!({ "field": body_canary }))
    })
    .await;
    assert_eq!(
        status, 200,
        "the proxied probe should reach the upstream: {body}"
    );

    // Refusals, because an error path is where a value gets echoed. Each
    // of these must be answered without repeating what it was given.
    let rejected_credential = canary("rejected-bearer");
    let (status, _, _) =
        send_settled(|| cluster.get("a", STATUS_ROUTE).bearer(&rejected_credential)).await;
    assert_eq!(status, 401, "a nonsense credential should be refused");
    let (status, _, _) = send_settled(|| {
        cluster
            .post("b", TOKENS_ROUTE)
            .bearer(&admin)
            .header("x-ha-probe", &header_canary)
            .json(&json!({ "scopes": [ADMIN_ROLE], "unknown_field": body_canary.clone() }))
    })
    .await;
    assert!(
        (400..500).contains(&status),
        "an unknown field should be refused, and answered {status}"
    );

    // ---- the search -------------------------------------------------

    let haystack = Haystack::collect(&cluster).await;

    haystack.assert_absent("database password from the DSN", &database_password);
    haystack.assert_absent("OIDC client secret", oidc::FAKE_CLIENT_SECRET);
    haystack.assert_absent("login state", &state);
    haystack.assert_absent("login nonce", &nonce);
    haystack.assert_absent("PKCE code challenge", &code_challenge);
    haystack.assert_absent("session token the callback returned", &session);
    haystack.assert_absent("service token plaintext", &service_token);
    haystack.assert_absent("connection secret plaintext", &connection_secret);
    haystack.assert_absent("bearer JWT", &admin);
    haystack.assert_absent("JWT jti", &jti);
    haystack.assert_absent("request query value", &query_canary);
    haystack.assert_absent("request header value", &header_canary);
    haystack.assert_absent("request body value", &body_canary);
    haystack.assert_absent("refused bearer credential", &rejected_credential);
    // The cookie needle, asserted rather than guarded.
    //
    // The completion redirect sets no cookie at all today: the session
    // travels in the URL fragment, and the only `Set-Cookie` this binary
    // emits comes from the CSRF middleware (which the harness disables) and
    // the tools playground (which this suite never reaches). A `if
    // !cookies.is_empty()` around the needle would therefore be dead in
    // every run — a search that reports success without having searched.
    // So the shape of the response is what is asserted: no cookie here. A
    // change that starts setting one fails HERE, with a message saying to
    // add the value to the needles below, instead of silently turning this
    // category off.
    assert!(
        cookies.is_empty(),
        "the admin callback set a cookie ({cookies}); the session used to travel only in the \
         redirect fragment. Add the cookie to the needles below now that there is one to leak."
    );

    // The rate-limit keyring's material, which never leaves the process
    // but whose digests are written to a shared table: neither the key nor
    // its hex may appear in anything an operator reads.
    let (secrets_root, _) = cluster.temporary_paths();
    for name in ["rate-limit-key", "admin-login-key"] {
        let material = std::fs::read(secrets_root.join(name))
            .unwrap_or_else(|error| panic!("the harness {name} should be readable: {error}"));
        haystack.assert_absent(
            &format!("{name} material, hex-encoded"),
            &hex::encode(&material),
        );
    }

    haystack.assert_absent("runtime DSN", &runtime_dsn);
    haystack.assert_absent("service token's stored digest", &stored_token_digest);
    haystack.assert_absent("pending login's state", &pending_state);
    haystack.assert_absent("pending login's nonce", &pending_nonce);
    // Control-plane material: the policy API and the capability inventory
    // publish these, and nothing an operator reads without asking may.
    haystack.assert_absent("policy document's canary role", &policy_role_canary);
    haystack.assert_absent(
        "tools document's canary description",
        &tool_description_canary,
    );

    // And the shapes no canary can anticipate, because the deployment
    // invents the values: a DSN of any kind, the compact-JWS prefix every
    // token this deployment accepts begins with, a cookie header, and a
    // SQL statement — which would carry its bound parameters with it.
    haystack.assert_absent_shape(
        "database connection string",
        &["postgres://", "postgresql://"],
    );
    haystack.assert_absent_shape("compact JWS", &["eyJ"]);
    haystack.assert_absent_shape("cookie header", &["set-cookie", "Set-Cookie"]);
    haystack.assert_absent_shape(
        "SQL statement",
        &[
            "INSERT INTO greengateway.",
            "UPDATE greengateway.",
            "DELETE FROM greengateway.",
            "FROM greengateway.",
        ],
    );

    // ---- the API surfaces --------------------------------------------
    //
    // Different rules from the process output: these endpoints exist to
    // return the deployment's own state, so the control-plane canaries
    // are *expected* here (and asserted, so they cannot be vacuous) while
    // every credential is not.
    let api = Haystack::collect_api(&cluster, &admin).await;
    api.assert_present("policy document's canary role", &policy_role_canary);
    api.assert_present(
        "tools document's canary description",
        &tool_description_canary,
    );
    api.assert_absent("database password from the DSN", &database_password);
    api.assert_absent("runtime DSN", &runtime_dsn);
    api.assert_absent("OIDC client secret", oidc::FAKE_CLIENT_SECRET);
    api.assert_absent("login state", &state);
    api.assert_absent("login nonce", &nonce);
    api.assert_absent("PKCE code challenge", &code_challenge);
    api.assert_absent("session token the callback returned", &session);
    api.assert_absent("service token plaintext", &service_token);
    api.assert_absent("service token's stored digest", &stored_token_digest);
    api.assert_absent("connection secret plaintext", &connection_secret);
    api.assert_absent("bearer JWT", &admin);
    api.assert_absent("JWT jti", &jti);
    api.assert_absent("request query value", &query_canary);
    api.assert_absent("request header value", &header_canary);
    api.assert_absent("request body value", &body_canary);
    api.assert_absent("pending login's state", &pending_state);
    api.assert_absent("pending login's nonce", &pending_nonce);

    // ---- the rows the shared stores keep -----------------------------
    //
    // The limiter is keyed by an HMAC of the caller, and the pending
    // login by a digest of its state with its verifier and nonce sealed.
    // Both claims are about what a reader of the table — or of a backup —
    // would learn, so both are asserted against the bytes actually
    // stored.
    let rows = Haystack::collect_stored_rows(&cluster).await;
    rows.assert_absent(
        "caller identity the limiter is keyed by",
        "leak-probe@ha.test",
    );
    rows.assert_absent("caller's loopback address", "127.0.0.1");
    rows.assert_absent("pending login's state", &pending_state);
    rows.assert_absent("pending login's nonce", &pending_nonce);
    rows.assert_absent("bearer JWT", &admin);
    rows.assert_absent("service token plaintext", &service_token);
    rows.assert_absent("connection secret plaintext", &connection_secret);

    // Nothing crashed on the way through, which is what makes the "panic
    // output" half of the claim meaningful: a panic would have been in
    // the captured output searched above.
    for replica in &mut cluster.replicas {
        assert!(
            replica.is_running(),
            "replica {} exited during the leak workload",
            replica.name
        );
    }
}

/// A deployment whose database is taken away logs its failure without
/// printing the connection string it failed to use.
///
/// This is where connection strings actually leak. On the success path
/// nothing has any reason to render a DSN; on the failure path a
/// driver's error message, a `Debug` impl, or a well-meaning
/// `tracing::error!(dsn = %dsn)` will do it — and the failure path is
/// exactly the moment an operator copies the logs into a ticket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_broken_database_is_reported_without_printing_the_dsn() {
    let database_password = canary("fault-dsn-password");
    let Some(mut cluster) = Cluster::start(ClusterOptions {
        seed_policy: Some(admin_policy()),
        database_password: Some(database_password.clone()),
        // A short acquire timeout, so the replicas reach and log their
        // failure inside the test's patience rather than waiting on the
        // production default.
        shared_env: vec![("DATABASE_ACQUIRE_TIMEOUT_MS".to_owned(), "2000".to_owned())],
        ..ClusterOptions::default()
    })
    .await
    else {
        return skipped();
    };
    cluster.wait_until_all_ready().await;

    // Take the database away: the grant first, so reconnection is refused,
    // then the established sessions, so the pools have to reconnect.
    cluster.database.revoke_connect().await;
    let terminated = cluster.database.terminate_runtime_backends().await;
    assert!(
        terminated > 0,
        "the replicas should have held backends to terminate"
    );

    // Drive traffic that has to reach the authority, so the failure is
    // exercised on the request path and not only in a background task.
    // The probe is the proxied path rather than an admin read: this
    // cluster does not authenticate, so an admin route answers `401`
    // whether or not its database is reachable, and would prove nothing.
    let deadline = std::time::Instant::now() + FAULT_BUDGET;
    let mut refused = 0_usize;
    while std::time::Instant::now() < deadline && refused < 4 {
        for replica in ["a", "b"] {
            let (status, _) = cluster.get(replica, PROXIED_PATH).send().await;
            if status >= 500 {
                refused += 1;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        refused > 0,
        "with its database unreachable the deployment should be refusing, not serving"
    );

    // A one-shot command fails the same way, and its diagnostics are the
    // most operator-facing text the binary produces.
    let output = cluster.run_command(&["migrate", "check"]);
    let command_output = format!(
        "--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.status.success(),
        "migrate check should fail against an unreachable database, and said:\n{command_output}"
    );

    let haystack = Haystack::collect_process_output(&cluster)
        .plus("the `migrate check` command's output", command_output);
    haystack.assert_absent("database password from the DSN", &database_password);
    haystack.assert_absent_shape(
        "database connection string",
        &["postgres://", "postgresql://"],
    );

    // Recovery, so the fault is a fault and not a teardown: the grant back,
    // and both replicas ready again on their own.
    cluster.database.restore_connect().await;
    cluster.wait_until_all_ready().await;
    let (status, body) = cluster.get("a", PROXIED_PATH).send().await;
    assert_eq!(
        status, 200,
        "the deployment should serve again once its database returns: {body}"
    );
}
