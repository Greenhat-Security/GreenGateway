//! The fake OIDC issuer and its JWKS endpoint.
//!
//! Everything the two-replica security suite needs from an identity
//! provider, and nothing else:
//!
//! * a discovery document and a JWKS endpoint whose key set can be added
//!   to and removed from at runtime (the "JWKS key removal stops
//!   acceptance on every replica" row);
//! * an authorization endpoint that mints a one-time code and redirects
//!   back, so a login can *start* on replica A;
//! * a token endpoint that records every exchange and refuses a code it
//!   has already spent, so "simultaneous callbacks yield one exchange and
//!   replays fail" is decided here rather than inferred;
//! * a mint function for tokens the tests hand to the gateway directly.
//!
//! Keys are Ed25519 (JWKS `kty: OKP`), generated per run. Nothing in this
//! file is a checked-in credential: every secret-looking constant is a
//! `FAKE_`-prefixed placeholder, and the signing keys exist only in memory
//! for the life of the test process.

use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use axum::{
    extract::{Form, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::Engine as _;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{json, Value};

/// The confidential-client placeholder these suites configure. Not a
/// credential: it authenticates nothing outside this test process, and the
/// prefix is what keeps a history scanner from having to decide.
pub const FAKE_CLIENT_SECRET: &str = "FAKE-ha-harness-client-secret";
/// The public client identifier the gateway is configured with.
pub const CLIENT_ID: &str = "ha-harness";
/// The audience minted tokens carry.
pub const AUDIENCE: &str = "ha-harness";
/// The kid of the key the issuer signs with unless told otherwise.
pub const PRIMARY_KID: &str = "ha-primary";
/// The configured name of the provider pointed at the first issuer.
pub const PRIMARY_PROVIDER: &str = "primary";
/// The configured name of the provider pointed at the second issuer, when
/// a suite asked for one.
pub const SECONDARY_PROVIDER: &str = "secondary";

struct TestKey {
    kid: String,
    encoding: EncodingKey,
    jwk: Value,
}

fn generate_key(kid: &str) -> TestKey {
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .expect("the harness Ed25519 key should generate");
    let pkcs8 = pair.serialize_der();
    let spki = pair.public_key_der();
    // An Ed25519 SubjectPublicKeyInfo is a 12-byte prefix over the raw
    // 32-byte key; the JWK carries the raw key as base64url `x`.
    assert!(
        spki.len() >= 32,
        "an Ed25519 SPKI is longer than its raw key"
    );
    let raw = &spki[spki.len() - 32..];
    TestKey {
        kid: kid.to_owned(),
        encoding: EncodingKey::from_ed_der(&pkcs8),
        jwk: json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "alg": "EdDSA",
            "kid": kid,
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw),
        }),
    }
}

#[derive(Clone, Debug)]
pub struct AuthorizeRecord {
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub redirect_uri: Option<String>,
    pub code: String,
}

#[derive(Clone, Debug)]
pub struct ExchangeRecord {
    pub code: String,
    pub accepted: bool,
    pub parameters: BTreeMap<String, String>,
}

struct CodeRecord {
    nonce: Option<String>,
    subject: String,
    spent: bool,
}

struct IssuerState {
    issuer: Mutex<String>,
    keys: Mutex<Vec<TestKey>>,
    codes: Mutex<HashMap<String, CodeRecord>>,
    authorizations: Mutex<Vec<AuthorizeRecord>>,
    exchanges: Mutex<Vec<ExchangeRecord>>,
    jwks_fetches: AtomicU64,
    unknown_kid_fetches: AtomicU64,
}

/// A running fake issuer. Dropping it stops the server.
pub struct FakeOidcIssuer {
    pub addr: SocketAddr,
    /// The `iss` value and the base of every endpoint.
    pub issuer: String,
    pub jwks_url: String,
    pub authorize_url: String,
    pub token_url: String,
    state: Arc<IssuerState>,
    server: super::ServerHandle,
}

impl FakeOidcIssuer {
    pub async fn start() -> Self {
        let state = Arc::new(IssuerState {
            issuer: Mutex::new(String::new()),
            keys: Mutex::new(vec![generate_key(PRIMARY_KID)]),
            codes: Mutex::new(HashMap::new()),
            authorizations: Mutex::new(Vec::new()),
            exchanges: Mutex::new(Vec::new()),
            jwks_fetches: AtomicU64::new(0),
            unknown_kid_fetches: AtomicU64::new(0),
        });
        let router = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .route("/userinfo", get(userinfo))
            .with_state(Arc::clone(&state));
        let (addr, server) = super::serve_on_ephemeral_port(router).await;
        let issuer = format!("http://{addr}");
        *lock(&state.issuer) = issuer.clone();
        Self {
            addr,
            jwks_url: format!("{issuer}/jwks"),
            authorize_url: format!("{issuer}/authorize"),
            token_url: format!("{issuer}/token"),
            issuer,
            state,
            server,
        }
    }

    /// Add a signing key to the published set.
    pub fn add_key(&self, kid: &str) {
        lock(&self.state.keys).push(generate_key(kid));
    }

    /// Remove a signing key from the published set. Tokens already minted
    /// under it stay syntactically valid, which is exactly the case the
    /// key-removal row is about: acceptance must stop because the key is
    /// gone from the JWKS, not because the token changed.
    pub fn remove_key(&self, kid: &str) {
        lock(&self.state.keys).retain(|key| key.kid != kid);
    }

    pub fn key_ids(&self) -> Vec<String> {
        lock(&self.state.keys)
            .iter()
            .map(|key| key.kid.clone())
            .collect()
    }

    /// Sign `claims` with `kid`. Panics if the key is not in the set —
    /// a test that meant to sign with a removed key should add it back,
    /// keep its own handle, or say so.
    pub fn mint(&self, kid: &str, claims: &Value) -> String {
        let keys = lock(&self.state.keys);
        let key = keys
            .iter()
            .find(|key| key.kid == kid)
            .unwrap_or_else(|| panic!("the harness issuer has no key {kid}"));
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(key.kid.clone());
        encode(&header, claims, &key.encoding).expect("the harness token should sign")
    }

    /// A conventional access token: `iss`/`aud` matching this issuer, a
    /// caller-chosen `sub` and `jti`, and an expiry `ttl_seconds` ahead.
    ///
    /// The expiry is stamped from the host clock because the gateway
    /// validates `exp` against *its* clock and neither can be steered from
    /// here; nothing in the harness advances a clock, and every assertion
    /// about elapsed time goes through database time instead.
    pub fn mint_access_token(&self, subject: &str, jti: &str, ttl_seconds: u64) -> String {
        self.mint_role_token(PRIMARY_KID, subject, jti, &[], ttl_seconds)
    }

    /// An access token carrying `roles`, signed with `kid`.
    ///
    /// The roles claim is what the policy's role entries activate on, so
    /// every admin call in these suites carries one; the `kid` is a
    /// parameter because the key-removal row mints under a key it is about
    /// to withdraw.
    pub fn mint_role_token(
        &self,
        kid: &str,
        subject: &str,
        jti: &str,
        roles: &[&str],
        ttl_seconds: u64,
    ) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the host clock should follow the Unix epoch")
            .as_secs();
        let mut claims = json!({
            "iss": self.issuer,
            "aud": AUDIENCE,
            "sub": subject,
            "jti": jti,
            "iat": now,
            "exp": now + ttl_seconds,
        });
        if !roles.is_empty() {
            claims["roles"] = json!(roles);
        }
        self.mint(kid, &claims)
    }

    pub fn authorizations(&self) -> Vec<AuthorizeRecord> {
        lock(&self.state.authorizations).clone()
    }

    pub fn exchanges(&self) -> Vec<ExchangeRecord> {
        lock(&self.state.exchanges).clone()
    }

    /// How many times the JWKS endpoint has been fetched — the observable
    /// behind "without an unknown-kid request".
    pub fn jwks_fetch_count(&self) -> u64 {
        self.state.jwks_fetches.load(Ordering::SeqCst)
    }

    /// How many JWKS fetches carried a `kid` hint the set does not hold.
    pub fn unknown_kid_fetch_count(&self) -> u64 {
        self.state.unknown_kid_fetches.load(Ordering::SeqCst)
    }

    pub fn shutdown(&mut self) {
        self.server.shutdown();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

async fn discovery(State(state): State<Arc<IssuerState>>) -> Json<Value> {
    let issuer = lock(&state.issuer).clone();
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "code_challenge_methods_supported": ["S256"],
    }))
}

async fn jwks(
    State(state): State<Arc<IssuerState>>,
    Query(parameters): Query<HashMap<String, String>>,
) -> Json<Value> {
    state.jwks_fetches.fetch_add(1, Ordering::SeqCst);
    let keys = lock(&state.keys);
    if let Some(kid) = parameters.get("kid") {
        if !keys.iter().any(|key| &key.kid == kid) {
            state.unknown_kid_fetches.fetch_add(1, Ordering::SeqCst);
        }
    }
    Json(json!({ "keys": keys.iter().map(|key| key.jwk.clone()).collect::<Vec<_>>() }))
}

async fn authorize(
    State(state): State<Arc<IssuerState>>,
    Query(parameters): Query<HashMap<String, String>>,
) -> Response {
    let code = format!("ha-code-{}", uuid::Uuid::new_v4().simple());
    let subject = parameters
        .get("login_hint")
        .cloned()
        .unwrap_or_else(|| "ha-subject".to_owned());
    lock(&state.codes).insert(
        code.clone(),
        CodeRecord {
            nonce: parameters.get("nonce").cloned(),
            subject,
            spent: false,
        },
    );
    lock(&state.authorizations).push(AuthorizeRecord {
        state: parameters.get("state").cloned(),
        nonce: parameters.get("nonce").cloned(),
        redirect_uri: parameters.get("redirect_uri").cloned(),
        code: code.clone(),
    });
    let Some(redirect_uri) = parameters.get("redirect_uri") else {
        return (StatusCode::BAD_REQUEST, "redirect_uri is required").into_response();
    };
    let separator = if redirect_uri.contains('?') { '&' } else { '?' };
    let mut location = format!("{redirect_uri}{separator}code={code}");
    if let Some(value) = parameters.get("state") {
        location.push_str(&format!("&state={value}"));
    }
    (StatusCode::FOUND, [(header::LOCATION, location)]).into_response()
}

async fn token(
    State(state): State<Arc<IssuerState>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let parameters = form
        .iter()
        .map(|(name, value)| {
            // The client secret is a fake, but recording it would still put
            // a secret-shaped string in a test's failure output. Record its
            // presence.
            let redacted = if name == "client_secret" {
                "<present>".to_owned()
            } else {
                value.clone()
            };
            (name.clone(), redacted)
        })
        .collect::<BTreeMap<_, _>>();
    let code = form.get("code").cloned().unwrap_or_default();

    let issuer = lock(&state.issuer).clone();
    let outcome = {
        let mut codes = lock(&state.codes);
        match codes.get_mut(&code) {
            Some(record) if !record.spent => {
                record.spent = true;
                Some((record.subject.clone(), record.nonce.clone()))
            }
            _ => None,
        }
    };

    let Some((subject, nonce)) = outcome else {
        lock(&state.exchanges).push(ExchangeRecord {
            code,
            accepted: false,
            parameters,
        });
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid_grant" })),
        )
            .into_response();
    };
    lock(&state.exchanges).push(ExchangeRecord {
        code: code.clone(),
        accepted: true,
        parameters,
    });

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the host clock should follow the Unix epoch")
        .as_secs();
    let mut claims = json!({
        "iss": issuer,
        "aud": AUDIENCE,
        "sub": subject,
        "jti": format!("ha-jti-{}", uuid::Uuid::new_v4().simple()),
        "iat": now,
        "exp": now + 300,
    });
    if let Some(nonce) = nonce {
        claims["nonce"] = Value::String(nonce);
    }
    let signed = {
        let keys = lock(&state.keys);
        let Some(key) = keys.first() else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "no_signing_key" })),
            )
                .into_response();
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(key.kid.clone());
        encode(&header, &claims, &key.encoding).expect("the harness token should sign")
    };

    Json(json!({
        "access_token": signed,
        "id_token": signed,
        "token_type": "Bearer",
        "expires_in": 300,
    }))
    .into_response()
}

async fn userinfo() -> Json<Value> {
    Json(json!({ "sub": "ha-subject" }))
}
