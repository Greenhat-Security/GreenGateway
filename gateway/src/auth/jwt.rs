use std::{
    collections::HashMap,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use base64::Engine as _;
use http::Method;

use crate::lifecycle::GatewayLifecycle;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::{Map, Value};
use tokio::{
    sync::{Mutex, RwLock},
    time::timeout,
};

use crate::{
    config::{AuthProviderConfig, Config},
    egress::EgressClient,
};

use super::{
    claims::{extract_roles, extract_string_claim},
    oidc,
    principal::provider_issuer,
    AuthError, AuthMethod, Principal, SessionCredential, SessionValidator,
};

const INVALID_TOKEN: &str = "invalid or expired token";
/// The floor between two *demand-driven* JWKS fetches. Unknown kids are
/// attacker-controlled, so a kid miss cannot be allowed to turn into an IdP
/// request each time; this is the per-validator, per-replica cap on that
/// traffic. The scheduled background refresh is not subject to it -- it is
/// operator-paced -- but it stamps the same clock, so a storm of misses
/// right after a scheduled fetch is still throttled.
const MIN_JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// The cap on the operator's maximum key age: a day. Past that a withdrawn
/// key would be honoured for longer than any rotation window an IdP
/// documents.
pub const MAX_JWKS_KEY_AGE_SECS_LIMIT: u64 = 86_400;
/// The floor on the operator's maximum key age: the demand-refresh
/// throttle. Below it a key set could go stale before a demand refresh was
/// allowed again, and every request would fail closed against a reachable
/// issuer until the throttle window passed.
pub const MIN_JWKS_KEY_AGE_SECS_LIMIT: u64 = MIN_JWKS_REFRESH_INTERVAL.as_secs();
/// The `exp` leeway the validator grants (jsonwebtoken's default, made
/// explicit): a token is accepted until `exp + leeway`, so a revocation
/// keyed on the token's `exp` must stay effective at least that long past
/// it. The revocation store retains rows for exactly this leeway.
pub const JWT_EXP_LEEWAY_SECS: u64 = 60;

/// JWT bearer-token validator configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JwtAuthConfig {
    /// Effective JWKS endpoint containing supported JWT public keys.
    pub jwks_url: String,
    /// Optional expected `iss` claim.
    pub issuer: Option<String>,
    /// Optional expected `aud` claim.
    pub audience: Option<String>,
    /// Timeout for JWKS HTTP fetches.
    pub http_timeout: Duration,
    /// How long a fetched JWKS key set stays trusted.
    ///
    /// Without a bound, a cached `kid` is trusted for the life of the
    /// process: on-demand refresh happens only on a kid *miss*, so a key the
    /// issuer has withdrawn would never be evicted as long as callers keep
    /// presenting it. The key set carries the instant it was fetched, is
    /// refreshed in the background at half this age, and past this age is
    /// not trusted at all: a request then refreshes first or fails closed.
    /// Operator-configured (`JWT_JWKS_MAX_KEY_AGE_SECS` / a provider's
    /// `jwks_max_key_age_secs`), bounded above by
    /// [`MAX_JWKS_KEY_AGE_SECS_LIMIT`], and part of the static configuration
    /// fingerprint replicas must agree on.
    pub jwks_max_key_age: Duration,
    /// Reject tokens without a non-empty `jti` claim.
    pub require_jti: bool,
    /// Literal claim key or dotted nested claim path used to extract roles.
    pub roles_claim: String,
    /// Optional delimiter for splitting string-valued role claims.
    pub roles_claim_delimiter: Option<String>,
    /// Optional literal claim key or dotted nested claim path used to extract an organization ID.
    pub org_claim: Option<String>,
}

impl JwtAuthConfig {
    #[allow(dead_code)] // Legacy single-provider constructor retained for compatibility tests and callers.
    pub fn from_config(config: &Config) -> Option<Self> {
        Some(Self {
            jwks_url: config.jwt_jwks_url.clone()?,
            issuer: normalize_auth_config_issuer(config.jwt_issuer.as_deref()),
            audience: config.jwt_audience.clone(),
            http_timeout: Duration::from_millis(config.jwt_jwks_timeout_ms),
            jwks_max_key_age: Duration::from_secs(config.jwt_jwks_max_key_age_secs),
            require_jti: config.jwt_require_jti,
            roles_claim: config.roles_claim.clone(),
            roles_claim_delimiter: None,
            org_claim: None,
        })
    }

    pub fn from_provider_config(config: &AuthProviderConfig, jwks_url: String) -> Self {
        Self {
            jwks_url,
            issuer: normalize_auth_config_issuer(config.issuer.as_deref()),
            audience: config.audience.clone(),
            http_timeout: Duration::from_millis(config.jwks_timeout_ms),
            jwks_max_key_age: Duration::from_secs(config.jwks_max_key_age_secs),
            require_jti: config.require_jti,
            roles_claim: config.roles_claim.clone(),
            roles_claim_delimiter: config.roles_claim_delimiter.clone(),
            org_claim: config.org_claim.clone(),
        }
    }
}

/// Revocation lookup abstraction for JWT `jti` values.
///
/// A durable denylist can be plugged in later without changing the validator.
#[allow(dead_code)] // Real revocation stores are added after the JWT validator component lands.
#[async_trait::async_trait]
pub trait RevocationStore: Send + Sync {
    async fn is_revoked(&self, jti: &str) -> Result<bool, AuthError>;
}

/// Revocation store that never revokes a token.
#[allow(dead_code)] // Used as the default until a durable revocation store lands.
#[derive(Debug)]
pub struct NoopRevocationStore;

#[async_trait::async_trait]
impl RevocationStore for NoopRevocationStore {
    async fn is_revoked(&self, _jti: &str) -> Result<bool, AuthError> {
        Ok(false)
    }
}

/// JWT bearer-token validator backed by a kid-indexed JWKS key cache.
pub struct JwtValidator {
    cfg: JwtAuthConfig,
    principal_issuer: Option<String>,
    egress_client: Arc<EgressClient>,
    keys: Arc<RwLock<HashMap<String, CachedDecodingKey>>>,
    /// When the current key set was last fetched *successfully*. Distinct from
    /// `last_jwks_refresh`, which records attempts (including failures) to rate
    /// limit kid-miss traffic.
    keys_fetched_at: Arc<RwLock<Option<Instant>>>,
    last_jwks_refresh: Arc<Mutex<Option<Instant>>>,
    revocation: Arc<dyn RevocationStore>,
}

impl fmt::Debug for JwtValidator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JwtValidator")
            .field("jwks_url", &self.cfg.jwks_url)
            .field("issuer", &self.cfg.issuer)
            .field("audience", &self.cfg.audience)
            .field("require_jti", &self.cfg.require_jti)
            .field("roles_claim", &self.cfg.roles_claim)
            .field("roles_claim_delimiter", &self.cfg.roles_claim_delimiter)
            .field("org_claim", &self.cfg.org_claim)
            .finish_non_exhaustive()
    }
}

impl JwtValidator {
    pub fn new(cfg: JwtAuthConfig, egress_client: Arc<EgressClient>) -> Result<Self, AuthError> {
        Self::with_keys(
            cfg,
            None,
            egress_client,
            Arc::new(NoopRevocationStore),
            HashMap::new(),
        )
    }

    pub fn new_for_provider(
        cfg: JwtAuthConfig,
        provider_name: &str,
        egress_client: Arc<EgressClient>,
    ) -> Result<Self, AuthError> {
        Self::with_keys(
            cfg,
            Some(provider_issuer(provider_name)),
            egress_client,
            Arc::new(NoopRevocationStore),
            HashMap::new(),
        )
    }

    /// [`JwtValidator::new_for_provider`] with a real revocation store
    /// (issue #241, PR 9). The store is expected to be keyed by
    /// [`JwtValidator::provider_principal_issuer`] for the same
    /// configuration, so the denylist's identity boundary is the
    /// principal's.
    pub fn new_for_provider_with_revocation(
        cfg: JwtAuthConfig,
        provider_name: &str,
        egress_client: Arc<EgressClient>,
        revocation: Arc<dyn RevocationStore>,
    ) -> Result<Self, AuthError> {
        Self::with_keys(
            cfg,
            Some(provider_issuer(provider_name)),
            egress_client,
            revocation,
            HashMap::new(),
        )
    }

    /// The issuer a validator built from `cfg` for `provider_name` stamps
    /// on every principal: the configured issuer, normalized, or the
    /// provider's own label when none is configured. A revocation store
    /// keyed by anything else would let a `jti` revoked for one identity
    /// boundary go unrecognized -- or be recognized for the wrong one.
    pub fn provider_principal_issuer(
        cfg: &JwtAuthConfig,
        provider_name: &str,
    ) -> Result<String, AuthError> {
        match cfg.issuer.as_deref() {
            Some(issuer) => Self::issuer_boundary(issuer),
            None => Ok(provider_issuer(provider_name)),
        }
    }

    /// A configured issuer as the validator would normalize it -- the
    /// identity boundary a revocation must be recorded under. The
    /// operator's `revoke-jwt` command uses this so a revocation it writes
    /// is keyed exactly as the validators look it up.
    pub fn issuer_boundary(issuer: &str) -> Result<String, AuthError> {
        normalize_configured_issuer(issuer)
    }

    #[allow(dead_code)] // Future wiring can supply a real jti revocation store.
    pub fn new_with_revocation(
        cfg: JwtAuthConfig,
        egress_client: Arc<EgressClient>,
        revocation: Arc<dyn RevocationStore>,
    ) -> Result<Self, AuthError> {
        Self::with_keys(cfg, None, egress_client, revocation, HashMap::new())
    }

    #[allow(dead_code)] // Startup now builds JwtValidator instances from Config.auth_providers.
    pub fn from_config(
        config: &Config,
        egress_client: Arc<EgressClient>,
    ) -> Result<Option<Self>, AuthError> {
        JwtAuthConfig::from_config(config)
            .map(|cfg| Self::new(cfg, egress_client))
            .transpose()
    }

    #[cfg(test)]
    pub(crate) fn new_with_keys(
        cfg: JwtAuthConfig,
        egress_client: Arc<EgressClient>,
        revocation: Arc<dyn RevocationStore>,
        initial_keys: HashMap<String, CachedDecodingKey>,
    ) -> Result<Self, AuthError> {
        Self::with_keys(cfg, None, egress_client, revocation, initial_keys)
    }

    fn with_keys(
        mut cfg: JwtAuthConfig,
        fallback_principal_issuer: Option<String>,
        egress_client: Arc<EgressClient>,
        revocation: Arc<dyn RevocationStore>,
        initial_keys: HashMap<String, CachedDecodingKey>,
    ) -> Result<Self, AuthError> {
        cfg.issuer = cfg
            .issuer
            .as_deref()
            .map(normalize_configured_issuer)
            .transpose()?;
        let principal_issuer = cfg.issuer.clone().or(fallback_principal_issuer);
        // Keys handed in at construction are as fresh as a fetch; an empty set
        // has no fetch instant, so the first decode establishes one.
        let seeded_at = (!initial_keys.is_empty()).then(Instant::now);
        Ok(Self {
            cfg,
            principal_issuer,
            egress_client,
            keys: Arc::new(RwLock::new(initial_keys)),
            keys_fetched_at: Arc::new(RwLock::new(seeded_at)),
            last_jwks_refresh: Arc::new(Mutex::new(None)),
            revocation,
        })
    }

    /// Keep the key set fresh without waiting for a kid miss: refresh at
    /// half the maximum key age (never faster than the demand floor), with
    /// jitter so replicas that booted together do not fetch together.
    ///
    /// This is what makes "remove keys the issuer withdrew" prompt rather
    /// than eventual: every successful fetch replaces the whole set, so a
    /// withdrawn `kid` disappears at the next scheduled refresh instead of
    /// surviving until some request happens to age the set out. A failed
    /// refresh is logged and retried at the next tick; requests keep their
    /// own on-demand refresh and their fail-closed answer past the maximum
    /// age, so the task is a latency and hygiene improvement, never a
    /// correctness dependency.
    ///
    /// Cross-replica pressure on the IdP is bounded by construction at
    /// `replicas x JWT providers x (1 / interval)` scheduled fetches plus at
    /// most one demand fetch per [`MIN_JWKS_REFRESH_INTERVAL`] per validator;
    /// a shared lease that would let one replica fetch for all arrives with
    /// the membership work.
    pub fn spawn_background_refresh(self: &Arc<Self>, lifecycle: &GatewayLifecycle) {
        let interval = background_refresh_interval(self.cfg.jwks_max_key_age);
        self.spawn_background_refresh_every(interval, lifecycle);
    }

    fn spawn_background_refresh_every(
        self: &Arc<Self>,
        base: Duration,
        lifecycle: &GatewayLifecycle,
    ) {
        let validator = Arc::clone(self);
        let cancellation = lifecycle.background_cancellation();
        let handle = tokio::spawn(async move {
            loop {
                let wait = base + refresh_jitter(base);
                tokio::select! {
                    () = tokio::time::sleep(wait) => {}
                    () = cancellation.cancelled() => return,
                }
                if let Err(error) = validator.refresh_jwks_scheduled().await {
                    tracing::warn!(
                        error = %error,
                        "scheduled JWKS refresh failed; requests refresh on demand and fail \
                         closed past the maximum key age"
                    );
                }
            }
        });
        lifecycle.register_background_task(handle);
    }

    /// The scheduled refresh: not subject to the demand floor (it is
    /// operator-paced, not attacker-paced), but it stamps the same clock so
    /// a burst of kid misses right after it is still throttled.
    async fn refresh_jwks_scheduled(&self) -> Result<(), AuthError> {
        let mut last_refresh = self.last_jwks_refresh.lock().await;
        let result = self.fetch_jwks().await;
        *last_refresh = Some(Instant::now());
        result
    }

    #[cfg(test)]
    pub(crate) fn spawn_background_refresh_for_test(
        self: &Arc<Self>,
        interval: Duration,
        lifecycle: &GatewayLifecycle,
    ) {
        self.spawn_background_refresh_every(interval, lifecycle);
    }

    /// Test seam: make the key set look `by` older than it is, and forget
    /// the last demand fetch so the next refresh is not throttled.
    #[cfg(test)]
    pub(crate) async fn age_key_set(&self, by: Duration) {
        let mut fetched_at = self.keys_fetched_at.write().await;
        *fetched_at = fetched_at.and_then(|instant| instant.checked_sub(by));
        *self.last_jwks_refresh.lock().await = None;
    }

    async fn refresh_jwks(&self) -> Result<bool, AuthError> {
        let mut last_refresh = self.last_jwks_refresh.lock().await;
        // Unknown kids are attacker-controlled, so avoid turning each miss into
        // an IdP request while still allowing key rotation after the interval.
        if last_refresh
            .as_ref()
            .is_some_and(|last_refresh| last_refresh.elapsed() < MIN_JWKS_REFRESH_INTERVAL)
        {
            return Ok(false);
        }

        let result = self.fetch_jwks().await;
        *last_refresh = Some(Instant::now());
        result.map(|()| true)
    }

    async fn fetch_jwks(&self) -> Result<(), AuthError> {
        let response = timeout(
            self.cfg.http_timeout,
            self.egress_client.request(Method::GET, &self.cfg.jwks_url),
        )
        .await
        .map_err(|_| AuthError::Upstream("JWKS fetch failed".to_owned()))?
        .map_err(|err| {
            tracing::warn!(
                error_category = err.safe_category(),
                "JWKS fetch through egress failed"
            );
            AuthError::Upstream("JWKS fetch failed".to_owned())
        })?;

        if !response.status.is_success() {
            return Err(AuthError::Upstream("JWKS fetch failed".to_owned()));
        }

        let jwks = serde_json::from_slice::<JwksResponse>(&response.body)
            .map_err(|_| AuthError::Upstream("invalid JWKS response".to_owned()))?;
        let mut refreshed = HashMap::new();

        for key in jwks.keys {
            if let Some(cached_key) = cached_decoding_key(key) {
                refreshed.insert(cached_key.kid.clone(), cached_key);
            }
        }

        // A document that parses but yields no usable key is an IdP fault, not a
        // successful fetch: committing it would replace a working key set with an
        // empty one and stamp it fresh, so every token would then be rejected as
        // an unknown kid — an outage reported as bad credentials. Refusing to
        // commit keeps the previous keys inside their remaining trust window and
        // leaves the set stale, so the next request retries rather than settling
        // into the failure. Classified like an unparseable body.
        if refreshed.is_empty() {
            return Err(AuthError::Upstream("invalid JWKS response".to_owned()));
        }

        *self.keys.write().await = refreshed;
        *self.keys_fetched_at.write().await = Some(Instant::now());
        Ok(())
    }

    /// Whether the cached key set is still inside its trust window.
    async fn keys_are_fresh(&self) -> bool {
        self.keys_fetched_at
            .read()
            .await
            .is_some_and(|fetched_at| fetched_at.elapsed() < self.cfg.jwks_max_key_age)
    }

    async fn decode(&self, token: &str) -> Result<JwtClaims, AuthError> {
        let header = decode_header(token).map_err(|_| invalid_token())?;
        let kid = header
            .kid
            .ok_or_else(|| AuthError::InvalidSession("unknown kid".to_owned()))?;

        // A cached kid is only trusted while the key set it came from is inside
        // its trust window. Past that, the issuer may have withdrawn the key, so
        // re-fetch before honoring it rather than trusting it for the process
        // lifetime — a kid hit alone would otherwise never trigger a refresh.
        if self.keys_are_fresh().await {
            if let Some(key) = self.keys.read().await.get(&kid).cloned() {
                return self.decode_with_key(token, &key);
            }
        } else {
            self.refresh_jwks().await?;
            if !self.keys_are_fresh().await {
                // The refresh did not land (fetch failed, or the minimum
                // interval suppressed it). Freshness cannot be established, so
                // fail closed rather than fall back to the aged key set.
                return Err(AuthError::Upstream("JWKS refresh failed".to_owned()));
            }
            if let Some(key) = self.keys.read().await.get(&kid).cloned() {
                return self.decode_with_key(token, &key);
            }
            return Err(AuthError::InvalidSession("unknown kid".to_owned()));
        }

        self.refresh_jwks().await?;

        // A concurrent request may have populated this key while this caller
        // waited for the refresh mutex. Recheck even when the refresh interval
        // suppressed this caller's own fetch.
        if let Some(key) = self.keys.read().await.get(&kid).cloned() {
            return self.decode_with_key(token, &key);
        }

        Err(AuthError::InvalidSession("unknown kid".to_owned()))
    }

    fn decode_with_key(
        &self,
        token: &str,
        key: &CachedDecodingKey,
    ) -> Result<JwtClaims, AuthError> {
        let mut validation = Validation::new(key.algorithm);
        validation.validate_exp = true;
        validation.leeway = JWT_EXP_LEEWAY_SECS;
        // RFC 7519 4.1.5: a token must not be accepted before its `nbf`. The
        // library default is off, so an issuer that stamps a future start on a
        // scheduled-access token would otherwise have that window ignored.
        validation.validate_nbf = true;
        validation.validate_aud = self.cfg.audience.is_some();
        let mut required = vec!["exp"];

        if self.cfg.issuer.is_some() {
            required.push("iss");
        }

        if let Some(audience) = &self.cfg.audience {
            validation.set_audience(&[audience.as_str()]);
            required.push("aud");
        }

        validation.set_required_spec_claims(&required);

        let claims = decode::<JwtClaims>(token, &key.decoding_key, &validation)
            .map(|token_data| token_data.claims)
            .map_err(|_| invalid_token())?;
        self.validate_issuer_claim(&claims)?;

        Ok(claims)
    }

    fn validate_issuer_claim(&self, claims: &JwtClaims) -> Result<(), AuthError> {
        let Some(expected_issuer) = &self.cfg.issuer else {
            return Ok(());
        };
        let actual_issuer = claims
            .iss
            .as_deref()
            .and_then(oidc::normalize_issuer)
            .ok_or_else(invalid_token)?;
        if actual_issuer != *expected_issuer {
            return Err(invalid_token());
        }

        Ok(())
    }

    async fn validate_claims(&self, claims: JwtClaims) -> Result<Principal, AuthError> {
        let user_id = claims.sub.trim();
        if user_id.is_empty() {
            return Err(AuthError::InvalidSession("missing sub".to_owned()));
        }

        let jti = claims
            .jti
            .as_deref()
            .map(str::trim)
            .filter(|jti| !jti.is_empty());

        if self.cfg.require_jti && jti.is_none() {
            return Err(AuthError::InvalidSession("missing jti".to_owned()));
        }

        if let Some(jti) = jti {
            if self.revocation.is_revoked(jti).await? {
                return Err(AuthError::InvalidSession("revoked_token".to_owned()));
            }
        }

        let email = claims
            .email
            .as_deref()
            .map(str::trim)
            .filter(|email| !email.is_empty())
            .map(str::to_ascii_lowercase);
        let roles = extract_roles(
            &claims.extra,
            &self.cfg.roles_claim,
            self.cfg.roles_claim_delimiter.as_deref(),
        );
        let org_id = extract_string_claim(&claims.extra, self.cfg.org_claim.as_deref());
        let session_id = jti.unwrap_or("-").to_owned();

        Ok(Principal {
            user_id: user_id.to_owned(),
            issuer: self.principal_issuer.clone(),
            email,
            org_id,
            roles,
            session_id,
            auth_method: AuthMethod::Bearer,
        })
    }

    fn validate_resource_audience(
        &self,
        claims: &JwtClaims,
        resource: Option<&str>,
    ) -> Result<(), AuthError> {
        let Some(resource) = resource else {
            return Ok(());
        };

        if claims
            .aud
            .as_ref()
            .is_some_and(|audience| audience.contains(resource))
        {
            Ok(())
        } else {
            Err(invalid_token())
        }
    }

    pub(crate) async fn validate_oidc_id_token_nonce(
        &self,
        token: &str,
        expected_nonce: &str,
    ) -> Result<(), AuthError> {
        let claims = self.decode(token).await?;
        match extract_string_claim(&claims.extra, Some("nonce")).as_deref() {
            Some(nonce) if nonce == expected_nonce => Ok(()),
            _ => Err(invalid_token()),
        }
    }
}

#[async_trait::async_trait]
impl SessionValidator for JwtValidator {
    async fn validate_session(
        &self,
        credential: &SessionCredential,
    ) -> Result<Principal, AuthError> {
        self.validate_session_for_resource(credential, None).await
    }

    async fn validate_session_for_resource(
        &self,
        credential: &SessionCredential,
        resource: Option<&str>,
    ) -> Result<Principal, AuthError> {
        match credential {
            SessionCredential::Cookie(_) | SessionCredential::ClientCertificate(_) => Err(
                AuthError::InvalidSession("jwt validator only supports bearer tokens".to_owned()),
            ),
            SessionCredential::Bearer(token) => {
                let claims = self.decode(token).await?;
                self.validate_resource_audience(&claims, resource)?;
                self.validate_claims(claims).await
            }
        }
    }

    fn supports_cookie(&self) -> bool {
        false
    }

    fn supports_bearer(&self) -> bool {
        true
    }
}

#[derive(Deserialize)]
struct JwksResponse {
    keys: Vec<JwksKey>,
}

#[derive(Deserialize)]
struct JwksKey {
    kid: Option<String>,
    kty: Option<String>,
    n: Option<String>,
    e: Option<String>,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

#[derive(Clone)]
pub(crate) struct CachedDecodingKey {
    kid: String,
    decoding_key: DecodingKey,
    algorithm: Algorithm,
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    sub: String,
    iss: Option<String>,
    aud: Option<AudienceClaim>,
    email: Option<String>,
    #[allow(dead_code)] // jsonwebtoken validates `exp`; GreenGateway does not read it directly.
    exp: Option<u64>,
    jti: Option<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AudienceClaim {
    Single(String),
    Multiple(Vec<String>),
}

impl AudienceClaim {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::Single(value) => value == expected,
            Self::Multiple(values) => values.iter().any(|value| value == expected),
        }
    }
}

fn invalid_token() -> AuthError {
    AuthError::InvalidSession(INVALID_TOKEN.to_owned())
}

/// Half the maximum key age, never below the demand floor: a key set is
/// refreshed well before it stops being trusted.
fn background_refresh_interval(max_key_age: Duration) -> Duration {
    (max_key_age / 2).max(MIN_JWKS_REFRESH_INTERVAL)
}

/// Up to one eighth of the interval, from the OS random source, so replicas
/// drift apart rather than fetching in lockstep. Randomness failing here
/// costs only the jitter.
fn refresh_jitter(base: Duration) -> Duration {
    let mut byte = [0u8; 1];
    let _ = getrandom::fill(&mut byte);
    base.mul_f64(f64::from(byte[0]) / 255.0 / 8.0)
}

fn normalize_configured_issuer(issuer: &str) -> Result<String, AuthError> {
    oidc::normalize_issuer(issuer)
        .ok_or_else(|| AuthError::Upstream("JWT issuer must be non-empty".to_owned()))
}

fn normalize_auth_config_issuer(issuer: Option<&str>) -> Option<String> {
    issuer.map(|issuer| oidc::normalize_issuer(issuer).unwrap_or_else(|| issuer.to_owned()))
}

// Public modulus of the retired, publicly disclosed development signing key.
const RETIRED_DEV_RSA_MODULUS: &str = "nZz3xMSjSyuvBiVU_kM7Bs_xpDc2gLgguzFbLwW2iN2Lhs_pCB6r5-Xi5xyMlbZARlq-uUfm6O7RvYhhjIdHS6BjcsfSDwTZi3FzB1JYs0jP2y0sbmwf9VS1mYD65GyPuMArMY930-htQTXTil-RUkvZzodETTXcJ-W_0HQmjJ7euE-X_BVyN4IjuACFQgFBPKO8OWx_9V3V3e0nzWtUTYX4zErCuyrqslhgDRQNFTS7oL5AT3cY3fkQJNbbtrPR30rC2_fI9yHFpfc3Hi8GBLnogdNrGJYX58ibn4uZiQQ6jcIG-glY_1v6pNI1TDuArQeMc1cEXomzk_cWjp0u5Q";

fn is_retired_dev_key(modulus: &str) -> bool {
    let decoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    match (
        decoder.decode(modulus.trim_end_matches('=')),
        decoder.decode(RETIRED_DEV_RSA_MODULUS),
    ) {
        (Ok(candidate), Ok(retired)) => candidate
            .iter()
            .skip_while(|byte| **byte == 0)
            .eq(retired.iter()),
        _ => false,
    }
}

fn cached_decoding_key(key: JwksKey) -> Option<CachedDecodingKey> {
    let JwksKey {
        kid,
        kty,
        n,
        e,
        crv,
        x,
        y,
    } = key;

    match kty.as_deref() {
        Some("RSA") => {
            let (Some(kid), Some(n), Some(e)) = (kid, n, e) else {
                return None;
            };
            if is_retired_dev_key(&n) {
                tracing::warn!("refusing retired public development JWT key");
                return None;
            }
            DecodingKey::from_rsa_components(&n, &e)
                .ok()
                .map(|decoding_key| CachedDecodingKey {
                    kid,
                    decoding_key,
                    algorithm: Algorithm::RS256,
                })
        }
        Some("EC") if crv.as_deref() == Some("P-256") => {
            let (Some(kid), Some(x), Some(y)) = (kid, x, y) else {
                return None;
            };
            DecodingKey::from_ec_components(&x, &y)
                .ok()
                .map(|decoding_key| CachedDecodingKey {
                    kid,
                    decoding_key,
                    algorithm: Algorithm::ES256,
                })
        }
        Some("OKP") if crv.as_deref() == Some("Ed25519") => {
            let (Some(kid), Some(x)) = (kid, x) else {
                return None;
            };
            DecodingKey::from_ed_components(&x)
                .ok()
                .map(|decoding_key| CachedDecodingKey {
                    kid,
                    decoding_key,
                    algorithm: Algorithm::EdDSA,
                })
        }
        _ => None,
    }
}

#[cfg(test)]
#[path = "jwt_tests.rs"]
mod tests;
