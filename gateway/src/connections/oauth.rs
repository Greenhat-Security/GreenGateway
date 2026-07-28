use std::{
    collections::HashMap,
    fmt,
    future::Future,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use http::{
    header::{self},
    HeaderMap, HeaderValue, Method, StatusCode,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;
use url::form_urlencoded;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    audit::{self, AuditEvent, AuditLog},
    egress::{EgressClient, EgressError},
};

use super::{
    control_plane::ConnectionControlPlane,
    model::{ConnectionId, MAX_CONNECTIONS},
    secret::{SecretPurpose, SecretResolveErrorKind, MAX_HTTP_CREDENTIAL_BYTES},
};

pub(crate) const OAUTH_MAX_RESPONSE_BYTES: usize = 16 * 1024;
pub(crate) const OAUTH_MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_TOKEN_TYPE_BYTES: usize = 32;
const MAX_RESPONSE_SCOPE_BYTES: usize = 4 * 1024;
const MAX_TOKEN_LIFETIME_SECS: u64 = 7 * 24 * 60 * 60;
const REFRESH_SKEW_SECS: u64 = 30;
const MAX_REFRESH_JITTER_SECS: u64 = 5;
const TOKEN_CACHE_CAPACITY: usize = MAX_CONNECTIONS;

#[derive(Clone)]
pub(crate) struct OAuthClientCredentialsRuntime {
    control_plane: ConnectionControlPlane,
    cache: Arc<OAuthTokenCache>,
    audit: Option<AuditLog>,
}

pub(crate) struct OAuthBinding {
    pub connection_id: ConnectionId,
    pub connection_etag: String,
    pub client_id: String,
    pub client_secret_id: String,
    pub token_url: String,
    pub scopes: Vec<String>,
    pub audience: Option<String>,
    pub resource: Option<String>,
    pub token_client: Arc<EgressClient>,
}

pub(crate) struct OAuthTokenLease {
    access_token: Zeroizing<Vec<u8>>,
    slot: Arc<OAuthTokenSlot>,
    generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OAuthError {
    CredentialInvalid,
    CredentialUnavailable,
    TokenEgressDenied,
    TokenUnavailable,
    TokenRejected,
    InvalidTokenResponse,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct OAuthTokenCacheKey {
    connection_id: String,
    connection_etag: String,
    secret_version: Option<u64>,
    egress_generation: [u8; 32],
}

struct OAuthTokenCache {
    slots: Mutex<HashMap<OAuthTokenCacheKey, Arc<OAuthTokenSlot>>>,
    clock: Arc<dyn OAuthClock>,
}

struct OAuthTokenSlot {
    state: AsyncMutex<OAuthTokenSlotState>,
}

#[derive(Default)]
struct OAuthTokenSlotState {
    cached: Option<CachedOAuthToken>,
    generation: u64,
}

struct CachedOAuthToken {
    access_token: Zeroizing<Vec<u8>>,
    refresh_at: Instant,
    generation: u64,
}

struct MintedOAuthToken {
    access_token: Zeroizing<Vec<u8>>,
    lifetime: Duration,
}

trait OAuthClock: Send + Sync {
    fn now(&self) -> Instant;
}

struct SystemOAuthClock;

impl OAuthClock for SystemOAuthClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

impl Drop for TokenResponse {
    fn drop(&mut self) {
        self.access_token.zeroize();
        if let Some(refresh_token) = self.refresh_token.as_mut() {
            refresh_token.zeroize();
        }
    }
}

impl OAuthClientCredentialsRuntime {
    pub(crate) fn new(control_plane: ConnectionControlPlane) -> Self {
        Self {
            control_plane,
            cache: Arc::new(OAuthTokenCache::new(Arc::new(SystemOAuthClock))),
            audit: None,
        }
    }

    pub(crate) fn with_audit(mut self, audit: AuditLog) -> Self {
        self.audit = Some(audit);
        self
    }

    #[cfg(test)]
    fn with_clock(mut self, clock: Arc<dyn OAuthClock>) -> Self {
        self.cache = Arc::new(OAuthTokenCache::new(clock));
        self
    }

    pub(crate) async fn access_token(
        &self,
        binding: &OAuthBinding,
    ) -> Result<OAuthTokenLease, OAuthError> {
        let secret_version = self
            .control_plane
            .local_secret_version(&binding.client_secret_id);
        let key = OAuthTokenCacheKey {
            connection_id: binding.connection_id.to_string(),
            connection_etag: binding.connection_etag.clone(),
            secret_version,
            egress_generation: binding.token_client.configuration_generation(),
        };
        self.cache
            .get_or_mint(key, || async { self.mint(binding).await })
            .await
    }

    async fn mint(&self, binding: &OAuthBinding) -> Result<MintedOAuthToken, OAuthError> {
        let started = Instant::now();
        let result = self.mint_inner(binding).await;
        self.emit_refresh_event(binding, &result, started.elapsed());
        result
    }

    async fn mint_inner(&self, binding: &OAuthBinding) -> Result<MintedOAuthToken, OAuthError> {
        let destination = binding
            .token_client
            .checked_destination(&binding.token_url)
            .await
            .map_err(|error| oauth_egress_error(&error))?;

        let client_secret = self
            .control_plane
            .secret_resolver()
            .resolve(&binding.client_secret_id, SecretPurpose::OAuthClientSecret)
            .await
            .map_err(|error| match error.kind() {
                SecretResolveErrorKind::UnknownAlias
                | SecretResolveErrorKind::SourceDenied
                | SecretResolveErrorKind::InvalidMaterial => OAuthError::CredentialInvalid,
                SecretResolveErrorKind::ProviderBusy
                | SecretResolveErrorKind::SourceUnavailable
                | SecretResolveErrorKind::UnsafeSource
                | SecretResolveErrorKind::ProviderFailure => OAuthError::CredentialUnavailable,
            })?;

        let headers = token_request_headers(&binding.client_id, client_secret.expose())?;
        let body = token_request_body(binding)?;
        let response = binding
            .token_client
            .request_with_headers_at_checked_destination(
                &destination,
                Method::POST,
                &binding.token_url,
                headers,
                Some(body),
            )
            .await
            .map_err(|error| oauth_egress_error(&error))?;

        let status = response.status;
        let content_type_is_json = is_json_content_type(response.headers.get(header::CONTENT_TYPE));
        let response_body = Zeroizing::new(response.body);
        if status != StatusCode::OK {
            return Err(OAuthError::TokenRejected);
        }
        if !content_type_is_json {
            return Err(OAuthError::InvalidTokenResponse);
        }

        let mut token: TokenResponse = serde_json::from_slice(response_body.as_slice())
            .map_err(|_| OAuthError::InvalidTokenResponse)?;
        validate_token_response(&token)?;
        let access_token = Zeroizing::new(std::mem::take(&mut token.access_token).into_bytes());
        Ok(MintedOAuthToken {
            access_token,
            lifetime: Duration::from_secs(token.expires_in),
        })
    }

    fn emit_refresh_event(
        &self,
        binding: &OAuthBinding,
        result: &Result<MintedOAuthToken, OAuthError>,
        latency: Duration,
    ) {
        let (outcome, reason) = match result {
            Ok(_) => ("success", "refreshed"),
            Err(error) => ("failure", error.safe_reason()),
        };
        ::metrics::counter!(
            "connection_oauth_token_refresh_total",
            "result" => outcome,
            "reason" => reason
        )
        .increment(1);
        let Some(audit) = self.audit.as_ref() else {
            return;
        };
        audit.emit(AuditEvent::new(
            audit::event::CONNECTION_OAUTH_TOKEN_REFRESH,
            "connection-oauth-token",
            "internal",
            None,
            json!({
                "connection_id": binding.connection_id,
                "auth_type": "oauth2_client_credentials",
                "outcome": outcome,
                "reason": reason,
                "latency_ms": duration_millis(latency),
            }),
        ));
    }
}

impl fmt::Debug for OAuthClientCredentialsRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthClientCredentialsRuntime")
            .field("cached_slot_count", &self.cache.slot_guard().len())
            .field("audit_configured", &self.audit.is_some())
            .finish()
    }
}

impl OAuthTokenLease {
    pub(crate) fn inject(&self, headers: &mut HeaderMap) -> Result<(), OAuthError> {
        let mut bearer = Zeroizing::new(Vec::with_capacity(
            "Bearer ".len() + self.access_token.len(),
        ));
        bearer.extend_from_slice(b"Bearer ");
        bearer.extend_from_slice(self.access_token.as_slice());
        let mut authorization = HeaderValue::from_bytes(bearer.as_slice())
            .map_err(|_| OAuthError::InvalidTokenResponse)?;
        authorization.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, authorization);
        Ok(())
    }

    pub(crate) async fn invalidate_after_unauthorized(&self) {
        let mut state = self.slot.state.lock().await;
        if state
            .cached
            .as_ref()
            .is_some_and(|cached| cached.generation == self.generation)
        {
            state.cached = None;
        }
    }
}

impl fmt::Debug for OAuthTokenLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-oauth-token>")
    }
}

impl OAuthError {
    pub(crate) const fn safe_reason(self) -> &'static str {
        match self {
            Self::CredentialInvalid => "credential_invalid",
            Self::CredentialUnavailable => "credential_unavailable",
            Self::TokenEgressDenied => "oauth_token_egress_denied",
            Self::TokenUnavailable => "oauth_token_unavailable",
            Self::TokenRejected => "oauth_token_rejected",
            Self::InvalidTokenResponse => "oauth_token_invalid_response",
        }
    }
}

impl OAuthTokenCache {
    fn new(clock: Arc<dyn OAuthClock>) -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
            clock,
        }
    }

    async fn get_or_mint<F, Fut>(
        &self,
        key: OAuthTokenCacheKey,
        mint: F,
    ) -> Result<OAuthTokenLease, OAuthError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<MintedOAuthToken, OAuthError>>,
    {
        let slot = self.slot_for(&key)?;
        let mut state = slot.state.lock().await;
        let now = self.clock.now();
        if let Some(cached) = state
            .cached
            .as_ref()
            .filter(|cached| now < cached.refresh_at)
        {
            return lease_from_cached(Arc::clone(&slot), cached);
        }
        state.cached = None;

        let minted = mint().await?;
        let now = self.clock.now();
        state.generation = state.generation.saturating_add(1).max(1);
        let generation = state.generation;
        let refresh_at = now
            .checked_add(refresh_after(&key, minted.lifetime))
            .unwrap_or(now);
        state.cached = Some(CachedOAuthToken {
            access_token: minted.access_token,
            refresh_at,
            generation,
        });
        lease_from_cached(
            Arc::clone(&slot),
            state
                .cached
                .as_ref()
                .expect("OAuth token was inserted before lease construction"),
        )
    }

    fn slot_for(&self, key: &OAuthTokenCacheKey) -> Result<Arc<OAuthTokenSlot>, OAuthError> {
        let mut slots = self.slot_guard();
        if let Some(slot) = slots.get(key) {
            return Ok(Arc::clone(slot));
        }
        if slots.len() >= TOKEN_CACHE_CAPACITY {
            let idle_key = slots
                .iter()
                .find_map(|(key, slot)| (Arc::strong_count(slot) == 1).then(|| key.clone()))
                .ok_or(OAuthError::TokenUnavailable)?;
            slots.remove(&idle_key);
        }
        let slot = Arc::new(OAuthTokenSlot {
            state: AsyncMutex::new(OAuthTokenSlotState::default()),
        });
        slots.insert(key.clone(), Arc::clone(&slot));
        Ok(slot)
    }

    fn slot_guard(&self) -> MutexGuard<'_, HashMap<OAuthTokenCacheKey, Arc<OAuthTokenSlot>>> {
        match self.slots.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("OAuth token cache lock poisoned; discarding cached slots");
                let mut guard = poisoned.into_inner();
                guard.clear();
                guard
            }
        }
    }
}

fn lease_from_cached(
    slot: Arc<OAuthTokenSlot>,
    cached: &CachedOAuthToken,
) -> Result<OAuthTokenLease, OAuthError> {
    Ok(OAuthTokenLease {
        access_token: Zeroizing::new(cached.access_token.to_vec()),
        slot,
        generation: cached.generation,
    })
}

fn token_request_headers(client_id: &str, client_secret: &[u8]) -> Result<HeaderMap, OAuthError> {
    let encoded_client_id =
        Zeroizing::new(form_urlencoded::byte_serialize(client_id.as_bytes()).collect::<String>());
    let encoded_client_secret =
        Zeroizing::new(form_urlencoded::byte_serialize(client_secret).collect::<String>());
    let mut user_info = Zeroizing::new(Vec::with_capacity(
        encoded_client_id.len() + encoded_client_secret.len() + 1,
    ));
    user_info.extend_from_slice(encoded_client_id.as_bytes());
    user_info.push(b':');
    user_info.extend_from_slice(encoded_client_secret.as_bytes());
    let encoded = Zeroizing::new(BASE64_STANDARD.encode(user_info.as_slice()));
    let mut basic = Zeroizing::new(Vec::with_capacity("Basic ".len() + encoded.len()));
    basic.extend_from_slice(b"Basic ");
    basic.extend_from_slice(encoded.as_bytes());
    let mut authorization =
        HeaderValue::from_bytes(basic.as_slice()).map_err(|_| OAuthError::CredentialInvalid)?;
    authorization.set_sensitive(true);

    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, authorization);
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
    Ok(headers)
}

fn token_request_body(binding: &OAuthBinding) -> Result<Vec<u8>, OAuthError> {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("grant_type", "client_credentials");
    if !binding.scopes.is_empty() {
        serializer.append_pair("scope", &binding.scopes.join(" "));
    }
    if let Some(audience) = binding.audience.as_deref() {
        serializer.append_pair("audience", audience);
    }
    if let Some(resource) = binding.resource.as_deref() {
        serializer.append_pair("resource", resource);
    }
    let body = serializer.finish().into_bytes();
    if body.len() > OAUTH_MAX_REQUEST_BYTES {
        return Err(OAuthError::InvalidTokenResponse);
    }
    Ok(body)
}

fn validate_token_response(token: &TokenResponse) -> Result<(), OAuthError> {
    if token.access_token.is_empty()
        || token.access_token.len() > MAX_HTTP_CREDENTIAL_BYTES
        || token.access_token.contains('\0')
        || token.token_type.len() > MAX_TOKEN_TYPE_BYTES
        || !token.token_type.eq_ignore_ascii_case("bearer")
        || token.expires_in == 0
        || token.expires_in > MAX_TOKEN_LIFETIME_SECS
        || token.refresh_token.as_ref().is_some_and(|refresh| {
            refresh.len() > MAX_HTTP_CREDENTIAL_BYTES || refresh.contains('\0')
        })
        || token
            .scope
            .as_ref()
            .is_some_and(|scope| scope.len() > MAX_RESPONSE_SCOPE_BYTES || scope.contains('\0'))
    {
        return Err(OAuthError::InvalidTokenResponse);
    }
    HeaderValue::from_bytes(token.access_token.as_bytes())
        .map(|_| ())
        .map_err(|_| OAuthError::InvalidTokenResponse)
}

fn is_json_content_type(value: Option<&HeaderValue>) -> bool {
    value
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

fn oauth_egress_error(error: &EgressError) -> OAuthError {
    match error {
        EgressError::HostNotAllowed(_)
        | EgressError::PortNotAllowed(_)
        | EgressError::NonGlobalIpBlocked(_)
        | EgressError::InvalidPolicy(_)
        | EgressError::InvalidUrl(_)
        | EgressError::SchemeNotAllowed(_) => OAuthError::TokenEgressDenied,
        EgressError::ResponseTooLarge { .. } => OAuthError::InvalidTokenResponse,
        EgressError::DnsResolutionFailed(_)
        | EgressError::RequestBodyTooLarge { .. }
        | EgressError::RequestBodyReadFailed
        | EgressError::UnexpectedStatus(_)
        | EgressError::ResponseIdleTimeout { .. }
        | EgressError::InvalidTlsCaBundle { .. }
        | EgressError::InvalidTlsClientIdentity
        | EgressError::Http(_) => OAuthError::TokenUnavailable,
    }
}

fn refresh_after(key: &OAuthTokenCacheKey, lifetime: Duration) -> Duration {
    let lifetime_secs = lifetime.as_secs();
    let skew = REFRESH_SKEW_SECS.min(lifetime_secs / 5);
    let jitter_cap = MAX_REFRESH_JITTER_SECS.min(lifetime_secs / 10);
    let jitter = if jitter_cap == 0 {
        0
    } else {
        deterministic_jitter(key) % (jitter_cap + 1)
    };
    Duration::from_secs(lifetime_secs.saturating_sub(skew.saturating_add(jitter)))
}

fn deterministic_jitter(key: &OAuthTokenCacheKey) -> u64 {
    let mut digest = Sha256::new();
    digest.update(b"greengateway:oauth-refresh-jitter:v1\0");
    digest.update(key.connection_id.as_bytes());
    digest.update([0]);
    digest.update(key.connection_etag.as_bytes());
    digest.update([0]);
    digest.update(key.secret_version.unwrap_or_default().to_be_bytes());
    digest.update(key.egress_generation);
    let digest = digest.finalize();
    u64::from_be_bytes(
        digest[..8]
            .try_into()
            .expect("SHA-256 prefix is exactly eight bytes"),
    )
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use futures_util::future::join_all;

    use super::*;

    struct FakeClock {
        base: Instant,
        millis: AtomicU64,
    }

    impl FakeClock {
        fn new() -> Self {
            Self {
                base: Instant::now(),
                millis: AtomicU64::new(0),
            }
        }

        fn advance(&self, duration: Duration) {
            self.millis.fetch_add(
                u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
                Ordering::AcqRel,
            );
        }
    }

    impl OAuthClock for FakeClock {
        fn now(&self) -> Instant {
            self.base + Duration::from_millis(self.millis.load(Ordering::Acquire))
        }
    }

    fn key(revision: u64, secret_version: Option<u64>) -> OAuthTokenCacheKey {
        OAuthTokenCacheKey {
            connection_id: "connection-1".to_owned(),
            connection_etag: format!("etag-{revision}"),
            secret_version,
            egress_generation: [u8::try_from(revision).unwrap_or(u8::MAX); 32],
        }
    }

    fn token(value: &str, lifetime: Duration) -> MintedOAuthToken {
        MintedOAuthToken {
            access_token: Zeroizing::new(value.as_bytes().to_vec()),
            lifetime,
        }
    }

    #[tokio::test]
    async fn one_hundred_concurrent_calls_share_one_mint_and_refresh_once() {
        let clock = Arc::new(FakeClock::new());
        let cache = Arc::new(OAuthTokenCache::new(clock.clone()));
        let mints = Arc::new(AtomicUsize::new(0));

        let calls = (0..100).map(|_| {
            let cache = Arc::clone(&cache);
            let mints = Arc::clone(&mints);
            async move {
                cache
                    .get_or_mint(key(1, Some(1)), || async {
                        mints.fetch_add(1, Ordering::AcqRel);
                        tokio::task::yield_now().await;
                        Ok(token("first-token", Duration::from_secs(3_600)))
                    })
                    .await
                    .expect("single-flight mint should succeed")
            }
        });
        let leases = join_all(calls).await;
        assert_eq!(leases.len(), 100);
        assert_eq!(mints.load(Ordering::Acquire), 1);

        clock.advance(Duration::from_secs(3_600));
        let refreshes = (0..100).map(|_| {
            let cache = Arc::clone(&cache);
            let mints = Arc::clone(&mints);
            async move {
                cache
                    .get_or_mint(key(1, Some(1)), || async {
                        mints.fetch_add(1, Ordering::AcqRel);
                        tokio::task::yield_now().await;
                        Ok(token("second-token", Duration::from_secs(3_600)))
                    })
                    .await
                    .expect("single-flight refresh should succeed")
            }
        });
        assert_eq!(join_all(refreshes).await.len(), 100);
        assert_eq!(mints.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn revision_and_secret_rotation_partition_tokens_without_reviving_old_generation() {
        let clock = Arc::new(FakeClock::new());
        let cache = OAuthTokenCache::new(clock);
        let first = cache
            .get_or_mint(key(1, Some(1)), || async {
                Ok(token("old-token", Duration::from_secs(3_600)))
            })
            .await
            .expect("first token should mint");
        let rotated = cache
            .get_or_mint(key(1, Some(2)), || async {
                Ok(token("rotated-token", Duration::from_secs(3_600)))
            })
            .await
            .expect("secret rotation should mint a separate token");
        first.invalidate_after_unauthorized().await;

        let mint_count = AtomicUsize::new(0);
        let retained = cache
            .get_or_mint(key(1, Some(2)), || async {
                mint_count.fetch_add(1, Ordering::AcqRel);
                Ok(token("unexpected", Duration::from_secs(3_600)))
            })
            .await
            .expect("new token generation should remain cached");
        assert_eq!(mint_count.load(Ordering::Acquire), 0);

        let mut headers = HeaderMap::new();
        rotated
            .inject(&mut headers)
            .expect("rotated token should inject");
        assert_eq!(
            headers.get(header::AUTHORIZATION),
            Some(&HeaderValue::from_static("Bearer rotated-token"))
        );
        headers.clear();
        retained
            .inject(&mut headers)
            .expect("retained token should inject");
        assert_eq!(
            headers.get(header::AUTHORIZATION),
            Some(&HeaderValue::from_static("Bearer rotated-token"))
        );
    }

    #[tokio::test]
    async fn unauthorized_invalidates_only_the_matching_token_generation() {
        let clock = Arc::new(FakeClock::new());
        let cache = OAuthTokenCache::new(clock);
        let rejected = cache
            .get_or_mint(key(1, Some(1)), || async {
                Ok(token("rejected", Duration::from_secs(3_600)))
            })
            .await
            .expect("token should mint");
        rejected.invalidate_after_unauthorized().await;

        let mints = AtomicUsize::new(0);
        let replacement = cache
            .get_or_mint(key(1, Some(1)), || async {
                mints.fetch_add(1, Ordering::AcqRel);
                Ok(token("replacement", Duration::from_secs(3_600)))
            })
            .await
            .expect("invalidated token should refresh");
        assert_eq!(mints.load(Ordering::Acquire), 1);
        rejected.invalidate_after_unauthorized().await;

        let retained = cache
            .get_or_mint(key(1, Some(1)), || async {
                mints.fetch_add(1, Ordering::AcqRel);
                Ok(token("unexpected", Duration::from_secs(3_600)))
            })
            .await
            .expect("stale rejection must not remove replacement");
        assert_eq!(mints.load(Ordering::Acquire), 1);

        let mut headers = HeaderMap::new();
        replacement
            .inject(&mut headers)
            .expect("replacement token should inject");
        assert_eq!(
            headers.get(header::AUTHORIZATION),
            Some(&HeaderValue::from_static("Bearer replacement"))
        );
        headers.clear();
        retained
            .inject(&mut headers)
            .expect("retained token should inject");
        assert_eq!(
            headers.get(header::AUTHORIZATION),
            Some(&HeaderValue::from_static("Bearer replacement"))
        );
    }

    #[tokio::test]
    async fn cache_capacity_never_evicts_active_or_in_flight_slots() {
        let clock = Arc::new(FakeClock::new());
        let cache = OAuthTokenCache::new(clock);
        let mut active_leases = Vec::with_capacity(TOKEN_CACHE_CAPACITY);
        for revision in 0..TOKEN_CACHE_CAPACITY {
            active_leases.push(
                cache
                    .get_or_mint(
                        key(
                            u64::try_from(revision).expect("cache bound fits u64"),
                            Some(1),
                        ),
                        || async { Ok(token("active-token", Duration::from_secs(3_600))) },
                    )
                    .await
                    .expect("bounded active token should mint"),
            );
        }
        assert_eq!(cache.slot_guard().len(), TOKEN_CACHE_CAPACITY);

        let blocked_mints = AtomicUsize::new(0);
        let unavailable = cache
            .get_or_mint(key(u64::MAX, Some(1)), || async {
                blocked_mints.fetch_add(1, Ordering::AcqRel);
                Ok(token("must-not-mint", Duration::from_secs(3_600)))
            })
            .await;
        assert!(matches!(unavailable, Err(OAuthError::TokenUnavailable)));
        assert_eq!(blocked_mints.load(Ordering::Acquire), 0);
        assert_eq!(cache.slot_guard().len(), TOKEN_CACHE_CAPACITY);

        drop(active_leases.pop());
        cache
            .get_or_mint(key(u64::MAX, Some(1)), || async {
                Ok(token("replacement-token", Duration::from_secs(3_600)))
            })
            .await
            .expect("an idle slot should be safely replaceable");
        assert_eq!(cache.slot_guard().len(), TOKEN_CACHE_CAPACITY);
    }

    #[test]
    fn token_response_validation_is_strict_and_bounded() {
        let valid = TokenResponse {
            access_token: "token".to_owned(),
            token_type: "Bearer".to_owned(),
            expires_in: 60,
            refresh_token: None,
            scope: Some("read".to_owned()),
        };
        assert_eq!(validate_token_response(&valid), Ok(()));

        let wrong_type = TokenResponse {
            access_token: "token".to_owned(),
            token_type: "DPoP".to_owned(),
            expires_in: 60,
            refresh_token: None,
            scope: Some("read".to_owned()),
        };
        assert_eq!(
            validate_token_response(&wrong_type),
            Err(OAuthError::InvalidTokenResponse)
        );
        assert!(serde_json::from_str::<TokenResponse>(
            r#"{"access_token":"token","token_type":"Bearer","expires_in":60,"extension":true}"#
        )
        .is_err());
        assert!(serde_json::from_slice::<TokenResponse>(b"{not-json").is_err());

        let invalid_discarded_fields = TokenResponse {
            access_token: "token".to_owned(),
            token_type: "Bearer".to_owned(),
            expires_in: 60,
            refresh_token: Some("discarded\0refresh".to_owned()),
            scope: Some("read".to_owned()),
        };
        assert_eq!(
            validate_token_response(&invalid_discarded_fields),
            Err(OAuthError::InvalidTokenResponse)
        );
    }

    #[test]
    fn client_secret_basic_and_form_body_are_encoded_without_raw_secret_headers() {
        let headers = token_request_headers("client:name", b"secret\r\nvalue")
            .expect("encoded Basic header should be valid");
        let expected = format!(
            "Basic {}",
            BASE64_STANDARD.encode("client%3Aname:secret%0D%0Avalue")
        );
        assert_eq!(
            headers.get(header::AUTHORIZATION),
            Some(&HeaderValue::from_str(&expected).expect("expected header should parse"))
        );
        assert!(headers
            .get(header::AUTHORIZATION)
            .expect("authorization should exist")
            .is_sensitive());
    }
}
