use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

use super::{
    protected_resource,
    tokens::{TokenVerification, TokenVerificationFailure},
    AuthError, AuthMethod, Principal, SessionCredential, SessionValidator,
};
use crate::{
    metrics::LOCK_POISON_RECOVERIES_TOTAL,
    storage::{RepositoryError, ServiceTokenStore},
};

const SERVICE_TOKEN_PREFIX: &str = "ggw_";
const SERVICE_TOKEN_CACHE_MAX_ENTRIES: usize = 1024;

/// The authoritative security revision, read per request (issue #241,
/// PR 9). In cluster mode every token mutation -- create, revoke, rotate
/// -- advances this counter inside its own transaction, so a cached
/// verification is only trustworthy while the counter still reads what it
/// read when the entry was made. Standalone mode has no such counter and
/// no such source: its process is the only writer.
#[async_trait::async_trait]
pub trait AuthRevisionSource: Send + Sync {
    async fn current(&self) -> Result<i64, RepositoryError>;
}

pub struct ServiceTokenValidator {
    store: Arc<dyn ServiceTokenStore>,
    cache: ServiceTokenVerificationCache,
    /// Cluster mode's per-request authority check. When present, a
    /// cached entry is served only if it was verified at the revision the
    /// authority reports NOW; otherwise the store is asked again. A
    /// revoke committed on any replica moves the revision, so the very
    /// next request on this replica -- however fresh its cache -- goes
    /// back to the store and is refused. A source that cannot be read is
    /// a dependency failure, answered `503`, never a fallback to the cache.
    revision_source: Option<Arc<dyn AuthRevisionSource>>,
}

impl ServiceTokenValidator {
    pub fn new(store: Arc<dyn ServiceTokenStore>, ttl: Duration) -> Self {
        Self {
            store,
            cache: ServiceTokenVerificationCache::new(ttl),
            revision_source: None,
        }
    }

    /// Bind the validator to the shared security revision (cluster mode).
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))] // Only cluster mode has a source.
    pub fn with_revision_source(mut self, source: Arc<dyn AuthRevisionSource>) -> Self {
        self.revision_source = Some(source);
        self
    }

    pub fn invalidate_token_id(&self, token_id: &str) {
        self.cache.invalidate_token_id(token_id);
    }

    /// Drop every cached verification. The cluster reconciler calls this
    /// when the service-token resource moved; the per-request revision
    /// check is what makes correctness not depend on it, this keeps stale
    /// entries from lingering until their TTL.
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))] // Called by the cluster reconciler.
    pub fn invalidate_all(&self) {
        self.cache.clear();
    }
}

#[async_trait::async_trait]
impl SessionValidator for ServiceTokenValidator {
    async fn validate_session(
        &self,
        credential: &SessionCredential,
    ) -> Result<Principal, AuthError> {
        let SessionCredential::Bearer(token) = credential else {
            return Err(AuthError::InvalidSession(
                "service tokens require bearer credentials".to_owned(),
            ));
        };

        if !token.starts_with(SERVICE_TOKEN_PREFIX) {
            return Err(AuthError::InvalidSession(
                "credential is not a GreenGateway service token".to_owned(),
            ));
        }

        // The revision is read BEFORE the store is consulted, so an entry
        // is tagged with a revision at or below the one its verification
        // observed. A mutation landing between the two reads therefore
        // shows up as a newer revision on the next request, which
        // re-verifies -- the safe direction.
        let revision = match self.revision_source.as_ref() {
            Some(source) => Some(
                source
                    .current()
                    .await
                    .map_err(service_token_store_auth_error)?,
            ),
            None => None,
        };
        let cache_key = cache_key_for_token(token);
        if let Some(result) = self.cache.get(&cache_key, revision) {
            return result.into_principal();
        }

        // The store contract runs its blocking work off the request
        // executors; awaiting here keeps request handling responsive while
        // the verification stays authoritative.
        // The store measures the remaining lifetime on its own clock at
        // some point inside the round-trip; anchor before it starts so the
        // time the round-trip took is never credited to the token.
        let verified_at = Instant::now();
        let verification = self
            .store
            .verify(token)
            .await
            .map_err(service_token_store_auth_error)?;
        let lifetime_cap = match &verification {
            TokenVerification::Valid(verified) => verified
                .remaining_lifetime
                .map(|remaining| remaining.saturating_sub(verified_at.elapsed())),
            TokenVerification::Invalid(_) => None,
        };
        let cached = CachedVerification::from_verification(verification);
        self.cache
            .insert(cache_key, cached.clone(), revision, lifetime_cap);
        cached.into_principal()
    }

    async fn validate_session_for_resource(
        &self,
        credential: &SessionCredential,
        resource: Option<&str>,
    ) -> Result<Principal, AuthError> {
        let principal = self.validate_session(credential).await?;

        if resource.is_some()
            && !principal
                .roles
                .iter()
                .any(|scope| scope == protected_resource::MCP_SCOPE)
        {
            return Err(AuthError::InvalidSession(
                "service token lacks required MCP scope".to_owned(),
            ));
        }

        Ok(principal)
    }

    fn supports_cookie(&self) -> bool {
        false
    }

    fn supports_bearer(&self) -> bool {
        true
    }
}

struct ServiceTokenVerificationCache {
    ttl: Duration,
    inner: Mutex<HashMap<String, CacheEntry<CachedVerification>>>,
}

#[derive(Clone)]
enum CachedVerification {
    Valid(CachedValidToken),
    Invalid(TokenVerificationFailure),
}

#[derive(Clone)]
struct CachedValidToken {
    id: String,
    scopes: Vec<String>,
}

struct CacheEntry<T> {
    value: T,
    expires_at: Instant,
    /// The security revision this entry was verified at; `None` outside
    /// cluster mode.
    revision: Option<i64>,
}

impl ServiceTokenVerificationCache {
    fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// A hit only if the entry is inside its TTL AND was made at
    /// `revision` (`None` in standalone mode, where there is no revision to
    /// compare and the TTL is the whole contract).
    fn get(&self, key: &str, revision: Option<i64>) -> Option<CachedVerification> {
        let now = Instant::now();
        self.inner_guard()
            .get(key)
            .filter(|entry| entry.revision == revision)
            .and_then(|entry| entry.fresh_value(now))
    }

    #[cfg_attr(not(feature = "postgres"), allow(dead_code))] // Reached through `invalidate_all`.
    fn clear(&self) {
        self.inner_guard().clear();
    }

    fn insert(
        &self,
        key: String,
        value: CachedVerification,
        revision: Option<i64>,
        lifetime_cap: Option<Duration>,
    ) {
        let now = Instant::now();
        // An entry lives no longer than the store's own clock says the
        // token does: expiry moves no revision, and this replica's clock
        // is not the authority's.
        let ttl = lifetime_cap.map_or(self.ttl, |cap| cap.min(self.ttl));
        let mut inner = self.inner_guard();
        inner.retain(|_, entry| entry.is_fresh(now));
        if inner.len() >= SERVICE_TOKEN_CACHE_MAX_ENTRIES {
            if let Some(oldest_key) = inner
                .iter()
                .min_by_key(|(_, entry)| entry.expires_at)
                .map(|(key, _)| key.clone())
            {
                inner.remove(&oldest_key);
            }
        }
        inner.insert(key, CacheEntry::new(value, now + ttl, revision));
    }

    fn invalidate_token_id(&self, token_id: &str) {
        let mut inner = self.inner_guard();
        inner.retain(|_, entry| match &entry.value {
            CachedVerification::Valid(valid) => valid.id != token_id,
            CachedVerification::Invalid(_) => true,
        });
    }

    fn inner_guard(&self) -> MutexGuard<'_, HashMap<String, CacheEntry<CachedVerification>>> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                ::metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "auth_service_token",
                    "lock" => "verification_cache"
                )
                .increment(1);
                tracing::error!("service-token verification cache lock poisoned; recovering");
                poisoned.into_inner()
            }
        }
    }
}

impl CachedVerification {
    fn from_verification(verification: TokenVerification) -> Self {
        match verification {
            TokenVerification::Valid(verified) => Self::Valid(CachedValidToken {
                id: verified.id,
                scopes: verified.scopes,
            }),
            TokenVerification::Invalid(failure) => Self::Invalid(failure),
        }
    }

    fn into_principal(self) -> Result<Principal, AuthError> {
        match self {
            // Validity is the store's verdict, judged on its own clock:
            // this replica's wall clock never rejects a token the authority
            // accepted, and the entry's lifetime cap (measured at the
            // store) is what expires it here.
            Self::Valid(valid) => Ok(Principal {
                user_id: format!("service-token:{}", valid.id),
                issuer: None,
                email: None,
                org_id: None,
                roles: valid.scopes,
                session_id: valid.id,
                auth_method: AuthMethod::ServiceToken,
            }),
            Self::Invalid(failure) => Err(AuthError::InvalidSession(format!(
                "service token is {}",
                verification_failure_label(failure)
            ))),
        }
    }
}

impl<T: Clone> CacheEntry<T> {
    fn new(value: T, expires_at: Instant, revision: Option<i64>) -> Self {
        Self {
            value,
            expires_at,
            revision,
        }
    }

    fn fresh_value(&self, now: Instant) -> Option<T> {
        self.is_fresh(now).then(|| self.value.clone())
    }

    fn is_fresh(&self, now: Instant) -> bool {
        now < self.expires_at
    }
}

fn cache_key_for_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(digest)
}

fn service_token_store_auth_error(error: crate::storage::RepositoryError) -> AuthError {
    AuthError::Upstream(format!("service-token store error: {error}"))
}

fn verification_failure_label(failure: TokenVerificationFailure) -> &'static str {
    match failure {
        TokenVerificationFailure::NotFound => "not found",
        TokenVerificationFailure::Revoked => "revoked",
        TokenVerificationFailure::Expired => "expired",
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    use crate::auth::{
        tokens::{
            CreateTokenRequest, CreatedToken, SqliteTokenStore, TokenListFilters, TokenPage,
            TokenRecord, TokenVerification, TokenVerificationFailure, VerifiedToken,
        },
        AuthError, AuthMethod, ServiceTokenValidator, SessionCredential, SessionValidator,
    };
    use crate::storage::{RepositoryError, ServiceTokenStore};

    #[tokio::test]
    async fn valid_service_token_authenticates_with_scopes_as_roles() {
        let db = TempDb::new("valid");
        let store = Arc::new(SqliteTokenStore::open(&db.path).expect("token store should open"));
        let created = store
            .create(create_request(&["admin:tokens:read", "admin:tokens:write"]))
            .await
            .expect("token should create");
        let validator = ServiceTokenValidator::new(store, Duration::from_secs(5));

        let principal = validator
            .validate_session(&SessionCredential::Bearer(created.plaintext_token.clone()))
            .await
            .expect("service token should validate");

        assert_eq!(
            principal.user_id,
            format!("service-token:{}", created.record.id)
        );
        assert_eq!(principal.email, None);
        assert_eq!(principal.issuer, None);
        assert_eq!(principal.org_id, None);
        assert_eq!(
            principal.roles,
            vec![
                "admin:tokens:read".to_owned(),
                "admin:tokens:write".to_owned()
            ]
        );
        assert_eq!(principal.session_id, created.record.id);
        assert_eq!(principal.auth_method, AuthMethod::ServiceToken);
    }

    #[tokio::test]
    async fn service_token_without_mcp_scope_is_rejected_for_mcp_resource() {
        let db = TempDb::new("missing-mcp-scope");
        let store = Arc::new(SqliteTokenStore::open(&db.path).expect("token store should open"));
        let created = store
            .create(create_request(&["admin:tokens:read"]))
            .await
            .expect("token should create");
        let validator = ServiceTokenValidator::new(store, Duration::from_secs(5));

        let error = validator
            .validate_session_for_resource(
                &SessionCredential::Bearer(created.plaintext_token),
                Some("https://gateway.example.test/mcp"),
            )
            .await
            .expect_err("service token without MCP scope should be rejected for MCP resource");

        assert_invalid_session(error, "service token lacks required MCP scope");
    }

    #[tokio::test]
    async fn service_token_with_mcp_scope_is_accepted_for_mcp_resource() {
        let db = TempDb::new("with-mcp-scope");
        let store = Arc::new(SqliteTokenStore::open(&db.path).expect("token store should open"));
        let created = store
            .create(create_request(&["admin:tokens:read", "mcp:tools"]))
            .await
            .expect("token should create");
        let validator = ServiceTokenValidator::new(store, Duration::from_secs(5));

        let principal = validator
            .validate_session_for_resource(
                &SessionCredential::Bearer(created.plaintext_token),
                Some("https://gateway.example.test/mcp"),
            )
            .await
            .expect("service token with MCP scope should validate for MCP resource");

        assert_eq!(
            principal.roles,
            vec!["admin:tokens:read".to_owned(), "mcp:tools".to_owned()]
        );
        assert_eq!(principal.auth_method, AuthMethod::ServiceToken);
    }

    #[tokio::test]
    async fn service_token_without_mcp_scope_still_authenticates_without_resource() {
        let db = TempDb::new("non-mcp-no-scope");
        let store = Arc::new(SqliteTokenStore::open(&db.path).expect("token store should open"));
        let created = store
            .create(create_request(&["admin:tokens:read"]))
            .await
            .expect("token should create");
        let validator = ServiceTokenValidator::new(store, Duration::from_secs(5));

        let principal = validator
            .validate_session_for_resource(
                &SessionCredential::Bearer(created.plaintext_token),
                None,
            )
            .await
            .expect("service token without MCP scope should still validate without resource");

        assert_eq!(principal.roles, vec!["admin:tokens:read".to_owned()]);
        assert_eq!(principal.auth_method, AuthMethod::ServiceToken);
    }

    #[tokio::test]
    async fn invalid_and_revoked_service_tokens_are_rejected() {
        let db = TempDb::new("invalid-revoked");
        let store = Arc::new(SqliteTokenStore::open(&db.path).expect("token store should open"));
        let revoked = store
            .create(create_request(&["admin:tokens:read"]))
            .await
            .expect("token should create");
        store
            .revoke(&revoked.record.id)
            .await
            .expect("token should revoke")
            .expect("token should exist");
        let validator = ServiceTokenValidator::new(store, Duration::from_secs(5));

        let invalid = validator
            .validate_session(&SessionCredential::Bearer("ggw_not-real".to_owned()))
            .await
            .expect_err("garbage ggw token should be rejected");
        assert!(matches!(invalid, AuthError::InvalidSession(_)));

        let revoked = validator
            .validate_session(&SessionCredential::Bearer(revoked.plaintext_token))
            .await
            .expect_err("revoked token should be rejected");
        assert!(matches!(revoked, AuthError::InvalidSession(_)));
    }

    #[tokio::test]
    async fn revoked_cached_token_is_accepted_until_cache_ttl_then_rejected() {
        let store = Arc::new(RevocableStore::default());
        let validator_store: Arc<dyn ServiceTokenStore> = store.clone();
        let validator = ServiceTokenValidator::new(validator_store, Duration::from_millis(20));
        let plaintext_token = "ggw_cached-service-token".to_owned();

        validator
            .validate_session(&SessionCredential::Bearer(plaintext_token.clone()))
            .await
            .expect("token should be cached as valid");
        store
            .revoked
            .store(true, std::sync::atomic::Ordering::SeqCst);

        validator
            .validate_session(&SessionCredential::Bearer(plaintext_token.clone()))
            .await
            .expect("cached token remains valid inside TTL window");

        tokio::time::sleep(Duration::from_millis(50)).await;
        let error = validator
            .validate_session(&SessionCredential::Bearer(plaintext_token))
            .await
            .expect_err("token should be rejected after cache TTL expires");
        assert!(matches!(error, AuthError::InvalidSession(_)));
    }

    /// Cluster mode: a cached verification is only served while the
    /// authority's revision still reads what it read when the entry was
    /// made. Move the revision -- what any replica's revoke does -- and the
    /// next request re-verifies and is refused, TTL notwithstanding.
    #[tokio::test]
    async fn a_moved_security_revision_forces_reverification_inside_the_ttl() {
        let store = Arc::new(RevocableStore::default());
        let validator_store: Arc<dyn ServiceTokenStore> = store.clone();
        let revision = Arc::new(std::sync::atomic::AtomicI64::new(7));
        let validator = ServiceTokenValidator::new(validator_store, Duration::from_secs(60))
            .with_revision_source(Arc::new(CountingSource {
                revision: revision.clone(),
            }));
        let plaintext_token = "ggw_cluster-cached-token".to_owned();

        validator
            .validate_session(&SessionCredential::Bearer(plaintext_token.clone()))
            .await
            .expect("token should be cached as valid at revision 7");
        store
            .revoked
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // Same revision: the cache still answers (a revoke that had
        // committed would have moved it).
        validator
            .validate_session(&SessionCredential::Bearer(plaintext_token.clone()))
            .await
            .expect("cached entry is served while the revision is unchanged");

        // The revoke commits on some replica and moves the shared counter.
        revision.store(8, std::sync::atomic::Ordering::SeqCst);
        let error = validator
            .validate_session(&SessionCredential::Bearer(plaintext_token))
            .await
            .expect_err("the next request re-verifies and is refused inside the TTL");
        assert!(matches!(error, AuthError::InvalidSession(_)));
    }

    /// A revision source that cannot be read is a dependency failure:
    /// `503`, never a fallback to the cache and never `401`.
    #[tokio::test]
    async fn an_unreadable_security_revision_is_a_dependency_failure() {
        let store = Arc::new(RevocableStore::default());
        let validator_store: Arc<dyn ServiceTokenStore> = store.clone();
        let validator = ServiceTokenValidator::new(validator_store, Duration::from_secs(60))
            .with_revision_source(Arc::new(FailingSource));
        let error = validator
            .validate_session(&SessionCredential::Bearer("ggw_cluster-token".to_owned()))
            .await
            .expect_err("no authority, no answer");
        assert!(
            matches!(error, AuthError::Upstream(_)),
            "dependency failure must map to Upstream (503), got {error:?}"
        );
    }

    struct CountingSource {
        revision: Arc<std::sync::atomic::AtomicI64>,
    }

    #[async_trait::async_trait]
    impl super::AuthRevisionSource for CountingSource {
        async fn current(&self) -> Result<i64, RepositoryError> {
            Ok(self.revision.load(std::sync::atomic::Ordering::SeqCst))
        }
    }

    struct FailingSource;

    #[async_trait::async_trait]
    impl super::AuthRevisionSource for FailingSource {
        async fn current(&self) -> Result<i64, RepositoryError> {
            Err(RepositoryError::new(
                crate::storage::RepositoryErrorKind::Unavailable,
                "test_revision_source",
            ))
        }
    }

    #[tokio::test]
    async fn non_service_bearer_is_rejected_without_store_lookup() {
        let store = Arc::new(SpyStore::default());
        let validator_store: Arc<dyn ServiceTokenStore> = store.clone();
        let validator = ServiceTokenValidator::new(validator_store, Duration::from_secs(5));

        let error = validator
            .validate_session(&SessionCredential::Bearer(
                "eyJhbGciOiJSUzI1NiJ9.jwt-shaped".to_owned(),
            ))
            .await
            .expect_err("non-ggw bearer should not validate as service token");

        assert!(matches!(error, AuthError::InvalidSession(_)));
        assert_eq!(store.verify_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn validator_is_bearer_only() {
        let store = Arc::new(SpyStore::default());
        let validator = ServiceTokenValidator::new(store, Duration::from_secs(5));

        assert!(validator.supports_bearer());
        assert!(!validator.supports_cookie());
    }

    fn create_request(scopes: &[&str]) -> CreateTokenRequest {
        CreateTokenRequest {
            scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            created_by: "creator".to_owned(),
            expires_at: None,
        }
    }

    #[derive(Default)]
    struct SpyStore {
        verify_calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ServiceTokenStore for SpyStore {
        async fn create(
            &self,
            _request: CreateTokenRequest,
        ) -> Result<CreatedToken, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }

        async fn list(&self, _filters: &TokenListFilters) -> Result<TokenPage, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }

        async fn get_by_id(&self, _id: &str) -> Result<Option<TokenRecord>, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }

        async fn revoke(&self, _id: &str) -> Result<Option<TokenRecord>, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }

        async fn rotate(&self, _id: &str) -> Result<Option<CreatedToken>, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }

        async fn verify(
            &self,
            _plaintext_token: &str,
        ) -> Result<TokenVerification, RepositoryError> {
            self.verify_calls.fetch_add(1, Ordering::SeqCst);
            Ok(TokenVerification::Invalid(
                TokenVerificationFailure::NotFound,
            ))
        }

        async fn touch_last_used(&self, _id: &str) -> Result<Option<TokenRecord>, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }
    }

    #[derive(Default)]
    struct RevocableStore {
        revoked: AtomicBool,
    }

    #[async_trait::async_trait]
    impl ServiceTokenStore for RevocableStore {
        async fn create(
            &self,
            _request: CreateTokenRequest,
        ) -> Result<CreatedToken, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }

        async fn list(&self, _filters: &TokenListFilters) -> Result<TokenPage, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }

        async fn get_by_id(&self, _id: &str) -> Result<Option<TokenRecord>, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }

        async fn revoke(&self, _id: &str) -> Result<Option<TokenRecord>, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }

        async fn rotate(&self, _id: &str) -> Result<Option<CreatedToken>, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }

        async fn verify(
            &self,
            _plaintext_token: &str,
        ) -> Result<TokenVerification, RepositoryError> {
            if self.revoked.load(Ordering::SeqCst) {
                Ok(TokenVerification::Invalid(
                    TokenVerificationFailure::Revoked,
                ))
            } else {
                Ok(verified_token("tok-cache", &["admin:tokens:read"]))
            }
        }

        async fn touch_last_used(&self, _id: &str) -> Result<Option<TokenRecord>, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }
    }

    /// The prefix every fake verification reports: the service-token
    /// prefix plus digits, never a credential.
    const FAKE_PREFIX: &str = "ggw_1234567890";

    fn verified_token(id: &str, scopes: &[&str]) -> TokenVerification {
        TokenVerification::Valid(VerifiedToken {
            id: id.to_owned(),
            token_prefix: FAKE_PREFIX.to_owned(),
            scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            expires_at: None,
            last_used_at: None,
            remaining_lifetime: None,
        })
    }

    /// A store whose clock says the token has 300 ms left, however far
    /// away its `expires_at` looks to this replica.
    #[derive(Default)]
    struct ExpiringStore {
        verify_calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ServiceTokenStore for ExpiringStore {
        async fn create(
            &self,
            _request: CreateTokenRequest,
        ) -> Result<CreatedToken, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }

        async fn list(&self, _filters: &TokenListFilters) -> Result<TokenPage, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }

        async fn get_by_id(&self, _id: &str) -> Result<Option<TokenRecord>, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }

        async fn revoke(&self, _id: &str) -> Result<Option<TokenRecord>, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }

        async fn rotate(&self, _id: &str) -> Result<Option<CreatedToken>, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }

        async fn verify(
            &self,
            _plaintext_token: &str,
        ) -> Result<TokenVerification, RepositoryError> {
            self.verify_calls.fetch_add(1, Ordering::SeqCst);
            Ok(TokenVerification::Valid(VerifiedToken {
                id: "tok-expiring".to_owned(),
                token_prefix: FAKE_PREFIX.to_owned(),
                scopes: vec!["admin:tokens:read".to_owned()],
                expires_at: Some("2999-01-01T00:00:00Z".to_owned()),
                last_used_at: None,
                remaining_lifetime: Some(Duration::from_millis(300)),
            }))
        }

        async fn touch_last_used(&self, _id: &str) -> Result<Option<TokenRecord>, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }
    }

    /// A store whose verification takes 200 ms and reports 300 ms of life
    /// measured somewhere inside that round-trip.
    #[derive(Default)]
    struct SlowExpiringStore {
        verify_calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ServiceTokenStore for SlowExpiringStore {
        async fn create(
            &self,
            _request: CreateTokenRequest,
        ) -> Result<CreatedToken, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }

        async fn list(&self, _filters: &TokenListFilters) -> Result<TokenPage, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }

        async fn get_by_id(&self, _id: &str) -> Result<Option<TokenRecord>, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }

        async fn revoke(&self, _id: &str) -> Result<Option<TokenRecord>, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }

        async fn rotate(&self, _id: &str) -> Result<Option<CreatedToken>, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }

        async fn verify(
            &self,
            _plaintext_token: &str,
        ) -> Result<TokenVerification, RepositoryError> {
            self.verify_calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(200)).await;
            Ok(TokenVerification::Valid(VerifiedToken {
                id: "tok-slow".to_owned(),
                token_prefix: FAKE_PREFIX.to_owned(),
                scopes: vec!["admin:tokens:read".to_owned()],
                expires_at: Some("2999-01-01T00:00:00Z".to_owned()),
                last_used_at: None,
                remaining_lifetime: Some(Duration::from_millis(300)),
            }))
        }

        async fn touch_last_used(&self, _id: &str) -> Result<Option<TokenRecord>, RepositoryError> {
            unimplemented!("not needed by this validator test")
        }
    }

    /// Validity is the store's verdict on the store's clock. A replica
    /// whose wall clock runs ahead of the authority must not reject a token
    /// the authority just accepted: the store reports it valid with life
    /// remaining, and the cached entry expires by that lifetime, not by
    /// this replica's reading of `expires_at`.
    #[tokio::test]
    async fn a_store_verified_token_is_accepted_whatever_this_replica_clock_says() {
        struct PastByLocalClockStore;

        #[async_trait::async_trait]
        impl ServiceTokenStore for PastByLocalClockStore {
            async fn create(
                &self,
                _request: CreateTokenRequest,
            ) -> Result<CreatedToken, RepositoryError> {
                unimplemented!("not needed by this validator test")
            }

            async fn list(
                &self,
                _filters: &TokenListFilters,
            ) -> Result<TokenPage, RepositoryError> {
                unimplemented!("not needed by this validator test")
            }

            async fn get_by_id(&self, _id: &str) -> Result<Option<TokenRecord>, RepositoryError> {
                unimplemented!("not needed by this validator test")
            }

            async fn revoke(&self, _id: &str) -> Result<Option<TokenRecord>, RepositoryError> {
                unimplemented!("not needed by this validator test")
            }

            async fn rotate(&self, _id: &str) -> Result<Option<CreatedToken>, RepositoryError> {
                unimplemented!("not needed by this validator test")
            }

            async fn verify(
                &self,
                _plaintext_token: &str,
            ) -> Result<TokenVerification, RepositoryError> {
                Ok(TokenVerification::Valid(VerifiedToken {
                    id: "tok-authority-says-valid".to_owned(),
                    token_prefix: FAKE_PREFIX.to_owned(),
                    scopes: vec!["admin:tokens:read".to_owned()],
                    // Long past by this replica's clock; the authority
                    // nevertheless verified it with life remaining.
                    expires_at: Some("2000-01-01T00:00:00Z".to_owned()),
                    last_used_at: None,
                    remaining_lifetime: Some(Duration::from_secs(30)),
                }))
            }

            async fn touch_last_used(
                &self,
                _id: &str,
            ) -> Result<Option<TokenRecord>, RepositoryError> {
                unimplemented!("not needed by this validator test")
            }
        }

        let validator =
            ServiceTokenValidator::new(Arc::new(PastByLocalClockStore), Duration::from_secs(60));
        let principal = validator
            .validate_session(&SessionCredential::Bearer("ggw_ahead-of-time".to_owned()))
            .await
            .expect("the authority's verdict stands over this replica's clock");
        assert_eq!(principal.session_id, "tok-authority-says-valid");
    }

    /// The lifetime cap is anchored before the verification round-trip:
    /// the time the round-trip took is not credited to the token, so a
    /// slow store cannot stretch a cache entry past the store's expiry.
    #[tokio::test]
    async fn the_cache_cap_is_anchored_before_the_verify_round_trip() {
        let store = Arc::new(SlowExpiringStore::default());
        let validator_store: Arc<dyn ServiceTokenStore> = store.clone();
        let validator = ServiceTokenValidator::new(validator_store, Duration::from_secs(60));
        let token = "ggw_slow-token".to_owned();

        validator
            .validate_session(&SessionCredential::Bearer(token.clone()))
            .await
            .expect("the token verifies");
        // 300 ms of life reported inside a 200 ms round-trip: at most
        // ~100 ms of cache remain after it returns.
        tokio::time::sleep(Duration::from_millis(150)).await;
        validator
            .validate_session(&SessionCredential::Bearer(token))
            .await
            .expect("re-verified at the store");
        assert_eq!(
            store.verify_calls.load(Ordering::SeqCst),
            2,
            "the round-trip's own duration was not credited to the token"
        );
    }

    /// A cached verification is served no longer than the store's own
    /// clock says the token lives, whatever this replica's clock or the
    /// cache TTL say: expiry moves no revision, so the cache cannot lean
    /// on one.
    #[tokio::test]
    async fn the_cache_never_outlives_the_store_clock_expiry() {
        let store = Arc::new(ExpiringStore::default());
        let validator_store: Arc<dyn ServiceTokenStore> = store.clone();
        let validator = ServiceTokenValidator::new(validator_store, Duration::from_secs(60));
        let token = "ggw_expiring-token".to_owned();

        validator
            .validate_session(&SessionCredential::Bearer(token.clone()))
            .await
            .expect("the token verifies");
        validator
            .validate_session(&SessionCredential::Bearer(token.clone()))
            .await
            .expect("served from the cache inside the store's lifetime");
        assert_eq!(store.verify_calls.load(Ordering::SeqCst), 1);

        tokio::time::sleep(Duration::from_millis(450)).await;
        validator
            .validate_session(&SessionCredential::Bearer(token))
            .await
            .expect("re-verified at the store");
        assert_eq!(
            store.verify_calls.load(Ordering::SeqCst),
            2,
            "the entry expired with the store's clock, well inside the cache TTL"
        );
    }

    fn assert_invalid_session(error: AuthError, expected: &str) {
        match error {
            AuthError::InvalidSession(message) => assert_eq!(message, expected),
            AuthError::Upstream(message) => {
                panic!("expected invalid session, got upstream error: {message}")
            }
        }
    }

    struct TempDb {
        path: PathBuf,
    }

    impl TempDb {
        fn new(test_name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-service-token-validator-{test_name}-{}.sqlite",
                uuid::Uuid::new_v4()
            ));

            Self { path }
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let path = PathBuf::from(format!("{}{}", self.path.display(), suffix));
                let _ = std::fs::remove_file(path);
            }
        }
    }
}
