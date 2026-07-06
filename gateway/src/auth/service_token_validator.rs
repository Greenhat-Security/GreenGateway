use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use super::{
    protected_resource,
    tokens::{TokenStore, TokenStoreError, TokenVerification, TokenVerificationFailure},
    AuthError, AuthMethod, Principal, SessionCredential, SessionValidator,
};
use crate::metrics::LOCK_POISON_RECOVERIES_TOTAL;

const SERVICE_TOKEN_PREFIX: &str = "ggw_";
const SERVICE_TOKEN_CACHE_MAX_ENTRIES: usize = 1024;

pub struct ServiceTokenValidator {
    store: Arc<dyn TokenStore>,
    cache: ServiceTokenVerificationCache,
}

impl ServiceTokenValidator {
    pub fn new(store: Arc<dyn TokenStore>, ttl: Duration) -> Self {
        Self {
            store,
            cache: ServiceTokenVerificationCache::new(ttl),
        }
    }

    pub fn invalidate_token_id(&self, token_id: &str) {
        self.cache.invalidate_token_id(token_id);
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

        let cache_key = cache_key_for_token(token);
        if let Some(result) = self.cache.get(&cache_key) {
            return result.into_principal();
        }

        let verification = self
            .store
            .verify(token)
            .map_err(service_token_store_auth_error)?;
        let cached = CachedVerification::from_verification(verification);
        self.cache.insert(cache_key, cached.clone());
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
    expires_at: Option<String>,
}

struct CacheEntry<T> {
    value: T,
    expires_at: Instant,
}

impl ServiceTokenVerificationCache {
    fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(HashMap::new()),
        }
    }

    fn get(&self, key: &str) -> Option<CachedVerification> {
        let now = Instant::now();
        self.inner_guard()
            .get(key)
            .and_then(|entry| entry.fresh_value(now))
    }

    fn insert(&self, key: String, value: CachedVerification) {
        let now = Instant::now();
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
        inner.insert(key, CacheEntry::new(value, now + self.ttl));
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
                expires_at: verified.expires_at,
            }),
            TokenVerification::Invalid(failure) => Self::Invalid(failure),
        }
    }

    fn into_principal(self) -> Result<Principal, AuthError> {
        match self {
            Self::Valid(valid) => {
                if cached_token_expired(valid.expires_at.as_deref()) {
                    return Err(AuthError::InvalidSession(
                        "service token is expired".to_owned(),
                    ));
                }

                Ok(Principal {
                    user_id: format!("service-token:{}", valid.id),
                    issuer: None,
                    email: None,
                    org_id: None,
                    roles: valid.scopes,
                    session_id: valid.id,
                    auth_method: AuthMethod::ServiceToken,
                })
            }
            Self::Invalid(failure) => Err(AuthError::InvalidSession(format!(
                "service token is {}",
                verification_failure_label(failure)
            ))),
        }
    }
}

impl<T: Clone> CacheEntry<T> {
    fn new(value: T, expires_at: Instant) -> Self {
        Self { value, expires_at }
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

fn service_token_store_auth_error(error: TokenStoreError) -> AuthError {
    AuthError::Upstream(format!("service-token store error: {error}"))
}

fn verification_failure_label(failure: TokenVerificationFailure) -> &'static str {
    match failure {
        TokenVerificationFailure::NotFound => "not found",
        TokenVerificationFailure::Revoked => "revoked",
        TokenVerificationFailure::Expired => "expired",
    }
}

fn cached_token_expired(expires_at: Option<&str>) -> bool {
    let Some(expires_at) = expires_at else {
        return false;
    };

    OffsetDateTime::parse(expires_at, &Rfc3339)
        .is_ok_and(|expires_at| expires_at <= OffsetDateTime::now_utc())
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
            TokenRecord, TokenStore, TokenStoreError, TokenVerification, TokenVerificationFailure,
            VerifiedToken,
        },
        AuthError, AuthMethod, ServiceTokenValidator, SessionCredential, SessionValidator,
    };

    #[tokio::test]
    async fn valid_service_token_authenticates_with_scopes_as_roles() {
        let db = TempDb::new("valid");
        let store = Arc::new(SqliteTokenStore::open(&db.path).expect("token store should open"));
        let created = store
            .create(create_request(&["admin:tokens:read", "admin:tokens:write"]))
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
            .expect("token should create");
        store
            .revoke(&revoked.record.id)
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
        let validator_store: Arc<dyn TokenStore> = store.clone();
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

    #[tokio::test]
    async fn non_service_bearer_is_rejected_without_store_lookup() {
        let store = Arc::new(SpyStore::default());
        let validator_store: Arc<dyn TokenStore> = store.clone();
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

    impl TokenStore for SpyStore {
        fn create(&self, _request: CreateTokenRequest) -> Result<CreatedToken, TokenStoreError> {
            unimplemented!("not needed by this validator test")
        }

        fn list(&self, _filters: &TokenListFilters) -> Result<TokenPage, TokenStoreError> {
            unimplemented!("not needed by this validator test")
        }

        fn get_by_id(&self, _id: &str) -> Result<Option<TokenRecord>, TokenStoreError> {
            unimplemented!("not needed by this validator test")
        }

        fn revoke(&self, _id: &str) -> Result<Option<TokenRecord>, TokenStoreError> {
            unimplemented!("not needed by this validator test")
        }

        fn rotate(&self, _id: &str) -> Result<Option<CreatedToken>, TokenStoreError> {
            unimplemented!("not needed by this validator test")
        }

        fn verify(&self, _plaintext_token: &str) -> Result<TokenVerification, TokenStoreError> {
            self.verify_calls.fetch_add(1, Ordering::SeqCst);
            Ok(TokenVerification::Invalid(
                TokenVerificationFailure::NotFound,
            ))
        }

        fn touch_last_used(&self, _id: &str) -> Result<Option<TokenRecord>, TokenStoreError> {
            unimplemented!("not needed by this validator test")
        }
    }

    #[derive(Default)]
    struct RevocableStore {
        revoked: AtomicBool,
    }

    impl TokenStore for RevocableStore {
        fn create(&self, _request: CreateTokenRequest) -> Result<CreatedToken, TokenStoreError> {
            unimplemented!("not needed by this validator test")
        }

        fn list(&self, _filters: &TokenListFilters) -> Result<TokenPage, TokenStoreError> {
            unimplemented!("not needed by this validator test")
        }

        fn get_by_id(&self, _id: &str) -> Result<Option<TokenRecord>, TokenStoreError> {
            unimplemented!("not needed by this validator test")
        }

        fn revoke(&self, _id: &str) -> Result<Option<TokenRecord>, TokenStoreError> {
            unimplemented!("not needed by this validator test")
        }

        fn rotate(&self, _id: &str) -> Result<Option<CreatedToken>, TokenStoreError> {
            unimplemented!("not needed by this validator test")
        }

        fn verify(&self, _plaintext_token: &str) -> Result<TokenVerification, TokenStoreError> {
            if self.revoked.load(Ordering::SeqCst) {
                Ok(TokenVerification::Invalid(
                    TokenVerificationFailure::Revoked,
                ))
            } else {
                Ok(verified_token("tok-cache", &["admin:tokens:read"]))
            }
        }

        fn touch_last_used(&self, _id: &str) -> Result<Option<TokenRecord>, TokenStoreError> {
            unimplemented!("not needed by this validator test")
        }
    }

    fn verified_token(id: &str, scopes: &[&str]) -> TokenVerification {
        TokenVerification::Valid(VerifiedToken {
            id: id.to_owned(),
            token_prefix: "ggw_1234567890".to_owned(),
            scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            expires_at: None,
            last_used_at: None,
        })
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
