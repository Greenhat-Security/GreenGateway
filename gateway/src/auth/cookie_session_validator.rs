//! Cookie-session validator backed by a generic HTTP introspection endpoint.
//!
//! The endpoint contract is intentionally simple and product-neutral:
//! GreenGateway sends `POST {"session":"<cookie value>"}` and expects a 2xx JSON
//! object whose fields are mapped to `Principal` through the shared claim
//! resolver. `401`, `403`, and `404` mean the session was rejected; transport,
//! timeout, 5xx, and malformed successful responses are operational failures.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use http::{
    header::{ACCEPT, CONTENT_TYPE},
    HeaderMap, HeaderValue, Method, StatusCode,
};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tokio::time::timeout;

use crate::{
    config::AuthProviderConfig, egress::EgressClient, metrics::LOCK_POISON_RECOVERIES_TOTAL,
};

use super::{
    claims::{extract_roles, extract_string_claim},
    AuthError, AuthMethod, Principal, SessionCredential, SessionValidator,
};

const COOKIE_SESSION_CACHE_MAX_ENTRIES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CookieSessionAuthConfig {
    pub introspection_url: String,
    pub http_timeout: Duration,
    pub cache_ttl: Duration,
    pub user_id_claim: String,
    pub email_claim: Option<String>,
    pub org_claim: Option<String>,
    pub roles_claim: String,
    pub roles_claim_delimiter: Option<String>,
}

impl CookieSessionAuthConfig {
    pub fn from_provider_config(config: &AuthProviderConfig) -> Result<Self, AuthError> {
        let introspection_url =
            required_provider_field(&config.introspection_url, &config.name, "introspection_url")?;
        let user_id_claim =
            required_provider_field(&config.user_id_claim, &config.name, "user_id_claim")?;

        Ok(Self {
            introspection_url,
            http_timeout: Duration::from_millis(config.introspection_timeout_ms),
            cache_ttl: Duration::from_millis(config.cache_ttl_ms),
            user_id_claim,
            email_claim: config.email_claim.clone(),
            org_claim: config.org_claim.clone(),
            roles_claim: config.roles_claim.clone(),
            roles_claim_delimiter: config.roles_claim_delimiter.clone(),
        })
    }
}

pub struct CookieSessionValidator {
    cfg: CookieSessionAuthConfig,
    egress_client: Arc<EgressClient>,
    cache: CookieSessionValidationCache,
}

impl CookieSessionValidator {
    pub fn new(
        cfg: CookieSessionAuthConfig,
        egress_client: Arc<EgressClient>,
    ) -> Result<Self, AuthError> {
        Ok(Self {
            cache: CookieSessionValidationCache::new(cfg.cache_ttl),
            cfg,
            egress_client,
        })
    }

    #[allow(dead_code)] // Future session-admin hooks can evict a cached cookie value.
    pub fn invalidate_session(&self, cookie_value: &str) {
        self.cache.invalidate(&cache_key_for_cookie(cookie_value));
    }

    async fn introspect(
        &self,
        cookie_value: &str,
        session_id: String,
    ) -> Result<CachedSessionValidation, AuthError> {
        let body = serde_json::to_vec(&IntrospectionRequest {
            session: cookie_value,
        })
        .map_err(|err| {
            AuthError::Upstream(format!(
                "cookie-session introspection request could not be encoded: {err}"
            ))
        })?;
        let response = timeout(
            self.cfg.http_timeout,
            self.egress_client.request_with_headers(
                Method::POST,
                &self.cfg.introspection_url,
                introspection_headers(),
                Some(body),
            ),
        )
        .await
        .map_err(|_| AuthError::Upstream("cookie-session introspection timed out".to_owned()))?
        .map_err(|err| {
            tracing::warn!(error = %err, "cookie-session introspection through egress failed");
            AuthError::Upstream("cookie-session introspection failed".to_owned())
        })?;

        if invalid_session_status(response.status) {
            return Ok(CachedSessionValidation::Invalid(format!(
                "cookie-session introspection rejected session with status {}",
                response.status.as_u16()
            )));
        }

        if !response.status.is_success() {
            return Err(AuthError::Upstream(format!(
                "cookie-session introspection returned status {}",
                response.status.as_u16()
            )));
        }

        let body = serde_json::from_slice::<Value>(&response.body).map_err(|_| {
            AuthError::Upstream("cookie-session introspection returned invalid JSON".to_owned())
        })?;
        let Value::Object(claims) = body else {
            return Err(AuthError::Upstream(
                "cookie-session introspection response must be a JSON object".to_owned(),
            ));
        };

        self.principal_from_claims(&claims, session_id)
    }

    fn principal_from_claims(
        &self,
        claims: &Map<String, Value>,
        session_id: String,
    ) -> Result<CachedSessionValidation, AuthError> {
        let user_id = extract_string_claim(claims, Some(&self.cfg.user_id_claim))
            .map(|user_id| user_id.trim().to_owned())
            .filter(|user_id| !user_id.is_empty())
            .ok_or_else(|| {
                AuthError::Upstream(
                    "cookie-session introspection response missing user_id claim".to_owned(),
                )
            })?;
        let email = extract_string_claim(claims, self.cfg.email_claim.as_deref())
            .map(|email| email.trim().to_owned())
            .filter(|email| !email.is_empty())
            .map(|email| email.to_ascii_lowercase());
        let org_id = extract_string_claim(claims, self.cfg.org_claim.as_deref())
            .map(|org_id| org_id.trim().to_owned())
            .filter(|org_id| !org_id.is_empty());
        let roles = extract_roles(
            claims,
            &self.cfg.roles_claim,
            self.cfg.roles_claim_delimiter.as_deref(),
        );

        Ok(CachedSessionValidation::Valid(CachedValidSession {
            user_id,
            email,
            org_id,
            roles,
            session_id,
        }))
    }
}

#[async_trait::async_trait]
impl SessionValidator for CookieSessionValidator {
    async fn validate_session(
        &self,
        credential: &SessionCredential,
    ) -> Result<Principal, AuthError> {
        let SessionCredential::Cookie(cookie_value) = credential else {
            return Err(AuthError::InvalidSession(
                "cookie-session validator requires cookie credentials".to_owned(),
            ));
        };

        let cache_key = cache_key_for_cookie(cookie_value);
        if let Some(result) = self.cache.get(&cache_key) {
            return result.into_principal();
        }

        let session_id = format!("sha256:{cache_key}");
        let result = self.introspect(cookie_value, session_id).await?;
        self.cache.insert(cache_key, result.clone());
        result.into_principal()
    }

    fn supports_cookie(&self) -> bool {
        true
    }

    fn supports_bearer(&self) -> bool {
        false
    }
}

#[derive(Serialize)]
struct IntrospectionRequest<'a> {
    session: &'a str,
}

struct CookieSessionValidationCache {
    ttl: Duration,
    inner: Mutex<HashMap<String, CacheEntry<CachedSessionValidation>>>,
}

#[derive(Clone)]
enum CachedSessionValidation {
    Valid(CachedValidSession),
    Invalid(String),
}

#[derive(Clone)]
struct CachedValidSession {
    user_id: String,
    email: Option<String>,
    org_id: Option<String>,
    roles: Vec<String>,
    session_id: String,
}

struct CacheEntry<T> {
    value: T,
    expires_at: Instant,
}

impl CookieSessionValidationCache {
    fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(HashMap::new()),
        }
    }

    fn get(&self, key: &str) -> Option<CachedSessionValidation> {
        let now = Instant::now();
        self.inner_guard()
            .get(key)
            .and_then(|entry| entry.fresh_value(now))
    }

    fn insert(&self, key: String, value: CachedSessionValidation) {
        let now = Instant::now();
        let mut inner = self.inner_guard();
        inner.retain(|_, entry| entry.is_fresh(now));
        if inner.len() >= COOKIE_SESSION_CACHE_MAX_ENTRIES {
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

    #[allow(dead_code)] // Called by the public invalidation hook above.
    fn invalidate(&self, key: &str) {
        self.inner_guard().remove(key);
    }

    fn inner_guard(&self) -> MutexGuard<'_, HashMap<String, CacheEntry<CachedSessionValidation>>> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                ::metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "auth_cookie_session",
                    "lock" => "validation_cache"
                )
                .increment(1);
                tracing::error!("cookie-session validation cache lock poisoned; recovering");
                poisoned.into_inner()
            }
        }
    }
}

impl CachedSessionValidation {
    fn into_principal(self) -> Result<Principal, AuthError> {
        match self {
            Self::Valid(valid) => Ok(Principal {
                user_id: valid.user_id,
                email: valid.email,
                org_id: valid.org_id,
                roles: valid.roles,
                session_id: valid.session_id,
                auth_method: AuthMethod::Cookie,
            }),
            Self::Invalid(reason) => Err(AuthError::InvalidSession(reason)),
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

fn cache_key_for_cookie(cookie_value: &str) -> String {
    let digest = Sha256::digest(cookie_value.as_bytes());
    hex::encode(digest)
}

fn introspection_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers
}

fn invalid_session_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND
    )
}

fn required_provider_field(
    value: &Option<String>,
    provider_name: &str,
    field_name: &str,
) -> Result<String, AuthError> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            AuthError::Upstream(format!(
                "cookie-session auth provider '{provider_name}' is missing {field_name}"
            ))
        })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        io::ErrorKind,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
        time::Duration,
    };

    use serde_json::{json, Value};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    use super::{CookieSessionAuthConfig, CookieSessionValidator};
    use crate::{
        auth::{AuthError, AuthMethod, SessionCredential, SessionValidator},
        egress::{EgressClient, EgressConfig},
    };

    #[tokio::test]
    async fn valid_cookie_introspection_maps_principal_fields_from_json_claims() {
        let response_body = json!({
            "account": {
                "id": "user-123",
                "email": "User@Example.COM",
                "tenant": { "id": "org-456" },
                "scope": "admin member"
            }
        });
        let (url, server) = introspection_server(
            [TestResponse::json(StatusLine::Ok, response_body)],
            "127.0.0.1",
        )
        .await;
        let validator = validator(CookieSessionAuthConfig {
            introspection_url: url,
            http_timeout: Duration::from_secs(1),
            cache_ttl: Duration::from_secs(5),
            user_id_claim: "account.id".to_owned(),
            email_claim: Some("account.email".to_owned()),
            org_claim: Some("account.tenant.id".to_owned()),
            roles_claim: "account.scope".to_owned(),
            roles_claim_delimiter: Some(" ".to_owned()),
        });

        let principal = validator
            .validate_session(&SessionCredential::Cookie("session-secret-123".to_owned()))
            .await
            .expect("valid cookie should authenticate");

        assert_eq!(principal.user_id, "user-123");
        assert_eq!(principal.email, Some("user@example.com".to_owned()));
        assert_eq!(principal.org_id, Some("org-456".to_owned()));
        assert_eq!(principal.roles, vec!["admin", "member"]);
        assert_eq!(principal.auth_method, AuthMethod::Cookie);
        assert!(principal.session_id.starts_with("sha256:"));
        assert!(!principal.session_id.contains("session-secret-123"));

        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("POST /introspect HTTP/1.1"));
        assert!(requests[0].contains("content-type: application/json"));
        let body = request_body(&requests[0]);
        assert_eq!(body["session"], json!("session-secret-123"));
    }

    #[tokio::test]
    async fn invalid_cookie_response_maps_to_invalid_session() {
        let (url, _server) = introspection_server(
            [TestResponse::json(
                StatusLine::Unauthorized,
                json!({"error": "invalid_session"}),
            )],
            "127.0.0.1",
        )
        .await;
        let validator = validator(config(&url));

        let error = validator
            .validate_session(&SessionCredential::Cookie("bad-session".to_owned()))
            .await
            .expect_err("rejected cookie should fail validation");

        assert!(matches!(error, AuthError::InvalidSession(_)));
    }

    #[tokio::test]
    async fn upstream_status_and_malformed_success_body_map_to_upstream_errors() {
        for response in [
            TestResponse::json(StatusLine::InternalServerError, json!({"error": "down"})),
            TestResponse::raw(StatusLine::Ok, "not-json"),
        ] {
            let (url, _server) = introspection_server([response], "127.0.0.1").await;
            let validator = validator(config(&url));

            let error = validator
                .validate_session(&SessionCredential::Cookie("session".to_owned()))
                .await
                .expect_err("upstream failure should reject validation");

            assert!(matches!(error, AuthError::Upstream(_)));
        }
    }

    #[tokio::test]
    async fn introspection_timeout_maps_to_upstream_error() {
        let (url, _server) = introspection_server(
            [
                TestResponse::json(StatusLine::Ok, json!({"user_id": "user-123"}))
                    .with_delay(Duration::from_millis(200)),
            ],
            "127.0.0.1",
        )
        .await;
        let validator = validator(CookieSessionAuthConfig {
            http_timeout: Duration::from_millis(20),
            ..config(&url)
        });

        let error = validator
            .validate_session(&SessionCredential::Cookie("session".to_owned()))
            .await
            .expect_err("timeout should reject validation");

        assert!(matches!(error, AuthError::Upstream(_)));
    }

    #[tokio::test]
    async fn cached_cookie_result_skips_introspection_until_ttl_expires() {
        let (url, server) = introspection_server(
            [
                TestResponse::json(StatusLine::Ok, json!({"user_id": "user-123"})),
                TestResponse::json(StatusLine::Ok, json!({"user_id": "user-123"})),
            ],
            "127.0.0.1",
        )
        .await;
        let validator = validator(CookieSessionAuthConfig {
            cache_ttl: Duration::from_millis(30),
            ..config(&url)
        });
        let credential = SessionCredential::Cookie("cached-session".to_owned());

        validator
            .validate_session(&credential)
            .await
            .expect("first request should introspect");
        validator
            .validate_session(&credential)
            .await
            .expect("second request should use cache");
        assert_eq!(server.call_count(), 1);

        tokio::time::sleep(Duration::from_millis(60)).await;
        validator
            .validate_session(&credential)
            .await
            .expect("request after TTL should introspect again");

        assert_eq!(server.call_count(), 2);
    }

    #[tokio::test]
    async fn validator_accepts_only_cookie_credentials() {
        let (url, _server) = introspection_server(
            [TestResponse::json(
                StatusLine::Ok,
                json!({"user_id": "user-123"}),
            )],
            "127.0.0.1",
        )
        .await;
        let validator = validator(config(&url));

        assert!(validator.supports_cookie());
        assert!(!validator.supports_bearer());
        let error = validator
            .validate_session(&SessionCredential::Bearer("token".to_owned()))
            .await
            .expect_err("bearer credentials should not be accepted");
        assert!(matches!(error, AuthError::InvalidSession(_)));
    }

    fn validator(config: CookieSessionAuthConfig) -> CookieSessionValidator {
        CookieSessionValidator::new(config, egress_client()).expect("validator should build")
    }

    fn config(url: &str) -> CookieSessionAuthConfig {
        CookieSessionAuthConfig {
            introspection_url: url.to_owned(),
            http_timeout: Duration::from_secs(1),
            cache_ttl: Duration::from_secs(5),
            user_id_claim: "user_id".to_owned(),
            email_claim: None,
            org_claim: None,
            roles_claim: "roles".to_owned(),
            roles_claim_delimiter: None,
        }
    }

    fn egress_client() -> Arc<EgressClient> {
        Arc::new(
            EgressClient::new(EgressConfig {
                allowed_hosts: HashSet::from(["127.0.0.1".to_owned()]),
                deny_private_ips: false,
                ..EgressConfig::default()
            })
            .expect("egress client should build"),
        )
    }

    async fn introspection_server(
        responses: impl IntoIterator<Item = TestResponse>,
        host: &'static str,
    ) -> (String, TestServer) {
        let listener = TcpListener::bind((host, 0))
            .await
            .expect("introspection test server should bind");
        let addr = listener
            .local_addr()
            .expect("introspection test server address should be available");
        let responses = responses.into_iter().collect::<Vec<_>>();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let call_count = Arc::new(AtomicUsize::new(0));
        let server_requests = Arc::clone(&requests);
        let server_call_count = Arc::clone(&call_count);
        let handle = tokio::spawn(async move {
            for response in responses {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .expect("introspection test server should accept request");
                server_call_count.fetch_add(1, Ordering::SeqCst);
                let request = read_request(&mut stream).await;
                server_requests
                    .lock()
                    .expect("request log should not be poisoned")
                    .push(request);
                if let Some(delay) = response.delay {
                    tokio::time::sleep(delay).await;
                }
                write_response(&mut stream, &response).await;
            }
        });

        (
            format!("http://{host}:{}/introspect", addr.port()),
            TestServer {
                handle,
                requests,
                call_count,
            },
        )
    }

    struct TestServer {
        handle: tokio::task::JoinHandle<()>,
        requests: Arc<Mutex<Vec<String>>>,
        call_count: Arc<AtomicUsize>,
    }

    impl TestServer {
        fn call_count(&self) -> usize {
            self.call_count.load(Ordering::SeqCst)
        }

        fn requests(&self) -> Vec<String> {
            self.requests
                .lock()
                .expect("request log should not be poisoned")
                .clone()
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    struct TestResponse {
        status: StatusLine,
        body: String,
        delay: Option<Duration>,
    }

    impl TestResponse {
        fn json(status: StatusLine, body: Value) -> Self {
            Self::raw(status, &body.to_string())
        }

        fn raw(status: StatusLine, body: &str) -> Self {
            Self {
                status,
                body: body.to_owned(),
                delay: None,
            }
        }

        fn with_delay(mut self, delay: Duration) -> Self {
            self.delay = Some(delay);
            self
        }
    }

    #[derive(Clone, Copy)]
    enum StatusLine {
        Ok,
        Unauthorized,
        InternalServerError,
    }

    impl StatusLine {
        fn as_str(self) -> &'static str {
            match self {
                Self::Ok => "200 OK",
                Self::Unauthorized => "401 Unauthorized",
                Self::InternalServerError => "500 Internal Server Error",
            }
        }
    }

    async fn read_request(stream: &mut TcpStream) -> String {
        let mut buffer = Vec::new();
        let mut chunk = [0; 1024];
        loop {
            let read = stream
                .read(&mut chunk)
                .await
                .expect("request read should succeed");
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if has_complete_request(&buffer) {
                break;
            }
        }

        String::from_utf8(buffer).expect("request should be UTF-8")
    }

    fn has_complete_request(buffer: &[u8]) -> bool {
        let Some(header_end) = find_header_end(buffer) else {
            return false;
        };
        let headers = String::from_utf8_lossy(&buffer[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);

        buffer.len() >= header_end + 4 + content_length
    }

    fn find_header_end(buffer: &[u8]) -> Option<usize> {
        buffer.windows(4).position(|window| window == b"\r\n\r\n")
    }

    async fn write_response(stream: &mut TcpStream, response: &TestResponse) {
        let bytes = format!(
            "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response.status.as_str(),
            response.body.len(),
            response.body
        )
        .into_bytes();
        if let Err(err) = stream.write_all(&bytes).await {
            assert_eq!(
                err.kind(),
                ErrorKind::BrokenPipe,
                "unexpected response write error: {err}"
            );
        }
    }

    fn request_body(request: &str) -> Value {
        let body = request
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .expect("request should contain body separator");
        serde_json::from_str(body).expect("request body should be JSON")
    }
}
