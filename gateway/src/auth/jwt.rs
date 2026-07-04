use std::{
    collections::HashMap,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use http::Method;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::{Map, Value};
use tokio::{
    sync::{Mutex, RwLock},
    time::timeout,
};

use crate::{config::Config, egress::EgressClient};

use super::{AuthError, AuthMethod, Principal, SessionCredential, SessionValidator};

const INVALID_TOKEN: &str = "invalid or expired token";
const MIN_JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

/// JWT bearer-token validator configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JwtAuthConfig {
    /// JWKS endpoint containing RS256 public keys.
    pub jwks_url: String,
    /// Optional expected `iss` claim.
    pub issuer: Option<String>,
    /// Optional expected `aud` claim.
    pub audience: Option<String>,
    /// Timeout for JWKS HTTP fetches.
    pub http_timeout: Duration,
    /// Reject tokens without a non-empty `jti` claim.
    pub require_jti: bool,
    /// Flat string-array claim name used to extract roles.
    pub roles_claim: String,
}

impl JwtAuthConfig {
    pub fn from_config(config: &Config) -> Option<Self> {
        Some(Self {
            jwks_url: config.jwt_jwks_url.clone()?,
            issuer: config.jwt_issuer.clone(),
            audience: config.jwt_audience.clone(),
            http_timeout: Duration::from_millis(config.jwt_jwks_timeout_ms),
            require_jti: config.jwt_require_jti,
            roles_claim: config.roles_claim.clone(),
        })
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

/// RS256 JWT bearer-token validator backed by a kid-indexed JWKS key cache.
pub struct JwtValidator {
    cfg: JwtAuthConfig,
    egress_client: Arc<EgressClient>,
    keys: Arc<RwLock<HashMap<String, DecodingKey>>>,
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
            .finish_non_exhaustive()
    }
}

impl JwtValidator {
    pub fn new(cfg: JwtAuthConfig, egress_client: Arc<EgressClient>) -> Result<Self, AuthError> {
        Self::with_keys(
            cfg,
            egress_client,
            Arc::new(NoopRevocationStore),
            HashMap::new(),
        )
    }

    #[allow(dead_code)] // Future wiring can supply a real jti revocation store.
    pub fn new_with_revocation(
        cfg: JwtAuthConfig,
        egress_client: Arc<EgressClient>,
        revocation: Arc<dyn RevocationStore>,
    ) -> Result<Self, AuthError> {
        Self::with_keys(cfg, egress_client, revocation, HashMap::new())
    }

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
        initial_keys: HashMap<String, DecodingKey>,
    ) -> Result<Self, AuthError> {
        Self::with_keys(cfg, egress_client, revocation, initial_keys)
    }

    fn with_keys(
        cfg: JwtAuthConfig,
        egress_client: Arc<EgressClient>,
        revocation: Arc<dyn RevocationStore>,
        initial_keys: HashMap<String, DecodingKey>,
    ) -> Result<Self, AuthError> {
        Ok(Self {
            cfg,
            egress_client,
            keys: Arc::new(RwLock::new(initial_keys)),
            last_jwks_refresh: Arc::new(Mutex::new(None)),
            revocation,
        })
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
            tracing::warn!(error = %err, "JWKS fetch through egress failed");
            AuthError::Upstream("JWKS fetch failed".to_owned())
        })?;

        if !response.status.is_success() {
            return Err(AuthError::Upstream("JWKS fetch failed".to_owned()));
        }

        let jwks = serde_json::from_slice::<JwksResponse>(&response.body)
            .map_err(|_| AuthError::Upstream("invalid JWKS response".to_owned()))?;
        let mut refreshed = HashMap::new();

        for key in jwks.keys {
            if key.kty.as_deref() != Some("RSA") {
                continue;
            }

            let (Some(kid), Some(n), Some(e)) = (key.kid, key.n, key.e) else {
                continue;
            };

            if let Ok(decoding_key) = DecodingKey::from_rsa_components(&n, &e) {
                refreshed.insert(kid, decoding_key);
            }
        }

        *self.keys.write().await = refreshed;
        Ok(())
    }

    async fn decode(&self, token: &str) -> Result<JwtClaims, AuthError> {
        let header = decode_header(token).map_err(|_| invalid_token())?;
        let kid = header
            .kid
            .ok_or_else(|| AuthError::InvalidSession("unknown kid".to_owned()))?;

        if let Some(key) = self.keys.read().await.get(&kid).cloned() {
            return self.decode_with_key(token, &key);
        }

        if !self.refresh_jwks().await? {
            return Err(AuthError::InvalidSession("unknown kid".to_owned()));
        }

        if let Some(key) = self.keys.read().await.get(&kid).cloned() {
            return self.decode_with_key(token, &key);
        }

        Err(AuthError::InvalidSession("unknown kid".to_owned()))
    }

    fn decode_with_key(&self, token: &str, key: &DecodingKey) -> Result<JwtClaims, AuthError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;
        validation.validate_aud = self.cfg.audience.is_some();
        let mut required = vec!["exp"];

        if let Some(issuer) = &self.cfg.issuer {
            validation.set_issuer(&[issuer.as_str()]);
            required.push("iss");
        }

        if let Some(audience) = &self.cfg.audience {
            validation.set_audience(&[audience.as_str()]);
            required.push("aud");
        }

        validation.set_required_spec_claims(&required);

        decode::<JwtClaims>(token, key, &validation)
            .map(|token_data| token_data.claims)
            .map_err(|_| invalid_token())
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
        let roles = extract_roles(&claims.extra, &self.cfg.roles_claim);
        let session_id = jti.unwrap_or("-").to_owned();

        Ok(Principal {
            user_id: user_id.to_owned(),
            email,
            org_id: None,
            roles,
            session_id,
            auth_method: AuthMethod::Bearer,
        })
    }
}

#[async_trait::async_trait]
impl SessionValidator for JwtValidator {
    async fn validate_session(
        &self,
        credential: &SessionCredential,
    ) -> Result<Principal, AuthError> {
        match credential {
            SessionCredential::Cookie(_) => Err(AuthError::InvalidSession(
                "jwt validator only supports bearer tokens".to_owned(),
            )),
            SessionCredential::Bearer(token) => {
                let claims = self.decode(token).await?;
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
}

#[derive(Debug, Deserialize)]
struct JwtClaims {
    sub: String,
    email: Option<String>,
    #[allow(dead_code)] // jsonwebtoken validates `exp`; GreenGateway does not read it directly.
    exp: Option<u64>,
    jti: Option<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

fn extract_roles(extra: &Map<String, Value>, claim_name: &str) -> Vec<String> {
    // Nested/provider-specific role claim shapes are out of scope for this phase.
    match extra.get(claim_name).and_then(Value::as_array) {
        Some(values) if values.iter().all(Value::is_string) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

fn invalid_token() -> AuthError {
    AuthError::InvalidSession(INVALID_TOKEN.to_owned())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        io::ErrorKind,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;
    use tokio::net::{TcpListener, TcpStream};

    use crate::egress::{EgressClient, EgressConfig};

    use super::*;

    const KID: &str = "test-kid";
    const TEST_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCnhXdj9xmwS1xg
0FSkz/Czegzbs7x52/LjNeVoaKsKFiiZh2X6TfeNv9FBHlqaP4crN3ONOutajg2o
jVy2LqOlmX0oWOsu7s9x1SZoy18N5jtOw/knSsYDc4y6ir/0H/WNRf+qMZXo/ZGU
eDU0C2fONU0XXaGWD3ypaQeqClnSInMIIjpJ0gATyGPJVNuVgmdeYdkNBdmlOKrX
dsRg7UjAmt9WXgCm6w1MRAIeZJ6cTNhQ5cx0JBVZRxeNRcVDpXx+IW6QC+HWTcbr
GxGpNzC1AaY9q67VyV/nLypaLF2m4SyKrYbkf5azoyH7zkpvpb6mgJPjdYlhO5M8
dVHvbB81AgMBAAECggEAByEJ7KomYLdETiZvg7gJsUmfZHYorjLrCjpP8fqKVNqO
jcISV+2bfF/OYuwMxQWxFei9NSRtwaPL9wFVEbe4ZSK8DcyC7bNiBqEgilMlT20d
1wNGBiMLfDgdpA6ljpkRlRqGf9KuY4Tu/heDhBx8JW1lQ3pLlxw/nOIIXnckTWny
I5qOpk5XZ/QzJNC2ze0F2VsQ5RAGNdDG9vKHm5qeYHzgM1z9SOUMXsfPYOiXvdZP
BPa59BdP7cmXDVCuh12ZhpVnDErYtA9iPXqmoAah14JP4xKju5QIvavsQt9S8gB5
cxhAu4LmT9p1iOsKaDsG44gxUzmHS0bcuoIgFzDh4QKBgQDp3q9If/ZfZuu3+NPr
F/o36JvUY5SPnbYf1p5hSyBkVhTzKyGiYq7W0Lxs/RcOhw8YlfNfzqRNnhjmZhlE
FXpUCSXVSAtdC3MpCx2XimZltJ+TdIzajeWmh2Wx6SpJJek10UL2n6ht2BBALWyz
Dt2s709dVlxfYwHnZWBe4xxJTQKBgQC3X4prVHXcIKTyNyMS8cC/iMgbOu+Q58CF
VnBuRWsL96vzrHUgUcoYNTPbMOjm98Wzrk2roW+fnDMp0Y8ZusceKOVraihDifN2
yQ2H053ctC8YEvZeOE6JlDq+llAGnRv+113pmfZ51qNeVFcwdR5ujhAunnW7UC28
+IGqI3H5iQKBgQDik2iUP8zsbqTuLrb5K9iyM7xND1DNtsjMnbwBnKw8KR3Q3LeQ
QDUNT1tN6AFfhL++XQBVkLijrgiHpuDRklFaeyZZNJw1v7MJT4iS2XYNEOoNDLyt
vQ2BwelnbPMXvQ/soNlUYCfoi4xq8Nc/vqZLNepZDiMeEqi0iwXLyBIOfQKBgQCv
wF1to2TXF16gXCI8vQKNUO7h0mncS5Mk+QUHW3dO4BGpmegkkt+Mtik+czE2ddHB
9lSxJChVJSOQeC6cbXz8thu1COkQWn7Doc1bGoLaDsR4YWxKP9NeX3iyRGTtAdXc
OdTj2VH30rV/6nwqkIYbVgPCetPCNQWxccjtJc3OaQKBgHGijhVSMmlnGeAIiPmq
0hj0A9bv7QQz5M2TS+yuhQjHDJWa4Asic+AkgfOu5belhSDd13QCou1r8CcUc9uv
mu96vvRxLhwFLatFo4mL0WnOwBvMrR+5YwboH7Er4PBhmVJ2UKiQn8bNX3qdhVTp
O2gecI9QwDJNpm29J9wJB2F8
-----END PRIVATE KEY-----"#;
    const TEST_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp4V3Y/cZsEtcYNBUpM/w
s3oM27O8edvy4zXlaGirChYomYdl+k33jb/RQR5amj+HKzdzjTrrWo4NqI1cti6j
pZl9KFjrLu7PcdUmaMtfDeY7TsP5J0rGA3OMuoq/9B/1jUX/qjGV6P2RlHg1NAtn
zjVNF12hlg98qWkHqgpZ0iJzCCI6SdIAE8hjyVTblYJnXmHZDQXZpTiq13bEYO1I
wJrfVl4ApusNTEQCHmSenEzYUOXMdCQVWUcXjUXFQ6V8fiFukAvh1k3G6xsRqTcw
tQGmPauu1clf5y8qWixdpuEsiq2G5H+Ws6Mh+85Kb6W+poCT43WJYTuTPHVR72wf
NQIDAQAB
-----END PUBLIC KEY-----"#;
    const TEST_PUBLIC_KEY_N: &str = "p4V3Y_cZsEtcYNBUpM_ws3oM27O8edvy4zXlaGirChYomYdl-k33jb_RQR5amj-HKzdzjTrrWo4NqI1cti6jpZl9KFjrLu7PcdUmaMtfDeY7TsP5J0rGA3OMuoq_9B_1jUX_qjGV6P2RlHg1NAtnzjVNF12hlg98qWkHqgpZ0iJzCCI6SdIAE8hjyVTblYJnXmHZDQXZpTiq13bEYO1IwJrfVl4ApusNTEQCHmSenEzYUOXMdCQVWUcXjUXFQ6V8fiFukAvh1k3G6xsRqTcwtQGmPauu1clf5y8qWixdpuEsiq2G5H-Ws6Mh-85Kb6W-poCT43WJYTuTPHVR72wfNQ";
    const TEST_PUBLIC_KEY_E: &str = "AQAB";
    const OTHER_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw/aUzeUUmwEI8FZH92NP
GVGZMV+rP6qUJSiRXlRvaNzj6Pr0vn6NrZtyiAwixyGRkzzVeoCNVek1U1eBOliJ
AF64QSM/9n4lxNLS5IyC/hm5swMdVwF4HQkvMVAoH2dskDVEw3cGWd8wEG/O8R2o
Wlxz8TC7nQxW0Aq24Rt64qUfgD2Q5AqlI4Wysc+KkD57MsNems+Fsj/JdpttjP5R
D06N4uTKth9Tvy8REyk8gqnvUm80RsHMIMjTzFyH2pMxKGVZ8YkFqubhfhBYaMK1
Mqr96rIzKrhNTlduosMC0/W5cHRPnTk3eGcnFRa5QIJ/uLJcX8WT5pKzPiIAX4Tx
mQIDAQAB
-----END PUBLIC KEY-----"#;

    #[derive(Debug)]
    struct StaticRevocationStore {
        revoked: HashSet<String>,
    }

    #[async_trait::async_trait]
    impl RevocationStore for StaticRevocationStore {
        async fn is_revoked(&self, jti: &str) -> Result<bool, AuthError> {
            Ok(self.revoked.contains(jti))
        }
    }

    #[tokio::test]
    async fn valid_rs256_token_returns_principal_with_default_roles() {
        let validator = validator(
            default_cfg(),
            Arc::new(NoopRevocationStore),
            TEST_PUBLIC_KEY,
        );
        let token = signed_token(base_claims(), TEST_PRIVATE_KEY);

        let principal = validator
            .validate_session(&SessionCredential::Bearer(token))
            .await
            .expect("valid token should produce a principal");

        assert_eq!(principal.user_id, "user-123");
        assert_eq!(principal.email, Some("user@example.com".to_owned()));
        assert_eq!(principal.roles, vec!["admin", "member"]);
        assert_eq!(principal.session_id, "session-123");
        assert_eq!(principal.auth_method, AuthMethod::Bearer);
    }

    #[tokio::test]
    async fn configurable_roles_claim_extracts_groups_and_default_roles_stays_empty() {
        let mut claims = base_claims();
        let object = claims.as_object_mut().expect("claims should be an object");
        object.remove("roles");
        object.insert("groups".to_owned(), json!(["team-a", "team-b"]));
        let token = signed_token(claims, TEST_PRIVATE_KEY);

        let mut groups_cfg = default_cfg();
        groups_cfg.roles_claim = "groups".to_owned();
        let groups_validator =
            validator(groups_cfg, Arc::new(NoopRevocationStore), TEST_PUBLIC_KEY);
        let groups_principal = groups_validator
            .validate_session(&SessionCredential::Bearer(token.clone()))
            .await
            .expect("groups claim should validate");

        let roles_validator = validator(
            default_cfg(),
            Arc::new(NoopRevocationStore),
            TEST_PUBLIC_KEY,
        );
        let roles_principal = roles_validator
            .validate_session(&SessionCredential::Bearer(token))
            .await
            .expect("default roles claim should validate");

        assert_eq!(groups_principal.roles, vec!["team-a", "team-b"]);
        assert!(roles_principal.roles.is_empty());
    }

    #[tokio::test]
    async fn email_is_lowercased() {
        let validator = validator(
            default_cfg(),
            Arc::new(NoopRevocationStore),
            TEST_PUBLIC_KEY,
        );
        let mut claims = base_claims();
        claims["email"] = json!("USER@EXAMPLE.COM");
        let token = signed_token(claims, TEST_PRIVATE_KEY);

        let principal = validator
            .validate_session(&SessionCredential::Bearer(token))
            .await
            .expect("valid token should produce a principal");

        assert_eq!(principal.email, Some("user@example.com".to_owned()));
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let validator = validator(
            default_cfg(),
            Arc::new(NoopRevocationStore),
            TEST_PUBLIC_KEY,
        );
        let mut claims = base_claims();
        claims["exp"] = json!(past_timestamp());
        let token = signed_token(claims, TEST_PRIVATE_KEY);

        let error = validator
            .validate_session(&SessionCredential::Bearer(token))
            .await
            .expect_err("expired token should be rejected");

        assert_invalid_session(error, INVALID_TOKEN);
    }

    #[tokio::test]
    async fn wrong_issuer_is_rejected() {
        let mut cfg = default_cfg();
        cfg.issuer = Some("https://expected.example.test/".to_owned());
        let validator = validator(cfg, Arc::new(NoopRevocationStore), TEST_PUBLIC_KEY);
        let mut claims = base_claims();
        claims["iss"] = json!("https://other.example.test/");
        let token = signed_token(claims, TEST_PRIVATE_KEY);

        let error = validator
            .validate_session(&SessionCredential::Bearer(token))
            .await
            .expect_err("wrong issuer should be rejected");

        assert_invalid_session(error, INVALID_TOKEN);
    }

    #[tokio::test]
    async fn wrong_audience_is_rejected() {
        let mut cfg = default_cfg();
        cfg.audience = Some("expected-audience".to_owned());
        let validator = validator(cfg, Arc::new(NoopRevocationStore), TEST_PUBLIC_KEY);
        let mut claims = base_claims();
        claims["aud"] = json!("other-audience");
        let token = signed_token(claims, TEST_PRIVATE_KEY);

        let error = validator
            .validate_session(&SessionCredential::Bearer(token))
            .await
            .expect_err("wrong audience should be rejected");

        assert_invalid_session(error, INVALID_TOKEN);
    }

    #[tokio::test]
    async fn missing_audience_is_rejected_when_audience_is_configured() {
        let mut cfg = default_cfg();
        cfg.audience = Some("expected-audience".to_owned());
        let validator = validator(cfg, Arc::new(NoopRevocationStore), TEST_PUBLIC_KEY);
        let token = signed_token(base_claims(), TEST_PRIVATE_KEY);

        let error = validator
            .validate_session(&SessionCredential::Bearer(token))
            .await
            .expect_err("missing audience should be rejected when audience is configured");

        assert_invalid_session(error, INVALID_TOKEN);
    }

    #[tokio::test]
    async fn missing_issuer_is_rejected_when_issuer_is_configured() {
        let mut cfg = default_cfg();
        cfg.issuer = Some("https://expected.example.test/".to_owned());
        let validator = validator(cfg, Arc::new(NoopRevocationStore), TEST_PUBLIC_KEY);
        let token = signed_token(base_claims(), TEST_PRIVATE_KEY);

        let error = validator
            .validate_session(&SessionCredential::Bearer(token))
            .await
            .expect_err("missing issuer should be rejected when issuer is configured");

        assert_invalid_session(error, INVALID_TOKEN);
    }

    #[tokio::test]
    async fn missing_issuer_and_audience_are_allowed_when_not_configured() {
        let validator = validator(
            default_cfg(),
            Arc::new(NoopRevocationStore),
            TEST_PUBLIC_KEY,
        );
        let token = signed_token(base_claims(), TEST_PRIVATE_KEY);

        let principal = validator
            .validate_session(&SessionCredential::Bearer(token))
            .await
            .expect("missing issuer and audience should be allowed by default");

        assert_eq!(principal.user_id, "user-123");
    }

    #[tokio::test]
    async fn bad_signature_is_rejected() {
        let validator = validator(
            default_cfg(),
            Arc::new(NoopRevocationStore),
            OTHER_PUBLIC_KEY,
        );
        let token = signed_token(base_claims(), TEST_PRIVATE_KEY);

        let error = validator
            .validate_session(&SessionCredential::Bearer(token))
            .await
            .expect_err("bad signature should be rejected");

        assert_invalid_session(error, INVALID_TOKEN);
    }

    #[tokio::test]
    async fn cookie_credential_is_rejected() {
        let validator = validator(
            default_cfg(),
            Arc::new(NoopRevocationStore),
            TEST_PUBLIC_KEY,
        );

        let error = validator
            .validate_session(&SessionCredential::Cookie("session=abc".to_owned()))
            .await
            .expect_err("cookie credential should be rejected");

        assert_invalid_session(error, "jwt validator only supports bearer tokens");
        assert!(!validator.supports_cookie());
        assert!(validator.supports_bearer());
    }

    #[tokio::test]
    async fn require_jti_rejects_missing_jti_and_allows_when_disabled() {
        let mut claims = base_claims();
        claims
            .as_object_mut()
            .expect("claims should be an object")
            .remove("jti");
        let token = signed_token(claims, TEST_PRIVATE_KEY);

        let mut require_jti_cfg = default_cfg();
        require_jti_cfg.require_jti = true;
        let require_jti_validator = validator(
            require_jti_cfg,
            Arc::new(NoopRevocationStore),
            TEST_PUBLIC_KEY,
        );
        let error = require_jti_validator
            .validate_session(&SessionCredential::Bearer(token.clone()))
            .await
            .expect_err("missing jti should be rejected when required");

        let optional_jti_validator = validator(
            default_cfg(),
            Arc::new(NoopRevocationStore),
            TEST_PUBLIC_KEY,
        );
        let principal = optional_jti_validator
            .validate_session(&SessionCredential::Bearer(token))
            .await
            .expect("missing jti should be accepted when not required");

        assert_invalid_session(error, "missing jti");
        assert_eq!(principal.session_id, "-");
    }

    #[tokio::test]
    async fn revoked_jti_is_rejected_and_noop_revocation_allows() {
        let token = signed_token(base_claims(), TEST_PRIVATE_KEY);
        let revoked = Arc::new(StaticRevocationStore {
            revoked: HashSet::from(["session-123".to_owned()]),
        });
        let revoked_validator = validator(default_cfg(), revoked, TEST_PUBLIC_KEY);

        let error = revoked_validator
            .validate_session(&SessionCredential::Bearer(token.clone()))
            .await
            .expect_err("revoked jti should be rejected");

        let noop_validator = validator(
            default_cfg(),
            Arc::new(NoopRevocationStore),
            TEST_PUBLIC_KEY,
        );
        let principal = noop_validator
            .validate_session(&SessionCredential::Bearer(token))
            .await
            .expect("noop revocation store should allow the token");

        assert_invalid_session(error, "revoked_token");
        assert_eq!(principal.session_id, "session-123");
    }

    #[tokio::test]
    async fn jwt_validator_is_usable_as_dyn_session_validator() {
        let validator: Arc<dyn SessionValidator> = Arc::new(validator(
            default_cfg(),
            Arc::new(NoopRevocationStore),
            TEST_PUBLIC_KEY,
        ));
        let token = signed_token(base_claims(), TEST_PRIVATE_KEY);

        let principal = validator
            .validate_session(&SessionCredential::Bearer(token))
            .await
            .expect("dyn validator should validate the token");

        assert_eq!(principal.user_id, "user-123");
        assert_eq!(principal.auth_method, AuthMethod::Bearer);
    }

    #[tokio::test]
    async fn unknown_kid_fetches_jwks_through_egress_and_validates_token() {
        let jwks = json!({
            "keys": [{
                "kty": "RSA",
                "kid": KID,
                "use": "sig",
                "alg": "RS256",
                "n": TEST_PUBLIC_KEY_N,
                "e": TEST_PUBLIC_KEY_E
            }]
        })
        .to_string();
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("JWKS test server should bind");
        let addr = listener
            .local_addr()
            .expect("JWKS test server address should be available");
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("JWKS test server should accept one request");
            read_one_request(&stream).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                jwks.len(),
                jwks
            );
            write_all(&stream, response.as_bytes()).await;
        });
        let mut cfg = default_cfg();
        cfg.jwks_url = format!("http://127.0.0.1:{}/.well-known/jwks.json", addr.port());
        let mut config = test_config(Some(&cfg.jwks_url));
        config.egress_deny_private_ips = false;
        let egress_config = EgressConfig::from_config(&config);

        assert!(config.egress_allowed_hosts.is_empty());
        assert!(egress_config.allowed_hosts.contains("127.0.0.1"));

        let egress_client =
            Arc::new(EgressClient::new(egress_config).expect("test egress client should build"));
        let validator = JwtValidator::new(cfg, egress_client).expect("validator should build");
        let token = signed_token(base_claims(), TEST_PRIVATE_KEY);

        let principal = validator
            .validate_session(&SessionCredential::Bearer(token))
            .await
            .expect("JWKS-fetched key should validate the token");

        assert_eq!(principal.user_id, "user-123");
        assert_eq!(principal.email, Some("user@example.com".to_owned()));
        server.await.expect("JWKS test server task should finish");
    }

    #[test]
    fn from_config_returns_none_without_jwks_url() {
        let config = test_config(None);

        let validator = JwtValidator::from_config(&config, test_egress_client())
            .expect("validator construction should not fail");

        assert!(validator.is_none());
    }

    #[test]
    fn from_config_builds_validator_when_jwks_url_is_set() {
        let config = test_config(Some("https://issuer.example.test/jwks.json"));

        let validator = JwtValidator::from_config(&config, test_egress_client())
            .expect("validator construction should not fail");

        assert!(validator.is_some());
    }

    fn validator(
        cfg: JwtAuthConfig,
        revocation: Arc<dyn RevocationStore>,
        public_key: &str,
    ) -> JwtValidator {
        JwtValidator::new_with_keys(
            cfg,
            test_egress_client(),
            revocation,
            decoding_keys(public_key),
        )
        .expect("validator should build")
    }

    fn test_egress_client() -> Arc<EgressClient> {
        egress_client(HashSet::from(["issuer.example.test".to_owned()]), false)
    }

    fn egress_client(allowed_hosts: HashSet<String>, deny_private_ips: bool) -> Arc<EgressClient> {
        Arc::new(
            EgressClient::new(EgressConfig {
                allowed_hosts,
                deny_private_ips,
                ..EgressConfig::default()
            })
            .expect("test egress client should build"),
        )
    }

    fn decoding_keys(public_key: &str) -> HashMap<String, DecodingKey> {
        HashMap::from([(
            KID.to_owned(),
            DecodingKey::from_rsa_pem(public_key.as_bytes())
                .expect("test RSA public key should parse"),
        )])
    }

    fn signed_token(mut claims: Value, private_key: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KID.to_owned());
        claims
            .as_object_mut()
            .expect("claims should be an object")
            .entry("exp")
            .or_insert_with(|| json!(future_timestamp()));

        encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(private_key.as_bytes())
                .expect("test RSA private key should parse"),
        )
        .expect("test token should sign")
    }

    fn base_claims() -> Value {
        json!({
            "sub": "user-123",
            "email": "User@Example.COM",
            "exp": future_timestamp(),
            "jti": "session-123",
            "roles": ["admin", "member"]
        })
    }

    fn default_cfg() -> JwtAuthConfig {
        JwtAuthConfig {
            jwks_url: "https://issuer.example.test/.well-known/jwks.json".to_owned(),
            issuer: None,
            audience: None,
            http_timeout: Duration::from_secs(1),
            require_jti: false,
            roles_claim: "roles".to_owned(),
        }
    }

    fn test_config(jwks_url: Option<&str>) -> Config {
        Config {
            listen_addr: "127.0.0.1:0"
                .parse()
                .expect("test listen address should parse"),
            admin_listen_addr: None,
            admin_prefix: "/admin".to_owned(),
            audit_log_file: None,
            audit_sqlite_path: None,
            audit_sqlite_retention_days: None,
            discovery_sqlite_path: None,
            policy_file: None,
            cors_allow_origins: Vec::new(),
            max_body_size: 1_048_576,
            rate_limit_read_rps: 50.0,
            rate_limit_read_burst: 100,
            rate_limit_write_rps: 10.0,
            rate_limit_write_burst: 20,
            trust_proxy_headers: false,
            rbac_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
            session_cookie_name: String::new(),
            validation_allowed_content_types: vec!["application/json".to_owned()],
            auth_enabled: true,
            auth_mode: crate::config::AuthMode::Required,
            auth_cookie_name: "session".to_owned(),
            auth_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
            jwt_jwks_url: jwks_url.map(str::to_owned),
            jwt_issuer: None,
            jwt_audience: None,
            jwt_jwks_timeout_ms: 2000,
            jwt_require_jti: false,
            roles_claim: "roles".to_owned(),
            csrf_enabled: true,
            csrf_cookie_name: "csrf_token".to_owned(),
            csrf_header_name: "x-csrf-token".to_owned(),
            csrf_cookie_domain: None,
            csrf_exempt_paths: vec![
                "/health".to_owned(),
                "/version".to_owned(),
                "/metrics".to_owned(),
            ],
            upstream_url: None,
            upstream_routes: Vec::new(),
            upstream_timeout_ms: None,
            upstream_response_idle_timeout_ms: None,
            upstream_connect_timeout_ms: None,
            egress_allowed_hosts: Vec::new(),
            egress_timeout_ms: 30_000,
            egress_response_idle_timeout_ms: 30_000,
            egress_connect_timeout_ms: 10_000,
            egress_max_response_bytes: 5_242_880,
            egress_max_request_body_bytes: 1_048_576,
            egress_deny_private_ips: true,
        }
    }

    fn future_timestamp() -> u64 {
        now_seconds() + 3600
    }

    fn past_timestamp() -> u64 {
        now_seconds() - 3600
    }

    fn now_seconds() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after Unix epoch")
            .as_secs()
    }

    fn assert_invalid_session(error: AuthError, expected: &str) {
        match error {
            AuthError::InvalidSession(message) => assert_eq!(message, expected),
            AuthError::Upstream(message) => {
                panic!("expected invalid session, got upstream error: {message}")
            }
        }
    }

    async fn read_one_request(stream: &TcpStream) {
        let mut buffer = [0; 1024];

        loop {
            stream
                .readable()
                .await
                .expect("test stream should become readable");

            match stream.try_read(&mut buffer) {
                Ok(_) => return,
                Err(err) if err.kind() == ErrorKind::WouldBlock => continue,
                Err(err) => panic!("failed to read test request: {err}"),
            }
        }
    }

    async fn write_all(stream: &TcpStream, bytes: &[u8]) {
        let mut written = 0;

        while written < bytes.len() {
            stream
                .writable()
                .await
                .expect("test stream should become writable");

            match stream.try_write(&bytes[written..]) {
                Ok(0) => panic!("test stream closed before response was written"),
                Ok(count) => written += count,
                Err(err) if err.kind() == ErrorKind::WouldBlock => continue,
                Err(err) => panic!("failed to write test response: {err}"),
            }
        }
    }
}
