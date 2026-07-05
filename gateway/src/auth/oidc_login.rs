//! OIDC authorization-code + PKCE login support for the admin UI.
//!
//! This module initiates an OAuth client flow only for the admin UI. The
//! resulting access token is still used by the existing bearer-token validator;
//! this module does not create a parallel server-side session.

use std::{
    collections::HashMap,
    error::Error,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use http::{
    header::{ACCEPT, CONTENT_TYPE},
    HeaderMap, HeaderValue, Method, StatusCode,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::time::timeout;
use url::Url;
use uuid::Uuid;

use crate::{egress::EgressClient, metrics::LOCK_POISON_RECOVERIES_TOTAL};

use super::{AuthError, JwtAuthConfig, JwtValidator};

const ADMIN_LOGIN_PENDING_TTL: Duration = Duration::from_secs(5 * 60);
const ADMIN_LOGIN_PENDING_MAX_ENTRIES: usize = 1024;
const PKCE_VERIFIER_RANDOM_BYTES: usize = 32;
const OIDC_SCOPE: &str = "openid email profile";

#[derive(Clone, Eq, PartialEq)]
pub struct OidcLoginConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub issuer: String,
    pub jwks_url: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub http_timeout: Duration,
}

impl fmt::Debug for OidcLoginConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcLoginConfig")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("redirect_uri", &self.redirect_uri)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .field("token_endpoint", &self.token_endpoint)
            .field("http_timeout", &self.http_timeout)
            .finish()
    }
}

#[derive(Clone)]
pub struct OidcLoginState {
    cfg: Arc<OidcLoginConfig>,
    egress_client: Arc<EgressClient>,
    id_token_validator: Arc<JwtValidator>,
    pending: Arc<PendingLoginStore>,
}

#[derive(Debug)]
pub struct LoginStart {
    pub authorization_url: String,
}

#[derive(Debug)]
pub struct TokenExchange {
    pub access_token: String,
}

#[derive(Debug)]
pub enum OidcLoginError {
    Random(getrandom::Error),
    InvalidAuthorizationEndpoint(String),
    InvalidState,
    TokenExchangeTimedOut,
    TokenExchangeFailed,
    InvalidTokenResponse,
    MissingAccessToken,
    InvalidIdToken,
}

impl fmt::Display for OidcLoginError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Random(err) => write!(formatter, "OIDC login random generation failed: {err}"),
            Self::InvalidAuthorizationEndpoint(err) => {
                write!(formatter, "OIDC authorization endpoint is invalid: {err}")
            }
            Self::InvalidState => write!(formatter, "OIDC login state is unknown or expired"),
            Self::TokenExchangeTimedOut => write!(formatter, "OIDC token exchange timed out"),
            Self::TokenExchangeFailed => write!(formatter, "OIDC token exchange failed"),
            Self::InvalidTokenResponse => write!(formatter, "OIDC token response is invalid"),
            Self::MissingAccessToken => {
                write!(formatter, "OIDC token response missing access_token")
            }
            Self::InvalidIdToken => write!(formatter, "OIDC id_token validation failed"),
        }
    }
}

impl Error for OidcLoginError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Random(err) => Some(err),
            _ => None,
        }
    }
}

impl OidcLoginError {
    pub fn is_invalid_state(&self) -> bool {
        matches!(self, Self::InvalidState)
    }
}

impl OidcLoginState {
    pub fn new(cfg: OidcLoginConfig, egress_client: Arc<EgressClient>) -> Result<Self, AuthError> {
        let id_token_validator = JwtValidator::new(
            JwtAuthConfig {
                jwks_url: cfg.jwks_url.clone(),
                issuer: Some(cfg.issuer.clone()),
                audience: Some(cfg.client_id.clone()),
                http_timeout: cfg.http_timeout,
                require_jti: false,
                roles_claim: "roles".to_owned(),
                roles_claim_delimiter: None,
                org_claim: None,
            },
            Arc::clone(&egress_client),
        )?;

        Ok(Self {
            cfg: Arc::new(cfg),
            egress_client,
            id_token_validator: Arc::new(id_token_validator),
            pending: Arc::new(PendingLoginStore::new(ADMIN_LOGIN_PENDING_TTL)),
        })
    }

    pub fn begin_login(&self) -> Result<LoginStart, OidcLoginError> {
        let state = Uuid::new_v4().to_string();
        let nonce = Uuid::new_v4().to_string();
        let pkce = PkcePair::generate()?;
        let authorization_url = self.authorization_url(&state, &nonce, &pkce.code_challenge)?;

        self.pending.insert(
            state,
            PendingLogin {
                code_verifier: pkce.code_verifier,
                nonce,
                created_at: Instant::now(),
            },
        );

        Ok(LoginStart { authorization_url })
    }

    pub async fn exchange_code(
        &self,
        code: &str,
        state: &str,
    ) -> Result<TokenExchange, OidcLoginError> {
        let Some(pending) = self.pending.take(state) else {
            return Err(OidcLoginError::InvalidState);
        };

        self.exchange_code_with_pending(code, pending).await
    }

    fn authorization_url(
        &self,
        state: &str,
        nonce: &str,
        code_challenge: &str,
    ) -> Result<String, OidcLoginError> {
        let mut url = Url::parse(&self.cfg.authorization_endpoint)
            .map_err(|err| OidcLoginError::InvalidAuthorizationEndpoint(err.to_string()))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.cfg.client_id)
            .append_pair("redirect_uri", &self.cfg.redirect_uri)
            .append_pair("scope", OIDC_SCOPE)
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", code_challenge)
            .append_pair("code_challenge_method", "S256");

        Ok(url.into())
    }

    async fn exchange_code_with_pending(
        &self,
        code: &str,
        pending: PendingLogin,
    ) -> Result<TokenExchange, OidcLoginError> {
        let PendingLogin {
            code_verifier,
            nonce,
            created_at: _,
        } = pending;

        let body = token_exchange_body(
            code,
            &self.cfg.redirect_uri,
            &self.cfg.client_id,
            &self.cfg.client_secret,
            &code_verifier,
        );
        let response = timeout(
            self.cfg.http_timeout,
            self.egress_client.request_with_headers(
                Method::POST,
                &self.cfg.token_endpoint,
                token_exchange_headers(),
                Some(body),
            ),
        )
        .await
        .map_err(|_| OidcLoginError::TokenExchangeTimedOut)?
        .map_err(|err| {
            tracing::warn!(error = %err, "OIDC token exchange through egress failed");
            OidcLoginError::TokenExchangeFailed
        })?;

        if response.status != StatusCode::OK && !response.status.is_success() {
            tracing::warn!(
                status = response.status.as_u16(),
                "OIDC token endpoint returned non-success status"
            );
            return Err(OidcLoginError::TokenExchangeFailed);
        }

        let token_response = serde_json::from_slice::<TokenResponse>(&response.body)
            .map_err(|_| OidcLoginError::InvalidTokenResponse)?;
        let access_token = token_response
            .access_token
            .map(|token| token.trim().to_owned())
            .filter(|token| !token.is_empty())
            .ok_or(OidcLoginError::MissingAccessToken)?;

        if let Some(id_token) = token_response.id_token {
            let id_token = id_token.trim();
            if id_token.is_empty() {
                return Err(OidcLoginError::InvalidIdToken);
            }
            self.id_token_validator
                .validate_oidc_id_token_nonce(id_token, &nonce)
                .await
                .map_err(|err| {
                    tracing::warn!(error = %err, "OIDC id_token validation failed");
                    OidcLoginError::InvalidIdToken
                })?;
        }

        Ok(TokenExchange { access_token })
    }
}

#[derive(Debug)]
struct PkcePair {
    code_verifier: String,
    code_challenge: String,
}

impl PkcePair {
    fn generate() -> Result<Self, OidcLoginError> {
        let mut random = [0u8; PKCE_VERIFIER_RANDOM_BYTES];
        getrandom::fill(&mut random).map_err(OidcLoginError::Random)?;
        let code_verifier = base64url_no_padding(&random);
        let code_challenge = base64url_no_padding(&Sha256::digest(code_verifier.as_bytes()));

        Ok(Self {
            code_verifier,
            code_challenge,
        })
    }
}

struct PendingLogin {
    code_verifier: String,
    nonce: String,
    created_at: Instant,
}

struct PendingLoginStore {
    ttl: Duration,
    inner: Mutex<HashMap<String, PendingLogin>>,
}

impl PendingLoginStore {
    fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(HashMap::new()),
        }
    }

    fn insert(&self, state: String, pending: PendingLogin) {
        let mut inner = self.inner_guard();
        remove_expired_pending_logins(&mut inner, self.ttl);
        if inner.len() >= ADMIN_LOGIN_PENDING_MAX_ENTRIES {
            if let Some(oldest_key) = inner
                .iter()
                .min_by_key(|(_, pending)| pending.created_at)
                .map(|(state, _)| state.clone())
            {
                inner.remove(&oldest_key);
            }
        }
        inner.insert(state, pending);
    }

    fn take(&self, state: &str) -> Option<PendingLogin> {
        let mut inner = self.inner_guard();
        remove_expired_pending_logins(&mut inner, self.ttl);
        inner.remove(state)
    }

    fn inner_guard(&self) -> MutexGuard<'_, HashMap<String, PendingLogin>> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                ::metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "auth_oidc_login",
                    "lock" => "pending_login"
                )
                .increment(1);
                tracing::error!("OIDC pending-login lock poisoned; recovering");
                poisoned.into_inner()
            }
        }
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    id_token: Option<String>,
}

fn remove_expired_pending_logins(inner: &mut HashMap<String, PendingLogin>, ttl: Duration) {
    let now = Instant::now();
    inner.retain(|_, pending| {
        now.checked_duration_since(pending.created_at)
            .is_some_and(|age| age < ttl)
    });
}

fn token_exchange_body(
    code: &str,
    redirect_uri: &str,
    client_id: &str,
    client_secret: &str,
    code_verifier: &str,
) -> Vec<u8> {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("client_id", client_id)
        .append_pair("client_secret", client_secret)
        .append_pair("code_verifier", code_verifier);
    serializer.finish().into_bytes()
}

fn token_exchange_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers
}

fn base64url_no_padding(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(b0 >> 2) as usize] as char);
        output.push(ALPHABET[(((b0 & 0b0000_0011) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[(((b1 & 0b0000_1111) << 2) | (b2 >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(b2 & 0b0011_1111) as usize] as char);
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oidc_login_config_debug_redacts_client_secret() {
        let secret = "oidc-client-secret-value";
        let config = OidcLoginConfig {
            client_id: "admin-ui".to_owned(),
            client_secret: secret.to_owned(),
            redirect_uri: "https://gateway.example.test/v1/admin/auth/callback".to_owned(),
            authorization_endpoint: "https://issuer.example.test/oauth2/authorize".to_owned(),
            token_endpoint: "https://issuer.example.test/oauth2/token".to_owned(),
            http_timeout: Duration::from_secs(2),
        };

        let output = format!("{config:?}");

        assert!(!output.contains(secret));
        assert!(output.contains("<redacted>"));
        assert!(output.contains("client_secret"));
    }
}
