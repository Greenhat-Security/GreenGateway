//! Opt-in, single-process admin sessions. There is deliberately no HA fallback.
//!
//! Cookies contain independent random capabilities; only their digests index
//! the bounded memory store. Access tokens stay on the server and the selected
//! OIDC provider's existing bearer validator remains the authority on every
//! request. Restart, expiry, and logout discard the capability. No refresh
//! token is requested or retained.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use http::{header, HeaderMap, HeaderValue};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{AuthError, AuthMethod, Principal, SessionCredential, SessionValidator};

const INVALID: &str = "admin session is unknown, expired, or revoked";
const UNAVAILABLE: &str = "admin session authority is unavailable";

#[derive(Clone, Debug, PartialEq)]
pub struct AdminSessionConfig {
    pub ttl: Duration,
    pub max_entries: usize,
}

#[derive(Clone)]
pub struct AdminSessions {
    config: AdminSessionConfig,
    authority: Arc<dyn SessionValidator>,
    store: Arc<Mutex<SessionStore>>,
    pub cookie_name: String,
    pub api_prefix: String,
    pub origin: String,
}

struct StoredSession {
    token: Arc<Zeroizing<String>>,
    expires_at: Instant,
    identity: (String, Option<String>),
    // Independent, non-credential identifier: never use the cookie in a Principal.
    id: String,
}

#[derive(Default)]
struct SessionStore {
    entries: HashMap<[u8; 32], StoredSession>,
    attempts: HashMap<[u8; 32], LoginAttempt>,
}

struct LoginAttempt {
    expires_at: Instant,
    issued: Option<[u8; 32]>,
}

pub struct IssuedSession {
    pub cookie: HeaderValue,
    pub expires_in: u64,
}

impl fmt::Debug for IssuedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedSession")
            .field("cookie", &"<redacted>")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

impl AdminSessions {
    pub fn new(
        config: AdminSessionConfig,
        authority: Arc<dyn SessionValidator>,
        admin_prefix: &str,
        origin: String,
    ) -> Result<Self, AuthError> {
        if config.ttl.as_secs() == 0
            || config.ttl > Duration::from_secs(86_400)
            || config.max_entries == 0
            || config.max_entries > 100_000
            || !origin.starts_with("https://")
            || !authority.supports_bearer()
        {
            return Err(AuthError::Upstream(
                "invalid admin session configuration".to_owned(),
            ));
        }
        let namespace = hex::encode(Sha256::digest(admin_prefix.as_bytes()));
        Ok(Self {
            config,
            authority,
            store: Arc::new(Mutex::new(SessionStore::default())),
            cookie_name: format!("__Host-ggw-admin-session-{}", &namespace[..16]),
            api_prefix: format!("/v1{admin_prefix}/"),
            origin,
        })
    }

    pub fn ttl_seconds(&self) -> u64 {
        self.config.ttl.as_secs()
    }

    /// Track the binding until its pending-login TTL so logout can cancel a
    /// completion already awaiting the IdP, or revoke an issued cookie whose
    /// response has not yet reached the browser. This registry is bounded too.
    pub fn begin_login(
        &self,
        binding: &str,
        ttl: Duration,
        headers: &HeaderMap,
    ) -> Result<(), AuthError> {
        let mut store = self
            .store
            .lock()
            .map_err(|_| AuthError::Upstream(UNAVAILABLE.to_owned()))?;
        let now = Instant::now();
        let expires_at = now
            .checked_add(ttl)
            .ok_or_else(|| AuthError::Upstream(UNAVAILABLE.to_owned()))?;
        let SessionStore { entries, attempts } = &mut *store;
        entries.retain(|_, entry| entry.expires_at > now);
        attempts.retain(|_, attempt| {
            attempt.expires_at > now && attempt.issued.is_none_or(|key| entries.contains_key(&key))
        });
        // Presenting the issued capability proves its response arrived. The
        // pending binding is no longer needed to cancel an undelivered cookie.
        if let Some(value) = self.credential(headers) {
            let key = digest(&value);
            store
                .attempts
                .retain(|_, attempt| attempt.issued != Some(key));
        }
        if store.attempts.len() >= self.config.max_entries {
            return Err(AuthError::Upstream(
                "admin session login registry is at capacity".to_owned(),
            ));
        }
        store.attempts.insert(
            digest(binding),
            LoginAttempt {
                expires_at,
                issued: None,
            },
        );
        Ok(())
    }

    /// Called only after browser-bound OIDC completion. The ID token proves
    /// the login transaction; the selected provider validates the access token
    /// before a session can carry its identity.
    pub async fn issue(
        &self,
        token: String,
        headers: &HeaderMap,
        binding: &str,
    ) -> Result<IssuedSession, AuthError> {
        let token = Zeroizing::new(token);
        if token.is_empty() || token.len() > 32_768 {
            return Err(AuthError::InvalidSession(INVALID.to_owned()));
        }
        let principal = self
            .authority
            .validate_session(&SessionCredential::Bearer(token.to_string()))
            .await?;
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|_| AuthError::Upstream(UNAVAILABLE.to_owned()))?;
        let value = Zeroizing::new(hex::encode(random));
        let key = digest(&value);
        let cookie = self.cookie(&value, self.ttl_seconds())?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| AuthError::Upstream(UNAVAILABLE.to_owned()))?;
        let now = Instant::now();
        if !store
            .attempts
            .get(&digest(binding))
            .is_some_and(|attempt| attempt.expires_at > now && attempt.issued.is_none())
        {
            return Err(AuthError::InvalidSession(INVALID.to_owned()));
        }
        store.entries.retain(|_, entry| entry.expires_at > now);
        // Successful identity replacement revokes the prior session atomically.
        // Do not remove a prior session if admission would fail.
        let previous = self.credential(headers).map(|value| digest(&value));
        let replaces = previous.is_some_and(|key| store.entries.contains_key(&key));
        if store.entries.len() >= self.config.max_entries && !replaces {
            return Err(AuthError::Upstream(
                "admin session store is at capacity".to_owned(),
            ));
        }
        if let Some(previous) = previous {
            store.entries.remove(&previous);
        }
        if let Some(attempt) = store.attempts.get_mut(&digest(binding)) {
            attempt.issued = Some(key);
        }
        store.entries.insert(
            key,
            StoredSession {
                token: Arc::new(token),
                expires_at: now + self.config.ttl,
                identity: (principal.user_id, principal.issuer),
                id: uuid::Uuid::new_v4().to_string(),
            },
        );
        Ok(IssuedSession {
            cookie,
            expires_in: self.ttl_seconds(),
        })
    }

    /// A duplicate or malformed named cookie stays selected, but is invalid;
    /// it must never fall through to a different identity provider.
    pub fn credential(&self, headers: &HeaderMap) -> Option<String> {
        let mut values = headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|header| header.to_str().ok())
            .flat_map(|header| header.split(';'))
            .filter_map(|pair| pair.trim().split_once('='))
            .filter(|(name, _)| *name == self.cookie_name)
            .map(|(_, value)| value);
        let value = values.next()?;
        Some(if values.next().is_some() {
            String::new()
        } else {
            value.to_owned()
        })
    }

    pub fn origin_matches(&self, headers: &HeaderMap) -> bool {
        let mut origins = headers.get_all(header::ORIGIN).iter();
        origins.next().and_then(|origin| origin.to_str().ok()) == Some(self.origin.as_str())
            && origins.next().is_none()
    }

    pub fn revoke(&self, headers: &HeaderMap, binding: Option<&str>) -> Result<(), AuthError> {
        let mut store = self
            .store
            .lock()
            .map_err(|_| AuthError::Upstream(UNAVAILABLE.to_owned()))?;
        if let Some(value) = self.credential(headers) {
            let key = digest(&value);
            store.entries.remove(&key);
            store
                .attempts
                .retain(|_, attempt| attempt.issued != Some(key));
        }
        if let Some(binding) = binding {
            if let Some(attempt) = store.attempts.remove(&digest(binding)) {
                if let Some(key) = attempt.issued {
                    store.entries.remove(&key);
                }
            }
        }
        Ok(())
    }

    pub fn expired_cookie(&self) -> Result<HeaderValue, AuthError> {
        self.cookie("", 0)
    }

    fn cookie(&self, value: &str, max_age: u64) -> Result<HeaderValue, AuthError> {
        let mut cookie = HeaderValue::from_str(&format!(
            "{}={value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age}",
            self.cookie_name
        ))
        .map_err(|_| AuthError::Upstream(UNAVAILABLE.to_owned()))?;
        cookie.set_sensitive(true);
        Ok(cookie)
    }
}

fn digest(value: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"greengateway.admin-session.v1\0");
    hasher.update(value.as_bytes());
    hasher.finalize().into()
}

#[async_trait::async_trait]
impl SessionValidator for AdminSessions {
    async fn validate_session(
        &self,
        credential: &SessionCredential,
    ) -> Result<Principal, AuthError> {
        let SessionCredential::Cookie(value) = credential else {
            return Err(AuthError::InvalidSession(INVALID.to_owned()));
        };
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(AuthError::InvalidSession(INVALID.to_owned()));
        }
        let key = digest(value);
        let token = {
            let mut store = self
                .store
                .lock()
                .map_err(|_| AuthError::Upstream(UNAVAILABLE.to_owned()))?;
            if store
                .entries
                .get(&key)
                .is_some_and(|entry| entry.expires_at <= Instant::now())
            {
                store.entries.remove(&key);
            }
            store
                .entries
                .get(&key)
                .map(|entry| Arc::clone(&entry.token))
                .ok_or_else(|| AuthError::InvalidSession(INVALID.to_owned()))?
        };
        let result = self
            .authority
            .validate_session(&SessionCredential::Bearer(token.to_string()))
            .await;
        let mut store = self
            .store
            .lock()
            .map_err(|_| AuthError::Upstream(UNAVAILABLE.to_owned()))?;
        // Recheck after the await: logout/expiry during validation wins. The
        // request may be admitted only while its server session still exists.
        let entry = store
            .entries
            .get(&key)
            .filter(|entry| entry.expires_at > Instant::now())
            .ok_or_else(|| AuthError::InvalidSession(INVALID.to_owned()))?;
        match result {
            Ok(mut principal)
                if entry.identity == (principal.user_id.clone(), principal.issuer.clone()) =>
            {
                principal.auth_method = AuthMethod::Cookie;
                principal.session_id = entry.id.clone();
                store
                    .attempts
                    .retain(|_, attempt| attempt.issued != Some(key));
                Ok(principal)
            }
            Err(error @ AuthError::Upstream(_)) => Err(error),
            _ => {
                store.entries.remove(&key);
                Err(AuthError::InvalidSession(INVALID.to_owned()))
            }
        }
    }

    fn supports_cookie(&self) -> bool {
        true
    }
    fn supports_bearer(&self) -> bool {
        false
    }
}

#[cfg(test)]
#[path = "admin_session_tests.rs"]
mod tests;
