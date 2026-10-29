//! Opt-in, gateway-issued admin sessions (issue #424, ADR-0009).
//!
//! Cookies contain independent random capabilities; only purpose-separated
//! digests of them reach a store. Access tokens stay on the server and the
//! selected OIDC provider's existing bearer validator remains the authority
//! on every request. Expiry, logout, a rejected access token and an identity
//! change end a session. No refresh token is requested or retained.
//!
//! One contract ([`AdminSessionStore`]), two stores, each valid in exactly
//! one state backend:
//!
//! - `standalone_memory` ([`MemoryAdminSessionStore`]): a bounded map in
//!   this process. There is deliberately no HA fallback, and a restart
//!   discards every session.
//! - `cluster_postgres` (`storage::postgres_admin_sessions`): rows on the
//!   PostgreSQL primary that every replica reads on every request, with the
//!   access token sealed under the admin login keyring.
//!
//! [`AdminSessions`] owns what the two share: the cookie, the exact-origin
//! check, the CSRF binding, provider revalidation and the identity
//! comparison. A store owns persistence, both deadlines and capacity.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use http::{header, HeaderMap, HeaderValue, Method};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{AuthError, AuthMethod, Principal, SessionCredential, SessionValidator};

const INVALID: &str = "admin session is unknown, expired, or revoked";
const UNAVAILABLE: &str = "admin session authority is unavailable";

/// The longest absolute session lifetime, in seconds.
pub const MAX_SESSION_TTL_SECS: u64 = 86_400;
/// The most sessions, and the most pending cookie logins, a store holds.
pub const MAX_SESSION_ENTRIES: usize = 100_000;
/// The largest access token a session holds, in bytes.
pub const MAX_ACCESS_TOKEN_BYTES: usize = 32_768;

const PURPOSE_SESSION: &str = "session";
const PURPOSE_BINDING: &str = "binding";
const PURPOSE_CSRF: &str = "csrf";

/// Where issued sessions live. Each store is valid in exactly one state
/// backend; configuration refuses every other combination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminSessionStorage {
    /// A bounded map in this process (`STATE_BACKEND=sqlite` only).
    StandaloneMemory,
    /// Rows on the PostgreSQL primary (`STATE_BACKEND=postgres` only).
    ClusterPostgres,
}

impl AdminSessionStorage {
    /// The `ADMIN_SESSION_MODE` value, also advertised as `storage`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StandaloneMemory => "standalone_memory",
            Self::ClusterPostgres => "cluster_postgres",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AdminSessionConfig {
    pub storage: AdminSessionStorage,
    /// The absolute lifetime. Requests never extend it.
    pub ttl: Duration,
    /// The inactivity limit, at most `ttl`; equal to `ttl` it never binds.
    pub idle_timeout: Duration,
    pub max_entries: usize,
}

impl AdminSessionConfig {
    fn is_valid(&self) -> bool {
        self.ttl.as_secs() > 0
            && self.ttl <= Duration::from_secs(MAX_SESSION_TTL_SECS)
            && self.idle_timeout.as_secs() > 0
            && self.idle_timeout <= self.ttl
            && self.max_entries > 0
            && self.max_entries <= MAX_SESSION_ENTRIES
    }
}

/// A purpose-separated SHA-256 digest of a session secret: the only form in
/// which a session cookie, a login binding or a CSRF token reaches a store.
pub type SessionDigest = [u8; 32];

/// One live session, as a store returns it.
#[derive(Clone)]
pub struct StoredSession {
    /// The provider access token, revalidated on every request. A store
    /// protects it at rest; this copy is wiped on drop.
    pub token: Zeroizing<String>,
    pub user_id: String,
    pub issuer: Option<String>,
    /// Independent, non-credential identifier: never use the cookie in a Principal.
    pub id: String,
    /// The digest of the double-submit token presented at issuance.
    pub csrf: SessionDigest,
}

/// A session to admit for a pending cookie login.
pub struct SessionGrant {
    pub key: SessionDigest,
    pub binding: SessionDigest,
    /// The session this browser presented. A successful grant withdraws it.
    pub previous: Option<SessionDigest>,
    pub session: StoredSession,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantOutcome {
    Granted,
    /// The binding has no live, unissued cookie login: it was never begun,
    /// has expired, was cancelled by logout, or was already issued.
    NoPendingLogin,
    /// The store is full and the grant would not replace a live session.
    AtCapacity,
}

/// The storage contract both session stores implement. Every method that
/// cannot consult its store answers `AuthError::Upstream`, never a verdict.
#[async_trait::async_trait]
pub trait AdminSessionStore: Send + Sync {
    /// The domain separator every digest is computed under: the deployment
    /// ID in cluster mode.
    fn namespace(&self) -> &str;

    /// Track a pending cookie login for `binding` until `ttl` passes, so
    /// logout can cancel a completion already awaiting the IdP, or an issued
    /// cookie whose response has not reached the browser. `delivered` is a
    /// session the browser presented: presenting it proves its response
    /// arrived, so no pending login needs to track it. `false` at capacity.
    async fn begin_login(
        &self,
        binding: &SessionDigest,
        ttl: Duration,
        delivered: Option<&SessionDigest>,
    ) -> Result<bool, AuthError>;

    /// Admit a session for its pending login, withdrawing `previous` in the
    /// same step. Nothing changes unless the grant is admitted.
    async fn grant(&self, grant: SessionGrant) -> Result<GrantOutcome, AuthError>;

    /// The live session for `key`, judged on the store's clock.
    async fn lookup(&self, key: &SessionDigest) -> Result<Option<StoredSession>, AuthError>;

    /// After the provider accepted the token: admit the request only while
    /// the same session is still live, move its idle deadline (never past
    /// its absolute one), and release any pending login still tracking it.
    async fn admit(&self, key: &SessionDigest, id: &str) -> Result<bool, AuthError>;

    /// The provider rejected the token, or it names another identity.
    async fn reject(&self, key: &SessionDigest, id: &str) -> Result<(), AuthError>;

    /// Logout: withdraw the presented session, and cancel the pending login
    /// for `binding` together with any session issued for it. Idempotent.
    async fn withdraw(
        &self,
        key: Option<&SessionDigest>,
        binding: Option<&SessionDigest>,
    ) -> Result<(), AuthError>;
}

#[derive(Clone)]
pub struct AdminSessions {
    config: AdminSessionConfig,
    authority: Arc<dyn SessionValidator>,
    store: Arc<dyn AdminSessionStore>,
    csrf_header: String,
    pub cookie_name: String,
    pub api_prefix: String,
    pub origin: String,
}

/// Why a presented session did not authenticate a request.
#[derive(Debug)]
pub enum SessionRefusal {
    /// Unknown, expired, revoked or rejected (`InvalidSession`), or the
    /// authority could not decide (`Upstream`).
    Auth(AuthError),
    /// An unsafe request carried a CSRF token other than the one the session
    /// was issued with.
    CsrfUnbound,
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

/// Methods that change nothing: they need no exact origin and no CSRF
/// binding.
pub fn is_safe_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

impl AdminSessions {
    pub fn new(
        config: AdminSessionConfig,
        authority: Arc<dyn SessionValidator>,
        store: Arc<dyn AdminSessionStore>,
        admin_prefix: &str,
        origin: String,
        csrf_header: &str,
    ) -> Result<Self, AuthError> {
        if !config.is_valid()
            || !origin.starts_with("https://")
            || !authority.supports_bearer()
            || csrf_header.is_empty()
        {
            return Err(AuthError::Upstream(
                "invalid admin session configuration".to_owned(),
            ));
        }
        let namespace = hex::encode(Sha256::digest(admin_prefix.as_bytes()));
        Ok(Self {
            config,
            authority,
            store,
            csrf_header: csrf_header.to_owned(),
            cookie_name: format!("__Host-ggw-admin-session-{}", &namespace[..16]),
            api_prefix: format!("/v1{admin_prefix}/"),
            origin,
        })
    }

    pub fn storage(&self) -> AdminSessionStorage {
        self.config.storage
    }

    pub fn ttl_seconds(&self) -> u64 {
        self.config.ttl.as_secs()
    }

    /// Track the binding until its pending-login TTL so logout can cancel a
    /// completion already awaiting the IdP, or revoke an issued cookie whose
    /// response has not yet reached the browser. This registry is bounded too.
    pub async fn begin_login(
        &self,
        binding: &str,
        ttl: Duration,
        headers: &HeaderMap,
    ) -> Result<(), AuthError> {
        let delivered = self
            .credential(headers)
            .map(|value| self.digest(PURPOSE_SESSION, &value));
        let binding = self.digest(PURPOSE_BINDING, binding);
        if self
            .store
            .begin_login(&binding, ttl, delivered.as_ref())
            .await?
        {
            Ok(())
        } else {
            Err(AuthError::Upstream(
                "admin session login registry is at capacity".to_owned(),
            ))
        }
    }

    /// Called only after browser-bound OIDC completion. The ID token proves
    /// the login transaction; the selected provider validates the access token
    /// before a session can carry its identity. The session is bound to the
    /// double-submit token `csrf` the completion presented.
    pub async fn issue(
        &self,
        token: String,
        headers: &HeaderMap,
        binding: &str,
        csrf: &str,
    ) -> Result<IssuedSession, AuthError> {
        let token = Zeroizing::new(token);
        if token.is_empty() || token.len() > MAX_ACCESS_TOKEN_BYTES || csrf.is_empty() {
            return Err(AuthError::InvalidSession(INVALID.to_owned()));
        }
        let principal = self
            .authority
            .validate_session(&SessionCredential::Bearer(token.to_string()))
            .await?;
        let mut random = [0u8; 32];
        getrandom::fill(&mut random).map_err(|_| AuthError::Upstream(UNAVAILABLE.to_owned()))?;
        let value = Zeroizing::new(hex::encode(random));
        let cookie = self.cookie(&value, self.ttl_seconds())?;
        let grant = SessionGrant {
            key: self.digest(PURPOSE_SESSION, &value),
            binding: self.digest(PURPOSE_BINDING, binding),
            // Successful identity replacement revokes the prior session
            // atomically; a refused grant leaves it alone.
            previous: self
                .credential(headers)
                .map(|value| self.digest(PURPOSE_SESSION, &value)),
            session: StoredSession {
                token,
                user_id: principal.user_id,
                issuer: principal.issuer,
                id: uuid::Uuid::new_v4().to_string(),
                csrf: self.digest(PURPOSE_CSRF, csrf),
            },
        };
        match self.store.grant(grant).await? {
            GrantOutcome::Granted => Ok(IssuedSession {
                cookie,
                expires_in: self.ttl_seconds(),
            }),
            GrantOutcome::NoPendingLogin => Err(AuthError::InvalidSession(INVALID.to_owned())),
            GrantOutcome::AtCapacity => Err(AuthError::Upstream(
                "admin session store is at capacity".to_owned(),
            )),
        }
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

    /// Authenticate one admin API request by its session cookie `value`. An
    /// unsafe `method` must also present, in the configured CSRF header, the
    /// token the session was issued with; the global double-submit check has
    /// already matched that header against the CSRF cookie.
    pub async fn authenticate(
        &self,
        value: &str,
        method: &Method,
        headers: &HeaderMap,
    ) -> Result<Principal, SessionRefusal> {
        let (key, session) = self
            .live_session(value)
            .await
            .map_err(SessionRefusal::Auth)?;
        if !is_safe_method(method)
            && self
                .presented_csrf(headers)
                .map(|token| self.digest(PURPOSE_CSRF, token))
                != Some(session.csrf)
        {
            return Err(SessionRefusal::CsrfUnbound);
        }
        let mut principal = self
            .provider_principal(&key, &session)
            .await
            .map_err(SessionRefusal::Auth)?;
        // Recheck after the await: logout/expiry during validation wins.
        // The request is admitted only while its session still exists.
        if !self
            .store
            .admit(&key, &session.id)
            .await
            .map_err(SessionRefusal::Auth)?
        {
            return Err(SessionRefusal::Auth(AuthError::InvalidSession(
                INVALID.to_owned(),
            )));
        }
        principal.auth_method = AuthMethod::Cookie;
        principal.session_id = session.id;
        Ok(principal)
    }

    /// Judge the session cookie `value` again for a request that was already
    /// admitted with it and is still answering: the admin audit event stream.
    ///
    /// The same checks as [`AdminSessions::authenticate`] -- the session is
    /// live, the provider still accepts its token for the same identity, and
    /// it is still live afterwards, so a logout during validation wins -- but
    /// it is not a new request: it needs no CSRF token, and it does not move
    /// the idle deadline. Watching a stream is not activity, so an open
    /// stream cannot keep an idle session alive.
    pub async fn reauthenticate(&self, value: &str) -> Result<Principal, AuthError> {
        let (key, session) = self.live_session(value).await?;
        let mut principal = self.provider_principal(&key, &session).await?;
        match self.store.lookup(&key).await? {
            Some(current) if current.id == session.id => {}
            _ => return Err(AuthError::InvalidSession(INVALID.to_owned())),
        }
        principal.auth_method = AuthMethod::Cookie;
        principal.session_id = session.id;
        Ok(principal)
    }

    /// The live session for cookie `value`, with its store key.
    async fn live_session(&self, value: &str) -> Result<(SessionDigest, StoredSession), AuthError> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(AuthError::InvalidSession(INVALID.to_owned()));
        }
        let key = self.digest(PURPOSE_SESSION, value);
        let session = self
            .store
            .lookup(&key)
            .await?
            .ok_or_else(|| AuthError::InvalidSession(INVALID.to_owned()))?;
        Ok((key, session))
    }

    /// Ask the provider about `session`'s token. A rejection, or a token
    /// that now names another identity, withdraws the session; an
    /// unavailable provider leaves it alone.
    async fn provider_principal(
        &self,
        key: &SessionDigest,
        session: &StoredSession,
    ) -> Result<Principal, AuthError> {
        let result = self
            .authority
            .validate_session(&SessionCredential::Bearer(session.token.to_string()))
            .await;
        match result {
            Ok(principal)
                if principal.user_id == session.user_id && principal.issuer == session.issuer =>
            {
                Ok(principal)
            }
            Err(error @ AuthError::Upstream(_)) => Err(error),
            _ => {
                self.store.reject(key, &session.id).await?;
                Err(AuthError::InvalidSession(INVALID.to_owned()))
            }
        }
    }

    pub async fn revoke(
        &self,
        headers: &HeaderMap,
        binding: Option<&str>,
    ) -> Result<(), AuthError> {
        let key = self
            .credential(headers)
            .map(|value| self.digest(PURPOSE_SESSION, &value));
        let binding = binding.map(|binding| self.digest(PURPOSE_BINDING, binding));
        self.store.withdraw(key.as_ref(), binding.as_ref()).await
    }

    pub fn expired_cookie(&self) -> Result<HeaderValue, AuthError> {
        self.cookie("", 0)
    }

    /// The one CSRF header value, if exactly one non-empty value was sent.
    fn presented_csrf<'a>(&self, headers: &'a HeaderMap) -> Option<&'a str> {
        let mut values = headers.get_all(self.csrf_header.as_str()).iter();
        let value = values.next()?.to_str().ok()?;
        (values.next().is_none() && !value.is_empty()).then_some(value)
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

    fn digest(&self, purpose: &str, value: &str) -> SessionDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"greengateway.admin-session.v1\0");
        hasher.update(self.store.namespace().as_bytes());
        hasher.update([0u8]);
        hasher.update(purpose.as_bytes());
        hasher.update([0u8]);
        hasher.update(value.as_bytes());
        hasher.finalize().into()
    }

    /// The store key of a session cookie value, so tests can find the row
    /// they tamper with.
    #[cfg(test)]
    pub(crate) fn session_key_for_test(&self, value: &str) -> SessionDigest {
        self.digest(PURPOSE_SESSION, value)
    }
}

/// The `standalone_memory` store: a bounded map in this process. There is
/// deliberately no HA fallback; a restart discards every session.
pub struct MemoryAdminSessionStore {
    config: AdminSessionConfig,
    state: Mutex<MemoryState>,
}

#[derive(Default)]
struct MemoryState {
    entries: HashMap<SessionDigest, MemoryEntry>,
    attempts: HashMap<SessionDigest, LoginAttempt>,
}

struct MemoryEntry {
    session: StoredSession,
    expires_at: Instant,
    idle_expires_at: Instant,
}

impl MemoryEntry {
    fn live(&self, now: Instant) -> bool {
        self.expires_at > now && self.idle_expires_at > now
    }
}

struct LoginAttempt {
    expires_at: Instant,
    issued: Option<SessionDigest>,
}

impl MemoryAdminSessionStore {
    pub fn new(config: AdminSessionConfig) -> Self {
        Self {
            config,
            state: Mutex::new(MemoryState::default()),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, MemoryState>, AuthError> {
        self.state
            .lock()
            .map_err(|_| AuthError::Upstream(UNAVAILABLE.to_owned()))
    }

    fn deadline(now: Instant, after: Duration) -> Result<Instant, AuthError> {
        now.checked_add(after)
            .ok_or_else(|| AuthError::Upstream(UNAVAILABLE.to_owned()))
    }
}

#[async_trait::async_trait]
impl AdminSessionStore for MemoryAdminSessionStore {
    fn namespace(&self) -> &str {
        ""
    }

    async fn begin_login(
        &self,
        binding: &SessionDigest,
        ttl: Duration,
        delivered: Option<&SessionDigest>,
    ) -> Result<bool, AuthError> {
        let mut state = self.lock()?;
        let now = Instant::now();
        let expires_at = Self::deadline(now, ttl)?;
        let MemoryState { entries, attempts } = &mut *state;
        entries.retain(|_, entry| entry.live(now));
        attempts.retain(|_, attempt| {
            attempt.expires_at > now && attempt.issued.is_none_or(|key| entries.contains_key(&key))
        });
        if let Some(delivered) = delivered {
            attempts.retain(|_, attempt| attempt.issued.as_ref() != Some(delivered));
        }
        if attempts.len() >= self.config.max_entries {
            return Ok(false);
        }
        attempts.insert(
            *binding,
            LoginAttempt {
                expires_at,
                issued: None,
            },
        );
        Ok(true)
    }

    async fn grant(&self, grant: SessionGrant) -> Result<GrantOutcome, AuthError> {
        let mut state = self.lock()?;
        let now = Instant::now();
        let expires_at = Self::deadline(now, self.config.ttl)?;
        let idle_expires_at = Self::deadline(now, self.config.idle_timeout)?.min(expires_at);
        if !state
            .attempts
            .get(&grant.binding)
            .is_some_and(|attempt| attempt.expires_at > now && attempt.issued.is_none())
        {
            return Ok(GrantOutcome::NoPendingLogin);
        }
        state.entries.retain(|_, entry| entry.live(now));
        // Do not remove a prior session if admission would fail.
        let replaces = grant
            .previous
            .is_some_and(|key| state.entries.contains_key(&key));
        if state.entries.len() >= self.config.max_entries && !replaces {
            return Ok(GrantOutcome::AtCapacity);
        }
        if let Some(previous) = grant.previous {
            state.entries.remove(&previous);
        }
        if let Some(attempt) = state.attempts.get_mut(&grant.binding) {
            attempt.issued = Some(grant.key);
        }
        state.entries.insert(
            grant.key,
            MemoryEntry {
                session: grant.session,
                expires_at,
                idle_expires_at,
            },
        );
        Ok(GrantOutcome::Granted)
    }

    async fn lookup(&self, key: &SessionDigest) -> Result<Option<StoredSession>, AuthError> {
        let mut state = self.lock()?;
        let now = Instant::now();
        if state.entries.get(key).is_some_and(|entry| !entry.live(now)) {
            state.entries.remove(key);
        }
        Ok(state.entries.get(key).map(|entry| entry.session.clone()))
    }

    async fn admit(&self, key: &SessionDigest, id: &str) -> Result<bool, AuthError> {
        let mut state = self.lock()?;
        let now = Instant::now();
        let idle_deadline = Self::deadline(now, self.config.idle_timeout)?;
        let MemoryState { entries, attempts } = &mut *state;
        let Some(entry) = entries
            .get_mut(key)
            .filter(|entry| entry.live(now) && entry.session.id == id)
        else {
            return Ok(false);
        };
        entry.idle_expires_at = idle_deadline.min(entry.expires_at);
        attempts.retain(|_, attempt| attempt.issued.as_ref() != Some(key));
        Ok(true)
    }

    async fn reject(&self, key: &SessionDigest, id: &str) -> Result<(), AuthError> {
        let mut state = self.lock()?;
        if state
            .entries
            .get(key)
            .is_some_and(|entry| entry.session.id == id)
        {
            state.entries.remove(key);
            state
                .attempts
                .retain(|_, attempt| attempt.issued.as_ref() != Some(key));
        }
        Ok(())
    }

    async fn withdraw(
        &self,
        key: Option<&SessionDigest>,
        binding: Option<&SessionDigest>,
    ) -> Result<(), AuthError> {
        let mut state = self.lock()?;
        if let Some(key) = key {
            state.entries.remove(key);
            state
                .attempts
                .retain(|_, attempt| attempt.issued.as_ref() != Some(key));
        }
        if let Some(binding) = binding {
            if let Some(attempt) = state.attempts.remove(binding) {
                if let Some(issued) = attempt.issued {
                    state.entries.remove(&issued);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "admin_session_tests.rs"]
pub(crate) mod tests;
