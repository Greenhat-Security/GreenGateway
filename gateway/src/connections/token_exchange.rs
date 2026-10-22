//! Delegated issuer tokens (issue #441): the calling user's own upstream token, obtained by OAuth
//! 2.0 token exchange (RFC 8693) and cached per caller.
//!
//! A `delegated_issuer_token` Connection does not hold an upstream credential at all. An issuer the
//! operator trusts -- the wallet -- holds each user's grant for the upstream, and on a cache miss
//! this asks it for the calling user's access token:
//!
//! - The gateway authenticates as itself with `client_secret_basic`, using a client secret bound
//!   under [`SecretPurpose::TokenExchangeClientSecret`].
//! - The subject token says who the caller is. It is a JWT signed with the Connection's
//!   caller-assertion key, exactly as a caller assertion names its caller, and the issuer verifies
//!   it against the published JWKS. It is never the caller's own inbound bearer token: forwarding
//!   that is a separate decision this module does not make.
//! - The answer is injected as `Authorization: Bearer` and cached under the Connection's revision,
//!   the caller and the egress policy, until shortly before the issuer's `expires_in` and for at
//!   most [`MAX_DELEGATED_TOKEN_CACHE_SECONDS`]. Rotating the client secret behind its alias does
//!   not move that key (see [`DelegatedTokenRuntime::access_token`]); a save that changes the
//!   Connection does, and an unchanged save is a no-op.
//!
//! A call that names nobody is refused before anything is read or sent; so is one whose exchange
//! fails, with a reason of its own, and never with a fallback to a shared identity. Every exchange
//! is audited as [`audit::event::CONNECTION_DELEGATED_TOKEN_EXCHANGE`] with the caller as its
//! actor. No token -- the subject token, the issued token, or anything the issuer answered with --
//! reaches an error, a log line or an audit event.
//!
//! A principal's tokens can also be purged (see [`DelegatedTokenRuntime::purge_principal`]): when
//! an operator says the user was disabled, or when a validator refuses one of the principal's
//! credentials as revoked. Every token cached for that principal, under every delegated
//! Connection, leaves the cache at once, and each is then revoked at its issuer by OAuth 2.0 token
//! revocation (RFC 7009) when its Connection names a `revocation_url`. Revocation is best effort:
//! it is attempted once, in the background, and audited as
//! [`audit::event::CONNECTION_DELEGATED_TOKEN_REVOCATION`] whatever the issuer says.

use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use http::{header, HeaderValue, Method, StatusCode};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use url::form_urlencoded;
use zeroize::Zeroizing;

use crate::{
    audit::{self, Actor, AuditEvent, AuditLog},
    auth::principal::canonical_issuer,
    egress::{EgressClient, EgressError},
};

use super::{
    caller_assertion::{
        load_signing_key, sign_caller_assertion, AssertionAlgorithm, AttestedCaller,
        CallerAssertionConfig, PrincipalClaim,
    },
    control_plane::ConnectionControlPlane,
    model::ConnectionId,
    oauth::{
        connection_test_owns_token_requests, duration_millis, is_json_content_type,
        token_request_headers, MintedOAuthToken, OAuthTokenCache, OAuthTokenCacheKey,
        OAuthTokenLease, RetiredTokenSlot, SecretString, SystemOAuthClock, TokenCacheFailure,
        MAX_RESPONSE_SCOPE_BYTES, MAX_TOKEN_LIFETIME_SECS, MAX_TOKEN_TYPE_BYTES,
        OAUTH_MAX_REQUEST_BYTES,
    },
    secret::{SecretPurpose, SecretResolveErrorKind, MAX_HTTP_CREDENTIAL_BYTES},
};

/// Most callers' tokens held at once, across every delegated Connection.
///
/// A full cache evicts an idle entry, which costs that caller one more exchange; it refuses a call,
/// with `delegated_token_unavailable`, only while every entry is held by a call in flight.
pub const MAX_DELEGATED_TOKEN_CACHE_ENTRIES: usize = 1_024;

/// Longest a delegated token is reused, whatever the issuer's `expires_in` says.
///
/// A user's token is reused only for that user, but a grant the issuer revokes keeps working here
/// until the cached token is refreshed. This bounds that window.
pub const MAX_DELEGATED_TOKEN_CACHE_SECONDS: u64 = 900;

const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const SUBJECT_TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";
const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";

/// The `request_id` of an exchange's audit event. An exchange serves every call of its caller
/// until it is refreshed, so it belongs to none of them; its `subject_token.jti` is what an
/// operator joins to the issuer's own log.
const EXCHANGE_AUDIT_REQUEST_ID: &str = "connection-delegated-token";

/// The `request_id` of the audit events of a purge no request asked for: one a validator's refusal
/// of a revoked credential started. Their `purge_id` joins them to each other.
const PURGE_AUDIT_REQUEST_ID: &str = "connection-delegated-token-purge";

/// RFC 7009 section 2.1: the hint that the token being revoked is an access token.
const TOKEN_TYPE_HINT_ACCESS_TOKEN: &str = "access_token";

/// The error codes RFC 6749 section 5.2 and RFC 8693 section 2.2.2 register for a token endpoint.
/// An issuer's code is recorded only when it is one of these, so audit never carries text the
/// issuer chose.
pub(super) const REGISTERED_ERROR_CODES: &[&str] = &[
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
    "invalid_target",
    "access_denied",
];

/// The error codes a revocation endpoint may answer with: RFC 6749 section 5.2's, through RFC 7009
/// section 2.2.1, and the one RFC 7009 adds.
const REGISTERED_REVOCATION_ERROR_CODES: &[&str] = &[
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
    "unsupported_token_type",
];

/// Why a delegated token could not be obtained. Every variant refuses the call: nothing is sent
/// upstream without the caller's own token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegatedTokenError {
    /// The call names nobody: it has no principal, or a service token's.
    NoPrincipal,
    /// The egress policy refuses the token-exchange endpoint.
    EgressDenied,
    /// The issuer refused this caller: no grant, a revoked grant, or a subject it does not accept
    /// (`invalid_grant` or `access_denied`, or any `403`).
    Denied,
    /// No usable token came back: the issuer could not be reached, failed, refused the gateway's
    /// own client authentication or request, or answered with something other than a bearer
    /// access token with a bounded lifetime.
    ExchangeFailed,
    /// Every cache entry is held by a call or an exchange in flight.
    Unavailable,
    /// The client secret or the subject-token signing key is unknown, refused by its source, or not
    /// valid for its purpose.
    CredentialInvalid,
    /// The client secret's or the signing key's source could not be read just now.
    CredentialUnavailable,
}

impl DelegatedTokenError {
    /// A stable, non-revealing reason for errors, audit and metrics.
    pub const fn safe_reason(self) -> &'static str {
        match self {
            Self::NoPrincipal => "delegated_token_no_principal",
            Self::EgressDenied => "delegated_token_egress_denied",
            Self::Denied => "delegated_token_denied",
            Self::ExchangeFailed => "delegated_token_exchange_failed",
            Self::Unavailable => "delegated_token_unavailable",
            Self::CredentialInvalid => "credential_invalid",
            Self::CredentialUnavailable => "credential_unavailable",
        }
    }
}

impl fmt::Display for DelegatedTokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_reason())
    }
}

impl std::error::Error for DelegatedTokenError {}

impl TokenCacheFailure for DelegatedTokenError {
    const CACHE_FULL: Self = Self::Unavailable;
    const MINT_PANICKED: Self = Self::ExchangeFailed;
    const INVALID_TOKEN: Self = Self::ExchangeFailed;
    // The caller's own tokens were being purged as the call arrived.
    const RETIRED: Self = Self::Unavailable;
}

/// One Connection's exchange, as a target built from one revision of it binds it.
#[derive(Clone)]
pub(crate) struct DelegatedTokenBinding {
    pub connection_id: ConnectionId,
    pub connection_etag: String,
    pub client_id: String,
    pub client_secret_id: String,
    pub token_exchange_url: String,
    pub requested_scopes: Vec<String>,
    pub audience: Option<String>,
    pub resource: Option<String>,
    /// The issuer's RFC 7009 endpoint, when the Connection names one: where a purged token of this
    /// revision is revoked, with the same client credentials and egress client as its exchange.
    pub revocation_url: Option<String>,
    pub subject_token: SubjectTokenSettings,
    pub token_client: Arc<EgressClient>,
}

/// How the subject token is signed: the Connection's `caller_assertion` settings, holding the key's
/// alias and never the key, which is read and loaded on every exchange.
#[derive(Clone)]
pub(crate) struct SubjectTokenSettings {
    pub signing_key_id: String,
    pub kid: String,
    pub algorithm: AssertionAlgorithm,
    pub issuer: String,
    pub audience: String,
    pub token_type: String,
    pub lifetime_seconds: u64,
    pub claims: Vec<PrincipalClaim>,
}

/// A delegated token one call holds: injected as `Authorization: Bearer`, and dropped from the
/// cache by an upstream `401`.
pub(crate) type DelegatedTokenLease = OAuthTokenLease<DelegatedTokenError, DelegatedTokenBinding>;

/// The delegated-token cache. Each entry keeps the binding of the revision it was exchanged under,
/// so a purged token is revoked at the issuer that issued it, whatever the Connection says now.
type DelegatedTokenCache = OAuthTokenCache<DelegatedTokenError, DelegatedTokenBinding>;

type RetiredDelegatedToken = RetiredTokenSlot<DelegatedTokenError, DelegatedTokenBinding>;

/// Why a principal's delegated tokens are purged.
#[derive(Clone, Debug)]
pub enum DelegatedTokenPurgeTrigger {
    /// An operator asked, through the admin API: typically because the user was disabled at their
    /// identity provider. The actor and request are the operator's.
    Operator {
        actor: Actor,
        request_id: String,
        source_ip: String,
    },
    /// A validator refused one of the principal's credentials because it is revoked. The
    /// credential's signature was verified first, so the principal is the one its issuer named.
    CredentialRevoked,
}

impl DelegatedTokenPurgeTrigger {
    const fn label(&self) -> &'static str {
        match self {
            Self::Operator { .. } => "operator",
            Self::CredentialRevoked => "credential_revoked",
        }
    }
}

#[derive(Clone)]
pub(crate) struct DelegatedTokenRuntime {
    control_plane: ConnectionControlPlane,
    cache: Arc<DelegatedTokenCache>,
    audit: Option<AuditLog>,
}

impl fmt::Debug for DelegatedTokenRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DelegatedTokenRuntime")
            .field("cache_entries", &self.cache.slot_count())
            .field("audit_configured", &self.audit.is_some())
            .finish()
    }
}

impl DelegatedTokenRuntime {
    pub(crate) fn new(control_plane: ConnectionControlPlane) -> Self {
        Self {
            control_plane,
            cache: Arc::new(OAuthTokenCache::with_capacity(
                Arc::new(SystemOAuthClock),
                MAX_DELEGATED_TOKEN_CACHE_ENTRIES,
            )),
            audit: None,
        }
    }

    pub(crate) fn with_audit(mut self, audit: AuditLog) -> Self {
        self.audit = Some(audit);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_cache_for_test(
        mut self,
        clock: Arc<ManualTokenClock>,
        capacity: usize,
    ) -> Self {
        self.cache = Arc::new(OAuthTokenCache::with_capacity(clock, capacity));
        self
    }

    /// How many callers' tokens are cached now, across every delegated Connection.
    pub(crate) fn cache_entry_count(&self) -> usize {
        self.cache.slot_count()
    }

    /// The token `caller` holds for `binding`'s upstream: the cached one, or a fresh exchange.
    ///
    /// Concurrent calls of one caller share one exchange, and an exchange outlives a call that
    /// stops waiting for it, so a cancelled call never cancels another caller's work or its audit.
    ///
    /// A Connection test is the exception: it exchanges inline, within its own deadline, for the
    /// principal running it, and neither reads nor fills the cache. The token serves the test's one
    /// request and is dropped with it, so a test never hands a later call a token, and a later
    /// call never lets a test pass on a token an earlier exchange obtained.
    pub(crate) async fn access_token(
        &self,
        binding: &DelegatedTokenBinding,
        caller: &AttestedCaller,
    ) -> Result<DelegatedTokenLease, DelegatedTokenError> {
        if connection_test_owns_token_requests() {
            return Ok(OAuthTokenLease::uncached(
                self.exchange(binding, caller).await?,
            ));
        }
        let identity = caller.identity();
        let key = OAuthTokenCacheKey {
            connection_id: binding.connection_id.to_string(),
            connection_etag: binding.connection_etag.clone(),
            subject: Some(subject_digest(caller)),
            principal: Some(principal_digest(identity.issuer, identity.subject)),
            // Always `None` today. The encrypted local store's version is the
            // only one a rotation moves while the gateway runs, and that store
            // cannot hold this purpose; an operator alias or an external
            // provider's alias is read afresh on each exchange, with nothing
            // to say it changed. So rotating the client secret does not drop
            // cached tokens (nor does it revoke the tokens the issuer already
            // handed out); a save that changes the Connection, which moves its
            // etag, does. An unchanged save keeps the etag and the cache.
            // Kept rather than written as `None`, so that a local store able
            // to hold the purpose would partition the cache by rotation.
            secret_version: self
                .control_plane
                .local_secret_version(&binding.client_secret_id),
            egress_generation: binding.token_client.configuration_generation(),
        };
        let runtime = self.clone();
        let exchanged_for = binding.clone();
        let caller = caller.clone();
        self.cache
            .get_or_mint_with(
                key,
                || binding.clone(),
                move || async move { runtime.exchange(&exchanged_for, &caller).await },
            )
            .await
    }

    /// Drops every token cached for the principal `issuer` and `subject` name, under every
    /// delegated Connection and whatever email or roles it carried, and returns how many entries
    /// that was. Each token is then revoked at its issuer in the background, when the revision it
    /// was exchanged under names a `revocation_url`.
    ///
    /// No later call is served a purged token: the principal's next call exchanges again, and the
    /// issuer decides whether it still holds a grant. A call already holding its token finishes
    /// with it. A call that arrives while the purge runs may be refused with
    /// `delegated_token_unavailable`.
    ///
    /// An operator's purge is audited even when it finds nothing. One a revoked credential started
    /// is audited only when it purged something, because the same refused credential can be
    /// presented any number of times.
    ///
    /// `google_purged` is how many Google domain-wide delegation tokens the caller already dropped
    /// for the same principal (see
    /// [`super::google_delegation::GoogleDelegationRuntime::purge_principal`]): they count towards
    /// the total and are named in the same audit event, so one purge has one record. Google
    /// offers no revocation for them, so none is attempted.
    pub(crate) fn purge_principal(
        &self,
        issuer: &str,
        subject: &str,
        trigger: DelegatedTokenPurgeTrigger,
        google_purged: usize,
    ) -> usize {
        let Some(issuer) = canonical_issuer(issuer) else {
            return 0;
        };
        let principal = principal_digest(&issuer, subject);
        let retired = self
            .cache
            .retire_where(|key| key.principal == Some(principal));
        let purged = retired.len().saturating_add(google_purged);
        if purged == 0 && matches!(trigger, DelegatedTokenPurgeTrigger::CredentialRevoked) {
            return 0;
        }
        let purge = Arc::new(DelegatedTokenPurge {
            audit: self.audit.clone(),
            purge_id: uuid::Uuid::new_v4().to_string(),
            trigger,
            issuer,
            subject: subject.to_owned(),
        });
        purge.emit(purged, google_purged);
        if !retired.is_empty() {
            let runtime = self.clone();
            // Detached, like an exchange: the request that asked for the purge may end before the
            // issuers answer, and must not cancel their revocations or their audit.
            tokio::spawn(async move { runtime.revoke_retired(&purge, retired).await });
        }
        purged
    }

    /// Revokes each retired token at its issuer, one after another, once any exchange still in
    /// flight for it has finished.
    async fn revoke_retired(
        &self,
        purge: &DelegatedTokenPurge,
        retired: Vec<RetiredDelegatedToken>,
    ) {
        for slot in retired {
            let Some(token) = slot.take_token().await else {
                continue;
            };
            let binding = slot.context();
            let mut attempt = RevocationAttempt::new(purge, binding);
            let result = self.revoke(binding, &token, &mut attempt).await;
            drop(token);
            attempt.finish(&result);
        }
    }

    /// One RFC 7009 request: the token, hinted as an access token, posted to the issuer's
    /// revocation endpoint with the client credentials it was exchanged with. The endpoint passes
    /// the egress policy before the client secret is read.
    async fn revoke(
        &self,
        binding: &DelegatedTokenBinding,
        token: &[u8],
        attempt: &mut RevocationAttempt<'_>,
    ) -> Result<(), RevocationError> {
        let revocation_url = binding
            .revocation_url
            .as_deref()
            .ok_or(RevocationError::NotConfigured)?;
        let destination = binding
            .token_client
            .checked_destination(revocation_url)
            .await
            .map_err(|error| revocation_egress_error(&error))?;
        let client_secret = self
            .control_plane
            .secret_resolver()
            .resolve(
                &binding.client_secret_id,
                SecretPurpose::TokenExchangeClientSecret,
            )
            .await
            .map_err(|error| revocation_credential_error(error.kind()))?;
        let headers = token_request_headers(&binding.client_id, client_secret.expose())
            .map_err(|_| RevocationError::CredentialInvalid)?;
        drop(client_secret);
        let body = revocation_request_body(token)?;

        let response = binding
            .token_client
            .sensitive_request_with_headers_at_checked_destination(
                &destination,
                Method::POST,
                revocation_url,
                headers,
                Some(body),
            )
            .await
            .map_err(|error| revocation_egress_error(&error))?;
        attempt.issuer_status = Some(response.status.as_u16());
        // RFC 7009 section 2.2: `200` whether the token was revoked or was already invalid, and the
        // body means nothing.
        if response.status == StatusCode::OK {
            return Ok(());
        }
        if is_json_content_type(response.headers.get(header::CONTENT_TYPE)) {
            attempt.issuer_error =
                registered_error_code(response.body.as_slice(), REGISTERED_REVOCATION_ERROR_CODES);
        }
        Err(if response.status == StatusCode::SERVICE_UNAVAILABLE {
            RevocationError::Failed
        } else {
            RevocationError::Refused
        })
    }

    async fn exchange(
        &self,
        binding: &DelegatedTokenBinding,
        caller: &AttestedCaller,
    ) -> Result<MintedOAuthToken, DelegatedTokenError> {
        let jti = uuid::Uuid::new_v4().to_string();
        let mut attempt = ExchangeAttempt::new(self.audit.clone(), binding, caller, &jti);
        let result = self
            .exchange_inner(binding, caller, &jti, &mut attempt)
            .await;
        attempt.finish(&result);
        result
    }

    async fn exchange_inner(
        &self,
        binding: &DelegatedTokenBinding,
        caller: &AttestedCaller,
        jti: &str,
        attempt: &mut ExchangeAttempt,
    ) -> Result<MintedOAuthToken, DelegatedTokenError> {
        // The endpoint passes the egress policy before any key or secret is read.
        let destination = binding
            .token_client
            .checked_destination(&binding.token_exchange_url)
            .await
            .map_err(|error| exchange_egress_error(&error))?;

        let subject_token = self.sign_subject_token(binding, caller, jti).await?;
        let client_secret = self
            .control_plane
            .secret_resolver()
            .resolve(
                &binding.client_secret_id,
                SecretPurpose::TokenExchangeClientSecret,
            )
            .await
            .map_err(|error| credential_error(error.kind()))?;
        let headers = token_request_headers(&binding.client_id, client_secret.expose())
            .map_err(|_| DelegatedTokenError::CredentialInvalid)?;
        drop(client_secret);
        let body = exchange_request_body(binding, &subject_token)?;
        drop(subject_token);

        let response = binding
            .token_client
            .sensitive_request_with_headers_at_checked_destination(
                &destination,
                Method::POST,
                &binding.token_exchange_url,
                headers,
                Some(body),
            )
            .await
            .map_err(|error| exchange_egress_error(&error))?;

        attempt.issuer_status = Some(response.status.as_u16());
        let json = is_json_content_type(response.headers.get(header::CONTENT_TYPE));
        if response.status != StatusCode::OK {
            let code = if json {
                registered_error_code(response.body.as_slice(), REGISTERED_ERROR_CODES)
            } else {
                None
            };
            attempt.issuer_error = code;
            return Err(classify_refusal(response.status, code));
        }
        if !json {
            return Err(DelegatedTokenError::ExchangeFailed);
        }
        let mut token: ExchangeResponse = serde_json::from_slice(response.body.as_slice())
            .map_err(|_| DelegatedTokenError::ExchangeFailed)?;
        let expires_in = validate_exchange_response(&token)?;
        Ok(MintedOAuthToken {
            access_token: token.access_token.take_bytes(),
            lifetime: cache_lifetime(expires_in),
        })
    }

    /// Signs the subject token: a caller assertion naming `caller`, as the Connection's
    /// `caller_assertion` block configures it, bound to no request because the token it buys
    /// serves many.
    async fn sign_subject_token(
        &self,
        binding: &DelegatedTokenBinding,
        caller: &AttestedCaller,
        jti: &str,
    ) -> Result<Zeroizing<String>, DelegatedTokenError> {
        let settings = &binding.subject_token;
        let material = self
            .control_plane
            .secret_resolver()
            .resolve(&settings.signing_key_id, SecretPurpose::AssertionSigningKey)
            .await
            .map_err(|error| credential_error(error.kind()))?;
        let key = load_signing_key(&settings.kid, settings.algorithm, material.expose())
            .map_err(|_| DelegatedTokenError::CredentialInvalid)?;
        drop(material);
        let config = CallerAssertionConfig {
            issuer: &settings.issuer,
            audience: &settings.audience,
            token_type: &settings.token_type,
            lifetime_seconds: settings.lifetime_seconds,
            claims: &settings.claims,
            bind_request: false,
            bind_approval: false,
        };
        let issued_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DelegatedTokenError::ExchangeFailed)?
            .as_secs();
        sign_caller_assertion(
            &key,
            &config,
            Some(&caller.identity()),
            jti,
            issued_at,
            None,
            None,
        )
        .map(Zeroizing::new)
        .map_err(|_| DelegatedTokenError::ExchangeFailed)
    }
}

/// How long a token the issuer says lives `expires_in` seconds is offered to the cache, which
/// refreshes it shortly before that ends: never longer than [`MAX_DELEGATED_TOKEN_CACHE_SECONDS`].
fn cache_lifetime(expires_in: u64) -> Duration {
    Duration::from_secs(expires_in.min(MAX_DELEGATED_TOKEN_CACHE_SECONDS))
}

/// Whose tokens a purge drops: a digest of the attested issuer and subject alone, so it matches
/// every token exchanged for that principal whatever email or roles it carried. Length-prefixed
/// so no two principals share an encoding.
pub(super) fn principal_digest(issuer: &str, subject: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"greengateway:delegated-token-principal:v1\0");
    for part in [issuer, subject] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    digest.finalize().into()
}

/// Who a cached token belongs to: a digest of every attested field, so a caller whose email or
/// roles changed at their provider is exchanged for again rather than served a token issued for
/// claims that no longer hold. Length-prefixed so no two identities share an encoding.
fn subject_digest(caller: &AttestedCaller) -> [u8; 32] {
    let identity = caller.identity();
    let mut digest = Sha256::new();
    digest.update(b"greengateway:delegated-token-subject:v1\0");
    for part in [identity.issuer, identity.subject] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    match identity.email {
        Some(email) => {
            digest.update([1]);
            digest.update((email.len() as u64).to_be_bytes());
            digest.update(email.as_bytes());
        }
        None => digest.update([0]),
    }
    digest.update((identity.roles.len() as u64).to_be_bytes());
    for role in identity.roles {
        digest.update((role.len() as u64).to_be_bytes());
        digest.update(role.as_bytes());
    }
    digest.finalize().into()
}

fn exchange_request_body(
    binding: &DelegatedTokenBinding,
    subject_token: &str,
) -> Result<Vec<u8>, DelegatedTokenError> {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("grant_type", GRANT_TYPE_TOKEN_EXCHANGE);
    serializer.append_pair("subject_token", subject_token);
    serializer.append_pair("subject_token_type", SUBJECT_TOKEN_TYPE_JWT);
    serializer.append_pair("requested_token_type", TOKEN_TYPE_ACCESS_TOKEN);
    if !binding.requested_scopes.is_empty() {
        serializer.append_pair("scope", &binding.requested_scopes.join(" "));
    }
    if let Some(audience) = binding.audience.as_deref() {
        serializer.append_pair("audience", audience);
    }
    if let Some(resource) = binding.resource.as_deref() {
        serializer.append_pair("resource", resource);
    }
    let body = Zeroizing::new(serializer.finish());
    if body.len() > OAUTH_MAX_REQUEST_BYTES {
        return Err(DelegatedTokenError::ExchangeFailed);
    }
    Ok(body.as_bytes().to_vec())
}

/// An RFC 7009 request body: the token and the hint that it is an access token.
fn revocation_request_body(token: &[u8]) -> Result<Vec<u8>, RevocationError> {
    // The issuer handed the token out as a JSON string, so it is UTF-8.
    let token = std::str::from_utf8(token).map_err(|_| RevocationError::Failed)?;
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("token", token);
    serializer.append_pair("token_type_hint", TOKEN_TYPE_HINT_ACCESS_TOKEN);
    let body = Zeroizing::new(serializer.finish());
    if body.len() > OAUTH_MAX_REQUEST_BYTES {
        return Err(RevocationError::Failed);
    }
    Ok(body.as_bytes().to_vec())
}

/// The fields of an RFC 8693 response this reads. Anything else an issuer adds -- a refresh token,
/// a session identifier -- is skipped unread rather than refused: issuers routinely add fields,
/// and none of them is kept.
#[derive(Deserialize)]
struct ExchangeResponse {
    access_token: SecretString,
    issued_token_type: String,
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    scope: Option<String>,
}

/// Accepts only what was asked for, an access token usable as a bearer header with a bounded,
/// stated lifetime, and returns that lifetime in seconds. RFC 8693 only recommends `expires_in`;
/// this requires it, because a token with no stated lifetime could only be cached on a guess.
fn validate_exchange_response(token: &ExchangeResponse) -> Result<u64, DelegatedTokenError> {
    let expires_in = token
        .expires_in
        .filter(|seconds| (1..=MAX_TOKEN_LIFETIME_SECS).contains(seconds))
        .ok_or(DelegatedTokenError::ExchangeFailed)?;
    let access_token = token.access_token.as_str();
    if access_token.is_empty()
        || access_token.len() > MAX_HTTP_CREDENTIAL_BYTES
        || access_token.contains('\0')
        || token.issued_token_type != TOKEN_TYPE_ACCESS_TOKEN
        || token.token_type.len() > MAX_TOKEN_TYPE_BYTES
        || !token.token_type.eq_ignore_ascii_case("bearer")
        || token
            .scope
            .as_ref()
            .is_some_and(|scope| scope.len() > MAX_RESPONSE_SCOPE_BYTES || scope.contains('\0'))
        || HeaderValue::from_bytes(access_token.as_bytes()).is_err()
    {
        return Err(DelegatedTokenError::ExchangeFailed);
    }
    Ok(expires_in)
}

#[derive(Deserialize)]
struct ExchangeErrorResponse {
    #[serde(default)]
    error: Option<String>,
}

/// The issuer's error code when it is one of `registered`, `unregistered` for any other, and
/// `None` when the body names none.
pub(super) fn registered_error_code(
    body: &[u8],
    registered: &[&'static str],
) -> Option<&'static str> {
    let code = serde_json::from_slice::<ExchangeErrorResponse>(body)
        .ok()?
        .error?;
    Some(
        registered
            .iter()
            .copied()
            .find(|registered| *registered == code)
            .unwrap_or("unregistered"),
    )
}

/// A refusal is the issuer declining this caller only when it says so: `invalid_grant` (no grant,
/// or one revoked) or `access_denied` on a client error, or a `403`. Everything else -- the gateway's
/// own client authentication refused, a malformed request, a server error -- is the exchange
/// failing, which no caller can fix by reconnecting.
fn classify_refusal(status: StatusCode, code: Option<&'static str>) -> DelegatedTokenError {
    if status == StatusCode::FORBIDDEN
        || (status.is_client_error() && matches!(code, Some("invalid_grant" | "access_denied")))
    {
        DelegatedTokenError::Denied
    } else {
        DelegatedTokenError::ExchangeFailed
    }
}

fn credential_error(kind: SecretResolveErrorKind) -> DelegatedTokenError {
    match kind {
        SecretResolveErrorKind::UnknownAlias
        | SecretResolveErrorKind::SourceDenied
        | SecretResolveErrorKind::InvalidMaterial => DelegatedTokenError::CredentialInvalid,
        SecretResolveErrorKind::ProviderBusy
        | SecretResolveErrorKind::SourceUnavailable
        | SecretResolveErrorKind::UnsafeSource
        | SecretResolveErrorKind::ProviderFailure => DelegatedTokenError::CredentialUnavailable,
    }
}

fn exchange_egress_error(error: &EgressError) -> DelegatedTokenError {
    match error {
        EgressError::HostNotAllowed(_)
        | EgressError::PortNotAllowed(_)
        | EgressError::NonGlobalIpBlocked(_)
        | EgressError::InvalidPolicy(_)
        | EgressError::InvalidUrl(_)
        | EgressError::SchemeNotAllowed(_) => DelegatedTokenError::EgressDenied,
        EgressError::ResponseTooLarge { .. }
        | EgressError::DnsResolutionFailed(_)
        | EgressError::RequestBodyTooLarge { .. }
        | EgressError::RequestBodyReadFailed
        | EgressError::UnexpectedStatus(_)
        | EgressError::ResponseIdleTimeout { .. }
        | EgressError::InvalidTlsCaBundle { .. }
        | EgressError::InvalidTlsClientIdentity
        | EgressError::Http(_) => DelegatedTokenError::ExchangeFailed,
        // Unreachable: the exchange goes through the pinned HTTP/1.1 transport, never through
        // `egress::grpc`. Named rather than wildcarded so a new transport cannot land here
        // silently.
        EgressError::Grpc(_) => DelegatedTokenError::ExchangeFailed,
    }
}

/// Why a purged token was not revoked. Revocation is best effort: none of these is retried, and
/// none of them puts the token back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RevocationError {
    /// The revision the token was exchanged under names no `revocation_url`.
    NotConfigured,
    /// The egress policy refuses the revocation endpoint.
    EgressDenied,
    /// The client secret is unknown, refused by its source, or not valid for its purpose.
    CredentialInvalid,
    /// The client secret's source could not be read just now.
    CredentialUnavailable,
    /// The issuer answered with an error.
    Refused,
    /// The issuer could not be reached, timed out, or answered `503`.
    Failed,
}

impl RevocationError {
    const fn outcome_and_reason(self) -> (&'static str, &'static str) {
        match self {
            Self::NotConfigured => ("skipped", "revocation_not_configured"),
            Self::EgressDenied => ("failure", "revocation_egress_denied"),
            Self::CredentialInvalid => ("failure", "credential_invalid"),
            Self::CredentialUnavailable => ("failure", "credential_unavailable"),
            Self::Refused => ("failure", "revocation_refused"),
            Self::Failed => ("failure", "revocation_failed"),
        }
    }
}

/// The revocation request travels exactly as the exchange does, so it is refused for exactly the
/// same reasons.
fn revocation_egress_error(error: &EgressError) -> RevocationError {
    match exchange_egress_error(error) {
        DelegatedTokenError::EgressDenied => RevocationError::EgressDenied,
        DelegatedTokenError::NoPrincipal
        | DelegatedTokenError::Denied
        | DelegatedTokenError::ExchangeFailed
        | DelegatedTokenError::Unavailable
        | DelegatedTokenError::CredentialInvalid
        | DelegatedTokenError::CredentialUnavailable => RevocationError::Failed,
    }
}

fn revocation_credential_error(kind: SecretResolveErrorKind) -> RevocationError {
    match credential_error(kind) {
        DelegatedTokenError::CredentialUnavailable => RevocationError::CredentialUnavailable,
        DelegatedTokenError::CredentialInvalid
        | DelegatedTokenError::NoPrincipal
        | DelegatedTokenError::EgressDenied
        | DelegatedTokenError::Denied
        | DelegatedTokenError::ExchangeFailed
        | DelegatedTokenError::Unavailable => RevocationError::CredentialInvalid,
    }
}

/// One purge, as its audit events name it.
struct DelegatedTokenPurge {
    audit: Option<AuditLog>,
    purge_id: String,
    trigger: DelegatedTokenPurgeTrigger,
    issuer: String,
    subject: String,
}

impl DelegatedTokenPurge {
    fn emit(&self, purged: usize, google_purged: usize) {
        metrics::counter!(
            "connection_delegated_token_purge_total",
            "trigger" => self.trigger.label()
        )
        .increment(1);
        self.audit_event(
            audit::event::CONNECTION_DELEGATED_TOKEN_PURGE,
            json!({
                "purge_id": self.purge_id,
                "trigger": self.trigger.label(),
                "principal": { "issuer": self.issuer, "subject": self.subject },
                "purged_entries": purged,
                "google_delegation_entries": google_purged,
            }),
        );
    }

    /// An event of this purge: the operator's actor and request when an operator asked for it,
    /// none when a revoked credential did.
    fn audit_event(&self, event_type: &str, payload: serde_json::Value) {
        let Some(audit) = self.audit.as_ref() else {
            return;
        };
        let event = match &self.trigger {
            DelegatedTokenPurgeTrigger::Operator {
                actor,
                request_id,
                source_ip,
            } => AuditEvent::new(
                event_type,
                request_id.as_str(),
                source_ip.as_str(),
                Some(actor.clone()),
                payload,
            ),
            DelegatedTokenPurgeTrigger::CredentialRevoked => AuditEvent::new(
                event_type,
                PURGE_AUDIT_REQUEST_ID,
                "internal",
                None,
                payload,
            ),
        };
        audit.emit(event);
    }
}

/// The audit record of one revocation, emitted exactly once: when it finishes, or, should the task
/// running it be dropped first, as cancelled.
struct RevocationAttempt<'a> {
    purge: &'a DelegatedTokenPurge,
    connection_id: String,
    started: Instant,
    issuer_status: Option<u16>,
    issuer_error: Option<&'static str>,
    completed: bool,
}

impl<'a> RevocationAttempt<'a> {
    fn new(purge: &'a DelegatedTokenPurge, binding: &DelegatedTokenBinding) -> Self {
        Self {
            purge,
            connection_id: binding.connection_id.to_string(),
            started: Instant::now(),
            issuer_status: None,
            issuer_error: None,
            completed: false,
        }
    }

    fn finish(&mut self, result: &Result<(), RevocationError>) {
        let (outcome, reason) = match result {
            Ok(()) => ("success", "revoked"),
            Err(error) => error.outcome_and_reason(),
        };
        self.completed = true;
        self.emit(outcome, reason);
    }

    fn emit(&self, outcome: &'static str, reason: &'static str) {
        metrics::counter!(
            "connection_delegated_token_revocation_total",
            "result" => outcome,
            "reason" => reason
        )
        .increment(1);
        self.purge.audit_event(
            audit::event::CONNECTION_DELEGATED_TOKEN_REVOCATION,
            json!({
                "purge_id": self.purge.purge_id,
                "connection_id": self.connection_id,
                "auth_type": "delegated_issuer_token",
                "principal": { "issuer": self.purge.issuer, "subject": self.purge.subject },
                "outcome": outcome,
                "reason": reason,
                "issuer_status": self.issuer_status,
                "issuer_error": self.issuer_error,
                "latency_ms": duration_millis(self.started.elapsed()),
            }),
        );
    }
}

impl Drop for RevocationAttempt<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.emit("failure", "revocation_cancelled");
        }
    }
}

/// The audit record of one exchange, emitted exactly once: when it finishes, or, should the task
/// running it be dropped first, as cancelled.
struct ExchangeAttempt {
    audit: Option<AuditLog>,
    connection_id: String,
    actor: Actor,
    kid: String,
    jti: String,
    started: Instant,
    issuer_status: Option<u16>,
    issuer_error: Option<&'static str>,
    completed: bool,
}

impl ExchangeAttempt {
    fn new(
        audit: Option<AuditLog>,
        binding: &DelegatedTokenBinding,
        caller: &AttestedCaller,
        jti: &str,
    ) -> Self {
        Self {
            audit,
            connection_id: binding.connection_id.to_string(),
            actor: caller.audit_actor(),
            kid: binding.subject_token.kid.clone(),
            jti: jti.to_owned(),
            started: Instant::now(),
            issuer_status: None,
            issuer_error: None,
            completed: false,
        }
    }

    fn finish(&mut self, result: &Result<MintedOAuthToken, DelegatedTokenError>) {
        let (outcome, reason) = match result {
            Ok(_) => ("success", "exchanged"),
            Err(error) => ("failure", error.safe_reason()),
        };
        self.completed = true;
        self.emit(outcome, reason);
    }

    fn emit(&self, outcome: &'static str, reason: &'static str) {
        metrics::counter!(
            "connection_delegated_token_exchange_total",
            "result" => outcome,
            "reason" => reason
        )
        .increment(1);
        let Some(audit) = self.audit.as_ref() else {
            return;
        };
        audit.emit(AuditEvent::new(
            audit::event::CONNECTION_DELEGATED_TOKEN_EXCHANGE,
            EXCHANGE_AUDIT_REQUEST_ID,
            "internal",
            Some(self.actor.clone()),
            json!({
                "connection_id": self.connection_id,
                "auth_type": "delegated_issuer_token",
                "outcome": outcome,
                "reason": reason,
                "subject_token": { "kid": self.kid, "jti": self.jti },
                "issuer_status": self.issuer_status,
                "issuer_error": self.issuer_error,
                "latency_ms": duration_millis(self.started.elapsed()),
            }),
        ));
    }
}

impl Drop for ExchangeAttempt {
    fn drop(&mut self) {
        if !self.completed {
            self.emit("failure", "delegated_token_exchange_cancelled");
        }
    }
}

/// A clock a test moves by hand, so expiry is tested without waiting for it.
#[cfg(test)]
pub(crate) struct ManualTokenClock {
    base: Instant,
    nanos: std::sync::atomic::AtomicU64,
}

#[cfg(test)]
impl ManualTokenClock {
    pub(crate) fn new() -> Self {
        Self {
            base: Instant::now(),
            nanos: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub(crate) fn advance(&self, duration: Duration) {
        self.nanos.fetch_add(
            u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::AcqRel,
        );
    }
}

#[cfg(test)]
impl super::oauth::OAuthClock for ManualTokenClock {
    fn now(&self) -> Instant {
        self.base + Duration::from_nanos(self.nanos.load(std::sync::atomic::Ordering::Acquire))
    }
}

#[cfg(test)]
#[path = "token_exchange_tests.rs"]
mod tests;
