//! Google Workspace domain-wide delegation (issue #442): the calling user's own Google token,
//! obtained without a per-user grant and without a private key in the gateway.
//!
//! A Workspace super-admin authorises one service account for a fixed set of scopes. Anyone who can
//! sign a JWT as that account can then obtain a token for any user in the domain, for those
//! scopes, by naming the user as `sub` and exchanging the JWT at Google's token endpoint with the
//! JWT bearer grant (RFC 7523). On a cache miss, for one caller:
//!
//! - The caller is checked first: it must have been attested by one of the Connection's
//!   `subject_issuers`, and carry an email, which becomes `sub`. Nothing else could name a
//!   Workspace user, and an email is only as trustworthy as the provider that vouched for it.
//! - Both Google endpoints pass the egress policy before anything is read or signed.
//! - The claims (`iss` = the service account, `sub`, `scope`, `aud` = the token endpoint, `iat`,
//!   `exp` [`ASSERTION_LIFETIME_SECONDS`] later) are signed by Google itself, through the IAM
//!   Credentials `signJwt` method, authenticated as the federated identity of the Connection's
//!   workload identity profile (see [`GoogleWorkloadIdentity`]). The service account's key never
//!   leaves Google. A refused federated token earns exactly one retry, with a fresh one.
//! - What comes back must carry exactly the claims that were sent, so a signer that answered for
//!   another user is refused rather than exchanged.
//! - The assertion is exchanged once, and the access token injected as `Authorization: Bearer`
//!   and cached under the Connection's revision, the caller and the egress policy, until shortly
//!   before Google's `expires_in` and for at most [`MAX_DELEGATED_TOKEN_CACHE_SECONDS`].
//!
//! Every endpoint is fixed: nothing a Connection or a caller supplies reaches a URL but the
//! validated service account's address. Every mint is audited as
//! [`audit::event::CONNECTION_GOOGLE_DELEGATION_TOKEN`] with the caller as its actor. No token
//! -- the federated identity's, the signed assertion or the issued access token -- and nothing
//! Google answered with beyond its status and a registered error code reaches an error, a log line
//! or an audit event.

use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use serde::{Deserialize, Serialize};
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
    caller_assertion::AttestedCaller,
    gcp_secret::{EgressGcpTransport, GcpHttpResponse, GcpTransport},
    model::ConnectionId,
    oauth::{
        connection_test_owns_token_requests, duration_millis, is_json_content_type,
        MintedOAuthToken, OAuthTokenCache, OAuthTokenCacheKey, OAuthTokenLease, SecretString,
        SystemOAuthClock, TokenCacheFailure, MAX_TOKEN_LIFETIME_SECS, MAX_TOKEN_TYPE_BYTES,
        OAUTH_MAX_REQUEST_BYTES,
    },
    secret::MAX_HTTP_CREDENTIAL_BYTES,
    token_exchange::{
        principal_digest, registered_error_code, MAX_DELEGATED_TOKEN_CACHE_ENTRIES,
        MAX_DELEGATED_TOKEN_CACHE_SECONDS, REGISTERED_ERROR_CODES,
    },
};

/// Google's OAuth 2.0 token endpoint: the `aud` of every assertion, and where it is exchanged.
/// Fixed rather than configurable, like the GCP provider's STS endpoint: tests substitute a
/// hermetic transport instead of redirecting identity traffic.
pub(crate) const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// The IAM Credentials API, whose `signJwt` method signs as a service account.
const IAM_CREDENTIALS_ORIGIN: &str = "https://iamcredentials.googleapis.com";

const GRANT_TYPE_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// How long a signed assertion is valid. Google accepts at most an hour; the assertion is
/// exchanged the moment it is signed, so a few minutes are plenty, and a copy that leaked is worth
/// little.
pub(crate) const ASSERTION_LIFETIME_SECONDS: u64 = 300;

// Google refuses an assertion that lives longer than an hour.
const _: () = assert!(ASSERTION_LIFETIME_SECONDS <= 3_600);

/// Longest signed assertion accepted from `signJwt`. An RS256 JWT over these claims is well under
/// 2 KiB.
const MAX_SIGNED_ASSERTION_BYTES: usize = 8 * 1024;

/// Longest email accepted as `sub` (RFC 5321's path limit).
const MAX_SUBJECT_EMAIL_BYTES: usize = 254;

const AUTH_TYPE: &str = "google_domain_wide_delegation";

/// The `request_id` of a mint's audit event. A mint serves every call of its caller until it is
/// refreshed, so it belongs to none of them.
const MINT_AUDIT_REQUEST_ID: &str = "connection-google-delegation";

/// Why a caller's Google token could not be obtained. Every variant refuses the call: nothing is
/// sent upstream without the caller's own token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoogleDelegationError {
    /// The caller carries no email, or one that is not a single plain address.
    NoEmail,
    /// The caller was attested by an identity provider the Connection does not trust to name
    /// Workspace users.
    IssuerNotTrusted,
    /// The egress policy refuses the token endpoint or the IAM Credentials API.
    EgressDenied,
    /// The federated identity could not be obtained: its profile is not configured, or its token
    /// file, Google STS or its impersonation refused or failed.
    IdentityFailed,
    /// `signJwt` refused or failed, typically because the federated identity may not sign as the
    /// service account, or answered with something other than the assertion asked for.
    SigningFailed,
    /// Google refused a token for this user: `invalid_grant` or `access_denied` on a 4xx, or any
    /// `403`.
    Denied,
    /// No usable token came back for a reason no caller can fix: the delegation is not authorised
    /// for these scopes (`unauthorized_client`), Google failed or could not be reached, or it
    /// answered with something other than a bearer token with a bounded lifetime.
    ExchangeFailed,
    /// Every cache entry is held by a call or a mint in flight.
    Unavailable,
}

impl GoogleDelegationError {
    /// A stable, non-revealing reason for errors, audit and metrics.
    pub const fn safe_reason(self) -> &'static str {
        match self {
            Self::NoEmail => "google_delegation_no_email",
            Self::IssuerNotTrusted => "google_delegation_issuer_not_trusted",
            Self::EgressDenied => "google_delegation_egress_denied",
            Self::IdentityFailed => "google_delegation_identity_failed",
            Self::SigningFailed => "google_delegation_signing_failed",
            Self::Denied => "google_delegation_denied",
            Self::ExchangeFailed => "google_delegation_exchange_failed",
            Self::Unavailable => "google_delegation_unavailable",
        }
    }

    /// Whether the egress policy refused the flow, as opposed to anything else failing.
    pub const fn is_egress_denial(self) -> bool {
        matches!(self, Self::EgressDenied)
    }

    /// Whether the caller, rather than the Connection or Google, is why there is no token: the
    /// call names nobody this Connection can act as.
    pub const fn is_caller_refusal(self) -> bool {
        matches!(self, Self::NoEmail | Self::IssuerNotTrusted)
    }
}

impl fmt::Display for GoogleDelegationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_reason())
    }
}

impl std::error::Error for GoogleDelegationError {}

impl TokenCacheFailure for GoogleDelegationError {
    const CACHE_FULL: Self = Self::Unavailable;
    const MINT_PANICKED: Self = Self::ExchangeFailed;
    const INVALID_TOKEN: Self = Self::ExchangeFailed;
    // The caller's own tokens were being purged as the call arrived.
    const RETIRED: Self = Self::Unavailable;
}

/// A federated Google identity, as a workload identity profile of the GCP secret provider holds
/// it: what the gateway authenticates to `signJwt` with.
///
/// [`super::gcp_secret::GcpSecretManagerProvider`] is the production implementation, with that
/// profile's own token cache, single flight and refresh; nothing here holds a federated token
/// beyond the one request it authenticates.
#[async_trait]
pub(crate) trait GoogleWorkloadIdentity: Send + Sync {
    /// The access token of the profile `profile_id` names, from an exchange of at least
    /// `minimum_generation`: `0` for whatever is cached, one more than a token's own generation
    /// to replace a token Google refused.
    async fn access_token(
        &self,
        profile_id: &str,
        minimum_generation: u64,
    ) -> Result<FederatedAccessToken, FederatedIdentityError>;
}

/// A federated identity's access token and the generation of the exchange that produced it.
pub(crate) struct FederatedAccessToken {
    pub token: Zeroizing<Vec<u8>>,
    pub generation: u64,
}

impl fmt::Debug for FederatedAccessToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FederatedAccessToken")
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

/// Why a federated identity could not be obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FederatedIdentityError {
    /// No profile of that ID is configured.
    UnknownProfile,
    /// The egress policy refuses an identity endpoint.
    EgressDenied,
    /// Anything else, with the provider's own fixed, non-revealing reason.
    Failed { reason: &'static str },
}

/// One Connection's delegation, as a target built from one revision of it binds it.
#[derive(Clone)]
pub(crate) struct GoogleDelegationBinding {
    pub connection_id: ConnectionId,
    pub connection_etag: String,
    pub service_account_email: String,
    pub workload_identity_profile: String,
    /// Sorted and unique, as validation stores them.
    pub scopes: Vec<String>,
    /// Canonical, as validation stores them.
    pub subject_issuers: Vec<String>,
    /// The Connection's OAuth-token egress client: both Google requests go through it, with its
    /// 16 KiB limits and the Connection's timeouts.
    pub token_client: Arc<EgressClient>,
    /// The federated identity the assertion is signed through (see
    /// `ConnectionControlPlane::google_workload_identity`), or `None` when the GCP provider is not
    /// active, which refuses every mint.
    pub identity: Option<Arc<dyn GoogleWorkloadIdentity>>,
}

/// Whose Google token a cache entry holds: the issuer and subject the key's principal digest is
/// taken over, so a purge another replica recorded -- which names only a digest -- is audited with
/// the principal it dropped (issue #441).
pub(crate) struct GooglePrincipal {
    issuer: String,
    subject: String,
}

/// A Google token one call holds: injected as `Authorization: Bearer`, and dropped from the cache
/// by an upstream `401`.
pub(crate) type GoogleDelegationLease = OAuthTokenLease<GoogleDelegationError, GooglePrincipal>;

type GoogleDelegationCache = OAuthTokenCache<GoogleDelegationError, GooglePrincipal>;

/// Small on purpose: every clone of the Connection runtime carries one, and it holds nothing a
/// binding cannot bring.
#[derive(Clone)]
pub(crate) struct GoogleDelegationRuntime {
    cache: Arc<GoogleDelegationCache>,
    audit: Option<AuditLog>,
    /// Test seam: the transport every Google request goes through instead of one over the
    /// binding's egress client. Always `None` outside tests.
    transport: Option<Arc<dyn GcpTransport>>,
}

impl fmt::Debug for GoogleDelegationRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GoogleDelegationRuntime")
            .field("cache_entries", &self.cache.slot_count())
            .field("audit_configured", &self.audit.is_some())
            .finish()
    }
}

impl GoogleDelegationRuntime {
    pub(crate) fn new() -> Self {
        Self {
            cache: Arc::new(OAuthTokenCache::with_capacity(
                Arc::new(SystemOAuthClock),
                MAX_DELEGATED_TOKEN_CACHE_ENTRIES,
            )),
            audit: None,
            transport: None,
        }
    }

    pub(crate) fn with_audit(mut self, audit: AuditLog) -> Self {
        self.audit = Some(audit);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_cache_for_test(
        mut self,
        clock: Arc<super::token_exchange::ManualTokenClock>,
        capacity: usize,
    ) -> Self {
        self.cache = Arc::new(OAuthTokenCache::with_capacity(clock, capacity));
        self
    }

    #[cfg(test)]
    pub(crate) fn with_transport_for_test(mut self, transport: Arc<dyn GcpTransport>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// How many callers' Google tokens are cached now, across every delegating Connection.
    pub(crate) fn cache_entry_count(&self) -> usize {
        self.cache.slot_count()
    }

    /// The token `caller` holds for `binding`'s upstream: the cached one, or a fresh mint.
    ///
    /// A caller the Connection cannot act as is refused before anything is read or sent.
    /// Concurrent calls of one caller share one mint, and a mint outlives a call that stops
    /// waiting for it, so a cancelled call never cancels another caller's work or its audit.
    ///
    /// A Connection test is the exception, as for a delegated issuer token: it mints inline,
    /// within its own deadline, for the principal running it, and neither reads nor fills the
    /// cache, so a test never hands a later call a token, nor passes on one an earlier call
    /// obtained.
    pub(crate) async fn access_token(
        &self,
        binding: &GoogleDelegationBinding,
        caller: &AttestedCaller,
    ) -> Result<GoogleDelegationLease, GoogleDelegationError> {
        let subject = delegated_subject(binding, caller)?.to_owned();
        if connection_test_owns_token_requests() {
            return Ok(OAuthTokenLease::uncached(
                self.mint(binding, caller, &subject).await?,
            ));
        }
        let identity = caller.identity();
        let key = OAuthTokenCacheKey {
            connection_id: binding.connection_id.to_string(),
            connection_etag: binding.connection_etag.clone(),
            subject: Some(subject_digest(identity.issuer, identity.subject, &subject)),
            principal: Some(principal_digest(identity.issuer, identity.subject)),
            // Nothing secret is bound: the profile is startup configuration, and a restart
            // already empties the cache.
            secret_version: None,
            egress_generation: binding.token_client.configuration_generation(),
        };
        let principal = || GooglePrincipal {
            issuer: identity.issuer.to_owned(),
            subject: identity.subject.to_owned(),
        };
        let runtime = self.clone();
        let minted_for = binding.clone();
        let caller_for_mint = caller.clone();
        self.cache
            .get_or_mint_with(key, principal, move || async move {
                runtime.mint(&minted_for, &caller_for_mint, &subject).await
            })
            .await
    }

    /// Drops every Google token cached for the principal `issuer` and `subject` name, under every
    /// delegating Connection and whatever email it carried, and returns how many entries that
    /// was. The principal's next call mints again, and Google decides whether the user may still
    /// have one. Nothing is revoked at Google: a dropped token stays valid there until it expires.
    pub(crate) fn purge_principal(&self, issuer: &str, subject: &str) -> usize {
        let Some(issuer) = canonical_issuer(issuer) else {
            return 0;
        };
        let principal = principal_digest(&issuer, subject);
        self.cache
            .retire_where(|key| key.principal == Some(principal))
            .len()
    }

    /// Drops every Google token cached for a principal `matches` accepts, by the digest
    /// [`principal_digest`] takes over its issuer and subject, and names the principal of each
    /// entry dropped: what applying a purge another replica recorded needs (issue #441). Nothing
    /// is revoked at Google.
    pub(crate) fn purge_principals_where(
        &self,
        matches: &dyn Fn(&[u8; 32]) -> bool,
    ) -> Vec<(String, String)> {
        self.cache
            .retire_where(|key| key.principal.as_ref().is_some_and(matches))
            .iter()
            .map(|slot| {
                let principal = slot.context();
                (principal.issuer.clone(), principal.subject.clone())
            })
            .collect()
    }

    fn transport_for(&self, binding: &GoogleDelegationBinding) -> Arc<dyn GcpTransport> {
        match self.transport.as_ref() {
            Some(transport) => Arc::clone(transport),
            None => Arc::new(EgressGcpTransport::new(Arc::clone(&binding.token_client))),
        }
    }

    async fn mint(
        &self,
        binding: &GoogleDelegationBinding,
        caller: &AttestedCaller,
        subject: &str,
    ) -> Result<MintedOAuthToken, GoogleDelegationError> {
        let mut attempt = MintAttempt::new(self.audit.clone(), binding, caller);
        let result = self.mint_inner(binding, subject, &mut attempt).await;
        attempt.finish(&result);
        result
    }

    async fn mint_inner(
        &self,
        binding: &GoogleDelegationBinding,
        subject: &str,
        attempt: &mut MintAttempt,
    ) -> Result<MintedOAuthToken, GoogleDelegationError> {
        let transport = self.transport_for(binding);
        let sign_url = sign_jwt_url(&binding.service_account_email);

        // Both endpoints pass the egress policy before the federated identity is read or anything
        // is signed: a refused host never sees a request, and nothing is signed that could not be
        // exchanged.
        attempt.stage = "egress";
        for (url, failure) in [
            (GOOGLE_TOKEN_URL, GoogleDelegationError::ExchangeFailed),
            (sign_url.as_str(), GoogleDelegationError::SigningFailed),
        ] {
            transport
                .preflight(url)
                .await
                .map_err(|error| egress_error(&error, failure))?;
        }

        let claims = AssertionClaims::new(binding, subject, unix_now()?);
        let assertion = self
            .sign_assertion(transport.as_ref(), binding, &sign_url, &claims, attempt)
            .await?;
        exchange_assertion(transport.as_ref(), &assertion, attempt).await
    }

    /// Has Google sign `claims` as the service account, authenticated as the profile's federated
    /// identity, and returns the signed assertion once it is checked to carry exactly `claims`.
    async fn sign_assertion(
        &self,
        transport: &dyn GcpTransport,
        binding: &GoogleDelegationBinding,
        sign_url: &str,
        claims: &AssertionClaims,
        attempt: &mut MintAttempt,
    ) -> Result<Zeroizing<String>, GoogleDelegationError> {
        attempt.stage = "identity";
        let Some(identity) = binding.identity.as_ref() else {
            attempt.identity_reason = Some("identity_not_configured");
            return Err(GoogleDelegationError::IdentityFailed);
        };
        let payload =
            serde_json::to_string(claims).map_err(|_| GoogleDelegationError::SigningFailed)?;
        let body = serde_json::to_vec(&json!({ "payload": payload }))
            .map_err(|_| GoogleDelegationError::SigningFailed)?;

        let profile = binding.workload_identity_profile.as_str();
        let mut federated = identity
            .access_token(profile, 0)
            .await
            .map_err(|error| attempt.identity_error(error))?;
        attempt.stage = "sign";
        let mut response = send_signing_request(transport, sign_url, &federated, &body).await?;
        if matches!(
            response.status,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            // A rotated, revoked or expired federated token is the one condition that earns a
            // second attempt, and only after a fresh exchange through the same profile.
            attempt.stage = "identity";
            federated = identity
                .access_token(profile, federated.generation.saturating_add(1))
                .await
                .map_err(|error| attempt.identity_error(error))?;
            attempt.stage = "sign";
            response = send_signing_request(transport, sign_url, &federated, &body).await?;
        }
        drop(federated);

        attempt.google_status = Some(response.status.as_u16());
        if response.status != StatusCode::OK
            || !is_json_content_type(response.headers.get(header::CONTENT_TYPE))
        {
            return Err(GoogleDelegationError::SigningFailed);
        }
        let signed: SignJwtResponse = serde_json::from_slice(response.body.as_slice())
            .map_err(|_| GoogleDelegationError::SigningFailed)?;
        let assertion = Zeroizing::new(signed.signed_jwt.as_str().to_owned());
        drop(signed);
        validate_signed_assertion(&assertion, claims)?;
        Ok(assertion)
    }
}

/// The address `caller` is acted as: their email, once their issuer is one the Connection trusts
/// to name Workspace users.
fn delegated_subject<'caller>(
    binding: &GoogleDelegationBinding,
    caller: &'caller AttestedCaller,
) -> Result<&'caller str, GoogleDelegationError> {
    let identity = caller.identity();
    if !binding
        .subject_issuers
        .iter()
        .any(|issuer| issuer == identity.issuer)
    {
        return Err(GoogleDelegationError::IssuerNotTrusted);
    }
    identity
        .email
        .filter(|email| is_single_plain_address(email))
        .ok_or(GoogleDelegationError::NoEmail)
}

/// Exactly one `@` between a non-empty local part and a dotted domain, printable ASCII only, and
/// no longer than [`MAX_SUBJECT_EMAIL_BYTES`]. Google decides whether the address is a user of
/// the domain; this only refuses a value that could not be one.
fn is_single_plain_address(email: &str) -> bool {
    if email.len() > MAX_SUBJECT_EMAIL_BYTES || !email.bytes().all(|byte| byte.is_ascii_graphic()) {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.contains('@')
        && domain.split('.').all(|label| !label.is_empty())
        && domain.contains('.')
}

/// Who a cached token belongs to: the attested issuer and subject, and the address it was minted
/// for, so a caller whose email changed at their provider is minted for again rather than served
/// a token for the old address. Length-prefixed so no two callers share an encoding.
fn subject_digest(issuer: &str, subject: &str, email: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"greengateway:google-delegation-subject:v1\0");
    for part in [issuer, subject, email] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    digest.finalize().into()
}

fn sign_jwt_url(service_account_email: &str) -> String {
    format!(
        "{IAM_CREDENTIALS_ORIGIN}/v1/projects/-/serviceAccounts/{service_account_email}:signJwt"
    )
}

/// Seconds since the Unix epoch, for `iat`. A clock that reads before the epoch is a broken host,
/// and nothing is signed with a made-up time.
fn unix_now() -> Result<u64, GoogleDelegationError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| GoogleDelegationError::SigningFailed)
}

/// The claims of one assertion, as Google's service-account flow defines them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AssertionClaims {
    iss: String,
    sub: String,
    scope: String,
    aud: String,
    iat: u64,
    exp: u64,
}

impl AssertionClaims {
    fn new(binding: &GoogleDelegationBinding, subject: &str, issued_at: u64) -> Self {
        Self {
            iss: binding.service_account_email.clone(),
            sub: subject.to_owned(),
            scope: binding.scopes.join(" "),
            aud: GOOGLE_TOKEN_URL.to_owned(),
            iat: issued_at,
            exp: issued_at.saturating_add(ASSERTION_LIFETIME_SECONDS),
        }
    }
}

fn federated_headers(federated: &FederatedAccessToken) -> Result<HeaderMap, GoogleDelegationError> {
    let mut bearer = Zeroizing::new(Vec::with_capacity("Bearer ".len() + federated.token.len()));
    bearer.extend_from_slice(b"Bearer ");
    bearer.extend_from_slice(federated.token.as_slice());
    let mut authorization = HeaderValue::from_bytes(bearer.as_slice())
        .map_err(|_| GoogleDelegationError::IdentityFailed)?;
    authorization.set_sensitive(true);
    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, authorization);
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
    Ok(headers)
}

async fn send_signing_request(
    transport: &dyn GcpTransport,
    sign_url: &str,
    federated: &FederatedAccessToken,
    body: &[u8],
) -> Result<GcpHttpResponse, GoogleDelegationError> {
    transport
        .send(
            Method::POST,
            sign_url,
            federated_headers(federated)?,
            Some(body.to_vec()),
        )
        .await
        .map_err(|error| egress_error(&error, GoogleDelegationError::SigningFailed))
}

/// The fields of a `signJwt` answer this reads. Anything else, the signing key's ID included, is
/// skipped unread.
#[derive(Deserialize)]
struct SignJwtResponse {
    #[serde(rename = "signedJwt")]
    signed_jwt: SecretString,
}

/// A JWS compact serialisation of at most [`MAX_SIGNED_ASSERTION_BYTES`] whose payload carries
/// exactly `expected`. The signature is Google's to produce and the token endpoint's to verify;
/// the payload is checked here because it is what says whom the token will be for.
fn validate_signed_assertion(
    assertion: &str,
    expected: &AssertionClaims,
) -> Result<(), GoogleDelegationError> {
    if assertion.len() > MAX_SIGNED_ASSERTION_BYTES
        || !assertion
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(GoogleDelegationError::SigningFailed);
    }
    let mut segments = assertion.split('.');
    let (Some(header), Some(payload), Some(signature), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(GoogleDelegationError::SigningFailed);
    };
    if header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(GoogleDelegationError::SigningFailed);
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| GoogleDelegationError::SigningFailed)?;
    let signed: AssertionClaims =
        serde_json::from_slice(&payload).map_err(|_| GoogleDelegationError::SigningFailed)?;
    if &signed != expected {
        return Err(GoogleDelegationError::SigningFailed);
    }
    Ok(())
}

/// Exchanges a signed assertion at Google's token endpoint with the JWT bearer grant (RFC 7523
/// section 2.1) and returns the access token, to be cached for at most
/// [`MAX_DELEGATED_TOKEN_CACHE_SECONDS`].
async fn exchange_assertion(
    transport: &dyn GcpTransport,
    assertion: &str,
    attempt: &mut MintAttempt,
) -> Result<MintedOAuthToken, GoogleDelegationError> {
    attempt.stage = "exchange";
    attempt.google_status = None;
    let body = exchange_request_body(assertion)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
    let response = transport
        .send(Method::POST, GOOGLE_TOKEN_URL, headers, Some(body))
        .await
        .map_err(|error| egress_error(&error, GoogleDelegationError::ExchangeFailed))?;

    attempt.google_status = Some(response.status.as_u16());
    let json = is_json_content_type(response.headers.get(header::CONTENT_TYPE));
    if response.status != StatusCode::OK {
        let code = if json {
            registered_error_code(response.body.as_slice(), REGISTERED_ERROR_CODES)
        } else {
            None
        };
        attempt.google_error = code;
        return Err(classify_refusal(response.status, code));
    }
    if !json {
        return Err(GoogleDelegationError::ExchangeFailed);
    }
    let mut token: TokenResponse = serde_json::from_slice(response.body.as_slice())
        .map_err(|_| GoogleDelegationError::ExchangeFailed)?;
    let expires_in = validate_token_response(&token)?;
    Ok(MintedOAuthToken {
        access_token: token.access_token.take_bytes(),
        lifetime: Duration::from_secs(expires_in.min(MAX_DELEGATED_TOKEN_CACHE_SECONDS)),
    })
}

fn exchange_request_body(assertion: &str) -> Result<Vec<u8>, GoogleDelegationError> {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("grant_type", GRANT_TYPE_JWT_BEARER);
    serializer.append_pair("assertion", assertion);
    let body = Zeroizing::new(serializer.finish());
    if body.len() > OAUTH_MAX_REQUEST_BYTES {
        return Err(GoogleDelegationError::ExchangeFailed);
    }
    Ok(body.as_bytes().to_vec())
}

/// The fields of a token response this reads. Anything else Google adds -- an ID token for an
/// `openid` scope, the granted scope -- is skipped unread rather than refused.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: SecretString,
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// Accepts only a token usable as a bearer header with a bounded, stated lifetime, and returns
/// that lifetime in seconds.
fn validate_token_response(token: &TokenResponse) -> Result<u64, GoogleDelegationError> {
    let expires_in = token
        .expires_in
        .filter(|seconds| (1..=MAX_TOKEN_LIFETIME_SECS).contains(seconds))
        .ok_or(GoogleDelegationError::ExchangeFailed)?;
    let access_token = token.access_token.as_str();
    if access_token.is_empty()
        || access_token.len() > MAX_HTTP_CREDENTIAL_BYTES
        || access_token.contains('\0')
        || token.token_type.len() > MAX_TOKEN_TYPE_BYTES
        || !token.token_type.eq_ignore_ascii_case("bearer")
        || HeaderValue::from_bytes(access_token.as_bytes()).is_err()
    {
        return Err(GoogleDelegationError::ExchangeFailed);
    }
    Ok(expires_in)
}

/// A refusal is Google declining this user only when it says so: `invalid_grant` (not a user of
/// the domain, or suspended) or `access_denied` on a client error, or a `403`. Everything else --
/// `unauthorized_client` for a delegation the administrator never authorised for these scopes, a
/// malformed request, a server error -- is the exchange failing, which no caller can fix.
fn classify_refusal(status: StatusCode, code: Option<&'static str>) -> GoogleDelegationError {
    if status == StatusCode::FORBIDDEN
        || (status.is_client_error() && matches!(code, Some("invalid_grant" | "access_denied")))
    {
        GoogleDelegationError::Denied
    } else {
        GoogleDelegationError::ExchangeFailed
    }
}

/// A policy refusal is [`GoogleDelegationError::EgressDenied`] wherever it happens; any other
/// transport failure is `otherwise`, the failure of the step that was being attempted.
fn egress_error(error: &EgressError, otherwise: GoogleDelegationError) -> GoogleDelegationError {
    match error {
        EgressError::HostNotAllowed(_)
        | EgressError::PortNotAllowed(_)
        | EgressError::NonGlobalIpBlocked(_)
        | EgressError::InvalidPolicy(_)
        | EgressError::InvalidUrl(_)
        | EgressError::SchemeNotAllowed(_) => GoogleDelegationError::EgressDenied,
        EgressError::ResponseTooLarge { .. }
        | EgressError::DnsResolutionFailed(_)
        | EgressError::RequestBodyTooLarge { .. }
        | EgressError::RequestBodyReadFailed
        | EgressError::UnexpectedStatus(_)
        | EgressError::ResponseIdleTimeout { .. }
        | EgressError::InvalidTlsCaBundle { .. }
        | EgressError::InvalidTlsClientIdentity
        | EgressError::Http(_) => otherwise,
        // Unreachable: both requests go through the pinned HTTP/1.1 transport, never through
        // `egress::grpc`. Named rather than wildcarded so a new transport cannot land here
        // silently.
        EgressError::Grpc(_) => otherwise,
    }
}

/// The audit record of one mint, emitted exactly once: when it finishes, or, should the task
/// running it be dropped first, as cancelled.
struct MintAttempt {
    audit: Option<AuditLog>,
    connection_id: String,
    actor: Actor,
    service_account: String,
    scopes: Vec<String>,
    started: Instant,
    /// The last step attempted: `egress`, `identity`, `sign` or `exchange`.
    stage: &'static str,
    /// The federated identity's own fixed reason, when that is what failed.
    identity_reason: Option<&'static str>,
    google_status: Option<u16>,
    google_error: Option<&'static str>,
    completed: bool,
}

impl MintAttempt {
    fn new(
        audit: Option<AuditLog>,
        binding: &GoogleDelegationBinding,
        caller: &AttestedCaller,
    ) -> Self {
        Self {
            audit,
            connection_id: binding.connection_id.to_string(),
            actor: caller.audit_actor(),
            service_account: binding.service_account_email.clone(),
            scopes: binding.scopes.clone(),
            started: Instant::now(),
            stage: "egress",
            identity_reason: None,
            google_status: None,
            google_error: None,
            completed: false,
        }
    }

    fn identity_error(&mut self, error: FederatedIdentityError) -> GoogleDelegationError {
        match error {
            FederatedIdentityError::UnknownProfile => {
                self.identity_reason = Some("unknown_profile");
                GoogleDelegationError::IdentityFailed
            }
            FederatedIdentityError::EgressDenied => GoogleDelegationError::EgressDenied,
            FederatedIdentityError::Failed { reason } => {
                self.identity_reason = Some(reason);
                GoogleDelegationError::IdentityFailed
            }
        }
    }

    fn finish(&mut self, result: &Result<MintedOAuthToken, GoogleDelegationError>) {
        let (outcome, reason) = match result {
            Ok(_) => ("success", "minted"),
            Err(error) => ("failure", error.safe_reason()),
        };
        self.completed = true;
        self.emit(outcome, reason);
    }

    fn emit(&self, outcome: &'static str, reason: &'static str) {
        metrics::counter!(
            "connection_google_delegation_token_total",
            "result" => outcome,
            "reason" => reason
        )
        .increment(1);
        let Some(audit) = self.audit.as_ref() else {
            return;
        };
        audit.emit(AuditEvent::new(
            audit::event::CONNECTION_GOOGLE_DELEGATION_TOKEN,
            MINT_AUDIT_REQUEST_ID,
            "internal",
            Some(self.actor.clone()),
            json!({
                "connection_id": self.connection_id,
                "auth_type": AUTH_TYPE,
                "outcome": outcome,
                "reason": reason,
                "service_account": self.service_account,
                "scopes": self.scopes,
                "stage": self.stage,
                "identity_reason": self.identity_reason,
                "google_status": self.google_status,
                "google_error": self.google_error,
                "latency_ms": duration_millis(self.started.elapsed()),
            }),
        ));
    }
}

impl Drop for MintAttempt {
    fn drop(&mut self) {
        if !self.completed {
            self.emit("failure", "google_delegation_cancelled");
        }
    }
}

#[cfg(test)]
#[path = "google_delegation_tests.rs"]
mod tests;
