use std::{
    collections::HashMap,
    error::Error,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};

use http::{
    header::{self, HeaderName},
    HeaderMap, HeaderValue, Method, Uri,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::egress::{CheckedEgressDestination, EgressClient, EgressConfig};

use super::{
    caller_assertion::{
        load_signing_key, sign_caller_assertion, AssertionAlgorithm, AssertionSigningKey,
        AttestedCaller, CallerAssertionConfig, CallerAssertionError, PrincipalClaim,
        RequestBinding,
    },
    control_plane::ConnectionControlPlane,
    google_delegation::{
        GoogleDelegationBinding, GoogleDelegationError, GoogleDelegationLease,
        GoogleDelegationRuntime,
    },
    model::{
        normalize_origin_relative_path, CallerAssertionSettings, ConnectionAuthentication,
        ConnectionId, ConnectionKind, ConnectionTestProfile, ConnectionTimeouts, ConnectionWrite,
        DiscoveryConfig, GoogleSubjectClaim, OAuthClientAuthMethod, SubjectTokenSource, TlsProfile,
        MAX_CONNECTIONS, MAX_EXPECTED_STATUSES, MAX_URL_BYTES,
    },
    oauth::{
        OAuthBinding, OAuthClientCredentialsRuntime, OAuthError, OAuthTokenLease,
        OAUTH_MAX_REQUEST_BYTES, OAUTH_MAX_RESPONSE_BYTES,
    },
    secret::{ResolvedSecret, SecretPurpose, SecretResolveError, SecretResolveErrorKind},
    status::ConnectionRevisions,
    store::{ConnectionDependencyKind, StoredConnection},
    token_exchange::{
        DelegatedTokenBinding, DelegatedTokenError, DelegatedTokenLease,
        DelegatedTokenPurgeTrigger, DelegatedTokenRuntime, SubjectTokenSettings,
    },
};

#[derive(Clone)]
pub struct ConnectionHttpRuntime {
    control_plane: ConnectionControlPlane,
    base_egress_config: EgressConfig,
    base_egress_client: Arc<EgressClient>,
    clients: Arc<Mutex<HashMap<ConnectionClientCacheKey, Arc<EgressClient>>>>,
    oauth: OAuthClientCredentialsRuntime,
    delegated: DelegatedTokenRuntime,
    google: GoogleDelegationRuntime,
    #[cfg(test)]
    additional_resolution_delay: Option<std::time::Duration>,
}

/// A validator's refusal of a revoked credential purges the principal's delegated tokens: whatever
/// else that principal still holds, nothing exchanged for them before the revocation is served
/// again without asking the issuer.
impl crate::auth::RevokedCredentialObserver for ConnectionHttpRuntime {
    fn credential_revoked(&self, issuer: &str, subject: &str) {
        self.purge_delegated_tokens(
            issuer,
            subject,
            DelegatedTokenPurgeTrigger::CredentialRevoked,
        );
    }
}

impl fmt::Debug for ConnectionHttpRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionHttpRuntime")
            .field("cached_client_count", &self.client_guard().len())
            .field(
                "delegated_token_cache_entries",
                &self.delegated.cache_entry_count(),
            )
            .field(
                "google_delegation_cache_entries",
                &self.google.cache_entry_count(),
            )
            .finish_non_exhaustive()
    }
}

pub struct ConnectionHttpTarget {
    connection_id: ConnectionId,
    connection_etag: String,
    url: String,
    client: Arc<EgressClient>,
    authentication: HttpAuthenticationBinding,
    additional_headers: Vec<AdditionalHeaderBinding>,
    /// Every header this Connection owns on the wire, primary credential
    /// first and then the additional headers in configured order. Each lane
    /// strips exactly this set from the inbound request before injection.
    credential_header_names: Vec<HeaderName>,
    transport: ConnectionTransportBinding,
    /// What a tool call signs and where it sends it, when the Connection
    /// attests its caller. Only the constructors of an [`AttestingLane`] ever
    /// set this; every other constructor refuses such a Connection.
    caller_assertion: Option<CallerAssertionBinding>,
}

/// A Connection's caller assertion, as a tool call signs it.
///
/// Holds the key's alias, never the key: the key is read and loaded on every
/// call that signs, exactly like every other secret a Connection binds, so a
/// rotated or withdrawn key takes effect on the next call.
#[derive(Clone)]
struct CallerAssertionBinding {
    header_name: HeaderName,
    signing_key_id: String,
    kid: String,
    algorithm: AssertionAlgorithm,
    issuer: String,
    audience: String,
    token_type: String,
    lifetime_seconds: u64,
    claims: Vec<PrincipalClaim>,
    bind_request: bool,
    /// Whether the assertion goes upstream as `header_name`. A
    /// `delegated_issuer_token` Connection sends it only to its issuer, as the
    /// subject token: the upstream there is a third party that receives the
    /// caller's own token and has no use for a statement it could replay at
    /// the issuer. Admission still applies, because the issuer verifies the
    /// subject token against the same published keys.
    signs_upstream: bool,
    /// The configuration this binding was read from. Admission judges the
    /// Connection against this snapshot rather than reading the live one
    /// again, so the verdict and the key the call signs with always describe
    /// the same record.
    configuration: Arc<super::control_plane::ConnectionRuntimeSnapshot>,
}

impl CallerAssertionBinding {
    fn from_settings(
        settings: &CallerAssertionSettings,
        configuration: Arc<super::control_plane::ConnectionRuntimeSnapshot>,
    ) -> Result<Self, ConnectionHttpError> {
        Ok(Self {
            header_name: HeaderName::from_bytes(settings.header_name.as_bytes())
                .map_err(|_| ConnectionHttpError::CallerAssertionNotEnforced)?,
            signing_key_id: settings.signing_key_id.clone(),
            kid: settings.kid.clone(),
            algorithm: settings.algorithm.into(),
            issuer: settings.issuer.clone(),
            audience: settings.audience.clone(),
            token_type: settings.token_type.clone(),
            lifetime_seconds: u64::from(settings.lifetime_seconds),
            claims: settings.claims.iter().copied().map(Into::into).collect(),
            bind_request: settings.bind_request,
            signs_upstream: true,
            configuration,
        })
    }
}

/// The signing key of one tool call's caller assertion, read and loaded, and
/// the request target it will bind.
///
/// The key is loaded before the call resolves its credential, so a key that
/// cannot sign refuses the call before any token endpoint is asked for a
/// token; the assertion itself is signed only once the request is final, by
/// [`Self::sign`], which consumes the signer so a call signs exactly once.
pub struct CallerAssertionSigner<'target> {
    binding: &'target CallerAssertionBinding,
    key: AssertionSigningKey,
    /// The origin-form request target, when the assertion binds the request.
    request_target: Option<String>,
}

impl fmt::Debug for CallerAssertionSigner<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallerAssertionSigner")
            .field("kid", &self.binding.kid)
            .finish_non_exhaustive()
    }
}

impl CallerAssertionSigner<'_> {
    /// Signs the one assertion this request carries.
    ///
    /// Called once, after every other header and the body are final, because
    /// with `bind_request` the assertion covers the method, the request
    /// target exactly as it goes on the wire, and the exact body bytes.
    /// `request_id` becomes `jti`, which is how an upstream joins its log
    /// line to this gateway's audit event for the call.
    pub fn sign(
        self,
        caller: Option<&AttestedCaller>,
        request_id: &str,
        method: &Method,
        body: &[u8],
    ) -> Result<SignedCallerAssertion, CallerAssertionError> {
        let caller = caller.ok_or(CallerAssertionError::NoPrincipal)?;
        sign_bound_request(
            self.binding,
            &self.key,
            self.request_target.as_deref(),
            caller,
            request_id,
            method,
            body,
        )
    }

    /// Whether the assertion covers the request body, which a lane must then
    /// hold in full before it signs: an assertion over part of a body is one
    /// no upstream could verify.
    pub fn binds_request_body(&self) -> bool {
        self.request_target.is_some()
    }

    /// Keeps the loaded key for a call that sends several requests, each of
    /// which carries its own assertion: a managed MCP tool call opens a
    /// session, and every request of it -- initialization, the call itself,
    /// the event stream and the closing `DELETE` -- names the caller.
    ///
    /// Each request is signed separately, with its own `jti`, so an upstream
    /// that keeps a replay cache keyed on `sub` and `jti` accepts every one of
    /// them, and with `bind_request` each covers its own method and body.
    pub fn into_session(
        self,
        caller: &AttestedCaller,
        request_id: &str,
    ) -> SessionCallerAssertions {
        SessionCallerAssertions {
            inner: Arc::new(SessionCallerAssertionsInner {
                binding: self.binding.clone(),
                key: self.key,
                request_target: self.request_target,
                caller: caller.clone(),
                jti_base: request_id.to_owned(),
                state: Mutex::new(SessionAssertionState::default()),
            }),
        }
    }
}

/// Signs one assertion for one request: the claims `binding` configures, for
/// `caller`, with `jti` and, when `request_target` is set, the method, that
/// target and the exact body bytes.
fn sign_bound_request(
    binding: &CallerAssertionBinding,
    key: &AssertionSigningKey,
    request_target: Option<&str>,
    caller: &AttestedCaller,
    jti: &str,
    method: &Method,
    body: &[u8],
) -> Result<SignedCallerAssertion, CallerAssertionError> {
    let request_binding = request_target.map(|path| RequestBinding {
        method: method.as_str(),
        path,
        body,
    });
    let config = CallerAssertionConfig {
        issuer: &binding.issuer,
        audience: &binding.audience,
        token_type: &binding.token_type,
        lifetime_seconds: binding.lifetime_seconds,
        claims: &binding.claims,
        bind_request: binding.bind_request,
        // Validation refuses `bind_approval` on every Connection this
        // target can be built for.
        bind_approval: false,
    };
    let token = sign_caller_assertion(
        key,
        &config,
        Some(&caller.identity()),
        jti,
        unix_now()?,
        request_binding.as_ref(),
        None,
    )?;
    let mut value =
        HeaderValue::from_str(&token).map_err(|_| CallerAssertionError::SignatureFailed)?;
    value.set_sensitive(true);
    Ok(SignedCallerAssertion {
        header_name: binding.header_name.clone(),
        value,
        record: IssuedCallerAssertion {
            kid: binding.kid.clone(),
            jti: jti.to_owned(),
        },
    })
}

/// The assertions of one call that sends several requests, signed one per
/// request; see [`CallerAssertionSigner::into_session`].
///
/// Cheap to clone: every clone signs from the same key and counts into the
/// same sequence. The `n`th request signed carries `jti` `<request ID>.<n>`,
/// counting from 1. [`Self::seal`] ends the sequence, so every assertion this
/// gateway sent for the call is one the call's audit event counts.
#[derive(Clone)]
pub struct SessionCallerAssertions {
    inner: Arc<SessionCallerAssertionsInner>,
}

struct SessionCallerAssertionsInner {
    binding: CallerAssertionBinding,
    key: AssertionSigningKey,
    request_target: Option<String>,
    caller: AttestedCaller,
    jti_base: String,
    state: Mutex<SessionAssertionState>,
}

#[derive(Default)]
struct SessionAssertionState {
    signed: u32,
    sealed: bool,
}

/// What audit records about the assertions one call's requests carried: the
/// key that signed them, the request ID their `jti`s extend, and how many
/// were sent. Request `n` carried `jti` `<jti_base>.<n>`. Never a token.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IssuedSessionCallerAssertions {
    pub kid: String,
    pub jti_base: String,
    pub count: u32,
}

impl fmt::Debug for SessionCallerAssertions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionCallerAssertions")
            .field("kid", &self.inner.binding.kid)
            .field("jti_base", &self.inner.jti_base)
            .finish_non_exhaustive()
    }
}

impl SessionCallerAssertions {
    /// The header every assertion of the session travels in.
    pub fn header_name(&self) -> &HeaderName {
        &self.inner.binding.header_name
    }

    /// Signs the assertion for the next request, once its method and body
    /// are final. Refuses once the call has been sealed: a request sent
    /// after the call's audit event was written would carry an assertion no
    /// record names.
    pub fn sign_next(
        &self,
        method: &Method,
        body: &[u8],
    ) -> Result<SignedCallerAssertion, CallerAssertionError> {
        // Held while signing, which does no I/O: a request that fails to sign
        // is never counted, and sealing waits for a signature in progress, so
        // the count is exactly what was signed.
        let mut state = self.state_guard();
        if state.sealed {
            return Err(CallerAssertionError::SignatureFailed);
        }
        let sequence = state
            .signed
            .checked_add(1)
            .ok_or(CallerAssertionError::SignatureFailed)?;
        let jti = format!("{}.{sequence}", self.inner.jti_base);
        let signed = sign_bound_request(
            &self.inner.binding,
            &self.inner.key,
            self.inner.request_target.as_deref(),
            &self.inner.caller,
            &jti,
            method,
            body,
        )?;
        state.signed = sequence;
        Ok(signed)
    }

    /// Ends the session's sequence and says what it sent, or `None` when no
    /// request was signed. Nothing signs after this.
    pub fn seal(&self) -> Option<IssuedSessionCallerAssertions> {
        let mut state = self.state_guard();
        state.sealed = true;
        (state.signed > 0).then(|| IssuedSessionCallerAssertions {
            kid: self.inner.binding.kid.clone(),
            jti_base: self.inner.jti_base.clone(),
            count: state.signed,
        })
    }

    fn state_guard(&self) -> MutexGuard<'_, SessionAssertionState> {
        // The state is a counter and a flag, each written whole under the
        // lock, so a poisoned guard still holds a consistent value.
        match self.inner.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// One signed caller assertion, ready to go on exactly one request.
///
/// Its `Debug` and every error it can produce name only the `kid` and `jti`:
/// the token is a bearer credential until it expires.
pub struct SignedCallerAssertion {
    header_name: HeaderName,
    value: HeaderValue,
    record: IssuedCallerAssertion,
}

/// What audit records about an assertion this gateway sent: which key signed
/// it and the identifier the upstream sees as `jti`. Never the token.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IssuedCallerAssertion {
    pub kid: String,
    pub jti: String,
}

impl fmt::Debug for SignedCallerAssertion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedCallerAssertion")
            .field("header_name", &self.header_name)
            .field("kid", &self.record.kid)
            .field("jti", &self.record.jti)
            .finish_non_exhaustive()
    }
}

impl SignedCallerAssertion {
    /// Puts the assertion on `headers`, as the last header written.
    ///
    /// Refuses, rather than replaces, a value already under the name: by the
    /// time this runs every other header source has written, so anything
    /// there would leave the upstream with a second or substitute assertion
    /// it did not get from this gateway. Validation keeps the name apart from
    /// every header the Connection or the tool sets; this is the check that
    /// holds even if one of those rules were to change.
    pub fn inject(
        self,
        headers: &mut HeaderMap,
    ) -> Result<IssuedCallerAssertion, CallerAssertionError> {
        if headers.contains_key(&self.header_name) {
            return Err(CallerAssertionError::HeaderConflict);
        }
        headers.insert(self.header_name, self.value);
        Ok(self.record)
    }

    pub fn issued(&self) -> &IssuedCallerAssertion {
        &self.record
    }
}

impl ConnectionHttpTarget {
    fn assemble(
        connection_id: ConnectionId,
        connection_etag: String,
        url: String,
        client: Arc<EgressClient>,
        authentication: HttpAuthenticationBinding,
        additional_headers: Vec<AdditionalHeaderBinding>,
        transport: ConnectionTransportBinding,
    ) -> Self {
        let mut credential_header_names = Vec::with_capacity(additional_headers.len() + 1);
        match &authentication {
            HttpAuthenticationBinding::None => {}
            HttpAuthenticationBinding::HeaderApiKey { header_name, .. } => {
                credential_header_names.push(header_name.clone());
            }
            HttpAuthenticationBinding::StaticBearer { .. }
            | HttpAuthenticationBinding::OAuth2ClientCredentials(_)
            | HttpAuthenticationBinding::DelegatedIssuerToken(_)
            | HttpAuthenticationBinding::GoogleDomainWideDelegation(_) => {
                credential_header_names.push(header::AUTHORIZATION);
            }
        }
        credential_header_names.extend(
            additional_headers
                .iter()
                .map(|binding| binding.header_name.clone()),
        );
        Self {
            connection_id,
            connection_etag,
            url,
            client,
            authentication,
            additional_headers,
            credential_header_names,
            transport,
            caller_assertion: None,
        }
    }
}

struct AdditionalHeaderBinding {
    header_name: HeaderName,
    secret_id: String,
}

#[derive(Clone)]
struct ConnectionTransportBinding {
    tls: TlsProfile,
    timeouts: ConnectionTimeouts,
    revisions: ConnectionRevisions,
}

struct ResolvedTlsProfile {
    ca_bundle: Option<ResolvedSecret>,
    client_identity: Option<(ResolvedSecret, ResolvedSecret)>,
}

pub struct PreparedConnectionTransport {
    client: Arc<EgressClient>,
    destination: CheckedEgressDestination,
}

pub struct ConnectionHttpTestTarget {
    target: ConnectionHttpTarget,
    method: Method,
    expected_statuses: Vec<u16>,
}

enum HttpAuthenticationBinding {
    None,
    HeaderApiKey {
        header_name: HeaderName,
        secret_id: String,
    },
    StaticBearer {
        secret_id: String,
    },
    OAuth2ClientCredentials(OAuthBinding),
    DelegatedIssuerToken(DelegatedTokenBinding),
    GoogleDomainWideDelegation(GoogleDelegationBinding),
}

pub struct ResolvedConnectionCredential {
    material: Option<ResolvedCredentialMaterial>,
    additional_headers: Vec<ResolvedAdditionalHeader>,
}

struct ResolvedAdditionalHeader {
    header_name: HeaderName,
    secret: ResolvedSecret,
}

enum ResolvedCredentialMaterial {
    HeaderApiKey {
        header_name: HeaderName,
        secret: ResolvedSecret,
    },
    StaticBearer {
        secret: ResolvedSecret,
    },
    OAuthBearer(OAuthTokenLease),
    /// The caller's own token, from the Connection's token-exchange issuer.
    DelegatedBearer(DelegatedTokenLease),
    /// The caller's own Google token, from a domain-wide delegation.
    GoogleBearer(GoogleDelegationLease),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionHttpError {
    InvalidConnectionId,
    ConnectionNotFound,
    ConnectionDisabled,
    WrongConnectionKind,
    UnsupportedAuthentication,
    /// The Connection carries a `caller_assertion` block that this lane does
    /// not sign, or that only the legacy reading of a stored document admits.
    /// Sending the call anyway would hand the upstream a request it cannot
    /// attribute while the operator believes every call is attested.
    CallerAssertionNotEnforced,
    TlsInvalid,
    TlsUnavailable,
    InvalidTargetPath,
    CredentialHeaderConflict,
    CredentialInvalid,
    CredentialUnavailable,
    OAuthTokenEgressDenied,
    OAuthTokenUnavailable,
    OAuthTokenRejected,
    OAuthTokenInvalidResponse,
    /// A `delegated_issuer_token` Connection was asked for a call that names
    /// nobody: no principal, or a service token. There is no shared identity
    /// to fall back to.
    DelegatedTokenNoPrincipal,
    /// The egress policy refuses the token-exchange endpoint.
    DelegatedTokenEgressDenied,
    /// The issuer refused this caller: no grant for the upstream, or a
    /// revoked one.
    DelegatedTokenDenied,
    /// The exchange produced no usable token for a reason no caller can fix.
    DelegatedTokenExchangeFailed,
    /// Every cached delegated token is held by a call in flight.
    DelegatedTokenUnavailable,
    /// A `google_domain_wide_delegation` Connection could not obtain the
    /// caller's own Google token. A call that names nobody is
    /// [`Self::DelegatedTokenNoPrincipal`] instead, as for any credential
    /// that belongs to the caller.
    GoogleDelegation(GoogleDelegationError),
    UpstreamAuthenticationRejected,
    TransportUnavailable,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConnectionClientProfile {
    Upstream,
    OAuthToken,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum ConnectionClientCacheKey {
    Preflight([u8; 32]),
    Prepared([u8; 32]),
}

impl ConnectionClientProfile {
    const fn key(self) -> &'static str {
        match self {
            Self::Upstream => "upstream",
            Self::OAuthToken => "oauth-token",
        }
    }
}

impl ConnectionHttpRuntime {
    pub fn new(
        control_plane: ConnectionControlPlane,
        base_egress_config: EgressConfig,
        base_egress_client: Arc<EgressClient>,
    ) -> Self {
        let oauth = OAuthClientCredentialsRuntime::new(control_plane.clone());
        let delegated = DelegatedTokenRuntime::new(control_plane.clone());
        let google = GoogleDelegationRuntime::new();
        Self {
            control_plane,
            base_egress_config,
            base_egress_client,
            clients: Arc::new(Mutex::new(HashMap::new())),
            oauth,
            delegated,
            google,
            #[cfg(test)]
            additional_resolution_delay: None,
        }
    }

    pub fn with_audit(mut self, audit: crate::audit::AuditLog) -> Self {
        self.oauth = self.oauth.with_audit(audit.clone());
        self.delegated = self.delegated.with_audit(audit.clone());
        self.google = self.google.with_audit(audit);
        self
    }

    /// Purges every delegated token this process caches for the principal `issuer` and `subject`
    /// name, under every `delegated_issuer_token` Connection, and revokes each at its issuer in
    /// the background where the Connection names a `revocation_url`. Every Google token cached
    /// for the principal under a `google_domain_wide_delegation` Connection is dropped too, and
    /// counted, though Google offers no revocation for it. Returns how many cache entries were
    /// purged. Each replica holds its own caches, so this purges this process's only.
    pub fn purge_delegated_tokens(
        &self,
        issuer: &str,
        subject: &str,
        trigger: DelegatedTokenPurgeTrigger,
    ) -> usize {
        let google_purged = self.google.purge_principal(issuer, subject);
        self.delegated
            .purge_principal(issuer, subject, trigger, google_purged)
    }

    /// Sends every Google request of every domain-wide delegation through `transport`, and keeps
    /// at most `capacity` callers' tokens on `clock`, so a test can stand in for Google.
    #[cfg(test)]
    pub(crate) fn with_google_delegation_for_test(
        mut self,
        transport: Arc<dyn super::gcp_secret::GcpTransport>,
        clock: Arc<super::token_exchange::ManualTokenClock>,
        capacity: usize,
    ) -> Self {
        self.google = self
            .google
            .with_transport_for_test(transport)
            .with_cache_for_test(clock, capacity);
        self
    }

    /// How many callers' Google tokens are cached now.
    #[cfg(test)]
    pub(crate) fn google_delegation_cache_entries(&self) -> usize {
        self.google.cache_entry_count()
    }

    /// Replaces the delegated-token cache with one of `capacity` entries
    /// driven by `clock`, so a test can expire and evict tokens on purpose.
    #[cfg(test)]
    pub(crate) fn with_delegated_token_cache_for_test(
        mut self,
        clock: Arc<super::token_exchange::ManualTokenClock>,
        capacity: usize,
    ) -> Self {
        self.delegated = self.delegated.with_cache_for_test(clock, capacity);
        self
    }

    /// How many callers' delegated tokens are cached now.
    #[cfg(test)]
    pub(crate) fn delegated_token_cache_entries(&self) -> usize {
        self.delegated.cache_entry_count()
    }

    #[cfg(test)]
    fn with_additional_resolution_delay_for_test(mut self, delay: std::time::Duration) -> Self {
        self.additional_resolution_delay = Some(delay);
        self
    }

    /// The Connection snapshot a target is resolved from: the one pinned
    /// for the current request when the security gate admitted it, or the
    /// live one outside a request. A request admitted at revision N must
    /// dispatch to the Connection state of N -- never to an endpoint a
    /// later reconcile installed while the request was in flight, under an
    /// allow that a later policy would have withdrawn.
    fn effective_snapshot(&self) -> Arc<super::control_plane::ConnectionRuntimeSnapshot> {
        PINNED_CONNECTIONS
            .try_with(Arc::clone)
            .unwrap_or_else(|_| self.control_plane.runtime_snapshot())
    }

    pub fn target(
        &self,
        connection_id: &str,
        path_and_query: &str,
    ) -> Result<ConnectionHttpTarget, ConnectionHttpError> {
        let connection_id = ConnectionId::parse(connection_id.to_owned())
            .map_err(|_| ConnectionHttpError::InvalidConnectionId)?;
        let snapshot = self.effective_snapshot();
        let record = managed_record(&snapshot, &connection_id)?;
        validate_http_connection(record)?;
        let url = connection_target_url(record, path_and_query)?;
        let client = self.client_for(record)?;
        let authentication = self.authentication_binding(record)?;
        let additional_headers = additional_header_bindings(record)?;

        Ok(ConnectionHttpTarget::assemble(
            connection_id,
            record.etag().to_string(),
            url,
            client,
            authentication,
            additional_headers,
            connection_transport_binding(record),
        ))
    }

    /// The target of one manual HTTP tool call. Like every attesting lane's
    /// constructor it serves a Connection carrying a `caller_assertion`, and
    /// it is one of the two tool lanes, with [`Self::openapi_tool_target`],
    /// that serve a `delegated_issuer_token` Connection, whose assertion is
    /// the subject token of its exchange.
    ///
    /// A lane may attest its caller when it has a validated principal to
    /// attest and the exact bytes it sends in hand before it sends them: tool
    /// calls (this, [`Self::openapi_tool_target`] and
    /// [`Self::mcp_tool_call_target`]), the leaf requests of a composite tool
    /// ([`Self::composite_leaf_target`]) and proxied requests
    /// ([`Self::proxy_route_target`]). A stored test attests the principal
    /// running it, for a delegated Connection only ([`Self::test_target`]).
    /// Every other lane -- discovery, enum and label sources -- builds its
    /// target with a constructor that keeps refusing such a Connection with
    /// `caller_assertion_not_enforced`, as do these for a stored assertion
    /// that only the legacy reading admits
    /// ([`ConnectionWrite::caller_assertion_enforceable`]).
    ///
    /// The returned target carries the assertion's settings. The caller must
    /// admit the call with [`Self::admit_caller_assertion`] before any I/O,
    /// load the key with [`Self::caller_assertion_signer`] before it resolves
    /// the credential, and sign with [`CallerAssertionSigner::sign`] once the
    /// request is final.
    ///
    /// [`ConnectionWrite::caller_assertion_enforceable`]:
    ///     super::model::ConnectionWrite::caller_assertion_enforceable
    pub fn tool_call_target(
        &self,
        connection_id: &str,
        path_and_query: &str,
    ) -> Result<ConnectionHttpTarget, ConnectionHttpError> {
        self.attesting_http_target(connection_id, path_and_query, AttestingLane::ManualTool)
    }

    /// The target of one managed OpenAPI tool call, attested like a manual
    /// tool's; see [`Self::tool_call_target`]. Like a manual tool's, it
    /// serves a `delegated_issuer_token` Connection: the call runs through
    /// the same executor path, which obtains the caller's own token, so a
    /// catalog whose user-consent schemes bound to the per-caller credential
    /// (issue #443) sends each caller's token and no one else's.
    pub fn openapi_tool_target(
        &self,
        connection_id: &str,
        path_and_query: &str,
    ) -> Result<ConnectionHttpTarget, ConnectionHttpError> {
        self.attesting_http_target(connection_id, path_and_query, AttestingLane::OpenApiTool)
    }

    /// The target of one leaf request of a composite tool: a forward step,
    /// one iteration of a fan-out, or a compensation. Each leaf calls one of
    /// the managed OpenAPI tools the composite is built from, so it is
    /// attested like one (see [`Self::openapi_tool_target`]), with an
    /// assertion of its own: the composite gives every leaf a distinct `jti`,
    /// so an upstream that refuses a `jti` it has already seen accepts every
    /// request of the call. A `delegated_issuer_token` Connection is refused
    /// with `caller_assertion_not_enforced`, as before composite steps signed
    /// anything.
    pub fn composite_leaf_target(
        &self,
        connection_id: &str,
        path_and_query: &str,
    ) -> Result<ConnectionHttpTarget, ConnectionHttpError> {
        self.attesting_http_target(connection_id, path_and_query, AttestingLane::CompositeLeaf)
    }

    /// The target of one request a connection-bound proxy route forwards,
    /// attested like a tool call; see [`Self::tool_call_target`]. A
    /// `delegated_issuer_token` Connection is refused with
    /// `caller_assertion_not_enforced`, as before the proxy signed anything:
    /// a proxied request is never served by a credential that belongs to the
    /// caller.
    pub fn proxy_route_target(
        &self,
        connection_id: &str,
        path_and_query: &str,
    ) -> Result<ConnectionHttpTarget, ConnectionHttpError> {
        self.attesting_http_target(connection_id, path_and_query, AttestingLane::ProxyRoute)
    }

    fn attesting_http_target(
        &self,
        connection_id: &str,
        path_and_query: &str,
        lane: AttestingLane,
    ) -> Result<ConnectionHttpTarget, ConnectionHttpError> {
        let connection_id = ConnectionId::parse(connection_id.to_owned())
            .map_err(|_| ConnectionHttpError::InvalidConnectionId)?;
        let snapshot = self.effective_snapshot();
        let record = snapshot
            .managed()
            .get(&connection_id)
            .ok_or(ConnectionHttpError::ConnectionNotFound)?;
        let caller_assertion = attesting_binding(record, &snapshot, lane)?;
        refuse_google_delegation_off_caller_lanes(record, Some(lane))?;
        validate_http_connection(record)?;
        let url = connection_target_url(record, path_and_query)?;
        let client = self.client_for(record)?;
        let authentication = self.authentication_binding(record)?;
        let additional_headers = additional_header_bindings(record)?;

        // A delegated Connection's assertion is its subject token, which goes
        // to the issuer alone; see `CallerAssertionBinding::signs_upstream`.
        let caller_assertion = caller_assertion.map(|mut binding| {
            binding.signs_upstream = !matches!(
                authentication,
                HttpAuthenticationBinding::DelegatedIssuerToken(_)
            );
            binding
        });
        let mut target = ConnectionHttpTarget::assemble(
            connection_id,
            record.etag().to_string(),
            url,
            client,
            authentication,
            additional_headers,
            connection_transport_binding(record),
        );
        target.caller_assertion = caller_assertion;
        Ok(target)
    }

    /// Whether a manual tool may be bound to `connection_id`: the same checks
    /// [`Self::tool_call_target`] applies, so a binding the registry accepts
    /// is a binding a call can use.
    pub fn validate_tool_binding(&self, connection_id: &str) -> Result<(), ConnectionHttpError> {
        self.tool_call_target(connection_id, "/").map(|_| ())
    }

    /// Whether a managed OpenAPI catalog's tools may be bound to
    /// `connection_id`: the checks [`Self::openapi_tool_target`] applies.
    pub fn validate_openapi_tool_binding(
        &self,
        connection_id: &str,
    ) -> Result<(), ConnectionHttpError> {
        self.openapi_tool_target(connection_id, "/").map(|_| ())
    }

    /// Refuses, before any DNS lookup, credential read or upstream byte, a
    /// call `target` cannot attest.
    ///
    /// A Connection configured to name its caller must never send a request
    /// that names nobody: a call with no principal, which includes a service
    /// token (see [`AttestedCaller`]), is refused with
    /// [`CallerAssertionError::NoPrincipal`].
    ///
    /// Nor does it sign with keys this replica does not publish: no upstream
    /// that fetched the current JWKS could verify such an assertion, and its
    /// rejection would look like an attack on the upstream's side. A call is
    /// refused with [`CallerAssertionError::KeyNotPublished`] when the
    /// Connection publishes a `kid` another enabled Connection publishes for
    /// a different key, and while this replica's last check of exactly the
    /// keys it configures left them out of the JWKS: one of its keys, the
    /// signing key or any published key, did not resolve or load.
    ///
    /// A recorded problem is checked again before it refuses: the keys are
    /// read the way a JWKS fetch reads them, at most once per retry interval
    /// however many calls ask, so a key that loads again is published, and
    /// serves calls, without waiting for a verifier to fetch the set. Those
    /// reads, the JWKS build's own, are the only I/O a call can cause before
    /// this answers.
    ///
    /// Every verdict is reached on the configuration `target` was built from.
    /// A disabled Connection publishes no keys at all, so a target built from
    /// one -- only a stored test builds such a target -- is refused with
    /// [`CallerAssertionError::KeyNotPublished`] too.
    pub async fn admit_caller_assertion(
        &self,
        target: &ConnectionHttpTarget,
        caller: Option<&AttestedCaller>,
    ) -> Result<(), CallerAssertionError> {
        let Some(binding) = target.caller_assertion.as_ref() else {
            return Ok(());
        };
        if caller.is_none() {
            return Err(CallerAssertionError::NoPrincipal);
        }
        let record = binding
            .configuration
            .managed()
            .get(target.connection_id())
            .ok_or(CallerAssertionError::KeyNotPublished)?;
        if !record.write.enabled {
            return Err(CallerAssertionError::KeyNotPublished);
        }
        if super::control_plane::publishes_an_ambiguous_kid(&binding.configuration, record) {
            return Err(CallerAssertionError::KeyNotPublished);
        }
        if self
            .control_plane
            .caller_assertion_key_problem(record)
            .is_none()
        {
            return Ok(());
        }
        // A set that cannot be built at all leaves the problem recorded.
        if self.control_plane.caller_assertion_jwks().await.is_err()
            || self
                .control_plane
                .caller_assertion_key_problem(record)
                .is_some()
        {
            return Err(CallerAssertionError::KeyNotPublished);
        }
        Ok(())
    }

    /// Reads and loads the key `target` signs its caller assertion with, or
    /// `None` for a target that sends no assertion upstream: one that attests
    /// nobody, or a `delegated_issuer_token` target, whose assertion is signed
    /// as the subject token of its exchange instead.
    ///
    /// The key is read through the same resolver and loaded by the same
    /// loader that admit it on a save and publish it in the JWKS, on every
    /// call, so a key that stops loading stops signing on the next call.
    pub async fn caller_assertion_signer<'target>(
        &self,
        target: &'target ConnectionHttpTarget,
    ) -> Result<Option<CallerAssertionSigner<'target>>, CallerAssertionError> {
        let Some(binding) = target
            .caller_assertion
            .as_ref()
            .filter(|binding| binding.signs_upstream)
        else {
            return Ok(None);
        };
        let material = self
            .control_plane
            .secret_resolver()
            .resolve(&binding.signing_key_id, SecretPurpose::AssertionSigningKey)
            .await
            .map_err(|error| match error.kind() {
                SecretResolveErrorKind::UnknownAlias
                | SecretResolveErrorKind::SourceDenied
                | SecretResolveErrorKind::InvalidMaterial => CallerAssertionError::KeyUnusable,
                SecretResolveErrorKind::ProviderBusy
                | SecretResolveErrorKind::SourceUnavailable
                | SecretResolveErrorKind::UnsafeSource
                | SecretResolveErrorKind::ProviderFailure => CallerAssertionError::KeyUnavailable,
            })?;
        let key = load_signing_key(&binding.kid, binding.algorithm, material.expose())
            .map_err(|_| CallerAssertionError::KeyUnusable)?;
        drop(material);
        let request_target = if binding.bind_request {
            Some(origin_form_request_target(target.url())?)
        } else {
            None
        };
        Ok(Some(CallerAssertionSigner {
            binding,
            key,
            request_target,
        }))
    }

    /// The target of a managed MCP session that discovers the Connection's
    /// catalog. Discovery has no caller to attest, so a Connection carrying a
    /// `caller_assertion` is refused with `caller_assertion_not_enforced`;
    /// a tool call uses [`Self::mcp_tool_call_target`].
    pub fn mcp_target(
        &self,
        connection_id: &str,
    ) -> Result<ConnectionHttpTarget, ConnectionHttpError> {
        let connection_id = ConnectionId::parse(connection_id.to_owned())
            .map_err(|_| ConnectionHttpError::InvalidConnectionId)?;
        let snapshot = self.effective_snapshot();
        let record = managed_record(&snapshot, &connection_id)?;
        self.mcp_session_target(connection_id, record)
    }

    /// The target of the session one managed MCP tool call opens, attested
    /// like an HTTP tool call (see [`Self::tool_call_target`]): every request
    /// of the session carries its own assertion, through
    /// [`CallerAssertionSigner::into_session`].
    pub fn mcp_tool_call_target(
        &self,
        connection_id: &str,
    ) -> Result<ConnectionHttpTarget, ConnectionHttpError> {
        let connection_id = ConnectionId::parse(connection_id.to_owned())
            .map_err(|_| ConnectionHttpError::InvalidConnectionId)?;
        let snapshot = self.effective_snapshot();
        let record = snapshot
            .managed()
            .get(&connection_id)
            .ok_or(ConnectionHttpError::ConnectionNotFound)?;
        let caller_assertion = attesting_binding(record, &snapshot, AttestingLane::ManagedMcpTool)?;
        let mut target = self.mcp_session_target(connection_id, record)?;
        target.caller_assertion = caller_assertion;
        Ok(target)
    }

    fn mcp_session_target(
        &self,
        connection_id: ConnectionId,
        record: &StoredConnection,
    ) -> Result<ConnectionHttpTarget, ConnectionHttpError> {
        let use_connection_authentication = validate_mcp_connection(record)?;
        let url = connection_target_url(record, "/")?;
        let client = self.client_for(record)?;
        let (authentication, additional_headers) = if use_connection_authentication {
            (
                self.authentication_binding(record)?,
                additional_header_bindings(record)?,
            )
        } else {
            (HttpAuthenticationBinding::None, Vec::new())
        };

        Ok(ConnectionHttpTarget::assemble(
            connection_id,
            record.etag().to_string(),
            url,
            client,
            authentication,
            additional_headers,
            connection_transport_binding(record),
        ))
    }

    pub fn openapi_discovery_target(
        &self,
        connection_id: &str,
    ) -> Result<ConnectionHttpTarget, ConnectionHttpError> {
        let connection_id = ConnectionId::parse(connection_id.to_owned())
            .map_err(|_| ConnectionHttpError::InvalidConnectionId)?;
        let snapshot = self.control_plane.runtime_snapshot();
        let record = managed_record(&snapshot, &connection_id)?;
        let (path, use_connection_authentication) = validate_openapi_connection(record)?;
        let url = connection_target_url(record, path)?;
        let client = self.client_for(record)?;
        let (authentication, additional_headers) = if use_connection_authentication {
            (
                self.authentication_binding(record)?,
                additional_header_bindings(record)?,
            )
        } else {
            (HttpAuthenticationBinding::None, Vec::new())
        };

        Ok(ConnectionHttpTarget::assemble(
            connection_id,
            record.etag().to_string(),
            url,
            client,
            authentication,
            additional_headers,
            connection_transport_binding(record),
        ))
    }

    /// Builds the exact persisted HTTP test target, including for a disabled
    /// managed connection. Normal data-plane target constructors remain
    /// fail-closed for disabled connections. A missing target indicates that
    /// the persisted connection no longer matches `expected_connection_etag`.
    ///
    /// A `delegated_issuer_token` Connection is tested as the principal who
    /// runs the test: the target carries its caller assertion, as the subject
    /// token of that principal's exchange, and the caller must admit the test
    /// with [`Self::admit_caller_assertion`] before any I/O. Every other
    /// Connection carrying a `caller_assertion` is refused with
    /// `caller_assertion_not_enforced`; see [`caller_assertion_servable_on`].
    /// A `google_domain_wide_delegation` Connection, which carries no
    /// assertion, is tested as that principal too: its token is minted for
    /// the principal's own email, inline and uncached.
    pub fn test_target(
        &self,
        connection_id: &str,
        expected_connection_etag: &str,
    ) -> Result<Option<ConnectionHttpTestTarget>, ConnectionHttpError> {
        let connection_id = ConnectionId::parse(connection_id.to_owned())
            .map_err(|_| ConnectionHttpError::InvalidConnectionId)?;
        let snapshot = self.control_plane.runtime_snapshot();
        let record = snapshot
            .managed()
            .get(&connection_id)
            .ok_or(ConnectionHttpError::ConnectionNotFound)?;
        let caller_assertion = attesting_binding(record, &snapshot, AttestingLane::ConnectionTest)?;
        refuse_google_delegation_off_caller_lanes(record, Some(AttestingLane::ConnectionTest))?;
        let connection_etag = record.etag();
        if connection_etag.as_str() != expected_connection_etag {
            return Ok(None);
        }
        if record.write.kind != ConnectionKind::HttpApi {
            return Err(ConnectionHttpError::WrongConnectionKind);
        }
        validate_authentication(record)?;
        let ConnectionTestProfile {
            method,
            path,
            expected_statuses,
        } = record
            .write
            .test_profile
            .as_ref()
            .ok_or(ConnectionHttpError::InvalidTargetPath)?;
        let method = Method::from_bytes(method.as_bytes())
            .map_err(|_| ConnectionHttpError::InvalidTargetPath)?;
        if !matches!(method, Method::GET | Method::HEAD) {
            return Err(ConnectionHttpError::InvalidTargetPath);
        }
        if expected_statuses.is_empty()
            || expected_statuses.len() > MAX_EXPECTED_STATUSES
            || expected_statuses
                .iter()
                .any(|status| !(100..=599).contains(status))
            || expected_statuses
                .iter()
                .enumerate()
                .any(|(index, status)| expected_statuses[..index].contains(status))
        {
            return Err(ConnectionHttpError::InvalidTargetPath);
        }
        let url = connection_target_url(record, path)?;
        let client = self.client_for(record)?;
        let authentication = self.authentication_binding(record)?;
        let additional_headers = additional_header_bindings(record)?;

        // Only a delegated Connection's block gets here, and its assertion is
        // the subject token of the tester's exchange: it goes to the issuer
        // alone; see `CallerAssertionBinding::signs_upstream`.
        let caller_assertion = caller_assertion.map(|mut binding| {
            binding.signs_upstream = !matches!(
                authentication,
                HttpAuthenticationBinding::DelegatedIssuerToken(_)
            );
            binding
        });
        let mut target = ConnectionHttpTarget::assemble(
            connection_id,
            connection_etag.to_string(),
            url,
            client,
            authentication,
            additional_headers,
            connection_transport_binding(record),
        );
        target.caller_assertion = caller_assertion;
        Ok(Some(ConnectionHttpTestTarget {
            target,
            method,
            expected_statuses: expected_statuses.clone(),
        }))
    }

    /// Builds a managed MCP test target without requiring the persisted
    /// connection to be enabled. No caller-provided target or authentication
    /// override is accepted. A missing target indicates that the persisted
    /// connection no longer matches `expected_connection_etag`.
    pub fn mcp_test_target(
        &self,
        connection_id: &str,
        expected_connection_etag: &str,
    ) -> Result<Option<ConnectionHttpTarget>, ConnectionHttpError> {
        let connection_id = ConnectionId::parse(connection_id.to_owned())
            .map_err(|_| ConnectionHttpError::InvalidConnectionId)?;
        let snapshot = self.control_plane.runtime_snapshot();
        let record = managed_record(&snapshot, &connection_id)?;
        let connection_etag = record.etag();
        if connection_etag.as_str() != expected_connection_etag {
            return Ok(None);
        }
        let use_connection_authentication = validate_mcp_connection_mode(record, false)?;
        let url = connection_target_url(record, "/")?;
        let client = self.client_for(record)?;
        let (authentication, additional_headers) = if use_connection_authentication {
            (
                self.authentication_binding(record)?,
                additional_header_bindings(record)?,
            )
        } else {
            (HttpAuthenticationBinding::None, Vec::new())
        };

        Ok(Some(ConnectionHttpTarget::assemble(
            connection_id,
            connection_etag.to_string(),
            url,
            client,
            authentication,
            additional_headers,
            connection_transport_binding(record),
        )))
    }

    pub fn validate_binding(&self, connection_id: &str) -> Result<(), ConnectionHttpError> {
        self.target(connection_id, "/").map(|_| ())
    }

    /// Returns whether the exact managed Connection revision captured by
    /// `target` is still current.
    ///
    /// Callers can use this after evaluating an execution precondition to
    /// close the window where that evaluation observed the old revision while
    /// a concurrent update published a new target. This check reads only the
    /// in-memory control-plane snapshot; it performs no DNS, egress, TLS, OAuth,
    /// or secret-provider work.
    pub fn target_is_current(&self, target: &ConnectionHttpTarget) -> bool {
        self.effective_snapshot()
            .managed()
            .get(target.connection_id())
            .is_some_and(|record| record.etag().as_str() == target.connection_etag())
    }

    pub fn replace_dependencies(
        &self,
        kind: ConnectionDependencyKind,
        desired: &[(String, String)],
    ) -> Result<(), ConnectionHttpError> {
        let desired = desired
            .iter()
            .map(|(connection_id, consumer_id)| {
                ConnectionId::parse(connection_id.clone())
                    .map(|connection_id| (connection_id, consumer_id.clone()))
                    .map_err(|_| ConnectionHttpError::InvalidConnectionId)
            })
            .collect::<Result<Vec<_>, _>>()?;
        self.control_plane
            .replace_runtime_dependencies(kind, &desired)
            .map_err(|_| ConnectionHttpError::TransportUnavailable)
    }

    /// Resolves everything the target injects: the primary credential, then
    /// each additional header in configured order. `None` means the target
    /// owns no header at all. Every secret is read on every call; a failure
    /// anywhere fails the whole request, so a request never leaves with a
    /// partial set of the Connection's headers.
    ///
    /// `caller` is who the call is made for, as the lane that admitted it
    /// attested them (see [`AttestedCaller::from_principal`]); a lane with no
    /// caller to name passes `None`. A credential that belongs to the caller
    /// rather than to the Connection -- `delegated_issuer_token` -- is refused
    /// with [`ConnectionHttpError::DelegatedTokenNoPrincipal`] without one,
    /// before any secret is read or any byte is sent.
    pub async fn resolve_credential(
        &self,
        target: &ConnectionHttpTarget,
        caller: Option<&AttestedCaller>,
    ) -> Result<Option<ResolvedConnectionCredential>, ConnectionHttpError> {
        if target.credential_header_names.is_empty() {
            return Ok(None);
        }
        let material = self.resolve_primary_credential(target, caller).await?;
        let additional_headers = self.resolve_additional_headers(target).await?;

        Ok(Some(ResolvedConnectionCredential {
            material,
            additional_headers,
        }))
    }

    /// Resolves a credential under the proxy route's absolute request
    /// deadline without losing which phase exhausted it. OAuth minting owns
    /// the primary phase; once that completes, every additional header is a
    /// static credential-provider read and therefore reports the ordinary
    /// credential-unavailable category on timeout. `caller` is as for
    /// [`Self::resolve_credential`].
    pub async fn resolve_credential_before(
        &self,
        target: &ConnectionHttpTarget,
        caller: Option<&AttestedCaller>,
        deadline: tokio::time::Instant,
    ) -> Result<Option<ResolvedConnectionCredential>, ConnectionHttpError> {
        if target.credential_header_names.is_empty() {
            return Ok(None);
        }
        let material =
            tokio::time::timeout_at(deadline, self.resolve_primary_credential(target, caller))
                .await
                .map_err(|_| target.primary_credential_timeout_error())??;
        let additional_headers =
            tokio::time::timeout_at(deadline, self.resolve_additional_headers(target))
                .await
                .map_err(|_| ConnectionHttpError::CredentialUnavailable)??;

        Ok(Some(ResolvedConnectionCredential {
            material,
            additional_headers,
        }))
    }

    async fn resolve_primary_credential(
        &self,
        target: &ConnectionHttpTarget,
        caller: Option<&AttestedCaller>,
    ) -> Result<Option<ResolvedCredentialMaterial>, ConnectionHttpError> {
        let material = match &target.authentication {
            HttpAuthenticationBinding::None => None,
            HttpAuthenticationBinding::HeaderApiKey {
                header_name,
                secret_id,
            } => Some(ResolvedCredentialMaterial::HeaderApiKey {
                header_name: header_name.clone(),
                secret: self
                    .resolve_static_secret(secret_id, SecretPurpose::HeaderApiKey)
                    .await?,
            }),
            HttpAuthenticationBinding::StaticBearer { secret_id } => {
                Some(ResolvedCredentialMaterial::StaticBearer {
                    secret: self
                        .resolve_static_secret(secret_id, SecretPurpose::StaticBearer)
                        .await?,
                })
            }
            HttpAuthenticationBinding::OAuth2ClientCredentials(binding) => {
                let token = self
                    .oauth
                    .access_token(binding)
                    .await
                    .map_err(connection_oauth_error)?;
                Some(ResolvedCredentialMaterial::OAuthBearer(token))
            }
            HttpAuthenticationBinding::DelegatedIssuerToken(binding) => {
                let caller = caller.ok_or(ConnectionHttpError::DelegatedTokenNoPrincipal)?;
                let token = self
                    .delegated
                    .access_token(binding, caller)
                    .await
                    .map_err(connection_delegated_error)?;
                Some(ResolvedCredentialMaterial::DelegatedBearer(token))
            }
            HttpAuthenticationBinding::GoogleDomainWideDelegation(binding) => {
                let caller = caller.ok_or(ConnectionHttpError::DelegatedTokenNoPrincipal)?;
                let token = self
                    .google
                    .access_token(binding, caller)
                    .await
                    .map_err(ConnectionHttpError::GoogleDelegation)?;
                Some(ResolvedCredentialMaterial::GoogleBearer(token))
            }
        };
        Ok(material)
    }

    async fn resolve_additional_headers(
        &self,
        target: &ConnectionHttpTarget,
    ) -> Result<Vec<ResolvedAdditionalHeader>, ConnectionHttpError> {
        #[cfg(test)]
        if !target.additional_headers.is_empty() {
            if let Some(delay) = self.additional_resolution_delay {
                tokio::time::sleep(delay).await;
            }
        }
        let mut additional_headers = Vec::with_capacity(target.additional_headers.len());
        for binding in &target.additional_headers {
            additional_headers.push(ResolvedAdditionalHeader {
                header_name: binding.header_name.clone(),
                secret: self
                    .resolve_static_secret(&binding.secret_id, SecretPurpose::HeaderApiKey)
                    .await?,
            });
        }
        Ok(additional_headers)
    }

    async fn resolve_static_secret(
        &self,
        secret_id: &str,
        purpose: SecretPurpose,
    ) -> Result<ResolvedSecret, ConnectionHttpError> {
        self.control_plane
            .secret_resolver()
            .resolve(secret_id, purpose)
            .await
            .map_err(|error| match error.kind() {
                SecretResolveErrorKind::UnknownAlias
                | SecretResolveErrorKind::SourceDenied
                | SecretResolveErrorKind::InvalidMaterial => ConnectionHttpError::CredentialInvalid,
                SecretResolveErrorKind::ProviderBusy
                | SecretResolveErrorKind::SourceUnavailable
                | SecretResolveErrorKind::UnsafeSource
                | SecretResolveErrorKind::ProviderFailure => {
                    ConnectionHttpError::CredentialUnavailable
                }
            })
    }

    /// Applies connection-owned TLS only after the caller has completed the
    /// ordinary egress preflight. The exact checked socket is rebound without
    /// another DNS lookup.
    pub async fn prepare_transport(
        &self,
        target: &ConnectionHttpTarget,
        checked: &CheckedEgressDestination,
    ) -> Result<PreparedConnectionTransport, ConnectionHttpError> {
        if target.transport.tls.is_empty() {
            let destination = target
                .client
                .rebind_checked_destination(checked, target.url())
                .map_err(|_| ConnectionHttpError::TransportUnavailable)?;
            return Ok(PreparedConnectionTransport {
                client: Arc::clone(&target.client),
                destination,
            });
        }

        let versions_before = self.tls_secret_versions(&target.transport.tls);
        let resolved = self.resolve_tls_profile(&target.transport.tls).await?;
        let versions_after = self.tls_secret_versions(&target.transport.tls);
        if versions_before != versions_after {
            return Err(ConnectionHttpError::TlsUnavailable);
        }

        let mut config = self.config_for_timeouts(&target.transport.timeouts);
        if let Some(ca_bundle) = resolved.ca_bundle.as_ref() {
            config
                .apply_tls_ca_bundle_pem(ca_bundle.expose())
                .map_err(|_| ConnectionHttpError::TlsInvalid)?;
        }
        if let Some((certificate, private_key)) = resolved.client_identity.as_ref() {
            let identity = crate::egress::join_tls_client_identity_pem(
                certificate.expose(),
                private_key.expose(),
            )
            .ok_or(ConnectionHttpError::TlsInvalid)?;
            config
                .apply_tls_client_identity_pem(identity.as_slice())
                .map_err(|_| ConnectionHttpError::TlsInvalid)?;
        }
        config.apply_transport_partition(&connection_transport_partition(
            &target.connection_id,
            &target.transport.revisions,
            ConnectionClientProfile::Upstream,
            versions_after,
        ));
        let client = self.cached_client(config)?;
        let destination = client
            .rebind_checked_destination(checked, target.url())
            .map_err(|_| ConnectionHttpError::TransportUnavailable)?;

        Ok(PreparedConnectionTransport {
            client,
            destination,
        })
    }

    fn authentication_binding(
        &self,
        record: &StoredConnection,
    ) -> Result<HttpAuthenticationBinding, ConnectionHttpError> {
        match &record.write.authentication {
            ConnectionAuthentication::None => Ok(HttpAuthenticationBinding::None),
            ConnectionAuthentication::HeaderApiKey {
                header_name,
                secret_id: Some(secret_id),
            } => Ok(HttpAuthenticationBinding::HeaderApiKey {
                header_name: HeaderName::from_bytes(header_name.as_bytes())
                    .map_err(|_| ConnectionHttpError::UnsupportedAuthentication)?,
                secret_id: secret_id.clone(),
            }),
            ConnectionAuthentication::StaticBearer {
                secret_id: Some(secret_id),
            } => Ok(HttpAuthenticationBinding::StaticBearer {
                secret_id: secret_id.clone(),
            }),
            ConnectionAuthentication::OAuth2ClientCredentials {
                client_id,
                client_secret_id: Some(client_secret_id),
                token_url,
                scopes,
                audience,
                resource,
                client_auth_method: OAuthClientAuthMethod::ClientSecretBasic,
            } => Ok(HttpAuthenticationBinding::OAuth2ClientCredentials(
                OAuthBinding {
                    connection_id: record.id.clone(),
                    connection_etag: record.etag().to_string(),
                    client_id: client_id.clone(),
                    client_secret_id: client_secret_id.clone(),
                    token_url: token_url.clone(),
                    scopes: scopes.clone(),
                    audience: audience.clone(),
                    resource: resource.clone(),
                    token_client: self.oauth_client_for(record)?,
                },
            )),
            ConnectionAuthentication::DelegatedIssuerToken {
                token_exchange_url,
                client_id,
                client_secret_id: Some(client_secret_id),
                requested_scopes,
                audience,
                resource,
                revocation_url,
                subject_token_source: SubjectTokenSource::CallerAssertion,
            } => {
                // Validation guarantees the block on every stored document;
                // this is the check that holds if that rule were to change.
                let assertion = record
                    .write
                    .caller_assertion
                    .as_ref()
                    .filter(|assertion| {
                        !assertion.bind_request && record.write.caller_assertion_enforceable()
                    })
                    .ok_or(ConnectionHttpError::UnsupportedAuthentication)?;
                Ok(HttpAuthenticationBinding::DelegatedIssuerToken(
                    DelegatedTokenBinding {
                        connection_id: record.id.clone(),
                        connection_etag: record.etag().to_string(),
                        client_id: client_id.clone(),
                        client_secret_id: client_secret_id.clone(),
                        token_exchange_url: token_exchange_url.clone(),
                        requested_scopes: requested_scopes.clone(),
                        audience: audience.clone(),
                        resource: resource.clone(),
                        revocation_url: revocation_url.clone(),
                        subject_token: SubjectTokenSettings {
                            signing_key_id: assertion.signing_key_id.clone(),
                            kid: assertion.kid.clone(),
                            algorithm: assertion.algorithm.into(),
                            issuer: assertion.issuer.clone(),
                            audience: assertion.audience.clone(),
                            token_type: assertion.token_type.clone(),
                            lifetime_seconds: u64::from(assertion.lifetime_seconds),
                            claims: assertion.claims.iter().copied().map(Into::into).collect(),
                        },
                        token_client: self.oauth_client_for(record)?,
                    },
                ))
            }
            ConnectionAuthentication::GoogleDomainWideDelegation {
                service_account_email,
                workload_identity_profile,
                scopes,
                subject_claim: GoogleSubjectClaim::Email,
                subject_issuers,
            } => Ok(HttpAuthenticationBinding::GoogleDomainWideDelegation(
                GoogleDelegationBinding {
                    connection_id: record.id.clone(),
                    connection_etag: record.etag().to_string(),
                    service_account_email: service_account_email.clone(),
                    workload_identity_profile: workload_identity_profile.clone(),
                    scopes: scopes.clone(),
                    subject_issuers: subject_issuers.clone(),
                    token_client: self.oauth_client_for(record)?,
                    identity: self.control_plane.google_workload_identity(),
                },
            )),
            ConnectionAuthentication::HeaderApiKey {
                secret_id: None, ..
            }
            | ConnectionAuthentication::StaticBearer { secret_id: None }
            | ConnectionAuthentication::OAuth2ClientCredentials {
                client_secret_id: None,
                ..
            }
            | ConnectionAuthentication::DelegatedIssuerToken {
                client_secret_id: None,
                ..
            } => Err(ConnectionHttpError::UnsupportedAuthentication),
        }
    }

    fn oauth_client_for(
        &self,
        record: &StoredConnection,
    ) -> Result<Arc<EgressClient>, ConnectionHttpError> {
        self.client_for_profile(record, ConnectionClientProfile::OAuthToken)
    }

    fn client_for(
        &self,
        record: &StoredConnection,
    ) -> Result<Arc<EgressClient>, ConnectionHttpError> {
        self.client_for_profile(record, ConnectionClientProfile::Upstream)
    }

    fn client_for_profile(
        &self,
        record: &StoredConnection,
        profile: ConnectionClientProfile,
    ) -> Result<Arc<EgressClient>, ConnectionHttpError> {
        let partition = connection_transport_partition(
            &record.id,
            &record.revisions,
            profile,
            [None, None, None],
        );
        let cache_key = ConnectionClientCacheKey::Preflight(partition);
        if let Some(client) = self.client_guard().get(&cache_key).cloned() {
            return Ok(client);
        }

        let timeouts = record.write.timeouts.clone().unwrap_or_default();
        let mut config = self.config_for_timeouts(&timeouts);
        if profile == ConnectionClientProfile::OAuthToken {
            config.max_response_bytes = OAUTH_MAX_RESPONSE_BYTES;
            config.max_request_body_bytes = OAUTH_MAX_REQUEST_BYTES;
        }
        config.apply_transport_partition(&partition);
        let candidate = self.build_client(config)?;
        Ok(self.insert_cached_client(cache_key, candidate))
    }

    fn config_for_timeouts(&self, timeouts: &ConnectionTimeouts) -> EgressConfig {
        let mut config = self.base_egress_config.clone();
        config.apply_timeout_overrides(
            Some(timeouts.request_timeout_ms),
            Some(timeouts.response_idle_timeout_ms),
            Some(timeouts.connect_timeout_ms),
        );
        config
    }

    fn cached_client(
        &self,
        config: EgressConfig,
    ) -> Result<Arc<EgressClient>, ConnectionHttpError> {
        let candidate = self.build_client(config)?;
        let cache_key = ConnectionClientCacheKey::Prepared(candidate.configuration_generation());
        if let Some(client) = self.client_guard().get(&cache_key).cloned() {
            return Ok(client);
        }
        Ok(self.insert_cached_client(cache_key, candidate))
    }

    fn build_client(&self, config: EgressConfig) -> Result<Arc<EgressClient>, ConnectionHttpError> {
        Ok(Arc::new(
            self.base_egress_client
                .reconfigured(config)
                .map_err(|_| ConnectionHttpError::TransportUnavailable)?,
        ))
    }

    fn insert_cached_client(
        &self,
        cache_key: ConnectionClientCacheKey,
        candidate: Arc<EgressClient>,
    ) -> Arc<EgressClient> {
        let mut clients = self.client_guard();
        if clients.len() >= MAX_CONNECTIONS.saturating_mul(2) && !clients.contains_key(&cache_key) {
            clients.clear();
        }
        Arc::clone(clients.entry(cache_key).or_insert(candidate))
    }

    fn tls_secret_versions(&self, tls: &TlsProfile) -> [Option<u64>; 3] {
        [
            tls.ca_bundle_alias
                .as_deref()
                .and_then(|id| self.control_plane.local_secret_version(id)),
            tls.client_certificate_id
                .as_deref()
                .and_then(|id| self.control_plane.local_secret_version(id)),
            tls.client_private_key_id
                .as_deref()
                .and_then(|id| self.control_plane.local_secret_version(id)),
        ]
    }

    async fn resolve_tls_profile(
        &self,
        tls: &TlsProfile,
    ) -> Result<ResolvedTlsProfile, ConnectionHttpError> {
        let ca_bundle = match tls.ca_bundle_alias.as_deref() {
            Some(id) => Some(
                self.control_plane
                    .secret_resolver()
                    .resolve(id, SecretPurpose::TlsCaBundle)
                    .await
                    .map_err(connection_tls_secret_error)?,
            ),
            None => None,
        };
        let client_identity = match (
            tls.client_certificate_id.as_deref(),
            tls.client_private_key_id.as_deref(),
        ) {
            (Some(certificate_id), Some(private_key_id)) => {
                let certificate = self
                    .control_plane
                    .secret_resolver()
                    .resolve(certificate_id, SecretPurpose::TlsCertificate)
                    .await
                    .map_err(connection_tls_secret_error)?;
                let private_key = self
                    .control_plane
                    .secret_resolver()
                    .resolve(private_key_id, SecretPurpose::TlsPrivateKey)
                    .await
                    .map_err(connection_tls_secret_error)?;
                Some((certificate, private_key))
            }
            (None, None) => None,
            (Some(_), None) | (None, Some(_)) => return Err(ConnectionHttpError::TlsInvalid),
        };

        Ok(ResolvedTlsProfile {
            ca_bundle,
            client_identity,
        })
    }

    fn client_guard(&self) -> MutexGuard<'_, HashMap<ConnectionClientCacheKey, Arc<EgressClient>>> {
        match self.clients.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!(
                    "Connection HTTP client cache lock poisoned; discarding stale cache state"
                );
                let mut guard = poisoned.into_inner();
                guard.clear();
                guard
            }
        }
    }
}

impl ConnectionHttpTarget {
    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    pub fn connection_etag(&self) -> &str {
        &self.connection_etag
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn client(&self) -> &Arc<EgressClient> {
        &self.client
    }

    pub fn preflight_client(&self) -> &Arc<EgressClient> {
        &self.client
    }

    /// Every header the Connection owns on the wire: the primary credential's
    /// header first (when there is one), then each additional header in
    /// configured order. Empty for a target that injects nothing.
    pub fn credential_header_names(&self) -> &[HeaderName] {
        &self.credential_header_names
    }

    /// Whether this target injects any secret-backed header at all; the
    /// upstream's `401`/`403` is only a credential rejection when it does. A
    /// caller assertion counts: it is signed with a secret key and is a
    /// bearer credential for its lifetime, so a `TRACE` must not echo it back.
    pub fn is_credentialed(&self) -> bool {
        !self.credential_header_names.is_empty() || self.caller_assertion.is_some()
    }

    /// Whether the primary credential is the caller's own rather than the
    /// Connection's, so resolving it needs the caller named
    /// (`delegated_issuer_token`, `google_domain_wide_delegation`).
    pub fn credential_belongs_to_caller(&self) -> bool {
        matches!(
            self.authentication,
            HttpAuthenticationBinding::DelegatedIssuerToken(_)
                | HttpAuthenticationBinding::GoogleDomainWideDelegation(_)
        )
    }

    /// The header the caller assertion travels in, when this target attests
    /// its caller. A lane strips it from anything a caller supplied, like the
    /// credential headers, before the gateway writes its own.
    pub fn caller_assertion_header_name(&self) -> Option<&HeaderName> {
        self.caller_assertion
            .as_ref()
            .map(|binding| &binding.header_name)
    }

    /// Whether this target carries a caller assertion: a call on it must be
    /// admitted with [`ConnectionHttpRuntime::admit_caller_assertion`], and
    /// names its caller to the upstream or, on a delegated Connection, to
    /// the token issuer.
    pub fn attests_caller(&self) -> bool {
        self.caller_assertion.is_some()
    }

    /// Whether a request to this target carries an assertion that covers the
    /// exact body sent (`bind_request`), so a lane that streams bodies must
    /// hold this one in full, within its size limit, before it signs.
    pub fn caller_assertion_binds_request_body(&self) -> bool {
        self.caller_assertion
            .as_ref()
            .is_some_and(|binding| binding.signs_upstream && binding.bind_request)
    }

    pub fn authentication_kind(&self) -> &'static str {
        match self.authentication {
            HttpAuthenticationBinding::None => "none",
            HttpAuthenticationBinding::HeaderApiKey { .. } => "header_api_key",
            HttpAuthenticationBinding::StaticBearer { .. } => "static_bearer",
            HttpAuthenticationBinding::OAuth2ClientCredentials(_) => "oauth2_client_credentials",
            HttpAuthenticationBinding::DelegatedIssuerToken(_) => "delegated_issuer_token",
            HttpAuthenticationBinding::GoogleDomainWideDelegation(_) => {
                "google_domain_wide_delegation"
            }
        }
    }

    fn primary_credential_timeout_error(&self) -> ConnectionHttpError {
        match self.authentication {
            HttpAuthenticationBinding::OAuth2ClientCredentials(_) => {
                ConnectionHttpError::OAuthTokenUnavailable
            }
            HttpAuthenticationBinding::DelegatedIssuerToken(_) => {
                ConnectionHttpError::DelegatedTokenExchangeFailed
            }
            HttpAuthenticationBinding::GoogleDomainWideDelegation(_) => {
                ConnectionHttpError::GoogleDelegation(GoogleDelegationError::ExchangeFailed)
            }
            HttpAuthenticationBinding::None
            | HttpAuthenticationBinding::HeaderApiKey { .. }
            | HttpAuthenticationBinding::StaticBearer { .. } => {
                ConnectionHttpError::CredentialUnavailable
            }
        }
    }
}

impl ResolvedConnectionCredential {
    /// Writes every Connection-owned header, primary credential first and
    /// then the additional headers in configured order. Each value is marked
    /// sensitive and replaces whatever the caller left under that name; the
    /// lanes strip those names beforehand, so this is belt and braces.
    pub fn inject(&self, headers: &mut HeaderMap) -> Result<(), ConnectionHttpError> {
        match &self.material {
            None => {}
            Some(ResolvedCredentialMaterial::HeaderApiKey {
                header_name,
                secret,
            }) => insert_sensitive_header(headers, header_name.clone(), secret.expose())?,
            Some(ResolvedCredentialMaterial::StaticBearer { secret }) => {
                let mut bearer =
                    Zeroizing::new(Vec::with_capacity("Bearer ".len() + secret.expose().len()));
                bearer.extend_from_slice(b"Bearer ");
                bearer.extend_from_slice(secret.expose());
                insert_sensitive_header(headers, header::AUTHORIZATION, bearer.as_slice())?;
            }
            Some(ResolvedCredentialMaterial::OAuthBearer(token)) => {
                token.inject(headers).map_err(connection_oauth_error)?;
            }
            Some(ResolvedCredentialMaterial::DelegatedBearer(token)) => {
                token.inject(headers).map_err(connection_delegated_error)?;
            }
            Some(ResolvedCredentialMaterial::GoogleBearer(token)) => {
                token
                    .inject(headers)
                    .map_err(ConnectionHttpError::GoogleDelegation)?;
            }
        }
        for additional in &self.additional_headers {
            insert_sensitive_header(
                headers,
                additional.header_name.clone(),
                additional.secret.expose(),
            )?;
        }
        Ok(())
    }

    pub async fn invalidate_after_unauthorized(&self) {
        match &self.material {
            Some(ResolvedCredentialMaterial::OAuthBearer(token)) => {
                token.invalidate_after_unauthorized().await;
            }
            Some(ResolvedCredentialMaterial::DelegatedBearer(token)) => {
                token.invalidate_after_unauthorized().await;
            }
            Some(ResolvedCredentialMaterial::GoogleBearer(token)) => {
                token.invalidate_after_unauthorized().await;
            }
            Some(
                ResolvedCredentialMaterial::HeaderApiKey { .. }
                | ResolvedCredentialMaterial::StaticBearer { .. },
            )
            | None => {}
        }
    }

    /// Whether the primary credential is an OAuth access token this gateway
    /// obtained from a token endpoint and caches -- a client-credentials
    /// token, or a caller's delegated or Google one -- so that an upstream
    /// `401` must drop it from the cache.
    pub fn is_oauth(&self) -> bool {
        matches!(
            self.material,
            Some(
                ResolvedCredentialMaterial::OAuthBearer(_)
                    | ResolvedCredentialMaterial::DelegatedBearer(_)
                    | ResolvedCredentialMaterial::GoogleBearer(_)
            )
        )
    }

    #[cfg(test)]
    pub(crate) fn header_api_key_for_test(
        header_name: HeaderName,
        value: &[u8],
    ) -> ResolvedConnectionCredential {
        ResolvedConnectionCredential {
            material: Some(ResolvedCredentialMaterial::HeaderApiKey {
                header_name,
                secret: ResolvedSecret::new(SecretPurpose::HeaderApiKey, value.to_vec())
                    .expect("test API-key material should be valid"),
            }),
            additional_headers: Vec::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_additional_header_for_test(
        mut self,
        header_name: HeaderName,
        value: &[u8],
    ) -> ResolvedConnectionCredential {
        self.additional_headers.push(ResolvedAdditionalHeader {
            header_name,
            secret: ResolvedSecret::new(SecretPurpose::HeaderApiKey, value.to_vec())
                .expect("test additional-header material should be valid"),
        });
        self
    }
}

fn insert_sensitive_header(
    headers: &mut HeaderMap,
    name: HeaderName,
    value: &[u8],
) -> Result<(), ConnectionHttpError> {
    let mut value =
        HeaderValue::from_bytes(value).map_err(|_| ConnectionHttpError::CredentialInvalid)?;
    value.set_sensitive(true);
    headers.insert(name, value);
    Ok(())
}

/// The additional headers a record binds, in configured order. An entry
/// without a secret is a draft that must never reach a live target, exactly
/// like a primary credential without one.
fn additional_header_bindings(
    record: &StoredConnection,
) -> Result<Vec<AdditionalHeaderBinding>, ConnectionHttpError> {
    record
        .write
        .additional_headers
        .iter()
        .map(|header| {
            let secret_id = header
                .secret_id
                .clone()
                .ok_or(ConnectionHttpError::UnsupportedAuthentication)?;
            Ok(AdditionalHeaderBinding {
                header_name: HeaderName::from_bytes(header.header_name.as_bytes())
                    .map_err(|_| ConnectionHttpError::UnsupportedAuthentication)?,
                secret_id,
            })
        })
        .collect()
}

impl ConnectionHttpError {
    pub fn safe_reason(self) -> &'static str {
        match self {
            Self::InvalidConnectionId => "invalid_connection_id",
            Self::ConnectionNotFound => "connection_not_found",
            Self::ConnectionDisabled => "connection_disabled",
            Self::WrongConnectionKind => "connection_kind_mismatch",
            Self::UnsupportedAuthentication => "authentication_not_supported",
            Self::CallerAssertionNotEnforced => "caller_assertion_not_enforced",
            Self::TlsInvalid => "tls_invalid",
            Self::TlsUnavailable => "tls_unavailable",
            Self::InvalidTargetPath => "invalid_target_path",
            Self::CredentialHeaderConflict => "credential_header_conflict",
            Self::CredentialInvalid => "credential_invalid",
            Self::CredentialUnavailable => "credential_unavailable",
            Self::OAuthTokenEgressDenied => "oauth_token_egress_denied",
            Self::OAuthTokenUnavailable => "oauth_token_unavailable",
            Self::OAuthTokenRejected => "oauth_token_rejected",
            Self::OAuthTokenInvalidResponse => "oauth_token_invalid_response",
            Self::DelegatedTokenNoPrincipal => DelegatedTokenError::NoPrincipal.safe_reason(),
            Self::DelegatedTokenEgressDenied => DelegatedTokenError::EgressDenied.safe_reason(),
            Self::DelegatedTokenDenied => DelegatedTokenError::Denied.safe_reason(),
            Self::DelegatedTokenExchangeFailed => DelegatedTokenError::ExchangeFailed.safe_reason(),
            Self::DelegatedTokenUnavailable => DelegatedTokenError::Unavailable.safe_reason(),
            Self::GoogleDelegation(error) => error.safe_reason(),
            Self::UpstreamAuthenticationRejected => "auth_failed",
            Self::TransportUnavailable => "transport_unavailable",
        }
    }

    pub fn is_secret_resolution_failure(self) -> bool {
        matches!(
            self,
            Self::CredentialInvalid
                | Self::CredentialUnavailable
                | Self::TlsInvalid
                | Self::TlsUnavailable
        )
    }
}

impl fmt::Display for ConnectionHttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "connection-bound HTTP request failed: {}",
            self.safe_reason()
        )
    }
}

impl Error for ConnectionHttpError {}

fn connection_transport_binding(record: &StoredConnection) -> ConnectionTransportBinding {
    ConnectionTransportBinding {
        tls: record.write.tls.clone(),
        timeouts: record.write.timeouts.clone().unwrap_or_default(),
        revisions: record.revisions.clone(),
    }
}

fn connection_transport_partition(
    connection_id: &ConnectionId,
    revisions: &ConnectionRevisions,
    profile: ConnectionClientProfile,
    local_tls_versions: [Option<u64>; 3],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"greengateway:connection-transport:v1\0");
    hasher.update((connection_id.as_str().len() as u64).to_be_bytes());
    hasher.update(connection_id.as_str().as_bytes());
    for revision in [
        revisions.connection,
        revisions.credential,
        revisions.tls,
        revisions.discovery,
        revisions.status,
    ] {
        hasher.update(revision.to_be_bytes());
    }
    hasher.update((profile.key().len() as u64).to_be_bytes());
    hasher.update(profile.key().as_bytes());
    for version in local_tls_versions {
        match version {
            Some(version) => {
                hasher.update([1]);
                hasher.update(version.to_be_bytes());
            }
            None => hasher.update([0]),
        }
    }
    hasher.finalize().into()
}

/// The request target a client sends for `url` in origin form: the path and,
/// when present, `?` and the query, exactly as the egress client serializes
/// them onto the request line. This is what `bind_request` attests, so an
/// upstream compares it with the request line it received rather than with a
/// reconstruction.
fn origin_form_request_target(url: &str) -> Result<String, CallerAssertionError> {
    let parsed = url::Url::parse(url).map_err(|_| CallerAssertionError::InvalidClaim("path"))?;
    Ok(parsed[url::Position::BeforePath..url::Position::AfterQuery].to_owned())
}

/// Seconds since the Unix epoch, for `iat`. A clock that reads before the
/// epoch is a broken host: rather than sign with a made-up time, which would
/// send the upstream an assertion that expired decades ago, the call is
/// refused.
fn unix_now() -> Result<u64, CallerAssertionError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| CallerAssertionError::SignatureFailed)
}

fn connection_tls_secret_error(error: SecretResolveError) -> ConnectionHttpError {
    match error.kind() {
        SecretResolveErrorKind::UnknownAlias
        | SecretResolveErrorKind::SourceDenied
        | SecretResolveErrorKind::InvalidMaterial => ConnectionHttpError::TlsInvalid,
        SecretResolveErrorKind::ProviderBusy
        | SecretResolveErrorKind::SourceUnavailable
        | SecretResolveErrorKind::UnsafeSource
        | SecretResolveErrorKind::ProviderFailure => ConnectionHttpError::TlsUnavailable,
    }
}

/// Looks up the managed record a target is built from, and refuses one this
/// gateway cannot honour.
///
/// Every constructor for a lane that does not attest its caller goes through
/// here; the attesting lanes' constructors refuse what they cannot honour
/// through [`attesting_binding`] instead. A [`ConnectionHttpTarget`] is the
/// only way any lane -- tool calls, the proxy, managed MCP sessions and
/// discovery, OpenAPI discovery, enum sources and Connection tests -- reaches
/// an egress client, a TLS identity or a credential. A refusal here therefore
/// lands before DNS, before any secret is read, before OAuth minting and before
/// a byte leaves the gateway, and no lane can route around it.
fn managed_record<'a>(
    snapshot: &'a super::control_plane::ConnectionRuntimeSnapshot,
    connection_id: &ConnectionId,
) -> Result<&'a StoredConnection, ConnectionHttpError> {
    let record = snapshot
        .managed()
        .get(connection_id)
        .ok_or(ConnectionHttpError::ConnectionNotFound)?;
    refuse_unenforced_caller_assertion(record)?;
    Ok(record)
}

/// Refuses a Connection that asks for a signed caller assertion, on every lane
/// that does not sign one.
///
/// Only an [`AttestingLane`] attests its caller (see
/// [`ConnectionHttpRuntime::tool_call_target`]). Serving such a Connection on
/// any other lane would be a silent fail-open: the operator configured "every
/// call names its caller" and the upstream would receive a request naming
/// nobody. On those lanes the configured intent is honoured the only way it
/// can be -- by not sending the call.
fn refuse_unenforced_caller_assertion(
    record: &StoredConnection,
) -> Result<(), ConnectionHttpError> {
    if record.write.caller_assertion.is_some() {
        return Err(ConnectionHttpError::CallerAssertionNotEnforced);
    }
    refuse_google_delegation_off_caller_lanes(record, None)
}

/// Refuses a `google_domain_wide_delegation` Connection, with
/// `authentication_not_supported` and before anything is resolved, on every
/// lane but two that obtain a caller's own token: a manual tool call, and a
/// stored test run as the principal who asked for it.
///
/// Those are the lanes a `delegated_issuer_token` Connection is served on
/// (see [`caller_assertion_servable_on`]) except the managed OpenAPI tool
/// lane: a catalog's user-consent schemes bind to a delegated issuer token
/// alone (issue #443), so this Connection stays refused there, and the
/// catalog lifecycle neither registers nor keeps a catalog on it. A delegated
/// issuer token is kept off the other lanes by the caller assertion it must
/// carry; this Connection carries none, so the rule is stated in
/// [`credential_servable_on`]. `lane` is `None` for a lane that attests
/// nobody.
fn refuse_google_delegation_off_caller_lanes(
    record: &StoredConnection,
    lane: Option<AttestingLane>,
) -> Result<(), ConnectionHttpError> {
    if !credential_servable(&record.write, lane) {
        return Err(ConnectionHttpError::UnsupportedAuthentication);
    }
    Ok(())
}

/// Whether `write`'s credential can be sent on `lane` at all, whatever its
/// caller assertion says (see [`caller_assertion_servable_on`] for that).
///
/// A Connection this answers `false` for is refused on `lane` with
/// `authentication_not_supported`, before anything is resolved. Only a
/// `google_domain_wide_delegation` Connection is refused here, on every lane
/// but a manual tool call and a stored test, the two that obtain a caller's
/// own Google token. The managed OpenAPI catalog lifecycle asks it for
/// [`AttestingLane::OpenApiTool`], so a catalog is never registered on, nor
/// left live on, a Connection whose tools could not send a request.
pub fn credential_servable_on(write: &ConnectionWrite, lane: AttestingLane) -> bool {
    credential_servable(write, Some(lane))
}

/// [`credential_servable_on`], with `None` for a lane that attests nobody.
/// Exhaustive on purpose: a new credential type must decide here.
fn credential_servable(write: &ConnectionWrite, lane: Option<AttestingLane>) -> bool {
    match &write.authentication {
        ConnectionAuthentication::GoogleDomainWideDelegation { .. } => matches!(
            lane,
            Some(AttestingLane::ManualTool | AttestingLane::ConnectionTest)
        ),
        // A delegated issuer token is kept off the lanes that cannot obtain
        // a caller's token by the caller assertion it must carry.
        ConnectionAuthentication::None
        | ConnectionAuthentication::HeaderApiKey { .. }
        | ConnectionAuthentication::StaticBearer { .. }
        | ConnectionAuthentication::OAuth2ClientCredentials { .. }
        | ConnectionAuthentication::DelegatedIssuerToken { .. } => true,
    }
}

/// A lane that signs a caller assertion on every request it sends for a
/// caller, and so may serve a Connection carrying a `caller_assertion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestingLane {
    /// A manual HTTP tool call. It also serves a `delegated_issuer_token`
    /// or `google_domain_wide_delegation`
    /// Connection.
    ManualTool,
    /// A managed OpenAPI tool call. It also serves a `delegated_issuer_token`
    /// Connection, for the catalogs bound to it (issue #443), but never a
    /// `google_domain_wide_delegation` one.
    OpenApiTool,
    /// One leaf request of a composite tool, each signed separately.
    CompositeLeaf,
    /// A request a connection-bound proxy route forwards.
    ProxyRoute,
    /// The session a managed MCP tool call opens.
    ManagedMcpTool,
    /// A stored test. A `delegated_issuer_token` or
    /// `google_domain_wide_delegation` Connection is tested with the token of
    /// the principal running the test. It sends no assertion upstream and
    /// serves no other attested Connection.
    ConnectionTest,
}

/// Whether `write` can be served on `lane` as far as its caller assertion is
/// concerned: it carries none, or one `lane` signs.
///
/// A stored block only the legacy reading admits is served by no lane (see
/// [`ConnectionWrite::caller_assertion_enforceable`]). A
/// `delegated_issuer_token` Connection, whose assertion is the subject token
/// of the caller's own credential, is served by manual and managed OpenAPI
/// tool calls and by stored tests alone: those are the lanes that obtain a
/// caller's delegated token, so on every other lane the Connection stays
/// refused exactly as it was before those lanes signed anything. A stored
/// test serves no other attested Connection: it would have to send the
/// upstream an assertion naming the tester, which no operator configured a
/// test to do.
///
/// [`ConnectionWrite::caller_assertion_enforceable`]:
///     super::model::ConnectionWrite::caller_assertion_enforceable
pub fn caller_assertion_servable_on(write: &ConnectionWrite, lane: AttestingLane) -> bool {
    if write.caller_assertion.is_none() {
        return true;
    }
    let delegated = matches!(
        write.authentication,
        ConnectionAuthentication::DelegatedIssuerToken { .. }
    );
    write.caller_assertion_enforceable()
        && match lane {
            AttestingLane::ManualTool | AttestingLane::OpenApiTool => true,
            AttestingLane::ConnectionTest => delegated,
            AttestingLane::CompositeLeaf
            | AttestingLane::ProxyRoute
            | AttestingLane::ManagedMcpTool => !delegated,
        }
}

/// The caller assertion a target built for `lane` carries, or the refusal
/// when `lane` cannot honour the block `record` carries.
fn attesting_binding(
    record: &StoredConnection,
    snapshot: &Arc<super::control_plane::ConnectionRuntimeSnapshot>,
    lane: AttestingLane,
) -> Result<Option<CallerAssertionBinding>, ConnectionHttpError> {
    let Some(settings) = record.write.caller_assertion.as_ref() else {
        return Ok(None);
    };
    if !caller_assertion_servable_on(&record.write, lane) {
        return Err(ConnectionHttpError::CallerAssertionNotEnforced);
    }
    CallerAssertionBinding::from_settings(settings, Arc::clone(snapshot)).map(Some)
}

fn validate_http_connection(record: &StoredConnection) -> Result<(), ConnectionHttpError> {
    if !record.write.enabled {
        return Err(ConnectionHttpError::ConnectionDisabled);
    }
    if record.write.kind != ConnectionKind::HttpApi {
        return Err(ConnectionHttpError::WrongConnectionKind);
    }
    validate_authentication(record)
}

fn validate_authentication(record: &StoredConnection) -> Result<(), ConnectionHttpError> {
    match &record.write.authentication {
        ConnectionAuthentication::None
        | ConnectionAuthentication::HeaderApiKey {
            secret_id: Some(_), ..
        }
        | ConnectionAuthentication::StaticBearer { secret_id: Some(_) }
        | ConnectionAuthentication::OAuth2ClientCredentials {
            client_secret_id: Some(_),
            client_auth_method: OAuthClientAuthMethod::ClientSecretBasic,
            ..
        }
        | ConnectionAuthentication::DelegatedIssuerToken {
            client_secret_id: Some(_),
            subject_token_source: SubjectTokenSource::CallerAssertion,
            ..
        }
        | ConnectionAuthentication::GoogleDomainWideDelegation {
            subject_claim: GoogleSubjectClaim::Email,
            ..
        } => Ok(()),
        ConnectionAuthentication::HeaderApiKey {
            secret_id: None, ..
        }
        | ConnectionAuthentication::StaticBearer { secret_id: None }
        | ConnectionAuthentication::OAuth2ClientCredentials {
            client_secret_id: None,
            ..
        }
        | ConnectionAuthentication::DelegatedIssuerToken {
            client_secret_id: None,
            ..
        } => Err(ConnectionHttpError::UnsupportedAuthentication),
    }
}

fn validate_mcp_connection(record: &StoredConnection) -> Result<bool, ConnectionHttpError> {
    validate_mcp_connection_mode(record, true)
}

fn validate_mcp_connection_mode(
    record: &StoredConnection,
    require_enabled: bool,
) -> Result<bool, ConnectionHttpError> {
    if require_enabled && !record.write.enabled {
        return Err(ConnectionHttpError::ConnectionDisabled);
    }
    if record.write.kind != ConnectionKind::McpStreamableHttp {
        return Err(ConnectionHttpError::WrongConnectionKind);
    }
    let use_connection_authentication = match &record.write.discovery {
        Some(DiscoveryConfig::ManagedMcp {
            use_connection_authentication,
        }) => *use_connection_authentication,
        _ => return Err(ConnectionHttpError::WrongConnectionKind),
    };
    if !use_connection_authentication {
        return Ok(false);
    }
    validate_authentication(record)?;
    Ok(true)
}

impl PreparedConnectionTransport {
    pub fn client(&self) -> &Arc<EgressClient> {
        &self.client
    }

    pub fn destination(&self) -> &CheckedEgressDestination {
        &self.destination
    }
}

impl ConnectionHttpTestTarget {
    pub fn target(&self) -> &ConnectionHttpTarget {
        &self.target
    }

    pub fn method(&self) -> &Method {
        &self.method
    }

    pub fn expected_statuses(&self) -> &[u16] {
        &self.expected_statuses
    }

    pub fn into_target(self) -> ConnectionHttpTarget {
        self.target
    }
}

fn validate_openapi_connection(
    record: &StoredConnection,
) -> Result<(&str, bool), ConnectionHttpError> {
    validate_http_connection(record)?;
    match &record.write.discovery {
        Some(DiscoveryConfig::ManagedOpenapi {
            path: Some(path),
            use_connection_authentication,
        }) => Ok((path.as_str(), *use_connection_authentication)),
        Some(DiscoveryConfig::ManagedOpenapi { path: None, .. }) | None => {
            Err(ConnectionHttpError::InvalidTargetPath)
        }
        Some(DiscoveryConfig::ManagedMcp { .. }) => Err(ConnectionHttpError::WrongConnectionKind),
    }
}

fn connection_oauth_error(error: OAuthError) -> ConnectionHttpError {
    match error {
        OAuthError::CredentialInvalid => ConnectionHttpError::CredentialInvalid,
        OAuthError::CredentialUnavailable => ConnectionHttpError::CredentialUnavailable,
        OAuthError::TokenEgressDenied => ConnectionHttpError::OAuthTokenEgressDenied,
        OAuthError::TokenUnavailable => ConnectionHttpError::OAuthTokenUnavailable,
        OAuthError::TokenRejected => ConnectionHttpError::OAuthTokenRejected,
        OAuthError::InvalidTokenResponse => ConnectionHttpError::OAuthTokenInvalidResponse,
    }
}

fn connection_delegated_error(error: DelegatedTokenError) -> ConnectionHttpError {
    match error {
        DelegatedTokenError::NoPrincipal => ConnectionHttpError::DelegatedTokenNoPrincipal,
        DelegatedTokenError::EgressDenied => ConnectionHttpError::DelegatedTokenEgressDenied,
        DelegatedTokenError::Denied => ConnectionHttpError::DelegatedTokenDenied,
        DelegatedTokenError::ExchangeFailed => ConnectionHttpError::DelegatedTokenExchangeFailed,
        DelegatedTokenError::Unavailable => ConnectionHttpError::DelegatedTokenUnavailable,
        DelegatedTokenError::CredentialInvalid => ConnectionHttpError::CredentialInvalid,
        DelegatedTokenError::CredentialUnavailable => ConnectionHttpError::CredentialUnavailable,
    }
}

fn connection_target_url(
    record: &StoredConnection,
    path_and_query: &str,
) -> Result<String, ConnectionHttpError> {
    let uri = path_and_query
        .parse::<Uri>()
        .map_err(|_| ConnectionHttpError::InvalidTargetPath)?;
    if uri.scheme().is_some() || uri.authority().is_some() {
        return Err(ConnectionHttpError::InvalidTargetPath);
    }
    let normalized_path = normalize_origin_relative_path("connection.request_path", uri.path())
        .map_err(|_| ConnectionHttpError::InvalidTargetPath)?;
    let base_path = record.write.endpoint.base_path.as_str();
    let combined_path = if base_path == "/" {
        normalized_path
    } else if normalized_path == "/" {
        base_path.to_owned()
    } else {
        format!("{}{}", base_path.trim_end_matches('/'), normalized_path)
    };
    let mut target = format!("{}{}", record.write.endpoint.base_url, combined_path);
    if let Some(query) = uri.query() {
        target.push('?');
        target.push_str(query);
    }
    if target.len() > MAX_URL_BYTES {
        return Err(ConnectionHttpError::InvalidTargetPath);
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        fs,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        path::PathBuf,
        time::{Duration, Instant},
    };

    use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
    use http::StatusCode;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, SanType,
    };
    use serde_json::json;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_rustls::{
        rustls::{
            pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
            ServerConfig,
        },
        TlsAcceptor,
    };

    use super::*;
    use crate::{
        audit::{self, sink::tests::CaptureSink, AuditSink},
        config::Config,
        connections::{
            model::{
                AdditionalHeader, CallerAssertionAlgorithm, CallerAssertionSettings,
                ConnectionEndpoint, ConnectionTimeouts, ConnectionWrite, OAuthClientAuthMethod,
                TlsProfile,
            },
            secret::{OperatorSecretAliasConfig, OperatorSecretAliasSource, SecretRootConfig},
            status::{ConnectionOperationalState, ConnectionRevisions, ConnectionStatusReason},
            test::{
                ConnectionTestReason, ConnectionTestService, ConnectionTestStage,
                ConnectionTestStageName,
            },
        },
    };

    const OAUTH_CLIENT_SECRET_CANARY: &[u8] = b"oauth-client-secret-canary";
    const OAUTH_ACCESS_TOKEN_CANARY: &str = "oauth-access-token-canary";
    const OAUTH_REFRESH_TOKEN_CANARY: &str = "oauth-refresh-token-canary";

    struct CapturedTokenRequest {
        head: String,
        body: String,
        response_sent: bool,
    }

    async fn one_request_tls_token_server(
        status: StatusCode,
        content_type: &str,
        body: Vec<u8>,
    ) -> (
        SocketAddr,
        String,
        tokio::task::JoinHandle<CapturedTokenRequest>,
    ) {
        let (addr, ca_pem, handle, _received) =
            one_request_delayed_tls_token_server(status, content_type, body, Duration::ZERO).await;
        (addr, ca_pem, handle)
    }

    async fn one_request_delayed_tls_token_server(
        status: StatusCode,
        content_type: &str,
        body: Vec<u8>,
        response_delay: Duration,
    ) -> (
        SocketAddr,
        String,
        tokio::task::JoinHandle<CapturedTokenRequest>,
        tokio::sync::oneshot::Receiver<()>,
    ) {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let mut ca_params = CertificateParams::default();
        ca_params.distinguished_name = DistinguishedName::new();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "GreenGateway OAuth Test CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().expect("test CA key should generate");
        let ca = ca_params
            .self_signed(&ca_key)
            .expect("test CA certificate should build");
        let mut server_params = CertificateParams::default();
        server_params.distinguished_name = DistinguishedName::new();
        server_params
            .distinguished_name
            .push(DnType::CommonName, "127.0.0.1");
        server_params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let server_key = rcgen::KeyPair::generate().expect("test server key should generate");
        let server_certificate = server_params
            .signed_by(&server_key, &Issuer::from_params(&ca_params, &ca_key))
            .expect("test server certificate should build");
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(
                    server_certificate.der().as_ref().to_vec(),
                )],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            )
            .expect("test TLS server config should build");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test TLS listener should bind");
        let addr = listener.local_addr().expect("test TLS address");
        let content_type = content_type.to_owned();
        let (request_received_tx, request_received_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("token server should accept one request");
            let mut stream = acceptor
                .accept(stream)
                .await
                .expect("token server TLS should succeed");
            let request = read_http_request(&mut stream).await;
            let _ = request_received_tx.send(());
            let mut disconnected = [0_u8; 1];
            let response_sent = tokio::select! {
                () = tokio::time::sleep(response_delay) => {
                    let reason = status.canonical_reason().unwrap_or("Response");
                    let response = format!(
                        "HTTP/1.1 {} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        status.as_u16(),
                        body.len()
                    );
                    stream
                        .write_all(response.as_bytes())
                        .await
                        .expect("token response headers should write");
                    stream
                        .write_all(&body)
                        .await
                        .expect("token response body should write");
                    true
                }
                _ = stream.read(&mut disconnected) => false,
            };
            let mut request = request;
            request.response_sent = response_sent;
            request
        });
        (addr, ca.pem(), handle, request_received_rx)
    }

    async fn read_http_request<T>(stream: &mut T) -> CapturedTokenRequest
    where
        T: AsyncReadExt + Unpin,
    {
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 2048];
        let header_end = loop {
            let read = stream
                .read(&mut chunk)
                .await
                .expect("token request should read");
            assert!(read > 0, "token request closed before headers completed");
            bytes.extend_from_slice(&chunk[..read]);
            if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let content_length = String::from_utf8_lossy(&bytes[..header_end])
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find_map(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        while bytes.len() < header_end.saturating_add(content_length) {
            let read = stream
                .read(&mut chunk)
                .await
                .expect("token request body should read");
            assert!(read > 0, "token request closed before body completed");
            bytes.extend_from_slice(&chunk[..read]);
        }
        CapturedTokenRequest {
            head: String::from_utf8_lossy(&bytes[..header_end]).into_owned(),
            body: String::from_utf8_lossy(
                &bytes[header_end..header_end.saturating_add(content_length)],
            )
            .into_owned(),
            response_sent: false,
        }
    }

    async fn captured_audit_events(
        capture: &CaptureSink,
        expected_count: usize,
    ) -> Vec<audit::AuditEvent> {
        let started = Instant::now();
        while capture.len() < expected_count && started.elapsed() < Duration::from_secs(1) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        capture.events()
    }

    struct TemporaryRuntime {
        root: PathBuf,
        runtime: ConnectionHttpRuntime,
        connection_id: ConnectionId,
    }

    impl TemporaryRuntime {
        async fn header_api_key(name: &str, header_name: &str, secret: &[u8]) -> Self {
            Self::header_api_key_with_additional(name, header_name, secret, &[]).await
        }

        async fn header_api_key_with_additional(
            name: &str,
            header_name: &str,
            secret: &[u8],
            additional: &[(&str, &str, &[u8])],
        ) -> Self {
            let root = std::env::temp_dir().join(format!(
                "greengateway-static-auth-{name}-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&root).expect("temporary secret root should create");
            let secret_path = root.join("api-key");
            fs::write(&secret_path, secret).expect("temporary secret should write");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                    .expect("temporary secret root permissions should set");
                fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))
                    .expect("temporary secret permissions should set");
            }

            let mut aliases = vec![OperatorSecretAliasConfig {
                id: "billing-api-key".to_owned(),
                label: "Billing API key".to_owned(),
                source: OperatorSecretAliasSource::File {
                    key: "api-key".to_owned(),
                },
            }];
            for (_, alias_id, value) in additional {
                let path = root.join(alias_id);
                fs::write(&path, value).expect("temporary additional secret should write");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                        .expect("temporary additional secret permissions should set");
                }
                aliases.push(OperatorSecretAliasConfig {
                    id: (*alias_id).to_owned(),
                    label: format!("Additional header {alias_id}"),
                    source: OperatorSecretAliasSource::File {
                        key: (*alias_id).to_owned(),
                    },
                });
            }

            let mut config = Config::test_defaults();
            config.connections_sqlite_path =
                Some(root.join("connections.sqlite").display().to_string());
            config.connection_secrets_root = Some(SecretRootConfig::new(root.clone()));
            config.connection_secret_aliases = aliases;
            let control_plane =
                ConnectionControlPlane::from_config(&config).expect("control plane should build");
            let initial = control_plane.runtime_snapshot();
            let mut write = record("/v1").write;
            write.authentication = ConnectionAuthentication::HeaderApiKey {
                header_name: header_name.to_owned(),
                secret_id: Some("billing-api-key".to_owned()),
            };
            write.additional_headers = additional
                .iter()
                .map(|(header_name, alias_id, _)| AdditionalHeader {
                    header_name: (*header_name).to_owned(),
                    secret_id: Some((*alias_id).to_owned()),
                })
                .collect();
            let created = control_plane
                .create_managed(
                    initial.collection_etag(),
                    write,
                    &crate::auth::change_actor::ChangeActor::for_test("test-admin"),
                )
                .await
                .expect("connection should create");
            let egress_config = EgressConfig {
                allowed_hosts: HashSet::from(["billing.example.test".to_owned()]),
                ..EgressConfig::default()
            };
            let egress_client = Arc::new(
                EgressClient::new(egress_config.clone()).expect("egress client should build"),
            );
            let runtime = ConnectionHttpRuntime::new(control_plane, egress_config, egress_client);

            Self {
                root,
                runtime,
                connection_id: created.id,
            }
        }
    }

    impl Drop for TemporaryRuntime {
        fn drop(&mut self) {
            if self
                .root
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("greengateway-static-auth-"))
                && self.root.starts_with(std::env::temp_dir())
            {
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }

    struct TemporaryManagedRuntime {
        root: PathBuf,
        runtime: ConnectionHttpRuntime,
        connection_id: ConnectionId,
        ca_path: Option<PathBuf>,
    }

    impl TemporaryManagedRuntime {
        async fn from_write(name: &str, write: ConnectionWrite) -> Self {
            Self::build(name, write, Vec::new(), None).await
        }

        async fn tls_identity(name: &str) -> Self {
            Self::tls_identity_with_oauth(name, false).await
        }

        async fn tls_identity_with_oauth(name: &str, with_oauth: bool) -> Self {
            let root = temporary_managed_root(name);
            fs::create_dir(&root).expect("temporary managed root should create");
            let identity_key = rcgen::KeyPair::generate().expect("test identity key should build");
            let identity_certificate = CertificateParams::default()
                .self_signed(&identity_key)
                .expect("test identity certificate should build");
            let ca_path = root.join("ca.pem");
            let certificate_path = root.join("client-certificate.pem");
            let private_key_path = root.join("client-private-key.pem");
            let oauth_secret_path = root.join("oauth-secret");
            fs::write(&ca_path, identity_certificate.pem()).expect("test CA bundle should write");
            fs::write(&certificate_path, identity_certificate.pem())
                .expect("test client certificate should write");
            fs::write(&private_key_path, identity_key.serialize_pem())
                .expect("test client private key should write");
            if with_oauth {
                fs::write(&oauth_secret_path, OAUTH_CLIENT_SECRET_CANARY)
                    .expect("test OAuth secret should write");
            }

            let mut write = record("/").write;
            write.endpoint.base_url = "https://127.0.0.1".to_owned();
            write.tls = TlsProfile {
                ca_bundle_alias: Some("test-ca".to_owned()),
                client_certificate_id: Some("test-client-certificate".to_owned()),
                client_private_key_id: Some("test-client-private-key".to_owned()),
            };
            if with_oauth {
                write.authentication = ConnectionAuthentication::OAuth2ClientCredentials {
                    client_id: "test-client".to_owned(),
                    client_secret_id: Some("test-oauth-secret".to_owned()),
                    token_url: "https://token.example.test/oauth/token".to_owned(),
                    scopes: vec![],
                    audience: None,
                    resource: None,
                    client_auth_method: OAuthClientAuthMethod::ClientSecretBasic,
                };
            }
            let mut aliases = vec![
                OperatorSecretAliasConfig {
                    id: "test-ca".to_owned(),
                    label: "Test CA".to_owned(),
                    source: OperatorSecretAliasSource::File {
                        key: "ca.pem".to_owned(),
                    },
                },
                OperatorSecretAliasConfig {
                    id: "test-client-certificate".to_owned(),
                    label: "Test client certificate".to_owned(),
                    source: OperatorSecretAliasSource::File {
                        key: "client-certificate.pem".to_owned(),
                    },
                },
                OperatorSecretAliasConfig {
                    id: "test-client-private-key".to_owned(),
                    label: "Test client private key".to_owned(),
                    source: OperatorSecretAliasSource::File {
                        key: "client-private-key.pem".to_owned(),
                    },
                },
            ];
            if with_oauth {
                aliases.push(OperatorSecretAliasConfig {
                    id: "test-oauth-secret".to_owned(),
                    label: "Test OAuth secret".to_owned(),
                    source: OperatorSecretAliasSource::File {
                        key: "oauth-secret".to_owned(),
                    },
                });
            }
            Self::build_with_root(name, root, write, aliases, Some(ca_path)).await
        }

        async fn build(
            name: &str,
            write: ConnectionWrite,
            aliases: Vec<OperatorSecretAliasConfig>,
            ca_path: Option<PathBuf>,
        ) -> Self {
            let root = temporary_managed_root(name);
            fs::create_dir(&root).expect("temporary managed root should create");
            Self::build_with_root(name, root, write, aliases, ca_path).await
        }

        async fn build_with_root(
            _name: &str,
            root: PathBuf,
            write: ConnectionWrite,
            aliases: Vec<OperatorSecretAliasConfig>,
            ca_path: Option<PathBuf>,
        ) -> Self {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                    .expect("temporary managed root permissions should set");
                for entry in fs::read_dir(&root).expect("temporary managed root should read") {
                    let path = entry.expect("temporary managed entry should read").path();
                    if path.is_file() {
                        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                            .expect("temporary managed file permissions should set");
                    }
                }
            }
            let mut config = Config::test_defaults();
            config.connections_sqlite_path =
                Some(root.join("connections.sqlite").display().to_string());
            config.connection_secrets_root = Some(SecretRootConfig::new(root.clone()));
            config.connection_secret_aliases = aliases;
            let control_plane =
                ConnectionControlPlane::from_config(&config).expect("control plane should build");
            let initial = control_plane.runtime_snapshot();
            let created = control_plane
                .create_managed(
                    initial.collection_etag(),
                    write,
                    &crate::auth::change_actor::ChangeActor::for_test("test-admin"),
                )
                .await
                .expect("managed connection should create");
            let egress_config = EgressConfig {
                allowed_hosts: HashSet::from([
                    "127.0.0.1".to_owned(),
                    "billing.example.test".to_owned(),
                    "token.example.test".to_owned(),
                ]),
                deny_private_ips: false,
                ..EgressConfig::default()
            };
            let egress_client = Arc::new(
                EgressClient::new(egress_config.clone()).expect("egress client should build"),
            );
            let runtime = ConnectionHttpRuntime::new(control_plane, egress_config, egress_client);
            Self {
                root,
                runtime,
                connection_id: created.id,
                ca_path,
            }
        }

        fn stored_connection(&self) -> StoredConnection {
            self.runtime
                .control_plane
                .runtime_snapshot()
                .managed()
                .get(&self.connection_id)
                .expect("managed test connection should remain present")
                .clone()
        }

        fn cached_client_count(&self) -> usize {
            self.runtime.client_guard().len()
        }
    }

    impl Drop for TemporaryManagedRuntime {
        fn drop(&mut self) {
            if self
                .root
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("greengateway-managed-http-"))
                && self.root.starts_with(std::env::temp_dir())
            {
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }

    fn temporary_managed_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "greengateway-managed-http-{name}-{}",
            uuid::Uuid::new_v4()
        ))
    }

    struct TemporaryOAuthRuntime {
        root: PathBuf,
        secret_path: PathBuf,
        runtime: ConnectionHttpRuntime,
        connection_id: ConnectionId,
        capture: CaptureSink,
    }

    impl TemporaryOAuthRuntime {
        async fn new(
            name: &str,
            base_url: String,
            token_url: String,
            allowed_hosts: HashSet<String>,
            ca_pem: Option<&str>,
        ) -> Self {
            let root = std::env::temp_dir().join(format!(
                "greengateway-oauth-{name}-{}",
                uuid::Uuid::new_v4()
            ));
            fs::create_dir(&root).expect("temporary OAuth root should create");
            let secret_path = root.join("client-secret");
            fs::write(&secret_path, OAUTH_CLIENT_SECRET_CANARY)
                .expect("temporary OAuth secret should write");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                    .expect("temporary OAuth root permissions should set");
                fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))
                    .expect("temporary OAuth secret permissions should set");
            }

            let mut config = Config::test_defaults();
            config.connections_sqlite_path =
                Some(root.join("connections.sqlite").display().to_string());
            config.connection_secrets_root = Some(SecretRootConfig::new(root.clone()));
            config.connection_secret_aliases = vec![OperatorSecretAliasConfig {
                id: "billing-oauth-secret".to_owned(),
                label: "Billing OAuth client secret".to_owned(),
                source: OperatorSecretAliasSource::File {
                    key: "client-secret".to_owned(),
                },
            }];
            let control_plane =
                ConnectionControlPlane::from_config(&config).expect("control plane should build");
            let initial = control_plane.runtime_snapshot();
            let mut write = record("/v1").write;
            write.endpoint.base_url = base_url;
            write.authentication = ConnectionAuthentication::OAuth2ClientCredentials {
                client_id: "billing:client".to_owned(),
                client_secret_id: Some("billing-oauth-secret".to_owned()),
                token_url,
                scopes: vec!["invoices.read".to_owned(), "payments.write".to_owned()],
                audience: Some("billing-api".to_owned()),
                resource: Some("urn:billing".to_owned()),
                client_auth_method: OAuthClientAuthMethod::ClientSecretBasic,
            };
            let created = control_plane
                .create_managed(
                    initial.collection_etag(),
                    write,
                    &crate::auth::change_actor::ChangeActor::for_test("test-admin"),
                )
                .await
                .expect("OAuth connection should create");

            let mut egress_config = EgressConfig {
                allowed_hosts,
                deny_private_ips: false,
                ..EgressConfig::default()
            };
            if let Some(ca_pem) = ca_pem {
                let ca_path = root.join("oauth-ca.pem");
                fs::write(&ca_path, ca_pem).expect("OAuth CA should write");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o600))
                        .expect("OAuth CA permissions should set");
                }
                egress_config
                    .apply_tls_ca_bundle_path(ca_path)
                    .expect("OAuth CA should configure");
            }
            let egress_client = Arc::new(
                EgressClient::new(egress_config.clone()).expect("egress client should build"),
            );
            let capture = CaptureSink::new();
            let audit = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
            let runtime = ConnectionHttpRuntime::new(control_plane, egress_config, egress_client)
                .with_audit(audit);

            Self {
                root,
                secret_path,
                runtime,
                connection_id: created.id,
                capture,
            }
        }

        fn stored_connection(&self) -> StoredConnection {
            self.runtime
                .control_plane
                .runtime_snapshot()
                .managed()
                .get(&self.connection_id)
                .expect("managed OAuth test connection should remain present")
                .clone()
        }
    }

    impl Drop for TemporaryOAuthRuntime {
        fn drop(&mut self) {
            if self
                .root
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("greengateway-oauth-"))
                && self.root.starts_with(std::env::temp_dir())
            {
                let _ = fs::remove_dir_all(&self.root);
            }
        }
    }

    fn record(base_path: &str) -> StoredConnection {
        StoredConnection {
            id: ConnectionId::parse("billing").expect("test connection ID"),
            write: ConnectionWrite {
                display_name: "Billing".to_owned(),
                description: None,
                enabled: true,
                kind: ConnectionKind::HttpApi,
                endpoint: ConnectionEndpoint {
                    base_url: "https://billing.example.test".to_owned(),
                    base_path: base_path.to_owned(),
                },
                authentication: ConnectionAuthentication::None,
                caller_assertion: None,
                additional_headers: Vec::new(),
                tls: TlsProfile::default(),
                timeouts: Some(ConnectionTimeouts::default()),
                discovery: None,
                test_profile: None,
            },
            revisions: ConnectionRevisions {
                connection: 1,
                credential: 1,
                tls: 1,
                discovery: 1,
                status: 0,
            },
            created_at: "2026-07-28T00:00:00Z".to_owned(),
            updated_at: "2026-07-28T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn target_url_stays_inside_connection_base_path() {
        assert_eq!(
            connection_target_url(&record("/v1"), "/charges/123?expand=customer")
                .expect("safe target"),
            "https://billing.example.test/v1/charges/123?expand=customer"
        );
        assert_eq!(
            connection_target_url(&record("/v1/"), "/").expect("base target"),
            "https://billing.example.test/v1/"
        );
    }

    #[test]
    fn authority_and_path_confusion_forms_fail_closed() {
        for path in [
            "https://attacker.example/",
            "//attacker.example/",
            "/safe/../escape",
            "/safe/%2fescape",
            "/safe\\escape",
        ] {
            assert_eq!(
                connection_target_url(&record("/v1"), path),
                Err(ConnectionHttpError::InvalidTargetPath),
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn connection_tls_is_resolved_only_after_egress_preflight() {
        let temporary = TemporaryManagedRuntime::tls_identity("tls-preflight-order").await;
        let target = temporary
            .runtime
            .target(temporary.connection_id.as_str(), "/health")
            .expect("TLS target creation must not resolve secret material");
        fs::remove_file(
            temporary
                .ca_path
                .as_ref()
                .expect("TLS helper should retain CA path"),
        )
        .expect("test CA should be removed after target creation");

        let checked = target
            .preflight_client()
            .checked_destination(target.url())
            .await
            .expect("egress preflight must not require TLS secret material");
        let error = match temporary.runtime.prepare_transport(&target, &checked).await {
            Ok(_) => panic!("missing TLS material must fail closed"),
            Err(error) => error,
        };

        assert_eq!(error, ConnectionHttpError::TlsUnavailable);
        assert_eq!(error.safe_reason(), "tls_unavailable");
        assert!(!error.to_string().contains("ca.pem"));
    }

    #[tokio::test]
    async fn malformed_runtime_tls_material_has_only_stable_redacted_error() {
        const INVALID_TLS_CANARY: &[u8] = b"invalid-tls-private-canary";
        let temporary = TemporaryManagedRuntime::tls_identity("invalid-runtime-tls").await;
        fs::write(
            temporary
                .ca_path
                .as_ref()
                .expect("TLS helper should retain CA path"),
            INVALID_TLS_CANARY,
        )
        .expect("test CA should be corrupted after activation");
        let target = temporary
            .runtime
            .target(temporary.connection_id.as_str(), "/health")
            .expect("target construction must stay TLS-material-free");
        let checked = target
            .preflight_client()
            .checked_destination(target.url())
            .await
            .expect("egress preflight should precede TLS resolution");
        let error = match temporary.runtime.prepare_transport(&target, &checked).await {
            Ok(_) => panic!("malformed TLS material must fail closed"),
            Err(error) => error,
        };

        assert_eq!(error, ConnectionHttpError::TlsInvalid);
        assert_eq!(error.safe_reason(), "tls_invalid");
        assert!(!error.to_string().contains(
            std::str::from_utf8(INVALID_TLS_CANARY).expect("test canary should be UTF-8")
        ));
    }

    #[tokio::test]
    async fn prepared_upstream_applies_identity_without_leaking_it_to_oauth() {
        let temporary =
            TemporaryManagedRuntime::tls_identity_with_oauth("tls-oauth-isolation", true).await;
        let target = temporary
            .runtime
            .target(temporary.connection_id.as_str(), "/health")
            .expect("TLS OAuth target should build");
        let oauth_client = match &target.authentication {
            HttpAuthenticationBinding::OAuth2ClientCredentials(binding) => &binding.token_client,
            _ => panic!("test connection should use OAuth"),
        };
        assert_eq!(
            oauth_client.client_identity_fingerprint(),
            None,
            "connection-owned mTLS must not be applied to the OAuth token host"
        );

        let checked = target
            .preflight_client()
            .checked_destination(target.url())
            .await
            .expect("upstream preflight should succeed");
        let prepared = temporary
            .runtime
            .prepare_transport(&target, &checked)
            .await
            .expect("valid in-memory TLS material should prepare");

        assert!(
            prepared.client().client_identity_fingerprint().is_some(),
            "prepared upstream must carry the connection-owned identity"
        );
        assert_ne!(
            target.preflight_client().configuration_generation(),
            prepared.client().configuration_generation(),
            "resolved TLS material must select a distinct final transport"
        );
        assert_eq!(prepared.destination().host, "127.0.0.1");
    }

    #[tokio::test]
    async fn tls_material_is_resolved_again_before_each_cache_selection() {
        let temporary = TemporaryManagedRuntime::tls_identity("tls-runtime-rotation").await;
        let target = temporary
            .runtime
            .target(temporary.connection_id.as_str(), "/health")
            .expect("TLS target should build");
        let checked = target
            .preflight_client()
            .checked_destination(target.url())
            .await
            .expect("upstream preflight should succeed");
        let first = temporary
            .runtime
            .prepare_transport(&target, &checked)
            .await
            .expect("first TLS material should prepare");

        let replacement_key =
            rcgen::KeyPair::generate().expect("replacement identity key should build");
        let replacement_certificate = CertificateParams::default()
            .self_signed(&replacement_key)
            .expect("replacement identity certificate should build");
        fs::write(temporary.root.join("ca.pem"), replacement_certificate.pem())
            .expect("replacement CA should write");
        fs::write(
            temporary.root.join("client-certificate.pem"),
            replacement_certificate.pem(),
        )
        .expect("replacement certificate should write");
        fs::write(
            temporary.root.join("client-private-key.pem"),
            replacement_key.serialize_pem(),
        )
        .expect("replacement private key should write");

        let second = temporary
            .runtime
            .prepare_transport(&target, &checked)
            .await
            .expect("rotated TLS material should prepare");
        assert_ne!(
            first.client().client_identity_fingerprint(),
            second.client().client_identity_fingerprint(),
            "material rotation must not reuse the previous identity"
        );
        assert_ne!(
            first.client().configuration_generation(),
            second.client().configuration_generation(),
            "material rotation must select a distinct cached transport"
        );
    }

    #[tokio::test]
    async fn persisted_http_test_target_can_probe_disabled_connection_without_widening_runtime() {
        let mut write = record("/v1").write;
        write.enabled = false;
        write.test_profile = Some(ConnectionTestProfile {
            method: "HEAD".to_owned(),
            path: "/ready".to_owned(),
            expected_statuses: vec![200, 204],
        });
        let temporary = TemporaryManagedRuntime::from_write("disabled-http-test", write).await;

        let normal_error = match temporary
            .runtime
            .target(temporary.connection_id.as_str(), "/ready")
        {
            Ok(_) => panic!("normal target must reject a disabled connection"),
            Err(error) => error,
        };
        assert_eq!(normal_error, ConnectionHttpError::ConnectionDisabled);
        let expected_etag = temporary.stored_connection().etag().to_string();
        let test = temporary
            .runtime
            .test_target(temporary.connection_id.as_str(), &expected_etag)
            .expect("persisted test mode should permit a disabled connection")
            .expect("unchanged connection should return a test target");
        assert_eq!(test.method(), Method::HEAD);
        assert_eq!(test.target().url(), "https://billing.example.test/v1/ready");
        assert_eq!(test.expected_statuses(), &[200, 204]);
    }

    #[tokio::test]
    async fn persisted_mcp_test_target_can_probe_disabled_managed_mcp_only() {
        let mut write = record("/mcp").write;
        write.enabled = false;
        write.kind = ConnectionKind::McpStreamableHttp;
        write.discovery = Some(DiscoveryConfig::ManagedMcp {
            use_connection_authentication: false,
        });
        let temporary = TemporaryManagedRuntime::from_write("disabled-mcp-test", write).await;

        let normal_error = match temporary
            .runtime
            .mcp_target(temporary.connection_id.as_str())
        {
            Ok(_) => panic!("normal MCP target must reject a disabled connection"),
            Err(error) => error,
        };
        assert_eq!(normal_error, ConnectionHttpError::ConnectionDisabled);
        let expected_etag = temporary.stored_connection().etag().to_string();
        let test = temporary
            .runtime
            .mcp_test_target(temporary.connection_id.as_str(), &expected_etag)
            .expect("persisted MCP test mode should permit a disabled managed MCP connection")
            .expect("unchanged connection should return an MCP test target");
        assert_eq!(test.url(), "https://billing.example.test/mcp");
        assert_eq!(test.authentication_kind(), "none");
    }

    /// A caller assertion as an operator would configure one. Its signing key
    /// is loaded when the Connection is saved; every target but an attesting
    /// lane's must still refuse before anything would sign with it.
    fn unenforced_caller_assertion() -> CallerAssertionSettings {
        CallerAssertionSettings {
            signing_key_id: crate::connections::test_support::ASSERTION_SIGNING_KEY_ALIAS
                .to_owned(),
            kid: "gw-test-1".to_owned(),
            algorithm: CallerAssertionAlgorithm::Es256,
            issuer: "https://gateway.example.test".to_owned(),
            audience: "https://billing.example.test".to_owned(),
            token_type: "at+jwt".to_owned(),
            header_name: "x-caller-assertion".to_owned(),
            lifetime_seconds: 60,
            claims: Vec::new(),
            bind_request: false,
            bind_approval: false,
            published_keys: Vec::new(),
        }
    }

    /// A managed runtime whose single Connection is `write`, with a generated
    /// caller-assertion signing key behind the alias it binds.
    async fn attested_runtime(name: &str, write: ConnectionWrite) -> TemporaryManagedRuntime {
        let root = temporary_managed_root(name);
        fs::create_dir(&root).expect("temporary managed root should create");
        let alias = crate::connections::test_support::write_assertion_signing_key(
            &root,
            &crate::connections::test_support::generated_es256_pem(),
        );
        // A header-safe secret too, for a test that adds an additional header.
        let header = crate::connections::test_support::write_secret_file(
            &root,
            "proxy-header-secret",
            b"proxy-header-value",
        );
        TemporaryManagedRuntime::build_with_root(name, root, write, vec![alias, header], None).await
    }

    #[tokio::test]
    async fn every_http_target_refuses_an_unenforced_caller_assertion_before_preparation() {
        // Only an attesting lane signs the assertion, so serving this
        // Connection on any other lane would send the upstream calls it cannot
        // attribute while the operator believes every call names its caller.
        let mut write = record("/v1").write;
        write.caller_assertion = Some(unenforced_caller_assertion());
        write.discovery = Some(DiscoveryConfig::ManagedOpenapi {
            path: Some("/openapi.json".to_owned()),
            use_connection_authentication: false,
        });
        write.test_profile = Some(ConnectionTestProfile {
            method: "GET".to_owned(),
            path: "/ready".to_owned(),
            expected_statuses: vec![200],
        });
        let temporary = attested_runtime("caller-assertion-http", write).await;
        let connection_id = temporary.connection_id.as_str();
        let stored = temporary.stored_connection();
        let etag = stored.etag().to_string();
        let refused = Some(ConnectionHttpError::CallerAssertionNotEnforced);

        // Enum and label sources.
        assert_eq!(
            temporary.runtime.target(connection_id, "/charges").err(),
            refused
        );
        assert_eq!(
            temporary.runtime.validate_binding(connection_id).err(),
            refused
        );
        // OpenAPI discovery.
        assert_eq!(
            temporary
                .runtime
                .openapi_discovery_target(connection_id)
                .err(),
            refused
        );
        // Connection tests, which otherwise probe even a disabled Connection.
        assert_eq!(
            temporary.runtime.test_target(connection_id, &etag).err(),
            refused
        );
        // No egress client was prepared for a target that was never built.
        assert_eq!(temporary.cached_client_count(), 0);

        let execution = ConnectionTestService::new(temporary.runtime.clone())
            .execute(&stored, &etag)
            .await;
        assert!(!execution.result.ok);
        assert_eq!(
            execution.result.stages,
            vec![ConnectionTestStage::failure(
                ConnectionTestStageName::Authenticated,
                ConnectionTestReason::CallerAssertionNotEnforced,
            )]
        );
        assert_eq!(
            execution.status_reason,
            ConnectionStatusReason::RequestFailed
        );
        assert_eq!(temporary.cached_client_count(), 0);

        // The assertion is the only reason: the same Connection without one
        // builds a target again.
        let mut without_assertion = stored.write.clone();
        without_assertion.caller_assertion = None;
        temporary
            .runtime
            .control_plane
            .replace_managed(
                &stored.id,
                &stored.etag(),
                without_assertion,
                &crate::auth::change_actor::ChangeActor::for_test("test-admin"),
            )
            .await
            .expect("the Connection without an assertion should save");
        assert!(temporary.runtime.target(connection_id, "/charges").is_ok());
    }

    #[tokio::test]
    async fn every_mcp_target_refuses_an_unenforced_caller_assertion_before_preparation() {
        // Even a session that would not use the Connection's own credential is
        // refused: the assertion is about the caller, not the credential.
        let mut write = record("/mcp").write;
        write.kind = ConnectionKind::McpStreamableHttp;
        write.discovery = Some(DiscoveryConfig::ManagedMcp {
            use_connection_authentication: false,
        });
        write.caller_assertion = Some(unenforced_caller_assertion());
        let temporary = attested_runtime("caller-assertion-mcp", write).await;
        let connection_id = temporary.connection_id.as_str();
        let stored = temporary.stored_connection();
        let etag = stored.etag().to_string();
        let refused = Some(ConnectionHttpError::CallerAssertionNotEnforced);

        // MCP catalog discovery, which has no caller to attest.
        assert_eq!(temporary.runtime.mcp_target(connection_id).err(), refused);
        // MCP Connection tests.
        assert_eq!(
            temporary
                .runtime
                .mcp_test_target(connection_id, &etag)
                .err(),
            refused
        );
        assert_eq!(temporary.cached_client_count(), 0);

        let execution = ConnectionTestService::new(temporary.runtime.clone())
            .execute(&stored, &etag)
            .await;
        assert!(!execution.result.ok);
        assert_eq!(
            execution.result.stages,
            vec![ConnectionTestStage::failure(
                ConnectionTestStageName::Authenticated,
                ConnectionTestReason::CallerAssertionNotEnforced,
            )]
        );
        assert_eq!(
            execution.status_reason,
            ConnectionStatusReason::RequestFailed
        );
        assert_eq!(temporary.cached_client_count(), 0);

        // A tool call's session is the one MCP target that carries it, even
        // when the session does not use the Connection's own credential: the
        // assertion is about the caller, not the credential.
        let target = temporary
            .runtime
            .mcp_tool_call_target(connection_id)
            .expect("a valid attested Connection serves MCP tool calls");
        assert!(target.attests_caller());
        assert!(target.is_credentialed());
        assert!(target.credential_header_names().is_empty());
        assert_eq!(
            target
                .caller_assertion_header_name()
                .map(HeaderName::as_str),
            Some("x-caller-assertion")
        );
        // An MCP Connection is never an HTTP lane's.
        assert_eq!(
            temporary
                .runtime
                .proxy_route_target(connection_id, "/")
                .err(),
            Some(ConnectionHttpError::WrongConnectionKind)
        );
    }

    fn principal(auth_method: crate::auth::AuthMethod) -> crate::auth::Principal {
        crate::auth::Principal {
            user_id: "alice".to_owned(),
            issuer: Some("https://idp.example.test".to_owned()),
            email: None,
            org_id: None,
            roles: Vec::new(),
            session_id: "session-alice".to_owned(),
            auth_method,
        }
    }

    #[tokio::test]
    async fn the_attesting_lanes_carry_the_assertion_and_every_other_lane_refuses() {
        let mut write = record("/v1").write;
        let mut assertion = unenforced_caller_assertion();
        assertion.bind_request = true;
        write.caller_assertion = Some(assertion);
        let temporary = attested_runtime("caller-assertion-tool-target", write).await;
        let connection_id = temporary.connection_id.as_str();

        let target = temporary
            .runtime
            .tool_call_target(connection_id, "/charges?limit=2")
            .expect("a valid attested Connection serves tool calls");
        assert_eq!(
            target
                .caller_assertion_header_name()
                .map(HeaderName::as_str),
            Some("x-caller-assertion")
        );
        // It is a credential even with `authentication: none`: a TRACE must
        // not reflect it, and an upstream 401 is a rejection of it.
        assert!(target.is_credentialed());
        assert!(target.credential_header_names().is_empty());
        assert!(target.attests_caller());
        // With `bind_request` a lane that streams bodies must hold this one.
        assert!(target.caller_assertion_binds_request_body());
        assert!(temporary
            .runtime
            .validate_tool_binding(connection_id)
            .is_ok());
        // Managed OpenAPI tools, composite leaves and proxied requests attest
        // the same way.
        for lane_target in [
            temporary
                .runtime
                .openapi_tool_target(connection_id, "/charges")
                .expect("a valid attested Connection serves OpenAPI tool calls"),
            temporary
                .runtime
                .composite_leaf_target(connection_id, "/charges")
                .expect("a valid attested Connection serves composite leaves"),
            temporary
                .runtime
                .proxy_route_target(connection_id, "/charges")
                .expect("a valid attested Connection serves proxied requests"),
        ] {
            assert_eq!(
                lane_target
                    .caller_assertion_header_name()
                    .map(HeaderName::as_str),
                Some("x-caller-assertion")
            );
            assert!(lane_target.is_credentialed());
            assert!(lane_target.caller_assertion_binds_request_body());
        }
        assert!(temporary
            .runtime
            .validate_openapi_tool_binding(connection_id)
            .is_ok());
        // Every lane without a caller to attest still refuses the same
        // Connection.
        assert_eq!(
            temporary.runtime.target(connection_id, "/charges").err(),
            Some(ConnectionHttpError::CallerAssertionNotEnforced)
        );
        assert_eq!(
            temporary
                .runtime
                .openapi_discovery_target(connection_id)
                .err(),
            Some(ConnectionHttpError::CallerAssertionNotEnforced)
        );

        // No principal, or a service token, is nobody to attest.
        let alice = AttestedCaller::from_principal(&principal(crate::auth::AuthMethod::Bearer))
            .expect("a provider-vouched principal is attestable");
        assert!(
            AttestedCaller::from_principal(&principal(crate::auth::AuthMethod::ServiceToken))
                .is_none()
        );
        let mut issuerless = principal(crate::auth::AuthMethod::Bearer);
        issuerless.issuer = None;
        assert!(AttestedCaller::from_principal(&issuerless).is_none());
        assert_eq!(
            temporary
                .runtime
                .admit_caller_assertion(&target, None)
                .await,
            Err(CallerAssertionError::NoPrincipal)
        );
        assert_eq!(
            temporary
                .runtime
                .caller_assertion_signer(&target)
                .await
                .expect("the key loads")
                .expect("an attested target signs")
                .sign(None, "request-1", &Method::GET, b"")
                .err(),
            Some(CallerAssertionError::NoPrincipal)
        );
        assert_eq!(
            temporary
                .runtime
                .admit_caller_assertion(&target, Some(&alice))
                .await,
            Ok(())
        );

        let loaded = temporary
            .runtime
            .caller_assertion_signer(&target)
            .await
            .expect("the key loads")
            .expect("an attested target signs");
        assert!(
            format!("{loaded:?}").contains("gw-test-1"),
            "the signer names its kid"
        );
        let signed = loaded
            .sign(Some(&alice), "request-1", &Method::GET, b"")
            .expect("the loaded key signs");
        assert_eq!(
            signed.issued(),
            &IssuedCallerAssertion {
                kid: "gw-test-1".to_owned(),
                jti: "request-1".to_owned(),
            }
        );
        let token = signed
            .value
            .to_str()
            .expect("an assertion is visible ASCII")
            .to_owned();
        assert!(signed.value.is_sensitive());
        assert!(
            !format!("{signed:?}").contains(&token),
            "Debug must not print the assertion"
        );

        // Written once, last: a value already under the name is refused, not
        // replaced or joined.
        let mut headers = HeaderMap::new();
        headers.insert("x-caller-assertion", HeaderValue::from_static("forged"));
        assert_eq!(
            signed.inject(&mut headers),
            Err(CallerAssertionError::HeaderConflict)
        );
        assert_eq!(headers.get_all("x-caller-assertion").iter().count(), 1);
        assert_eq!(
            headers.get("x-caller-assertion"),
            Some(&HeaderValue::from_static("forged"))
        );

        // A target without an assertion signs nothing and admits anybody.
        let mut plain = temporary.stored_connection().write;
        plain.caller_assertion = None;
        let stored = temporary.stored_connection();
        temporary
            .runtime
            .control_plane
            .replace_managed(
                &stored.id,
                &stored.etag(),
                plain,
                &crate::auth::change_actor::ChangeActor::for_test("test-admin"),
            )
            .await
            .expect("the Connection without an assertion should save");
        let unattested = temporary
            .runtime
            .tool_call_target(connection_id, "/charges")
            .expect("an unattested Connection serves tool calls");
        assert!(unattested.caller_assertion_header_name().is_none());
        assert!(!unattested.attests_caller());
        assert!(!unattested.caller_assertion_binds_request_body());
        assert_eq!(
            temporary
                .runtime
                .admit_caller_assertion(&unattested, None)
                .await,
            Ok(())
        );
        assert!(temporary
            .runtime
            .caller_assertion_signer(&unattested)
            .await
            .expect("nothing to load")
            .is_none());
    }

    #[tokio::test]
    async fn a_delegated_connection_serves_tool_calls_only_and_sends_no_assertion_upstream() {
        let mut write = record("/v1").write;
        write.caller_assertion = Some(unenforced_caller_assertion());
        write.authentication = ConnectionAuthentication::DelegatedIssuerToken {
            token_exchange_url: "https://token.example.test/oauth2/token-exchange".to_owned(),
            client_id: "greengateway".to_owned(),
            client_secret_id: Some("issuer-exchange-secret".to_owned()),
            requested_scopes: vec!["mail.read".to_owned()],
            audience: Some("https://billing.example.test".to_owned()),
            resource: None,
            revocation_url: None,
            subject_token_source: SubjectTokenSource::CallerAssertion,
        };
        let root = temporary_managed_root("delegated-tool-target");
        fs::create_dir(&root).expect("temporary managed root should create");
        let aliases = vec![
            crate::connections::test_support::write_assertion_signing_key(
                &root,
                &crate::connections::test_support::generated_es256_pem(),
            ),
            crate::connections::test_support::write_secret_file(
                &root,
                "issuer-exchange-secret",
                b"issuer-exchange-value",
            ),
        ];
        let temporary = TemporaryManagedRuntime::build_with_root(
            "delegated-tool-target",
            root,
            write,
            aliases,
            None,
        )
        .await;
        let connection_id = temporary.connection_id.as_str();
        let stored = temporary.stored_connection();

        let target = temporary
            .runtime
            .tool_call_target(connection_id, "/messages")
            .expect("a delegated Connection serves manual tool calls");
        assert_eq!(target.authentication_kind(), "delegated_issuer_token");
        assert!(target.credential_belongs_to_caller());
        assert_eq!(target.credential_header_names(), &[header::AUTHORIZATION]);
        // The assertion header is still stripped from what a caller sent, but
        // the gateway writes no assertion there: it goes to the issuer only.
        assert_eq!(
            target
                .caller_assertion_header_name()
                .map(HeaderName::as_str),
            Some("x-caller-assertion")
        );
        assert!(temporary
            .runtime
            .caller_assertion_signer(&target)
            .await
            .expect("nothing is loaded")
            .is_none());

        // A call that names nobody is refused before anything is read or
        // sent: the issuer host does not even resolve.
        let alice = AttestedCaller::from_principal(&principal(crate::auth::AuthMethod::Bearer))
            .expect("a provider-vouched principal is attestable");
        assert_eq!(
            temporary
                .runtime
                .resolve_credential(&target, None)
                .await
                .err(),
            Some(ConnectionHttpError::DelegatedTokenNoPrincipal)
        );
        assert_eq!(
            temporary
                .runtime
                .resolve_credential_before(
                    &target,
                    None,
                    tokio::time::Instant::now() + Duration::from_secs(5),
                )
                .await
                .err(),
            Some(ConnectionHttpError::DelegatedTokenNoPrincipal)
        );
        assert_eq!(temporary.runtime.delegated_token_cache_entries(), 0);
        assert_eq!(
            temporary
                .runtime
                .admit_caller_assertion(&target, Some(&alice))
                .await,
            Ok(())
        );

        // A delegated subject token is never a request binding.
        assert!(!target.caller_assertion_binds_request_body());

        // A managed OpenAPI tool is served the same way (issue #443): its
        // target carries the caller's own credential and keeps the
        // assertion for the issuer alone.
        let openapi = temporary
            .runtime
            .openapi_tool_target(connection_id, "/messages")
            .expect("a delegated Connection serves managed OpenAPI tool calls");
        assert_eq!(openapi.authentication_kind(), "delegated_issuer_token");
        assert!(openapi.credential_belongs_to_caller());
        assert_eq!(openapi.credential_header_names(), &[header::AUTHORIZATION]);
        assert!(temporary
            .runtime
            .caller_assertion_signer(&openapi)
            .await
            .expect("nothing is loaded")
            .is_none());
        assert_eq!(
            temporary
                .runtime
                .resolve_credential(&openapi, None)
                .await
                .err(),
            Some(ConnectionHttpError::DelegatedTokenNoPrincipal)
        );
        assert!(temporary
            .runtime
            .validate_openapi_tool_binding(connection_id)
            .is_ok());

        // Every other tool and proxy lane refuses it before preparing
        // anything, because it carries the caller assertion its subject token
        // is signed with. That includes the lanes that attest their callers:
        // only a manual or managed OpenAPI tool obtains a caller's own
        // delegated token, and a stored test its tester's (see the next test).
        let refused = Some(ConnectionHttpError::CallerAssertionNotEnforced);
        assert_eq!(
            temporary.runtime.target(connection_id, "/messages").err(),
            refused
        );
        assert_eq!(
            temporary.runtime.validate_binding(connection_id).err(),
            refused
        );
        assert_eq!(
            temporary
                .runtime
                .composite_leaf_target(connection_id, "/messages")
                .err(),
            refused
        );
        assert_eq!(
            temporary
                .runtime
                .proxy_route_target(connection_id, "/messages")
                .err(),
            refused
        );
        for lane in [
            AttestingLane::CompositeLeaf,
            AttestingLane::ProxyRoute,
            AttestingLane::ManagedMcpTool,
        ] {
            assert!(!caller_assertion_servable_on(&stored.write, lane));
        }
        for lane in [
            AttestingLane::ManualTool,
            AttestingLane::OpenApiTool,
            AttestingLane::ConnectionTest,
        ] {
            assert!(caller_assertion_servable_on(&stored.write, lane));
        }
    }

    #[tokio::test]
    async fn a_delegated_connection_is_tested_as_the_tester_and_sends_no_assertion_upstream() {
        let mut write = record("/v1").write;
        write.caller_assertion = Some(unenforced_caller_assertion());
        write.authentication = ConnectionAuthentication::DelegatedIssuerToken {
            token_exchange_url: "https://token.example.test/oauth2/token-exchange".to_owned(),
            client_id: "greengateway".to_owned(),
            client_secret_id: Some("issuer-exchange-secret".to_owned()),
            requested_scopes: vec!["mail.read".to_owned()],
            audience: None,
            resource: None,
            revocation_url: None,
            subject_token_source: SubjectTokenSource::CallerAssertion,
        };
        write.test_profile = Some(ConnectionTestProfile {
            method: "GET".to_owned(),
            path: "/messages".to_owned(),
            expected_statuses: vec![200],
        });
        let root = temporary_managed_root("delegated-test-target");
        fs::create_dir(&root).expect("temporary managed root should create");
        let aliases = vec![
            crate::connections::test_support::write_assertion_signing_key(
                &root,
                &crate::connections::test_support::generated_es256_pem(),
            ),
            crate::connections::test_support::write_secret_file(
                &root,
                "issuer-exchange-secret",
                b"issuer-exchange-value",
            ),
        ];
        let temporary = TemporaryManagedRuntime::build_with_root(
            "delegated-test-target",
            root,
            write,
            aliases,
            None,
        )
        .await;
        let connection_id = temporary.connection_id.as_str();
        let stored = temporary.stored_connection();
        let etag = stored.etag().to_string();

        let test_target = temporary
            .runtime
            .test_target(connection_id, &etag)
            .expect("a delegated Connection is tested")
            .expect("the etag is current");
        let target = test_target.target();
        assert!(target.attests_caller());
        assert!(target.credential_belongs_to_caller());
        // The subject token goes to the issuer only, as on a tool call.
        assert!(temporary
            .runtime
            .caller_assertion_signer(target)
            .await
            .expect("nothing is loaded")
            .is_none());
        assert!(!target.caller_assertion_binds_request_body());

        // A test that names nobody, and one of a Connection whose keys are
        // not published, is refused before anything is resolved or sent: the
        // issuer host does not even resolve.
        let alice = AttestedCaller::from_principal(&principal(crate::auth::AuthMethod::Bearer))
            .expect("a provider-vouched principal is attestable");
        let tests = ConnectionTestService::new(temporary.runtime.clone());
        assert_eq!(
            tests.execute(&stored, &etag).await.result.stages,
            vec![ConnectionTestStage::failure(
                ConnectionTestStageName::SecretAvailable,
                ConnectionTestReason::DelegatedTokenNoPrincipal,
            )]
        );
        let mut disabled = stored.write.clone();
        disabled.enabled = false;
        let disabled = temporary
            .runtime
            .control_plane
            .replace_managed(
                &stored.id,
                &stored.etag(),
                disabled,
                &crate::auth::change_actor::ChangeActor::for_test("test-admin"),
            )
            .await
            .expect("the Connection disables");
        let disabled_etag = disabled.etag().to_string();
        let target = temporary
            .runtime
            .test_target(connection_id, &disabled_etag)
            .expect("a disabled delegated Connection still builds a test target")
            .expect("the etag is current");
        assert_eq!(
            temporary
                .runtime
                .admit_caller_assertion(target.target(), Some(&alice))
                .await,
            Err(CallerAssertionError::KeyNotPublished)
        );
        let execution = tests
            .execute_as(&disabled, &disabled_etag, Some(&alice))
            .await;
        assert_eq!(
            execution.result.stages,
            vec![ConnectionTestStage::failure(
                ConnectionTestStageName::Authenticated,
                ConnectionTestReason::CallerAssertionKeyNotPublished,
            )]
        );
        assert_eq!(
            execution.status_reason,
            ConnectionStatusReason::RequestFailed
        );
        assert_eq!(temporary.runtime.delegated_token_cache_entries(), 0);
    }

    #[test]
    fn every_delegated_refusal_has_a_distinct_fixed_reason() {
        let reasons = [
            ConnectionHttpError::DelegatedTokenNoPrincipal,
            ConnectionHttpError::DelegatedTokenEgressDenied,
            ConnectionHttpError::DelegatedTokenDenied,
            ConnectionHttpError::DelegatedTokenExchangeFailed,
            ConnectionHttpError::DelegatedTokenUnavailable,
        ]
        .map(ConnectionHttpError::safe_reason);
        assert_eq!(
            reasons,
            [
                "delegated_token_no_principal",
                "delegated_token_egress_denied",
                "delegated_token_denied",
                "delegated_token_exchange_failed",
                "delegated_token_unavailable",
            ]
        );
        // None of them is a secret-resolution failure: the issuer answered,
        // or was never asked.
        assert!(!ConnectionHttpError::DelegatedTokenDenied.is_secret_resolution_failure());
        // A secret the exchange cannot read is reported like any other.
        assert_eq!(
            connection_delegated_error(DelegatedTokenError::CredentialInvalid),
            ConnectionHttpError::CredentialInvalid
        );
        assert_eq!(
            connection_delegated_error(DelegatedTokenError::CredentialUnavailable),
            ConnectionHttpError::CredentialUnavailable
        );
    }

    #[tokio::test]
    async fn a_kid_another_connection_publishes_for_a_different_key_refuses_the_call() {
        let mut write = record("/v1").write;
        write.caller_assertion = Some(unenforced_caller_assertion());
        let temporary = attested_runtime("caller-assertion-kid-clash", write).await;
        let connection_id = temporary.connection_id.as_str();
        let stored = temporary.stored_connection();
        let alice = AttestedCaller::from_principal(&principal(crate::auth::AuthMethod::Bearer))
            .expect("a provider-vouched principal is attestable");

        // Another replica admitted a second Connection that publishes the same
        // kid for an RS256 key. The JWKS leaves both out, so neither may sign.
        let mut other = stored.clone();
        other.id = ConnectionId::parse("billing-two").expect("test connection ID");
        if let Some(assertion) = other.write.caller_assertion.as_mut() {
            assertion.algorithm = CallerAssertionAlgorithm::Rs256;
        }
        temporary
            .runtime
            .control_plane
            .publish_authoritative_records(vec![stored.clone(), other.clone()])
            .await
            .expect("the clash still loads");
        let target = temporary
            .runtime
            .tool_call_target(connection_id, "/charges")
            .expect("the document itself is valid");
        assert_eq!(
            temporary
                .runtime
                .admit_caller_assertion(&target, Some(&alice))
                .await,
            Err(CallerAssertionError::KeyNotPublished)
        );

        // A disabled Connection publishes nothing, so it clashes with nothing.
        other.write.enabled = false;
        temporary
            .runtime
            .control_plane
            .publish_authoritative_records(vec![stored, other])
            .await
            .expect("the disabled Connection loads");
        // A target is judged on the configuration it was built from, so the
        // call already in hand is still refused; the next one is admitted.
        assert_eq!(
            temporary
                .runtime
                .admit_caller_assertion(&target, Some(&alice))
                .await,
            Err(CallerAssertionError::KeyNotPublished)
        );
        let target = temporary
            .runtime
            .tool_call_target(connection_id, "/charges")
            .expect("the document itself is valid");
        assert_eq!(
            temporary
                .runtime
                .admit_caller_assertion(&target, Some(&alice))
                .await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn a_stored_assertion_only_the_legacy_reading_admits_is_never_served() {
        let mut write = record("/v1").write;
        write.caller_assertion = Some(unenforced_caller_assertion());
        let temporary = attested_runtime("caller-assertion-legacy", write).await;
        let connection_id = temporary.connection_id.as_str();
        let stored = temporary.stored_connection();
        assert!(stored.write.caller_assertion_enforceable());

        let mut approval = stored.clone();
        if let Some(assertion) = approval.write.caller_assertion.as_mut() {
            assertion.bind_approval = true;
        }
        let mut collision = stored.clone();
        collision.write.additional_headers.push(AdditionalHeader {
            header_name: "X-Caller-Assertion".to_owned(),
            secret_id: Some("proxy-header-secret".to_owned()),
        });
        let mut plain_http = stored.clone();
        plain_http.write.endpoint.base_url = "http://billing.example.test".to_owned();

        for legacy in [approval, collision, plain_http] {
            // Readable, as a document an earlier release stored ...
            assert!(legacy.write.clone().validated_persisted_v0().is_ok());
            // ... refused for any new or replacement write ...
            assert!(legacy.write.clone().validated().is_err());
            // ... and not served.
            assert!(!legacy.write.caller_assertion_enforceable());
            temporary
                .runtime
                .control_plane
                .publish_authoritative_records(vec![legacy])
                .await
                .expect("a legacy document still loads");
            assert_eq!(
                temporary
                    .runtime
                    .tool_call_target(connection_id, "/charges")
                    .err(),
                Some(ConnectionHttpError::CallerAssertionNotEnforced)
            );
            assert_eq!(
                temporary.runtime.validate_tool_binding(connection_id),
                Err(ConnectionHttpError::CallerAssertionNotEnforced)
            );
            // No attesting lane serves it either.
            assert_eq!(
                temporary
                    .runtime
                    .openapi_tool_target(connection_id, "/charges")
                    .err(),
                Some(ConnectionHttpError::CallerAssertionNotEnforced)
            );
            assert_eq!(
                temporary
                    .runtime
                    .composite_leaf_target(connection_id, "/charges")
                    .err(),
                Some(ConnectionHttpError::CallerAssertionNotEnforced)
            );
            assert_eq!(
                temporary
                    .runtime
                    .proxy_route_target(connection_id, "/charges")
                    .err(),
                Some(ConnectionHttpError::CallerAssertionNotEnforced)
            );
            assert_eq!(
                temporary.runtime.mcp_tool_call_target(connection_id).err(),
                Some(ConnectionHttpError::CallerAssertionNotEnforced)
            );
        }
        assert_eq!(temporary.cached_client_count(), 0);
    }

    #[tokio::test]
    async fn a_session_signs_each_request_with_its_own_jti_and_nothing_once_sealed() {
        let mut write = record("/mcp").write;
        write.kind = ConnectionKind::McpStreamableHttp;
        write.discovery = Some(DiscoveryConfig::ManagedMcp {
            use_connection_authentication: false,
        });
        let mut assertion = unenforced_caller_assertion();
        assertion.bind_request = true;
        write.caller_assertion = Some(assertion);
        let temporary = attested_runtime("caller-assertion-session", write).await;
        let connection_id = temporary.connection_id.as_str();
        let alice = AttestedCaller::from_principal(&principal(crate::auth::AuthMethod::Bearer))
            .expect("a provider-vouched principal is attestable");
        let target = temporary
            .runtime
            .mcp_tool_call_target(connection_id)
            .expect("an attested MCP Connection serves tool calls");
        let session = temporary
            .runtime
            .caller_assertion_signer(&target)
            .await
            .expect("the key loads")
            .expect("an attested target signs")
            .into_session(&alice, "request-7");
        assert_eq!(
            session.header_name().as_str(),
            "x-caller-assertion",
            "every request of the session uses the Connection's header"
        );
        assert!(
            !format!("{session:?}").contains("BEGIN"),
            "Debug names the kid and the request, never the key"
        );

        let jwks = temporary
            .runtime
            .control_plane
            .caller_assertion_jwks()
            .await
            .expect("the signing key is published");
        let set: jsonwebtoken::jwk::JwkSet =
            serde_json::from_str(jwks.body()).expect("the JWKS is a JWK Set");
        let verify = |signed: SignedCallerAssertion| {
            let token = signed
                .value
                .to_str()
                .expect("an assertion is visible ASCII")
                .to_owned();
            let key = jsonwebtoken::DecodingKey::from_jwk(
                set.find("gw-test-1").expect("the signing key is published"),
            )
            .expect("the published key loads");
            let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
            validation.set_issuer(&["https://gateway.example.test"]);
            validation.set_audience(&["https://billing.example.test"]);
            (
                signed.issued().clone(),
                jsonwebtoken::decode::<serde_json::Value>(&token, &key, &validation)
                    .expect("each assertion verifies against the published set")
                    .claims,
            )
        };
        let initialize = br#"{"jsonrpc":"2.0","id":0,"method":"initialize"}"#;
        let call = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#;
        let (first, first_claims) = verify(
            session
                .sign_next(&Method::POST, initialize)
                .expect("the first request signs"),
        );
        // A clone signs into the same sequence, as the transport's do.
        let (second, second_claims) = verify(
            session
                .clone()
                .sign_next(&Method::POST, call)
                .expect("the second request signs"),
        );
        let (third, third_claims) = verify(
            session
                .sign_next(&Method::DELETE, b"")
                .expect("the closing request signs"),
        );
        // Each request has its own `jti`, so a replay cache keyed on `sub`
        // and `jti` accepts all of them, and each binds its own request.
        assert_eq!(first.jti, "request-7.1");
        assert_eq!(second.jti, "request-7.2");
        assert_eq!(third.jti, "request-7.3");
        for (claims, issued) in [
            (&first_claims, &first),
            (&second_claims, &second),
            (&third_claims, &third),
        ] {
            assert_eq!(claims["jti"], json!(issued.jti));
            assert_eq!(claims["sub"], json!("https://idp.example.test#alice"));
            assert_eq!(claims["path"], json!("/mcp"));
        }
        assert_eq!(first_claims["method"], json!("POST"));
        assert_eq!(third_claims["method"], json!("DELETE"));
        assert_eq!(
            first_claims["request_sha256"],
            json!(crate::connections::caller_assertion::body_digest(
                initialize
            ))
        );
        assert_eq!(
            second_claims["request_sha256"],
            json!(crate::connections::caller_assertion::body_digest(call))
        );
        assert_eq!(
            third_claims["request_sha256"],
            json!(crate::connections::caller_assertion::body_digest(b""))
        );

        // Sealing says what was sent, and nothing signs after it.
        assert_eq!(
            session.seal(),
            Some(IssuedSessionCallerAssertions {
                kid: "gw-test-1".to_owned(),
                jti_base: "request-7".to_owned(),
                count: 3,
            })
        );
        assert_eq!(
            session.sign_next(&Method::DELETE, b"").err(),
            Some(CallerAssertionError::SignatureFailed)
        );
        assert_eq!(
            session.seal().map(|issued| issued.count),
            Some(3),
            "a refused request is not counted"
        );

        // A session that sent nothing has nothing to record.
        let idle = temporary
            .runtime
            .caller_assertion_signer(&target)
            .await
            .expect("the key loads")
            .expect("an attested target signs")
            .into_session(&alice, "request-8");
        assert_eq!(idle.seal(), None);

        // A request that fails to sign is not counted: with its sequence
        // suffix this request ID is longer than a `jti` may be.
        let overlong = temporary
            .runtime
            .caller_assertion_signer(&target)
            .await
            .expect("the key loads")
            .expect("an attested target signs")
            .into_session(&alice, &"r".repeat(127));
        assert_eq!(
            overlong.sign_next(&Method::POST, initialize).err(),
            Some(CallerAssertionError::InvalidClaim("jti"))
        );
        assert_eq!(overlong.seal(), None);
    }

    #[test]
    fn the_bound_request_target_is_the_origin_form_sent_on_the_wire() {
        assert_eq!(
            origin_form_request_target("https://billing.example.test/v1/charges?limit=2&q=a+b")
                .as_deref(),
            Ok("/v1/charges?limit=2&q=a+b")
        );
        assert_eq!(
            origin_form_request_target("https://billing.example.test:8443/v1/charges").as_deref(),
            Ok("/v1/charges")
        );
        assert_eq!(
            origin_form_request_target("https://billing.example.test").as_deref(),
            Ok("/")
        );
        assert_eq!(
            origin_form_request_target("not a url"),
            Err(CallerAssertionError::InvalidClaim("path"))
        );
    }

    #[test]
    fn the_caller_assertion_refusal_has_a_distinct_safe_reason() {
        let error = ConnectionHttpError::CallerAssertionNotEnforced;
        assert_eq!(error.safe_reason(), "caller_assertion_not_enforced");
        // It is a configuration refusal, not a secret-provider failure, so it
        // must not raise a secret-resolution alarm for a key nobody read.
        assert!(!error.is_secret_resolution_failure());
    }

    #[tokio::test]
    async fn stale_http_test_etag_stops_before_client_tls_or_secret_preparation() {
        let temporary =
            TemporaryManagedRuntime::tls_identity_with_oauth("stale-http-test-etag", true).await;
        let original = temporary.stored_connection();
        let stale_etag = original.etag();
        let mut replacement = original.write.clone();
        replacement.test_profile = Some(ConnectionTestProfile {
            method: "GET".to_owned(),
            path: "/".to_owned(),
            expected_statuses: vec![200],
        });
        let record = temporary
            .runtime
            .control_plane
            .replace_managed(
                &original.id,
                &stale_etag,
                replacement,
                &crate::auth::change_actor::ChangeActor::for_test("test-admin"),
            )
            .await
            .expect("current connection should gain a valid persisted test profile");
        assert_ne!(record.etag(), stale_etag);
        for secret in [
            "ca.pem",
            "client-certificate.pem",
            "client-private-key.pem",
            "oauth-secret",
        ] {
            fs::remove_file(temporary.root.join(secret))
                .expect("test secret should be removed before the stale probe");
        }
        assert_eq!(temporary.cached_client_count(), 0);

        let execution = ConnectionTestService::new(temporary.runtime.clone())
            .execute(&record, stale_etag.as_str())
            .await;

        assert!(!execution.result.ok);
        assert_eq!(
            execution.result.stages,
            vec![ConnectionTestStage::failure(
                ConnectionTestStageName::ProtocolValid,
                ConnectionTestReason::ConnectionChanged,
            )]
        );
        assert_eq!(
            execution.status_reason,
            ConnectionStatusReason::RequestFailed
        );
        assert_eq!(
            temporary.cached_client_count(),
            0,
            "stale tests must not prepare upstream or OAuth clients"
        );
    }

    #[tokio::test]
    async fn stale_mcp_test_etag_stops_before_client_selection() {
        let mut write = record("/mcp").write;
        write.kind = ConnectionKind::McpStreamableHttp;
        write.discovery = Some(DiscoveryConfig::ManagedMcp {
            use_connection_authentication: false,
        });
        let temporary = TemporaryManagedRuntime::from_write("stale-mcp-test-etag", write).await;
        assert_eq!(temporary.cached_client_count(), 0);

        let target = temporary
            .runtime
            .mcp_test_target(
                temporary.connection_id.as_str(),
                "\"stale-connection-etag\"",
            )
            .expect("stale revision lookup should be safe");

        assert!(target.is_none());
        assert_eq!(temporary.cached_client_count(), 0);
    }

    #[tokio::test]
    async fn persisted_http_test_enforces_response_body_idle_timeout() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("test listener should bind");
        let addr = listener.local_addr().expect("test listener address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("test server should accept one connection");
            let _ = read_http_request(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nhi\r\n",
                )
                .await
                .expect("test response headers and first chunk should write");
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let mut write = record("/").write;
        write.endpoint.base_url = format!("http://127.0.0.1:{}", addr.port());
        write.timeouts = Some(ConnectionTimeouts {
            connect_timeout_ms: 500,
            request_timeout_ms: 2_000,
            response_idle_timeout_ms: 50,
        });
        write.test_profile = Some(ConnectionTestProfile {
            method: "GET".to_owned(),
            path: "/".to_owned(),
            expected_statuses: vec![200],
        });
        let temporary = TemporaryManagedRuntime::from_write("http-test-response-idle", write).await;
        let record = temporary.stored_connection();
        let expected_etag = record.etag().to_string();

        let execution = tokio::time::timeout(
            Duration::from_secs(1),
            ConnectionTestService::new(temporary.runtime.clone()).execute(&record, &expected_etag),
        )
        .await
        .expect("saved response idle timeout should end the probe promptly");
        server.abort();
        let server_error = server
            .await
            .expect_err("aborted stalled server should stop promptly");
        assert!(server_error.is_cancelled());

        assert!(!execution.result.ok);
        assert_eq!(
            execution.result.state,
            ConnectionOperationalState::Unavailable
        );
        assert_eq!(
            execution.result.stages,
            vec![
                ConnectionTestStage::success(ConnectionTestStageName::EgressPolicy),
                ConnectionTestStage::not_applicable(ConnectionTestStageName::SecretAvailable),
                ConnectionTestStage::failure(
                    ConnectionTestStageName::Connected,
                    ConnectionTestReason::ResponseIdleTimeout,
                ),
            ]
        );
        assert_eq!(
            execution.status_reason,
            ConnectionStatusReason::RequestFailed
        );
    }

    #[tokio::test]
    async fn timed_out_connection_test_drops_owned_oauth_mint_before_return() {
        let token_response = serde_json::to_vec(&json!({
            "access_token": OAUTH_ACCESS_TOKEN_CANARY,
            "token_type": "Bearer",
            "expires_in": 3600
        }))
        .expect("token response should serialize");
        let (addr, ca_pem, token_server, request_received) = one_request_delayed_tls_token_server(
            StatusCode::OK,
            "application/json",
            token_response,
            Duration::from_secs(30),
        )
        .await;
        let temporary = TemporaryOAuthRuntime::new(
            "probe-owned-timeout",
            format!("https://127.0.0.1:{}", addr.port()),
            format!("https://127.0.0.1:{}/oauth/token", addr.port()),
            HashSet::from(["127.0.0.1".to_owned()]),
            Some(&ca_pem),
        )
        .await;
        let original = temporary.stored_connection();
        let mut replacement = original.write.clone();
        replacement.test_profile = Some(ConnectionTestProfile {
            method: "GET".to_owned(),
            path: "/".to_owned(),
            expected_statuses: vec![200],
        });
        let record = temporary
            .runtime
            .control_plane
            .replace_managed(
                &original.id,
                &original.etag(),
                replacement,
                &crate::auth::change_actor::ChangeActor::for_test("test-admin"),
            )
            .await
            .expect("OAuth test profile should replace");
        let expected_etag = record.etag().to_string();

        let execution = tokio::time::timeout(
            Duration::from_secs(3),
            ConnectionTestService::new(temporary.runtime.clone()).execute_before(
                &record,
                &expected_etag,
                None,
                tokio::time::Instant::now() + Duration::from_secs(1),
            ),
        )
        .await
        .expect("the hard probe deadline should return promptly");
        tokio::time::timeout(Duration::from_secs(1), request_received)
            .await
            .expect("the token request should start before the probe deadline")
            .expect("the token endpoint should observe the owned mint");
        let request = tokio::time::timeout(Duration::from_secs(1), token_server)
            .await
            .expect("no token-server I/O may survive the completed probe")
            .expect("the token server should observe a cleanly dropped request");

        assert!(
            !request.response_sent,
            "the cancelled mint must not complete"
        );
        assert_eq!(
            execution.result.stages,
            vec![ConnectionTestStage::failure(
                ConnectionTestStageName::Connected,
                ConnectionTestReason::DeadlineExceeded,
            )]
        );
        let events = captured_audit_events(&temporary.capture, 1).await;
        let refreshes = events
            .iter()
            .filter(|event| event.event_type == audit::event::CONNECTION_OAUTH_TOKEN_REFRESH)
            .collect::<Vec<_>>();
        assert_eq!(refreshes.len(), 1);
        assert_eq!(refreshes[0].payload["outcome"], json!("failure"));
        assert_eq!(
            refreshes[0].payload["reason"],
            json!("oauth_token_cancelled")
        );
    }

    #[tokio::test]
    async fn stalled_oauth_denial_is_classified_and_invalidates_the_cached_token() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let mut upstream_ca_params = CertificateParams::default();
        upstream_ca_params.distinguished_name = DistinguishedName::new();
        upstream_ca_params
            .distinguished_name
            .push(DnType::CommonName, "GreenGateway Upstream Test CA");
        upstream_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let upstream_ca_key =
            rcgen::KeyPair::generate().expect("upstream test CA key should generate");
        let upstream_ca = upstream_ca_params
            .self_signed(&upstream_ca_key)
            .expect("upstream test CA certificate should build");
        let mut upstream_server_params = CertificateParams::default();
        upstream_server_params.distinguished_name = DistinguishedName::new();
        upstream_server_params
            .distinguished_name
            .push(DnType::CommonName, "127.0.0.1");
        upstream_server_params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let upstream_server_key =
            rcgen::KeyPair::generate().expect("upstream server key should generate");
        let upstream_server_certificate = upstream_server_params
            .signed_by(
                &upstream_server_key,
                &Issuer::from_params(&upstream_ca_params, &upstream_ca_key),
            )
            .expect("upstream server certificate should build");
        let upstream_server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(
                    upstream_server_certificate.der().as_ref().to_vec(),
                )],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    upstream_server_key.serialize_der(),
                )),
            )
            .expect("upstream TLS server config should build");
        let upstream_acceptor = TlsAcceptor::from(Arc::new(upstream_server_config));
        let upstream_listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("upstream listener should bind");
        let upstream_addr = upstream_listener
            .local_addr()
            .expect("upstream listener address");
        let upstream = tokio::spawn(async move {
            let (stream, _) = upstream_listener
                .accept()
                .await
                .expect("upstream should accept one connection");
            let mut stream = upstream_acceptor
                .accept(stream)
                .await
                .expect("upstream TLS should succeed");
            let _ = read_http_request(&mut stream).await;
            stream
                .write_all(
                    b"HTTP/1.1 401 Unauthorized\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nno\r\n",
                )
                .await
                .expect("denial headers and first chunk should write");
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let token_response = serde_json::to_vec(&json!({
            "access_token": OAUTH_ACCESS_TOKEN_CANARY,
            "token_type": "Bearer",
            "expires_in": 3600
        }))
        .expect("token response should serialize");
        let (token_addr, ca_pem, token_request) =
            one_request_tls_token_server(StatusCode::OK, "application/json", token_response).await;
        let trusted_ca_pem = format!("{ca_pem}\n{}", upstream_ca.pem());
        let temporary = TemporaryOAuthRuntime::new(
            "stalled-denial",
            format!("https://127.0.0.1:{}", upstream_addr.port()),
            format!("https://127.0.0.1:{}/oauth/token", token_addr.port()),
            HashSet::from(["127.0.0.1".to_owned()]),
            Some(&trusted_ca_pem),
        )
        .await;
        let original = temporary.stored_connection();
        let mut replacement = original.write.clone();
        replacement.timeouts = Some(ConnectionTimeouts {
            connect_timeout_ms: 500,
            request_timeout_ms: 2_000,
            response_idle_timeout_ms: 50,
        });
        replacement.test_profile = Some(ConnectionTestProfile {
            method: "GET".to_owned(),
            path: "/".to_owned(),
            expected_statuses: vec![200],
        });
        let record = temporary
            .runtime
            .control_plane
            .replace_managed(
                &original.id,
                &original.etag(),
                replacement,
                &crate::auth::change_actor::ChangeActor::for_test("test-admin"),
            )
            .await
            .expect("OAuth test profile should replace");
        let expected_etag = record.etag().to_string();

        let execution = tokio::time::timeout(
            Duration::from_secs(1),
            ConnectionTestService::new(temporary.runtime.clone()).execute(&record, &expected_etag),
        )
        .await
        .expect("authenticated denial must not wait for its stalled body");
        upstream.abort();
        let upstream_error = upstream
            .await
            .expect_err("aborted stalled upstream should stop promptly");
        assert!(upstream_error.is_cancelled());
        token_request
            .await
            .expect("initial OAuth token request should complete");

        assert!(!execution.result.ok);
        assert_eq!(execution.result.state, ConnectionOperationalState::Degraded);
        assert_eq!(
            execution.result.stages,
            vec![
                ConnectionTestStage::success(ConnectionTestStageName::EgressPolicy),
                ConnectionTestStage::success(ConnectionTestStageName::SecretAvailable),
                ConnectionTestStage::success(ConnectionTestStageName::Connected),
                ConnectionTestStage::not_applicable(ConnectionTestStageName::TlsValid),
                ConnectionTestStage::failure(
                    ConnectionTestStageName::Authenticated,
                    ConnectionTestReason::AuthenticationFailed,
                ),
            ]
        );
        assert_eq!(
            execution.status_reason,
            ConnectionStatusReason::InvalidResponse
        );

        let target = temporary
            .runtime
            .test_target(temporary.connection_id.as_str(), &expected_etag)
            .expect("current OAuth test target should build")
            .expect("current OAuth test target should remain unchanged");
        let remint_error = match tokio::time::timeout(
            Duration::from_secs(1),
            temporary.runtime.resolve_credential(target.target(), None),
        )
        .await
        .expect("invalidated token should trigger a prompt replacement attempt")
        {
            Ok(_) => panic!("the rejected OAuth token must not remain cached"),
            Err(error) => error,
        };
        assert_eq!(
            remint_error,
            ConnectionHttpError::OAuthTokenUnavailable,
            "a second mint attempt proves the rejected cached token was invalidated"
        );
    }

    #[test]
    fn transport_partition_covers_identity_revisions_profile_and_local_tls_versions() {
        let base = record("/");
        let expected = connection_transport_partition(
            &base.id,
            &base.revisions,
            ConnectionClientProfile::Upstream,
            [None, None, None],
        );

        let mut other_id = base.clone();
        other_id.id = ConnectionId::parse("another").expect("test connection ID");
        assert_ne!(
            expected,
            connection_transport_partition(
                &other_id.id,
                &other_id.revisions,
                ConnectionClientProfile::Upstream,
                [None, None, None],
            )
        );
        for field in 0..5 {
            let mut revisions = base.revisions.clone();
            match field {
                0 => revisions.connection += 1,
                1 => revisions.credential += 1,
                2 => revisions.tls += 1,
                3 => revisions.discovery += 1,
                4 => revisions.status += 1,
                _ => unreachable!(),
            }
            assert_ne!(
                expected,
                connection_transport_partition(
                    &base.id,
                    &revisions,
                    ConnectionClientProfile::Upstream,
                    [None, None, None],
                ),
                "stored revision field {field} must partition transport identity"
            );
        }
        assert_ne!(
            expected,
            connection_transport_partition(
                &base.id,
                &base.revisions,
                ConnectionClientProfile::OAuthToken,
                [None, None, None],
            )
        );
        assert_ne!(
            expected,
            connection_transport_partition(
                &base.id,
                &base.revisions,
                ConnectionClientProfile::Upstream,
                [Some(1), Some(2), Some(3)],
            )
        );
    }

    #[test]
    fn static_credentials_are_sensitive_and_replace_existing_values() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("attacker"));
        let credential = ResolvedConnectionCredential {
            material: Some(ResolvedCredentialMaterial::HeaderApiKey {
                header_name: HeaderName::from_static("x-api-key"),
                secret: ResolvedSecret::new(SecretPurpose::HeaderApiKey, b"real-key".to_vec())
                    .expect("test secret"),
            }),
            additional_headers: Vec::new(),
        };
        credential
            .inject(&mut headers)
            .expect("credential injection");

        let value = headers.get("x-api-key").expect("injected API key");
        assert_eq!(value, "real-key");
        assert!(value.is_sensitive());
    }

    #[test]
    fn static_bearer_replaces_authorization_and_marks_it_sensitive() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer caller-value"),
        );
        let credential = ResolvedConnectionCredential {
            material: Some(ResolvedCredentialMaterial::StaticBearer {
                secret: ResolvedSecret::new(
                    SecretPurpose::StaticBearer,
                    b"operator-token".to_vec(),
                )
                .expect("test secret"),
            }),
            additional_headers: Vec::new(),
        };
        credential.inject(&mut headers).expect("bearer injection");

        let value = headers
            .get(header::AUTHORIZATION)
            .expect("injected bearer should exist");
        assert_eq!(value, "Bearer operator-token");
        assert!(value.is_sensitive());
    }

    #[tokio::test]
    async fn runtime_binds_url_and_secret_resolution_to_the_stored_connection() {
        let temporary =
            TemporaryRuntime::header_api_key("bound-runtime", "x-api-key", b"operator-key").await;
        let target = temporary
            .runtime
            .target(
                temporary.connection_id.as_str(),
                "/charges/123?expand=customer",
            )
            .expect("stored connection target should resolve");
        assert_eq!(
            target.url(),
            "https://billing.example.test/v1/charges/123?expand=customer"
        );
        assert_eq!(target.authentication_kind(), "header_api_key");
        assert_eq!(
            target.credential_header_names(),
            &[HeaderName::from_static("x-api-key")]
        );

        let credential = temporary
            .runtime
            .resolve_credential(&target, None)
            .await
            .expect("operator-owned credential should resolve")
            .expect("API-key connection should have a credential");
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("caller-value"));
        credential
            .inject(&mut headers)
            .expect("credential should inject");
        let value = headers
            .get("x-api-key")
            .expect("configured credential header should exist");
        assert_eq!(value, "operator-key");
        assert!(value.is_sensitive());
    }

    #[tokio::test]
    async fn primary_and_additional_headers_resolve_and_inject_all_or_nothing() {
        let temporary = TemporaryRuntime::header_api_key_with_additional(
            "additional-headers",
            "x-api-key",
            b"operator-key",
            &[
                (
                    "cf-access-client-id",
                    "proxy-client-id",
                    b"operator-client-id",
                ),
                (
                    "cf-access-client-secret",
                    "proxy-client-secret",
                    b"operator-client-secret",
                ),
            ],
        )
        .await;
        let target = temporary
            .runtime
            .target(temporary.connection_id.as_str(), "/charges")
            .expect("stored connection target should resolve");
        assert_eq!(
            target.credential_header_names(),
            &[
                HeaderName::from_static("x-api-key"),
                HeaderName::from_static("cf-access-client-id"),
                HeaderName::from_static("cf-access-client-secret"),
            ]
        );

        let credential = temporary
            .runtime
            .resolve_credential(&target, None)
            .await
            .expect("all configured secrets should resolve")
            .expect("credentialed target should return material");
        let mut headers = HeaderMap::new();
        for name in target.credential_header_names() {
            headers.insert(name, HeaderValue::from_static("caller-controlled"));
        }
        credential
            .inject(&mut headers)
            .expect("every configured header should inject");
        for (name, expected) in [
            ("x-api-key", "operator-key"),
            ("cf-access-client-id", "operator-client-id"),
            ("cf-access-client-secret", "operator-client-secret"),
        ] {
            let value = headers.get(name).expect("configured header should exist");
            assert_eq!(value, expected);
            assert!(value.is_sensitive(), "{name} must be marked sensitive");
        }

        fs::remove_file(temporary.root.join("proxy-client-secret"))
            .expect("test should remove one additional secret");
        let error = match temporary.runtime.resolve_credential(&target, None).await {
            Ok(_) => panic!("one unavailable additional secret must fail the whole resolution"),
            Err(error) => error,
        };
        assert_eq!(error, ConnectionHttpError::CredentialUnavailable);
    }

    #[tokio::test]
    async fn secret_provider_failure_returns_only_a_safe_bounded_reason() {
        let temporary =
            TemporaryRuntime::header_api_key("provider-failure", "x-api-key", b"do-not-leak").await;
        let target = temporary
            .runtime
            .target(temporary.connection_id.as_str(), "/charges")
            .expect("stored connection target should resolve");
        fs::remove_file(temporary.root.join("api-key"))
            .expect("test should remove the provider file after activation");

        let error = match temporary.runtime.resolve_credential(&target, None).await {
            Ok(_) => panic!("missing provider file must fail closed"),
            Err(error) => error,
        };
        assert_eq!(error, ConnectionHttpError::CredentialUnavailable);
        let rendered = format!("{error:?}\n{error}");
        assert!(!rendered.contains("do-not-leak"));
        assert!(!rendered.contains("api-key"));
    }

    #[tokio::test]
    async fn oauth_runtime_uses_checked_basic_token_exchange_and_caches_bearer_safely() {
        let token_response = serde_json::to_vec(&json!({
            "access_token": OAUTH_ACCESS_TOKEN_CANARY,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": OAUTH_REFRESH_TOKEN_CANARY,
            "scope": "invoices.read payments.write"
        }))
        .expect("token response should serialize");
        let (addr, ca_pem, request_handle) =
            one_request_tls_token_server(StatusCode::OK, "application/json", token_response).await;
        let temporary = TemporaryOAuthRuntime::new(
            "success",
            format!("https://127.0.0.1:{}", addr.port()),
            format!("https://127.0.0.1:{}/oauth/token", addr.port()),
            HashSet::from(["127.0.0.1".to_owned()]),
            Some(&ca_pem),
        )
        .await;
        let target = temporary
            .runtime
            .target(temporary.connection_id.as_str(), "/charges")
            .expect("OAuth target should resolve");
        assert_eq!(target.authentication_kind(), "oauth2_client_credentials");
        assert_eq!(target.credential_header_names(), &[header::AUTHORIZATION]);
        target
            .client()
            .checked_destination(target.url())
            .await
            .expect("upstream destination should pass before token work");

        let first = temporary
            .runtime
            .resolve_credential(&target, None)
            .await
            .expect("OAuth token should mint")
            .expect("OAuth target should return a credential");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer caller-token"),
        );
        first
            .inject(&mut headers)
            .expect("OAuth bearer should inject");
        let authorization = headers
            .get(header::AUTHORIZATION)
            .expect("OAuth bearer should exist");
        assert_eq!(
            authorization,
            &HeaderValue::from_static("Bearer oauth-access-token-canary")
        );
        assert!(authorization.is_sensitive());

        let request = request_handle
            .await
            .expect("token request capture should complete");
        assert!(request.head.starts_with("POST /oauth/token HTTP/1.1\r\n"));
        let authorization = request
            .head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find_map(|(name, value)| {
                name.eq_ignore_ascii_case("authorization")
                    .then(|| value.trim().to_owned())
            })
            .expect("token request should contain client Basic authorization");
        let expected_basic = format!(
            "Basic {}",
            BASE64_STANDARD.encode("billing%3Aclient:oauth-client-secret-canary")
        );
        assert_eq!(authorization, expected_basic);
        let form = url::form_urlencoded::parse(request.body.as_bytes())
            .into_owned()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            form.get("grant_type").map(String::as_str),
            Some("client_credentials")
        );
        assert_eq!(
            form.get("scope").map(String::as_str),
            Some("invoices.read payments.write")
        );
        assert_eq!(
            form.get("audience").map(String::as_str),
            Some("billing-api")
        );
        assert_eq!(
            form.get("resource").map(String::as_str),
            Some("urn:billing")
        );

        let cached = temporary
            .runtime
            .resolve_credential(&target, None)
            .await
            .expect("cached OAuth token should resolve")
            .expect("cached OAuth credential should exist");
        let mut cached_headers = HeaderMap::new();
        cached
            .inject(&mut cached_headers)
            .expect("cached OAuth bearer should inject");
        assert_eq!(
            cached_headers.get(header::AUTHORIZATION),
            Some(&HeaderValue::from_static(
                "Bearer oauth-access-token-canary"
            ))
        );

        let events = captured_audit_events(&temporary.capture, 1).await;
        let refreshes = events
            .iter()
            .filter(|event| event.event_type == audit::event::CONNECTION_OAUTH_TOKEN_REFRESH)
            .collect::<Vec<_>>();
        assert_eq!(refreshes.len(), 1, "cache hit must not emit another mint");
        assert_eq!(refreshes[0].payload["outcome"], json!("success"));
        assert_eq!(refreshes[0].payload["reason"], json!("refreshed"));
        let audit_json = serde_json::to_string(&events).expect("audit should serialize");
        for canary in [
            std::str::from_utf8(OAUTH_CLIENT_SECRET_CANARY).expect("ASCII canary"),
            OAUTH_ACCESS_TOKEN_CANARY,
            OAUTH_REFRESH_TOKEN_CANARY,
            "/oauth/token",
        ] {
            assert!(!audit_json.contains(canary), "audit leaked {canary}");
        }
    }

    #[tokio::test]
    async fn credential_deadline_preserves_oauth_and_additional_header_timeout_phases() {
        let token_response = serde_json::to_vec(&json!({
            "access_token": OAUTH_ACCESS_TOKEN_CANARY,
            "token_type": "Bearer",
            "expires_in": 3600
        }))
        .expect("token response should serialize");
        let (slow_addr, slow_ca_pem, slow_request, _) = one_request_delayed_tls_token_server(
            StatusCode::OK,
            "application/json",
            token_response.clone(),
            Duration::from_millis(250),
        )
        .await;
        let slow = TemporaryOAuthRuntime::new(
            "deadline-primary-oauth",
            format!("https://127.0.0.1:{}", slow_addr.port()),
            format!("https://127.0.0.1:{}/oauth/token", slow_addr.port()),
            HashSet::from(["127.0.0.1".to_owned()]),
            Some(&slow_ca_pem),
        )
        .await;
        let slow_target = slow
            .runtime
            .target(slow.connection_id.as_str(), "/charges")
            .expect("slow OAuth target should build");
        let error = match slow
            .runtime
            .resolve_credential_before(
                &slow_target,
                None,
                tokio::time::Instant::now() + Duration::from_millis(20),
            )
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("an OAuth mint exceeding the deadline must fail"),
        };
        assert_eq!(error, ConnectionHttpError::OAuthTokenUnavailable);
        tokio::time::timeout(Duration::from_secs(1), slow_request)
            .await
            .expect("the detached slow mint should finish")
            .expect("the slow token server should finish");

        let (fast_addr, fast_ca_pem, fast_request) =
            one_request_tls_token_server(StatusCode::OK, "application/json", token_response).await;
        let mut mixed = TemporaryOAuthRuntime::new(
            "deadline-additional-header",
            format!("https://127.0.0.1:{}", fast_addr.port()),
            format!("https://127.0.0.1:{}/oauth/token", fast_addr.port()),
            HashSet::from(["127.0.0.1".to_owned()]),
            Some(&fast_ca_pem),
        )
        .await;
        let current = mixed.stored_connection();
        let mut replacement = current.write.clone();
        replacement.additional_headers.push(AdditionalHeader {
            header_name: "x-proxy-token".to_owned(),
            // Reusing the client-secret alias is safe for this phase test: the
            // material is header-safe and the binding purpose is validated
            // independently for each use.
            secret_id: Some("billing-oauth-secret".to_owned()),
        });
        let replaced = mixed
            .runtime
            .control_plane
            .replace_managed(
                &current.id,
                &current.etag(),
                replacement,
                &crate::auth::change_actor::ChangeActor::for_test("test-admin"),
            )
            .await
            .expect("mixed OAuth Connection should replace");
        let target = mixed
            .runtime
            .target(replaced.id.as_str(), "/charges")
            .expect("mixed OAuth target should build");
        mixed
            .runtime
            .resolve_credential(&target, None)
            .await
            .expect("OAuth and the additional header should resolve before the timeout test")
            .expect("the mixed target should be credentialed");
        fast_request
            .await
            .expect("the successful OAuth mint should be observed");

        mixed.runtime = mixed
            .runtime
            .clone()
            .with_additional_resolution_delay_for_test(Duration::from_millis(250));
        let target = mixed
            .runtime
            .target(replaced.id.as_str(), "/charges")
            .expect("delayed mixed OAuth target should build");
        let error = match mixed
            .runtime
            .resolve_credential_before(
                &target,
                None,
                tokio::time::Instant::now() + Duration::from_millis(20),
            )
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("an additional-header read exceeding the deadline must fail"),
        };
        assert_eq!(
            error,
            ConnectionHttpError::CredentialUnavailable,
            "a completed OAuth phase must not relabel an additional-header timeout"
        );
    }

    #[tokio::test]
    async fn cancelled_oauth_waiter_does_not_cancel_token_attempt_or_its_audit() {
        let token_response = serde_json::to_vec(&json!({
            "access_token": OAUTH_ACCESS_TOKEN_CANARY,
            "token_type": "Bearer",
            "expires_in": 3600
        }))
        .expect("token response should serialize");
        let (addr, ca_pem, request_handle, request_received) =
            one_request_delayed_tls_token_server(
                StatusCode::OK,
                "application/json",
                token_response,
                Duration::from_millis(50),
            )
            .await;
        let temporary = TemporaryOAuthRuntime::new(
            "cancelled-waiter",
            format!("https://127.0.0.1:{}", addr.port()),
            format!("https://127.0.0.1:{}/oauth/token", addr.port()),
            HashSet::from(["127.0.0.1".to_owned()]),
            Some(&ca_pem),
        )
        .await;
        let target = temporary
            .runtime
            .target(temporary.connection_id.as_str(), "/charges")
            .expect("OAuth target should resolve");
        let runtime = temporary.runtime.clone();
        let waiter = tokio::spawn(async move { runtime.resolve_credential(&target, None).await });

        request_received
            .await
            .expect("token endpoint should observe the detached mint");
        waiter.abort();
        assert!(
            matches!(waiter.await, Err(error) if error.is_cancelled()),
            "caller waiter should be cancelled"
        );
        request_handle
            .await
            .expect("detached token request should complete");

        let events = captured_audit_events(&temporary.capture, 1).await;
        let refreshes = events
            .iter()
            .filter(|event| event.event_type == audit::event::CONNECTION_OAUTH_TOKEN_REFRESH)
            .collect::<Vec<_>>();
        assert_eq!(refreshes.len(), 1);
        assert_eq!(refreshes[0].payload["outcome"], json!("success"));
        let rendered = serde_json::to_string(&events).expect("audit should serialize");
        assert!(!rendered.contains(OAUTH_ACCESS_TOKEN_CANARY));
        assert!(!rendered.contains("/oauth/token"));
    }

    #[tokio::test]
    async fn oauth_token_egress_is_checked_before_client_secret_resolution() {
        let temporary = TemporaryOAuthRuntime::new(
            "egress-before-secret",
            "https://allowed.example.test".to_owned(),
            "https://blocked.example.test/oauth/token".to_owned(),
            HashSet::from(["allowed.example.test".to_owned()]),
            None,
        )
        .await;
        let target = temporary
            .runtime
            .target(temporary.connection_id.as_str(), "/charges")
            .expect("OAuth target should resolve");
        fs::remove_file(&temporary.secret_path)
            .expect("secret should be removed after activation for ordering proof");

        let error = match temporary.runtime.resolve_credential(&target, None).await {
            Ok(_) => panic!("blocked token endpoint must fail closed"),
            Err(error) => error,
        };
        assert_eq!(error, ConnectionHttpError::OAuthTokenEgressDenied);
        let events = captured_audit_events(&temporary.capture, 1).await;
        let refresh = events
            .iter()
            .find(|event| event.event_type == audit::event::CONNECTION_OAUTH_TOKEN_REFRESH)
            .expect("failed mint should be audited");
        assert_eq!(refresh.payload["outcome"], json!("failure"));
        assert_eq!(
            refresh.payload["reason"],
            json!("oauth_token_egress_denied")
        );
        let rendered = format!("{error:?}\n{error}\n{}", refresh.payload);
        assert!(!rendered.contains("blocked.example.test"));
        assert!(!rendered.contains("billing-oauth-secret"));
        assert!(!rendered.contains("client-secret"));
    }

    #[tokio::test]
    async fn oauth_rejection_discards_and_redacts_response_secrets() {
        let rejected_body = format!(
            r#"{{"error":"invalid_client","access_token":"{OAUTH_ACCESS_TOKEN_CANARY}","refresh_token":"{OAUTH_REFRESH_TOKEN_CANARY}"}}"#
        )
        .into_bytes();
        let (addr, ca_pem, request_handle) = one_request_tls_token_server(
            StatusCode::BAD_REQUEST,
            "application/json",
            rejected_body,
        )
        .await;
        let temporary = TemporaryOAuthRuntime::new(
            "rejected",
            format!("https://127.0.0.1:{}", addr.port()),
            format!("https://127.0.0.1:{}/oauth/token", addr.port()),
            HashSet::from(["127.0.0.1".to_owned()]),
            Some(&ca_pem),
        )
        .await;
        let target = temporary
            .runtime
            .target(temporary.connection_id.as_str(), "/charges")
            .expect("OAuth target should resolve");

        let error = match temporary.runtime.resolve_credential(&target, None).await {
            Ok(_) => panic!("rejected token response must fail closed"),
            Err(error) => error,
        };
        assert_eq!(error, ConnectionHttpError::OAuthTokenRejected);
        request_handle
            .await
            .expect("rejected token request should complete");
        let events = captured_audit_events(&temporary.capture, 1).await;
        let rendered = format!(
            "{error:?}\n{error}\n{}",
            serde_json::to_string(&events).expect("audit should serialize")
        );
        for canary in [
            std::str::from_utf8(OAUTH_CLIENT_SECRET_CANARY).expect("ASCII canary"),
            OAUTH_ACCESS_TOKEN_CANARY,
            OAUTH_REFRESH_TOKEN_CANARY,
            "invalid_client",
        ] {
            assert!(!rendered.contains(canary), "failure leaked {canary}");
        }
        assert!(rendered.contains("oauth_token_rejected"));
    }

    #[tokio::test]
    async fn oauth_invalid_token_responses_fail_closed_with_safe_audits() {
        let valid_shape = serde_json::to_vec(&json!({
            "access_token": OAUTH_ACCESS_TOKEN_CANARY,
            "token_type": "Bearer",
            "expires_in": 3600
        }))
        .expect("token response should serialize");
        let wrong_token_type = serde_json::to_vec(&json!({
            "access_token": OAUTH_ACCESS_TOKEN_CANARY,
            "token_type": "DPoP",
            "expires_in": 3600
        }))
        .expect("token response should serialize");
        let oversized = OAUTH_ACCESS_TOKEN_CANARY
            .as_bytes()
            .iter()
            .copied()
            .cycle()
            .take(super::OAUTH_MAX_RESPONSE_BYTES + 1)
            .collect::<Vec<_>>();
        let cases = [
            (
                "malformed-response",
                "application/json",
                format!("{{{OAUTH_ACCESS_TOKEN_CANARY}").into_bytes(),
            ),
            ("wrong-token-type", "application/json", wrong_token_type),
            ("wrong-content-type", "text/plain", valid_shape),
            ("oversized-response", "application/json", oversized),
        ];

        for (name, content_type, body) in cases {
            let (addr, ca_pem, request_handle) =
                one_request_tls_token_server(StatusCode::OK, content_type, body).await;
            let temporary = TemporaryOAuthRuntime::new(
                name,
                format!("https://127.0.0.1:{}", addr.port()),
                format!("https://127.0.0.1:{}/oauth/token", addr.port()),
                HashSet::from(["127.0.0.1".to_owned()]),
                Some(&ca_pem),
            )
            .await;
            let target = temporary
                .runtime
                .target(temporary.connection_id.as_str(), "/charges")
                .expect("OAuth target should resolve");

            let error = match temporary.runtime.resolve_credential(&target, None).await {
                Ok(_) => panic!("{name} must fail closed"),
                Err(error) => error,
            };
            assert_eq!(
                error,
                ConnectionHttpError::OAuthTokenInvalidResponse,
                "{name}"
            );
            request_handle
                .await
                .expect("invalid token request should complete");
            let events = captured_audit_events(&temporary.capture, 1).await;
            let rendered = format!(
                "{error:?}\n{error}\n{}",
                serde_json::to_string(&events).expect("audit should serialize")
            );
            for canary in [
                std::str::from_utf8(OAUTH_CLIENT_SECRET_CANARY).expect("ASCII canary"),
                OAUTH_ACCESS_TOKEN_CANARY,
                "/oauth/token",
            ] {
                assert!(!rendered.contains(canary), "{name} leaked {canary}");
            }
            assert!(rendered.contains("oauth_token_invalid_response"), "{name}");
        }
    }
}

tokio::task_local! {
    /// The Connection snapshot pinned for the request being served, set by
    /// the security gate when it admits the request. Everything that
    /// resolves a Connection target inside the request -- the proxy, the
    /// tool executor -- reads it through `ConnectionHttpRuntime`, so one
    /// admitted request sees one Connection state.
    static PINNED_CONNECTIONS: Arc<super::control_plane::ConnectionRuntimeSnapshot>;
}

/// Run `future` with `snapshot` pinned as the request's Connection state.
pub async fn with_pinned_connections<F: std::future::Future>(
    snapshot: Arc<super::control_plane::ConnectionRuntimeSnapshot>,
    future: F,
) -> F::Output {
    PINNED_CONNECTIONS.scope(snapshot, future).await
}
