//! Client-certificate authentication: what a verified certificate is allowed
//! to mean.
//!
//! Everything here runs *after* rustls has already verified the peer's chain
//! against the operator's configured client CA bundle. That ordering is the
//! whole security model: a certificate that failed verification never reaches
//! this module, because the handshake it was presented in never completed.
//! Nothing below re-checks a signature, an expiry, or a revocation, and nothing
//! below can be reached without one.
//!
//! What is left is the question rustls does not answer: which *principal* a
//! verified certificate is. That answer has to be a single, bounded, canonical
//! string, because it becomes a `Principal::user_id`, an audit `actor.user_id`,
//! and an RBAC `principal_ids` match. Three rules make it one:
//!
//! 1. **One configured source.** The operator names the field that carries
//!    identity ([`ClientCertIdentitySource`]); the gateway never guesses, and
//!    never falls back from one field to another. A fallback chain is an
//!    escalation path: an attacker who can obtain a certificate with an empty
//!    preferred field chooses which field the gateway reads.
//! 2. **Exactly one value.** A certificate carrying no value of the configured
//!    kind has no identity, and one carrying two *different* values has no
//!    identity either. Taking the first of several would let whoever ordered
//!    the SAN sequence choose the principal.
//! 3. **Canonical and bounded.** The value must already be in canonical form --
//!    the gateway rejects rather than repairs -- and must fit
//!    [`MAX_IDENTITY_BYTES`] of printable ASCII. It is caller-influenced text
//!    on its way to a log line, an audit row, and a policy comparison.
//!
//! Subject DN is deliberately **not** an available source. See
//! [`ClientCertIdentitySource`] for why.

use std::{fmt, str::FromStr, sync::Arc};

use sha2::{Digest, Sha256};
use tokio_rustls::rustls::pki_types::CertificateDer;

use super::{
    principal::provider_issuer, AuthError, AuthMethod, Principal, SessionCredential,
    SessionValidator,
};

/// The provider label a certificate principal carries as its issuer.
///
/// A certificate has no issuer in the sense the rest of the auth chain means:
/// there is no token issuer URL to canonicalise. But the identity boundary
/// still has to be nameable, or an RBAC rule cannot distinguish the SPIFFE ID
/// `spiffe://prod/api` presented as a certificate from a JWT whose `sub` is the
/// same string. This is the same sentinel shape configured providers without an
/// issuer already use.
pub const CLIENT_CERTIFICATE_PROVIDER: &str = "client-certificate";

/// The longest identity a certificate may carry.
///
/// A certificate authority can put a kilobyte in a SAN. Whatever it puts there
/// becomes a principal id, an audit field, and a policy comparison, so the
/// length is bounded here rather than wherever it first hurts. 255 is generous
/// for every real workload identity and short enough to be a log line.
pub const MAX_IDENTITY_BYTES: usize = 255;

/// Which certificate field carries the caller's identity.
///
/// **Why not the subject DN.** A DN is not a string; it is a sequence of
/// relative distinguished names, each of which may hold several attributes, in
/// several string encodings. Turning one into text means picking an escaping
/// and an ordering, libraries disagree about both, and the escaping is where
/// the bugs live: a CA that lets a requester choose their own `CN` lets them
/// choose a `CN` containing `,OU=` and produce a rendered DN that collides with
/// somebody else's. Comparing identities as rendered DNs means comparing the
/// output of an encoder nobody agreed on. There is no canonical DN renderer in
/// this dependency graph, and writing one to decide who an authenticated caller
/// is would be exactly the wrong place to hand-roll ASN.1.
///
/// **Why not an email SAN.** `rfc822Name` identifies a mailbox, not a workload,
/// and mailboxes are reassigned. It is also the SAN type most often left
/// unconstrained by the name constraints in an internal PKI.
///
/// The three that remain are all names the certificate *asserts about itself*
/// in a single canonical text encoding, and all three are read out of the
/// already-verified certificate by `rustls-webpki` rather than by a parser
/// written here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientCertIdentitySource {
    /// A SPIFFE ID in a URI SAN: `spiffe://<trust-domain>/<path>`.
    ///
    /// The strongest of the three, and the recommended choice. SPIFFE requires
    /// exactly one URI SAN per SVID, the encoding is canonical by
    /// specification, and the ID is stable across the certificate rotation
    /// SPIFFE expects to happen hourly -- which is the property that matters
    /// most, because an identity that changes when a certificate is renewed
    /// silently breaks every policy that names it.
    Spiffe,
    /// Any URI SAN, taken verbatim.
    ///
    /// For a private PKI that encodes workload identity as a URI but not as a
    /// SPIFFE ID.
    Uri,
    /// A DNS SAN, lower-cased.
    ///
    /// The weakest of the three and the one to reach for last: DNS SANs were
    /// designed to name the *server* a client is connecting to, so certificates
    /// routinely carry several of them, and under the exactly-one rule such a
    /// certificate simply has no identity. Wildcard names are never an identity
    /// and are discarded before the count.
    Dns,
}

impl ClientCertIdentitySource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Spiffe => "spiffe",
            Self::Uri => "uri",
            Self::Dns => "dns",
        }
    }
}

impl FromStr for ClientCertIdentitySource {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "spiffe" => Ok(Self::Spiffe),
            "uri" => Ok(Self::Uri),
            "dns" => Ok(Self::Dns),
            _ => Err("expected `spiffe`, `uri`, or `dns`"),
        }
    }
}

impl fmt::Display for ClientCertIdentitySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Why a verified certificate produced no identity.
///
/// Every variant means the same thing to the caller -- no principal -- and they
/// are distinguished only so an operator can tell a misconfigured identity
/// source from a misissued certificate. [`Self::reason`] is a closed set of
/// static strings precisely because it is used as a metric label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientCertIdentityError {
    /// The leaf did not parse. rustls verified it, so this is close to
    /// impossible; it is still an error rather than an assumption.
    Unparsable,
    /// No value of the configured kind is present.
    Absent,
    /// Two or more different values of the configured kind are present.
    Ambiguous,
    /// A value is present but is not in canonical form.
    Malformed,
    /// A value is present and canonical but longer than [`MAX_IDENTITY_BYTES`].
    TooLong,
}

impl ClientCertIdentityError {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Unparsable => "identity_unparsable",
            Self::Absent => "identity_absent",
            Self::Ambiguous => "identity_ambiguous",
            Self::Malformed => "identity_malformed",
            Self::TooLong => "identity_too_long",
        }
    }
}

impl fmt::Display for ClientCertIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unparsable => "the client certificate could not be parsed",
            Self::Absent => "the client certificate carries no identity of the configured kind",
            Self::Ambiguous => {
                "the client certificate carries more than one identity of the configured kind"
            }
            Self::Malformed => "the client certificate's identity is not in canonical form",
            Self::TooLong => "the client certificate's identity is too long",
        })
    }
}

/// A bounded, canonical identity read out of a certificate rustls has already
/// verified.
///
/// Constructed only by [`identity_from_certificate`], and only from a leaf that
/// completed a handshake against the configured client CA bundle. There is no
/// other constructor and no public field, so an identity cannot be built from a
/// header, a query parameter, or anything else a caller can write.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedClientIdentity {
    identity: Arc<str>,
    fingerprint: Arc<str>,
    source: ClientCertIdentitySource,
}

impl VerifiedClientIdentity {
    /// The identity string, already bounded and canonical.
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// The SHA-256 of the leaf certificate's DER, lower-case hex.
    ///
    /// A hash of public material, not the material: it identifies *which*
    /// issued certificate authenticated a session without putting certificate
    /// bytes anywhere. Used as the principal's session id so an operator can
    /// tie an audit trail to one issued credential.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    #[allow(dead_code)] // Read by tests and by future scheme-dependent policy.
    pub fn source(&self) -> ClientCertIdentitySource {
        self.source
    }
}

/// Prints the identity and the fingerprint, both of which are public and
/// bounded. Neither is a secret, and neither can carry a control character or a
/// newline past [`is_bounded_identity`], so this cannot forge a log line.
impl fmt::Debug for VerifiedClientIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedClientIdentity")
            .field("identity", &self.identity)
            .field("fingerprint", &self.fingerprint)
            .field("source", &self.source)
            .finish()
    }
}

/// Reads the one identity a verified leaf certificate carries, or explains why
/// it carries none.
///
/// The certificate must already have been verified: this function makes no
/// trust decision, and calling it on an unverified certificate would produce a
/// principal from an unauthenticated assertion.
pub fn identity_from_certificate(
    leaf: &CertificateDer<'_>,
    source: ClientCertIdentitySource,
) -> Result<VerifiedClientIdentity, ClientCertIdentityError> {
    let parsed =
        webpki::EndEntityCert::try_from(leaf).map_err(|_| ClientCertIdentityError::Unparsable)?;

    // Collected, canonicalised, then de-duplicated -- rather than "find the
    // first" -- so that "which value did we pick" is never a question anyone
    // outside this function gets to influence. Two SANs spelling the *same*
    // canonical identity are one identity; two spelling different ones are no
    // identity at all.
    let mut candidates: Vec<String> = match source {
        ClientCertIdentitySource::Spiffe => parsed
            .valid_uri_names()
            .filter(|name| is_spiffe_scheme(name))
            .map(str::to_owned)
            .collect(),
        ClientCertIdentitySource::Uri => parsed.valid_uri_names().map(str::to_owned).collect(),
        ClientCertIdentitySource::Dns => parsed
            .valid_dns_names()
            // A wildcard names a set of hosts, not a caller. It is discarded
            // before the count rather than rejected, so a certificate carrying
            // one real name and one wildcard still authenticates as the real
            // name.
            .filter(|name| !name.contains('*'))
            .map(str::to_ascii_lowercase)
            .collect(),
    };
    candidates.sort_unstable();
    candidates.dedup();

    let identity = match candidates.len() {
        0 => return Err(ClientCertIdentityError::Absent),
        1 => candidates.remove(0),
        _ => return Err(ClientCertIdentityError::Ambiguous),
    };

    if identity.len() > MAX_IDENTITY_BYTES {
        return Err(ClientCertIdentityError::TooLong);
    }
    if !is_bounded_identity(&identity) {
        return Err(ClientCertIdentityError::Malformed);
    }
    match source {
        ClientCertIdentitySource::Spiffe => require_canonical_spiffe_id(&identity)?,
        ClientCertIdentitySource::Uri => require_canonical_uri(&identity)?,
        ClientCertIdentitySource::Dns => require_canonical_dns_name(&identity)?,
    }

    Ok(VerifiedClientIdentity {
        identity: Arc::from(identity),
        fingerprint: Arc::from(fingerprint(leaf)),
        source,
    })
}

const SPIFFE_SCHEME: &str = "spiffe://";

/// Whether a URI names the SPIFFE scheme, compared the way URI schemes compare:
/// case-insensitively.
///
/// Candidacy is case-insensitive and *acceptance* is not, deliberately. If
/// `SPIFFE://x` were merely skipped, a certificate carrying it plus a real
/// SPIFFE ID would authenticate as the real one and the odd spelling would go
/// unnoticed; making it a candidate means such a certificate is ambiguous, and
/// one carrying only the odd spelling is rejected as non-canonical. Two
/// spellings of one identity must never become two identity strings.
fn is_spiffe_scheme(name: &str) -> bool {
    name.get(..SPIFFE_SCHEME.len())
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case(SPIFFE_SCHEME))
}

/// Whether every byte is printable ASCII with no space.
///
/// This is the bound that makes an identity safe to put in a log line, an audit
/// row, and a metric-adjacent context: no control characters, no newlines, no
/// tabs, no DEL, no non-ASCII, and nothing that needs quoting. Every identity
/// kind this module accepts is ASCII by specification, so nothing legitimate is
/// lost.
fn is_bounded_identity(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| (0x21..=0x7E).contains(&byte))
}

/// Enforces the canonical SPIFFE ID form.
///
/// Rejects rather than repairs. A SPIFFE ID has one spelling: a lower-case
/// `spiffe` scheme, a lower-case trust domain, no userinfo, no port, no query,
/// no fragment, and path segments that are non-empty and not dot segments. A
/// gateway that normalised any of these would be deciding that two different
/// strings are the same principal, which is the decision this whole module
/// exists to make impossible.
fn require_canonical_spiffe_id(value: &str) -> Result<(), ClientCertIdentityError> {
    let Some(rest) = value.strip_prefix(SPIFFE_SCHEME) else {
        return Err(ClientCertIdentityError::Malformed);
    };
    if value.contains('?') || value.contains('#') {
        return Err(ClientCertIdentityError::Malformed);
    }

    let (trust_domain, path) = match rest.split_once('/') {
        Some((trust_domain, path)) => (trust_domain, Some(path)),
        None => (rest, None),
    };
    if trust_domain.is_empty()
        || trust_domain.contains('@')
        || trust_domain.contains(':')
        || trust_domain.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(ClientCertIdentityError::Malformed);
    }

    if let Some(path) = path {
        // A trailing slash, an empty segment, or a dot segment would each let
        // two spellings denote one workload.
        if path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        {
            return Err(ClientCertIdentityError::Malformed);
        }
    }

    Ok(())
}

/// Enforces a canonical absolute URI: a lower-case scheme, then something.
fn require_canonical_uri(value: &str) -> Result<(), ClientCertIdentityError> {
    let Some((scheme, rest)) = value.split_once(':') else {
        return Err(ClientCertIdentityError::Malformed);
    };
    if rest.is_empty() {
        return Err(ClientCertIdentityError::Malformed);
    }

    let mut scheme_bytes = scheme.bytes();
    let starts_valid = scheme_bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase());
    let continues_valid = scheme_bytes.all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'.')
    });
    if !starts_valid || !continues_valid {
        return Err(ClientCertIdentityError::Malformed);
    }

    Ok(())
}

/// Enforces a canonical DNS name.
///
/// `rustls-webpki` has already refused anything that is not a syntactically
/// valid DNS name, and the caller has already lower-cased it. What is left is
/// to refuse the shapes that are valid DNS but ambiguous as an identity: a
/// trailing root dot, which spells the same name twice.
fn require_canonical_dns_name(value: &str) -> Result<(), ClientCertIdentityError> {
    if value.ends_with('.') || value.contains("..") || value.len() > 253 {
        return Err(ClientCertIdentityError::Malformed);
    }

    Ok(())
}

fn fingerprint(leaf: &CertificateDer<'_>) -> String {
    hex::encode(Sha256::digest(leaf.as_ref()))
}

/// Maps a verified client certificate to a principal.
///
/// Deliberately trivial: every trust decision was made by rustls at the
/// handshake and by [`identity_from_certificate`] immediately after it, and
/// this validator's whole job is to put the result on the same footing as every
/// other authentication method -- same `Principal`, same RBAC evaluation, same
/// audit shape.
///
/// It never returns [`AuthError::Upstream`], and that is a requirement rather
/// than an accident. `ChainValidator` treats an upstream failure as "this
/// credential could not be judged" and reports it when nothing accepted the
/// credential, which turns a 401 into a 503. This validator has no upstream to
/// fail: no network call, no cache, no identity provider. Every rejection it
/// can produce is a judgement, so every rejection is
/// [`AuthError::InvalidSession`].
pub struct ClientCertificateValidator;

#[async_trait::async_trait]
impl SessionValidator for ClientCertificateValidator {
    async fn validate_session(
        &self,
        credential: &SessionCredential,
    ) -> Result<Principal, AuthError> {
        let SessionCredential::ClientCertificate(identity) = credential else {
            return Err(AuthError::InvalidSession(
                "client-certificate validator only accepts client-certificate credentials"
                    .to_owned(),
            ));
        };

        Ok(Principal {
            user_id: identity.identity().to_owned(),
            issuer: Some(provider_issuer(CLIENT_CERTIFICATE_PROVIDER)),
            email: None,
            org_id: None,
            // A certificate asserts who the caller is, not what they may do. A
            // role granted to every holder of any certificate the CA ever
            // issued would be a role granted to the CA. Authorize these
            // principals with RBAC `principal_ids` and `auth_methods` instead.
            roles: Vec::new(),
            session_id: identity.fingerprint().to_owned(),
            auth_method: AuthMethod::ClientCertificate,
        })
    }

    // `validate_session_for_resource` is deliberately not overridden. The
    // default refuses resource-bound sessions, and a certificate cannot satisfy
    // one: MCP resource binding exists so a token issued for one resource
    // cannot be replayed at another, and it is enforced by comparing the
    // token's audience. A certificate has no audience, so accepting one for a
    // resource-bound route would be asserting a property nothing checked.

    fn supports_cookie(&self) -> bool {
        false
    }

    fn supports_bearer(&self) -> bool {
        false
    }

    fn supports_client_certificate(&self) -> bool {
        true
    }
}

#[cfg(test)]
#[path = "client_certificate_tests.rs"]
mod tests;
