//! Signed caller assertions: telling an upstream who is calling, in a form it can verify.
//!
//! A Connection presents one credential for every caller, so an upstream holding per-user data
//! cannot tell two principals apart and can only ever act as one identity. This mints a short-lived
//! JWT naming the validated calling principal and sends it alongside that credential: the credential
//! says which system is calling, the assertion says on whose behalf.
//!
//! The upstream verifies it against this gateway's published JWKS, so the trust is a signature
//! rather than a header anyone on the path could set -- the reason ADR 0006 rejected forwarding
//! identity as a plain header. Google IAP (`X-Goog-IAP-JWT-Assertion`) and Cloudflare Access
//! (`Cf-Access-Jwt-Assertion`) are the same shape, and an upstream that already verifies either of
//! those needs no new machinery to verify this.
//!
//! This is not a replacement for the delegated-credential types. Those obtain the caller's *own*
//! token for a third-party SaaS upstream that will never trust an operator's keys. This serves
//! upstreams the operator controls, and needs no wallet, no IdP integration and no storage of
//! anybody's access token -- only a signing key.
//!
//! ## The asserted subject is scoped to the provider that issued it
//!
//! `iss` on these tokens is this gateway, not the caller's identity provider, and RFC 7519 requires
//! `sub` to be unique within the issuer's own namespace. A gateway can have several providers
//! configured, and nothing stops two of them issuing the same `sub` for two different people, so the
//! asserted `sub` is `<provider issuer>#<provider subject>`. Without that, an upstream applying
//! per-user ownership checks would treat a caller from one provider as the identically named caller
//! from another -- the precise confusion this module exists to prevent. `Principal` keeps the issuer
//! for the same reason, and audit actors record it.
//!
//! The unscoped halves ride along as `caller_iss` and `caller_sub`, so an upstream matching its own
//! user records reads those and never parses the composite. This is the same rule OpenID Connect
//! states as `(iss, sub)` being the only stable identifier for an end user, and the same shape Istio
//! uses when it attests a caller across issuers.
//!
//! ## Request binding hashes the bytes on the wire
//!
//! `bind_request` covers the exact body sent upstream, not a canonical rewriting of it. That is a
//! deliberate rejection of the obvious alternative: a canonical-JSON digest forces every upstream to
//! reimplement the same canonicalization, and the failure mode when it differs by one character is a
//! rejected request that looks exactly like tampering. It is also harder than it looks --
//! JavaScript's default key sort orders by UTF-16 code unit, so `U+10000` sorts below `U+FFFF`,
//! while comparing Rust `str`s sorts by UTF-8 byte and reverses them; an implementation that sorts
//! natively agrees on every ASCII payload and diverges the first time a value contains an emoji.
//! Hashing what was transmitted has none of that. Both sides see the same bytes, verification is a
//! few lines in any language, and it is what AWS SigV4, Stripe and GitHub webhook signatures do.
//!
//! This module signs and refuses. It does not decide who may call an operation or whether a mutation
//! was approved; policy and the approval store run before anything here is asked for a token.

use std::fmt;

use base64::Engine as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Longest assertion this will emit. Beyond this a header is likely to be refused by an upstream or
/// an intermediary before anyone reads it, so it is a failure to sign rather than a surprise later.
const MAX_TOKEN_BYTES: usize = 8192;

/// Longest lifetime an operator may configure. An assertion is a bearer credential for the moment it
/// exists; minutes of replay window is a different risk from seconds of one.
pub const MAX_LIFETIME_SECONDS: u64 = 300;

/// Signature algorithms an upstream may ask for.
///
/// Both are offered because verifier libraries and platform documentation differ on which is
/// convenient -- Google IAP publishes ES256, Cloudflare Access publishes RS256 -- and supporting the
/// pair costs nothing here while removing a reason an operator could not adopt this at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertionAlgorithm {
    Es256,
    Rs256,
}

impl AssertionAlgorithm {
    fn jsonwebtoken(self) -> Algorithm {
        match self {
            Self::Es256 => Algorithm::ES256,
            Self::Rs256 => Algorithm::RS256,
        }
    }

    /// JWK `alg`, and the value published in the JWKS.
    pub fn name(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Rs256 => "RS256",
        }
    }
}

/// A principal field an operator may include in the assertion.
///
/// A fixed vocabulary rather than free-form templating: every value here comes from the validated
/// principal, so an operator cannot accidentally attest something a caller supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalClaim {
    /// The caller's stable identifier. Always present as `sub`; listing it is a no-op.
    Subject,
    Email,
    Roles,
}

impl PrincipalClaim {
    fn claim_name(self) -> &'static str {
        match self {
            Self::Subject => "sub",
            Self::Email => "email",
            Self::Roles => "roles",
        }
    }
}

/// Anything that stops this gateway producing an assertion.
///
/// Every variant is a refusal to sign, and each is deliberate. An assertion the upstream will reject
/// is worse than no request at all: it consumes an identifier, and it appears in the upstream's audit
/// as a failed verification, which is indistinguishable from an attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerAssertionError {
    /// The call arrived without a validated principal, so there is nobody to attest.
    NoPrincipal,
    /// A configured or derived claim value fails its shape rule.
    InvalidClaim(&'static str),
    /// The configured lifetime is zero or longer than this gateway will issue.
    InvalidLifetime,
    /// The configured signing key is not usable for the chosen algorithm.
    KeyUnusable,
    /// A mutation required an approval binding and none was supplied.
    ApprovalRequired,
    /// Signing itself failed.
    SignatureFailed,
    /// The finished assertion is too long to send.
    TokenTooLong,
}

impl CallerAssertionError {
    /// A stable, non-revealing reason for audit and metrics.
    pub fn safe_reason(self) -> &'static str {
        match self {
            Self::NoPrincipal => "caller_assertion_no_principal",
            Self::InvalidClaim(_) => "caller_assertion_claim_invalid",
            Self::InvalidLifetime => "caller_assertion_lifetime_invalid",
            Self::KeyUnusable => "caller_assertion_key_unusable",
            Self::ApprovalRequired => "caller_assertion_approval_required",
            Self::SignatureFailed => "caller_assertion_signature_failed",
            Self::TokenTooLong => "caller_assertion_token_too_long",
        }
    }
}

impl fmt::Display for CallerAssertionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_reason())
    }
}

impl std::error::Error for CallerAssertionError {}

/// A claim value must survive a JWT round trip and mean the same thing on the other side, so control
/// characters and unbounded strings are refused rather than truncated.
fn is_printable_claim(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.chars().any(|character| character.is_control())
}

/// The signing key, and the key id identifying its public half in the published JWKS.
pub struct AssertionSigningKey {
    key_id: String,
    algorithm: AssertionAlgorithm,
    encoding: EncodingKey,
}

impl fmt::Debug for AssertionSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key never reaches a log line, an error, or a panic message.
        formatter
            .debug_struct("AssertionSigningKey")
            .field("key_id", &self.key_id)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl AssertionSigningKey {
    /// Loads a PKCS#8 PEM private key for the given algorithm.
    ///
    /// The key id is validated here rather than per request: it has to match a `kid` in the JWKS the
    /// upstream holds, and a mismatch fails every call, so it is worth catching at configuration
    /// time.
    pub fn from_pkcs8_pem(
        key_id: &str,
        algorithm: AssertionAlgorithm,
        pem: &[u8],
    ) -> Result<Self, CallerAssertionError> {
        if !is_printable_claim(key_id, 128) {
            return Err(CallerAssertionError::InvalidClaim("key_id"));
        }
        let encoding = match algorithm {
            AssertionAlgorithm::Es256 => EncodingKey::from_ec_pem(pem),
            AssertionAlgorithm::Rs256 => EncodingKey::from_rsa_pem(pem),
        }
        .map_err(|_| CallerAssertionError::KeyUnusable)?;
        Ok(Self {
            key_id: key_id.to_owned(),
            algorithm,
            encoding,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn algorithm(&self) -> AssertionAlgorithm {
        self.algorithm
    }
}

/// What an operator configured for one Connection.
pub struct CallerAssertionConfig<'a> {
    pub issuer: &'a str,
    pub audience: &'a str,
    /// JOSE `typ`. Naming the intended use stops a token minted for one upstream being replayed at
    /// another that trusts the same keys.
    pub token_type: &'a str,
    pub lifetime_seconds: u64,
    /// Principal fields to include beyond the always-present `sub`.
    pub claims: &'a [PrincipalClaim],
    /// Include the method, path and a digest of the body actually sent.
    pub bind_request: bool,
    /// Require, and include, the approval that authorised a mutation.
    pub bind_approval: bool,
}

/// The validated caller. Every field comes from the authenticated principal, never from arguments.
pub struct CallerIdentity<'a> {
    /// The identity provider that authenticated this caller, in canonical form.
    ///
    /// Required, and deliberately not an `Option`: a subject on its own does not identify anybody,
    /// because two configured providers can issue the same `sub` for two different people.
    /// [`Principal`](crate::auth::principal::Principal) keeps the issuer for exactly this reason and
    /// every audit actor carries it. A provider configured without an issuer URL still has a label
    /// here -- `auth::principal::provider_issuer` produces one.
    pub issuer: &'a str,
    pub subject: &'a str,
    pub email: Option<&'a str>,
    pub roles: &'a [String],
}

/// The `sub` this gateway asserts for a caller: the provider issuer, `#`, then the provider subject.
///
/// RFC 7519 requires `sub` to be locally unique within the issuer's namespace, and the `iss` of
/// these tokens is *this gateway*, not the caller's provider. A raw provider subject therefore does
/// not satisfy it once a second provider is configured: two providers issuing `alice` would produce
/// one asserted identity, and an upstream doing per-user ownership checks would treat them as the
/// same person. Scoping the subject is what makes the guarantee in this module's name true.
///
/// `#` is a safe separator in one direction, which is the direction that matters: OpenID Connect
/// forbids a fragment in an issuer identifier, and [`caller_issuer_is_scopeable`] enforces that, so
/// the first `#` always ends the issuer. Nothing needs to parse this anyway -- the parts travel
/// alongside it as `caller_iss` and `caller_sub`.
fn scoped_subject(issuer: &str, subject: &str) -> String {
    format!("{issuer}#{subject}")
}

/// Whether an issuer label can scope a subject unambiguously.
fn caller_issuer_is_scopeable(issuer: &str) -> bool {
    is_printable_claim(issuer, 512) && !issuer.contains('#')
}

/// The request being attested, when `bind_request` is on.
pub struct RequestBinding<'a> {
    pub method: &'a str,
    pub path: &'a str,
    /// The exact bytes being sent upstream.
    pub body: &'a [u8],
}

/// Lowercase hexadecimal SHA-256 of the bytes sent upstream.
///
/// Deliberately over the transmitted bytes rather than a canonical form; see the module comment.
pub fn body_digest(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest.iter() {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

#[derive(Serialize)]
struct AssertionClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    sub: &'a str,
    iat: u64,
    exp: u64,
    jti: &'a str,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// Signs one caller assertion, or refuses.
///
/// `request_id` becomes `jti`, so it must be the identifier this call is already known by elsewhere:
/// that is what lets an upstream deduplicate a retry and lets an operator join the two audit trails.
#[allow(clippy::too_many_arguments)]
pub fn sign_caller_assertion(
    key: &AssertionSigningKey,
    config: &CallerAssertionConfig<'_>,
    caller: Option<&CallerIdentity<'_>>,
    request_id: &str,
    issued_at: u64,
    binding: Option<&RequestBinding<'_>>,
    approval_id: Option<&str>,
) -> Result<String, CallerAssertionError> {
    // A Connection configured to attest its caller must never fall back to acting anonymously: that
    // would silently hand the upstream a request it cannot attribute, which is the failure this
    // whole mechanism exists to prevent.
    let caller = caller.ok_or(CallerAssertionError::NoPrincipal)?;

    if !is_printable_claim(caller.subject, 256) {
        return Err(CallerAssertionError::InvalidClaim("sub"));
    }
    if !caller_issuer_is_scopeable(caller.issuer) {
        return Err(CallerAssertionError::InvalidClaim("caller_iss"));
    }
    if !is_printable_claim(config.issuer, 512) {
        return Err(CallerAssertionError::InvalidClaim("iss"));
    }
    if !is_printable_claim(config.audience, 512) {
        return Err(CallerAssertionError::InvalidClaim("aud"));
    }
    if !is_printable_claim(config.token_type, 128) {
        return Err(CallerAssertionError::InvalidClaim("typ"));
    }
    if !is_printable_claim(request_id, 128) {
        return Err(CallerAssertionError::InvalidClaim("jti"));
    }
    if config.lifetime_seconds == 0 || config.lifetime_seconds > MAX_LIFETIME_SECONDS {
        return Err(CallerAssertionError::InvalidLifetime);
    }
    let expires_at = issued_at
        .checked_add(config.lifetime_seconds)
        .ok_or(CallerAssertionError::InvalidLifetime)?;

    let mut extra = Map::new();

    // The two halves of the identity, unscoped, so an upstream matching its own records never has to
    // take the composite `sub` apart. Always present: an upstream that reads these instead of `sub`
    // must not have to care which Connection or which provider the call arrived through.
    extra.insert(
        "caller_iss".to_owned(),
        Value::String(caller.issuer.to_owned()),
    );
    extra.insert(
        "caller_sub".to_owned(),
        Value::String(caller.subject.to_owned()),
    );

    for claim in config.claims {
        match claim {
            // Always emitted, scoped as `sub` and raw as `caller_sub`; listing it changes nothing.
            PrincipalClaim::Subject => {}
            PrincipalClaim::Email => {
                if let Some(email) = caller.email {
                    if !is_printable_claim(email, 320) {
                        return Err(CallerAssertionError::InvalidClaim("email"));
                    }
                    extra.insert(
                        claim.claim_name().to_owned(),
                        Value::String(email.to_owned()),
                    );
                }
            }
            PrincipalClaim::Roles => {
                let mut roles = Vec::with_capacity(caller.roles.len());
                for role in caller.roles {
                    if !is_printable_claim(role, 128) {
                        return Err(CallerAssertionError::InvalidClaim("roles"));
                    }
                    roles.push(Value::String(role.clone()));
                }
                extra.insert(claim.claim_name().to_owned(), Value::Array(roles));
            }
        }
    }

    if config.bind_request {
        let binding = binding.ok_or(CallerAssertionError::InvalidClaim("request_binding"))?;
        if !is_printable_claim(binding.method, 16) {
            return Err(CallerAssertionError::InvalidClaim("method"));
        }
        if !is_printable_claim(binding.path, 2048) {
            return Err(CallerAssertionError::InvalidClaim("path"));
        }
        extra.insert(
            "method".to_owned(),
            Value::String(binding.method.to_ascii_uppercase()),
        );
        extra.insert("path".to_owned(), Value::String(binding.path.to_owned()));
        extra.insert(
            "request_sha256".to_owned(),
            Value::String(body_digest(binding.body)),
        );
    }

    if config.bind_approval {
        let approval_id = approval_id.ok_or(CallerAssertionError::ApprovalRequired)?;
        if !is_printable_claim(approval_id, 128) {
            return Err(CallerAssertionError::InvalidClaim("approval_id"));
        }
        extra.insert(
            "approval_id".to_owned(),
            Value::String(approval_id.to_owned()),
        );
    }

    let scoped = scoped_subject(caller.issuer, caller.subject);
    let claims = AssertionClaims {
        iss: config.issuer,
        aud: config.audience,
        sub: &scoped,
        iat: issued_at,
        exp: expires_at,
        jti: request_id,
        extra,
    };

    let mut header = Header::new(key.algorithm.jsonwebtoken());
    header.typ = Some(config.token_type.to_owned());
    header.kid = Some(key.key_id.clone());

    let token = jsonwebtoken::encode(&header, &claims, &key.encoding)
        .map_err(|_| CallerAssertionError::SignatureFailed)?;
    if token.len() > MAX_TOKEN_BYTES {
        return Err(CallerAssertionError::TokenTooLong);
    }
    Ok(token)
}

/// Whether `(x, y)` satisfies the P-256 curve equation `y^2 = x^3 - 3x + b (mod p)`.
///
/// A point that is merely 65 bytes starting with `0x04` can still be off the curve -- a truncated
/// read, a coordinate pair taken from the wrong key, or a transcription slip all produce one. The
/// resulting JWK is syntactically perfect and cryptographically useless: this gateway keeps signing
/// while every upstream rejects the key, and the operator sees an authentication failure rather than
/// a configuration error. Refusing at load turns that into the second thing.
///
/// Public data only, so this is deliberately plain arithmetic with no constant-time requirement.
fn is_on_p256(x: &[u8], y: &[u8]) -> bool {
    use num_bigint::BigUint;

    // FIPS 186-4 P-256: p = 2^256 - 2^224 + 2^192 + 2^96 - 1, and the curve's b coefficient.
    let Some(prime) = BigUint::parse_bytes(
        b"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        16,
    ) else {
        return false;
    };
    let Some(coefficient_b) = BigUint::parse_bytes(
        b"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        16,
    ) else {
        return false;
    };

    let x = BigUint::from_bytes_be(x);
    let y = BigUint::from_bytes_be(y);
    // A coordinate at or above the field prime is not a field element, whatever it satisfies.
    if x >= prime || y >= prime {
        return false;
    }

    // -3 as a field element, so the whole comparison stays in the non-negative naturals.
    let a = &prime - BigUint::from(3u32);
    let left = (&y * &y) % &prime;
    let right = (&x * &x % &prime * &x + a * &x + coefficient_b) % &prime;
    left == right
}

/// The public JWK for an ES256 signing key, from its uncompressed SEC1 point.
pub fn es256_public_jwk(
    key_id: &str,
    uncompressed_point: &[u8],
) -> Result<Value, CallerAssertionError> {
    if !is_printable_claim(key_id, 128) {
        return Err(CallerAssertionError::InvalidClaim("key_id"));
    }
    // 0x04, then the two 32-byte coordinates.
    if uncompressed_point.len() != 65 || uncompressed_point[0] != 0x04 {
        return Err(CallerAssertionError::KeyUnusable);
    }
    if !is_on_p256(&uncompressed_point[1..33], &uncompressed_point[33..65]) {
        return Err(CallerAssertionError::KeyUnusable);
    }
    let encoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    Ok(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "use": "sig",
        "kid": key_id,
        "x": encoder.encode(&uncompressed_point[1..33]),
        "y": encoder.encode(&uncompressed_point[33..65]),
    }))
}

/// The public JWK for an RS256 signing key, from its modulus and exponent.
pub fn rs256_public_jwk(
    key_id: &str,
    modulus: &[u8],
    exponent: &[u8],
) -> Result<Value, CallerAssertionError> {
    if !is_printable_claim(key_id, 128) {
        return Err(CallerAssertionError::InvalidClaim("key_id"));
    }
    if modulus.is_empty() || exponent.is_empty() {
        return Err(CallerAssertionError::KeyUnusable);
    }
    let encoder = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    Ok(serde_json::json!({
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": key_id,
        "n": encoder.encode(modulus),
        "e": encoder.encode(exponent),
    }))
}

#[cfg(test)]
#[path = "caller_assertion_tests.rs"]
mod caller_assertion_tests;
