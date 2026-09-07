//! GreenCal scoped-gateway actor assertions.
//!
//! GreenCal's `/api/gateway/v2` API refuses any caller-supplied owner or organizer ID. The calling
//! user is instead carried in `X-GreenGateway-Actor`: a short-lived ES256 JWT this gateway signs,
//! bound to the exact operation and request body, which GreenCal verifies against a pinned public
//! JWKS before resolving the actor against its own directory. Without it a shared service bearer
//! would let whatever chose the arguments also choose whose calendar it acted on.
//!
//! The wire contract is GreenCal's `docs/scoped-gateway-v2.md`, and its verifier
//! (`src/gateway/scopedGatewayActor.ts`) is the authority on every rule below. That verifier hashes
//! a canonical form of the request rather than the bytes on the wire, so both sides must agree on
//! canonicalization exactly; its documentation asks for cross-language fixtures rather than a
//! second guess at how JavaScript serializes JSON. Those fixtures are in `greencal_actor_tests.rs`
//! and are generated from the TypeScript implementation.
//!
//! This module signs and validates. It does not decide who may call an operation, whether a
//! mutation was approved, or which operations exist; those are the connection allowlist, the policy
//! engine and the approval store, and they run before anything here is asked for a token.

use std::fmt;

use base64::Engine as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Issuer GreenCal pins. Not configurable: it identifies this gateway to that service, and a
/// mismatch is a misconfiguration to fail on rather than a value to accept from an operator.
pub const ACTOR_ISSUER: &str = "https://gateway.greenhatsec.com";

/// Audience GreenCal pins, as a single string rather than an array.
pub const ACTOR_AUDIENCE: &str = "https://cal.greenhatsec.com/api/gateway/v2";

/// JOSE `typ`. GreenCal requires this exact value, so a token minted for anything else cannot be
/// replayed at its API.
pub const ACTOR_TYP: &str = "greencal-actor+jwt";

/// Path prefix the request digest covers.
const OPERATION_PATH_PREFIX: &str = "/api/gateway/v2/";

/// Longest assertion GreenCal will read before rejecting it unexamined.
const MAX_TOKEN_BYTES: usize = 8192;

/// Maximum assertion lifetime GreenCal accepts, in seconds.
pub const MAX_LIFETIME_SECONDS: u64 = 60;

/// Nesting cap shared with the verifier's `canonicalJson`.
const MAX_CANONICAL_DEPTH: usize = 32;

/// Largest integer both sides can represent exactly (`Number.MAX_SAFE_INTEGER`).
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// Anything that stops this gateway producing an assertion.
///
/// Every variant is a refusal to sign. There is no lenient path: an assertion that GreenCal would
/// reject is worse than no request at all, because it spends a request key and reads as a
/// tampering attempt in its audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorSigningError {
    /// A subject, request key, approval ID or operation failed its shape rule.
    InvalidClaim(&'static str),
    /// The request body is not something the shared canonical form can represent.
    UncanonicalizableBody(&'static str),
    /// A mutation was asked for without an approval, or a read was given one.
    ApprovalMismatch,
    /// The requested lifetime is zero or longer than GreenCal accepts.
    InvalidLifetime,
    /// The configured signing key is not a usable ES256 key.
    KeyUnusable,
    /// Signing itself failed.
    SignatureFailed,
    /// The finished assertion is longer than GreenCal will read.
    TokenTooLong,
}

impl ActorSigningError {
    /// A stable, non-revealing reason for audit and metrics.
    pub fn safe_reason(self) -> &'static str {
        match self {
            Self::InvalidClaim(_) => "actor_claim_invalid",
            Self::UncanonicalizableBody(_) => "actor_body_uncanonicalizable",
            Self::ApprovalMismatch => "actor_approval_mismatch",
            Self::InvalidLifetime => "actor_lifetime_invalid",
            Self::KeyUnusable => "actor_key_unusable",
            Self::SignatureFailed => "actor_signature_failed",
            Self::TokenTooLong => "actor_token_too_long",
        }
    }
}

impl fmt::Display for ActorSigningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_reason())
    }
}

impl std::error::Error for ActorSigningError {}

/// `^[A-Za-z0-9_-]{1,128}$`: GreenCal's `ID`, used for `sub` and for key IDs.
fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// `^[A-Za-z0-9._:-]{32,128}$`: GreenCal's `KEY`, used for `jti` and `approval_id`.
///
/// The 32-character floor is a security property rather than a formatting one: the request key is
/// what makes a retry idempotent and a replay detectable, so it has to carry real entropy.
fn is_request_key(value: &str) -> bool {
    (32..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// Operation IDs are the reviewed identifiers from the tool contract, and they land in a URL path,
/// so they are deliberately narrower than a general identifier: no dots, colons or slashes.
fn is_operation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Compares two object keys the way `Array.prototype.sort()` does.
///
/// The verifier sorts with JavaScript's default comparator, which orders strings by UTF-16 code
/// unit. Rust's own `str` ordering is by UTF-8 byte, and the two disagree: a supplementary
/// character encodes in UTF-16 as a surrogate pair starting at 0xD800, which sorts *below* every
/// character in U+E000..U+FFFF, while by code point it sorts above them. Getting this wrong would
/// produce a digest mismatch only for keys nobody tests with, so it is done properly here rather
/// than left to the common case.
fn compare_utf16(left: &str, right: &str) -> std::cmp::Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

/// The canonical text `JSON.stringify` would produce for a string.
///
/// `serde_json` escapes the same set JavaScript does -- quote, backslash, and the C0 controls, with
/// `\b \t \n \f \r` spelled short and the rest as lowercase `\u00xx` -- and leaves everything else,
/// including non-ASCII, literal. Lone surrogates are the one case JavaScript escapes that cannot
/// occur here: a Rust `str` is well-formed UTF-8, and `serde_json` refuses such input at the parse
/// step, so this gateway never holds one to serialize.
fn write_canonical_string(out: &mut String, value: &str) -> Result<(), ActorSigningError> {
    let encoded = serde_json::to_string(value)
        .map_err(|_| ActorSigningError::UncanonicalizableBody("string"))?;
    out.push_str(&encoded);
    Ok(())
}

/// Appends the canonical form of one value.
fn write_canonical(out: &mut String, value: &Value, depth: usize) -> Result<(), ActorSigningError> {
    if depth > MAX_CANONICAL_DEPTH {
        return Err(ActorSigningError::UncanonicalizableBody("depth"));
    }
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::String(text) => write_canonical_string(out, text)?,
        Value::Number(number) => {
            // Only safe integers. The v2 body schemas allow nothing else, and matching
            // JavaScript's shortest-round-trip formatting for arbitrary doubles is a large amount
            // of subtle code to support values the API would reject anyway. `-0` is normalized the
            // way `JSON.stringify` normalizes it.
            let integer = number
                .as_i64()
                .ok_or(ActorSigningError::UncanonicalizableBody("number"))?;
            if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&integer) {
                return Err(ActorSigningError::UncanonicalizableBody("number"));
            }
            out.push_str(itoa_i64(integer).as_str());
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(out, item, depth + 1)?;
            }
            out.push(']');
        }
        Value::Object(entries) => {
            let mut keys: Vec<&String> = entries.keys().collect();
            keys.sort_by(|left, right| compare_utf16(left, right));
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical_string(out, key)?;
                out.push(':');
                let entry = entries
                    .get(key)
                    .ok_or(ActorSigningError::UncanonicalizableBody("object"))?;
                write_canonical(out, entry, depth + 1)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Decimal form of an integer, without pulling in a formatting dependency.
fn itoa_i64(value: i64) -> String {
    value.to_string()
}

/// The canonical JSON text both sides hash.
///
/// Object keys are sorted by UTF-16 code unit, array order and string contents are preserved, no
/// whitespace is added, and no Unicode normalization is applied.
pub fn canonical_json(value: &Value) -> Result<String, ActorSigningError> {
    let mut out = String::new();
    write_canonical(&mut out, value, 0)?;
    Ok(out)
}

/// Lowercase hexadecimal SHA-256 of `POST\n/api/gateway/v2/{operation}\n{canonical body}`.
///
/// The body is the canonical form rather than the bytes sent, so the digest survives any
/// re-serialization between here and GreenCal.
pub fn request_digest(operation: &str, body: &Value) -> Result<String, ActorSigningError> {
    if !is_operation_id(operation) {
        return Err(ActorSigningError::InvalidClaim("operation"));
    }
    let canonical = canonical_json(body)?;
    let mut hasher = Sha256::new();
    hasher.update(b"POST\n");
    hasher.update(OPERATION_PATH_PREFIX.as_bytes());
    hasher.update(operation.as_bytes());
    hasher.update(b"\n");
    hasher.update(canonical.as_bytes());
    Ok(hex_lower(&hasher.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// What the caller is asking to be attested, before it becomes claims.
///
/// Every field comes from a source this gateway has already authenticated or decided: the subject
/// and organization from the verified inbound principal, the service client ID from the Cloudflare
/// Access assertion this connection presents, the approval from the approval store. None of it is
/// model-supplied, which is the point of the whole mechanism.
pub struct ActorAssertionRequest<'a> {
    /// Immutable Green Hat user ID of the signed-in caller. Never an email, never an argument.
    pub subject: &'a str,
    /// Organization of the authenticated service principal.
    pub org_id: &'a str,
    /// `common_name` of the validated Cloudflare Access service token.
    pub service_client_id: &'a str,
    /// Reviewed operation ID being invoked.
    pub operation: &'a str,
    /// Request body as it will be sent, including `requestKey` for mutations.
    pub body: &'a Value,
    /// Stable per-request key. Also the idempotency key GreenCal records, so a retry of the same
    /// logical write must reuse it rather than mint a new one.
    pub request_key: &'a str,
    /// Approval covering these exact arguments. Required for mutations, refused for reads.
    pub approval_id: Option<&'a str>,
    /// Whether this operation mutates. Decided by the allowlist, not by a tool annotation.
    pub mutation: bool,
    /// Issue time, Unix seconds.
    pub issued_at: u64,
    /// Lifetime in seconds. GreenCal caps this at 60 and allows 5 seconds of clock skew.
    pub lifetime_seconds: u64,
}

#[derive(Serialize)]
struct ActorClaims<'a> {
    iss: &'static str,
    aud: &'static str,
    sub: &'a str,
    org_id: &'a str,
    service_client_id: &'a str,
    iat: u64,
    exp: u64,
    jti: &'a str,
    operation: &'a str,
    request_sha256: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    approved: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_id: Option<&'a str>,
}

/// An ES256 signing key and the key ID that identifies its public half in the published JWKS.
pub struct ActorSigningKey {
    key_id: String,
    encoding: EncodingKey,
}

impl fmt::Debug for ActorSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key itself never reaches a log line.
        formatter
            .debug_struct("ActorSigningKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl ActorSigningKey {
    /// Builds a signing key from a PKCS#8 PEM private key.
    ///
    /// The key ID has to match a `kid` in the JWKS GreenCal is configured with, or every assertion
    /// is rejected; it is validated here so that fails at startup rather than per request.
    pub fn from_pkcs8_pem(key_id: &str, pem: &[u8]) -> Result<Self, ActorSigningError> {
        if !is_identifier(key_id) {
            return Err(ActorSigningError::InvalidClaim("kid"));
        }
        let encoding = EncodingKey::from_ec_pem(pem).map_err(|_| ActorSigningError::KeyUnusable)?;
        Ok(Self {
            key_id: key_id.to_owned(),
            encoding,
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// Signs one actor assertion, or refuses.
///
/// The checks here mirror the verifier's, deliberately: a token this gateway would not accept back
/// is a token that spends a request key and shows up in GreenCal's audit as a rejected assertion,
/// which is indistinguishable from an attack. Failing before the network call keeps that signal
/// meaningful.
pub fn sign_actor_assertion(
    key: &ActorSigningKey,
    request: &ActorAssertionRequest<'_>,
) -> Result<String, ActorSigningError> {
    if !is_identifier(request.subject) {
        return Err(ActorSigningError::InvalidClaim("sub"));
    }
    if request.org_id.is_empty() || request.org_id.len() > 128 {
        return Err(ActorSigningError::InvalidClaim("org_id"));
    }
    if request.service_client_id.is_empty() || request.service_client_id.len() > 256 {
        return Err(ActorSigningError::InvalidClaim("service_client_id"));
    }
    if !is_operation_id(request.operation) {
        return Err(ActorSigningError::InvalidClaim("operation"));
    }
    if !is_request_key(request.request_key) {
        return Err(ActorSigningError::InvalidClaim("jti"));
    }
    if request.lifetime_seconds == 0 || request.lifetime_seconds > MAX_LIFETIME_SECONDS {
        return Err(ActorSigningError::InvalidLifetime);
    }
    let expires_at = request
        .issued_at
        .checked_add(request.lifetime_seconds)
        .ok_or(ActorSigningError::InvalidLifetime)?;
    if expires_at > i64::MAX as u64 {
        return Err(ActorSigningError::InvalidLifetime);
    }

    // Reads must not carry an approval, and mutations must. The verifier only enforces the
    // mutation direction; refusing a read that arrives with an approval ID keeps an approval for
    // one operation from being attached to another.
    let approval_id = match (request.mutation, request.approval_id) {
        (true, Some(approval_id)) if is_request_key(approval_id) => approval_id,
        (true, Some(_)) => return Err(ActorSigningError::InvalidClaim("approval_id")),
        (false, None) => "",
        _ => return Err(ActorSigningError::ApprovalMismatch),
    };

    // A mutation body must carry the request key so GreenCal can tie its stored intent to this
    // assertion. Checked rather than inserted: the body is what the approval was granted over, and
    // editing it here would sign something the approver never saw.
    if request.mutation {
        let carried = request
            .body
            .as_object()
            .and_then(|object| object.get("requestKey"))
            .and_then(Value::as_str);
        if carried != Some(request.request_key) {
            return Err(ActorSigningError::InvalidClaim("requestKey"));
        }
    }

    let digest = request_digest(request.operation, request.body)?;
    let claims = ActorClaims {
        iss: ACTOR_ISSUER,
        aud: ACTOR_AUDIENCE,
        sub: request.subject,
        org_id: request.org_id,
        service_client_id: request.service_client_id,
        iat: request.issued_at,
        exp: expires_at,
        jti: request.request_key,
        operation: request.operation,
        request_sha256: &digest,
        approved: request.mutation.then_some(true),
        approval_id: request.mutation.then_some(approval_id),
    };

    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some(ACTOR_TYP.to_owned());
    header.kid = Some(key.key_id.clone());

    let token = jsonwebtoken::encode(&header, &claims, &key.encoding)
        .map_err(|_| ActorSigningError::SignatureFailed)?;
    if token.len() > MAX_TOKEN_BYTES {
        return Err(ActorSigningError::TokenTooLong);
    }
    Ok(token)
}

/// The public JWK for a signing key, in exactly the seven members GreenCal accepts.
///
/// Its verifier rejects a key carrying any other member, `d` included, so this is built field by
/// field from the public coordinates rather than by filtering a fuller structure.
pub fn public_jwk(key_id: &str, uncompressed_point: &[u8]) -> Result<Value, ActorSigningError> {
    if !is_identifier(key_id) {
        return Err(ActorSigningError::InvalidClaim("kid"));
    }
    // SEC1 uncompressed: 0x04 then the two 32-byte coordinates.
    if uncompressed_point.len() != 65 || uncompressed_point[0] != 0x04 {
        return Err(ActorSigningError::KeyUnusable);
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

#[cfg(test)]
#[path = "greencal_actor_tests.rs"]
mod greencal_actor_tests;
