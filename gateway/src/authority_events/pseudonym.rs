//! Keyed, domain-separated safe references for authority evidence.
//!
//! An authority event says who acted and what changed without carrying either
//! identifier. Each subject, issuer and resource identifier is replaced by a
//! *safe reference*: a pseudonym that is stable for one identity within one
//! evidence authority and tells a reader without the key nothing about it.
//!
//! ## Keyed, because the identifiers are guessable
//!
//! A subject is often an email address, a Connection ID is chosen by an
//! operator, and a service-token ID is printed to whoever issued it. A plain
//! SHA-256 of any of them is one dictionary away from the original, so a
//! reference is HMAC-SHA256 under a key only the gateway holds. Without the key
//! a reference can only be compared with other references. With it, a guessed
//! identity can be confirmed, which is why the key is resolved like any other
//! secret and never leaves the gateway.
//!
//! ## Layout
//!
//! A reference is 64 lowercase hexadecimal characters, the shape the proposed
//! event schema already requires of `subject_ref`, `issuer_ref` and
//! `resource.ref`:
//!
//! * the first 8 are the **key ID**: the leftmost 4 bytes of HMAC-SHA256 under
//!   the key over the framed label `greengateway.authority_pseudonym.key_id.v1`.
//!   It depends on the key alone, so every replica holding the key agrees on it
//!   without configuration, and after a rotation it says which key made a
//!   reference;
//! * the remaining 56 are the leftmost 28 bytes of HMAC-SHA256 under the same
//!   key over the framed derivation input.
//!
//! Every field of both inputs is framed as its length (8 bytes, big endian)
//! followed by its bytes. The derivation input is the label
//! `greengateway.authority_pseudonym.v1`, the 16 bytes of the authority ID, the
//! domain label (such as `actor.subject` or `resource.connection`), the number
//! of components (8 bytes, big endian), then each component. Length prefixes
//! rather than separators keep `("ab", "c")` and `("a", "bc")` apart whatever
//! bytes an identifier contains. A component is the identifier's canonical
//! text exactly as its store keeps it; a different spelling of the same
//! identifier is a different reference.
//!
//! ## Domain separation and authority scope
//!
//! Every reference is derived in one closed [`ReferenceDomain`], so the same
//! string used as a subject and as a Connection ID yields two unrelated
//! references. The authority ID is part of every derivation, so a clone that
//! is deliberately re-namespaced under a new authority ID cannot be correlated
//! with its source even if it kept the key. A subject is scoped to the issuer
//! that vouched for it, as `Principal` and caller assertions scope it: the
//! actor-subject domain takes exactly two components, the canonical issuer and
//! then the subject, so a producer cannot drop the issuer by accident.
//!
//! ## Rotation
//!
//! A [`PseudonymKeyring`] holds the current key, which derives every new
//! reference, and optionally the previous key, which only verifies. During that
//! dual-key window [`PseudonymKeyring::verify`] recognises a reference made
//! under either, so evidence written before the rotation still matches the
//! identity it names. Committed references are never rewritten. Once the
//! previous key is dropped, its references stay valid opaque identifiers that
//! can no longer be recomputed from an identity.
//!
//! The key is resolved through the secret providers under
//! [`SecretPurpose::AuthorityPseudonymKey`], which the encrypted local store
//! neither holds nor resolves. `docs/authority-evidence.md` gives the key
//! source, rotation and backup policy. Nothing calls this module at runtime
//! yet: the producer that puts these references into authority events is a
//! later #425 slice.

#![allow(dead_code)] // No runtime producer exists yet; a later #425 slice wires this in.

use std::{error::Error, fmt};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use uuid::{Uuid, Variant};
use zeroize::Zeroizing;

use crate::{
    auth::principal::{MAX_PRINCIPAL_ISSUER_BYTES, MAX_PRINCIPAL_SUBJECT_BYTES},
    connections::secret::{
        ResolvedSecret, SecretPurpose, SecretResolveErrorKind, SecretResolver,
        MAX_AUTHORITY_PSEUDONYM_KEY_BYTES,
    },
};

/// Raw bytes of a pseudonym key: the HMAC-SHA256 output length.
pub(crate) const PSEUDONYM_KEY_BYTES: usize = 32;
/// Hexadecimal characters in a safe reference.
pub(crate) const REFERENCE_HEX_CHARS: usize = 64;
/// Hexadecimal characters of the key ID that leads every safe reference.
pub(crate) const KEY_ID_HEX_CHARS: usize = 8;
/// The most components one reference is derived from.
pub(crate) const MAX_REFERENCE_COMPONENTS: usize = 4;
/// The largest single component. It is at least the largest subject and
/// issuer a principal may carry, so every admitted actor can be referenced.
pub(crate) const MAX_REFERENCE_COMPONENT_BYTES: usize = 4096;

// Every subject and issuer a principal may carry can be referenced, and the
// secret purpose's byte bound is exactly one hex-encoded key.
const _: () = assert!(MAX_REFERENCE_COMPONENT_BYTES >= MAX_PRINCIPAL_SUBJECT_BYTES);
const _: () = assert!(MAX_REFERENCE_COMPONENT_BYTES >= MAX_PRINCIPAL_ISSUER_BYTES);
const _: () = assert!(MAX_AUTHORITY_PSEUDONYM_KEY_BYTES == PSEUDONYM_KEY_BYTES * 2);

const KEY_ID_BYTES: usize = KEY_ID_HEX_CHARS / 2;
const TAG_BYTES: usize = (REFERENCE_HEX_CHARS - KEY_ID_HEX_CHARS) / 2;
const DERIVATION_LABEL: &[u8] = b"greengateway.authority_pseudonym.v1";
const KEY_ID_LABEL: &[u8] = b"greengateway.authority_pseudonym.key_id.v1";

type HmacSha256 = Hmac<Sha256>;

/// What a reference names. Each variant is its own derivation domain.
///
/// The resource variants are the proposed event schema's closed
/// `resource.kind` vocabulary, one for one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ReferenceDomain {
    /// The acting principal: exactly two components, its canonical issuer and
    /// then its subject.
    ActorSubject,
    /// The issuer that authenticated the actor: exactly one component, the
    /// canonical issuer.
    ActorIssuer,
    Policy,
    Tools,
    Connection,
    Catalog,
    CredentialBinding,
    LocalSecret,
    ExternalSecret,
    ServiceToken,
    JwtRevocation,
    Configuration,
    AdminSession,
}

impl ReferenceDomain {
    pub(crate) const ALL: [Self; 13] = [
        Self::ActorSubject,
        Self::ActorIssuer,
        Self::Policy,
        Self::Tools,
        Self::Connection,
        Self::Catalog,
        Self::CredentialBinding,
        Self::LocalSecret,
        Self::ExternalSecret,
        Self::ServiceToken,
        Self::JwtRevocation,
        Self::Configuration,
        Self::AdminSession,
    ];

    /// The label framed into every derivation in this domain. Changing one
    /// changes every reference in that domain, so they are fixed for v1.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::ActorSubject => "actor.subject",
            Self::ActorIssuer => "actor.issuer",
            Self::Policy => "resource.policy",
            Self::Tools => "resource.tools",
            Self::Connection => "resource.connection",
            Self::Catalog => "resource.catalog",
            Self::CredentialBinding => "resource.credential_binding",
            Self::LocalSecret => "resource.local_secret",
            Self::ExternalSecret => "resource.external_secret",
            Self::ServiceToken => "resource.service_token",
            Self::JwtRevocation => "resource.jwt_revocation",
            Self::Configuration => "resource.configuration",
            Self::AdminSession => "resource.admin_session",
        }
    }

    /// Whether `count` components fit this domain. The actor domains take an
    /// exact shape; a resource takes its identifier, optionally preceded by
    /// the identifiers of the resources that own it.
    fn accepts(self, count: usize) -> bool {
        match self {
            Self::ActorSubject => count == 2,
            Self::ActorIssuer => count == 1,
            _ => (1..=MAX_REFERENCE_COMPONENTS).contains(&count),
        }
    }
}

/// Which key of a keyring a failure concerns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyRole {
    Current,
    Previous,
}

impl KeyRole {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Previous => "previous",
        }
    }
}

/// Why resolved material is not a usable pseudonym key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyRejection {
    /// The material was resolved under another purpose.
    WrongPurpose,
    /// Not exactly 64 hexadecimal characters.
    Malformed,
    /// Every byte is the same: a placeholder, not a generated key.
    Placeholder,
    /// HMAC-SHA256 refused the key. It accepts keys of every length, so this
    /// is unreachable; it exists so the refusal is an error, not a panic.
    Unusable,
}

impl KeyRejection {
    const fn as_str(self) -> &'static str {
        match self {
            Self::WrongPurpose => "resolved_under_another_purpose",
            Self::Malformed => "not_64_hex_characters",
            Self::Placeholder => "placeholder_key",
            Self::Unusable => "unusable_key",
        }
    }
}

impl fmt::Display for KeyRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "authority pseudonym key rejected: {}",
            self.as_str()
        )
    }
}

impl Error for KeyRejection {}

/// A failure to build a keyring or to derive or check a reference. None
/// carries key material, an identifier or a reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PseudonymError {
    /// The same alias was named as both the current and the previous key.
    SameAlias,
    /// The secret provider did not supply the key.
    KeyUnavailable {
        role: KeyRole,
        kind: SecretResolveErrorKind,
    },
    /// The provider supplied material that is not a usable key.
    KeyRejected { role: KeyRole, reason: KeyRejection },
    /// The current and previous key share a key ID: one key named twice.
    DuplicateKey,
    /// The authority ID is not a versioned RFC 4122 UUID.
    InvalidAuthority,
    /// The components do not fit the domain, or one is empty or too large.
    InvalidComponents,
    /// A reference that is not 64 lowercase hexadecimal characters.
    MalformedReference,
}

impl fmt::Display for PseudonymError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SameAlias => formatter
                .write_str("the current and previous authority pseudonym keys name the same alias"),
            Self::KeyUnavailable { role, kind } => write!(
                formatter,
                "the {} authority pseudonym key is unavailable: {}",
                role.as_str(),
                kind.as_str()
            ),
            Self::KeyRejected { role, reason } => write!(
                formatter,
                "the {} authority pseudonym key was rejected: {}",
                role.as_str(),
                reason.as_str()
            ),
            Self::DuplicateKey => formatter
                .write_str("the current and previous authority pseudonym keys are the same key"),
            Self::InvalidAuthority => {
                formatter.write_str("the evidence authority ID is not a versioned UUID")
            }
            Self::InvalidComponents => {
                formatter.write_str("reference components do not fit their domain")
            }
            Self::MalformedReference => formatter.write_str("malformed safe reference"),
        }
    }
}

impl Error for PseudonymError {}

/// One pseudonym key and the key ID derived from it.
pub(crate) struct PseudonymKey {
    id: String,
    material: Zeroizing<[u8; PSEUDONYM_KEY_BYTES]>,
}

impl PseudonymKey {
    /// Parse material resolved under
    /// [`SecretPurpose::AuthorityPseudonymKey`]: exactly 64 hexadecimal
    /// characters, as `openssl rand -hex 32` prints them without the newline.
    pub(crate) fn from_resolved(secret: &ResolvedSecret) -> Result<Self, KeyRejection> {
        if secret.purpose() != SecretPurpose::AuthorityPseudonymKey {
            return Err(KeyRejection::WrongPurpose);
        }
        let encoded = secret.expose();
        if encoded.len() != PSEUDONYM_KEY_BYTES * 2 {
            return Err(KeyRejection::Malformed);
        }
        let mut material = Zeroizing::new([0_u8; PSEUDONYM_KEY_BYTES]);
        hex::decode_to_slice(encoded, material.as_mut_slice())
            .map_err(|_| KeyRejection::Malformed)?;
        let first = material[0];
        if material.iter().all(|byte| *byte == first) {
            return Err(KeyRejection::Placeholder);
        }
        let mut mac = keyed_mac(&material).ok_or(KeyRejection::Unusable)?;
        update_framed(&mut mac, KEY_ID_LABEL);
        let id = hex::encode(&mac.finalize().into_bytes()[..KEY_ID_BYTES]);
        Ok(Self { id, material })
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }
}

impl fmt::Debug for PseudonymKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PseudonymKey")
            .field("id", &self.id)
            .field("material", &"<redacted>")
            .finish()
    }
}

/// A safe reference: 64 lowercase hexadecimal characters, the key ID first.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SafeReference(String);

impl SafeReference {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// The key ID of the key this reference was made with.
    pub(crate) fn key_id(&self) -> &str {
        // ASCII by construction, so this never splits a character.
        &self.0[..KEY_ID_HEX_CHARS]
    }
}

impl fmt::Display for SafeReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// How a reference relates to one input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReferenceCheck {
    /// Made from this input under the current key.
    Current,
    /// Made from this input under the previous key, inside the rotation
    /// window.
    Previous,
    /// Made under a key this keyring holds, from a different input.
    Mismatch,
    /// Made under a key this keyring does not hold: one retired before this
    /// window, or a key from elsewhere.
    UnknownKey,
}

/// The keys one evidence authority derives and checks references with.
#[derive(Debug)]
pub(crate) struct PseudonymKeyring {
    authority_id: Uuid,
    current: PseudonymKey,
    previous: Option<PseudonymKey>,
}

impl PseudonymKeyring {
    /// Build a keyring for one evidence authority. The authority ID must be a
    /// versioned RFC 4122 UUID, as the event schema requires, and a previous
    /// key must be a different key from the current one.
    pub(crate) fn new(
        authority_id: Uuid,
        current: PseudonymKey,
        previous: Option<PseudonymKey>,
    ) -> Result<Self, PseudonymError> {
        let version = authority_id.get_version_num();
        if !(1..=8).contains(&version) || authority_id.get_variant() != Variant::RFC4122 {
            return Err(PseudonymError::InvalidAuthority);
        }
        if previous.as_ref().is_some_and(|key| key.id == current.id) {
            return Err(PseudonymError::DuplicateKey);
        }
        Ok(Self {
            authority_id,
            current,
            previous,
        })
    }

    pub(crate) fn authority_id(&self) -> Uuid {
        self.authority_id
    }

    pub(crate) fn current_key_id(&self) -> &str {
        self.current.id()
    }

    pub(crate) fn previous_key_id(&self) -> Option<&str> {
        self.previous.as_ref().map(PseudonymKey::id)
    }

    /// Derive the reference for `components` in `domain` under the current
    /// key.
    pub(crate) fn derive(
        &self,
        domain: ReferenceDomain,
        components: &[&str],
    ) -> Result<SafeReference, PseudonymError> {
        let mac = self.derivation_mac(&self.current, KeyRole::Current, domain, components)?;
        let tag = mac.finalize().into_bytes();
        let mut reference = String::with_capacity(REFERENCE_HEX_CHARS);
        reference.push_str(&self.current.id);
        reference.push_str(&hex::encode(&tag[..TAG_BYTES]));
        Ok(SafeReference(reference))
    }

    /// Check whether `reference` was derived from `components` in `domain`
    /// under either key this keyring holds. The tag comparison is constant
    /// time.
    pub(crate) fn verify(
        &self,
        domain: ReferenceDomain,
        components: &[&str],
        reference: &str,
    ) -> Result<ReferenceCheck, PseudonymError> {
        validate_components(domain, components)?;
        if reference.len() != REFERENCE_HEX_CHARS
            || !reference
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(PseudonymError::MalformedReference);
        }
        let (key_id, encoded_tag) = reference.split_at(KEY_ID_HEX_CHARS);
        let (key, role) = if key_id == self.current.id {
            (&self.current, KeyRole::Current)
        } else {
            match self.previous.as_ref() {
                Some(previous) if key_id == previous.id => (previous, KeyRole::Previous),
                _ => return Ok(ReferenceCheck::UnknownKey),
            }
        };
        let mut tag = [0_u8; TAG_BYTES];
        hex::decode_to_slice(encoded_tag, &mut tag)
            .map_err(|_| PseudonymError::MalformedReference)?;
        let mac = self.derivation_mac(key, role, domain, components)?;
        if mac.verify_truncated_left(&tag).is_err() {
            return Ok(ReferenceCheck::Mismatch);
        }
        Ok(match role {
            KeyRole::Current => ReferenceCheck::Current,
            KeyRole::Previous => ReferenceCheck::Previous,
        })
    }

    fn derivation_mac(
        &self,
        key: &PseudonymKey,
        role: KeyRole,
        domain: ReferenceDomain,
        components: &[&str],
    ) -> Result<HmacSha256, PseudonymError> {
        validate_components(domain, components)?;
        let mut mac = keyed_mac(&key.material).ok_or(PseudonymError::KeyRejected {
            role,
            reason: KeyRejection::Unusable,
        })?;
        update_framed(&mut mac, DERIVATION_LABEL);
        update_framed(&mut mac, self.authority_id.as_bytes());
        update_framed(&mut mac, domain.label().as_bytes());
        mac.update(&frame_length(components.len()));
        for component in components {
            update_framed(&mut mac, component.as_bytes());
        }
        Ok(mac)
    }
}

/// Resolve the current and, during a rotation window, the previous key under
/// [`SecretPurpose::AuthorityPseudonymKey`] and build the keyring. Every
/// failure is fatal: there is no fallback key and no unkeyed mode.
pub(crate) async fn resolve_keyring(
    resolver: &dyn SecretResolver,
    authority_id: Uuid,
    current_alias: &str,
    previous_alias: Option<&str>,
) -> Result<PseudonymKeyring, PseudonymError> {
    if previous_alias == Some(current_alias) {
        return Err(PseudonymError::SameAlias);
    }
    let current = resolve_key(resolver, current_alias, KeyRole::Current).await?;
    let previous = match previous_alias {
        Some(alias) => Some(resolve_key(resolver, alias, KeyRole::Previous).await?),
        None => None,
    };
    PseudonymKeyring::new(authority_id, current, previous)
}

async fn resolve_key(
    resolver: &dyn SecretResolver,
    alias: &str,
    role: KeyRole,
) -> Result<PseudonymKey, PseudonymError> {
    let secret = resolver
        .resolve(alias, SecretPurpose::AuthorityPseudonymKey)
        .await
        .map_err(|error| PseudonymError::KeyUnavailable {
            role,
            kind: error.kind(),
        })?;
    PseudonymKey::from_resolved(&secret)
        .map_err(|reason| PseudonymError::KeyRejected { role, reason })
}

fn validate_components(domain: ReferenceDomain, components: &[&str]) -> Result<(), PseudonymError> {
    if !domain.accepts(components.len())
        || components.iter().any(|component| {
            component.is_empty() || component.len() > MAX_REFERENCE_COMPONENT_BYTES
        })
    {
        return Err(PseudonymError::InvalidComponents);
    }
    Ok(())
}

fn keyed_mac(material: &[u8; PSEUDONYM_KEY_BYTES]) -> Option<HmacSha256> {
    <HmacSha256 as KeyInit>::new_from_slice(material).ok()
}

fn update_framed(mac: &mut HmacSha256, field: &[u8]) {
    mac.update(&frame_length(field.len()));
    mac.update(field);
}

fn frame_length(length: usize) -> [u8; 8] {
    // usize is at most 64 bits on every target Rust supports, so this is
    // lossless.
    (length as u64).to_be_bytes()
}

#[cfg(test)]
#[path = "pseudonym_tests.rs"]
mod tests;
