//! The inbound TLS settings the configuration compiler reads: the minimum
//! protocol version and the client-certificate mode of a listener.
//!
//! The gateway's listeners act on these; it re-exports them from
//! `inbound_tls`.

use std::{fmt, str::FromStr};

/// Minimum TLS protocol version an inbound listener will negotiate.
///
/// Stated explicitly rather than inherited from whatever rustls defaults to, so
/// that the floor an operator is running on is a configured, auditable value
/// and cannot move under them on a dependency bump.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsMinVersion {
    Tls12,
    Tls13,
}

impl TlsMinVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tls12 => "1.2",
            Self::Tls13 => "1.3",
        }
    }
}

impl FromStr for TlsMinVersion {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "1.2" => Ok(Self::Tls12),
            "1.3" => Ok(Self::Tls13),
            _ => Err("expected `1.2` or `1.3`"),
        }
    }
}

impl fmt::Display for TlsMinVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Whether a listener asks callers for a client certificate, and what it does
/// with a caller that has none.
///
/// Three states rather than a boolean, because "request a certificate" and
/// "insist on one" are different deployments and the difference is not a
/// degree. `Optional` exists for a migration: a listener that already serves
/// bearer-token callers can start accepting certificate identities without
/// locking out everything that has not been issued one yet.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ClientCertMode {
    /// Never ask. This is what every listener does unless told otherwise, and
    /// it is byte-for-byte the behaviour that shipped in #327.
    #[default]
    Off,
    /// Ask, and serve callers who decline.
    ///
    /// What `optional` does NOT mean is "trust a certificate less". A caller
    /// who presents one is held to exactly the same verification as under
    /// `required` -- rustls verifies every certificate that is presented -- so
    /// a certificate that fails verification fails the handshake in both modes.
    /// The only difference is the caller who presents none, and that caller has
    /// no certificate identity at all rather than a partial one.
    Optional,
    /// Ask, and refuse the handshake when the caller declines.
    Required,
}

/// A mode with `Off` removed, for the listener that has already decided to ask.
///
/// Separate from [`ClientCertMode`] so that the verifier builder cannot be
/// handed a mode it has no meaning for: a listener holding this type is asking
/// for certificates, and the only open question is what to do about a caller
/// that brings none.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientCertRequirement {
    Optional,
    Required,
}

impl ClientCertMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Optional => "optional",
            Self::Required => "required",
        }
    }

    /// The requirement this mode expresses, or `None` when it expresses none.
    pub fn requirement(self) -> Option<ClientCertRequirement> {
        match self {
            Self::Off => None,
            Self::Optional => Some(ClientCertRequirement::Optional),
            Self::Required => Some(ClientCertRequirement::Required),
        }
    }
}

impl FromStr for ClientCertMode {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "off" => Ok(Self::Off),
            "optional" => Ok(Self::Optional),
            "required" => Ok(Self::Required),
            _ => Err("expected `off`, `optional`, or `required`"),
        }
    }
}

impl fmt::Display for ClientCertMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
