//! The authentication settings the configuration compiler reads and the
//! shapes it holds them to (issue #242): issuer canonicalization, the
//! principal identity bounds a policy's identity mappings are held to, the
//! JWKS key age bounds, cookie names, the client-certificate identity source
//! and the admin session settings.
//!
//! The gateway's validators and stores act on these; it re-exports each from
//! the module that uses it (`auth::principal`, `auth::jwt`,
//! `middleware::auth`, `auth::client_certificate` and `auth::admin_session`).

use std::{fmt, str::FromStr, time::Duration};

/// The prefix of the issuer label a configured provider without an issuer
/// carries ([`provider_issuer`]). A configured issuer may not start with it.
pub const PROVIDER_ISSUER_PREFIX: &str = "provider:";

/// Longest issuer, in bytes.
pub const MAX_PRINCIPAL_ISSUER_BYTES: usize = 4096;
/// Longest role name, in bytes.
pub const MAX_PRINCIPAL_ROLE_BYTES: usize = 256;
/// Longest subject (`user_id`), in bytes.
pub const MAX_PRINCIPAL_SUBJECT_BYTES: usize = 4096;

/// Canonical issuer form used by authentication, policy, audit, and discovery.
pub fn canonical_issuer(issuer: &str) -> Option<String> {
    let issuer = issuer.trim().trim_end_matches('/');
    if issuer.is_empty() {
        return None;
    }

    Some(issuer.to_owned())
}

/// Stable identity-boundary label for configured providers without an issuer.
pub fn provider_issuer(provider_name: &str) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(provider_name.len());
    for byte in provider_name.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
        }
    }

    format!("{PROVIDER_ISSUER_PREFIX}{encoded}")
}

/// The cap on the operator's maximum JWKS key age: a day. Past that a
/// withdrawn key would be honoured for longer than any rotation window an IdP
/// documents.
pub const MAX_JWKS_KEY_AGE_SECS_LIMIT: u64 = 86_400;
/// The floor on the operator's maximum JWKS key age: the gateway's
/// demand-refresh throttle, which is defined from it. Below it a key set could
/// go stale before a demand refresh was allowed again, and every request would
/// fail closed against a reachable issuer until the throttle window passed.
pub const MIN_JWKS_KEY_AGE_SECS_LIMIT: u64 = 10;

/// Whether `value` is an RFC 6265 cookie-name token.
pub fn safe_cookie_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

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

/// The longest absolute admin session lifetime, in seconds.
pub const MAX_SESSION_TTL_SECS: u64 = 86_400;
/// The most admin sessions, and the most pending cookie logins, a store holds.
pub const MAX_SESSION_ENTRIES: usize = 100_000;

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
    /// Whether these settings are within the bounds every session store
    /// enforces: a positive lifetime of at most [`MAX_SESSION_TTL_SECS`], a
    /// positive idle timeout no longer than the lifetime, and between one and
    /// [`MAX_SESSION_ENTRIES`] entries.
    pub fn is_valid(&self) -> bool {
        self.ttl.as_secs() > 0
            && self.ttl <= Duration::from_secs(MAX_SESSION_TTL_SECS)
            && self.idle_timeout.as_secs() > 0
            && self.idle_timeout <= self.ttl
            && self.max_entries > 0
            && self.max_entries <= MAX_SESSION_ENTRIES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_issuer_trims_whitespace_and_trailing_slashes() {
        assert_eq!(
            canonical_issuer(" https://idp.example/// "),
            Some("https://idp.example".to_owned())
        );
        assert_eq!(canonical_issuer("///"), None);
    }

    #[test]
    fn provider_issuer_encodes_reserved_provider_name_bytes() {
        assert_eq!(provider_issuer("workforce"), "provider:workforce");
        assert_eq!(provider_issuer("team/red"), "provider:team%2Fred");
        assert_ne!(provider_issuer("team/red"), provider_issuer("team%2Fred"));
    }

    #[test]
    fn provider_issuer_escapes_every_other_byte_as_two_uppercase_hex_digits() {
        assert_eq!(provider_issuer("a b"), "provider:a%20b");
        assert_eq!(provider_issuer("\0\n"), "provider:%00%0A");
        assert_eq!(provider_issuer("\u{e9}"), "provider:%C3%A9");
        assert_eq!(provider_issuer("A-Z.0_9~"), "provider:A-Z.0_9~");
        assert_eq!(provider_issuer(""), "provider:");
    }
}
