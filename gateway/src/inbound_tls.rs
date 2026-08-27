//! Inbound TLS termination for the gateway's own listeners.
//!
//! `axum::serve` is generic over [`axum::serve::Listener`], so terminating TLS
//! is a listener concern rather than a serving concern. Wrapping the listener
//! leaves the router, `.with_graceful_shutdown(..)`, and
//! `into_make_service_with_connect_info::<SocketAddr>()` exactly as they are on
//! the plaintext path -- which matters, because `ConnectInfo` is how
//! [`crate::client_ip`] learns the peer address and graceful shutdown is what
//! the WebSocket transport's drain behaviour depends on.
//!
//! The hazard that shape introduces is that `Listener::accept` is awaited
//! serially by the serve loop. Running the TLS handshake inside `accept` would
//! let one client that connects and then sends nothing stall every other
//! connection for the length of its timeout -- a trivial denial of service. So
//! handshakes run off the accept path: an internal task pulls TCP connections,
//! runs each handshake in its own task under a bounded semaphore with a
//! per-handshake timeout, and feeds the completed streams into a channel that
//! `accept` reads. Every outcome -- established, failed, or timed out --
//! releases its slot, so the bound is on handshakes actually in progress rather
//! than on connections ever seen.
//!
//! The accept itself is never gated on that bound. Connections are accepted
//! unconditionally and admitted or shed afterwards, because a listener that
//! stops draining the kernel's accept queue leaves arriving clients neither
//! served nor refused -- including the readiness and liveness probes that ride
//! the same listener -- and parking it costs an attacker nothing but idle
//! sockets. A connection that finds no slot is closed immediately and counted
//! as `shed`.

use std::{
    fmt, fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use axum::{extract::connect_info::Connected, serve::IncomingStream};
use cap_std::{ambient_authority, fs::Dir};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Semaphore, TryAcquireError},
};
use tokio_rustls::{
    rustls::{
        crypto::{ring, CryptoProvider},
        pki_types::{pem::PemObject, CertificateDer, CertificateRevocationListDer, PrivateKeyDer},
        server::{NoServerSessionStorage, VerifierBuilderError, WebPkiClientVerifier},
        version, CertificateError, RootCertStore, ServerConfig, SupportedProtocolVersion,
    },
    server::TlsStream,
    TlsAcceptor,
};
use tokio_util::sync::{CancellationToken, DropGuard};
use zeroize::Zeroize;

use crate::{
    auth::{
        client_certificate::identity_from_certificate, ClientCertIdentitySource,
        VerifiedClientIdentity,
    },
    config::{Config, InboundClientAuthSettings, InboundTlsSettings},
    connections::secret::{
        projected_root_permissions_are_safe, read_bounded_file_secret, FileSecretPermissions,
        SecretPurpose, SecretResolveErrorKind,
    },
    metrics::{
        INBOUND_CLIENT_CERTIFICATES_TOTAL, INBOUND_TLS_HANDSHAKES_IN_FLIGHT,
        INBOUND_TLS_HANDSHAKES_TOTAL,
    },
};

/// How deep the completed-handshake channel runs.
///
/// This is how far ahead of the serve loop the handshake pool may run: a
/// handshake releases its admission slot once the established stream is queued
/// here, so at most this many finished connections can wait beyond the
/// concurrency bound. When the buffer fills, the queueing handshake blocks with
/// its slot still held, which is the backpressure that stops the pool from
/// racing ahead of a serve loop that is not taking connections.
const ESTABLISHED_CHANNEL_DEPTH: usize = 16;

/// How long to pause after an `accept` error that is not per-connection.
///
/// Mirrors `axum::serve`'s own listener behaviour: a per-connection error is
/// retried immediately, and anything else (a descriptor limit, most often) is
/// backed off so the loop does not spin a core while the condition clears.
const ACCEPT_BACKOFF: Duration = Duration::from_secs(1);

/// The scheme the listener that carried a request terminated.
///
/// Inserted as a request extension by every listener, TLS or not, so a consumer
/// can read it without knowing how the process was configured. Nothing enforces
/// scheme-dependent policy yet -- HSTS and secure-cookie enforcement are
/// follow-ups -- but they need this to exist first, and it can only be known at
/// the listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionScheme {
    Http,
    Https,
}

impl ConnectionScheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

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

static TLS12_AND_ABOVE: &[&SupportedProtocolVersion] = &[&version::TLS12, &version::TLS13];
static TLS13_ONLY: &[&SupportedProtocolVersion] = &[&version::TLS13];

impl TlsMinVersion {
    fn protocol_versions(self) -> &'static [&'static SupportedProtocolVersion] {
        match self {
            Self::Tls12 => TLS12_AND_ABOVE,
            Self::Tls13 => TLS13_ONLY,
        }
    }

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

/// The bound and the deadline that keep a slow handshake off the accept path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HandshakeLimits {
    pub(crate) max_concurrent: usize,
    pub(crate) timeout: Duration,
}

impl HandshakeLimits {
    pub(crate) fn from_config(config: &Config) -> Self {
        Self {
            max_concurrent: config.tls_max_concurrent_handshakes,
            timeout: Duration::from_millis(config.tls_handshake_timeout_ms),
        }
    }
}

/// Why inbound TLS could not be brought up.
///
/// Every variant names the setting an operator has to fix and carries nothing
/// else: no path, no file contents, no rustls error text. A private key is the
/// most sensitive material this process holds, and a startup error is printed
/// to stderr and frequently scraped into a log aggregator, so the error type is
/// the wrong place to be clever about diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InboundTlsError {
    MaterialPathInvalid {
        setting: &'static str,
    },
    MaterialDirectoryUnavailable {
        setting: &'static str,
    },
    MaterialDirectoryPermissions {
        setting: &'static str,
    },
    MaterialUnavailable {
        setting: &'static str,
    },
    MaterialDenied {
        setting: &'static str,
    },
    MaterialUnsafe {
        setting: &'static str,
    },
    PrivateKeyMaterialUnsafe {
        setting: &'static str,
    },
    MaterialInvalid {
        setting: &'static str,
    },
    CertificateContainsPrivateKey {
        setting: &'static str,
    },
    KeyDoesNotMatchCertificate {
        certificate_setting: &'static str,
        private_key_setting: &'static str,
    },
    ProtocolVersionsUnsupported {
        setting: &'static str,
    },
    ClientTrustAnchorsUnusable {
        setting: &'static str,
    },
    RevocationListUnusable {
        setting: &'static str,
    },
}

impl fmt::Display for InboundTlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MaterialPathInvalid { setting } => write!(
                formatter,
                "{setting} must name a file, not a directory or a path with no final component"
            ),
            Self::MaterialDirectoryUnavailable { setting } => write!(
                formatter,
                "the directory containing {setting} is missing or cannot be opened"
            ),
            Self::MaterialDirectoryPermissions { setting } => write!(
                formatter,
                "the directory containing {setting} is group- or world-writable without the sticky bit"
            ),
            Self::MaterialUnavailable { setting } => {
                write!(formatter, "the file named by {setting} does not exist")
            }
            Self::MaterialDenied { setting } => write!(
                formatter,
                "the file named by {setting} cannot be read by this process"
            ),
            Self::MaterialUnsafe { setting } => write!(
                formatter,
                "the file named by {setting} is not a regular file, escapes its directory, or is group- or world-writable"
            ),
            Self::PrivateKeyMaterialUnsafe { setting } => write!(
                formatter,
                "the file named by {setting} is not a regular file, escapes its directory, or is readable or writable by group or other; a server private key must grant no group or other permission at all, so mount it with `defaultMode: 0400` on a Kubernetes Secret volume -- which publishes 0644 by default and is refused -- or `chmod 0400` for a bind mount"
            ),
            Self::MaterialInvalid { setting } => write!(
                formatter,
                "the file named by {setting} is empty, oversized, or is not the PEM material this setting expects"
            ),
            Self::CertificateContainsPrivateKey { setting } => write!(
                formatter,
                "the file named by {setting} also contains a private key; keep the key in its own file so it can be mounted with tighter permissions"
            ),
            Self::KeyDoesNotMatchCertificate {
                certificate_setting,
                private_key_setting,
            } => write!(
                formatter,
                "the key in {private_key_setting} does not match the leaf certificate in {certificate_setting}"
            ),
            Self::ProtocolVersionsUnsupported { setting } => write!(
                formatter,
                "{setting} selects a protocol version this build of rustls does not support"
            ),
            Self::ClientTrustAnchorsUnusable { setting } => write!(
                formatter,
                "the file named by {setting} contains no certificate usable as a client-authentication trust anchor"
            ),
            Self::RevocationListUnusable { setting } => write!(
                formatter,
                "the file named by {setting} is not a PEM certificate revocation list this build can parse"
            ),
        }
    }
}

impl std::error::Error for InboundTlsError {}

/// The server configuration each listener will serve, resolved at startup.
///
/// `None` means that listener stays plaintext. There is deliberately no third
/// state: a listener whose material failed to load never reaches this type,
/// because [`InboundTlsBindings::load`] returns the error and startup aborts.
pub(crate) struct InboundTlsBindings {
    data: Option<ListenerTls>,
    admin: Option<ListenerTls>,
    min_version: Option<TlsMinVersion>,
    limits: HandshakeLimits,
}

/// One listener's resolved TLS: what rustls will serve, and how to read an
/// identity out of whatever client certificate it verifies.
///
/// The two travel together because they are two halves of one decision. A
/// listener whose `ServerConfig` requests client certificates always has an
/// identity source, and a listener whose config does not request them never
/// has one, so there is no state in which a certificate is verified and then
/// read with a source nobody configured -- or requested and then ignored.
#[derive(Clone)]
pub(crate) struct ListenerTls {
    server_config: Arc<ServerConfig>,
    identity_source: Option<ClientCertIdentitySource>,
}

impl InboundTlsBindings {
    /// Loads every configured certificate and key, or fails startup.
    ///
    /// Fail-closed is the whole point: an operator who set the TLS settings and
    /// then gets a process listening in plaintext has the worst outcome
    /// available, so a missing, unreadable, malformed, mismatched, or
    /// unsafely-permissioned file aborts startup instead of degrading.
    pub(crate) fn load(config: &Config) -> Result<Self, InboundTlsError> {
        let data = config
            .data_inbound_tls()
            .map(load_server_config)
            .transpose()?;
        let admin = config
            .admin_inbound_tls()
            .map(load_server_config)
            .transpose()?;

        Ok(Self {
            min_version: (data.is_some() || admin.is_some()).then_some(config.tls_min_version),
            data,
            admin,
            limits: HandshakeLimits::from_config(config),
        })
    }

    /// The identity source the data listener reads certificates with, if any.
    #[cfg(test)]
    pub(crate) fn data_identity_source(&self) -> Option<ClientCertIdentitySource> {
        self.data
            .as_ref()
            .and_then(|listener| listener.identity_source)
    }

    #[cfg(test)]
    pub(crate) fn plaintext() -> Self {
        Self {
            data: None,
            admin: None,
            min_version: None,
            limits: HandshakeLimits {
                max_concurrent: crate::config::DEFAULT_TLS_MAX_CONCURRENT_HANDSHAKES,
                timeout: Duration::from_millis(crate::config::DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS),
            },
        }
    }

    /// Wraps the data listener, or hands it back unchanged when TLS is off.
    pub(crate) fn bind_data(&self, listener: TcpListener) -> io::Result<BoundListener> {
        BoundListener::bind(listener, self.data.clone(), self.limits, "data")
    }

    /// Wraps the admin listener, or hands it back unchanged when TLS is off.
    pub(crate) fn bind_admin(&self, listener: TcpListener) -> io::Result<BoundListener> {
        BoundListener::bind(listener, self.admin.clone(), self.limits, "admin")
    }

    /// The negotiated floor, or `None` when neither listener terminates TLS.
    pub(crate) fn min_version(&self) -> Option<TlsMinVersion> {
        self.min_version
    }
}

/// A bound listener, before or after TLS wrapping.
///
/// Both variants are handed to the same `axum::serve` call in
/// [`crate::lifecycle::serve_router_with_shutdown`]; only the `Listener`
/// implementation differs. Keeping the two arms one call apart is what makes
/// "TLS is off by default and the plaintext path is unchanged" checkable rather
/// than asserted.
pub(crate) enum BoundListener {
    Plain(TcpListener),
    Tls(TlsListener),
}

impl BoundListener {
    fn bind(
        listener: TcpListener,
        tls: Option<ListenerTls>,
        limits: HandshakeLimits,
        listener_label: &'static str,
    ) -> io::Result<Self> {
        match tls {
            Some(tls) => Ok(Self::Tls(TlsListener::wrap(
                listener,
                tls,
                limits,
                listener_label,
            )?)),
            None => Ok(Self::Plain(listener)),
        }
    }

    pub(crate) fn scheme(&self) -> ConnectionScheme {
        match self {
            Self::Plain(_) => ConnectionScheme::Http,
            Self::Tls(_) => ConnectionScheme::Https,
        }
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            Self::Plain(listener) => listener.local_addr(),
            Self::Tls(listener) => Ok(listener.local_addr),
        }
    }
}

/// Written by hand because the derived form would print the whole
/// `ServerConfig`, and a config carries the resolved signing key.
impl fmt::Debug for InboundTlsBindings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboundTlsBindings")
            .field("data", &self.data.is_some())
            .field("admin", &self.admin.is_some())
            .field("min_version", &self.min_version)
            .field("limits", &self.limits)
            .finish()
    }
}

/// A parsed private key that is wiped when it leaves scope.
///
/// `rustls_pki_types::PrivateKeyDer` implements `Zeroize` but not `Drop`, so
/// the decoded DER would otherwise sit in freed heap after the signing key is
/// built. Wrapping it keeps every failure path -- a mismatched key, an
/// unsupported version -- wiping the material it already decoded, which is the
/// same discipline `ResolvedSecret` applies to the PEM bytes it came from. The
/// success path hands the key to rustls, which owns it from then on.
struct ZeroizingKey(Option<PrivateKeyDer<'static>>);

impl ZeroizingKey {
    fn take(&mut self) -> Option<PrivateKeyDer<'static>> {
        self.0.take()
    }
}

impl Drop for ZeroizingKey {
    fn drop(&mut self) {
        if let Some(key) = self.0.as_mut() {
            key.zeroize();
        }
    }
}

impl fmt::Debug for ZeroizingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-private-key>")
    }
}

fn load_server_config(settings: InboundTlsSettings<'_>) -> Result<ListenerTls, InboundTlsError> {
    let certificate_pem = read_material(
        settings.certificate_setting,
        settings.certificate_file,
        SecretPurpose::TlsCertificate,
        FileSecretPermissions::PlatformProjected,
    )?;
    // A key concatenated into the certificate file inherits the certificate's
    // permissions, and a certificate is the one piece of this pair an operator
    // reasonably mounts world-readable. Refusing the shape outright is cheaper
    // than hoping nobody ever runs `cat key.pem >> cert.pem`.
    if PrivateKeyDer::from_pem_slice(certificate_pem.expose()).is_ok() {
        return Err(InboundTlsError::CertificateContainsPrivateKey {
            setting: settings.certificate_setting,
        });
    }
    let certificates = CertificateDer::pem_slice_iter(certificate_pem.expose())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| InboundTlsError::MaterialInvalid {
            setting: settings.certificate_setting,
        })?;
    if certificates.is_empty() {
        return Err(InboundTlsError::MaterialInvalid {
            setting: settings.certificate_setting,
        });
    }

    let private_key_pem = read_material(
        settings.private_key_setting,
        settings.private_key_file,
        SecretPurpose::TlsPrivateKey,
        FileSecretPermissions::ProjectedExclusive,
    )?;
    let mut private_key = ZeroizingKey(Some(
        PrivateKeyDer::from_pem_slice(private_key_pem.expose()).map_err(|_| {
            InboundTlsError::MaterialInvalid {
                setting: settings.private_key_setting,
            }
        })?,
    ));
    drop(private_key_pem);

    // Build from an explicitly named provider rather than the process default:
    // both `ring` and `aws-lc-rs` are in this dependency graph, so there is no
    // unambiguous process default to inherit, and a listener's cipher suites
    // should not depend on which module happened to install one first.
    let provider = Arc::new(ring::default_provider());
    let client_verifier = settings
        .client_auth
        .map(|client_auth| load_client_verifier(client_auth, Arc::clone(&provider)))
        .transpose()?;
    let identity_source = settings
        .client_auth
        .map(|client_auth| client_auth.identity_source);
    let versions = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(settings.min_version.protocol_versions())
        .map_err(|_| InboundTlsError::ProtocolVersionsUnsupported {
            setting: settings.min_version_setting,
        })?;
    let mut server_config = match client_verifier {
        Some(client_verifier) => versions.with_client_cert_verifier(client_verifier),
        None => versions.with_no_client_auth(),
    }
    .with_single_cert(
        certificates,
        private_key
            .take()
            .expect("the parsed private key is taken exactly once"),
    )
    .map_err(|_| InboundTlsError::KeyDoesNotMatchCertificate {
        certificate_setting: settings.certificate_setting,
        private_key_setting: settings.private_key_setting,
    })?;

    // Advertise HTTP/1.1 and nothing else. Offering `h2` here would be a
    // protocol change smuggled in through ALPN: `axum::serve` builds on
    // `hyper_util`'s auto builder, and what it will actually speak is decided
    // by whether the `h2` crate is in the build -- which `scripts/check-egress-only.sh`
    // deliberately keeps it out of. A client that offers h2 and http/1.1 gets
    // http/1.1; a client that offers only h2 is refused at the handshake rather
    // than being handed a connection nothing will parse.
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    // Only where certificates are actually being asked for. A listener with
    // `CLIENT_CERT_MODE=off` keeps rustls' resumption exactly as #327 shipped
    // it, so no deployment that has never heard of client certificates changes
    // behaviour here.
    if settings.client_auth.is_some() {
        disable_session_resumption(&mut server_config);
    }

    Ok(ListenerTls {
        server_config: Arc::new(server_config),
        identity_source,
    })
}

/// Removes every way a listener can resume an earlier TLS session.
///
/// rustls verifies a client certificate exactly once, during a full handshake.
/// On a *resumed* handshake it restores the earlier connection's chain instead:
/// `peer_certificates` is cloned out of the stored session in
/// `rustls::server::tls13` and assigned from the resumed session data in
/// `rustls::server::tls12`. The only thing consulted before that happens is
/// `can_resume`, which compares the cipher suite, the extended-master-secret
/// state, and the SNI. Nothing about the certificate is re-examined: not its
/// validity window, not the CRL, not the trust path. So
/// [`client_identity`] would go on minting an identity from a certificate no
/// check had touched on this connection.
///
/// Under rustls' defaults that window is a day. `NeverProducesTickets` means
/// TLS 1.3 tickets are *stateful* -- kept in a `ServerSessionMemoryCache` under
/// a hard-coded 24-hour lifetime -- and `send_tls13_tickets` defaults to 2, and
/// `TLS_MIN_VERSION` defaults to 1.2 so the abbreviated TLS 1.2 handshake is
/// live as well. An expired or revoked client certificate would keep
/// authenticating for up to 24 hours after it stopped being valid, and the
/// fail-closed CRL handling [`load_client_verifier`] is careful about would
/// stop applying to precisely the callers it exists to stop.
///
/// The alternative was to keep resumption and re-check the restored chain
/// before minting an identity. It is not taken, for two reasons.
///
/// **A resumed handshake proves the wrong thing.** Neither TLS 1.2's
/// abbreviated handshake nor TLS 1.3's PSK resumption carries a
/// CertificateVerify. The peer proves it holds the resumption secret; it does
/// not prove it holds the certificate's private key. Re-running the verifier
/// over the restored chain would establish that the certificate is still valid.
/// It could not establish that the caller still holds the key -- which is the
/// entire proposition a client-certificate listener sells -- because there is
/// nothing on a resumed connection for the caller to have signed. No amount of
/// re-validation recovers that property; only a full handshake does.
///
/// **It would be a second copy of a trust decision.** `WebPkiClientVerifier`
/// owns path building, validity windows, extended key usage, name constraints,
/// and revocation including CRL expiry. Re-implementing enough of that
/// elsewhere to match it exactly is the shape #332 has just finished removing
/// from the outbound path, on the grounds that two copies of one decision
/// drift.
///
/// The cost is a full handshake per connection, and it is charged only to
/// listeners that asked for certificates.
fn disable_session_resumption(server_config: &mut ServerConfig) {
    // Both halves are load-bearing and neither is redundant. Emptying the store
    // kills TLS 1.2 session ids *and* the stateful TLS 1.3 tickets that the
    // default `NeverProducesTickets` implies, because both resolve the session
    // through it. Sending no tickets stops a client being handed anything to
    // offer back in the first place, so a later change of ticketer -- which
    // would make tickets self-contained and stop consulting the store --
    // cannot quietly reintroduce the path.
    server_config.session_storage = Arc::new(NoServerSessionStorage {});
    server_config.send_tls13_tickets = 0;
}

/// Builds the verifier that decides which client certificates are acceptable.
///
/// Three properties are load-bearing, and all three are decided here rather
/// than inherited:
///
/// **The trust anchors are the operator's, and only the operator's.** There is
/// no path here to `rustls-platform-verifier` or to any other ambient trust
/// store. Trusting the platform roots for *client* authentication would mean
/// every certificate every public CA has ever issued authenticates to this
/// gateway, which is essentially never what an operator configuring mutual TLS
/// means. A bundle that yields no usable trust anchor fails startup.
///
/// **Revocation is checked when, and only when, CRLs are configured.** rustls
/// checks neither CRLs nor OCSP by default, so a deployment with no
/// `*_CLIENT_CERT_CRL_FILE` has no revocation checking at all -- documented in
/// `docs/configuration.md` under exactly that heading, because an operator who
/// believes revocation works when it does not has a worse problem than one who
/// knows it does not. When CRLs *are* configured, they are enforced the strict
/// way: over the whole verified chain rather than the end entity alone, with an
/// undeterminable status treated as a failure, and with an expired CRL treated
/// as no CRL at all rather than as a still-valid one.
///
/// **`optional` weakens only the anonymous case.** `allow_unauthenticated`
/// permits a caller that sends no certificate; it does not soften the
/// verification applied to a caller that sends one.
fn load_client_verifier(
    settings: InboundClientAuthSettings<'_>,
    provider: Arc<CryptoProvider>,
) -> Result<Arc<dyn tokio_rustls::rustls::server::danger::ClientCertVerifier>, InboundTlsError> {
    let ca_pem = read_material(
        settings.ca_setting,
        settings.ca_file,
        SecretPurpose::TlsCaBundle,
        FileSecretPermissions::PlatformProjected,
    )?;
    // Same rule the server certificate is held to: a key concatenated into a
    // file mounted for public material inherits that file's permissions.
    if PrivateKeyDer::from_pem_slice(ca_pem.expose()).is_ok() {
        return Err(InboundTlsError::CertificateContainsPrivateKey {
            setting: settings.ca_setting,
        });
    }

    let anchors = CertificateDer::pem_slice_iter(ca_pem.expose())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| InboundTlsError::MaterialInvalid {
            setting: settings.ca_setting,
        })?;
    if anchors.is_empty() {
        return Err(InboundTlsError::MaterialInvalid {
            setting: settings.ca_setting,
        });
    }
    let mut roots = RootCertStore::empty();
    for anchor in anchors {
        // `add` rather than `add_parsable_certificates`: a bundle with one
        // unusable entry is a bundle an operator is wrong about, and silently
        // trusting the remainder would mean the set of callers who can
        // authenticate is not the set the operator wrote down.
        roots
            .add(anchor)
            .map_err(|_| InboundTlsError::ClientTrustAnchorsUnusable {
                setting: settings.ca_setting,
            })?;
    }

    let mut builder = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider);
    if let Some(crl_file) = settings.crl_file {
        let crl_pem = read_material(
            settings.crl_setting,
            crl_file,
            SecretPurpose::TlsCaBundle,
            FileSecretPermissions::PlatformProjected,
        )?;
        let crls = CertificateRevocationListDer::pem_slice_iter(crl_pem.expose())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| InboundTlsError::RevocationListUnusable {
                setting: settings.crl_setting,
            })?;
        if crls.is_empty() {
            return Err(InboundTlsError::RevocationListUnusable {
                setting: settings.crl_setting,
            });
        }
        builder = builder.with_crls(crls).enforce_revocation_expiration();
    }
    if settings.requirement == ClientCertRequirement::Optional {
        builder = builder.allow_unauthenticated();
    }

    // The two ways this can fail name two different files, so they name two
    // different settings. A well-formed PEM block that is not a DER CRL gets
    // this far -- `pem_slice_iter` only decoded the base64 -- and telling that
    // operator to look at their CA bundle would send them to the wrong file.
    builder.build().map_err(|error| match error {
        VerifierBuilderError::InvalidCrl(_) => InboundTlsError::RevocationListUnusable {
            setting: settings.crl_setting,
        },
        _ => InboundTlsError::ClientTrustAnchorsUnusable {
            setting: settings.ca_setting,
        },
    })
}

/// Reads one PEM file with the discipline `gateway/src/connections/secret.rs`
/// established for connection secrets.
///
/// The parent directory is opened as a capability root and the leaf is read
/// through [`read_bounded_file_secret`], so this inherits the bounded read, the
/// regular-file revalidation after open, the confinement of symlink resolution
/// beneath the root, and the permission rules -- rather than reimplementing any
/// of them slightly differently.
///
/// The two files get different policies, because they are different material.
///
/// The certificate is public: it is served to every client that connects, so
/// [`FileSecretPermissions::PlatformProjected`] is the right policy for it --
/// group and other *read* are of no consequence, and group or other *write*
/// still fails closed because a certificate an attacker can rewrite is a
/// certificate an attacker chooses.
///
/// The private key gets [`FileSecretPermissions::ProjectedExclusive`], which
/// permits the same symlinked leaf and forbids group and other *read* as well.
/// Both halves of that are load-bearing. `Exclusive` refuses a symlinked leaf,
/// and every Kubernetes TLS Secret mount publishes its leaves as relative
/// symlinks into the kubelet atomic writer's `..data` directory, so `Exclusive`
/// would reject the commonest way this material is mounted for a shape that is
/// not unsafe. `PlatformProjected` would accept a world-readable private key
/// without a word, which no other private key in this codebase does. The cost
/// is real and deliberate: Kubernetes publishes Secret volume files `0644` by
/// default, so a default TLS Secret mount is refused until the operator sets
/// `defaultMode: 0400`. The error says so, and `docs/configuration.md` says so.
fn read_material(
    setting: &'static str,
    path: &str,
    purpose: SecretPurpose,
    permissions: FileSecretPermissions,
) -> Result<crate::connections::secret::ResolvedSecret, InboundTlsError> {
    let path = PathBuf::from(path);
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(InboundTlsError::MaterialPathInvalid { setting });
    };
    let directory = open_material_directory(setting, path.parent())?;

    read_bounded_file_secret(setting, &directory, file_name, purpose, permissions).map_err(
        |error| match error.kind() {
            SecretResolveErrorKind::SourceUnavailable => {
                InboundTlsError::MaterialUnavailable { setting }
            }
            SecretResolveErrorKind::SourceDenied => InboundTlsError::MaterialDenied { setting },
            // The two policies fail closed on different things, so they owe the
            // operator different instructions: only the key's rule can be
            // tripped by a mode an orchestrator picked rather than a mistake.
            SecretResolveErrorKind::UnsafeSource => match permissions {
                FileSecretPermissions::ProjectedExclusive => {
                    InboundTlsError::PrivateKeyMaterialUnsafe { setting }
                }
                _ => InboundTlsError::MaterialUnsafe { setting },
            },
            _ => InboundTlsError::MaterialInvalid { setting },
        },
    )
}

fn open_material_directory(
    setting: &'static str,
    parent: Option<&Path>,
) -> Result<Dir, InboundTlsError> {
    // A bare file name has an empty parent, which is the current directory.
    let parent = match parent {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let canonical = fs::canonicalize(&parent)
        .map_err(|_| InboundTlsError::MaterialDirectoryUnavailable { setting })?;
    let directory = Dir::open_ambient_dir(&canonical, ambient_authority())
        .map_err(|_| InboundTlsError::MaterialDirectoryUnavailable { setting })?;
    let metadata = directory
        .try_clone()
        .and_then(|directory| directory.into_std_file().metadata())
        .map_err(|_| InboundTlsError::MaterialDirectoryUnavailable { setting })?;
    if !metadata.is_dir() {
        return Err(InboundTlsError::MaterialDirectoryUnavailable { setting });
    }
    if !projected_root_permissions_are_safe(&metadata) {
        return Err(InboundTlsError::MaterialDirectoryPermissions { setting });
    }
    Ok(directory)
}

/// An `axum::serve::Listener` that yields connections whose TLS handshake has
/// already completed.
///
/// Construct with [`TlsListener::wrap`]. Dropping it -- which `axum::serve`
/// does once graceful shutdown finishes -- stops accepting and abandons every
/// handshake still in progress. Established connections are unaffected; they
/// belong to the serve loop by then and drain on the usual path.
pub(crate) struct TlsListener {
    local_addr: SocketAddr,
    established: mpsc::Receiver<(InboundTlsStream, SocketAddr)>,
    _accept_task: tokio_util::task::AbortOnDropHandle<()>,
    _handshake_cancellation: DropGuard,
}

impl TlsListener {
    pub(crate) fn wrap(
        listener: TcpListener,
        tls: ListenerTls,
        limits: HandshakeLimits,
        listener_label: &'static str,
    ) -> io::Result<Self> {
        let local_addr = listener.local_addr()?;
        let (established_tx, established) = mpsc::channel(ESTABLISHED_CHANNEL_DEPTH);
        let cancellation = CancellationToken::new();
        let accept_task = tokio::spawn(accept_loop(
            listener,
            TlsAcceptor::from(tls.server_config),
            tls.identity_source,
            limits,
            listener_label,
            established_tx,
            cancellation.clone(),
        ));

        Ok(Self {
            local_addr,
            established,
            _accept_task: tokio_util::task::AbortOnDropHandle::new(accept_task),
            _handshake_cancellation: cancellation.drop_guard(),
        })
    }
}

impl fmt::Debug for TlsListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsListener")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = InboundTlsStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.established.recv().await {
            Some(established) => established,
            None => {
                // The accept task ends only when this listener is being
                // dropped, so an open listener whose channel closed means the
                // task stopped unexpectedly. `Listener::accept` has no way to
                // report that, and inventing a connection would be far worse
                // than serving none, so park: `axum::serve` still selects on
                // graceful shutdown, and the process stays killable.
                tracing::error!(
                    listen_addr = %self.local_addr,
                    "inbound TLS accept loop ended unexpectedly; this listener will serve no further connections"
                );
                std::future::pending().await
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local_addr)
    }
}

#[allow(clippy::too_many_arguments)] // Every argument is one listener-scoped decision.
async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    identity_source: Option<ClientCertIdentitySource>,
    limits: HandshakeLimits,
    listener_label: &'static str,
    established: mpsc::Sender<(InboundTlsStream, SocketAddr)>,
    cancellation: CancellationToken,
) {
    // One semaphore per accept loop, so the budget is per listener rather than
    // per process. The admin listener is how an operator reaches a deployment
    // that is already under load, and a flood on the data listener must not be
    // able to spend the budget that reaches it.
    let in_flight = Arc::new(Semaphore::new(limits.max_concurrent));

    loop {
        let (stream, peer_addr) = loop {
            tokio::select! {
                () = cancellation.cancelled() => return,
                result = listener.accept() => match result {
                    Ok(accepted) => break accepted,
                    Err(error) => {
                        if is_connection_error(&error) {
                            continue;
                        }
                        tracing::error!(
                            listener = listener_label,
                            error = %error,
                            "inbound TLS listener accept failed; retrying"
                        );
                        tokio::time::sleep(ACCEPT_BACKOFF).await;
                    }
                },
            }
        };

        // Admission is decided after the accept and without waiting.
        //
        // Waiting for a slot here -- taking the permit before the accept -- was
        // tried and rejected: a stalled accept is worse than a refused
        // connection. A connection the process never accepts is neither served
        // nor told, so it sits in the kernel's backlog until somebody else's
        // slot expires, and the gateway's own readiness and liveness probes ride
        // this same listener. Holding a slot that way costs an attacker nothing
        // but an idle socket -- no TLS, no crypto, no auth, no completed
        // handshake -- because the slot would be gating "waiting for a
        // ClientHello", which is free, rather than the handshake itself, which
        // is not.
        //
        // Sockets inside the process stay bounded all the same: a connection
        // that finds no slot is dropped right here rather than retained, and
        // dropping it closes it, so the client learns at once and can retry or
        // fail over. Saturation degrades to "some connections are refused
        // promptly" and never to "the listener stopped accepting".
        let permit = match Arc::clone(&in_flight).try_acquire_owned() {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => {
                record_handshake(listener_label, "shed");
                drop(stream);
                continue;
            }
            // Nothing closes this semaphore while the loop runs, so this is the
            // shutdown path rather than a saturation path; shedding for ever
            // would be the wrong answer to it.
            Err(TryAcquireError::Closed) => return,
        };

        let acceptor = acceptor.clone();
        let established = established.clone();
        let cancellation = cancellation.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _in_flight = InFlightGauge::new(listener_label);

            let handshake = tokio::time::timeout(limits.timeout, acceptor.accept(stream));
            let outcome = tokio::select! {
                () = cancellation.cancelled() => return,
                outcome = handshake => outcome,
            };

            match outcome {
                Ok(Ok(stream)) => {
                    record_handshake(listener_label, "established");
                    // Read the identity here, in the handshake task, rather
                    // than later on the serve loop: this task is already off
                    // the accept path and already inside the admission bound,
                    // so parsing a caller-supplied certificate is work an
                    // attacker cannot use to stall the listener. What travels
                    // onward is a bounded identity, not the chain.
                    let identity = client_identity(&stream, identity_source, listener_label);
                    let _ = established
                        .send((InboundTlsStream::new(stream, identity), peer_addr))
                        .await;
                }
                Ok(Err(error)) => {
                    record_handshake(listener_label, "failed");
                    if identity_source.is_some() {
                        record_client_certificate(
                            listener_label,
                            classify_client_certificate_failure(&error),
                        );
                    }
                }
                Err(_) => record_handshake(listener_label, "timeout"),
            }
        });
    }
}

/// A TLS connection, plus whatever identity its client certificate carried.
///
/// The identity has to ride on something that reaches `axum::serve`, and the
/// only two things that do are the listener's `Io` and its `Addr`. It rides on
/// the `Io`, so that `Addr` stays `SocketAddr` and every existing
/// `ConnectInfo<SocketAddr>` consumer -- `crate::client_ip` above all -- keeps
/// working unchanged.
///
/// It is deliberately the *identity* and not the certificate chain. A chain is
/// unbounded, caller-supplied, and would then be one careless `Debug` away from
/// a log; the identity is bounded, canonical, and is the only part any consumer
/// has a use for.
pub(crate) struct InboundTlsStream {
    inner: TlsStream<TcpStream>,
    client_identity: Option<VerifiedClientIdentity>,
}

impl InboundTlsStream {
    fn new(inner: TlsStream<TcpStream>, client_identity: Option<VerifiedClientIdentity>) -> Self {
        Self {
            inner,
            client_identity,
        }
    }
}

// Straight delegation. `TlsStream<TcpStream>` is `Unpin`, so the wrapper needs
// no projection machinery, and the vectored-write hooks are forwarded rather
// than defaulted so that wrapping the stream does not quietly cost hyper its
// scatter/gather writes.
impl AsyncRead for InboundTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for InboundTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(context, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

/// What every listener, TLS or not, tells the router about a connection.
///
/// `axum::serve` allows exactly one connect-info type, and
/// `ConnectInfo<SocketAddr>` was already spoken for. So this carries both, and
/// `crate::lifecycle::spread_inbound_connect_info` splits it back into the
/// `ConnectInfo<SocketAddr>` the rest of the gateway reads plus a separate
/// identity extension. The alternative -- changing every
/// `ConnectInfo<SocketAddr>` consumer -- would have put the peer address, which
/// rate limiting and audit attribution depend on, in the blast radius of a
/// client-certificate feature.
#[derive(Clone, Debug)]
pub(crate) struct InboundConnectInfo {
    pub(crate) peer_addr: SocketAddr,
    pub(crate) client_identity: Option<VerifiedClientIdentity>,
}

impl Connected<IncomingStream<'_, TcpListener>> for InboundConnectInfo {
    fn connect_info(stream: IncomingStream<'_, TcpListener>) -> Self {
        // A plaintext listener never requested a certificate and can never have
        // verified one, so there is nothing here to make conditional.
        Self {
            peer_addr: *stream.remote_addr(),
            client_identity: None,
        }
    }
}

impl Connected<IncomingStream<'_, TlsListener>> for InboundConnectInfo {
    fn connect_info(stream: IncomingStream<'_, TlsListener>) -> Self {
        Self {
            peer_addr: *stream.remote_addr(),
            client_identity: stream.io().client_identity.clone(),
        }
    }
}

/// Reads the identity out of a completed handshake, or records why there is
/// none.
///
/// Returns `None` in every case that is not an unambiguous, canonical,
/// in-bounds identity: no certificate, an unreadable one, one with no identity
/// of the configured kind, one with several. `None` means the connection
/// carries no certificate identity at all, which is the same position a
/// plaintext connection is in -- never a partial or provisional one.
fn client_identity(
    stream: &TlsStream<TcpStream>,
    identity_source: Option<ClientCertIdentitySource>,
    listener_label: &'static str,
) -> Option<VerifiedClientIdentity> {
    let identity_source = identity_source?;
    // Only reachable in `optional` mode: `required` refuses the handshake, so
    // this is a caller who was asked and declined, not one who slipped past.
    let Some(leaf) = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
    else {
        record_client_certificate(listener_label, "absent");
        return None;
    };

    match identity_from_certificate(leaf, identity_source) {
        Ok(identity) => {
            record_client_certificate(listener_label, "accepted");
            Some(identity)
        }
        Err(error) => {
            // The reason is a closed set of static strings, and the identity
            // that was rejected is deliberately not recorded anywhere: it is
            // caller-controlled text, and this is the one place where putting
            // it in a metric label would turn a misissued certificate into a
            // cardinality attack.
            record_client_certificate(listener_label, error.reason());
            tracing::warn!(
                listener = listener_label,
                reason = error.reason(),
                "a verified client certificate carried no usable identity; the connection has no certificate identity"
            );
            None
        }
    }
}

/// Names why a handshake carrying a client certificate failed, as one of a
/// closed set of labels.
///
/// This exists because "the handshake failed" is not an operable answer when an
/// operator is trying to find out whether revocation is working. A
/// `reason="rejected_revoked"` counter is the only evidence available that a
/// CRL is being consulted at all, and `rejected_expired_revocation_list` is the
/// only warning an operator gets that their CRL went stale and is now refusing
/// every caller.
///
/// The rustls error is classified, never rendered: `CertificateError::Other`
/// wraps an arbitrary payload, and this value is a metric label.
fn classify_client_certificate_failure(error: &io::Error) -> &'static str {
    use tokio_rustls::rustls::Error as TlsError;

    let Some(error) = error
        .get_ref()
        .and_then(|source| source.downcast_ref::<TlsError>())
    else {
        return "rejected_other";
    };

    match error {
        TlsError::NoCertificatesPresented => "rejected_absent",
        TlsError::InvalidCertificate(certificate_error) => match certificate_error {
            CertificateError::Revoked => "rejected_revoked",
            CertificateError::Expired | CertificateError::ExpiredContext { .. } => {
                "rejected_expired"
            }
            CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => {
                "rejected_not_yet_valid"
            }
            CertificateError::UnknownIssuer => "rejected_untrusted",
            CertificateError::UnknownRevocationStatus => "rejected_unknown_revocation_status",
            CertificateError::ExpiredRevocationList
            | CertificateError::ExpiredRevocationListContext { .. } => {
                "rejected_expired_revocation_list"
            }
            CertificateError::InvalidPurpose | CertificateError::InvalidPurposeContext { .. } => {
                "rejected_wrong_purpose"
            }
            CertificateError::BadEncoding => "rejected_bad_encoding",
            CertificateError::BadSignature => "rejected_bad_signature",
            _ => "rejected_other",
        },
        _ => "rejected_other",
    }
}

fn record_client_certificate(listener_label: &'static str, outcome: &'static str) {
    ::metrics::counter!(
        INBOUND_CLIENT_CERTIFICATES_TOTAL,
        "listener" => listener_label,
        "outcome" => outcome
    )
    .increment(1);
}

/// Keeps the in-flight gauge honest across every exit from a handshake task,
/// including the cancellation path that returns early.
struct InFlightGauge {
    listener_label: &'static str,
}

impl InFlightGauge {
    fn new(listener_label: &'static str) -> Self {
        ::metrics::gauge!(INBOUND_TLS_HANDSHAKES_IN_FLIGHT, "listener" => listener_label)
            .increment(1.0);
        Self { listener_label }
    }
}

impl Drop for InFlightGauge {
    fn drop(&mut self) {
        ::metrics::gauge!(INBOUND_TLS_HANDSHAKES_IN_FLIGHT, "listener" => self.listener_label)
            .decrement(1.0);
    }
}

fn record_handshake(listener_label: &'static str, outcome: &'static str) {
    ::metrics::counter!(
        INBOUND_TLS_HANDSHAKES_TOTAL,
        "listener" => listener_label,
        "outcome" => outcome
    )
    .increment(1);
}

/// Whether an `accept` error belongs to the connection rather than the listener.
///
/// Same set `axum::serve` treats as retry-immediately: the peer went away
/// between the SYN and the accept, which says nothing about the listener's
/// health and must not cost a backoff.
fn is_connection_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}

#[cfg(test)]
#[path = "inbound_tls_tests.rs"]
mod tests;
