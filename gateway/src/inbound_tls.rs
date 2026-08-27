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
//!
//! Certificates reload while the listener serves, on the same
//! file-watch machinery `TOOLS_FILE` and `POLICY_FILE` established. The
//! `ServerConfig` a listener was started with is never replaced -- that object
//! carries the client-certificate verifier (whose CA bundle and CRL are
//! deliberately read once, at startup), the disabled session resumption of a
//! client-certificate listener, and the ALPN list -- so a reload swaps exactly
//! one thing: the set of certificate chains the config's resolver hands to new
//! handshakes, through an atomic pointer read per handshake. A connection
//! whose handshake already completed never consults the resolver again, which
//! is what makes "reload without dropping established connections" a property
//! of the shape rather than a promise of the timing: the reload path holds no
//! handle that could reach an established stream, the accept loop, or the
//! admission semaphore.

use std::{
    collections::{HashMap, HashSet},
    ffi::OsString,
    fmt, fs, io,
    net::SocketAddr,
    path::{Path, PathBuf},
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use arc_swap::ArcSwap;
use axum::{extract::connect_info::Connected, serve::IncomingStream};
use cap_std::{ambient_authority, fs::Dir};
use notify::{RecursiveMode, Watcher};
use serde_json::json;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Semaphore, TryAcquireError},
};
use tokio_rustls::{
    rustls::{
        crypto::{ring, CryptoProvider},
        pki_types::{pem::PemObject, CertificateDer, CertificateRevocationListDer, PrivateKeyDer},
        server::{
            ClientHello, NoServerSessionStorage, ResolvesServerCert, VerifierBuilderError,
            WebPkiClientVerifier,
        },
        sign::CertifiedKey,
        version, CertificateError, RootCertStore, ServerConfig, SupportedProtocolVersion,
    },
    server::TlsStream,
    TlsAcceptor,
};
use tokio_util::sync::{CancellationToken, DropGuard};
use zeroize::Zeroize;

use crate::{
    audit::{self, AuditEvent, AuditLog},
    auth::{
        client_certificate::identity_from_certificate, ClientCertIdentitySource,
        VerifiedClientIdentity,
    },
    config::{Config, InboundClientAuthSettings, InboundTlsSettings},
    connections::secret::{
        projected_root_permissions_are_safe, read_bounded_file_secret, FileSecretPermissions,
        SecretPurpose, SecretResolveErrorKind,
    },
    lifecycle::GatewayLifecycle,
    metrics::{
        INBOUND_CLIENT_CERTIFICATES_TOTAL, INBOUND_TLS_HANDSHAKES_IN_FLIGHT,
        INBOUND_TLS_HANDSHAKES_TOTAL, INBOUND_TLS_RELOADS_TOTAL,
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

/// How long the material watcher waits after a filesystem event before
/// re-reading, so a replace that surfaces as several events (write, rename,
/// metadata) causes one reload.
///
/// Same value and same shape as the `TOOLS_FILE` and `POLICY_FILE` watchers;
/// the three reload paths should not diverge on debounce discipline, because
/// an operator reasoning about "when does my change apply" should not have to
/// know which file they changed.
const TLS_MATERIAL_RELOAD_DEBOUNCE: Duration = Duration::from_millis(200);

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
/// Every variant names the setting an operator has to fix, and carries nothing
/// that is not already public: no file contents, no rustls error text. A
/// private key is the most sensitive material this process holds, and a startup
/// error is printed to stderr and frequently scraped into a log aggregator, so
/// the error type is the wrong place to be clever about diagnostics. Server
/// names from configured certificates are the one deliberate exception -- a
/// DNS SAN is broadcast in every TLS handshake that serves the chain, and an
/// operator resolving a name collision cannot act on an error that refuses to
/// name the name.
#[derive(Clone, Debug, Eq, PartialEq)]
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
    ServerNameMalformed {
        setting: &'static str,
        name: String,
    },
    ServerNameClaimedTwice {
        setting: &'static str,
        name: String,
    },
    ServerNameUnselectable {
        setting: &'static str,
        chain: usize,
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
            Self::ServerNameMalformed { setting, name } => write!(
                formatter,
                "a certificate chain in {setting} presents the server name '{name}', which this gateway cannot match: a wildcard must be the whole first label (as in '*.example.com'), and a name must not be empty, end in a root dot, or contain an empty label"
            ),
            Self::ServerNameClaimedTwice { setting, name } => write!(
                formatter,
                "two certificate chains in {setting} both claim the server name '{name}'; a client naming it must land on exactly one chain, so name it in one chain only"
            ),
            Self::ServerNameUnselectable { setting, chain } => write!(
                formatter,
                "the certificate chain at position {} in {setting} presents no DNS subject alternative name, so no server name can ever select it; only the first chain serves callers that name no recognised server, so every later chain must carry at least one DNS name",
                chain + 1
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
    /// The handle a material reload swaps chains through. Always present: a
    /// listener that terminates TLS is a listener whose certificates can
    /// expire, so there is no configuration in which watching its material
    /// would be wrong.
    reload: Arc<InboundTlsReload>,
}

/// Everything a material reload needs: the shared resolver the live
/// `ServerConfig` consults, and the owned description of the files to
/// re-read.
///
/// The material description is captured at startup, not re-parsed from the
/// environment, so a reload re-reads exactly the files startup validated --
/// the same lists, in the same order, under the same setting names -- and no
/// reload can change *which* files a listener serves, only their contents.
pub(crate) struct InboundTlsReload {
    listener_label: &'static str,
    resolver: Arc<ReloadableServerCertResolver>,
    material: TlsMaterialSettings,
}

impl InboundTlsReload {
    fn material_paths(&self) -> impl Iterator<Item = &Path> {
        self.material
            .certificate_files
            .iter()
            .chain(self.material.private_key_files.iter())
            .map(Path::new)
    }
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
            .map(|settings| load_server_config(settings, "data"))
            .transpose()?;
        let admin = config
            .admin_inbound_tls()
            .map(|settings| load_server_config(settings, "admin"))
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

    /// Starts a material watcher for every listener that terminates TLS.
    ///
    /// Mirrors the `TOOLS_FILE`/`POLICY_FILE` reload tasks: filesystem events
    /// (and SIGHUP, where it exists) trigger one debounced reload per change,
    /// each task is registered on the gateway lifecycle so shutdown cancels
    /// it, and a watcher that cannot be installed fails startup -- a
    /// deployment whose certificate files cannot be watched is a deployment
    /// whose certificates silently stop being renewable, which is not a state
    /// to run in quietly.
    pub(crate) fn spawn_material_reload_tasks_with_lifecycle(
        &self,
        audit: AuditLog,
        lifecycle: &GatewayLifecycle,
    ) -> notify::Result<()> {
        for listener in [self.data.as_ref(), self.admin.as_ref()]
            .into_iter()
            .flatten()
        {
            spawn_tls_material_reload_tasks_inner(
                listener.reload.clone(),
                audit.clone(),
                lifecycle.background_cancellation(),
                Some(lifecycle),
            )?;
        }
        Ok(())
    }

    /// The test entry point, mirroring `spawn_policy_reload_tasks`: no
    /// lifecycle, so a test's watchers live exactly as long as its runtime.
    #[cfg(test)]
    pub(crate) fn spawn_material_reload_tasks(&self, audit: AuditLog) -> notify::Result<()> {
        for listener in [self.data.as_ref(), self.admin.as_ref()]
            .into_iter()
            .flatten()
        {
            spawn_tls_material_reload_tasks_inner(
                listener.reload.clone(),
                audit.clone(),
                CancellationToken::new(),
                None,
            )?;
        }
        Ok(())
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

/// The material files of one listener as an owned description, paired with
/// the setting names that produced them.
///
/// This is the input both startup and reload validate against, and the reason
/// it exists as a type: `InboundTlsSettings` borrows from `Config`, which
/// lives on the startup stack, while a reload may run at any point in the
/// process's life. Capturing the lists here rather than re-reading the
/// environment keeps the two paths on literally one loader -- and keeps a
/// reload from ever changing which files a listener serves.
struct TlsMaterialSettings {
    certificate_setting: &'static str,
    certificate_files: Vec<String>,
    private_key_setting: &'static str,
    private_key_files: Vec<String>,
}

fn load_server_config(
    settings: InboundTlsSettings<'_>,
    listener_label: &'static str,
) -> Result<ListenerTls, InboundTlsError> {
    let material = TlsMaterialSettings {
        certificate_setting: settings.certificate_setting,
        certificate_files: settings.certificate_files.to_vec(),
        private_key_setting: settings.private_key_setting,
        private_key_files: settings.private_key_files.to_vec(),
    };
    let chains = load_certified_chains(&material)?;

    let client_verifier = settings
        .client_auth
        .map(|client_auth| load_client_verifier(client_auth, Arc::new(ring::default_provider())))
        .transpose()?;
    let identity_source = settings
        .client_auth
        .map(|client_auth| client_auth.identity_source);
    let versions = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(settings.min_version.protocol_versions())
        .map_err(|_| InboundTlsError::ProtocolVersionsUnsupported {
            setting: settings.min_version_setting,
        })?;
    let resolver = SniServerCertResolver::build(chains, settings.certificate_setting)?;
    // The one piece of this config a reload may replace. Everything the
    // builder assembled above -- verifier, versions, ALPN, resumption --
    // is startup-fixed for the life of the process; see
    // [`ReloadableServerCertResolver`].
    let resolver = Arc::new(ReloadableServerCertResolver {
        current: ArcSwap::from_pointee(resolver),
    });
    let mut server_config = match client_verifier {
        Some(client_verifier) => versions.with_client_cert_verifier(client_verifier),
        None => versions.with_no_client_auth(),
    }
    .with_cert_resolver(resolver.clone() as Arc<dyn ResolvesServerCert>);

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
        reload: Arc::new(InboundTlsReload {
            listener_label,
            resolver,
            material,
        }),
    })
}

/// Loads and validates one listener's certificate chains from its material
/// files.
///
/// This is the one loader both the startup path and the reload path run --
/// extracted from `load_server_config` when reload landed so that the two
/// cannot drift, for the same reason #332 collapsed the outbound TLS
/// construction to one site: two copies of one trust decision are two
/// opportunities to differ. Every check startup performs on certificate
/// material happens here -- the bounded, capability-confined read, the
/// permission rules, the refusal of a key concatenated into a public file,
/// parse, the key-matches-leaf pairing, and the per-chain DNS name validation
/// -- so a reload runs all of them, or none of it runs at all.
fn load_certified_chains(
    material: &TlsMaterialSettings,
) -> Result<Vec<ServerCertChain>, InboundTlsError> {
    // The two lists arrive equal in length -- `Config::from_env` rejects a
    // count mismatch as a configuration problem, and the reload re-reads the
    // same lists startup validated -- so the zip below yields exactly one key
    // per certificate chain, in the order the operator wrote them.
    let mut chains = Vec::with_capacity(material.certificate_files.len());
    for (certificate_file, private_key_file) in material
        .certificate_files
        .iter()
        .zip(material.private_key_files.iter())
    {
        let certificate_pem = read_material(
            material.certificate_setting,
            certificate_file,
            SecretPurpose::TlsCertificate,
            FileSecretPermissions::PlatformProjected,
        )?;
        // A key concatenated into the certificate file inherits the
        // certificate's permissions, and a certificate is the one piece of this
        // pair an operator reasonably mounts world-readable. Refusing the shape
        // outright is cheaper than hoping nobody ever runs
        // `cat key.pem >> cert.pem`.
        if PrivateKeyDer::from_pem_slice(certificate_pem.expose()).is_ok() {
            return Err(InboundTlsError::CertificateContainsPrivateKey {
                setting: material.certificate_setting,
            });
        }
        let certificates = CertificateDer::pem_slice_iter(certificate_pem.expose())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| InboundTlsError::MaterialInvalid {
                setting: material.certificate_setting,
            })?;
        if certificates.is_empty() {
            return Err(InboundTlsError::MaterialInvalid {
                setting: material.certificate_setting,
            });
        }

        let private_key_pem = read_material(
            material.private_key_setting,
            private_key_file,
            SecretPurpose::TlsPrivateKey,
            FileSecretPermissions::ProjectedExclusive,
        )?;
        let mut private_key = ZeroizingKey(Some(
            PrivateKeyDer::from_pem_slice(private_key_pem.expose()).map_err(|_| {
                InboundTlsError::MaterialInvalid {
                    setting: material.private_key_setting,
                }
            })?,
        ));
        drop(private_key_pem);

        // Build from an explicitly named provider rather than the process
        // default: both `ring` and `aws-lc-rs` are in this dependency graph, so
        // there is no unambiguous process default to inherit, and a listener's
        // cipher suites should not depend on which module happened to install
        // one first. The provider is shared across chains of the same listener
        // for the same reason.
        let provider = Arc::new(ring::default_provider());
        let names = chain_server_names(&certificates, material.certificate_setting)?;
        // `CertifiedKey::from_der` is the same construction `with_single_cert`
        // performs internally, including the key-matches-leaf check -- so a
        // swapped key is caught here with the same error either path reports.
        let certified_key = CertifiedKey::from_der(
            certificates,
            private_key
                .take()
                .expect("the parsed private key is taken exactly once"),
            &provider,
        )
        .map_err(|_| InboundTlsError::KeyDoesNotMatchCertificate {
            certificate_setting: material.certificate_setting,
            private_key_setting: material.private_key_setting,
        })?;
        chains.push(ServerCertChain {
            names,
            key: Arc::new(certified_key),
        });
    }

    Ok(chains)
}

/// One loaded certificate chain and the DNS names it answers to.
struct ServerCertChain {
    names: Vec<String>,
    key: Arc<CertifiedKey>,
}

/// The DNS names a server certificate chain claims, validated for matching.
///
/// Names come from the leaf's DNS SANs, read by `rustls-webpki` -- the same
/// parser rustls itself uses, as in the client-certificate identity work --
/// lower-cased for ASCII because DNS matching is defined case-insensitively.
/// The subject CN is deliberately not consulted: it is deprecated for name
/// matching, it can disagree with the SANs, and a name that decides which chain
/// serves a caller is exactly the wrong place for a second opinion. IP and URI
/// SANs are ignored because SNI carries DNS names only; a certificate whose
/// names are all IP SANs behaves as a nameless certificate, which is only
/// acceptable for the default chain.
///
/// Each name is validated into a shape the resolver's matching rules can honour
/// exactly rather than approximately: no trailing root dot, no empty labels,
/// and a wildcard only as the entire first label. Anything looser would make
/// `*.example.com` mean something RFC 6125 does not say it means.
///
/// The reader is `rustls-webpki`, and it does its own filtering: a SAN that is
/// neither a valid DNS name nor a valid wildcard name -- `a.*.b`, `*foo.b`, a
/// bare `*` -- never reaches this validator at all, so a chain carrying only
/// such names behaves as a nameless chain, which only the first chain may be.
/// That is the fail-closed direction: an unmatchable name is unclaimable
/// rather than matched by something looser than it says. The checks below are
/// defence in depth for the names webpki does let through -- a trailing root
/// dot among them.
fn chain_server_names(
    certificates: &[CertificateDer<'_>],
    setting: &'static str,
) -> Result<Vec<String>, InboundTlsError> {
    let leaf = certificates
        .first()
        .expect("the caller checked the chain is non-empty");
    let parsed = webpki::EndEntityCert::try_from(leaf)
        .map_err(|_| InboundTlsError::MaterialInvalid { setting })?;
    let mut names = Vec::new();
    for name in parsed.valid_dns_names() {
        let name = name.to_ascii_lowercase();
        validate_server_name(&name, setting)?;
        if !names.contains(&name) {
            names.push(name);
        }
    }
    Ok(names)
}

/// Accepts a single DNS name in the exact shape the resolver can match.
fn validate_server_name(name: &str, setting: &'static str) -> Result<(), InboundTlsError> {
    let malformed = |name: &str| InboundTlsError::ServerNameMalformed {
        setting,
        name: name.to_owned(),
    };
    // A wildcard is the whole first label or it is nothing this gateway
    // promises to match: `a.*.b` and `*foo.b` are refused rather than
    // half-supported, and a stray `*` in a later label is a name no client can
    // legally send.
    if let Some(suffix) = name.strip_prefix("*.") {
        return if suffix.contains('*') || !suffix.split('.').all(|label| !label.is_empty()) {
            Err(malformed(name))
        } else {
            Ok(())
        };
    }
    if name.is_empty()
        || name.contains('*')
        || name.ends_with('.')
        || name.split('.').any(|label| label.is_empty())
    {
        return Err(malformed(name));
    }
    Ok(())
}

/// Chooses the certificate chain for a connection from the client's server
/// name, with the first configured chain as the default for everything the
/// name does not select.
///
/// The selection rule is stated rather than implied: an exact name beats a
/// wildcard, and a wildcard matches exactly one label, so `*.example.com`
/// serves `a.example.com` and neither `a.b.example.com` nor `example.com`.
/// Two facts make that rule total rather than best-effort. A name can be
/// claimed twice only across chains, which startup rejects, so an exact lookup
/// is never ambiguous. And two *different* wildcards can never both match one
/// name -- a wildcard matches a name precisely when the name minus its first
/// label equals the wildcard minus `*.`, and two distinct patterns cannot both
/// equal that same remainder -- so wildcard resolution is never a
/// first-match-wins accident of ordering.
///
/// A caller that sends no server name, or a name nothing claims, gets the
/// first chain. That is the behaviour `with_single_cert` had when there was
/// only one chain, carried forward deliberately: the resolver never answers
/// `None`, because refusing the handshake is a policy decision this gateway
/// has not been asked to make, and a mis-set SNI should fail in the client's
/// certificate verification rather than in a connection reset the operator
/// cannot tell from a broken listener.
struct SniServerCertResolver {
    exact: HashMap<String, usize>,
    wildcards: HashMap<String, usize>,
    chains: Vec<Arc<CertifiedKey>>,
}

impl SniServerCertResolver {
    /// Builds the lookup tables, rejecting the two configurations whose
    /// selection could never be honest: a name claimed by two chains, and a
    /// non-first chain no name can ever select.
    fn build(chains: Vec<ServerCertChain>, setting: &'static str) -> Result<Self, InboundTlsError> {
        let mut exact = HashMap::new();
        let mut wildcards = HashMap::new();
        for (index, chain) in chains.iter().enumerate() {
            if index > 0 && chain.names.is_empty() {
                return Err(InboundTlsError::ServerNameUnselectable {
                    setting,
                    chain: index,
                });
            }
            for name in &chain.names {
                let (claimed, map) = match name.strip_prefix("*.") {
                    Some(suffix) => (suffix.to_owned(), &mut wildcards),
                    None => (name.to_owned(), &mut exact),
                };
                if map.insert(claimed.clone(), index).is_some() {
                    return Err(InboundTlsError::ServerNameClaimedTwice {
                        setting,
                        name: claimed,
                    });
                }
            }
        }
        let keys = chains.into_iter().map(|chain| chain.key).collect();
        Ok(Self {
            exact,
            wildcards,
            chains: keys,
        })
    }
}

impl ResolvesServerCert for SniServerCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(name) = client_hello.server_name() {
            let name = name.to_ascii_lowercase();
            if let Some(chain) = self.exact.get(&name) {
                return Some(Arc::clone(&self.chains[*chain]));
            }
            // A wildcard matches when everything after the caller's first label
            // is exactly the wildcard's suffix -- one label consumed, no more.
            if let Some((_, suffix)) = name.split_once('.') {
                if let Some(chain) = self.wildcards.get(suffix) {
                    return Some(Arc::clone(&self.chains[*chain]));
                }
            }
        }
        // No server name at all, or a name nothing claims: the first chain.
        // Returning `None` here instead would abort the handshake, which is a
        // policy decision this gateway has not been asked to make.
        self.chains.first().cloned()
    }
}

/// Hand-written because the derived form would print certificate chains, and a
/// chain is public material attached to keys that are not.
impl fmt::Debug for SniServerCertResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SniServerCertResolver")
            .field("chains", &self.chains.len())
            .field("exact_names", &self.exact.len())
            .field("wildcard_names", &self.wildcards.len())
            .finish()
    }
}

/// The resolver the live `ServerConfig` consults, holding the chain set
/// behind an atomic pointer so it can be replaced while the listener serves.
///
/// This is the entire reload surface, and it is deliberately this narrow. A
/// reload builds a fully validated [`SniServerCertResolver`] off the
/// handshake path and then performs one `ArcSwap` store; each new *full*
/// handshake performs one `load_full` -- an atomic read, never a lock -- and
/// resolves against that single consistent snapshot. A handshake that already
/// read a snapshot finishes against it even if the store lands mid-flight,
/// which is the per-connection equivalent of the swap boundary a replaced
/// whole-config design would draw at the accept loop, without the drawbacks:
/// the accept loop, its admission semaphore, and the in-flight handshake
/// tasks are not touched at all, and a connection whose handshake completed
/// never calls `resolve` again.
///
/// Keeping the `ServerConfig` fixed and swapping only the resolver is also
/// what preserves the startup decisions a reload must not be able to revisit:
/// the client-certificate verifier (CA bundle and CRL, read once), the
/// disabled session resumption of a client-certificate listener, the ALPN
/// list, and the protocol floor are the same objects for the life of the
/// process, because there is no code path that replaces them.
struct ReloadableServerCertResolver {
    current: ArcSwap<SniServerCertResolver>,
}

impl ResolvesServerCert for ReloadableServerCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current.load_full().resolve(client_hello)
    }
}

/// Hand-written for the same reason [`SniServerCertResolver`]'s is: the
/// derived form would print certificate chains, and a chain is public
/// material attached to keys that are not.
impl fmt::Debug for ReloadableServerCertResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReloadableServerCertResolver")
            .field("current", &self.current.load())
            .finish()
    }
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

// --- material reload ---------------------------------------------------------
//
// The shape is the `TOOLS_FILE`/`POLICY_FILE` machinery's, deliberately: a
// `notify` watcher on the material's directories feeding an unbounded channel,
// a debounce, a single reload attempt per settled change, SIGHUP alongside on
// Unix, and registration on the gateway lifecycle so shutdown cancels the
// tasks. An operator should not have to learn a second reload dialect because
// the material happens to be a certificate.

/// Re-reads, re-validates, and swaps one listener's certificate chains.
///
/// Validation is the startup path, not a copy of it: the same
/// [`load_certified_chains`] and the same [`SniServerCertResolver::build`]
/// run here, so every check startup applies -- bounded and confined reads,
/// permissions, PEM parse, the key-matches-leaf pairing, the DNS name rules,
/// duplicate-name rejection across the whole set -- decides whether the swap
/// happens. A reload that validated less than startup would be a fail-open
/// door wearing an operational convenience; two copies of a trust decision
/// drift, which is the mistake #332 removed from the outbound path and the
/// reason this function owns no validation of its own.
///
/// On any validation failure the listener keeps serving the last good chains
/// and the failure is observable three ways -- an `inbound_tls.reload_failed`
/// audit event, `inbound_tls_reloads_total{listener,outcome="rejected"}`, and
/// an error log line -- so a rejected rotation cannot look like a completed
/// one. The error payload carries [`InboundTlsError`]'s Display text, which
/// names settings and (for SNI conflicts) DNS names, both already public;
/// key bytes cannot appear in it, on the same discipline startup errors are
/// held to.
///
/// There is deliberately no retry and no schedule: the next attempt happens
/// when the files change again or SIGHUP arrives, so material that stays
/// broken costs exactly one failed attempt, not a loop.
fn reload_listener_material(reload: &InboundTlsReload, audit: &AuditLog) {
    match reload_server_chains(reload) {
        Ok(chain_count) => {
            audit.emit(AuditEvent::new(
                audit::event::INBOUND_TLS_RELOADED,
                "inbound-tls",
                "internal",
                None,
                json!({
                    "listener": reload.listener_label,
                    "certificate_setting": reload.material.certificate_setting,
                    "chain_count": chain_count,
                    "outcome": "success",
                }),
            ));
            ::metrics::counter!(
                INBOUND_TLS_RELOADS_TOTAL,
                "listener" => reload.listener_label,
                "outcome" => "accepted"
            )
            .increment(1);
            tracing::info!(
                listener = reload.listener_label,
                chain_count,
                "inbound TLS material reload accepted"
            );
        }
        Err(error) => {
            audit.emit(AuditEvent::new(
                audit::event::INBOUND_TLS_RELOAD_FAILED,
                "inbound-tls",
                "internal",
                None,
                json!({
                    "listener": reload.listener_label,
                    "certificate_setting": reload.material.certificate_setting,
                    "outcome": "failure",
                    "reason": error.to_string(),
                }),
            ));
            ::metrics::counter!(
                INBOUND_TLS_RELOADS_TOTAL,
                "listener" => reload.listener_label,
                "outcome" => "rejected"
            )
            .increment(1);
            tracing::error!(
                listener = reload.listener_label,
                error = %error,
                "inbound TLS material reload rejected; the previous certificate chains remain active"
            );
        }
    }
}

/// Validates the next chain set and, only if every startup check passes,
/// swaps it in. The store and the validation are ordered so that no state
/// other than fully-validated-new or fully-intact-old can exist.
fn reload_server_chains(reload: &InboundTlsReload) -> Result<usize, InboundTlsError> {
    let chains = load_certified_chains(&reload.material)?;
    let chain_count = chains.len();
    let resolver = SniServerCertResolver::build(chains, reload.material.certificate_setting)?;
    reload.resolver.current.store(Arc::new(resolver));
    Ok(chain_count)
}

fn spawn_tls_material_reload_tasks_inner(
    reload: Arc<InboundTlsReload>,
    audit: AuditLog,
    cancellation: CancellationToken,
    lifecycle: Option<&GatewayLifecycle>,
) -> notify::Result<()> {
    let watcher = spawn_tls_material_file_watcher(&reload, &audit, cancellation.clone())?;
    let sighup = spawn_sighup_reload_task(reload, audit, cancellation);
    if let Some(lifecycle) = lifecycle {
        lifecycle.register_background_task(watcher);
        if let Some(sighup) = sighup {
            lifecycle.register_background_task(sighup);
        }
    }
    Ok(())
}

fn spawn_tls_material_file_watcher(
    reload: &Arc<InboundTlsReload>,
    audit: &AuditLog,
    cancellation: CancellationToken,
) -> notify::Result<tokio::task::JoinHandle<()>> {
    let (sender, receiver) = mpsc::unbounded_channel();
    let mut watcher = notify::recommended_watcher(move |event| {
        let _ = sender.send(event);
    })?;
    for directory in tls_material_watch_directories(reload) {
        watcher.watch(&directory, RecursiveMode::NonRecursive)?;
    }

    Ok(tokio::spawn(tls_material_file_watch_loop(
        reload.clone(),
        audit.clone(),
        receiver,
        watcher,
        cancellation,
    )))
}

async fn tls_material_file_watch_loop(
    reload: Arc<InboundTlsReload>,
    audit: AuditLog,
    mut events: mpsc::UnboundedReceiver<notify::Result<notify::Event>>,
    _watcher: notify::RecommendedWatcher,
    cancellation: CancellationToken,
) {
    let names = tls_material_watch_names(&reload);
    loop {
        let event = tokio::select! {
            event = events.recv() => event,
            () = cancellation.cancelled() => return,
        };
        let Some(event) = event else {
            return;
        };
        if !handle_tls_material_watch_event(event, &names) {
            continue;
        }

        tokio::select! {
            () = tokio::time::sleep(TLS_MATERIAL_RELOAD_DEBOUNCE) => {}
            () = cancellation.cancelled() => return,
        }
        while let Ok(event) = events.try_recv() {
            let _ = handle_tls_material_watch_event(event, &names);
        }

        reload_listener_material(&reload, &audit);
    }
}

fn handle_tls_material_watch_event(
    event: notify::Result<notify::Event>,
    names: &HashSet<OsString>,
) -> bool {
    match event {
        Ok(event) => tls_material_reload_event(&event, names),
        Err(err) => {
            tracing::error!(error = %err, "inbound TLS material watch error");
            false
        }
    }
}

/// Whether a filesystem event could have changed the material, judged by
/// entry *name* in the watched directories rather than by full path -- the
/// same rule the `TOOLS_FILE`/`POLICY_FILE` watchers use, so a provider that
/// reports the event through a differently-spelled prefix (a symlinked
/// directory, a relative watch root) still matches. Certificate and key
/// names are operator-chosen and rarely collide; where two watched listeners
/// keep material in one directory, the cost of a name collision is one
/// redundant reload of unchanged files, not a missed one.
fn tls_material_reload_event(event: &notify::Event, names: &HashSet<OsString>) -> bool {
    !matches!(event.kind, notify::EventKind::Access(_))
        && event.paths.iter().any(|path| {
            path.file_name()
                .is_some_and(|name| names.contains(&name.to_owned()))
        })
}

/// The directory-entry names whose change can alter the material.
///
/// Two shapes have to be covered. A plain file answers to its own name, and
/// an atomic replace (`write tmp; rename`) lands on that name. A Kubernetes
/// Secret volume is different: the leaf the setting names is a relative
/// symlink into a `..data` directory, and rotation flips the `..data`
/// *symlink* -- the leaf's own directory entry never changes. So for a
/// symlinked leaf, the first component of its target is a watched name too,
/// which is what makes the kubelet flip observable. The name set is fixed at
/// watcher start, from the same paths startup validated; a volume that
/// switched from plain files to the projected shape mid-flight would need a
/// restart, and the reader's confinement rules still apply to every reload.
fn tls_material_watch_names(reload: &InboundTlsReload) -> HashSet<OsString> {
    let mut names = HashSet::new();
    for path in reload.material_paths() {
        let Some(file_name) = path.file_name() else {
            continue;
        };
        names.insert(file_name.to_owned());
        let flipped_component =
            fs::read_link(path)
                .ok()
                .and_then(|target| match target.components().next() {
                    Some(std::path::Component::Normal(first)) => Some(first.to_owned()),
                    _ => None,
                });
        if let Some(flipped) = flipped_component {
            names.insert(flipped);
        }
    }
    names
}

/// The distinct directories holding one listener's material, canonicalized.
///
/// Certificates and keys may live in different directories (and SNI lists may
/// span several), so every distinct parent is watched, non-recursively, the
/// way the single-file watchers watch their one parent.
fn tls_material_watch_directories(reload: &InboundTlsReload) -> Vec<PathBuf> {
    let mut directories = Vec::new();
    for path in reload.material_paths() {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        // Canonical so that two spellings of one directory are one watch, and
        // so events arriving through a symlinked path still carry the prefix
        // this watcher registered. A directory that cannot be resolved is
        // watched by its configured name; the reload itself reads through the
        // capability-confined reader either way.
        let resolved = fs::canonicalize(parent).unwrap_or_else(|_| parent.to_owned());
        if !directories.contains(&resolved) {
            directories.push(resolved);
        }
    }
    directories
}

#[cfg(unix)]
fn spawn_sighup_reload_task(
    reload: Arc<InboundTlsReload>,
    audit: AuditLog,
    cancellation: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    Some(tokio::spawn(async move {
        let mut sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(signal) => signal,
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "failed to register SIGHUP inbound TLS reload handler"
                );
                return;
            }
        };

        loop {
            let signal = tokio::select! {
                signal = sighup.recv() => signal,
                () = cancellation.cancelled() => return,
            };
            if signal.is_none() {
                return;
            }
            reload_listener_material(&reload, &audit);
        }
    }))
}

#[cfg(not(unix))]
fn spawn_sighup_reload_task(
    _reload: Arc<InboundTlsReload>,
    _audit: AuditLog,
    _cancellation: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    None
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
