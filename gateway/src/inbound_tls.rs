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
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use cap_std::{ambient_authority, fs::Dir};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, Semaphore, TryAcquireError},
};
use tokio_rustls::{
    rustls::{
        crypto::ring,
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
        version, ServerConfig, SupportedProtocolVersion,
    },
    server::TlsStream,
    TlsAcceptor,
};
use tokio_util::sync::{CancellationToken, DropGuard};
use zeroize::Zeroize;

use crate::{
    config::{Config, InboundTlsSettings},
    connections::secret::{
        projected_root_permissions_are_safe, read_bounded_file_secret, FileSecretPermissions,
        SecretPurpose, SecretResolveErrorKind,
    },
    metrics::{INBOUND_TLS_HANDSHAKES_IN_FLIGHT, INBOUND_TLS_HANDSHAKES_TOTAL},
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
    data: Option<Arc<ServerConfig>>,
    admin: Option<Arc<ServerConfig>>,
    min_version: Option<TlsMinVersion>,
    limits: HandshakeLimits,
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
        server_config: Option<Arc<ServerConfig>>,
        limits: HandshakeLimits,
        listener_label: &'static str,
    ) -> io::Result<Self> {
        match server_config {
            Some(server_config) => Ok(Self::Tls(TlsListener::wrap(
                listener,
                server_config,
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

fn load_server_config(
    settings: InboundTlsSettings<'_>,
) -> Result<Arc<ServerConfig>, InboundTlsError> {
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
    let mut server_config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(settings.min_version.protocol_versions())
        .map_err(|_| InboundTlsError::ProtocolVersionsUnsupported {
            setting: settings.min_version_setting,
        })?
        .with_no_client_auth()
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

    Ok(Arc::new(server_config))
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
    established: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    _accept_task: tokio_util::task::AbortOnDropHandle<()>,
    _handshake_cancellation: DropGuard,
}

impl TlsListener {
    pub(crate) fn wrap(
        listener: TcpListener,
        server_config: Arc<ServerConfig>,
        limits: HandshakeLimits,
        listener_label: &'static str,
    ) -> io::Result<Self> {
        let local_addr = listener.local_addr()?;
        let (established_tx, established) = mpsc::channel(ESTABLISHED_CHANNEL_DEPTH);
        let cancellation = CancellationToken::new();
        let accept_task = tokio::spawn(accept_loop(
            listener,
            TlsAcceptor::from(server_config),
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
    type Io = TlsStream<TcpStream>;
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

async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    limits: HandshakeLimits,
    listener_label: &'static str,
    established: mpsc::Sender<(TlsStream<TcpStream>, SocketAddr)>,
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
                    let _ = established.send((stream, peer_addr)).await;
                }
                Ok(Err(_)) => record_handshake(listener_label, "failed"),
                Err(_) => record_handshake(listener_label, "timeout"),
            }
        });
    }
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
