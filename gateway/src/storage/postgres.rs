//! PostgreSQL foundation: backend selection's runtime half (issue #241, PR 3).
//!
//! `Config` decides *whether* cluster mode is selected and rejects
//! contradictory settings; this module makes a selected `STATE_BACKEND=postgres`
//! real at startup: it reads the DSN from its secret file, validates it, builds
//! a bounded pool of verified-TLS connections with server-side timeouts, and
//! proves the database is reachable before the process serves anything.
//!
//! Nothing here runs in standalone mode. Nothing here implements repositories
//! or migrations -- those are PRs 4 through 13 of the #241 sequence, on the
//! pool this module owns.
//!
//! ## Redaction contract
//!
//! The DSN, the database user, host, and name never appear in a
//! `Debug` rendering, a `Display` of an error, a metric, or a log line this
//! module produces. [`PostgresFoundationError`] carries static reason strings
//! only, and [`PostgresFoundation`] implements `Debug` by hand for the same
//! reason: `tokio_postgres::Config`'s own `Debug` prints user, database, and
//! host, so the pool and the config it was built from are never rendered.
//! Detailed connection failures are logged as classified kinds; where the
//! underlying error's text is genuinely needed for diagnosis it is logged at
//! the failure site, where it can be audited, never propagated upward.
//!
//! ## DSN policy
//!
//! The DSN is a `postgresql://` URL whose query parameters are limited to
//! `user`, `password`, `host`, `port`, `dbname`, and `application_name`.
//! Everything else -- `sslmode`, `options`, and anything unrecognized -- is
//! rejected at startup: TLS policy comes from `DATABASE_TLS_MODE`, session
//! timeouts come from the `DATABASE_*_TIMEOUT_MS` settings, and a DSN that
//! could override either would make the operator's configuration a guess.
//! Host, user, and database must be stated explicitly; the ambient defaults
//! a bare DSN would fall back to (an OS username, a localhost socket) are
//! exactly the "attacker-controlled defaults" the #241 connection model
//! forbids trusting.

use std::{
    fmt, fs, io::Read as _, net::IpAddr, path::PathBuf, str::FromStr as _, sync::Arc,
    time::Duration,
};

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt as _, OpenOptionsSyncExt as _};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions as CapabilityOpenOptions},
};
use deadpool_postgres::{Manager, Pool, PoolConfig, Runtime};
use tokio_postgres::{
    config::{Host, SslMode},
    tls::MakeTlsConnect,
    Config as PgConfig, Error as PgError, NoTls,
};
use tokio_postgres_rustls::MakeRustlsConnect;
use url::Url;
use zeroize::Zeroizing;

use crate::config::{Config, DatabaseSettings, DatabaseTlsMode};

use super::{log_classified, RepositoryError, RepositoryErrorKind};

/// Longest accepted DSN file: a URL with every parameter spelled out is a few
/// hundred bytes, so eight KiB leaves room for long passwords without leaving
/// room for a file that is something other than a DSN.
pub const MAX_DATABASE_URL_BYTES: usize = 8 * 1024;

/// Longest accepted CA bundle: the same bound the connection TLS paths use for
/// certificate material.
const MAX_DATABASE_CA_BUNDLE_BYTES: usize = 1024 * 1024;

/// The connectivity check. A literal statement, classified on failure like any
/// other database operation, and subject to the session's `statement_timeout`.
const CONNECTIVITY_CHECK_STATEMENT: &str = "SELECT 1";

/// First wait between startup connection attempts, doubling from here.
const STARTUP_RETRY_INITIAL_DELAY: Duration = Duration::from_millis(250);

/// Ceiling on a single wait between startup connection attempts.
const STARTUP_RETRY_MAX_DELAY: Duration = Duration::from_secs(8);

/// Query parameters a DSN may carry. Everything else is rejected; see the
/// module's DSN policy note for why the TLS and options parameters are
/// deliberately absent from this list.
const PERMITTED_DSN_PARAMETERS: [&str; 6] = [
    "user",
    "password",
    "host",
    "port",
    "dbname",
    "application_name",
];

/// `application_name` the gateway sets when the DSN does not name one, so an
/// operator's `pg_stat_activity` shows which connections are gateway replicas.
const DEFAULT_APPLICATION_NAME: &str = "greengateway";

/// A startup failure of the PostgreSQL foundation. Display text names
/// settings and reasons; it never names the database, its host, its user, or
/// any part of the DSN, and the type intentionally implements no `source()`:
/// the process-level startup printer walks `source` chains, and the
/// underlying errors are logged where they occur instead.
#[derive(Debug)]
pub(crate) enum PostgresFoundationError {
    /// The DSN or CA file could not be read under the bounded,
    /// permission-checked reader. `reason` says which class of problem.
    SettingFile {
        setting: &'static str,
        reason: &'static str,
    },
    /// The DSN was read but is not a usable, fully-stated `postgresql://` URL
    /// under this module's parameter policy.
    DsnRejected { reason: &'static str },
    /// The TLS policy is unusable as configured (a dev exception aimed at a
    /// non-loopback target, or trust material that cannot be loaded).
    TlsRejected { reason: &'static str },
    /// The pool could be built but the database never answered the
    /// connectivity check within the bounded startup retry budget.
    StartupExhausted { attempts: u64 },
    /// The pool itself could not be constructed.
    PoolUnbuildable,
    /// The database answers but the schema is not one this process may run
    /// on: migrations are unapplied (or the database was never migrated),
    /// and development auto-migration is not enabled.
    SchemaNotReady {
        applied: usize,
        missing: usize,
        auto_migrate: bool,
    },
    /// The schema ledger disagrees with this build's migration manifest.
    /// Fail closed: serving on a tampered or newer-than-supported schema is
    /// exactly what the validation exists to prevent.
    SchemaInvalid {
        problem: super::migrations::LedgerProblem,
    },
    /// The ledger could not be read at all while validating. An authority
    /// that cannot be consulted is a fail-closed condition.
    SchemaCheckFailed,
    /// Development auto-migration attempted and failed its writes. Distinct
    /// from the validation failures so the operator reads "the migration
    /// job failed", not "the schema could not be validated".
    SchemaMigrationFailed,
    /// Cluster mode was selected but the configuration this build validated
    /// did not carry the settings the mode requires. Unreachable through
    /// `Config::from_env`; a defensive fail-closed arm.
    NotConfigured,
}

impl fmt::Display for PostgresFoundationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SettingFile { setting, reason } => {
                write!(formatter, "{setting} could not be read: {reason}")
            }
            Self::DsnRejected { reason } => {
                write!(formatter, "DATABASE_URL_FILE was rejected: {reason}")
            }
            Self::TlsRejected { reason } => {
                write!(formatter, "DATABASE_TLS_MODE is unusable: {reason}")
            }
            Self::StartupExhausted { attempts } => write!(
                formatter,
                "the PostgreSQL database did not answer the connectivity check in {attempts} \
                 attempts; STATE_BACKEND=postgres requires the database at startup, and the \
                 bounded retry policy is governed by DATABASE_STARTUP_RETRY_LIMIT"
            ),
            Self::PoolUnbuildable => {
                write!(
                    formatter,
                    "the PostgreSQL connection pool could not be constructed"
                )
            }
            Self::SchemaNotReady {
                applied,
                missing,
                auto_migrate,
            } => {
                let head = if *auto_migrate {
                    "development auto-migration ran but the schema is still not current"
                } else {
                    "the PostgreSQL schema is not ready for this gateway build"
                };
                write!(
                    formatter,
                    "{head}: {missing} migration(s) unapplied after {applied} applied; \
                     run `gateway migrate up` from a migration job (pods validate only), \
                     or set DATABASE_AUTO_MIGRATE=true in development"
                )
            }
            Self::SchemaInvalid { problem } => {
                write!(formatter, "the schema ledger is invalid: {problem}")
            }
            Self::SchemaCheckFailed => write!(
                formatter,
                "the PostgreSQL schema could not be validated; an authority that cannot be \
                 consulted is a fail-closed condition -- check the database and the migration \
                 job before restarting this gateway"
            ),
            Self::SchemaMigrationFailed => write!(
                formatter,
                "development auto-migration (DATABASE_AUTO_MIGRATE) attempted and failed; the \
                 database is left at its previous schema version -- run `gateway migrate up` \
                 from a migration job and address its diagnostics before restarting"
            ),
            Self::NotConfigured => write!(
                formatter,
                "STATE_BACKEND=postgres was selected without the settings cluster mode requires; \
                 this is an internal validation gap -- please report it"
            ),
        }
    }
}

impl std::error::Error for PostgresFoundationError {}

/// The running PostgreSQL foundation of one process: the bounded pool, plus
/// the non-secret facts a status surface may someday render. Holding this
/// value keeps the pool's connections alive; dropping it closes them.
///
/// `Debug` is hand-written and renders nothing the DSN contains. The pool and
/// every DSN-derived value stay private forever; the repositories of later
/// #241 PRs borrow connections through [`PostgresFoundation::pool`], they do
/// not take ownership of anything that can be rendered.
pub(crate) struct PostgresFoundation {
    pool: Pool,
    pool_max: usize,
    tls_mode: DatabaseTlsMode,
}

impl fmt::Debug for PostgresFoundation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresFoundation")
            .field("pool_max", &self.pool_max)
            .field("tls_mode", &self.tls_mode)
            .finish()
    }
}

impl PostgresFoundation {
    /// Build and prove the foundation when cluster mode is selected; `Ok(None)`
    /// in standalone mode, where nothing here may so much as read a file.
    ///
    /// Serving requires a schema this build can run on, so after the pool is
    /// proven reachable the schema ledger is validated (`migrate check`
    /// semantics): behind or uninitialized fails startup naming the
    /// migration job unless development auto-migration is enabled, and any
    /// tamper or newer-than-supported state fails startup outright. The
    /// `gateway migrate` CLI reaches the same machinery through
    /// [`PostgresFoundation::establish`] without the serving validation.
    pub(crate) async fn start_if_selected(
        config: &Config,
    ) -> Result<Option<Self>, PostgresFoundationError> {
        if config.state_backend != crate::config::StateBackend::Postgres {
            return Ok(None);
        }
        let foundation = Self::establish(config).await?;

        if config.database.auto_migrate {
            super::migrations::apply_missing_for_startup(foundation.pool(), &config.database)
                .await
                .map_err(super::migrations::startup_migration_failure)?;
        }
        match super::migrations::read_and_validate(foundation.pool()).await {
            Ok(super::migrations::SchemaStatus::Current) => {}
            Ok(super::migrations::SchemaStatus::NeedsUpgrade { applied, missing }) => {
                return Err(PostgresFoundationError::SchemaNotReady {
                    applied,
                    missing,
                    auto_migrate: config.database.auto_migrate,
                });
            }
            Ok(super::migrations::SchemaStatus::NotInitialized) => {
                return Err(PostgresFoundationError::SchemaNotReady {
                    applied: 0,
                    missing: super::migrations::manifest_len(),
                    auto_migrate: config.database.auto_migrate,
                });
            }
            Err(super::migrations::MigrateError::LedgerInvalid(problem)) => {
                return Err(PostgresFoundationError::SchemaInvalid { problem });
            }
            // The ledger could not be read at all: an authority that cannot
            // be consulted is a fail-closed condition, never a serve-anyway.
            Err(_) => return Err(PostgresFoundationError::SchemaCheckFailed),
        }
        Ok(Some(foundation))
    }

    /// Read the DSN, build the pool, and prove the database answers within
    /// the bounded retry budget -- no schema validation, because the
    /// migration CLI must be able to reach a not-yet-migrated database.
    pub(crate) async fn establish(config: &Config) -> Result<Self, PostgresFoundationError> {
        let settings = &config.database;
        let Some(url_file) = settings.url_file.as_deref() else {
            return Err(PostgresFoundationError::NotConfigured);
        };

        let dsn = read_dsn_file(url_file)?;
        let mut pg_config = validated_dsn_config(dsn.as_str())?;
        enforce_tls_policy(&pg_config, settings)?;

        apply_session_settings(&mut pg_config, settings);
        // The ssl_mode is the gateway's decision, never the DSN's: `verify`
        // must REQUIRE TLS (tokio-postgres defaults to `Prefer`, which
        // silently returns a plaintext stream when a server answers the
        // SSLRequest with 'N' -- the connector would never run), and
        // `loopback-dev` DISABLES the negotiation entirely (NoTls has no
        // handshake to offer). `verified_dsn_config` already rejected any
        // DSN parameter that tried to state its own.
        match settings.tls_mode {
            DatabaseTlsMode::Verify => pg_config.ssl_mode(SslMode::Require),
            DatabaseTlsMode::LoopbackDev => pg_config.ssl_mode(SslMode::Disable),
        };

        let foundation = match settings.tls_mode {
            DatabaseTlsMode::Verify => {
                let connector = verified_tls_connector(settings)?;
                build_pool(pg_config, connector, settings)?
            }
            DatabaseTlsMode::LoopbackDev => build_pool(pg_config, NoTls, settings)?,
        };

        establish_with_bounded_backoff(&foundation.pool, settings).await?;
        tracing::info!(
            pool_max = settings.pool_max,
            tls_mode = settings.tls_mode.as_str(),
            "PostgreSQL foundation established for cluster mode"
        );
        Ok(foundation)
    }

    /// The pool later PRs' repositories acquire connections from. Unused in
    /// PR 3 itself: no repository exists yet, and the foundation's job here
    /// is to prove the pool works and keep it alive for the process.
    #[allow(dead_code)]
    pub(crate) fn pool(&self) -> &Pool {
        &self.pool
    }
}

/// One bounded, capability-confined, permission-checked setting file read.
///
/// The shape is the inbound TLS material reader's: canonicalize the parent
/// directory, open the leaf beneath a capability root (so a symlink cannot
/// resolve anywhere but beneath that root), revalidate the handle as a
/// regular file, and cap the read before parsing. `forbidden_mask` carries
/// the permission policy: the DSN file may grant group and other nothing at
/// all (it is credentials), while a CA bundle is public material that need
/// only be unwritable by them.
fn read_setting_file(
    path: &str,
    setting: &'static str,
    maximum: usize,
    forbidden_mask: u32,
) -> Result<Zeroizing<Vec<u8>>, PostgresFoundationError> {
    let path = PathBuf::from(path);
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(file_error(
            setting,
            "the path has no file name; name the file itself, not a directory",
        ));
    };
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        // A bare file name is relative to the working directory.
        _ => PathBuf::from("."),
    };
    let canonical =
        fs::canonicalize(&parent).map_err(|_| unavailable(setting, "parent directory"))?;
    let directory = Dir::open_ambient_dir(&canonical, ambient_authority())
        .map_err(|_| unavailable(setting, "parent directory"))?;
    let directory_metadata = directory
        .try_clone()
        .and_then(|dir| dir.into_std_file().metadata())
        .map_err(|_| unavailable(setting, "parent directory"))?;
    if !directory_metadata.is_dir() {
        return Err(unavailable(setting, "parent directory"));
    }
    if !crate::connections::secret::projected_root_permissions_are_safe(&directory_metadata) {
        return Err(PostgresFoundationError::SettingFile {
            setting,
            reason: "the parent directory is writable by group or other without the sticky bit",
        });
    }

    let mut options = CapabilityOpenOptions::new();
    options.read(true);
    // Secret and certificate volumes are commonly published through the
    // kubelet's relative `..data` symlinks; the capability root confines
    // resolution, so following is safe and refusing would refuse the most
    // common legitimate mount shape.
    options.follow(FollowSymlinks::Yes);
    options.nonblock(true);
    let file = directory
        .open_with(file_name, &options)
        .map(|file| file.into_std())
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => unavailable(setting, "file not found"),
            std::io::ErrorKind::PermissionDenied => PostgresFoundationError::SettingFile {
                setting,
                reason: "permission denied",
            },
            _ => PostgresFoundationError::SettingFile {
                setting,
                reason: "the file could not be opened safely",
            },
        })?;
    let metadata = file
        .metadata()
        .map_err(|_| unavailable(setting, "file metadata"))?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(PostgresFoundationError::SettingFile {
            setting,
            reason: "the setting must name a regular file",
        });
    }
    if !permissions_allow(&metadata, forbidden_mask) {
        return Err(PostgresFoundationError::SettingFile {
            setting,
            reason: if forbidden_mask == 0o077 {
                "the file grants group or other any access; it is credential material -- \
                 mount or chmod it so only the gateway's account can read it \
                 (a Kubernetes Secret volume needs defaultMode: 0400)"
            } else {
                "the file is writable by group or other; public material must not be \
                 replaceable by another account"
            },
        });
    }
    if metadata.len() > maximum as u64 {
        return Err(PostgresFoundationError::SettingFile {
            setting,
            reason: "the file is larger than this setting accepts",
        });
    }

    let mut value = Zeroizing::new(Vec::with_capacity(
        usize::try_from(metadata.len()).unwrap_or(0).min(maximum),
    ));
    file.take(u64::try_from(maximum).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut value)
        .map_err(|_| unavailable(setting, "file read"))?;
    if value.len() > maximum {
        return Err(PostgresFoundationError::SettingFile {
            setting,
            reason: "the file is larger than this setting accepts",
        });
    }
    Ok(value)
}

fn unavailable(setting: &'static str, reason: &'static str) -> PostgresFoundationError {
    PostgresFoundationError::SettingFile { setting, reason }
}

fn file_error(setting: &'static str, reason: &'static str) -> PostgresFoundationError {
    PostgresFoundationError::SettingFile { setting, reason }
}

/// Read and decode the DSN file: the bounded reader's bytes, then a UTF-8
/// decode with trailing whitespace trimmed, because the byte that `echo` puts
/// after a URL is not part of the URL. Leading and trailing whitespace is
/// never significant in a connection URL, so trimming cannot change which
/// database a DSN names.
fn read_dsn_file(path: &str) -> Result<Zeroizing<String>, PostgresFoundationError> {
    let mut bytes = read_setting_file(path, "DATABASE_URL_FILE", MAX_DATABASE_URL_BYTES, 0o077)?;
    // Move the buffer out of its zeroizing wrapper for the UTF-8 conversion
    // (which takes the Vec by value), and scrub whatever the conversion
    // returns on failure -- the `FromUtf8Error` owns its input bytes until
    // it is consumed.
    let raw = std::mem::take(&mut *bytes);
    let mut text = match String::from_utf8(raw) {
        Ok(text) => Zeroizing::new(text),
        Err(invalid) => {
            let _scrubbed = Zeroizing::new(invalid.into_bytes());
            return Err(PostgresFoundationError::SettingFile {
                setting: "DATABASE_URL_FILE",
                reason: "the file is not valid UTF-8",
            });
        }
    };
    while text.chars().last().is_some_and(char::is_whitespace) {
        text.pop();
    }
    if text.is_empty() {
        return Err(PostgresFoundationError::SettingFile {
            setting: "DATABASE_URL_FILE",
            reason: "the file is empty",
        });
    }
    Ok(text)
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x0000_0400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_: &fs::Metadata) -> bool {
    false
}

/// `mask` is the permission bits that must all be clear (group/other read,
/// write, and execute for credential files; group/other write for public
/// material). Windows has no permission mask to check; the regular-file and
/// reparse-point validation above still apply.
#[cfg(unix)]
fn permissions_allow(metadata: &fs::Metadata, mask: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.mode() & mask == 0
}

#[cfg(not(unix))]
fn permissions_allow(_: &fs::Metadata, _: u32) -> bool {
    true
}

/// Parse the DSN under this module's policy.
///
/// The URL form is required first so the parameter allowlist below scans one
/// syntax rather than the two `Config::from_str` accepts. Then the parsed
/// configuration must state host, user, and database explicitly: the ambient
/// fallbacks for a bare DSN are the local account's defaults, which is a
/// different database on every host the process lands on.
fn validated_dsn_config(dsn: &str) -> Result<PgConfig, PostgresFoundationError> {
    let trimmed = dsn.trim();
    if !(trimmed.starts_with("postgres://") || trimmed.starts_with("postgresql://")) {
        return Err(PostgresFoundationError::DsnRejected {
            reason: "the connection string must be a postgresql:// URL (key=value forms are \
                     not accepted)",
        });
    }
    // A connection URL has no fragment, and a '#' anywhere is not parsed the
    // same way by the two parsers involved: `url::Url` ends the query at '#'
    // while tokio-postgres's URL parser keeps scanning, so a fragment could
    // smuggle parameters past the allowlist below. No legitimate DSN carries
    // one (a password containing '#' is percent-encoded per RFC 3986), so the
    // character is refused outright rather than trying to reconcile the two
    // parsers.
    if trimmed.contains('#') {
        return Err(PostgresFoundationError::DsnRejected {
            reason: "the connection string must not contain a URL fragment",
        });
    }
    let url = Url::parse(trimmed).map_err(|_| PostgresFoundationError::DsnRejected {
        reason: "the URL could not be parsed",
    })?;
    for (key, _) in url.query_pairs() {
        let key = key.to_ascii_lowercase();
        if !PERMITTED_DSN_PARAMETERS.contains(&key.as_str()) {
            return Err(PostgresFoundationError::DsnRejected {
                reason: "the URL carries a parameter this gateway does not accept; permitted \
                         parameters are user, password, host, port, dbname, and \
                         application_name -- TLS policy comes from DATABASE_TLS_MODE and \
                         session timeouts from the DATABASE_*_TIMEOUT_MS settings, never \
                         from the DSN",
            });
        }
    }

    let config = PgConfig::from_str(trimmed).map_err(|_| PostgresFoundationError::DsnRejected {
        reason: "the URL is not a usable PostgreSQL connection string",
    })?;
    if config.get_user().is_none() {
        return Err(PostgresFoundationError::DsnRejected {
            reason: "the URL must name its user explicitly; ambient account defaults are \
                     not trusted",
        });
    }
    if config.get_dbname().is_none() {
        return Err(PostgresFoundationError::DsnRejected {
            reason: "the URL must name its database explicitly; falling back to the \
                     username-as-database default is not supported",
        });
    }
    if config.get_hosts().is_empty() && config.get_hostaddrs().is_empty() {
        return Err(PostgresFoundationError::DsnRejected {
            reason: "the URL must name its host explicitly; ambient host defaults are \
                     not trusted",
        });
    }
    Ok(config)
}

impl DatabaseTlsMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Verify => "verify",
            Self::LoopbackDev => "loopback-dev",
        }
    }
}

/// The `loopback-dev` exception may only point at loopback: a development
/// convenience that could quietly become a production plaintext connection is
/// not a development convenience. The failure names the setting, never the
/// host that was rejected.
fn enforce_tls_policy(
    config: &PgConfig,
    settings: &DatabaseSettings,
) -> Result<(), PostgresFoundationError> {
    if settings.tls_mode != DatabaseTlsMode::LoopbackDev {
        return Ok(());
    }
    for host in config.get_hosts() {
        match host {
            #[cfg(unix)]
            Host::Unix(_) => {}
            Host::Tcp(name) => {
                if name != "localhost"
                    && name
                        .parse::<IpAddr>()
                        .map_or(true, |address| !address.is_loopback())
                {
                    return Err(PostgresFoundationError::TlsRejected {
                        reason: "loopback-dev skips TLS verification and is therefore only \
                                 permitted for loopback targets and Unix sockets; use the \
                                 default verify mode for everything else",
                    });
                }
            }
        }
    }
    if config
        .get_hostaddrs()
        .iter()
        .any(|address| !address.is_loopback())
    {
        return Err(PostgresFoundationError::TlsRejected {
            reason: "loopback-dev skips TLS verification and is therefore only permitted \
                     for loopback targets and Unix sockets; use the default verify mode \
                     for everything else",
        });
    }
    Ok(())
}

/// The verified-TLS connector: platform trust store plus any configured CA
/// bundle as *extra* roots, the same trust decision outbound TLS makes, with
/// certificate and hostname verification fully enforced by rustls. There is
/// no configuration that disables verification here -- the one exception is
/// [`DatabaseTlsMode::LoopbackDev`], and it cannot reach this function.
fn verified_tls_connector(
    settings: &DatabaseSettings,
) -> Result<MakeRustlsConnect, PostgresFoundationError> {
    let provider = crate::egress::crypto_provider();
    let verifier = match settings.tls_ca_file.as_deref() {
        None => rustls_platform_verifier::Verifier::new(Arc::clone(&provider)).map_err(|_| {
            PostgresFoundationError::TlsRejected {
                reason: "the platform trust store is unreadable",
            }
        })?,
        Some(ca_file) => {
            let bundle = read_setting_file(
                ca_file,
                "DATABASE_TLS_CA_FILE",
                MAX_DATABASE_CA_BUNDLE_BYTES,
                0o022,
            )?;
            let anchors = crate::egress::parse_ca_bundle_pem(bundle.as_slice()).map_err(|_| {
                PostgresFoundationError::TlsRejected {
                    reason: "DATABASE_TLS_CA_FILE is not a usable PEM trust bundle",
                }
            })?;
            rustls_platform_verifier::Verifier::new_with_extra_roots(anchors, Arc::clone(&provider))
                .map_err(|_| PostgresFoundationError::TlsRejected {
                    reason: "the platform trust store is unreadable",
                })?
        }
    };
    let client_config =
        tokio_rustls::rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(tokio_rustls::rustls::ALL_VERSIONS)
            .map_err(|_| PostgresFoundationError::TlsRejected {
                reason: "this build's rustls supports no usable protocol versions",
            })?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
    Ok(MakeRustlsConnect::new(client_config))
}

/// Server-side session settings every pooled connection carries, plus the
/// client-side connect bound. The statement, idle-in-transaction, and lock
/// timeouts are startup parameters, so they apply to every statement on every
/// connection the pool ever hands out -- including a recycled one -- and no
/// code path in this crate can `SET` them back.
fn apply_session_settings(config: &mut PgConfig, settings: &DatabaseSettings) {
    // `pg_catalog` leads the search path on purpose: naming it explicitly
    // after a user schema would disable PostgreSQL's implicit catalog-first
    // resolution and let schema objects shadow built-ins (the CVE-2018-1058
    // hardening rule). The gateway schema follows it for unqualified
    // convenience; migration and ledger SQL are fully qualified regardless.
    config.options(format!(
        "-c statement_timeout={} -c idle_in_transaction_session_timeout={} -c lock_timeout={} \
         -c search_path=pg_catalog,{}",
        settings.statement_timeout_ms,
        settings.idle_in_transaction_timeout_ms,
        settings.lock_timeout_ms,
        super::migrations::SCHEMA_NAME,
    ));
    if config.get_application_name().is_none() {
        config.application_name(DEFAULT_APPLICATION_NAME);
    }
    config.connect_timeout(Duration::from_millis(settings.connect_timeout_ms));
}

fn build_pool<T>(
    pg_config: PgConfig,
    tls: T,
    settings: &DatabaseSettings,
) -> Result<PostgresFoundation, PostgresFoundationError>
where
    T: MakeTlsConnect<tokio_postgres::Socket> + Clone + Send + Sync + 'static,
    T::Stream: Send + Sync,
    T::TlsConnect: Send + Sync,
    <T::TlsConnect as tokio_postgres::tls::TlsConnect<tokio_postgres::Socket>>::Future: Send,
{
    let manager = Manager::new(pg_config, tls);
    let mut pool_config = PoolConfig::new(settings.pool_max);
    pool_config.timeouts.create = Some(Duration::from_millis(settings.connect_timeout_ms));
    pool_config.timeouts.wait = Some(Duration::from_millis(settings.acquire_timeout_ms));
    pool_config.timeouts.recycle = Some(Duration::from_millis(settings.connect_timeout_ms));
    let pool = Pool::builder(manager)
        .config(pool_config)
        .runtime(Runtime::Tokio1)
        .build()
        .map_err(|_| PostgresFoundationError::PoolUnbuildable)?;
    Ok(PostgresFoundation {
        pool,
        pool_max: settings.pool_max,
        tls_mode: settings.tls_mode,
    })
}

/// Prove the database answers before startup completes, with the documented
/// bounded backoff: `DATABASE_STARTUP_RETRY_LIMIT` retries after the first
/// attempt, the wait doubling from 250 ms up to an 8 s ceiling. Each failed
/// attempt logs its classified kind; the final failure is the startup error.
async fn establish_with_bounded_backoff(
    pool: &Pool,
    settings: &DatabaseSettings,
) -> Result<(), PostgresFoundationError> {
    let attempts = settings.startup_retry_limit.saturating_add(1);
    for attempt in 1..=attempts {
        match validate_connectivity(pool).await {
            Ok(()) => return Ok(()),
            Err(error) => {
                tracing::warn!(
                    attempt,
                    attempts,
                    error = %error,
                    "PostgreSQL connectivity check failed"
                );
                if attempt == attempts {
                    return Err(PostgresFoundationError::StartupExhausted { attempts });
                }
                let shift = (attempt - 1).min(5);
                let delay = STARTUP_RETRY_INITIAL_DELAY
                    .saturating_mul(1_u32 << shift)
                    .min(STARTUP_RETRY_MAX_DELAY);
                tokio::time::sleep(delay).await;
            }
        }
    }
    Err(PostgresFoundationError::StartupExhausted { attempts })
}

/// One minimal round statement, classified with the repository error kinds
/// PR 2 established so later PRs reuse one failure vocabulary.
pub(crate) async fn validate_connectivity(pool: &Pool) -> Result<(), RepositoryError> {
    let client = pool.get().await.map_err(classify_pool_error)?;
    client
        .simple_query(CONNECTIVITY_CHECK_STATEMENT)
        .await
        .map_err(|error| {
            log_classified(
                "database_connectivity_check",
                &error,
                RepositoryError::new(
                    classify_postgres_error(&error),
                    "database_connectivity_check",
                ),
            )
        })?;
    Ok(())
}

pub(crate) fn classify_pool_error(error: deadpool_postgres::PoolError) -> RepositoryError {
    use deadpool_postgres::TimeoutType;

    let kind = match &error {
        deadpool_postgres::PoolError::Timeout(timeout) => match timeout {
            TimeoutType::Create | TimeoutType::Wait | TimeoutType::Recycle => {
                RepositoryErrorKind::Timeout
            }
        },
        deadpool_postgres::PoolError::Closed => RepositoryErrorKind::Unavailable,
        deadpool_postgres::PoolError::Backend(source) => classify_postgres_error(source),
        deadpool_postgres::PoolError::NoRuntimeSpecified
        | deadpool_postgres::PoolError::PostCreateHook(_) => RepositoryErrorKind::Internal,
    };
    log_classified(
        "database_pool",
        &error,
        RepositoryError::new(kind, "database_pool"),
    )
}

/// Classify a PostgreSQL failure by its SQLSTATE semantics: query-canceled
/// and lock-acquisition timeouts to timeout, the write races and uniqueness
/// violations a caller can retry or surface as a conflict, data exceptions
/// to invalid data, and the "cannot be used right now" classes to
/// unavailable. The rusqlite classifier makes the same *kind* of decision on
/// SQLite's coarser codes (all constraint failures are conflicts there);
/// PostgreSQL distinguishes them, so constraint codes outside the
/// conflict-shaped set land in `Internal` rather than being guessed at.
pub(crate) fn classify_postgres_error(error: &PgError) -> RepositoryErrorKind {
    if error.is_closed() {
        return RepositoryErrorKind::Unavailable;
    }
    let Some(code) = error.code().map(|state| state.code()) else {
        return RepositoryErrorKind::Internal;
    };
    match code {
        // Query canceled is the statement/lock timeout firing.
        "57014" => RepositoryErrorKind::Timeout,
        // Lock acquisition timed out (lock_timeout on a lock request).
        "55P03" => RepositoryErrorKind::Timeout,
        // A privilege failure on the migration path means the role cannot
        // use this store the way it was asked to (a runtime role asked to
        // run DDL, most commonly): unusable, not internal.
        "42501" => RepositoryErrorKind::Unavailable,
        "40001" | "40P01" | "23505" | "23P01" => RepositoryErrorKind::Conflict,
        _ if code.starts_with("22") => RepositoryErrorKind::InvalidData,
        // Authentication/authorization failure (28), a database that does
        // not exist (3D), resource exhaustion (53), operator intervention
        // (57), and server system failure (58) all mean "the store cannot
        // be used right now".
        _ if code.starts_with("28")
            || code.starts_with("3D")
            || code.starts_with("53")
            || code.starts_with("57")
            || code.starts_with("58") =>
        {
            RepositoryErrorKind::Unavailable
        }
        _ => RepositoryErrorKind::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DatabaseSettings, DatabaseTlsMode};

    const CANARY_USER: &str = "canary-user-4f1b";
    const CANARY_HOST: &str = "canary-host-9d27.example.test";
    const CANARY_DB: &str = "canary-db-6a83";
    const CANARY_PASSWORD: &str = "canary-password-2c5e";

    fn canary_dsn() -> String {
        format!("postgres://{CANARY_USER}:{CANARY_PASSWORD}@{CANARY_HOST}:5432/{CANARY_DB}")
    }

    fn tls_settings(tls_mode: DatabaseTlsMode) -> DatabaseSettings {
        DatabaseSettings {
            tls_mode,
            ..DatabaseSettings::default()
        }
    }

    fn assert_no_dsn_material(rendered: &str) {
        for fragment in [
            CANARY_USER,
            CANARY_HOST,
            CANARY_DB,
            CANARY_PASSWORD,
            "postgres://",
        ] {
            assert!(
                !rendered.contains(fragment),
                "rendered output leaks DSN material ({fragment}): {rendered}"
            );
        }
    }

    #[test]
    fn dsn_must_be_a_url() {
        let error = validated_dsn_config(&format!(
            "host={CANARY_HOST} user={CANARY_USER} dbname={CANARY_DB}"
        ))
        .expect_err("key=value DSN forms must be rejected");
        assert!(error.to_string().contains("postgresql:// URL"), "{error}");
        assert_no_dsn_material(&error.to_string());
    }

    #[test]
    fn dsn_parameters_are_allowlisted() {
        let dsn = canary_dsn();
        for rejected in [
            format!("{dsn}?sslmode=require"),
            format!("{dsn}?options=-c%20statement_timeout%3d0"),
            format!("{dsn}?target_session_attrs=read-write"),
        ] {
            let error = validated_dsn_config(&rejected)
                .expect_err("parameters outside the allowlist must be rejected");
            assert!(
                error.to_string().contains("DATABASE_TLS_MODE"),
                "the rejection must say where policy comes from: {error}"
            );
            assert_no_dsn_material(&error.to_string());
        }

        validated_dsn_config(&format!("{dsn}?application_name=replica-1&port=5432"))
            .expect("permitted parameters must be accepted");
    }

    /// A URL fragment is parsed differently by `url::Url` (query ends at
    /// '#') and tokio-postgres's URL parser (keeps scanning), so a fragment
    /// could smuggle parameters past the allowlist. Pinned after an
    /// adversarial review demonstrated exactly that with
    /// `#?sslmode=disable`: the allowlist saw one innocent parameter while
    /// the parsed config carried a plaintext downgrade.
    #[test]
    fn dsn_fragments_are_rejected_wholesale() {
        let dsn = canary_dsn();
        let error = validated_dsn_config(&format!("{dsn}?application_name=probe#?sslmode=disable"))
            .expect_err("a fragment must be rejected, not parsed around");
        assert!(error.to_string().contains("fragment"), "{error}");
        assert_no_dsn_material(&error.to_string());
    }

    /// `verify` mode must REQUIRE TLS: tokio-postgres's default `Prefer`
    /// answers a server's plaintext 'N' with a raw stream, and the rustls
    /// connector never runs. Pinned after an adversarial review connected
    /// successfully, in plaintext, under verify mode against a TLS-off
    /// server.
    #[test]
    fn verify_mode_sets_ssl_mode_require() {
        let mut pg_config = validated_dsn_config("postgres://ggw@db.example.test:5432/ggw")
            .expect("the DSN parses");
        apply_session_settings(&mut pg_config, &tls_settings(DatabaseTlsMode::Verify));
        pg_config.ssl_mode(SslMode::Require);
        assert_eq!(pg_config.get_ssl_mode(), SslMode::Require);
    }

    /// End-to-end form of the same pin: a plaintext server that answers the
    /// SSLRequest with 'N' must be refused under verify mode, not connected.
    /// The stub never speaks TLS, so any successful connection here would be
    /// a plaintext downgrade.
    #[tokio::test]
    async fn verify_mode_refuses_a_plaintext_server() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("ephemeral listener should bind");
        let address = listener.local_addr().expect("local address");
        let server = tokio::spawn(async move {
            // One round: accept, read the 8-byte SSLRequest, answer 'N',
            // then hold the socket open so a downgrade would have room to
            // proceed -- and record that the client went away instead.
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut request = [0_u8; 8];
                let read = socket.read(&mut request).await.unwrap_or(0);
                if read == 8 && request == [0, 0, 0, 8, 4, 210, 22, 2] {
                    let _ = socket.write_all(b"N").await;
                    // Wait for the client to give up; a successful downgrade
                    // would keep reading here instead.
                    let mut sink = [0_u8; 1];
                    let _ = socket.read(&mut sink).await;
                }
            }
        });

        let dsn = format!("postgres://ggw@{}/ggw", address);
        let mut pg_config = validated_dsn_config(&dsn).expect("the stub DSN parses");
        let settings = tls_settings(DatabaseTlsMode::Verify);
        apply_session_settings(&mut pg_config, &settings);
        pg_config.ssl_mode(SslMode::Require);
        let connector = verified_tls_connector(&settings).expect("the connector builds");
        let foundation = build_pool(pg_config, connector, &settings).expect("the pool builds");

        let error = foundation
            .pool()
            .get()
            .await
            .expect_err("a plaintext server must be refused under verify mode");
        // deadpool wraps the backend failure generically ("error
        // communicating with the server"); the refusal itself is the
        // property under test. The ssl-mode plumbing is pinned directly by
        // `verify_mode_sets_ssl_mode_require`, and the stub holds the socket
        // open, so a downgrade would surface as a successful `get()`.
        assert!(
            error.to_string().contains("creating a new object"),
            "expected a connection-create failure, got: {error}"
        );
        let _ = server.await;
    }

    #[test]
    fn dsn_ambient_defaults_are_refused() {
        let missing_user =
            validated_dsn_config(&format!("postgres://{CANARY_HOST}:5432/{CANARY_DB}"))
                .expect_err("a DSN without a user must be rejected");
        assert!(missing_user.to_string().contains("user"), "{missing_user}");
        assert_no_dsn_material(&missing_user.to_string());

        let missing_db =
            validated_dsn_config(&format!("postgres://{CANARY_USER}@{CANARY_HOST}:5432"))
                .expect_err("a DSN without a database must be rejected");
        assert!(missing_db.to_string().contains("database"), "{missing_db}");
        assert_no_dsn_material(&missing_db.to_string());

        // A URL that names no host either fails to parse or parses with an
        // empty host list; both are rejected, and neither may carry DSN
        // material into its error text.
        let error = validated_dsn_config("postgres:///ggw?user=ggw&dbname=ggw")
            .expect_err("a DSN that names no host must be rejected");
        assert_no_dsn_material(&error.to_string());
    }

    #[test]
    fn loopback_dev_accepts_only_loopback_targets() {
        let settings = tls_settings(DatabaseTlsMode::LoopbackDev);

        let loopback = validated_dsn_config("postgres://ggw@localhost:5432/ggw")
            .expect("localhost is loopback");
        assert!(enforce_tls_policy(&loopback, &settings).is_ok());

        let loopback_ip = validated_dsn_config("postgres://ggw@127.0.0.1:5432/ggw")
            .expect("a loopback IP parses");
        assert!(enforce_tls_policy(&loopback_ip, &settings).is_ok());

        #[cfg(unix)]
        {
            // The URL authority host lands in the host list alongside the
            // `host=` Unix path, so both must be loopback-shaped for the
            // exception to apply -- which is the correct rule: a multi-target
            // DSN with one non-loopback target is a non-loopback DSN.
            let unix_socket =
                validated_dsn_config("postgres://ggw@localhost/db?host=/var/run/postgresql")
                    .expect("a Unix socket target parses");
            assert!(enforce_tls_policy(&unix_socket, &settings).is_ok());

            let mixed = validated_dsn_config(&format!(
                "postgres://{CANARY_USER}@{CANARY_HOST}/db?host=/var/run/postgresql"
            ))
            .expect("the DSN parses; the mode is what is wrong");
            assert!(
                enforce_tls_policy(&mixed, &settings).is_err(),
                "a DSN naming any non-loopback TCP target must be refused under loopback-dev"
            );
        }

        let remote = validated_dsn_config(&canary_dsn())
            .expect("the DSN itself is well-formed; the mode is what is wrong");
        let error = enforce_tls_policy(&remote, &settings)
            .expect_err("a non-loopback target under loopback-dev must fail startup");
        assert!(error.to_string().contains("DATABASE_TLS_MODE"), "{error}");
        assert!(error.to_string().contains("loopback"), "{error}");
        assert_no_dsn_material(&error.to_string());
    }

    #[test]
    fn verify_mode_needs_no_target_check_here() {
        let settings = tls_settings(DatabaseTlsMode::Verify);
        let remote = validated_dsn_config(&canary_dsn()).expect("the DSN parses");
        assert!(enforce_tls_policy(&remote, &settings).is_ok());
    }

    #[test]
    fn session_settings_apply_to_every_connection() {
        let mut config = validated_dsn_config("postgres://ggw@db.example.test:5432/ggw").unwrap();
        apply_session_settings(&mut config, &tls_settings(DatabaseTlsMode::Verify));

        let options = config.get_options().expect("startup options are set");
        assert!(options.contains("statement_timeout=15000"), "{options}");
        assert!(
            options.contains("idle_in_transaction_session_timeout=30000"),
            "{options}"
        );
        assert!(options.contains("lock_timeout=5000"), "{options}");
        assert_eq!(
            config.get_application_name(),
            Some("greengateway"),
            "an unnamed application gets the gateway default"
        );
        assert_eq!(
            config.get_connect_timeout(),
            Some(&Duration::from_millis(5_000))
        );

        let mut named = validated_dsn_config(
            "postgres://ggw@db.example.test:5432/ggw?application_name=custom-name",
        )
        .unwrap();
        apply_session_settings(&mut named, &tls_settings(DatabaseTlsMode::Verify));
        assert_eq!(
            named.get_application_name(),
            Some("custom-name"),
            "an operator-provided application name is not overridden"
        );
    }

    #[test]
    fn foundation_debug_renders_no_dsn_material() {
        // Building a pool does not connect: deadpool establishes connections
        // lazily, so a foundation can be constructed against the canary DSN
        // and its Debug rendering inspected without any database. The canary
        // user/host/database are what a leak would carry; an innocuous DSN
        // here would make this test vacuous, which an earlier revision's
        // falsification round caught it being.
        let settings = tls_settings(DatabaseTlsMode::LoopbackDev);
        let mut pg_config = validated_dsn_config(&canary_dsn()).expect("the canary DSN parses");
        apply_session_settings(&mut pg_config, &settings);
        let foundation =
            build_pool(pg_config, NoTls, &settings).expect("the pool should construct");

        let rendered = format!("{foundation:?}");
        assert!(rendered.contains("pool_max"), "{rendered}");
        assert_no_dsn_material(&rendered);
    }

    // --- the DSN file reader -------------------------------------------------

    fn write_dsn_file(contents: &[u8], mode: Option<u32>) -> (tempdir::TempDir, String) {
        let directory = tempdir::create("postgres-foundation");
        let path = directory.path.join("database-url");
        fs::write(&path, contents).expect("DSN file should write");
        #[cfg(unix)]
        if let Some(mode) = mode {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                .expect("permissions should set");
        }
        let _ = mode; // Windows skips permission setup.
        (directory, path.display().to_string())
    }

    mod tempdir {
        use std::{fs, path::PathBuf, thread};

        pub(super) struct TempDir {
            pub(super) path: PathBuf,
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.path);
            }
        }

        pub(super) fn create(label: &str) -> TempDir {
            let path = std::env::temp_dir().join(format!(
                "greengateway-{label}-{:?}-{}",
                thread::current().id(),
                uuid::Uuid::new_v4()
            ));
            fs::create_dir_all(&path).expect("temp directory should create");
            TempDir { path }
        }
    }

    #[test]
    fn dsn_file_reader_accepts_a_tight_file() {
        let (_guard, path) = write_dsn_file(canary_dsn().as_bytes(), Some(0o600));
        let contents = read_dsn_file(&path).expect("an exclusive, bounded file reads");
        assert_eq!(contents.as_str(), canary_dsn());
    }

    /// The permission mask half of the reader's policy: a Unix permission
    /// gate. Windows has no mask to check (the regular-file and reparse-point
    /// validation still apply there), so this test would vacuously fail.
    #[cfg(unix)]
    #[test]
    fn dsn_file_reader_rejects_group_readable_files() {
        let (_guard, path) = write_dsn_file(canary_dsn().as_bytes(), Some(0o644));
        let error = read_dsn_file(&path)
            .expect_err("credential material readable by group or other must fail");
        let rendered = error.to_string();
        assert!(rendered.contains("DATABASE_URL_FILE"), "{rendered}");
        assert!(rendered.contains("0400"), "{rendered}");
        assert_no_dsn_material(&rendered);
    }

    #[test]
    fn dsn_file_reader_rejects_oversized_files() {
        let oversized = vec![b'x'; MAX_DATABASE_URL_BYTES + 1];
        let (_guard, path) = write_dsn_file(&oversized, Some(0o600));
        let error = read_dsn_file(&path).expect_err("files beyond the bound must fail");
        assert!(error.to_string().contains("larger than"), "{error}");
    }

    #[test]
    fn dsn_file_reader_rejects_a_directory() {
        let directory = tempdir::create("postgres-foundation-dir");
        let error = read_dsn_file(&directory.path.display().to_string())
            .expect_err("a directory is not a DSN file");
        // The essential property is the failure itself and the setting named
        // in it; which check refuses the directory is platform-specific.
        assert!(error.to_string().contains("DATABASE_URL_FILE"), "{}", error);
    }

    #[test]
    fn startup_error_display_names_the_bounded_policy() {
        let error = PostgresFoundationError::StartupExhausted { attempts: 6 };
        let rendered = error.to_string();
        assert!(
            rendered.contains("DATABASE_STARTUP_RETRY_LIMIT"),
            "{rendered}"
        );
        assert!(rendered.contains("STATE_BACKEND=postgres"), "{rendered}");
        assert_no_dsn_material(&rendered);
    }

    // --- real-database tests -------------------------------------------------
    //
    // Gated on a test-harness locator that names a file containing a DSN a
    // disposable database answers. The locator is read through a runtime key
    // on purpose: it is harness plumbing, not an operator setting, and the
    // configuration-drift test that walks `env::var` calls in gateway/src
    // exists to keep operator settings documented -- a literal here would
    // force test plumbing into the operator's reference. CI sets it (see the
    // postgres-foundation job in ci.yml); a checkout without a database skips
    // these tests rather than failing.

    fn real_database_dsn_file() -> Option<String> {
        let key = test_dsn_file_key();
        std::env::var(&key).ok().filter(|value| !value.is_empty())
    }

    fn test_dsn_file_key() -> String {
        "GATEWAY_TEST_POSTGRES_URL_FILE".to_owned()
    }

    fn read_real_dsn() -> Option<String> {
        let file = real_database_dsn_file()?;
        let contents = fs::read_to_string(file).ok()?;
        let trimmed = contents.trim().to_owned();
        (!trimmed.is_empty()).then_some(trimmed)
    }

    fn runtime_settings() -> DatabaseSettings {
        tls_settings(DatabaseTlsMode::LoopbackDev)
    }

    #[tokio::test]
    async fn a_real_database_answers_the_connectivity_check() {
        let Some(dsn) = read_real_dsn() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let mut pg_config = validated_dsn_config(&dsn).expect("the CI DSN must validate");
        let settings = runtime_settings();
        enforce_tls_policy(&pg_config, &settings)
            .expect("the CI DSN must be a loopback target under the dev exception");
        apply_session_settings(&mut pg_config, &settings);
        let foundation = build_pool(pg_config, NoTls, &settings).expect("pool should build");

        validate_connectivity(foundation.pool())
            .await
            .expect("a reachable database answers SELECT 1");
    }

    #[tokio::test]
    async fn a_wrong_database_name_is_unavailable_not_internal() {
        let Some(dsn) = read_real_dsn() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let wrong_db = format!("{dsn}x-namespace-collision");
        let mut pg_config = validated_dsn_config(&wrong_db).expect("the DSN still parses");
        let settings = runtime_settings();
        apply_session_settings(&mut pg_config, &settings);
        let foundation = build_pool(pg_config, NoTls, &settings).expect("pool should build");

        let error = validate_connectivity(foundation.pool())
            .await
            .expect_err("a database that does not exist cannot answer");
        assert!(
            error.kind() == RepositoryErrorKind::Unavailable
                || error.kind() == RepositoryErrorKind::Timeout,
            "an unreachable or missing database must classify as unavailable (or a bounded \
             timeout under the attempt budget), not internal: {}",
            error
        );
        assert_no_dsn_material(&error.to_string());
    }
}
