//! Versioned, checksummed PostgreSQL migrations (issue #241, PR 4).
//!
//! This module owns the schema's whole lifecycle discipline: one checked-in,
//! ordered, checksummed set of migrations; a ledger table that records what
//! was applied and by which checksum; an advisory lock that serializes
//! concurrent migrators; a `migrate check` / `migrate up` CLI; and the
//! startup validation an application pod performs (validate only -- a pod
//! never migrates unless development auto-migration is explicitly enabled).
//!
//! ## The rules, and why
//!
//! - **Migrations are append-only and transactional.** Each runs inside one
//!   transaction together with its ledger row: a migration that fails rolls
//!   back completely, so the ledger is never mid-flight and a "dirty"
//!   database cannot exist. Destructive changes are a later, explicit
//!   finalization step, never smuggled into a migration -- that is what lets
//!   version N and N+1 binaries coexist during a rolling deployment (expand
//!   first, contract in a later release).
//! - **The ledger must be a prefix of the embedded manifest, checksums
//!   matching.** Anything else -- an unknown version (written by a newer
//!   gateway), a checksum mismatch (edited migration files), a gap or
//!   reorder (manual tampering) -- is refused by `check` and by startup.
//!   There is no automatic downgrade and no "best effort" interpretation.
//! - **The migrator serializes with a session advisory lock** keyed to a
//!   stable, compile-time constant, so two migration jobs started
//!   simultaneously produce exactly one applier and one no-op observer.
//!   The lock is taken under the session's `lock_timeout`, and it is held on
//!   a connection the migrator then detaches from the pool, so the lock dies
//!   with the session the moment the migrator returns -- on success and on
//!   every error path alike, with nothing to forget.
//! - **Migration statements run under their own bounded timeout**
//!   (`DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS`), set with `SET LOCAL`
//!   inside each migration's transaction: long enough for real DDL, still
//!   finite, and it cannot leak into pooled sessions.
//! - **Names are fully qualified.** The migrator and the ledger queries
//!   spell out the `greengateway.` schema prefix; pooled sessions
//!   additionally pin `search_path` at connect time, so nothing depends on
//!   whatever the server or an attacker's defaults would resolve first.
//!
//! ## Redaction
//!
//! As everywhere in the PostgreSQL foundation: no SQL text, no query values,
//! and no database identifiers beyond the compile-time schema name cross an
//! error boundary; failures are classified and carry setting names, counts,
//! and reasons.

use std::{fmt, sync::LazyLock};

use sha2::{Digest, Sha256};

use crate::config::{Config, DatabaseSettings};

/// The one schema every cluster-mode object lives in. Pinned here, pinned in
/// pooled sessions' `search_path`, and pinned in the migration SQL; nothing
/// resolves objects through ambient defaults.
pub const SCHEMA_NAME: &str = "greengateway";

/// The ledger: one row per applied migration. Created by the migrator's
/// bootstrap (which runs as the DDL-capable migration role), read by every
/// replica's validate-only startup check.
const LEDGER_TABLE: &str = "greengateway.schema_migrations";

/// The advisory-lock key, derived once from the lock's name so two binaries
/// of different versions still agree on it. The top bit is cleared to keep
/// the value a positive i64 on every platform.
static MIGRATION_LOCK_KEY: LazyLock<i64> = LazyLock::new(|| {
    let digest = Sha256::digest(b"greengateway.schema-migrations");
    let mut value = [0_u8; 8];
    value.copy_from_slice(&digest[..8]);
    value[0] &= 0x7f;
    i64::from_be_bytes(value)
});

/// One embedded migration. Constructed only by [`MANIFEST`] (and by tests);
/// the checksum is computed from the SQL at construction so a build and its
/// ledger always agree on what a migration's bytes are.
pub struct Migration {
    pub version: i64,
    pub name: &'static str,
    sql: &'static str,
    checksum: String,
    /// The hex SHA-256 of `sql` at the time the migration was added, pinned
    /// by `migration_checksums_match_their_pinned_literals` so editing the
    /// SQL without deliberately updating the literal fails the suite. The
    /// runtime compares the computed checksum against every deployment's
    /// ledger, so editing an applied migration fails every `check`.
    pinned_checksum: &'static str,
}

impl Migration {
    const fn new(version: i64, name: &'static str, sql: &'static str) -> Self {
        Self {
            version,
            name,
            sql,
            // Filled by `finalize` below; a `const fn` cannot hash.
            checksum: String::new(),
            pinned_checksum: "",
        }
    }

    /// Compute the checksum the manifest was declared without. A
    /// `LazyLock` construction can hash; a `const` one cannot, so the
    /// manifest is declared with [`Migration::new`] and finalized here.
    fn finalize(mut self) -> Self {
        self.checksum = hex_checksum(self.sql);
        self
    }

    fn current_checksum(&self) -> &str {
        &self.checksum
    }

    fn with_pinned_checksum(mut self, pinned: &'static str) -> Self {
        self.pinned_checksum = pinned;
        self
    }
}

fn hex_checksum(sql: &str) -> String {
    hex::encode(Sha256::digest(sql.as_bytes()))
}

/// The embedded, ordered manifest: append only, never edit an applied entry,
/// never reorder, keep the versions contiguous and increasing.
static MANIFEST: LazyLock<Vec<Migration>> = LazyLock::new(|| {
    vec![
        Migration::new(
            1,
            "cluster_foundation",
            include_str!("migrations/0001_cluster_foundation.sql"),
        )
        .finalize()
        .with_pinned_checksum("2b8d809a08d5253a6dffb01033587ea3ad5b4152745e92044331639fd87bf13d"),
        Migration::new(
            2,
            "audit_events",
            include_str!("migrations/0002_audit_events.sql"),
        )
        .finalize()
        .with_pinned_checksum("b48d999c02476e18dedcd5c67d99fe0d5eebdcf5be756c88a6dd2e9bc09ac1ca"),
        Migration::new(
            3,
            "audit_stream_state",
            include_str!("migrations/0003_audit_stream_state.sql"),
        )
        .finalize()
        .with_pinned_checksum("cd4a959d338c06997cbb4ef06e5197de11312501135ec527a8df80c3dd96d062"),
        Migration::new(
            4,
            "policy_control_plane",
            include_str!("migrations/0004_policy_control_plane.sql"),
        )
        .finalize()
        .with_pinned_checksum("e4df4506f452de59d4686c8064b7cac1813a3f88ad5908fa9e59fd3a1ad137ab"),
        Migration::new(
            5,
            "tools_control_plane",
            include_str!("migrations/0005_tools_control_plane.sql"),
        )
        .finalize()
        .with_pinned_checksum("5d6d2149e7dd714bf4dfeb5537d5b1d048170c8cffbc11a428e5890ed3ba4cd7"),
        Migration::new(
            6,
            "connections_control_plane",
            include_str!("migrations/0006_connections_control_plane.sql"),
        )
        .finalize()
        .with_pinned_checksum("46209bad8cf579733ab7996194f76e972ff0dec102fe5299e9de8c2dc33ac32a"),
        Migration::new(
            7,
            "service_tokens",
            include_str!("migrations/0007_service_tokens.sql"),
        )
        .finalize()
        .with_pinned_checksum("ea451758adee74af5f71a842c4ea6b11bb6485a259dc3a8dcdcb778b37afb2ad"),
        Migration::new(
            8,
            "limits_and_leases",
            include_str!("migrations/0008_limits_and_leases.sql"),
        )
        .finalize()
        .with_pinned_checksum("5b7050a2e85f32a0f183dc2bd1ca2307e1377245452fd05566bfa0844d8453b5"),
        Migration::new(
            9,
            "discovery_projector",
            include_str!("migrations/0009_discovery_projector.sql"),
        )
        .finalize()
        .with_pinned_checksum("a13f87e19303cb8f37fa06b447bebf04bf37d6b85636f8a0b872e843f30d54e3"),
        Migration::new(
            10,
            "cluster_membership",
            include_str!("migrations/0010_cluster_membership.sql"),
        )
        .finalize()
        .with_pinned_checksum("74b264596e14a1a01b17c212c558051c6fc74f340c0e238597b75d77362974d8"),
        Migration::new(
            11,
            "discovery_lifecycle",
            include_str!("migrations/0011_discovery_lifecycle.sql"),
        )
        .finalize()
        .with_pinned_checksum("62867cfebe55b9a31f2aa010add3c6b71ba3adaabb84d356936ead2836583787"),
    ]
});

/// The schema-version range this binary accepts, as a cluster member
/// advertises it (issue #241, PR 13): `(min, max)` in manifest versions.
///
/// Both ends are the manifest length. The ledger rules above admit exactly
/// one shape -- a checksum-matching prefix covering the whole manifest --
/// so a serving replica tolerates neither a ledger behind its manifest
/// (it refuses to serve until migrated) nor one ahead of it (written by a
/// newer gateway). The range is still advertised as a pair so PR 14's
/// status view and a future expand/contract release that widens the
/// tolerated window need no schema change to say so.
pub(crate) fn schema_version_range() -> (i32, i32) {
    let len = i32::try_from(MANIFEST.len()).unwrap_or(i32::MAX);
    (len, len)
}

/// What `check` (and startup validation) concluded about the schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SchemaStatus {
    /// The ledger is a checksum-matching prefix covering the whole manifest.
    Current,
    /// The database answers but carries no ledger at all: `migrate up` has
    /// never run here.
    NotInitialized,
    /// The ledger is valid but behind the manifest by `missing` migrations.
    NeedsUpgrade { applied: usize, missing: usize },
}

/// How the ledger disagrees with this binary's manifest. Every variant is a
/// refuse-to-serve condition; none is repaired automatically.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LedgerProblem {
    /// A ledger row names a version this binary does not carry: written by a
    /// newer gateway. Serving on would mean guessing at a schema this
    /// binary cannot fully understand.
    UnknownVersion,
    /// A known version's stored checksum differs from the embedded SQL: the
    /// migration files were edited after being applied somewhere.
    ChecksumMismatch,
    /// The ledger's versions do not form an increasing, gap-free prefix of
    /// the manifest: rows were deleted or reordered by hand.
    NotAPrefix,
}

impl fmt::Display for LedgerProblem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownVersion => formatter.write_str(
                "the schema ledger contains a migration this gateway build does not carry; \
                 it was written by a newer gateway — upgrade this gateway before serving",
            ),
            Self::ChecksumMismatch => formatter.write_str(
                "a recorded migration checksum does not match this build's migration SQL; \
                 applied migrations are immutable — restore the original migration files \
                 or restore the database from backup",
            ),
            Self::NotAPrefix => formatter.write_str(
                "the schema ledger is not an ordered, gap-free prefix of this build's \
                 migrations; it was modified outside the migrator — restore it from backup",
            ),
        }
    }
}

/// Validate a ledger read back from the database against a manifest.
///
/// Pure, so the tamper/dirty/too-new matrix is unit-tested without any
/// database: `applied` is the ordered `(version, checksum)` rows.
pub(crate) fn validate_ledger(
    applied: &[(i64, String)],
    manifest: &[Migration],
) -> Result<SchemaStatus, LedgerProblem> {
    for (index, (version, checksum)) in applied.iter().enumerate() {
        let Some(migration) = manifest.get(index) else {
            // More ledger rows than manifest entries: the extra versions
            // are unknown no matter their numbering.
            return Err(LedgerProblem::UnknownVersion);
        };
        if *version != migration.version {
            if manifest.iter().any(|m| m.version == *version) {
                // A known version in the wrong place: reordered or gapped.
                return Err(LedgerProblem::NotAPrefix);
            }
            return Err(LedgerProblem::UnknownVersion);
        }
        if checksum != migration.current_checksum() {
            return Err(LedgerProblem::ChecksumMismatch);
        }
    }
    if applied.len() == manifest.len() {
        Ok(SchemaStatus::Current)
    } else {
        Ok(SchemaStatus::NeedsUpgrade {
            applied: applied.len(),
            missing: manifest.len() - applied.len(),
        })
    }
}

// --- the CLI -----------------------------------------------------------------

/// What a completed `migrate` command reports. Display is the operator's
/// whole output: counts and statuses only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MigrateOutput {
    CheckCurrent,
    CheckNotInitialized,
    CheckNeedsUpgrade { applied: usize, missing: usize },
    UpToDate { applied: usize },
    Applied { applied: usize },
}

impl fmt::Display for MigrateOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CheckCurrent => formatter.write_str("schema: current"),
            Self::CheckNotInitialized => formatter.write_str(
                "schema: not initialized (run `gateway migrate up` from a migration job)",
            ),
            Self::CheckNeedsUpgrade { applied, missing } => write!(
                formatter,
                "schema: {missing} migration(s) unapplied after {applied} applied \
                 (run `gateway migrate up` from a migration job)"
            ),
            Self::UpToDate { applied } => {
                write!(
                    formatter,
                    "schema: already current at {applied} migration(s)"
                )
            }
            Self::Applied { applied } => {
                write!(formatter, "schema: applied {applied} migration(s)")
            }
        }
    }
}

impl MigrateOutput {
    /// The process exit status for a completed command. `check` is a gate:
    /// it exits zero only when the schema is current, so deployment scripts
    /// and CI can chain on it; the not-current outcomes print their status
    /// line and exit nonzero. `up` succeeds on every clean outcome
    /// (including "nothing to do"), because a no-op migration job is a
    /// successful one.
    pub(crate) fn exit_code(&self) -> i32 {
        match self {
            Self::CheckCurrent | Self::UpToDate { .. } | Self::Applied { .. } => 0,
            Self::CheckNotInitialized | Self::CheckNeedsUpgrade { .. } => 1,
        }
    }
}

/// A migration CLI or validation failure. Display names commands, settings,
/// and reasons -- never SQL text, identifiers beyond the schema name, or
/// query values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MigrateError {
    InvalidArguments,
    /// `migrate` was used while standalone mode is selected.
    ModeNotSelected,
    /// The configuration did not validate; carries the rendered problems
    /// (setting names and bounds only -- the same text a serving startup
    /// prints).
    ConfigurationInvalid(String),
    /// The database could not be reached within the bounded retry budget.
    DatabaseUnavailable,
    /// The database is bound to another deployment; neither `check` nor
    /// `up` may proceed against it.
    DeploymentMismatch {
        bound: String,
    },
    /// The ledger disagrees with this binary's manifest.
    LedgerInvalid(LedgerProblem),
    /// Applying a migration failed. The classified detail is logged at the
    /// failure site; this variant deliberately carries nothing else.
    ApplyFailed,
}

impl fmt::Display for MigrateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArguments => formatter.write_str(
                "invalid arguments; expected `gateway migrate check` or `gateway migrate up`",
            ),
            Self::ModeNotSelected => formatter.write_str(
                "`gateway migrate` requires STATE_BACKEND=postgres with DEPLOYMENT_ID and \
                 DATABASE_URL_FILE configured",
            ),
            Self::ConfigurationInvalid(problems) => {
                write!(formatter, "configuration is invalid:\n{problems}")
            }
            Self::DatabaseUnavailable => formatter.write_str(
                "the PostgreSQL database did not become reachable within the bounded retry \
                 budget; see DATABASE_STARTUP_RETRY_LIMIT",
            ),
            Self::DeploymentMismatch { bound } => write!(
                formatter,
                "this database is bound to deployment '{bound}'; deployments never share a \
                 database, so `gateway migrate` refuses to run against it"
            ),
            Self::LedgerInvalid(problem) => {
                write!(formatter, "schema ledger invalid: {problem}")
            }
            Self::ApplyFailed => formatter.write_str(
                "applying a migration failed; every migration runs in one transaction, so \
                 the database is left at its previous schema version",
            ),
        }
    }
}

impl std::error::Error for MigrateError {}

/// Parse the `migrate` subcommand. `Some(true)` = `check`, `Some(false)` =
/// `up`, `None` = not a migrate command, `Err` = malformed.
fn parse_migrate_command<I>(arguments: I) -> Result<Option<bool>, MigrateError>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    let mut arguments = arguments.into_iter();
    let Some(first) = arguments.next() else {
        return Ok(None);
    };
    if first != *"migrate" {
        return Ok(None);
    }
    let subcommand = arguments.next();
    if arguments.next().is_some() {
        return Err(MigrateError::InvalidArguments);
    }
    match subcommand.as_deref().and_then(|word| word.to_str()) {
        Some("check") => Ok(Some(true)),
        Some("up") => Ok(Some(false)),
        _ => Err(MigrateError::InvalidArguments),
    }
}

/// Parse and (when recognized) execute a `migrate` subcommand. Returns
/// `Ok(None)` when the arguments are not a `migrate` command, so startup
/// proceeds exactly as before.
pub(crate) async fn run_if_requested<I, F, E>(
    arguments: I,
    load_config: F,
) -> Result<Option<MigrateOutput>, MigrateError>
where
    I: IntoIterator<Item = std::ffi::OsString>,
    F: FnOnce() -> Result<Config, E>,
    E: fmt::Display,
{
    let Some(check_only) = parse_migrate_command(arguments)? else {
        return Ok(None);
    };
    let config = load_config().map_err(|error| {
        // Surface the real validation problems: a bounded-out
        // DATABASE_* setting misreported as "standalone mode selected"
        // would send an operator hunting the wrong setting.
        MigrateError::ConfigurationInvalid(error.to_string())
    })?;
    execute(&config, check_only).await.map(Some)
}

#[cfg(feature = "postgres")]
pub(crate) async fn execute(
    config: &Config,
    check_only: bool,
) -> Result<MigrateOutput, MigrateError> {
    use crate::config::StateBackend;

    if config.state_backend != StateBackend::Postgres {
        return Err(MigrateError::ModeNotSelected);
    }
    let foundation = super::postgres::PostgresFoundation::establish(config)
        .await
        .map_err(|_| MigrateError::DatabaseUnavailable)?;

    if check_only {
        return match read_and_validate(foundation.pool()).await? {
            // A current schema carries the deployment binding (0007): a
            // database bound to another deployment is not "current" for
            // this one. An older schema reports the upgrade it needs first.
            SchemaStatus::Current => {
                // Validation only: read the binding, never write it. An
                // unbound database is left for `migrate up` or startup to
                // claim, and a read-only check role can run this.
                refuse_other_deployment_read_only(&foundation, config).await?;
                Ok(MigrateOutput::CheckCurrent)
            }
            SchemaStatus::NotInitialized => Ok(MigrateOutput::CheckNotInitialized),
            SchemaStatus::NeedsUpgrade { applied, missing } => {
                Ok(MigrateOutput::CheckNeedsUpgrade { applied, missing })
            }
        };
    }

    let output = apply_missing(foundation.pool(), &config.database).await?;
    // The schema now carries the binding table; bind this deployment (a
    // first migration) or refuse another deployment's database.
    refuse_other_deployment(&foundation, config).await?;
    Ok(output)
}

/// Bind the database to this deployment, or refuse one bound elsewhere.
#[cfg(feature = "postgres")]
async fn refuse_other_deployment(
    foundation: &super::postgres::PostgresFoundation,
    config: &Config,
) -> Result<(), MigrateError> {
    let deployment_id = config
        .deployment_id
        .as_deref()
        .ok_or(MigrateError::ModeNotSelected)?;
    super::postgres::bind_deployment(foundation.pool(), deployment_id)
        .await
        .map_err(|error| match error {
            super::postgres::DeploymentBindingError::Mismatch { bound } => {
                MigrateError::DeploymentMismatch { bound }
            }
            super::postgres::DeploymentBindingError::Store(_) => MigrateError::DatabaseUnavailable,
        })
}

/// Refuse a database bound to another deployment, reading the binding
/// only: `migrate check` must not write, and must not claim an unbound
/// database for whichever deployment ran the check.
#[cfg(feature = "postgres")]
async fn refuse_other_deployment_read_only(
    foundation: &super::postgres::PostgresFoundation,
    config: &Config,
) -> Result<(), MigrateError> {
    let deployment_id = config
        .deployment_id
        .as_deref()
        .ok_or(MigrateError::ModeNotSelected)?;
    match super::postgres::read_deployment_binding(foundation.pool()).await {
        Ok(Some(bound)) if bound != deployment_id => {
            Err(MigrateError::DeploymentMismatch { bound })
        }
        Ok(_) => Ok(()),
        Err(_) => Err(MigrateError::DatabaseUnavailable),
    }
}

/// Read the ledger from a pool and validate it against this binary's
/// manifest. This is also the startup-validation entry point.
#[cfg(feature = "postgres")]
pub(crate) async fn read_and_validate(
    pool: &deadpool_postgres::Pool,
) -> Result<SchemaStatus, MigrateError> {
    let client = acquire(pool).await?;
    match read_ledger(&client).await? {
        LedgerRead::Table(rows) => {
            validate_ledger(&rows, &MANIFEST).map_err(MigrateError::LedgerInvalid)
        }
        LedgerRead::TableMissing => Ok(SchemaStatus::NotInitialized),
    }
}

enum LedgerRead {
    Table(Vec<(i64, String)>),
    TableMissing,
}

#[cfg(feature = "postgres")]
async fn acquire(
    pool: &deadpool_postgres::Pool,
) -> Result<deadpool_postgres::Object, MigrateError> {
    pool.get().await.map_err(|error| {
        tracing::error!(error = %error, "migration database checkout failed");
        MigrateError::DatabaseUnavailable
    })
}

#[cfg(feature = "postgres")]
async fn read_ledger(
    client: &deadpool_postgres::ClientWrapper,
) -> Result<LedgerRead, MigrateError> {
    let rows = client
        .query(
            &format!("SELECT version, checksum FROM {LEDGER_TABLE} ORDER BY version"),
            &[],
        )
        .await;
    match rows {
        Ok(rows) => Ok(LedgerRead::Table(
            rows.iter()
                .map(|row| (row.get::<_, i64>(0), row.get::<_, String>(1)))
                .collect(),
        )),
        // 42P01 undefined_table: the bootstrap has not run here.
        Err(error) if error.code().is_some_and(|state| state.code() == "42P01") => {
            Ok(LedgerRead::TableMissing)
        }
        Err(error) => {
            tracing::error!(error = %error, "schema ledger read failed");
            Err(MigrateError::ApplyFailed)
        }
    }
}

/// Apply every missing migration under the advisory lock.
///
/// The lock lives on a connection that is then **detached from the pool**
/// (`Object::take`), so it is released by the session closing the moment
/// this function returns -- success or error -- rather than by remembering
/// to unlock on every path. A second migrator started simultaneously waits
/// on the lock under the session's `lock_timeout`, then re-reads the ledger
/// and finds nothing left to do. Each migration runs in one transaction
/// with its ledger row and its own `SET LOCAL` statement/lock timeouts, so
/// a failure anywhere leaves the database at its previous schema version.
#[cfg(feature = "postgres")]
async fn apply_missing(
    pool: &deadpool_postgres::Pool,
    settings: &DatabaseSettings,
) -> Result<MigrateOutput, MigrateError> {
    let connection = acquire(pool).await?;

    // Method calls auto-deref the pooled object to the underlying client.
    // This session is about to be detached from the pool, so widening its
    // budgets is safe: they die with the connection. The advisory lock
    // wait and the bootstrap DDL run under the migration budget
    // (N migrations could legitimately hold the lock for N times the
    // per-migration timeout), not the pooled session's request-path
    // lock_timeout -- a second migrator waiting behind a slow first one
    // must observe, not spuriously fail.
    connection
        .simple_query(&format!(
            "SET lock_timeout = {}; SET statement_timeout = {};",
            settings.migration_statement_timeout_ms * (MANIFEST.len() as u64),
            settings.migration_statement_timeout_ms,
        ))
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "migration session budget setup failed");
            MigrateError::ApplyFailed
        })?;
    connection
        .simple_query(&format!("SELECT pg_advisory_lock({})", *MIGRATION_LOCK_KEY))
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "migration advisory lock failed");
            MigrateError::ApplyFailed
        })?;
    // Detach the connection from the pool: `take` consumes the wrapper and
    // returns the client itself, marked so the pool will never recycle it.
    // When `client` drops -- at every return below, success or error -- the
    // session closes and PostgreSQL releases the advisory lock. Nothing to
    // remember, nothing left dangling in the pool holding a lock.
    let client = deadpool_postgres::Object::take(connection);

    bootstrap_ledger(&client).await?;

    let rows = match read_ledger(&client).await? {
        LedgerRead::Table(rows) => rows,
        LedgerRead::TableMissing => Vec::new(),
    };
    let status = validate_ledger(&rows, &MANIFEST).map_err(MigrateError::LedgerInvalid)?;
    let SchemaStatus::NeedsUpgrade { applied, .. } = status else {
        return Ok(MigrateOutput::UpToDate {
            applied: rows.len(),
        });
    };

    for migration in &MANIFEST[applied..] {
        apply_one(&client, migration, settings).await?;
        tracing::info!(
            version = migration.version,
            name = migration.name,
            "applied schema migration"
        );
    }
    Ok(MigrateOutput::Applied {
        applied: MANIFEST.len() - applied,
    })
}

/// Create the schema and ledger if absent. Runs as the DDL-capable migration
/// role; a runtime role without CREATE fails here, which is the no-DDL
/// boundary doing its job.
#[cfg(feature = "postgres")]
async fn bootstrap_ledger(client: &deadpool_postgres::ClientWrapper) -> Result<(), MigrateError> {
    client
        .batch_execute(&format!(
            "CREATE SCHEMA IF NOT EXISTS {SCHEMA_NAME}; \
             CREATE TABLE IF NOT EXISTS {LEDGER_TABLE} (\
                 version bigint PRIMARY KEY, \
                 name text NOT NULL, \
                 checksum text NOT NULL, \
                 applied_at timestamptz NOT NULL DEFAULT now(), \
                 applied_by text NOT NULL DEFAULT current_user\
             );"
        ))
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "schema bootstrap failed");
            MigrateError::ApplyFailed
        })
}

#[cfg(feature = "postgres")]
async fn apply_one(
    client: &deadpool_postgres::ClientWrapper,
    migration: &Migration,
    settings: &DatabaseSettings,
) -> Result<(), MigrateError> {
    // One transaction per migration, driven explicitly over this session:
    // BEGIN, the bounded timeouts, the migration body, the ledger row, and
    // COMMIT are one atomic unit, so a failure anywhere rolls the whole
    // migration back and the database keeps its previous schema version.
    client.batch_execute("BEGIN").await.map_err(|error| {
        tracing::error!(error = %error, "migration transaction begin failed");
        MigrateError::ApplyFailed
    })?;
    match migration_transaction(client, migration, settings).await {
        Ok(()) => match client.batch_execute("COMMIT").await {
            // A failed COMMIT has already rolled the transaction back
            // server-side; the ledger was never durably written.
            Ok(()) => Ok(()),
            Err(error) => {
                tracing::error!(error = %error, "migration commit failed");
                Err(MigrateError::ApplyFailed)
            }
        },
        Err(error) => {
            // Best-effort rollback; the session ends with the migrator's
            // connection regardless, and PostgreSQL discards an abandoned
            // transaction either way.
            let _ = client.batch_execute("ROLLBACK").await;
            Err(error)
        }
    }
}

/// The statements inside one migration's transaction, after BEGIN and
/// before COMMIT.
#[cfg(feature = "postgres")]
async fn migration_transaction(
    client: &deadpool_postgres::ClientWrapper,
    migration: &Migration,
    settings: &DatabaseSettings,
) -> Result<(), MigrateError> {
    // `SET LOCAL`: bounded to this transaction, cannot leak into the pooled
    // session, and covers exactly the statements that need the larger
    // budget. The lock timeout matches, so DDL blocked by a stray lock
    // fails bounded rather than queuing past the operator's patience.
    client
        .batch_execute(&format!(
            "SET LOCAL statement_timeout = {}; SET LOCAL lock_timeout = {};",
            settings.migration_statement_timeout_ms, settings.migration_statement_timeout_ms
        ))
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "migration timeout setup failed");
            MigrateError::ApplyFailed
        })?;
    client.batch_execute(migration.sql).await.map_err(|error| {
        tracing::error!(error = %error, version = migration.version, "migration statement failed");
        MigrateError::ApplyFailed
    })?;
    client
        .execute(
            &format!("INSERT INTO {LEDGER_TABLE} (version, name, checksum) VALUES ($1, $2, $3)"),
            &[&migration.version, &migration.name, &migration.checksum],
        )
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "migration ledger insert failed");
            MigrateError::ApplyFailed
        })?;
    Ok(())
}

/// How many migrations this build carries; startup errors name the count so
/// an operator can see the gap without access to the manifest.
pub(crate) fn manifest_len() -> usize {
    MANIFEST.len()
}

/// Development auto-migration: run the same `migrate up` the CLI runs, from
/// the serving process. Production pods validate only; this path exists for
/// single-process development databases and is opt-in through
/// `DATABASE_AUTO_MIGRATE`.
#[cfg(feature = "postgres")]
pub(crate) async fn apply_missing_for_startup(
    pool: &deadpool_postgres::Pool,
    settings: &DatabaseSettings,
) -> Result<(), MigrateError> {
    apply_missing(pool, settings).await.map(|_| ())
}

/// Translate an auto-migration failure into the foundation's startup error.
/// Ledger problems keep their specific text; an apply failure is its own
/// condition (it was a write attempt, not a validation), and anything else
/// was a store failure, already logged at its site.
#[cfg(feature = "postgres")]
pub(crate) fn startup_migration_failure(
    error: MigrateError,
) -> super::postgres::PostgresFoundationError {
    match error {
        MigrateError::LedgerInvalid(problem) => {
            super::postgres::PostgresFoundationError::SchemaInvalid { problem }
        }
        MigrateError::ApplyFailed => {
            super::postgres::PostgresFoundationError::SchemaMigrationFailed
        }
        _ => super::postgres::PostgresFoundationError::SchemaCheckFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn migration_checksums_match_their_pinned_literals() {
        for migration in MANIFEST.iter() {
            assert_eq!(
                migration.current_checksum(),
                migration.pinned_checksum,
                "migration {} ({}) SQL changed without updating its pinned checksum; \
                 applied ledgers will refuse this build",
                migration.version,
                migration.name
            );
        }
    }

    #[test]
    fn the_advisory_lock_key_is_stable_and_positive() {
        // The value is pinned so a build change cannot silently split
        // migrators of different versions onto different lock keys.
        let digest = Sha256::digest(b"greengateway.schema-migrations");
        let mut expected = [0_u8; 8];
        expected.copy_from_slice(&digest[..8]);
        expected[0] &= 0x7f;
        assert_eq!(*MIGRATION_LOCK_KEY, i64::from_be_bytes(expected));
        assert!(*MIGRATION_LOCK_KEY > 0, "must fit a positive bigint");
    }

    fn synthetic_manifest() -> Vec<Migration> {
        (1..=3)
            .map(|version| {
                let sql: &'static str =
                    Box::leak(format!("-- synthetic v{version}").into_boxed_str());
                Migration::new(version, "synthetic", sql)
                    .finalize()
                    .with_pinned_checksum("")
            })
            .collect()
    }

    fn ledger_for(manifest: &[Migration], up_to: usize, salt: &str) -> Vec<(i64, String)> {
        manifest[..up_to]
            .iter()
            .map(|migration| {
                (
                    migration.version,
                    if salt.is_empty() {
                        migration.current_checksum().to_owned()
                    } else {
                        hex_checksum(salt)
                    },
                )
            })
            .collect()
    }

    #[test]
    fn an_empty_ledger_needs_upgrade() {
        let manifest = synthetic_manifest();
        assert_eq!(
            validate_ledger(&[], &manifest),
            Ok(SchemaStatus::NeedsUpgrade {
                applied: 0,
                missing: 3
            })
        );
    }

    #[test]
    fn a_full_matching_ledger_is_current() {
        let manifest = synthetic_manifest();
        let applied = ledger_for(&manifest, 3, "");
        assert_eq!(
            validate_ledger(&applied, &manifest),
            Ok(SchemaStatus::Current)
        );
    }

    #[test]
    fn a_valid_partial_ledger_needs_upgrade() {
        let manifest = synthetic_manifest();
        let applied = ledger_for(&manifest, 2, "");
        assert_eq!(
            validate_ledger(&applied, &manifest),
            Ok(SchemaStatus::NeedsUpgrade {
                applied: 2,
                missing: 1
            })
        );
    }

    #[test]
    fn an_unknown_version_is_refused() {
        let manifest = synthetic_manifest();
        let mut applied = ledger_for(&manifest, 3, "");
        applied.push((99, hex_checksum("future")));
        assert_eq!(
            validate_ledger(&applied, &manifest),
            Err(LedgerProblem::UnknownVersion)
        );
    }

    #[test]
    fn a_checksum_mismatch_is_refused() {
        let manifest = synthetic_manifest();
        let applied = ledger_for(&manifest, 3, "edited-sql");
        assert_eq!(
            validate_ledger(&applied, &manifest),
            Err(LedgerProblem::ChecksumMismatch)
        );
    }

    #[test]
    fn a_gap_or_reorder_is_refused() {
        let manifest = synthetic_manifest();
        // A deleted middle row: known versions, wrong coverage order.
        let gapped = vec![
            (
                manifest[0].version,
                manifest[0].current_checksum().to_owned(),
            ),
            (
                manifest[2].version,
                manifest[2].current_checksum().to_owned(),
            ),
        ];
        assert_eq!(
            validate_ledger(&gapped, &manifest),
            Err(LedgerProblem::NotAPrefix)
        );
        // A reorder: version 2 appears where 1 belongs.
        let reordered = vec![
            (
                manifest[1].version,
                manifest[1].current_checksum().to_owned(),
            ),
            (
                manifest[0].version,
                manifest[0].current_checksum().to_owned(),
            ),
        ];
        assert_eq!(
            validate_ledger(&reordered, &manifest),
            Err(LedgerProblem::NotAPrefix)
        );
    }

    #[test]
    fn ledger_rows_beyond_the_manifest_are_unknown() {
        let manifest = synthetic_manifest();
        let mut applied = ledger_for(&manifest, 3, "");
        applied.push((4, manifest[2].current_checksum().to_owned()));
        assert_eq!(
            validate_ledger(&applied, &manifest),
            Err(LedgerProblem::UnknownVersion)
        );
    }

    #[test]
    fn cli_arguments_are_parsed_or_refused() {
        fn parse(args: &[&str]) -> Result<Option<bool>, MigrateError> {
            parse_migrate_command(args.iter().map(OsString::from))
        }

        assert_eq!(parse(&[]), Ok(None));
        assert_eq!(parse(&["serve"]), Ok(None));
        assert_eq!(parse(&["migrate", "check"]), Ok(Some(true)));
        assert_eq!(parse(&["migrate", "up"]), Ok(Some(false)));
        assert_eq!(parse(&["migrate"]), Err(MigrateError::InvalidArguments));
        assert_eq!(
            parse(&["migrate", "down"]),
            Err(MigrateError::InvalidArguments)
        );
        assert_eq!(
            parse(&["migrate", "check", "extra"]),
            Err(MigrateError::InvalidArguments)
        );
    }

    #[test]
    fn error_displays_carry_no_sql_or_identifiers() {
        for rendered in [
            MigrateError::LedgerInvalid(LedgerProblem::ChecksumMismatch).to_string(),
            MigrateError::ApplyFailed.to_string(),
            MigrateError::ModeNotSelected.to_string(),
        ] {
            assert!(!rendered.contains("SELECT"), "{rendered}");
            assert!(!rendered.contains("INSERT"), "{rendered}");
        }
    }

    // --- real-database tests -------------------------------------------------
    //
    // Gated on the same test-harness locator as the foundation tests: a file
    // naming a DSN a disposable database answers (CI sets it; a checkout
    // without a database skips instead of failing). The tests share that one
    // database, so a module mutex serializes them and each starts by
    // dropping the gateway schema for a clean slate.

    use tokio::sync::Mutex;

    /// Serializes the real-database tests: they share one disposable
    /// database and each starts by resetting its schema. Async-aware
    /// because every step under it awaits.
    static REAL_DATABASE: Mutex<()> = Mutex::const_new(());

    fn real_dsn() -> Option<String> {
        let key = test_dsn_file_key();
        let file = std::env::var(&key).ok()?;
        if file.trim().is_empty() {
            return None;
        }
        let contents = std::fs::read_to_string(file).ok()?;
        let trimmed = contents.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    }

    fn test_dsn_file_key() -> String {
        "GATEWAY_TEST_POSTGRES_URL_FILE".to_owned()
    }

    fn no_ddl_dsn() -> Option<String> {
        let key = "GATEWAY_TEST_POSTGRES_NODDL_URL_FILE".to_owned();
        let file = std::env::var(&key).ok()?;
        if file.trim().is_empty() {
            return None;
        }
        let contents = std::fs::read_to_string(file).ok()?;
        let trimmed = contents.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    }

    fn test_settings() -> DatabaseSettings {
        DatabaseSettings {
            tls_mode: crate::config::DatabaseTlsMode::LoopbackDev,
            ..DatabaseSettings::default()
        }
    }

    /// A DSN file the bounded reader accepts, plus a guard keeping the
    /// scratch directory alive (and cleaning it up) for the test's length.
    struct DsnFile {
        path: String,
        directory: std::path::PathBuf,
    }

    impl Drop for DsnFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn write_dsn_file(dsn: &str) -> DsnFile {
        let directory = std::env::temp_dir().join(format!(
            "greengateway-migration-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&directory).expect("temp directory should create");
        let path = directory.join("database-url");
        std::fs::write(&path, format!("{dsn}\n")).expect("DSN file should write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("DSN permissions should set");
        }
        DsnFile {
            path: path.display().to_string(),
            directory,
        }
    }

    /// Unwrap a startup result that must be a failure, distinguishing
    /// "served anyway" (the dangerous outcome) from "ran standalone".
    fn expect_startup_failure(
        result: Result<
            Option<super::super::postgres::PostgresFoundation>,
            super::super::postgres::PostgresFoundationError,
        >,
    ) -> super::super::postgres::PostgresFoundationError {
        match result {
            Err(error) => error,
            Ok(Some(_)) => panic!("startup should have failed, but the gateway served"),
            Ok(None) => panic!("cluster mode was selected; a standalone no-op is wrong here"),
        }
    }

    #[tokio::test]
    async fn startup_refuses_an_unmigrated_schema_and_auto_migrate_serves() {
        let Some(dsn) = real_dsn() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = REAL_DATABASE.lock().await;
        let dsn_file = write_dsn_file(&dsn);

        // Validate-only (the production posture) on an unmigrated database:
        // startup fails naming the migration job.
        let mut strict = migration_config(&dsn_file);
        strict.database.auto_migrate = false;
        let foundation = establish(&strict).await;
        clean_database(foundation.pool()).await;
        let error = expect_startup_failure(
            super::super::postgres::PostgresFoundation::start_if_selected(&strict).await,
        );
        assert!(
            error.to_string().contains("migrate up"),
            "the failure must name the remedy: {error}"
        );
        assert!(
            error.to_string().contains("DATABASE_AUTO_MIGRATE"),
            "the failure must name the development opt-in: {error}"
        );

        // Development auto-migration brings the same database up and serves.
        let mut dev = migration_config(&dsn_file);
        dev.database.auto_migrate = true;
        let started = super::super::postgres::PostgresFoundation::start_if_selected(&dev)
            .await
            .expect("auto-migrating startup should succeed")
            .expect("cluster mode was selected");
        let _ = started;
    }

    #[tokio::test]
    async fn startup_refuses_a_tampered_schema_even_with_auto_migrate() {
        let Some(dsn) = real_dsn() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = REAL_DATABASE.lock().await;
        let dsn_file = write_dsn_file(&dsn);
        let mut config = migration_config(&dsn_file);
        config.database.auto_migrate = true;
        let foundation = establish(&config).await;
        clean_database(foundation.pool()).await;
        apply_missing(foundation.pool(), &test_settings())
            .await
            .expect("setup migrate up");
        let client = foundation.pool().get().await.expect("checkout");
        client
            .execute(&format!("UPDATE {LEDGER_TABLE} SET checksum = '0'"), &[])
            .await
            .expect("tamper");

        let error = expect_startup_failure(
            super::super::postgres::PostgresFoundation::start_if_selected(&config).await,
        );
        assert!(
            error.to_string().contains("checksum"),
            "the failure must name the tamper class: {error}"
        );
    }

    fn migration_config(guard: &DsnFile) -> crate::config::Config {
        let mut config = crate::config::Config::test_defaults();
        config.state_backend = crate::config::StateBackend::Postgres;
        config.deployment_id = Some("deploy-migration-tests".to_owned());
        config.database.url_file = Some(guard.path.clone());
        // The test database is the loopback-dev shape CI and local runs use;
        // verify mode would (correctly) refuse it.
        config.database.tls_mode = crate::config::DatabaseTlsMode::LoopbackDev;
        config
    }

    async fn establish(
        config: &crate::config::Config,
    ) -> super::super::postgres::PostgresFoundation {
        super::super::postgres::PostgresFoundation::establish(config)
            .await
            .expect("the test database should establish")
    }

    async fn clean_database(pool: &deadpool_postgres::Pool) {
        pool.get()
            .await
            .expect("cleanup connection should check out")
            .batch_execute("DROP SCHEMA IF EXISTS greengateway CASCADE")
            .await
            .expect("cleanup should drop the gateway schema");
    }

    #[tokio::test]
    async fn up_bootstraps_applies_and_is_idempotent() {
        let Some(dsn) = real_dsn() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = REAL_DATABASE.lock().await;
        let dsn_file = write_dsn_file(&dsn);
        let config = migration_config(&dsn_file);
        let foundation = establish(&config).await;
        clean_database(foundation.pool()).await;

        let applied = apply_missing(foundation.pool(), &test_settings())
            .await
            .expect("migrate up should bootstrap and apply");
        assert_eq!(
            applied,
            MigrateOutput::Applied {
                applied: MANIFEST.len()
            }
        );

        // A second run finds nothing to do and changes nothing.
        let again = apply_missing(foundation.pool(), &test_settings())
            .await
            .expect("second migrate up should succeed");
        assert!(matches!(again, MigrateOutput::UpToDate { .. }));

        let status = read_and_validate(foundation.pool())
            .await
            .expect("check should validate the applied ledger");
        assert_eq!(status, SchemaStatus::Current);

        // Exactly one ledger row per manifest entry, in order.
        let client = foundation.pool().get().await.expect("checkout");
        let rows = client
            .query(
                &format!("SELECT version FROM {LEDGER_TABLE} ORDER BY version"),
                &[],
            )
            .await
            .expect("ledger rows should read");
        assert_eq!(rows.len(), MANIFEST.len());
        for (index, row) in rows.iter().enumerate() {
            assert_eq!(row.get::<_, i64>(0), MANIFEST[index].version);
        }
    }

    #[tokio::test]
    async fn check_reports_an_unmigrated_database() {
        let Some(dsn) = real_dsn() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = REAL_DATABASE.lock().await;
        let dsn_file = write_dsn_file(&dsn);
        let config = migration_config(&dsn_file);
        let foundation = establish(&config).await;
        clean_database(foundation.pool()).await;

        let status = read_and_validate(foundation.pool())
            .await
            .expect("check should classify, not fail");
        assert_eq!(status, SchemaStatus::NotInitialized);
    }

    #[tokio::test]
    async fn a_tampered_checksum_is_refused() {
        let Some(dsn) = real_dsn() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = REAL_DATABASE.lock().await;
        let dsn_file = write_dsn_file(&dsn);
        let config = migration_config(&dsn_file);
        let foundation = establish(&config).await;
        clean_database(foundation.pool()).await;
        apply_missing(foundation.pool(), &test_settings())
            .await
            .expect("setup migrate up");

        let client = foundation.pool().get().await.expect("checkout");
        client
            .execute(
                &format!("UPDATE {LEDGER_TABLE} SET checksum = '0' WHERE version = $1"),
                &[&MANIFEST[0].version],
            )
            .await
            .expect("tamper");

        let error = read_and_validate(foundation.pool())
            .await
            .expect_err("a tampered checksum must refuse service");
        assert_eq!(
            error,
            MigrateError::LedgerInvalid(LedgerProblem::ChecksumMismatch)
        );
    }

    #[tokio::test]
    async fn a_newer_gateways_migration_is_refused() {
        let Some(dsn) = real_dsn() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = REAL_DATABASE.lock().await;
        let dsn_file = write_dsn_file(&dsn);
        let config = migration_config(&dsn_file);
        let foundation = establish(&config).await;
        clean_database(foundation.pool()).await;
        apply_missing(foundation.pool(), &test_settings())
            .await
            .expect("setup migrate up");

        let client = foundation.pool().get().await.expect("checkout");
        let future_version: i64 = MANIFEST.last().expect("manifest").version + 1;
        client
            .execute(
                &format!(
                    "INSERT INTO {LEDGER_TABLE} (version, name, checksum) \
                     VALUES ($1, 'from_the_future', 'deadbeef')"
                ),
                &[&future_version],
            )
            .await
            .expect("plant a future row");

        let error = read_and_validate(foundation.pool())
            .await
            .expect_err("an unknown future version must refuse service");
        assert_eq!(
            error,
            MigrateError::LedgerInvalid(LedgerProblem::UnknownVersion)
        );
    }

    #[tokio::test]
    async fn concurrent_migrators_produce_one_applier() {
        let Some(dsn) = real_dsn() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = REAL_DATABASE.lock().await;
        let first_dsn = write_dsn_file(&dsn);
        let first = establish(&migration_config(&first_dsn)).await;
        let second_dsn = write_dsn_file(&dsn);
        let second = establish(&migration_config(&second_dsn)).await;
        clean_database(first.pool()).await;

        let (a, b) = {
            let settings = test_settings();
            tokio::join!(
                apply_missing(first.pool(), &settings),
                apply_missing(second.pool(), &settings),
            )
        };
        // Both succeed; one applied, the other observed an up-to-date
        // schema; and neither outcome can be a failure, because the loser
        // must not error on a schema the winner just wrote.
        let outcomes = [a.expect("first migrator"), b.expect("second migrator")];
        assert!(
            outcomes
                .iter()
                .any(|outcome| matches!(outcome, MigrateOutput::Applied { .. })),
            "exactly one migrator should apply: {outcomes:?}"
        );
        assert!(
            outcomes
                .iter()
                .any(|outcome| matches!(outcome, MigrateOutput::UpToDate { .. })),
            "the other migrator should observe an applied schema: {outcomes:?}"
        );

        let client = first.pool().get().await.expect("checkout");
        let rows = client
            .query(&format!("SELECT count(*) FROM {LEDGER_TABLE}"), &[])
            .await
            .expect("count");
        assert_eq!(rows[0].get::<_, i64>(0), MANIFEST.len() as i64);
    }

    #[tokio::test]
    async fn a_runtime_role_without_ddl_cannot_migrate_but_can_validate() {
        let (Some(dsn), Some(no_ddl)) = (real_dsn(), no_ddl_dsn()) else {
            eprintln!("skipping: no test database locator pair; CI runs this test");
            return;
        };
        let _guard = REAL_DATABASE.lock().await;
        // As the privileged role: migrate, then grant the runtime role
        // exactly what validate-only startup needs.
        let privileged_dsn = write_dsn_file(&dsn);
        let privileged = establish(&migration_config(&privileged_dsn)).await;
        clean_database(privileged.pool()).await;
        apply_missing(privileged.pool(), &test_settings())
            .await
            .expect("setup migrate up");
        let grantor = privileged.pool().get().await.expect("checkout");
        grantor
            .batch_execute(&format!(
                "GRANT USAGE ON SCHEMA {SCHEMA_NAME} TO PUBLIC; \
                 GRANT SELECT ON {LEDGER_TABLE} TO PUBLIC;"
            ))
            .await
            .expect("grants");

        // The runtime role validates the current schema...
        let runtime_dsn = write_dsn_file(&no_ddl);
        let runtime = establish(&migration_config(&runtime_dsn)).await;
        assert_eq!(
            read_and_validate(runtime.pool()).await.expect("validate"),
            SchemaStatus::Current
        );

        // ...and cannot migrate a clean database: the bootstrap's CREATE
        // SCHEMA is refused by the server's own privilege check.
        clean_database(privileged.pool()).await;
        let error = apply_missing(runtime.pool(), &test_settings())
            .await
            .expect_err("a no-DDL role must not be able to migrate");
        assert_eq!(error, MigrateError::ApplyFailed);

        // The classification table entry that failure exercises, pinned
        // directly: 42501 (insufficient_privilege) is `Unavailable`, not
        // `Internal`, so a privilege boundary reads as "cannot use this
        // store" in every consumer of PR 2's error kinds.
        let runtime_client = runtime.pool().get().await.expect("checkout");
        let privilege_error = runtime_client
            .batch_execute("CREATE SCHEMA greengateway_attempted")
            .await
            .expect_err("DDL must be refused for this role");
        assert_eq!(
            super::super::postgres::classify_postgres_error(&privilege_error),
            super::super::RepositoryErrorKind::Unavailable,
            "42501 must classify as unavailable"
        );
    }
}
