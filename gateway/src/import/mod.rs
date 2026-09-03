//! `gateway import-standalone`: the one-way standalone-to-cluster import
//! (issue #241, PRs 9-10 of the state model; PR 15 of the HA sequence).
//!
//! An operator who has been running GreenGateway in standalone mode holds
//! durable, operator-owned state in files and SQLite databases: a policy
//! document and its history, a tools document, Connections and their
//! bindings, audit events, discovery aggregates, principals and service
//! tokens. Cluster mode keeps all of it in one PostgreSQL deployment
//! namespace. This command carries the first across to the second, once,
//! offline, in one direction, with the evidence an operator needs to
//! decide whether the cutover succeeded.
//!
//! Two configurations are involved and they cannot be one process
//! environment: `Config::from_env` deliberately refuses a configuration
//! that names both a local authority (`POLICY_FILE`, the `*_SQLITE_PATH`
//! settings) and `STATE_BACKEND=postgres`. So the process environment is
//! the TARGET (the cluster: `STATE_BACKEND=postgres`, `DEPLOYMENT_ID`,
//! `DATABASE_URL_FILE`), exactly as every other one-shot command reads it,
//! and the SOURCE is named by `--from <env-file>`: the standalone
//! deployment's own environment file, parsed and validated through the
//! same `Config` validator, so "both configurations valid" is a real
//! check rather than a claim.
//!
//! Modes:
//!
//! - `--dry-run` (the default) reads the source and the target's
//!   emptiness and writes NOTHING. It reports the counts and checksums an
//!   apply would produce, so a cutover rehearsal is free.
//! - `--apply` performs the import.
//! - `--apply --resume` re-runs an import interrupted after some sections
//!   committed. Each section is its own transaction, so an interrupted run
//!   leaves whole sections committed and nothing partial; a resumed
//!   section that is already present is recognized by its natural key and
//!   skipped, and every insert underneath is idempotent on that key.
//!
//! The command is run with the MIGRATION role's DSN, beside `gateway
//! migrate up` in the cutover order, not with a serving replica's runtime
//! role: importing a standalone deployment's policy history preserves its
//! version numbers, which means naming an identity column's values and
//! realigning the sequence afterwards -- a privilege the least-privilege
//! runtime role deliberately does not hold.
//!
//! Sections, in order, each with its own transaction, counts and
//! checksum. A section failure aborts the run and leaves the sections
//! before it committed:
//!
//! 1. Preflight ([`preflight`]): both configurations valid, every
//!    configured SQLite file openable read-only, the target's schema
//!    current, the target namespace empty, and every policy, tools and
//!    Connection document on disk parseable by THIS binary. An
//!    unparseable document refuses the import: a document the importing
//!    binary cannot read is a document the cluster could not serve.
//! 2. Policy and history ([`sections::PolicySection`]).
//! 3. Tools and name reservations ([`sections::ToolsSection`]).
//! 4. Connections ([`sections::ConnectionsSection`]): records, credential
//!    bindings as references, statuses and their history, dependencies
//!    and the managed catalogs.
//! 5. Audit ([`sections::AuditSection`]): the standalone log in event
//!    order, deduplicated by `event_id`, appended to the durable stream
//!    with contiguous positions.
//! 6. Observations and discovery ([`sections::DiscoverySection`]): the
//!    endpoint inventory and its child rows, the detector windows and
//!    learner groups derived from it, the signals, rule suggestions and
//!    endpoint reviews with their revisions set explicitly, and the
//!    projector checkpoint set to the imported stream head.
//! 7. Principals and service tokens ([`sections::PrincipalsSection`]):
//!    the token hashes, with their revisions. The principal directory has
//!    no cluster counterpart and is not carried; the report names it.
//! 8. Validation ([`validation`]): row counts, a read-only constraint
//!    pass, logical checksums computed from BOTH sides, the active ETags,
//!    the projector checkpoint, and the runtime tables proven untouched. A
//!    failed check fails the run.
//! 9. The report: this module's [`ImportReport`], as pretty JSON on
//!    stdout.
//!
//! What is deliberately NOT imported is listed in [`NOT_IMPORTED`] and
//! proven by the validation pass rather than asserted in prose.
//!
//! Privacy, non-negotiable: nothing this command prints or logs is a
//! plaintext token, secret, credential, login material or DSN. Standalone
//! configuration problems are reported by SETTING NAME only, because the
//! `Config` validator's own messages quote the offending value and some of
//! those values are key material. Credential bindings (section 4) are
//! imported as references; local-secret keyring material is never moved.

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fmt,
    path::{Path, PathBuf},
    time::Instant,
};

use serde::Serialize;
use serde_json::Value;

use crate::{config::Config, storage::RepositoryError};

mod exports;
mod preflight;
mod sections;
mod source;
pub(crate) mod validation;

#[cfg(test)]
mod tests;

pub(crate) use source::StandaloneSource;

/// The actor recorded on every row this command writes. It is not a user:
/// a history reader must be able to tell an imported version from one an
/// administrator committed.
pub(crate) const IMPORT_ACTOR: &str = "import-standalone";

/// What the import deliberately leaves behind, named in every report.
///
/// The first group is runtime state a replica rebuilds, elects, or
/// accumulates while serving: carrying it across would hand a fresh
/// cluster another deployment's leadership, leases and counters. The
/// validation pass proves each of these tables is empty after an apply,
/// so this list is a checked property and not a promise.
///
/// The last two entries are different, and are named for honesty rather
/// than safety:
///
/// - `security_outbox` is not carried because it is a change feed for
///   running replicas, and replaying an import through it would announce a
///   change history the standalone deployment never had. The two rows the
///   policy and tools commits append describe this deployment's own
///   initialization.
/// - `principal_directory` has no cluster counterpart at all: cluster mode
///   refuses `PRINCIPAL_SQLITE_PATH` and no migration creates the table,
///   because the directory is a projection of authenticated traffic. The
///   traffic it was projected from IS imported, with the audit log.
/// - `connection_local_secrets` is the encrypted local-secret keyring that
///   lives inside `CONNECTIONS_SQLITE_PATH`. Credential bindings cross as
///   REFERENCES (a purpose, a secret id, a version) and this command never
///   moves key material, so a Connection whose binding resolved through the
///   local keyring resolves through nothing after the cutover until the
///   operator re-provisions it in the cluster's secret store. The count is
///   in the report's `source.connection_local_secrets`, so the size of that
///   job is a number an operator reads during the rehearsal rather than a
///   surprise after scale-out.
const NOT_IMPORTED: &[&str] = &[
    "cluster_members",
    "maintenance_jobs",
    "execution_leases",
    "rate_limit_buckets",
    "rate_limit_cardinality",
    "admin_pending_logins",
    "jwt_revocations",
    "security_outbox (the import announces nothing; a commit appends its own row)",
    "principal_directory (cluster mode has none; the audit log it projects from is imported)",
    "connection_local_secrets (the local-secret keyring stays with the standalone deployment; \
     credential bindings cross as references and must be re-provisioned in the cluster's \
     secret store)",
];

/// The command line, after `import-standalone`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ImportRequest {
    /// The standalone deployment's environment file (`--from`).
    pub standalone_env_file: PathBuf,
    pub mode: ImportMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ImportMode {
    /// Read everything, write nothing.
    DryRun,
    /// Import into an empty namespace.
    Apply,
    /// Import into a namespace an interrupted run left partly written.
    Resume,
}

impl ImportMode {
    pub(crate) fn writes(self) -> bool {
        !matches!(self, Self::DryRun)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::DryRun => "dry-run",
            Self::Apply => "apply",
            Self::Resume => "apply-resume",
        }
    }
}

pub(crate) const USAGE: &str =
    "usage: gateway import-standalone --from <standalone-env-file> [--dry-run | --apply [--resume]]";

impl ImportRequest {
    /// Parse the words after `import-standalone`. Hand-rolled to match the
    /// other one-shot commands (`cluster-members`, `maintenance-run`):
    /// this binary has no argument parser and gains none here.
    pub(crate) fn parse<I>(arguments: I) -> Result<Self, ImportError>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut standalone_env_file: Option<PathBuf> = None;
        let mut apply = false;
        let mut dry_run = false;
        let mut resume = false;
        let mut arguments = arguments.into_iter();
        while let Some(word) = arguments.next() {
            let Some(word) = word.to_str().map(str::to_owned) else {
                return Err(ImportError::Usage);
            };
            match word.as_str() {
                "--from" => {
                    let Some(value) = arguments.next() else {
                        return Err(ImportError::Usage);
                    };
                    if standalone_env_file.is_some() {
                        return Err(ImportError::Usage);
                    }
                    standalone_env_file = Some(PathBuf::from(value));
                }
                "--apply" => apply = true,
                "--dry-run" => dry_run = true,
                "--resume" => resume = true,
                _ => return Err(ImportError::Usage),
            }
        }
        let Some(standalone_env_file) = standalone_env_file else {
            return Err(ImportError::Usage);
        };
        // `--apply --dry-run` is not a preference, it is a contradiction:
        // one of the two is a mistake and guessing which would be the
        // dangerous half of the guess.
        if apply && dry_run {
            return Err(ImportError::Usage);
        }
        // `--resume` resumes an APPLY. On its own it would read as "resume
        // the dry run", which is not a thing that can be interrupted.
        if resume && !apply {
            return Err(ImportError::Usage);
        }
        let mode = match (apply, resume) {
            (true, true) => ImportMode::Resume,
            (true, false) => ImportMode::Apply,
            (false, _) => ImportMode::DryRun,
        };
        Ok(Self {
            standalone_env_file,
            mode,
        })
    }
}

/// Why an import did not happen. Every variant carries a stable `code()`:
/// operators script against the code, not the prose, and a refusal that
/// changed its wording between releases would break their runbooks.
#[derive(Debug)]
pub(crate) enum ImportError {
    Usage,
    /// The `--from` file could not be read at all.
    StandaloneEnvFileUnreadable {
        path: PathBuf,
    },
    /// A line of the `--from` file is not `KEY=VALUE`. Only the line
    /// NUMBER is reported: the line's text may be key material.
    StandaloneEnvFileMalformed {
        line: usize,
    },
    /// The standalone configuration does not validate. Setting names
    /// only -- the validator's messages quote values.
    StandaloneConfigInvalid {
        settings: Vec<String>,
    },
    /// The `--from` file names a cluster, not a standalone deployment.
    StandaloneNotStandalone,
    /// Cluster mode has no "no policy" state: startup refuses a
    /// deployment whose policy control plane was never initialized, so an
    /// import that installed no policy document would produce a cluster
    /// that cannot boot.
    StandalonePolicyFileMissing,
    /// A configured SQLite file exists but this binary cannot open it
    /// read-only.
    SourceSqliteUnreadable {
        setting: &'static str,
        path: PathBuf,
    },
    /// A configured SQLite file could not be copied into the import's
    /// private snapshot. The readers this command reads the source with
    /// normalize a database's schema on open, so they are pointed at a
    /// COPY; a snapshot that cannot be taken is a refusal, never a reason
    /// to fall back to opening the operator's live database read-write.
    SourceSnapshotFailed {
        setting: &'static str,
    },
    /// A document on disk does not parse. `detail` is the parser's own
    /// message: policy, tools and Connection documents carry no secrets.
    SourceDocumentUnparseable {
        kind: &'static str,
        detail: String,
    },
    TargetNotPostgres,
    TargetDeploymentIdMissing,
    TargetUnavailable {
        detail: String,
    },
    /// The target's schema is not this binary's manifest.
    TargetSchemaNotCurrent {
        detail: String,
    },
    /// The target database belongs to another deployment.
    TargetDeploymentMismatch {
        bound: String,
    },
    /// The target namespace already holds authoritative state. `occupied`
    /// names the tables and counters, never their contents.
    TargetNamespaceNotEmpty {
        occupied: Vec<String>,
    },
    /// A section found its resource already initialized with something
    /// other than what this import would write. `--resume` cannot repair
    /// that: the namespace is another import's, or a cluster's.
    SectionConflict {
        section: &'static str,
    },
    /// A section's transaction failed. Classified, never SQL text.
    SectionFailed {
        section: &'static str,
        detail: String,
    },
    /// The import wrote, and then could not verify what it wrote. The
    /// sections stay committed -- the operator needs them to diagnose --
    /// but the run fails, because an import that cannot verify itself is
    /// not one anybody should scale out on.
    ValidationFailed {
        checks: Vec<String>,
    },
    Store(RepositoryError),
}

impl ImportError {
    /// The stable machine-readable refusal reason.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Usage => "usage",
            Self::StandaloneEnvFileUnreadable { .. } => "standalone_env_file_unreadable",
            Self::StandaloneEnvFileMalformed { .. } => "standalone_env_file_malformed",
            Self::StandaloneConfigInvalid { .. } => "standalone_config_invalid",
            Self::StandaloneNotStandalone => "standalone_config_is_not_standalone",
            Self::StandalonePolicyFileMissing => "standalone_policy_file_missing",
            Self::SourceSqliteUnreadable { .. } => "source_sqlite_unreadable",
            Self::SourceSnapshotFailed { .. } => "source_snapshot_failed",
            Self::SourceDocumentUnparseable { .. } => "source_document_unparseable",
            Self::TargetNotPostgres => "target_not_postgres",
            Self::TargetDeploymentIdMissing => "target_deployment_id_missing",
            Self::TargetUnavailable { .. } => "target_unavailable",
            Self::TargetSchemaNotCurrent { .. } => "target_schema_not_current",
            Self::TargetDeploymentMismatch { .. } => "target_deployment_mismatch",
            Self::TargetNamespaceNotEmpty { .. } => "target_namespace_not_empty",
            Self::SectionConflict { .. } => "section_conflict",
            Self::SectionFailed { .. } => "section_failed",
            Self::ValidationFailed { .. } => "validation_failed",
            Self::Store(_) => "store_failure",
        }
    }
}

impl fmt::Display for ImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: ", self.code())?;
        match self {
            Self::Usage => formatter.write_str(USAGE),
            Self::StandaloneEnvFileUnreadable { path } => write!(
                formatter,
                "the standalone environment file {} could not be read",
                path.display()
            ),
            Self::StandaloneEnvFileMalformed { line } => write!(
                formatter,
                "line {line} of the standalone environment file is not a KEY=VALUE assignment \
                 (the line's text is withheld: it may be credential material)"
            ),
            Self::StandaloneConfigInvalid { settings } => write!(
                formatter,
                "the standalone configuration is not valid; settings with problems: {} \
                 (values are withheld: some of them are credential material -- run the \
                 standalone gateway against this file to see the full messages)",
                settings.join(", ")
            ),
            Self::StandaloneNotStandalone => formatter.write_str(
                "the --from configuration selects STATE_BACKEND=postgres; it names a cluster, \
                 not the standalone deployment being imported",
            ),
            Self::StandalonePolicyFileMissing => formatter.write_str(
                "the standalone configuration sets no POLICY_FILE; cluster mode refuses to \
                 start without an initialized policy document, so there is nothing to import \
                 that a replica could serve",
            ),
            Self::SourceSqliteUnreadable { setting, path } => write!(
                formatter,
                "{setting} names {}, which exists but could not be opened read-only as a \
                 SQLite database",
                path.display()
            ),
            Self::SourceSnapshotFailed { setting } => write!(
                formatter,
                "the database named by {setting} could not be copied into this command's \
                 private snapshot; the import reads a copy so the standalone deployment's \
                 own files are never written to, and it will not read the original instead"
            ),
            Self::SourceDocumentUnparseable { kind, detail } => write!(
                formatter,
                "a {kind} document on disk is not one this gateway build can read: {detail}"
            ),
            Self::TargetNotPostgres => {
                formatter.write_str("gateway import-standalone requires STATE_BACKEND=postgres")
            }
            Self::TargetDeploymentIdMissing => {
                formatter.write_str("STATE_BACKEND=postgres requires DEPLOYMENT_ID")
            }
            Self::TargetUnavailable { detail } => {
                write!(formatter, "the target database is not usable: {detail}")
            }
            Self::TargetSchemaNotCurrent { detail } => write!(
                formatter,
                "the target schema is not current; run `gateway migrate up` first ({detail})"
            ),
            Self::TargetDeploymentMismatch { bound } => write!(
                formatter,
                "the target database is bound to deployment '{bound}'"
            ),
            Self::TargetNamespaceNotEmpty { occupied } => write!(
                formatter,
                "the target deployment namespace already holds authoritative state ({}); \
                 import into an empty namespace, or pass --resume to continue an \
                 interrupted import",
                occupied.join(", ")
            ),
            Self::SectionConflict { section } => write!(
                formatter,
                "the {section} section's resource is already initialized with a different \
                 document; this namespace is not the one this import started"
            ),
            Self::SectionFailed { section, detail } => {
                write!(formatter, "the {section} section failed: {detail}")
            }
            Self::ValidationFailed { checks } => write!(
                formatter,
                "the import was written but did not verify; failed checks: {}",
                checks.join(", ")
            ),
            Self::Store(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ImportError {}

impl From<RepositoryError> for ImportError {
    fn from(error: RepositoryError) -> Self {
        Self::Store(error)
    }
}

/// One section's result.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct SectionReport {
    pub section: &'static str,
    /// `planned` (dry run), `imported`, or `already-imported` (a resumed
    /// section this import had already committed).
    pub status: &'static str,
    pub counts: BTreeMap<String, i64>,
    /// SHA-256 over the section's canonical export, as `sha256:<hex>`.
    pub checksum: String,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SchemaReport {
    pub status: &'static str,
    pub applied: usize,
    pub version_min: i32,
    pub version_max: i32,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SourceReport {
    pub policy_file: String,
    pub policy_history_file: String,
    pub policy_history_present: bool,
    pub tools_file: Option<String>,
    pub connections_file: Option<String>,
    pub audit_file: Option<String>,
    /// Whether the configured audit database exists. A standalone
    /// deployment that never enabled the SQLite sink has none, which is an
    /// empty log and not a failure.
    pub audit_present: bool,
    pub discovery_file: Option<String>,
    pub discovery_present: bool,
    pub service_token_file: Option<String>,
    /// The principal directory the source holds and the import does NOT
    /// carry: cluster mode has no principal directory, so there is no
    /// destination for it. Named here so an operator sees what stayed
    /// behind instead of finding it missing after the cutover.
    pub principal_file: Option<String>,
    pub principal_present: bool,
    pub policy_history_versions: i64,
    pub tools: i64,
    pub connections: i64,
    /// How many encrypted local-secret rows the Connections database holds
    /// -- key material this command never moves (see [`NOT_IMPORTED`]). A
    /// COUNT, never a row: the metadata answers "how much re-provisioning
    /// does the cutover owe?" and nothing here reads the ciphertext, the
    /// keyring or `CONNECTION_SECRETS_ROOT`.
    pub connection_local_secrets: i64,
    pub discovery_endpoints: i64,
    pub service_tokens: i64,
}

/// The command's whole output: counts, checksums, revisions and durations.
/// Never a token, a secret, login material or a DSN.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ImportReport {
    pub command: &'static str,
    pub mode: &'static str,
    pub deployment_id: String,
    pub schema: SchemaReport,
    pub source: SourceReport,
    pub sections: Vec<SectionReport>,
    /// Step 8: the comparison half. Counts and checksums for BOTH sides,
    /// and the named checks the target had to satisfy.
    pub validation: validation::ValidationReport,
    /// What the import deliberately did not carry. Named on every run so a
    /// complete import cannot be mistaken for a total one.
    pub not_imported: &'static [&'static str],
    pub duration_ms: u64,
}

impl fmt::Display for ImportReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Pretty JSON: the report is read by operators during a cutover
        // and diffed between the dry run and the apply.
        match serde_json::to_string_pretty(self) {
            Ok(json) => formatter.write_str(&json),
            Err(_) => {
                formatter.write_str("{\"error\":\"the import report could not be rendered\"}")
            }
        }
    }
}

/// Run the import against `target` (the process's cluster configuration).
///
/// An apply establishes the foundation exactly as a replica's boot does
/// (`start_if_selected`: schema validation, then the deployment binding),
/// so the import claims the database for this `DEPLOYMENT_ID` the same way
/// and by the same code as everything else that writes to it. A dry run
/// takes the plain connection instead, because both of those steps -- the
/// binding, and the auto-migration a boot may perform -- are writes, and a
/// dry run's whole promise is that it makes none.
#[cfg(feature = "postgres")]
pub(crate) async fn run(
    request: &ImportRequest,
    target: &Config,
) -> Result<ImportReport, ImportError> {
    use crate::storage::postgres::PostgresFoundation;

    let started = Instant::now();

    // Section 1a: the source. Every SQLite read and every document parse
    // is blocking work; a one-shot command still owes the runtime the
    // same discipline the request path keeps.
    let env_file = request.standalone_env_file.clone();
    let source = tokio::task::spawn_blocking(move || StandaloneSource::load(&env_file))
        .await
        .map_err(|error| ImportError::SectionFailed {
            section: "preflight",
            detail: format!("the source could not be read: {error}"),
        })??;

    // Section 1b: the target.
    if target.state_backend != crate::config::StateBackend::Postgres {
        return Err(ImportError::TargetNotPostgres);
    }
    let deployment_id = target
        .deployment_id
        .clone()
        .ok_or(ImportError::TargetDeploymentIdMissing)?;
    // An apply establishes the foundation the way every replica does:
    // `start_if_selected` validates the schema and BINDS the database to
    // this DEPLOYMENT_ID, which is exactly the claim an import should
    // make. A dry run must not make it -- binding is a write, and a dry
    // run that bound a database an operator then decided against would
    // have changed the thing it promised only to read. So a dry run takes
    // the plain connection and relies on preflight, which validates the
    // schema and READS the binding either way.
    let foundation = if request.mode.writes() {
        PostgresFoundation::start_if_selected(target)
            .await
            .map_err(foundation_refusal)?
            .ok_or(ImportError::TargetNotPostgres)?
    } else {
        PostgresFoundation::establish(target)
            .await
            .map_err(foundation_refusal)?
    };
    let pool = foundation.pool().clone();
    let schema = preflight::verify_target(&pool, &deployment_id, request.mode).await?;

    let policy = sections::PolicySection::plan(&source)?;
    let tools = sections::ToolsSection::plan(&source)?;
    let connections = sections::ConnectionsSection::plan(&source)?;
    let audit = sections::AuditSection::plan(&source);
    let discovery = sections::DiscoverySection::plan(&source)?;
    let principals = sections::PrincipalsSection::plan(&source);

    let mut reports = Vec::new();
    if request.mode.writes() {
        reports.push(policy.apply(&pool).await?);
        reports.push(tools.apply(&pool).await?);
        reports.push(connections.apply(&pool).await?);
        // The discovery section reads the stream head the audit section
        // left behind, so the order here is load-bearing.
        reports.push(audit.run(Some(&pool)).await?);
        reports.push(discovery.apply(&pool).await?);
        reports.push(principals.apply(&pool).await?);
    } else {
        reports.push(policy.planned());
        reports.push(tools.planned());
        reports.push(connections.planned());
        // The audit section has no plan separate from its pass: the
        // counts and checksum a dry run reports are produced by reading
        // the whole log, which is exactly what the apply does before it
        // writes anything.
        reports.push(audit.run(None).await?);
        reports.push(discovery.planned());
        reports.push(principals.planned());
    }

    // Step 8. The source-side checksums are the ones the sections just
    // reported, so the comparison is against exactly what was printed
    // rather than a second computation that could differ from it.
    let audit_events = reports
        .iter()
        .find(|report| report.section == "audit")
        .and_then(|report| report.counts.get("audit_events_deduplicated").copied())
        .unwrap_or(0);
    let inputs = validation::ValidationInputs {
        source: &source,
        checksums: reports
            .iter()
            .map(|report| (report.section, report.checksum.clone()))
            .collect(),
        expected_rows: validation::expected_rows(&source, audit_events),
    };
    let verified = validation::run(request.mode.writes().then_some(&pool), &inputs).await?;

    Ok(ImportReport {
        command: "import-standalone",
        mode: request.mode.as_str(),
        deployment_id,
        schema,
        source: source.report(),
        sections: reports,
        validation: verified,
        not_imported: NOT_IMPORTED,
        duration_ms: elapsed_ms(started),
    })
}

/// Classify a foundation failure as the refusal an operator scripts
/// against.
///
/// `start_if_selected` does three things an import can be refused for --
/// reach the database, validate the schema, and BIND it to this
/// `DEPLOYMENT_ID` -- and they are not one condition. Collapsing all of them
/// into `target_unavailable` told an operator pointed at another
/// deployment's database to check their TLS and retry (the runbook reads
/// that code as "a connectivity, TLS or credentials problem"), when the
/// answer is to stop. So each maps to the code that already exists for it,
/// and an apply refuses with the SAME code a dry run of the same target
/// refuses with.
#[cfg(feature = "postgres")]
fn foundation_refusal(error: crate::storage::postgres::PostgresFoundationError) -> ImportError {
    use crate::storage::postgres::PostgresFoundationError as Foundation;

    let detail = error.to_string();
    match error {
        Foundation::DeploymentMismatch { bound } => ImportError::TargetDeploymentMismatch { bound },
        // The schema is not this binary's manifest, or could not be read at
        // all. `gateway migrate up` is the answer to every one of them,
        // which is what `target_schema_not_current` tells the operator.
        Foundation::SchemaNotReady { .. }
        | Foundation::SchemaInvalid { .. }
        | Foundation::SchemaCheckFailed
        | Foundation::SchemaMigrationFailed => ImportError::TargetSchemaNotCurrent { detail },
        Foundation::NotConfigured => ImportError::TargetNotPostgres,
        // Everything left is the database not being reachable and usable:
        // the DSN, the TLS material, the pool, the connectivity budget.
        Foundation::SettingFile { .. }
        | Foundation::DsnRejected { .. }
        | Foundation::TlsRejected { .. }
        | Foundation::StartupExhausted { .. }
        | Foundation::PoolUnbuildable => ImportError::TargetUnavailable { detail },
    }
}

pub(crate) fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// SHA-256 over a canonical JSON export, as `sha256:<hex>`.
///
/// The value is canonicalized with the same `sort_json_value` the ETags
/// use, so the digest depends on the document's content and not on the
/// key order a serializer happened to produce. Both sides of the
/// validation step (issue #241 §9 step 8) can therefore compute the same
/// number from their own reads.
pub(crate) fn canonical_digest(value: &Value) -> String {
    use sha2::{Digest, Sha256};

    let mut value = value.clone();
    crate::sort_json_value(&mut value);
    let bytes = serde_json::to_vec(&value).unwrap_or_default();
    format!("sha256:{}", hex::encode(Sha256::digest(&bytes)))
}

/// [`canonical_digest`] over a SEQUENCE that is never held in memory at
/// once: the audit log's events, folded one at a time as they are paged
/// out of the source.
///
/// Each element is canonicalized exactly as `canonical_digest`
/// canonicalizes a document, and is then framed by its own byte length
/// before being hashed. The framing is what makes the digest a function
/// of the sequence rather than of its concatenation: without it, two
/// different splits of the same bytes would collide, and a checksum that
/// cannot tell two histories apart is not evidence of anything.
pub(crate) struct CanonicalDigestStream {
    hasher: sha2::Sha256,
    elements: u64,
}

impl CanonicalDigestStream {
    pub(crate) fn new() -> Self {
        use sha2::Digest;
        Self {
            hasher: sha2::Sha256::new(),
            elements: 0,
        }
    }

    pub(crate) fn update(&mut self, value: &Value) {
        use sha2::Digest;

        let mut value = value.clone();
        crate::sort_json_value(&mut value);
        let bytes = serde_json::to_vec(&value).unwrap_or_default();
        self.hasher
            .update((bytes.len() as u64).to_be_bytes().as_slice());
        self.hasher.update(&bytes);
        self.elements += 1;
    }

    pub(crate) fn finish(mut self) -> String {
        use sha2::Digest;

        // The element count closes the sequence, so a prefix of a longer
        // history never digests to the same value as the history itself.
        self.hasher.update(self.elements.to_be_bytes().as_slice());
        format!("sha256:{}", hex::encode(self.hasher.finalize()))
    }
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}
