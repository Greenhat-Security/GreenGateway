//! The standalone deployment the import reads (issue #241, PR 15, step 1).
//!
//! Everything here is a READ of the operator's existing standalone state,
//! and every read goes through the parser or store standalone mode itself
//! uses -- `Policy::from_file`, the tools registry's document loader,
//! `PolicyHistoryStore`, `SqliteConnectionStore` -- so a document this
//! import accepts is exactly a document this binary would serve, and a
//! document it refuses is one the cluster could not have served either.
//! No ad-hoc SQL is ever run against the source databases.
//!
//! **Those stores normalize on open, so they are pointed at a COPY.** Each
//! of them runs its schema migrations when it opens a file --
//! `CREATE TABLE`, `ALTER TABLE ADD COLUMN`, `PRAGMA journal_mode=WAL`, and
//! in the discovery suggestions engine's case an `UPDATE` that dismisses
//! every open legacy `baseline_allow` suggestion. Running those against the
//! operator's live standalone deployment would make a `--dry-run` a write,
//! and a rehearsal that mutates the thing it is rehearsing against is worse
//! than no rehearsal. So [`SourceSnapshot`] copies each of those databases
//! into a private temporary directory (`VACUUM INTO`, from a READ-ONLY
//! connection, which is the one copy that is consistent with a WAL file
//! still open), the stores normalize the copies, and the copies are deleted
//! when the load returns. The audit log is not copied -- it is the one
//! unbounded surface, and its query store runs no schema statement at all,
//! so it is opened read-only in place instead.
//!
//! The source's environment is a FILE, not the process environment:
//! `Config::from_env` refuses a configuration that names both a local
//! authority and `STATE_BACKEND=postgres`, so the two configurations
//! cannot share one environment (see the module documentation).

use std::{
    collections::BTreeMap,
    env::VarError,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use serde_json::Value;

use crate::{
    audit::query::AuditQueryStore,
    auth::tokens::{ExportedServiceToken, SqliteTokenStore},
    config::{Config, StateBackend},
    connections::{
        pg_store::ImportedConnection,
        store::{ConnectionStore, SqliteConnectionStore, StoredOpenApiOverlay},
    },
    discovery::{
        aggregator::{AggregatorState, EndpointKey, PendingFlush},
        query::{DiscoveryQueryStore, ExportedEndpointReview, RawSignal},
        suggestions::{RuleSuggestion, RuleSuggestionConfig, RuleSuggestionEngine},
    },
    rbac::{
        policy_history::{PolicyHistoryListFilters, PolicyHistoryStore, PolicyVersion},
        Policy,
    },
};

use super::{display_path, ImportError, SourceReport};

/// How many history rows are read per page from the standalone store. The
/// store's own paging contract is used rather than one unbounded query.
const HISTORY_PAGE: usize = 500;

/// Every SQLite path a standalone configuration can name, with the
/// setting that names it. The import proves each openable read-only in
/// preflight even when the section that reads it lands in a later stage:
/// discovering an unreadable audit database after the policy section has
/// committed would leave the operator resuming an import they could have
/// been refused up front.
fn configured_sqlite_paths(config: &Config) -> Vec<(&'static str, PathBuf)> {
    let mut paths = Vec::new();
    let mut push = |setting: &'static str, value: Option<&String>| {
        if let Some(value) = value {
            paths.push((setting, PathBuf::from(value)));
        }
    };
    push("AUDIT_SQLITE_PATH", config.audit_sqlite_path.as_ref());
    push(
        "DISCOVERY_SQLITE_PATH",
        config.discovery_sqlite_path.as_ref(),
    );
    push(
        "PRINCIPAL_SQLITE_PATH",
        config.principal_sqlite_path.as_ref(),
    );
    push(
        "CONNECTIONS_SQLITE_PATH",
        config.connections_sqlite_path.as_ref(),
    );
    push(
        "SERVICE_TOKEN_SQLITE_PATH",
        config.service_token_sqlite_path.as_ref(),
    );
    if let Some(history) = crate::policy_history_sqlite_path(config) {
        // Named by POLICY_HISTORY_SQLITE_PATH or derived from POLICY_FILE;
        // the setting reported is the one an operator can change.
        paths.push(("POLICY_HISTORY_SQLITE_PATH", history));
    }
    paths
}

/// The standalone state, loaded and validated.
pub(crate) struct StandaloneSource {
    /// The standalone configuration itself. The validation pass reads the
    /// discovery settings back out of it (the endpoint limit, the payload
    /// capture flag, the detector thresholds) so it rebuilds the TARGET's
    /// discovery model with exactly the settings the source's was built
    /// with -- a comparison under two different limits would be a
    /// comparison of two different models.
    pub config: Config,
    pub policy_file: PathBuf,
    pub policy: Policy,
    pub policy_history_file: PathBuf,
    pub policy_history_present: bool,
    /// Oldest-first: the order the cluster's immutable versions take.
    pub history: Vec<PolicyVersion>,
    pub tools_file: Option<PathBuf>,
    /// The tools document to activate. When the standalone configuration
    /// sets no `TOOLS_FILE` this is the empty document -- exactly what
    /// standalone mode serves without one, and what a cluster's first
    /// boot would otherwise seed.
    pub tools_document: Value,
    pub connections_file: Option<PathBuf>,
    /// Every managed Connection and everything durable that hangs off it,
    /// read through the standalone store (which validates each record and
    /// its credential bindings on the way out). Bounded by the store's own
    /// ceilings -- 256 records, 512 bindings, 4,096 catalog entries and
    /// status rows -- so the whole set is held in memory deliberately.
    pub connections: Vec<ImportedConnection>,
    /// How many encrypted local-secret rows the Connections database holds.
    /// A COUNT and nothing else: the keyring is key material, the import
    /// never moves it, and an operator whose bindings resolved through it
    /// has re-provisioning to do after the cutover. Reported so the size of
    /// that job is visible during the rehearsal.
    pub connection_local_secrets: i64,
    pub audit_file: Option<PathBuf>,
    /// The standalone audit log, open for reading. NOT read into memory:
    /// the log is the one part of a standalone deployment with no bound
    /// at all, so the audit section pages it (see
    /// [`AuditQueryStore::events_after`]) instead.
    pub audit: Option<Arc<AuditQueryStore>>,
    pub discovery_file: Option<PathBuf>,
    /// The endpoint inventory and its lifecycle rows, or `None` when the
    /// standalone deployment never ran discovery. Bounded by
    /// `DISCOVERY_ENDPOINT_LIMIT`, which is what the aggregator itself
    /// holds in memory, so reading the whole set is the same working set
    /// the standalone process had.
    pub discovery: Option<StandaloneDiscovery>,
    pub service_token_file: Option<PathBuf>,
    /// Every service token as stored, hash included. The plaintext never
    /// existed on disk and is not here; the hash is what makes an issued
    /// token still verify after the cutover.
    pub service_tokens: Vec<ExportedServiceToken>,
    pub principal_file: Option<PathBuf>,
    /// Whether a principal directory exists in the source. It is NOT read
    /// and NOT imported: cluster mode has no principal directory at all
    /// (`Config` refuses `PRINCIPAL_SQLITE_PATH` alongside
    /// `STATE_BACKEND=postgres`, and no migration creates the table), so
    /// there is no destination for it. Opening one would also START a
    /// flusher thread against the source, which an import must never do.
    /// The report names the file so an operator can see what was left
    /// behind rather than discovering it missing later.
    pub principal_present: bool,
}

/// The standalone deployment's discovery state, rebuilt through the model
/// the aggregator itself rebuilds with.
///
/// `AggregatorState::from_rows` is the same call a standalone restart
/// makes: it applies the endpoint limit, drops rows for endpoints the
/// aggregates table no longer holds, and rebuilds each endpoint's
/// classified-signal counters. What the import writes is therefore the
/// working set the standalone process WOULD have held on its next start,
/// not a second reading of the same tables that could differ from it.
///
/// The detector windows and learner groups come from that same rebuilt
/// state (issue #241 §9 step 6). SQLite never persisted either, so what is
/// carried across is what a standalone restart would have had -- the
/// counters, with empty rolling windows -- rather than nothing at all:
/// the counters are what the `new_endpoint_seen`, `schema_mismatch` and
/// `principal_new_to_endpoint` detectors compare against, so carrying them
/// is what stops the cluster's first projector run from raising the whole
/// inventory's signals a second time.
pub(crate) struct StandaloneDiscovery {
    /// Every endpoint aggregate, as one batch, ordered by key.
    pub batch: PendingFlush,
    pub detector_states: Vec<(EndpointKey, String)>,
    pub template_groups_json: Option<String>,
    pub signals: Vec<RawSignal>,
    pub suggestions: Vec<RuleSuggestion>,
    pub reviews: Vec<ExportedEndpointReview>,
    pub payload_capture_enabled: bool,
}

impl StandaloneSource {
    /// Read and validate the whole source. Blocking: the caller runs it on
    /// Tokio's blocking pool.
    pub(crate) fn load(env_file: &Path) -> Result<Self, ImportError> {
        let variables = read_env_file(env_file)?;
        let config =
            Config::from_env_vars(|name| variables.get(name).cloned().ok_or(VarError::NotPresent))
                .map_err(|error| ImportError::StandaloneConfigInvalid {
                    settings: setting_names(error.problems()),
                })?;
        if config.state_backend != StateBackend::Sqlite {
            return Err(ImportError::StandaloneNotStandalone);
        }
        let Some(policy_file) = config.policy_file.clone().map(PathBuf::from) else {
            return Err(ImportError::StandalonePolicyFileMissing);
        };

        // Every configured SQLite file that exists must open READ-ONLY
        // before anything else happens. A file that cannot be read is the
        // cheapest possible refusal, and opening read-only proves the
        // import needs no write access to the source to make the claim.
        let sqlite_paths = configured_sqlite_paths(&config);
        for (setting, path) in &sqlite_paths {
            if path.exists() {
                open_read_only(setting, path)?;
            }
        }

        // The private copies the normalizing stores are pointed at. Held
        // for the whole load and deleted when it returns: everything read
        // through them is in memory by then, and the audit store -- the one
        // reader that outlives this function -- reads the original file
        // read-only rather than a copy.
        let snapshot = SourceSnapshot::create()?;

        let policy = Policy::from_file(&policy_file).map_err(|error| {
            ImportError::SourceDocumentUnparseable {
                kind: "policy",
                detail: error.to_string(),
            }
        })?;

        let policy_history_file = crate::policy_history_sqlite_path(&config)
            .unwrap_or_else(|| PathBuf::from(format!("{}.history.sqlite", policy_file.display())));
        let policy_history_present = policy_history_file.exists();
        let history = if policy_history_present {
            read_history(&snapshot.copy_of(
                "POLICY_HISTORY_SQLITE_PATH",
                "policy-history",
                &policy_history_file,
            )?)?
        } else {
            // A standalone deployment that never edited its policy has no
            // history database. That is an empty history, not a failure --
            // and the import must not CREATE the file by opening it.
            Vec::new()
        };

        let tools_file = config.tools_file.clone().map(PathBuf::from);
        let tools_document = match tools_file.as_deref() {
            Some(path) => {
                crate::tools::definitions::tools_document_from_file(path).map_err(|error| {
                    ImportError::SourceDocumentUnparseable {
                        kind: "tools",
                        detail: error.to_string(),
                    }
                })?
            }
            None => empty_tools_document(),
        };

        let connections_file = config.connections_sqlite_path.clone().map(PathBuf::from);
        let (connections, connection_local_secrets) = match connections_file.as_deref() {
            Some(path) if path.exists() => read_connections(&snapshot.copy_of(
                "CONNECTIONS_SQLITE_PATH",
                "connections",
                path,
            )?)?,
            // A standalone deployment that never created a Connection has
            // no database. Opening the path would CREATE one; there is
            // nothing to import, so it is not opened.
            _ => (Vec::new(), 0),
        };

        let audit_file = config.audit_sqlite_path.clone().map(PathBuf::from);
        let audit = match audit_file.as_deref() {
            Some(path) if path.exists() => Some(Arc::new(open_audit(path)?)),
            _ => None,
        };

        let discovery_file = config.discovery_sqlite_path.clone().map(PathBuf::from);
        let discovery = match discovery_file.as_deref() {
            Some(path) if path.exists() => Some(read_discovery(
                &snapshot.copy_of("DISCOVERY_SQLITE_PATH", "discovery", path)?,
                &config,
            )?),
            // A standalone deployment that never enabled discovery has no
            // database. Opening the path would CREATE one.
            _ => None,
        };

        let service_token_file = config.service_token_sqlite_path.clone().map(PathBuf::from);
        let service_tokens = match service_token_file.as_deref() {
            Some(path) if path.exists() => read_service_tokens(&snapshot.copy_of(
                "SERVICE_TOKEN_SQLITE_PATH",
                "service-tokens",
                path,
            )?)?,
            _ => Vec::new(),
        };

        let principal_file = config.principal_sqlite_path.clone().map(PathBuf::from);
        let principal_present = principal_file.as_deref().is_some_and(Path::exists);

        // Everything read through a copy is in memory now. The copies go.
        drop(snapshot);

        Ok(Self {
            config,
            policy_file,
            policy,
            policy_history_file,
            policy_history_present,
            history,
            tools_file,
            tools_document,
            connections_file,
            connections,
            connection_local_secrets,
            audit_file,
            audit,
            discovery_file,
            discovery,
            service_token_file,
            service_tokens,
            principal_file,
            principal_present,
        })
    }

    pub(crate) fn report(&self) -> SourceReport {
        SourceReport {
            policy_file: display_path(&self.policy_file),
            policy_history_file: display_path(&self.policy_history_file),
            policy_history_present: self.policy_history_present,
            tools_file: self.tools_file.as_deref().map(display_path),
            connections_file: self.connections_file.as_deref().map(display_path),
            audit_file: self.audit_file.as_deref().map(display_path),
            audit_present: self.audit.is_some(),
            discovery_file: self.discovery_file.as_deref().map(display_path),
            discovery_present: self.discovery.is_some(),
            service_token_file: self.service_token_file.as_deref().map(display_path),
            principal_file: self.principal_file.as_deref().map(display_path),
            principal_present: self.principal_present,
            policy_history_versions: i64::try_from(self.history.len()).unwrap_or(i64::MAX),
            tools: tool_count(&self.tools_document),
            connections: i64::try_from(self.connections.len()).unwrap_or(i64::MAX),
            connection_local_secrets: self.connection_local_secrets,
            discovery_endpoints: self
                .discovery
                .as_ref()
                .map(|discovery| {
                    i64::try_from(discovery.batch.dirty_aggregates.len()).unwrap_or(i64::MAX)
                })
                .unwrap_or(0),
            service_tokens: i64::try_from(self.service_tokens.len()).unwrap_or(i64::MAX),
        }
    }
}

/// The document a standalone gateway serves without `TOOLS_FILE`, and the
/// one a cluster's first boot seeds. Kept in step with
/// `postgres_tools::empty_tools_document` by the tools section's ETag,
/// which is computed by the same helper the store uses.
pub(crate) fn empty_tools_document() -> Value {
    serde_json::json!({
        "schema_version": "0.1.0",
        "tools": [],
    })
}

pub(crate) fn tool_count(document: &Value) -> i64 {
    document["tools"]
        .as_array()
        .map(|tools| i64::try_from(tools.len()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Parse a `KEY=VALUE` environment file in the shape `.env.example`
/// ships and `docker compose env_file` / systemd `EnvironmentFile` read:
/// blank lines and `#` comments ignored, the value taken verbatim after
/// the first `=` (so a value containing `=` survives), later assignments
/// winning over earlier ones.
///
/// A malformed line is reported by NUMBER only. The text of a line in a
/// standalone deployment's environment file may be a keyring key or a
/// client secret, and an error message is the last place either belongs.
pub(super) fn read_env_file(path: &Path) -> Result<BTreeMap<String, String>, ImportError> {
    let contents =
        fs::read_to_string(path).map_err(|_| ImportError::StandaloneEnvFileUnreadable {
            path: path.to_path_buf(),
        })?;
    let mut variables = BTreeMap::new();
    for (index, line) in contents.lines().enumerate() {
        let trimmed_end = line.trim_end();
        let trimmed = trimmed_end.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // `export KEY=VALUE` is the other shape operators write.
        let assignment = trimmed.strip_prefix("export ").unwrap_or(trimmed);
        let Some((key, value)) = assignment.split_once('=') else {
            return Err(ImportError::StandaloneEnvFileMalformed { line: index + 1 });
        };
        let key = key.trim();
        if key.is_empty() {
            return Err(ImportError::StandaloneEnvFileMalformed { line: index + 1 });
        }
        variables.insert(key.to_owned(), value.to_owned());
    }
    Ok(variables)
}

/// The leading setting name of each validation problem, deduplicated.
///
/// Every problem the validator produces starts with the setting's name
/// (`FOO_BAR must be ...`); a problem that does not is reported as an
/// unnamed one rather than being echoed, because the part that would
/// identify it is also the part that may quote a value.
fn setting_names(problems: &[String]) -> Vec<String> {
    let mut names: Vec<String> = problems
        .iter()
        .map(|problem| {
            let name: String = problem
                .chars()
                .take_while(|character| {
                    character.is_ascii_uppercase()
                        || character.is_ascii_digit()
                        || *character == '_'
                })
                .collect();
            if name.len() >= 3 {
                name
            } else {
                "<unnamed setting>".to_owned()
            }
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Prove the file is a SQLite database this process can read without
/// asking for write access. `SQLITE_OPEN_READ_ONLY` never creates the
/// file and never upgrades the journal, so the check itself cannot
/// modify the standalone deployment's state.
fn open_read_only(setting: &'static str, path: &Path) -> Result<(), ImportError> {
    use rusqlite::{Connection, OpenFlags};

    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| ImportError::SourceSqliteUnreadable {
        setting,
        path: path.to_path_buf(),
    })?;
    // Opening is lazy: the header is only read on first use, so a file
    // that is not a database at all opens and then fails. Touch it.
    connection
        .pragma_query_value(None, "user_version", |_| Ok(()))
        .map_err(|_| ImportError::SourceSqliteUnreadable {
            setting,
            path: path.to_path_buf(),
        })
}

/// The standalone policy history, oldest-first, read through the store's
/// own paging contract (newest-first pages walked with its version
/// cursor) rather than a query of our own.
fn read_history(path: &Path) -> Result<Vec<PolicyVersion>, ImportError> {
    let store =
        PolicyHistoryStore::open(path).map_err(|error| ImportError::SourceDocumentUnparseable {
            kind: "policy history",
            detail: error.to_string(),
        })?;
    let mut versions = Vec::new();
    let mut cursor = None;
    loop {
        let page = store
            .list_versions(&PolicyHistoryListFilters {
                limit: HISTORY_PAGE,
                cursor: cursor.clone(),
                include_policy: true,
            })
            .map_err(|error| ImportError::SourceDocumentUnparseable {
                kind: "policy history",
                detail: error.to_string(),
            })?;
        versions.extend(page.versions);
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    // The store pages newest-first; the cluster's immutable versions are
    // written oldest-first so their numbering is the source's.
    versions.reverse();
    Ok(versions)
}

/// Read every managed Connection and everything durable that hangs off
/// it, through the standalone store's own surfaces.
///
/// `list` is also the "every Connection document on disk parses" half of
/// preflight: it decodes each specification, re-validates it, and checks
/// the record against its derived credential bindings, so a Connection
/// this import accepts is exactly one this binary would serve.
///
/// Secrets are not here and are never read: a credential binding is a
/// PURPOSE, a SECRET ID and a version. The value behind that id lives in
/// the operator's secret store -- or, for a local-secret keyring, in a
/// file bound to `CONNECTIONS_SQLITE_PATH` that cluster mode has no
/// counterpart for and this command never touches.
/// Returns the Connections and the NUMBER of encrypted local secrets the
/// database holds. The count is metadata -- `SELECT COUNT(*)` through the
/// store's own helper -- and no ciphertext, key or keyring path is read:
/// the import carries bindings as references and the report says how many
/// secrets stayed behind.
fn read_connections(path: &Path) -> Result<(Vec<ImportedConnection>, i64), ImportError> {
    let store = SqliteConnectionStore::open(path).map_err(connection_source_error)?;
    let local_secrets = i64::try_from(
        store
            .local_secret_count()
            .map_err(connection_source_error)?,
    )
    .unwrap_or(i64::MAX);
    let records = store.list().map_err(connection_source_error)?;
    let mut activity = store.activity_times().map_err(connection_source_error)?;
    let statuses = store.exported_statuses().map_err(connection_source_error)?;
    let mut mcp_catalogs: BTreeMap<_, _> = store
        .mcp_catalogs()
        .map_err(connection_source_error)?
        .into_iter()
        .map(|catalog| (catalog.connection_id.clone(), catalog))
        .collect();
    let mut openapi_catalogs: BTreeMap<_, _> = store
        .openapi_catalogs()
        .map_err(connection_source_error)?
        .into_iter()
        .map(|catalog| (catalog.connection_id.clone(), catalog))
        .collect();
    let openapi_overlays = store.openapi_overlays().map_err(connection_source_error)?;
    for overlay in &openapi_overlays {
        validate_imported_openapi_overlay(overlay)?;
    }
    let mut openapi_overlays: BTreeMap<_, _> = openapi_overlays
        .into_iter()
        .map(|overlay| (overlay.connection_id.clone(), overlay))
        .collect();

    // Dynamic enum rows belong to a later importer revision. Their absence
    // is not an overlay compatibility check: every durable overlay above is
    // decoded and validated by this binary independently before this
    // forward-version gate is considered.
    let enum_source_values = store
        .openapi_enum_source_value_count()
        .map_err(connection_source_error)?;
    if enum_source_values != 0 {
        return Err(ImportError::SourceDocumentUnparseable {
            kind: "Connection",
            detail: format!(
                "the Connections database contains {enum_source_values} dynamic OpenAPI enum \
                 source value row(s), which this importer cannot preserve; run the import with \
                 an enum-capable gateway version"
            ),
        });
    }

    let mut current_statuses: BTreeMap<_, _> = statuses
        .current
        .into_iter()
        .map(|status| (status.connection_id.clone(), status))
        .collect();
    let mut history: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for status in statuses.history {
        history
            .entry(status.connection_id.clone())
            .or_default()
            .push(status);
    }

    let mut connections = Vec::with_capacity(records.len());
    for record in records {
        let dependencies = store
            .dependencies(&record.id)
            .map_err(connection_source_error)?;
        connections.push(ImportedConnection {
            activity: activity.remove(&record.id).unwrap_or_default(),
            dependencies,
            current_status: current_statuses.remove(&record.id),
            status_history: history.remove(&record.id).unwrap_or_default(),
            mcp_catalog: mcp_catalogs.remove(&record.id),
            openapi_catalog: openapi_catalogs.remove(&record.id),
            openapi_overlay: openapi_overlays.remove(&record.id),
            record,
        });
    }
    // A status, catalog or activity row whose Connection is gone is a
    // source the standalone store's own foreign keys say cannot exist.
    // Refusing here means the import never silently drops durable state.
    if !current_statuses.is_empty()
        || !history.is_empty()
        || !mcp_catalogs.is_empty()
        || !openapi_catalogs.is_empty()
        || !openapi_overlays.is_empty()
        || !activity.is_empty()
    {
        return Err(ImportError::SourceDocumentUnparseable {
            kind: "Connection",
            detail:
                "the Connections database holds status, catalog, overlay, or activity rows for \
                     Connections it has no record of"
                    .to_owned(),
        });
    }
    Ok((connections, local_secrets))
}

/// Decode and validate a stored overlay with the same schema, Rust model,
/// and catalog-free semantic validator used by preview and PUT. The SQLite
/// store deliberately treats the document as opaque JSON bytes, so opening
/// the store alone cannot prove that this binary could serve the overlay
/// after it is imported.
fn validate_imported_openapi_overlay(overlay: &StoredOpenApiOverlay) -> Result<(), ImportError> {
    let document = serde_json::from_str::<Value>(&overlay.overlay_json).map_err(|error| {
        ImportError::SourceDocumentUnparseable {
            kind: "Connection",
            detail: format!(
                "stored OpenAPI overlay for {} is not JSON: {error}",
                overlay.connection_id
            ),
        }
    })?;
    let parsed = crate::tools::overlay::validate(&document).map_err(|error| {
        ImportError::SourceDocumentUnparseable {
            kind: "Connection",
            detail: format!(
                "stored OpenAPI overlay for {} is not supported: {error}",
                overlay.connection_id
            ),
        }
    })?;
    if parsed.schema_version != overlay.schema_version {
        return Err(ImportError::SourceDocumentUnparseable {
            kind: "Connection",
            detail: format!(
                "stored OpenAPI overlay for {} declares schema_version '{}' but its row records '{}'",
                overlay.connection_id, parsed.schema_version, overlay.schema_version
            ),
        });
    }
    Ok(())
}

fn connection_source_error(error: crate::connections::store::ConnectionStoreError) -> ImportError {
    ImportError::SourceDocumentUnparseable {
        kind: "Connection",
        detail: error.to_string(),
    }
}

/// Read the standalone deployment's discovery state through the stores
/// standalone mode reads it with.
///
/// `DiscoveryQueryStore::open` and `RuleSuggestionEngine::open` NORMALIZE
/// the source's schema the way a standalone start normalizes it -- they
/// create missing tables, add the revision columns migration 11's SQLite
/// twin adds, and dismiss the legacy baseline suggestions the issuer-bound
/// migration dismisses. That is a write to the source, and it is the
/// deliberate choice: it is exactly what the standalone binary would do on
/// its next boot, so the import carries the state the operator's own
/// gateway would next have served, and a suggestion that binary would
/// dismiss is never imported as open. The cutover runbook's order (stop
/// the standalone control plane, back up, migrate, import) is what makes
/// that safe. `SqliteConnectionStore::open` already normalizes the
/// Connections database the same way.
///
/// No ad-hoc SQL: the aggregate rows come from the reader the aggregator
/// sink itself loads with, and the working set is rebuilt by the same
/// `from_rows` a restart calls.
fn read_discovery(path: &Path, config: &Config) -> Result<StandaloneDiscovery, ImportError> {
    let store = DiscoveryQueryStore::open(path).map_err(discovery_source_error)?;
    let rows = store
        .loaded_rows(config.payload_capture_enabled)
        .map_err(discovery_source_error)?;
    let mut state = AggregatorState::from_rows(
        rows,
        config.payload_capture_enabled,
        config.discovery_endpoint_limit,
        config.signal_detector_config(),
    )
    .map_err(|error| ImportError::SourceDocumentUnparseable {
        kind: "discovery",
        detail: error.to_string(),
    })?;
    let batch = state.full_flush();
    let detector_states = AggregatorState::detector_states_for(&batch);
    // The learner persisted nothing in SQLite, so this is normally "[]".
    // An empty export is written as no row at all: a groups row saying
    // "no groups" and no row are the same state to `from_rows`, and the
    // report should not claim a snapshot that carries nothing.
    let template_groups_json = {
        let exported = state.template_groups_json_within(
            crate::storage::postgres_discovery::TEMPLATE_GROUPS_MAX_BYTES,
        );
        (exported != "[]").then_some(exported)
    };

    let signals = store.exported_signals().map_err(discovery_source_error)?;
    let reviews = store.exported_reviews().map_err(discovery_source_error)?;
    // The suggestion engine owns the suggestions table and is the surface
    // that decodes a row into a `RuleSuggestion` (proposed rule included),
    // so a suggestion this import accepts is one this binary can serve.
    // No audit path: the engine only reads the log to GENERATE, and the
    // import generates nothing.
    let suggestions =
        RuleSuggestionEngine::open(path, Option::<&Path>::None, RuleSuggestionConfig::default())
            .and_then(|engine| engine.list_suggestions())
            .map_err(|error| ImportError::SourceDocumentUnparseable {
                kind: "rule suggestion",
                detail: error.to_string(),
            })?;

    Ok(StandaloneDiscovery {
        batch,
        detector_states,
        template_groups_json,
        signals,
        suggestions,
        reviews,
        payload_capture_enabled: config.payload_capture_enabled,
    })
}

fn discovery_source_error(error: crate::discovery::query::DiscoveryQueryError) -> ImportError {
    ImportError::SourceDocumentUnparseable {
        kind: "discovery",
        detail: error.to_string(),
    }
}

/// Read the standalone service tokens through the store standalone serves
/// them from. Hashes, never plaintext: the plaintext appears once, in the
/// response to the create that minted it, and was never written down.
fn read_service_tokens(path: &Path) -> Result<Vec<ExportedServiceToken>, ImportError> {
    SqliteTokenStore::open(path)
        .and_then(|store| store.exported_tokens())
        .map_err(|error| ImportError::SourceDocumentUnparseable {
            kind: "service token",
            detail: error.to_string(),
        })
}

/// Open the standalone audit log for reading, through the query store the
/// admin API reads it with. The log is not read here: it is the one
/// standalone surface with no bound, so the audit section pages it.
///
/// READ-ONLY, and the only source database opened in place rather than
/// through [`SourceSnapshot`]. The query store runs no schema statement on
/// open, so there is nothing to normalize; a read-only connection also
/// never checkpoints the write-ahead log on close, so a dry run leaves the
/// file byte-for-byte as it found it. Copying it instead would double the
/// disk a rehearsal needs on the one file that has no size bound.
fn open_audit(path: &Path) -> Result<AuditQueryStore, ImportError> {
    AuditQueryStore::open_read_only(path).map_err(|error| ImportError::SourceDocumentUnparseable {
        kind: "audit log",
        detail: error.to_string(),
    })
}

/// The import's private copies of the standalone databases whose readers
/// normalize a schema on open (issue #241, PR 15, step 1).
///
/// Every store this module reads the source with runs its own migrations
/// when it opens a file, and one of them -- the discovery suggestions
/// engine -- also runs an `UPDATE` that dismisses open legacy
/// `baseline_allow` suggestions. Pointed at the operator's live standalone
/// deployment, a `--dry-run` would therefore write to the thing it is
/// rehearsing a cutover against, and a run that then refuses (a mismatched
/// target, a namespace that is not empty) would have written to the source
/// and nothing else. Pointed at a copy, the same normalization produces the
/// same read and the source is untouched in every mode.
///
/// The copy is `VACUUM INTO` on a READ-ONLY connection, not a file copy: it
/// asks SQLite for one consistent database file, so a source with a
/// write-ahead log the standalone process is still appending to snapshots
/// as a single committed state rather than as a torn pair of files. The
/// directory is removed when the value is dropped, which is when the load
/// returns.
struct SourceSnapshot {
    directory: PathBuf,
}

impl SourceSnapshot {
    fn create() -> Result<Self, ImportError> {
        let directory = std::env::temp_dir().join(format!(
            "greengateway-import-source-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&directory)
            .map_err(|_| ImportError::SourceSnapshotFailed { setting: "TMPDIR" })?;
        Ok(Self { directory })
    }

    /// A private copy of `path`, named by `label` inside the snapshot
    /// directory. `setting` is the configuration setting that named the
    /// original, so a refusal points at something the operator can change.
    fn copy_of(
        &self,
        setting: &'static str,
        label: &str,
        path: &Path,
    ) -> Result<PathBuf, ImportError> {
        use rusqlite::{Connection, OpenFlags};

        let destination = self.directory.join(format!("{label}.sqlite"));
        let source = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| ImportError::SourceSqliteUnreadable {
            setting,
            path: path.to_path_buf(),
        })?;
        // `VACUUM INTO` is the only statement this module runs against a
        // source database, and it reads: it writes exclusively to the file
        // named in the clause, which is why it is legal on the read-only
        // connection above.
        source
            .execute(
                "VACUUM INTO ?1",
                rusqlite::params![path_argument(&destination)?],
            )
            .map_err(|_| ImportError::SourceSnapshotFailed { setting })?;
        Ok(destination)
    }
}

impl Drop for SourceSnapshot {
    fn drop(&mut self) {
        // Best effort: a temp directory that survives a crash is a
        // nuisance, and there is nothing useful to do about a failure here
        // in the middle of a one-shot command's teardown.
        let _ = fs::remove_dir_all(&self.directory);
    }
}

/// The snapshot path as the string SQLite's `VACUUM INTO` takes. The
/// directory is this process's own temporary directory, so a path that is
/// not valid UTF-8 is a refusal rather than something to guess at.
fn path_argument(path: &Path) -> Result<&str, ImportError> {
    path.to_str()
        .ok_or(ImportError::SourceSnapshotFailed { setting: "TMPDIR" })
}
