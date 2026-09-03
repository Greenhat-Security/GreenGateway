//! The import's write sections (issue #241, PR 15, steps 2-7).
//!
//! Each section is planned from the source alone -- which is what
//! `--dry-run` prints -- and then applied in ONE transaction. A section
//! that fails leaves the sections before it committed, so the run is
//! resumable; a section that has already been applied recognizes its own
//! work by the resource's natural key and writes nothing.
//!
//! The section-2 sequence itself is not re-implemented here. The policy
//! section runs `commit_policy_in` -- the reviewed lock/precondition/
//! version/revision/pointer/outbox transaction -- between its own
//! statements, exactly as rule-suggestion acceptance does, and the tools
//! section calls the tools store's own commit, which also reserves the
//! local lane's tool names inside that same transaction. What is new here
//! is only the history: imported versions keep the standalone
//! deployment's numbering, actors and timestamps, and are written by the
//! one write path that names a version
//! ([`insert_imported_policy_versions_in`]).

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Instant,
};

use serde_json::{json, Value};

use crate::{
    audit::{query::AuditQueryStore, AuditEvent},
    connections::{
        pg_store::{import_connections_in, ImportedConnection, ImportedConnectionCounts},
        store::expected_bindings,
    },
    storage::{
        postgres::classify_pool_error,
        postgres_audit::PostgresAuditEventStore,
        postgres_discovery::{import_discovery_in, ImportedDiscovery},
        postgres_documents::{begin, end_transaction},
        postgres_policy::{
            commit_policy_in, insert_imported_policy_versions_in, ImportedPolicyVersion,
            PostgresPolicyStore,
        },
        postgres_service_tokens::import_service_tokens_in,
        postgres_tools::PostgresToolStore,
        AuditEventStore, PolicyCommitError, PolicyCommitPrecondition, PolicyCommitRequest,
        PolicyControlPlane, RepositoryError, ToolControlPlane,
    },
};

use super::{
    canonical_digest, elapsed_ms,
    exports::{
        connections_export, counts, discovery_export, event_export, normalized_instant,
        policy_export, service_tokens_export, tool_names, tools_export, AUDIT_SECTION,
        CONNECTIONS_SECTION, DISCOVERY_SECTION, POLICY_SECTION, PRINCIPALS_SECTION, TOOLS_SECTION,
    },
    source::{tool_count, StandaloneDiscovery},
    CanonicalDigestStream, ImportError, SectionReport, StandaloneSource, IMPORT_ACTOR,
};

const POLICY_OPERATION: &str = "import_policy_section";
const CONNECTIONS_OPERATION: &str = "import_connections_section";
const DISCOVERY_OPERATION: &str = "import_discovery_section";
const PRINCIPALS_OPERATION: &str = "import_principals_section";

/// Step 2: the policy document and its history.
///
/// The standalone history becomes the cluster's immutable versions with
/// its own numbering intact, and the standalone POLICY FILE is then
/// ACTIVATED as the next version through the section-2 commit. The
/// activation is a control-plane event of its own and gets its own
/// version deliberately: the import never points the active pointer at a
/// row it did not write in the same transaction, and an operator reading
/// the history can see exactly when the deployment became a cluster.
pub(super) struct PolicySection {
    versions: Vec<ImportedPolicyVersion>,
    policy: crate::rbac::Policy,
    active_etag: String,
    checksum: String,
}

impl PolicySection {
    pub(super) fn plan(source: &StandaloneSource) -> Result<Self, ImportError> {
        let export = policy_export(&source.history, &source.policy)?;
        let mut versions = Vec::with_capacity(source.history.len());
        for (entry, exported) in source.history.iter().zip(
            export["history"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or(&[]),
        ) {
            versions.push(ImportedPolicyVersion {
                version: entry.version,
                actor_user_id: entry.actor_user_id.clone(),
                // Truncated to the column's precision on the way IN, so
                // the stored value is the one the validation digests on
                // both sides; see `normalized_instant`.
                created_at: normalized_instant(Some(&entry.created_at))
                    .unwrap_or_else(|| entry.created_at.clone()),
                diff_summary_json: entry.diff_summary.to_string(),
                document_json: exported["document"].to_string(),
                document_etag: exported["etag"].as_str().unwrap_or_default().to_owned(),
            });
        }
        let active_etag = export["active_etag"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        Ok(Self {
            versions,
            policy: source.policy.clone(),
            active_etag,
            checksum: canonical_digest(&export),
        })
    }

    /// What `--dry-run` reports: the counts and checksum an apply would
    /// produce, with nothing written.
    pub(super) fn planned(&self) -> SectionReport {
        let history = i64::try_from(self.versions.len()).unwrap_or(i64::MAX);
        SectionReport {
            section: POLICY_SECTION,
            status: "planned",
            counts: counts([
                ("policy_history_versions", history),
                ("policy_documents", history + 1),
                ("policy_active_version", history + 1),
            ]),
            checksum: self.checksum.clone(),
            duration_ms: 0,
        }
    }

    pub(super) async fn apply(
        &self,
        pool: &deadpool_postgres::Pool,
    ) -> Result<SectionReport, ImportError> {
        let started = Instant::now();
        let store = PostgresPolicyStore::new(pool.clone());
        // Resume: a committed policy section is recognized by the active
        // document's ETag, which is the resource's natural key. An active
        // document that is NOT this import's is a namespace that belongs
        // to somebody else, and no re-run repairs that.
        match PolicyControlPlane::active(&store).await {
            Ok(Some(active)) if active.etag == self.active_etag => {
                return Ok(SectionReport {
                    section: POLICY_SECTION,
                    status: "already-imported",
                    counts: counts([
                        ("policy_history_versions", 0),
                        ("policy_active_version", active.version),
                        ("security_revision", active.security_revision),
                    ]),
                    checksum: self.checksum.clone(),
                    duration_ms: elapsed_ms(started),
                })
            }
            Ok(Some(_)) => {
                return Err(ImportError::SectionConflict {
                    section: POLICY_SECTION,
                })
            }
            Ok(None) => {}
            Err(error) => return Err(ImportError::Store(error)),
        }

        let diff_summary = json!({
            "action": "imported_from_standalone",
            "source": "policy_file",
            "history_versions": self.versions.len(),
        });
        let client = pool
            .get()
            .await
            .map_err(crate::storage::postgres::classify_pool_error)?;
        begin(&client, POLICY_OPERATION).await?;
        let outcome = self.apply_in(&client, &diff_summary).await;
        let (inserted, active) =
            end_transaction(&client, POLICY_OPERATION, outcome, ImportError::from).await?;

        Ok(SectionReport {
            section: POLICY_SECTION,
            status: "imported",
            counts: counts([
                (
                    "policy_history_versions",
                    i64::try_from(inserted).unwrap_or(i64::MAX),
                ),
                ("policy_active_version", active.version),
                ("security_revision", active.security_revision),
            ]),
            checksum: self.checksum.clone(),
            duration_ms: elapsed_ms(started),
        })
    }

    /// The section's whole transaction body: the history, then the
    /// activation. One `BEGIN`/`COMMIT` covers both, so a failure in
    /// either leaves the namespace exactly as it was.
    async fn apply_in(
        &self,
        client: &deadpool_postgres::Object,
        diff_summary: &Value,
    ) -> Result<(u64, crate::storage::ActivePolicy), ImportError> {
        let inserted = insert_imported_policy_versions_in(client, &self.versions).await?;
        let active = commit_policy_in(
            client,
            PolicyCommitRequest {
                precondition: PolicyCommitPrecondition::Initialize,
                candidate: &self.policy,
                actor_user_id: IMPORT_ACTOR,
                diff_summary,
            },
        )
        .await
        .map_err(|error| commit_failure(POLICY_SECTION, error))?;
        Ok((inserted, active))
    }
}

/// Step 3: the tools document and the local lane's name reservations.
///
/// The store's own commit does both in one transaction: the document
/// becomes version 1 of the tools control plane, its `tools[].name` values
/// are reserved for the local lane at the authority, and the shared
/// security revision advances once. A standalone deployment with no
/// `TOOLS_FILE` imports the empty document -- which is what it was already
/// serving, and what a cluster's first boot would otherwise seed.
pub(super) struct ToolsSection {
    document: Value,
    etag: String,
    names: Vec<String>,
    checksum: String,
}

impl ToolsSection {
    pub(super) fn plan(source: &StandaloneSource) -> Result<Self, ImportError> {
        let document = source.tools_document.clone();
        let etag = crate::tools_file_etag(&document).map_err(|error| {
            ImportError::SourceDocumentUnparseable {
                kind: "tools",
                detail: error.to_string(),
            }
        })?;
        // The names the authority will hold for the local lane, in the
        // same shape the store reserves them: `tools[].name`, verbatim,
        // deduplicated and ordered.
        let names = tool_names(&document);
        let checksum = canonical_digest(&tools_export(&document, &etag, &names));
        Ok(Self {
            document,
            etag,
            names,
            checksum,
        })
    }

    pub(super) fn planned(&self) -> SectionReport {
        SectionReport {
            section: TOOLS_SECTION,
            status: "planned",
            counts: counts([
                ("tools", tool_count(&self.document)),
                (
                    "tool_name_reservations",
                    i64::try_from(self.names.len()).unwrap_or(i64::MAX),
                ),
                ("tool_document_version", 1),
            ]),
            checksum: self.checksum.clone(),
            duration_ms: 0,
        }
    }

    pub(super) async fn apply(
        &self,
        pool: &deadpool_postgres::Pool,
    ) -> Result<SectionReport, ImportError> {
        let started = Instant::now();
        let store = PostgresToolStore::new(pool.clone());
        match ToolControlPlane::active_tools(&store).await {
            Ok(Some(active)) if active.etag == self.etag => {
                return Ok(SectionReport {
                    section: TOOLS_SECTION,
                    status: "already-imported",
                    counts: counts([
                        ("tools", tool_count(&self.document)),
                        (
                            "tool_name_reservations",
                            i64::try_from(self.names.len()).unwrap_or(i64::MAX),
                        ),
                        ("tool_document_version", active.version),
                        ("security_revision", active.security_revision),
                    ]),
                    checksum: self.checksum.clone(),
                    duration_ms: elapsed_ms(started),
                })
            }
            Ok(Some(_)) => {
                return Err(ImportError::SectionConflict {
                    section: TOOLS_SECTION,
                })
            }
            Ok(None) => {}
            Err(error) => return Err(ImportError::Store(error)),
        }

        let diff_summary = json!({
            "action": "imported_from_standalone",
            "source": "tools_file",
            "tools": tool_count(&self.document),
        });
        let active = store
            .commit_tools(
                PolicyCommitPrecondition::Initialize,
                &self.document,
                IMPORT_ACTOR,
                &diff_summary,
            )
            .await
            .map_err(|error| commit_failure(TOOLS_SECTION, error))?;

        Ok(SectionReport {
            section: TOOLS_SECTION,
            status: "imported",
            counts: counts([
                ("tools", tool_count(&self.document)),
                (
                    "tool_name_reservations",
                    i64::try_from(self.names.len()).unwrap_or(i64::MAX),
                ),
                ("tool_document_version", active.version),
                ("security_revision", active.security_revision),
            ]),
            checksum: self.checksum.clone(),
            duration_ms: elapsed_ms(started),
        })
    }
}

/// Step 4: Connections -- records, credential bindings, statuses and
/// their history, dependencies, and the managed catalogs.
///
/// One transaction for the whole section, because the tables are one
/// graph: a status row without its record, or a catalog without the
/// dependencies derived from it, is a namespace the cluster's own startup
/// validation (`PostgresConnectionStore::validate_persisted_state`)
/// refuses to boot on. A failure therefore leaves the section untouched
/// and `--resume` starts it again.
///
/// Credential bindings are carried as REFERENCES: a purpose, a secret id
/// and a version, derived from the record by the same `expected_bindings`
/// the live write path derives them with. No secret value is read from
/// the source and none is written to the target -- the operator's secret
/// store keeps them, and a local-secret keyring (bound to
/// `CONNECTIONS_SQLITE_PATH`, which cluster mode rejects outright) is
/// never moved by this command.
pub(super) struct ConnectionsSection<'a> {
    connections: &'a [ImportedConnection],
    /// The section's natural key: the set of record IDs it will write.
    ids: BTreeSet<String>,
    planned: BTreeMap<String, i64>,
    checksum: String,
}

impl<'a> ConnectionsSection<'a> {
    pub(super) fn plan(source: &'a StandaloneSource) -> Result<Self, ImportError> {
        let connections = source.connections.as_slice();
        let mut ids = BTreeSet::new();
        let mut bindings = 0_i64;
        let mut dependencies = 0_i64;
        let mut current_statuses = 0_i64;
        let mut status_history = 0_i64;
        let mut mcp_catalogs = 0_i64;
        let mut openapi_catalogs = 0_i64;
        let mut catalog_entries = 0_i64;
        let mut reservations = 0_i64;

        for connection in connections {
            let record = &connection.record;
            ids.insert(record.id.to_string());
            bindings += i64::try_from(expected_bindings(&record.write, &record.revisions).len())
                .unwrap_or(i64::MAX);
            dependencies += i64::try_from(connection.dependencies.len()).unwrap_or(i64::MAX);
            status_history += i64::try_from(connection.status_history.len()).unwrap_or(i64::MAX);
            if connection.current_status.is_some() {
                current_statuses += 1;
            }
            if let Some(catalog) = connection.mcp_catalog.as_ref() {
                mcp_catalogs += 1;
                let names = i64::try_from(catalog.entries.len()).unwrap_or(i64::MAX);
                reservations += names;
                catalog_entries += names
                    + i64::try_from(catalog.resources.len()).unwrap_or(i64::MAX)
                    + i64::try_from(catalog.resource_templates.len()).unwrap_or(i64::MAX);
            }
            if let Some(catalog) = connection.openapi_catalog.as_ref() {
                openapi_catalogs += 1;
                let names = i64::try_from(catalog.entries.len()).unwrap_or(i64::MAX);
                reservations += names;
                catalog_entries += names;
            }
        }

        let records = i64::try_from(connections.len()).unwrap_or(i64::MAX);
        Ok(Self {
            connections,
            ids,
            planned: counts([
                ("connection_records", records),
                ("connection_documents", records),
                ("credential_bindings", bindings),
                ("dependencies", dependencies),
                ("current_statuses", current_statuses),
                ("status_history", status_history),
                ("mcp_catalogs", mcp_catalogs),
                ("openapi_catalogs", openapi_catalogs),
                ("catalog_entries", catalog_entries),
                ("tool_name_reservations", reservations),
            ]),
            checksum: canonical_digest(&connections_export(connections)?),
        })
    }

    pub(super) fn planned(&self) -> SectionReport {
        SectionReport {
            section: CONNECTIONS_SECTION,
            status: "planned",
            counts: self.planned.clone(),
            checksum: self.checksum.clone(),
            duration_ms: 0,
        }
    }

    pub(super) async fn apply(
        &self,
        pool: &deadpool_postgres::Pool,
    ) -> Result<SectionReport, ImportError> {
        let started = Instant::now();
        let client = pool.get().await.map_err(classify_pool_error)?;
        // Resume by natural key: the record IDs already in the namespace.
        // All of them present is this section's own completed work; a
        // record this import does not carry belongs to somebody else, and
        // no re-run repairs that.
        let present: BTreeSet<String> = client
            .query("SELECT id::text FROM greengateway.connection_records", &[])
            .await
            .map_err(|error| section_query_failure(CONNECTIONS_SECTION, error))?
            .iter()
            .map(|row| row.get::<_, String>(0))
            .collect();
        if !present.is_subset(&self.ids) {
            return Err(ImportError::SectionConflict {
                section: CONNECTIONS_SECTION,
            });
        }
        if !present.is_empty() && present == self.ids {
            return Ok(SectionReport {
                section: CONNECTIONS_SECTION,
                status: "already-imported",
                counts: self.planned.clone(),
                checksum: self.checksum.clone(),
                duration_ms: elapsed_ms(started),
            });
        }

        begin(&client, CONNECTIONS_OPERATION).await?;
        let outcome = import_connections_in(&client, self.connections, IMPORT_ACTOR)
            .await
            .map_err(|error| ImportError::SectionFailed {
                section: CONNECTIONS_SECTION,
                detail: error.to_string(),
            });
        let written =
            end_transaction(&client, CONNECTIONS_OPERATION, outcome, ImportError::from).await?;

        Ok(SectionReport {
            section: CONNECTIONS_SECTION,
            status: "imported",
            counts: written_counts(&written),
            checksum: self.checksum.clone(),
            duration_ms: elapsed_ms(started),
        })
    }
}

fn written_counts(written: &ImportedConnectionCounts) -> BTreeMap<String, i64> {
    counts([
        ("connection_records", written.records),
        ("connection_documents", written.documents),
        ("credential_bindings", written.credential_bindings),
        ("dependencies", written.dependencies),
        ("current_statuses", written.current_statuses),
        ("status_history", written.status_history),
        ("mcp_catalogs", written.mcp_catalogs),
        ("openapi_catalogs", written.openapi_catalogs),
        (
            "catalog_entries",
            written.mcp_catalog_entries
                + written.mcp_catalog_resources
                + written.mcp_catalog_resource_templates
                + written.openapi_catalog_entries,
        ),
        ("tool_name_reservations", written.tool_name_reservations),
        ("security_revision", written.security_revision),
    ])
}

/// How many events one batch carries. The log is the only standalone
/// surface with no bound of its own, so the section pages it rather than
/// reading it: memory is one page of events, not one deployment's history.
const AUDIT_PAGE: usize = 500;

/// Step 5: the audit log.
///
/// The standalone log's rows go into `audit_events` in EVENT ORDER --
/// `id` order, which is the order the SQLite sink committed them -- and
/// each batch is appended to the durable stream in the same pass. Both
/// halves are the audit store's own `insert_events`: one transaction per
/// batch, `UNNEST` plus `ON CONFLICT (event_id) DO NOTHING` for the
/// events, and the stream append under the transaction-scoped advisory
/// lock that makes position order commit order. So the section is
/// idempotent per batch by construction: a re-run stores nothing twice
/// and appends no second stream row, and an interrupted run resumes by
/// simply being run again.
///
/// Deduplication by `event_id` happens HERE as well as in the SQL, and
/// the reason is the stream rather than the events: the stream's position
/// reservation counts the ids a batch presents that are not yet in the
/// stream, so one batch carrying the same id twice would reserve two
/// positions and insert one row -- a permanent gap in a sequence whose
/// whole contract is that it has none. Ids already stored by an earlier
/// batch or an earlier run are excluded by the statement's own anti-join
/// and cost no position.
///
/// That set is therefore PER PAGE ([`PageDedup`]), which is what keeps the
/// stated bound true. A set of every id in the log would be the one thing
/// this section holds that grows with the deployment's whole history -- ten
/// million events is ten million 36-byte ids plus set overhead, several
/// hundred megabytes to a gigabyte, in a one-shot command run inside a
/// cutover window, and a dry run would pay it too. Nothing needs it: the
/// standalone sink declares `event_id TEXT NOT NULL UNIQUE`
/// (`audit::sqlite_sink`), so an id cannot repeat in the source at all, and
/// an id repeated across pages of a hand-made source that violated that
/// constraint would be caught by step 8's checksum rather than silently
/// stored twice.
pub(super) struct AuditSection<'a> {
    store: Option<&'a Arc<AuditQueryStore>>,
}

impl<'a> AuditSection<'a> {
    pub(super) fn plan(source: &'a StandaloneSource) -> Self {
        Self {
            store: source.audit.as_ref(),
        }
    }

    /// One pass over the source. `target` is `None` for a dry run, which
    /// reads and checksums exactly what an apply would write and writes
    /// nothing.
    pub(super) async fn run(
        &self,
        target: Option<&deadpool_postgres::Pool>,
    ) -> Result<SectionReport, ImportError> {
        let started = Instant::now();
        let sink = target.map(|pool| PostgresAuditEventStore::new(pool.clone(), None));
        let before = match target {
            Some(pool) => stored_event_count(pool).await?,
            None => 0,
        };

        let mut digest = CanonicalDigestStream::new();
        // The ids this PAGE has offered, so a batch never presents one
        // twice. Cleared at every page, which is what makes the section's
        // memory a function of the page size and not of the log's length.
        let mut seen = PageDedup::default();
        let mut cursor = 0_i64;
        let mut scanned = 0_i64;
        let mut duplicates = 0_i64;
        let mut offered = 0_i64;

        while let Some(store) = self.store {
            let store = Arc::clone(store);
            let page = tokio::task::spawn_blocking(move || store.events_after(cursor, AUDIT_PAGE))
                .await
                .map_err(|error| ImportError::SectionFailed {
                    section: AUDIT_SECTION,
                    detail: format!("the audit log could not be read: {error}"),
                })?
                .map_err(|error| ImportError::SourceDocumentUnparseable {
                    kind: "audit log",
                    detail: error.to_string(),
                })?;
            if page.is_empty() {
                break;
            }
            let mut batch: Vec<AuditEvent> = Vec::with_capacity(page.len());
            seen.start_page();
            for (id, mut event) in page {
                cursor = cursor.max(id);
                scanned += 1;
                if !seen.offer(&event.event_id) {
                    duplicates += 1;
                    continue;
                }
                // `audit_events.occurred_at` is `timestamptz`, which holds
                // microseconds; the standalone sink stores whatever
                // precision its clock gave. Truncating here rather than
                // letting the cast round means the stored instant is a
                // stated transformation of the source's, and the
                // validation's two digests are computed over the same
                // text.
                if let Some(normalized) = normalized_instant(Some(&event.timestamp)) {
                    event.timestamp = normalized;
                }
                digest.update(&event_export(&event));
                offered += 1;
                batch.push(event);
            }
            if let Some(sink) = sink.as_ref() {
                sink.insert_events(&batch)
                    .await
                    .map_err(|error| ImportError::SectionFailed {
                        section: AUDIT_SECTION,
                        detail: error.to_string(),
                    })?;
            }
        }

        let checksum = digest.finish();
        let mut report = counts([
            ("audit_events_source", scanned),
            ("audit_events_deduplicated", offered),
            ("duplicate_event_ids", duplicates),
        ]);
        let mut status = "planned";
        if let Some(pool) = target {
            let stream = stream_state(pool).await?;
            report.insert("audit_events".to_owned(), stream.events);
            report.insert("audit_stream_rows".to_owned(), stream.rows);
            report.insert("audit_stream_first_position".to_owned(), stream.first);
            report.insert("audit_stream_head".to_owned(), stream.head);
            report.insert("audit_events_inserted".to_owned(), stream.events - before);
            status = if stream.events == before && before > 0 {
                "already-imported"
            } else {
                "imported"
            };
        }
        Ok(SectionReport {
            section: AUDIT_SECTION,
            status,
            counts: report,
            checksum,
            duration_ms: elapsed_ms(started),
        })
    }
}

/// The event ids one page of the audit log has already offered.
///
/// The whole reason it exists is the stream's position reservation: a batch
/// that presents one id twice reserves two positions and inserts one row,
/// which leaves a permanent gap in a gapless sequence. That is a
/// within-batch property, so a within-page set answers it, and clearing the
/// set at every page is what bounds the section's memory by `AUDIT_PAGE`
/// rather than by the length of the operator's history.
#[derive(Default)]
pub(super) struct PageDedup {
    ids: BTreeSet<String>,
}

impl PageDedup {
    /// Forget the previous page. The ids it held are already stored, and
    /// the store's own anti-join is what stops a later page paying a
    /// position for one of them.
    pub(super) fn start_page(&mut self) {
        self.ids.clear();
    }

    /// True when this id is new to the page and should be offered to the
    /// store; false when the page has already offered it.
    pub(super) fn offer(&mut self, event_id: &str) -> bool {
        if self.ids.contains(event_id) {
            return false;
        }
        self.ids.insert(event_id.to_owned());
        true
    }

    #[cfg(test)]
    pub(super) fn tracked(&self) -> usize {
        self.ids.len()
    }
}

/// Step 6: observations and discovery.
///
/// The endpoint inventory, its child rows, the detector windows and
/// learner groups derived from it, the three lifecycle tables with their
/// revisions, and the projector checkpoint.
///
/// Three things about this section are decisions rather than mechanics,
/// and each is falsifiable:
///
/// 1. **The checkpoint is set to the imported stream head.** The audit
///    section put the standalone log on the durable stream; those positions
///    describe traffic already aggregated into the rows written here.
///    Leaving the checkpoint at zero would have the cluster's first leader
///    project the whole imported history again on top of the imported
///    counters -- every call counted twice, every threshold crossed a
///    second time. The head is read from the stream after the audit
///    section, inside this section's own transaction's snapshot. It is set
///    even when the standalone deployment ran no discovery at all: the
///    imported log is pre-cutover traffic either way, and a checkpoint left
///    at zero there would have the first leader build an endpoint inventory
///    out of it and raise `new_endpoint_seen` for every endpoint in the
///    operator's history against empty detector state. Which is why the
///    step-8 check is unconditional too.
/// 2. **The revisions on signals, suggestions and reviews are set, not
///    defaulted.** Migration 11 defaults them to 1; the import binds the
///    source's value, so a signal an admin transitioned twice arrives at
///    the revision an operator's `If-Match` still matches.
/// 3. **The detector state is carried.** SQLite never persisted the rolling
///    windows, so what crosses is what a standalone restart would have
///    rebuilt: the classified-signal counters with empty windows. Those
///    counters are what the `new_endpoint_seen`, `schema_mismatch` and
///    `principal_new_to_endpoint` detectors compare against, so carrying
///    them is what stops the first projector run from re-raising the whole
///    inventory's signals.
pub(super) struct DiscoverySection<'a> {
    discovery: Option<&'a StandaloneDiscovery>,
    /// The source's own setting, carried so the checkpoint-only apply -- a
    /// deployment that ran no discovery -- writes through the same call
    /// with the same shape rather than a second, emptier path.
    payload_capture_enabled: bool,
    planned: BTreeMap<String, i64>,
    checksum: String,
}

impl<'a> DiscoverySection<'a> {
    pub(super) fn plan(source: &'a StandaloneSource) -> Result<Self, ImportError> {
        let discovery = source.discovery.as_ref();
        let empty = PendingFlushView::default();
        let (batch, detectors, groups, signals, suggestions, reviews) = match discovery {
            Some(discovery) => (
                &discovery.batch,
                discovery.detector_states.as_slice(),
                discovery.template_groups_json.as_deref(),
                discovery.signals.as_slice(),
                discovery.suggestions.as_slice(),
                discovery.reviews.as_slice(),
            ),
            None => (&empty.batch, &[][..], None, &[][..], &[][..], &[][..]),
        };
        let export = discovery_export(batch, detectors, groups, signals, suggestions, reviews)?;
        Ok(Self {
            discovery,
            payload_capture_enabled: source.config.payload_capture_enabled,
            planned: counts([
                (
                    "discovery_endpoints",
                    i64::try_from(batch.dirty_aggregates.len()).unwrap_or(i64::MAX),
                ),
                (
                    "detector_states",
                    i64::try_from(detectors.len()).unwrap_or(i64::MAX),
                ),
                ("template_groups", i64::from(groups.is_some())),
                (
                    "discovery_signals",
                    i64::try_from(signals.len()).unwrap_or(i64::MAX),
                ),
                (
                    "discovery_rule_suggestions",
                    i64::try_from(suggestions.len()).unwrap_or(i64::MAX),
                ),
                (
                    "discovery_endpoint_reviews",
                    i64::try_from(reviews.len()).unwrap_or(i64::MAX),
                ),
            ]),
            checksum: canonical_digest(&export),
        })
    }

    /// What `--dry-run` reports. The checkpoint is not among the planned
    /// counts: it is the stream head an apply will have produced, and a
    /// dry run writes no stream.
    pub(super) fn planned(&self) -> SectionReport {
        SectionReport {
            section: DISCOVERY_SECTION,
            status: "planned",
            counts: self.planned.clone(),
            checksum: self.checksum.clone(),
            duration_ms: 0,
        }
    }

    pub(super) async fn apply(
        &self,
        pool: &deadpool_postgres::Pool,
    ) -> Result<SectionReport, ImportError> {
        let started = Instant::now();
        // A source with no discovery database still runs this section, and
        // the reason is the checkpoint. The audit section has just put the
        // whole standalone log on the durable stream; if the checkpoint
        // stayed at zero, the cluster's first leader would project all of
        // it, build an endpoint inventory out of pre-cutover traffic and
        // raise a signal for every endpoint in it. There are no aggregates
        // to write, so what this section writes in that case is exactly one
        // number -- through the same call, so the fence and the transaction
        // are the same ones the full path takes.
        let empty = PendingFlushView::default();
        let client = pool.get().await.map_err(classify_pool_error)?;
        // Resume by natural key: the projector checkpoint. A namespace this
        // section has already written carries the stream head there, and
        // one that carries a DIFFERENT non-zero checkpoint belongs to a
        // projector that has run -- which no re-run repairs.
        let existing: i64 = client
            .query_one(
                "SELECT checkpoint_position FROM greengateway.discovery_projector_state \
                 WHERE singleton",
                &[],
            )
            .await
            .map_err(|error| section_query_failure(DISCOVERY_SECTION, error))?
            .get(0);
        let head = stream_state(pool).await?.head;
        if existing != 0 {
            if existing != head {
                return Err(ImportError::SectionConflict {
                    section: DISCOVERY_SECTION,
                });
            }
            let mut counted = self.planned.clone();
            counted.insert("checkpoint_position".to_owned(), existing);
            return Ok(SectionReport {
                section: DISCOVERY_SECTION,
                status: "already-imported",
                counts: counted,
                checksum: self.checksum.clone(),
                duration_ms: elapsed_ms(started),
            });
        }

        let imported = match self.discovery {
            Some(discovery) => ImportedDiscovery {
                batch: &discovery.batch,
                detector_states: &discovery.detector_states,
                template_groups_json: discovery.template_groups_json.as_deref(),
                signals: &discovery.signals,
                suggestions: &discovery.suggestions,
                reviews: &discovery.reviews,
                checkpoint_position: head,
                payload_capture_enabled: discovery.payload_capture_enabled,
            },
            None => ImportedDiscovery {
                batch: &empty.batch,
                detector_states: &[],
                template_groups_json: None,
                signals: &[],
                suggestions: &[],
                reviews: &[],
                checkpoint_position: head,
                payload_capture_enabled: self.payload_capture_enabled,
            },
        };
        begin(&client, DISCOVERY_OPERATION).await?;
        let outcome = import_discovery_in(&client, &imported)
            .await
            .map_err(ImportError::Store);
        let written =
            end_transaction(&client, DISCOVERY_OPERATION, outcome, ImportError::from).await?;

        Ok(SectionReport {
            section: DISCOVERY_SECTION,
            status: "imported",
            counts: counts([
                ("discovery_endpoints", written.aggregates),
                ("detector_states", written.detector_states),
                ("template_groups", written.template_groups),
                ("discovery_signals", written.signals),
                ("discovery_rule_suggestions", written.suggestions),
                ("discovery_endpoint_reviews", written.reviews),
                ("checkpoint_position", written.checkpoint_position),
            ]),
            checksum: self.checksum.clone(),
            duration_ms: elapsed_ms(started),
        })
    }
}

/// An empty batch to plan against when the source has no discovery
/// database. A struct rather than a bare `PendingFlush` so the borrow
/// outlives the match that produced it.
#[derive(Default)]
struct PendingFlushView {
    batch: crate::discovery::aggregator::PendingFlush,
}

/// Step 7: principals and service tokens.
///
/// Service tokens cross with their HASHES: the hash is what an issued
/// token verifies against, so an import that carried the display prefix
/// and not the hash would silently invalidate every token the operator
/// has handed out. No plaintext is involved -- it existed once, in the
/// response to the create that minted it, and was never written down.
///
/// The PRINCIPAL DIRECTORY does not cross, and that is a property of the
/// destination rather than a gap in this command: cluster mode has no
/// principal directory. `Config` refuses `PRINCIPAL_SQLITE_PATH` alongside
/// `STATE_BACKEND=postgres` and no migration creates the table, because
/// the directory is a projection of authenticated traffic rather than
/// operator-owned state. The traffic it was projected FROM is imported
/// (the audit log), so nothing durable is lost; the report names the
/// source file and counts the rows it did not carry so an operator sees
/// the decision rather than discovering it.
pub(super) struct PrincipalsSection {
    tokens: Vec<crate::auth::tokens::ExportedServiceToken>,
    principal_directory_present: bool,
    checksum: String,
}

impl PrincipalsSection {
    pub(super) fn plan(source: &StandaloneSource) -> Self {
        // Every timestamp is truncated to the precision the `timestamptz`
        // columns hold BEFORE it is written, so the stored instant is a
        // stated transformation of the source's rather than whatever the
        // cast's rounding produced, and the validation's two digests are
        // computed over the same text. See `normalized_instant`.
        let tokens: Vec<_> = source
            .service_tokens
            .iter()
            .map(|token| crate::auth::tokens::ExportedServiceToken {
                created_at: normalized_instant(Some(&token.created_at))
                    .unwrap_or_else(|| token.created_at.clone()),
                expires_at: normalized_instant(token.expires_at.as_deref()),
                last_used_at: normalized_instant(token.last_used_at.as_deref()),
                revoked_at: normalized_instant(token.revoked_at.as_deref()),
                ..token.clone()
            })
            .collect();
        let checksum = canonical_digest(&service_tokens_export(&tokens));
        Self {
            tokens,
            principal_directory_present: source.principal_present,
            checksum,
        }
    }

    fn counted(&self, imported: i64, security_revision: i64) -> BTreeMap<String, i64> {
        counts([
            (
                "service_tokens",
                i64::try_from(self.tokens.len()).unwrap_or(i64::MAX),
            ),
            ("service_tokens_inserted", imported),
            (
                "principal_directory_present",
                i64::from(self.principal_directory_present),
            ),
            // Always zero, and reported rather than omitted: cluster mode
            // has no principal directory to import one into.
            ("principal_directory_rows_imported", 0),
            ("security_revision", security_revision),
        ])
    }

    pub(super) fn planned(&self) -> SectionReport {
        SectionReport {
            section: PRINCIPALS_SECTION,
            status: "planned",
            counts: self.counted(0, 0),
            checksum: self.checksum.clone(),
            duration_ms: 0,
        }
    }

    pub(super) async fn apply(
        &self,
        pool: &deadpool_postgres::Pool,
    ) -> Result<SectionReport, ImportError> {
        let started = Instant::now();
        let client = pool.get().await.map_err(classify_pool_error)?;
        // Resume by natural key: the token ids already present. All of
        // them is this section's own completed work; an id this import
        // does not carry belongs to somebody else.
        let present: BTreeSet<String> = client
            .query("SELECT id FROM greengateway.service_tokens", &[])
            .await
            .map_err(|error| section_query_failure(PRINCIPALS_SECTION, error))?
            .iter()
            .map(|row| row.get::<_, String>(0))
            .collect();
        let expected: BTreeSet<String> = self.tokens.iter().map(|token| token.id.clone()).collect();
        if !present.is_subset(&expected) {
            return Err(ImportError::SectionConflict {
                section: PRINCIPALS_SECTION,
            });
        }
        if !present.is_empty() && present == expected {
            return Ok(SectionReport {
                section: PRINCIPALS_SECTION,
                status: "already-imported",
                counts: self.counted(0, 0),
                checksum: self.checksum.clone(),
                duration_ms: elapsed_ms(started),
            });
        }
        if self.tokens.is_empty() {
            return Ok(SectionReport {
                section: PRINCIPALS_SECTION,
                status: "imported",
                counts: self.counted(0, 0),
                checksum: self.checksum.clone(),
                duration_ms: elapsed_ms(started),
            });
        }

        begin(&client, PRINCIPALS_OPERATION).await?;
        let outcome = import_service_tokens_in(&client, &self.tokens)
            .await
            .map_err(ImportError::Store);
        let (inserted, security_revision) =
            end_transaction(&client, PRINCIPALS_OPERATION, outcome, ImportError::from).await?;

        Ok(SectionReport {
            section: PRINCIPALS_SECTION,
            status: "imported",
            counts: self.counted(inserted, security_revision),
            checksum: self.checksum.clone(),
            duration_ms: elapsed_ms(started),
        })
    }
}

pub(super) struct AuditStreamState {
    pub events: i64,
    pub rows: i64,
    pub first: i64,
    pub head: i64,
}

async fn stored_event_count(pool: &deadpool_postgres::Pool) -> Result<i64, ImportError> {
    let client = pool.get().await.map_err(classify_pool_error)?;
    let row = client
        .query_one("SELECT count(*) FROM greengateway.audit_events", &[])
        .await
        .map_err(|error| section_query_failure(AUDIT_SECTION, error))?;
    Ok(row.get(0))
}

pub(super) async fn stream_state(
    pool: &deadpool_postgres::Pool,
) -> Result<AuditStreamState, ImportError> {
    let client = pool.get().await.map_err(classify_pool_error)?;
    let row = client
        .query_one(
            r#"
            SELECT (SELECT count(*) FROM greengateway.audit_events),
                   (SELECT count(*) FROM greengateway.audit_stream),
                   (SELECT coalesce(min(position), 0) FROM greengateway.audit_stream),
                   (SELECT coalesce(max(position), 0) FROM greengateway.audit_stream)
            "#,
            &[],
        )
        .await
        .map_err(|error| section_query_failure(AUDIT_SECTION, error))?;
    Ok(AuditStreamState {
        events: row.get(0),
        rows: row.get(1),
        first: row.get(2),
        head: row.get(3),
    })
}

/// A read this module issues on its own behalf. Classified through the
/// storage vocabulary, so no SQL text or query value crosses the boundary.
fn section_query_failure(section: &'static str, error: tokio_postgres::Error) -> ImportError {
    let kind = crate::storage::postgres::classify_postgres_error(&error);
    let classified = crate::storage::log_classified(
        "import_section_read",
        &error,
        RepositoryError::new(kind, "import_section_read"),
    );
    ImportError::SectionFailed {
        section,
        detail: classified.to_string(),
    }
}

/// A control-plane commit failure, classified for the operator without
/// carrying SQL text or document contents across the boundary.
fn commit_failure(section: &'static str, error: PolicyCommitError) -> ImportError {
    match error {
        // The namespace changed under a one-shot, offline command: either
        // it was not empty after all, or a replica is already serving it.
        PolicyCommitError::PreconditionFailed => ImportError::SectionConflict { section },
        PolicyCommitError::ToolNameTaken {
            tool_name,
            lane,
            owner_id,
        } => ImportError::SectionFailed {
            section,
            detail: format!(
                "tool name '{tool_name}' is already published by the {lane} lane ({owner_id})"
            ),
        },
        PolicyCommitError::Store(error) => ImportError::Store(error),
    }
}
