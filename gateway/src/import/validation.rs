//! The import's validation pass (issue #241, PR 15, step 8).
//!
//! Every section before this one reports what it BELIEVES it wrote. This
//! one goes back to the target and reads, so the report an operator uses
//! to decide whether the cutover succeeded is evidence rather than a claim.
//! Five things are checked, and each of them can fail:
//!
//! 1. **Row counts per table.** The number of rows the source implies,
//!    against the number the target holds, for every authoritative table.
//! 2. **Logical checksums for both sides.** The same canonical export
//!    ([`super::exports`]) computed from the SOURCE and from the TARGET,
//!    per section. Both numbers are printed. This is the check that
//!    catches a faithful-looking import that dropped a field: counts would
//!    agree and the digests would not.
//! 3. **A read-only constraint pass.** Every foreign key and unique index
//!    in the schema is present and VALIDATED (a catalog read: PostgreSQL
//!    enforces them, so what is worth proving is that none was created
//!    `NOT VALID` or left invalid), plus the cross-table relationships the
//!    schema does NOT enforce with a constraint -- a rule suggestion's
//!    `source_signal_id`, a stream row's event, and the whole Connections
//!    graph through the cluster's own boot-time
//!    `validate_persisted_state`.
//! 4. **ETags, revisions and token hashes.** The active policy and tools
//!    ETags equal the ones this binary derives from the source documents;
//!    every Connection's per-axis revisions equal the source's (they are
//!    inside the connections checksum); every service-token hash equals
//!    the source's (inside the principals checksum, and counted here).
//! 5. **The runtime tables are empty.** Membership, the maintenance
//!    ledger, leases, rate-limit state, pending logins and JWT revocations
//!    are state a replica rebuilds or elects, and the import must have
//!    written none of it. Asserting it is what turns "we do not import
//!    those" from a comment into a property.
//!
//! A failed check fails the run (`validation_failed`): an import that
//! cannot verify itself is not a completed import, and an operator must
//! not be told to scale out on it.
//!
//! `--dry-run` computes the SOURCE half and reports the target half as
//! zero, with `status: "planned"`. There is nothing to verify yet, and a
//! rehearsal that failed because the target was empty would be a rehearsal
//! that could never pass.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::{
    connections::{
        model::MAX_CONNECTIONS,
        pg_store::{ImportedConnection, PostgresConnectionStore},
    },
    discovery::{
        aggregator::{AggregatorState, EndpointKey, LoadedRows},
        query::RawSignal,
    },
    rbac::policy_history::{PolicyHistoryListFilters, PolicyVersion},
    storage::{
        postgres::classify_pool_error, postgres_audit::PostgresAuditEventStore,
        postgres_discovery::PostgresDiscoveryStore,
        postgres_discovery_lifecycle::PostgresDiscoveryLifecycleStore,
        postgres_discovery_read::PostgresDiscoveryReadStore, postgres_policy::PostgresPolicyStore,
        postgres_service_tokens, postgres_tools::PostgresToolStore, PolicyControlPlane,
        PolicyHistory, RepositoryError, ToolControlPlane,
    },
};

use super::{
    canonical_digest,
    exports::{
        connections_export, discovery_export, event_export, policy_export, service_tokens_export,
        tools_export, CONNECTIONS_SECTION, DISCOVERY_SECTION, POLICY_SECTION, PRINCIPALS_SECTION,
        TOOLS_SECTION,
    },
    CanonicalDigestStream, ImportError, StandaloneSource,
};

const OPERATION: &str = "import_validation";

/// How many rows a paging read takes at a time.
const PAGE: usize = 500;

/// The runtime tables the import must never write: state a replica
/// rebuilds, elects, or accumulates while serving. Asserted EMPTY after an
/// apply.
///
/// `security_outbox` is deliberately absent: the import writes no outbox
/// row of its own, but the policy and tools sections run the reviewed
/// control-plane commits, and a control-plane commit appends one. Those
/// two rows describe this deployment's own initialization, not the
/// standalone deployment's history, which is exactly what the outbox is
/// for.
pub(super) const EXCLUDED_RUNTIME_TABLES: &[&str] = &[
    "cluster_members",
    "maintenance_jobs",
    "execution_leases",
    "rate_limit_buckets",
    "rate_limit_cardinality",
    "admin_pending_logins",
    "jwt_revocations",
];

/// One table's row count on each side.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct TableComparison {
    pub table: &'static str,
    /// What the source implies the target should hold.
    pub source: i64,
    pub target: i64,
}

/// One section's logical checksum on each side.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ChecksumComparison {
    pub section: &'static str,
    pub source: String,
    /// Empty on a dry run: there is nothing on the target to digest.
    pub target: String,
}

/// One named property and whether the target satisfies it.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ValidationCheck {
    pub check: &'static str,
    pub passed: bool,
    /// Why it failed, in names and numbers only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The whole comparison half of the report.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ValidationReport {
    /// `planned` on a dry run, `verified` when every check passed.
    pub status: &'static str,
    pub tables: Vec<TableComparison>,
    pub checksums: Vec<ChecksumComparison>,
    pub checks: Vec<ValidationCheck>,
    pub duration_ms: u64,
}

/// What the sections believe they planned, handed to the validation so it
/// can state the expected row counts and the source-side checksums without
/// recomputing them.
pub(super) struct ValidationInputs<'a> {
    pub source: &'a StandaloneSource,
    /// Section name to source-side checksum, in report order.
    pub checksums: Vec<(&'static str, String)>,
    /// Table name to the number of rows the source implies.
    pub expected_rows: BTreeMap<&'static str, i64>,
}

/// Run the pass. `pool` is `None` for a dry run.
pub(super) async fn run(
    pool: Option<&deadpool_postgres::Pool>,
    inputs: &ValidationInputs<'_>,
) -> Result<ValidationReport, ImportError> {
    let started = std::time::Instant::now();
    let Some(pool) = pool else {
        return Ok(ValidationReport {
            status: "planned",
            tables: inputs
                .expected_rows
                .iter()
                .map(|(table, source)| TableComparison {
                    table,
                    source: *source,
                    target: 0,
                })
                .collect(),
            checksums: inputs
                .checksums
                .iter()
                .map(|(section, source)| ChecksumComparison {
                    section,
                    source: source.clone(),
                    target: String::new(),
                })
                .collect(),
            checks: Vec::new(),
            duration_ms: super::elapsed_ms(started),
        });
    };

    let mut checks = Vec::new();

    // 1. Row counts.
    let actual = table_counts(pool, inputs.expected_rows.keys().copied()).await?;
    let tables: Vec<TableComparison> = inputs
        .expected_rows
        .iter()
        .map(|(table, source)| TableComparison {
            table,
            source: *source,
            target: actual.get(*table).copied().unwrap_or(0),
        })
        .collect();
    let mismatched: Vec<String> = tables
        .iter()
        .filter(|row| row.source != row.target)
        .map(|row| format!("{}: source {} target {}", row.table, row.source, row.target))
        .collect();
    checks.push(ValidationCheck {
        check: "row_counts_match",
        passed: mismatched.is_empty(),
        detail: (!mismatched.is_empty()).then(|| mismatched.join(", ")),
    });

    // 2. Logical checksums, computed from the TARGET with the same
    // exports the source side used.
    let target = target_checksums(pool, inputs).await?;
    let checksums: Vec<ChecksumComparison> = inputs
        .checksums
        .iter()
        .map(|(section, source)| ChecksumComparison {
            section,
            source: source.clone(),
            target: target.get(section).cloned().unwrap_or_default(),
        })
        .collect();
    let differing: Vec<String> = checksums
        .iter()
        .filter(|row| row.source != row.target)
        .map(|row| {
            format!(
                "{}: source {} target {}",
                row.section, row.source, row.target
            )
        })
        .collect();
    checks.push(ValidationCheck {
        check: "checksums_match",
        passed: differing.is_empty(),
        detail: (!differing.is_empty()).then(|| differing.join(", ")),
    });

    // 3. The constraint pass.
    checks.push(constraints_validated(pool).await?);
    checks.push(referential_integrity(pool).await?);
    checks.push(connections_graph(pool).await);

    // 4. The ETags and the projector checkpoint.
    checks.push(active_documents_match(pool, inputs).await?);
    checks.push(checkpoint_at_stream_head(pool).await?);

    // 5. The runtime tables the import must never have written.
    checks.push(runtime_tables_empty(pool).await?);

    // A failed check is reported with its own detail: an operator reading
    // the refusal needs to know WHICH table or section disagreed, and the
    // details are names and numbers only.
    let failed: Vec<String> = checks
        .iter()
        .filter(|check| !check.passed)
        .map(|check| match check.detail.as_deref() {
            Some(detail) => format!("{} ({detail})", check.check),
            None => check.check.to_owned(),
        })
        .collect();
    if !failed.is_empty() {
        return Err(ImportError::ValidationFailed { checks: failed });
    }

    Ok(ValidationReport {
        status: "verified",
        tables,
        checksums,
        checks,
        duration_ms: super::elapsed_ms(started),
    })
}

/// `count(*)` for each named table in one statement. Every fragment comes
/// from a compile-time constant; no caller text reaches the SQL.
async fn table_counts<'a>(
    pool: &deadpool_postgres::Pool,
    tables: impl Iterator<Item = &'a str>,
) -> Result<BTreeMap<String, i64>, ImportError> {
    let fragments: Vec<String> = tables
        .map(|table| {
            format!("SELECT '{table}' AS name, count(*) AS value FROM greengateway.{table}")
        })
        .collect();
    if fragments.is_empty() {
        return Ok(BTreeMap::new());
    }
    let client = pool.get().await.map_err(classify_pool_error)?;
    Ok(client
        .query(fragments.join(" UNION ALL ").as_str(), &[])
        .await
        .map_err(query_failure)?
        .iter()
        .map(|row| (row.get::<_, String>(0), row.get::<_, i64>(1)))
        .collect())
}

/// Every section's checksum, computed from the target.
async fn target_checksums(
    pool: &deadpool_postgres::Pool,
    inputs: &ValidationInputs<'_>,
) -> Result<BTreeMap<&'static str, String>, ImportError> {
    let mut checksums = BTreeMap::new();
    let source = inputs.source;

    // Policy: the imported history is every version BELOW the one the
    // import minted for the activation, plus the active document.
    let policy_store = PostgresPolicyStore::new(pool.clone());
    let active = PolicyControlPlane::active(&policy_store)
        .await?
        .ok_or_else(|| ImportError::SectionFailed {
            section: POLICY_SECTION,
            detail: "the target has no active policy document".to_owned(),
        })?;
    let mut history = target_policy_history(&policy_store).await?;
    history.retain(|version| version.version < active.version);
    checksums.insert(
        POLICY_SECTION,
        canonical_digest(&policy_export(&history, &active.policy)?),
    );

    // Tools: the active document with the names actually reserved for the
    // local lane, so a missing reservation is a checksum difference and
    // not just an uncounted row.
    let tool_store = PostgresToolStore::new(pool.clone());
    let active_tools = ToolControlPlane::active_tools(&tool_store)
        .await?
        .ok_or_else(|| ImportError::SectionFailed {
            section: TOOLS_SECTION,
            detail: "the target has no active tools document".to_owned(),
        })?;
    let client = pool.get().await.map_err(classify_pool_error)?;
    let names: Vec<String> = client
        .query(
            "SELECT tool_name FROM greengateway.tool_name_reservations \
             WHERE lane = 'local' ORDER BY tool_name",
            &[],
        )
        .await
        .map_err(query_failure)?
        .iter()
        .map(|row| row.get::<_, String>(0))
        .collect();
    drop(client);
    checksums.insert(
        TOOLS_SECTION,
        canonical_digest(&tools_export(
            &active_tools.document,
            &active_tools.etag,
            &names,
        )),
    );

    checksums.insert(
        CONNECTIONS_SECTION,
        canonical_digest(&connections_export(&target_connections(pool).await?)?),
    );
    checksums.insert(super::exports::AUDIT_SECTION, target_audit(pool).await?);
    checksums.insert(DISCOVERY_SECTION, target_discovery(pool, source).await?);
    checksums.insert(
        PRINCIPALS_SECTION,
        canonical_digest(&service_tokens_export(
            &postgres_service_tokens::exported_tokens(pool).await?,
        )),
    );
    Ok(checksums)
}

/// The target's policy history, oldest-first, through the same paging
/// contract the source is read with.
async fn target_policy_history(
    store: &PostgresPolicyStore,
) -> Result<Vec<PolicyVersion>, ImportError> {
    let mut versions = Vec::new();
    let mut cursor = None;
    loop {
        let page = PolicyHistory::list_versions(
            store,
            &PolicyHistoryListFilters {
                limit: PAGE,
                cursor: cursor.clone(),
                include_policy: true,
            },
        )
        .await?;
        versions.extend(page.versions);
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    versions.reverse();
    Ok(versions)
}

/// The target's Connections in the same shape the source's are read into,
/// so one export function digests both.
async fn target_connections(
    pool: &deadpool_postgres::Pool,
) -> Result<Vec<ImportedConnection>, ImportError> {
    let store =
        PostgresConnectionStore::new(pool.clone(), MAX_CONNECTIONS).map_err(connections_failure)?;
    let records = store.list().await.map_err(connections_failure)?;
    let mut activity = store.activity_times().await.map_err(connections_failure)?;
    let statuses = store
        .exported_statuses()
        .await
        .map_err(connections_failure)?;
    let mut current: BTreeMap<_, _> = statuses
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
    let mut mcp: BTreeMap<_, _> = store
        .mcp_catalogs()
        .await
        .map_err(connections_failure)?
        .into_iter()
        .map(|catalog| (catalog.connection_id.clone(), catalog))
        .collect();
    let mut openapi: BTreeMap<_, _> = store
        .openapi_catalogs()
        .await
        .map_err(connections_failure)?
        .into_iter()
        .map(|catalog| (catalog.connection_id.clone(), catalog))
        .collect();
    let mut openapi_overlays: BTreeMap<_, _> = store
        .openapi_overlays()
        .await
        .map_err(connections_failure)?
        .into_iter()
        .map(|overlay| (overlay.connection_id.clone(), overlay))
        .collect();
    let mut enum_source_values: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for row in store
        .enum_source_values()
        .await
        .map_err(connections_failure)?
    {
        enum_source_values
            .entry(row.connection_id.clone())
            .or_default()
            .push(row);
    }

    let mut connections = Vec::with_capacity(records.len());
    for record in records {
        let dependencies = store
            .dependencies(&record.id)
            .await
            .map_err(connections_failure)?;
        connections.push(ImportedConnection {
            activity: activity.remove(&record.id).unwrap_or_default(),
            dependencies,
            current_status: current.remove(&record.id),
            status_history: history.remove(&record.id).unwrap_or_default(),
            mcp_catalog: mcp.remove(&record.id),
            openapi_catalog: openapi.remove(&record.id),
            openapi_overlay: openapi_overlays.remove(&record.id),
            enum_source_values: enum_source_values.remove(&record.id).unwrap_or_default(),
            record,
        });
    }
    Ok(connections)
}

/// The target's audit log, digested in STREAM order with the same
/// streaming fold the source side used. Stream order, not insertion
/// order: the positions are what a durable cursor reads, so the digest
/// states what a replica would replay.
async fn target_audit(pool: &deadpool_postgres::Pool) -> Result<String, ImportError> {
    let store = PostgresAuditEventStore::new(pool.clone(), None);
    let mut digest = CanonicalDigestStream::new();
    let mut cursor = 0_i64;
    loop {
        let page = store.stream_after(cursor, PAGE).await?;
        if page.is_empty() {
            break;
        }
        for (position, event) in page {
            cursor = cursor.max(position);
            digest.update(&event_export(&event));
        }
    }
    Ok(digest.finish())
}

/// The target's discovery state, rebuilt through the SAME aggregator model
/// the source was read through, so the comparison is between two runs of
/// one model rather than two readings of two schemas.
///
/// The detector states and the learner groups are taken as STORED rather
/// than re-derived: they are what the import wrote, and re-deriving them
/// would compare the model against itself instead of against the database.
async fn target_discovery(
    pool: &deadpool_postgres::Pool,
    source: &StandaloneSource,
) -> Result<String, ImportError> {
    let store = PostgresDiscoveryStore::new(pool.clone());
    let rows: LoadedRows = store.load_rows().await?;
    let detector_states: Vec<(EndpointKey, String)> = rows
        .detector_states
        .iter()
        .map(|row| {
            (
                EndpointKey::new(row.method.clone(), row.endpoint_template.clone()),
                row.state_json.clone(),
            )
        })
        .collect();
    let template_groups_json = rows.template_groups_json.clone();
    let state = AggregatorState::from_rows(
        rows,
        source.config.payload_capture_enabled,
        source.config.discovery_endpoint_limit,
        source.config.signal_detector_config(),
    )
    .map_err(|error| ImportError::SectionFailed {
        section: DISCOVERY_SECTION,
        detail: format!("the imported discovery rows do not rebuild: {error}"),
    })?;
    let batch = state.full_flush();

    let read_store = PostgresDiscoveryReadStore::new(pool.clone());
    let signals: Vec<RawSignal> = read_store
        .exported_signals()
        .await
        .map_err(discovery_failure)?;
    let reviews = read_store
        .exported_reviews()
        .await
        .map_err(discovery_failure)?;
    let suggestions = PostgresDiscoveryLifecycleStore::new(pool.clone())
        .list_suggestions()
        .await
        .map_err(|error| ImportError::SectionFailed {
            section: DISCOVERY_SECTION,
            detail: error.to_string(),
        })?;

    Ok(canonical_digest(&discovery_export(
        &batch,
        &detector_states,
        template_groups_json.as_deref(),
        &signals,
        &suggestions,
        &reviews,
    )?))
}

/// Every foreign key and unique index in the schema is present and
/// validated.
///
/// PostgreSQL ENFORCES both, so re-deriving them row by row would prove
/// nothing the database has not already proved. What a read-only pass can
/// prove, and what actually matters after a bulk load, is that none of
/// them was created `NOT VALID`, dropped, or left invalid by a failed
/// build -- any of which would mean rows the schema no longer constrains.
async fn constraints_validated(
    pool: &deadpool_postgres::Pool,
) -> Result<ValidationCheck, ImportError> {
    let client = pool.get().await.map_err(classify_pool_error)?;
    let row = client
        .query_one(
            r#"
            SELECT (SELECT count(*) FROM pg_constraint c
                    JOIN pg_class t ON t.oid = c.conrelid
                    JOIN pg_namespace n ON n.oid = t.relnamespace
                    WHERE n.nspname = 'greengateway' AND c.contype = 'f'),
                   (SELECT count(*) FROM pg_constraint c
                    JOIN pg_class t ON t.oid = c.conrelid
                    JOIN pg_namespace n ON n.oid = t.relnamespace
                    WHERE n.nspname = 'greengateway' AND c.contype = 'f'
                      AND NOT c.convalidated),
                   (SELECT count(*) FROM pg_index i
                    JOIN pg_class t ON t.oid = i.indrelid
                    JOIN pg_namespace n ON n.oid = t.relnamespace
                    WHERE n.nspname = 'greengateway' AND i.indisunique),
                   (SELECT count(*) FROM pg_index i
                    JOIN pg_class t ON t.oid = i.indrelid
                    JOIN pg_namespace n ON n.oid = t.relnamespace
                    WHERE n.nspname = 'greengateway' AND i.indisunique
                      AND NOT (i.indisvalid AND i.indisready))
            "#,
            &[],
        )
        .await
        .map_err(query_failure)?;
    let foreign_keys: i64 = row.get(0);
    let unvalidated: i64 = row.get(1);
    let unique_indexes: i64 = row.get(2);
    let invalid: i64 = row.get(3);
    Ok(ValidationCheck {
        check: "constraints_validated",
        passed: unvalidated == 0 && invalid == 0 && foreign_keys > 0 && unique_indexes > 0,
        detail: Some(format!(
            "{foreign_keys} foreign keys ({unvalidated} unvalidated), \
             {unique_indexes} unique indexes ({invalid} invalid)"
        )),
    })
}

/// The cross-table relationships the schema does NOT enforce with a
/// foreign key, re-derived here.
///
/// A rule suggestion names the signal it was derived from and a stream row
/// names its event; migration 9 indexes the first and migration 3 relies
/// on insert order for the second, and neither is a constraint. After a
/// bulk load they are exactly the relationships that could be broken
/// without the database noticing.
async fn referential_integrity(
    pool: &deadpool_postgres::Pool,
) -> Result<ValidationCheck, ImportError> {
    let client = pool.get().await.map_err(classify_pool_error)?;
    let row = client
        .query_one(
            r#"
            SELECT (SELECT count(*) FROM greengateway.discovery_rule_suggestions s
                    WHERE s.source_signal_id IS NOT NULL
                      AND NOT EXISTS (SELECT 1 FROM greengateway.discovery_signals g
                                      WHERE g.id = s.source_signal_id)),
                   (SELECT count(*) FROM greengateway.audit_stream s
                    WHERE NOT EXISTS (SELECT 1 FROM greengateway.audit_events e
                                      WHERE e.event_id = s.event_id)),
                   (SELECT count(*) FROM greengateway.discovery_detector_state d
                    WHERE NOT EXISTS (SELECT 1 FROM greengateway.discovery_endpoint_aggregates a
                                      WHERE a.method = d.method
                                        AND a.endpoint_template = d.endpoint_template))
            "#,
            &[],
        )
        .await
        .map_err(query_failure)?;
    let dangling_suggestions: i64 = row.get(0);
    let dangling_stream_rows: i64 = row.get(1);
    let dangling_detectors: i64 = row.get(2);
    let total = dangling_suggestions + dangling_stream_rows + dangling_detectors;
    Ok(ValidationCheck {
        check: "referential_integrity",
        passed: total == 0,
        detail: (total != 0).then(|| {
            format!(
                "{dangling_suggestions} suggestions without their signal, \
                 {dangling_stream_rows} stream rows without their event, \
                 {dangling_detectors} detector states without their aggregate"
            )
        }),
    })
}

/// The Connections graph, through the cluster's OWN boot-time validation.
///
/// `validate_persisted_state` is what a replica runs before it serves:
/// bindings against their record, the current status against the record's
/// revisions, catalog counters against their child rows, managed-tool
/// dependencies against catalog entries. Running it here means the
/// validation answers the question an operator actually has -- would a
/// replica boot on this? -- with the replica's own code.
async fn connections_graph(pool: &deadpool_postgres::Pool) -> ValidationCheck {
    let outcome = match PostgresConnectionStore::new(pool.clone(), MAX_CONNECTIONS) {
        Ok(store) => store.validate_persisted_state().await,
        Err(error) => Err(error),
    };
    match outcome {
        Ok(()) => ValidationCheck {
            check: "connections_graph_boots",
            passed: true,
            detail: None,
        },
        Err(error) => ValidationCheck {
            check: "connections_graph_boots",
            passed: false,
            detail: Some(error.to_string()),
        },
    }
}

/// The active policy and tools ETags are the ones this binary derives from
/// the SOURCE documents. The checksums already cover this, but an ETag
/// mismatch is the failure an operator's automation feels first (every
/// `If-Match` it holds stops matching), so it is named on its own.
async fn active_documents_match(
    pool: &deadpool_postgres::Pool,
    inputs: &ValidationInputs<'_>,
) -> Result<ValidationCheck, ImportError> {
    let expected_policy = crate::policy_etag(&inputs.source.policy).map_err(|error| {
        ImportError::SourceDocumentUnparseable {
            kind: "policy",
            detail: error.to_string(),
        }
    })?;
    let expected_tools =
        crate::tools_file_etag(&inputs.source.tools_document).map_err(|error| {
            ImportError::SourceDocumentUnparseable {
                kind: "tools",
                detail: error.to_string(),
            }
        })?;
    let policy_store = PostgresPolicyStore::new(pool.clone());
    let tool_store = PostgresToolStore::new(pool.clone());
    let policy_etag = PolicyControlPlane::active(&policy_store)
        .await?
        .map(|active| active.etag);
    let tools_etag = ToolControlPlane::active_tools(&tool_store)
        .await?
        .map(|active| active.etag);
    let policy_ok = policy_etag.as_deref() == Some(expected_policy.as_str());
    let tools_ok = tools_etag.as_deref() == Some(expected_tools.as_str());
    Ok(ValidationCheck {
        check: "active_etags_match_the_source",
        passed: policy_ok && tools_ok,
        // Names, not values: an ETag is a digest of a document an operator
        // already has, but the report says which side disagreed rather
        // than printing either.
        detail: (!(policy_ok && tools_ok)).then(|| {
            let mut differing = Vec::new();
            if !policy_ok {
                differing.push("policy");
            }
            if !tools_ok {
                differing.push("tools");
            }
            differing.join(", ")
        }),
    })
}

/// The projector checkpoint sits at the imported stream head, so the
/// cluster's first leader projects nothing the import already aggregated.
/// This is the falsifiable half of step 6's second decision.
async fn checkpoint_at_stream_head(
    pool: &deadpool_postgres::Pool,
) -> Result<ValidationCheck, ImportError> {
    let client = pool.get().await.map_err(classify_pool_error)?;
    let row = client
        .query_one(
            r#"
            SELECT (SELECT checkpoint_position FROM greengateway.discovery_projector_state
                    WHERE singleton),
                   (SELECT coalesce(max(position), 0) FROM greengateway.audit_stream)
            "#,
            &[],
        )
        .await
        .map_err(query_failure)?;
    let checkpoint: i64 = row.get(0);
    let head: i64 = row.get(1);
    // Unconditional, including for a deployment that imported no
    // aggregates at all. The check used to pass automatically when
    // `discovery_endpoint_aggregates` was empty, which is precisely the
    // case where the import had left the checkpoint at zero: a standalone
    // deployment with an audit log and no discovery database. The imported
    // log is pre-cutover traffic whether or not it was ever aggregated, and
    // the checkpoint is what stops the first leader projecting it.
    let passed = checkpoint == head;
    Ok(ValidationCheck {
        check: "projector_checkpoint_at_stream_head",
        passed,
        detail: (!passed).then(|| format!("checkpoint {checkpoint}, stream head {head}")),
    })
}

/// The runtime tables are empty: the import elected no leader, ran no
/// maintenance job, took no lease, accumulated no rate-limit state, and
/// carried across no pending login or JWT revocation.
async fn runtime_tables_empty(
    pool: &deadpool_postgres::Pool,
) -> Result<ValidationCheck, ImportError> {
    let counts = table_counts(pool, EXCLUDED_RUNTIME_TABLES.iter().copied()).await?;
    let occupied: Vec<String> = counts
        .iter()
        .filter(|(_, value)| **value > 0)
        .map(|(name, value)| format!("{name}={value}"))
        .collect();
    Ok(ValidationCheck {
        check: "runtime_tables_untouched",
        passed: occupied.is_empty(),
        detail: (!occupied.is_empty()).then(|| occupied.join(", ")),
    })
}

/// Which authoritative tables the row-count comparison covers, and how
/// many rows each should hold, derived from the source alone.
pub(super) fn expected_rows(
    source: &StandaloneSource,
    audit_events: i64,
) -> BTreeMap<&'static str, i64> {
    let history = i64::try_from(source.history.len()).unwrap_or(i64::MAX);
    let records = i64::try_from(source.connections.len()).unwrap_or(i64::MAX);
    let mut bindings = 0_i64;
    let mut dependencies = 0_i64;
    let mut current_statuses = 0_i64;
    let mut status_history = 0_i64;
    let mut mcp_catalogs = 0_i64;
    let mut mcp_entries = 0_i64;
    let mut mcp_resources = 0_i64;
    let mut mcp_templates = 0_i64;
    let mut openapi_catalogs = 0_i64;
    let mut openapi_overlays = 0_i64;
    let mut enum_source_values = 0_i64;
    let mut openapi_entries = 0_i64;
    let mut reservations =
        i64::try_from(super::exports::tool_names(&source.tools_document).len()).unwrap_or(i64::MAX);
    for connection in &source.connections {
        let record = &connection.record;
        bindings += i64::try_from(
            crate::connections::store::expected_bindings(&record.write, &record.revisions).len(),
        )
        .unwrap_or(i64::MAX);
        dependencies += i64::try_from(connection.dependencies.len()).unwrap_or(i64::MAX);
        status_history += i64::try_from(connection.status_history.len()).unwrap_or(i64::MAX);
        if connection.current_status.is_some() {
            current_statuses += 1;
        }
        if let Some(catalog) = connection.mcp_catalog.as_ref() {
            mcp_catalogs += 1;
            let entries = i64::try_from(catalog.entries.len()).unwrap_or(i64::MAX);
            mcp_entries += entries;
            reservations += entries;
            mcp_resources += i64::try_from(catalog.resources.len()).unwrap_or(i64::MAX);
            mcp_templates += i64::try_from(catalog.resource_templates.len()).unwrap_or(i64::MAX);
        }
        if let Some(catalog) = connection.openapi_catalog.as_ref() {
            openapi_catalogs += 1;
            let entries = i64::try_from(catalog.entries.len()).unwrap_or(i64::MAX);
            openapi_entries += entries;
            reservations += entries;
        }
        if connection.openapi_overlay.is_some() {
            openapi_overlays += 1;
        }
        enum_source_values +=
            i64::try_from(connection.enum_source_values.len()).unwrap_or(i64::MAX);
    }

    let discovery = source.discovery.as_ref();
    let endpoints = discovery
        .map(|discovery| i64::try_from(discovery.batch.dirty_aggregates.len()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let signals = discovery
        .map(|discovery| i64::try_from(discovery.signals.len()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let suggestions = discovery
        .map(|discovery| i64::try_from(discovery.suggestions.len()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let reviews = discovery
        .map(|discovery| i64::try_from(discovery.reviews.len()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let detectors = discovery
        .map(|discovery| i64::try_from(discovery.detector_states.len()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let groups = discovery
        .map(|discovery| i64::from(discovery.template_groups_json.is_some()))
        .unwrap_or(0);

    let mut expected: BTreeMap<&'static str, i64> = BTreeMap::new();
    // The activation the import mints is one version beyond the source's.
    expected.insert("policy_documents", history + 1);
    expected.insert("policy_active", 1);
    expected.insert("tool_documents", 1);
    expected.insert("tool_active", 1);
    expected.insert("tool_name_reservations", reservations);
    expected.insert("connection_records", records);
    expected.insert("connection_documents", records);
    expected.insert("connection_credential_bindings", bindings);
    expected.insert("connection_dependencies", dependencies);
    expected.insert("connection_current_status", current_statuses);
    expected.insert("connection_status_history", status_history);
    expected.insert("connection_mcp_catalogs", mcp_catalogs);
    expected.insert("connection_mcp_catalog_entries", mcp_entries);
    expected.insert("connection_mcp_catalog_resources", mcp_resources);
    expected.insert("connection_mcp_catalog_resource_templates", mcp_templates);
    expected.insert("connection_openapi_catalogs", openapi_catalogs);
    expected.insert("connection_openapi_catalog_entries", openapi_entries);
    expected.insert("connection_openapi_overlays", openapi_overlays);
    expected.insert("connection_enum_source_values", enum_source_values);
    expected.insert("audit_events", audit_events);
    expected.insert("audit_stream", audit_events);
    expected.insert("discovery_endpoint_aggregates", endpoints);
    expected.insert("discovery_detector_state", detectors);
    expected.insert("discovery_template_groups", groups);
    expected.insert("discovery_signals", signals);
    expected.insert("discovery_rule_suggestions", suggestions);
    expected.insert("discovery_endpoint_reviews", reviews);
    expected.insert(
        "service_tokens",
        i64::try_from(source.service_tokens.len()).unwrap_or(i64::MAX),
    );
    expected
}

fn query_failure(error: tokio_postgres::Error) -> ImportError {
    let kind = crate::storage::postgres::classify_postgres_error(&error);
    ImportError::Store(crate::storage::log_classified(
        OPERATION,
        &error,
        RepositoryError::new(kind, OPERATION),
    ))
}

fn connections_failure(error: crate::connections::store::ConnectionStoreError) -> ImportError {
    ImportError::SectionFailed {
        section: CONNECTIONS_SECTION,
        detail: error.to_string(),
    }
}

fn discovery_failure(error: crate::discovery::query::DiscoveryQueryError) -> ImportError {
    ImportError::SectionFailed {
        section: DISCOVERY_SECTION,
        detail: error.to_string(),
    }
}
