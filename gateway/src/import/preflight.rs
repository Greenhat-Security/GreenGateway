//! Target-side preflight (issue #241, PR 15, step 1).
//!
//! The source half of preflight is [`super::source`]; this half asks the
//! three questions that decide whether the target database is a legal
//! destination at all:
//!
//! 1. Is its schema exactly this binary's manifest? An import that wrote
//!    through a binary whose migrations the database has not applied would
//!    be writing into a shape it cannot see all of.
//! 2. Is it unbound, or bound to THIS deployment? Deployments never share
//!    a database.
//! 3. Is the deployment namespace empty? "Empty" is defined here, once,
//!    as a list: every authoritative table the import writes holds no rows
//!    and every authoritative counter still sits at the value migration
//!    seeded it with. Runtime state a replica rebuilds or elects --
//!    membership, maintenance ledger, leases, rate-limit buckets, pending
//!    logins, JWT revocations -- is deliberately NOT in the list: a
//!    database that a replica has merely connected to is still an empty
//!    namespace, and refusing it would make the import impossible to run
//!    twice in a cutover rehearsal.
//!
//! `--resume` skips question 3 only. The sections it resumes are the ones
//! that made the namespace non-empty, and each recognizes its own work by
//! the resource's natural key before writing anything.

use crate::{
    import::{ImportError, ImportMode, SchemaReport},
    storage::{migrations, postgres::read_deployment_binding, RepositoryError},
};

/// The authoritative content tables. A row in any of them means the
/// namespace is not empty. Ordered as the migrations create them so a
/// reviewer can diff the list against `storage/migrations/` directly.
const AUTHORITATIVE_TABLES: &[&str] = &[
    // 0002/0003: audit
    "audit_events",
    "audit_stream",
    // 0004: policy control plane
    "policy_documents",
    "policy_active",
    "security_outbox",
    // 0005: tools control plane
    "tool_documents",
    "tool_active",
    "tool_name_reservations",
    // 0006: Connections
    "connection_records",
    "connection_documents",
    "connection_credential_bindings",
    "connection_dependencies",
    "connection_current_status",
    "connection_status_history",
    "connection_mcp_catalogs",
    "connection_mcp_catalog_entries",
    "connection_mcp_catalog_resources",
    "connection_mcp_catalog_resource_templates",
    "connection_openapi_catalogs",
    "connection_openapi_catalog_entries",
    // 0007: service tokens
    "service_tokens",
    // 0009/0011: discovery
    "discovery_endpoint_aggregates",
    "discovery_endpoint_status_counts",
    "discovery_endpoint_principals",
    "discovery_endpoint_routing_contexts",
    "discovery_endpoint_routing_principals",
    "discovery_endpoint_routing_classifications",
    "discovery_endpoint_classified_signal_stats",
    "discovery_endpoint_classified_signal_principals",
    "discovery_payload_shape_stats",
    "discovery_payload_shape_samples",
    "discovery_endpoint_reviews",
    "discovery_signals",
    "discovery_rule_suggestions",
    "discovery_detector_state",
    "discovery_template_groups",
];

/// The authoritative singleton counters and the column that carries them.
/// Migration seeds each at zero; a non-zero value means something has
/// already reserved a revision, a stream position or a projector
/// checkpoint in this namespace.
const AUTHORITATIVE_COUNTERS: &[(&str, &str)] = &[
    ("security_revision_state", "last_revision"),
    ("audit_stream_state", "last_position"),
    ("connection_state_revision", "last_revision"),
    ("service_token_state_revision", "last_revision"),
    ("discovery_projector_state", "checkpoint_position"),
];

const OPERATION: &str = "import_namespace_inspect";

/// Verify the target and describe its schema for the report.
pub(super) async fn verify_target(
    pool: &deadpool_postgres::Pool,
    deployment_id: &str,
    mode: ImportMode,
) -> Result<SchemaReport, ImportError> {
    let status = migrations::read_and_validate(pool).await.map_err(|error| {
        ImportError::TargetSchemaNotCurrent {
            detail: error.to_string(),
        }
    })?;
    let schema = match status {
        migrations::SchemaStatus::Current => {
            let (version_min, version_max) = migrations::schema_version_range();
            SchemaReport {
                status: "current",
                applied: migrations::manifest_len(),
                version_min,
                version_max,
            }
        }
        migrations::SchemaStatus::NotInitialized => {
            return Err(ImportError::TargetSchemaNotCurrent {
                detail: "the database carries no schema ledger; `gateway migrate up` has never \
                         run here"
                    .to_owned(),
            })
        }
        migrations::SchemaStatus::NeedsUpgrade { applied, missing } => {
            return Err(ImportError::TargetSchemaNotCurrent {
                detail: format!("{applied} migrations applied, {missing} missing"),
            })
        }
    };

    // The binding is READ, never written: claiming an unbound database for
    // this deployment is the first section's business (through the same
    // startup path every replica uses), not preflight's, and a dry run
    // must leave the database exactly as it found it.
    match read_deployment_binding(pool).await {
        Ok(Some(bound)) if bound != deployment_id => {
            return Err(ImportError::TargetDeploymentMismatch { bound })
        }
        Ok(_) => {}
        Err(error) => {
            return Err(ImportError::TargetUnavailable {
                detail: error.to_string(),
            })
        }
    }

    if mode != ImportMode::Resume {
        let occupied = occupied_namespace(pool).await?;
        if !occupied.is_empty() {
            return Err(ImportError::TargetNamespaceNotEmpty { occupied });
        }
    }
    Ok(schema)
}

/// The authoritative tables that hold rows and the counters that have
/// moved, as `name=count` strings. Names and numbers only: the contents
/// of an occupied namespace are never read, let alone printed.
pub(super) async fn occupied_namespace(
    pool: &deadpool_postgres::Pool,
) -> Result<Vec<String>, ImportError> {
    let client = pool
        .get()
        .await
        .map_err(crate::storage::postgres::classify_pool_error)?;

    // One statement rather than 40 round trips. Every fragment is built
    // from the compile-time constants above; no caller-supplied text
    // reaches the SQL.
    let counts_sql = AUTHORITATIVE_TABLES
        .iter()
        .map(|table| {
            format!("SELECT '{table}' AS name, count(*) AS value FROM greengateway.{table}")
        })
        .collect::<Vec<_>>()
        .join(" UNION ALL ");
    let counters_sql = AUTHORITATIVE_COUNTERS
        .iter()
        .map(|(table, column)| {
            format!(
                "SELECT '{table}' AS name, coalesce(max({column}), 0) AS value \
                 FROM greengateway.{table}"
            )
        })
        .collect::<Vec<_>>()
        .join(" UNION ALL ");
    let sql = format!("{counts_sql} UNION ALL {counters_sql}");

    let rows = client.query(sql.as_str(), &[]).await.map_err(|error| {
        let kind = crate::storage::postgres::classify_postgres_error(&error);
        crate::storage::log_classified(OPERATION, &error, RepositoryError::new(kind, OPERATION))
    })?;
    let mut occupied: Vec<String> = rows
        .iter()
        .filter_map(|row| {
            let name: &str = row.get(0);
            let value: i64 = row.get(1);
            (value > 0).then(|| format!("{name}={value}"))
        })
        .collect();
    occupied.sort();
    Ok(occupied)
}
