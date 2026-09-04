//! PostgreSQL versioned policy/history control plane (issue #241, PR 7).
//!
//! Implements [`PolicyControlPlane`] against migration 4's tables. The
//! `commit` transaction is the HA state model's section 2 template, verbatim:
//!
//! 1. `SELECT ... FROM policy_active WHERE singleton FOR UPDATE` locks and
//!    reads the expected active state, serializing writers on the row.
//! 2. The caller's precondition is re-verified against that state: a stale
//!    expected ETag (or a race against another initializer) is
//!    [`PolicyCommitError::PreconditionFailed`] and the transaction rolls
//!    back with nothing written.
//! 3. The candidate (already fully validated by the caller) becomes a new
//!    immutable `policy_documents` row -- which is also the history entry:
//!    actor, diff summary, and the full snapshot append together.
//! 4. The next security revision is reserved by updating the
//!    `security_revision_state` counter row. The reservation is a plain row
//!    update inside the transaction, so an aborted mutation's revision rolls
//!    back with it (the property a bare sequence does not have).
//! 5. The active pointer advances to the new version and revision.
//! 6. One `security_outbox` row records the change durably; notifications
//!    and reconciliation build on it later. Its columns are identifiers and
//!    revisions only (the state model's privacy section).
//! 7. `COMMIT` -- once. Every step above rolls back together.
//!
//! Steps 1-6 are [`commit_policy_in`], over a client whose transaction the
//! caller owns: the `PolicyControlPlane::commit` endpoint path wraps it in
//! `BEGIN`/`COMMIT`, and rule-suggestion acceptance (issue #241, PR 12;
//! `postgres_discovery_lifecycle`) runs it between locking the suggestion
//! row and transitioning it, so a suggestion is accepted in the same
//! transaction as the rule it proposes and never without it.
//!
//! Reads are plain committed reads: `active` re-verifies the stored ETag
//! against the recomputed document hash (a tampered pointer fails closed as
//! `InvalidData` rather than serving an unverifiable document) and parses
//! the document through [`Policy::validate_json_value`], so callers only
//! ever see a document this binary can serve.
//!
//! Redaction follows the foundation's rules: no SQL text, no query values,
//! and no DSN-derived material cross the error boundary.

use std::{collections::BTreeSet, sync::LazyLock};

use async_trait::async_trait;
use serde_json::Value;

use crate::rbac::{
    policy_history::{PolicyHistoryListFilters, PolicyHistoryPage, PolicyVersion},
    Policy,
};

use super::{
    log_classified,
    policy_history::{
        ActivePolicy, PolicyCommitError, PolicyCommitRequest, PolicyControlPlane, PolicyHistory,
    },
    postgres::classify_pool_error,
    postgres_documents::{self, DocumentResource},
    RepositoryError, RepositoryErrorKind,
};

/// The policy document's tables and outbox identity in the shared
/// versioned-document core.
const POLICY_DOCUMENT_RESOURCE: DocumentResource = DocumentResource {
    documents_table: "greengateway.policy_documents",
    active_table: "greengateway.policy_active",
    resource_type: "policy",
    operation: "policy_commit",
};

/// The operation labels the classified errors of this module carry. Static
/// strings only: the contract never carries SQL text or values.
const OPERATION_ACTIVE: &str = "policy_active_read";
const OPERATION_REVISION: &str = "policy_revision_read";
const OPERATION_COMMIT: &str = "policy_commit";
const OPERATION_HISTORY_LIST: &str = "policy_history_list";
const OPERATION_HISTORY_GET: &str = "policy_history_get";
const OPERATION_OUTBOX: &str = "policy_outbox_read";
const OPERATION_POLICY_OVERLAY_LOCK: &str = "policy_overlay_advisory_lock";

/// Serializes policy adoption with OpenAPI overlay name adoption across
/// every PostgreSQL replica. A transaction-scoped lock is intentional:
/// cancellation and rollback release it automatically, unlike a pooled
/// session lock.
pub(crate) static POLICY_OVERLAY_LOCK_KEY: LazyLock<i64> = LazyLock::new(|| {
    super::postgres_session::advisory_lock_key("greengateway.policy-openapi-overlay")
});

pub(crate) async fn acquire_policy_overlay_lock(
    client: &deadpool_postgres::Object,
) -> Result<(), RepositoryError> {
    client
        .execute(
            "SELECT pg_advisory_xact_lock($1)",
            &[&*POLICY_OVERLAY_LOCK_KEY],
        )
        .await
        .map_err(|error| classify_query(error, OPERATION_POLICY_OVERLAY_LOCK))?;
    Ok(())
}

/// Read and self-verify the authoritative policy while the shared
/// policy/overlay lock is held. Overlay writers use this instead of a
/// replica-local RBAC snapshot, closing the cross-replica rename race.
pub(crate) async fn active_policy_tool_names_in(
    client: &deadpool_postgres::Object,
) -> Result<BTreeSet<String>, RepositoryError> {
    let row = postgres_documents::read_active(client, POLICY_DOCUMENT_RESOURCE).await?;
    let Some((_version, stored_etag, _security_revision, _created_at, document_json)) = row else {
        return Ok(BTreeSet::new());
    };
    let policy = policy_from_json(&document_json, OPERATION_ACTIVE)?;
    let etag = crate::policy_etag(&policy).map_err(|_| invalid_data(OPERATION_ACTIVE))?;
    if etag != stored_etag {
        return Err(invalid_data(OPERATION_ACTIVE));
    }
    Ok(policy.tools.into_keys().collect())
}

/// One durable change record from `security_outbox`. Reconciliation and
/// (later) notification consumers read these; the payload is identifiers
/// and revisions only.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)] // Read by the PR 7 store tests; the notification and
                    // retention consumers that poll it in production arrive with #241 PR 13.
pub struct SecurityOutboxEntry {
    pub revision: i64,
    pub resource_type: String,
    pub from_version: Option<i64>,
    pub to_version: i64,
}

/// The read-only view of the global security-revision counter that the
/// cluster runtime gates on. Every control-plane commit -- policy since
/// PR 7, tools since PR 8, and the later #241 resources -- advances the
/// same `security_revision_state` counter inside its transaction, so one
/// read answers "is my compiled snapshot of ALL shared security state
/// current?".
pub struct SecurityRevisionSource {
    pool: deadpool_postgres::Pool,
}

impl SecurityRevisionSource {
    pub fn new(pool: deadpool_postgres::Pool) -> Self {
        Self { pool }
    }

    pub async fn current(&self) -> Result<i64, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let row = client
            .query_opt(
                "SELECT last_revision FROM greengateway.security_revision_state WHERE singleton",
                &[],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_REVISION))?;
        // The counter row is seeded by migration 4 and never deleted; its
        // absence means the schema is not what this build expects.
        row.map(|row| row.get::<_, i64>(0))
            .ok_or_else(|| invalid_data(OPERATION_REVISION))
    }
}

/// The authoritative PostgreSQL policy control plane. Cheap to construct:
/// it borrows the foundation's pool and holds no per-instance state.
pub struct PostgresPolicyStore {
    pool: deadpool_postgres::Pool,
}

impl PostgresPolicyStore {
    pub fn new(pool: deadpool_postgres::Pool) -> Self {
        Self { pool }
    }

    /// The shared revision-counter view over this store's pool, for the
    /// cluster runtime's gate. Read-only; commits advance the counter
    /// inside their own transactions.
    pub fn revision_source(&self) -> SecurityRevisionSource {
        SecurityRevisionSource::new(self.pool.clone())
    }

    /// Outbox entries after a revision, oldest-first. The durable half of
    /// reconciliation: correctness never depends on notifications, only on
    /// these rows plus the revision counter.
    #[allow(dead_code)] // Exercised by the PR 7 store tests; the production
                        // consumers (notification relay, retention) arrive with #241 PR 13.
    pub async fn outbox_after(
        &self,
        after_revision: i64,
        limit: usize,
    ) -> Result<Vec<SecurityOutboxEntry>, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let rows = client
            .query(
                r#"
                SELECT revision, resource_type, from_version, to_version
                FROM greengateway.security_outbox
                WHERE revision > $1
                ORDER BY revision
                LIMIT $2
                "#,
                &[&after_revision, &(limit as i64)],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_OUTBOX))?;
        Ok(rows
            .iter()
            .map(|row| SecurityOutboxEntry {
                revision: row.get(0),
                resource_type: row.get(1),
                from_version: row.get(2),
                to_version: row.get(3),
            })
            .collect())
    }
}

#[async_trait]
impl PolicyControlPlane for PostgresPolicyStore {
    async fn active(&self) -> Result<Option<ActivePolicy>, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let row = postgres_documents::read_active(&client, POLICY_DOCUMENT_RESOURCE)
            .await?
            .map(
                |(version, stored_etag, security_revision, _created_at, document_json)| {
                    (version, stored_etag, security_revision, document_json)
                },
            );
        let Some((version, stored_etag, security_revision, document_json)) = row else {
            return Ok(None);
        };
        let policy = policy_from_json(&document_json, OPERATION_ACTIVE)?;
        let etag = crate::policy_etag(&policy).map_err(|_| invalid_data(OPERATION_ACTIVE))?;
        if etag != stored_etag {
            // The pointer names an ETag the document does not hash to.
            // Either the row was edited out-of-band or the deployment's
            // data is corrupt; either way the document is unverifiable and
            // must never be served. Fail closed.
            tracing::error!(
                "the active policy document does not match its recorded ETag; \
                 refusing to serve an unverifiable document"
            );
            return Err(invalid_data(OPERATION_ACTIVE));
        }
        Ok(Some(ActivePolicy {
            policy,
            version,
            etag,
            security_revision,
        }))
    }

    async fn commit(
        &self,
        request: PolicyCommitRequest<'_>,
    ) -> Result<ActivePolicy, PolicyCommitError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(classify_pool_error)
            .map_err(store_error)?;
        postgres_documents::begin(&client, OPERATION_COMMIT)
            .await
            .map_err(store_error)?;
        let outcome = commit_policy_in(&client, request).await;
        postgres_documents::end_transaction(&client, OPERATION_COMMIT, outcome, store_error).await
    }
}

/// The policy commit's steps 1-6 over a client whose transaction the
/// caller opened and will close (see the module documentation): lock and
/// self-verify the pointer, re-check the precondition, write the immutable
/// version (the history row), reserve the security revision, advance the
/// pointer, append the outbox row. A `PreconditionFailed` -- the caller's
/// expected ETag is not the active one -- is returned before anything is
/// written, so the caller's `ROLLBACK` has nothing of the policy's to undo
/// and everything of its own.
pub(crate) async fn commit_policy_in(
    client: &deadpool_postgres::Object,
    request: PolicyCommitRequest<'_>,
) -> Result<ActivePolicy, PolicyCommitError> {
    acquire_policy_overlay_lock(client)
        .await
        .map_err(store_error)?;
    let document_json = serde_json::to_string(request.candidate)
        .map_err(|_| invalid_data(OPERATION_COMMIT))
        .map_err(store_error)?;
    let diff_summary_json = serde_json::to_string(request.diff_summary)
        .map_err(|_| invalid_data(OPERATION_COMMIT))
        .map_err(store_error)?;
    let etag = crate::policy_etag(request.candidate)
        .map_err(|_| invalid_data(OPERATION_COMMIT))
        .map_err(store_error)?;

    let committed = postgres_documents::commit_in(
        client,
        POLICY_DOCUMENT_RESOURCE,
        request.precondition.clone(),
        postgres_documents::DocumentCommit {
            document_json: &document_json,
            document_etag: &etag,
            actor_user_id: request.actor_user_id,
            diff_summary_json: &diff_summary_json,
            tool_names: None,
        },
    )
    .await?;

    Ok(ActivePolicy {
        policy: request.candidate.clone(),
        version: committed.version,
        etag,
        security_revision: committed.security_revision,
    })
}

/// One standalone policy-history row as the import writes it (issue #241,
/// PR 15). Every field is the source's own: the version number, the actor
/// who made the change, the timestamp SQLite recorded, the diff summary,
/// the snapshot, and the ETag recomputed from that snapshot by this
/// binary's [`crate::policy_etag`].
pub(crate) struct ImportedPolicyVersion {
    pub version: i64,
    pub actor_user_id: String,
    /// RFC 3339, bound as text and cast (`$n::text::timestamptz`): the
    /// driver carries no `time` feature.
    pub created_at: String,
    pub diff_summary_json: String,
    pub document_json: String,
    pub document_etag: String,
}

/// Append imported history versions verbatim inside the caller's
/// transaction, then realign the identity sequence behind them.
///
/// This is the ONLY write path that names a `policy_documents` version
/// instead of letting the identity assign one, and it exists for exactly
/// one caller: the standalone-to-cluster import (issue #241, PR 15), which
/// carries a standalone deployment's history into an empty namespace with
/// its version numbers, actors and timestamps intact. It writes history
/// only -- it never touches `policy_active`, the security-revision counter
/// or the outbox, so no imported row is ever *activated* by this path; the
/// import activates the operator's policy file afterwards through
/// [`commit_policy_in`], the one reviewed section-2 sequence.
///
/// PRIVILEGE: `setval` needs UPDATE on the identity's sequence, which the
/// documented runtime role (USAGE/SELECT on sequences) does not hold. The
/// import is a cutover command run beside `gateway migrate up` with the
/// MIGRATION role's DSN, which owns the sequence it created. A runtime
/// role's connection fails this statement, the section's transaction rolls
/// back with nothing written, and the classified failure is logged with
/// the permission error PostgreSQL returned.
///
/// `ON CONFLICT (version) DO NOTHING` makes a re-run (`--resume`) write
/// nothing a previous run already wrote, and the `setval` afterwards
/// leaves the identity pointing past the highest imported version so the
/// activation commit that follows gets the next number rather than
/// colliding with an imported one.
pub(crate) async fn insert_imported_policy_versions_in(
    client: &deadpool_postgres::Object,
    versions: &[ImportedPolicyVersion],
) -> Result<u64, RepositoryError> {
    const OPERATION: &str = "policy_history_import";
    if versions.is_empty() {
        return Ok(0);
    }
    let numbers: Vec<i64> = versions.iter().map(|version| version.version).collect();
    let actors: Vec<&str> = versions
        .iter()
        .map(|version| version.actor_user_id.as_str())
        .collect();
    let created_at: Vec<&str> = versions
        .iter()
        .map(|version| version.created_at.as_str())
        .collect();
    let diff_summaries: Vec<&str> = versions
        .iter()
        .map(|version| version.diff_summary_json.as_str())
        .collect();
    let documents: Vec<&str> = versions
        .iter()
        .map(|version| version.document_json.as_str())
        .collect();
    let etags: Vec<&str> = versions
        .iter()
        .map(|version| version.document_etag.as_str())
        .collect();
    let inserted = client
        .execute(
            r#"
            INSERT INTO greengateway.policy_documents (
                version, actor_user_id, created_at, diff_summary, document, document_etag
            )
            OVERRIDING SYSTEM VALUE
            SELECT * FROM unnest(
                $1::bigint[],
                $2::text[],
                $3::text[]::timestamptz[],
                $4::text[]::jsonb[],
                $5::text[]::jsonb[],
                $6::text[]
            )
            ON CONFLICT (version) DO NOTHING
            "#,
            &[
                &numbers,
                &actors,
                &created_at,
                &diff_summaries,
                &documents,
                &etags,
            ],
        )
        .await
        .map_err(|error| classify_query(error, OPERATION))?;
    // The identity was bypassed above, so it still points at 1. Move it
    // past every stored version; the next `commit_policy_in` then appends
    // rather than colliding.
    client
        .execute(
            r#"
            SELECT setval(
                pg_get_serial_sequence('greengateway.policy_documents', 'version'),
                (SELECT max(version) FROM greengateway.policy_documents),
                true
            )
            "#,
            &[],
        )
        .await
        .map_err(|error| classify_query(error, OPERATION))?;
    Ok(inserted)
}

#[async_trait]
impl PolicyHistory for PostgresPolicyStore {
    async fn append_version(
        &self,
        _actor_user_id: &str,
        _diff_summary: &Value,
        _policy: &Policy,
    ) -> Result<PolicyVersion, RepositoryError> {
        // Cluster-mode history is written inside `commit`; there is no
        // post-commit append to make, and a caller reaching this arm has
        // bypassed the endpoint contract. Fail closed rather than inventing
        // a history row no transaction authorized.
        tracing::error!("policy history append called outside a control-plane commit");
        Err(RepositoryError::new(
            RepositoryErrorKind::Internal,
            "policy_history_append",
        ))
    }

    async fn list_versions(
        &self,
        filters: &PolicyHistoryListFilters,
    ) -> Result<PolicyHistoryPage, RepositoryError> {
        let cursor = match filters.cursor.as_deref() {
            None => None,
            Some(value) => match value.parse::<i64>() {
                Ok(version) if version > 0 => Some(version),
                _ => {
                    return Err(RepositoryError::invalid_parameter(
                        OPERATION_HISTORY_LIST,
                        "cursor",
                    ))
                }
            },
        };
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let rows = match cursor {
            Some(cursor) => {
                client
                    .query(
                        r#"
                        SELECT version, actor_user_id,
                            to_char(created_at AT TIME ZONE 'UTC',
                                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                            diff_summary::text, document::text
                        FROM greengateway.policy_documents
                        WHERE version < $1
                        ORDER BY version DESC
                        LIMIT $2
                        "#,
                        &[&cursor, &(query_limit(filters.limit))],
                    )
                    .await
            }
            None => {
                client
                    .query(
                        r#"
                        SELECT version, actor_user_id,
                            to_char(created_at AT TIME ZONE 'UTC',
                                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                            diff_summary::text, document::text
                        FROM greengateway.policy_documents
                        ORDER BY version DESC
                        LIMIT $1
                        "#,
                        &[&(query_limit(filters.limit))],
                    )
                    .await
            }
        }
        .map_err(|error| classify_query(error, OPERATION_HISTORY_LIST))?;

        policy_history_page(rows, filters.limit, filters.include_policy)
    }

    async fn get_version(&self, version: i64) -> Result<Option<PolicyVersion>, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let row = client
            .query_opt(
                r#"
                SELECT version, actor_user_id,
                    to_char(created_at AT TIME ZONE 'UTC',
                            'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                    diff_summary::text, document::text
                FROM greengateway.policy_documents
                WHERE version = $1
                "#,
                &[&version],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_HISTORY_GET))?;
        row.map(|row| policy_version_from_row(&row, true))
            .transpose()
    }
}

/// Shared row shape of both history queries: version, actor, created_at,
/// diff summary, document. The cursor is the last RETURNED version (the
/// SQLite adapter's convention), so the next page's `version < cursor`
/// starts exactly where this one ended.
fn policy_history_page(
    rows: Vec<tokio_postgres::Row>,
    limit: usize,
    include_policy: bool,
) -> Result<PolicyHistoryPage, RepositoryError> {
    let has_more = rows.len() > limit;
    let mut versions = Vec::with_capacity(rows.len().min(limit));
    for (index, row) in rows.iter().enumerate() {
        if has_more && index == limit {
            break;
        }
        versions.push(policy_version_from_row(row, include_policy)?);
    }
    let next_cursor = if has_more {
        versions.last().map(|version| version.version.to_string())
    } else {
        None
    };
    Ok(PolicyHistoryPage {
        versions,
        next_cursor,
    })
}

fn policy_version_from_row(
    row: &tokio_postgres::Row,
    include_policy: bool,
) -> Result<PolicyVersion, RepositoryError> {
    let operation = OPERATION_HISTORY_GET;
    let diff_summary: String = row.get(3);
    let document_json: String = row.get(4);
    let diff_summary =
        serde_json::from_str::<Value>(&diff_summary).map_err(|_| invalid_data(operation))?;
    let policy = if include_policy {
        Some(policy_from_json(&document_json, operation)?)
    } else {
        None
    };
    Ok(PolicyVersion {
        version: row.get(0),
        actor_user_id: row.get(1),
        created_at: row.get(2),
        diff_summary,
        policy,
    })
}

fn policy_from_json(
    document_json: &str,
    operation: &'static str,
) -> Result<Policy, RepositoryError> {
    let value =
        serde_json::from_str::<Value>(document_json).map_err(|_| invalid_data(operation))?;
    Policy::validate_json_value(value).map_err(|error| {
        log_classified(
            operation,
            &error,
            RepositoryError::new(RepositoryErrorKind::InvalidData, operation),
        )
    })
}

fn invalid_data(operation: &'static str) -> RepositoryError {
    RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
}

fn store_error(error: RepositoryError) -> PolicyCommitError {
    PolicyCommitError::Store(error)
}

fn classify_query(error: tokio_postgres::Error, operation: &'static str) -> RepositoryError {
    let kind = super::postgres::classify_postgres_error(&error);
    log_classified(operation, &error, RepositoryError::new(kind, operation))
}

fn query_limit(limit: usize) -> i64 {
    limit.saturating_add(1).min(i64::MAX as usize) as i64
}
