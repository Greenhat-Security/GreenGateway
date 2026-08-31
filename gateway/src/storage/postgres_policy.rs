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
//! Reads are plain committed reads: `active` re-verifies the stored ETag
//! against the recomputed document hash (a tampered pointer fails closed as
//! `InvalidData` rather than serving an unverifiable document) and parses
//! the document through [`Policy::validate_json_value`], so callers only
//! ever see a document this binary can serve.
//!
//! Redaction follows the foundation's rules: no SQL text, no query values,
//! and no DSN-derived material cross the error boundary.

use async_trait::async_trait;
use serde_json::Value;

use crate::rbac::{
    policy_history::{PolicyHistoryListFilters, PolicyHistoryPage, PolicyVersion},
    Policy,
};

use super::{
    log_classified,
    policy_history::{
        ActivePolicy, PolicyCommitError, PolicyCommitPrecondition, PolicyCommitRequest,
        PolicyControlPlane, PolicyHistory,
    },
    postgres::classify_pool_error,
    RepositoryError, RepositoryErrorKind,
};

/// The operation labels the classified errors of this module carry. Static
/// strings only: the contract never carries SQL text or values.
const OPERATION_ACTIVE: &str = "policy_active_read";
const OPERATION_REVISION: &str = "policy_revision_read";
const OPERATION_COMMIT: &str = "policy_commit";
const OPERATION_HISTORY_LIST: &str = "policy_history_list";
const OPERATION_HISTORY_GET: &str = "policy_history_get";
const OPERATION_OUTBOX: &str = "policy_outbox_read";

/// Locks only the pointer row (`FOR UPDATE OF a`): the immutable document
/// needs no lock, but joining it lets the transaction verify the pointer's
/// recorded ETag against the document it names -- the same self-consistency
/// check `active()` performs, so a pointer edited out-of-band fails closed
/// on the commit path too instead of being silently "healed" by the next
/// writer.
const LOCK_ACTIVE_SQL: &str = r#"
SELECT a.active_version, a.document_etag, d.document_etag
FROM greengateway.policy_active a
JOIN greengateway.policy_documents d ON d.version = a.active_version
WHERE a.singleton
FOR UPDATE OF a
"#;

const INSERT_DOCUMENT_SQL: &str = r#"
INSERT INTO greengateway.policy_documents (
    actor_user_id, diff_summary, document, document_etag
)
VALUES ($1, $2::text::jsonb, $3::text::jsonb, $4)
RETURNING version
"#;

const RESERVE_REVISION_SQL: &str = r#"
UPDATE greengateway.security_revision_state
SET last_revision = last_revision + 1
WHERE singleton
RETURNING last_revision
"#;

const ADVANCE_POINTER_SQL: &str = r#"
UPDATE greengateway.policy_active
SET active_version = $1, document_etag = $2, security_revision = $3,
    activated_at = now()
WHERE singleton
"#;

/// `ON CONFLICT DO NOTHING` turns the initialize race into a row count: a
/// concurrent initializer that committed first leaves this insert at zero
/// rows, which the caller-side check maps to `PreconditionFailed`.
const INITIALIZE_POINTER_SQL: &str = r#"
INSERT INTO greengateway.policy_active (
    singleton, active_version, document_etag, security_revision
)
VALUES (true, $1, $2, $3)
ON CONFLICT (singleton) DO NOTHING
"#;

const APPEND_OUTBOX_SQL: &str = r#"
INSERT INTO greengateway.security_outbox (
    revision, resource_type, from_version, to_version
)
VALUES ($1, 'policy', $2, $3)
"#;

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

/// The authoritative PostgreSQL policy control plane. Cheap to construct:
/// it borrows the foundation's pool and holds no per-instance state.
pub struct PostgresPolicyStore {
    pool: deadpool_postgres::Pool,
}

impl PostgresPolicyStore {
    pub fn new(pool: deadpool_postgres::Pool) -> Self {
        Self { pool }
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
        let row = client
            .query_opt(
                r#"
                SELECT a.active_version,
                    a.document_etag,
                    a.security_revision,
                    to_char(d.created_at AT TIME ZONE 'UTC',
                            'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                    d.document::text
                FROM greengateway.policy_active a
                JOIN greengateway.policy_documents d ON d.version = a.active_version
                WHERE a.singleton
                "#,
                &[],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_ACTIVE))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let stored_etag: String = row.get(1);
        let document_json: String = row.get(4);
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
            version: row.get(0),
            etag,
            security_revision: row.get(2),
        }))
    }

    async fn current_security_revision(&self) -> Result<i64, RepositoryError> {
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
        let document_json = serde_json::to_string(request.candidate)
            .map_err(|_| invalid_data(OPERATION_COMMIT))
            .map_err(store_error)?;
        let diff_summary_json = serde_json::to_string(request.diff_summary)
            .map_err(|_| invalid_data(OPERATION_COMMIT))
            .map_err(store_error)?;
        let etag = crate::policy_etag(request.candidate)
            .map_err(|_| invalid_data(OPERATION_COMMIT))
            .map_err(store_error)?;

        // The transaction is driven explicitly over the simple protocol
        // (the audit store's and the migrator's pattern). A request
        // abandoned between BEGIN and COMMIT returns its connection to the
        // pool with the transaction open; the row locks it holds are
        // reclaimed by the session's server-side bounds (`lock_timeout`
        // bounds other writers' waits, `idle_in_transaction_session_timeout`
        // closes the session), so the failure mode is bounded 503s, never
        // corruption. A drop-guarded interactive transaction can harden
        // this and the audit append together if abandonment proves real.
        client
            .batch_execute("BEGIN")
            .await
            .map_err(|error| classify_query(error, OPERATION_COMMIT))
            .map_err(store_error)?;
        let outcome: Result<ActivePolicy, PolicyCommitError> = async {
            // 1. Lock and read the expected active state, verifying the
            //    pointer's recorded ETag against the document it names.
            let active_row = client
                .query_opt(LOCK_ACTIVE_SQL, &[])
                .await
                .map_err(|error| classify_query(error, OPERATION_COMMIT))
                .map_err(store_error)?;
            let current = active_row.map(|row| {
                let recorded_etag: String = row.get(1);
                let document_etag: String = row.get(2);
                (row.get::<_, i64>(0), recorded_etag, document_etag)
            });

            if let Some((_, recorded_etag, document_etag)) = &current {
                if recorded_etag != document_etag {
                    tracing::error!(
                        "the active policy pointer's recorded ETag does not match the \
                         document it names; refusing to commit over an inconsistent authority"
                    );
                    return Err(PolicyCommitError::Store(invalid_data(OPERATION_COMMIT)));
                }
            }

            // 2. Re-verify the precondition against the authority.
            match (&request.precondition, &current) {
                (
                    PolicyCommitPrecondition::Expected { etag: expected },
                    Some((_, current_etag, _)),
                ) if current_etag == expected => {}
                (PolicyCommitPrecondition::Initialize, None) => {}
                _ => return Err(PolicyCommitError::PreconditionFailed),
            }

            // 3. The new immutable version (also the history row).
            let document_row = client
                .query_one(
                    INSERT_DOCUMENT_SQL,
                    &[
                        &request.actor_user_id,
                        &diff_summary_json,
                        &document_json,
                        &etag,
                    ],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_COMMIT))
                .map_err(store_error)?;
            let new_version: i64 = document_row.get(0);

            // 4. Reserve the next security revision (rollback-safe).
            let revision_row = client
                .query_opt(RESERVE_REVISION_SQL, &[])
                .await
                .map_err(|error| classify_query(error, OPERATION_COMMIT))
                .map_err(store_error)?;
            let new_revision: i64 = revision_row
                .map(|row| row.get(0))
                .ok_or_else(|| invalid_data(OPERATION_COMMIT))
                .map_err(store_error)?;

            // 5. Advance the active pointer.
            match current {
                Some((previous_version, _, _)) => {
                    client
                        .execute(ADVANCE_POINTER_SQL, &[&new_version, &etag, &new_revision])
                        .await
                        .map_err(|error| classify_query(error, OPERATION_COMMIT))
                        .map_err(store_error)?;
                    client
                        .execute(
                            APPEND_OUTBOX_SQL,
                            &[&new_revision, &previous_version, &new_version],
                        )
                        .await
                        .map_err(|error| classify_query(error, OPERATION_COMMIT))
                        .map_err(store_error)?;
                }
                None => {
                    let inserted = client
                        .execute(
                            INITIALIZE_POINTER_SQL,
                            &[&new_version, &etag, &new_revision],
                        )
                        .await
                        .map_err(|error| classify_query(error, OPERATION_COMMIT))
                        .map_err(store_error)?;
                    if inserted == 0 {
                        // Another initializer won the race; the lock on a
                        // not-yet-existing row protected nothing, so this
                        // insert's conflict clause is the serialization
                        // point. Nothing of ours committed.
                        return Err(PolicyCommitError::PreconditionFailed);
                    }
                    client
                        .execute(
                            APPEND_OUTBOX_SQL,
                            &[&new_revision, &None::<i64>, &new_version],
                        )
                        .await
                        .map_err(|error| classify_query(error, OPERATION_COMMIT))
                        .map_err(store_error)?;
                }
            }

            Ok(ActivePolicy {
                policy: request.candidate.clone(),
                version: new_version,
                etag,
                security_revision: new_revision,
            })
        }
        .await;
        match outcome {
            Ok(active) => client
                .batch_execute("COMMIT")
                .await
                .map_err(|error| classify_query(error, OPERATION_COMMIT))
                .map_err(store_error)
                .map(|_| active),
            Err(error) => {
                let _ = client.batch_execute("ROLLBACK").await;
                Err(error)
            }
        }
    }
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
