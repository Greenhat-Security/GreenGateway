//! PostgreSQL record of delegated-token purges (issue #441).
//!
//! Each replica caches the delegated issuer tokens it exchanged in its own
//! memory, so a purge one replica applies leaves every other replica's
//! copies in place. Cluster mode therefore records each purge at the
//! authority, and every replica applies what was recorded before it serves
//! another protected request.
//!
//! The record is the shared security change feed, not a table of its own:
//!
//! - **A purge is a committed control-plane mutation.** One transaction
//!   reserves the next shared security revision and appends a
//!   `security_outbox` row with `resource_type = 'delegated_token_purge'`
//!   and `resource_id` = the purge key. The strict per-request gate reads
//!   that counter on every protected request, so a replica behind it
//!   reconciles -- and applies the purge -- before it serves again. No
//!   migration: the outbox has carried an opaque `resource_id` since
//!   migration 6, and its `resource_type` is not constrained.
//! - **The row names no principal.** The purge key is a SHA-256 digest
//!   under the deployment ID of the cache's own principal digest (see
//!   `connections::token_exchange::purge_key`), so the outbox keeps its
//!   "identifiers and revisions only" rule and a replica matches the key
//!   against the tokens it holds without learning who it names.
//! - **Rows are append-only and read by revision range.** A replica keeps
//!   the revision through which it has applied every purge and reads only
//!   the rows above it, on the outbox's primary key. A repeat purge of the
//!   same principal is a new row: each one retires whatever that principal
//!   was exchanged on any replica since the previous one.
//!
//! Errors carry a classification and a static operation label only -- no
//! SQL, no values, no purge key.

use super::{
    log_classified,
    postgres::{checkout, timed_operation, CheckoutClass},
    RepositoryError, RepositoryErrorKind,
};

const OPERATION_RECORD: &str = "delegated_token_purge_record";
const OPERATION_FRONTIER: &str = "delegated_token_purge_frontier_read";
const OPERATION_READ: &str = "delegated_token_purge_read";

/// The `security_outbox.resource_type` of a recorded purge.
pub const RESOURCE_TYPE: &str = "delegated_token_purge";

/// Where the record stands, read in one statement: every purge recorded at
/// or below `authority_revision` is visible to the same statement, because a
/// revision is reserved under the counter row's lock and published by the
/// commit that also writes its outbox row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelegatedTokenPurgeFrontier {
    /// The shared security revision when the statement ran.
    pub authority_revision: i64,
    /// The latest purge recorded above the revision asked about and at or
    /// below `authority_revision`; `None` when there is none.
    pub latest_purge: Option<i64>,
}

/// One purge as the authority recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedDelegatedTokenPurge {
    pub security_revision: i64,
    /// The purge key as stored. A row written by anything but
    /// [`PostgresDelegatedTokenPurgeStore::record`] may carry none, or one
    /// of the wrong shape; the reader decides what that means.
    pub purge_key: Option<String>,
}

/// The cluster-mode purge record over the shared pool. Cheap to construct.
pub struct PostgresDelegatedTokenPurgeStore {
    pool: deadpool_postgres::Pool,
}

impl PostgresDelegatedTokenPurgeStore {
    pub fn new(pool: deadpool_postgres::Pool) -> Self {
        Self { pool }
    }

    /// Records a purge of the principal `purge_key` names and returns the
    /// security revision it took. The key must be 64 lowercase hex digits,
    /// the shape every reader expects; anything else is the caller's error
    /// and nothing is written.
    pub async fn record(&self, purge_key: &str) -> Result<i64, RepositoryError> {
        if !crate::connections::token_exchange::is_purge_key(purge_key) {
            return Err(RepositoryError::invalid_parameter(
                OPERATION_RECORD,
                "purge_key",
            ));
        }
        let client = checkout(&self.pool, CheckoutClass::ControlPlaneWrite).await?;
        timed_operation(OPERATION_RECORD, async {
            client
                .batch_execute("BEGIN")
                .await
                .map_err(|error| classify_query(error, OPERATION_RECORD))?;
            let recorded: Result<i64, RepositoryError> = async {
                // The reservation and the row commit together, or neither
                // does: an aborted purge gives its revision back.
                let revision: i64 = client
                    .query_one(
                        r#"
                        UPDATE greengateway.security_revision_state
                        SET last_revision = last_revision + 1
                        WHERE singleton
                        RETURNING last_revision
                        "#,
                        &[],
                    )
                    .await
                    .map_err(|error| classify_query(error, OPERATION_RECORD))?
                    .try_get(0)
                    .map_err(|_| invalid_data(OPERATION_RECORD))?;
                client
                    .execute(
                        r#"
                        INSERT INTO greengateway.security_outbox (
                            revision, resource_type, from_version, to_version, resource_id
                        ) VALUES ($1, $2, NULL, 1, $3)
                        "#,
                        &[&revision, &RESOURCE_TYPE, &purge_key],
                    )
                    .await
                    .map_err(|error| classify_query(error, OPERATION_RECORD))?;
                Ok(revision)
            }
            .await;
            match recorded {
                Ok(revision) => {
                    client
                        .batch_execute("COMMIT")
                        .await
                        .map_err(|error| classify_query(error, OPERATION_RECORD))?;
                    Ok(revision)
                }
                Err(error) => {
                    let _ = client.batch_execute("ROLLBACK").await;
                    Err(error)
                }
            }
        })
        .await
    }

    /// The shared security revision, and the latest purge recorded above
    /// `after` and at or below it, in one statement.
    pub async fn frontier(
        &self,
        after: i64,
    ) -> Result<DelegatedTokenPurgeFrontier, RepositoryError> {
        let client = checkout(&self.pool, CheckoutClass::SecurityStateRead).await?;
        timed_operation(OPERATION_FRONTIER, async {
            let row = client
                .query_opt(
                    r#"
                    SELECT state.last_revision,
                           (SELECT max(outbox.revision)
                            FROM greengateway.security_outbox AS outbox
                            WHERE outbox.revision > $1
                              AND outbox.revision <= state.last_revision
                              AND outbox.resource_type = $2)
                    FROM greengateway.security_revision_state AS state
                    WHERE state.singleton
                    "#,
                    &[&after, &RESOURCE_TYPE],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_FRONTIER))?
                // Seeded by migration 4 and never deleted; absence means the
                // schema is not the one this build expects.
                .ok_or_else(|| invalid_data(OPERATION_FRONTIER))?;
            Ok(DelegatedTokenPurgeFrontier {
                authority_revision: row
                    .try_get(0)
                    .map_err(|_| invalid_data(OPERATION_FRONTIER))?,
                latest_purge: row
                    .try_get(1)
                    .map_err(|_| invalid_data(OPERATION_FRONTIER))?,
            })
        })
        .await
    }

    /// The purges recorded above `after` and at or below `through`, oldest
    /// first, at most `limit` of them.
    pub async fn recorded_between(
        &self,
        after: i64,
        through: i64,
        limit: usize,
    ) -> Result<Vec<RecordedDelegatedTokenPurge>, RepositoryError> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let client = checkout(&self.pool, CheckoutClass::SecurityStateRead).await?;
        timed_operation(OPERATION_READ, async {
            let rows = client
                .query(
                    r#"
                    SELECT revision, resource_id
                    FROM greengateway.security_outbox
                    WHERE revision > $1 AND revision <= $2 AND resource_type = $3
                    ORDER BY revision
                    LIMIT $4
                    "#,
                    &[&after, &through, &RESOURCE_TYPE, &limit],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_READ))?;
            rows.iter()
                .map(|row| {
                    Ok(RecordedDelegatedTokenPurge {
                        security_revision: row
                            .try_get(0)
                            .map_err(|_| invalid_data(OPERATION_READ))?,
                        purge_key: row.try_get(1).map_err(|_| invalid_data(OPERATION_READ))?,
                    })
                })
                .collect()
        })
        .await
    }
}

fn classify_query(error: tokio_postgres::Error, operation: &'static str) -> RepositoryError {
    let kind = super::postgres::classify_postgres_error(&error);
    log_classified(operation, &error, RepositoryError::new(kind, operation))
}

fn invalid_data(operation: &'static str) -> RepositoryError {
    RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
}

#[cfg(test)]
#[path = "postgres_delegated_token_purges_tests.rs"]
mod tests;
