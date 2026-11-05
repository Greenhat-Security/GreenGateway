//! PostgreSQL policy analysis suppression store (issue #243, slice 15).
//!
//! Implements [`AnalysisSuppressionStore`] against migration 28's
//! `greengateway.policy_analysis_suppressions`, so every replica of a
//! cluster marks the same findings suppressed. The contract is the one the
//! standalone SQLite store satisfies (`storage::analysis_suppressions`);
//! what differs is where the clock and the serialization come from:
//!
//! - Every time is database time, read once per statement from
//!   `clock_timestamp()` (`docs/architecture/ha-state-model.md`, section 2
//!   rule 5). A replica's wall clock never decides whether a suppression has
//!   ended or how far ahead an expiry may be.
//! - A create takes a transaction-scoped advisory lock, checks for a
//!   duplicate, counts, removes only the ended rows it needs room for, and
//!   inserts, so two replicas cannot both admit the suppression that fills
//!   the last slot.
//! - A withdrawal is one conditional statement on the expected revision and
//!   unended state.
//!
//! Nothing here touches the policy control plane: suppressions are not
//! security state, advance no revision and write no outbox row. Errors carry
//! a stable operation label only, never SQL text, values or DSN-derived
//! material.

use std::sync::LazyLock;

use async_trait::async_trait;

use super::{
    analysis_suppressions::{
        check_new, check_record, excess_rows, AnalysisSuppressionActor, AnalysisSuppressionCreated,
        AnalysisSuppressionLimits, AnalysisSuppressionRecord, AnalysisSuppressionStore,
        NewAnalysisSuppression,
    },
    log_classified,
    policy_drafts::count_reaches,
    postgres::{checkout, timed_operation, CheckoutClass},
    RepositoryError, RepositoryErrorKind,
};

const OPERATION_CREATE: &str = "analysis_suppression_create";
const OPERATION_GET: &str = "analysis_suppression_get";
const OPERATION_LIST: &str = "analysis_suppression_list";
const OPERATION_WITHDRAW: &str = "analysis_suppression_withdraw";

/// Serializes suppression creation across every replica of one deployment
/// (one database is one deployment). Transaction-scoped, so a rollback or a
/// dropped connection releases it.
static ANALYSIS_SUPPRESSION_CREATE_LOCK_KEY: LazyLock<i64> = LazyLock::new(|| {
    super::postgres_session::advisory_lock_key("greengateway.policy-analysis-suppressions")
});

/// The columns in the order [`record_from_row`] reads them, with `ended`
/// judged against `c.now`, the statement's single clock read.
const RECORD_COLUMNS: &str = "s.suppression_id, s.revision, s.fingerprint, s.code, s.reason, \
     s.actor_issuer, s.actor_subject, s.policy_etag, s.policy_semantic_digest, \
     s.resource_snapshot_digest, \
     floor(extract(epoch FROM s.created_at))::bigint, \
     floor(extract(epoch FROM s.expires_at))::bigint, \
     floor(extract(epoch FROM s.withdrawn_at))::bigint, \
     (s.withdrawn_at IS NOT NULL OR s.expires_at <= c.now)";

/// The cluster suppression store. Cheap to construct: it borrows the
/// foundation's pool and holds no per-instance state.
pub struct PostgresAnalysisSuppressionStore {
    pool: deadpool_postgres::Pool,
    limits: AnalysisSuppressionLimits,
}

impl PostgresAnalysisSuppressionStore {
    pub fn new(pool: deadpool_postgres::Pool) -> Self {
        Self {
            pool,
            limits: AnalysisSuppressionLimits::default(),
        }
    }

    /// The same store under smaller bounds, for the quota contract tests.
    #[cfg(test)]
    pub(crate) fn with_limits(mut self, limits: AnalysisSuppressionLimits) -> Self {
        self.limits = limits;
        self
    }

    fn max_ttl_secs(&self) -> f64 {
        // TTLs are whole seconds far inside f64's exact integer range.
        self.limits.max_ttl_secs as f64
    }
}

#[async_trait]
impl AnalysisSuppressionStore for PostgresAnalysisSuppressionStore {
    fn limits(&self) -> AnalysisSuppressionLimits {
        self.limits
    }

    async fn create(
        &self,
        suppression: NewAnalysisSuppression<'_>,
    ) -> Result<AnalysisSuppressionCreated, RepositoryError> {
        check_new(&suppression, OPERATION_CREATE)?;
        // Unix seconds are far inside f64's exact integer range.
        let expires_at = suppression.expires_at as f64;
        let max_total = i64::try_from(self.limits.max_total).unwrap_or(i64::MAX);
        let client = checkout(&self.pool, CheckoutClass::ControlPlaneWrite).await?;
        timed_operation(OPERATION_CREATE, async {
            client
                .batch_execute("BEGIN")
                .await
                .map_err(|error| classify_query(error, OPERATION_CREATE))?;
            let outcome: Result<AnalysisSuppressionCreated, RepositoryError> = async {
                client
                    .execute(
                        "SELECT pg_advisory_xact_lock($1)",
                        &[&*ANALYSIS_SUPPRESSION_CREATE_LOCK_KEY],
                    )
                    .await
                    .map_err(|error| classify_query(error, OPERATION_CREATE))?;
                // Every clock below is read after the lock was granted, so a
                // wait behind another creator cannot stretch the expiry
                // window or let a count see rows as unended that have since
                // ended.
                let in_window: bool = client
                    .query_one(
                        r#"
                        SELECT to_timestamp($1::float8) > c.now
                           AND to_timestamp($1::float8)
                               <= c.now + make_interval(secs => $2::float8)
                        FROM (SELECT clock_timestamp() AS now) c
                        "#,
                        &[&expires_at, &self.max_ttl_secs()],
                    )
                    .await
                    .map_err(|error| classify_query(error, OPERATION_CREATE))?
                    .try_get(0)
                    .map_err(|_| invalid_data(OPERATION_CREATE))?;
                if !in_window {
                    return Ok(AnalysisSuppressionCreated::ExpiryOutOfRange);
                }
                let duplicate = client
                    .query_opt(
                        r#"
                        SELECT suppression_id FROM greengateway.policy_analysis_suppressions
                        WHERE fingerprint = $1 AND code = $2 AND policy_etag = $3
                          AND policy_semantic_digest IS NOT DISTINCT FROM $4
                          AND resource_snapshot_digest = $5
                          AND withdrawn_at IS NULL AND expires_at > clock_timestamp()
                        ORDER BY created_at, suppression_id COLLATE "C"
                        LIMIT 1
                        "#,
                        &[
                            &suppression.fingerprint,
                            &suppression.code,
                            &suppression.policy_etag,
                            &suppression.policy_semantic_digest,
                            &suppression.resource_snapshot_digest,
                        ],
                    )
                    .await
                    .map_err(|error| classify_query(error, OPERATION_CREATE))?;
                if let Some(row) = duplicate {
                    return Ok(AnalysisSuppressionCreated::Duplicate {
                        suppression_id: row
                            .try_get(0)
                            .map_err(|_| invalid_data(OPERATION_CREATE))?,
                    });
                }
                let counts = client
                    .query_one(
                        r#"
                        SELECT
                            count(*) FILTER (
                                WHERE withdrawn_at IS NULL AND expires_at > c.now
                            ),
                            count(*)
                        FROM greengateway.policy_analysis_suppressions,
                             (SELECT clock_timestamp() AS now) c
                        "#,
                        &[],
                    )
                    .await
                    .map_err(|error| classify_query(error, OPERATION_CREATE))?;
                let unended: i64 = counts
                    .try_get(0)
                    .map_err(|_| invalid_data(OPERATION_CREATE))?;
                let total: i64 = counts
                    .try_get(1)
                    .map_err(|_| invalid_data(OPERATION_CREATE))?;
                if count_reaches(unended, self.limits.max_total) {
                    return Ok(AnalysisSuppressionCreated::DeploymentQuotaExceeded);
                }
                let excess = excess_rows(total, self.limits.max_total);
                if excess > 0 {
                    client
                        .execute(
                            r#"
                            DELETE FROM greengateway.policy_analysis_suppressions
                            WHERE suppression_id IN (
                                SELECT suppression_id
                                FROM greengateway.policy_analysis_suppressions
                                WHERE withdrawn_at IS NOT NULL
                                   OR expires_at <= clock_timestamp()
                                ORDER BY COALESCE(withdrawn_at, expires_at),
                                         suppression_id COLLATE "C"
                                LIMIT $1
                            )
                            "#,
                            &[&excess.min(max_total)],
                        )
                        .await
                        .map_err(|error| classify_query(error, OPERATION_CREATE))?;
                }
                let row = client
                    .query_opt(
                        &format!(
                            r#"
                            WITH c AS (SELECT clock_timestamp() AS now),
                            s AS (
                                INSERT INTO greengateway.policy_analysis_suppressions (
                                    suppression_id, revision, fingerprint, code, reason,
                                    actor_issuer, actor_subject, policy_etag,
                                    policy_semantic_digest, resource_snapshot_digest,
                                    created_at, expires_at, withdrawn_at
                                )
                                SELECT $1::text, 1, $2::text, $3::text, $4::text, $5::text,
                                       $6::text, $7::text, $8::text, $9::text, c.now,
                                       to_timestamp($10::float8), NULL
                                FROM c
                                WHERE to_timestamp($10::float8) > c.now
                                  AND to_timestamp($10::float8)
                                      <= c.now + make_interval(secs => $11::float8)
                                RETURNING *
                            )
                            SELECT {RECORD_COLUMNS} FROM s, c
                            "#
                        ),
                        &[
                            &suppression.suppression_id,
                            &suppression.fingerprint,
                            &suppression.code,
                            &suppression.reason,
                            &suppression.actor.issuer,
                            &suppression.actor.subject,
                            &suppression.policy_etag,
                            &suppression.policy_semantic_digest,
                            &suppression.resource_snapshot_digest,
                            &expires_at,
                            &self.max_ttl_secs(),
                        ],
                    )
                    .await
                    .map_err(|error| classify_query(error, OPERATION_CREATE))?;
                // The window was checked a moment ago on the same clock; an
                // expiry that crossed its bound since is refused, not stored.
                match row {
                    Some(row) => Ok(AnalysisSuppressionCreated::Created(Box::new(
                        record_from_row(&row, OPERATION_CREATE)?,
                    ))),
                    None => Ok(AnalysisSuppressionCreated::ExpiryOutOfRange),
                }
            }
            .await;
            match outcome {
                Ok(AnalysisSuppressionCreated::Created(record)) => {
                    client
                        .batch_execute("COMMIT")
                        .await
                        .map_err(|error| classify_query(error, OPERATION_CREATE))?;
                    Ok(AnalysisSuppressionCreated::Created(record))
                }
                // A refused create wrote nothing it needs to keep: the room
                // it made, if any, belongs to the row it did not insert.
                Ok(refused) => {
                    client
                        .batch_execute("ROLLBACK")
                        .await
                        .map_err(|error| classify_query(error, OPERATION_CREATE))?;
                    Ok(refused)
                }
                Err(error) => {
                    let _ = client.batch_execute("ROLLBACK").await;
                    Err(error)
                }
            }
        })
        .await
    }

    async fn get(
        &self,
        suppression_id: &str,
    ) -> Result<Option<AnalysisSuppressionRecord>, RepositoryError> {
        let client = checkout(&self.pool, CheckoutClass::SecurityStateRead).await?;
        timed_operation(OPERATION_GET, async {
            let row = client
                .query_opt(
                    &format!(
                        r#"
                        SELECT {RECORD_COLUMNS}
                        FROM greengateway.policy_analysis_suppressions s,
                             (SELECT clock_timestamp() AS now) c
                        WHERE s.suppression_id = $1
                        "#
                    ),
                    &[&suppression_id],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_GET))?;
            row.map(|row| record_from_row(&row, OPERATION_GET))
                .transpose()
        })
        .await
    }

    async fn list(&self) -> Result<Vec<AnalysisSuppressionRecord>, RepositoryError> {
        let limit = i64::try_from(self.limits.max_total).unwrap_or(i64::MAX);
        let client = checkout(&self.pool, CheckoutClass::SecurityStateRead).await?;
        timed_operation(OPERATION_LIST, async {
            let rows = client
                .query(
                    &format!(
                        r#"
                        SELECT {RECORD_COLUMNS}
                        FROM greengateway.policy_analysis_suppressions s,
                             (SELECT clock_timestamp() AS now) c
                        ORDER BY s.created_at, s.suppression_id COLLATE "C"
                        LIMIT $1
                        "#
                    ),
                    &[&limit],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_LIST))?;
            rows.iter()
                .map(|row| record_from_row(row, OPERATION_LIST))
                .collect()
        })
        .await
    }

    async fn withdraw(
        &self,
        suppression_id: &str,
        expected_revision: i64,
    ) -> Result<Option<AnalysisSuppressionRecord>, RepositoryError> {
        let client = checkout(&self.pool, CheckoutClass::ControlPlaneWrite).await?;
        timed_operation(OPERATION_WITHDRAW, async {
            let row = client
                .query_opt(
                    &format!(
                        r#"
                        WITH c AS (SELECT clock_timestamp() AS now),
                        s AS (
                            UPDATE greengateway.policy_analysis_suppressions p
                            SET withdrawn_at = GREATEST(c.now, p.created_at),
                                revision = p.revision + 1
                            FROM c
                            WHERE p.suppression_id = $1 AND p.revision = $2
                              AND p.withdrawn_at IS NULL AND p.expires_at > c.now
                            RETURNING p.*
                        )
                        SELECT {RECORD_COLUMNS} FROM s, c
                        "#
                    ),
                    &[&suppression_id, &expected_revision],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_WITHDRAW))?;
            row.map(|row| record_from_row(&row, OPERATION_WITHDRAW))
                .transpose()
        })
        .await
    }
}

fn record_from_row(
    row: &tokio_postgres::Row,
    operation: &'static str,
) -> Result<AnalysisSuppressionRecord, RepositoryError> {
    let invalid = |_| invalid_data(operation);
    let record = AnalysisSuppressionRecord {
        suppression_id: row.try_get(0).map_err(invalid)?,
        revision: row.try_get(1).map_err(invalid)?,
        fingerprint: row.try_get(2).map_err(invalid)?,
        code: row.try_get(3).map_err(invalid)?,
        reason: row.try_get(4).map_err(invalid)?,
        actor: AnalysisSuppressionActor {
            issuer: row.try_get(5).map_err(invalid)?,
            subject: row.try_get(6).map_err(invalid)?,
        },
        policy_etag: row.try_get(7).map_err(invalid)?,
        policy_semantic_digest: row.try_get(8).map_err(invalid)?,
        resource_snapshot_digest: row.try_get(9).map_err(invalid)?,
        created_at: row.try_get(10).map_err(invalid)?,
        expires_at: row.try_get(11).map_err(invalid)?,
        withdrawn_at: row.try_get(12).map_err(invalid)?,
        ended: row.try_get(13).map_err(invalid)?,
    };
    check_record(record, operation)
}

fn invalid_data(operation: &'static str) -> RepositoryError {
    RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
}

fn classify_query(error: tokio_postgres::Error, operation: &'static str) -> RepositoryError {
    let kind = super::postgres::classify_postgres_error(&error);
    log_classified(operation, &error, RepositoryError::new(kind, operation))
}
