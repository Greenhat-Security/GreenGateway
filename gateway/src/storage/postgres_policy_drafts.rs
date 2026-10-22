//! PostgreSQL policy draft store (issue #243, slice 9).
//!
//! Implements [`PolicyDraftStore`] against migration 22's
//! `greengateway.policy_drafts`, so every replica of a cluster serves the
//! same drafts. The contract is the one the standalone SQLite store
//! satisfies (`storage::policy_drafts`); what differs is where the clock and
//! the serialization come from:
//!
//! - Every time is database time, read once per statement from
//!   `clock_timestamp()` (`docs/architecture/ha-state-model.md`, section 2
//!   rule 5). A replica's wall clock never decides whether a draft expired.
//! - A create takes a transaction-scoped advisory lock, prunes a bounded
//!   batch of expired rows, counts, and inserts, so two replicas cannot both
//!   admit the draft that fills the last slot.
//! - Every other write is one conditional statement on the owner, the
//!   expected revision, open state and unexpired time.
//!
//! Nothing here touches the policy control plane: drafts are not security
//! state, advance no revision and write no outbox row. Errors carry a stable
//! operation label only, never SQL text, values or DSN-derived material.

use std::sync::LazyLock;

use async_trait::async_trait;

use super::{
    log_classified,
    policy_drafts::{
        candidate_from_stored, count_reaches, stored_candidate, NewPolicyDraft, PolicyDraftChange,
        PolicyDraftCreated, PolicyDraftLimits, PolicyDraftOwner, PolicyDraftRecord,
        PolicyDraftStore, PolicyDraftSummary, POLICY_DRAFT_PRUNE_BATCH,
    },
    postgres::{checkout, timed_operation, CheckoutClass},
    RepositoryError, RepositoryErrorKind,
};

const OPERATION_CREATE: &str = "policy_draft_create";
const OPERATION_GET: &str = "policy_draft_get";
const OPERATION_LIST: &str = "policy_draft_list";
const OPERATION_UPDATE: &str = "policy_draft_update";
const OPERATION_DELETE: &str = "policy_draft_delete";

/// Serializes draft creation across every replica of one deployment (one
/// database is one deployment). Transaction-scoped, so a rollback or a
/// dropped connection releases it.
static POLICY_DRAFT_CREATE_LOCK_KEY: LazyLock<i64> =
    LazyLock::new(|| super::postgres_session::advisory_lock_key("greengateway.policy-drafts"));

/// The summary columns in the order [`summary_from_row`] reads them, with
/// `expired` judged against `c.now`, the statement's single clock read.
const SUMMARY_COLUMNS: &str = "d.draft_id, d.revision, d.base_etag, d.candidate_etag, \
     d.published_etag, \
     floor(extract(epoch FROM d.created_at))::bigint, \
     floor(extract(epoch FROM d.updated_at))::bigint, \
     floor(extract(epoch FROM d.expires_at))::bigint, \
     d.expires_at <= c.now";

/// The cluster draft store. Cheap to construct: it borrows the foundation's
/// pool and holds no per-instance state.
pub struct PostgresPolicyDraftStore {
    pool: deadpool_postgres::Pool,
    limits: PolicyDraftLimits,
}

impl PostgresPolicyDraftStore {
    pub fn new(pool: deadpool_postgres::Pool) -> Self {
        Self {
            pool,
            limits: PolicyDraftLimits::default(),
        }
    }

    /// The same store under smaller bounds, for the quota contract tests.
    #[cfg(test)]
    pub(crate) fn with_limits(mut self, limits: PolicyDraftLimits) -> Self {
        self.limits = limits;
        self
    }

    fn ttl_secs(&self) -> f64 {
        // TTLs are whole seconds far inside f64's exact integer range.
        self.limits.ttl_secs as f64
    }
}

#[async_trait]
impl PolicyDraftStore for PostgresPolicyDraftStore {
    fn limits(&self) -> PolicyDraftLimits {
        self.limits
    }

    async fn create(
        &self,
        draft: NewPolicyDraft<'_>,
    ) -> Result<PolicyDraftCreated, RepositoryError> {
        let stored = stored_candidate(draft.candidate, OPERATION_CREATE)?;
        let client = checkout(&self.pool, CheckoutClass::ControlPlaneWrite).await?;
        timed_operation(OPERATION_CREATE, async {
            client
                .batch_execute("BEGIN")
                .await
                .map_err(|error| classify_query(error, OPERATION_CREATE))?;
            let outcome: Result<PolicyDraftCreated, RepositoryError> = async {
                client
                    .execute(
                        "SELECT pg_advisory_xact_lock($1)",
                        &[&*POLICY_DRAFT_CREATE_LOCK_KEY],
                    )
                    .await
                    .map_err(|error| classify_query(error, OPERATION_CREATE))?;
                // Every clock below is read after the lock was granted, so a
                // wait behind another creator cannot shorten the TTL or let a
                // quota count see rows as unexpired that have since lapsed.
                client
                    .execute(
                        r#"
                        DELETE FROM greengateway.policy_drafts
                        WHERE draft_id IN (
                            SELECT draft_id FROM greengateway.policy_drafts
                            WHERE expires_at <= clock_timestamp()
                            ORDER BY expires_at, draft_id
                            LIMIT $1
                        )
                        "#,
                        &[&POLICY_DRAFT_PRUNE_BATCH],
                    )
                    .await
                    .map_err(|error| classify_query(error, OPERATION_CREATE))?;
                let counts = client
                    .query_one(
                        r#"
                        SELECT
                            count(*) FILTER (WHERE owner_issuer = $1 AND owner_subject = $2),
                            count(*)
                        FROM greengateway.policy_drafts
                        WHERE expires_at > clock_timestamp()
                        "#,
                        &[&draft.owner.issuer, &draft.owner.subject],
                    )
                    .await
                    .map_err(|error| classify_query(error, OPERATION_CREATE))?;
                let owned: i64 = counts
                    .try_get(0)
                    .map_err(|_| invalid_data(OPERATION_CREATE))?;
                let total: i64 = counts
                    .try_get(1)
                    .map_err(|_| invalid_data(OPERATION_CREATE))?;
                if count_reaches(owned, self.limits.max_per_owner) {
                    return Ok(PolicyDraftCreated::OwnerQuotaExceeded);
                }
                if count_reaches(total, self.limits.max_total) {
                    return Ok(PolicyDraftCreated::DeploymentQuotaExceeded);
                }
                let row = client
                    .query_one(
                        &format!(
                            r#"
                            WITH c AS (SELECT clock_timestamp() AS now),
                            d AS (
                                INSERT INTO greengateway.policy_drafts (
                                    draft_id, owner_issuer, owner_subject, revision,
                                    base_etag, candidate_json, candidate_etag, published_etag,
                                    created_at, updated_at, expires_at
                                )
                                SELECT $1::text, $2::text, $3::text, 1, $4::text, $5::text,
                                       $6::text, NULL, c.now, c.now,
                                       c.now + make_interval(secs => $7::float8)
                                FROM c
                                RETURNING *
                            )
                            SELECT {SUMMARY_COLUMNS} FROM d, c
                            "#
                        ),
                        &[
                            &draft.draft_id,
                            &draft.owner.issuer,
                            &draft.owner.subject,
                            &draft.base_etag,
                            &stored.json,
                            &stored.etag,
                            &self.ttl_secs(),
                        ],
                    )
                    .await
                    .map_err(|error| classify_query(error, OPERATION_CREATE))?;
                Ok(PolicyDraftCreated::Created(Box::new(PolicyDraftRecord {
                    summary: summary_from_row(&row, OPERATION_CREATE)?,
                    candidate: draft.candidate.clone(),
                })))
            }
            .await;
            match outcome {
                Ok(created) => {
                    // A refused create still commits: the prune is cleanup
                    // progress and never depends on winning a slot.
                    client
                        .batch_execute("COMMIT")
                        .await
                        .map_err(|error| classify_query(error, OPERATION_CREATE))?;
                    Ok(created)
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
        owner: &PolicyDraftOwner,
        draft_id: &str,
    ) -> Result<Option<PolicyDraftRecord>, RepositoryError> {
        let client = checkout(&self.pool, CheckoutClass::SecurityStateRead).await?;
        timed_operation(OPERATION_GET, async {
            let row = client
                .query_opt(
                    &format!(
                        r#"
                        SELECT {SUMMARY_COLUMNS}, d.candidate_json
                        FROM greengateway.policy_drafts d,
                             (SELECT clock_timestamp() AS now) c
                        WHERE d.draft_id = $1 AND d.owner_issuer = $2 AND d.owner_subject = $3
                        "#
                    ),
                    &[&draft_id, &owner.issuer, &owner.subject],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_GET))?;
            row.map(|row| record_from_row(&row, OPERATION_GET))
                .transpose()
        })
        .await
    }

    async fn list(
        &self,
        owner: &PolicyDraftOwner,
    ) -> Result<Vec<PolicyDraftSummary>, RepositoryError> {
        let limit = i64::try_from(self.limits.max_total).unwrap_or(i64::MAX);
        let client = checkout(&self.pool, CheckoutClass::SecurityStateRead).await?;
        timed_operation(OPERATION_LIST, async {
            let rows = client
                .query(
                    &format!(
                        r#"
                        SELECT {SUMMARY_COLUMNS}
                        FROM greengateway.policy_drafts d,
                             (SELECT clock_timestamp() AS now) c
                        WHERE d.owner_issuer = $1 AND d.owner_subject = $2
                          AND d.expires_at > c.now
                        ORDER BY d.updated_at DESC, d.draft_id COLLATE "C" ASC
                        LIMIT $3
                        "#
                    ),
                    &[&owner.issuer, &owner.subject, &limit],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_LIST))?;
            rows.iter()
                .map(|row| summary_from_row(row, OPERATION_LIST))
                .collect()
        })
        .await
    }

    async fn update(
        &self,
        owner: &PolicyDraftOwner,
        draft_id: &str,
        expected_revision: i64,
        change: PolicyDraftChange<'_>,
    ) -> Result<Option<PolicyDraftRecord>, RepositoryError> {
        let client = checkout(&self.pool, CheckoutClass::ControlPlaneWrite).await?;
        timed_operation(OPERATION_UPDATE, async {
            let row = match change {
                PolicyDraftChange::Candidate {
                    candidate,
                    base_etag,
                } => {
                    let stored = stored_candidate(candidate, OPERATION_UPDATE)?;
                    client
                        .query_opt(
                            &format!(
                                r#"
                                WITH c AS (SELECT clock_timestamp() AS now),
                                d AS (
                                    UPDATE greengateway.policy_drafts p
                                    SET candidate_json = $5, candidate_etag = $6,
                                        base_etag = $7, revision = p.revision + 1,
                                        updated_at = c.now,
                                        expires_at = c.now + make_interval(secs => $8::float8)
                                    FROM c
                                    WHERE p.draft_id = $1 AND p.owner_issuer = $2
                                      AND p.owner_subject = $3 AND p.revision = $4
                                      AND p.published_etag IS NULL AND p.expires_at > c.now
                                    RETURNING p.*
                                )
                                SELECT {SUMMARY_COLUMNS}, d.candidate_json FROM d, c
                                "#
                            ),
                            &[
                                &draft_id,
                                &owner.issuer,
                                &owner.subject,
                                &expected_revision,
                                &stored.json,
                                &stored.etag,
                                &base_etag,
                                &self.ttl_secs(),
                            ],
                        )
                        .await
                }
                PolicyDraftChange::Published { published_etag } => {
                    client
                        .query_opt(
                            &format!(
                                r#"
                                WITH c AS (SELECT clock_timestamp() AS now),
                                d AS (
                                    UPDATE greengateway.policy_drafts p
                                    SET published_etag = $5, revision = p.revision + 1,
                                        updated_at = c.now
                                    FROM c
                                    WHERE p.draft_id = $1 AND p.owner_issuer = $2
                                      AND p.owner_subject = $3 AND p.revision = $4
                                      AND p.published_etag IS NULL AND p.expires_at > c.now
                                    RETURNING p.*
                                )
                                SELECT {SUMMARY_COLUMNS}, d.candidate_json FROM d, c
                                "#
                            ),
                            &[
                                &draft_id,
                                &owner.issuer,
                                &owner.subject,
                                &expected_revision,
                                &published_etag,
                            ],
                        )
                        .await
                }
            }
            .map_err(|error| classify_query(error, OPERATION_UPDATE))?;
            row.map(|row| record_from_row(&row, OPERATION_UPDATE))
                .transpose()
        })
        .await
    }

    async fn delete(
        &self,
        owner: &PolicyDraftOwner,
        draft_id: &str,
        expected_revision: i64,
    ) -> Result<bool, RepositoryError> {
        let client = checkout(&self.pool, CheckoutClass::ControlPlaneWrite).await?;
        timed_operation(OPERATION_DELETE, async {
            let deleted = client
                .execute(
                    r#"
                    DELETE FROM greengateway.policy_drafts
                    WHERE draft_id = $1 AND owner_issuer = $2 AND owner_subject = $3
                      AND revision = $4 AND expires_at > clock_timestamp()
                    "#,
                    &[&draft_id, &owner.issuer, &owner.subject, &expected_revision],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_DELETE))?;
            Ok(deleted == 1)
        })
        .await
    }
}

fn summary_from_row(
    row: &tokio_postgres::Row,
    operation: &'static str,
) -> Result<PolicyDraftSummary, RepositoryError> {
    let invalid = |_| invalid_data(operation);
    Ok(PolicyDraftSummary {
        draft_id: row.try_get(0).map_err(invalid)?,
        revision: row.try_get(1).map_err(invalid)?,
        base_etag: row.try_get(2).map_err(invalid)?,
        candidate_etag: row.try_get(3).map_err(invalid)?,
        published_etag: row.try_get(4).map_err(invalid)?,
        created_at: row.try_get(5).map_err(invalid)?,
        updated_at: row.try_get(6).map_err(invalid)?,
        expires_at: row.try_get(7).map_err(invalid)?,
        expired: row.try_get(8).map_err(invalid)?,
    })
}

fn record_from_row(
    row: &tokio_postgres::Row,
    operation: &'static str,
) -> Result<PolicyDraftRecord, RepositoryError> {
    let summary = summary_from_row(row, operation)?;
    let candidate_json: String = row.try_get(9).map_err(|_| invalid_data(operation))?;
    let candidate = candidate_from_stored(&candidate_json, &summary.candidate_etag, operation)?;
    Ok(PolicyDraftRecord { summary, candidate })
}

fn invalid_data(operation: &'static str) -> RepositoryError {
    RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
}

fn classify_query(error: tokio_postgres::Error, operation: &'static str) -> RepositoryError {
    let kind = super::postgres::classify_postgres_error(&error);
    log_classified(operation, &error, RepositoryError::new(kind, operation))
}
